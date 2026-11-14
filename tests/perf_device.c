/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <urov/urov.h>
#include "../test_config.h"

extern unsigned char perf_pages[], perf_patch_word[];
extern uint64_t perf_read(const void *);
extern void perf_block(const void *, void *);
extern unsigned perf_llsc_long(uint64_t *, const void *);
extern unsigned perf_llsc_clrex(uint64_t *, const void *);
extern unsigned perf_llsc_skip(uint64_t *, const void *);
extern unsigned perf_mutable(uint64_t *, const void *);
extern unsigned perf_self(const void *);
extern uint64_t perf_ldadd(void *, uint64_t);

static struct urov_client client;
static int active;
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d errno=%d\n", __LINE__, errno); goto fail; } } while (0)
static uint64_t now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static int cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static double scan(unsigned n, size_t page, int full)
{
    unsigned char block[64];
    uint64_t times[9];
    for (unsigned r = 0; r < 11; ++r) {
        uint64_t start = now();
        for (unsigned p = 0; p < n; ++p)
            for (size_t off = 0; off < (full ? page : 64); off += 64)
                perf_block(perf_pages + p * page + off, block);
        if (r >= 2) times[r - 2] = now() - start;
        if (block[0] != 0x6a || block[63] != 0x6a) return -1;
    }
    qsort(times, 9, sizeof(times[0]), cmp);
    return times[4] / 1000.0;
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    struct urov_info info;
    struct urov_status status;
    struct urov_page desc[256];
    unsigned sizes[] = {1, 2, 4, 8, 10, 32, 64, 128, 256};
    unsigned char *image = NULL;
    uint64_t lock = 5;
    unsigned native_long, native_clear, native_skip;
    CHECK(page == 4096 || page == 16384);
    CHECK(!urov_client_init(&client, UROV_TEST_KEY) && !urov_query(&client, &info));
    image = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (image == MAP_FAILED) image = NULL;
    CHECK(image); /* mmap supplies untagged addresses required by the wire ABI. */
    memset(image, 0x6a, page);
    for (unsigned i = 0; i < 256; ++i)
        desc[i] = (struct urov_page){perf_pages + i * page, image, 0, 0};
    /* First execution can demand-fault code/data pages and clear the native
     * reservation. Warm the entire 32 KiB instruction window before checking. */
    native_long = 1;
    for (unsigned i = 0; i < 32 && native_long; ++i)
        native_long = perf_llsc_long(&lock, perf_pages);
    native_clear = perf_llsc_clrex(&lock, perf_pages);
    native_skip = perf_llsc_skip(&lock, perf_pages);
    printf("NATIVE long=%u clear=%u skip=%u\n", native_long, native_clear, native_skip);
    CHECK(native_long == 0 && native_clear == 1 && native_skip == 1);
    for (unsigned s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        unsigned n = sizes[s];
        if (n > info.max_pages || (size_t)n * page > 1048576) continue;
        CHECK(!urov_register_pages(&client, desc, n, &status));
        active = 1;
        CHECK(perf_read(perf_pages) == UINT64_C(0x6a6a6a6a6a6a6a6a));
        double one = scan(1, page, 1), all = scan(n, page, 1);
        CHECK(one > 0 && all > 0);
        printf("SCALE pages=%u fixed_one_page_us=%.3f all_pages_us=%.3f\n", n, one, all);
        CHECK(!urov_deactivate(&client));
        active = 0;
    }
    CHECK(!urov_register_pages(&client, desc, 1, &status));
    active = 1;
    lock = 5;
    CHECK(perf_llsc_long(&lock, perf_pages) == native_long && lock == 6);
    CHECK(perf_llsc_clrex(&lock, perf_pages) == native_clear && lock == 6);
    CHECK(perf_llsc_skip(&lock, perf_pages) == native_skip && lock == 6);
    for (unsigned i = 0; i < 4; ++i) CHECK(perf_mutable(&lock, perf_pages) == 1);
    void *reader_page = (void *)((uintptr_t)perf_patch_word & ~(page - 1));
    CHECK(!mprotect(reader_page, page, PROT_READ | PROT_WRITE | PROT_EXEC));
    *(uint32_t *)(void *)perf_patch_word = 0xc85f7c02U; /* LDXR X2,[X0] */
    __builtin___clear_cache((char *)perf_patch_word, (char *)perf_patch_word + 4);
    CHECK(!mprotect(reader_page, page, PROT_READ | PROT_EXEC));
    CHECK(perf_mutable(&lock, perf_pages) == 0 && lock == 7);
    CHECK(!mprotect(reader_page, page, PROT_READ | PROT_WRITE | PROT_EXEC));
    *(uint32_t *)(void *)perf_patch_word = 0xd503201fU;
    __builtin___clear_cache((char *)perf_patch_word, (char *)perf_patch_word + 4);
    CHECK(!mprotect(reader_page, page, PROT_READ | PROT_EXEC));
    CHECK(perf_mutable(&lock, perf_pages) == 1 && lock == 7);
    /* A native write without mprotect or image SET must also invalidate the
     * negative proof; no native-code epoch is available for this region. */
    int mem = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    uint32_t opcode = 0xc85f7c02U;
    CHECK(mem >= 0);
    CHECK(pwrite(mem, &opcode, 4, (off_t)(uintptr_t)perf_patch_word) == 4);
    __builtin___clear_cache((char *)perf_patch_word, (char *)perf_patch_word + 4);
    CHECK(perf_mutable(&lock, perf_pages) == 0 && lock == 8);
    opcode = 0xd503201fU;
    CHECK(pwrite(mem, &opcode, 4, (off_t)(uintptr_t)perf_patch_word) == 4);
    __builtin___clear_cache((char *)perf_patch_word, (char *)perf_patch_word + 4);
    close(mem);
    CHECK(perf_mutable(&lock, perf_pages) == 1 && lock == 8);
    /* A child's same-VA instruction must use the child's COW native snapshot,
     * while both data views still contain the registered fake bytes. */
    image[257] = 0x7c;
    CHECK(!urov_get_status(&client, &status));
    CHECK(!urov_set_page(&client, 0, status.generation, 0, image, (uint32_t)page, &status));
    CHECK(perf_self(perf_pages + 256) == 0x6a);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        alarm(10);
        if (mprotect(perf_pages, page, PROT_READ | PROT_WRITE | PROT_EXEC)) _exit(2);
        *(volatile uint32_t *)(uintptr_t)perf_self = 0x39400400U; /* LDRB W0,[X0,#1] */
        /* The emulated store already does the backend's I-cache flush. EL0
         * DC CVAU on an AP-trapped page needs the optional native-step path;
         * that separate limitation is not part of this snapshot regression. */
        __asm__ volatile("isb" ::: "memory");
        _exit(perf_self(perf_pages + 256) == 0x7c ? 0 : 3);
    }
    int child_status;
    CHECK(waitpid(child, &child_status, 0) == child && WIFEXITED(child_status) &&
          WEXITSTATUS(child_status) == 0);
    CHECK(perf_self(perf_pages + 256) == 0x6a);
    /* LSE is optional on older ARM64 SoCs. Keep the remaining regression
     * useful there instead of terminating it with an illegal instruction. */
    if (getauxval(AT_HWCAP) & HWCAP_ATOMICS) {
        CHECK(!mprotect(perf_pages, page, PROT_READ | PROT_WRITE | PROT_EXEC));
        CHECK(perf_ldadd(perf_pages, 1) == UINT64_C(0x6a6a6a6a6a6a6a6a));
        CHECK(perf_read(perf_pages) == UINT64_C(0x6a6a6a6a6a6a6a6b));
        CHECK(!mprotect(perf_pages, page, PROT_READ | PROT_EXEC));
        puts("PASS LSE");
    } else {
        puts("SKIP LSE: CPU does not advertise HWCAP_ATOMICS");
    }
    /* The address operand may point anywhere inside a DC ZVA block. Check
     * the runtime geometry and its neighbours, not a hard-coded cache line. */
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    unsigned zva_bytes = 4U << (dczid & 15U);
    if (!(dczid & ~UINT64_C(15)) && zva_bytes >= 8U && zva_bytes <= 64U) {
        unsigned char *block = perf_pages + 1024;
        CHECK(!mprotect(perf_pages, page, PROT_READ | PROT_WRITE | PROT_EXEC));
        __asm__ volatile("dc zva, %0; dsb ish" :: "r"(block + zva_bytes / 2U + 1U) : "memory");
        for (unsigned i = 0; i < zva_bytes; i += 8U) CHECK(perf_read(block + i) == 0);
        CHECK(perf_read(block - 8) == UINT64_C(0x6a6a6a6a6a6a6a6a));
        CHECK(perf_read(block + zva_bytes) == UINT64_C(0x6a6a6a6a6a6a6a6a));
        CHECK(!mprotect(perf_pages, page, PROT_READ | PROT_EXEC));
        printf("PASS DC ZVA runtime_block=%u unaligned_operand and untouched neighbours\n", zva_bytes);
    } else {
        printf("SKIP DC ZVA emulation: dczid=%" PRIx64 " block=%u outside this test's 8..64-byte range\n",
               dczid, zva_bytes);
    }
    CHECK(!urov_get_status(&client, &status) && status.failures == 0);
    CHECK(!urov_deactivate(&client));
    active = 0;
    munmap(image, page);
    puts("PASS scale/LLSC-8192/CLREX/indirect-skip/native-code-change/proc-write/child-code-view");
    return 0;
fail:
    if (active) (void)urov_deactivate(&client);
    if (image) munmap(image, page);
    return 1;
}
