/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native A64 versus software-core differential. No faults/hooks are installed.
 * Shadow mapping supplies the independent native expected data, not a claim
 * that the kernel has intercepted any user load. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../emulate.h"
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Requires little-endian AArch64"
#endif

struct native_input { uint64_t base, index, r2, r3, nzcv; };
struct native_output { uint64_t base, index, r2, r3, nzcv, next_pc; };
typedef void (*native_fn)(const struct native_input *, struct native_output *);
#define NATIVE(name, instruction) \
    __asm__(".text\n.p2align 2\n.global " #name "\n.type " #name ", %function\n" \
        #name ":\nbti c\nmov x5,x1\nmov x6,x0\nldp x0,x1,[x6]\n" \
        "ldp x2,x3,[x6,#16]\nldr x7,[x6,#32]\nmsr nzcv,x7\n" \
        ".global " #name "_pc\n" #name "_pc:\n" instruction "\n" \
        #name "_after:\nmrs x7,nzcv\nstp x0,x1,[x5]\nstp x2,x3,[x5,#16]\n" \
        "str x7,[x5,#32]\nadr x7," #name "_after\nstr x7,[x5,#40]\nret\n" \
        ".size " #name ",.-" #name "\n"); \
    extern void name(const struct native_input *, struct native_output *); \
    extern const uint32_t name##_pc
NATIVE(n_u8, "ldrb w2,[x0]");
NATIVE(n_u16, "ldrh w2,[x0]");
NATIVE(n_u32, "ldr w2,[x0]");
NATIVE(n_u64, "ldr x2,[x0]");
NATIVE(n_s8x, "ldrsb x2,[x0]");
NATIVE(n_s8w, "ldrsb w2,[x0]");
NATIVE(n_s16x, "ldrsh x2,[x0]");
NATIVE(n_s16w, "ldrsh w2,[x0]");
NATIVE(n_s32, "ldrsw x2,[x0]");
NATIVE(n_scaled, "ldr x2,[x0,#8]");
NATIVE(n_unscaled, "ldur x2,[x0,#-8]");
NATIVE(n_pre, "ldr x2,[x0,#8]!");
NATIVE(n_post, "ldr x2,[x0],#8");
NATIVE(n_reg, "ldr x2,[x0,x1]");
NATIVE(n_lsl, "ldr x2,[x0,x1,lsl #3]");
NATIVE(n_uxtw, "ldr x2,[x0,w1,uxtw #3]");
NATIVE(n_sxtw, "ldr x2,[x0,w1,sxtw #3]");
NATIVE(n_sxtx, "ldr x2,[x0,x1,sxtx #3]");
NATIVE(n_pairx, "ldp x2,x3,[x0]");
NATIVE(n_pairw, "ldp w2,w3,[x0]");
NATIVE(n_pairs, "ldpsw x2,x3,[x0]");
NATIVE(n_pairpre, "ldp x2,x3,[x0,#16]!");
NATIVE(n_pairpost, "ldp x2,x3,[x0],#16");
NATIVE(n_npx, "ldnp x2,x3,[x0]");
NATIVE(n_npw, "ldnp w2,w3,[x0]");
NATIVE(n_xzr, "ldr xzr,[x0]");

struct native_case { const char *name; native_fn fn; const uint32_t *pc; int displacement; uint64_t index; };
#define CASE(name, disp, idx) { #name, name, &name##_pc, disp, idx }
static const struct native_case cases[] = {
    CASE(n_u8,0,0),CASE(n_u16,0,0),CASE(n_u32,0,0),CASE(n_u64,0,0),
    CASE(n_s8x,0,0),CASE(n_s8w,0,0),CASE(n_s16x,0,0),CASE(n_s16w,0,0),CASE(n_s32,0,0),
    CASE(n_scaled,8,0),CASE(n_unscaled,-8,0),CASE(n_pre,8,0),CASE(n_post,0,0),
    CASE(n_reg,3,3),CASE(n_lsl,8,1),CASE(n_uxtw,8,0xffffffff00000001ULL),
    CASE(n_sxtw,-8,0xffffffff),CASE(n_sxtx,-8,~UINT64_C(0)),
    CASE(n_pairx,0,0),CASE(n_pairw,0,0),CASE(n_pairs,0,0),CASE(n_pairpre,16,0),
    CASE(n_pairpost,0,0),CASE(n_npx,0,0),CASE(n_npw,0,0),CASE(n_xzr,0,0)
};
static uint64_t random_state = UINT64_C(0x40d9c278fde03118);
static uint64_t random64(void)
{
    random_state ^= random_state << 13; random_state ^= random_state >> 7;
    random_state ^= random_state << 17; return random_state;
}
static void *sealed_page(const uint8_t *contents, int data_only)
{
    int fd = memfd_create("urov-native-differential", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    int saved_errno;
    const char *stage = "memfd_create";
    void *p = MAP_FAILED;
    if (fd < 0) { perror(stage); return MAP_FAILED; }
    stage = "ftruncate";
    if (ftruncate(fd, URO_PAGE_SIZE)) goto out;
    stage = "mmap_rw";
    p = mmap(NULL, URO_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) goto out;
    /* Test setup deliberately uses byte stores, not libc's vector copy path;
     * the target emulator's first profile supports GPR loads only. */
    {
        unsigned at;
        for (at = 0; at < URO_PAGE_SIZE; ++at) ((volatile uint8_t *)p)[at] = contents[at];
    }
    {
        unsigned at;
        for (at = 0; at < URO_PAGE_SIZE; ++at) {
            if (((const volatile uint8_t *)p)[at] != contents[at]) {
                fprintf(stderr, "FAIL rw_copy byte=%u actual=%u expected=%u\n", at,
                        ((const volatile uint8_t *)p)[at], contents[at]);
                munmap(p, URO_PAGE_SIZE); p = MAP_FAILED; errno = EIO; goto out;
            }
        }
    }
    __builtin___clear_cache(p, (char *)p + URO_PAGE_SIZE);
    stage = "munmap_rw";
    if (munmap(p, URO_PAGE_SIZE)) { p = MAP_FAILED; goto out; }
    p = MAP_FAILED;
    stage = "add_seals";
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)) goto out;
    {
        /* Drop writable-file permission as well as the writable mapping. */
        char path[64];
        int readonly;
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        stage = "reopen_readonly";
        readonly = open(path, O_RDONLY | O_CLOEXEC);
        if (readonly < 0) goto out;
        close(fd); fd = readonly;
    }
    stage = data_only ? "mmap_r" : "mmap_rx";
    p = mmap(NULL, URO_PAGE_SIZE, PROT_READ | (data_only ? 0 : PROT_EXEC), MAP_SHARED, fd, 0);
out:
    saved_errno = errno;
    if (p == MAP_FAILED) {
        struct stat st;
        int seals = fcntl(fd, F_GET_SEALS);
        if (!fstat(fd, &st))
            fprintf(stderr, "sealed_page stage=%s errno=%d mode=%o seals=0x%x\n", stage, saved_errno,
                    (unsigned)(st.st_mode & 0777), seals);
        else fprintf(stderr, "sealed_page stage=%s errno=%d\n", stage, saved_errno);
    }
    close(fd); errno = saved_errno; return p;
}
int main(int argc, char **argv)
{
    uint8_t source[URO_PAGE_SIZE], shadow[URO_PAGE_SIZE];
    const uint32_t code[] = {0xd503245f,0x52800540,0xd65f03c0,0xd503201f};
    const uint64_t fake = UINT64_C(0x8877665544332211);
    uint8_t fake_bytes[8];
    cpu_set_t allowed, one;
    void *original = MAP_FAILED, *replacement = MAP_FAILED;
    unsigned i, c, iteration, rounds = 100, cpus = 0;
    unsigned long comparisons = 0;
    int cpu, rc = 1, affinity_saved = 0, data_only = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "--data-only")) { data_only = 1; --argc; ++argv; }
    if (argc == 2) {
        char *end; unsigned long n;
        errno = 0; n = strtoul(argv[1], &end, 10);
        if (errno || !argv[1][0] || *end || n < 1 || n > 10000) goto usage;
        rounds = (unsigned)n;
    } else if (argc != 1) goto usage;
    if (sysconf(_SC_PAGESIZE) != URO_PAGE_SIZE) { fprintf(stderr, "Unsupported page size\n"); goto done; }
    for (i = 0; i < URO_PAGE_SIZE; ++i) source[i] = (uint8_t)random64();
    for (i = 0; i < sizeof(code); ++i) source[64 + i] = ((const uint8_t *)code)[i];
    for (i = 0; i < 8; ++i) fake_bytes[i] = (uint8_t)(fake >> (i * 8U));
    for (i = 0; i < URO_PAGE_SIZE; ++i) ((volatile uint8_t *)shadow)[i] = source[i];
    for (i = 0; i < 8; ++i) shadow[64 + i] = (uint8_t)(fake >> (i * 8));
    original = sealed_page(source, data_only); replacement = sealed_page(shadow, data_only);
    if (original == MAP_FAILED || replacement == MAP_FAILED) { perror("sealed RX memfd"); goto done; }
    for (i = 0; i < URO_PAGE_SIZE; ++i) {
        if (((const volatile uint8_t *)original)[i] != source[i]) {
            fprintf(stderr, "FAIL initial original byte=%u actual=%u expected=%u\n", i,
                    ((const volatile uint8_t *)original)[i], source[i]); goto done;
        }
    }
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) { perror("getaffinity"); goto done; }
    affinity_saved = 1;
    for (cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed)) continue;
        CPU_ZERO(&one); CPU_SET(cpu, &one);
        if (sched_setaffinity(0, sizeof(one), &one)) { perror("setaffinity"); goto done; }
        for (c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
            for (iteration = 0; iteration < rounds; ++iteration) {
                unsigned mode;
                /* Both overlap directions, exact hits and non-overlay reads. */
                unsigned pos = 52 + iteration % 36;
                for (mode = 0; mode < 2; ++mode) {
                    struct native_input input;
                    struct native_output out;
                    struct uro_regs r = { { 0 }, 0x40000, (uintptr_t)cases[c].pc, 0 };
                    struct uro_view v = { source, fake_bytes, (uintptr_t)original, UINT64_C(1) << 48, mode ? 64U : 4000U, 8U };
                    unsigned base_offset = (unsigned)((int)pos - cases[c].displacement);
                    uintptr_t native_page = (uintptr_t)(mode ? replacement : original);
                    input.base = native_page + base_offset;
                    input.index = cases[c].index; input.r2 = random64(); input.r3 = random64();
                    input.nzcv = random64() & UINT64_C(0xf0000000);
                    r.x[0] = v.base + base_offset; r.x[1] = input.index;
                    r.x[2] = input.r2; r.x[3] = input.r3; r.pstate = input.nzcv;
                    cases[c].fn(&input, &out);
                    if (uro_emulate(&v, *cases[c].pc, URO_READ_ESR, v.base + pos, &r) != URO_OK ||
                        r.x[0] - v.base != out.base - native_page || r.x[1] != out.index ||
                        r.x[2] != out.r2 || r.x[3] != out.r3 || r.pstate != out.nzcv || r.pc != out.next_pc) {
                        fprintf(stderr, "FAIL cpu=%d case=%s iteration=%u mode=%u\n", cpu, cases[c].name, iteration, mode);
                        goto done;
                    }
                    ++comparisons;
                }
            }
        }
        {
            int executed = data_only ? 42 : ((int (*)(void))((char *)original + 64))();
            int changed = 0;
            for (i = 0; i < URO_PAGE_SIZE; ++i)
                if (((const volatile uint8_t *)original)[i] != source[i]) { changed = 1; break; }
            if (executed != 42 || changed) {
                unsigned diff = 0;
                while (diff < URO_PAGE_SIZE && ((const uint8_t *)original)[diff] == source[diff]) ++diff;
                fprintf(stderr, "FAIL original bytes/execution result=%d first_diff=%u actual=%u expected=%u\n", executed, diff,
                        diff < URO_PAGE_SIZE ? ((const volatile uint8_t *)original)[diff] : 0,
                        diff < URO_PAGE_SIZE ? source[diff] : 0);
                goto done;
            }
        }
        printf("cpu=%d native_differential=PASS original_execute=%s\n", cpu,
               data_only ? "SKIPPED_data_only" : "42"); ++cpus;
    }
    printf("PASS cpus=%u native_cases=%zu comparisons=%lu scope=native_vs_software_model overlay=NOT_ENABLED\n",
           cpus, sizeof(cases) / sizeof(cases[0]), comparisons);
    rc = 0;
done:
    if (affinity_saved && sched_setaffinity(0, sizeof(allowed), &allowed)) rc = 1;
    if (original != MAP_FAILED) munmap(original, URO_PAGE_SIZE);
    if (replacement != MAP_FAILED) munmap(replacement, URO_PAGE_SIZE);
    return rc;
usage:
    fprintf(stderr, "Usage: urov_native_test [--data-only] [rounds 1..10000]\n");
    goto done;
}
