/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * UROV-LAB ordinary-app acceptance test.
 *
 * Runs as a real untrusted_app (NativeActivity, uid 10xxx, Seccomp mode 2).
 * The urov-lab KPM must already be loaded by root; this process talks to it
 * only through the app-facing __NR_prctl channel and registers a one-page
 * read-only executable mapping that belongs to itself:
 *
 *   A. a one-page MAP_PRIVATE RX alias of its own installed native library,
 *      overlaid on the code bytes of urov_payload(); execution must still run
 *      the original instructions while data loads see the fake bytes, or
 *   B. a one-page payload file in its private data directory when A cannot be
 *      registered (for example because the map was merged with a neighbour).
 *
 * The test covers 1/2/4/8-byte scalar loads, a 16-byte LDP, partial overlap at
 * both window edges, update, mapping gates, concurrent readers, fail-closed
 * for an unsupported SIMD load, deactivation and restoration.
 */
#define _GNU_SOURCE
#include <android/log.h>
#include <android/native_activity.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "urov_abi.h"

#define TAG "urovapp"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#define WIN_MAX UROV_FAKE_MAX

static int g_fail;

#define CHECK(cond, ...) do { \
    if (cond) { \
        LOG(__VA_ARGS__); \
    } else { \
        LOG("FAIL: " __VA_ARGS__); \
        g_fail = 1; \
    } \
} while (0)

/* A leaf, position-independent function with a BTI landing pad.  It must stay
 * inside one page and must not use a literal pool: the test executes it from a
 * one-page alias of the library file. */
__asm__(".pushsection .text.urov_payload,\"ax\",%progbits\n"
        ".p2align 4\n.global urov_payload\n.type urov_payload,%function\n"
        "urov_payload:\n"
        " hint #34\n"
        " mov x1, #0x7788\n"
        " movk x1, #0x5566, lsl #16\n"
        " movk x1, #0x3344, lsl #32\n"
        " movk x1, #0x1122, lsl #48\n"
        " eor x0, x0, x1\n"
        " ret\n"
        ".size urov_payload, .-urov_payload\n.popsection\n");
extern uint64_t urov_payload(uint64_t x);

static const uint64_t fake_a[4] = {
    UINT64_C(0x8877665544332211), UINT64_C(0xa1b2c3d4e5f60718),
    UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)
};
static const uint64_t fake_b[4] = {
    UINT64_C(0x1020304050607080), UINT64_C(0x1827364554637281),
    UINT64_C(0xf0e1d2c3b4a59687), UINT64_C(0x89abcdef01234567)
};

/* ------------------------------------------------------------ control path */

static long notify(unsigned int cmd, struct urov_request *q)
{
    errno = 0;
    return syscall(__NR_prctl, (long)UROV_PRCTL_OPTION, (long)UROV_PRCTL_MAGIC,
                   (long)cmd, q, (long)sizeof(*q));
}

static struct urov_request request(unsigned int op)
{
    struct urov_request q;
    memset(&q, 0, sizeof(q));
    q.size = sizeof(q);
    q.version = UROV_ABI_VERSION;
    q.op = (uint16_t)op;
    return q;
}

static void set_fake(struct urov_request *q, const uint64_t words[4], unsigned len)
{
    q->value = words[0];
    q->value_hi[0] = len > 8 ? words[1] : 0;
    q->value_hi[1] = len > 16 ? words[2] : 0;
    q->value_hi[2] = len > 24 ? words[3] : 0;
}

/* ------------------------------------------------------------- load helpers */

static uint64_t load_n(const void *p, unsigned size)
{
    uint64_t v = 0;
    switch (size) {
    case 1: __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); break;
    case 2: __asm__ volatile("ldrh %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); break;
    case 4: __asm__ volatile("ldr %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); break;
    default: __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory"); break;
    }
    return v;
}

static void load_pair(const void *p, uint64_t *a, uint64_t *b)
{
    __asm__ volatile("ldp %0, %1, [%2]" : "=&r"(*a), "=&r"(*b) : "r"(p) : "memory");
}

static volatile uint64_t g_bench_sink;

static uint64_t bench_loop_ns(const uint8_t *p, unsigned n)
{
    struct timespec t0, t1;
    uint64_t sum = 0, ns;
    unsigned i;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < n; ++i)
        sum += load_n(p, 8);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    g_bench_sink = sum;
    ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL +
         (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    return n ? ns * 1000ULL / n : 0;
}

static void bench_overlay(const char *tag, const uint8_t *page, unsigned win_off)
{
    uint8_t *normal = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t normal_ns, overlay_ns;
    if (normal == MAP_FAILED) return;
    memset(normal, 0x5a, UROV_PAGE_BYTES);
    normal_ns = bench_loop_ns(normal + win_off, 65536);
    overlay_ns = bench_loop_ns(page + win_off, 65536);
    LOG("%s bench ns_per_1k normal=%llu overlay=%llu overhead=%llux", tag,
        (unsigned long long)normal_ns, (unsigned long long)overlay_ns,
        (unsigned long long)(normal_ns ? overlay_ns / normal_ns : 0));
    munmap(normal, UROV_PAGE_BYTES);
}

static uint64_t expected(const uint8_t *orig, unsigned base, unsigned off,
                         unsigned size, const uint64_t words[4], unsigned win_off,
                         unsigned win_len, int active)
{
    uint64_t v = 0;
    unsigned i;
    for (i = 0; i < size; ++i) {
        unsigned pos = off + i;
        uint8_t byte = orig[pos - base];
        if (active && pos >= win_off && pos - win_off < win_len)
            byte = ((const uint8_t *)words)[pos - win_off];
        v |= (uint64_t)byte << (i * 8);
    }
    return v;
}

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_expect_segv, g_segv_seen;

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
    (void)sig;
    (void)ctx;
    if (g_expect_segv) {
        g_segv_seen = 1;
        siglongjmp(g_jmp, 1);
    }
    LOG("unexpected SIGSEGV addr=%p code=%d", si->si_addr, si->si_code);
    _exit(70);
}

/* Fail-closed probe: a SIMD load is outside the audited subset.  The module
 * must deliver SIGSEGV rather than the original bytes. */
static int check_fail_closed(const void *p)
{
    int ok;
    g_expect_segv = 1;
    g_segv_seen = 0;
    if (!sigsetjmp(g_jmp, 1)) {
        __asm__ volatile("ldr q0, [%0]" ::"r"(p) : "v0", "memory");
        g_expect_segv = 0;
        return -1;
    }
    g_expect_segv = 0;
    ok = g_segv_seen;
    g_segv_seen = 0;
    return ok ? 0 : -1;
}

/* --------------------------------------------------------------- page tests */

static int check_values(const char *tag, const uint8_t *page, unsigned base,
                        unsigned win_off, unsigned win_len, const uint64_t words[4],
                        const uint8_t *orig, int active)
{
    unsigned start = win_off > 8U ? win_off - 8U : 0U;
    unsigned end = win_off + win_len + 8U;
    unsigned size, off;
    int rc = 0;

    if (start < base) start = base;
    if (end > base + 64U) end = base + 64U;
    for (size = 1; size <= 8; size *= 2) {
        for (off = start; off < end; ++off) {
            uint64_t want, got;
            if (off + size > base + 64U) break;
            want = expected(orig, base, off, size, words, win_off, win_len, active);
            got = load_n(page + off, size);
            if (got != want) {
                LOG("FAIL %s width=%u off=%u size=%u got=0x%llx want=0x%llx",
                    tag, win_len, off, size, (unsigned long long)got,
                    (unsigned long long)want);
                g_fail = 1;
                rc = -1;
            }
        }
    }
    /* One aligned 16-byte GPR pair around the window.  It may straddle the
     * fake/original boundary, which is exactly the mixed-byte LDP case. */
    {
        unsigned pair_off = win_off & ~7U;
        uint64_t a, b, wa, wb;
        if (pair_off + 16U > UROV_PAGE_BYTES) pair_off = UROV_PAGE_BYTES - 16U;
        load_pair(page + pair_off, &a, &b);
        wa = expected(orig, base, pair_off, 8, words, win_off, win_len, active);
        wb = expected(orig, base, pair_off + 8U, 8, words, win_off, win_len, active);
        if (a != wa || b != wb) {
            LOG("FAIL %s pair off=%u got=0x%llx/0x%llx want=0x%llx/0x%llx",
                tag, pair_off, (unsigned long long)a, (unsigned long long)b,
                (unsigned long long)wa, (unsigned long long)wb);
            g_fail = 1;
            rc = -1;
        }
    }
    return rc;
}

struct reader_ctx {
    atomic_int *go, *stop, *errors, *ready;
    atomic_uint *loops;
    const uint8_t *page;
    unsigned win_off, win_len;
    uint64_t a0, b0, a1, b1;
    uint64_t (*exec_fn)(uint64_t);
    uint64_t exec_arg, exec_want;
};

static void *reader_main(void *opaque)
{
    struct reader_ctx *c = opaque;
    while (!atomic_load_explicit(c->go, memory_order_acquire)) sched_yield();
    atomic_fetch_add_explicit(c->ready, 1, memory_order_release);
    while (!atomic_load_explicit(c->stop, memory_order_acquire)) {
        uint64_t v = load_n(c->page + c->win_off, 8);
        if (v != c->a0 && v != c->a1) {
            atomic_fetch_add_explicit(c->errors, 1, memory_order_relaxed);
            break;
        }
        if (c->exec_fn && c->exec_fn(c->exec_arg) != c->exec_want) {
            atomic_fetch_add_explicit(c->errors, 1, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(c->loops, 1, memory_order_relaxed);
    }
    return NULL;
}

static int check_concurrency(const uint8_t *page, unsigned win_off, unsigned win_len,
                             uint64_t (*exec_fn)(uint64_t), uint64_t exec_arg,
                             uint64_t exec_want, uint64_t generation)
{
    pthread_t tids[4];
    atomic_int go, stop, errors, ready;
    atomic_uint loops;
    struct reader_ctx c;
    struct urov_request q;
    unsigned threads = 4, i;
    long rc;

    atomic_init(&go, 0);
    atomic_init(&stop, 0);
    atomic_init(&errors, 0);
    atomic_init(&ready, 0);
    atomic_init(&loops, 0);
    c.go = &go; c.stop = &stop; c.errors = &errors; c.ready = &ready; c.loops = &loops;
    c.page = page; c.win_off = win_off; c.win_len = win_len;
    c.a0 = fake_a[0]; c.a1 = fake_b[0];
    c.exec_fn = exec_fn; c.exec_arg = exec_arg; c.exec_want = exec_want;
    for (i = 0; i < threads; ++i) {
        if (pthread_create(&tids[i], NULL, reader_main, &c)) {
            threads = i;
            break;
        }
    }
    atomic_store_explicit(&go, 1, memory_order_release);
    while (atomic_load_explicit(&ready, memory_order_acquire) < (int)threads)
        sched_yield();
    for (i = 0; i < 128; ++i) {
        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = generation;
        q.length = win_len;
        set_fake(&q, (i & 1U) ? fake_b : fake_a, win_len);
        rc = notify(UROV_NOTIFY_SET, &q);
        if (rc) {
            LOG("FAIL concurrent SET rc=%ld errno=%d", rc, errno);
            g_fail = 1;
            break;
        }
        generation = q.generation;
    }
    atomic_store_explicit(&stop, 1, memory_order_release);
    for (i = 0; i < threads; ++i) pthread_join(tids[i], NULL);
    LOG("concurrent readers=%u loops=%u errors=%d generation=%llu", threads,
        atomic_load_explicit(&loops, memory_order_relaxed),
        atomic_load_explicit(&errors, memory_order_relaxed),
        (unsigned long long)generation);
    if (atomic_load_explicit(&errors, memory_order_relaxed)) {
        g_fail = 1;
        return -1;
    }
    return 0;
}

/* Run the full protocol against one registered page. */
static int page_test(const char *name, uint8_t *page, unsigned win_off, unsigned win_len,
                     uint64_t (*exec_fn)(uint64_t), uint64_t exec_arg, uint64_t exec_want)
{
    struct urov_request q;
    uint8_t orig[64];
    unsigned base;
    uint64_t generation;
    long rc;

    if (win_off + win_len > UROV_PAGE_BYTES || win_len < 8U || win_len > WIN_MAX) {
        LOG("FAIL %s bad window off=%u len=%u", name, win_off, win_len);
        g_fail = 1;
        return -1;
    }
    base = win_off >= 16U ? win_off - 16U : 0U;
    if (base + 64U > UROV_PAGE_BYTES) base = UROV_PAGE_BYTES - 64U;
    memcpy(orig, page + base, sizeof(orig));

    CHECK(exec_fn(exec_arg) == exec_want, "%s baseline execution", name);

    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)page;
    q.offset = win_off;
    q.length = win_len;
    q.flags = UROV_F_RAW_XOM;
    set_fake(&q, fake_a, win_len);
    rc = notify(UROV_NOTIFY_REGISTER, &q);
    if (rc) {
        LOG("FAIL %s REGISTER rc=%ld errno=%d", name, rc, errno);
        g_fail = 1;
        return -1;
    }
    generation = q.generation;
    LOG("%s registered offset=%u length=%u generation=%llu", name, win_off, win_len,
        (unsigned long long)generation);

    if (check_values(name, page, base, win_off, win_len, fake_a, orig, 1)) return -1;
    CHECK(exec_fn(exec_arg) == exec_want, "%s execution after register (fetch original)", name);

    q = request(UROV_NOTIFY_SET);
    q.session = 1;
    q.expected_generation = generation;
    q.length = win_len;
    set_fake(&q, fake_b, win_len);
    rc = notify(UROV_NOTIFY_SET, &q);
    if (rc) {
        LOG("FAIL %s SET rc=%ld errno=%d", name, rc, errno);
        g_fail = 1;
        return -1;
    }
    generation = q.generation;
    if (check_values(name, page, base, win_off, win_len, fake_b, orig, 1)) return -1;
    CHECK(exec_fn(exec_arg) == exec_want, "%s execution after SET", name);
    bench_overlay(name, page, win_off);

    q = request(UROV_NOTIFY_SET);
    q.session = 1;
    q.expected_generation = generation - 1;
    q.length = win_len;
    set_fake(&q, fake_a, win_len);
    errno = 0;
    rc = notify(UROV_NOTIFY_SET, &q);
    CHECK(rc == -1 && errno == EAGAIN, "%s stale SET rejected", name);
    if (check_values(name, page, base, win_off, win_len, fake_b, orig, 1)) return -1;

    q = request(UROV_NOTIFY_STATUS);
    q.session = 1;
    rc = notify(UROV_NOTIFY_STATUS, &q);
    CHECK(rc == 0 && q.hits > 0 && q.failures == 0,
          "%s STATUS rc=%ld hits=%llu failures=%llu", name, rc,
          (unsigned long long)q.hits, (unsigned long long)q.failures);

    errno = 0;
    rc = mprotect(page, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC);
    CHECK(rc == -1 && errno == EBUSY, "%s mprotect gate errno=%d", name, errno);

    if (check_fail_closed(page + win_off) == 0)
        LOG("%s unsupported SIMD access fails closed", name);
    else {
        LOG("FAIL %s unsupported SIMD access did not fail closed", name);
        g_fail = 1;
    }

    check_concurrency(page, win_off, win_len, exec_fn, exec_arg, exec_want, generation);

    q = request(UROV_NOTIFY_DEACTIVATE);
    q.session = 1;
    rc = notify(UROV_NOTIFY_DEACTIVATE, &q);
    CHECK(rc == 0 && q.state == UROV_INACTIVE, "%s DEACTIVATE rc=%ld state=%u", name, rc, q.state);
    if (check_values(name, page, base, win_off, win_len, fake_a, orig, 0)) return -1;
    CHECK(exec_fn(exec_arg) == exec_want, "%s execution after restore", name);
    errno = 0;
    rc = mprotect(page, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC);
    CHECK(rc == 0, "%s mprotect after restore errno=%d", name, errno);
    return 0;
}

/* -------------------------------------------------------- app page sources */

struct lib_page {
    uint8_t *alias;
    unsigned in_page;
    unsigned file_off;
};

/* Map exactly one RX page of this process's own installed library at the page
 * containing fn.  Returns 0 and fills out on success. */
static int map_lib_page(const void *fn, struct lib_page *out)
{
    Dl_info info;
    const Elf64_Ehdr *eh;
    const Elf64_Phdr *ph;
    unsigned long vaddr, file_off = 0;
    int i, fd;
    void *alias;

    memset(&info, 0, sizeof(info));
    if (!dladdr(fn, &info) || !info.dli_fbase || !info.dli_fname) return -1;
    eh = (const Elf64_Ehdr *)info.dli_fbase;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    vaddr = (unsigned long)fn - (unsigned long)info.dli_fbase;
    ph = (const Elf64_Phdr *)((const char *)eh + eh->e_phoff);
    for (i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_memsz) {
            file_off = ph[i].p_offset + (vaddr - ph[i].p_vaddr);
            break;
        }
    }
    if (!file_off) return -1;
    if ((file_off & 0xfffUL) + 32UL > UROV_PAGE_BYTES) return -1;
    fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    /* MAP_SHARED, not MAP_PRIVATE: the library's normal text mapping is
     * MAP_PRIVATE, and a private alias can be merged into it by the kernel
     * (vma_merge) into a multi-page VMA that the module must reject.  The
     * shared alias has different VM_SHARED flags, so it stays a one-page VMA. */
    alias = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC, MAP_SHARED, fd,
                 (off_t)(file_off & ~0xfffUL));
    close(fd);
    if (alias == MAP_FAILED) return -1;
    out->alias = alias;
    out->in_page = (unsigned)file_off & 0xfffU;
    out->file_off = (unsigned)file_off;
    return 0;
}

static void log_vma(const char *tag, const void *addr)
{
    FILE *f = fopen("/proc/self/maps", "re");
    char line[1024];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8], path[512] = "";
        int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511c", &start, &end, perms, path);
        if (n < 3) continue;
        if ((unsigned long)addr >= start && (unsigned long)addr < end) {
            char *p = n >= 4 ? path : (char *)"";
            while (*p == ' ') ++p;
            {
                char *nl = strchr(p, '\n');
                if (nl) *nl = 0;
            }
            LOG("%s vma=%lx-%lx perms=%s size=%lu path=%s", tag, start, end, perms,
                end - start, p);
            break;
        }
    }
    fclose(f);
}

static int run_lib_alias_test(void)
{
    struct lib_page lp;
    uint64_t want = 0x123456789abcdef0ULL ^ 0x1122334455667788ULL;
    int rc;

    if (map_lib_page((const void *)&urov_payload, &lp)) {
        LOG("lib_alias: unavailable");
        return -1;
    }
    LOG("lib_alias: page=%p in_page=0x%x file_off=0x%x", lp.alias, lp.in_page, lp.file_off);
    log_vma("lib_alias", lp.alias);
    /* dli_fname may be an APK for extractNativeLibs=false installs; the ELF
     * p_offset is then relative to a zip entry rather than to the file.  Do
     * not execute a page whose bytes do not match the loaded function. */
    if (memcmp(lp.alias + lp.in_page, (const void *)&urov_payload, 32) != 0) {
        LOG("lib_alias: page content mismatch, skipping");
        munmap(lp.alias, UROV_PAGE_BYTES);
        return -1;
    }
    rc = page_test("lib_alias", lp.alias, lp.in_page + 4U, 16U,
                   (uint64_t (*)(uint64_t))(lp.alias + lp.in_page),
                   0x123456789abcdef0ULL, want);
    munmap(lp.alias, UROV_PAGE_BYTES);
    return rc;
}

static void *map_datafile_page(const char *dir, int map_flags, const char *tag)
{
    char path[512];
    uint8_t page[UROV_PAGE_BYTES];
    static const uint32_t code[] = {
        0xd503245f, /* bti c */
        0x52800540, /* mov w0, #42 */
        0xd65f03c0, /* ret */
        0xd503201f, /* nop */
    };
    int fd;
    void *rx;
    unsigned i;

    if (!dir) return MAP_FAILED;
    for (i = 0; i < sizeof(page); ++i) page[i] = (uint8_t)(i * 37U + 19U);
    memcpy(page, code, sizeof(code));
    snprintf(path, sizeof(path), "%s/urov_overlay.bin", dir);
    unlink(path);
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) {
        LOG("%s: create errno=%d", tag, errno);
        return MAP_FAILED;
    }
    if (write(fd, page, sizeof(page)) != (ssize_t)sizeof(page)) {
        LOG("%s: write errno=%d", tag, errno);
        close(fd);
        unlink(path);
        return MAP_FAILED;
    }
    close(fd);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG("%s: reopen errno=%d", tag, errno);
        unlink(path);
        return MAP_FAILED;
    }
    rx = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC, map_flags, fd, 0);
    close(fd);
    unlink(path);
    if (rx == MAP_FAILED) {
        LOG("%s: mmap errno=%d", tag, errno);
        return MAP_FAILED;
    }
    LOG("%s: page=%p flags=0x%x", tag, rx, map_flags);
    log_vma(tag, rx);
    return rx;
}

static int run_datafile_test(const char *dir)
{
    void *rx = map_datafile_page(dir, MAP_SHARED, "data_shared");
    int rc;
    if (rx == MAP_FAILED) return -1;
    rc = page_test("data_shared", rx, 8U, 16U, (uint64_t (*)(uint64_t))rx, 0, 42);
    munmap(rx, UROV_PAGE_BYTES);
    return rc;
}

/* A private file mapping carries VM_MAYWRITE on this kernel (it can be made
 * writable by mprotect or a FOLL_FORCE remote write, which would COW the page
 * out from under the pin).  The module must refuse it instead of pretending
 * the pinned page is stable.  This is the negative half of the page-shape
 * contract, not a required functionality path. */
static int run_private_reject_test(const char *dir)
{
    void *rx = map_datafile_page(dir, MAP_PRIVATE, "data_private_reject");
    struct urov_request q;
    long rc;

    if (rx == MAP_FAILED) return -1;
    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)rx;
    q.offset = 8U;
    q.length = 16U;
    q.flags = UROV_F_RAW_XOM;
    set_fake(&q, fake_a, 16U);
    errno = 0;
    rc = notify(UROV_NOTIFY_REGISTER, &q);
    if (rc == -1 && errno == EINVAL) {
        LOG("data_private_reject: rejected errno=%d as designed", errno);
        rc = 0;
    } else {
        LOG("FAIL data_private_reject: accepted rc=%ld errno=%d", rc, errno);
        g_fail = 1;
        rc = -1;
    }
    munmap(rx, UROV_PAGE_BYTES);
    return rc;
}

#ifdef UROV_HOLD
/* Lifecycle probe: register once and keep the session observable while root
 * runs foreign-control / unload / kill experiments. */
static int run_hold_test(void)
{
    struct lib_page lp;
    struct urov_request q;
    uint64_t (*fn)(uint64_t);
    long rc;
    int i;

    if (map_lib_page((const void *)&urov_payload, &lp)) return -1;
    fn = (uint64_t (*)(uint64_t))(lp.alias + lp.in_page);
    log_vma("hold", lp.alias);
    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)lp.alias;
    q.offset = lp.in_page + 4U;
    q.length = 16U;
    q.flags = UROV_F_RAW_XOM;
    set_fake(&q, fake_a, 16U);
    rc = notify(UROV_NOTIFY_REGISTER, &q);
    if (rc) {
        LOG("HOLD register failed rc=%ld errno=%d", rc, errno);
        return -1;
    }
    LOG("HOLD active pid=%d page=%p offset=%u generation=%llu",
        (int)getpid(), lp.alias, lp.in_page + 4U, (unsigned long long)q.generation);
    for (i = 0; i < 120; ++i) {
        uint64_t value = load_n(lp.alias + lp.in_page + 4U, 8);
        LOG("HOLD t=%d read=0x%llx exec=0x%llx", i, (unsigned long long)value,
            (unsigned long long)fn(0));
        sleep(1);
    }
    q = request(UROV_NOTIFY_DEACTIVATE);
    q.session = 1;
    rc = notify(UROV_NOTIFY_DEACTIVATE, &q);
    LOG("HOLD deactivate rc=%ld errno=%d state=%u", rc, errno, q.state);
    munmap(lp.alias, UROV_PAGE_BYTES);
    return 0;
}
#endif

/* ------------------------------------------------------------------- main */

static int query_backend(void)
{
    struct urov_request q = request(UROV_NOTIFY_QUERY);
    long rc = notify(UROV_NOTIFY_QUERY, &q);
    LOG("QUERY rc=%ld errno=%d caps=0x%llx state=%u", rc, errno,
        (unsigned long long)q.caps, q.state);
    if (rc) return -1;
    if ((q.caps & (UROV_CAP_READY | UROV_CAP_RAW_XOM | UROV_CAP_FAKE16 |
                   UROV_CAP_FAKE32 | UROV_CAP_PRCTL)) !=
        (UROV_CAP_READY | UROV_CAP_RAW_XOM | UROV_CAP_FAKE16 |
         UROV_CAP_FAKE32 | UROV_CAP_PRCTL)) {
        LOG("backend lacks app/fake caps");
        return -1;
    }
    return 0;
}

/* The control channel reuses __NR_prctl; every ordinary prctl call must still
 * reach the native implementation unchanged. */
static int check_prctl_passthrough(void)
{
    char got[17] = { 0 };
    int rc;
    rc = prctl(PR_SET_NAME, "urovapp", 0, 0, 0);
    if (rc) {
        LOG("FAIL prctl(PR_SET_NAME) rc=%d errno=%d", rc, errno);
        g_fail = 1;
        return -1;
    }
    rc = prctl(PR_GET_NAME, got, 0, 0, 0);
    if (rc || strcmp(got, "urovapp")) {
        LOG("FAIL prctl(PR_GET_NAME) rc=%d errno=%d name=%s", rc, errno, got);
        g_fail = 1;
        return -1;
    }
    LOG("prctl passthrough name=%s", got);
    return 0;
}

static void log_context(void)
{
    char ctx[128] = { 0 };
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, ctx, sizeof(ctx) - 1);
        if (n > 0) LOG("context=%s", ctx);
        close(fd);
    }
}

void ANativeActivity_onCreate(ANativeActivity *activity, void *saved_state, size_t saved_size)
{
    struct sigaction sa;
    int lib_rc = -1;
#ifndef UROV_HOLD
    int file_rc = -1;
#endif
    (void)saved_state;
    (void)saved_size;

    LOG("=== app test begin pid=%d uid=%d ===", (int)getpid(), (int)getuid());
    log_context();
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);

#ifdef UROV_HOLD
    if (query_backend() == 0)
        lib_rc = run_hold_test();
    LOG("=== HOLD result=%s ===", lib_rc == 0 ? "PASS" : "FAIL");
#else
    if (check_prctl_passthrough() == 0 && query_backend() == 0) {
        lib_rc = run_lib_alias_test();
        file_rc = run_datafile_test(activity->internalDataPath);
        if (run_private_reject_test(activity->internalDataPath) != 0)
            file_rc = -1;
    }
    LOG("=== result lib_alias=%s datafile=%s overall=%s ===",
        lib_rc == 0 ? "PASS" : (lib_rc < 0 ? "SKIP/FAIL" : "FAIL"),
        file_rc == 0 ? "PASS" : "FAIL",
        (!g_fail && (lib_rc == 0 || file_rc == 0)) ? "PASS" : "FAIL");
    LOG("RESULT %s", (!g_fail && (lib_rc == 0 || file_rc == 0)) ? "PASS" : "FAIL");
#endif
    ANativeActivity_finish(activity);
}
