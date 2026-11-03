/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Standalone overlay acceptance test, wide-window edition.
 *
 * The urov-lab KPM must already be loaded (kpatch kpm load). This process:
 *   1. builds a sealed one-page memfd, mapped PROT_READ|PROT_EXEC;
 *   2. registers it through the hooked __NR_kcmp control syscall with an
 *      8-, 16- and 32-byte fake window in turn;
 *   3. checks ordinary scalar A64 loads and 16-byte LDP reads around both
 *      window edges while execution still returns the original result;
 *   4. exercises update, mapping gates, fork, fail-closed, concurrent readers
 *      and restoration for every width.
 *
 * No host-side kernel change is involved: only the KPM's own hooks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../urov_abi.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "urov_overlay_test models little-endian fake bytes"
#endif

struct fake_set {
    uint64_t w[4];
};

/* Deliberately unlike the deterministic source page in every window byte. */
static const struct fake_set fake_a = { {
    UINT64_C(0x8877665544332211), UINT64_C(0xa1b2c3d4e5f60718),
    UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210)
} };
static const struct fake_set fake_b = { {
    UINT64_C(0x1020304050607080), UINT64_C(0x1827364554637281),
    UINT64_C(0xf0e1d2c3b4a59687), UINT64_C(0x89abcdef01234567)
} };

static uint8_t source[UROV_PAGE_BYTES];
static uint8_t *code = MAP_FAILED;
static unsigned win_offset = 4;
static unsigned win_len = 8;

/* A real function copied into the sealed page. It executes from the protected
 * page and performs one ordinary LDR from the caller-supplied pointer. */
__asm__(".pushsection .text.urov_reader,\"ax\",%progbits\n"
        ".p2align 4\n.global urov_reader\n.type urov_reader,%function\n"
        "urov_reader:\n hint #34\n ldr x0, [x0]\n ret\n nop\n"
        ".size urov_reader, .-urov_reader\n.popsection\n");
extern const char urov_reader[];

static void fail(const char *what, long rc)
{
    fprintf(stderr, "FAIL %s rc=%ld errno=%d\n", what, rc, errno);
    _exit(1);
}

static long notify(unsigned int cmd, struct urov_request *q)
{
    errno = 0;
    return syscall(UROV_NOTIFY_NR, (long)UROV_NOTIFY_MAGIC, (long)cmd, q, (long)sizeof(*q));
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

static void set_fake(struct urov_request *q, const struct fake_set *set)
{
    unsigned words = (win_len + 7U) / 8U;
    q->value = set->w[0];
    q->value_hi[0] = words > 1U ? set->w[1] : 0;
    q->value_hi[1] = words > 2U ? set->w[2] : 0;
    q->value_hi[2] = words > 3U ? set->w[3] : 0;
}

static uint64_t load_one(const void *p, unsigned size)
{
    uint64_t value;
    switch (size) {
    case 1: __asm__ volatile("ldrb %w0, [%1]" : "=r"(value) : "r"(p) : "memory"); break;
    case 2: __asm__ volatile("ldrh %w0, [%1]" : "=r"(value) : "r"(p) : "memory"); break;
    case 4: __asm__ volatile("ldr %w0, [%1]" : "=r"(value) : "r"(p) : "memory"); break;
    default: __asm__ volatile("ldr %0, [%1]" : "=r"(value) : "r"(p) : "memory"); break;
    }
    return value;
}

static void load_pair(const void *p, uint64_t *a, uint64_t *b)
{
    __asm__ volatile("ldp %0, %1, [%2]" : "=&r"(*a), "=&r"(*b) : "r"(p) : "memory");
}

static void load_pair_w(const void *p, uint32_t *a, uint32_t *b)
{
    __asm__ volatile("ldp %w0, %w1, [%2]" : "=&r"(*a), "=&r"(*b) : "r"(p) : "memory");
}

static uint8_t fake_byte(const struct fake_set *set, unsigned rel)
{
    return ((const uint8_t *)set->w)[rel];
}

static uint64_t expected(unsigned offset, unsigned size,
                         const struct fake_set *set, int active)
{
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < size; ++i) {
        unsigned pos = offset + i;
        uint8_t byte = (active && pos >= win_offset && pos - win_offset < win_len)
                           ? fake_byte(set, pos - win_offset)
                           : source[pos];
        result |= (uint64_t)byte << (i * 8);
    }
    return result;
}

static int check_value(const struct fake_set *set, int active)
{
    unsigned size, offset, end = win_offset + win_len + 8U;
    uint64_t a, b;

    if (end > 64U) end = 64U;
    for (size = 1; size <= 8; size *= 2) {
        for (offset = 0; offset < end; ++offset) {
            uint64_t want;
            if (offset + size > UROV_PAGE_BYTES) break;
            want = expected(offset, size, set, active);
            if (load_one(code + offset, size) != want) {
                fprintf(stderr, "mismatch width=%u offset=%u size=%u active=%d\n",
                        win_len, offset, size, active);
                return -1;
            }
        }
    }
    /* 16-byte LDP pair straddling and fully inside the fake window. */
    for (offset = 0; offset + 16U <= end; offset += 8U) {
        load_pair(code + offset, &a, &b);
        if (a != expected(offset, 8, set, active) ||
            b != expected(offset + 8, 8, set, active)) {
            fprintf(stderr, "pair mismatch width=%u offset=%u active=%d\n",
                    win_len, offset, active);
            return -1;
        }
    }
    /* 32-bit LDP pair for the narrower element form. */
    for (offset = 0; offset + 8U <= end; offset += 4U) {
        uint32_t wa, wb;
        load_pair_w(code + offset, &wa, &wb);
        if (wa != (uint32_t)expected(offset, 4, set, active) ||
            wb != (uint32_t)expected(offset + 4, 4, set, active)) {
            fprintf(stderr, "pair_w mismatch width=%u offset=%u active=%d\n",
                    win_len, offset, active);
            return -1;
        }
    }
    /* Instruction fetch from the protected page is unaffected. */
    if (((int (*)(void))code)() != 42) {
        fprintf(stderr, "execution mismatch width=%u\n", win_len);
        return -1;
    }
    /* A reader whose own instructions live in the protected page. */
    if (((uint64_t (*)(const void *))(code + 64))(code + win_offset) !=
        expected(win_offset, 8, set, active)) {
        fprintf(stderr, "reader mismatch width=%u\n", win_len);
        return -1;
    }
    return 0;
}

static sigjmp_buf fault_jmp;
static volatile sig_atomic_t expect_fail_closed, fail_closed_seen;

static void segv(int sig, siginfo_t *si, void *ctx)
{
    (void)sig;
    (void)ctx;
    if (expect_fail_closed) {
        fail_closed_seen = 1;
        siglongjmp(fault_jmp, 1);
    }
    fprintf(stderr, "FAIL unexpected SIGSEGV addr=%p code=%d\n", si->si_addr, si->si_code);
    _exit(66);
}

static int check_fail_closed(void)
{
    expect_fail_closed = 1;
    fail_closed_seen = 0;
    if (!sigsetjmp(fault_jmp, 1)) {
        __asm__ volatile("ldr q0, [%0]" ::"r"(code + win_offset) : "v0", "memory");
        expect_fail_closed = 0;
        return -1;
    }
    expect_fail_closed = 0;
    return fail_closed_seen ? 0 : -1;
}

static int check_mapping_gates(void)
{
    void *other;
    errno = 0;
    if (syscall(__NR_mprotect, code, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC) != -1 ||
        errno != EBUSY) {
        fprintf(stderr, "gate_mprotect errno=%d\n", errno);
        return -1;
    }
    errno = 0;
    if (syscall(__NR_madvise, code, UROV_PAGE_BYTES, MADV_DONTNEED) != -1 ||
        errno != EBUSY) {
        fprintf(stderr, "gate_madvise errno=%d\n", errno);
        return -1;
    }
    errno = 0;
    if (syscall(__NR_munmap, code, UROV_PAGE_BYTES) != -1 || errno != EBUSY) {
        fprintf(stderr, "gate_munmap errno=%d\n", errno);
        return -1;
    }
    errno = 0;
    if (syscall(__NR_mremap, code, UROV_PAGE_BYTES, UROV_PAGE_BYTES, 0) != -1 ||
        errno != EBUSY) {
        fprintf(stderr, "gate_mremap errno=%d\n", errno);
        return -1;
    }
    errno = 0;
    if (mmap(code, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != MAP_FAILED ||
        errno != EBUSY) {
        fprintf(stderr, "gate_mmap_fixed errno=%d\n", errno);
        return -1;
    }
    other = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (other == MAP_FAILED) return -1;
    if (mprotect(other, UROV_PAGE_BYTES, PROT_READ)) return -1;
    if (munmap(other, UROV_PAGE_BYTES)) return -1;
    return 0;
}

static void child_segv(int sig)
{
    (void)sig;
    _exit(77);
}

static int check_fork_blocked(void)
{
    pid_t child;
    int status;
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        struct sigaction ca;
        memset(&ca, 0, sizeof(ca));
        ca.sa_handler = child_segv;
        sigemptyset(&ca.sa_mask);
        sigaction(SIGSEGV, &ca, NULL);
        alarm(3);
        (void)*(volatile uint64_t *)(code + win_offset);
        _exit(0); /* mapping was inherited unexpectedly */
    }
    if (waitpid(child, &status, 0) != child) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? -1 : 0;
}

static atomic_int readers_go, readers_stop, readers_ready;
static atomic_uint reader_loops;
static atomic_int reader_errors;
static uint64_t pair_a[2], pair_b[2], word_a, word_b;

static void *reader_main(void *opaque)
{
    unsigned cpu = (unsigned)(uintptr_t)opaque;
    cpu_set_t one;
    uint64_t value, a, b;
    CPU_ZERO(&one);
    CPU_SET((int)cpu, &one);
    (void)sched_setaffinity(0, sizeof(one), &one);
    atomic_fetch_add_explicit(&readers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&readers_go, memory_order_acquire)) sched_yield();
    while (!atomic_load_explicit(&readers_stop, memory_order_acquire)) {
        value = load_one(code + win_offset, 8);
        if (value != word_a && value != word_b) {
            atomic_fetch_add_explicit(&reader_errors, 1, memory_order_relaxed);
            break;
        }
        load_pair(code, &a, &b);
        if (!((a == pair_a[0] && b == pair_a[1]) ||
              (a == pair_b[0] && b == pair_b[1]))) {
            atomic_fetch_add_explicit(&reader_errors, 1, memory_order_relaxed);
            break;
        }
        if (((int (*)(void))code)() != 42) {
            atomic_fetch_add_explicit(&reader_errors, 1, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(&reader_loops, 1, memory_order_relaxed);
    }
    return NULL;
}

static int make_page(void)
{
    static const uint32_t insns[] = { 0xd503245f, 0x52800540, 0xd65f03c0, 0xd503201f };
    uint8_t *rw;
    int fd = -1, ro = -1, ret = -1;
    char path[64];
    unsigned i;

    for (i = 0; i < sizeof(source); ++i) source[i] = (uint8_t)(i * 37U + 19U);
    for (i = 0; i < sizeof(insns); ++i)
        source[i] = (uint8_t)(insns[i >> 2] >> ((i & 3) * 8));
    for (i = 0; i < 16; ++i) source[64 + i] = (uint8_t)urov_reader[i];

    fd = memfd_create("urov-overlay-wide", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { perror("memfd_create"); goto out; }
    if (ftruncate(fd, UROV_PAGE_BYTES)) { perror("ftruncate"); goto out; }
    rw = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) { perror("mmap rw"); goto out; }
    for (i = 0; i < UROV_PAGE_BYTES; ++i) ((volatile uint8_t *)rw)[i] = source[i];
    for (i = 0; i < UROV_PAGE_BYTES; ++i)
        if (((volatile uint8_t *)rw)[i] != source[i]) {
            fprintf(stderr, "fill mismatch\n");
            goto out;
        }
    __builtin___clear_cache((char *)rw, (char *)rw + UROV_PAGE_BYTES);
    if (munmap(rw, UROV_PAGE_BYTES)) { perror("munmap rw"); goto out; }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
        perror("F_ADD_SEALS");
        goto out;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ro = open(path, O_RDONLY | O_CLOEXEC);
    if (ro < 0) { perror("open /proc/self/fd"); goto out; }
    code = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC, MAP_SHARED, ro, 0);
    if (code == MAP_FAILED) { perror("mmap rx"); goto out; }
    if (((int (*)(void))code)() != 42) {
        fprintf(stderr, "baseline execution != 42\n");
        goto out;
    }
    ret = 0;
out:
    if (ro >= 0) close(ro);
    if (fd >= 0) close(fd);
    return ret;
}

int main(int argc, char **argv)
{
    static const unsigned widths[] = { 8, 16, 24, 32 };
    struct urov_request q;
    struct sigaction sa;
    long rc;
    uint64_t generation;
    unsigned iterations = 32;
    unsigned wi, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--cleanup")) {
        long crc;
        q = request(UROV_NOTIFY_QUERY);
        crc = notify(UROV_NOTIFY_QUERY, &q);
        if (crc) { fprintf(stderr, "module_not_loaded rc=%ld errno=%d\n", crc, errno); return 2; }
        if (q.state != UROV_ACTIVE) { puts("no_active_session"); return 0; }
        q = request(UROV_NOTIFY_DEACTIVATE);
        q.session = 1;
        crc = notify(UROV_NOTIFY_DEACTIVATE, &q);
        if (crc) { fprintf(stderr, "cleanup_failed rc=%ld errno=%d\n", crc, errno); return 1; }
        puts("cleanup=deactivated");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--iterations"))
        iterations = (unsigned)strtoul(argv[2], NULL, 10);
    if (!iterations || iterations > 10000) {
        fprintf(stderr, "usage: %s [--iterations N] [--cleanup]\n", argv[0]);
        return 2;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL)) { perror("sigaction"); return 2; }

    q = request(UROV_NOTIFY_QUERY);
    rc = notify(UROV_NOTIFY_QUERY, &q);
    if (rc) {
        fprintf(stderr, "module_not_loaded rc=%ld errno=%d\n", rc, errno);
        return 2;
    }
    printf("backend_caps=0x%llx state=%u\n", (unsigned long long)q.caps, q.state);
    if ((q.caps & (UROV_CAP_READY | UROV_CAP_RAW_XOM |
                   UROV_CAP_FAKE16 | UROV_CAP_FAKE32)) !=
        (UROV_CAP_READY | UROV_CAP_RAW_XOM | UROV_CAP_FAKE16 | UROV_CAP_FAKE32)) {
        fprintf(stderr, "backend not ready or lacks wide-fake caps\n");
        return 2;
    }
    if (q.state != UROV_INACTIVE) {
        fprintf(stderr, "stale session present\n");
        return 2;
    }

    if (make_page()) return 2;
    printf("page=%p baseline_ok\n", code);

    /* A 32-byte window that would run past the page must be rejected before
     * any valid session exists. */
    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)code;
    q.offset = UROV_PAGE_BYTES - 16U;
    q.length = 32;
    set_fake(&q, &fake_a);
    errno = 0;
    if (notify(UROV_NOTIFY_REGISTER, &q) != -1 || errno != EINVAL)
        fail("register_overrun", errno);
    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)code;
    q.offset = 4;
    q.length = 12;
    set_fake(&q, &fake_a);
    errno = 0;
    if (notify(UROV_NOTIFY_REGISTER, &q) != -1 || errno != EINVAL)
        fail("register_bad_length", errno);

    for (wi = 0; wi < sizeof(widths) / sizeof(widths[0]); ++wi) {
        int widest = wi + 1U == sizeof(widths) / sizeof(widths[0]);
        win_len = widths[wi];

        q = request(UROV_NOTIFY_REGISTER);
        q.address = (uintptr_t)code;
        q.offset = win_offset;
        q.length = win_len;
        q.flags = UROV_F_RAW_XOM;
        set_fake(&q, &fake_a);
        rc = notify(UROV_NOTIFY_REGISTER, &q);
        if (rc) fail("register", rc);
        if (q.session != 1 || q.generation != 1 || q.state != UROV_ACTIVE ||
            q.length != win_len || q.offset != win_offset)
            fail("register_reply", rc);
        generation = q.generation;
        if (check_value(&fake_a, 1)) fail("value_a", 0);
        printf("registered width=%u session=%llu generation=%llu\n", win_len,
               (unsigned long long)q.session, (unsigned long long)q.generation);

        if (widest) {
            /* Protocol negatives. */
            q = request(UROV_NOTIFY_REGISTER);
            q.address = (uintptr_t)code;
            q.offset = win_offset;
            q.length = win_len;
            set_fake(&q, &fake_a);
            errno = 0;
            if (notify(UROV_NOTIFY_REGISTER, &q) != -1 || errno != EBUSY)
                fail("double_register", errno);
            q = request(UROV_NOTIFY_SET);
            q.session = 99;
            q.expected_generation = generation;
            q.length = win_len;
            set_fake(&q, &fake_b);
            errno = 0;
            if (notify(UROV_NOTIFY_SET, &q) != -1 || errno != ENOENT)
                fail("bad_session", errno);
            q = request(UROV_NOTIFY_SET);
            q.session = 1;
            q.expected_generation = generation;
            q.length = 8;
            set_fake(&q, &fake_b);
            errno = 0;
            if (notify(UROV_NOTIFY_SET, &q) != -1 || errno != EINVAL)
                fail("wrong_set_length", errno);
            q = request(UROV_NOTIFY_QUERY);
            q.version = UROV_ABI_VERSION + 1;
            errno = 0;
            if (notify(UROV_NOTIFY_QUERY, &q) != -1 || errno != EINVAL)
                fail("bad_version", errno);

            if (check_mapping_gates()) fail("mapping_gates", 0);
            printf("mapping_gates=verified\n");
            if (check_fork_blocked()) fail("fork_inherit", 0);
            printf("fork_inherit=blocked\n");
            if (check_fail_closed()) fail("fail_closed_missing", 0);
            if (check_value(&fake_a, 1)) fail("value_after_fail_closed", 0);
            printf("unsupported_access=fail_closed\n");
        }

        /* Explicit wide update, then a stale-generation rejection. */
        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = generation;
        q.length = win_len;
        set_fake(&q, &fake_b);
        rc = notify(UROV_NOTIFY_SET, &q);
        if (rc) fail("set_b", rc);
        if (q.generation != generation + 1 || q.length != win_len)
            fail("set_b_reply", (long)q.generation);
        generation = q.generation;
        if (check_value(&fake_b, 1)) fail("value_b", 0);

        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = generation - 1;
        q.length = win_len;
        set_fake(&q, &fake_a);
        errno = 0;
        if (notify(UROV_NOTIFY_SET, &q) != -1 || errno != EAGAIN)
            fail("stale_set", errno);
        if (check_value(&fake_b, 1)) fail("value_stale_unchanged", 0);

        /* Concurrent readers while the fake bytes are republished. */
        pair_a[0] = expected(0, 8, &fake_a, 1);
        pair_a[1] = expected(8, 8, &fake_a, 1);
        pair_b[0] = expected(0, 8, &fake_b, 1);
        pair_b[1] = expected(8, 8, &fake_b, 1);
        word_a = expected(win_offset, 8, &fake_a, 1);
        word_b = expected(win_offset, 8, &fake_b, 1);
        {
            pthread_t tids[8];
            cpu_set_t allowed;
            unsigned cpus = 0, threads = 0;
            if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
                for (i = 0; i < 8 && i < CPU_SETSIZE; ++i)
                    if (CPU_ISSET((int)i, &allowed)) ++cpus;
                threads = cpus < 8 ? cpus : 8;
            }
            atomic_store(&readers_go, 0);
            atomic_store(&readers_stop, 0);
            atomic_store(&readers_ready, 0);
            atomic_store(&reader_errors, 0);
            atomic_store(&reader_loops, 0);
            for (i = 0; i < threads; ++i) {
                if (pthread_create(&tids[i], NULL, reader_main, (void *)(uintptr_t)i)) {
                    threads = i;
                    break;
                }
            }
            while ((unsigned)atomic_load_explicit(&readers_ready, memory_order_acquire) != threads)
                sched_yield();
            atomic_store_explicit(&readers_go, 1, memory_order_release);
            for (i = 0; i < iterations; ++i) {
                const struct fake_set *value = (i & 1U) ? &fake_a : &fake_b;
                q = request(UROV_NOTIFY_SET);
                q.session = 1;
                q.expected_generation = generation;
                q.length = win_len;
                set_fake(&q, value);
                rc = notify(UROV_NOTIFY_SET, &q);
                if (rc) fail("concurrent_set", rc);
                if (q.generation != generation + 1)
                    fail("concurrent_set_generation", (long)q.generation);
                generation = q.generation;
                if (check_value(value, 1)) fail("concurrent_value", 0);
            }
            atomic_store_explicit(&readers_stop, 1, memory_order_release);
            for (i = 0; i < threads; ++i) pthread_join(tids[i], NULL);
            if (atomic_load_explicit(&reader_errors, memory_order_relaxed))
                fail("reader_errors", 0);
            if (!atomic_load_explicit(&reader_loops, memory_order_relaxed))
                fail("reader_loops", 0);
            printf("concurrent_readers=%u updates=%u loops=%u\n", threads, iterations,
                   atomic_load_explicit(&reader_loops, memory_order_relaxed));
        }

        q = request(UROV_NOTIFY_STATUS);
        q.session = 1;
        rc = notify(UROV_NOTIFY_STATUS, &q);
        if (rc) fail("status", rc);
        printf("status width=%u generation=%llu hits=%llu failures=%llu\n",
               q.length, (unsigned long long)q.generation,
               (unsigned long long)q.hits, (unsigned long long)q.failures);
        if (!q.hits || q.length != win_len) fail("status_fields", (long)q.length);
        if (q.failures != (widest ? 1U : 0U)) fail("counters", (long)q.failures);
        /* The last update was fake_a for odd iteration counts. */
        if (q.generation < 2U) fail("status_generation", (long)q.generation);

        q = request(UROV_NOTIFY_DEACTIVATE);
        q.session = 1;
        rc = notify(UROV_NOTIFY_DEACTIVATE, &q);
        if (rc) fail("deactivate", rc);
        if (q.state != UROV_INACTIVE) fail("deactivate_state", (long)q.state);
        if (check_value(&fake_a, 0)) fail("restored_value", 0);
        if (syscall(__NR_mprotect, code, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC) != 0)
            fail("gate_released", errno);
        printf("width=%u restored=verified\n", win_len);
    }

    if (munmap(code, UROV_PAGE_BYTES)) fail("munmap", errno);
    puts("PASS scope=standalone_active_overlay widths=8,16,24,32 ordinary_loads=1,2,4,8,ldp "
         "execution=42 update=verified gates=verified fork=blocked fail_closed=verified "
         "concurrency=verified restore=verified");
    return 0;
}
