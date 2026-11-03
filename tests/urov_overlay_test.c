/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Standalone overlay acceptance test.
 *
 * The urov-lab KPM must already be loaded (kpatch kpm load). This process:
 *   1. builds a sealed one-page memfd, mapped PROT_READ|PROT_EXEC;
 *   2. registers it through the hooked __NR_kcmp control syscall;
 *   3. checks that ordinary scalar A64 loads return the overlaid bytes while
 *      executing the page still returns the original function result;
 *   4. updates the value, exercises the mapping gates, deactivates and checks
 *      that the original bytes and execution are restored.
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

static const uint64_t fake_a = UINT64_C(0x8877665544332211);
static const uint64_t fake_b = UINT64_C(0x1020304050607080);

static uint8_t source[UROV_PAGE_BYTES];
static uint8_t *code = MAP_FAILED;

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

static uint64_t expected(unsigned offset, unsigned size, uint64_t fake, int active)
{
    uint64_t result = 0;
    unsigned i;
    for (i = 0; i < size; ++i) {
        unsigned pos = offset + i;
        uint8_t byte = (active && pos >= 4 && pos < 12)
                           ? (uint8_t)(fake >> ((pos - 4) * 8))
                           : source[pos];
        result |= (uint64_t)byte << (i * 8);
    }
    return result;
}

static int check_value(uint64_t fake, int active)
{
    unsigned size, offset;
    uint64_t a, b, want;
    for (size = 1; size <= 8; size *= 2)
        for (offset = 0; offset < 24; ++offset) {
            want = expected(offset, size, fake, active);
            if (load_one(code + offset, size) != want) {
                fprintf(stderr, "mismatch offset=%u size=%u active=%d\n", offset, size, active);
                return -1;
            }
        }
    /* Aliasing checks around the 8-byte window. */
    for (offset = 1; offset < 12; ++offset) {
        if (load_one(code + offset, 8) != expected(offset, 8, fake, active)) return -1;
    }
    if (load_one(code + 4096 - 8, 8) != expected(4096 - 8, 8, fake, active)) return -1;
    load_pair(code, &a, &b);
    if (a != expected(0, 8, fake, active) || b != expected(8, 8, fake, active)) return -1;
    /* Instruction fetch from the protected page is unaffected. */
    if (((int (*)(void))code)() != 42) return -1;
    /* A reader whose own instructions live in the protected page. */
    if (((uint64_t (*)(const void *))(code + 64))(code + 4) != expected(4, 8, fake, active))
        return -1;
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

/* A real function copied into the sealed page. It executes from the protected
 * page and performs one ordinary LDR from the caller-supplied pointer. */
__asm__(".pushsection .text.urov_reader,\"ax\",%progbits\n"
        ".p2align 4\n.global urov_reader\n.type urov_reader,%function\n"
        "urov_reader:\n hint #34\n ldr x0, [x0]\n ret\n nop\n"
        ".size urov_reader, .-urov_reader\n.popsection\n");
extern const char urov_reader[];

static int make_page(void)
{
    static const uint32_t insns[] = { 0xd503245f, 0x52800540, 0xd65f03c0, 0xd503201f };
    uint8_t *rw;
    int fd = -1, ro = -1, ret = -1;
    char path[64];
    unsigned i;

    for (i = 0; i < sizeof(source); ++i) source[i] = (uint8_t)(i * 37U + 19U);
    for (i = 0; i < sizeof(insns); ++i) {
        source[i] = (uint8_t)(insns[i >> 2] >> ((i & 3) * 8));
    }
    for (i = 0; i < 16; ++i) source[64 + i] = (uint8_t)urov_reader[i];

    fd = memfd_create("urov-overlay", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { perror("memfd_create"); goto out; }
    if (ftruncate(fd, UROV_PAGE_BYTES)) { perror("ftruncate"); goto out; }
    rw = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) { perror("mmap rw"); goto out; }
    for (i = 0; i < UROV_PAGE_BYTES; ++i) ((volatile uint8_t *)rw)[i] = source[i];
    for (i = 0; i < UROV_PAGE_BYTES; ++i)
        if (((volatile uint8_t *)rw)[i] != source[i]) { fprintf(stderr, "fill mismatch\n"); goto out; }
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
    if (((int (*)(void))code)() != 42) { fprintf(stderr, "baseline execution != 42\n"); goto out; }
    ret = 0;
out:
    if (ro >= 0) close(ro);
    if (fd >= 0) close(fd);
    return ret;
}

static void child_segv(int sig)
{
    (void)sig;
    _exit(77);
}

/* Concurrent readers on several CPUs while the value is updated. */
static atomic_int readers_go, readers_stop, readers_ready;
static atomic_uint reader_loops;
static atomic_int reader_errors;

static void *reader_main(void *opaque)
{
    unsigned cpu = (unsigned)(uintptr_t)opaque;
    cpu_set_t one;
    uint64_t value;
    CPU_ZERO(&one);
    CPU_SET((int)cpu, &one);
    (void)sched_setaffinity(0, sizeof(one), &one);
    atomic_fetch_add_explicit(&readers_ready, 1, memory_order_release);
    while (!atomic_load_explicit(&readers_go, memory_order_acquire)) sched_yield();
    while (!atomic_load_explicit(&readers_stop, memory_order_acquire)) {
        value = load_one(code + 4, 8);
        if (value != fake_a && value != fake_b) {
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

int main(int argc, char **argv)
{
    struct urov_request q;
    struct sigaction sa;
    long rc;
    uint64_t generation;
    unsigned iterations = 32;
    unsigned i, cpus = 0, threads = 0;
    pthread_t tids[8];
    cpu_set_t allowed;

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
    if (argc == 3 && !strcmp(argv[1], "--iterations")) iterations = (unsigned)strtoul(argv[2], NULL, 10);
    if (!iterations || iterations > 10000) {
        fprintf(stderr, "usage: %s [--iterations N]\n", argv[0]);
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
    if ((q.caps & (UROV_CAP_READY | UROV_CAP_RAW_XOM)) != (UROV_CAP_READY | UROV_CAP_RAW_XOM)) {
        fprintf(stderr, "backend not ready\n");
        return 2;
    }
    if (q.state != UROV_INACTIVE) {
        fprintf(stderr, "stale session present\n");
        return 2;
    }

    if (make_page()) return 2;
    printf("page=%p baseline_ok\n", code);

    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)code;
    q.offset = 4;
    q.flags = UROV_F_RAW_XOM;
    q.value = fake_a;
    rc = notify(UROV_NOTIFY_REGISTER, &q);
    if (rc) fail("register", rc);
    if (q.session != 1 || q.generation != 1 || q.state != UROV_ACTIVE) fail("register_reply", rc);
    generation = q.generation;
    if (check_value(fake_a, 1)) fail("value_a", 0);
    printf("registered session=%llu generation=%llu\n",
           (unsigned long long)q.session, (unsigned long long)q.generation);

    /* Protocol negatives: a second session, wrong handles and bad variants. */
    q = request(UROV_NOTIFY_REGISTER);
    q.address = (uintptr_t)code;
    q.offset = 4;
    q.value = fake_a;
    errno = 0;
    if (notify(UROV_NOTIFY_REGISTER, &q) != -1 || errno != EBUSY) fail("double_register", errno);
    q = request(UROV_NOTIFY_SET);
    q.session = 99;
    q.expected_generation = generation;
    q.value = fake_b;
    errno = 0;
    if (notify(UROV_NOTIFY_SET, &q) != -1 || errno != ENOENT) fail("bad_session", errno);
    q = request(UROV_NOTIFY_QUERY);
    q.version = UROV_ABI_VERSION + 1;
    errno = 0;
    if (notify(UROV_NOTIFY_QUERY, &q) != -1 || errno != EINVAL) fail("bad_version", errno);

    /* Mapping gates: none of these may disturb an armed session. */
    errno = 0;
    if (syscall(__NR_mprotect, code, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC) != -1 || errno != EBUSY)
        fail("gate_mprotect", errno);
    errno = 0;
    if (syscall(__NR_madvise, code, UROV_PAGE_BYTES, MADV_DONTNEED) != -1 || errno != EBUSY)
        fail("gate_madvise", errno);
    errno = 0;
    if (syscall(__NR_munmap, code, UROV_PAGE_BYTES) != -1 || errno != EBUSY)
        fail("gate_munmap", errno);
    errno = 0;
    if (syscall(__NR_mremap, code, UROV_PAGE_BYTES, UROV_PAGE_BYTES, 0) != -1 || errno != EBUSY)
        fail("gate_mremap", errno);
    errno = 0;
    if (mmap(code, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != MAP_FAILED || errno != EBUSY)
        fail("gate_mmap_fixed", errno);
    {
        void *other = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (other == MAP_FAILED) fail("unrelated_mmap", errno);
        if (mprotect(other, UROV_PAGE_BYTES, PROT_READ)) fail("unrelated_mprotect", errno);
        munmap(other, UROV_PAGE_BYTES);
    }
    if (check_value(fake_a, 1)) fail("value_after_gates", 0);
    printf("mapping_gates=verified\n");

    /* fork must not inherit the protected mapping (VM_DONTCOPY). A child that
     * gets the cleared PTE would fault with no session for its own mm. */
    {
        pid_t child;
        int status;
        child = fork();
        if (child < 0) fail("fork", errno);
        if (child == 0) {
            struct sigaction ca;
            memset(&ca, 0, sizeof(ca));
            ca.sa_handler = child_segv;
            sigemptyset(&ca.sa_mask);
            sigaction(SIGSEGV, &ca, NULL);
            alarm(3);
            (void)*(volatile uint64_t *)(code + 4);
            _exit(0); /* mapping was inherited unexpectedly */
        }
        if (waitpid(child, &status, 0) != child) fail("waitpid", errno);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) fail("fork_inherited", 0);
    }
    printf("fork_inherit=blocked\n");

    /* An instruction outside the audited scalar subset must fail closed with
     * SIGSEGV instead of looping in the fault path or leaking original bytes. */
    expect_fail_closed = 1;
    if (!sigsetjmp(fault_jmp, 1)) {
        __asm__ volatile("ldr q0, [%0]" ::"r"(code + 4) : "v0", "memory");
        expect_fail_closed = 0;
        fail("fail_closed_missing", 0);
    }
    expect_fail_closed = 0;
    if (!fail_closed_seen) fail("fail_closed_flag", 0);
    if (check_value(fake_a, 1)) fail("value_after_fail_closed", 0);
    printf("unsupported_access=fail_closed\n");

    /* Concurrent update/read on all allowed CPUs. */
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
        for (i = 0; i < 8 && i < CPU_SETSIZE; ++i)
            if (CPU_ISSET((int)i, &allowed)) ++cpus;
        threads = cpus < 8 ? cpus : 8;
    }
    for (i = 0; i < threads; ++i) {
        if (pthread_create(&tids[i], NULL, reader_main, (void *)(uintptr_t)i)) {
            threads = i;
            break;
        }
    }
    while ((unsigned)atomic_load_explicit(&readers_ready, memory_order_acquire) != threads) sched_yield();
    atomic_store_explicit(&readers_go, 1, memory_order_release);
    for (i = 0; i < iterations; ++i) {
        uint64_t value = (i & 1U) ? fake_a : fake_b;
        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = generation;
        q.value = value;
        rc = notify(UROV_NOTIFY_SET, &q);
        if (rc) fail("set", rc);
        if (q.generation != generation + 1) fail("set_generation", (long)q.generation);
        generation = q.generation;
        if (check_value(value, 1)) fail("value_update", 0);
        /* A stale generation must not publish a value. */
        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = generation - 1;
        q.value = ~value;
        errno = 0;
        rc = notify(UROV_NOTIFY_SET, &q);
        if (rc != -1 || errno != EAGAIN) fail("stale_set", errno);
    }
    atomic_store_explicit(&readers_stop, 1, memory_order_release);
    for (i = 0; i < threads; ++i) pthread_join(tids[i], NULL);
    if (atomic_load_explicit(&reader_errors, memory_order_relaxed)) fail("reader_errors", 0);
    if (!atomic_load_explicit(&reader_loops, memory_order_relaxed)) fail("reader_loops", 0);
    printf("concurrent_readers=%u updates=%u loops=%u\n", threads, iterations,
           atomic_load_explicit(&reader_loops, memory_order_relaxed));

    q = request(UROV_NOTIFY_STATUS);
    q.session = 1;
    rc = notify(UROV_NOTIFY_STATUS, &q);
    if (rc) fail("status", rc);
    printf("status generation=%llu hits=%llu failures=%llu\n",
           (unsigned long long)q.generation, (unsigned long long)q.hits,
           (unsigned long long)q.failures);
    if (!q.hits || q.failures != 1) fail("counters", (long)q.failures);

    q = request(UROV_NOTIFY_DEACTIVATE);
    q.session = 1;
    rc = notify(UROV_NOTIFY_DEACTIVATE, &q);
    if (rc) fail("deactivate", rc);
    if (q.state != UROV_INACTIVE) fail("deactivate_state", (long)q.state);
    if (check_value(0, 0)) fail("restored_value", 0);
    if (syscall(__NR_mprotect, code, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC) != 0)
        fail("gate_released", errno);
    printf("deactivated restored=verified\n");

    if (munmap(code, UROV_PAGE_BYTES)) fail("munmap", errno);
    puts("PASS scope=standalone_active_overlay ordinary_loads=1,2,4,8,ldp execution=42 update=verified "
         "gates=verified concurrency=verified restore=verified");
    return 0;
}
