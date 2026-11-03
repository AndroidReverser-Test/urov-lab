/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define _KP_KTYPES_H_
#include "uapi/scdefs.h"
#undef _KP_KTYPES_H_
#include "version"
#include "../urov_abi.h"

/* A real function linked into this executable's ELF text. Its PC-independent
 * instructions are copied into the sealed executable test page. The caller
 * reads that page with ordinary A64 loads and executes exactly these bytes. */
__asm__(".pushsection .text.urov_subject,\"ax\",%progbits\n"
        ".p2align 12\n.global urov_subject\n.type urov_subject,%function\n"
        "urov_subject:\n hint #34\n mov w0, #42\n ret\n nop\n"
        ".size urov_subject, .-urov_subject\n.popsection\n");
extern int urov_subject(void);
__asm__(".pushsection .text.urov_reader,\"ax\",%progbits\n"
        ".p2align 4\n.global urov_reader\n.type urov_reader,%function\n"
        "urov_reader:\n hint #34\n.global urov_reader_ldr_site\n"
        "urov_reader_ldr_site:\n ldr x0, [x0]\n ret\n nop\n"
        ".size urov_reader, .-urov_reader\n.popsection\n");
extern uint64_t urov_reader(const void *);
extern const char urov_reader_ldr_site[];

static const uint64_t fake_a = UINT64_C(0x8877665544332211);
static const uint64_t fake_b = UINT64_C(0x1020304050607080);
static uint8_t source[UROV_PAGE_BYTES];
static char key[64];
static uint8_t *code = MAP_FAILED;
static atomic_int start_readers, stop_readers, ready_readers;
struct reader { pthread_t thread; unsigned cpu, errors; atomic_uint loops; int created; };

static long command(unsigned cmd)
{
    return ((long)((MAJOR << 16) | (MINOR << 8) | PATCH) << 32) |
           (0x1158L << 16) | cmd;
}
static long norm(long result) { return result == -1 ? -(long)errno : result; }
static long control(struct urov_request *q)
{
    errno = 0;
    return norm(syscall(__NR_supercall, key, command(SUPERCALL_KPM_CONTROL),
                        UROV_MODULE_NAME, "request", q, sizeof(*q)));
}
static struct urov_request request(unsigned op)
{
    struct urov_request q = { .size = sizeof(q), .version = UROV_ABI_VERSION, .op = (uint16_t)op };
    return q;
}
static int read_key(int fd)
{
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t got = read(fd, &c, 1);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -1;
        if (!got || c == '\n') break;
        if (!c || n + 1 >= sizeof(key)) return -1;
        key[n++] = c;
    }
    if (n && key[n - 1] == '\r') --n;
    key[n] = 0;
    return n ? 0 : -1;
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
        uint8_t byte = active && pos >= 4 && pos < 12 ? (uint8_t)(fake >> ((pos - 4) * 8)) : source[pos];
        result |= (uint64_t)byte << (i * 8);
    }
    return result;
}
static int verify(uint64_t value, int active)
{
    unsigned size, offset;
    uint64_t a, b;
    for (size = 1; size <= 8; size *= 2)
        for (offset = 0; offset < 24; ++offset)
            if (load_one(code + offset, size) != expected(offset, size, value, active)) return -1;
    load_pair(code, &a, &b);
    if (a != expected(0, 8, value, active) || b != expected(8, 8, value, active)) return -1;
    /* Both the faulting LDR and its data are now in the protected page. */
    if (((uint64_t (*)(const void *))(code + 64))(code + 4) != expected(4, 8, value, active)) return -1;
    return ((int (*)(void))code)() == 42 ? 0 : -1;
}
static void *reader_main(void *opaque)
{
    struct reader *r = opaque;
    cpu_set_t affinity;
    CPU_ZERO(&affinity); CPU_SET((int)r->cpu, &affinity);
    if (sched_setaffinity(0, sizeof(affinity), &affinity)) ++r->errors;
    atomic_fetch_add_explicit(&ready_readers, 1, memory_order_release);
    while (!atomic_load_explicit(&start_readers, memory_order_acquire)) sched_yield();
    while (!atomic_load_explicit(&stop_readers, memory_order_acquire)) {
        uint64_t a, b;
        load_pair(code, &a, &b);
        if (!((a == expected(0, 8, fake_a, 1) && b == expected(8, 8, fake_a, 1)) ||
              (a == expected(0, 8, fake_b, 1) && b == expected(8, 8, fake_b, 1)))) ++r->errors;
        if (((int (*)(void))code)() != 42) ++r->errors;
        atomic_fetch_add_explicit(&r->loops, 1, memory_order_relaxed);
    }
    return NULL;
}
static int make_code_page(void)
{
    static const uint32_t instructions[] = { 0xd503245f, 0x52800540, 0xd65f03c0, 0xd503201f };
    const volatile uint8_t *text = (const volatile uint8_t *)(uintptr_t)&urov_subject;
    uint8_t *rw = MAP_FAILED;
    int fd = -1, readonly = -1, ret = -1;
    unsigned i;
    char path[64];
    if (sysconf(_SC_PAGESIZE) != UROV_PAGE_BYTES || urov_subject() != 42) return -1;
    for (i = 0; i < sizeof(instructions); ++i) {
        source[i] = text[i];
        if (source[i] != ((const uint8_t *)instructions)[i]) return -1;
    }
    for (; i < sizeof(source); ++i) source[i] = (uint8_t)(i * 37U + 19U);
    for (i = 0; i < 16; ++i) source[64 + i] = ((const volatile uint8_t *)(uintptr_t)&urov_reader)[i];
    printf("self_elf_text=verified original_function=42 bytes=%zu\n", sizeof(instructions));
    fd = memfd_create("urov-self-code", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, UROV_PAGE_BYTES)) goto out;
    rw = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) goto out;
    for (i = 0; i < sizeof(source); ++i) ((volatile uint8_t *)rw)[i] = source[i];
    for (i = 0; i < sizeof(source); ++i) if (((volatile uint8_t *)rw)[i] != source[i]) goto out;
    __builtin___clear_cache((char *)rw, (char *)rw + UROV_PAGE_BYTES);
    if (munmap(rw, UROV_PAGE_BYTES)) goto out;
    rw = MAP_FAILED;
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) goto out;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    readonly = open(path, O_RDONLY | O_CLOEXEC);
    if (readonly < 0) goto out;
    code = mmap(NULL, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC, MAP_SHARED, readonly, 0);
    if (code == MAP_FAILED || verify(0, 0)) goto out;
    ret = 0;
out:
    if (ret) perror("sealed_self_code");
    if (rw != MAP_FAILED) munmap(rw, UROV_PAGE_BYTES);
    if (readonly >= 0) close(readonly);
    if (fd >= 0) close(fd);
    return ret;
}
/* Child exit codes distinguish observed read permissions from harness errors. */
enum { PROBE_READABLE = 40, PROBE_READ_FAULT, PROBE_ERROR };
static volatile sig_atomic_t probe_read_stage;
static _Atomic(void *) probe_address;
_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2, "signal handler requires lock-free pointer loads");

static void probe_segv(int signo, siginfo_t *info, void *context)
{
    ucontext_t *uc = context;
    if (probe_read_stage && signo == SIGSEGV && info && info->si_code == SEGV_ACCERR &&
        info->si_addr == atomic_load_explicit(&probe_address, memory_order_relaxed) &&
        uc && uc->uc_mcontext.pc == (uintptr_t)urov_reader_ldr_site)
        _exit(PROBE_READ_FAULT);
    _exit(PROBE_ERROR);
}

static int probe_public_xom_child(unsigned cpu)
{
    cpu_set_t one;
    sigset_t signals;
    struct sigaction action = { .sa_sigaction = probe_segv, .sa_flags = SA_SIGINFO };
    uint64_t observed, original = expected(4, 8, 0, 0);
    CPU_ZERO(&one);
    CPU_SET((int)cpu, &one);
    if (sched_setaffinity(0, sizeof(one), &one) || sched_getcpu() != (int)cpu)
        return PROBE_ERROR;
    sigemptyset(&action.sa_mask);
    sigemptyset(&signals);
    sigaddset(&signals, SIGSEGV);
    if (sigaction(SIGSEGV, &action, NULL) || sigprocmask(SIG_UNBLOCK, &signals, NULL))
        return PROBE_ERROR;
    if (urov_reader(code + 4) != original) return PROBE_ERROR;
    if (mprotect(code, UROV_PAGE_BYTES, PROT_EXEC)) { perror("mprotect(PROT_EXEC)"); return PROBE_ERROR; }
    /* Require successful execution under PROT_EXEC before arming the handler. */
    if (((int (*)(void))code)() != 42) return PROBE_ERROR;
    atomic_store_explicit(&probe_address, code + 4, memory_order_relaxed);
    probe_read_stage = 1;
    observed = urov_reader(code + 4);
    probe_read_stage = 0;
    return observed == original ? PROBE_READABLE : PROBE_ERROR;
}

static int probe_public_xom(void)
{
    cpu_set_t allowed;
    unsigned i, cpus = 0, readable = 0, read_fault = 0;
    int rc = 1;
    if (make_code_page()) goto out;
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) { perror("sched_getaffinity"); goto out; }
    for (i = 0; i < CPU_SETSIZE; ++i) if (CPU_ISSET((int)i, &allowed)) {
        pid_t child, waited;
        int status;
        ++cpus;
        child = fork();
        if (child < 0) { perror("fork"); goto out; }
        if (!child) _exit(probe_public_xom_child(i));
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0) { perror("waitpid"); goto out; }
        if (WIFEXITED(status) && WEXITSTATUS(status) == PROBE_READABLE) ++readable;
        else if (WIFEXITED(status) && WEXITSTATUS(status) == PROBE_READ_FAULT) ++read_fault;
        else { fprintf(stderr, "public_prot_exec cpu=%u unexpected_wait_status=0x%x\n", i, status); goto out; }
    }
    if (cpus && cpus == readable + read_fault) rc = 0;
out:
    if (code != MAP_FAILED && munmap(code, UROV_PAGE_BYTES)) { perror("munmap"); rc = 1; }
    if (!rc) printf("PASS scope=public_prot_exec cpus=%u readable=%u read_fault=%u\n",
                    cpus, readable, read_fault);
    return rc;
}

static int number(const char *text, unsigned maximum, unsigned *out)
{
    char *end;
    unsigned long n;
    errno = 0; n = strtoul(text, &end, 10);
    if (errno || !*text || *end || n > maximum) return -1;
    *out = (unsigned)n; return 0;
}
int main(int argc, char **argv)
{
    struct urov_request q;
    struct reader readers[CPU_SETSIZE] = { 0 };
    cpu_set_t allowed;
    const char *module = NULL;
    uint64_t session = 0, generation = 0, flags = 0, last_hits = 0;
    unsigned fd = 0, iterations = 100, count = 0, i, round;
    int loaded = 0, active = 0, rc = 1, have_fd = 0, text_only = 0, inspect_only = 0;
    long result;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--probe-xom")) return probe_public_xom();
    for (i = 1; i < (unsigned)argc; ++i) {
        if (!strcmp(argv[i], "--module") && i + 1 < (unsigned)argc) module = argv[++i];
        else if (!strcmp(argv[i], "--key-fd") && i + 1 < (unsigned)argc) {
            if (number(argv[++i], 1024, &fd)) goto usage;
            have_fd = 1;
        } else if (!strcmp(argv[i], "--iterations") && i + 1 < (unsigned)argc) {
            if (number(argv[++i], 10000, &iterations) || !iterations) goto usage;
        } else if (!strcmp(argv[i], "--allow-raw-xom")) flags = UROV_F_RAW_XOM;
        else if (!strcmp(argv[i], "--text-only")) text_only = 1;
        else if (!strcmp(argv[i], "--inspect-only")) inspect_only = 1;
        else goto usage;
    }
    if (text_only) {
        if (module || have_fd || flags || inspect_only) goto usage;
        if (!make_code_page()) { puts("PASS scope=self_text_baseline overlay=NOT_ENABLED"); rc = 0; }
        goto out;
    }
    if (!module || module[0] != '/' || !have_fd || (inspect_only && flags)) goto usage;
    if (read_key((int)fd)) { fprintf(stderr, "Invalid key input\n"); goto out; }
    errno = 0;
    if (norm(syscall(__NR_supercall, key, command(SUPERCALL_HELLO))) != SUPERCALL_HELLO_MAGIC) {
        fprintf(stderr, "KP authorization failed\n"); goto out;
    }
    if (access(module, R_OK)) { perror("module"); goto out; }
    q = request(UROV_QUERY);
    result = control(&q);
    if (result != -ENOENT) { fprintf(stderr, "Module already present or status ambiguous: %ld\n", result); goto out; }
    errno = 0;
    result = norm(syscall(__NR_supercall, key, command(SUPERCALL_KPM_LOAD), module,
                         inspect_only ? "inspect" : "", NULL));
    if (result) {
        fprintf(stderr, "module_load=%ld overlay_test=NOT_RUN\n", result);
        rc = result == -ENOENT || result == -EOPNOTSUPP ? 2 : 1;
        goto out;
    }
    loaded = 1;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL line=%d errno=%d\n", __LINE__, errno); goto out; } } while (0)
#define OK(expr) do { result = (expr); if (result) { fprintf(stderr, "FAIL line=%d result=%ld\n", __LINE__, result); goto out; } } while (0)
    q = request(UROV_QUERY); OK(control(&q));
    printf("backend_caps=0x%" PRIx64 "\n", q.caps);
    if (inspect_only) {
        char response[192] = { 0 };
        CHECK(q.caps == UROV_CAP_MODEL_CORE && q.state == UROV_INACTIVE && !q.session);
        OK(norm(syscall(__NR_supercall, key, command(SUPERCALL_KPM_CONTROL),
                        UROV_MODULE_NAME, "status", response, sizeof(response))));
        CHECK(strstr(response, "mode=standalone-inspect") && strstr(response, "core_checks=4114"));
        fputs(response, stdout);
        q = request(UROV_QUERY); q.version++; CHECK(control(&q) == -EINVAL);
        q = request(UROV_QUERY); q.reserved[2] = 1; CHECK(control(&q) == -EINVAL);
        q = request(UROV_REGISTER); CHECK(control(&q) == -EOPNOTSUPP);
        q = request(UROV_STATUS); CHECK(control(&q) == -ENOENT);
        q = request(UROV_SET); CHECK(control(&q) == -ENOENT);
        q = request(UROV_DEACTIVATE); OK(control(&q)); CHECK(q.state == UROV_INACTIVE);
        rc = 0; goto out;
    }
    if ((q.caps & (UROV_CAP_READY | UROV_CAP_MM_GATES)) != (UROV_CAP_READY | UROV_CAP_MM_GATES)) {
        fprintf(stderr, "backend_capability=inactive overlay_test=NOT_RUN\n"); rc = 2; goto out;
    }
    if (!(q.caps & UROV_CAP_EPAN) && (!(q.caps & UROV_CAP_RAW_XOM) || !flags)) {
        fprintf(stderr, "Platform requires explicit laboratory raw-XOM configuration and option\n"); rc = 2; goto out;
    }
    CHECK(!make_code_page());
    CHECK(!sched_getaffinity(0, sizeof(allowed), &allowed));
    for (i = 0; i < CPU_SETSIZE; ++i) if (CPU_ISSET((int)i, &allowed)) {
        readers[count].cpu = i;
        CHECK(!pthread_create(&readers[count].thread, NULL, reader_main, &readers[count]));
        readers[count++].created = 1;
    }
    CHECK(count > 0);
    while ((unsigned)atomic_load_explicit(&ready_readers, memory_order_acquire) != count) sched_yield();
    q = request(UROV_REGISTER); q.flags = flags; q.request_id = 1;
    q.address = (uintptr_t)code; q.offset = 4; q.value = fake_a;
    /* An EFAULT response may follow commit. Cleanup can recover this request. */
    active = 1;
    OK(control(&q)); session = q.session; generation = q.generation;
    CHECK(q.state == UROV_ACTIVE && session && generation == 1);
    CHECK(!verify(fake_a, 1));
    errno = 0; CHECK(mprotect(code, UROV_PAGE_BYTES, PROT_READ | PROT_EXEC) == -1 && errno == EBUSY);
    errno = 0; CHECK(madvise(code, UROV_PAGE_BYTES, MADV_DONTNEED) == -1 && errno == EBUSY);
    errno = 0; CHECK(munmap(code, UROV_PAGE_BYTES) == -1 && errno == EBUSY);
    errno = 0; CHECK(mremap(code, UROV_PAGE_BYTES, UROV_PAGE_BYTES, MREMAP_MAYMOVE) == MAP_FAILED && errno == EBUSY);
    CHECK(!verify(fake_a, 1));
    atomic_store_explicit(&start_readers, 1, memory_order_release);
    {
        struct timespec now;
        time_t deadline;
        CHECK(!clock_gettime(CLOCK_MONOTONIC, &now)); deadline = now.tv_sec + 5;
        for (;;) {
            unsigned started = 0;
            for (i = 0; i < count; ++i) if (atomic_load_explicit(&readers[i].loops, memory_order_relaxed)) ++started;
            if (started == count) break;
            CHECK(!clock_gettime(CLOCK_MONOTONIC, &now) && now.tv_sec < deadline);
            sched_yield();
        }
    }
    for (round = 0; round < iterations; ++round) {
        uint64_t value = round & 1U ? fake_a : fake_b;
        q = request(UROV_SET); q.session = session; q.request_id = 2U + round;
        q.expected_generation = generation; q.value = value;
        OK(control(&q)); CHECK(q.generation == generation + 1); generation = q.generation;
        CHECK(!verify(value, 1));
        /* A stale generation must not modify the published value. */
        q = request(UROV_SET); q.session = session; q.request_id = UINT64_C(0x100000000) + round;
        q.expected_generation = generation - 1; q.value = ~value;
        CHECK(control(&q) == -EAGAIN);
    }
    atomic_store_explicit(&stop_readers, 1, memory_order_release);
    for (i = 0; i < count; ++i) {
        CHECK(!pthread_join(readers[i].thread, NULL)); readers[i].created = 0;
        CHECK(!readers[i].errors && atomic_load_explicit(&readers[i].loops, memory_order_relaxed));
    }
    q = request(UROV_STATUS); q.session = session; OK(control(&q));
    CHECK(q.hits && !q.failures); last_hits = q.hits;
    q = request(UROV_DEACTIVATE); q.session = session; OK(control(&q)); active = 0;
    CHECK(q.state == UROV_INACTIVE && !verify(0, 0) && urov_subject() == 42);
    rc = 0;
out:
    atomic_store_explicit(&stop_readers, 1, memory_order_release);
    atomic_store_explicit(&start_readers, 1, memory_order_release);
    for (i = 0; i < count; ++i) if (readers[i].created) pthread_join(readers[i].thread, NULL);
    if (loaded && active) {
        if (!session) {
            q = request(UROV_STATUS); q.request_id = 1;
            if (!control(&q)) session = q.session;
        }
        if (session) {
            q = request(UROV_DEACTIVATE); q.session = session;
            result = control(&q);
            if (result) fprintf(stderr, "cleanup_deactivate=%ld\n", result);
            else active = 0;
        }
    }
    if (loaded) {
        errno = 0;
        result = norm(syscall(__NR_supercall, key, command(SUPERCALL_KPM_UNLOAD), UROV_MODULE_NAME, NULL));
        if (result) { fprintf(stderr, "cleanup_unload=%ld instance_retained=1\n", result); rc = 1; }
        else active = 0;
    }
    if (code != MAP_FAILED && !active) munmap(code, UROV_PAGE_BYTES);
    for (i = 0; i < sizeof(key); ++i) ((volatile char *)key)[i] = 0;
    if (!rc && inspect_only)
        puts("PASS scope=standalone_inspection protocol=verified unloaded=1 overlay=NOT_ENABLED");
    if (!rc && !text_only && !inspect_only)
        printf("PASS cpus=%u updates=%u fault_hits=%" PRIu64
               " ordinary_loads=1,2,4,8,16 execution=42 restored=verified unloaded=1 scope=active_overlay\n",
               count, iterations, last_hits);
    return rc;
usage:
    fprintf(stderr, "Usage: %s --text-only | --probe-xom | --module /absolute/urov-lab.kpm --key-fd FD [--inspect-only | --iterations N [--allow-raw-xom]]\n", argv[0]);
    goto out;
}
