/* SPDX-License-Identifier: GPL-2.0-or-later
 * Test fixtures below REGISTER/SET/DEACTIVATE only their own dedicated alias.
 * The reusable detector is native/urov_detect.c and performs none of those.
 */
#define _GNU_SOURCE
#include <android/log.h>
#include <jni.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "urov_detect.h"
#include "../../urov_abi.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "urovdetect", __VA_ARGS__)
#define REQUIRE(c, ...) do { ++g_checks; if (!(c)) { ++g_fail; LOG("FAIL " __VA_ARGS__); } } while (0)
static unsigned g_checks, g_fail, g_cases;

__asm__(".pushsection .text.ud_payload,\"ax\",%progbits\n"
        ".p2align 12\n.global ud_payload\n.type ud_payload,%function\n"
        "ud_payload:\n hint #34\n mov x1, #0x7788\n"
        "movk x1, #0x5566, lsl #16\n movk x1, #0x3344, lsl #32\n"
        "movk x1, #0x1122, lsl #48\n eor x0, x0, x1\n ret\n"
        ".size ud_payload, .-ud_payload\n.popsection\n");
extern uint64_t ud_payload(uint64_t x);
typedef uint64_t (*payload_fn)(uint64_t);

struct page { uint8_t *address; int fd; off_t file_offset; unsigned entry; };
struct business { atomic_int stop, errors; atomic_ullong ops; payload_fn fn; };

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static int fd_count(void)
{
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    if (!d) return -1;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) ++n;
    closedir(d);
    return n;
}

static int probe_fd_count(void)
{
    int n = 0;
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    char target[128];
    if (!d) return -1;
    while ((e = readdir(d))) {
        ssize_t got = readlinkat(dirfd(d), e->d_name, target, sizeof(target) - 1);
        if (got > 0) {
            target[got] = '\0';
            if (!strncmp(target, "/proc/", 6) &&
                (strstr(target, "/maps") || strstr(target, "/smaps") || strstr(target, "/mem"))) ++n;
        }
    }
    closedir(d);
    return n;
}

static struct urov_request req(unsigned op)
{
    struct urov_request q = {0};
    q.size = sizeof(q); q.version = UROV_ABI_VERSION; q.op = (uint16_t)op;
    return q;
}

static long control(unsigned op, struct urov_request *q)
{
    return syscall(__NR_prctl, (long)UROV_PRCTL_OPTION, (long)UROV_PRCTL_MAGIC,
                   (long)op, q, (long)sizeof(*q));
}

static void copy_scalar(uint8_t *out, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned v;
        __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p + i) : "memory");
        out[i] = (uint8_t)v;
    }
}

static int page_open(struct page *p, int flags)
{
    struct ud_mapping map;
    Dl_info info;
    memset(p, 0, sizeof(*p));
    p->fd = -1;
    if (!dladdr((void *)&ud_payload, &info) ||
        ud_mapping_at("/proc/self/maps", (void *)&ud_payload, &map)) return -1;
    uint64_t offset = map.offset + (uintptr_t)&ud_payload - map.start;
    p->entry = offset & 4095U;
    p->file_offset = (off_t)(offset & ~UINT64_C(4095));
    if (p->entry + 192U > 4096U) return -1;
    p->fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
    if (p->fd < 0) return -1;
    p->address = mmap(NULL, 4096, PROT_READ | PROT_EXEC, flags, p->fd, p->file_offset);
    if (p->address == MAP_FAILED) { close(p->fd); p->fd = -1; p->address = NULL; return -1; }
    if (memcmp(p->address + p->entry, (void *)&ud_payload, 28)) {
        munmap(p->address, 4096); close(p->fd); p->fd = -1; p->address = NULL; return -1;
    }
    return 0;
}

static void page_close(struct page *p)
{
    if (p->address) munmap(p->address, 4096);
    if (p->fd >= 0) close(p->fd);
    p->address = NULL; p->fd = -1;
}

static int same_signal(const struct sigaction *a, const struct sigaction *b)
{
    if (a->sa_sigaction != b->sa_sigaction || a->sa_flags != b->sa_flags) return 0;
    for (int i = 1; i < NSIG; ++i)
        if (sigismember(&a->sa_mask, i) != sigismember(&b->sa_mask, i)) return 0;
    return 1;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void check_case(const char *name, const struct page *p, unsigned start, size_t length,
                       int repeats, int expected_control, int expected_scope,
                       int expected_file, int expected_dc, int expected_rr)
{
    const int signals[] = {SIGSEGV, SIGBUS, SIGSYS, SIGPIPE};
    struct sigaction old[4], after;
    struct ud_mapping sm, sm_after;
    struct ud_control c = {0};
    struct ud_views v = {0};
    uint64_t costs[200], ctl_costs[200], sm_costs[200];
    char thread_before[17] = {0}, thread_after[17] = {0};
    int before_fail = (int)g_fail, fds = fd_count(), probe_fds = probe_fd_count();
    const uint8_t *at = p->address + p->entry + start;
    for (unsigned i = 0; i < 4; ++i) sigaction(signals[i], NULL, &old[i]);
    prctl(PR_GET_NAME, thread_before, 0L, 0L, 0L);
    for (int i = 0; i < repeats; ++i) {
        uint64_t t;
        errno = EDOM;
        t = now_ns();
        ud_probe_control(&c);
        ctl_costs[i] = now_ns() - t;
        REQUIRE(errno == EDOM, "%s control changed errno", name);
        if (expected_control != 2)
            REQUIRE((int)c.verdict == expected_control, "%s control=%d expected=%d error=%d", name,
                    c.verdict, expected_control, c.error);
        if (expected_control != 2)
            REQUIRE((int)c.scope == expected_scope, "%s scope=%d expected=%d error=%d", name,
                    c.scope, expected_scope, c.error);
        errno = EDOM;
        t = now_ns();
        ud_check_views(at, length, p->fd, p->file_offset + p->entry + start, &v);
        costs[i] = now_ns() - t;
        REQUIRE(errno == EDOM, "%s views changed errno", name);
        REQUIRE((int)v.file_diff == expected_file && v.completed == UD_REPEATS,
                "%s file=%d done=%u error=%d", name, v.file_diff, v.completed, v.error_file);
        errno = EDOM;
        t = now_ns();
        int sm_error = ud_mapping_at("/proc/self/smaps", at, &sm);
        sm_costs[i] = now_ns() - t;
        REQUIRE(!sm_error && sm.dontcopy == expected_dc && sm.randomread == expected_rr && errno == EDOM,
                "%s smaps error=%d dc=%d/%d rr=%d/%d", name, sm_error,
                sm.dontcopy, expected_dc, sm.randomread, expected_rr);
    }
    for (unsigned i = 0; i < 4; ++i) {
        sigaction(signals[i], NULL, &after);
        REQUIRE(same_signal(&old[i], &after), "%s changed signal %d", name, signals[i]);
    }
    prctl(PR_GET_NAME, thread_after, 0L, 0L, 0L);
    REQUIRE(!strcmp(thread_before, thread_after), "%s changed thread name", name);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &sm_after) &&
            sm.start == sm_after.start && sm.end == sm_after.end && sm.offset == sm_after.offset &&
            sm.readable == sm_after.readable && sm.writable == sm_after.writable &&
            sm.executable == sm_after.executable && sm.dontcopy == sm_after.dontcopy &&
            sm.maywrite == sm_after.maywrite && sm.randomread == sm_after.randomread,
            "%s changed mapping flags", name);
    int fds_after = fd_count();
    int probe_fds_after = probe_fd_count();
    /* ART and the UI may open/close unrelated fds while this worker runs.
     * Account specifically for this detector's /proc metadata fds. */
    REQUIRE(probe_fds >= 0 && probe_fds == probe_fds_after,
            "%s leaked probe fd before=%d after=%d", name, probe_fds, probe_fds_after);
    qsort(costs, (size_t)repeats, sizeof(costs[0]), cmp_u64);
    qsort(ctl_costs, (size_t)repeats, sizeof(ctl_costs[0]), cmp_u64);
    qsort(sm_costs, (size_t)repeats, sizeof(sm_costs[0]), cmp_u64);
    ++g_cases;
    LOG("CASE %s result=%s n=%d ctl=%d scope=%d caps=0x%llx file=%d dc=%d rr=%d "
        "diff_at=%lld views_us_p50=%llu views_us_p95=%llu views_us_max=%llu "
        "ctl_us_p50=%llu ctl_us_p95=%llu smaps_us_p50=%llu smaps_us_p95=%llu "
        "fd_delta=%d probe_fd_delta=%d", name,
        before_fail == (int)g_fail ? "PASS" : "FAIL", repeats, c.verdict,
        c.scope, (unsigned long long)c.caps, v.file_diff, sm.dontcopy, sm.randomread,
        v.first_file_diff == SIZE_MAX ? -1LL : (long long)v.first_file_diff,
        (unsigned long long)(costs[(repeats - 1) / 2] / 1000),
        (unsigned long long)(costs[(repeats * 95 + 99) / 100 - 1] / 1000),
        (unsigned long long)(costs[repeats - 1] / 1000),
        (unsigned long long)(ctl_costs[(repeats - 1) / 2] / 1000),
        (unsigned long long)(ctl_costs[(repeats * 95 + 99) / 100 - 1] / 1000),
        (unsigned long long)(sm_costs[(repeats - 1) / 2] / 1000),
        (unsigned long long)(sm_costs[(repeats * 95 + 99) / 100 - 1] / 1000), fds_after - fds,
        probe_fds_after - probe_fds);
}

static void *business_main(void *arg)
{
    struct business *b = arg;
    uint64_t counter = 0;
    int io[2];
    if (pipe2(io, O_CLOEXEC | O_NONBLOCK)) { atomic_fetch_add(&b->errors, 1); return NULL; }
    while (!atomic_load_explicit(&b->stop, memory_order_acquire)) {
        for (unsigned i = 0; i < 128; ++i, ++counter) {
            uint64_t want = counter ^ UINT64_C(0x1122334455667788);
            if (b->fn(counter) != want || ud_payload(counter) != want) atomic_fetch_add(&b->errors, 1);
        }
        uint64_t back = ~counter;
        if (write(io[1], &counter, sizeof(counter)) != sizeof(counter) ||
            read(io[0], &back, sizeof(back)) != sizeof(back) || back != counter)
            atomic_fetch_add(&b->errors, 1);
        atomic_store_explicit(&b->ops, counter, memory_order_release);
        usleep(500);
    }
    close(io[0]); close(io[1]);
    return NULL;
}

static int register_page(const struct page *p, unsigned length, uint64_t *generation)
{
    struct urov_request q = req(UROV_REGISTER);
    q.address = (uintptr_t)p->address;
    q.offset = p->entry + 4U; q.length = length; q.flags = UROV_F_RAW_XOM;
    q.value = UINT64_C(0x8877665544332211);
    if (length > 8) q.value_hi[0] = UINT64_C(0xa1b2c3d4e5f60718);
    if (length > 16) q.value_hi[1] = UINT64_C(0x0123456789abcdef);
    if (length > 24) q.value_hi[2] = UINT64_C(0xfedcba9876543210);
    int rc = (int)control(UROV_REGISTER, &q);
    REQUIRE(!rc && q.state == UROV_ACTIVE && q.generation == 1,
            "REGISTER len=%u rc=%d errno=%d", length, rc, errno);
    *generation = q.generation;
    return rc;
}

static int set_page(unsigned length, uint64_t *generation, const uint8_t *bytes)
{
    struct urov_request q = req(UROV_SET);
    q.session = 1; q.expected_generation = *generation; q.length = length;
    memcpy(&q.value, bytes, 8);
    if (length > 8) memcpy(q.value_hi, bytes + 8, length - 8);
    int rc = (int)control(UROV_SET, &q);
    REQUIRE(!rc, "SET len=%u rc=%d errno=%d", length, rc, errno);
    *generation = q.generation;
    return rc;
}

static void deactivate(void)
{
    struct urov_request q = req(UROV_DEACTIVATE);
    q.session = 1;
    int rc = (int)control(UROV_DEACTIVATE, &q);
    REQUIRE(!rc && q.state == UROV_INACTIVE, "DEACTIVATE rc=%d errno=%d", rc, errno);
}

static void active_matrix(const struct page *p, int repeats)
{
    uint8_t original[32], fake_b[32];
    copy_scalar(original, p->address + p->entry + 4, sizeof(original));
    for (unsigned i = 0; i < 32; ++i) fake_b[i] = (uint8_t)(0xa5U ^ (i * 7U));
    for (unsigned length = 8; length <= 32; length += 8) {
        uint64_t generation;
        char label[80];
        if (register_page(p, length, &generation)) return;
        struct urov_request before = req(UROV_STATUS), after = req(UROV_STATUS);
        before.session = after.session = 1;
        REQUIRE(!control(UROV_STATUS, &before), "STATUS before");
        snprintf(label, sizeof(label), "active_%u_A", length);
        check_case(label, p, 0, 64, repeats, UD_MATCH, UD_SCOPE_SELF, UD_MATCH, 0, 1);
        REQUIRE(!control(UROV_STATUS, &after) && after.failures == before.failures &&
                after.failures == 0 && after.generation == before.generation && after.hits > before.hits,
                "detection must not fail emulator or update session len=%u", length);
        LOG("ORACLE len=%u gen=%llu hits_delta=%llu failures=%llu", length,
            (unsigned long long)after.generation,
            (unsigned long long)(after.hits - before.hits), (unsigned long long)after.failures);
        set_page(length, &generation, fake_b);
        snprintf(label, sizeof(label), "active_%u_B", length);
        check_case(label, p, 0, 64, repeats, UD_MATCH, UD_SCOPE_SELF, UD_MATCH, 0, 1);
        /* Loads elsewhere on an active page are slow, but contain no altered
         * data. Timing or dc alone must not turn these into positives. */
        snprintf(label, sizeof(label), "active_%u_outside_window", length);
        check_case(label, p, 128, 32, repeats, UD_MATCH, UD_SCOPE_SELF, UD_NO_MATCH, 0, 1);
        set_page(length, &generation, original);
        snprintf(label, sizeof(label), "active_%u_identity", length);
        check_case(label, p, 0, 64, repeats, UD_MATCH, UD_SCOPE_SELF, UD_NO_MATCH, 0, 1);
        deactivate();
        snprintf(label, sizeof(label), "restored_%u", length);
        check_case(label, p, 0, 64, repeats, UD_MATCH, UD_SCOPE_IDLE, UD_NO_MATCH, 0, 0);
    }
}

static void negative_cases(const struct page *p, int expected_control, int expected_scope, int repeats)
{
    struct ud_views v;
    int rc = madvise(p->address, 4096, MADV_DONTFORK);
    REQUIRE(!rc, "fixture MADV_DONTFORK errno=%d", errno);
    if (!rc) {
        check_case("legitimate_dontfork", p, 0, 64, repeats, expected_control, expected_scope, UD_NO_MATCH, 1, 0);
        REQUIRE(!madvise(p->address, 4096, MADV_DOFORK), "restore fixture MADV_DOFORK");
    }
    rc = madvise(p->address, 4096, MADV_RANDOM);
    REQUIRE(!rc, "fixture MADV_RANDOM errno=%d", errno);
    if (!rc) {
        check_case("legitimate_random", p, 0, 64, repeats, expected_control, expected_scope, UD_NO_MATCH, 0, 1);
        REQUIRE(!madvise(p->address, 4096, MADV_NORMAL), "restore fixture MADV_NORMAL");
    }
    ud_check_views(p->address + p->entry, 64, -1, 0, &v);
    REQUIRE(v.file_diff == UD_UNKNOWN && v.error_file == EBADF,
            "missing reference fd must be UNKNOWN, file=%d err=%d", v.file_diff, v.error_file);
    ud_check_views(p->address + p->entry, 64, p->fd, p->file_offset + p->entry + 1, &v);
    REQUIRE(v.file_diff == UD_UNKNOWN && v.error_file == ESTALE,
            "wrong reference offset must be UNKNOWN");
    ud_check_views(p->address + 4095, 2, p->fd, p->file_offset + 4095, &v);
    REQUIRE(v.file_diff == UD_UNKNOWN && v.error_file == EINVAL,
            "cross-page request must be UNKNOWN without target access");
    void *unreadable = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(unreadable != MAP_FAILED, "unreadable fixture mmap");
    if (unreadable != MAP_FAILED) {
        ud_check_views(unreadable, 32, -1, 0, &v);
        REQUIRE(v.file_diff == UD_UNKNOWN && v.error_file == EACCES,
                "unreadable request must be UNKNOWN without signal");
        munmap(unreadable, 4096);
    }
    struct page patched;
    if (page_open(&patched, MAP_PRIVATE)) { REQUIRE(0, "private fixture"); return; }
    rc = mprotect(patched.address, 4096, PROT_READ | PROT_WRITE);
    if (!rc) {
        patched.address[patched.entry + 128] ^= 1;
        rc = mprotect(patched.address, 4096, PROT_READ | PROT_EXEC);
        if (!rc) check_case("ordinary_private_patch", &patched, 128, 32, repeats,
                            expected_control, expected_scope, UD_MATCH, 0, 0);
        else if (errno == EACCES || errno == EPERM)
            LOG("SKIP ordinary_private_patch execmod denied errno=%d", errno);
        else REQUIRE(0, "restore private fixture RX errno=%d", errno);
    } else LOG("SKIP ordinary_private_patch permission=%d", errno);
    page_close(&patched);
    LOG("NEGATIVE_CASES done no faults or process signal handlers required");
}

static void hold_until_unload(const struct page *p)
{
    uint64_t generation;
    if (register_page(p, 16, &generation)) return;
    check_case("hold_active", p, 0, 64, 3, UD_MATCH, UD_SCOPE_SELF, UD_MATCH, 0, 1);
    LOG("HOLD_READY pid=%d uid=%d", getpid(), getuid());
    int restored = 0;
    for (unsigned i = 0; i < 200; ++i) {
        struct ud_control c;
        ud_probe_control(&c);
        if (c.verdict == UD_NO_MATCH) {
            check_case("unloaded_live", p, 0, 64, 10, UD_NO_MATCH, UD_SCOPE_UNKNOWN, UD_NO_MATCH, 0, 0);
            LOG("HOLD_UNLOADED restored=1 execution=original");
            restored = 1;
            break;
        }
        usleep(100000);
    }
    if (!restored) deactivate();
    REQUIRE(restored, "hold timed out waiting for module unload");
}

static void log_context(void)
{
    char buf[256];
    FILE *f = fopen("/proc/self/attr/current", "re");
    if (f) { if (fgets(buf, sizeof(buf), f)) LOG("CONTEXT pid=%d uid=%d selinux=%s", getpid(), getuid(), buf); fclose(f); }
    f = fopen("/proc/self/status", "re");
    if (f) {
        while (fgets(buf, sizeof(buf), f))
            if (!strncmp(buf, "Seccomp:", 8) || !strncmp(buf, "CapEff:", 7)) LOG("CONTEXT %s", buf);
        fclose(f);
    }
}

JNIEXPORT jstring JNICALL Java_com_example_urovdetect_MainActivity_runNative(
    JNIEnv *env, jclass cls, jstring mode_value, jint repeats)
{
    (void)cls;
    const char *mode = (*env)->GetStringUTFChars(env, mode_value, NULL);
    char result[192];
    struct page p;
    struct business business;
    pthread_t thread;
    int expected_control = !strcmp(mode, "clean") ? UD_NO_MATCH :
                          (!strcmp(mode, "passive") ? 2 : UD_MATCH);
    int expected_scope = !strcmp(mode, "clean") ? UD_SCOPE_UNKNOWN :
                        (!strcmp(mode, "observer") ? UD_SCOPE_OTHER : UD_SCOPE_IDLE);
    int have_thread = 0;
    if (repeats < 3 || repeats > 200) repeats = 30;
    g_checks = g_fail = g_cases = 0;
    log_context();
    LOG("BEGIN mode=%s repeats=%d", mode, (int)repeats);
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        snprintf(result, sizeof(result), "FAIL no supported 4KiB owned library mapping errno=%d", errno);
        goto done;
    }
    memset(&business, 0, sizeof(business));
    atomic_init(&business.stop, 0); atomic_init(&business.errors, 0); atomic_init(&business.ops, 0);
    business.fn = (payload_fn)(p.address + p.entry);
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "business worker create");
    // Allow its two normal IO fds to settle before leak checks.
    usleep(10000);
    check_case("baseline_owned", &p, 0, 64, repeats, expected_control, expected_scope, UD_NO_MATCH, 0, 0);
    if (!strcmp(mode, "active")) active_matrix(&p, repeats);
    else if (!strcmp(mode, "hold")) hold_until_unload(&p);
    if (strcmp(mode, "hold") && strcmp(mode, "passive"))
        negative_cases(&p, expected_control, expected_scope, repeats);
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.errors) == 0 && atomic_load(&business.ops) > 0,
                "business errors=%d ops=%llu", atomic_load(&business.errors),
                (unsigned long long)atomic_load(&business.ops));
        LOG("BUSINESS ops=%llu errors=%d execution=original normal_io=ok",
            (unsigned long long)atomic_load(&business.ops), atomic_load(&business.errors));
    }
    struct ud_control observed_control;
    struct ud_views observed_views;
    ud_probe_control(&observed_control);
    ud_check_views(p.address + p.entry, 64, p.fd, p.file_offset + p.entry, &observed_views);
    snprintf(result, sizeof(result), "%s cases=%u assertions=%u failures=%u module=%d scope=%d integrity_diff=%d",
             g_fail ? "FAIL" : "PASS", g_cases, g_checks, g_fail,
             observed_control.verdict, observed_control.scope, observed_views.file_diff);
    page_close(&p);
done:
    LOG("NATIVE_RESULT %s mode=%s", result, mode);
    (*env)->ReleaseStringUTFChars(env, mode_value, mode);
    return (*env)->NewStringUTF(env, result);
}
