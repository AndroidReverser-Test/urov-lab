/* SPDX-License-Identifier: GPL-2.0-or-later
 * Test fixtures below REGISTER/SET/DEACTIVATE only their own dedicated alias.
 * The reusable detector is native/urov_detect.c and performs none of those.
 *
 * The x-* modes exercise urov-x (the covert, read-site-bound variant).  They
 * are still fixture code: the detector calls (ud_probe_control, ud_check_views,
 * ud_mapping_at) are used unchanged and must stay blind while the overlay is
 * active at the registered read sites.
 */
#define _GNU_SOURCE
#include <android/log.h>
#include <jni.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "urov_detect.h"
#include "urov_observe.h"
#include "../../urov_abi.h"
#include "../../urov_x_abi.h"
#include "../../urov_y_abi.h"

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

/* Reader sites for urov-x.  ux_site_ldr/ux_site_ldrb are registered as the
 * only instruction PCs allowed to observe the fake bytes; ux_watch_ldrb is a
 * byte-identical instruction at a different PC and must keep returning the
 * installed file bytes. */
__asm__(".pushsection .text.ux_sites,\"ax\",%progbits\n"
        ".p2align 2\n"
        ".global ux_site_ldr\n.type ux_site_ldr,%function\n"
        "ux_site_ldr:\n ldr x0, [x0]\n ret\n"
        ".size ux_site_ldr, .-ux_site_ldr\n"
        ".global ux_site_ldrb\n.type ux_site_ldrb,%function\n"
        "ux_site_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size ux_site_ldrb, .-ux_site_ldrb\n"
        ".global ux_watch_ldrb\n.type ux_watch_ldrb,%function\n"
        "ux_watch_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size ux_watch_ldrb, .-ux_watch_ldrb\n"
        ".popsection\n");
extern uint64_t ux_site_ldr(const void *p);
extern uint32_t ux_site_ldrb(const void *p);
extern uint32_t ux_watch_ldrb(const void *p);

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

static int page_open_at(struct page *p, int flags, const void *entry)
{
    struct ud_mapping map;
    Dl_info info;
    memset(p, 0, sizeof(*p));
    p->fd = -1;
    if (!dladdr(entry, &info) || ud_mapping_at("/proc/self/maps", entry, &map)) return -1;
    uint64_t offset = map.offset + (uintptr_t)entry - map.start;
    p->entry = offset & 4095U;
    p->file_offset = (off_t)(offset & ~UINT64_C(4095));
    if (p->entry + 192U > 4096U) return -1;
    p->fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
    if (p->fd < 0) return -1;
    p->address = mmap(NULL, 4096, PROT_READ | PROT_EXEC, flags, p->fd, p->file_offset);
    if (p->address == MAP_FAILED) { close(p->fd); p->fd = -1; p->address = NULL; return -1; }
    if (memcmp(p->address + p->entry, entry, 28)) {
        munmap(p->address, 4096); close(p->fd); p->fd = -1; p->address = NULL; return -1;
    }
    return 0;
}

static int page_open(struct page *p, int flags)
{
    return page_open_at(p, flags, (const void *)(uintptr_t)&ud_payload);
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

/* ---------------------------------------------------------- urov-x fixtures */

struct ux_ctx {
    int have;
    struct urov_x_keys keys;
};

static int ux_init_key(struct ux_ctx *ctx, const char *hex)
{
    uint8_t key[16];
    unsigned len = hex ? (unsigned)strlen(hex) : 0U;
    memset(ctx, 0, sizeof(*ctx));
    if (urov_x_parse_key(hex, len, key)) return -1;
    urov_x_derive(key, &ctx->keys);
    memset(key, 0, sizeof(key));
    ctx->have = 1;
    return 0;
}

static struct urov_x_request ux_req(unsigned op)
{
    struct urov_x_request q;
    memset(&q, 0, sizeof(q));
    q.size = (uint32_t)sizeof(q);
    q.version = UROV_X_ABI_VERSION;
    q.op = (uint16_t)op;
    q.request_id = UINT64_C(0x55524f56584c4142);
    return q;
}

static long ux_control(const struct ux_ctx *ctx, unsigned op, struct urov_x_request *q)
{
    q->size = (uint32_t)sizeof(*q);
    q->version = UROV_X_ABI_VERSION;
    q->op = (uint16_t)op;
    q->mac = urov_x_request_mac(ctx->keys.mac, q);
    return syscall(__NR_prctl, (long)ctx->keys.option, (long)ctx->keys.magic,
                   (long)op, q, (long)sizeof(*q));
}

static int app_pread(int fd, off_t offset, uint8_t *out, size_t n)
{
    size_t at = 0;
    while (at < n) {
        ssize_t got = pread(fd, out + at, n - at, offset + (off_t)at);
        if (got > 0) at += (size_t)got;
        else if (got == 0) return EIO;
        else if (errno != EINTR) return errno;
    }
    return 0;
}

static uint64_t load64_at(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (i * 8U);
    return v;
}

static uint32_t load32_at(const uint8_t *p)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (i * 8U);
    return v;
}

/* An unauthorized reader whose instruction is outside the audited decoder
 * subset (here a 128-bit vector load). urov-x must restore the page and retry
 * the instruction instead of raising SIGSEGV. */
static uint32_t vector_probe(const void *p)
{
    uint32_t first;
    __asm__ volatile("ldr q0, [%1]\n\tumov %w0, v0.s[0]"
                     : "=r"(first) : "r"(p) : "v0", "memory");
    return first;
}

static int ux_register_page(const struct ux_ctx *ctx, const struct page *p,
                            unsigned length, uint64_t *generation)
{
    struct urov_x_request q = ux_req(UROV_X_REGISTER);
    int rc;

    q.address = (uintptr_t)p->address;
    q.offset = p->entry + 4U;
    q.length = length;
    q.value = UINT64_C(0x8877665544332211);
    if (length > 8) q.value_hi[0] = UINT64_C(0xa1b2c3d4e5f60718);
    if (length > 16) q.value_hi[1] = UINT64_C(0x0123456789abcdef);
    if (length > 24) q.value_hi[2] = UINT64_C(0xfedcba9876543210);
    q.site_count = 2;
    q.sites[0] = (uint64_t)(uintptr_t)&ux_site_ldr;
    q.sites[1] = (uint64_t)(uintptr_t)&ux_site_ldrb;
    rc = (int)ux_control(ctx, UROV_X_REGISTER, &q);
    REQUIRE(!rc && q.state == UROV_X_ACTIVE && q.generation == 1,
            "UX REGISTER rc=%d errno=%d", rc, errno);
    if (rc) return rc;
    *generation = q.generation;
    return 0;
}

/* No key: every selector derived here is wrong, so the channel must be
 * indistinguishable from an absent module (native EINVAL). */
static void stealth_clean(void)
{
    struct ux_ctx ctx;
    struct page p;
    struct ud_control ctl;
    struct ud_views views;
    struct urov_x_request q;
    uint8_t key[16];
    long rc;

    memset(&ctx, 0, sizeof(ctx));
    memset(key, 0x5a, sizeof(key));
    urov_x_derive(key, &ctx.keys);
    memset(key, 0, sizeof(key));
    ++g_cases;

    ud_probe_control(&ctl);
    REQUIRE(ctl.verdict == UD_NO_MATCH && ctl.scope == UD_SCOPE_UNKNOWN,
            "UX clean control verdict=%d scope=%d", ctl.verdict, ctl.scope);
    q = ux_req(UROV_X_STATUS);
    q.session = 1;
    errno = 0;
    rc = ux_control(&ctx, UROV_X_STATUS, &q);
    REQUIRE(rc == -1 && errno == EINVAL, "UX clean selector rc=%ld errno=%d", rc, errno);
    {
        struct urov_request old = {0};
        old.size = sizeof(old); old.version = 2; old.op = 1;
        errno = 0;
        rc = syscall(__NR_prctl, 0x55524f56L, 0x55524f5653595343ULL, 1L, &old, 128L);
        REQUIRE(rc == -1 && errno == EINVAL, "UX clean legacy rc=%ld errno=%d", rc, errno);
    }
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UX clean page errno=%d", errno);
        return;
    }
    errno = EDOM;
    ud_check_views(p.address + p.entry, 64, p.fd, p.file_offset + p.entry, &views);
    REQUIRE(errno == EDOM && views.file_diff == UD_NO_MATCH && views.completed == UD_REPEATS,
            "UX clean views file=%d done=%u error=%d", views.file_diff, views.completed,
            views.error_file);
    page_close(&p);
}

static void stealth_active(const char *key_hex, int repeats)
{
    struct ux_ctx ctx;
    struct page p;
    struct business business;
    pthread_t thread;
    int have_thread = 0;
    uint64_t generation = 0;
    uint8_t disk[64], direct[64];
    struct ud_control ctl;
    struct ud_views views;
    struct ud_mapping sm;
    const uint8_t *at;
    uint64_t site_value = 0, hits_delta = 0;
    uint64_t read_ns_base = 0, read_ns_active = 0;
    unsigned watch_value = 0;
    long rc;

    (void)repeats;
    if (ux_init_key(&ctx, key_hex)) { REQUIRE(0, "UX missing key"); return; }
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UX page open errno=%d", errno);
        return;
    }
    at = p.address + p.entry + 4U;
    ++g_cases;

    /* The unmodified detector must stay blind. */
    errno = EDOM;
    ud_probe_control(&ctl);
    REQUIRE(errno == EDOM, "UX control changed errno");
    REQUIRE(ctl.verdict == UD_NO_MATCH && ctl.scope == UD_SCOPE_UNKNOWN,
            "UX detector verdict=%d scope=%d error=%d", ctl.verdict, ctl.scope, ctl.error);

    /* The legacy urov-lab channel must be native EINVAL. */
    {
        struct urov_request old = {0};
        old.size = sizeof(old); old.version = 2; old.op = 1;
        errno = 0;
        rc = syscall(__NR_prctl, 0x55524f56L, 0x55524f5653595343ULL, 1L, &old, 128L);
        REQUIRE(rc == -1 && errno == EINVAL, "UX legacy channel rc=%ld errno=%d", rc, errno);
    }
    /* A forged MAC must behave like an unknown prctl option and create nothing. */
    {
        struct urov_x_request bad = ux_req(UROV_X_REGISTER);
        bad.address = (uintptr_t)p.address;
        bad.offset = p.entry + 4U;
        bad.length = 8;
        bad.value = 1;
        bad.site_count = 2;
        bad.sites[0] = (uint64_t)(uintptr_t)&ux_site_ldr;
        bad.sites[1] = (uint64_t)(uintptr_t)&ux_site_ldrb;
        bad.mac = urov_x_request_mac(ctx.keys.mac, &bad) ^ 1ULL;
        errno = 0;
        rc = syscall(__NR_prctl, (long)ctx.keys.option, (long)ctx.keys.magic,
                     (long)UROV_X_REGISTER, &bad, (long)sizeof(bad));
        REQUIRE(rc == -1 && errno == EINVAL, "UX forged MAC rc=%ld errno=%d", rc, errno);
    }
    {
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_INACTIVE,
                "UX forged MAC created a session state=%u", st.state);
    }

    /* Baseline: the page matches the installed file. */
    REQUIRE(app_pread(p.fd, p.file_offset + p.entry + 4, disk, sizeof(disk)) == 0, "UX pread");
    {
        uint64_t t = now_ns();
        copy_scalar(direct, at, sizeof(direct));
        read_ns_base = now_ns() - t;
    }
    REQUIRE(!memcmp(direct, disk, sizeof(direct)), "UX baseline page differs from file");

    /* Activate the overlay bound to the two reader sites. */
    if (ux_register_page(&ctx, &p, 8, &generation)) { page_close(&p); return; }

    {
        uint64_t want = UINT64_C(0x8877665544332211);
        uint64_t got = ux_site_ldr(at);
        REQUIRE(got == want, "UX authorized LDR got=%llx want=%llx",
                (unsigned long long)got, (unsigned long long)want);
        REQUIRE((uint8_t)ux_site_ldrb(at) == 0x11U, "UX authorized LDRB got=%02x",
                (unsigned)ux_site_ldrb(at));
        site_value = got;
    }
    /* Every other reader, same bytes, sees the installed file. */
    copy_scalar(direct, at, sizeof(direct));
    REQUIRE(!memcmp(direct, disk, sizeof(direct)), "UX unauthorized reader diverged");
    watch_value = (uint8_t)ux_watch_ldrb(at);
    REQUIRE(watch_value == disk[0], "UX watch site saw fake");

    /* The delivered detector's integrity comparison is blind. */
    {
        uint64_t t = now_ns();
        copy_scalar(direct, at, sizeof(direct));
        read_ns_active = now_ns() - t;
    }
    errno = EDOM;
    ud_check_views(at, 64, p.fd, p.file_offset + p.entry + 4, &views);
    REQUIRE(errno == EDOM, "UX views changed errno");
    REQUIRE(views.file_diff == UD_NO_MATCH && views.completed == UD_REPEATS,
            "UX file/read diff file=%d done=%u error=%d", views.file_diff, views.completed,
            views.error_file);
    errno = EDOM;
    ud_probe_control(&ctl);
    REQUIRE(errno == EDOM && ctl.verdict == UD_NO_MATCH,
            "UX control visible verdict=%d error=%d", ctl.verdict, ctl.error);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &sm) && sm.dontcopy == 0 && sm.randomread == 0,
            "UX smaps dc=%d rr=%d", sm.dontcopy, sm.randomread);

    /* Counters only move for emulated loads; SET is visible at the site only. */
    {
        struct urov_x_request before = ux_req(UROV_X_STATUS);
        struct urov_x_request after = ux_req(UROV_X_STATUS);
        before.session = 1;
        after.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &before) && before.state == UROV_X_ACTIVE &&
                before.site_count == 2 && before.failures == 0, "UX status before");
        (void)ux_site_ldr(at);
        (void)ux_site_ldr(at);
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &after) &&
                after.hits == before.hits + 2 && after.failures == 0 &&
                after.generation == before.generation,
                "UX hits delta=%llu failures=%llu",
                (unsigned long long)(after.hits - before.hits),
                (unsigned long long)after.failures);
        hits_delta = after.hits - before.hits;
        {
            struct urov_x_request s = ux_req(UROV_X_SET);
            s.session = 1;
            s.expected_generation = generation;
            s.length = 8;
            s.value = UINT64_C(0x0123456789abcdef);
            REQUIRE(!ux_control(&ctx, UROV_X_SET, &s) && s.generation == generation + 1,
                    "UX SET rc generation");
            generation = s.generation;
            REQUIRE(ux_site_ldr(at) == UINT64_C(0x0123456789abcdef), "UX SET not at site");
            ud_check_views(at, 64, p.fd, p.file_offset + p.entry + 4, &views);
            REQUIRE(views.file_diff == UD_NO_MATCH && views.completed == UD_REPEATS,
                    "UX SET leaked to the file diff");
        }
    }

    /* Execution still uses the original instruction bytes. */
    {
        uint64_t x = UINT64_C(0x0123456789abcdef);
        payload_fn fn = (payload_fn)(void *)(p.address + p.entry);
        REQUIRE(fn(x) == (x ^ UINT64_C(0x1122334455667788)), "UX execution changed");
    }

    /* Self-documenting evidence for the device run report. */
    LOG("UX_PROOF control=%d scope=%d file_diff=%d rounds=%u smaps_dc=%d smaps_rr=%d "
        "site=0x%llx file_word=0x%llx watch=0x%02x hits_delta=%llu "
        "read_us_base=%llu read_us_active=%llu",
        ctl.verdict, ctl.scope, views.file_diff, views.completed, sm.dontcopy,
        sm.randomread, (unsigned long long)site_value,
        (unsigned long long)load64_at(disk), watch_value,
        (unsigned long long)hits_delta,
        (unsigned long long)(read_ns_base / 1000),
        (unsigned long long)(read_ns_active / 1000));

    /* A concurrent business thread keeps executing and doing normal IO. */
    memset(&business, 0, sizeof(business));
    atomic_init(&business.stop, 0);
    atomic_init(&business.errors, 0);
    atomic_init(&business.ops, 0);
    business.fn = (payload_fn)(void *)(p.address + p.entry);
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "UX business worker");
    usleep(20000);
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.errors) == 0 && atomic_load(&business.ops) > 0,
                "UX business errors=%d ops=%llu", atomic_load(&business.errors),
                (unsigned long long)atomic_load(&business.ops));
    }

    /* An overlapping mprotect runs natively and silently ends the session. */
    errno = 0;
    rc = mprotect(p.address, 4096, PROT_READ | PROT_EXEC);
    REQUIRE(rc == 0 && errno == 0, "UX mprotect rc=%ld errno=%d", rc, errno);
    {
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_INACTIVE,
                "UX mprotect did not end the session state=%u", st.state);
    }
    copy_scalar(direct, at, sizeof(direct));
    REQUIRE(!memcmp(direct, disk, sizeof(direct)), "UX page not native after mprotect");
    {
        struct urov_x_request d = ux_req(UROV_X_DEACTIVATE);
        d.session = 0;
        REQUIRE(!ux_control(&ctx, UROV_X_DEACTIVATE, &d) && d.state == UROV_X_INACTIVE,
                "UX deactivate idempotent");
    }
    page_close(&p);
}

static void stealth_hold(const char *key_hex)
{
    struct ux_ctx ctx;
    struct page p;
    uint64_t generation = 0;
    uint8_t disk[8];
    const uint8_t *at;
    int restored = 0;

    if (ux_init_key(&ctx, key_hex)) { REQUIRE(0, "UX hold key"); return; }
    if (page_open(&p, MAP_SHARED)) { REQUIRE(0, "UX hold page errno=%d", errno); return; }
    at = p.address + p.entry + 4U;
    if (app_pread(p.fd, p.file_offset + p.entry + 4, disk, sizeof(disk))) {
        REQUIRE(0, "UX hold pread");
        page_close(&p);
        return;
    }
    if (ux_register_page(&ctx, &p, 8, &generation)) { page_close(&p); return; }
    REQUIRE(ux_site_ldr(at) == UINT64_C(0x8877665544332211), "UX hold not overlaid");
    ++g_cases;
    LOG("HOLD_READY pid=%d uid=%d", getpid(), getuid());
    for (unsigned i = 0; i < 300; ++i) {
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        /* Keep the fault path busy while the module may be unloaded. */
        uint64_t seen = ux_site_ldr(at);
        st.session = 1;
        errno = 0;
        if (ux_control(&ctx, UROV_X_STATUS, &st) == -1 && errno == EINVAL) {
            REQUIRE(ux_site_ldr(at) == load64_at(disk), "UX hold unload not restored");
            LOG("HOLD_UNLOADED restored=1");
            restored = 1;
            break;
        }
        REQUIRE(seen == UINT64_C(0x8877665544332211), "UX hold site lost");
        usleep(100000);
    }
    REQUIRE(restored, "UX hold timed out waiting for unload");
    page_close(&p);
}

static void stealth_simd(const char *key_hex)
{
    struct ux_ctx ctx;
    struct page p;
    uint64_t generation = 0;
    uint8_t disk[16], direct[16];
    uint32_t got, want;
    const uint8_t *at;

    if (ux_init_key(&ctx, key_hex)) { REQUIRE(0, "UX simd key"); return; }
    if (page_open(&p, MAP_SHARED)) { REQUIRE(0, "UX simd page errno=%d", errno); return; }
    at = p.address + p.entry + 4U;
    if (app_pread(p.fd, p.file_offset + p.entry + 4, disk, sizeof(disk))) {
        REQUIRE(0, "UX simd pread");
        page_close(&p);
        return;
    }
    if (ux_register_page(&ctx, &p, 8, &generation)) { page_close(&p); return; }
    ++g_cases;
    got = vector_probe(at);
    want = load32_at(disk);
    REQUIRE(got == want, "UX SIMD probe got=%x want=%x", got, want);
    {
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_INACTIVE,
                "UX SIMD fallback state=%u", st.state);
    }
    copy_scalar(direct, at, sizeof(direct));
    REQUIRE(!memcmp(direct, disk, sizeof(direct)), "UX SIMD page not restored");
    page_close(&p);
}

/* A forked child must not inherit a page that faults for data reads: urov-x
 * restores the parent page around clone()/fork(), so the child sees a normal
 * mapping while the parent keeps its session. */
static void stealth_fork(const char *key_hex)
{
    struct ux_ctx ctx;
    struct page p;
    uint64_t generation = 0;
    uint8_t disk[8], direct[8];
    const uint8_t *at;
    pid_t pid;
    int status = 0;

    if (ux_init_key(&ctx, key_hex)) { REQUIRE(0, "UX fork key"); return; }
    if (page_open(&p, MAP_SHARED)) { REQUIRE(0, "UX fork page errno=%d", errno); return; }
    at = p.address + p.entry + 4U;
    if (app_pread(p.fd, p.file_offset + p.entry + 4, disk, sizeof(disk))) {
        REQUIRE(0, "UX fork pread");
        page_close(&p);
        return;
    }
    if (ux_register_page(&ctx, &p, 8, &generation)) { page_close(&p); return; }
    REQUIRE(ux_site_ldr(at) == UINT64_C(0x8877665544332211), "UX fork not overlaid");
    ++g_cases;

    pid = fork();
    if (pid == 0) {
        /* Child: only normal scalar loads, bounded by an alarm. */
        alarm(3);
        copy_scalar(direct, at, sizeof(direct));
        _exit(memcmp(direct, disk, sizeof(direct)) == 0 ? 0 : 7);
    }
    REQUIRE(pid > 0, "UX fork pid=%d errno=%d", (int)pid, errno);
    if (pid > 0) {
        REQUIRE(waitpid(pid, &status, 0) == pid, "UX fork waitpid errno=%d", errno);
        REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "UX child status=0x%x signal=%d code=%d", status,
                WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    /* The parent keeps the overlay at its registered site. */
    REQUIRE(ux_site_ldr(at) == UINT64_C(0x8877665544332211), "UX parent site lost after fork");
    copy_scalar(direct, at, sizeof(direct));
    REQUIRE(!memcmp(direct, disk, sizeof(direct)), "UX parent unauthorized read diverged");
    {
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_ACTIVE,
                "UX parent session lost after fork state=%u", st.state);
    }
    {
        struct urov_x_request d = ux_req(UROV_X_DEACTIVATE);
        d.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_DEACTIVATE, &d) && d.state == UROV_X_INACTIVE,
                "UX fork deactivate");
    }
    page_close(&p);
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

/* Observation fixtures know the key only to establish ground truth. Neither
 * detector API accepts a key, context, selector, request, or expected verdict.
 */
static void observation_case(const char *name, const struct page *p, unsigned delta,
                             int repeats, int expected_exclusive, int expected_reader)
{
    const uint8_t *at = p->address + p->entry + delta;
    const uint8_t *reference = (const uint8_t *)(uintptr_t)&ud_payload + delta;
    const off_t offset = p->file_offset + p->entry + delta;
    struct ud_exclusive_observation ex = {0};
    struct ud_reader_observation rd = {0};
    uint64_t costs[200];
    unsigned matches = 0, clean = 0, unknown = 0, reader_matches = 0;
    unsigned accepted = 0, failed = 0, control_failed = 0;
    unsigned failures_before = g_fail;
    const int signals[] = {SIGSEGV, SIGBUS, SIGSYS, SIGPIPE};
    struct sigaction old[4], after;
    struct ud_mapping oldmap, newmap;
    char name_before[17] = {0}, name_after[17] = {0};
    int probe_fds = probe_fd_count();
    off_t position = lseek(p->fd, 0, SEEK_CUR);
    for (unsigned i = 0; i < 4; ++i) sigaction(signals[i], NULL, &old[i]);
    prctl(PR_GET_NAME, name_before, 0L, 0L, 0L);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &oldmap), "%s before mapping", name);
    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        errno = EDOM;
        ud_observe_exclusive(at, reference, p->fd, offset, &ex);
        REQUIRE(errno == EDOM, "%s exclusive changed errno", name);
        /* A native read can lose its reservation to an unrelated interrupt.
         * The detector must report UNKNOWN for that partial pattern. Such a
         * sample is not a clean negative and is never an allowed positive.
         */
        REQUIRE((int)ex.reservation_loss == expected_exclusive ||
                (expected_exclusive == UD_NO_MATCH && ex.reservation_loss == UD_UNKNOWN &&
                 ex.error == EAGAIN),
                "%s exclusive=%d expected=%d accepted=%u failed=%u control=%u error=%d",
                name, ex.reservation_loss, expected_exclusive, ex.accepted,
                ex.target_failed, ex.control_failed, ex.error);
        costs[i] = ex.elapsed_ns;
        matches += ex.reservation_loss == UD_MATCH;
        clean += ex.reservation_loss == UD_NO_MATCH;
        unknown += ex.reservation_loss == UD_UNKNOWN;
        accepted += ex.accepted;
        failed += ex.target_failed;
        control_failed += ex.control_failed;
        errno = EDOM;
        ud_observe_reader(at, p->fd, offset, ux_site_ldr, &rd);
        REQUIRE(errno == EDOM, "%s reader changed errno", name);
        REQUIRE((int)rd.reader_diff == expected_reader && rd.completed == UD_REPEATS,
                "%s reader=%d expected=%d rounds=%u error=%d", name,
                rd.reader_diff, expected_reader, rd.completed, rd.error);
        reader_matches += rd.reader_diff == UD_MATCH;
    }
    for (unsigned i = 0; i < 4; ++i) {
        sigaction(signals[i], NULL, &after);
        REQUIRE(same_signal(&old[i], &after), "%s changed signal %d", name, signals[i]);
    }
    prctl(PR_GET_NAME, name_after, 0L, 0L, 0L);
    REQUIRE(!strcmp(name_before, name_after), "%s thread name changed", name);
    REQUIRE(lseek(p->fd, 0, SEEK_CUR) == position, "%s file position changed", name);
    REQUIRE(probe_fds == probe_fd_count(), "%s leaked metadata fd", name);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &newmap) &&
            oldmap.start == newmap.start && oldmap.end == newmap.end &&
            oldmap.offset == newmap.offset && oldmap.readable == newmap.readable &&
            oldmap.writable == newmap.writable && oldmap.executable == newmap.executable &&
            oldmap.dontcopy == newmap.dontcopy && oldmap.randomread == newmap.randomread &&
            oldmap.maywrite == newmap.maywrite, "%s VMA changed", name);
    qsort(costs, (size_t)repeats, sizeof(costs[0]), cmp_u64);
    LOG("OBS_CASE name=%s result=%s n=%d match=%u clean=%u unknown=%u "
        "accepted=%u failed=%u control_failed=%u reader_match=%u "
        "direct=0x%llx reader=0x%llx file=0x%llx p50_us=%llu p95_us=%llu max_us=%llu",
        name, failures_before == g_fail ? "PASS" : "FAIL", repeats, matches, clean, unknown,
        accepted, failed, control_failed, reader_matches,
        (unsigned long long)rd.direct_value, (unsigned long long)rd.reader_value,
        (unsigned long long)rd.file_value,
        (unsigned long long)(costs[(repeats - 1) / 2] / 1000),
        (unsigned long long)(costs[(repeats * 95 + 99) / 100 - 1] / 1000),
        (unsigned long long)(costs[repeats - 1] / 1000));
}

static unsigned observation_alternation;

static uint64_t observation_unstable_reader(const void *address)
{
    return ux_site_ldr(address) ^ (uint64_t)(observation_alternation++ & 1U);
}

static void observation_contract_cases(const struct page *p)
{
    struct ud_exclusive_observation ex;
    struct ud_reader_observation rd;
    const void *at = p->address + p->entry + 8;
    const void *reference = (const uint8_t *)(uintptr_t)&ud_payload + 8;
    off_t offset = p->file_offset + p->entry + 8;
    unsigned before = g_fail;
    ++g_cases;
    errno = EDOM;
    ud_observe_exclusive(at, at, p->fd, offset, &ex);
    REQUIRE(errno == EDOM && ex.reservation_loss == UD_UNKNOWN && ex.error == EINVAL,
            "OBS same-page control accepted");
    ud_observe_exclusive(at, reference, p->fd, offset + 1, &ex);
    REQUIRE(ex.reservation_loss == UD_UNKNOWN && ex.error == ESTALE, "OBS wrong offset accepted");
    ud_observe_exclusive(at, reference, -1, offset, &ex);
    REQUIRE(ex.reservation_loss == UD_UNKNOWN && ex.error == EBADF, "OBS bad fd accepted");
    ud_observe_reader(at, p->fd, offset, NULL, &rd);
    REQUIRE(rd.reader_diff == UD_UNKNOWN && rd.error == EINVAL, "OBS missing reader accepted");
    ud_observe_reader((const uint8_t *)at + 1, p->fd, offset + 1, ux_site_ldr, &rd);
    REQUIRE(rd.reader_diff == UD_UNKNOWN && rd.error == EINVAL, "OBS unaligned reader accepted");
    observation_alternation = 0;
    ud_observe_reader(at, p->fd, offset, observation_unstable_reader, &rd);
    REQUIRE(rd.reader_diff == UD_UNKNOWN && rd.error == EAGAIN,
            "OBS unstable reader reported a finding");
    void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(rw != MAP_FAILED, "OBS RW negative fixture allocation");
    if (rw != MAP_FAILED) {
        ud_observe_exclusive(rw, reference, p->fd, offset, &ex);
        REQUIRE(ex.reservation_loss == UD_UNKNOWN && ex.error == EACCES,
                "OBS writable/non-executable target accepted");
        munmap(rw, 4096);
    }
    REQUIRE(errno == EDOM, "OBS contract probes changed errno");
    LOG("OBS_CONTRACT result=%s rejected=7 unstable_reader=unknown",
        before == g_fail ? "PASS" : "FAIL");
}

static void observation_normal_variants(const struct page *p, int repeats)
{
    REQUIRE(!madvise(p->address, 4096, MADV_RANDOM), "OBS MADV_RANDOM fixture");
    observation_case("normal_madv_random", p, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
    REQUIRE(!madvise(p->address, 4096, MADV_NORMAL), "OBS MADV_NORMAL fixture");
    REQUIRE(!madvise(p->address, 4096, MADV_DONTFORK), "OBS DONTFORK fixture");
    observation_case("normal_madv_dontfork", p, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
    REQUIRE(!madvise(p->address, 4096, MADV_DOFORK), "OBS DOFORK fixture");
    REQUIRE(!madvise(p->address, 4096, MADV_DONTNEED), "OBS DONTNEED fixture");
    observation_case("normal_cold_pte", p, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
}

static void observation_each_cpu(const struct page *p)
{
    cpu_set_t available;
    unsigned tested = 0;
    if (sched_getaffinity(0, sizeof(available), &available)) {
        LOG("OBS_CPUS skipped=getaffinity errno=%d", errno); return;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        cpu_set_t selected;
        char label[40];
        if (!CPU_ISSET(cpu, &available)) continue;
        CPU_ZERO(&selected); CPU_SET(cpu, &selected);
        if (sched_setaffinity(0, sizeof(selected), &selected)) {
            LOG("OBS_CPU skipped=%d errno=%d", cpu, errno); continue;
        }
        snprintf(label, sizeof(label), "active_cpu_%d", cpu);
        observation_case(label, p, 8, 3, UD_MATCH, UD_MATCH);
        ++tested;
    }
    REQUIRE(!sched_setaffinity(0, sizeof(available), &available), "OBS restore worker affinity");
    LOG("OBS_CPUS tested=%u worker_affinity_restored=1", tested);
}

static void observation_matrix(const char *key, int repeats, int active)
{
    struct page p;
    struct ux_ctx ctx;
    struct business business;
    pthread_t thread;
    int have_thread;
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "OBS owned page errno=%d", errno); return;
    }
    memset(&business, 0, sizeof(business));
    atomic_init(&business.stop, 0); atomic_init(&business.errors, 0); atomic_init(&business.ops, 0);
    business.fn = (payload_fn)(void *)(p.address + p.entry);
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "OBS business worker");
    usleep(10000);
    observation_case("baseline", &p, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
    observation_contract_cases(&p);
    if (!active) observation_normal_variants(&p, repeats);
    if (active) {
        if (ux_init_key(&ctx, key)) { REQUIRE(0, "OBS fixture key missing"); goto finish; }
        struct urov_x_request reg = ux_req(UROV_X_REGISTER);
        reg.address = (uintptr_t)p.address;
        reg.offset = p.entry + 8;
        reg.length = 8;
        reg.value = UINT64_C(0x8877665544332211);
        reg.site_count = 2;
        reg.sites[0] = (uintptr_t)&ux_site_ldr;
        reg.sites[1] = (uintptr_t)&ux_site_ldrb;
        if (ux_control(&ctx, UROV_X_REGISTER, &reg)) {
            REQUIRE(0, "OBS register errno=%d", errno); goto finish;
        }
        observation_case("active_changed", &p, 8, repeats, UD_MATCH, UD_MATCH);
        observation_case("active_outside_window", &p, 96, repeats, UD_MATCH, UD_NO_MATCH);
        struct page alias;
        if (!page_open(&alias, MAP_SHARED)) {
            observation_case("active_normal_alias", &alias, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
            page_close(&alias);
        } else REQUIRE(0, "OBS second native alias");
        observation_each_cpu(&p);
        struct urov_x_request st = ux_req(UROV_X_STATUS);
        st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_ACTIVE &&
                st.generation == 1 && st.failures == 0 && st.site_count == 2 &&
                st.value == reg.value, "OBS detector affected active session");
        LOG("OBS_STATE active=%u generation=%llu sites=%u failures=%llu hits=%llu",
            st.state, (unsigned long long)st.generation, st.site_count,
            (unsigned long long)st.failures, (unsigned long long)st.hits);
        /* Equal fake bytes defeat content comparisons but retain every fault.
         * These SETs are fixture actions, outside both detector implementations.
         */
        uint64_t original;
        REQUIRE(!app_pread(p.fd, p.file_offset + p.entry + 8, (uint8_t *)&original, 8),
                "OBS equal-value fixture pread");
        struct urov_x_request same = ux_req(UROV_X_SET);
        same.session = 1; same.expected_generation = 1; same.length = 8; same.value = original;
        REQUIRE(!ux_control(&ctx, UROV_X_SET, &same) && same.generation == 2,
                "OBS equal-value fixture SET");
        observation_case("active_equal_original", &p, 8, repeats, UD_MATCH, UD_NO_MATCH);
        st = ux_req(UROV_X_STATUS); st.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_STATUS, &st) && st.state == UROV_X_ACTIVE &&
                st.generation == 2 && st.value == original && st.failures == 0,
                "OBS equal-value detection affected session");
        LOG("OBS_STATE active=%u generation=%llu sites=%u failures=%llu hits=%llu",
            st.state, (unsigned long long)st.generation, st.site_count,
            (unsigned long long)st.failures, (unsigned long long)st.hits);
        struct urov_x_request deact = ux_req(UROV_X_DEACTIVATE);
        deact.session = 1;
        REQUIRE(!ux_control(&ctx, UROV_X_DEACTIVATE, &deact), "OBS fixture deactivate");
        observation_case("deactivated", &p, 8, repeats, UD_NO_MATCH, UD_NO_MATCH);
    }
finish:
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.errors) == 0 && atomic_load(&business.ops) > 0,
                "OBS business failed");
        LOG("OBS_BUSINESS ops=%llu errors=%d execution=original normal_io=ok",
            (unsigned long long)atomic_load(&business.ops), atomic_load(&business.errors));
    }
    page_close(&p);
}

/* urov-y (site-trap variant) fixtures live in their own include so the
 * detector core and the urov-x fixtures stay untouched. */
#include "uy_fixture.inc"

JNIEXPORT jstring JNICALL Java_com_example_urovdetect_MainActivity_runNative(
    JNIEnv *env, jclass cls, jstring mode_value, jint repeats, jstring key_value)
{
    (void)cls;
    const char *mode = (*env)->GetStringUTFChars(env, mode_value, NULL);
    const char *key = key_value ? (*env)->GetStringUTFChars(env, key_value, NULL) : "";
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
    if (!strncmp(mode, "observe-", 8)) {
        observation_matrix(key, (int)repeats, !strcmp(mode, "observe-active"));
        snprintf(result, sizeof(result), "%s cases=%u assertions=%u failures=%u",
                 g_fail ? "FAIL" : "PASS", g_cases, g_checks, g_fail);
        goto done;
    }
    if (!strncmp(mode, "x-", 2)) {
        /* urov-x fixtures: the detector calls stay unmodified and unkeyed. */
        if (!strcmp(mode, "x-active")) stealth_active(key, (int)repeats);
        else if (!strcmp(mode, "x-hold")) stealth_hold(key);
        else if (!strcmp(mode, "x-simd")) stealth_simd(key);
        else if (!strcmp(mode, "x-fork")) stealth_fork(key);
        else stealth_clean();
        snprintf(result, sizeof(result), "%s cases=%u assertions=%u failures=%u",
                 g_fail ? "FAIL" : "PASS", g_cases, g_checks, g_fail);
        goto done;
    }
    if (!strncmp(mode, "y-", 2) || !strncmp(mode, "z-", 2) || !strncmp(mode, "w-", 2)) {
        /* urov-y fixtures: the detector calls are unkeyed.
         * y-* is the BRK site mode, z-* the page-trap (UXN) mode, w-* the
         * target-page AP[1] data-trap mode. */
        unsigned trap = mode[0] == 'z' ? UROV_Y_MODE_PAGE_UXN :
                        mode[0] == 'w' ? UROV_Y_MODE_PAGE_AP : UROV_Y_MODE_SITE_BRK;
        if (!strcmp(mode, "y-active") || !strcmp(mode, "z-active") ||
            !strcmp(mode, "w-active"))
            elimination_active(key, (int)repeats, trap);
        else if (!strcmp(mode, "y-hold") || !strcmp(mode, "z-hold") ||
                 !strcmp(mode, "w-hold"))
            elimination_hold(key, trap);
        else {
            if (strcmp(mode, "z-observer")) elimination_clean();
            elimination_exec_passive((int)repeats);
        }
        snprintf(result, sizeof(result), "%s cases=%u assertions=%u failures=%u",
                 g_fail ? "FAIL" : "PASS", g_cases, g_checks, g_fail);
        goto done;
    }
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
    if (key_value) (*env)->ReleaseStringUTFChars(env, key_value, key);
    return (*env)->NewStringUTF(env, result);
}
