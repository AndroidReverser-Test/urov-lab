/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "shared.h"
#include "control.h"
#include <urov/urov.h>
#include <android/log.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#define DECLARE(i) extern int uz_test_target_##i(int, int);
DECLARE(0) DECLARE(1) DECLARE(2) DECLARE(3) DECLARE(4)
DECLARE(5) DECLARE(6) DECLARE(7) DECLARE(8) DECLARE(9)
extern int uz_test_sleep(const struct timespec *);
extern void uz_read_block(const void *, void *);
static const test_target targets[TEST_TARGETS] = {
    uz_test_target_0, uz_test_target_1, uz_test_target_2, uz_test_target_3, uz_test_target_4,
    uz_test_target_5, uz_test_target_6, uz_test_target_7, uz_test_target_8, uz_test_target_9
};
static struct test_context ctx;
static const unsigned char *code, *pages[TEST_TARGETS];
static size_t code_size, page_size;
static uint32_t page_crc[TEST_TARGETS], patched_crc;
static int command, completed, command_rc, stop_worker, used_process;
static int action_timed_out;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static char output[96 * 1024];
static char crc_snapshot[6144], return_snapshot[4096], timing_snapshot[1024];
static char overlay_crc_snapshot[512];
static size_t output_used;
static unsigned failures;
/* Serialize sampling with mutations, injection and individual timed reads.
 * Stress threads use the same immutable inputs and atomically record results. */
static pthread_mutex_t observation_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *observation_stage = "baseline";
static int observation_paused, stop_observer, overlay_returns_valid;
static unsigned observation_tick, return_failures;
static uint64_t observation_due, observation_origin;
static int overlay_returns[TEST_TARGETS];
enum { SAMPLES = 9, WARMUP = 2, THREADS = 4, STRESS_ROUNDS = 8 };
struct timing { double median[3]; };

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static void report(const char *format, ...)
{
    char line[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    __android_log_write(ANDROID_LOG_INFO, "UROVZ-CRC", line);
    pthread_mutex_lock(&log_lock);
    size_t n = strlen(line);
    if (output_used + n + 2 >= sizeof(output)) {
        /* Retain recent complete lines; dashboard snapshots are independent
         * so long runs cannot freeze the current CRC/return-value display. */
        char *next = strchr(output + sizeof(output) / 4, '\n');
        size_t removed = next ? (size_t)(next + 1 - output) : output_used;
        memmove(output, output + removed, output_used - removed);
        output_used -= removed;
    }
    memcpy(output + output_used, line, n);
    output_used += n;
    output[output_used++] = '\n';
    output[output_used] = 0;
    pthread_mutex_unlock(&log_lock);
}
static int require(int condition, const char *what)
{
    if (condition) return 0;
    failures++;
    report("ASSERT FAIL %s", what);
    return -1;
}

/* Called with observation_lock held. Every displayed actual value comes from
 * a fresh call through the real target entry; expected values are separate. */
static void observe_returns_locked(void)
{
    if (observation_paused) return;
    uint64_t now = now_ns();
    if (!observation_origin) observation_origin = now;
    observation_due = now + UINT64_C(1000000000);
    unsigned tick = ++observation_tick;
    char snapshot[4096];
    int used = snprintf(snapshot, sizeof(snapshot),
                        "RETURNS tick=%u elapsed_ms=%llu stage=%s hooked=%d overlay=%d\n",
                        tick, (unsigned long long)((now - observation_origin) / 1000000),
                        observation_stage, ctx.hooked, ctx.overlaid);
    report("%.*s", used - 1, snapshot);
    for (unsigned i = 0; i < TEST_TARGETS; ++i) {
        int actual = ctx.targets[i](3 + (int)i, 4 + 2 * (int)i);
        int expected = test_expected(i, ctx.hooked != 0);
        if (actual != expected) return_failures++;
        if (ctx.overlaid) overlay_returns[i] = actual;
        char row[256];
        snprintf(row, sizeof(row),
                 "RETURN index=%u actual=%d expected=%d baseline=%d overlay_actual=%d result=%s",
                 i, actual, expected, test_expected(i, 0),
                 ctx.overlaid || overlay_returns_valid ? overlay_returns[i] : -1,
                 actual == expected ? "PASS" : "FAIL");
        report("%s", row);
        used += snprintf(snapshot + used, sizeof(snapshot) - (size_t)used, "%s\n", row);
    }
    if (ctx.overlaid) overlay_returns_valid = 1;
    pthread_mutex_lock(&log_lock);
    snprintf(return_snapshot, sizeof(return_snapshot), "%s", snapshot);
    pthread_mutex_unlock(&log_lock);
}
static void observe_if_due(void)
{
    pthread_mutex_lock(&observation_lock);
    if (now_ns() >= observation_due) observe_returns_locked();
    pthread_mutex_unlock(&observation_lock);
}
static void *observer(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "uz-returns");
    while (!__atomic_load_n(&stop_observer, __ATOMIC_ACQUIRE)) {
        observe_if_due();
        usleep(100000);
    }
    return NULL;
}

__attribute__((visibility("hidden"), noinline))
int uz_test_impl(int a, int b, unsigned i)
{
    __atomic_store_n(&ctx.seen_a[i], a, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx.seen_b[i], b, __ATOMIC_RELAXED);
    return a * 7 + b + (int)i * 17;
}
static uint32_t direct_range(const void *base, size_t size)
{
    uint32_t crc = ~0U;
    const volatile unsigned char *p = base;
    unsigned char block[64];
    for (size_t off = 0; off < size;) {
        size_t n = size - off < sizeof(block) ? size - off : sizeof(block);
        if (n == sizeof(block)) uz_read_block((const char *)base + off, block);
        else for (size_t j = 0; j < n; ++j) block[j] = p[off + j];
        for (size_t j = 0; j < n; ++j) {
            crc ^= block[j];
            for (unsigned b = 0; b < 8; ++b)
                crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
        off += n;
    }
    return ~crc;
}
static uint32_t direct_crc(void) { return direct_range(code, code_size); }
static int crc_channel(unsigned mode, const void *base, size_t size, uint32_t *out)
{
    if (!mode) { *out = direct_range(base, size); return 0; }
    unsigned char buffer[4096];
    uint32_t crc = crc32(0, NULL, 0);
    int fd = mode == 2 ? open("/proc/self/mem", O_RDONLY | O_CLOEXEC) : -1;
    if (mode == 2 && fd < 0) return -errno;
    for (size_t off = 0; off < size;) {
        size_t n = size - off;
        if (n > sizeof(buffer)) n = sizeof(buffer);
        ssize_t got;
        if (mode == 2) got = pread64(fd, buffer, n, (off64_t)(uintptr_t)((const char *)base + off));
        else {
            struct iovec local = {buffer, n}, remote = {(char *)base + off, n};
            got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        }
        if (got <= 0) { int rc = got < 0 ? -errno : -EIO; if (fd >= 0) close(fd); return rc; }
        crc = crc32(crc, buffer, (uInt)got);
        off += (size_t)got;
    }
    if (fd >= 0) close(fd);
    *out = crc;
    return 0;
}
static int find_code(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    if (!strstr(info->dlpi_name, "/libuzhost.so")) return 0;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) {
            if (code) return -1;
            code = (const unsigned char *)(info->dlpi_addr + p->p_vaddr);
            code_size = p->p_memsz;
        }
    }
    return 1;
}
static int setup(void)
{
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (require(page_size == 4096 || page_size == 16384, "supported page size") ||
        require(dl_iterate_phdr(find_code, NULL) == 1 && code && code_size && code_size < (1U << 20),
                "exactly one executable PT_LOAD")) return -1;
    ctx.magic = TEST_MAGIC; ctx.pid = getpid(); ctx.direct_crc = direct_crc;
    memcpy(ctx.targets, targets, sizeof(targets));
    char address_text[32];
    snprintf(address_text, sizeof(address_text), "%llx", (unsigned long long)(uintptr_t)&ctx);
    if (setenv(TEST_CONTEXT_ENV, address_text, 1)) return -1;
    for (unsigned i = 0; i < TEST_TARGETS; ++i) {
        uintptr_t addr = (uintptr_t)targets[i];
        pages[i] = (const unsigned char *)(addr & ~(page_size - 1));
        if (require(pages[i] >= code && pages[i] + page_size <= code + code_size &&
                    addr + 64 <= (uintptr_t)pages[i] + page_size, "whole target page inside executable segment")) return -1;
        for (unsigned j = 0; j < i; ++j)
            if (require(pages[i] != pages[j], "ten DISTINCT runtime pages")) return -1;
        page_crc[i] = direct_range(pages[i], page_size);
        report("TARGET index=%u address=%p page=%p baseline_crc=%08x", i, (void *)targets[i], pages[i], page_crc[i]);
    }
    ctx.baseline_crc = direct_crc();
    report("LAYOUT PASS functions=10 distinct_pages=10 page_size=%zu code=%p bytes=%zu baseline_crc=%08x uid=%u",
           page_size, code, code_size, ctx.baseline_crc, getuid());
    return 0;
}
static void *cooperative(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "uz-inject");
    __atomic_store_n(&ctx.tid, (int)syscall(SYS_gettid), __ATOMIC_RELEASE);
    const struct timespec delay = {0, 20000000};
    while (!__atomic_load_n(&stop_worker, __ATOMIC_ACQUIRE)) {
        uz_test_sleep(&delay);
        int cmd = __atomic_exchange_n(&command, 0, __ATOMIC_ACQUIRE);
        if (cmd) {
            int (*action)(int) = __atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE);
            command_rc = action ? action(cmd - 1) : -ENODEV;
            __atomic_store_n(&completed, 1, __ATOMIC_RELEASE);
        }
    }
    return NULL;
}
static int action_unlocked(int cmd)
{
    if (action_timed_out) return -ETIMEDOUT;
    __atomic_store_n(&completed, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&command, cmd + 1, __ATOMIC_RELEASE);
    uint64_t deadline = now_ns() + UINT64_C(60000000000);
    while (!__atomic_load_n(&completed, __ATOMIC_ACQUIRE)) {
        if (now_ns() >= deadline) { action_timed_out = 1; return -ETIMEDOUT; }
        usleep(10000);
    }
    if (command_rc) report("ACTION FAIL command=%d rc=%d", cmd, command_rc);
    return command_rc;
}
static int action(int cmd)
{
    pthread_mutex_lock(&observation_lock);
    int rc = action_unlocked(cmd);
    if (rc) observation_paused = 1;
    else if (cmd != INSPECT) {
        static const char *names[] = {"inspect", "hooked_uncovered", "overlay", "deactivated", "unhooked"};
        observation_stage = names[cmd];
    }
    pthread_mutex_unlock(&observation_lock);
    return rc;
}
static int ctl(const char *key, const char *cmd, char *out)
{
    int rc = test_kpatch(key, "ctl0", cmd, out, 8192);
    if (rc) report("CONTROL FAIL command=%s rc=%d response=%s", cmd, rc, out);
    return rc;
}
static int inject_unlocked(const char *key, const char *libdir, const char *backend, int probe)
{
    char command_text[512], state[8192];
    int n = snprintf(command_text, sizeof(command_text), "kclf,inject,%d,%s/lib%s.so,%s,wake%s",
                     ctx.tid, libdir, probe ? "uzprobe" : "uzpayload", backend, probe ? ",unload" : "");
    if (n < 0 || n >= (int)sizeof(command_text)) return -ENAMETOOLONG;
    if (ctl(key, command_text, state)) return -1;
    unsigned long long id = 0;
    const char *queued = strstr(state, "queued id=");
    if (!queued || sscanf(queued, "queued id=%llu", &id) != 1) { report("INJECT FAIL %s", state); return -1; }
    report("INJECT queued id=%llu kind=%s backend=%s tid=%d", id, probe ? "probe" : "payload", backend, ctx.tid);
    char match[64];
    snprintf(match, sizeof(match), " id=%llu ", id);
    uint64_t deadline = now_ns() + UINT64_C(60000000000);
    while (now_ns() < deadline) {
        if (ctl(key, "kclf,status", state)) return -1;
        char *line = strstr(state, match);
        if (line) {
            char *end = strchr(line, '\n');
            if (end) *end = 0;
            if (strstr(line, "state=failed") || strstr(line, "state=cancelled") || strstr(line, " err=")) {
                report("INJECT FAIL%s", line); return -1;
            }
            char *handle = strstr(line, " handle=");
            unsigned long long value = 0;
            if (strstr(line, "state=done") && !strstr(line, " pending=") && !strstr(line, " map=") &&
                handle && sscanf(handle, " handle=%llx", &value) == 1 && value) {
                if (probe && !strstr(line, "unload=ok rc=0")) { report("PROBE UNLOAD FAIL%s", line); return -1; }
                report("INJECT DONE%s", line);
                return ctl(key, "kclf,reap", state);
            }
        }
        usleep(100000);
    }
    report("INJECT TIMEOUT %s", state);
    return -ETIMEDOUT;
}
static int inject(const char *key, const char *libdir, const char *backend, int probe)
{
    pthread_mutex_lock(&observation_lock);
    int rc = inject_unlocked(key, libdir, backend, probe);
    if (rc) observation_paused = 1;
    pthread_mutex_unlock(&observation_lock);
    return rc;
}
static int calls(unsigned rounds)
{
    for (unsigned r = 0; r < rounds; ++r)
        for (unsigned i = 0; i < TEST_TARGETS; ++i) {
            int a = 3 + (int)i, b = 4 + 2 * (int)i;
            if (ctx.targets[i](a, b) != test_expected(i, ctx.hooked != 0)) return -1;
            if (__atomic_load_n(&ctx.seen_a[i], __ATOMIC_RELAXED) != (ctx.hooked ? a + 10 : a) ||
                __atomic_load_n(&ctx.seen_b[i], __ATOMIC_RELAXED) != (ctx.hooked ? b * 3 : b)) return -1;
            if (ctx.hooked && __atomic_load_n(&ctx.original_result[i], __ATOMIC_RELAXED) != test_expected(i, 1) - 1000) return -1;
        }
    return 0;
}
static int check_stage(const char *stage)
{
    pthread_mutex_lock(&observation_lock);
    observation_stage = stage;
    observe_returns_locked();
    pthread_mutex_unlock(&observation_lock);
    uint32_t values[3] = {0};
    int read_rc[3];
    char page_rows[TEST_TARGETS][384];
    unsigned ok_pages = 0;
    int ok = !calls(256);
    int patched = ctx.hooked && !ctx.overlaid;
    for (unsigned m = 0; m < 3; ++m)
        read_rc[m] = crc_channel(m, code, code_size, &values[m]);
    int readable = !read_rc[0] && !read_rc[1] && !read_rc[2];
    int equal = readable && values[0] == values[1] && values[0] == values[2];
    int crc_ok = equal && (patched ? values[0] != ctx.baseline_crc : values[0] == ctx.baseline_crc);
    ok &= crc_ok;
    for (unsigned i = 0; i < TEST_TARGETS; ++i) {
        uint32_t v[3] = {0};
        int page_ok = 1, page_readable = 1;
        for (unsigned m = 0; m < 3; ++m)
            if (crc_channel(m, pages[i], page_size, &v[m])) page_readable = 0;
        page_ok = page_readable;
        if (v[0] != v[1] || v[0] != v[2] ||
            (patched ? v[0] == page_crc[i] : v[0] != page_crc[i])) page_ok = 0;
        if (page_ok) ok_pages++;
        snprintf(page_rows[i], sizeof(page_rows[i]),
                 "PAGE stage=%s index=%u baseline=%08x direct=%08x readv=%08x proc=%08x integrity=%s result=%s",
                 stage, i, page_crc[i], v[0], v[1], v[2],
                 !page_readable ? "ERROR" : v[0] != v[1] || v[0] != v[2] ? "DIVERGED" :
                 v[0] == page_crc[i] ? "MATCH" : "CHANGED", page_ok ? "PASS" : "FAIL");
        report("%s", page_rows[i]);
    }
    if (__atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE)) {
        if (action(INSPECT)) ok = 0;
        if (ctx.overlaid && (ctx.armed != TEST_TARGETS || ctx.registered_pages != TEST_TARGETS ||
                            !ctx.overlay_hits || ctx.overlay_failures)) ok = 0;
    }
    ok &= ok_pages == TEST_TARGETS;
    char summary[512];
    snprintf(summary, sizeof(summary),
             "CRC stage=%s baseline=%08x direct=%08x readv=%08x proc=%08x integrity=%s expected=%s result=%s pages=%u/10",
             stage, ctx.baseline_crc, values[0], values[1], values[2],
             !readable ? "ERROR" : !equal ? "DIVERGED" : values[0] == ctx.baseline_crc ? "MATCH" : "CHANGED",
             patched ? "CHANGED" : "MATCH", crc_ok && ok_pages == TEST_TARGETS ? "PASS" : "FAIL", ok_pages);
    report("%s", summary);
    pthread_mutex_lock(&log_lock);
    if (ctx.overlaid) snprintf(overlay_crc_snapshot, sizeof(overlay_crc_snapshot), "OVERLAY_%s", summary);
    size_t used = (size_t)snprintf(crc_snapshot, sizeof(crc_snapshot), "%s\n", summary);
    for (unsigned i = 0; i < TEST_TARGETS; ++i)
        used += (size_t)snprintf(crc_snapshot + used, sizeof(crc_snapshot) - used, "%s\n", page_rows[i]);
    snprintf(crc_snapshot + used, sizeof(crc_snapshot) - used, "%s\n", overlay_crc_snapshot);
    pthread_mutex_unlock(&log_lock);
    report("STAGE %s %s hooked=%d overlay=%d pages_ok=%u/10 calls=2560 crc=%08x/%08x/%08x armed=%u registered=%u hits=%llu failures=%llu",
           stage, ok ? "PASS" : "FAIL", ctx.hooked, ctx.overlaid, ok_pages,
           values[0], values[1], values[2], ctx.armed, ctx.registered_pages,
           (unsigned long long)ctx.overlay_hits, (unsigned long long)ctx.overlay_failures);
    return require(ok, stage);
}
static int compare_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static int benchmark(const char *stage, uint32_t expected, struct timing *out)
{
    double samples[3][SAMPLES];
    memset(out, 0, sizeof(*out));
    for (unsigned r = 0; r < WARMUP + SAMPLES; ++r) {
        for (unsigned j = 0; j < 3; ++j) {
            unsigned m = (r + j) % 3;
            uint32_t value = 0;
            pthread_mutex_lock(&observation_lock);
            uint64_t start = now_ns();
            int rc = crc_channel(m, code, code_size, &value);
            uint64_t elapsed = now_ns() - start;
            pthread_mutex_unlock(&observation_lock);
            if (rc || value != expected)
                report("CRC FAIL stage=%s channel=%u expected=%08x actual=%08x rc=%d", stage, m, expected, value, rc);
            if (require(!rc && value == expected, "benchmark CRC validated on EVERY sample")) return -1;
            if (r >= WARMUP) samples[m][r - WARMUP] = elapsed / 1000.0;
            observe_if_due();
        }
    }
    for (unsigned m = 0; m < 3; ++m) {
        qsort(samples[m], SAMPLES, sizeof(double), compare_double);
        out->median[m] = samples[m][SAMPLES / 2];
    }
    return 0;
}
static void comparison(const char *label, const struct timing *before, const struct timing *after)
{
    char line[512];
    snprintf(line, sizeof(line), "TIME compare=%s direct_us=%.1f/%.1f readv_us=%.1f/%.1f proc_us=%.1f/%.1f",
             label, before->median[0], after->median[0], before->median[1], after->median[1],
             before->median[2], after->median[2]);
    report("%s", line);
    if (!strcmp(label, "hooked_uncovered_to_overlay") || !strcmp(label, "module_absent_to_overlay")) {
        pthread_mutex_lock(&log_lock);
        snprintf(timing_snapshot, sizeof(timing_snapshot), "%s", line);
        pthread_mutex_unlock(&log_lock);
    }
}
struct stress_arg { unsigned id, failed, scans, invocations; };
static int stress_start;
static void *stress_thread(void *opaque)
{
    struct stress_arg *a = opaque;
    while (!__atomic_load_n(&stress_start, __ATOMIC_ACQUIRE)) usleep(1000);
    for (unsigned r = 0; r < STRESS_ROUNDS; ++r) {
        if (calls(64)) a->failed++;
        a->invocations += 64 * TEST_TARGETS;
        for (unsigned j = 0; j < 3; ++j) {
            uint32_t value = 0;
            unsigned m = (a->id + r + j) % 3;
            if (crc_channel(m, code, code_size, &value) || value != ctx.baseline_crc) a->failed++;
            a->scans++;
        }
    }
    return NULL;
}
static int stress(void)
{
    pthread_t threads[THREADS];
    struct stress_arg args[THREADS] = {{0}};
    unsigned created = 0, bad = 0, scans = 0, invocations = 0;
    __atomic_store_n(&stress_start, 0, __ATOMIC_RELAXED);
    for (; created < THREADS; ++created) {
        args[created].id = created;
        if (pthread_create(&threads[created], NULL, stress_thread, &args[created])) break;
    }
    uint64_t start = now_ns();
    __atomic_store_n(&stress_start, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
        bad += args[i].failed; scans += args[i].scans; invocations += args[i].invocations;
    }
    int rc = action(INSPECT);
    report("STRESS %s threads=%u rounds=%d crc_scans=%u calls=%u mismatches=%u elapsed_ms=%.3f armed=%u hits=%llu failures=%llu",
           !bad && !rc && created == THREADS && !ctx.overlay_failures && ctx.armed == TEST_TARGETS ? "PASS" : "FAIL",
           created, STRESS_ROUNDS, scans, invocations, bad, (now_ns() - start) / 1000000.0,
           ctx.armed, (unsigned long long)ctx.overlay_hits, (unsigned long long)ctx.overlay_failures);
    return require(!bad && !rc && created == THREADS && !ctx.overlay_failures && ctx.armed == TEST_TARGETS, "concurrent CRC and calls");
}
static int suite(const char *key, const char *libdir, const char *backend, unsigned cycles)
{
    struct timing absent = {0}, loaded, off, on, restored;
    pthread_t worker, observation_thread;
    int worker_started = 0, observer_started = 0, safe = 1, rc = -1;
    char state[8192] = {0};
    report("RUN backend=%s cycles=%u module_key=MD5(urov-lab)=%s", backend, cycles, UROV_TEST_KEY);
    report("METHOD CRC32 whole RX; direct=LD1+IEEE, readv/proc=zlib; TIME=median us before/after (2 warmups, 9 samples); RETURN=1s real calls, deferred during transitions/timed reads.");
    if (setup()) goto finish;
    if (pthread_create(&observation_thread, NULL, observer, NULL)) goto finish;
    observer_started = 1;
    if (test_kpatch(key, "num", NULL, state, sizeof(state))) {
        report("ROOT FAIL cannot execute authenticated kpatch helper; check device superkey/path.");
        goto finish;
    }
    char *end;
    long modules = strtol(state, &end, 10);
    if (end == state || modules < 0) goto finish;
    if (modules == 0) {
        if (check_stage("module_absent") || benchmark("module_absent", ctx.baseline_crc, &absent)) goto finish;
        report("MODULE loading /data/local/tmp/urov-z.kpm with fixed project MD5 key");
        if (test_kpatch(key, "load", "/data/local/tmp/urov-z.kpm", state, sizeof(state))) {
            report("MODULE LOAD FAIL %s", state); goto finish;
        }
    } else {
        report("module_absent=SKIP already loaded; using loaded/inactive vs active paired comparison. No hot unload.");
    }
    struct urov_client client;
    struct urov_info info;
    if (urov_client_init(&client, UROV_TEST_KEY) || urov_query(&client, &info)) {
        report("MODULE AUTH FAIL expected fixed MD5 key; replace an incompatible loaded KPM after controlled reboot.");
        goto finish;
    }
    if (ctl(key, "status", state) || require(strstr(state, "state=inactive") != NULL &&
        strstr(state, "loader=kclf-1.5.7") != NULL, "integrated module inactive")) goto finish;
    report("MODULE %s", state);
    if (ctl(key, "kclf,reap", state) || ctl(key, "kclf,status", state) ||
        require(strstr(state, "no requests") != NULL, "no outstanding injection requests")) goto finish;
    if (check_stage("loaded_inactive") || benchmark("loaded_inactive", ctx.baseline_crc, &loaded)) goto finish;
    if (modules == 0) comparison("module_absent_to_loaded_inactive", &absent, &loaded);
    if (pthread_create(&worker, NULL, cooperative, NULL)) goto finish;
    worker_started = 1;
    while (!__atomic_load_n(&ctx.tid, __ATOMIC_ACQUIRE)) usleep(1000);
    safe = 0;
    if (inject(key, libdir, backend, 0)) goto finish;
    safe = 1;
    if (require(__atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE) && ctx.cookie == PAYLOAD_COOKIE &&
                ctx.constructors == 1, "payload constructor and action published once")) goto finish;
    for (unsigned cycle = 1; cycle <= cycles; ++cycle) {
        report("CYCLE %u/%u", cycle, cycles);
        if (action(HOOK) || require(ctx.hooked == TEST_TARGETS, "all ten Dobby hooks installed") || check_stage("hooked_uncovered")) goto finish;
        patched_crc = direct_crc();
        if (benchmark("hooked_uncovered", patched_crc, &off) || action(OVERLAY) ||
            require(ctx.overlaid && ctx.armed == TEST_TARGETS, "all ten pages armed") || check_stage("overlay")) goto finish;
        if (benchmark("overlay", ctx.baseline_crc, &on)) goto finish;
        comparison("hooked_uncovered_to_overlay", &off, &on);
        if (modules == 0 && cycle == 1) comparison("module_absent_to_overlay", &absent, &on);
        if (stress()) goto finish;
        unsigned constructors = __atomic_load_n(&ctx.probe_constructors, __ATOMIC_ACQUIRE);
        safe = 0;
        if (inject(key, libdir, backend, 1)) goto finish;
        safe = 1;
        if (require(__atomic_load_n(&ctx.probe_constructors, __ATOMIC_ACQUIRE) == constructors + 1 &&
                    ctx.probe_ok == TEST_TARGETS && ctx.probe_crc == ctx.baseline_crc,
                    "new injected SO sees original CRC and ten hooked returns")) goto finish;
        report("PROBE PASS constructors=%u functions=%u/10 crc=%08x", ctx.probe_constructors, ctx.probe_ok, ctx.probe_crc);
        if (action(DEACTIVATE) || check_stage("deactivated") || benchmark("deactivated", patched_crc, &restored)) goto finish;
        comparison("deactivated_to_overlay", &restored, &on);
        if (action(UNHOOK) || require(!ctx.hooked && !ctx.overlaid, "all hooks removed") || check_stage("unhooked")) goto finish;
    }
    rc = 0;
finish:
    if (observer_started) {
        __atomic_store_n(&stop_observer, 1, __ATOMIC_RELEASE);
        pthread_join(observation_thread, NULL);
    }
    failures += return_failures;
    safe = safe && !action_timed_out;
    if (worker_started && safe && __atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE)) {
        int inspect = action(INSPECT);
        int deactivate = inspect || ctx.overlaid ? action(DEACTIVATE) : 0;
        int unhook = deactivate ? -EBUSY : action(UNHOOK);
        report("CLEANUP inspect=%d deactivate=%d unhook=%d hooked=%d overlay=%d", inspect, deactivate, unhook, ctx.hooked, ctx.overlaid);
        if (deactivate || unhook || ctx.hooked || ctx.overlaid) rc = -1;
    }
    if (worker_started && safe && !action_timed_out) {
        __atomic_store_n(&stop_worker, 1, __ATOMIC_RELEASE);
        pthread_join(worker, NULL);
    }
    if (!rc && (ctl(key, "status", state) || !strstr(state, "state=inactive"))) rc = -1;
    if (!rc) report("FINAL MODULE %s", state);
    if (!rc && (ctl(key, "kclf,reap", state) || ctl(key, "kclf,status", state) || !strstr(state, "no requests"))) rc = -1;
    report("RESULT %s backend=%s cycles=%u targets=10 distinct_pages=10 assertions_failed=%u",
           !rc && !failures ? "PASS" : "FAIL", backend, cycles, failures);
    return rc || failures ? -1 : 0;
}
JNIEXPORT jint JNICALL Java_com_example_urovzinject_RunnerService_runNative(
    JNIEnv *env, jclass cls, jstring key, jstring libdir, jstring backend, jint cycles)
{
    (void)cls;
    if (__atomic_exchange_n(&used_process, 1, __ATOMIC_ACQ_REL)) return -EBUSY;
    if (!key || !libdir || !backend || cycles < 1 || cycles > 20) return -EINVAL;
    const char *k = (*env)->GetStringUTFChars(env, key, NULL);
    const char *l = (*env)->GetStringUTFChars(env, libdir, NULL);
    const char *b = (*env)->GetStringUTFChars(env, backend, NULL);
    int rc = -EINVAL;
    if (k && l && b && (!strcmp(b, "manual") || !strcmp(b, "linker"))) rc = suite(k, l, b, (unsigned)cycles);
    if (b) (*env)->ReleaseStringUTFChars(env, backend, b);
    if (l) (*env)->ReleaseStringUTFChars(env, libdir, l);
    if (k) (*env)->ReleaseStringUTFChars(env, key, k);
    return rc;
}
JNIEXPORT jobjectArray JNICALL Java_com_example_urovzinject_RunnerService_snapshotNative(JNIEnv *env, jclass cls)
{
    (void)cls;
    jclass string_class = (*env)->FindClass(env, "java/lang/String");
    if (!string_class) return NULL;
    jobjectArray result = (*env)->NewObjectArray(env, 4, string_class, NULL);
    (*env)->DeleteLocalRef(env, string_class);
    if (!result) return NULL;
    const char *snapshots[] = {output, crc_snapshot, return_snapshot, timing_snapshot};
    pthread_mutex_lock(&log_lock);
    for (unsigned i = 0; i < 4; ++i) {
        jstring text = (*env)->NewStringUTF(env, snapshots[i]);
        if (!text) break;
        (*env)->SetObjectArrayElement(env, result, (jsize)i, text);
        (*env)->DeleteLocalRef(env, text);
    }
    pthread_mutex_unlock(&log_lock);
    return result;
}
