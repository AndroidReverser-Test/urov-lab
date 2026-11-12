/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "shared.h"
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

extern int uz_test_target(int, int);
extern int uz_test_sleep(const struct timespec *);
static struct test_context ctx;
static const unsigned char *code;
static size_t code_size;
static int started;

__attribute__((visibility("hidden"), noinline))
int uz_test_impl(int a, int b)
{
    ctx.seen_a = a;
    ctx.seen_b = b;
    return a * 7 + b;
}

/* CRC covers the host's entire executable PT_LOAD, including the fixture.
 * Volatile byte loads prevent constant folding and exercise actual EL0 reads. */
static uint32_t direct_crc(void)
{
    uint32_t crc = ~0U;
    const volatile unsigned char *p = code;
    for (size_t i = 0; i < code_size; ++i) {
        crc ^= p[i];
        for (unsigned b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

static int find_code(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    (void)data;
    if (!strstr(info->dlpi_name, "/libuzhost.so")) return 0;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) {
            /* The controlled fixture links exactly one executable segment. */
            if (code) return -1;
            code = (const unsigned char *)(info->dlpi_addr + p->p_vaddr);
            code_size = p->p_memsz;
        }
    }
    return 1;
}

static int remote_crc(int proc_mem, uint32_t *out)
{
    unsigned char buffer[4096];
    uint32_t crc = crc32(0, NULL, 0);
    int fd = proc_mem ? open("/proc/self/mem", O_RDONLY | O_CLOEXEC) : -1;
    if (proc_mem && fd < 0) return -1;
    for (size_t off = 0; off < code_size;) {
        size_t n = code_size - off;
        if (n > sizeof(buffer)) n = sizeof(buffer);
        ssize_t got;
        if (proc_mem) got = pread64(fd, buffer, n, (off64_t)(uintptr_t)(code + off));
        else {
            struct iovec local = {buffer, n}, remote = {(void *)(code + off), n};
            got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        }
        if (got != (ssize_t)n) { if (fd >= 0) close(fd); return -1; }
        crc = crc32(crc, buffer, (uInt)n);
        off += n;
    }
    if (fd >= 0) close(fd);
    *out = crc;
    return 0;
}

static void report(unsigned sequence, const char *stage, int action_rc)
{
    uint32_t direct = direct_crc(), readv = 0, proc = 0;
    int readv_rc = remote_crc(0, &readv), proc_rc = remote_crc(1, &proc);
    int result = 0, calls_ok = 1;
    for (int i = 0; i < 256; ++i) {
        result = ctx.target(3, 4);
        if (result != (ctx.hooked ? 1103 : 25) ||
            ctx.seen_a != (ctx.hooked ? 13 : 3) || ctx.seen_b != (ctx.hooked ? 12 : 4)) calls_ok = 0;
        if (ctx.hooked && ctx.original_result != 103) calls_ok = 0;
    }
    int (*action)(int) = __atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE);
    int inspect_rc = action ? action(INSPECT) : 0;
    int crc_ok = (ctx.hooked && !ctx.overlaid) ? direct != ctx.baseline_crc : direct == ctx.baseline_crc;
    int pass = !action_rc && !inspect_rc && !readv_rc && !proc_rc && calls_ok && crc_ok &&
        direct == readv && direct == proc && (!ctx.overlaid || (ctx.armed && ctx.overlay_hits && !ctx.overlay_failures));
    FILE *f = fopen(TEST_DIR "/report.tmp", "w");
    if (!f) return;
    fprintf(f, "sequence=%u stage=%s result=%s rc=%d inspect_rc=%d\n"
        "pid=%d tid=%d code=%p bytes=%zu target=%p\n"
        "cookie=%llx constructors=%u hooked=%d overlay=%d\n"
        "input=3,4 observed=%d,%d original_return=%d return=%d calls=256 calls_ok=%d\n"
        "baseline_crc=%08x direct_crc=%08x readv_crc=%08x proc_crc=%08x readv_rc=%d proc_rc=%d\n"
        "hits=%llu failures=%llu armed=%u probe_constructors=%u probe_crc=%08x probe_return=%d\n",
        sequence, stage, pass ? "PASS" : "FAIL", action_rc, inspect_rc,
        ctx.pid, ctx.tid, code, code_size, (void *)ctx.target,
        (unsigned long long)ctx.cookie, ctx.constructors, ctx.hooked, ctx.overlaid,
        ctx.seen_a, ctx.seen_b, ctx.original_result, result, calls_ok,
        ctx.baseline_crc, direct, readv, proc, readv_rc, proc_rc,
        (unsigned long long)ctx.overlay_hits, (unsigned long long)ctx.overlay_failures,
        ctx.armed, ctx.probe_constructors, ctx.probe_crc, ctx.probe_result);
    fclose(f);
    rename(TEST_DIR "/report.tmp", TEST_DIR "/report.txt");
}

static void *worker(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "uz-inject");
    ctx.tid = (int)syscall(SYS_gettid);
    ctx.baseline_crc = direct_crc();
    report(0, "baseline", 0);
    FILE *f = fopen(TEST_DIR "/context.txt", "w");
    if (f) { fprintf(f, "%llx\n", (unsigned long long)(uintptr_t)&ctx); fclose(f); }
    unsigned last = 0;
    const struct timespec delay = {0, 100000000};
    for (;;) {
        uz_test_sleep(&delay);
        f = fopen(TEST_DIR "/command.txt", "r");
        if (!f) continue;
        unsigned sequence = 0;
        int command = -1;
        int n = fscanf(f, "%u %d", &sequence, &command);
        fclose(f);
        if (n != 2 || sequence <= last || command < INSPECT || command > UNHOOK) continue;
        last = sequence;
        int (*action)(int) = __atomic_load_n(&ctx.action, __ATOMIC_ACQUIRE);
        int rc = action ? action(command) : -2;
        static const char *names[] = {"inspect", "hook", "overlay", "deactivate", "unhook"};
        report(sequence, names[command], rc);
    }
    return NULL;
}

JNIEXPORT jint JNICALL Java_com_example_urovzinject_MainActivity_startNative(JNIEnv *env, jclass cls, jstring key)
{
    (void)cls;
    if (started) return 0;
    const char *text = (*env)->GetStringUTFChars(env, key, NULL);
    if (!text) return -1;
    if (strlen(text) != 32) { (*env)->ReleaseStringUTFChars(env, key, text); return -2; }
    memcpy(ctx.key, text, 33);
    (*env)->ReleaseStringUTFChars(env, key, text);
    if (dl_iterate_phdr(find_code, NULL) != 1 || !code || !code_size || code_size > (1U << 20) ||
        (uintptr_t)uz_test_target < (uintptr_t)code ||
        (uintptr_t)uz_test_target + 64 > (uintptr_t)code + code_size) return -3;
    ctx.magic = TEST_MAGIC;
    ctx.pid = getpid();
    ctx.target = uz_test_target;
    ctx.direct_crc = direct_crc;
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, worker, NULL);
    if (!rc) { started = 1; pthread_detach(thread); }
    return rc;
}
