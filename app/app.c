/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>
#include "../module/abi.h"

extern int uz_fixture(void);
extern unsigned uz_self_read(const void *);
extern unsigned uz_read8(const void *);
extern uint64_t uz_read64(const void *);
extern void uz_read_pair(const void *, void *);
extern void uz_read_quad(const void *, void *);
extern void uz_read_ld2(const void *, void *);
extern void uz_read_ld4(const void *, void *);

struct test_context {
    struct uz_keys keys;
    uint64_t generation;
    unsigned caps;
    size_t page_size;
    unsigned char *target;
    char output[24576];
    size_t used;
    unsigned checks;
    unsigned failed;
};
static void report(struct test_context *t, const char *format, ...)
{
    char line[768];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    __android_log_write(ANDROID_LOG_INFO, "UROVZ", line);
    if (t->used < sizeof(t->output) - 1) {
        int n = snprintf(t->output + t->used, sizeof(t->output) - t->used, "%s\n", line);
        if (n > 0) {
            size_t available = sizeof(t->output) - t->used - 1;
            t->used += (size_t)n < available ? (size_t)n : available;
        }
    }
}
static struct urov_z_request request(unsigned op)
{
    struct urov_z_request q = {0};
    q.size = sizeof(q);
    q.version = UROV_Z_ABI_VERSION;
    q.op = (uint16_t)op;
    return q;
}
static long control(struct test_context *t, struct urov_z_request *q)
{
    struct urov_z_request input = *q;
    for (unsigned attempt = 0; attempt < 100; ++attempt) {
        struct urov_z_request wire = input;
        wire.mac = urov_z_request_mac(t->keys.mac, &wire);
        long ret = syscall(__NR_prctl, (unsigned long)t->keys.option,
                           (unsigned long)UROV_Z_PRCTL_MAGIC, (unsigned long)wire.op,
                           &wire, (unsigned long)sizeof(wire));
        if (ret < 0) ret = -errno;
        if (ret != -EBUSY) {
            *q = wire;
            return ret;
        }
        usleep(2000);
    }
    return -EBUSY;
}
static long deactivate(struct test_context *t)
{
    struct urov_z_request q = request(UROV_Z_DEACTIVATE);
    q.session = 1;
    return control(t, &q);
}
static long register_pages(struct test_context *t, struct uz_page_desc *d, unsigned count)
{
    struct urov_z_request q = request(UROV_Z_REGISTER);
    q.page_count = count;
    q.page_stride = sizeof(*d);
    q.pages_addr = (uintptr_t)d;
    long rc = control(t, &q);
    if (!rc) t->generation = q.generation;
    return rc;
}
static long set_page(struct test_context *t, unsigned index, const void *image)
{
    struct urov_z_request q = request(UROV_Z_SET_PAGE);
    q.session = 1;
    q.expected_generation = t->generation;
    q.reserved = index;
    q.fake_addr = (uintptr_t)image;
    q.length = (uint32_t)t->page_size;
    long rc = control(t, &q);
    if (!rc) t->generation = q.generation;
    return rc;
}
static int uniform(const unsigned char *bytes, size_t n, unsigned char expected)
{
    for (size_t i = 0; i < n; ++i)
        if (bytes[i] != expected) return 0;
    return 1;
}
static long self_readv(void *dst, const void *src, size_t bytes)
{
    struct iovec local = {dst, bytes}, remote = {(void *)src, bytes};
    return syscall(__NR_process_vm_readv, getpid(), &local, 1UL, &remote, 1UL, 0UL);
}
struct worker {
    const unsigned char *source;
    atomic_int stop;
    atomic_uint_fast64_t reads;
    atomic_uint_fast64_t errors;
    int use_readv;
};
static void *reader_thread(void *arg)
{
    struct worker *w = arg;
    while (!atomic_load_explicit(&w->stop, memory_order_acquire)) {
        unsigned char value[16];
        if (w->use_readv) {
            if (self_readv(value, w->source, sizeof(value)) != sizeof(value)) {
                atomic_fetch_add(&w->errors, 1);
                break;
            }
        } else {
            uz_read_pair(w->source, value);
        }
        if ((!uniform(value, sizeof(value), 0x6a)) &&
            (!uniform(value, sizeof(value), 0x44)) &&
            (!uniform(value, sizeof(value), 0x88)))
            atomic_fetch_add(&w->errors, 1);
        atomic_fetch_add(&w->reads, 1);
    }
    return NULL;
}
static int concurrency(struct test_context *t, unsigned char *image)
{
    struct worker w[2] = {
        {.source = t->target + 256},
        {.source = t->target + 256, .use_readv = !!(t->caps & UROV_Z_CAP_READV)},
    };
    pthread_t threads[2];
    unsigned created = 0;
    int good = 1;
    for (; created < 2; ++created) {
        if (pthread_create(&threads[created], NULL, reader_thread, &w[created])) {
            good = 0;
            break;
        }
    }
    usleep(10000);
    for (unsigned i = 0; good && i < 48; ++i) {
        memset(image, (i & 1U) ? 0x88 : 0x44, t->page_size);
        if (set_page(t, 0, image)) good = 0;
    }
    for (unsigned i = 0; i < created; ++i) atomic_store(&w[i].stop, 1);
    for (unsigned i = 0; i < created; ++i) pthread_join(threads[i], NULL);
    uint64_t reads = atomic_load(&w[0].reads) + atomic_load(&w[1].reads);
    uint64_t errors = atomic_load(&w[0].errors) + atomic_load(&w[1].errors);
    report(t, "CONCURRENCY updates=48 reads=%" PRIu64 " torn_or_failed=%" PRIu64, reads, errors);
    return good && reads && !errors;
}

#define CHECK(condition, name) do {     ++t->checks;     if (!(condition)) {         ++t->failed; report(t, "FAIL %s line=%d errno=%d", name, __LINE__, errno);         goto done;     }     report(t, "PASS %s", name); } while (0)

static void run_tests(struct test_context *t, const char *hex, int baseline)
{
    unsigned char key[16], sample[64];
    unsigned char *original = NULL, *image = NULL;
    unsigned char *base = (unsigned char *)(uintptr_t)uz_fixture;
    struct urov_z_request q;
    struct uz_page_desc d[2];
    struct utsname info;
    int memfd = -1, pipefd[2] = {-1, -1};
    int active = 0;
    uname(&info);
    t->page_size = (size_t)sysconf(_SC_PAGESIZE);
    t->target = base;
    report(t, "UROV-Z app uid=%u kernel=%s page_size=%zu", (unsigned)getuid(), info.release, t->page_size);
    {
        char domain[128] = {0};
        int fd = open("/proc/self/attr/current", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, domain, sizeof(domain) - 1);
            close(fd);
            if (n > 0) report(t, "SELinux %s", domain);
        }
    }
    CHECK(t->page_size == 4096 || t->page_size == 16384, "runtime page size");
    CHECK(((uintptr_t)base & (t->page_size - 1)) == 0, "aligned file-backed .text");
    CHECK(uz_fixture() == 1235, "baseline native execution");
    CHECK(uz_read8(base + 256) == 0x11, "baseline direct load");
    if (baseline) {
        CHECK(uz_self_read(base + 256) == 0x11, "baseline self-reading code");
        goto done;
    }
    CHECK(hex && !uz_parse_key(hex, (unsigned)strlen(hex), key), "module key format");
    uz_derive(key, &t->keys);
    memset(key, 0, sizeof(key));
    q = request(UROV_Z_QUERY);
    CHECK(!control(t, &q), "authenticated QUERY");
    t->caps = (unsigned)q.session_flags;
    report(t, "CAPS 0x%x max_pages=%u page_shift=%u ABI=%u size=%zu",
           t->caps, q.page_count, q.page_stride, q.version, sizeof(q));
    CHECK((t->caps & UROV_Z_CAP_PAGE_AP) && q.page_stride < 32 &&
          (1UL << q.page_stride) == t->page_size, "PAGE_AP capability and geometry");
    original = malloc(2 * t->page_size);
    image = malloc(2 * t->page_size);
    CHECK(original && image, "image buffers");
    memcpy(original, base, 2 * t->page_size);
    memset(image, 0x6a, t->page_size);
    memset(image + t->page_size, 0x7b, t->page_size);
    image[t->page_size - 1] = 0;
    for (unsigned i = 0; i < 2; ++i) {
        d[i] = (struct uz_page_desc){
            .base = (uintptr_t)(base + i * t->page_size),
            .fake_addr = (uintptr_t)(image + i * t->page_size),
            .fake_len = (uint32_t)t->page_size,
            .flags = UROV_Z_PAGE_SRC_USER,
        };
    }
    d[1].base = d[0].base;
    CHECK(register_pages(t, d, 2) == -EINVAL, "duplicate descriptor rejection");
    d[1].base = (uintptr_t)(base + t->page_size);
    d[0].fake_len = (uint32_t)t->page_size + 8U;
    CHECK(register_pages(t, d, 2) == -EINVAL, "oversize descriptor rejection");
    d[0].fake_len = (uint32_t)t->page_size;
    CHECK(!register_pages(t, d, 2), "REGISTER two .text pages");
    active = 1;
    CHECK(uz_fixture() == 1235, "original instructions execute under overlay");
    CHECK(uz_read8(base + 256) == 0x6a, "independent scalar caller");
    CHECK(uz_self_read(base + 256) == 0x6a, "reader instruction inside target page");
    CHECK(uz_read8(base + t->page_size + 256) == 0x7b, "second registered page");
    uz_read_pair(base + 256, sample);
    CHECK(uniform(sample, 16, 0x6a), "LDP pair");
    uz_read_pair(base + t->page_size - 8, sample);
    CHECK(!memcmp(sample, image + t->page_size - 8, 16), "cross-page pair");
    if (t->caps & UROV_Z_CAP_LD2) {
        uz_read_quad(base + 256, sample);
        CHECK(uniform(sample, 16, 0x6a), "FPSIMD LDR Q");
        uz_read_ld2(base + 256, sample);
        CHECK(uniform(sample, 32, 0x6a), "LD2 structures");
        uz_read_ld4(base + 256, sample);
        CHECK(uniform(sample, 64, 0x6a), "LD4 structures");
    } else report(t, "SKIP vector loads capability unavailable");
    memcpy(sample, base + 256, sizeof(sample));
    CHECK(uniform(sample, sizeof(sample), 0x6a), "libc memcpy all-callers");
    CHECK(!memcmp(base, image, 2 * t->page_size), "libc memcmp two full pages");
    CHECK(strlen((char *)base + 128) == t->page_size - 129, "libc strlen");
    CHECK(crc32(0, base, (uInt)(2 * t->page_size)) ==
          crc32(0, image, (uInt)(2 * t->page_size)), "libz CRC full pages");
    if (t->caps & UROV_Z_CAP_REMOTE_VM) {
        memfd = open("/proc/self/mem", O_RDONLY);
        CHECK(memfd >= 0, "open proc self mem");
        CHECK(pread(memfd, sample, 32, (off_t)(uintptr_t)(base + 256)) == 32 &&
              uniform(sample, 32, 0x6a), "proc self mem image");
    } else report(t, "SKIP remote VM capability unavailable");
    if (t->caps & UROV_Z_CAP_READV) {
        CHECK(self_readv(sample, base + 256, 32) == 32 &&
              uniform(sample, 32, 0x6a), "process_vm_readv image");
    } else report(t, "SKIP process_vm_readv capability unavailable");
    if (t->caps & UROV_Z_CAP_GUP) {
        CHECK(!pipe(pipefd), "vmsplice pipe");
        struct iovec vector = {base + 256, 32};
        CHECK(vmsplice(pipefd[1], &vector, 1, 0) == 32 &&
              read(pipefd[0], sample, 32) == 32 && uniform(sample, 32, 0x6a),
              "vmsplice image page");
        close(pipefd[0]); close(pipefd[1]);
        pipefd[0] = pipefd[1] = -1;
    } else report(t, "SKIP GUP capability unavailable");
    q = request(UROV_Z_SET_PAGE);
    q.session = 1;
    q.expected_generation = t->generation + 10;
    q.fake_addr = (uintptr_t)image;
    q.length = (uint32_t)t->page_size;
    CHECK(control(t, &q) == -EAGAIN && uz_read8(base + 256) == 0x6a,
          "stale generation rejected");
    CHECK(concurrency(t, image), "concurrent SET_PAGE with direct and readv readers");
    CHECK(uz_read8(base + 256) == 0x88, "latest image publication");
    CHECK(uz_read8(base + t->page_size + 256) == 0x7b, "SET_PAGE preserves other page");
    CHECK(!mprotect(base, t->page_size, PROT_READ), "mprotect read");
    CHECK(uz_read8(base + 256) == 0x88, "overlay after mprotect");
    CHECK(!mprotect(base, t->page_size, PROT_READ | PROT_EXEC), "mprotect RX");
    CHECK(uz_fixture() == 1235, "execute after protection restore");
    CHECK(!madvise(base, t->page_size, MADV_DONTNEED), "drop target PTE");
    CHECK(uz_read8(base + 256) == 0x88, "fault-in rearms PAGE_AP");
    if (t->caps & UROV_Z_CAP_FORK_SNAPSHOT) {
        CHECK(!pipe(pipefd), "fork synchronization pipe");
        pid_t child = fork();
        CHECK(child >= 0, "fork");
        if (!child) {
            unsigned char token;
            close(pipefd[1]);
            if (read(pipefd[0], &token, 1) != 1) _exit(30);
            pid_t nested = fork();
            if (!nested) _exit(32);
            int rejected = nested < 0 && errno == EOPNOTSUPP;
            if (nested > 0) waitpid(nested, NULL, 0);
            _exit(uz_read8(base + 256) == 0x88 && uz_fixture() == 1235 && rejected ? 0 : 31);
        }
        close(pipefd[0]); pipefd[0] = -1;
        int refused = deactivate(t) == -EBUSY;
        memset(image, 0x44, t->page_size);
        int updated = !set_page(t, 0, image);
        unsigned char token = 1;
        int released = write(pipefd[1], &token, 1) == 1;
        close(pipefd[1]); pipefd[1] = -1;
        int status = 0;
        int waited = waitpid(child, &status, 0) == child;
        report(t, "FORK status=%d deactivate_refused=%d updated=%d", status, refused, updated);
        CHECK(refused, "DEACTIVATE refuses a live child snapshot");
        CHECK(updated && released && waited && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0, "child snapshot isolation, execution and descendant guard");
    } else report(t, "SKIP fork snapshot capability unavailable");
    q = request(UROV_Z_STATUS);
    q.session = 1;
    CHECK(!control(t, &q) && q.state == UROV_Z_ACTIVE &&
          q.page_count == 2 && q.failures == 0, "active STATUS");
    report(t, "COUNTERS hits=%" PRIu64 " replay=%" PRIu64 " failures=%" PRIu64
           " generation=%" PRIu64, q.hits, q.replays, q.failures, q.generation);
    CHECK(!deactivate(t), "DEACTIVATE");
    active = 0;
    CHECK(!memcmp(base, original, 2 * t->page_size) && uz_fixture() == 1235,
          "original reads and execution restored");
    q = request(UROV_Z_REGISTER);
    q.address = (uintptr_t)base;
    q.offset = 256;
    q.length = 8;
    q.value = UINT64_C(0x123456789abcdef0);
    CHECK(!control(t, &q), "inline single-page REGISTER");
    active = 1;
    CHECK(uz_read64(base + 256) == UINT64_C(0x123456789abcdef0), "inline 64-bit value");
    q = request(UROV_Z_SET);
    q.session = 1;
    q.expected_generation = 1;
    q.length = 8;
    q.value = UINT64_C(0xfedcba9876543210);
    CHECK(!control(t, &q) && uz_read64(base + 256) == UINT64_C(0xfedcba9876543210),
          "inline SET generation");
done:
    if (active) {
        long rc = deactivate(t);
        report(t, "CLEANUP deactivate=%ld", rc);
        if (rc) ++t->failed;
    }
    if (memfd >= 0) close(memfd);
    for (unsigned i = 0; i < 2; ++i) if (pipefd[i] >= 0) close(pipefd[i]);
    free(original);
    free(image);
    report(t, "RESULT %s checks=%u failures=%u", t->failed ? "FAIL" : "PASS", t->checks, t->failed);
}
JNIEXPORT jstring JNICALL
Java_com_example_urovz_MainActivity_runNative(JNIEnv *env, jclass cls, jstring key, jboolean baseline)
{
    (void)cls;
    struct test_context *t = calloc(1, sizeof(*t));
    if (!t) return (*env)->NewStringUTF(env, "RESULT FAIL allocation");
    const char *hex = key ? (*env)->GetStringUTFChars(env, key, NULL) : NULL;
    run_tests(t, hex, baseline);
    if (hex) (*env)->ReleaseStringUTFChars(env, key, hex);
    jstring result = (*env)->NewStringUTF(env, t->output);
    memset(&t->keys, 0, sizeof(t->keys));
    free(t);
    return result;
}
