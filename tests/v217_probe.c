/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * urov-y 2.17.0 device probe: one mode per process.
 *
 *   v217_probe <key> store|atomic|fork|gup|remap [iterations]
 *
 * The probe registers its own file-backed RX page of this executable and then
 * exercises one of the residual-feature paths.  It is fixture code: the key is
 * only used for REGISTER/SET/STATUS/DEACTIVATE, never by a detector.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "urov_x_abi.h"
#include "urov_y_abi.h"

#define PAGE 4096U

static unsigned g_checks, g_fail;

static unsigned first_diff(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) if (a[i] != b[i]) return (unsigned)i;
    return (unsigned)n;
}
#define CHECK(c, ...) do { ++g_checks; if (!(c)) { ++g_fail; \
    printf("FAIL " __VA_ARGS__); printf("\n"); } } while (0)

struct ctx {
    struct urov_x_keys keys;
};

static int ctx_init(struct ctx *c, const char *hex)
{
    uint8_t key[16];
    memset(c, 0, sizeof(*c));
    if (urov_x_parse_key(hex, (unsigned)strlen(hex), key)) return -1;
    urov_x_derive(key, &c->keys);
    memset(key, 0, sizeof(key));
    return 0;
}

static struct urov_y_request req(unsigned op)
{
    struct urov_y_request q;
    memset(&q, 0, sizeof(q));
    q.size = (uint32_t)sizeof(q);
    q.version = UROV_Y_ABI_VERSION;
    q.op = (uint16_t)op;
    q.request_id = UINT64_C(0x55524f56594c4142);
    return q;
}

static long ctl(const struct ctx *c, unsigned op, struct urov_y_request *q)
{
    q->size = (uint32_t)sizeof(*q);
    q->version = UROV_Y_ABI_VERSION;
    q->op = (uint16_t)op;
    q->mac = urov_y_request_mac(c->keys.mac, q);
    return syscall(__NR_prctl, (long)c->keys.option, (long)UROV_Y_PRCTL_MAGIC,
                   (long)op, q, (long)sizeof(*q));
}

static long reg_page(const struct ctx *c, void *page, const uint8_t *image,
                     uint64_t *generation)
{
    struct urov_y_request q = req(UROV_Y_REGISTER);
    long rc;

    q.address = (uintptr_t)page;
    q.length = PAGE;
    q.fake_addr = (uintptr_t)image;
    q.mode = UROV_Y_MODE_PAGE_AP;
    rc = ctl(c, UROV_Y_REGISTER, &q);
    if (!rc) *generation = q.generation;
    return rc;
}

static long set_image(const struct ctx *c, uint64_t generation, const uint8_t *image)
{
    struct urov_y_request q = req(UROV_Y_SET);
    q.session = 1;
    q.expected_generation = generation;
    q.length = PAGE;
    q.fake_addr = (uintptr_t)image;
    return ctl(c, UROV_Y_SET, &q);
}

static int status(const struct ctx *c, struct urov_y_request *out)
{
    struct urov_y_request q = req(UROV_Y_STATUS);
    q.session = 1;
    if (ctl(c, UROV_Y_STATUS, &q)) return -1;
    *out = q;
    return 0;
}

static long deactivate(const struct ctx *c)
{
    struct urov_y_request q = req(UROV_Y_DEACTIVATE);
    q.session = 1;
    return ctl(c, UROV_Y_DEACTIVATE, &q);
}

static void copy_scalar(uint8_t *out, const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; ++i) {
        uint32_t v;
        __asm__ volatile("ldrb %w0, [%1]" : "=r"(v) : "r"(p + i) : "memory");
        out[i] = (uint8_t)v;
    }
}

static int read_file_page(int fd, off_t off, uint8_t *out)
{
    ssize_t got = pread(fd, out, PAGE, off);
    return got == (ssize_t)PAGE ? 0 : -1;
}

/* vmsplice() reads the live page through GUP; the overlay must serve image. */
static int read_pipe(const void *source, uint8_t *out, size_t n)
{
    int fds[2];
    struct iovec iov;
    ssize_t got;

    if (pipe2(fds, O_CLOEXEC)) return -1;
    iov.iov_base = (void *)source;
    iov.iov_len = n;
    got = vmsplice(fds[1], &iov, 1, 0);
    if (got == (ssize_t)n) got = read(fds[0], out, n);
    close(fds[1]);
    close(fds[0]);
    return got == (ssize_t)n ? 0 : -1;
}

static int read_mem(const void *source, uint8_t *out, size_t n)
{
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    ssize_t got;

    if (fd < 0) return -1;
    got = pread(fd, out, n, (off_t)(uintptr_t)source);
    close(fd);
    return got == (ssize_t)n ? 0 : -1;
}

static int read_readv(const void *source, uint8_t *out, size_t n)
{
    struct iovec l, r;
    ssize_t got;

    l.iov_base = out;
    l.iov_len = n;
    r.iov_base = (void *)source;
    r.iov_len = n;
    got = syscall(__NR_process_vm_readv, getpid(), &l, 1UL, &r, 1UL, 0UL);
    return got == (ssize_t)n ? 0 : -1;
}

/* ST1 single-lane: a store the 2.16 decoder does not implement, so the module
 * has to let the hardware execute it and diff the page. */
static void lane_store(uint8_t *address)
{
    __asm__ volatile("movi v0.16b, #0x5a\n"
                     "st1 {v0.b}[3], [%0]\n"
                     :: "r"(address) : "v0", "memory");
}

struct add_work {
    uint8_t *address;
    unsigned count;
};

static void *add_thread(void *arg)
{
    struct add_work *w = arg;
    unsigned i;
    register uint64_t base asm("x9") = (uint64_t)w->address;

    /* ldadd x1, x2, [x9]: x1 is one, x2 receives the old value.  Encoded as
     * .inst so the test binary does not need -march=armv8.1-a. */
    for (i = 0; i < w->count; ++i)
        __asm__ volatile("mov x1, #1\n\t.inst 0xf8210122"
                         :: "r"(base) : "x1", "x2", "memory");
    return NULL;
}

static const char *own_path(void)
{
    static char path[512];
    ssize_t n;

    if (path[0]) return path;
    n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n <= 0) return "/proc/self/exe";
    path[n] = '\0';
    return path;
}

static void *map_own_page(int *fd, off_t off, int prot)
{
    void *p;

    *fd = open(own_path(), O_RDONLY | O_CLOEXEC);
    if (*fd < 0) return MAP_FAILED;
    p = mmap(NULL, PAGE, prot, MAP_PRIVATE, *fd, off);
    if (p == MAP_FAILED) { close(*fd); *fd = -1; }
    return p;
}

static int mode_store(const struct ctx *c)
{
    uint8_t file[PAGE], fake[PAGE], live[PAGE], view[PAGE], pipebuf[PAGE], membuf[PAGE], iovbuf[PAGE];
    struct urov_y_request st;
    uint64_t generation = 0;
    int fd = -1, rc = 1;
    uint8_t *page;

    page = map_own_page(&fd, 0, PROT_READ | PROT_EXEC);
    if (page == MAP_FAILED || read_file_page(fd, 0, file)) {
        printf("SKIP store: cannot map own page: %s\n", strerror(errno));
        return 0;
    }
    memcpy(fake, file, PAGE);
    fake[0] ^= 0xff;
    if (reg_page(c, page, fake, &generation)) {
        printf("SKIP store: register errno=%d\n", errno);
        goto out;
    }
    copy_scalar(view, page, 64);
    CHECK(!memcmp(view, fake, 64), "store clean read is not the image");
    if (mprotect(page, PAGE, PROT_READ | PROT_WRITE)) {
        printf("SKIP store: mprotect errno=%d\n", errno);
        goto deact;
    }
    lane_store(page + 8);
    memcpy(live, fake, PAGE);
    live[8] = 0x5a;
    copy_scalar(view, page, PAGE);
    CHECK(!memcmp(view, live, PAGE), "store replay read mismatch at %u view=%02x expect=%02x", first_diff(view, live, PAGE), view[first_diff(view, live, PAGE)], live[first_diff(view, live, PAGE)]);
    rc = read_pipe(page, pipebuf, PAGE);
    CHECK(!rc && !memcmp(pipebuf, live, PAGE), "store pipe view mismatch rc=%d", rc);
    rc = read_mem(page, membuf, PAGE);
    CHECK(!rc && !memcmp(membuf, live, PAGE), "store /proc/self/mem view mismatch rc=%d", rc);
    rc = read_readv(page, iovbuf, PAGE);
    CHECK(!rc && !memcmp(iovbuf, live, PAGE), "store process_vm_readv view mismatch rc=%d", rc);
    CHECK(!status(c, &st) && st.state == UROV_Y_ACTIVE && !st.failures,
          "store session state=%u failures=%llu", st.state, (unsigned long long)st.failures);
    printf("STORE replay view=%02x live=%02x active=%u armed=%llu\n", view[8], live[8], st.state, (unsigned long long)st.reserved);
deact:
    CHECK(!deactivate(c), "store deactivate errno=%d", errno);
    copy_scalar(view, page, PAGE);
    {
        uint8_t want[PAGE];

        memcpy(want, file, PAGE);
        want[8] = 0x5a;
        CHECK(!memcmp(view, want, PAGE), "store deactivated view mismatch");
    }
out:
    if (fd >= 0) close(fd);
    if (page != MAP_FAILED) munmap(page, PAGE);
    return g_fail ? 1 : 0;
}

static int mode_atomic(const struct ctx *c, unsigned iterations)
{
    enum { THREADS = 4 };
    pthread_t th[THREADS];
    struct add_work work;
    struct urov_y_request st;
    uint8_t fake[PAGE], view[PAGE];
    uint64_t generation = 0;
    uint64_t value = 0;
    uint8_t *page;
    int fd = -1, i;

    page = map_own_page(&fd, 0x1000, PROT_READ | PROT_EXEC);
    if (page == MAP_FAILED) {
        printf("SKIP atomic: map errno=%d\n", errno);
        return 0;
    }
    if (mprotect(page, PAGE, PROT_READ | PROT_WRITE)) {
        printf("SKIP atomic: mprotect errno=%d\n", errno);
        goto out;
    }
    *(uint64_t *)(page + 64) = 0;
    if (mprotect(page, PAGE, PROT_READ | PROT_EXEC)) goto out;
    copy_scalar(fake, page, PAGE);
    if (reg_page(c, page, fake, &generation)) {
        printf("SKIP atomic: register errno=%d\n", errno);
        goto out;
    }
    if (mprotect(page, PAGE, PROT_READ | PROT_WRITE)) goto deact;
    work.address = page + 64;
    work.count = iterations;
    for (i = 0; i < THREADS; ++i)
        pthread_create(&th[i], NULL, add_thread, &work);
    for (i = 0; i < THREADS; ++i) pthread_join(th[i], NULL);
    copy_scalar(view, page + 64, 8);
    memcpy(&value, view, 8);
    CHECK(value == (uint64_t)THREADS * iterations,
          "atomic overlay value=%llu expect=%u", (unsigned long long)value,
          THREADS * iterations);
    CHECK(!status(c, &st) && st.state == UROV_Y_ACTIVE && !st.failures,
          "atomic session state=%u failures=%llu", st.state, (unsigned long long)st.failures);
    printf("ATOMIC overlay=%llu expect=%u failures=%llu\n", (unsigned long long)value,
           THREADS * iterations, (unsigned long long)st.failures);
deact:
    CHECK(!deactivate(c), "atomic deactivate errno=%d", errno);
    copy_scalar(view, page + 64, 8);
    memcpy(&value, view, 8);
    CHECK(value == (uint64_t)THREADS * iterations,
          "atomic live value=%llu", (unsigned long long)value);
out:
    if (fd >= 0) close(fd);
    if (page != MAP_FAILED) munmap(page, PAGE);
    return g_fail ? 1 : 0;
}

static int mode_fork(const struct ctx *c)
{
    uint8_t file[PAGE], fake[PAGE], newer[PAGE], view[PAGE];
    uint64_t generation = 0;
    int fd = -1, pipefd[2];
    int status_code = 0;
    uint8_t *page;
    pid_t pid;

    page = map_own_page(&fd, 0x2000, PROT_READ | PROT_EXEC);
    if (page == MAP_FAILED || read_file_page(fd, 0x2000, file)) {
        printf("SKIP fork: map errno=%d\n", errno);
        return 0;
    }
    memcpy(fake, file, PAGE);
    fake[0] = 0xaa;
    if (reg_page(c, page, fake, &generation)) {
        printf("SKIP fork: register errno=%d\n", errno);
        goto out;
    }
    if (pipe(pipefd)) goto deact;
    pid = fork();
    if (pid == 0) {
        uint8_t child[PAGE], moved[PAGE];
        uint8_t *at;
        char byte;
        int fail = 0;

        close(pipefd[1]);
        copy_scalar(child, page, 8);
        dprintf(1, "CHILD first=%02x\n", child[0]);
        if (child[0] != 0xaa) fail |= 1;
        if (read(pipefd[0], &byte, 1) != 1) fail |= 2;
        /* The owner SET ran after fork; the child must keep the fork view. */
        copy_scalar(child, page, 8);
        dprintf(1, "CHILD after_set=%02x\n", child[0]);
        if (child[0] != 0xaa) fail |= 4;
        at = mremap(page, PAGE, PAGE, MREMAP_MAYMOVE);
        dprintf(1, "CHILD mremap rc=%p errno=%d\n", at, errno);
        if (at == MAP_FAILED) fail |= 8;
        else {
            copy_scalar(moved, at, 64);
            dprintf(1, "CHILD moved=%02x\n", moved[0]);
            if (moved[0] != 0xaa) fail |= 16;
            if (mprotect(at, PAGE, PROT_READ | PROT_WRITE)) {
                dprintf(1, "CHILD mprotect errno=%d\n", errno);
                fail |= 64;
            }
            at[32] = 0x77;
            copy_scalar(moved, at, 64);
            dprintf(1, "CHILD written=%02x\n", moved[32]);
            if (moved[0] != 0xaa || moved[32] != 0x77) fail |= 32;
        }
        close(pipefd[0]);
        dprintf(1, "CHILD fail=0x%x\n", fail);
        _exit(fail);
    }
    close(pipefd[0]);
    memcpy(newer, fake, PAGE);
    newer[0] = 0xbb;
    CHECK(!set_image(c, generation, newer), "fork owner SET errno=%d", errno);
    CHECK(write(pipefd[1], "x", 1) == 1, "fork release child");
    close(pipefd[1]);
    {
        int st = 0;

        waitpid(pid, &st, 0);
        status_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        if (!WIFEXITED(st)) dprintf(1, "FORK raw status=0x%x signal=%d\n", st, WTERMSIG(st));
    }
    CHECK(status_code == 0, "fork child failures=0x%x", status_code);
    copy_scalar(view, page, 64);
    CHECK(view[0] == 0xbb && view[32] == file[32],
          "fork owner view=%02x child_byte=%02x", view[0], view[32]);
    {
        struct urov_y_request st;

        CHECK(!status(c, &st) && st.state == UROV_Y_ACTIVE,
              "fork session state=%u", st.state);
        printf("FORK child=0x%x owner=0x%02x active=%u\n", status_code, view[0], st.state);
    }
deact:
    CHECK(!deactivate(c), "fork deactivate errno=%d", errno);
out:
    if (fd >= 0) close(fd);
    if (page != MAP_FAILED) munmap(page, PAGE);
    return g_fail ? 1 : 0;
}

static int mode_gup(const struct ctx *c)
{
    uint8_t file[PAGE], fake[PAGE], ref[PAGE], view[PAGE];
    uint64_t generation = 0;
    struct urov_y_request st;
    int fd = -1, direct = -1, rc;
    uint8_t *page;

    page = map_own_page(&fd, 0x3000, PROT_READ | PROT_EXEC);
    if (page == MAP_FAILED || read_file_page(fd, 0x3000, file)) {
        printf("SKIP gup: map errno=%d\n", errno);
        return 0;
    }
    memcpy(fake, file, PAGE);
    fake[0] ^= 0xff;
    if (reg_page(c, page, fake, &generation)) {
        printf("SKIP gup: register errno=%d\n", errno);
        goto out;
    }
    if (mprotect(page, PAGE, PROT_READ | PROT_WRITE)) {
        printf("SKIP gup: mprotect errno=%d\n", errno);
        goto deact;
    }
    dprintf(1, "GUP registered, mprotect ok\n");
    direct = open(own_path(), O_RDONLY | O_DIRECT | O_CLOEXEC);
    dprintf(1, "GUP O_DIRECT fd=%d errno=%d\n", direct, errno);
    if (direct < 0) {
        printf("SKIP gup: O_DIRECT open errno=%d\n", errno);
        goto deact;
    }
    rc = (int)pread(direct, page, PAGE, 0);
    dprintf(1, "GUP pread rc=%d errno=%d\n", rc, errno);
    if (rc != (int)PAGE) {
        printf("SKIP gup: O_DIRECT read rc=%d errno=%d\n", rc, errno);
        close(direct);
        goto deact;
    }
    close(direct);
    if (read_file_page(fd, 0, ref)) goto deact;
    copy_scalar(view, page, PAGE);
    CHECK(!memcmp(view, ref, PAGE), "gup FOLL_WRITE did not reach the live page");
    CHECK(!status(c, &st) && st.state == UROV_Y_ACTIVE,
          "gup session state=%u", st.state);
    printf("GUP live_matches_file=%d active=%u\n", !memcmp(view, ref, PAGE), st.state);
deact:
    CHECK(!deactivate(c), "gup deactivate errno=%d", errno);
out:
    if (fd >= 0) close(fd);
    if (page != MAP_FAILED) munmap(page, PAGE);
    return g_fail ? 1 : 0;
}

static int mode_remap(const struct ctx *c)
{
    uint8_t fake[PAGE], next[PAGE], view[PAGE];
    uint64_t generation = 0;
    struct urov_y_request st;
    int fd = -1, rc = 1;
    void *page;

    fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    page = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (page == MAP_FAILED) {
        printf("SKIP remap: mmap errno=%d\n", errno);
        goto out;
    }
    memset(fake, 0, PAGE);
    fake[0] = 0xdd;
    if (reg_page(c, page, fake, &generation)) {
        printf("SKIP remap: register errno=%d\n", errno);
        goto unmap;
    }
    copy_scalar(view, page, 8);
    CHECK(view[0] == 0xdd, "remap clean read=%02x", view[0]);
    rc = (int)syscall(__NR_remap_file_pages, page, PAGE, 0UL, 1UL, 0UL);
    /* This kernel's file VMA has no remap_pages op, so the call is rejected
     * after the module's gate.  The rejected call must leave the overlay
     * armed; 2.16 released the whole session before Linux answered. */
    CHECK(!status(c, &st) && st.state == UROV_Y_ACTIVE,
          "remap released the session rc=%d errno=%d state=%u", rc, errno, st.state);
    copy_scalar(view, page, PAGE);
    if (rc == 0) {
        if (read_file_page(fd, PAGE, next)) goto deact;
        CHECK(!memcmp(view, next, PAGE), "remap retired page did not become native");
        printf("REMAP rc=0 active=%u native=%d\n", st.state, !memcmp(view, next, PAGE));
    } else {
        CHECK(view[0] == 0xdd, "remap rejected call lost the overlay view=%02x", view[0]);
        printf("REMAP rc=%d errno=%d active=%u overlay=%02x\n", rc, errno, st.state, view[0]);
    }
deact:
    CHECK(!deactivate(c), "remap deactivate errno=%d", errno);
unmap:
    munmap(page, PAGE);
out:
    if (fd >= 0) close(fd);
    return g_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    struct ctx c;
    unsigned iterations = 500;
    int rc;

    if (argc < 3) {
        printf("usage: %s <key> store|atomic|fork|gup|remap [iterations]\n", argv[0]);
        return 2;
    }
    if (argc > 3) iterations = (unsigned)strtoul(argv[3], NULL, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    if (ctx_init(&c, argv[1])) {
        printf("bad key\n");
        return 2;
    }
    if (!strcmp(argv[2], "store")) rc = mode_store(&c);
    else if (!strcmp(argv[2], "atomic")) rc = mode_atomic(&c, iterations);
    else if (!strcmp(argv[2], "fork")) rc = mode_fork(&c);
    else if (!strcmp(argv[2], "gup")) rc = mode_gup(&c);
    else if (!strcmp(argv[2], "remap")) rc = mode_remap(&c);
    else { printf("unknown mode\n"); return 2; }
    printf("PROBE %s checks=%u failures=%u\n", argv[2], g_checks, g_fail);
    return rc;
}
