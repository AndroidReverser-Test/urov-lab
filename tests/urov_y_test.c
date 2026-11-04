/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Root acceptance test for urov-y (site-trap read overlay).
 *
 * The module must already be loaded with the same 32-hex key:
 *   kpatch <SUPERKEY> kpm load /data/local/tmp/urov-y.kpm "key=<key>"
 *
 * The test owns a sealed one-page RX file mapping (the immutable target) and a
 * private executable page in this binary that holds the reader sites.  The
 * overlay must be visible only through a registered business caller; a direct
 * call of the same site routine must return the file bytes, and the target
 * page must stay a completely ordinary readable mapping.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../urov_x_abi.h"
#include "../urov_y_abi.h"

#define PAGE 4096U
#define WIN 64U

static const uint64_t fake_a = UINT64_C(0x8877665544332211);
static const uint64_t fake_b = UINT64_C(0x0f0e0d0c0b0a0908);

__asm__(".pushsection .text.uy_sites,\"ax\",%progbits\n"
        ".p2align 12\n"
        ".global uy_site_ldr\n.type uy_site_ldr,%function\n"
        "uy_site_ldr:\n ldr x0, [x0]\n ret\n"
        ".size uy_site_ldr, .-uy_site_ldr\n"
        ".global uy_site_ldrb\n.type uy_site_ldrb,%function\n"
        "uy_site_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size uy_site_ldrb, .-uy_site_ldrb\n"
        ".global uy_business_ldr\n.type uy_business_ldr,%function\n"
        "uy_business_ldr:\n stp x29, x30, [sp, #-16]!\n mov x29, sp\n"
        " bl uy_site_ldr\n ldp x29, x30, [sp], #16\n ret\n"
        ".size uy_business_ldr, .-uy_business_ldr\n"
        ".global uy_business_ldr_end\nuy_business_ldr_end:\n"
        ".global uy_business_ldrb\n.type uy_business_ldrb,%function\n"
        "uy_business_ldrb:\n stp x29, x30, [sp, #-16]!\n mov x29, sp\n"
        " bl uy_site_ldrb\n ldp x29, x30, [sp], #16\n ret\n"
        ".size uy_business_ldrb, .-uy_business_ldrb\n"
        ".global uy_business_ldrb_end\nuy_business_ldrb_end:\n"
        ".popsection\n");

extern uint64_t uy_site_ldr(const void *p);
extern uint32_t uy_site_ldrb(const void *p);
extern uint64_t uy_business_ldr(const void *p);
extern uint32_t uy_business_ldrb(const void *p);
extern char uy_business_ldr_end[];
extern char uy_business_ldrb_end[];

static unsigned g_checks, g_fail;
static uint8_t g_source[PAGE];
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_sig;

#define CHECK(cond, ...) do { ++g_checks; if (!(cond)) { ++g_fail; \
    fprintf(stderr, "FAIL " __VA_ARGS__); fputc('\n', stderr); } } while (0)

static void sig_handler(int sig)
{
    g_sig = sig;
    siglongjmp(g_jmp, 1);
}

static uint64_t load64_scalar(const void *p)
{
    uint64_t v;
    __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

static uint32_t load32_scalar(const void *p)
{
    uint32_t v;
    __asm__ volatile("ldr %w0, [%1]" : "=r"(v) : "r"(p) : "memory");
    return v;
}

struct y_ctx {
    int have;
    struct urov_x_keys keys;
};

static int y_init_key(struct y_ctx *ctx, const char *hex)
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

static struct urov_y_request y_req(unsigned op)
{
    struct urov_y_request q;
    memset(&q, 0, sizeof(q));
    q.size = (uint32_t)sizeof(q);
    q.version = UROV_Y_ABI_VERSION;
    q.op = (uint16_t)op;
    q.request_id = UINT64_C(0x55524f56594c4142);
    return q;
}

static long y_control(const struct y_ctx *ctx, unsigned op, struct urov_y_request *q)
{
    q->size = (uint32_t)sizeof(*q);
    q->version = UROV_Y_ABI_VERSION;
    q->op = (uint16_t)op;
    q->mac = urov_y_request_mac(ctx->keys.mac, q);
    return syscall(__NR_prctl, (long)ctx->keys.option, (long)ctx->keys.magic,
                   (long)op, q, (long)sizeof(*q));
}

struct page {
    uint8_t *address;
    int fd;
};

static int page_open(struct page *p)
{
    char path[64];
    int fd, ro;
    unsigned i;

    memset(p, 0, sizeof(*p));
    p->fd = -1;
    for (i = 0; i < PAGE; ++i) g_source[i] = (uint8_t)(i * 37U + 11U);
    fd = memfd_create("urov-y-page", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) { perror("memfd_create"); return -1; }
    if (ftruncate(fd, PAGE)) { perror("ftruncate"); close(fd); return -1; }
    /* pwrite: a user-space memcpy into the shared page is unreliable in the
     * kpatch-su environment of this device, and the module must never depend
     * on how the frozen page was produced. */
    if (pwrite(fd, g_source, PAGE, 0) != (ssize_t)PAGE) {
        perror("pwrite");
        close(fd);
        return -1;
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
        perror("F_ADD_SEALS");
        close(fd);
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ro = open(path, O_RDONLY | O_CLOEXEC);
    if (ro < 0) { perror("open ro"); close(fd); return -1; }
    p->fd = open(path, O_RDONLY | O_CLOEXEC);
    p->address = mmap(NULL, PAGE, PROT_READ | PROT_EXEC, MAP_SHARED, ro, 0);
    close(ro);
    close(fd);
    if (p->address == MAP_FAILED || p->fd < 0) {
        if (p->address != MAP_FAILED) munmap(p->address, PAGE);
        if (p->fd >= 0) close(p->fd);
        p->address = NULL;
        p->fd = -1;
        return -1;
    }
    if (memcmp(p->address, g_source, PAGE)) {
        fprintf(stderr, "page content mismatch\n");
        munmap(p->address, PAGE);
        p->address = NULL;
        return -1;
    }
    return 0;
}
static void page_close(struct page *p)
{
    if (p->address) munmap(p->address, PAGE);
    if (p->fd >= 0) close(p->fd);
    p->address = NULL;
    p->fd = -1;
}

static long y_register(const struct y_ctx *ctx, const struct page *p,
                       uint64_t value, unsigned flags)
{
    struct urov_y_request q = y_req(UROV_Y_REGISTER);
    q.address = (uintptr_t)p->address;
    q.offset = WIN;
    q.length = 8;
    q.value = value;
    q.site_count = 2;
    q.sites[0] = (uint64_t)(uintptr_t)&uy_site_ldr;
    q.sites[1] = (uint64_t)(uintptr_t)&uy_site_ldrb;
    q.caller_count = 2;
    q.caller_start[0] = (uint64_t)(uintptr_t)&uy_business_ldr;
    q.caller_end[0] = (uint64_t)(uintptr_t)uy_business_ldr_end;
    q.caller_start[1] = (uint64_t)(uintptr_t)&uy_business_ldrb;
    q.caller_end[1] = (uint64_t)(uintptr_t)uy_business_ldrb_end;
    (void)flags;
    return y_control(ctx, UROV_Y_REGISTER, &q);
}

static int y_status(const struct y_ctx *ctx, struct urov_y_request *out)
{
    struct urov_y_request q = y_req(UROV_Y_STATUS);
    q.session = 1;
    if (y_control(ctx, UROV_Y_STATUS, &q)) return -1;
    *out = q;
    return 0;
}

static int y_set(const struct y_ctx *ctx, uint64_t generation, uint64_t value)
{
    struct urov_y_request q = y_req(UROV_Y_SET);
    q.session = 1;
    q.expected_generation = generation;
    q.length = 8;
    q.value = value;
    return (int)y_control(ctx, UROV_Y_SET, &q);
}

static int y_deactivate(const struct y_ctx *ctx)
{
    struct urov_y_request q = y_req(UROV_Y_DEACTIVATE);
    q.session = 1;
    return (int)y_control(ctx, UROV_Y_DEACTIVATE, &q);
}

static int run_clean(void)
{
    struct y_ctx ctx;
    struct urov_y_request q = y_req(UROV_Y_STATUS);
    long rc;

    memset(&ctx, 0, sizeof(ctx));
    memset(&ctx.keys, 0x5a, sizeof(ctx.keys));
    ctx.have = 1;
    errno = 0;
    rc = syscall(__NR_prctl, (long)ctx.keys.option, (long)ctx.keys.magic,
                 (long)UROV_Y_STATUS, &q, (long)sizeof(q));
    CHECK(rc == -1 && errno == EINVAL, "clean selector rc=%ld errno=%d", rc, errno);
    errno = 0;
    rc = syscall(__NR_prctl, 0x55524f56L, 0x55524f5653595343ULL, 1L, &q, 240L);
    CHECK(rc == -1 && errno == EINVAL, "legacy selector rc=%ld errno=%d", rc, errno);
    printf("%s cases=%u assertions=%u failures=%u\n",
           g_fail ? "FAIL" : "PASS", 1, g_checks, g_fail);
    return g_fail ? 1 : 0;
}

static int run_active(const char *key)
{
    struct y_ctx ctx;
    struct page p;
    uint64_t original, got;
    uint32_t st0;
    struct urov_y_request st;
    struct sigaction sa, old_segv;
    int rc;

    if (y_init_key(&ctx, key)) { fprintf(stderr, "bad key\n"); return 2; }
    if (page_open(&p)) { fprintf(stderr, "page open errno=%d\n", errno); return 2; }
    original = load64_scalar(p.address + WIN);
    st0 = load32_scalar((const void *)&uy_site_ldr);
    CHECK(original == load64_scalar(g_source + WIN), "source mismatch");
    CHECK(st0 == 0xf9400000U, "site opcode=%08x", st0);

    rc = y_register(&ctx, &p, fake_a, 0);
    CHECK(rc == 0, "REGISTER rc=%d errno=%d", rc, errno);

    got = uy_business_ldr(p.address + WIN);
    CHECK(got == fake_a, "business caller got=%llx", (unsigned long long)got);
    CHECK((uint32_t)uy_business_ldrb(p.address + WIN) == 0x11U,
          "business ldrb got=%02x", (unsigned)uy_business_ldrb(p.address + WIN));
    CHECK(uy_site_ldr(p.address + WIN) == original, "direct site diverged");
    CHECK((uint32_t)uy_site_ldrb(p.address + WIN) == g_source[WIN],
          "direct ldrb diverged");
    CHECK(uy_business_ldr(p.address + WIN + 64) == load64_scalar(g_source + WIN + 64),
          "outside window business diverged");
    CHECK(load64_scalar(p.address + WIN) == original, "plain native read diverged");

    rc = y_set(&ctx, 1, fake_b);
    CHECK(rc == 0, "SET rc=%d errno=%d", rc, errno);
    CHECK(uy_business_ldr(p.address + WIN) == fake_b, "business caller after SET");
    CHECK(uy_site_ldr(p.address + WIN) == original, "direct site after SET");
    CHECK(!y_status(&ctx, &st) && st.generation == 2 && st.state == UROV_Y_ACTIVE &&
          st.hits > 0 && st.replays > 0,
          "STATUS gen=%llu hits=%llu replays=%llu state=%u",
          (unsigned long long)st.generation, (unsigned long long)st.hits,
          (unsigned long long)st.replays, st.state);

    /* A load through the site from an unmapped address must still raise
     * SIGSEGV, like the original instruction would. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_segv);
    g_sig = 0;
    if (!sigsetjmp(g_jmp, 1)) {
        (void)uy_business_ldr((const void *)0x1000UL);
        CHECK(0, "unmapped site load did not fault");
    } else {
        CHECK(g_sig == SIGSEGV, "unmapped site load signal=%d", (int)g_sig);
    }
    sigaction(SIGSEGV, &old_segv, NULL);

    /* fork window: the child must inherit the original instruction, the parent
     * must keep the armed site. */
    {
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t child_business = uy_business_ldr(p.address + WIN);
            uint64_t child_direct = uy_site_ldr(p.address + WIN);
            _exit(child_business == original && child_direct == original ? 0 : 7);
        }
        CHECK(pid > 0, "fork pid=%d errno=%d", (int)pid, errno);
        if (pid > 0) {
            int status = 0;
            CHECK(waitpid(pid, &status, 0) == pid, "waitpid errno=%d", errno);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "child status=0x%x", status);
        }
        CHECK(uy_business_ldr(p.address + WIN) == fake_b, "parent site lost after fork");
        CHECK(uy_site_ldr(p.address + WIN) == original, "parent direct after fork");
    }

    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_ACTIVE && st.failures == 0,
          "STATUS before deactivate state=%u failures=%llu", st.state,
          (unsigned long long)st.failures);

    rc = y_deactivate(&ctx);
    CHECK(rc == 0, "DEACTIVATE rc=%d errno=%d", rc, errno);
    CHECK(uy_business_ldr(p.address + WIN) == original, "deactivated site not restored");
    CHECK(load32_scalar((const void *)&uy_site_ldr) == st0, "site opcode not restored");
    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_INACTIVE, "STATUS after deactivate");

    /* Mapping gate: a mapping change that overlaps the target page ends the
     * session silently and then behaves natively. */
    CHECK(y_register(&ctx, &p, fake_a, 0) == 0, "re-REGISTER failed");
    CHECK(uy_business_ldr(p.address + WIN) == fake_a, "re-registered site");
    errno = 0;
    rc = mprotect(p.address, PAGE, PROT_READ | PROT_EXEC);
    CHECK(rc == 0, "mprotect gate rc=%d errno=%d", rc, errno);
    CHECK(uy_business_ldr(p.address + WIN) == original, "mprotect did not restore");
    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_INACTIVE, "gate left session live");

    page_close(&p);
    printf("%s cases=%u assertions=%u failures=%u\n",
           g_fail ? "FAIL" : "PASS", 1, g_checks, g_fail);
    return g_fail ? 1 : 0;
}

/* Hold an active session while the harness unloads the module. The site keeps
 * being executed, so a module that failed to restore the original instruction
 * would SIGTRAP here instead of returning the file bytes. */
static int run_hold(const char *key)
{
    struct y_ctx ctx;
    struct page p;
    uint64_t original;
    int restored = 0;

    if (y_init_key(&ctx, key)) return 2;
    if (page_open(&p)) return 2;
    original = load64_scalar(g_source + WIN);
    if (y_register(&ctx, &p, fake_a, 0)) {
        fprintf(stderr, "hold REGISTER failed errno=%d\n", errno);
        return 1;
    }
    CHECK(uy_business_ldr(p.address + WIN) == fake_a, "hold site not armed");
    printf("HOLD_READY pid=%d uid=%d\n", (int)getpid(), (int)getuid());
    for (unsigned i = 0; i < 600; ++i) {
        struct urov_y_request st;
        uint64_t got;
        usleep(100000);
        got = uy_business_ldr(p.address + WIN);
        if (got == original) {
            uint32_t insn = load32_scalar((const void *)&uy_site_ldr);
            printf("HOLD_RESTORED pid=%d opcode=%08x direct=%llx\n", (int)getpid(),
                   insn, (unsigned long long)uy_site_ldr(p.address + WIN));
            restored = insn == 0xf9400000U &&
                       uy_site_ldr(p.address + WIN) == original;
            break;
        }
        if (!y_status(&ctx, &st) && st.state == UROV_Y_INACTIVE) {
            /* Deactivated but not yet restored is a different failure path. */
            continue;
        }
    }
    CHECK(restored, "hold did not observe a restored site");
    page_close(&p);
    printf("%s cases=%u assertions=%u failures=%u\n",
           g_fail ? "FAIL" : "PASS", 1, g_checks, g_fail);
    return g_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *key = NULL;
    int clean = 0, hold = 0, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) key = argv[++i];
        else if (!strcmp(argv[i], "--clean")) clean = 1;
        else if (!strcmp(argv[i], "--hold")) hold = 1;
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if (clean) return run_clean();
    if (!key) { fprintf(stderr, "--key required\n"); return 2; }
    if (hold) return run_hold(key);
    return run_active(key);
}
