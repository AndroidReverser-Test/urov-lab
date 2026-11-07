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
#include <time.h>
#include <unistd.h>

#include "../urov_x_abi.h"
#include "../urov_y_abi.h"

#define PAGE 4096U
#define WIN 64U

static const uint64_t fake_a = UINT64_C(0x8877665544332211);
static const uint64_t fake_b = UINT64_C(0x0f0e0d0c0b0a0908);

/* The reader sites live in their own page: the page-trap mode makes exactly
 * that page EL0 execute-never, so it must not share a page with code the
 * backend cannot emulate.  The business wrappers are deliberately in .text so
 * they run natively in every mode. */
__asm__(".pushsection .text.uy_sites,\"ax\",%progbits\n"
        ".p2align 12\n"
        ".global uy_site_ldr\n.type uy_site_ldr,%function\n"
        "uy_site_ldr:\n ldr x0, [x0]\n ret\n"
        ".size uy_site_ldr, .-uy_site_ldr\n"
        ".global uy_site_ldrb\n.type uy_site_ldrb,%function\n"
        "uy_site_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size uy_site_ldrb, .-uy_site_ldrb\n"
        ".p2align 12\n"
        ".popsection\n"
        ".pushsection .text,\"ax\",%progbits\n"
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

/* Private_Dirty / Anonymous kB of the VMA containing addr. A PAGE_UXN site must
 * stay a clean, file-backed page; a SITE_BRK site is a private COW page. */
static int mapping_private_kb(const void *addr, unsigned *dirty, unsigned *anon)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    char line[256];
    unsigned long start, end;
    int inside = 0, found = 0;

    if (!f) return -1;
    *dirty = 0;
    *anon = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            inside = (uintptr_t)addr >= start && (uintptr_t)addr < end;
            found |= inside;
            continue;
        }
        if (!inside) continue;
        if (!strncmp(line, "Private_Dirty:", 14))
            *dirty = (unsigned)strtoul(line + 14, NULL, 10);
        else if (!strncmp(line, "Anonymous:", 10))
            *anon = (unsigned)strtoul(line + 10, NULL, 10);
    }
    fclose(f);
    return found ? 0 : -1;
}

static const char *mode_name(unsigned mode)
{
    if (mode == UROV_Y_MODE_PAGE_UXN) return "page";
    if (mode == UROV_Y_MODE_PAGE_AP) return "ap";
    return "brk";
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
                       uint64_t value, unsigned mode)
{
    struct urov_y_request q = y_req(UROV_Y_REGISTER);
    q.address = (uintptr_t)p->address;
    q.offset = WIN;
    q.length = 8;
    q.value = value;
    q.mode = mode;
    q.site_count = 2;
    q.sites[0] = (uint64_t)(uintptr_t)&uy_site_ldr;
    q.sites[1] = (uint64_t)(uintptr_t)&uy_site_ldrb;
    q.caller_count = 2;
    q.caller_start[0] = (uint64_t)(uintptr_t)&uy_business_ldr;
    q.caller_end[0] = (uint64_t)(uintptr_t)uy_business_ldr_end;
    q.caller_start[1] = (uint64_t)(uintptr_t)&uy_business_ldrb;
    q.caller_end[1] = (uint64_t)(uintptr_t)uy_business_ldrb_end;
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

static uint64_t now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

/* Cost of one registered business call in ns. This is the honest timing side
 * channel of any trap-based overlay. */
static uint64_t call_cost_ns(const struct page *p, int rounds)
{
    uint64_t t0, t1, sum = 0;
    int i;

    t0 = now_ns();
    for (i = 0; i < rounds; ++i) sum += uy_business_ldr(p->address + WIN);
    t1 = now_ns();
    if (!sum) fputc(0, stderr);
    return rounds > 0 ? (t1 - t0) / (uint64_t)rounds : 0;
}

static int run_active(const char *key, unsigned mode)
{
    struct y_ctx ctx;
    struct page p;
    uint64_t original, got;
    uint32_t st0, live0;
    unsigned dirty = 0, anon = 0, base_dirty = 0, base_anon = 0;
    struct urov_y_request st;
    struct sigaction sa, old_segv;
    int rc;

    if (y_init_key(&ctx, key)) { fprintf(stderr, "bad key\n"); return 2; }
    if (page_open(&p)) { fprintf(stderr, "page open errno=%d\n", errno); return 2; }
    original = load64_scalar(p.address + WIN);
    st0 = load32_scalar((const void *)&uy_site_ldr);
    /* The page cache of a freshly pushed test binary can still be dirty; the
     * probe must compare against this baseline, not against zero. */
    CHECK(!mapping_private_kb((const void *)&uy_site_ldr, &base_dirty, &base_anon),
          "smaps baseline");
    CHECK(original == load64_scalar(g_source + WIN), "source mismatch");
    CHECK(st0 == 0xf9400000U, "site opcode=%08x", st0);

    rc = (int)y_register(&ctx, &p, fake_a, mode);
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

    /* The decisive observable: does the trap modify the code page at all? */
    live0 = load32_scalar((const void *)&uy_site_ldr);
    rc = mapping_private_kb((const void *)&uy_site_ldr, &dirty, &anon);
    if (mode != UROV_Y_MODE_SITE_BRK) {
        CHECK(live0 == st0, "page mode changed the site instruction: %08x -> %08x",
              st0, live0);
        CHECK(rc == 0 && dirty == base_dirty && anon == base_anon,
              "page mode left the site page private: dirty=%u (base %u) anon=%u (base %u)",
              dirty, base_dirty, anon, base_anon);
    } else {
        CHECK(live0 != st0, "brk mode did not patch the site instruction");
        CHECK(rc == 0 && anon >= base_anon + 4U,
              "brk mode left the site page clean: anon=%u (base %u)", anon, base_anon);
    }
    printf("TRAP mode=%s site_word=%08x dirty_kb=%u base_dirty_kb=%u anon_kb=%u "
           "base_anon_kb=%u\n",
           mode_name(mode), live0, dirty, base_dirty, anon, base_anon);
    printf("TRAP_CALL mode=%s active_ns=%llu\n",
           mode_name(mode), (unsigned long long)call_cost_ns(&p, 200));

    rc = y_set(&ctx, 1, fake_b);
    CHECK(rc == 0, "SET rc=%d errno=%d", rc, errno);
    CHECK(uy_business_ldr(p.address + WIN) == fake_b, "business caller after SET");
    CHECK(uy_site_ldr(p.address + WIN) == original, "direct site after SET");
    CHECK(!y_status(&ctx, &st) && st.generation == 2 && st.state == UROV_Y_ACTIVE &&
          st.mode == mode && st.hits > 0 && st.replays > 0 && st.failures == 0,
          "STATUS gen=%llu hits=%llu replays=%llu state=%u mode=%u failures=%llu",
          (unsigned long long)st.generation, (unsigned long long)st.hits,
          (unsigned long long)st.replays, st.state, st.mode, (unsigned long long)st.failures);

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

    /* BRK and UXN see the rejected load. AP leaves this unrelated fault to Linux. */
    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_ACTIVE &&
          st.failures == (mode == UROV_Y_MODE_PAGE_AP ? 0U : 1U),
          "STATUS before deactivate state=%u failures=%llu", st.state,
          (unsigned long long)st.failures);

    rc = y_deactivate(&ctx);
    CHECK(rc == 0, "DEACTIVATE rc=%d errno=%d", rc, errno);
    CHECK(uy_business_ldr(p.address + WIN) == original, "deactivated site not restored");
    CHECK(load32_scalar((const void *)&uy_site_ldr) == st0, "site opcode not restored");
    if (mode != UROV_Y_MODE_SITE_BRK) {
        /* Both page modes never touched the site page, so the baseline holds. */
        CHECK(!mapping_private_kb((const void *)&uy_site_ldr, &dirty, &anon) &&
              dirty == base_dirty && anon == base_anon,
              "deactivate left the site page private: dirty=%u (base %u) anon=%u (base %u)",
              dirty, base_dirty, anon, base_anon);
    } else {
        /* BRK mode: restoring the bytes does not undo the COW page, so the
         * site page stays private-dirty for the rest of the process lifetime.
         * That persistence is exactly the residual this mode cannot hide. */
        CHECK(!mapping_private_kb((const void *)&uy_site_ldr, &dirty, &anon) &&
              anon >= base_anon + 4U, "brk mode lost its COW page after deactivate");
    }
    printf("TRAP_CALL mode=%s restored_ns=%llu\n",
           mode_name(mode), (unsigned long long)call_cost_ns(&p, 200));
    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_INACTIVE, "STATUS after deactivate");

    /* A fork creating a new mm ends the session before it copies the mapping. */
    CHECK(y_register(&ctx, &p, fake_a, mode) == 0, "fork REGISTER failed");
    CHECK(uy_business_ldr(p.address + WIN) == fake_a, "fork session did not arm");
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
    }
    CHECK(uy_business_ldr(p.address + WIN) == original, "parent site not restored after fork");
    CHECK(!y_status(&ctx, &st) && st.state == UROV_Y_INACTIVE, "fork left session live");

    /* Mapping gate: a mapping change that overlaps the target page ends the
     * session silently and then behaves natively. */
    CHECK(y_register(&ctx, &p, fake_a, mode) == 0, "re-REGISTER failed");
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
static int run_hold(const char *key, unsigned mode)
{
    struct y_ctx ctx;
    struct page p;
    uint64_t original;
    unsigned base_dirty = 0, base_anon = 0;
    int restored = 0;

    if (y_init_key(&ctx, key)) return 2;
    if (page_open(&p)) return 2;
    original = load64_scalar(g_source + WIN);
    CHECK(!mapping_private_kb((const void *)&uy_site_ldr, &base_dirty, &base_anon),
          "hold smaps baseline");
    if (y_register(&ctx, &p, fake_a, mode)) {
        fprintf(stderr, "hold REGISTER failed errno=%d\n", errno);
        return 1;
    }
    CHECK(uy_business_ldr(p.address + WIN) == fake_a, "hold site not armed");
    printf("HOLD_READY pid=%d uid=%d mode=%s\n", (int)getpid(), (int)getuid(),
           mode_name(mode));
    for (unsigned i = 0; i < 600; ++i) {
        struct urov_y_request st;
        uint64_t got;
        usleep(100000);
        got = uy_business_ldr(p.address + WIN);
        if (got == original) {
            uint32_t insn = load32_scalar((const void *)&uy_site_ldr);
            unsigned dirty = 0, anon = 0;
            (void)mapping_private_kb((const void *)&uy_site_ldr, &dirty, &anon);
            printf("HOLD_RESTORED pid=%d opcode=%08x direct=%llx dirty_kb=%u "
                   "base_dirty_kb=%u anon_kb=%u base_anon_kb=%u\n",
                   (int)getpid(), insn, (unsigned long long)uy_site_ldr(p.address + WIN),
                   dirty, base_dirty, anon, base_anon);
            restored = insn == 0xf9400000U && uy_site_ldr(p.address + WIN) == original &&
                       (mode == UROV_Y_MODE_SITE_BRK || anon == base_anon);
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
    unsigned mode = UROV_Y_MODE_PAGE_UXN;
    int clean = 0, hold = 0, i;

    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) key = argv[++i];
        else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
            const char *m = argv[++i];
            if (!strcmp(m, "brk")) mode = UROV_Y_MODE_SITE_BRK;
            else if (!strcmp(m, "page")) mode = UROV_Y_MODE_PAGE_UXN;
            else if (!strcmp(m, "ap")) mode = UROV_Y_MODE_PAGE_AP;
            else { fprintf(stderr, "unknown mode %s\n", m); return 2; }
        }
        else if (!strcmp(argv[i], "--clean")) clean = 1;
        else if (!strcmp(argv[i], "--hold")) hold = 1;
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if (clean) return run_clean();
    if (!key) { fprintf(stderr, "--key required\n"); return 2; }
    if (hold) return run_hold(key, mode);
    return run_active(key, mode);
}
