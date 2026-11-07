/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ABI v8 fixture: arbitrary multi-page overlay, LD1/LD2/LD3/LD4 and loads that
 * cross a base-page boundary.  Included by app.c after uy_fixture.inc, so it
 * reuses uy_req(), uy_control(), uy_status() and the REQUIRE/LOG macros.
 *
 * The target pages are ordinary linker .text pages (private, file-backed, RX).
 * Every page gets a caller-supplied page image, which is the source the module
 * copies at REGISTER time.  All reads go through small noinline business
 * functions so the registered caller window is the same for every load.
 */

#define MP_MULTI_PAGES 24U
static unsigned mp_page_size;

#include <stddef.h>
#include <sys/uio.h>
#include <sys/wait.h>

/* 24 contiguous pages for the multi-page case, one page for the structure
 * loads and three pages for the cross-page case.  The fill is a repeated
 * 16-byte pattern; the fixture reads the real bytes at runtime and never
 * assumes the linker preserved this pattern. */
__asm__(".pushsection .text.mp_blob,\"ax\",%progbits\n"
        ".p2align 14\n"
        ".global mp_multi_blob\n"
        "mp_multi_blob:\n"
        ".rept 24576\n"
        ".quad 0x0706050403020100\n"
        ".quad 0x0f0e0d0c0b0a0908\n"
        ".endr\n"
        ".global mp_multi_blob_end\nmp_multi_blob_end:\n"
        ".p2align 14\n"
        ".global mp_ld_blob\n"
        "mp_ld_blob:\n"
        ".quad 0xfedcba9876543210, 0x1122334455667788\n"
        ".rept 1023\n"
        ".quad 0x0706050403020100\n"
        ".quad 0x0f0e0d0c0b0a0908\n"
        ".endr\n"
        ".global mp_ld_blob_end\nmp_ld_blob_end:\n"
        ".p2align 14\n"
        ".global mp_cross_blob\n"
        "mp_cross_blob:\n"
        ".rept 3072\n"
        ".quad 0x0706050403020100\n"
        ".quad 0x0f0e0d0c0b0a0908\n"
        ".endr\n"
        ".global mp_cross_blob_end\nmp_cross_blob_end:\n"
        ".p2align 14\n"
        ".global mp_audit_site\n.hidden mp_audit_site\n.type mp_audit_site,%function\n"
        "mp_audit_site:\n ldp x0, x1, [x0]\n ret\n"
        ".size mp_audit_site, .-mp_audit_site\n"
        ".p2align 7\n"
        ".global mp_audit_data\n.hidden mp_audit_data\n"
        "mp_audit_data:\n .quad 0x1020304050607080, 0x1020304050607080\n"
        ".p2align 14\n"
        ".popsection\n");

extern uint8_t mp_multi_blob[], mp_multi_blob_end[];
extern uint8_t mp_ld_blob[], mp_ld_blob_end[];
extern uint8_t mp_cross_blob[], mp_cross_blob_end[];

static uint8_t mp_fake[MP_MULTI_PAGES * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
static uint8_t mp_expected[MP_MULTI_PAGES * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
static uint8_t mp_original[MP_MULTI_PAGES * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
static uint8_t mp_out[MP_MULTI_PAGES * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));

static void *(*volatile mp_memcpy)(void *, const void *, size_t) = memcpy;
static int (*volatile mp_memcmp)(const void *, const void *, size_t) = memcmp;

/* ------------------------------------------------ multi-page target reads */

extern char mp_multi_start[], mp_multi_end[];

__attribute__((noinline))
static void mp_multi_business(void *dst, const void *src, size_t n)
{
    __asm__ volatile(".global mp_multi_start\nmp_multi_start:" ::: "memory");
    mp_memcpy(dst, src, n);
    __asm__ volatile("nop\n.global mp_multi_end\nmp_multi_end:" ::: "memory");
}

/* ------------------------------------------------------- LD1/LD2/LD3/LD4 */

/* Out-of-line assembly readers.  Keeping them out of the C translation unit
 * prevents IPA from cloning/specialising the inline asm with a hard-coded
 * base pointer and makes the fault PC/LR shape independent of optimisation. */
__asm__(".pushsection .text.mp_readers,\"ax\",%progbits\n"
        ".p2align 4\n"
        ".global mp_ld1_4x16\n.type mp_ld1_4x16,%function\n"
        "mp_ld1_4x16:\n"
        " ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]\n"
        " stp q0, q1, [x1]\n"
        " stp q2, q3, [x1, #32]\n"
        " ret\n"
        ".size mp_ld1_4x16, .-mp_ld1_4x16\n"
        ".global mp_ld1_2x16\n.type mp_ld1_2x16,%function\n"
        "mp_ld1_2x16:\n"
        " ld1 {v0.16b, v1.16b}, [x0]\n"
        " stp q0, q1, [x1]\n"
        " ret\n"
        ".size mp_ld1_2x16, .-mp_ld1_2x16\n"
        ".global mp_ld1_1x16\n.type mp_ld1_1x16,%function\n"
        "mp_ld1_1x16:\n"
        " ld1 {v0.16b}, [x0]\n"
        " str q0, [x1]\n"
        " ret\n"
        ".size mp_ld1_1x16, .-mp_ld1_1x16\n"
        ".global mp_ld1_1x8\n.type mp_ld1_1x8,%function\n"
        "mp_ld1_1x8:\n"
        " ld1 {v0.8b}, [x0]\n"
        " str q0, [x1]\n"
        " ret\n"
        ".size mp_ld1_1x8, .-mp_ld1_1x8\n"
        ".global mp_ld1_post_imm\n.type mp_ld1_post_imm,%function\n"
        "mp_ld1_post_imm:\n"
        " ld1 {v0.16b}, [x0], #16\n"
        " str q0, [x1]\n"
        " ret\n"
        ".size mp_ld1_post_imm, .-mp_ld1_post_imm\n"
        ".global mp_ld1_post_reg\n.type mp_ld1_post_reg,%function\n"
        "mp_ld1_post_reg:\n"
        " ld1 {v0.16b}, [x0], x1\n"
        " str q0, [x2]\n"
        " ret\n"
        ".size mp_ld1_post_reg, .-mp_ld1_post_reg\n"
        ".global mp_ld2_2x16\n.type mp_ld2_2x16,%function\n"
        "mp_ld2_2x16:\n"
        " ld2 {v0.16b, v1.16b}, [x0]\n"
        " stp q0, q1, [x1]\n"
        " ret\n"
        ".size mp_ld2_2x16, .-mp_ld2_2x16\n"
        ".global mp_ld3_3x16\n.type mp_ld3_3x16,%function\n"
        "mp_ld3_3x16:\n"
        " ld3 {v0.16b, v1.16b, v2.16b}, [x0]\n"
        " stp q0, q1, [x1]\n"
        " str q2, [x1, #32]\n"
        " ret\n"
        ".size mp_ld3_3x16, .-mp_ld3_3x16\n"
        ".global mp_ld4_4x16\n.type mp_ld4_4x16,%function\n"
        "mp_ld4_4x16:\n"
        " ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]\n"
        " stp q0, q1, [x1]\n"
        " stp q2, q3, [x1, #32]\n"
        " ret\n"
        ".size mp_ld4_4x16, .-mp_ld4_4x16\n"
        ".global mp_ldp_q\n.type mp_ldp_q,%function\n"
        "mp_ldp_q:\n"
        " ldp q0, q1, [x0]\n"
        " stp q0, q1, [x1]\n"
        " ret\n"
        ".size mp_ldp_q, .-mp_ldp_q\n"
        ".popsection\n");

extern void mp_ld1_4x16(const void *p, uint8_t *out);
extern void mp_ld1_2x16(const void *p, uint8_t *out);
extern void mp_ld1_1x16(const void *p, uint8_t *out);
extern void mp_ld1_1x8(const void *p, uint8_t *out);
extern uint64_t mp_ld1_post_imm(const void *p, uint8_t *out);
extern uint64_t mp_ld1_post_reg(const void *p, uint64_t step, uint8_t *out);
extern void mp_ld2_2x16(const void *p, uint8_t *out);
extern void mp_ld3_3x16(const void *p, uint8_t *out);
extern void mp_ld4_4x16(const void *p, uint8_t *out);
extern void mp_ldp_q(const void *p, uint8_t *out);

/* ------------------------------------------------ cross-page target reads */

extern char mp_cross_start[], mp_cross_end[];

/* A separate call keeps the caller's LR inside mp_cross_business; an inline
 * ldp directly in the business function would see the caller of the business
 * function in x30 and correctly be treated as a foreign caller. */
__attribute__((noinline))
static void mp_cross_business(uint8_t *out, const void *page1, const void *page0)
{
    __asm__ volatile(".global mp_cross_start\nmp_cross_start:" ::: "memory");
    /* 32 bytes starting 16 bytes before the page1/page2 boundary. */
    mp_ldp_q((const uint8_t *)page1 + mp_page_size - 16, out);
    /* 64 bytes starting 32 bytes before the page1/page2 boundary. */
    mp_ld1_4x16((const uint8_t *)page1 + mp_page_size - 32, out + 64);
    /* 16 bytes starting 8 bytes before the page1/page2 boundary. */
    mp_ld1_1x16((const uint8_t *)page1 + mp_page_size - 8, out + 128);
    /* 32 bytes starting 16 bytes before the page0/page1 boundary; page 0 is
     * deliberately NOT registered, so the first half must be native memory. */
    mp_ldp_q((const uint8_t *)page0 + mp_page_size - 16, out + 160);
    __asm__ volatile("nop\n.global mp_cross_end\nmp_cross_end:" ::: "memory");
}

/* --------------------------------------------------------------- helpers */

static void mp_pattern(uint8_t *p, size_t n, unsigned seed)
{
    size_t i;
    for (i = 0; i < n; ++i)
        p[i] = (uint8_t)(seed + (i * 37U + (i >> 8) * 11U) % 251U);
}

static unsigned mp_first_diff(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (a[i] != b[i]) return (unsigned)i;
    return (unsigned)n;
}

static void mp_check_status(const struct uy_ctx *ctx, unsigned pages, const char *name)
{
    struct urov_y_request st;

    REQUIRE(!uy_status(ctx, &st), "%s status failed", name);
    REQUIRE(st.state == UROV_Y_ACTIVE && st.page_count == pages &&
            (st.reserved & 0xffffffffU) == pages && st.failures == 0,
            "%s status state=%u pages=%u armed=%llu failures=%llu", name, st.state,
            st.page_count, (unsigned long long)(st.reserved & 0xffffffffU),
            (unsigned long long)st.failures);
    LOG("MP_STATUS name=%s pages=%u armed=%llu hits=%llu replays=%llu failures=%llu",
        name, st.page_count, (unsigned long long)(st.reserved & 0xffffffffU),
        (unsigned long long)st.hits, (unsigned long long)st.replays,
        (unsigned long long)st.failures);
}

/* -------------------------------------------------------- multi-page case */

static void mp_multi_case(const struct uy_ctx *ctx, int repeats)
{
    static struct uy_page_desc desc[MP_MULTI_PAGES];
    struct urov_y_request q;
    size_t total = (size_t)MP_MULTI_PAGES * mp_page_size;
    uint8_t saved[mp_page_size];
    unsigned i;
    int rc, active = 0;

    ++g_cases;
    if (sysconf(_SC_PAGESIZE) != (long)mp_page_size ||
        (uintptr_t)mp_multi_blob % mp_page_size ||
        (uintptr_t)(mp_multi_blob_end - mp_multi_blob) < (uintptr_t)total) {
        REQUIRE(0, "MP multi blob shape start=%p span=%lld page=%ld",
                mp_multi_blob, (long long)(mp_multi_blob_end - mp_multi_blob),
                (long)sysconf(_SC_PAGESIZE));
        return;
    }

    mp_memcpy(mp_original, mp_multi_blob, total);
    mp_pattern(mp_fake, total, 0x23);
    memcpy(mp_expected, mp_fake, total);
    REQUIRE(mp_first_diff(mp_original, mp_fake, total) < total,
            "MP multi fake image equals the target pages");

    for (i = 0; i < MP_MULTI_PAGES; ++i) {
        memset(&desc[i], 0, sizeof(desc[i]));
        desc[i].base = (uintptr_t)mp_multi_blob + (size_t)i * mp_page_size;
        desc[i].fake_addr = (uintptr_t)mp_fake + (size_t)i * mp_page_size;
        desc[i].fake_off = 0;
        desc[i].fake_len = mp_page_size;
        desc[i].flags = UROV_Y_PAGE_SRC_USER;
    }

    rc = uy_register_pages(ctx, desc, MP_MULTI_PAGES, (uintptr_t)mp_multi_start,
                     (uintptr_t)mp_multi_end, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.page_count == MP_MULTI_PAGES,
            "MP multi register rc=%d errno=%d state=%u pages=%u", rc, errno,
            q.state, q.page_count);
    if (!active) return;
    LOG("MP_MULTI pages=%u span=%zu register=1 generation=%llu", MP_MULTI_PAGES,
        total, (unsigned long long)q.generation);
    mp_check_status(ctx, MP_MULTI_PAGES, "multi");

    for (int r = 0; r < repeats; ++r) {
        memset(mp_out, 0, total);
        mp_multi_business(mp_out, mp_multi_blob, total);
        unsigned diff = mp_first_diff(mp_out, mp_expected, total);
        unsigned at = diff < total ? diff : 0;
        REQUIRE(diff == total, "MP multi window diff=%u page=%u expect=%02x got=%02x",
                diff, diff / mp_page_size, mp_expected[at], mp_out[at]);
        /* The same range read from outside the caller window must stay native. */
        memset(mp_out, 0, total);
        mp_memcpy(mp_out, mp_multi_blob, total);
        diff = mp_first_diff(mp_out, mp_original, total);
        at = diff < total ? diff : 0;
        REQUIRE(diff == total, "MP multi direct diff=%u got=%02x want=%02x", diff,
                mp_out[at], mp_original[at]);
    }

    /* SET_PAGE replaces exactly one page's image. */
    {
        struct urov_y_request set = uy_req(UROV_Y_SET_PAGE);
        unsigned target = 7;
        set.session = 1;
        set.expected_generation = 1;
        set.reserved = target;
        set.fake_addr = (uintptr_t)mp_fake + (size_t)target * mp_page_size;
        set.offset = 0;
        set.length = mp_page_size;
        mp_pattern(saved, mp_page_size, 0xd1);
        memcpy(mp_fake + (size_t)target * mp_page_size, saved, mp_page_size);
        memcpy(mp_expected + (size_t)target * mp_page_size, saved, mp_page_size);
        rc = (int)uy_control(ctx, UROV_Y_SET_PAGE, &set);
        REQUIRE(rc == 0 && set.generation == 2,
                "MP multi SET_PAGE rc=%d errno=%d generation=%llu", rc, errno,
                (unsigned long long)set.generation);
        memset(mp_out, 0, total);
        mp_multi_business(mp_out, mp_multi_blob, total);
        unsigned diff = mp_first_diff(mp_out, mp_expected, total);
        REQUIRE(diff == total, "MP multi SET_PAGE diff=%u page=%u", diff, diff / mp_page_size);
        LOG("MP_SET_PAGE page=%u generation=%llu diff=%u", target,
            (unsigned long long)set.generation, diff);
    }

    rc = uy_deactivate(ctx);
    REQUIRE(rc == 0, "MP multi deactivate rc=%d errno=%d", rc, errno);
    memset(mp_out, 0, total);
    mp_memcpy(mp_out, mp_multi_blob, total);
    REQUIRE(!mp_memcmp(mp_out, mp_original, total),
            "MP multi deactivation did not restore the pages");
    LOG("MP_MULTI_DONE pages=%u restored=1", MP_MULTI_PAGES);
}

/* ------------------------------------------------------ production reader */

/* A process that is not dumpable cannot open /proc/self/mem; enable it for the
 * length of one read and restore the previous value. */
static int mp_mem_read(const void *at, uint8_t *out, size_t n)
{
    int saved = prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
    int fd, error = 0;
    size_t done = 0;

    if (prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL)) return errno;
    fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error = errno;
    } else {
        while (done < n) {
            ssize_t got = pread(fd, out + done, n - done,
                                (off_t)((uintptr_t)at + done));
            if (got <= 0) {
                error = got < 0 ? errno : EIO;
                break;
            }
            done += (size_t)got;
        }
        close(fd);
    }
    (void)prctl(PR_SET_DUMPABLE, saved > 0 ? 1UL : 0UL, 0UL, 0UL, 0UL);
    return error;
}

/* Production-style pass: a whole multi-page code segment registered with no
 * caller window, then read back through every path an in-process CRC can use:
 * scalar EL0 loads, libc memcpy, process_vm_readv, /proc/self/mem and a forked
 * child.  All of them must observe the registered image. */
static void mp_prod_case(const struct uy_ctx *ctx, int repeats)
{
    static struct uy_page_desc desc[MP_MULTI_PAGES];
    static uint8_t out[MP_MULTI_PAGES * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    struct urov_y_request q;
    size_t total = (size_t)MP_MULTI_PAGES * mp_page_size;
    uint32_t want, crc;
    unsigned i, paths = 0;
    int rc, active = 0, mem_error = 0, child_ok = 0, fatal = 0;

    ++g_cases;
    if (sysconf(_SC_PAGESIZE) != (long)mp_page_size ||
        (uintptr_t)mp_multi_blob % mp_page_size ||
        (uintptr_t)(mp_multi_blob_end - mp_multi_blob) < (uintptr_t)total) {
        REQUIRE(0, "MP prod blob shape start=%p span=%lld",
                mp_multi_blob, (long long)(mp_multi_blob_end - mp_multi_blob));
        return;
    }
    mp_memcpy(mp_original, mp_multi_blob, total);
    mp_pattern(mp_fake, total, 0x5c);
    REQUIRE(mp_first_diff(mp_original, mp_fake, total) < total,
            "MP prod fake image equals the target pages");
    want = (uint32_t)crc32(0, mp_fake, total);
    for (i = 0; i < MP_MULTI_PAGES; ++i) {
        memset(&desc[i], 0, sizeof(desc[i]));
        desc[i].base = (uintptr_t)mp_multi_blob + (size_t)i * mp_page_size;
        desc[i].fake_addr = (uintptr_t)mp_fake + (size_t)i * mp_page_size;
        desc[i].fake_off = 0;
        desc[i].fake_len = mp_page_size;
        desc[i].flags = UROV_Y_PAGE_SRC_USER;
    }
    rc = uy_register_pages(ctx, desc, MP_MULTI_PAGES, 0, 0, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.caller_count == 0 &&
            q.page_count == MP_MULTI_PAGES,
            "MP prod register rc=%d errno=%d state=%u callers=%u pages=%u",
            rc, errno, q.state, q.caller_count, q.page_count);
    if (!active) return;
    LOG("MP_PROD pages=%u bytes=%zu image_crc=%08x", MP_MULTI_PAGES, total, want);

    for (int r = 0; r < repeats && !fatal; ++r) {
        /* 1. scalar EL0 loads, the common CRC loop shape */
        memset(out, 0, total);
        for (size_t k = 0; k < total; ++k) out[k] = mp_multi_blob[k];
        crc = (uint32_t)crc32(0, out, total);
        if (crc != want) {
            REQUIRE(0, "MP prod scalar crc=%08x want=%08x", crc, want);
            fatal = 1;
        }
        /* 2. libc memcpy */
        memset(out, 0, total);
        mp_memcpy(out, mp_multi_blob, total);
        crc = (uint32_t)crc32(0, out, total);
        if (crc != want) {
            REQUIRE(0, "MP prod memcpy crc=%08x want=%08x", crc, want);
            fatal = 1;
        }
        /* 3. process_vm_readv on the owner's own pid */
        {
            struct iovec local = { .iov_base = out, .iov_len = total };
            struct iovec remote = { .iov_base = (void *)mp_multi_blob, .iov_len = total };
            memset(out, 0, total);
            ssize_t got = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
            crc = got == (ssize_t)total ? (uint32_t)crc32(0, out, total) : 0;
            if (got != (ssize_t)total || crc != want) {
                REQUIRE(0, "MP prod vm_readv got=%zd errno=%d crc=%08x want=%08x",
                        got, errno, crc, want);
                fatal = 1;
            }
        }
        /* 4. /proc/self/mem: GUP, no EL0 abort */
        memset(out, 0, total);
        mem_error = mp_mem_read(mp_multi_blob, out, total);
        if (!mem_error) {
            crc = (uint32_t)crc32(0, out, total);
            if (crc != want) {
                REQUIRE(0, "MP prod /proc/self/mem crc=%08x want=%08x", crc, want);
                fatal = 1;
            }
        }
        /* 5. a forked child inherits the trap and must see the image */
        {
            pid_t child = fork();
            int status = 0;
            if (child == 0) {
                uint8_t first[64];
                for (unsigned k = 0; k < sizeof(first); ++k)
                    first[k] = ((const uint8_t *)mp_multi_blob)[k];
                _exit(!memcmp(first, mp_fake, sizeof(first)) ? 0 : 1);
            }
            child_ok = child > 0 && waitpid(child, &status, 0) == child &&
                       WIFEXITED(status) && WEXITSTATUS(status) == 0;
            if (!child_ok) {
                REQUIRE(0, "MP prod fork child saw the live bytes");
                fatal = 1;
            }
        }
        paths = mem_error ? 4 : 5;
    }
    if (mem_error) LOG("MP_PROD_KMEM errno=%d", mem_error);

    rc = uy_deactivate(ctx);
    REQUIRE(rc == 0, "MP prod deactivate rc=%d errno=%d", rc, errno);
    memset(out, 0, total);
    mp_memcpy(out, mp_multi_blob, total);
    REQUIRE(!mp_memcmp(out, mp_original, total),
            "MP prod deactivation did not restore the pages");
    LOG("MP_PROD_DONE paths=%u child_overlay=%d kmem_errno=%d", paths, child_ok, mem_error);
}

/* ------------------------------------------------------------- LD1 family */

static void mp_ld_expected_ld1(const uint8_t *fake, size_t off, size_t n,
                               uint8_t *out)
{
    memcpy(out, fake + off, n);
}

/* LD2/LD3/LD4 de-interleave: out[s * datasize + e * esize] =
 * fake[off + (e * selem + s) * esize]. */
static void mp_ld_expected_multi(const uint8_t *fake, size_t off, unsigned selem,
                                 unsigned esize, unsigned datasize, uint8_t *out)
{
    unsigned e, s;
    for (s = 0; s < selem; ++s)
        for (e = 0; e < datasize / esize; ++e)
            out[s * datasize + e * esize] = fake[off + (e * selem + s) * esize];
}

/* Straight-line reader bundle.  Keeping the two boundary labels in one basic
 * block makes the registered caller window cover every call site; the earlier
 * in-loop labels were reordered by the compiler and no longer bracketed the
 * reads.  The post-index base results are returned through globals because the
 * asm readers return them in registers. */
static uint64_t mp_ld_base_imm;
static uint64_t mp_ld_base_reg;

__attribute__((noinline))
static void mp_ld_business(uint8_t *out, const void *p)
{
    __asm__ volatile(".global mp_ld_start\nmp_ld_start:" ::: "memory");
    mp_ld1_4x16(p, out);
    mp_ld1_2x16((const uint8_t *)p + 64, out + 64);
    mp_ld1_1x16((const uint8_t *)p + 96, out + 96);
    mp_ld1_1x8((const uint8_t *)p + 112, out + 112);
    mp_ld_base_imm = mp_ld1_post_imm((const uint8_t *)p + 128, out + 128);
    mp_ld_base_reg = mp_ld1_post_reg((const uint8_t *)p + 144, 32, out + 144);
    mp_ld2_2x16((const uint8_t *)p + 160, out + 160);
    mp_ld3_3x16((const uint8_t *)p + 192, out + 192);
    mp_ld4_4x16((const uint8_t *)p + 240, out + 240);
    __asm__ volatile("nop\n.global mp_ld_end\nmp_ld_end:" ::: "memory");
}

static void mp_ld_case(const struct uy_ctx *ctx, int repeats)
{
    static struct uy_page_desc desc;
    static uint8_t fake[UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t native[UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t expect[512] __attribute__((aligned(16)));
    static uint8_t out[512] __attribute__((aligned(16)));
    struct urov_y_request q;
    int rc, active = 0;

    extern char mp_ld_start[], mp_ld_end[];

    ++g_cases;
    if ((uintptr_t)mp_ld_blob % mp_page_size ||
        (uintptr_t)(mp_ld_blob_end - mp_ld_blob) < (uintptr_t)mp_page_size) {
        REQUIRE(0, "MP ld blob shape span=%lld",
                (long long)(mp_ld_blob_end - mp_ld_blob));
        return;
    }
    mp_memcpy(native, mp_ld_blob, mp_page_size);
    mp_pattern(fake, mp_page_size, 0x5b);

    /* Native oracle: the exact same bundled readers against the unregistered
     * page.  mp_ld_business is also the registered caller window later. */
    memset(out, 0, sizeof(out));
    mp_ld_business(out, mp_ld_blob);
    REQUIRE(!memcmp(out, native, 64), "MP ld1 4x16 native");
    REQUIRE(!memcmp(out + 64, native + 64, 32), "MP ld1 2x16 native");
    REQUIRE(!memcmp(out + 96, native + 96, 16), "MP ld1 1x16 native");
    REQUIRE(!memcmp(out + 112, native + 112, 8) &&
            !memcmp(out + 120, "\0\0\0\0\0\0\0\0", 8), "MP ld1 8b native");
    REQUIRE(!memcmp(out + 128, native + 128, 16) &&
            mp_ld_base_imm == (uint64_t)(uintptr_t)(mp_ld_blob + 144),
            "MP ld1 post imm native base=%llx", (unsigned long long)mp_ld_base_imm);
    REQUIRE(!memcmp(out + 144, native + 144, 16) &&
            mp_ld_base_reg == (uint64_t)(uintptr_t)(mp_ld_blob + 176),
            "MP ld1 post reg native base=%llx", (unsigned long long)mp_ld_base_reg);
    mp_ld_expected_multi(native, 160, 2, 1, 16, expect);
    REQUIRE(!memcmp(out + 160, expect, 32), "MP ld2 native");
    mp_ld_expected_multi(native, 192, 3, 1, 16, expect);
    REQUIRE(!memcmp(out + 192, expect, 48), "MP ld3 native");
    mp_ld_expected_multi(native, 240, 4, 1, 16, expect);
    REQUIRE(!memcmp(out + 240, expect, 64), "MP ld4 native");

    memset(&desc, 0, sizeof(desc));
    desc.base = (uintptr_t)mp_ld_blob;
    desc.fake_addr = (uintptr_t)fake;
    desc.fake_off = 0;
    desc.fake_len = mp_page_size;
    desc.flags = UROV_Y_PAGE_SRC_USER;
    rc = uy_register_pages(ctx, &desc, 1, (uintptr_t)mp_ld_start, (uintptr_t)mp_ld_end, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE,
            "MP ld register rc=%d errno=%d state=%u", rc, errno, q.state);
    if (!active) return;
    LOG("MP_LD register=1 page=1 generation=%llu", (unsigned long long)q.generation);

    for (int r = 0; r < repeats; ++r) {
        memset(out, 0, sizeof(out));
        mp_ld_business(out, mp_ld_blob);
        mp_ld_expected_ld1(fake, 0, 64, expect);
        REQUIRE(!memcmp(out, expect, 64), "MP ld1 4x16 overlay");
        mp_ld_expected_ld1(fake, 64, 32, expect);
        REQUIRE(!memcmp(out + 64, expect, 32), "MP ld1 2x16 overlay");
        mp_ld_expected_ld1(fake, 96, 16, expect);
        REQUIRE(!memcmp(out + 96, expect, 16), "MP ld1 1x16 overlay");
        mp_ld_expected_ld1(fake, 112, 8, expect);
        memset(expect + 8, 0, 8);
        REQUIRE(!memcmp(out + 112, expect, 16), "MP ld1 1x8 overlay");
        mp_ld_expected_ld1(fake, 128, 16, expect);
        REQUIRE(!memcmp(out + 128, expect, 16) &&
                mp_ld_base_imm == (uint64_t)(uintptr_t)(mp_ld_blob + 144),
                "MP ld1 post imm overlay base=%llx", (unsigned long long)mp_ld_base_imm);
        mp_ld_expected_ld1(fake, 144, 16, expect);
        REQUIRE(!memcmp(out + 144, expect, 16) &&
                mp_ld_base_reg == (uint64_t)(uintptr_t)(mp_ld_blob + 176),
                "MP ld1 post reg overlay base=%llx", (unsigned long long)mp_ld_base_reg);
        mp_ld_expected_multi(fake, 160, 2, 1, 16, expect);
        REQUIRE(!memcmp(out + 160, expect, 32), "MP ld2 overlay");
        mp_ld_expected_multi(fake, 192, 3, 1, 16, expect);
        REQUIRE(!memcmp(out + 192, expect, 48), "MP ld3 overlay");
        mp_ld_expected_multi(fake, 240, 4, 1, 16, expect);
        if (memcmp(out + 240, expect, 64) != 0) {
            unsigned d = mp_first_diff(out + 240, expect, 64);
            LOG("MP_LD4_DIFF at=%u got=%02x want=%02x", d, out[240 + d], expect[d]);
        }
        REQUIRE(!memcmp(out + 240, expect, 64), "MP ld4 overlay");
    }
    LOG("MP_LD_DONE readers=ld1x4/ld1x2/ld1x1/ld1_8b/post_imm/post_reg/ld2/ld3/ld4 n=%d",
        repeats);

    rc = uy_deactivate(ctx);
    REQUIRE(rc == 0, "MP ld deactivate rc=%d errno=%d", rc, errno);
    memset(out, 0, sizeof(out));
    mp_ld_business(out, mp_ld_blob);
    REQUIRE(!memcmp(out, native, 64), "MP ld deactivation did not restore");
}

/* ------------------------------------------------------------ cross page */

static void mp_cross_case(const struct uy_ctx *ctx, int repeats)
{
    static struct uy_page_desc desc[2];
    static uint8_t fake[2 * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t native[3 * UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t expect[256] __attribute__((aligned(16)));
    static uint8_t out[256] __attribute__((aligned(16)));
    struct urov_y_request q;
    unsigned i;
    int rc, active = 0;

    ++g_cases;
    if ((uintptr_t)mp_cross_blob % mp_page_size ||
        (uintptr_t)(mp_cross_blob_end - mp_cross_blob) < (uintptr_t)(3 * mp_page_size)) {
        REQUIRE(0, "MP cross blob shape span=%lld",
                (long long)(mp_cross_blob_end - mp_cross_blob));
        return;
    }
    mp_memcpy(native, mp_cross_blob, 3U * mp_page_size);
    mp_pattern(fake, 2U * mp_page_size, 0x91);

    /* Native oracle for the four reads. */
    mp_cross_business(out, mp_cross_blob + mp_page_size, mp_cross_blob);
    REQUIRE(!memcmp(out, native + mp_page_size + mp_page_size - 16, 32), "MP cross ldp native");
    REQUIRE(!memcmp(out + 64, native + mp_page_size + mp_page_size - 32, 64), "MP cross ld1 native");
    REQUIRE(!memcmp(out + 128, native + mp_page_size + mp_page_size - 8, 16), "MP cross ld1 tail native");
    REQUIRE(!memcmp(out + 160, native + mp_page_size - 16, 32), "MP cross page0 native");

    for (i = 0; i < 2; ++i) {
        memset(&desc[i], 0, sizeof(desc[i]));
        desc[i].base = (uintptr_t)mp_cross_blob + (i + 1) * mp_page_size;
        desc[i].fake_addr = (uintptr_t)fake + i * mp_page_size;
        desc[i].fake_off = 0;
        desc[i].fake_len = mp_page_size;
        desc[i].flags = UROV_Y_PAGE_SRC_USER;
    }
    rc = uy_register_pages(ctx, desc, 2, (uintptr_t)mp_cross_start,
                     (uintptr_t)mp_cross_end, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.page_count == 2,
            "MP cross register rc=%d errno=%d state=%u pages=%u", rc, errno,
            q.state, q.page_count);
    if (!active) return;
    LOG("MP_CROSS register=1 pages=2 generation=%llu", (unsigned long long)q.generation);

    for (int r = 0; r < repeats; ++r) {
        memset(out, 0, sizeof(out));
        mp_cross_business(out, mp_cross_blob + mp_page_size, mp_cross_blob);
        /* ldp q at page1+4080: 16 bytes of page1, 16 bytes of page2. */
        memcpy(expect, fake + mp_page_size - 16, 16);
        memcpy(expect + 16, fake + mp_page_size, 16);
        if (memcmp(out, expect, 32) != 0)
            LOG("MP_CROSS_LDP_DIFF at=%u got0=%02x%02x got1=%02x%02x want0=%02x%02x want1=%02x%02x",
                mp_first_diff(out, expect, 32), out[0], out[1], out[16], out[17],
                expect[0], expect[1], expect[16], expect[17]);
        REQUIRE(!memcmp(out, expect, 32), "MP cross ldp overlay");
        /* ld1 4x16 at page1+4064: 32 bytes of page1, 32 bytes of page2. */
        memcpy(expect, fake + mp_page_size - 32, 32);
        memcpy(expect + 32, fake + mp_page_size, 32);
        REQUIRE(!memcmp(out + 64, expect, 64), "MP cross ld1 overlay");
        /* ld1 1x16 at page1+4088: 8 bytes of page1, 8 bytes of page2. */
        memcpy(expect, fake + mp_page_size - 8, 8);
        memcpy(expect + 8, fake + mp_page_size, 8);
        REQUIRE(!memcmp(out + 128, expect, 16), "MP cross ld1 tail overlay");
        /* page0 is unregistered: 16 native bytes then 16 fake page1 bytes. */
        memcpy(expect, native + mp_page_size - 16, 16);
        memcpy(expect + 16, fake, 16);
        REQUIRE(!memcmp(out + 160, expect, 32), "MP cross uncovered page0");
    }
    LOG("MP_CROSS_DONE reads=ldp_page1_page2/ld1_page1_page2/ld1_tail/uncovered_page0 n=%d",
        repeats);

    rc = uy_deactivate(ctx);
    REQUIRE(rc == 0, "MP cross deactivate rc=%d errno=%d", rc, errno);
    mp_cross_business(out, mp_cross_blob + mp_page_size, mp_cross_blob);
    REQUIRE(!memcmp(out + 64, native + mp_page_size + mp_page_size - 32, 64),
            "MP cross deactivation did not restore");
}

/* --------------------------------------------------------- SRC_USER page */

extern char mp_src_start[], mp_src_end[];

__attribute__((noinline))
static void mp_srcpage_business(void *dst, const void *src)
{
    __asm__ volatile(".global mp_src_start\nmp_src_start:" ::: "memory");
    mp_memcpy(dst, src, mp_page_size);
    __asm__ volatile("nop\n.global mp_src_end\nmp_src_end:" ::: "memory");
}

/* Register a full-page SRC_USER image.  The caller supplies exactly one base
 * page; the module copies it during REGISTER and never dereferences it
 * again.  A changed word at both ends proves the image, not the live page,
 * is being returned. */
static void mp_srcpage_case(const struct uy_ctx *ctx, int repeats)
{
    static struct uy_page_desc desc;
    static uint8_t native[UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t image[UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    static uint8_t out[UROV_Y_MAX_PAGE] __attribute__((aligned(16)));
    struct urov_y_request q;
    int rc, active = 0;

    ++g_cases;
    mp_memcpy(native, mp_ld_blob, mp_page_size);
    mp_memcpy(image, mp_ld_blob, mp_page_size);
    image[0] ^= 0x5aU;
    image[mp_page_size - 1] ^= 0xa5U;
    REQUIRE(memcmp(native, image, mp_page_size), "MP SRC_PAGE image equals live page");
    memset(&desc, 0, sizeof(desc));
    desc.base = (uintptr_t)mp_ld_blob;
    desc.fake_addr = (uintptr_t)image;
    desc.fake_off = 0;
    desc.fake_len = mp_page_size;
    desc.flags = UROV_Y_PAGE_SRC_USER;
    rc = uy_register_pages(ctx, &desc, 1, (uintptr_t)mp_src_start,
                     (uintptr_t)mp_src_end, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.page_count == 1,
            "MP SRC_PAGE register rc=%d errno=%d state=%u", rc, errno, q.state);
    if (!active) return;
    LOG("MP_SRC_PAGE register=1 page=1 generation=%llu",
        (unsigned long long)q.generation);
    for (int r = 0; r < repeats; ++r) {
        memset(out, 0, sizeof(out));
        mp_srcpage_business(out, mp_ld_blob);
        REQUIRE(!memcmp(out, image, mp_page_size), "MP SRC_PAGE view differs from image");
        memset(out, 0, sizeof(out));
        mp_memcpy(out, mp_ld_blob, mp_page_size);
        REQUIRE(!memcmp(out, native, mp_page_size), "MP SRC_PAGE outside-window read changed");
    }
    mp_check_status(ctx, 1, "srcpage");
    rc = uy_deactivate(ctx);
    REQUIRE(rc == 0, "MP SRC_PAGE deactivate rc=%d errno=%d", rc, errno);
    mp_memcpy(out, mp_ld_blob, mp_page_size);
    REQUIRE(!memcmp(out, native, mp_page_size), "MP SRC_PAGE deactivation did not restore");
    LOG("MP_SRC_PAGE_DONE page=1 reads=%d", repeats);
}

struct mp_pair {
    uint64_t lo, hi;
};

extern struct mp_pair mp_audit_site(const void *at);
extern const uint64_t mp_audit_data[2];

static const uint64_t mp_audit_values[] = {
    UINT64_C(0x1020304050607080), UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
};

struct mp_audit_worker {
    atomic_bool stop;
    atomic_uint reads, errors;
};

static void *mp_audit_read(void *arg)
{
    struct mp_audit_worker *worker = arg;

    while (!atomic_load_explicit(&worker->stop, memory_order_relaxed)) {
        struct mp_pair p = mp_audit_site(mp_audit_data);
        if (p.lo != p.hi || (p.lo != mp_audit_values[0] &&
                            p.lo != mp_audit_values[1] && p.lo != mp_audit_values[2]))
            atomic_fetch_add_explicit(&worker->errors, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&worker->reads, 1, memory_order_relaxed);
    }
    return NULL;
}

/* 2.12.0 keeps a PAGE_AP session across an overlapping mprotect that still
 * asks for read+execute, and across fork(): the child inherits a copy of the
 * trapped leaf PTE and is served from the same image.  The audit below pins
 * both behaviours with reads, not with the session state alone. */
static void mp_audit_case(const struct uy_ctx *ctx)
{
    struct mp_pair fake = {mp_audit_values[1], mp_audit_values[1]};
    const uintptr_t base = (uintptr_t)&mp_audit_site;
    struct uy_page_desc desc = {
        .base = base, .fake_addr = (uintptr_t)&fake,
        .fake_off = (unsigned)((uintptr_t)mp_audit_data - base), .fake_len = sizeof(fake),
        .flags = UROV_Y_PAGE_SRC_USER,
    };
    struct uy_page_desc bad[] = {desc, desc, desc, desc, desc};
    struct urov_y_request q = {0};
    struct mp_audit_worker worker = {0};
    pthread_t thread;
    uint64_t generation;
    unsigned invalid = 0, updates = 0;
    int rc, have_thread, child_overlay = 0, mprotect_active = 0;

    ++g_cases;
    bad[0].fake_len = mp_page_size + 8;
    bad[1].fake_len = UINT32_MAX & ~7U;
    bad[2].fake_off = UINT32_MAX;
    bad[3].flags |= UROV_Y_PAGE_SRC_FILE;
    bad[4].fake_addr = UINT64_MAX - 7;
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        rc = uy_register_pages(ctx, &bad[i], 1, 0, 0, &q);
        int saved_errno = errno;
        REQUIRE(rc == -1 && saved_errno == EINVAL, "MP malformed desc %u rc=%d errno=%d",
                i, rc, saved_errno);
        if (!rc) (void)uy_deactivate(ctx);
        if (rc == -1 && saved_errno == EINVAL) ++invalid;
    }
    REQUIRE(!uy_status(ctx, &q) && q.state == UROV_Y_INACTIVE, "MP invalid REGISTER armed a trap");
    rc = uy_register_pages(ctx, &desc, 1, 0, 0, &q);
    REQUIRE(!rc && q.state == UROV_Y_ACTIVE, "MP audit REGISTER rc=%d errno=%d", rc, errno);
    if (rc) return;
    generation = q.generation;
    struct mp_pair got = mp_audit_site(mp_audit_data);
    REQUIRE(got.lo == fake.lo && got.hi == fake.hi, "MP self-page fetch/read mismatch");

    q = uy_req(UROV_Y_SET_PAGE);
    q.session = 1;
    q.expected_generation = generation;
    q.fake_addr = (uintptr_t)&fake;
    q.length = mp_page_size + 8;
    rc = (int)uy_control(ctx, UROV_Y_SET_PAGE, &q);
    REQUIRE(rc == -1 && errno == EINVAL && !uy_status(ctx, &q) && q.generation == generation,
            "MP malformed SET_PAGE changed the session");

    have_thread = !pthread_create(&thread, NULL, mp_audit_read, &worker);
    REQUIRE(have_thread, "MP audit reader thread");
    for (unsigned i = 0; have_thread && i < 200 && !atomic_load(&worker.reads); ++i)
        usleep(1000);
    for (unsigned i = 0; i < 48; ++i) {
        q = uy_req(UROV_Y_SET_PAGE);
        fake.lo = fake.hi = mp_audit_values[1 + (i & 1U)];
        q.session = 1;
        q.expected_generation = generation;
        q.fake_addr = (uintptr_t)&fake;
        q.offset = desc.fake_off;
        q.length = sizeof(fake);
        rc = (int)uy_control(ctx, UROV_Y_SET_PAGE, &q);
        REQUIRE(!rc && q.generation == generation + 1, "MP concurrent SET_PAGE rc=%d errno=%d", rc, errno);
        if (rc) break;
        generation = q.generation;
        ++updates;
    }
    rc = mprotect((void *)base, mp_page_size, PROT_READ | PROT_EXEC);
    got = mp_audit_site(mp_audit_data);
    mprotect_active = !rc && !uy_status(ctx, &q) && q.state == UROV_Y_ACTIVE &&
                      got.lo == fake.lo && got.hi == fake.hi;
    REQUIRE(mprotect_active,
            "MP overlapping mprotect lost the overlay rc=%d errno=%d state=%u",
            rc, errno, q.state);
    atomic_store(&worker.stop, 1);
    if (have_thread) pthread_join(thread, NULL);
    REQUIRE(atomic_load(&worker.reads) > 0 && !atomic_load(&worker.errors), "MP concurrent read tore");

    /* A fork inherits a copy of the trapped leaf PTE.  The child must read the
     * same image as the owner and the parent's session must survive. */
    struct mp_pair expect = fake;
    pid_t child = fork();
    int status = 0;
    if (child == 0) {
        struct mp_pair value = mp_audit_site(mp_audit_data);
        _exit(value.lo == expect.lo && value.hi == expect.hi ? 0 : 1);
    }
    child_overlay = child > 0 && waitpid(child, &status, 0) == child &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0;
    got = mp_audit_site(mp_audit_data);
    REQUIRE(child_overlay && !uy_status(ctx, &q) && q.state == UROV_Y_ACTIVE &&
            got.lo == expect.lo && got.hi == expect.hi,
            "MP fork child=%d state=%u read=%llx/%llx", child_overlay, q.state,
            (unsigned long long)got.lo, (unsigned long long)got.hi);
    (void)uy_deactivate(ctx);
    LOG("MP_AUDIT invalid=%u updates=%u reads=%u errors=%u mprotect_active=%d "
        "child_overlay=%d", invalid, updates, atomic_load(&worker.reads),
        atomic_load(&worker.errors), mprotect_active, child_overlay);
}

/* --------------------------------------------------------------- dispatch */

static void mp_fixture(const char *mode, const char *key, int repeats)
{
    struct uy_ctx ctx;
    struct urov_y_request q;

    if (uy_init_key(&ctx, key)) {
        REQUIRE(0, "MP key init");
        return;
    }
    q = uy_req(UROV_Y_QUERY);
    const long page_size = sysconf(_SC_PAGESIZE);
    const uint64_t required = UROV_Y_CAP_MULTI | UROV_Y_CAP_LD1 | UROV_Y_CAP_LD2 |
                              UROV_Y_CAP_LD3 | UROV_Y_CAP_LD4 | UROV_Y_CAP_CROSS |
                              UROV_Y_CAP_PAGE_AP;
    if (uy_control(&ctx, UROV_Y_QUERY, &q) || q.state != UROV_Y_INACTIVE ||
        (q.session_flags & required) != required || q.page_count < MP_MULTI_PAGES ||
        (q.page_stride != 12U && q.page_stride != 14U) ||
        (1L << q.page_stride) != page_size ||
        !!(q.session_flags & UROV_Y_CAP_16K) != (q.page_stride == 14U)) {
        REQUIRE(0, "MP query caps=0x%x shift=%u max=%u state=%u page_size=%ld",
                (unsigned)q.session_flags, q.page_stride, q.page_count, q.state, page_size);
        return;
    }
    mp_page_size = (unsigned)page_size;
    LOG("MP_QUERY caps=0x%x max_pages=%u page_shift=%u abi=%u",
        (unsigned)q.session_flags, q.page_count, q.page_stride, UROV_Y_ABI_VERSION);

    if (!strcmp(mode, "mp-multi")) mp_multi_case(&ctx, repeats);
    else if (!strcmp(mode, "mp-ld1")) mp_ld_case(&ctx, repeats);
    else if (!strcmp(mode, "mp-cross")) mp_cross_case(&ctx, repeats);
    else if (!strcmp(mode, "mp-srcpage")) mp_srcpage_case(&ctx, repeats);
    else if (!strcmp(mode, "mp-audit")) mp_audit_case(&ctx);
    else if (!strcmp(mode, "mp-prod")) mp_prod_case(&ctx, repeats);
    else REQUIRE(0, "MP unknown mode %s", mode);
}
