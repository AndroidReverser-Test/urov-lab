/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "crc_patch_fixture.h"

#define CRC_STRING_IMPL(value) #value
#define CRC_STRING(value) CRC_STRING_IMPL(value)
__asm__(".pushsection .text.crc_payload,\"ax\",%progbits\n"
        ".macro crc_payload name, value\n"
        ".p2align 12\n.global \\name\n.hidden \\name\n.type \\name,%function\n"
        "\\name:\n hint #34\n mov w0, #\\value\n ret\n"
        ".size \\name, .-\\name\n.p2align 12\n.endm\n"
        "crc_payload crc_original, " CRC_STRING(CRC_ORIGINAL_RETURN) "\n"
        "crc_payload crc_patched, " CRC_STRING(CRC_PATCHED_RETURN) "\n"
        ".popsection\n");
#undef CRC_STRING
#undef CRC_STRING_IMPL

extern uint32_t crc_original(void);
extern uint32_t crc_patched(void);
typedef uint32_t (*crc_reader_fn)(const void *address);

struct crc_patch_api {
    __typeof__(&urov_crc_patch_private) patch_private;
    __typeof__(&urov_crc_remap) remap;
    __typeof__(&urov_crc_control) control;
};

static uint32_t crc_payload_bytes(const uint8_t bytes[CRC_PAYLOAD_SIZE])
{
    return (uint32_t)crc32(0, bytes, CRC_PAYLOAD_SIZE);
}

static uint32_t crc_read_code(const uint8_t *address, crc_reader_fn reader)
{
    uint8_t bytes[CRC_PAYLOAD_SIZE];
    if (reader) {
        for (unsigned i = 0; i < sizeof(bytes); ++i)
            bytes[i] = (uint8_t)reader(address + i);
    } else {
        copy_scalar(bytes, address, sizeof(bytes));
    }
    return crc_payload_bytes(bytes);
}

static uint32_t crc_execute(const void *address)
{
    uint32_t (*payload)(void) = (uint32_t (*)(void))address;
    return payload();
}

static long crc_register(const struct crc_patch_api *api, const char *key,
                         const void *page, const uint8_t original[CRC_PAYLOAD_SIZE],
                         unsigned mode, int all_callers, struct urov_y_request *out)
{
    *out = uy_req(UROV_Y_REGISTER);
    out->address = (uintptr_t)page;
    out->mode = mode;
    out->length = sizeof(out->value);
    memcpy(&out->value, original, sizeof(out->value));
    out->site_count = 1;
    out->sites[0] = (uintptr_t)&uy_site_ldrb;
    if (!all_callers) {
        out->caller_count = 1;
        out->caller_start[0] = (uintptr_t)&uy_business_ldrb;
        out->caller_end[0] = (uintptr_t)uy_business_ldrb_end;
    }
    return api->control(key, out);
}

static int crc_deactivate(const struct crc_patch_api *api, const char *key)
{
    struct urov_y_request q = uy_req(UROV_Y_DEACTIVATE);
    q.session = 1;
    long rc = api->control(key, &q);
    REQUIRE(!rc && q.state == UROV_Y_INACTIVE && q.session == 0,
            "CRC deactivate rc=%ld errno=%d state=%u", rc, errno, q.state);
    return !rc && q.state == UROV_Y_INACTIVE && q.session == 0;
}

/* UROV-Y 2.12.0 accepts VM_LOCKED: mlock() only pins a page against reclaim
 * and does not change the leaf PTE, so the overlay has to work on a locked
 * page.  The old EINVAL refusal was an app-visible way to stop REGISTER.
 * Verify the overlay instead of the refusal, then restore through the
 * authenticated DEACTIVATE. */
static bool crc_lock_guard(const struct crc_patch_api *api, const char *key,
                           const void *page, const uint8_t image[CRC_PAYLOAD_SIZE],
                           unsigned mode, int all_callers, int repeats, const char *name)
{
    uint32_t live_crc = crc_read_code(page, uy_business_ldrb);
    uint32_t image_crc = crc_payload_bytes(image);
    uint32_t expected_return = crc_execute(page);
    uint64_t begin = now_ns();
    int lock_error = mlock(page, UROV_Y_PAGE) ? errno : 0;
    uint64_t lock_ns = now_ns() - begin;
    REQUIRE(!lock_error, "CRC %s mlock errno=%d", name, lock_error);
    if (lock_error) return false;

    struct ud_mapping before, after;
    int map_error = ud_mapping_at("/proc/self/maps", page, &before);
    struct urov_y_request q;
    long rc = crc_register(api, key, page, image, mode, all_callers, &q);
    int register_error = rc ? errno : 0;
    bool active = !rc && q.state == UROV_Y_ACTIVE;
    uint32_t window_crc = active ? crc_read_code(page, uy_business_ldrb) : live_crc;
    uint32_t window_return = active ? crc_execute(page) : 0;
    int deactivate_error = 0;
    if (active && !crc_deactivate(api, key)) deactivate_error = errno ? errno : EIO;
    uint32_t restored_crc = crc_read_code(page, uy_business_ldrb);
    bool rx = !map_error && !ud_mapping_at("/proc/self/maps", page, &after) &&
              after.start == before.start && after.end == before.end &&
              after.offset == before.offset && after.readable && !after.writable &&
              after.executable;
    int unlock_error = munlock(page, UROV_Y_PAGE) ? errno : 0;
    bool passed = !register_error && active && window_crc != live_crc &&
                  window_crc == image_crc && window_return == expected_return &&
                  !deactivate_error && restored_crc == live_crc && rx && !unlock_error;
    REQUIRE(passed, "CRC %s locked page verification", name);
    LOG("CRC_LOCK_GUARD name=%s mode=%u all_callers=%d bytes=%u n=%d lock_ns=%llu "
        "register_errno=%d active=%d window=%08x image=%08x live=%08x "
        "execute=%04x deactivate_errno=%d restored=%08x rx=%d unlock_errno=%d",
        name, mode, all_callers, UROV_Y_PAGE, repeats, (unsigned long long)lock_ns,
        register_error, active, window_crc, image_crc, live_crc, window_return,
        deactivate_error, restored_crc, rx, unlock_error);
    return passed;
}

static void crc_reject_mapping(const struct crc_patch_api *api, const char *key,
                               const void *address, const uint8_t *original,
                               const char *name)
{
    struct ud_mapping mapping;
    struct urov_y_request q;
    int error = ud_mapping_at("/proc/self/smaps", address, &mapping);
    REQUIRE(!error && mapping.maywrite && !mapping.shared,
            "CRC %s private VMA error=%d", name, error);
    if (error) return;

    long rc = crc_register(api, key, address, original, UROV_Y_MODE_PAGE_AP, 0, &q);
    int rejected_errno = rc ? errno : 0;
    LOG("CRC_REJECT name=%s span=%llu rx=%d maywrite=%d writable=%d register_rc=%ld register_errno=%d",
        name, (unsigned long long)(mapping.end - mapping.start),
        mapping.readable && mapping.executable && !mapping.writable,
        mapping.maywrite, mapping.writable, rc, rejected_errno);
    REQUIRE(rc == -1 && rejected_errno == EINVAL, "CRC %s unexpectedly registered", name);
    if (!rc) (void)crc_deactivate(api, key);
}

/* One target page whose EL0 reads must return the fake bytes: bind it in
 * PAGE_AP mode, read it through the registered reader (both inside and outside
 * the business window), execute the page to prove fetch is untouched, and
 * verify that deactivation restores the native view.  The same helper covers
 * the dedicated one-page private alias and a page inside the linker's normal
 * multi-page MAP_PRIVATE .text VMA. */
static void crc_ap_page_case(const char *name, const struct crc_patch_api *api,
                             const char *key, const void *address,
                             off_t file_offset, int repeats, uint32_t clean_crc,
                             uint32_t patched_crc, const uint8_t fake[CRC_PAYLOAD_SIZE])
{
    struct urov_y_request q;
    struct ud_mapping before, after;
    unsigned dirty, anon;
    uint32_t execute = 0, direct = 0, site = 0, window = 0;
    int active = 0;

    ++g_cases;
    if (!crc_lock_guard(api, key, address, fake, UROV_Y_MODE_PAGE_AP, 0, repeats, name))
        return;
    if (ud_mapping_at("/proc/self/smaps", address, &before) ||
        uy_mapping_private_kb(address, &dirty, &anon)) {
        REQUIRE(0, "CRC %s mapping errno=%d", name, errno);
        return;
    }
    LOG("CRC_VMA name=%s span=%llu offset=%llx rx=%d shared=%d maywrite=%d dc=%d "
        "private_dirty_kb=%u anonymous_kb=%u",
        name, (unsigned long long)(before.end - before.start),
        (unsigned long long)before.offset, before.readable && before.executable &&
        !before.writable, before.shared, before.maywrite, before.dontcopy, dirty, anon);
    REQUIRE(before.readable && before.executable && !before.writable && !before.shared &&
            before.maywrite && before.end - (uintptr_t)address >= UROV_Y_PAGE &&
            before.offset + ((uintptr_t)address - before.start) == (uint64_t)file_offset,
            "CRC %s VMA shape rejected", name);
    REQUIRE(!dirty && !anon, "CRC %s page already private dirty=%u anon=%u", name, dirty, anon);

    execute = crc_execute(address);
    direct = crc_read_code(address, NULL);
    site = crc_read_code(address, uy_site_ldrb);
    window = crc_read_code(address, uy_business_ldrb);
    REQUIRE(execute == CRC_ORIGINAL_RETURN && direct == clean_crc && site == clean_crc &&
            window == clean_crc,
            "CRC %s clean execute=%04x direct=%08x site=%08x window=%08x", name,
            execute, direct, site, window);
    LOG("CRC_PAGE name=%s stage=clean n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        name, repeats, execute, clean_crc, patched_crc, direct, site, window, repeats);

    long rc = crc_register(api, key, address, fake, UROV_Y_MODE_PAGE_AP, 0, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.session == 1 &&
            q.mode == UROV_Y_MODE_PAGE_AP,
            "CRC %s register rc=%ld errno=%d state=%u", name, rc, errno, q.state);
    if (!active) return;

    for (int i = 0; i < repeats; ++i) {
        execute = crc_execute(address);
        direct = crc_read_code(address, NULL);
        site = crc_read_code(address, uy_site_ldrb);
        window = crc_read_code(address, uy_business_ldrb);
        REQUIRE(execute == CRC_ORIGINAL_RETURN && direct == clean_crc && site == clean_crc &&
                window == patched_crc,
                "CRC %s overlay execute=%04x direct=%08x site=%08x window=%08x", name,
                execute, direct, site, window);
    }
    LOG("CRC_PAGE name=%s stage=overlay n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        name, repeats, execute, clean_crc, patched_crc, direct, site, window, repeats);

    q = uy_req(UROV_Y_STATUS);
    q.session = 1;
    REQUIRE(!api->control(key, &q) && q.state == UROV_Y_ACTIVE && q.generation == 1 &&
            q.hits >= (uint64_t)repeats * CRC_PAYLOAD_SIZE && q.failures == 0,
            "CRC %s counters hits=%llu replays=%llu failures=%llu", name,
            (unsigned long long)q.hits, (unsigned long long)q.replays,
            (unsigned long long)q.failures);
    LOG("CRC_OVERLAY mode=%u generation=%llu hits=%llu replays=%llu failures=%llu", q.mode,
        (unsigned long long)q.generation, (unsigned long long)q.hits,
        (unsigned long long)q.replays, (unsigned long long)q.failures);

    REQUIRE(!ud_mapping_at("/proc/self/smaps", address, &after) &&
            after.start == before.start && after.end == before.end &&
            after.offset == before.offset && !after.writable && after.executable &&
            !after.shared && after.maywrite &&
            !uy_mapping_private_kb(address, &dirty, &anon) && !dirty && !anon,
            "CRC %s active mapping changed", name);

    /* 2.14.0: a production CRC often wraps its hash in a protection change
     * (drop EXEC, or make the text writable while it inspects it).  A
     * protection-only change must not end the session or expose live bytes;
     * the restore to RX must still execute the original code. */
    {
        struct ud_mapping prot;
        uint64_t base = (uint64_t)address & ~(uint64_t)(UROV_Y_PAGE - 1U);
        long ctl_rc;

        REQUIRE(!ud_mapping_at("/proc/self/smaps", address, &prot),
                "CRC %s protection VMA errno=%d", name, errno);
        q = uy_req(UROV_Y_STATUS);
        q.session = 1;
        errno = 0;
        ctl_rc = api->control(key, &q);
        LOG("CRC_PROT_CTL name=%s stage=before rc=%ld errno=%d state=%u gen=%llu",
            name, ctl_rc, errno, q.state, (unsigned long long)q.generation);
        errno = 0;
        REQUIRE(!mprotect((void *)(uintptr_t)base, UROV_Y_PAGE, PROT_READ),
                "CRC %s mprotect(R) errno=%d", name, errno);
        direct = crc_read_code(address, NULL);
        window = crc_read_code(address, uy_business_ldrb);
        q = uy_req(UROV_Y_STATUS);
        q.session = 1;
        errno = 0;
        ctl_rc = api->control(key, &q);
        LOG("CRC_PROT_CTL name=%s stage=R rc=%ld errno=%d state=%u gen=%llu",
            name, ctl_rc, errno, q.state, (unsigned long long)q.generation);
        REQUIRE(direct == clean_crc && window == patched_crc &&
                !ctl_rc && q.state == UROV_Y_ACTIVE,
                "CRC %s prot(R) direct=%08x window=%08x state=%u", name, direct, window,
                q.state);
        errno = 0;
        REQUIRE(!mprotect((void *)(uintptr_t)base, UROV_Y_PAGE,
                          PROT_READ | PROT_WRITE),
                "CRC %s mprotect(RW) errno=%d", name, errno);
        direct = crc_read_code(address, NULL);
        window = crc_read_code(address, uy_business_ldrb);
        q = uy_req(UROV_Y_STATUS);
        q.session = 1;
        errno = 0;
        ctl_rc = api->control(key, &q);
        LOG("CRC_PROT_CTL name=%s stage=RW rc=%ld errno=%d state=%u gen=%llu",
            name, ctl_rc, errno, q.state, (unsigned long long)q.generation);
        REQUIRE(direct == clean_crc && window == patched_crc &&
                !ctl_rc && q.state == UROV_Y_ACTIVE,
                "CRC %s prot(RW) direct=%08x window=%08x state=%u", name, direct, window,
                q.state);
        errno = 0;
        REQUIRE(!mprotect((void *)(uintptr_t)base, UROV_Y_PAGE,
                          PROT_READ | PROT_EXEC),
                "CRC %s mprotect(RX) errno=%d", name, errno);
        execute = crc_execute(address);
        direct = crc_read_code(address, NULL);
        window = crc_read_code(address, uy_business_ldrb);
        q = uy_req(UROV_Y_STATUS);
        q.session = 1;
        errno = 0;
        ctl_rc = api->control(key, &q);
        LOG("CRC_PROT_CTL name=%s stage=RX rc=%ld errno=%d state=%u gen=%llu",
            name, ctl_rc, errno, q.state, (unsigned long long)q.generation);
        REQUIRE(execute == CRC_ORIGINAL_RETURN && direct == clean_crc &&
                window == patched_crc && !ctl_rc && q.state == UROV_Y_ACTIVE,
                "CRC %s prot restore execute=%04x direct=%08x window=%08x state=%u",
                name, execute, direct, window, q.state);
        LOG("CRC_PROT name=%s stage=all base=%llx execute=%04x direct=%08x window=%08x "
            "state=%u generation=%llu", name, (unsigned long long)base, execute, direct,
            window, q.state, (unsigned long long)q.generation);
    }

    /* mprotect() of one page inside the linker's multi-page .text splits that
     * VMA in the kernel and does not merge it back.  That is native VMA
     * bookkeeping caused by the probe, not by the module: re-baseline the
     * post-deactivate identity check on the resulting mapping. */
    REQUIRE(!ud_mapping_at("/proc/self/smaps", address, &before),
            "CRC %s protection re-baseline errno=%d", name, errno);
    LOG("CRC_PROT_VMA name=%s start=%llx end=%llx offset=%llx rx=%d shared=%d maywrite=%d",
        name, (unsigned long long)before.start, (unsigned long long)before.end,
        (unsigned long long)before.offset, before.readable && before.executable &&
        !before.writable, before.shared, before.maywrite);

    if (!crc_deactivate(api, key)) return;

    execute = crc_execute(address);
    direct = crc_read_code(address, NULL);
    site = crc_read_code(address, uy_site_ldrb);
    window = crc_read_code(address, uy_business_ldrb);
    REQUIRE(execute == CRC_ORIGINAL_RETURN && direct == clean_crc && site == clean_crc &&
            window == clean_crc,
            "CRC %s deactivated execute=%04x direct=%08x site=%08x window=%08x", name,
            execute, direct, site, window);
    LOG("CRC_PAGE name=%s stage=deactivated n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        name, repeats, execute, clean_crc, patched_crc, direct, site, window, repeats);

    REQUIRE(!ud_mapping_at("/proc/self/smaps", address, &after) &&
            after.start == before.start && after.end == before.end && !after.writable &&
            after.executable && !after.shared && after.maywrite &&
            !uy_mapping_private_kb(address, &dirty, &anon) && !dirty && !anon,
            "CRC %s deactivated mapping changed", name);
}

/* A private one-page RX alias of the installed library.  This was the shape
 * the old backend rejected solely because of VM_MAYWRITE; register it and
 * prove the overlay works before exercising the execmod write path. */
static void crc_private_case(const struct crc_patch_api *api, const char *key,
                             const uint8_t original[CRC_PAYLOAD_SIZE],
                             const uint8_t patched[CRC_PAYLOAD_SIZE], int repeats,
                             uint32_t clean_crc, uint32_t patched_crc)
{
    const void *linker_text = (const void *)(uintptr_t)&crc_original;
    struct page p;
    ++g_cases;
    if (page_open_at(&p, MAP_PRIVATE, linker_text)) {
        REQUIRE(0, "CRC private alias errno=%d", errno);
        return;
    }

    crc_ap_page_case("private_alias", api, key, p.address, p.file_offset, repeats,
                     clean_crc, patched_crc, patched);

    int written = 0;
    int error = api->patch_private(p.address, &written);
    uint32_t actual = crc_read_code(p.address, NULL);
    uint32_t returned = error ? 0 : crc_execute(p.address);
    LOG("CRC_PRIVATE wrote=%d patch_errno=%d direct=%08x execute=%04x",
        written, error, actual, returned);
    REQUIRE(error == 0 || error == EACCES || error == EPERM,
            "CRC private patch unexpected errno=%d", error);
    REQUIRE(actual == (written ? patched_crc : clean_crc),
            "CRC private patch bytes disagree with write result");
    if (!error) REQUIRE(written && returned == CRC_PATCHED_RETURN, "CRC COW execution");
    if (written && error) {
        /* This device leaves the alias PROT_READ|PROT_WRITE after execmod is
         * denied.  VM_WRITE must still disqualify the page. */
        crc_reject_mapping(api, key, p.address, original, "private_after_write");
    }
    page_close(&p);
}

/* The normal linker-loaded code segment: the VMA is multi-page, MAP_PRIVATE
 * and carries VM_MAYWRITE, which the old one-page/no-MAYWRITE check rejected.
 * Bind the .text page at &crc_original, fake its read view with the bytes of
 * the sibling crc_patched payload, and require execution to stay original. */
static void crc_text_case(const struct crc_patch_api *api, const char *key,
                          const void *text, const struct page *file,
                          const uint8_t original[CRC_PAYLOAD_SIZE],
                          const uint8_t patched[CRC_PAYLOAD_SIZE], int repeats,
                          uint32_t clean_crc, uint32_t patched_crc)
{
    struct ud_mapping m;
    uint8_t live[CRC_PAYLOAD_SIZE];
    Dl_info info;

    ++g_cases;
    if (ud_mapping_at("/proc/self/smaps", text, &m)) {
        REQUIRE(0, "CRC text smaps errno=%d", errno);
        return;
    }
    LOG("CRC_TEXT address=%p lib=%s span=%llu offset=%llx shared=%d maywrite=%d",
        text, dladdr(text, &info) ? info.dli_fname : "?",
        (unsigned long long)(m.end - m.start), (unsigned long long)m.offset,
        m.shared, m.maywrite);
    REQUIRE(((uintptr_t)text & (UROV_Y_PAGE - 1U)) == 0, "CRC text page alignment");
    REQUIRE(m.end - m.start > UROV_Y_PAGE && !m.shared && !m.writable &&
            m.readable && m.executable && m.maywrite,
            "CRC text is not the normal private multi-page code VMA");
    copy_scalar(live, text, sizeof(live));
    REQUIRE(!memcmp(live, original, sizeof(live)) &&
            !memcmp(live + CRC_STABLE_OFFSET, patched + CRC_STABLE_OFFSET,
                    CRC_PAYLOAD_SIZE - CRC_STABLE_OFFSET) &&
            memcmp(live + CRC_PATCH_OFFSET, patched + CRC_PATCH_OFFSET, 4),
            "CRC text bytes do not match the file payload");

    crc_ap_page_case("linker_text", api, key, text, file->file_offset, repeats,
                     clean_crc, patched_crc, patched);
}


/* libc readers: memcpy/memcmp/strlen are leaf routines in bionic, so the LR
 * at their loads is the business return address and matches the registered
 * window directly.  crc32 calls an internal helper first, so its load-time LR
 * points into libz; the backend's frame-pointer walk finds the saved business
 * LR, including when libz signs it with PACIASP. The sizes below exercise the
 * short bionic paths (12 bytes
 * for memcpy, 32 for memcmp and a 31-byte strlen); the SIMD >32-byte paths are a separate
 * limitation and are not exercised here. */
static void *(*volatile crc_libc_memcpy)(void *, const void *, size_t) = memcpy;
static int (*volatile crc_libc_memcmp)(const void *, const void *, size_t) = memcmp;
static size_t (*volatile crc_libc_strlen)(const char *) = strlen;
extern char crc_libc_start[], crc_libc_end[];

__attribute__((noinline))
static uint32_t crc_libc_business(const void *address, const uint8_t *fake,
                                  const uint8_t *original, uint8_t *copy,
                                  uint32_t *window_out)
{
    uint32_t bad = 0;
    __asm__ volatile(".global crc_libc_start\ncrc_libc_start:" ::: "memory");
    crc_libc_memcpy(copy, address, 12);
    if (crc_libc_memcmp(address, fake, 32) != 0) bad |= 1;
    if (crc_libc_memcmp(address, original, 32) == 0) bad |= 2;
    if (crc_libc_strlen((const char *)address) != 31) bad |= 4;
    if (crc32(0, (const Bytef *)address, 12) != crc_payload_bytes(fake)) bad |= 8;
    if (crc32(0, copy, 12) != crc_payload_bytes(fake)) bad |= 16;
    *window_out = crc_read_code(address, uy_business_ldrb);
    if (*window_out != crc_payload_bytes(fake)) bad |= 32;
    __asm__ volatile(".global crc_libc_end\ncrc_libc_end:" ::: "memory");
    return bad;
}

static int crc_libc_register(const struct crc_patch_api *api, const char *key,
                             const void *text, const uint8_t fake[32],
                             struct urov_y_request *out)
{
    *out = uy_req(UROV_Y_REGISTER);
    out->address = (uintptr_t)text;
    out->mode = UROV_Y_MODE_PAGE_AP;
    out->offset = 0;
    out->length = 32;
    memcpy(&out->value, fake, sizeof(out->value));
    memcpy(&out->value_hi[0], fake + 8, 8);
    memcpy(&out->value_hi[1], fake + 16, 8);
    memcpy(&out->value_hi[2], fake + 24, 8);
    out->site_count = 1;
    out->sites[0] = (uintptr_t)&uy_site_ldrb;
    out->caller_count = 1;
    out->caller_start[0] = (uintptr_t)crc_libc_start;
    out->caller_end[0] = (uintptr_t)crc_libc_end;
    return (int)api->control(key, out);
}

/* The normal .text page with a 32-byte fake view.  Bytes 12..30 are 0x41 and
 * byte 31 is zero, so strlen returns 31 without leaving the first scalar
 * 32-byte window; the original executable-page padding at +12 is NOPs, not
 * zeros.  The 12-byte CRC still matches the patched payload because only the
 * MOV at +4 differs. */
static void crc_libc_case(const struct crc_patch_api *api, const char *key,
                          const void *text, const struct page *file,
                          const struct page *patched, int repeats,
                          uint32_t clean_crc, uint32_t patched_crc)
{
    struct urov_y_request q;
    struct ud_mapping before, after;
    unsigned dirty, anon;
    uint8_t original[32], fake[32], direct[32], copy[32], live[12];
    uint32_t execute, direct_crc, site_crc, window_crc, window_out = 0;
    int active = 0;

    ++g_cases;
    if (app_pread(file->fd, file->file_offset, original, sizeof(original)) ||
        app_pread(patched->fd, patched->file_offset, fake, 12)) {
        REQUIRE(0, "CRC libc pages errno=%d", errno);
        return;
    }
    memset(fake + 12, 0x41, sizeof(fake) - 12);
    fake[31] = 0; /* strlen terminator inside the first scalar 32 bytes */
    REQUIRE(crc_payload_bytes(original) == clean_crc &&
            crc_payload_bytes(fake) == patched_crc,
            "CRC libc payload mismatch");
    if (ud_mapping_at("/proc/self/smaps", text, &before) ||
        uy_mapping_private_kb(text, &dirty, &anon)) {
        REQUIRE(0, "CRC libc mapping errno=%d", errno);
        return;
    }
    REQUIRE(!before.writable && before.readable && before.executable && !before.shared &&
            before.maywrite && before.end - (uintptr_t)text > UROV_Y_PAGE &&
            before.offset + ((uintptr_t)text - before.start) == (uint64_t)file->file_offset &&
            !dirty && !anon,
            "CRC libc VMA shape");
    LOG("CRC_LIBC_VMA span=%llu offset=%llx shared=%d maywrite=%d private_dirty_kb=%u "
        "anonymous_kb=%u",
        (unsigned long long)(before.end - before.start),
        (unsigned long long)before.offset, before.shared, before.maywrite, dirty, anon);

    copy_scalar(live, text, sizeof(live));
    REQUIRE(!memcmp(live, original, sizeof(live)), "CRC libc live page != file");
    execute = crc_execute(text);
    direct_crc = crc_read_code(text, NULL);
    site_crc = crc_read_code(text, uy_site_ldrb);
    window_crc = crc_read_code(text, uy_business_ldrb);
    REQUIRE(execute == CRC_ORIGINAL_RETURN && direct_crc == clean_crc &&
            site_crc == clean_crc && window_crc == clean_crc,
            "CRC libc clean execute=%04x direct=%08x site=%08x window=%08x",
            execute, direct_crc, site_crc, window_crc);
    LOG("CRC_STAGE name=clean n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, execute, clean_crc, patched_crc, direct_crc, site_crc, window_crc,
        repeats);

    int rc = crc_libc_register(api, key, text, fake, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.session == 1 &&
            q.mode == UROV_Y_MODE_PAGE_AP,
            "CRC libc register rc=%d errno=%d state=%u", rc, errno, q.state);
    if (!active) return;

    for (int i = 0; i < repeats; ++i) {
        uint32_t bad;
        memset(copy, 0, sizeof(copy));
        bad = crc_libc_business(text, fake, original, copy, &window_out);
        REQUIRE(bad == 0, "CRC libc readers bad=%u copy=%02x%02x%02x%02x", bad,
                copy[0], copy[1], copy[2], copy[3]);
        REQUIRE(crc_execute(text) == CRC_ORIGINAL_RETURN, "CRC libc execution changed");
        copy_scalar(direct, text, sizeof(direct));
        REQUIRE(!memcmp(direct, original, sizeof(direct)),
                "CRC libc direct read did not stay original");
    }
    LOG("CRC_LIBC n=%d window=%08x direct=%08x execute=%04x readers=memcpy12/memcmp32/"
        "strlen31/crc32-direct/crc32-copy",
        repeats, patched_crc, clean_crc, CRC_ORIGINAL_RETURN);
    execute = crc_execute(text);
    direct_crc = crc_read_code(text, NULL);
    site_crc = crc_read_code(text, uy_site_ldrb);
    window_crc = window_out;
    REQUIRE(execute == CRC_ORIGINAL_RETURN && direct_crc == clean_crc &&
            site_crc == clean_crc && window_crc == patched_crc,
            "CRC libc overlay execute=%04x direct=%08x site=%08x window=%08x",
            execute, direct_crc, site_crc, window_crc);
    LOG("CRC_STAGE name=overlay n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, execute, clean_crc, patched_crc, direct_crc, site_crc, window_crc,
        repeats);

    q = uy_req(UROV_Y_STATUS);
    q.session = 1;
    REQUIRE(!api->control(key, &q) && q.state == UROV_Y_ACTIVE && q.generation == 1 &&
            q.hits > 0 && q.failures == 0,
            "CRC libc counters hits=%llu failures=%llu", (unsigned long long)q.hits,
            (unsigned long long)q.failures);
    LOG("CRC_LIBC_OVERLAY hits=%llu replays=%llu failures=%llu",
        (unsigned long long)q.hits, (unsigned long long)q.replays,
        (unsigned long long)q.failures);

    REQUIRE(!ud_mapping_at("/proc/self/smaps", text, &after) &&
            after.start == before.start && after.end == before.end &&
            after.offset == before.offset && !after.writable && after.executable &&
            !after.shared && after.maywrite &&
            !uy_mapping_private_kb(text, &dirty, &anon) && !dirty && !anon,
            "CRC libc active mapping changed");

    if (!crc_deactivate(api, key)) return;
    copy_scalar(direct, text, sizeof(direct));
    execute = crc_execute(text);
    direct_crc = crc_read_code(text, NULL);
    site_crc = crc_read_code(text, uy_site_ldrb);
    window_crc = crc_read_code(text, uy_business_ldrb);
    REQUIRE(!memcmp(direct, original, sizeof(direct)) &&
            execute == CRC_ORIGINAL_RETURN && direct_crc == clean_crc &&
            site_crc == clean_crc && window_crc == clean_crc,
            "CRC libc deactivation did not restore direct=%08x window=%08x",
            direct_crc, window_crc);
    LOG("CRC_STAGE name=deactivated n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, execute, clean_crc, patched_crc, direct_crc, site_crc, window_crc,
        repeats);
    LOG("CRC_LIBC_RESTORED direct=%08x window=%08x", direct_crc, window_crc);
}

/* -------------------------------------------------- large libc transfers */

/* Register the whole target page as the overlay window and drive bionic's
 * memcpy/memcmp/strlen across it.  bionic switches memcpy to LDR Q/LDP Q from
 * 16 bytes, memcmp from 160 bytes and strlen past its first 32 bytes, so this
 * is the path that used to fail closed (SIGSEGV): the old ABI carried at most
 * 32 overlay bytes and no vector register could be committed.  ABI v7 serves
 * the SIMD&FP loads through the task's FPSIMD state and can publish a full
 * 4 KiB image, which is what the sizes below exercise. */
#define CRC_BIG_PAGE UROV_Y_FAKE_PAGE

static void *(*volatile crc_big_memcpy)(void *, const void *, size_t) = memcpy;
static int (*volatile crc_big_memcmp)(const void *, const void *, size_t) = memcmp;
static size_t (*volatile crc_big_strlen)(const char *) = strlen;
extern char crc_big_start[], crc_big_end[];

static uint8_t crc_big_fake[CRC_BIG_PAGE];
static uint8_t crc_big_original[CRC_BIG_PAGE];
static uint8_t crc_big_copy[CRC_BIG_PAGE];
static uint8_t crc_big_scratch[CRC_BIG_PAGE];

static void crc_big_fill(void)
{
    unsigned i;
    for (i = 0; i < CRC_BIG_PAGE; ++i)
        crc_big_fake[i] = (uint8_t)(0x41U + (i * 37U) % 90U);
    crc_big_fake[CRC_BIG_PAGE - 1] = 0; /* strlen terminator in the last chunk */
}

static uint32_t crc_big_crc(const uint8_t *bytes)
{
    return (uint32_t)crc32(0, bytes, CRC_BIG_PAGE);
}

/* Runs entirely inside the registered business window. */
__attribute__((noinline))
static uint32_t crc_big_business(const void *address, const uint8_t *fake,
                                 uint8_t *copy, uint8_t *scratch, size_t *strlen_out)
{
    static const size_t lens[] = { 16, 32, 64, 160, 512, 1024, 4096 };
    uint32_t bad = 0;
    unsigned i;

    __asm__ volatile(".global crc_big_start\ncrc_big_start:" ::: "memory");
    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); ++i) {
        crc_big_memcpy(copy, address, lens[i]);
        if (memcmp(copy, fake, lens[i]) != 0) bad |= 1U << i;
    }
    if (crc_big_memcmp(address, fake, CRC_BIG_PAGE) != 0) bad |= 1U << 8;
    *strlen_out = crc_big_strlen((const char *)address);
    if (*strlen_out != CRC_BIG_PAGE - 1) bad |= 1U << 9;
    crc_big_memcpy(scratch, address, CRC_BIG_PAGE);
    if (crc32(0, scratch, CRC_BIG_PAGE) != crc_big_crc(fake)) bad |= 1U << 10;
    __asm__ volatile(".global crc_big_end\ncrc_big_end:" ::: "memory");
    return bad;
}

static int crc_big_register(const struct crc_patch_api *api, const char *key,
                            const void *text, struct urov_y_request *out)
{
    *out = uy_req(UROV_Y_REGISTER);
    out->address = (uintptr_t)text;
    out->mode = UROV_Y_MODE_PAGE_AP;
    out->offset = 0;
    out->length = CRC_BIG_PAGE;
    out->fake_addr = (uintptr_t)crc_big_fake;
    out->site_count = 1;
    out->sites[0] = (uintptr_t)&uy_site_ldrb;
    out->caller_count = 1;
    out->caller_start[0] = (uintptr_t)crc_big_start;
    out->caller_end[0] = (uintptr_t)crc_big_end;
    return (int)api->control(key, out);
}

/* Second phase: the same 4 KiB transfer under a 32-byte window that does not
 * start at offset 0.  The merged view must be the page's own bytes, with only
 * [CRC_MIXED_OFFSET, +32) replaced, so this pins the per-byte merge across both
 * window edges under LDR Q/LDP Q.  It also re-publishes the image through SET,
 * which exercises the large-image update path and its generation check. */
#define CRC_MIXED_OFFSET 64U
#define CRC_MIXED_LEN 32U

extern char crc_mixed_start[], crc_mixed_end[];

__attribute__((noinline))
static uint32_t crc_mixed_business(const void *address, const uint8_t *expected,
                                   uint8_t *copy)
{
    uint32_t bad = 0;

    __asm__ volatile(".global crc_mixed_start\ncrc_mixed_start:" ::: "memory");
    crc_big_memcpy(copy, address, CRC_BIG_PAGE);
    if (memcmp(copy, expected, CRC_BIG_PAGE) != 0) bad |= 1;
    if (crc_big_memcmp(address, expected, CRC_BIG_PAGE) != 0) bad |= 2;
    if (crc32(0, copy, CRC_BIG_PAGE) != crc32(0, expected, CRC_BIG_PAGE)) bad |= 4;
    __asm__ volatile(".global crc_mixed_end\ncrc_mixed_end:" ::: "memory");
    return bad;
}

static void crc_mixed_expected(uint8_t *out, const uint8_t window[CRC_MIXED_LEN])
{
    memcpy(out, crc_big_original, CRC_BIG_PAGE);
    memcpy(out + CRC_MIXED_OFFSET, window, CRC_MIXED_LEN);
}

static int crc_mixed_register(const struct crc_patch_api *api, const char *key,
                              const void *text, const uint8_t window[CRC_MIXED_LEN],
                              struct urov_y_request *out)
{
    *out = uy_req(UROV_Y_REGISTER);
    out->address = (uintptr_t)text;
    out->mode = UROV_Y_MODE_PAGE_AP;
    out->offset = CRC_MIXED_OFFSET;
    out->length = CRC_MIXED_LEN;
    memcpy(&out->value, window, 8);
    memcpy(&out->value_hi[0], window + 8, 8);
    memcpy(&out->value_hi[1], window + 16, 8);
    memcpy(&out->value_hi[2], window + 24, 8);
    out->site_count = 1;
    out->sites[0] = (uintptr_t)&uy_site_ldrb;
    out->caller_count = 1;
    out->caller_start[0] = (uintptr_t)crc_mixed_start;
    out->caller_end[0] = (uintptr_t)crc_mixed_end;
    return (int)api->control(key, out);
}

static void crc_big_case(const struct crc_patch_api *api, const char *key,
                         const void *text, int repeats)
{
    struct urov_y_request q;
    struct ud_mapping before, after;
    unsigned dirty, anon;
    uint32_t orig_crc, fake_crc, execute, window_crc;
    size_t strlen_out = 0;
    int active = 0;

    ++g_cases;
    if (ud_mapping_at("/proc/self/smaps", text, &before) ||
        uy_mapping_private_kb(text, &dirty, &anon)) {
        REQUIRE(0, "CRC big mapping errno=%d", errno);
        return;
    }
    REQUIRE(!before.writable && before.readable && before.executable && !before.shared &&
            before.maywrite && before.end - (uintptr_t)text >= CRC_BIG_PAGE &&
            !dirty && !anon,
            "CRC big VMA shape span=%llu dirty=%u anon=%u",
            (unsigned long long)(before.end - before.start), dirty, anon);
    LOG("CRC_BIG_VMA span=%llu offset=%llx shared=%d maywrite=%d private_dirty_kb=%u "
        "anonymous_kb=%u",
        (unsigned long long)(before.end - before.start),
        (unsigned long long)before.offset, before.shared, before.maywrite, dirty, anon);

    crc_big_fill();
    copy_scalar(crc_big_original, text, CRC_BIG_PAGE);
    REQUIRE(memcmp(crc_big_original, crc_big_fake, CRC_BIG_PAGE) != 0,
            "CRC big fake image equals the mapped page");
    orig_crc = crc_big_crc(crc_big_original);
    fake_crc = crc_big_crc(crc_big_fake);
    execute = crc_execute(text);
    REQUIRE(execute == CRC_ORIGINAL_RETURN, "CRC big clean execution=%04x", execute);
    LOG("CRC_STAGE name=clean n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, execute, orig_crc, fake_crc, orig_crc, orig_crc, orig_crc, repeats);

    int rc = crc_big_register(api, key, text, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.session == 1 &&
            q.mode == UROV_Y_MODE_PAGE_AP && q.length == CRC_BIG_PAGE,
            "CRC big register rc=%d errno=%d state=%u length=%u", rc, errno, q.state,
            q.length);
    if (!active) return;

    for (int i = 0; i < repeats; ++i) {
        uint32_t bad = crc_big_business(text, crc_big_fake, crc_big_copy,
                                        crc_big_scratch, &strlen_out);
        REQUIRE(bad == 0, "CRC big reader mask=%08x strlen=%zu", bad, strlen_out);
        REQUIRE(crc_execute(text) == CRC_ORIGINAL_RETURN, "CRC big execution changed");
        /* A call from outside the business window must see the original page
         * even for a 4 KiB transfer; every load takes the replay path. */
        memset(crc_big_scratch, 0, CRC_BIG_PAGE);
        crc_libc_memcpy(crc_big_scratch, text, CRC_BIG_PAGE);
        REQUIRE(!memcmp(crc_big_scratch, crc_big_original, CRC_BIG_PAGE),
                "CRC big outside-window memcpy did not stay original");
        copy_scalar(crc_big_copy, text, CRC_BIG_PAGE);
        REQUIRE(!memcmp(crc_big_copy, crc_big_original, CRC_BIG_PAGE),
                "CRC big outside-window read did not stay original");
    }
    (void)crc_big_business(text, crc_big_fake, crc_big_copy, crc_big_scratch, &strlen_out);
    window_crc = crc_big_crc(crc_big_copy);
    REQUIRE(window_crc == fake_crc, "CRC big window=%08x fake=%08x", window_crc, fake_crc);
    LOG("CRC_BIG n=%d lengths=16,32,64,160,512,1024,4096 fake_crc=%08x window_crc=%08x "
        "strlen=%zu file_crc=%08x", repeats, fake_crc, window_crc, strlen_out, orig_crc);
    LOG("CRC_STAGE name=overlay n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, crc_execute(text), orig_crc, fake_crc, orig_crc, orig_crc, window_crc,
        repeats);

    q = uy_req(UROV_Y_STATUS);
    q.session = 1;
    REQUIRE(!api->control(key, &q) && q.state == UROV_Y_ACTIVE && q.generation == 1 &&
            q.length == CRC_BIG_PAGE && q.hits > 0 && q.failures == 0,
            "CRC big counters hits=%llu failures=%llu length=%u",
            (unsigned long long)q.hits, (unsigned long long)q.failures, q.length);
    LOG("CRC_BIG_OVERLAY hits=%llu replays=%llu failures=%llu length=%u",
        (unsigned long long)q.hits, (unsigned long long)q.replays,
        (unsigned long long)q.failures, q.length);

    REQUIRE(!ud_mapping_at("/proc/self/smaps", text, &after) &&
            after.start == before.start && after.end == before.end &&
            after.offset == before.offset && !after.writable && after.executable &&
            !after.shared && after.maywrite &&
            !uy_mapping_private_kb(text, &dirty, &anon) && !dirty && !anon,
            "CRC big active mapping changed");

    if (!crc_deactivate(api, key)) return;
    copy_scalar(crc_big_original, text, CRC_BIG_PAGE);
    execute = crc_execute(text);
    REQUIRE(crc_big_crc(crc_big_original) == orig_crc &&
            execute == CRC_ORIGINAL_RETURN,
            "CRC big deactivation did not restore page=%08x execute=%04x",
            crc_big_crc(crc_big_original), execute);
    window_crc = crc_big_crc(crc_big_original);
    LOG("CRC_STAGE name=deactivated n=%d execute=%04x file=%08x backing=%08x direct=%08x "
        "site=%08x window=%08x bridge_match=0 bridge_clean=%d bridge_unknown=0",
        repeats, execute, orig_crc, fake_crc, window_crc, window_crc, window_crc, repeats);
    LOG("CRC_BIG_RESTORED page=%08x", window_crc);

    /* Phase 2: 32-byte interior window inside the same 4 KiB transfer. */
    uint8_t window_a[CRC_MIXED_LEN], window_b[CRC_MIXED_LEN];
    for (unsigned i = 0; i < CRC_MIXED_LEN; ++i) {
        window_a[i] = (uint8_t)(0xf0U - i);
        window_b[i] = (uint8_t)(0x21U + (i * 11U) % 0x50U);
    }
    crc_mixed_expected(crc_big_scratch, window_a);
    uint32_t expected_crc = crc_big_crc(crc_big_scratch);
    rc = crc_mixed_register(api, key, text, window_a, &q);
    active = rc == 0;
    REQUIRE(active && q.state == UROV_Y_ACTIVE && q.session == 1 &&
            q.mode == UROV_Y_MODE_PAGE_AP && q.length == CRC_MIXED_LEN &&
            q.offset == CRC_MIXED_OFFSET,
            "CRC mixed register rc=%d errno=%d state=%u length=%u offset=%u",
            rc, errno, q.state, q.length, q.offset);
    if (!active) return;
    for (int i = 0; i < repeats; ++i) {
        uint32_t bad = crc_mixed_business(text, crc_big_scratch, crc_big_copy);
        REQUIRE(bad == 0, "CRC mixed reader mask=%08x", bad);
        REQUIRE(crc_big_crc(crc_big_copy) == expected_crc,
                "CRC mixed window=%08x expected=%08x", crc_big_crc(crc_big_copy),
                expected_crc);
        REQUIRE(crc_execute(text) == CRC_ORIGINAL_RETURN, "CRC mixed execution changed");
    }
    LOG("CRC_MIXED n=%d offset=%u length=%u window_crc=%08x file_crc=%08x",
        repeats, CRC_MIXED_OFFSET, CRC_MIXED_LEN, expected_crc, orig_crc);

    crc_mixed_expected(crc_big_scratch, window_b);
    uint32_t set_crc = crc_big_crc(crc_big_scratch);
    q = uy_req(UROV_Y_SET);
    q.session = 1;
    q.expected_generation = 1;
    q.length = CRC_MIXED_LEN;
    memcpy(&q.value, window_b, 8);
    memcpy(&q.value_hi[0], window_b + 8, 8);
    memcpy(&q.value_hi[1], window_b + 16, 8);
    memcpy(&q.value_hi[2], window_b + 24, 8);
    rc = (int)api->control(key, &q);
    REQUIRE(rc == 0 && q.generation == 2 && q.length == CRC_MIXED_LEN,
            "CRC mixed set rc=%d errno=%d generation=%llu", rc, errno,
            (unsigned long long)q.generation);
    for (int i = 0; rc == 0 && i < repeats; ++i) {
        uint32_t bad = crc_mixed_business(text, crc_big_scratch, crc_big_copy);
        REQUIRE(bad == 0, "CRC mixed set reader mask=%08x", bad);
        REQUIRE(crc_big_crc(crc_big_copy) == set_crc,
                "CRC mixed set window=%08x expected=%08x", crc_big_crc(crc_big_copy),
                set_crc);
    }
    LOG("CRC_SET n=%d generation=%llu length=%u window_crc=%08x file_crc=%08x",
        repeats, (unsigned long long)q.generation, CRC_MIXED_LEN, set_crc, orig_crc);
    if (!crc_deactivate(api, key)) return;
    copy_scalar(crc_big_original, text, CRC_BIG_PAGE);
    REQUIRE(crc_big_crc(crc_big_original) == orig_crc,
            "CRC mixed deactivation did not restore page=%08x", crc_big_crc(crc_big_original));
    LOG("CRC_MIXED_RESTORED page=%08x", crc_big_crc(crc_big_original));
}

/* The checksum and the bridge check use only app-owned mappings. The fake
 * bytes, key, and authenticated requests are inputs to the fixture alone. */
static void crc_copy_window(uint8_t *out, const uint8_t *address, size_t size)
{
    for (size_t i = 0; i < size; ++i) out[i] = (uint8_t)uy_business_ldrb(address + i);
}

static void crc_stage(const char *name, const struct page *target, const struct page *backing,
                      uint32_t clean_crc, uint32_t patched_crc, int repeats,
                      unsigned active_mode, int all_callers)
{
    int patched = backing != target;
    const void *reference = patched ? backing->address : (const void *)(uintptr_t)&crc_original;
    uint32_t live_crc = patched ? patched_crc : clean_crc;
    uint32_t direct_expected = all_callers ? clean_crc : live_crc;
    uint32_t window_expected = active_mode ? clean_crc : live_crc;
    /* With no caller window every reader and the kernel-assisted view see the
     * registered image; the reference bytes are the original page.  With a
     * window the GUP view follows the snapshot outside it. */
    const struct page *expected_page = all_callers ? target : backing;
    unsigned match = 0, clean = 0, unknown = 0;
    unsigned direct_match = 0, window_match = 0, live_unknown = 0;
    uint32_t direct = 0, site = 0, window = 0, returned = 0, kernel = 0;
    uint8_t expected[CRC_PAYLOAD_SIZE];

    ++g_cases;
    if (app_pread(expected_page->fd, expected_page->file_offset, expected, sizeof(expected))) {
        REQUIRE(0, "CRC %s backing read", name);
        return;
    }
    for (int i = 0; i < repeats; ++i) {
        struct ud_store_observation obs;
        struct ud_live_observation direct_live, window_live;
        returned = crc_execute(target->address);
        ud_observe_live(target->address, CRC_PAYLOAD_SIZE, backing->fd, backing->file_offset,
                        copy_scalar, &direct_live);
        ud_observe_live(target->address, CRC_PAYLOAD_SIZE, backing->fd, backing->file_offset,
                        crc_copy_window, &window_live);
        direct = crc_payload_bytes(direct_live.user_bytes);
        window = crc_payload_bytes(window_live.user_bytes);
        kernel = crc_payload_bytes(window_live.kernel_bytes);
        direct_match += direct_live.verdict == UD_MATCH;
        window_match += window_live.verdict == UD_MATCH;
        live_unknown += direct_live.verdict == UD_UNKNOWN || window_live.verdict == UD_UNKNOWN;
        REQUIRE(direct_live.verdict == UD_NO_MATCH &&
                window_live.verdict == (active_mode && !all_callers ? UD_MATCH : UD_NO_MATCH) &&
                !memcmp(direct_live.kernel_bytes, expected, sizeof(expected)) &&
                !memcmp(window_live.kernel_bytes, expected, sizeof(expected)),
                "CRC %s live views direct=%d error=%d window=%d error=%d kernel=%08x",
                name, direct_live.verdict, direct_live.error, window_live.verdict,
                window_live.error, kernel);
        site = crc_read_code(target->address, uy_site_ldrb);
        ud_observe_unreserved_store(target->address + CRC_STABLE_OFFSET,
                                    (const uint8_t *)reference + CRC_STABLE_OFFSET,
                                    backing->fd, backing->file_offset + CRC_STABLE_OFFSET, &obs);
        REQUIRE(returned == (patched ? CRC_PATCHED_RETURN : CRC_ORIGINAL_RETURN) &&
                direct == direct_expected && site == direct_expected && window == window_expected,
                "CRC %s execute=%04x direct=%08x site=%08x window=%08x", name,
                returned, direct, site, window);
        /* The probe skips LDXR. Even PAGE_AP must leave that STXR native. */
        REQUIRE(obs.verdict == UD_NO_MATCH, "CRC %s bridge=%d error=%d", name,
                obs.verdict, obs.error);
        match += obs.verdict == UD_MATCH;
        clean += obs.verdict == UD_NO_MATCH;
        unknown += obs.verdict == UD_UNKNOWN;
    }
    LOG("CRC_STAGE name=%s n=%d execute=%04x file=%08x backing=%08x direct=%08x site=%08x "
        "window=%08x bridge_match=%u bridge_clean=%u bridge_unknown=%u kernel=%08x "
        "direct_match=%u window_match=%u live_unknown=%u",
        name, repeats, returned, clean_crc, live_crc, direct, site, window, match, clean, unknown,
        kernel, direct_match, window_match, live_unknown);
}

static void crc_overlay_signals(const struct page *target, const struct page *patched,
                                const struct page *exec_reference, unsigned mode,
                                int all_callers, int repeats)
{
    uint32_t file_word = 0;
    uint32_t site_word = load32_at((const uint8_t *)(uintptr_t)&uy_site_ldrb);
    off_t offset = exec_reference->file_offset + (uintptr_t)&uy_site_ldrb % UROV_Y_PAGE;
    int error = app_pread(exec_reference->fd, offset, (uint8_t *)&file_word, sizeof(file_word));
    REQUIRE(!error && file_word == 0x39400000U &&
            (site_word != file_word) == (mode == UROV_Y_MODE_SITE_BRK),
            "CRC read-site file=%08x live=%08x", file_word, site_word);
    LOG("CRC_SITE file=%08x live=%08x differs=%d", file_word, site_word, file_word != site_word);
    elimination_exec_case("crc_overlay", exec_reference, repeats,
                          mode == UROV_Y_MODE_PAGE_UXN ? UD_MATCH : UD_NO_MATCH);

    struct ud_store_observation obs;
    /* In all-caller AP mode the observed byte can differ from the backing file. */
    enum ud_verdict changed_byte = mode == UROV_Y_MODE_PAGE_AP && all_callers ? UD_UNKNOWN : UD_NO_MATCH;
    ud_observe_unreserved_store(target->address + CRC_PATCH_OFFSET,
                                patched->address + CRC_PATCH_OFFSET, patched->fd,
                                patched->file_offset + CRC_PATCH_OFFSET, &obs);
    REQUIRE(obs.verdict == changed_byte && (changed_byte != UD_UNKNOWN || obs.error == EAGAIN),
            "CRC changed byte probe verdict=%d errno=%d", obs.verdict, obs.error);
    LOG("CRC_CHANGED_BYTE probe=%d error=%d completed=%u", obs.verdict, obs.error, obs.completed);
}

/* Linux rejects the advice before touching the VMA.  Since 2.12.0 the range
 * gate no longer reads that rejection as a request to restore the session:
 * only the authenticated DEACTIVATE ends an active overlay. */
static bool crc_revoke(const struct crc_patch_api *api, const char *key,
                       const struct page *target, unsigned mode)
{
    int advice_error = uy_invalid_advice(target->address, UROV_Y_PAGE);
    struct urov_y_request q = uy_req(UROV_Y_STATUS);
    int survived;

    q.session = 1;
    survived = !api->control(key, &q) && q.state == UROV_Y_ACTIVE;
    REQUIRE(advice_error == EINVAL && survived,
            "CRC invalid advice changed the session errno=%d state=%u",
            advice_error, q.state);
    LOG("CRC_RESTORE mode=%u madvise_errno=%d survived=%d", mode, advice_error, survived);
    return crc_deactivate(api, key);
}

static void crc_injection(const char *mode_name, const char *key, int repeats,
                          uint32_t *clean_crc, uint32_t *patched_crc)
{
    struct page target = { .fd = -1 }, patched = { .fd = -1 }, exec_reference = { .fd = -1 };
    uint8_t original[CRC_PAYLOAD_SIZE], modified[CRC_PAYLOAD_SIZE], after[CRC_PAYLOAD_SIZE];
    unsigned mode = 0;
    int all_callers = !strcmp(mode_name, "crc-ap-all");
    int text_target = !strcmp(mode_name, "crc-ap-text");
    int libc_target = !strcmp(mode_name, "crc-ap-libc");
    int big_target = !strcmp(mode_name, "crc-ap-big");
    int active = 0;
    const void *text = (const void *)(uintptr_t)&crc_original;
    void *library;

    if (!strcmp(mode_name, "crc-brk")) mode = UROV_Y_MODE_SITE_BRK;
    else if (!strcmp(mode_name, "crc-uxn")) mode = UROV_Y_MODE_PAGE_UXN;
    else if (!strcmp(mode_name, "crc-ap") || all_callers || text_target || libc_target ||
             big_target)
        mode = UROV_Y_MODE_PAGE_AP;
    else if (strcmp(mode_name, "crc-clean")) { REQUIRE(0, "unknown CRC mode"); return; }

    library = dlopen("liburov_crc_patch.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) { REQUIRE(0, "CRC fixture dlopen %s", dlerror()); return; }
    struct crc_patch_api api = {
        .patch_private = dlsym(library, "urov_crc_patch_private"),
        .remap = dlsym(library, "urov_crc_remap"),
        .control = dlsym(library, "urov_crc_control"),
    };
    if (!api.patch_private || !api.remap || !api.control) {
        REQUIRE(0, "CRC fixture missing symbols");
        goto done;
    }
    LOG("CRC_FIXTURE dlopen=1 mode=%s all_callers=%d", mode_name, all_callers);
    if (sysconf(_SC_PAGESIZE) != UROV_Y_PAGE ||
        page_open_at(&target, MAP_SHARED, (const void *)(uintptr_t)&crc_original) ||
        page_open_at(&patched, MAP_SHARED, (const void *)(uintptr_t)&crc_patched) ||
        target.entry || patched.entry || target.file_offset == patched.file_offset ||
        app_pread(target.fd, target.file_offset, original, sizeof(original)) ||
        app_pread(patched.fd, patched.file_offset, modified, sizeof(modified))) {
        REQUIRE(0, "CRC test pages errno=%d", errno);
        goto done;
    }
    *clean_crc = crc_payload_bytes(original);
    *patched_crc = crc_payload_bytes(modified);
    if (crc32(0, (const Bytef *)"123456789", 9) != UINT32_C(0xcbf43926) ||
        *clean_crc == *patched_crc || memcmp(original, modified, CRC_PATCH_OFFSET) ||
        memcmp(original + CRC_STABLE_OFFSET, modified + CRC_STABLE_OFFSET,
               CRC_PAYLOAD_SIZE - CRC_STABLE_OFFSET)) {
        REQUIRE(0, "CRC payload or CRC32 self-test failed");
        goto done;
    }

    if (mode) {
        struct urov_y_request q = uy_req(UROV_Y_QUERY);
        if (api.control(key, &q) || q.state != UROV_Y_INACTIVE) {
            REQUIRE(0, "CRC authenticated query errno=%d state=%u", errno, q.state);
            goto done;
        }
        LOG("CRC_QUERY authenticated=1 state=%u", q.state);
        if (!text_target && !libc_target && !big_target && mode == UROV_Y_MODE_PAGE_AP && !all_callers)
            crc_private_case(&api, key, original, modified, repeats, *clean_crc,
                             *patched_crc);
        if (!text_target && !libc_target && !big_target && uy_open_exec_reference(&exec_reference)) {
            REQUIRE(0, "CRC open reader canary alias errno=%d", errno);
            goto done;
        }
    }

    if (text_target || libc_target || big_target) {
        if (text_target)
            crc_text_case(&api, key, text, &target, original, modified, repeats,
                          *clean_crc, *patched_crc);
        if (libc_target)
            crc_libc_case(&api, key, text, &target, &patched, repeats,
                          *clean_crc, *patched_crc);
        if (big_target)
            crc_big_case(&api, key, text, repeats);
        REQUIRE(!app_pread(target.fd, target.file_offset, after, sizeof(after)) &&
                !memcmp(original, after, sizeof(after)), "CRC text file bytes changed");
        goto done;
    }

    crc_stage("clean", &target, &target, *clean_crc, *patched_crc, repeats, 0, 0);
    int error = api.remap(target.address, patched.fd, patched.file_offset);
    REQUIRE(!error, "CRC fixture code remap errno=%d", error);
    if (error) goto done;
    LOG("CRC_REMAP same_va=1 original_offset=%lld patched_offset=%lld",
        (long long)target.file_offset, (long long)patched.file_offset);
    struct ud_views views;
    ud_check_views(target.address, CRC_PAYLOAD_SIZE, target.fd, target.file_offset, &views);
    REQUIRE(views.file_diff == UD_UNKNOWN && views.error_file == ESTALE,
            "CRC original mapping identity verdict=%d errno=%d", views.file_diff, views.error_file);
    struct ud_live_observation stale;
    ud_observe_live(target.address, CRC_PAYLOAD_SIZE, target.fd, target.file_offset, copy_scalar,
                    &stale);
    REQUIRE(stale.verdict == UD_UNKNOWN && stale.error == ESTALE,
            "CRC stale live mapping verdict=%d errno=%d", stale.verdict, stale.error);
    LOG("CRC_MAP original_identity=%d error=%d", views.file_diff, views.error_file);
    crc_stage("patch_only", &target, &patched, *clean_crc, *patched_crc, repeats, 0, 0);

    if (mode) {
        struct urov_y_request q;
        long rc = crc_register(&api, key, target.address, original, mode, all_callers, &q);
        active = rc == 0;
        REQUIRE(active && q.state == UROV_Y_ACTIVE && q.session == 1 && q.mode == mode,
                "CRC overlay register rc=%ld errno=%d state=%u", rc, errno, q.state);
        if (!active) goto done;
        crc_stage("overlay", &target, &patched, *clean_crc, *patched_crc, repeats, mode, all_callers);
        crc_overlay_signals(&target, &patched, &exec_reference, mode, all_callers, repeats);
        q = uy_req(UROV_Y_STATUS);
        q.session = 1;
        REQUIRE(!api.control(key, &q) && q.state == UROV_Y_ACTIVE && q.generation == 1 &&
                q.hits >= (uint64_t)repeats * CRC_PAYLOAD_SIZE && q.failures == 0,
                "CRC overlay counters hits=%llu failures=%llu", (unsigned long long)q.hits,
                (unsigned long long)q.failures);
        LOG("CRC_OVERLAY mode=%u generation=%llu hits=%llu replays=%llu failures=%llu", q.mode,
            (unsigned long long)q.generation, (unsigned long long)q.hits,
            (unsigned long long)q.replays, (unsigned long long)q.failures);
        if (!crc_revoke(&api, key, &target, mode)) goto done;
        active = 0;
        crc_stage("deactivated", &target, &patched, *clean_crc, *patched_crc, repeats, 0, 0);
        if (!crc_lock_guard(&api, key, target.address, original, mode, all_callers, repeats,
                            "shared_alias")) goto done;

        if (all_callers) {
            rc = crc_register(&api, key, target.address, original, mode, all_callers, &q);
            active = rc == 0;
            REQUIRE(active && q.state == UROV_Y_ACTIVE, "CRC re-register rc=%ld errno=%d", rc, errno);
            if (!active) goto done;
            struct ud_live_observation live;
            ud_observe_live(target.address, sizeof(original), patched.fd, patched.file_offset,
                            copy_scalar, &live);
            REQUIRE(live.verdict == UD_NO_MATCH &&
                    !memcmp(live.user_bytes, original, sizeof(original)) &&
                    !memcmp(live.kernel_bytes, original, sizeof(original)),
                    "CRC re-registered overlay verdict=%d errno=%d", live.verdict, live.error);
            LOG("CRC_REREGISTER state=%u match=%d", q.state, live.verdict);
            active = !crc_revoke(&api, key, &target, mode);
        }
    }
    REQUIRE(!app_pread(target.fd, target.file_offset, after, sizeof(after)) &&
            !memcmp(original, after, sizeof(after)), "CRC original file bytes changed");
done:
    if (active) (void)crc_deactivate(&api, key);
    page_close(&exec_reference);
    page_close(&patched);
    page_close(&target);
    dlclose(library);
}
