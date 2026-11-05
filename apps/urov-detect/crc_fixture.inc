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

    q = uy_req(UROV_Y_REGISTER);
    q.address = (uintptr_t)address;
    q.mode = UROV_Y_MODE_PAGE_AP;
    q.offset = 0;
    q.length = sizeof(q.value);
    memcpy(&q.value, fake, sizeof(q.value));
    q.site_count = 1;
    q.sites[0] = (uintptr_t)&uy_site_ldrb;
    q.caller_count = 1;
    q.caller_start[0] = (uintptr_t)&uy_business_ldrb;
    q.caller_end[0] = (uintptr_t)uy_business_ldrb_end;
    long rc = api->control(key, &q);
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
 * LR.  The sizes below deliberately select bionic's scalar paths (12 bytes
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

/* The checksum and the bridge check use only app-owned mappings. The fake
 * bytes, key, and authenticated requests are inputs to the fixture alone. */
static void crc_stage(const char *name, const struct page *target, const struct page *backing,
                      uint32_t clean_crc, uint32_t patched_crc, int repeats,
                      unsigned active_mode, int all_callers)
{
    int patched = backing != target;
    const void *reference = patched ? backing->address : (const void *)(uintptr_t)&crc_original;
    uint32_t live_crc = patched ? patched_crc : clean_crc;
    uint32_t direct_expected = all_callers ? clean_crc : live_crc;
    uint32_t window_expected = active_mode ? clean_crc : live_crc;
    unsigned match = 0, clean = 0, unknown = 0;
    uint32_t direct = 0, site = 0, window = 0, returned = 0;

    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        struct ud_store_observation obs;
        returned = crc_execute(target->address);
        direct = crc_read_code(target->address, NULL);
        site = crc_read_code(target->address, uy_site_ldrb);
        window = crc_read_code(target->address, uy_business_ldrb);
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
        "window=%08x bridge_match=%u bridge_clean=%u bridge_unknown=%u",
        name, repeats, returned, clean_crc, live_crc, direct, site, window, match, clean, unknown);
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

static void crc_injection(const char *mode_name, const char *key, int repeats,
                          uint32_t *clean_crc, uint32_t *patched_crc)
{
    struct page target = { .fd = -1 }, patched = { .fd = -1 }, exec_reference = { .fd = -1 };
    uint8_t original[CRC_PAYLOAD_SIZE], modified[CRC_PAYLOAD_SIZE], after[CRC_PAYLOAD_SIZE];
    unsigned mode = 0;
    int all_callers = !strcmp(mode_name, "crc-ap-all");
    int text_target = !strcmp(mode_name, "crc-ap-text");
    int libc_target = !strcmp(mode_name, "crc-ap-libc");
    int active = 0;
    const void *text = (const void *)(uintptr_t)&crc_original;
    void *library;

    if (!strcmp(mode_name, "crc-brk")) mode = UROV_Y_MODE_SITE_BRK;
    else if (!strcmp(mode_name, "crc-uxn")) mode = UROV_Y_MODE_PAGE_UXN;
    else if (!strcmp(mode_name, "crc-ap") || all_callers || text_target || libc_target)
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
        if (!text_target && !libc_target && mode == UROV_Y_MODE_PAGE_AP && !all_callers)
            crc_private_case(&api, key, original, modified, repeats, *clean_crc,
                             *patched_crc);
        if (!text_target && !libc_target && uy_open_exec_reference(&exec_reference)) {
            REQUIRE(0, "CRC open reader canary alias errno=%d", errno);
            goto done;
        }
    }

    if (text_target || libc_target) {
        if (text_target)
            crc_text_case(&api, key, text, &target, original, modified, repeats,
                          *clean_crc, *patched_crc);
        if (libc_target)
            crc_libc_case(&api, key, text, &target, &patched, repeats,
                          *clean_crc, *patched_crc);
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
        if (!crc_deactivate(&api, key)) goto done;
        active = 0;
        crc_stage("deactivated", &target, &patched, *clean_crc, *patched_crc, repeats, 0, 0);
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
