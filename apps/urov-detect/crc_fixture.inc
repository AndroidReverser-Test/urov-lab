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
    LOG("CRC_REJECT name=%s span=%llu rx=%d maywrite=%d register_rc=%ld register_errno=%d",
        name, (unsigned long long)(mapping.end - mapping.start),
        mapping.readable && mapping.executable && !mapping.writable,
        mapping.maywrite, rc, rejected_errno);
    REQUIRE(rc == -1 && rejected_errno == EINVAL, "CRC %s unexpectedly registered", name);
    if (!rc) (void)crc_deactivate(api, key);
}

static void crc_private_case(const struct crc_patch_api *api, const char *key,
                             const uint8_t original[CRC_PAYLOAD_SIZE], uint32_t patched_crc)
{
    const void *linker_text = (const void *)(uintptr_t)&crc_original;
    struct page p;
    ++g_cases;
    crc_reject_mapping(api, key, linker_text, original, "linker_text");
    if (page_open_at(&p, MAP_PRIVATE, linker_text)) {
        REQUIRE(0, "CRC private alias errno=%d", errno);
        return;
    }
    crc_reject_mapping(api, key, p.address, original, "private_rx_alias");

    int written = 0;
    int error = api->patch_private(p.address, &written);
    uint32_t actual = crc_read_code(p.address, NULL);
    uint32_t returned = error ? 0 : crc_execute(p.address);
    LOG("CRC_PRIVATE wrote=%d patch_errno=%d direct=%08x execute=%04x",
        written, error, actual, returned);
    REQUIRE(error == 0 || error == EACCES || error == EPERM,
            "CRC private patch unexpected errno=%d", error);
    REQUIRE(actual == (written ? patched_crc : crc_payload_bytes(original)),
            "CRC private patch bytes disagree with write result");
    if (!error) REQUIRE(written && returned == CRC_PATCHED_RETURN, "CRC COW execution");
    if (written) crc_reject_mapping(api, key, p.address, original, "private_after_write");
    page_close(&p);
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
    enum ud_verdict bridge_expected = active_mode == UROV_Y_MODE_PAGE_AP ? UD_MATCH : UD_NO_MATCH;
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
        REQUIRE(obs.verdict == bridge_expected, "CRC %s bridge=%d error=%d", name,
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
    enum ud_verdict changed_byte = UD_NO_MATCH;
    if (mode == UROV_Y_MODE_PAGE_AP) changed_byte = all_callers ? UD_UNKNOWN : UD_MATCH;
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
    int active = 0;
    void *library;

    if (!strcmp(mode_name, "crc-brk")) mode = UROV_Y_MODE_SITE_BRK;
    else if (!strcmp(mode_name, "crc-uxn")) mode = UROV_Y_MODE_PAGE_UXN;
    else if (!strcmp(mode_name, "crc-ap") || all_callers) mode = UROV_Y_MODE_PAGE_AP;
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
        if (mode == UROV_Y_MODE_PAGE_AP && !all_callers)
            crc_private_case(&api, key, original, *patched_crc);
        if (uy_open_exec_reference(&exec_reference)) {
            REQUIRE(0, "CRC open reader canary alias errno=%d", errno);
            goto done;
        }
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
