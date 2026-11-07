/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <dobby.h>

/* Keep the patch and AP trap on a dedicated ELF text page on 4 KiB and
 * 16 KiB kernels. The payload is eight instructions (32 bytes). */
__asm__(".pushsection .text.urov_dobby_payload,\"ax\",%progbits\n"
        ".p2align 14\n.global dobby_crc_payload\n.hidden dobby_crc_payload\n"
        ".type dobby_crc_payload,%function\ndobby_crc_payload:\n"
        "hint #34\nmov w0, #0x1234\n.rept 5\nnop\n.endr\nret\n"
        ".size dobby_crc_payload, .-dobby_crc_payload\n.p2align 14\n.popsection\n");
extern uint32_t dobby_crc_payload(void);

enum { DOBBY_CRC_BYTES = 32, DOBBY_ORIGINAL = 0x1234, DOBBY_HOOKED = 0x1235 };
static pthread_mutex_t dobby_crc_lock = PTHREAD_MUTEX_INITIALIZER;
static void *dobby_original;
static uint32_t dobby_file_crc;
static int dobby_setup_error = -1; /* set once per process */

static uint32_t dobby_replacement(void)
{
    return ((uint32_t (*)(void))dobby_original)() + 1;
}

static int dobby_crc_setup(void *text, size_t page_size)
{
    struct ud_mapping map;
    Dl_info info;
    uint8_t file[DOBBY_CRC_BYTES];
    if ((page_size != UROV_Y_PAGE && page_size != UROV_Y_MAX_PAGE) ||
        (uintptr_t)text % page_size) return EOPNOTSUPP;
    int error = ud_mapping_at("/proc/self/maps", text, &map);
    if (error) return error;
    if (!map.readable || !map.executable || map.writable || map.shared ||
        !dladdr(text, &info)) return EPROTO;
    int fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    off_t offset = (off_t)(map.offset + ((uintptr_t)text - map.start));
    error = app_pread(fd, offset, file, sizeof(file));
    close(fd);
    if (error) return error;
    if (memcmp(file, text, sizeof(file)) || dobby_crc_payload() != DOBBY_ORIGINAL)
        return EPROTO;

    /* This Dobby snapshot assumes its permission changes succeed. Verify
     * the transition before asking it to write to the owned text page. */
    if (mprotect(text, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) ||
        mprotect(text, page_size, PROT_READ | PROT_EXEC)) return errno;
    if (DobbyHook(text, (void *)(uintptr_t)&dobby_replacement, &dobby_original) ||
        !dobby_original || dobby_crc_payload() != DOBBY_HOOKED ||
        !memcmp(file, text, sizeof(file))) return EPROTO;

    dobby_file_crc = (uint32_t)crc32(0, file, sizeof(file));
    LOG("DOBBY_HOOK address=%p original=%04x hooked=%04x", text,
        (unsigned)DOBBY_ORIGINAL, (unsigned)DOBBY_HOOKED);
    return 0;
}

static int dobby_crc_arm(const struct uy_ctx *ctx, const void *text, size_t page_size,
                         const char **stage, bool *cleanup)
{
    struct urov_y_request q = uy_req(UROV_Y_QUERY);
    const uint64_t caps = UROV_Y_CAP_PAGE_AP | UROV_Y_CAP_SRC_FILE;
    *stage = "QUERY";
    q.session = 1;
    if (uy_control(ctx, UROV_Y_QUERY, &q)) return errno;
    if (q.state != UROV_Y_INACTIVE) return EBUSY;

    *stage = "PAGE_AP/SRC_FILE capability";
    if ((q.session_flags & caps) != caps || !q.page_count ||
        q.page_stride != (page_size == UROV_Y_MAX_PAGE ? 14U : 12U)) return EOPNOTSUPP;

    *stage = "REGISTER";
    struct uy_page_desc desc = { .base = (uintptr_t)text, .flags = UROV_Y_PAGE_SRC_FILE };
    int error = uy_register_pages(ctx, &desc, 1, 0, 0, &q) ? errno : 0;
    /* REGISTER may have armed the page before an error copying the reply. */
    *cleanup = error != EBUSY;
    if (error) return error;
    return q.state == UROV_Y_ACTIVE && q.session == 1 && q.page_count == 1 ? 0 : EPROTO;
}

static void dobby_crc_check(const char *key, char *result, size_t size)
{
    void *text = (void *)(uintptr_t)&dobby_crc_payload;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_lock(&dobby_crc_lock);
    if (dobby_setup_error < 0) dobby_setup_error = dobby_crc_setup(text, page_size);
    if (dobby_setup_error) {
        snprintf(result, size, "FAIL Dobby setup (errno=%d)", dobby_setup_error);
        goto out;
    }

    const char *stage = "module key";
    struct uy_ctx ctx;
    bool cleanup = false;
    int error = uy_init_key(&ctx, key) ? EINVAL :
                dobby_crc_arm(&ctx, text, page_size, &stage, &cleanup);

    uint8_t bytes[DOBBY_CRC_BYTES];
    copy_scalar(bytes, text, sizeof(bytes));
    uint32_t live_crc = (uint32_t)crc32(0, bytes, sizeof(bytes));
    uint32_t returned = dobby_crc_payload();

    struct urov_y_request status = {0};
    if (!error) {
        stage = "STATUS";
        if (uy_status(&ctx, &status)) error = errno;
        else if (status.state != UROV_Y_ACTIVE || status.reserved != 1 ||
                 status.hits < sizeof(bytes) || status.failures) error = EPROTO;
    }
    int deactivate_error = 0;
    if (cleanup && uy_deactivate(&ctx)) {
        deactivate_error = errno;
        stage = "DEACTIVATE";
        error = deactivate_error;
    } else if (!error && (live_crc != dobby_file_crc || returned != DOBBY_HOOKED)) {
        stage = "CRC or hook return";
        error = EPROTO;
    }

    LOG("DOBBY_CRC address=%p scans=1 bytes=%zu file=%08x live=%08x execute=%04x "
        "hits=%llu failures=%llu deactivate_errno=%d stage=%s errno=%d",
        text, sizeof(bytes), dobby_file_crc, live_crc, returned,
        (unsigned long long)status.hits, (unsigned long long)status.failures,
        deactivate_error, error ? stage : "verified", error);
    char verdict[64];
    if (error) snprintf(verdict, sizeof(verdict), "FAIL %s (errno=%d)", stage, error);
    else snprintf(verdict, sizeof(verdict), "PASS urov-y overlay verified");
    snprintf(result, size, "%s\nCRC32 live=%08x file=%08x\nHook return=0x%04x  KPM hits=%llu",
             verdict, live_crc, dobby_file_crc, returned, (unsigned long long)status.hits);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}

/* Sample an unchanged byte outside the Dobby patch on the same target page.
 * The observer gets only an address, a reference mapping and a file offset. */
static void dobby_detection_stage(const char *name, const uint8_t *text,
                                  const struct page *reference, int repeats,
                                  uint32_t file_crc, uint32_t expected_return,
                                  bool expect_crc_pass, bool expect_trap)
{
    const size_t sample = 64;
    unsigned matched = 0, clean = 0, unknown = 0, crc_pass = 0, accepted_crc = 0;
    unsigned accepted = 0, target_failed = 0, control_failed = 0;
    uint64_t total_ns = 0, max_ns = 0;
    uint32_t live_crc = 0, returned = 0;

    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        uint8_t bytes[DOBBY_CRC_BYTES];
        struct ud_exclusive_observation obs;
        copy_scalar(bytes, text, sizeof(bytes));
        live_crc = (uint32_t)crc32(0, bytes, sizeof(bytes));
        returned = dobby_crc_payload();
        REQUIRE(returned == expected_return && (live_crc == file_crc) == expect_crc_pass,
                "Dobby %s execute=%04x live=%08x file=%08x", name, returned, live_crc, file_crc);

        errno = EDOM;
        ud_observe_exclusive(text + sample, reference->address + reference->entry + sample,
                             reference->fd, reference->file_offset + reference->entry + sample,
                             &obs);
        REQUIRE(errno == EDOM, "Dobby %s changed errno", name);
        matched += obs.reservation_loss == UD_MATCH;
        clean += obs.reservation_loss == UD_NO_MATCH;
        unknown += obs.reservation_loss == UD_UNKNOWN;
        accepted += obs.accepted;
        target_failed += obs.target_failed;
        control_failed += obs.control_failed;
        crc_pass += live_crc == file_crc;
        /* This is an integrity test verdict. It never gates the payload call. */
        accepted_crc += live_crc == file_crc && obs.reservation_loss == UD_NO_MATCH;
        total_ns += obs.elapsed_ns;
        if (obs.elapsed_ns > max_ns) max_ns = obs.elapsed_ns;
    }
    REQUIRE(expect_trap ? matched > 0 && !clean : clean > 0 && !matched,
            "Dobby %s unexpected probe match=%u clean=%u unknown=%u", name, matched, clean, unknown);
    REQUIRE(accepted_crc == (expect_crc_pass && !expect_trap ? clean : 0),
            "Dobby %s accepted forged CRC", name);
    LOG("DOBBY_DETECT stage=%s n=%d execute=%04x file=%08x live=%08x crc_pass=%u "
        "accepted_crc=%u match=%u clean=%u unknown=%u accepted=%u target_failed=%u "
        "control_failed=%u probe_mean_ns=%llu probe_max_ns=%llu",
        name, repeats, returned, file_crc, live_crc, crc_pass, accepted_crc, matched, clean,
        unknown, accepted, target_failed, control_failed, (unsigned long long)(total_ns / repeats),
        (unsigned long long)max_ns);
}

static void dobby_detection_fixture(const char *key, int repeats)
{
    const uint8_t *text = (const uint8_t *)(uintptr_t)&dobby_crc_payload;
    const long page_size = sysconf(_SC_PAGESIZE);
    struct page reference;
    uint8_t file[DOBBY_CRC_BYTES];
    pthread_mutex_lock(&dobby_crc_lock);
    if (dobby_setup_error >= 0 || page_size != UROV_Y_PAGE ||
        page_open_at(&reference, MAP_PRIVATE, text)) {
        REQUIRE(0, "Dobby detection needs a fresh 4 KiB fixture with a file reference");
        goto out;
    }
    if (app_pread(reference.fd, reference.file_offset + reference.entry, file, sizeof(file))) {
        REQUIRE(0, "Dobby detection file read failed");
        goto close_reference;
    }
    uint32_t file_crc = (uint32_t)crc32(0, file, sizeof(file));
    dobby_detection_stage("clean", text, &reference, repeats, file_crc, DOBBY_ORIGINAL, true, false);

    dobby_setup_error = dobby_crc_setup((void *)text, (size_t)page_size);
    if (dobby_setup_error) {
        REQUIRE(0, "Dobby detection setup errno=%d", dobby_setup_error);
        goto close_reference;
    }
    dobby_detection_stage("patch_only", text, &reference, repeats, file_crc, DOBBY_HOOKED, false, false);
    if (!key) goto close_reference;

    const char *stage = "module key";
    struct uy_ctx ctx;
    bool cleanup = false;
    int error = uy_init_key(&ctx, key) ? EINVAL :
                dobby_crc_arm(&ctx, text, (size_t)page_size, &stage, &cleanup);
    REQUIRE(!error, "Dobby detection %s errno=%d", stage, error);
    if (!error) {
        struct urov_y_request status = {0};
        dobby_detection_stage("overlay", text, &reference, repeats, file_crc, DOBBY_HOOKED, true, false);
        REQUIRE(!uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && status.reserved == 1 &&
                status.hits >= (uint64_t)repeats * DOBBY_CRC_BYTES && !status.failures,
                "Dobby detection overlay hits=%llu failures=%llu",
                (unsigned long long)status.hits, (unsigned long long)status.failures);
        LOG("DOBBY_DETECT_STATUS hits=%llu failures=%llu",
            (unsigned long long)status.hits, (unsigned long long)status.failures);
    }
    if (cleanup && uy_deactivate(&ctx)) {
        REQUIRE(0, "Dobby detection DEACTIVATE errno=%d", errno);
        goto close_reference;
    }
    if (!error)
        dobby_detection_stage("deactivated", text, &reference, repeats, file_crc, DOBBY_HOOKED, false, false);

close_reference:
    page_close(&reference);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}
