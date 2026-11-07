/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <dobby.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

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
static uint8_t *dobby_file_page;      /* clean full page, SRC_USER image */
static size_t dobby_file_page_size;
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
    dobby_file_page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (dobby_file_page == MAP_FAILED) {
        dobby_file_page = NULL;
        return ENOMEM;
    }
    int fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    off_t offset = (off_t)(map.offset + ((uintptr_t)text - map.start));
    error = app_pread(fd, offset, dobby_file_page, page_size);
    close(fd);
    if (error) return error;
    memcpy(file, dobby_file_page, sizeof(file));
    if (memcmp(file, text, sizeof(file)) || dobby_crc_payload() != DOBBY_ORIGINAL)
        return EPROTO;
    dobby_file_page_size = page_size;

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
    const uint64_t caps = UROV_Y_CAP_PAGE_AP;
    *stage = "QUERY";
    q.session = 1;
    if (uy_control(ctx, UROV_Y_QUERY, &q)) return errno;
    if (q.state != UROV_Y_INACTIVE) return EBUSY;

    *stage = "PAGE_AP/SRC_USER capability";
    if ((q.session_flags & caps) != caps || !q.page_count || !dobby_file_page ||
        dobby_file_page_size != page_size ||
        q.page_stride != (page_size == UROV_Y_MAX_PAGE ? 14U : 12U)) return EOPNOTSUPP;

    *stage = "REGISTER";
    struct uy_page_desc desc = {
        .base = (uintptr_t)text,
        .fake_addr = (uintptr_t)dobby_file_page,
        .fake_off = 0,
        .fake_len = (uint32_t)page_size,
        .flags = UROV_Y_PAGE_SRC_USER,
    };
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

/* Opt-in fixture mitigation. Match just the arm64 ABI v8 REGISTER envelope.
 * TSYNC applies the rule to the process's existing threads as well. */
static int dobby_block_registration(void)
{
#define PASS_UNLESS_EQ(offset, value) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset), \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, 1, 0), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    struct sock_filter filter[] = {
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, arch), AUDIT_ARCH_AARCH64),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, nr), __NR_prctl),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[1]), (uint32_t)UROV_Y_PRCTL_MAGIC),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[1]) + 4, UROV_Y_PRCTL_MAGIC >> 32),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[2]), UROV_Y_REGISTER),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[2]) + 4, 0),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[4]), sizeof(struct urov_y_request)),
        PASS_UNLESS_EQ(offsetof(struct seccomp_data, args[4]) + 4, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    };
#undef PASS_UNLESS_EQ
    struct sock_fprog program = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) return errno;
    long rc = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
    if (rc < 0) return errno;
    return rc ? EBUSY : 0;
}

struct dobby_registration_retry {
    pthread_barrier_t start;
    const struct uy_ctx *ctx;
    const uint8_t *text;
    bool attempt;
    int error;
};

static int dobby_retry_register(const struct uy_ctx *ctx, const uint8_t *text)
{
    struct urov_y_request q;
    struct uy_page_desc desc = {
        .base = (uintptr_t)text,
        .fake_addr = (uintptr_t)dobby_file_page,
        .fake_off = 0,
        .fake_len = (uint32_t)dobby_file_page_size,
        .flags = UROV_Y_PAGE_SRC_USER,
    };
    if (!dobby_file_page) return EINVAL;
    return uy_register_pages(ctx, &desc, 1, 0, 0, &q) ? errno : 0;
}

static void *dobby_existing_registrant(void *arg)
{
    struct dobby_registration_retry *retry = arg;
    pthread_barrier_wait(&retry->start);
    if (retry->attempt) retry->error = dobby_retry_register(retry->ctx, retry->text);
    return NULL;
}

static bool dobby_restore_and_block(const struct uy_ctx *ctx, const uint8_t *text, size_t page_size)
{
    struct dobby_registration_retry retry = { .ctx = ctx, .text = text, .error = -1 };
    struct urov_y_request status = {0};
    pthread_t thread;
    int barrier_error = pthread_barrier_init(&retry.start, NULL, 2);
    int thread_error = barrier_error ? barrier_error :
        pthread_create(&thread, NULL, dobby_existing_registrant, &retry);

    int nnp_before = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
    int filter_error = dobby_block_registration();
    int nnp_after = prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL);
    bool still_active = !uy_status(ctx, &status) && status.state == UROV_Y_ACTIVE;

    /* Only the dedicated test page uses this recovery path. The advice is
     * already MADV_NORMAL, so the native call preserves its protections. */
    int restore_error = madvise((void *)text, page_size, MADV_NORMAL) ? errno : 0;
    bool inactive = !restore_error && !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;
    REQUIRE(still_active && inactive, "Dobby MADV_NORMAL recovery errno=%d state=%u",
            restore_error, status.state);
    LOG("DOBBY_DETECT_RESTORE madvise_errno=%d inactive=%d", restore_error, inactive);

    retry.attempt = !filter_error && inactive;
    int local_error = retry.attempt ? dobby_retry_register(ctx, text) : -1;
    if (!thread_error) {
        pthread_barrier_wait(&retry.start);
        thread_error = pthread_join(thread, NULL);
    }
    if (!barrier_error) pthread_barrier_destroy(&retry.start);
    bool idle = !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;
    REQUIRE(!filter_error && !thread_error && nnp_after == 1 && idle &&
            local_error == EPERM && retry.error == EPERM, "Dobby REGISTER guard failed");
    LOG("DOBBY_DETECT_GUARD filter_errno=%d thread_errno=%d register_errno=%d "
        "existing_thread_errno=%d inactive=%d nnp_before=%d nnp_after=%d",
        filter_error, thread_error, local_error, retry.error, idle, nnp_before, nnp_after);
    return idle;
}

/* Sample an unchanged byte outside the Dobby patch on the same target page.
 * The observer gets only an address, a reference mapping and a file offset. */
static void dobby_detection_stage(const char *name, const uint8_t *text,
                                  const struct page *reference, int repeats,
                                  uint32_t file_crc, uint32_t expected_return,
                                  bool expect_crc_pass, enum ud_verdict expected_path)
{
    const size_t sample = 64;
    const uint8_t *control = reference->address + reference->entry + sample;
    const off_t offset = reference->file_offset + reference->entry + sample;
    unsigned matched = 0, clean = 0, unknown = 0, crc_pass = 0, accepted_crc = 0;
    unsigned adjacent_match = 0, adjacent_unknown = 0;
    unsigned spaced_match = 0, spaced_unknown = 0, spaced_accepted = 0;
    unsigned spaced_failed = 0, spaced_control_failed = 0;
    unsigned bridge_match = 0, bridge_unknown = 0, bridge_trials = 0, bridge_successes = 0;
    unsigned nop_trials = 0, nop_successes = 0;
    unsigned ind_match = 0, ind_trials = 0, ind_successes = 0;
    uint64_t total_ns = 0, max_ns = 0;
    uint32_t live_crc = 0, returned = 0;

    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        uint8_t bytes[DOBBY_CRC_BYTES];
        struct ud_exclusive_observation adjacent, spaced;
        struct ud_store_observation bridge, nop, indirect;
        copy_scalar(bytes, text, sizeof(bytes));
        live_crc = (uint32_t)crc32(0, bytes, sizeof(bytes));
        returned = dobby_crc_payload();
        REQUIRE(returned == expected_return && (live_crc == file_crc) == expect_crc_pass,
                "Dobby %s execute=%04x live=%08x file=%08x", name, returned, live_crc, file_crc);

        errno = EDOM;
        ud_observe_exclusive(text + sample, control, reference->fd, offset, &adjacent);
        ud_observe_spaced_exclusive(text + sample, control, reference->fd, offset, &spaced);
        ud_observe_unreserved_status(text + sample, control, reference->fd, offset, &bridge);
        ud_observe_unreserved_nop_status(text + sample, control, reference->fd, offset, &nop);
        ud_observe_unreserved_indirect_status(text + sample, control, reference->fd, offset,
                                              &indirect);
        REQUIRE(errno == EDOM, "Dobby %s changed errno", name);
        adjacent_match += adjacent.reservation_loss == UD_MATCH;
        adjacent_unknown += adjacent.reservation_loss == UD_UNKNOWN;
        spaced_match += spaced.reservation_loss == UD_MATCH;
        spaced_unknown += spaced.reservation_loss == UD_UNKNOWN;
        spaced_accepted += spaced.accepted;
        spaced_failed += spaced.target_failed;
        spaced_control_failed += spaced.control_failed;
        bridge_match += bridge.verdict == UD_MATCH;
        bridge_unknown += bridge.verdict == UD_UNKNOWN;
        bridge_trials += bridge.completed;
        bridge_successes += bridge.unexpected_stores;
        nop_trials += nop.completed;
        nop_successes += nop.unexpected_stores;
        ind_match += indirect.verdict == UD_MATCH;
        ind_trials += indirect.completed;
        ind_successes += indirect.unexpected_stores;
        matched += nop.verdict == UD_MATCH;
        clean += nop.verdict == UD_NO_MATCH;
        unknown += nop.verdict == UD_UNKNOWN;
        crc_pass += live_crc == file_crc;
        accepted_crc += live_crc == file_crc && nop.verdict == UD_NO_MATCH;
        total_ns += nop.elapsed_ns;
        if (nop.elapsed_ns > max_ns) max_ns = nop.elapsed_ns;
    }
    REQUIRE(!adjacent_match && adjacent_unknown < (unsigned)repeats,
            "Dobby %s adjacent match=%u unknown=%u", name, adjacent_match, adjacent_unknown);
    REQUIRE(!spaced_match && spaced_unknown < (unsigned)repeats,
            "Dobby %s spaced match=%u unknown=%u", name, spaced_match, spaced_unknown);
    REQUIRE(!bridge_match && !bridge_unknown,
            "Dobby %s bridge match=%u unknown=%u", name, bridge_match, bridge_unknown);
    REQUIRE(!nop_successes, "Dobby %s NOP bridge stores=%u", name, nop_successes);
    REQUIRE(!ind_match && !ind_successes, "Dobby %s indirect bridge match=%u stores=%u",
            name, ind_match, ind_successes);
    REQUIRE(!unknown && matched == (expected_path == UD_MATCH ? (unsigned)repeats : 0),
            "Dobby %s read path match=%u unknown=%u", name, matched, unknown);
    REQUIRE(accepted_crc == (expect_crc_pass && expected_path == UD_NO_MATCH ? (unsigned)repeats : 0),
            "Dobby %s accepted_crc=%u", name, accepted_crc);
    LOG("DOBBY_DETECT stage=%s n=%d execute=%04x file=%08x live=%08x crc_pass=%u "
        "accepted_crc=%u match=%u clean=%u unknown=%u adjacent_match=%u adjacent_unknown=%u "
        "spaced_match=%u spaced_unknown=%u spaced_accepted=%u spaced_failed=%u "
        "spaced_control_failed=%u bridge_match=%u bridge_unknown=%u bridge_trials=%u "
        "bridge_successes=%u nop_trials=%u nop_successes=%u ind_match=%u ind_trials=%u "
        "ind_successes=%u probe_mean_ns=%llu probe_max_ns=%llu",
        name, repeats, returned, file_crc, live_crc, crc_pass, accepted_crc, matched, clean,
        unknown, adjacent_match, adjacent_unknown, spaced_match, spaced_unknown, spaced_accepted,
        spaced_failed, spaced_control_failed, bridge_match, bridge_unknown, bridge_trials,
        bridge_successes, nop_trials, nop_successes, ind_match, ind_trials, ind_successes,
        (unsigned long long)(total_ns / repeats),
        (unsigned long long)max_ns);
}

static void dobby_detection_fixture(const char *key, int repeats)
{
    const uint8_t *text = (const uint8_t *)(uintptr_t)&dobby_crc_payload;
    const long page_size = sysconf(_SC_PAGESIZE);
    struct page reference;
    struct business business = { .fn = ud_payload };
    pthread_t thread;
    bool have_thread = false;
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
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "Dobby detection business thread");
    dobby_detection_stage("clean", text, &reference, repeats, file_crc, DOBBY_ORIGINAL, true, UD_NO_MATCH);

    dobby_setup_error = dobby_crc_setup((void *)text, (size_t)page_size);
    if (dobby_setup_error) {
        REQUIRE(0, "Dobby detection setup errno=%d", dobby_setup_error);
        goto close_reference;
    }
    dobby_detection_stage("patch_only", text, &reference, repeats, file_crc, DOBBY_HOOKED, false, UD_NO_MATCH);
    if (!key) goto close_reference;

    const char *stage = "module key";
    struct uy_ctx ctx;
    bool cleanup = false;
    int error = uy_init_key(&ctx, key) ? EINVAL :
                dobby_crc_arm(&ctx, text, (size_t)page_size, &stage, &cleanup);
    REQUIRE(!error, "Dobby detection %s errno=%d", stage, error);
    if (!error) {
        struct urov_y_request status = {0};
        dobby_detection_stage("overlay", text, &reference, repeats, file_crc, DOBBY_HOOKED, true, UD_NO_MATCH);
        REQUIRE(!uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && status.reserved == 1 &&
                status.hits >= (uint64_t)repeats * DOBBY_CRC_BYTES && !status.failures,
                "Dobby detection overlay hits=%llu failures=%llu",
                (unsigned long long)status.hits, (unsigned long long)status.failures);
        LOG("DOBBY_DETECT_STATUS hits=%llu failures=%llu",
            (unsigned long long)status.hits, (unsigned long long)status.failures);

        if (dobby_restore_and_block(&ctx, text, (size_t)page_size)) cleanup = false;
    }
    if (cleanup && uy_deactivate(&ctx)) {
        REQUIRE(0, "Dobby detection DEACTIVATE errno=%d", errno);
        goto close_reference;
    }
    if (!error)
        dobby_detection_stage("deactivated", text, &reference, repeats, file_crc, DOBBY_HOOKED, false, UD_NO_MATCH);

close_reference:
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.ops) > 0 && !atomic_load(&business.errors),
                "Dobby detection business worker");
        LOG("DOBBY_DETECT_BUSINESS ops=%llu errors=%d",
            (unsigned long long)atomic_load(&business.ops), atomic_load(&business.errors));
    }
    page_close(&reference);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}
