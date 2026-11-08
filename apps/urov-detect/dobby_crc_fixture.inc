/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <dobby.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/uio.h>

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

/* Run after recovery and before installing seccomp, so rejection came from
 * the locked RX mapping alone in 2.11.0.  2.12.0 accepts VM_LOCKED, so the
 * same call must now register and serve the image on a locked page. */
static void dobby_check_page_lock(const struct uy_ctx *ctx, const uint8_t *text, size_t page_size)
{
    uint8_t before[DOBBY_CRC_BYTES], after[DOBBY_CRC_BYTES], restored[DOBBY_CRC_BYTES];
    struct urov_y_request status = {0};
    struct ud_mapping map;
    copy_scalar(before, text, sizeof(before));
    uint64_t begin = now_ns();
    int lock_error = mlock(text, page_size) ? errno : 0;
    uint64_t lock_ns = now_ns() - begin;
    int register_error = lock_error ? -1 : dobby_retry_register(ctx, text);
    bool active = !uy_status(ctx, &status) && status.state == UROV_Y_ACTIVE;
    copy_scalar(after, text, sizeof(after));
    bool overlay = dobby_file_page && !memcmp(after, dobby_file_page, sizeof(after)) &&
                   memcmp(after, before, sizeof(after)) != 0;
    bool execute = dobby_crc_payload() == DOBBY_HOOKED;
    int deactivate_error = register_error ? -1 : (uy_deactivate(ctx) ? errno : 0);
    copy_scalar(restored, text, sizeof(restored));
    bool restored_ok = !memcmp(restored, before, sizeof(restored));
    bool rx = !ud_mapping_at("/proc/self/maps", text, &map) &&
              map.readable && !map.writable && map.executable;
    int unlock_error = lock_error ? -1 : (munlock(text, page_size) ? errno : 0);
    REQUIRE(!lock_error && !unlock_error && !register_error && active && overlay &&
            execute && !deactivate_error && restored_ok && rx,
            "Dobby private RX lock guard failed");
    LOG("DOBBY_DETECT_LOCK bytes=%zu lock_errno=%d lock_ns=%llu register_errno=%d "
        "active=%d overlay=%d execute=%d rx=%d deactivate_errno=%d restored=%d "
        "unlock_errno=%d", page_size, lock_error, (unsigned long long)lock_ns,
        register_error, active, overlay, execute, rx, deactivate_error, restored_ok,
        unlock_error);
}

static void *dobby_existing_registrant(void *arg)
{
    struct dobby_registration_retry *retry = arg;
    pthread_barrier_wait(&retry->start);
    if (retry->attempt) retry->error = dobby_retry_register(retry->ctx, retry->text);
    return NULL;
}

static bool dobby_same_vma(const struct ud_mapping *a, const struct ud_mapping *b)
{
    return a->start == b->start && a->end == b->end && a->offset == b->offset &&
        a->inode == b->inode && a->dev_major == b->dev_major && a->dev_minor == b->dev_minor &&
        a->readable == b->readable && a->writable == b->writable &&
        a->executable == b->executable && a->shared == b->shared &&
        a->dontcopy == b->dontcopy && a->maywrite == b->maywrite &&
        a->randomread == b->randomread;
}

/* Test-only probe on the owned payload. Linux rejects page+1 before changing
 * the VMA; the 2.13.0 gate validates the arguments before it touches the
 * session, so the invalid call must leave the overlay armed. The errno is
 * identical on a clean kernel. Verify the bytes and execution. */
static void dobby_check_unaligned_protect(const char *name, const void *page,
                                         const uint8_t *text, size_t page_size,
                                         const uint8_t expected[DOBBY_CRC_BYTES])
{
    struct ud_mapping before, after;
    uint8_t live[DOBBY_CRC_BYTES];
    int map_error = ud_mapping_at("/proc/self/smaps", text, &before);
    int error = EPROTO;
    if (!map_error && before.readable && before.executable && !before.writable &&
        page && page_size > 1 && (uintptr_t)page % page_size == 0)
        error = mprotect((void *)((uintptr_t)page + 1U), 1, PROT_READ) ? errno : 0;

    copy_scalar(live, text, sizeof(live));
    uint32_t executed = dobby_crc_payload();
    bool expected_bytes = !memcmp(live, expected, sizeof(live));
    bool preserved = !map_error && !ud_mapping_at("/proc/self/smaps", text, &after) &&
        dobby_same_vma(&before, &after);
    REQUIRE(error == EINVAL && expected_bytes && preserved && executed == DOBBY_HOOKED,
            "Dobby keyless restore %s errno=%d bytes_expected=%d vma_preserved=%d execute=%04x",
            name, error, expected_bytes, preserved, executed);
    LOG("DOBBY_DETECT_KEYLESS_RESTORE stage=%s errno=%d bytes_expected=%d vma_preserved=%d execute=%04x",
        name, error, expected_bytes, preserved, executed);
}

/* The bad-advice and unaligned-protect calls must leave the overlay in place;
 * the owner then ends the session with the authenticated DEACTIVATE request.
 * The unaligned mprotect calls below use no module request or credentials;
 * STATUS only supplies fixture ground truth before and after the experiment. */
static bool dobby_restore(const struct uy_ctx *ctx, const uint8_t *text,
                          const void *reference, size_t page_size,
                          const uint8_t file[DOBBY_CRC_BYTES],
                          const uint8_t patched[DOBBY_CRC_BYTES])
{
    struct urov_y_request status = {0};
    struct ud_mapping before, after;
    uint8_t live[DOBBY_CRC_BYTES];

    (void)patched;
    int outside_error = uy_invalid_advice(reference, page_size);
    bool still_active = !uy_status(ctx, &status) && status.state == UROV_Y_ACTIVE;

    int map_error = ud_mapping_at("/proc/self/smaps", text, &before);
    int restore_error = uy_invalid_advice(text, page_size);
    copy_scalar(live, text, sizeof(live));
    bool image_kept = !memcmp(live, file, sizeof(live));
    bool preserved = !map_error && !ud_mapping_at("/proc/self/smaps", text, &after) &&
        before.randomread && dobby_same_vma(&before, &after);

    dobby_check_unaligned_protect("outside", reference, text, page_size, file);
    dobby_check_unaligned_protect("overlap", text, text, page_size, file);
    bool active_after_keyless = !uy_status(ctx, &status) && status.state == UROV_Y_ACTIVE;
    int deactivate_error = uy_deactivate(ctx) ? errno : 0;
    bool inactive = !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;

    REQUIRE(outside_error == EINVAL && still_active && restore_error == EINVAL &&
            image_kept && preserved && active_after_keyless && !deactivate_error && inactive,
            "Dobby invalid advice errno=%d still_active=%d image_kept=%d preserved=%d "
            "active_after_keyless=%d deactivate_errno=%d inactive=%d",
            restore_error, still_active, image_kept, preserved, active_after_keyless,
            deactivate_error, inactive);
    LOG("DOBBY_DETECT_RESTORE outside_errno=%d still_active=%d madvise_errno=%d "
        "image_kept=%d vma_preserved=%d active_after_keyless=%d inactive_after_deactivate=%d "
        "deactivate_errno=%d",
        outside_error, still_active, restore_error, image_kept, preserved,
        active_after_keyless, inactive, deactivate_error);
    return inactive;
}

static void dobby_check_registration_guard(const struct uy_ctx *ctx, const uint8_t *text)
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

    retry.attempt = !filter_error;
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
}

/* Permission probe on an ordinary RX page before any registration. The
 * forked reader has a distinct mm and keeps the app's original credentials. */
static void dobby_check_kernel_access(const uint8_t *text)
{
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    int mem_error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    pid_t parent = getpid();
    pid_t child = fork();
    int cross_error = child < 0 ? errno : -1;
    if (!child) {
        uint8_t byte;
        struct iovec local = { .iov_base = &byte, .iov_len = 1 };
        struct iovec remote = { .iov_base = (void *)text, .iov_len = 1 };
        ssize_t got = process_vm_readv(parent, &local, 1, &remote, 1, 0);
        _exit(got == 1 ? 0 : (got < 0 ? errno : EIO));
    }
    if (child > 0) {
        int status;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited == child && WIFEXITED(status)) cross_error = WEXITSTATUS(status);
    }
    LOG("DOBBY_DETECT_ACCESS self_mem_open_errno=%d other_mm_read_errno=%d", mem_error, cross_error);
}

/* A process that is not dumpable cannot open /proc/self/mem.  The fixture
 * enables it for the length of one read and restores the previous value, so
 * the kernel-assisted path can be compared with the EL0 view. */
static int dobby_mem_read(const uint8_t *text, uint8_t *out, size_t n)
{
    int saved = prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL);
    int fd, error;
    ssize_t got;

    if (prctl(PR_SET_DUMPABLE, 1UL, 0UL, 0UL, 0UL)) return errno;
    fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error = errno;
    } else {
        got = pread(fd, out, n, (off_t)(uintptr_t)text);
        error = got == (ssize_t)n ? 0 : (got < 0 ? errno : EIO);
        close(fd);
    }
    (void)prctl(PR_SET_DUMPABLE, saved > 0 ? 1UL : 0UL, 0UL, 0UL, 0UL);
    return error;
}

/* A forked child is a different mm; its own /proc/self/mem read must still be
 * overlaid while the session lives (the child inherited the trapped PTE). */
static void dobby_check_fork_kmem(const uint8_t *text, const uint8_t *image, size_t n)
{
    int status = 0, child_ok = 0;
    pid_t child = fork();

    if (child == 0) {
        uint8_t got[DOBBY_CRC_BYTES];
        memset(got, 0, sizeof(got));
        _exit(!dobby_mem_read(text, got, n) && !memcmp(got, image, n) ? 0 : 1);
    }
    if (child > 0)
        child_ok = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0;
    REQUIRE(child_ok, "Dobby forked child /proc/self/mem bypassed the overlay");
    LOG("DOBBY_DETECT_FORK_KMEM stage=overlay match=%d", child_ok);
}

/* Sample an unchanged byte outside the Dobby patch on the same target page.
 * The observer gets only an address, a reference mapping and a file offset. */
static void dobby_detection_stage(const char *name, const uint8_t *text,
                                  const struct page *reference, const uint8_t *ap_reference,
                                  pid_t sibling, int repeats,
                                  const uint8_t file[DOBBY_CRC_BYTES], uint32_t expected_return,
                                  bool expect_crc_pass, enum ud_verdict expected_live,
                                  bool expect_ap_loss)
{
    const size_t sample = 64;
    const uint8_t *control = reference->address + reference->entry + sample;
    const off_t text_offset = reference->file_offset + reference->entry;
    const off_t offset = text_offset + sample;
    const uint32_t file_crc = (uint32_t)crc32(0, file, DOBBY_CRC_BYTES);
    unsigned matched = 0, clean = 0, unknown = 0, crc_pass = 0, accepted_crc = 0;
    unsigned adjacent_match = 0, adjacent_unknown = 0;
    unsigned spaced_match = 0, spaced_unknown = 0, spaced_accepted = 0;
    unsigned spaced_failed = 0, spaced_control_failed = 0;
    unsigned bridge_match = 0, bridge_unknown = 0, bridge_trials = 0, bridge_successes = 0;
    unsigned nop_match = 0, nop_trials = 0, nop_successes = 0;
    unsigned ind_match = 0, ind_trials = 0, ind_successes = 0;
    unsigned cross_page_trials = 0, cross_page_successes = 0;
    unsigned live_match = 0, live_unknown = 0, kernel_file = 0;
    unsigned zero_match = 0, zero_clean = 0, zero_unknown = 0;
    unsigned ap_match = 0, ap_clean = 0, ap_unknown = 0, ap_accepted_crc = 0;
    unsigned ap_accepted = 0, ap_failed = 0, ap_control_failed = 0;
    uint64_t total_ns = 0, max_ns = 0;
    uint64_t live_total_ns = 0, live_max_ns = 0;
    uint64_t ap_total_ns = 0, ap_max_ns = 0;
    uint32_t live_crc = 0, kernel_crc = 0, single_crc = 0, returned = 0;
    uint8_t many_bytes[DOBBY_CRC_BYTES] = {0};
    uint8_t scalar_bytes[DOBBY_CRC_BYTES] = {0};
    struct iovec many_local[1024] = {{
        .iov_base = many_bytes, .iov_len = sizeof(many_bytes)
    }};
    struct iovec many_remote = { .iov_base = (void *)text, .iov_len = sizeof(many_bytes) };

    /* The largest iovec count Linux accepts: one byte-carrying entry followed
     * by zero-length entries.  This is the 1024 boundary of the same read. */
    copy_scalar(scalar_bytes, text, sizeof(scalar_bytes));
    /* /proc/self/mem goes through GUP and never takes the EL0 data abort.
     * 2.12.0 overlays that buffer from the same image, so this reader must
     * agree with the EL0 view in every stage.  The open is only attempted
     * with dumpable set; the process is restored immediately. */
    uint8_t kmem_bytes[DOBBY_CRC_BYTES] = {0};
    int kmem_error = dobby_mem_read(text, kmem_bytes, sizeof(kmem_bytes));
    if (!kmem_error)
        REQUIRE(!memcmp(kmem_bytes, scalar_bytes, sizeof(kmem_bytes)),
                "Dobby %s /proc/self/mem diverged from the EL0 view", name);
    LOG("DOBBY_DETECT_KMEM stage=%s errno=%d match=%u", name, kmem_error,
        kmem_error ? 0 : !memcmp(kmem_bytes, scalar_bytes, sizeof(kmem_bytes)));
    /* Use a changed byte when visible, so legitimate COW is a negative
     * control even when the target and its clean alias have different data. */
    size_t ap_sample = 0;
    for (size_t i = 0; i < sizeof(scalar_bytes); ++i) {
        if (scalar_bytes[i] != file[i]) { ap_sample = i; break; }
    }
    errno = 0;
    ssize_t many_got = process_vm_readv(getpid(), many_local, 1024, &many_remote, 1, 0);
    REQUIRE(many_got == (ssize_t)sizeof(many_bytes) &&
            !memcmp(many_bytes, scalar_bytes, sizeof(many_bytes)),
            "Dobby %s 1024 iovec got=%zd errno=%d", name, many_got, errno);
    LOG("DOBBY_DETECT_MANY stage=%s n=1024 got=%zd match=%u errno=%d",
        name, many_got, !memcmp(many_bytes, scalar_bytes, sizeof(many_bytes)), errno);

    /* A pid that names another thread of this mm must follow the same overlay
     * as the caller's own tgid.  The business thread is alive for every stage. */
    uint8_t sibling_bytes[DOBBY_CRC_BYTES] = {0};
    struct iovec sibling_local = { .iov_base = sibling_bytes, .iov_len = sizeof(sibling_bytes) };
    struct iovec sibling_remote = { .iov_base = (void *)text, .iov_len = sizeof(sibling_bytes) };
    errno = 0;
    ssize_t sibling_got = process_vm_readv(sibling, &sibling_local, 1, &sibling_remote, 1, 0);
    REQUIRE(sibling_got == (ssize_t)sizeof(sibling_bytes) &&
            !memcmp(sibling_bytes, scalar_bytes, sizeof(sibling_bytes)),
            "Dobby %s sibling tid=%d got=%zd errno=%d", name, sibling, sibling_got, errno);
    LOG("DOBBY_DETECT_SIBLING stage=%s tid=%d got=%zd match=%u errno=%d",
        name, sibling, sibling_got, !memcmp(sibling_bytes, scalar_bytes, sizeof(sibling_bytes)),
        errno);

    /* Split the same 32 bytes across four local and four remote iovecs with
     * different boundaries, so the module's streaming cursor must advance on
     * both sides and preserve every offset. */
    uint8_t split_bytes[4][8] = {{0}};
    struct iovec split_local[4] = {
        { .iov_base = split_bytes[0], .iov_len = 8 },
        { .iov_base = split_bytes[1], .iov_len = 8 },
        { .iov_base = split_bytes[2], .iov_len = 8 },
        { .iov_base = split_bytes[3], .iov_len = 8 },
    };
    struct iovec split_remote[4] = {
        { .iov_base = (void *)text, .iov_len = 4 },
        { .iov_base = (void *)(text + 4), .iov_len = 12 },
        { .iov_base = (void *)(text + 16), .iov_len = 8 },
        { .iov_base = (void *)(text + 24), .iov_len = 8 },
    };
    errno = 0;
    ssize_t split_got = process_vm_readv(getpid(), split_local, 4, split_remote, 4, 0);
    REQUIRE(split_got == (ssize_t)sizeof(split_bytes) &&
            !memcmp(split_bytes, scalar_bytes, sizeof(split_bytes)),
            "Dobby %s split iovec got=%zd errno=%d", name, split_got, errno);
    LOG("DOBBY_DETECT_SPLIT stage=%s got=%zd match=%u errno=%d",
        name, split_got, !memcmp(split_bytes, scalar_bytes, sizeof(split_bytes)), errno);

    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        struct ud_live_observation live;
        struct ud_exclusive_observation adjacent, spaced, zero, ap;
        struct ud_store_observation bridge, nop, indirect, cross_page;
        uint8_t single[DOBBY_CRC_BYTES] = {0};
        struct iovec local = { .iov_base = single, .iov_len = sizeof(single) };
        struct iovec remote = { .iov_base = (void *)text, .iov_len = sizeof(single) };
        errno = EDOM;
        ud_observe_live(text, DOBBY_CRC_BYTES, reference->fd, text_offset, copy_scalar, &live);
        REQUIRE(live.verdict == expected_live, "Dobby %s live views=%d error=%d", name,
                live.verdict, live.error);
        REQUIRE(process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == (ssize_t)sizeof(single) &&
                !memcmp(single, live.user_bytes, sizeof(single)), "Dobby %s single iovec", name);
        single_crc = (uint32_t)crc32(0, single, sizeof(single));
        live_match += live.verdict == UD_MATCH;
        live_unknown += live.verdict == UD_UNKNOWN;
        bool file_ok = live.verdict != UD_UNKNOWN &&
                       !memcmp(live.kernel_bytes, file, DOBBY_CRC_BYTES);
        kernel_file += file_ok;
        live_total_ns += live.elapsed_ns;
        if (live.elapsed_ns > live_max_ns) live_max_ns = live.elapsed_ns;
        live_crc = (uint32_t)crc32(0, live.user_bytes, DOBBY_CRC_BYTES);
        kernel_crc = (uint32_t)crc32(0, live.kernel_bytes, DOBBY_CRC_BYTES);
        returned = dobby_crc_payload();
        REQUIRE(returned == expected_return && (live_crc == file_crc) == expect_crc_pass,
                "Dobby %s execute=%04x live=%08x file=%08x", name, returned, live_crc, file_crc);

        ud_observe_exclusive(text + sample, control, reference->fd, offset, &adjacent);
        ud_observe_spaced_exclusive(text + sample, control, reference->fd, offset, &spaced);
        ud_observe_zero_exclusive(text + sample, control, reference->fd, offset, &zero);
        ud_observe_ap_reservation(text + ap_sample, ap_reference + reference->entry + ap_sample,
                                  reference->fd, text_offset + (off_t)ap_sample, &ap);
        REQUIRE(ap.reservation_loss == (expect_ap_loss ? UD_MATCH : UD_NO_MATCH) ||
                (ap.reservation_loss == UD_UNKNOWN && ap.error == EAGAIN),
                "Dobby %s AP verdict=%d accepted=%u failed=%u control=%u error=%d", name,
                ap.reservation_loss, ap.accepted, ap.target_failed, ap.control_failed, ap.error);
        ap_match += ap.reservation_loss == UD_MATCH;
        ap_clean += ap.reservation_loss == UD_NO_MATCH;
        ap_unknown += ap.reservation_loss == UD_UNKNOWN;
        ap_accepted += ap.accepted;
        ap_failed += ap.target_failed;
        ap_control_failed += ap.control_failed;
        ap_total_ns += ap.elapsed_ns;
        if (ap.elapsed_ns > ap_max_ns) ap_max_ns = ap.elapsed_ns;
        ud_observe_unreserved_status(text + sample, control, reference->fd, offset, &bridge);
        ud_observe_unreserved_nop_status(text + sample, control, reference->fd, offset, &nop);
        ud_observe_unreserved_indirect_status(text + sample, control, reference->fd, offset,
                                              &indirect);
        ud_observe_unreserved_cross_page_status(text + sample, control, reference->fd, offset,
                                                &cross_page);
        REQUIRE(errno == EDOM, "Dobby %s changed errno", name);
        adjacent_match += adjacent.reservation_loss == UD_MATCH;
        adjacent_unknown += adjacent.reservation_loss == UD_UNKNOWN;
        spaced_match += spaced.reservation_loss == UD_MATCH;
        spaced_unknown += spaced.reservation_loss == UD_UNKNOWN;
        spaced_accepted += spaced.accepted;
        spaced_failed += spaced.target_failed;
        spaced_control_failed += spaced.control_failed;
        zero_match += zero.reservation_loss == UD_MATCH;
        zero_clean += zero.reservation_loss == UD_NO_MATCH;
        zero_unknown += zero.reservation_loss == UD_UNKNOWN;
        bridge_match += bridge.verdict == UD_MATCH;
        bridge_unknown += bridge.verdict == UD_UNKNOWN;
        bridge_trials += bridge.completed;
        bridge_successes += bridge.unexpected_stores;
        nop_match += nop.verdict == UD_MATCH;
        nop_trials += nop.completed;
        nop_successes += nop.unexpected_stores;
        ind_match += indirect.verdict == UD_MATCH;
        ind_trials += indirect.completed;
        ind_successes += indirect.unexpected_stores;
        cross_page_trials += cross_page.completed;
        cross_page_successes += cross_page.unexpected_stores;
        matched += cross_page.verdict == UD_MATCH;
        clean += cross_page.verdict == UD_NO_MATCH;
        unknown += cross_page.verdict == UD_UNKNOWN;
        crc_pass += live_crc == file_crc;
        accepted_crc += live_crc == file_crc && live.verdict == UD_NO_MATCH && file_ok;
        ap_accepted_crc += live_crc == file_crc && live.verdict == UD_NO_MATCH && file_ok &&
                           ap.reservation_loss == UD_NO_MATCH;
        total_ns += cross_page.elapsed_ns;
        if (cross_page.elapsed_ns > max_ns) max_ns = cross_page.elapsed_ns;
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
    REQUIRE(!unknown && !matched,
            "Dobby %s read path match=%u unknown=%u", name, matched, unknown);
    REQUIRE(zero_clean > 0 && !zero_match, "Dobby %s XZR match=%u clean=%u unknown=%u",
            name, zero_match, zero_clean, zero_unknown);
    REQUIRE(accepted_crc == (expect_crc_pass && expected_live == UD_NO_MATCH ? (unsigned)repeats : 0),
            "Dobby %s accepted_crc=%u", name, accepted_crc);
    REQUIRE(ap_match + ap_clean && (!expect_ap_loss || !ap_accepted_crc),
            "Dobby %s AP policy match=%u clean=%u accepted_crc=%u", name,
            ap_match, ap_clean, ap_accepted_crc);
    LOG("DOBBY_DETECT_AP stage=%s n=%d match=%u clean=%u unknown=%u accepted=%u failed=%u "
        "control_failed=%u bytes_differ=%d accepted_crc=%u mean_ns=%llu max_ns=%llu",
        name, repeats, ap_match, ap_clean, ap_unknown, ap_accepted, ap_failed, ap_control_failed,
        scalar_bytes[ap_sample] != file[ap_sample], ap_accepted_crc,
        (unsigned long long)(ap_total_ns / repeats), (unsigned long long)ap_max_ns);
    LOG("DOBBY_DETECT stage=%s n=%d execute=%04x file=%08x live=%08x crc_pass=%u "
        "accepted_crc=%u match=%u clean=%u unknown=%u adjacent_match=%u adjacent_unknown=%u "
        "spaced_match=%u spaced_unknown=%u spaced_accepted=%u spaced_failed=%u "
        "spaced_control_failed=%u bridge_match=%u bridge_unknown=%u bridge_trials=%u "
        "bridge_successes=%u nop_match=%u nop_trials=%u nop_successes=%u ind_match=%u ind_trials=%u "
        "ind_successes=%u cross_page_trials=%u cross_page_successes=%u probe_mean_ns=%llu probe_max_ns=%llu",
        name, repeats, returned, file_crc, live_crc, crc_pass, accepted_crc, matched, clean,
        unknown, adjacent_match, adjacent_unknown, spaced_match, spaced_unknown, spaced_accepted,
        spaced_failed, spaced_control_failed, bridge_match, bridge_unknown, bridge_trials,
        bridge_successes, nop_match, nop_trials, nop_successes, ind_match, ind_trials, ind_successes,
        cross_page_trials, cross_page_successes,
        (unsigned long long)(total_ns / repeats),
        (unsigned long long)max_ns);
    LOG("DOBBY_DETECT_LIVE stage=%s n=%d match=%u unknown=%u kernel_file=%u kernel_crc=%08x "
        "single_crc=%08x zero_match=%u zero_clean=%u zero_unknown=%u mean_ns=%llu max_ns=%llu",
        name, repeats, live_match, live_unknown, kernel_file, kernel_crc, single_crc,
        zero_match, zero_clean, zero_unknown,
        (unsigned long long)(live_total_ns / repeats), (unsigned long long)live_max_ns);
}

static void dobby_detection_fixture(const char *key, int repeats)
{
    const uint8_t *text = (const uint8_t *)(uintptr_t)&dobby_crc_payload;
    const long page_size = sysconf(_SC_PAGESIZE);
    struct page reference;
    const uint8_t *ap_reference = MAP_FAILED;
    struct business business = { .fn = ud_payload };
    pthread_t thread;
    bool have_thread = false;
    uint8_t file[DOBBY_CRC_BYTES], patched[DOBBY_CRC_BYTES];
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
    ap_reference = mmap(NULL, (size_t)page_size, PROT_READ, MAP_PRIVATE,
                        reference.fd, reference.file_offset);
    REQUIRE(ap_reference != MAP_FAILED, "Dobby AP read-only alias errno=%d", errno);
    if (ap_reference == MAP_FAILED) goto close_reference;
    struct ud_exclusive_observation wrong_reference;
    ud_observe_ap_reservation(text, reference.address + reference.entry, reference.fd,
                               reference.file_offset + reference.entry, &wrong_reference);
    REQUIRE(wrong_reference.reservation_loss == UD_UNKNOWN && wrong_reference.error == EACCES,
            "Dobby AP accepted an executable reference");
    if (!key) dobby_check_kernel_access(text);
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "Dobby detection business thread");
    pid_t sibling = have_thread ? pthread_gettid_np(thread) : 0;
    REQUIRE(sibling > 0, "Dobby detection business tid");
    dobby_detection_stage("clean", text, &reference, ap_reference, sibling, repeats, file, DOBBY_ORIGINAL, true,
                          UD_NO_MATCH, false);

    dobby_setup_error = dobby_crc_setup((void *)text, (size_t)page_size);
    if (dobby_setup_error) {
        REQUIRE(0, "Dobby detection setup errno=%d", dobby_setup_error);
        goto close_reference;
    }
    dobby_detection_stage("patch_only", text, &reference, ap_reference, sibling, repeats, file, DOBBY_HOOKED,
                          false, UD_NO_MATCH, false);
    struct ud_mapping map;
    REQUIRE(!madvise((void *)text, (size_t)page_size, MADV_RANDOM) &&
            uy_invalid_advice(text, (size_t)page_size) == EINVAL &&
            !ud_mapping_at("/proc/self/smaps", text, &map) && map.randomread,
            "Dobby invalid advice changed an unregistered mapping");
    copy_scalar(patched, text, sizeof(patched));
    dobby_check_unaligned_protect("unarmed", text, text, (size_t)page_size, patched);
    if (!key) goto close_reference;

    const char *stage = "module key";
    struct uy_ctx ctx;
    bool cleanup = false;
    uint64_t arm_begin = now_ns();
    int error = uy_init_key(&ctx, key) ? EINVAL :
                dobby_crc_arm(&ctx, text, (size_t)page_size, &stage, &cleanup);
    uint64_t arm_ns = now_ns() - arm_begin;
    REQUIRE(!error, "Dobby detection %s errno=%d", stage, error);
    if (!error) LOG("DOBBY_ARM register_ns=%llu", (unsigned long long)arm_ns);
    if (!error) {
        struct urov_y_request status = {0};
        dobby_detection_stage("overlay", text, &reference, ap_reference, sibling, repeats, file, DOBBY_HOOKED,
                              true, UD_NO_MATCH, false);
        dobby_check_fork_kmem(text, dobby_file_page, DOBBY_CRC_BYTES);
        REQUIRE(!uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && status.reserved == 1 &&
                status.generation == 1 && status.hits >= (uint64_t)repeats * DOBBY_CRC_BYTES &&
                !status.failures,
                "Dobby detection overlay hits=%llu failures=%llu",
                (unsigned long long)status.hits, (unsigned long long)status.failures);
        LOG("DOBBY_DETECT_STATUS hits=%llu failures=%llu",
            (unsigned long long)status.hits, (unsigned long long)status.failures);

        if (dobby_restore(&ctx, text, ap_reference, (size_t)page_size, file, patched)) cleanup = false;
    }
    if (cleanup && uy_deactivate(&ctx)) {
        REQUIRE(0, "Dobby detection DEACTIVATE errno=%d", errno);
        goto close_reference;
    }
    if (!error) {
        dobby_detection_stage("deactivated", text, &reference, ap_reference, sibling, repeats, file, DOBBY_HOOKED,
                              false, UD_NO_MATCH, false);
        dobby_check_page_lock(&ctx, text, (size_t)page_size);
        dobby_check_registration_guard(&ctx, text);
    }

close_reference:
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.ops) > 0 && !atomic_load(&business.errors),
                "Dobby detection business worker");
        LOG("DOBBY_DETECT_BUSINESS ops=%llu errors=%d",
            (unsigned long long)atomic_load(&business.ops), atomic_load(&business.errors));
    }
    if (ap_reference != MAP_FAILED)
        REQUIRE(!munmap((void *)ap_reference, (size_t)page_size), "Dobby AP alias cleanup");
    page_close(&reference);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}
