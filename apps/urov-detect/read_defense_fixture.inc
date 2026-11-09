/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Use a private pipe so the kernel reads the RX source through GUP. The
 * caller owns and keeps the source mapped for the duration of the transfer. */
static int read_defense_pipe(const uint8_t *source, uint8_t out[DOBBY_CRC_BYTES])
{
    int fds[2];
    struct iovec iov = { .iov_base = (void *)source, .iov_len = DOBBY_CRC_BYTES };
    if (pipe2(fds, O_CLOEXEC | O_NONBLOCK)) return errno;

    ssize_t got = vmsplice(fds[1], &iov, 1, SPLICE_F_NONBLOCK);
    int error = got == DOBBY_CRC_BYTES ? 0 : got < 0 ? errno : EIO;
    if (!error) {
        got = read(fds[0], out, DOBBY_CRC_BYTES);
        error = got == DOBBY_CRC_BYTES ? 0 : got < 0 ? errno : EIO;
    }
    close(fds[1]);
    close(fds[0]);
    return error;
}

/* The unprivileged load form: at EL0 it performs the same access as LDURB, so
 * a read trap that decodes it should return the same image byte.  If a module
 * leaves it to fail-closed, the synthetic SIGSEGV terminates the fixture and
 * the matrix reports the missing result instead of a silent value mismatch. */
static uint8_t read_defense_ldtrb(const uint8_t *address)
{
    uint32_t value;

    __asm__ volatile("ldtrb %w0, [%1]" : "=r"(value) : "r"(address) : "memory");
    return (uint8_t)value;
}

/* Ground truth only: keyless observation and recovery take no context/key. */
static int read_defense_arm(const struct uy_ctx *ctx, const uint8_t *text, const uint8_t *image,
                            unsigned mode, bool all_callers)
{
    struct urov_y_request q = uy_req(UROV_Y_REGISTER);
    q.address = (uintptr_t)text;
    q.mode = mode;
    q.fake_addr = (uintptr_t)image;
    q.length = DOBBY_CRC_BYTES;
    if (mode != UROV_Y_MODE_PAGE_AP) {
        q.site_count = 1;
        q.sites[0] = (uintptr_t)&uy_site_ldrb;
    }
    if (!all_callers) {
        q.caller_count = 1;
        q.caller_start[0] = (uintptr_t)&uy_business_ldrb;
        q.caller_end[0] = (uintptr_t)uy_business_ldrb_end;
    }
    if (uy_control(ctx, UROV_Y_REGISTER, &q)) return errno;
    return q.state == UROV_Y_ACTIVE ? 0 : EPROTO;
}

/* The only store writes the old values back to private scratch. This shape
 * serves as a regression control for the paired bridge in 2.16.0. */
static bool read_defense_pair_store(const uint8_t *address)
{
    _Alignas(16) uint64_t scratch[2] = { UINT64_C(0x12345678), UINT64_C(0x87654321) };
    uint64_t low, high;
    unsigned byte, status;
    __asm__ volatile("ldxp %0, %1, [%4]\n"
                     "ldrb %w2, [%5]\n"
                     "stxp %w3, %0, %1, [%4]"
                     : "=&r"(low), "=&r"(high), "=&r"(byte), "=&r"(status)
                     : "r"(scratch), "r"(address) : "memory");
    return status == 0;
}

static void read_defense_pair(const char *name, const uint8_t *text, const uint8_t *control,
                              bool expect_trap)
{
    enum { TRIALS = 64, MIN_CONTROL = 62 };
    unsigned target_ok = 0, control_ok = 0;
    uint8_t target_byte, control_byte;
    /* Dobby patches the function, so sample an unchanged byte on its page. */
    text += DOBBY_CRC_BYTES;
    control += DOBBY_CRC_BYTES;
    copy_scalar(&target_byte, text, 1);
    copy_scalar(&control_byte, control, 1);
    for (unsigned i = 0; i < TRIALS; ++i) {
        if (i & 1U) control_ok += read_defense_pair_store(control);
        target_ok += read_defense_pair_store(text);
        if (!(i & 1U)) control_ok += read_defense_pair_store(control);
    }
    bool same_byte = target_byte == control_byte;
    enum ud_verdict verdict = UD_UNKNOWN;
    if (same_byte && control_ok >= MIN_CONTROL) {
        if (!target_ok) verdict = UD_MATCH;
        else if (target_ok >= MIN_CONTROL) verdict = UD_NO_MATCH;
    }
    REQUIRE(verdict == (expect_trap ? UD_MATCH : UD_NO_MATCH),
            "read-defense pair %s verdict=%d target=%u control=%u same_byte=%d",
            name, verdict, target_ok, control_ok, same_byte);
    LOG("READ_DEFENSE_PAIR stage=%s n=%u match=%d target_ok=%u control_ok=%u same_byte=%d",
        name, TRIALS, verdict, target_ok, control_ok, same_byte);
}

static void read_defense_stage(const char *name, const uint8_t *text, const uint8_t *control,
                               const uint8_t file[DOBBY_CRC_BYTES],
                               const uint8_t expected_live[DOBBY_CRC_BYTES],
                               bool overlay, bool ap_trap, uint32_t expected_return,
                               int repeats, bool hardened)
{
    struct ud_mapping before, after;
    uint8_t control_bytes[DOBBY_CRC_BYTES];
    int control_error = read_defense_pipe(control, control_bytes);
    bool control_ok = !control_error && !memcmp(control_bytes, file, DOBBY_CRC_BYTES);
    int map_error = ud_mapping_at("/proc/self/smaps", text, &before);
    unsigned matches = 0, unknown = 0, old_accept = 0, guarded_accept = 0, live_ok = 0;
    uint32_t user_crc = 0, live_crc = 0, returned = 0;
    uint64_t elapsed = 0;
    int last_error = 0;

    ++g_cases;
    REQUIRE(control_ok && !map_error && before.readable && before.executable && !before.writable,
            "read-defense %s control errno=%d maps errno=%d", name, control_error, map_error);
    if (!control_ok || map_error || !before.readable || before.writable || !before.executable)
        return;

    for (int i = 0; i < repeats; ++i) {
        uint8_t user[DOBBY_CRC_BYTES], user_again[DOBBY_CRC_BYTES];
        uint8_t live[DOBBY_CRC_BYTES], live_again[DOBBY_CRC_BYTES];
        uint64_t start = now_ns();
        int error = read_defense_pipe(text, live);
        elapsed += now_ns() - start;
        crc_copy_window(user, text, sizeof(user));
        if (!error) error = read_defense_pipe(text, live_again);
        crc_copy_window(user_again, text, sizeof(user_again));
        if (error || memcmp(live, live_again, sizeof(live)) ||
            memcmp(user, user_again, sizeof(user))) {
            last_error = error ? error : EAGAIN;
            ++unknown;
            continue;
        }
        /* Exact comparison precedes the CRC, so a CRC collision cannot mask a
         * split view. Only the independent view is accepted by the new check. */
        matches += memcmp(user, live, sizeof(live)) != 0;
        old_accept += !memcmp(user, file, sizeof(user));
        guarded_accept += !memcmp(live, file, sizeof(live));
        live_ok += !memcmp(live, expected_live, sizeof(live));
        user_crc = (uint32_t)crc32(0, user, sizeof(user));
        live_crc = (uint32_t)crc32(0, live, sizeof(live));
        returned = dobby_crc_payload();
        REQUIRE(returned == expected_return, "read-defense %s execute=%04x", name, returned);
    }

    unsigned n = (unsigned)repeats;
    bool original = expected_return == DOBBY_ORIGINAL;
    bool preserved = !ud_mapping_at("/proc/self/smaps", text, &after) && dobby_same_vma(&before, &after);
    unsigned want_match = overlay && !hardened ? n : 0;
    unsigned want_old = overlay || original ? n : 0;
    unsigned want_guarded = original || (hardened && overlay) ? n : 0;
    REQUIRE(!unknown && matches == want_match && old_accept == want_old &&
            guarded_accept == want_guarded && live_ok == n && preserved,
            "read-defense %s match=%u unknown=%u errno=%d old=%u guarded=%u live=%u vma=%d",
            name, matches, unknown, last_error, old_accept, guarded_accept, live_ok, preserved);
    LOG("READ_DEFENSE stage=%s n=%u match=%u unknown=%u old_accept=%u guarded_accept=%u "
        "live_ok=%u vma_preserved=%d execute=%04x user_crc=%08x live_crc=%08x "
        "pipe_mean_ns=%llu errno=%d", name, n, matches, unknown, old_accept, guarded_accept,
        live_ok, preserved, returned, user_crc, live_crc, (unsigned long long)(elapsed / n), last_error);
    read_defense_pair(name, text, control, ap_trap && !hardened);
}

static void read_defense_v216_stage(const char *name, const uint8_t *text,
                                    const struct page *reference, const uint8_t *file,
                                    const uint8_t *expected_live, unsigned mode,
                                    bool all_callers, int repeats)
{
    const uint8_t *control = reference->address + reference->entry;
    off_t offset = reference->file_offset + reference->entry;
    const bool ap = mode == UROV_Y_MODE_PAGE_AP;
    const bool original = expected_live == file;
    struct ud_exclusive_observation alu;
    struct ud_mapping before, after;
    int map_error = ud_mapping_at("/proc/self/maps", text, &before), read_error = 0;
    unsigned split = 0, post = 0, post_ok = 0, unknown = 0, raw_ok = 0;
    unsigned old_accept = 0, guarded_accept = 0;
    /* 2.18.0 no longer rebuilds the readv destination from user memory: the
     * kernel copies the overlay page itself, so `post` must stay untouched and
     * `live` carries the same view the overlay serves to that caller.  A
     * caller-window session answers the readv with the snapshot (outside the
     * window); an all-caller session answers with the image. */
    const uint8_t *want_view = (mode && all_callers && !original) ? file : expected_live;
    uint64_t read_ns = 0;
    uint32_t returned = 0;
    ++g_cases;

    ud_observe_ap_alu(text + DOBBY_CRC_BYTES, control + DOBBY_CRC_BYTES,
                     reference->fd, offset + DOBBY_CRC_BYTES, &alu);
    for (int i = 0; i < repeats; ++i) {
        struct ud_readv_observation views;
        ud_observe_readv_redirect(text, control, DOBBY_CRC_BYTES, reference->fd, offset,
                                  crc_copy_window, &views);
        read_ns += views.elapsed_ns;
        if (views.reader_diff == UD_UNKNOWN || views.post_copy == UD_UNKNOWN) {
            read_error = views.error;
            ++unknown;
            continue;
        }
        split += views.reader_diff == UD_MATCH;
        if (views.post_copy == UD_MATCH) {
            ++post;
            post_ok += !memcmp(views.post_bytes, all_callers ? file : expected_live, DOBBY_CRC_BYTES);
        }
        old_accept += !memcmp(views.user_bytes, file, DOBBY_CRC_BYTES);
        guarded_accept += !memcmp(views.live_bytes, file, DOBBY_CRC_BYTES);
        raw_ok += !memcmp(views.live_bytes, want_view, DOBBY_CRC_BYTES);
        returned = dobby_crc_payload();
        REQUIRE(returned == (original ? DOBBY_ORIGINAL : DOBBY_HOOKED),
                "v216 %s execute=%04x", name, returned);
    }
    bool preserved = !map_error && !ud_mapping_at("/proc/self/maps", text, &after) &&
                     dobby_same_vma(&before, &after);
    unsigned n = (unsigned)repeats;
    unsigned want_split = (mode && !all_callers && !original) ? n : 0U;
    unsigned want_guarded = want_view == file ? n : 0U;
    REQUIRE(alu.reservation_loss == (ap ? UD_MATCH : UD_NO_MATCH) ||
            (alu.reservation_loss == UD_UNKNOWN && alu.error == EAGAIN),
            "v216 %s ALU verdict=%d errno=%d", name, alu.reservation_loss, alu.error);
    REQUIRE(!unknown && split == want_split && post == 0U && raw_ok == n && preserved &&
            old_accept == (mode || original ? n : 0U) && guarded_accept == want_guarded,
            "v216 %s split=%u post=%u post_ok=%u unknown=%u read_errno=%d raw_ok=%u",
            name, split, post, post_ok, unknown, read_error, raw_ok);
    LOG("READ_DEFENSE_V216 stage=%s n=%u split=%u post=%u post_ok=%u unknown=%u read_errno=%d "
        "old_accept=%u guarded_accept=%u raw_ok=%u alu=%d alu_failed=%u alu_accepted=%u "
        "alu_errno=%d vma_preserved=%d execute=%04x read_mean_ns=%llu alu_ns=%llu",
        name, n, split, post, post_ok, unknown, read_error, old_accept, guarded_accept, raw_ok,
        alu.reservation_loss, alu.target_failed, alu.accepted, alu.error, preserved, returned,
        (unsigned long long)(read_ns / n), (unsigned long long)(alu.elapsed_ns));
}

static bool g_read_defense_fixed;
static bool g_read_defense_window;
static bool g_read_defense_221;
static bool g_read_defense_221_guarded;
static bool g_read_defense_222;
static bool g_read_defense_223;
static bool g_read_defense_224;

static const char *read_defense_version_tag(void)
{
    if (g_read_defense_224) return "V224";
    if (g_read_defense_223) return "V223";
    if (g_read_defense_222) return "V222";
    if (g_read_defense_221) return "V221";
    if (g_read_defense_221_guarded) return "V221";
    if (g_read_defense_window) return "V220";
    if (g_read_defense_fixed) return "V219";
    return "V218";
}

static void read_defense_observe_sites(enum ud_verdict *code, enum ud_verdict *fetch)
{
    struct page reference;
    *code = *fetch = UD_UNKNOWN;
    if (uy_open_exec_reference(&reference)) return;

    const uint8_t *site = (const uint8_t *)(uintptr_t)&uy_site_ldrb;
    const void *canary = (const void *)(uintptr_t)&uy_site_canary;
    const off_t site_offset = reference.file_offset + (uintptr_t)site % UROV_Y_PAGE;
    struct ud_views views;
    struct ud_exclusive_observation exec;
    ud_check_views(site, sizeof(uint32_t), reference.fd, site_offset, &views);
    *code = views.file_diff;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        ud_observe_execution(canary, reference.address + reference.entry, reference.fd,
                             reference.file_offset + reference.entry, &exec);
        if (exec.error != EAGAIN) break;
    }
    *fetch = exec.reservation_loss;
    page_close(&reference);
}

/* These observations have no module key or state. Keep both mappings and the
 * file stable. The scalar reader runs outside the business caller window and
 * at a different instruction from the business load. */
/* A single unstable sample (EAGAIN) is a scheduling or debug-event artifact, not
 * a finding: retry it like the 2.19 CSEL probe does before counting UNKNOWN. */
typedef void (*window_probe_fn)(const void *, const void *, int, off_t,
                                struct ud_exclusive_observation *);
typedef void (*window_store_probe_fn)(const void *, const void *, int, off_t,
                                      struct ud_store_observation *);

static void window_probe(window_probe_fn fn, const uint8_t *text, const uint8_t *control,
                         const struct page *reference, off_t offset,
                         struct ud_exclusive_observation *out)
{
    fn(text, control, reference->fd, offset, out);
    for (unsigned retry = 0; retry < 2 && out->error == EAGAIN; ++retry)
        fn(text, control, reference->fd, offset, out);
}

static void window_store_probe(window_store_probe_fn fn, const uint8_t *text,
                               const uint8_t *control, const struct page *reference,
                               off_t offset, struct ud_store_observation *out)
{
    fn(text, control, reference->fd, offset, out);
    for (unsigned retry = 0; retry < 2 && out->error == EAGAIN; ++retry)
        fn(text, control, reference->fd, offset, out);
}

struct read_defense_decisions {
    unsigned evidence, unknown, changed, accepted;
};

static void read_defense_classify(enum ud_verdict split, enum ud_verdict file_diff,
                                  enum ud_verdict ap, enum ud_verdict site_code,
                                  enum ud_verdict site_fetch, struct read_defense_decisions *out)
{
    if (split == UD_MATCH || ap == UD_MATCH || site_code == UD_MATCH || site_fetch == UD_MATCH) {
        ++out->evidence;
    } else if (split == UD_UNKNOWN || file_diff == UD_UNKNOWN || ap == UD_UNKNOWN ||
               site_code == UD_UNKNOWN || site_fetch == UD_UNKNOWN) {
        ++out->unknown;
    } else if (file_diff == UD_MATCH) {
        ++out->changed;
    } else {
        ++out->accepted;
    }
}

struct read_defense_boundary_stats {
    struct read_defense_decisions decision;
    unsigned ap, ap_unknown, triplets, target_failed, control_failed;
    uint64_t elapsed_ns, max_ns;
};

struct read_defense_v220_stats {
    struct read_defense_decisions decision;
    unsigned pre_alu, fp, ap, ap_unknown, triplets, target_failed, control_failed;
    unsigned baseline_ok, pre_gpr, simd, simd_value;
    unsigned leaf_call, permute, fp_arith, pre_mov, pre_long, residual_trials, residual_failed,
             residual_control_failed;
    unsigned self_bad, neon_bad, self_done, neon_done, deep_bad, deep_done;
    int self_err, neon_err;
    unsigned split;
    uint64_t elapsed_ns, max_ns, residual_ns;
};

/* Observe and gate the integrity result without a key, kernel-assisted copy,
 * payload execution or any of the fixture's ground-truth inputs. */
static void read_defense_v220_sample(const uint8_t *text, const struct page *reference,
                                    enum ud_verdict site_code, enum ud_verdict site_fetch,
                                    struct read_defense_v220_stats *stats,
                                    struct read_defense_boundary_stats *boundary,
                                    bool deep_window)
{
    const uint8_t *control = reference->address + reference->entry;
    off_t offset = reference->file_offset + reference->entry;
    struct ud_exclusive_observation pre_alu, fp;
    struct ud_views views;
    uint64_t begin = now_ns();
    enum ud_verdict split = ud_check_reader_views(text, DOBBY_CRC_BYTES, reference->fd,
                                                 offset, crc_copy_window, &views);
    window_probe(ud_observe_ap_pre_alu, text, control, reference, offset, &pre_alu);
    window_probe(ud_observe_ap_fp, text, control, reference, offset, &fp);
    enum ud_verdict ap = pre_alu.reservation_loss == fp.reservation_loss ?
                        pre_alu.reservation_loss : UD_UNKNOWN;
    if (g_read_defense_221_guarded) {
        struct ud_ap_v221_observation residual;
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            ud_observe_ap_v221(text + DOBBY_CRC_BYTES, control + DOBBY_CRC_BYTES,
                               reference->fd, offset + DOBBY_CRC_BYTES, &residual);
            if (residual.baseline.error != EAGAIN && residual.pre_gpr.error != EAGAIN &&
                residual.simd.error != EAGAIN)
                break;
        }
        stats->baseline_ok += residual.baseline.reservation_loss == UD_NO_MATCH;
        stats->pre_gpr += residual.pre_gpr.reservation_loss == UD_MATCH;
        stats->simd += residual.simd.reservation_loss == UD_MATCH;
        stats->simd_value += residual.simd.value_seen && residual.simd.value_match;
        ap = residual.verdict;
    }
    if (g_read_defense_222) {
        struct ud_ap_v222_observation residual;
        uint64_t residual_begin = now_ns();
        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            ud_observe_ap_v222(text, control, reference->fd, offset, &residual);
            if (residual.leaf_call.error != EAGAIN && residual.permute.error != EAGAIN)
                break;
        }
        stats->residual_ns += now_ns() - residual_begin;
        stats->leaf_call += residual.leaf_call.reservation_loss == UD_MATCH;
        stats->permute += residual.permute.reservation_loss == UD_MATCH;
        stats->residual_trials += residual.leaf_call.accepted + residual.permute.accepted;
        stats->residual_failed += residual.leaf_call.target_failed + residual.permute.target_failed;
        stats->residual_control_failed += residual.leaf_call.control_failed + residual.permute.control_failed;
        ap = residual.verdict;
    }
    if (g_read_defense_223) {
        struct ud_ap_v223_observation arith;

        for (unsigned attempt = 0; attempt < 3; ++attempt) {
            ud_observe_ap_v223(text, control, reference->fd, offset, &arith);
            if (arith.fparith.error != EAGAIN) break;
        }
        stats->fp_arith += arith.fparith.reservation_loss == UD_MATCH;
        stats->pre_mov += arith.pre_mov.reservation_loss == UD_MATCH;
        stats->pre_long += arith.pre_long.reservation_loss == UD_MATCH;
        if (deep_window) {
            uint64_t deep_scratch = 0;
            unsigned deep_byte = 0;

            /* Only the target is meaningful: the 6000-instruction native
             * control loop can be preempted and then its STXR legitimately
             * fails, while the modeled window completes it. */
            stats->deep_bad += ud_deep_window_status(text, &deep_scratch, &deep_byte) != 0;
            ++stats->deep_done;
        }
        stats->self_bad += arith.self_store.unexpected_stores;
        stats->neon_bad += arith.neon_self.unexpected_stores;
        stats->self_done += arith.self_store.error == 0;
        stats->neon_done += arith.neon_self.error == 0;
        stats->self_err = arith.self_store.error;
        stats->neon_err = arith.neon_self.error;
        ap = arith.verdict;
    }
    stats->pre_alu += pre_alu.reservation_loss == UD_MATCH;
    stats->fp += fp.reservation_loss == UD_MATCH;
    stats->ap += ap == UD_MATCH;
    stats->ap_unknown += ap == UD_UNKNOWN;
    stats->triplets += pre_alu.accepted + fp.accepted;
    stats->target_failed += pre_alu.target_failed + fp.target_failed;
    stats->control_failed += pre_alu.control_failed + fp.control_failed;
    stats->split += split == UD_MATCH;
    read_defense_classify(split, views.file_diff, ap, site_code, site_fetch, &stats->decision);
    uint64_t ns = now_ns() - begin;
    stats->elapsed_ns += ns;
    if (ns > stats->max_ns) stats->max_ns = ns;

    if (g_read_defense_223) {
        struct ud_exclusive_observation overwritten;

        begin = now_ns();
        window_probe(ud_observe_ap_overwrite_ldxr, text, control, reference, offset, &overwritten);
        ns = now_ns() - begin;
        boundary->elapsed_ns += ns;
        if (ns > boundary->max_ns) boundary->max_ns = ns;
        boundary->ap += overwritten.reservation_loss == UD_MATCH;
        boundary->ap_unknown += overwritten.reservation_loss == UD_UNKNOWN;
        boundary->triplets += overwritten.accepted;
        boundary->target_failed += overwritten.target_failed;
        boundary->control_failed += overwritten.control_failed;
        read_defense_classify(split, views.file_diff, overwritten.reservation_loss, site_code,
                              site_fetch, &boundary->decision);
    }
}

static void read_defense_v218_stage(const char *name, const uint8_t *text,
                                    const struct page *reference, const uint8_t *file,
                                    const uint8_t *expected_live, unsigned mode,
                                    bool all_callers, int repeats)
{
    const uint8_t *control = reference->address + reference->entry;
    off_t offset = reference->file_offset + reference->entry;
    bool ap = mode == UROV_Y_MODE_PAGE_AP;
    bool original = expected_live == file;
    bool fixed = g_read_defense_fixed;
    unsigned n = (unsigned)repeats;
    unsigned split = 0, traps = 0, unknown = 0, changed = 0, accepted = 0;
    unsigned business_file = 0, scalar_file = 0, kernel_file = 0;
    unsigned target_failed = 0, control_failed = 0, triplets = 0, retries = 0;
    unsigned csel_traps = 0, csel_unknown = 0, guarded = 0, csel_retries = 0;
    unsigned csel_failed = 0, csel_triplets = 0;
    unsigned load_traps = 0, store_traps = 0, branch_traps = 0, xload_traps = 0, xpair_traps = 0;
    unsigned window_unknown = 0, window_value = 0, window_value_ok = 0;
    struct read_defense_v220_stats policy = {0};
    struct read_defense_boundary_stats boundary = {0};
    unsigned clrex_bad = 0, clrex_done = 0, svc_bad = 0, svc_done = 0;
    bool window = g_read_defense_window;
    enum ud_verdict site_code = UD_NO_MATCH, site_fetch = UD_NO_MATCH;
    uint64_t elapsed = 0, max_ns = 0;
    uint32_t executed = 0;
    ++g_cases;

    if (fixed) read_defense_observe_sites(&site_code, &site_fetch);
    for (unsigned i = 0; i < n; ++i) {
        struct ud_live_observation business, scalar;
        struct ud_exclusive_observation alu, csel = { .reservation_loss = UD_NO_MATCH };
        uint64_t begin = now_ns();
        if (window) read_defense_v220_sample(text, reference, site_code, site_fetch, &policy,
                                             &boundary, g_read_defense_224 && ap);
        ud_observe_live(text, DOBBY_CRC_BYTES, reference->fd, offset, crc_copy_window, &business);
        ud_observe_live(text, DOBBY_CRC_BYTES, reference->fd, offset, copy_scalar, &scalar);
        ud_observe_ap_alu(text, control, reference->fd, offset, &alu);
        if (alu.reservation_loss == UD_UNKNOWN && alu.error == EAGAIN) {
            ++retries;
            ud_observe_ap_alu(text, control, reference->fd, offset, &alu);
        }
        if (fixed) {
            ud_observe_ap_csel(text, control, reference->fd, offset, &csel);
            for (unsigned retry = 0; retry < 2 && csel.error == EAGAIN; ++retry) {
                ++csel_retries;
                ud_observe_ap_csel(text, control, reference->fd, offset, &csel);
            }
            csel_traps += csel.reservation_loss == UD_MATCH;
            csel_unknown += csel.reservation_loss == UD_UNKNOWN;
            csel_failed += csel.target_failed;
            csel_triplets += csel.accepted;
        }
        if (window) {
            struct ud_exclusive_observation load = { .reservation_loss = UD_NO_MATCH };
            struct ud_exclusive_observation store = { .reservation_loss = UD_NO_MATCH };
            struct ud_exclusive_observation branch = { .reservation_loss = UD_NO_MATCH };
            struct ud_exclusive_observation xload = { .reservation_loss = UD_NO_MATCH };
            struct ud_exclusive_observation xpair = { .reservation_loss = UD_NO_MATCH };
            struct ud_store_observation clrex, svc;

            window_probe(ud_observe_ap_load, text, control, reference, offset, &load);
            window_probe(ud_observe_ap_store, text, control, reference, offset, &store);
            window_probe(ud_observe_ap_branch, text, control, reference, offset, &branch);
            window_probe(ud_observe_ap_xload, text, control, reference, offset, &xload);
            if (g_read_defense_224)
                window_probe(ud_observe_ap_xpair, text, control, reference, offset, &xpair);
            window_store_probe(ud_observe_gap_clrex_status, text, control, reference, offset,
                               &clrex);
            window_store_probe(ud_observe_gap_svc_status, text, control, reference, offset, &svc);
            load_traps += load.reservation_loss == UD_MATCH;
            store_traps += store.reservation_loss == UD_MATCH;
            branch_traps += branch.reservation_loss == UD_MATCH;
            xload_traps += xload.reservation_loss == UD_MATCH;
            xpair_traps += xpair.reservation_loss == UD_MATCH;
            window_unknown += load.reservation_loss == UD_UNKNOWN ||
                              store.reservation_loss == UD_UNKNOWN ||
                              branch.reservation_loss == UD_UNKNOWN ||
                              xload.reservation_loss == UD_UNKNOWN ||
                              xpair.reservation_loss == UD_UNKNOWN ||
                              load.error == EAGAIN || store.error == EAGAIN ||
                              branch.error == EAGAIN || xload.error == EAGAIN ||
                              xpair.error == EAGAIN;
            window_value += load.value_seen + store.value_seen + branch.value_seen +
                            xload.value_seen;
            window_value_ok += (load.value_seen && load.value_match) +
                               (store.value_seen && store.value_match) +
                               (branch.value_seen && branch.value_match) +
                               (xload.value_seen && xload.value_match);
            clrex_done += clrex.error == 0;
            clrex_bad += clrex.unexpected_stores;
            svc_done += svc.error == 0;
            svc_bad += svc.unexpected_stores;
        }
        uint64_t ns = now_ns() - begin;
        elapsed += ns;
        if (ns > max_ns) max_ns = ns;

        target_failed += alu.target_failed;
        control_failed += alu.control_failed;
        triplets += alu.accepted;
        traps += alu.reservation_loss == UD_MATCH;
        if (business.verdict == UD_UNKNOWN || scalar.verdict == UD_UNKNOWN ||
            memcmp(business.kernel_bytes, scalar.kernel_bytes, DOBBY_CRC_BYTES)) {
            ++unknown;
            continue;
        }
        bool diverged = business.verdict == UD_MATCH || scalar.verdict == UD_MATCH;
        bool matches_file = !memcmp(business.user_bytes, file, DOBBY_CRC_BYTES);
        split += diverged;
        business_file += matches_file;
        scalar_file += !memcmp(scalar.user_bytes, file, DOBBY_CRC_BYTES);
        kernel_file += !memcmp(business.kernel_bytes, file, DOBBY_CRC_BYTES);
        unknown += alu.reservation_loss == UD_UNKNOWN;
        changed += !diverged && !matches_file;
        accepted += !diverged && matches_file && alu.reservation_loss == UD_NO_MATCH;
        if (!window) {
            guarded += !diverged && matches_file && csel.reservation_loss == UD_NO_MATCH &&
                       site_code == UD_NO_MATCH && site_fetch == UD_NO_MATCH;
        }

        /* Execution is ground truth for this side-effect-free payload only. */
        const uint8_t *want_business = mode ? file : expected_live;
        const uint8_t *want_scalar = ap && all_callers ? file : expected_live;
        const uint8_t *want_kernel = mode && all_callers ? file : expected_live;
        REQUIRE(!memcmp(business.user_bytes, want_business, DOBBY_CRC_BYTES) &&
                !memcmp(scalar.user_bytes, want_scalar, DOBBY_CRC_BYTES) &&
                !memcmp(business.kernel_bytes, want_kernel, DOBBY_CRC_BYTES),
                "v218 %s unexpected sample bytes", name);
        executed = dobby_crc_payload();
        REQUIRE(executed == (original ? DOBBY_ORIGINAL : DOBBY_HOOKED),
                "v218 %s execute=%04x", name, executed);
    }
    unsigned want_traps = fixed ? 0U : (ap ? n : 0U);
    unsigned want_accept = fixed ? (original || (ap && all_callers) ? n : 0U) :
                                   (original && !ap ? n : 0U);
    REQUIRE(!unknown && split == (mode && !original && !(ap && all_callers) ? n : 0U) &&
            traps == want_traps && changed == (!mode && !original ? n : 0U) &&
            accepted == want_accept &&
            business_file == (original || mode ? n : 0U) &&
            scalar_file == (original || (ap && all_callers) ? n : 0U) &&
            kernel_file == (original || (mode && all_callers) ? n : 0U),
            "v218 %s split=%u trap=%u unknown=%u changed=%u accept=%u views=%u/%u/%u",
            name, split, traps, unknown, changed, accepted, business_file, scalar_file, kernel_file);
        LOG("READ_DEFENSE_%s stage=%s n=%u split=%u trap=%u unknown=%u changed=%u accept=%u "
        "business_file=%u scalar_file=%u kernel_file=%u execute=%04x "
        "triplets=%u target_failed=%u control_failed=%u retries=%u mean_ns=%llu max_ns=%llu",
        read_defense_version_tag(),
        name, n, split, traps, unknown, changed, accepted, business_file, scalar_file, kernel_file,
        executed, triplets, target_failed, control_failed, retries,
        (unsigned long long)(elapsed / n), (unsigned long long)max_ns);
    if (fixed) {
        unsigned want_csel = ap && !window ? n : 0U;
        /* The older unguarded 2.21 policy misses AP when no views disagree. */
        unsigned want_guarded = g_read_defense_221 && !g_read_defense_221_guarded && ap ?
            (original || all_callers ? n : 0U) : (!mode && original ? n : 0U);
        if (window) {
            guarded = policy.decision.accepted;
            if (g_read_defense_223) want_guarded = guarded;
        }

        LOG("READ_DEFENSE_KEYLESS stage=%s n=%u csel=%u csel_unknown=%u "
            "csel_failed=%u csel_triplets=%u csel_retries=%u site_code=%d site_fetch=%d guarded=%u",
            name, n, csel_traps, csel_unknown, csel_failed, csel_triplets, csel_retries,
            site_code, site_fetch, guarded);
        REQUIRE(csel_traps == want_csel && !csel_unknown &&
                site_code == (mode == UROV_Y_MODE_SITE_BRK ? UD_MATCH : UD_NO_MATCH) &&
                site_fetch == (mode == UROV_Y_MODE_PAGE_UXN ? UD_MATCH : UD_NO_MATCH) &&
                guarded == want_guarded,
                "v219 keyless %s csel=%u unknown=%u code=%d fetch=%d guarded=%u",
                name, csel_traps, csel_unknown, site_code, site_fetch, guarded);
    }
    if (window) {
        unsigned want_window = 0U;

        LOG("READ_DEFENSE_KEYLESS2 stage=%s n=%u load=%u store=%u branch=%u xload=%u xpair=%u "
            "unknown=%u value=%u value_ok=%u clrex_bad=%u clrex_done=%u svc_bad=%u svc_done=%u",
            name, n, load_traps, store_traps, branch_traps, xload_traps, xpair_traps,
            window_unknown, window_value, window_value_ok, clrex_bad, clrex_done,
            svc_bad, svc_done);
        REQUIRE(load_traps == want_window && store_traps == want_window &&
                branch_traps == want_window && xload_traps == want_window &&
                xpair_traps == want_window &&
                !window_unknown && window_value == 4U * n && window_value_ok == window_value &&
                !clrex_bad && clrex_done == n && !svc_bad && svc_done == n,
                "v220 window %s load=%u store=%u branch=%u xload=%u xpair=%u unknown=%u "
                "value=%u/%u clrex=%u/%u svc=%u/%u", name, load_traps, store_traps, branch_traps,
                xload_traps, xpair_traps, window_unknown, window_value_ok, window_value, clrex_bad,
                clrex_done, svc_bad, svc_done);

        unsigned want_old_ap = ap && !g_read_defense_221 && !g_read_defense_222 ? n : 0U;
        unsigned want_residual = ap && g_read_defense_221_guarded && !g_read_defense_222 ? n : 0U;
        unsigned want_ap_v222 = ap && g_read_defense_222 && !g_read_defense_223 ? n : 0U;
        unsigned want_evidence = g_read_defense_223 ?
                                 (!ap ? (mode ? n : 0U) :
                                  (mode && !original && !all_callers ? n : 0U)) :
                                 g_read_defense_221 && !g_read_defense_221_guarded && ap ?
                                 policy.split : (mode ? n : 0U);
        unsigned want_changed = !mode && !original ? n : 0U;
        unsigned want_split = mode && !original && !(ap && all_callers) ? n : 0U;
        unsigned paired_trials = 2U * UD_OBSERVE_EPOCHS * UD_OBSERVE_TRIALS;
        LOG("READ_DEFENSE_%s_POLICY stage=%s n=%u pre_alu=%u fp=%u ap=%u ap_unknown=%u "
            "triplets=%u target_failed=%u control_failed=%u split=%u evidence=%u changed=%u "
            "unknown=%u accepted=%u mean_ns=%llu max_ns=%llu baseline_ok=%u pre_gpr=%u simd=%u "
            "simd_value=%u",
            read_defense_version_tag(),
            name, n, policy.pre_alu, policy.fp, policy.ap, policy.ap_unknown,
            policy.triplets, policy.target_failed, policy.control_failed, policy.split,
            policy.decision.evidence, policy.decision.changed, policy.decision.unknown,
            policy.decision.accepted,
            (unsigned long long)(policy.elapsed_ns / n), (unsigned long long)policy.max_ns,
            policy.baseline_ok, policy.pre_gpr, policy.simd, policy.simd_value);
        REQUIRE(policy.pre_alu == want_old_ap && policy.fp == want_old_ap &&
                policy.ap == want_old_ap + want_residual + want_ap_v222 &&
                policy.pre_gpr == want_residual &&
                policy.simd == want_residual &&
                policy.simd_value == (g_read_defense_222 ? n : 0U) &&
                policy.baseline_ok == (g_read_defense_221_guarded ? n : 0U) &&
                !policy.ap_unknown && policy.triplets == n * paired_trials &&
                policy.target_failed == want_old_ap * paired_trials && policy.split == want_split &&
                policy.decision.evidence == want_evidence &&
                policy.decision.changed == want_changed && !policy.decision.unknown,
                "window policy %s pre_alu=%u fp=%u baseline=%u pre_gpr=%u simd=%u ap=%u "
                "split=%u unknown=%u evidence=%u changed=%u",
                name, policy.pre_alu, policy.fp, policy.baseline_ok, policy.pre_gpr, policy.simd,
                policy.ap, policy.split, policy.decision.unknown, policy.decision.evidence,
                policy.decision.changed);
        if (g_read_defense_222) {
            LOG("READ_DEFENSE_%s_RESIDUAL stage=%s n=%u leaf_call=%u permute=%u "
                "fp_arith=%u pre_mov=%u pre_long=%u self_bad=%u neon_bad=%u self_done=%u neon_done=%u "
                "deep_bad=%u deep_done=%u self_err=%d neon_err=%d trials=%u target_failed=%u "
                "control_failed=%u mean_ns=%llu",
                read_defense_version_tag(),
                name, n, policy.leaf_call, policy.permute, policy.fp_arith,
                policy.pre_mov, policy.pre_long, policy.self_bad, policy.neon_bad,
                policy.self_done, policy.neon_done, policy.deep_bad, policy.deep_done,
                policy.self_err, policy.neon_err,
                policy.residual_trials,
                policy.residual_failed, policy.residual_control_failed,
                (unsigned long long)(policy.residual_ns / n));
            REQUIRE(policy.leaf_call == want_ap_v222 && policy.permute == want_ap_v222 &&
                    (!g_read_defense_223 ||
                     (policy.fp_arith == 0 && policy.pre_mov == 0 && policy.pre_long == 0 &&
                      (!g_read_defense_224 ||
                       (policy.deep_bad == 0 && policy.deep_done == (ap ? n : 0U) &&
                        (!ap || (policy.self_bad == 0 && policy.neon_bad == 0)))))) &&
                    policy.residual_trials == n * paired_trials &&
                    policy.residual_failed == (g_read_defense_223 ? 0U : want_ap_v222) * paired_trials,
                    "v222 residual %s leaf_call=%u permute=%u fp_arith=%u trials=%u target_failed=%u",
                    name, policy.leaf_call, policy.permute, policy.fp_arith,
                    policy.residual_trials, policy.residual_failed);
        }
    }
    if (g_read_defense_223) {
        const struct read_defense_decisions *decision = &boundary.decision;
        unsigned trials = UD_OBSERVE_EPOCHS * UD_OBSERVE_TRIALS;
        unsigned want_boundary_evidence = g_read_defense_224 ?
            (!ap ? (mode ? n : 0U) :
             (mode && !original && !all_callers ? n : 0U)) : (mode ? n : 0U);

        LOG("READ_DEFENSE_%s_BOUNDARY stage=%s n=%u ap=%u ap_unknown=%u evidence=%u "
            "changed=%u unknown=%u accepted=%u triplets=%u target_failed=%u control_failed=%u "
            "mean_ns=%llu max_ns=%llu",
            read_defense_version_tag(),
            name, n, boundary.ap, boundary.ap_unknown, decision->evidence, decision->changed,
            decision->unknown, decision->accepted, boundary.triplets, boundary.target_failed,
            boundary.control_failed, (unsigned long long)(boundary.elapsed_ns / n),
            (unsigned long long)boundary.max_ns);
        if (g_read_defense_224) {
            /* 2.24.0 completes the read-back that overwrites the LDXR
             * destination and never fabricates an STXR success after a store
             * that cleared the reservation.  The boundary probe must be silent
             * in every AP mode; only the independent reader split and the
             * BRK/UXN site evidence still classify a takeover. */
            unsigned want_accepted = ((original && (!mode || ap)) ||
                (ap && all_callers && mode && !strcmp(name, "overlay"))) ? n : 0U;

            REQUIRE(boundary.ap == 0 && !boundary.ap_unknown &&
                    boundary.triplets == n * trials && boundary.target_failed == 0 &&
                    decision->evidence == want_boundary_evidence && !decision->unknown &&
                    decision->changed == (!mode && !original ? n : 0U) &&
                    decision->accepted == want_accepted,
                    "v224 boundary %s ap=%u/%u evidence=%u unknown=%u changed=%u accepted=%u",
                    name, boundary.ap, n, decision->evidence, decision->unknown,
                    decision->changed, decision->accepted);
        } else {
            REQUIRE(boundary.ap == (ap ? n : 0U) && !boundary.ap_unknown &&
                    boundary.triplets == n * trials && boundary.target_failed == (ap ? n * trials : 0U) &&
                    decision->evidence == (mode ? n : 0U) && !decision->unknown &&
                    decision->changed == (!mode && !original ? n : 0U) &&
                    decision->accepted == (!mode && original ? n : 0U),
                    "v223 boundary %s ap=%u/%u evidence=%u unknown=%u changed=%u accepted=%u",
                    name, boundary.ap, n, decision->evidence, decision->unknown,
                    decision->changed, decision->accepted);
        }
    }
    /* The unprivileged LDTRB form is outside the ordinary decoder set; 2.22.0
     * completes it through the equivalent LDUR encoding.  Run it on the live
     * overlay page so a fail-closed SIGSEGV shows up as a crash rather than a
     * silent value difference. */
    if (g_read_defense_222 && ap && all_callers && !strcmp(name, "overlay")) {
        uint8_t byte = read_defense_ldtrb(text + 1);

        REQUIRE(byte == file[1], "v222 ldtrb byte=%02x want=%02x", byte, file[1]);
        LOG("READ_DEFENSE_V222_LDTR byte=%02x want=%02x", byte, file[1]);
    }
}

/* Equal lengths and flags=0 keep the same VMA. Older range gates and
 * 2.16.0's BRK/UXN modes release an overlapping session. */
static void read_defense_same_remap(const char *name, const uint8_t *page, size_t page_size)
{
    struct ud_mapping before, after;
    int error = ud_mapping_at("/proc/self/smaps", page, &before);
    bool valid = !error && (uintptr_t)page % page_size == 0 && before.readable &&
                 before.executable && !before.writable && before.end - (uintptr_t)page >= page_size;
    REQUIRE(valid, "read-defense remap %s invalid RX page", name);
    if (!valid) return;
    uint64_t start = now_ns();
    void *result = mremap((void *)page, page_size, page_size, 0);
    uint64_t elapsed = now_ns() - start;
    int remap_error = result == MAP_FAILED ? errno : result == page ? 0 : EPROTO;
    bool preserved = !ud_mapping_at("/proc/self/smaps", page, &after) &&
                     dobby_same_vma(&before, &after);
    REQUIRE(!remap_error && preserved, "read-defense remap %s errno=%d vma=%d",
            name, remap_error, preserved);
    LOG("READ_DEFENSE_REMAP stage=%s errno=%d vma_preserved=%d ns=%llu", name, remap_error,
        preserved, (unsigned long long)elapsed);
}

/* A dedicated anonymous RX mapping has no vm_file, so REGISTER rejects it.
 * Use the position-independent test payload; never move existing ELF text. */
static void read_defense_anonymous_guard(const struct uy_ctx *ctx, const uint8_t *file,
                                         size_t page_size, unsigned mode, bool all_callers)
{
    uint8_t *alias = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(alias != MAP_FAILED, "read-defense anonymous alias mmap errno=%d", errno);
    if (alias == MAP_FAILED) return;
    memcpy(alias, file, DOBBY_CRC_BYTES);
    __builtin___clear_cache((char *)alias, (char *)alias + DOBBY_CRC_BYTES);
    int protect_error = mprotect(alias, page_size, PROT_READ | PROT_EXEC) ? errno : 0;
    REQUIRE(!protect_error, "read-defense anonymous RX errno=%d", protect_error);
    if (!protect_error) {
        struct ud_mapping map;
        struct urov_y_request status;
        bool shape = !ud_mapping_at("/proc/self/maps", alias, &map) && !map.inode && !map.shared &&
                     map.readable && map.executable && !map.writable;
        int error = shape ? read_defense_arm(ctx, alias, file, mode, all_callers) : EPROTO;
        uint32_t executed = crc_execute(alias);
        bool inactive = !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;
        REQUIRE(shape && error == EINVAL && executed == DOBBY_ORIGINAL && inactive &&
                !memcmp(alias, file, DOBBY_CRC_BYTES),
                "read-defense anonymous guard shape=%d errno=%d execute=%04x inactive=%d",
                shape, error, executed, inactive);
        LOG("READ_DEFENSE_GUARD shape=%d errno=%d execute=%04x inactive=%d", shape, error, executed, inactive);
    }
    REQUIRE(!munmap(alias, page_size), "read-defense anonymous alias cleanup");
}

/* No W-to-X transition and no change to an existing business mapping.
 * A fresh executable VMA without VM_READ cannot be a UROV-Y target.
 * The existing PROT_READ reference remains available for file verification. */
/* With no fixture context, check the independent read/execute path while the
 * original text is still overlaid. With a context, challenge registration. */
static void read_defense_exec_guard(const struct uy_ctx *ctx, const struct page *reference,
                                    const uint8_t *file, size_t page_size, unsigned mode,
                                    bool all_callers)
{
    uint8_t *alias = mmap(NULL, page_size, PROT_EXEC, MAP_PRIVATE,
                          reference->fd, reference->file_offset);
    REQUIRE(alias != MAP_FAILED, "v218 execute-only guard mmap errno=%d", errno);
    if (alias == MAP_FAILED) return;
    struct ud_mapping map;
    bool shape = !ud_mapping_at("/proc/self/maps", alias, &map) &&
                 map.executable && !map.readable && !map.writable;
    REQUIRE(shape, "v218 execute-only guard mapping shape");
    if (shape && ctx) {
        int error = read_defense_arm(ctx, alias, file, mode, all_callers);
        if (!error) REQUIRE(!uy_deactivate(ctx), "v218 execute-only guard cleanup");
        struct urov_y_request status;
        bool inactive = !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;
        bool bytes = !memcmp(reference->address + reference->entry, file, DOBBY_CRC_BYTES);
        uint32_t executed = bytes ? crc_execute(alias + reference->entry) : 0;
        REQUIRE(error == EINVAL && inactive && bytes && executed == DOBBY_ORIGINAL,
                "v218 execute-only guard errno=%d", error);
        LOG("READ_DEFENSE_%s_GUARD shape=%d errno=%d inactive=%d reference=%d execute=%04x",
            read_defense_version_tag(),
            shape, error, inactive, bytes, executed);
    } else if (shape) {
        uint8_t from_fd[DOBBY_CRC_BYTES];
        bool intact = !app_pread(reference->fd, reference->file_offset + reference->entry,
                                 from_fd, sizeof(from_fd)) &&
                      !memcmp(from_fd, file, sizeof(from_fd)) &&
                      !memcmp(reference->address + reference->entry, from_fd, sizeof(from_fd));
        uint32_t executed = intact ? crc_execute(alias + reference->entry) : 0;
        REQUIRE(intact && executed == DOBBY_ORIGINAL, "v220 independent reference or code changed");
        LOG("READ_DEFENSE_%s_FALLBACK shape=%d reference=%d execute=%04x",
        read_defense_version_tag(), shape, intact, executed);
    }
    REQUIRE(!munmap(alias, page_size), "v218 execute-only guard unmap errno=%d", errno);
}

static void read_defense_reference_guard(const struct uy_ctx *ctx, const struct page *reference,
                                         const uint8_t *file, const uint8_t *different,
                                         unsigned mode, bool all_callers)
{
    struct ud_mapping map;
    struct urov_y_request status;
    bool shape = !ud_mapping_at("/proc/self/maps", reference->address, &map) &&
                 map.readable && !map.writable && !map.executable;
    int error = shape ? read_defense_arm(ctx, reference->address, different, mode, all_callers) :
                        EPROTO;
    if (!error) REQUIRE(!uy_deactivate(ctx), "v219 read-only reference cleanup");
    bool inactive = !uy_status(ctx, &status) && status.state == UROV_Y_INACTIVE;
    bool intact = !memcmp(reference->address + reference->entry, file, DOBBY_CRC_BYTES);
    REQUIRE(shape && error == EINVAL && inactive && intact, "v219 reference guard errno=%d", error);
    LOG("READ_DEFENSE_KEYLESS_GUARD shape=%d errno=%d inactive=%d intact=%d",
        shape, error, inactive, intact);
}

static void read_defense_fixture(const char *name, const char *key, int repeats)
{
    unsigned mode = 0;
    const char *shape = name + sizeof("read-defense-") - 1;
    bool v216 = !strncmp(shape, "v216-", sizeof("v216-") - 1);
    bool v218 = !strncmp(shape, "v218-", sizeof("v218-") - 1);
    bool v219 = !strncmp(shape, "v219-", sizeof("v219-") - 1);
    bool v220 = !strncmp(shape, "v220-", sizeof("v220-") - 1);
    bool v221 = !strncmp(shape, "v221-", sizeof("v221-") - 1);
    bool v222 = !strncmp(shape, "v222-", sizeof("v222-") - 1);
    bool v223 = !strncmp(shape, "v223-", sizeof("v223-") - 1);
    bool v224 = !strncmp(shape, "v224-", sizeof("v224-") - 1);
    bool modern = v216 || v218 || v219 || v220 || v221 || v222 || v223 || v224;
    if (modern) shape += sizeof("v216-") - 1;
    g_read_defense_fixed = v219 || v220 || v221 || v222 || v223 || v224;
    g_read_defense_window = v220 || v221 || v222 || v223 || v224;
    g_read_defense_221 = v221;
    g_read_defense_221_guarded = (v221 &&
        !strncmp(shape, "guarded-", sizeof("guarded-") - 1)) || v222 || v223 || v224;
    g_read_defense_222 = v222 || v223 || v224;
    g_read_defense_223 = v223 || v224;
    g_read_defense_224 = v224;
    if (v221 && !strncmp(shape, "guarded-", sizeof("guarded-") - 1))
        shape += sizeof("guarded-") - 1;
    void (*stage)(const char *, const uint8_t *, const struct page *, const uint8_t *,
                  const uint8_t *, unsigned, bool, int) =
        (v218 || v219 || v220 || v221 || v222 || v223 || v224) ?
        read_defense_v218_stage : read_defense_v216_stage;
    bool hardened = strstr(shape, "-hard") != NULL;
    bool ap_all = !strcmp(shape, "ap-all") || !strcmp(shape, "ap-all-hard");
    bool brk_all = (v218 || v219 || v220 || v221 || v222 || v223 || v224) &&
                   !strcmp(shape, "brk-all");
    bool uxn_all = (v218 || v219 || v220 || v221 || v222 || v223 || v224) &&
                   !strcmp(shape, "uxn-all");
    bool all_callers = ap_all || brk_all || uxn_all;
    if (ap_all || !strcmp(shape, "ap") || !strcmp(shape, "ap-hard")) mode = UROV_Y_MODE_PAGE_AP;
    else if (brk_all || !strcmp(shape, "brk")) mode = UROV_Y_MODE_SITE_BRK;
    else if (uxn_all || !strcmp(shape, "uxn")) mode = UROV_Y_MODE_PAGE_UXN;
    else if (strcmp(shape, "clean")) {
        REQUIRE(0, "unknown read-defense mode");
        return;
    }

    const uint8_t *text = (const uint8_t *)(uintptr_t)&dobby_crc_payload;
    const long page_size = sysconf(_SC_PAGESIZE);
    uint8_t file[DOBBY_CRC_BYTES], patched[DOBBY_CRC_BYTES];
    struct page reference;
    struct uy_ctx ctx;
    struct urov_y_request status;
    struct business business = { .fn = ud_payload };
    pthread_t thread;
    bool have_thread = false, may_have_session = false;

    pthread_mutex_lock(&dobby_crc_lock);
    int reference_prot = modern ? PROT_READ : PROT_READ | PROT_EXEC;
    if (dobby_setup_error >= 0 || page_size != UROV_Y_PAGE ||
        page_open_at_prot(&reference, MAP_PRIVATE, text, reference_prot)) {
        REQUIRE(0, "read-defense needs a fresh 4 KiB fixture with a file reference");
        goto out;
    }
    const uint8_t *control = reference.address + reference.entry;
    int error = app_pread(reference.fd, reference.file_offset + reference.entry, file, sizeof(file));
    REQUIRE(!error, "read-defense file read errno=%d", error);
    if (error) goto close_reference;
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "read-defense business thread");
    if (modern) stage("clean", text, &reference, file, file, 0, false, repeats);
    else read_defense_stage("clean", text, control, file, file, false, false, DOBBY_ORIGINAL,
                            repeats, hardened);
    if (mode) {
        error = uy_init_key(&ctx, key);
        REQUIRE(!error, "read-defense fixture key invalid");
        if (error) goto close_reference;
    }
    if (modern && mode) {
        error = read_defense_arm(&ctx, text, file, mode, all_callers);
        may_have_session = error != EBUSY;
        REQUIRE(!error, "read-defense identity register mode=%u errno=%d", mode, error);
        if (error) goto close_reference;
        stage("identity", text, &reference, file, file, mode, all_callers, repeats);
        error = uy_deactivate(&ctx);
        REQUIRE(!error, "read-defense identity deactivate errno=%d", error ? errno : 0);
        if (error) goto close_reference;
    }
    dobby_setup_error = dobby_crc_setup((void *)text, (size_t)page_size);
    REQUIRE(!dobby_setup_error, "read-defense Dobby setup errno=%d", dobby_setup_error);
    if (dobby_setup_error) goto close_reference;
    copy_scalar(patched, text, sizeof(patched));
    if (modern) stage("patch_only", text, &reference, file, patched, 0, false, repeats);
    else {
        read_defense_same_remap("unarmed", text, (size_t)page_size);
        read_defense_stage("patch_only", text, control, file, patched, false, false, DOBBY_HOOKED,
                           repeats, hardened);
    }
    if (!mode) goto close_reference;

    error = read_defense_arm(&ctx, text, dobby_file_page, mode, all_callers || hardened);
    may_have_session = error != EBUSY;
    REQUIRE(!error, "read-defense register mode=%u errno=%d", mode, error);
    if (error) goto close_reference;
    if (modern) {
        stage("overlay", text, &reference, file, patched, mode, all_callers, repeats);
        if (v220 || v221 || v222 || v223 || v224)
            read_defense_exec_guard(NULL, &reference, file, (size_t)page_size, mode, all_callers);
        bool still_active = !uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && !status.failures;
        REQUIRE(still_active, "read-defense parent session was changed by the probes");
        LOG("READ_DEFENSE_%s_STATUS parent_active=%d callers=%u",
            read_defense_version_tag(),
            still_active, all_callers ? 0U : 1U);
        REQUIRE(!uy_deactivate(&ctx), "read-defense deactivate errno=%d", errno);
        stage("deactivated", text, &reference, file, patched, 0, false, repeats);
        read_defense_anonymous_guard(&ctx, file, (size_t)page_size, mode, all_callers);
        if (v218 || v219 || v220 || v221 || v222 || v223 || v224)
            read_defense_exec_guard(&ctx, &reference, file, (size_t)page_size, mode, all_callers);
        if (v219 || v220 || v221 || v222 || v223 || v224)
            read_defense_reference_guard(&ctx, &reference, file, patched, mode, all_callers);
        goto close_reference;
    }
    read_defense_same_remap("outside", reference.address, (size_t)page_size);
    read_defense_stage("overlay", text, control, file,
                       hardened && mode == UROV_Y_MODE_PAGE_AP ? file : patched, true,
                       mode == UROV_Y_MODE_PAGE_AP, DOBBY_HOOKED, repeats, hardened);
    bool active = !uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && !status.failures;
    read_defense_same_remap("overlap", text, (size_t)page_size);
    bool inactive;
    if (hardened && mode == UROV_Y_MODE_PAGE_AP) {
        bool remap_active = !uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE &&
                            !status.failures;
        REQUIRE(active && remap_active, "read-defense remap active=%d after=%d", active,
                remap_active);
        LOG("READ_DEFENSE_STATUS active_before=%d active_after_remap=%d", active,
            remap_active);
        read_defense_stage("restored", text, control, file, file, true, true,
                           DOBBY_HOOKED, repeats, true);
        REQUIRE(!uy_deactivate(&ctx), "read-defense deactivate errno=%d", errno);
        inactive = !uy_status(&ctx, &status) && status.state == UROV_Y_INACTIVE;
        REQUIRE(inactive, "read-defense deactivate left session");
    } else {
        inactive = !uy_status(&ctx, &status) && status.state == UROV_Y_INACTIVE;
        REQUIRE(active && inactive, "read-defense recovery active=%d inactive=%d", active, inactive);
        LOG("READ_DEFENSE_STATUS active_before=%d inactive_after=%d", active, inactive);
        read_defense_stage("restored", text, control, file, patched, false, false,
                           DOBBY_HOOKED, repeats, false);
    }
    if (inactive) read_defense_anonymous_guard(&ctx, file, (size_t)page_size, mode, all_callers);

close_reference:
    if (may_have_session && !uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE)
        REQUIRE(!uy_deactivate(&ctx), "read-defense cleanup errno=%d", errno);
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.ops) > 0 && !atomic_load(&business.errors), "read-defense business errors");
        LOG("READ_DEFENSE_BUSINESS ops=%llu errors=%d",
            (unsigned long long)atomic_load(&business.ops), atomic_load(&business.errors));
    }
    page_close(&reference);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}
