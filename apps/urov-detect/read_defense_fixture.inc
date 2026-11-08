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
        raw_ok += !memcmp(views.live_bytes, expected_live, DOBBY_CRC_BYTES);
        returned = dobby_crc_payload();
        REQUIRE(returned == (original ? DOBBY_ORIGINAL : DOBBY_HOOKED),
                "v216 %s execute=%04x", name, returned);
    }
    bool preserved = !map_error && !ud_mapping_at("/proc/self/maps", text, &after) &&
                     dobby_same_vma(&before, &after);
    unsigned n = (unsigned)repeats;
    REQUIRE(alu.reservation_loss == (ap ? UD_MATCH : UD_NO_MATCH),
            "v216 %s ALU verdict=%d errno=%d", name, alu.reservation_loss, alu.error);
    REQUIRE(!unknown && split == (mode && !original ? n : 0U) &&
            post == (mode ? n : 0U) && post_ok == post && raw_ok == n && preserved &&
            old_accept == (mode || original ? n : 0U) && guarded_accept == (original ? n : 0U),
            "v216 %s split=%u post=%u post_ok=%u unknown=%u read_errno=%d raw_ok=%u",
            name, split, post, post_ok, unknown, read_error, raw_ok);
    LOG("READ_DEFENSE_V216 stage=%s n=%u split=%u post=%u post_ok=%u unknown=%u read_errno=%d "
        "old_accept=%u guarded_accept=%u raw_ok=%u alu=%d alu_failed=%u alu_accepted=%u "
        "alu_errno=%d vma_preserved=%d execute=%04x read_mean_ns=%llu alu_ns=%llu",
        name, n, split, post, post_ok, unknown, read_error, old_accept, guarded_accept, raw_ok,
        alu.reservation_loss, alu.target_failed, alu.accepted, alu.error, preserved, returned,
        (unsigned long long)(read_ns / n), (unsigned long long)alu.elapsed_ns);
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

static void read_defense_fixture(const char *name, const char *key, int repeats)
{
    unsigned mode = 0;
    const char *shape = name + sizeof("read-defense-") - 1;
    bool v216 = !strncmp(shape, "v216-", sizeof("v216-") - 1);
    if (v216) shape += sizeof("v216-") - 1;
    bool hardened = strstr(shape, "-hard") != NULL;
    bool all_callers = !strcmp(shape, "ap-all") || !strcmp(shape, "ap-all-hard");
    if (all_callers || !strcmp(shape, "ap") || !strcmp(shape, "ap-hard")) mode = UROV_Y_MODE_PAGE_AP;
    else if (!strcmp(shape, "brk")) mode = UROV_Y_MODE_SITE_BRK;
    else if (!strcmp(shape, "uxn")) mode = UROV_Y_MODE_PAGE_UXN;
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
    if (dobby_setup_error >= 0 || page_size != UROV_Y_PAGE || page_open_at(&reference, MAP_PRIVATE, text)) {
        REQUIRE(0, "read-defense needs a fresh 4 KiB fixture with a file reference");
        goto out;
    }
    const uint8_t *control = reference.address + reference.entry;
    int error = app_pread(reference.fd, reference.file_offset + reference.entry, file, sizeof(file));
    REQUIRE(!error, "read-defense file read errno=%d", error);
    if (error) goto close_reference;
    if (v216 && mprotect(reference.address, (size_t)page_size, PROT_READ)) {
        REQUIRE(0, "v216 read-only control errno=%d", errno);
        goto close_reference;
    }

    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "read-defense business thread");
    if (v216) read_defense_v216_stage("clean", text, &reference, file, file, 0, false, repeats);
    else read_defense_stage("clean", text, control, file, file, false, false, DOBBY_ORIGINAL,
                            repeats, hardened);
    if (mode) {
        error = uy_init_key(&ctx, key);
        REQUIRE(!error, "read-defense fixture key invalid");
        if (error) goto close_reference;
    }
    if (v216 && mode) {
        error = read_defense_arm(&ctx, text, file, mode, all_callers);
        may_have_session = error != EBUSY;
        REQUIRE(!error, "v216 identity register mode=%u errno=%d", mode, error);
        if (error) goto close_reference;
        read_defense_v216_stage("identity", text, &reference, file, file, mode, all_callers, repeats);
        error = uy_deactivate(&ctx);
        REQUIRE(!error, "v216 identity deactivate errno=%d", error ? errno : 0);
        if (error) goto close_reference;
    }
    dobby_setup_error = dobby_crc_setup((void *)text, (size_t)page_size);
    REQUIRE(!dobby_setup_error, "read-defense Dobby setup errno=%d", dobby_setup_error);
    if (dobby_setup_error) goto close_reference;
    copy_scalar(patched, text, sizeof(patched));
    if (v216) read_defense_v216_stage("patch_only", text, &reference, file, patched, 0, false, repeats);
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
    if (v216) {
        read_defense_v216_stage("overlay", text, &reference, file, patched, mode, all_callers, repeats);
        bool still_active = !uy_status(&ctx, &status) && status.state == UROV_Y_ACTIVE && !status.failures;
        REQUIRE(still_active, "v216 parent session was changed by the probes");
        LOG("READ_DEFENSE_V216_STATUS parent_active=%d callers=%u", still_active, all_callers ? 0U : 1U);
        REQUIRE(!uy_deactivate(&ctx), "v216 deactivate errno=%d", errno);
        read_defense_v216_stage("deactivated", text, &reference, file, patched, 0, false, repeats);
        read_defense_anonymous_guard(&ctx, file, (size_t)page_size, mode, all_callers);
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
