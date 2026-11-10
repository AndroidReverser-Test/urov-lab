/* SPDX-License-Identifier: GPL-2.0-or-later */

enum keyless225_verdict { KEYLESS_CLEAR, KEYLESS_TRAP, KEYLESS_CHANGED, KEYLESS_UNKNOWN };
enum keyless_probe_set { KEYLESS_PRE_WINDOW, KEYLESS_AUDIT_226, KEYLESS_ENTRY_227 };

static enum keyless225_verdict keyless225_policy(enum ud_verdict ap, enum ud_verdict brk,
                                               enum ud_verdict fetch, enum ud_verdict split,
                                               enum ud_verdict file_diff)
{
    if (ap == UD_MATCH || brk == UD_MATCH || fetch == UD_MATCH || split == UD_MATCH)
        return KEYLESS_TRAP;
    if (ap == UD_UNKNOWN || brk == UD_UNKNOWN || fetch == UD_UNKNOWN ||
        split == UD_UNKNOWN || file_diff == UD_UNKNOWN)
        return KEYLESS_UNKNOWN;
    return file_diff == UD_MATCH ? KEYLESS_CHANGED : KEYLESS_CLEAR;
}

static enum ud_verdict keyless226_ap_evidence(enum ud_verdict add, enum ud_verdict mask,
                                              enum ud_verdict phantom)
{
    if (phantom == UD_MATCH || (mask == UD_MATCH && add == UD_NO_MATCH)) return UD_MATCH;
    if (add == UD_NO_MATCH && mask == UD_NO_MATCH && phantom == UD_NO_MATCH) return UD_NO_MATCH;
    return UD_UNKNOWN;
}

static void keyless226_regression(const char *name, const uint8_t *text, const struct page *ref)
{
    /* The long shape scans thousands of instructions inside the module, so
     * sample each of these historical regression shapes only once per stage. */
    unsigned v226_match[6] = {0}, v226_unknown = 0;
    int v226_err[6] = {0};
    for (unsigned v = 0; v < ud_observe_ap_v226_count() && v < 6; ++v) {
        struct ud_exclusive_observation pre;

        for (unsigned j = 0; j < 3; ++j) {
            ud_observe_ap_v226(text, ref->address + ref->entry, ref->fd,
                               ref->file_offset + ref->entry, v, &pre);
            if (pre.error != EAGAIN && pre.error != ESTALE) break;
        }
        if (pre.reservation_loss == UD_MATCH) ++v226_match[v];
        else if (pre.reservation_loss == UD_UNKNOWN || pre.error) {
            ++v226_unknown;
            v226_err[v] = pre.error;
        }
    }
    LOG("KEYLESS226_EXTRA stage=%s chain=%u adr=%u mrs=%u zva=%u cvac=%u long=%u unknown=%u "
        "e0=%d e1=%d e2=%d e3=%d e4=%d e5=%d",
        name, v226_match[0], v226_match[1], v226_match[2], v226_match[3], v226_match[4],
        v226_match[5], v226_unknown, v226_err[0], v226_err[1], v226_err[2], v226_err[3],
        v226_err[4], v226_err[5]);
}

/* Observations and fallback: no fixture mode, key, module command, kernel
 * assisted live read, mapping edit or global signal handler. */
static void keyless225_stage(const char *name, const uint8_t *text, const struct page *ref,
                            const uint8_t *exec_alias, const uint8_t *file, unsigned repeats,
                            enum keyless_probe_set probes)
{
    bool entry_limit = probes == KEYLESS_ENTRY_227;
    unsigned verdicts[KEYLESS_UNKNOWN + 1] = {0}, ap_matches = 0, ap_unknown = 0, splits = 0;
    unsigned triplets = 0, failed = 0, control_failed = 0, retries = 0;
    unsigned mask_matches = 0, mask_unknown = 0, mask_triplets = 0, mask_failed = 0;
    unsigned phantom_matches = 0, phantom_unknown = 0, phantom_trials = 0, phantom_writes = 0;
    unsigned entry_matches = 0, entry_unknown = 0, entry_trials = 0, entry_writes = 0;
    uint64_t total_ns = 0, max_ns = 0;
    enum ud_verdict site_code, site_fetch;
    const uint8_t *reference = ref->address + ref->entry;
    off_t offset = ref->file_offset + ref->entry;
    uint8_t disk[DOBBY_CRC_BYTES], direct[DOBBY_CRC_BYTES], business[DOBBY_CRC_BYTES];

    ++g_cases;
    read_defense_observe_sites(&site_code, &site_fetch);
    enum ud_verdict site_brk = site_code;
    if (site_code == UD_MATCH) {
        uint32_t opcode;
        copy_scalar((uint8_t *)&opcode, (const uint8_t *)(uintptr_t)&uy_site_ldrb, sizeof(opcode));
        /* A legitimate non-BRK change to the reader invalidates its CRC
         * evidence, but isn't itself evidence of a read trap. */
        site_brk = (opcode & UINT32_C(0xffe0001f)) == UINT32_C(0xd4200000) ?
                   UD_MATCH : UD_NO_MATCH;
    }
    for (unsigned i = 0; i < repeats; ++i) {
        struct ud_views views;
        uint64_t begin = now_ns();
        enum ud_verdict split = ud_check_reader_views(text, sizeof(direct), ref->fd, offset,
                                                      crc_copy_window, &views);
        enum ud_verdict ap_evidence = UD_UNKNOWN;
        if (!entry_limit) {
            struct ud_exclusive_observation ap;
            ud_observe_ap_base_write(text, reference, ref->fd, offset, &ap);
            for (unsigned j = 0; j < 2 && ap.error == EAGAIN; ++j) {
                ++retries;
                ud_observe_ap_base_write(text, reference, ref->fd, offset, &ap);
            }
            ap_evidence = ap.reservation_loss;
            ap_matches += ap.reservation_loss == UD_MATCH;
            ap_unknown += ap.reservation_loss == UD_UNKNOWN;
            triplets += ap.accepted;
            failed += ap.target_failed;
            control_failed += ap.control_failed;
        }
        if (probes != KEYLESS_PRE_WINDOW) {
            struct ud_store_observation phantom;
            window_store_probe(ud_observe_ap_phantom_store, text, reference, ref, offset, &phantom);
            phantom_matches += phantom.verdict == UD_MATCH;
            phantom_unknown += phantom.verdict == UD_UNKNOWN;
            phantom_trials += phantom.completed;
            phantom_writes += phantom.unexpected_stores;
            if (entry_limit) {
                struct ud_store_observation padded;
                window_store_probe(ud_observe_ap_entry_limit, text, reference, ref, offset, &padded);
                /* This profile requires the short-window 2.27.0 control to
                 * agree with hardware before classifying a padded-window hit. */
                ap_evidence = phantom.verdict == UD_NO_MATCH ? padded.verdict : UD_UNKNOWN;
                entry_matches += ap_evidence == UD_MATCH;
                entry_unknown += ap_evidence == UD_UNKNOWN;
                entry_trials += padded.completed;
                entry_writes += padded.unexpected_stores;
            } else {
                struct ud_exclusive_observation mask;
                window_probe(ud_observe_ap_aligned_base, text, reference, ref, offset, &mask);
                ap_evidence = keyless226_ap_evidence(ap_evidence, mask.reservation_loss,
                                                     phantom.verdict);
                mask_matches += mask.reservation_loss == UD_MATCH;
                mask_unknown += mask.reservation_loss == UD_UNKNOWN;
                mask_triplets += mask.accepted;
                mask_failed += mask.target_failed;
            }
        }
        enum ud_verdict file_diff = views.file_diff;
        if (site_code == UD_MATCH && file_diff == UD_NO_MATCH) file_diff = UD_MATCH;
        ++verdicts[keyless225_policy(ap_evidence, site_brk, site_fetch, split, file_diff)];
        splits += split == UD_MATCH;
        uint64_t elapsed = now_ns() - begin;
        total_ns += elapsed;
        if (elapsed > max_ns) max_ns = elapsed;
    }

    /* The fallback checks release bytes through a retained fd and an r--
     * alias, and only executes the separately mapped, self-contained code. */
    bool reference_ok = !app_pread(ref->fd, offset, disk, sizeof(disk)) &&
                        !memcmp(disk, file, sizeof(disk)) && !memcmp(disk, reference, sizeof(disk));
    uint32_t fallback_execute = reference_ok ? crc_execute(exec_alias + ref->entry) : 0;
    REQUIRE(reference_ok && fallback_execute == DOBBY_ORIGINAL, "keyless225 fallback %s", name);

    if (entry_limit) {
        LOG("KEYLESS227_ENTRY stage=%s short_match=%u short_unknown=%u short_trials=%u short_writes=%u "
            "match=%u unknown=%u trials=%u writes=%u no_evidence=%u",
            name, phantom_matches, phantom_unknown, phantom_trials, phantom_writes,
            entry_matches, entry_unknown, entry_trials, entry_writes, verdicts[KEYLESS_CLEAR]);
    } else if (probes == KEYLESS_AUDIT_226) {
        LOG("KEYLESS226_AUDIT stage=%s mask=%u mask_unknown=%u mask_triplets=%u mask_failed=%u "
            "phantom=%u phantom_unknown=%u phantom_trials=%u phantom_writes=%u",
            name, mask_matches, mask_unknown, mask_triplets, mask_failed,
            phantom_matches, phantom_unknown, phantom_trials, phantom_writes);
    } else {
        keyless226_regression(name, text, ref);
    }

    /* The 2.27 detector treats live CRC as diagnostic only, including when
     * the sample has no evidence. Earlier profiles keep their legacy metric. */
    copy_scalar(direct, text, sizeof(direct));
    crc_copy_window(business, text, sizeof(business));
    LOG("KEYLESS225_STAGE stage=%s n=%u ap=%u ap_unknown=%u triplets=%u target_failed=%u "
        "control_failed=%u retries=%u site_code=%d site_brk=%d site_fetch=%d split=%u trap=%u changed=%u "
        "unknown=%u crc_eligible=%u file=%08x direct=%08x business=%08x "
        "execute=%04x reference_ok=%d fallback_execute=%04x mean_ns=%llu max_ns=%llu",
        name, repeats, ap_matches, ap_unknown, triplets, failed, control_failed, retries,
        site_code, site_brk, site_fetch, splits, verdicts[KEYLESS_TRAP], verdicts[KEYLESS_CHANGED],
        verdicts[KEYLESS_UNKNOWN], entry_limit ? 0 : verdicts[KEYLESS_CLEAR],
        (uint32_t)crc32(0, file, sizeof(disk)),
        (uint32_t)crc32(0, direct, sizeof(direct)), (uint32_t)crc32(0, business, sizeof(business)),
        crc_execute(text), reference_ok, fallback_execute, (unsigned long long)(total_ns / repeats),
        (unsigned long long)max_ns);
}

/* The rest of this file is fixture setup and ground truth only. */
static bool keyless225_arm(const struct uy_ctx *ctx, const uint8_t *text,
                          const uint8_t *image, unsigned mode, bool all_callers)
{
    int error = read_defense_arm(ctx, text, image, mode, all_callers);
    REQUIRE(!error, "keyless225 register mode=%u errno=%d", mode, error);
    return !error;
}

static bool keyless225_disarm(const struct uy_ctx *ctx, const char *stage,
                             const struct urov_y_request *before)
{
    struct urov_y_request status;
    bool active = !uy_status(ctx, &status) && status.state == UROV_Y_ACTIVE &&
                  !status.failures && status.hits > 0;
    bool stable = active && (!before || (status.session == before->session &&
                  status.generation == before->generation && status.mode == before->mode &&
                  status.page_count == before->page_count && status.site_count == before->site_count));
    int error = uy_deactivate(ctx);
    REQUIRE(stable && !error, "keyless225 %s active=%d stable=%d deactivate=%d",
            stage, active, stable, error);
    LOG("KEYLESS225_TRUTH stage=%s active=%d deactivated=%d", stage, active, !error);
    if (before) LOG("KEYLESS226_STABILITY stage=%s stable=%d", stage, stable);
    return stable && !error;
}

static void keyless225_fixture(const char *shape, const char *key, unsigned repeats,
                               enum keyless_probe_set probes)
{
    bool all_callers = !strcmp(shape, "ap-all") || !strcmp(shape, "brk-all") ||
                       !strcmp(shape, "uxn-all");
    unsigned mode = 0;
    if (!strcmp(shape, "ap") || !strcmp(shape, "ap-all")) mode = UROV_Y_MODE_PAGE_AP;
    else if (!strcmp(shape, "brk") || !strcmp(shape, "brk-all")) mode = UROV_Y_MODE_SITE_BRK;
    else if (!strcmp(shape, "uxn") || !strcmp(shape, "uxn-all")) mode = UROV_Y_MODE_PAGE_UXN;
    else if (strcmp(shape, "clean")) {
        REQUIRE(0, "unknown keyless225 mode");
        return;
    }

    const uint8_t *text = (const uint8_t *)(uintptr_t)&dobby_crc_payload;
    uint8_t file[DOBBY_CRC_BYTES], patched[DOBBY_CRC_BYTES];
    struct page reference;
    struct uy_ctx ctx;
    struct urov_y_request before, *truth = probes == KEYLESS_PRE_WINDOW ? NULL : &before;
    struct business business = { .fn = ud_payload };
    pthread_t thread;
    bool running = false, armed = false;
    const uint8_t *exec_alias = MAP_FAILED;

    pthread_mutex_lock(&dobby_crc_lock);
    if (dobby_setup_error >= 0 || sysconf(_SC_PAGESIZE) != UROV_Y_PAGE ||
        page_open_at_prot(&reference, MAP_PRIVATE, text, PROT_READ)) {
        REQUIRE(0, "keyless225 needs a fresh 4 KiB fixture with a file reference");
        goto out;
    }
    int error = app_pread(reference.fd, reference.file_offset + reference.entry,
                         file, sizeof(file));
    REQUIRE(!error, "keyless225 file read errno=%d", error);
    if (error) goto close_reference;
    exec_alias = mmap(NULL, UROV_Y_PAGE, PROT_EXEC, MAP_PRIVATE,
                      reference.fd, reference.file_offset);
    struct ud_mapping data_map, exec_map;
    bool shape_ok = exec_alias != MAP_FAILED &&
                    !ud_mapping_at("/proc/self/maps", reference.address, &data_map) &&
                    data_map.readable && !data_map.executable && !data_map.writable &&
                    !ud_mapping_at("/proc/self/maps", exec_alias, &exec_map) &&
                    exec_map.executable && !exec_map.readable && !exec_map.writable;
    REQUIRE(shape_ok, "keyless225 guard mappings");
    if (!shape_ok) goto close_reference;

    running = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(running, "keyless225 business worker");
    if (!running) goto close_reference;
    keyless225_stage("clean", text, &reference, exec_alias, file, repeats, probes);
    enum ud_verdict invalid_verdict;
    unsigned invalid_samples;
    if (probes == KEYLESS_ENTRY_227) {
        struct ud_store_observation bad;
        ud_observe_ap_entry_limit(text, reference.address + reference.entry, reference.fd,
                                  reference.file_offset + reference.entry + 1, &bad);
        invalid_verdict = bad.verdict;
        invalid_samples = bad.completed;
        error = bad.error;
    } else {
        struct ud_exclusive_observation bad;
        window_probe_fn probe = probes == KEYLESS_AUDIT_226 ?
                                ud_observe_ap_aligned_base : ud_observe_ap_base_write;
        probe(text, reference.address + reference.entry, reference.fd,
              reference.file_offset + reference.entry + 1, &bad);
        invalid_verdict = bad.reservation_loss;
        invalid_samples = bad.accepted;
        error = bad.error;
    }
    enum keyless225_verdict policy = keyless225_policy(invalid_verdict, UD_NO_MATCH,
                                                       UD_NO_MATCH, UD_NO_MATCH, UD_NO_MATCH);
    REQUIRE(policy == KEYLESS_UNKNOWN && error == ESTALE && !invalid_samples,
            "keyless225 bad reference was not inconclusive");
    LOG("KEYLESS225_INVALID unknown=%d crc_eligible=%d errno=%d triplets=%u",
        policy == KEYLESS_UNKNOWN, policy == KEYLESS_CLEAR, error, invalid_samples);
    if (probes == KEYLESS_AUDIT_226) {
        struct ud_store_observation invalid;
        ud_observe_ap_phantom_store(text, reference.address + reference.entry, reference.fd,
                                    reference.file_offset + reference.entry + 1, &invalid);
        REQUIRE(invalid.verdict == UD_UNKNOWN && invalid.error == ESTALE && !invalid.completed,
                "keyless226 audit bad reference was not inconclusive");
    }

    if (mode) {
        error = uy_init_key(&ctx, key);
        REQUIRE(!error, "keyless225 fixture key");
        if (error) goto close_reference;
        armed = keyless225_arm(&ctx, text, file, mode, all_callers);
        if (!armed) goto close_reference;
        if (truth && uy_status(&ctx, truth)) {
            REQUIRE(0, "keyless226 identity initial status");
            goto close_reference;
        }
        keyless225_stage("identity", text, &reference, exec_alias, file, repeats, probes);
        if (!keyless225_disarm(&ctx, "identity", truth)) goto close_reference;
        armed = false;
    }
    dobby_setup_error = dobby_crc_setup((void *)text, UROV_Y_PAGE);
    REQUIRE(!dobby_setup_error, "keyless225 Dobby patch errno=%d", dobby_setup_error);
    if (dobby_setup_error) goto close_reference;
    copy_scalar(patched, text, sizeof(patched));
    keyless225_stage("patch_only", text, &reference, exec_alias, file, repeats, probes);
    if (!mode) goto close_reference;

    armed = keyless225_arm(&ctx, text, file, mode, all_callers);
    if (!armed) goto close_reference;
    if (truth && uy_status(&ctx, truth)) {
        REQUIRE(0, "keyless226 overlay initial status");
        goto close_reference;
    }
    keyless225_stage("overlay", text, &reference, exec_alias, file, repeats, probes);
    if (!keyless225_disarm(&ctx, "overlay", truth)) goto close_reference;
    armed = false;
    keyless225_stage("deactivated", text, &reference, exec_alias, file, repeats, probes);

    /* Both guards are challenged with a different image while there is no
     * competing session, so EBUSY cannot explain registration refusal. */
    int data_error = read_defense_arm(&ctx, reference.address, patched, mode, all_callers);
    if (!data_error) REQUIRE(!uy_deactivate(&ctx), "keyless225 data guard cleanup");
    int exec_error = read_defense_arm(&ctx, exec_alias, patched, mode, all_callers);
    if (!exec_error) REQUIRE(!uy_deactivate(&ctx), "keyless225 exec guard cleanup");
    struct urov_y_request status;
    bool inactive = !uy_status(&ctx, &status) && status.state == UROV_Y_INACTIVE;
    bool intact = !memcmp(reference.address + reference.entry, file, sizeof(file));
    uint32_t execute = crc_execute(exec_alias + reference.entry);
    REQUIRE(data_error == EINVAL && exec_error == EINVAL && inactive && intact &&
            execute == DOBBY_ORIGINAL, "keyless225 guarded registration");
    LOG("KEYLESS225_GUARD read_errno=%d exec_errno=%d inactive=%d reference_ok=%d execute=%04x",
        data_error, exec_error, inactive, intact, execute);

close_reference:
    if (armed) (void)uy_deactivate(&ctx);
    if (running) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        unsigned long long ops = (unsigned long long)atomic_load(&business.ops);
        int errors = atomic_load(&business.errors);
        REQUIRE(ops > 0 && !errors, "keyless225 business worker");
        LOG("KEYLESS225_BUSINESS ops=%llu errors=%d", ops, errors);
    }
    if (exec_alias != MAP_FAILED) munmap((void *)exec_alias, UROV_Y_PAGE);
    page_close(&reference);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}
