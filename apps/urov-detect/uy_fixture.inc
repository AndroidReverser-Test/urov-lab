/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * urov-y fixture, included by app.c.  The detector core
 * (native/urov_observe.c + native/urov_detect.c) is used completely unchanged.
 * The fixture owns a normal one-page RX alias of its own library and registers
 * uy_site_ldr/uy_site_ldrb as reader sites plus uy_business_ldr/uy_business_ldrb
 * as the business call windows.
 *
 * Expected result against urov-y:
 *   - ud_observe_exclusive() on the target page: NO_MATCH (the page is an
 *     ordinary readable mapping, no data abort is ever taken);
 *   - ud_observe_reader() with the bare reader routine: NO_MATCH (a call from
 *     outside the business window is emulated from the original bytes);
 *   - the registered business call still returns the fake value.
 */

__asm__(".pushsection .text.uy_sites,\"ax\",%progbits\n"
        ".p2align 12\n"
        ".global uy_site_ldr\n.type uy_site_ldr,%function\n"
        "uy_site_ldr:\n ldr x0, [x0]\n ret\n"
        ".size uy_site_ldr, .-uy_site_ldr\n"
        ".global uy_site_ldrb\n.type uy_site_ldrb,%function\n"
        "uy_site_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size uy_site_ldrb, .-uy_site_ldrb\n"
        /* The page-trap mode makes exactly this page EL0 execute-never, so it
         * must contain nothing but the two reader stubs: pad it to the end and
         * keep the business wrappers in a different page. */
        ".p2align 12\n"
        ".popsection\n"
        ".pushsection .text,\"ax\",%progbits\n"
        ".global uy_business_ldr\n.type uy_business_ldr,%function\n"
        "uy_business_ldr:\n stp x29, x30, [sp, #-16]!\n mov x29, sp\n"
        " bl uy_site_ldr\n ldp x29, x30, [sp], #16\n ret\n"
        ".size uy_business_ldr, .-uy_business_ldr\n"
        ".global uy_business_ldr_end\nuy_business_ldr_end:\n"
        ".global uy_business_ldrb\n.type uy_business_ldrb,%function\n"
        "uy_business_ldrb:\n stp x29, x30, [sp, #-16]!\n mov x29, sp\n"
        " bl uy_site_ldrb\n ldp x29, x30, [sp], #16\n ret\n"
        ".size uy_business_ldrb, .-uy_business_ldrb\n"
        ".global uy_business_ldrb_end\nuy_business_ldrb_end:\n"
        ".popsection\n");

extern uint64_t uy_site_ldr(const void *p);
extern uint32_t uy_site_ldrb(const void *p);
extern uint64_t uy_business_ldr(const void *p);
extern uint32_t uy_business_ldrb(const void *p);
extern char uy_business_ldr_end[];
extern char uy_business_ldrb_end[];

struct uy_ctx {
    int have;
    struct urov_x_keys keys;
};

static int uy_init_key(struct uy_ctx *ctx, const char *hex)
{
    uint8_t key[16];
    unsigned len = hex ? (unsigned)strlen(hex) : 0U;
    memset(ctx, 0, sizeof(*ctx));
    if (urov_x_parse_key(hex, len, key)) return -1;
    urov_x_derive(key, &ctx->keys);
    memset(key, 0, sizeof(key));
    ctx->have = 1;
    return 0;
}

static struct urov_y_request uy_req(unsigned op)
{
    struct urov_y_request q;
    memset(&q, 0, sizeof(q));
    q.size = (uint32_t)sizeof(q);
    q.version = UROV_Y_ABI_VERSION;
    q.op = (uint16_t)op;
    q.request_id = UINT64_C(0x55524f56594c4142);
    return q;
}

static long uy_control(const struct uy_ctx *ctx, unsigned op, struct urov_y_request *q)
{
    q->size = (uint32_t)sizeof(*q);
    q->version = UROV_Y_ABI_VERSION;
    q->op = (uint16_t)op;
    q->mac = urov_y_request_mac(ctx->keys.mac, q);
    return syscall(__NR_prctl, (long)ctx->keys.option, (long)ctx->keys.magic,
                   (long)op, q, (long)sizeof(*q));
}

static int uy_register_page(const struct uy_ctx *ctx, const struct page *p,
                            unsigned length, uint64_t value, unsigned mode,
                            uint64_t *generation)
{
    struct urov_y_request q = uy_req(UROV_Y_REGISTER);
    int rc;

    q.address = (uintptr_t)p->address;
    q.offset = p->entry + 8U;
    q.length = length;
    q.value = value;
    q.mode = mode;
    q.site_count = 2;
    q.sites[0] = (uint64_t)(uintptr_t)&uy_site_ldr;
    q.sites[1] = (uint64_t)(uintptr_t)&uy_site_ldrb;
    q.caller_count = 2;
    q.caller_start[0] = (uint64_t)(uintptr_t)&uy_business_ldr;
    q.caller_end[0] = (uint64_t)(uintptr_t)uy_business_ldr_end;
    q.caller_start[1] = (uint64_t)(uintptr_t)&uy_business_ldrb;
    q.caller_end[1] = (uint64_t)(uintptr_t)uy_business_ldrb_end;
    rc = (int)uy_control(ctx, UROV_Y_REGISTER, &q);
    REQUIRE(!rc && q.state == UROV_Y_ACTIVE && q.generation == 1,
            "UY REGISTER rc=%d errno=%d", rc, errno);
    if (rc) return rc;
    *generation = q.generation;
    return 0;
}

static int uy_set_page(const struct uy_ctx *ctx, uint64_t generation, uint64_t value)
{
    struct urov_y_request q = uy_req(UROV_Y_SET);
    q.session = 1;
    q.expected_generation = generation;
    q.length = 8;
    q.value = value;
    return (int)uy_control(ctx, UROV_Y_SET, &q);
}

static int uy_status(const struct uy_ctx *ctx, struct urov_y_request *out)
{
    struct urov_y_request q = uy_req(UROV_Y_STATUS);
    q.session = 1;
    if (uy_control(ctx, UROV_Y_STATUS, &q)) return -1;
    *out = q;
    return 0;
}

static const char *uy_mode_name(unsigned mode)
{
    return mode == UROV_Y_MODE_PAGE_UXN ? "page" : "brk";
}

/* Private_Dirty / Anonymous kB of the VMA holding addr. */
static int uy_mapping_private_kb(const void *addr, unsigned *dirty, unsigned *anon)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    char line[256];
    unsigned long start, end;
    int inside = 0, found = 0;

    if (!f) return -1;
    *dirty = 0;
    *anon = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            inside = (uintptr_t)addr >= start && (uintptr_t)addr < end;
            found |= inside;
            continue;
        }
        if (!inside) continue;
        if (!strncmp(line, "Private_Dirty:", 14))
            *dirty = (unsigned)strtoul(line + 14, NULL, 10);
        else if (!strncmp(line, "Anonymous:", 10))
            *anon = (unsigned)strtoul(line + 10, NULL, 10);
    }
    fclose(f);
    return found ? 0 : -1;
}

/* One full observation case: both delivered detector APIs must stay negative on
 * the target page, and the page itself must remain a plain native mapping. */
static void elimination_case(const char *name, const struct page *p, unsigned delta,
                             int repeats)
{
    const uint8_t *at = p->address + p->entry + delta;
    const uint8_t *reference = (const uint8_t *)(uintptr_t)&ud_payload + delta;
    const off_t offset = p->file_offset + p->entry + delta;
    struct ud_exclusive_observation ex = {0};
    struct ud_reader_observation rd = {0};
    unsigned exclusive_matches = 0, exclusive_clean = 0, exclusive_unknown = 0;
    unsigned reader_matches = 0, reader_clean = 0, reader_unknown = 0;
    unsigned accepted = 0, failed = 0, control_failed = 0;
    unsigned failures_before = g_fail;
    const int signals[] = {SIGSEGV, SIGBUS, SIGSYS, SIGPIPE};
    struct sigaction old[4], after;
    struct ud_mapping oldmap, newmap;
    char name_before[17] = {0}, name_after[17] = {0};
    int probe_fds = probe_fd_count();
    off_t position = lseek(p->fd, 0, SEEK_CUR);

    for (unsigned i = 0; i < 4; ++i) sigaction(signals[i], NULL, &old[i]);
    prctl(PR_GET_NAME, name_before, 0L, 0L, 0L);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &oldmap), "%s before mapping", name);
    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        errno = EDOM;
        ud_observe_exclusive(at, reference, p->fd, offset, &ex);
        REQUIRE(errno == EDOM, "%s exclusive changed errno", name);
        REQUIRE(ex.reservation_loss == UD_NO_MATCH ||
                (ex.reservation_loss == UD_UNKNOWN && ex.error == EAGAIN),
                "%s exclusive=%d accepted=%u failed=%u control=%u error=%d",
                name, ex.reservation_loss, ex.accepted, ex.target_failed,
                ex.control_failed, ex.error);
        exclusive_matches += ex.reservation_loss == UD_MATCH;
        exclusive_clean += ex.reservation_loss == UD_NO_MATCH;
        exclusive_unknown += ex.reservation_loss == UD_UNKNOWN;
        accepted += ex.accepted;
        failed += ex.target_failed;
        control_failed += ex.control_failed;
        errno = EDOM;
        ud_observe_reader(at, p->fd, offset, uy_site_ldr, &rd);
        REQUIRE(errno == EDOM, "%s reader changed errno", name);
        REQUIRE(rd.reader_diff == UD_NO_MATCH && rd.completed == UD_REPEATS,
                "%s reader=%d expected=0 rounds=%u error=%d", name,
                rd.reader_diff, rd.completed, rd.error);
        REQUIRE(rd.direct_value == rd.file_value, "%s direct=%llx file=%llx", name,
                (unsigned long long)rd.direct_value, (unsigned long long)rd.file_value);
        reader_matches += rd.reader_diff == UD_MATCH;
        reader_clean += rd.reader_diff == UD_NO_MATCH;
        reader_unknown += rd.reader_diff == UD_UNKNOWN;
    }
    for (unsigned i = 0; i < 4; ++i) {
        sigaction(signals[i], NULL, &after);
        REQUIRE(same_signal(&old[i], &after), "%s changed signal %d", name, signals[i]);
    }
    prctl(PR_GET_NAME, name_after, 0L, 0L, 0L);
    REQUIRE(!strcmp(name_before, name_after), "%s thread name changed", name);
    REQUIRE(lseek(p->fd, 0, SEEK_CUR) == position, "%s file position changed", name);
    REQUIRE(probe_fds == probe_fd_count(), "%s leaked metadata fd", name);
    REQUIRE(!ud_mapping_at("/proc/self/smaps", at, &newmap) &&
            oldmap.start == newmap.start && oldmap.end == newmap.end &&
            oldmap.offset == newmap.offset && oldmap.readable == newmap.readable &&
            oldmap.writable == newmap.writable && oldmap.executable == newmap.executable &&
            oldmap.dontcopy == newmap.dontcopy && oldmap.randomread == newmap.randomread &&
            oldmap.maywrite == newmap.maywrite, "%s VMA changed", name);
    REQUIRE(exclusive_matches == 0, "%s exclusive matched %u times", name, exclusive_matches);
    REQUIRE(reader_matches == 0, "%s reader matched %u times", name, reader_matches);
    LOG("ELIM_CASE name=%s result=%s n=%d exclusive_match=%u exclusive_clean=%u "
        "exclusive_unknown=%u accepted=%u failed=%u control_failed=%u "
        "reader_match=%u reader_clean=%u reader_unknown=%u direct=0x%llx file=0x%llx",
        name, failures_before == g_fail ? "PASS" : "FAIL", repeats,
        exclusive_matches, exclusive_clean, exclusive_unknown, accepted, failed,
        control_failed, reader_matches, reader_clean, reader_unknown,
        (unsigned long long)rd.direct_value, (unsigned long long)rd.file_value);
}

/* No key: the module is loaded but cannot be addressed; the same observation
 * APIs must also stay negative because nothing is registered. */
static void elimination_clean(void)
{
    struct uy_ctx ctx;
    struct page p;
    struct ud_control ctl;
    struct ud_views views;
    struct urov_y_request q;
    uint8_t key[16];
    long rc;
    uint64_t disk = 0;

    memset(&ctx, 0, sizeof(ctx));
    memset(key, 0x5a, sizeof(key));
    urov_x_derive(key, &ctx.keys);
    memset(key, 0, sizeof(key));
    ctx.have = 1;
    ++g_cases;

    ud_probe_control(&ctl);
    REQUIRE(ctl.verdict == UD_NO_MATCH && ctl.scope == UD_SCOPE_UNKNOWN,
            "UY clean control verdict=%d scope=%d", ctl.verdict, ctl.scope);
    q = uy_req(UROV_Y_STATUS);
    q.session = 1;
    errno = 0;
    rc = uy_control(&ctx, UROV_Y_STATUS, &q);
    REQUIRE(rc == -1 && errno == EINVAL, "UY clean selector rc=%ld errno=%d", rc, errno);
    {
        struct urov_request old = {0};
        old.size = sizeof(old); old.version = 2; old.op = 1;
        errno = 0;
        rc = syscall(__NR_prctl, 0x55524f56L, 0x55524f5653595343ULL, 1L, &old, 128L);
        REQUIRE(rc == -1 && errno == EINVAL, "UY clean legacy rc=%ld errno=%d", rc, errno);
    }
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UY clean page errno=%d", errno);
        return;
    }
    REQUIRE(!app_pread(p.fd, p.file_offset + p.entry + 8, (uint8_t *)&disk, 8),
            "UY clean pread");
    REQUIRE(uy_business_ldr(p.address + p.entry + 8) == disk, "UY clean business diverged");
    REQUIRE(uy_site_ldr(p.address + p.entry + 8) == disk, "UY clean site diverged");
    errno = EDOM;
    ud_check_views(p.address + p.entry, 64, p.fd, p.file_offset + p.entry, &views);
    REQUIRE(errno == EDOM && views.file_diff == UD_NO_MATCH && views.completed == UD_REPEATS,
            "UY clean views file=%d done=%u error=%d", views.file_diff,
            views.completed, views.error_file);
    elimination_case("idle_unregistered", &p, 8, 3);
    page_close(&p);
}

static void elimination_active(const char *key_hex, int repeats, unsigned mode)
{
    struct uy_ctx ctx;
    struct page p;
    struct business business;
    pthread_t thread;
    int have_thread = 0;
    uint64_t generation = 0;
    uint64_t disk = 0;
    uint8_t disk64[64], direct[64];
    const uint8_t *at;
    struct ud_reader_observation rd;
    struct urov_y_request st;
    unsigned base_dirty = 0, base_anon = 0;
    const uint64_t fake = UINT64_C(0x8877665544332211);

    if (uy_init_key(&ctx, key_hex)) { REQUIRE(0, "UY key missing"); return; }
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UY page open errno=%d", errno);
        return;
    }
    at = p.address + p.entry + 8U;
    (void)uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr, &base_dirty,
                                &base_anon);
    memset(&business, 0, sizeof(business));
    atomic_init(&business.stop, 0); atomic_init(&business.errors, 0); atomic_init(&business.ops, 0);
    business.fn = (payload_fn)(void *)(p.address + p.entry);
    have_thread = pthread_create(&thread, NULL, business_main, &business) == 0;
    REQUIRE(have_thread, "UY business worker");
    usleep(10000);
    ++g_cases;

    REQUIRE(!app_pread(p.fd, p.file_offset + p.entry + 8, (uint8_t *)&disk, 8), "UY pread");
    REQUIRE(!app_pread(p.fd, p.file_offset + p.entry, disk64, sizeof(disk64)), "UY pread64");
    elimination_case("baseline", &p, 8, repeats);

    if (uy_register_page(&ctx, &p, 8, fake, mode, &generation)) { page_close(&p); return; }

    /* The business call window still observes the fake value. */
    REQUIRE(uy_business_ldr(at) == fake, "UY business call got=%llx",
            (unsigned long long)uy_business_ldr(at));
    REQUIRE((uint32_t)uy_business_ldrb(at) == 0x11U,
            "UY business ldrb got=%02x", (unsigned)uy_business_ldrb(at));
    REQUIRE(uy_site_ldr(at) == disk, "UY direct site diverged");
    copy_scalar(direct, at, sizeof(direct));
    REQUIRE(!memcmp(direct, disk64 + 8, 8), "UY plain read diverged");

    /* The observable that the previous generation could not remove: does the
     * live trap change the code page at all?  The page-trap mode must leave
     * the instruction and the page accounting untouched; the BRK mode is the
     * positive control for this probe. */
    {
        struct ud_mapping sm;
        uint32_t file_word = 0, live_word = 0;
        unsigned dirty = 0, anon = 0;
        int have_pd = !uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr,
                                             &dirty, &anon);
        if (!ud_mapping_at("/proc/self/maps", (const void *)(uintptr_t)&uy_site_ldr, &sm)) {
            off_t site_off = (off_t)(sm.offset + ((uintptr_t)&uy_site_ldr - sm.start));
            if (!app_pread(p.fd, site_off, (uint8_t *)&file_word, 4)) {
                live_word = load32_at((const uint8_t *)(uintptr_t)&uy_site_ldr);
                LOG("ELIM_RESIDUAL mode=%s site_file_word=%08x site_live_word=%08x "
                    "differs=%d site_cow_private=%d private_dirty_kb=%u anonymous_kb=%u "
                    "base_dirty_kb=%u base_anonymous_kb=%u",
                    uy_mode_name(mode), file_word, live_word, file_word != live_word,
                    (have_pd && dirty > base_dirty) ? 1 : 0, dirty, anon,
                    base_dirty, base_anon);
                if (mode == UROV_Y_MODE_PAGE_UXN) {
                    REQUIRE(file_word == live_word,
                            "UY page mode changed the site word %08x -> %08x",
                            file_word, live_word);
                    REQUIRE(have_pd && dirty == base_dirty && anon == base_anon,
                            "UY page mode made the site page private dirty=%u/%u "
                            "anon=%u/%u", dirty, base_dirty, anon, base_anon);
                } else {
                    REQUIRE(file_word != live_word, "UY site code word was not patched");
                    REQUIRE(have_pd && anon >= base_anon + 4U,
                            "UY brk mode did not COW the site page anon=%u/%u",
                            anon, base_anon);
                }
            }
        }
    }

    /* Both delivered detectors must stay negative on the active page. */
    elimination_case("active_page", &p, 8, repeats);
    elimination_case("active_outside_window", &p, 96, repeats);

    /* A detector that runs the registered business call window observes the
     * overlay: that is the feature, not a module fingerprint. Log it so the
     * report cannot hide it. */
    errno = EDOM;
    ud_observe_reader(at, p.fd, p.file_offset + p.entry + 8, uy_business_ldr, &rd);
    LOG("ELIM_FEATURE business_reader=%d direct=0x%llx reader=0x%llx file=0x%llx",
        rd.reader_diff, (unsigned long long)rd.direct_value,
        (unsigned long long)rd.reader_value, (unsigned long long)rd.file_value);
    REQUIRE(rd.reader_diff == UD_MATCH, "UY business reader did not observe fake");

    /* Timing side channel, measured rather than hidden: one trap per call. */
    {
        uint64_t t0 = now_ns(), t1;
        for (int i = 0; i < 2000; ++i) (void)uy_business_ldr(at);
        t1 = now_ns();
        LOG("ELIM_TIMING mode=%s site_call_ns=%llu", uy_mode_name(mode),
            (unsigned long long)((t1 - t0) / 2000));
    }

    /* Update path: the business window follows SET, the detector stays blind. */
    REQUIRE(!uy_set_page(&ctx, generation, UINT64_C(0x0f0e0d0c0b0a0908)),
            "UY SET errno=%d", errno);
    REQUIRE(uy_business_ldr(at) == UINT64_C(0x0f0e0d0c0b0a0908), "UY SET not visible");
    elimination_case("active_after_set", &p, 8, repeats);
    REQUIRE(!uy_set_page(&ctx, generation + 1, disk), "UY SET identity errno=%d", errno);
    REQUIRE(uy_business_ldr(at) == disk, "UY identity SET not visible");
    elimination_case("active_equal_value", &p, 8, repeats);

    REQUIRE(!uy_status(&ctx, &st) && st.state == UROV_Y_ACTIVE &&
            st.generation == generation + 2 && st.failures == 0 &&
            st.mode == mode && st.hits > 0 && st.replays > 0,
            "UY STATUS gen=%llu state=%u mode=%u hits=%llu replays=%llu failures=%llu",
            (unsigned long long)st.generation, st.state, st.mode,
            (unsigned long long)st.hits, (unsigned long long)st.replays,
            (unsigned long long)st.failures);

    {
        struct urov_y_request d = uy_req(UROV_Y_DEACTIVATE);
        d.session = 1;
        REQUIRE(!uy_control(&ctx, UROV_Y_DEACTIVATE, &d), "UY DEACTIVATE");
    }
    REQUIRE(uy_business_ldr(at) == disk, "UY deactivated site not restored");
    REQUIRE(load32_at((const uint8_t *)(uintptr_t)&uy_site_ldr) == 0xf9400000U,
            "UY deactivated opcode not restored");
    {
        struct ud_mapping sm;
        uint32_t file_word = 0, live_word = load32_at((const uint8_t *)(uintptr_t)&uy_site_ldr);
        unsigned dirty = 0, anon = 0;
        (void)uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr, &dirty, &anon);
        if (!ud_mapping_at("/proc/self/maps", (const void *)(uintptr_t)&uy_site_ldr, &sm)) {
            off_t site_off = (off_t)(sm.offset + ((uintptr_t)&uy_site_ldr - sm.start));
            if (!app_pread(p.fd, site_off, (uint8_t *)&file_word, 4))
                LOG("ELIM_RESIDUAL restored_site_file_word=%08x live_word=%08x equal=%d "
                    "private_dirty_kb=%u anonymous_kb=%u base_dirty_kb=%u "
                    "base_anonymous_kb=%u",
                    file_word, live_word, file_word == live_word, dirty, anon,
                    base_dirty, base_anon);
        }
        if (mode == UROV_Y_MODE_PAGE_UXN)
            REQUIRE(dirty == base_dirty && anon == base_anon,
                    "UY page mode left the page private after deactivate");
    }
    elimination_case("deactivated", &p, 8, repeats);

    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.errors) == 0 && atomic_load(&business.ops) > 0,
                "UY business failed");
        LOG("ELIM_BUSINESS ops=%llu errors=%d execution=original",
            (unsigned long long)atomic_load(&business.ops),
            atomic_load(&business.errors));
    }
    page_close(&p);
}

/* Hold an active session while the harness unloads the module; the site must
 * come back to the original bytes without a signal in this process. */
static void elimination_hold(const char *key_hex, unsigned mode)
{
    struct uy_ctx ctx;
    struct page p;
    uint64_t generation = 0;
    uint64_t disk = 0;
    const uint8_t *at;
    unsigned base_dirty = 0, base_anon = 0;
    int restored = 0;

    if (uy_init_key(&ctx, key_hex)) { REQUIRE(0, "UY hold key missing"); return; }
    if (page_open(&p, MAP_SHARED)) { REQUIRE(0, "UY hold page errno=%d", errno); return; }
    at = p.address + p.entry + 8U;
    (void)uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr, &base_dirty,
                                &base_anon);
    REQUIRE(!app_pread(p.fd, p.file_offset + p.entry + 8, (uint8_t *)&disk, 8), "UY hold pread");
    if (uy_register_page(&ctx, &p, 8, UINT64_C(0x8877665544332211), mode, &generation)) {
        page_close(&p);
        return;
    }
    REQUIRE(uy_business_ldr(at) == UINT64_C(0x8877665544332211), "UY hold not armed");
    LOG("ELIM_HOLD_READY pid=%d uid=%d mode=%s", getpid(), getuid(), uy_mode_name(mode));
    for (unsigned i = 0; i < 900; ++i) {
        unsigned dirty = 0, anon = 0;
        usleep(100000);
        if (uy_business_ldr(at) == disk) {
            uint32_t insn = load32_at((const uint8_t *)(uintptr_t)&uy_site_ldr);
            (void)uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr, &dirty, &anon);
            LOG("ELIM_HOLD_RESTORED pid=%d opcode=%08x direct=%llx private_dirty_kb=%u "
                "anonymous_kb=%u base_dirty_kb=%u base_anonymous_kb=%u",
                getpid(), insn, (unsigned long long)uy_site_ldr(at), dirty, anon,
                base_dirty, base_anon);
            /* A BRK session legitimately keeps its COW page after the unload;
             * the page-trap session must leave the page exactly as it was. */
            restored = insn == 0xf9400000U && uy_site_ldr(at) == disk &&
                       (mode != UROV_Y_MODE_PAGE_UXN ||
                        (dirty == base_dirty && anon == base_anon));
            break;
        }
    }
    ++g_cases;
    REQUIRE(restored, "UY hold did not observe a restored site");
    page_close(&p);
}
