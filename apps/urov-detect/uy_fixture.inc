/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * urov-y fixture, included by app.c.  The detector core
 * (native/urov_observe.c + native/urov_detect.c) receives no control inputs.
 * The fixture owns a normal one-page RX alias of its own library and registers
 * uy_site_ldr/uy_site_ldrb as reader sites plus uy_business_ldr/uy_business_ldrb
 * as the business call windows.
 *
 * Expected result against urov-y:
 *   - ud_observe_unreserved_status() and ud_observe_unreserved_nop_status()
 *     see no PAGE_AP store after CLREX: a direct branch to the load or to a
 *     NOP in the LDXR gap is rejected by the bridge.
 *   - the fixed cross-page branch probe stays negative on 2.9.0; the XZR
 *     sequence detects reservation loss on active PAGE_AP, including
 *     reads outside the caller window and equal-value overlays.
 *   - ud_observe_reader() outside the business window returns original bytes.
 *   - ud_observe_execution() on the canary matches only in active PAGE_UXN.
 *   - ud_observe_unreserved_store() confirms STXR never writes without an
 *     exclusive reservation, including on an active AP page.
 *   - the registered business call still returns the fake value.
 */

#include "uy_fixture_control.h"

__asm__(".pushsection .text.uy_sites,\"ax\",%progbits\n"
        ".p2align 12\n"
        ".global uy_site_ldr\n.type uy_site_ldr,%function\n"
        "uy_site_ldr:\n ldr x0, [x0]\n ret\n"
        ".size uy_site_ldr, .-uy_site_ldr\n"
        ".global uy_site_ldrb\n.type uy_site_ldrb,%function\n"
        "uy_site_ldrb:\n ldrb w0, [x0]\n ret\n"
        ".size uy_site_ldrb, .-uy_site_ldrb\n"
        ".p2align 3\n"
        ".global uy_site_canary\n.hidden uy_site_canary\n.type uy_site_canary,%function\n"
        "uy_site_canary:\n hint #34\n ret\n"
        ".size uy_site_canary, .-uy_site_canary\n"
        /* The page-trap mode makes exactly this page EL0 execute-never, so it
         * holds just the reader stubs and canary: pad it to the end and
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
extern void uy_site_canary(void);
extern uint64_t uy_business_ldr(const void *p);
extern uint32_t uy_business_ldrb(const void *p);
extern char uy_business_ldr_end[];
extern char uy_business_ldrb_end[];

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

/* Linux rejects the advice before changing the VMA. Y's range gate runs
 * first, so an overlapping session can still be restored. */
static int uy_invalid_advice(const void *address, size_t page_size)
{
    return madvise((void *)address, page_size, -1) ? errno : 0;
}

static const char *uy_mode_name(unsigned mode)
{
    if (mode == UROV_Y_MODE_PAGE_UXN) return "page";
    if (mode == UROV_Y_MODE_PAGE_AP) return "ap";
    return "brk";
}

static int uy_open_exec_reference(struct page *reference)
{
    uintptr_t pc = (uintptr_t)&uy_site_canary;
    if (sysconf(_SC_PAGESIZE) != UROV_Y_PAGE ||
        pc / UROV_Y_PAGE != (uintptr_t)&uy_site_ldr / UROV_Y_PAGE ||
        pc / UROV_Y_PAGE != (uintptr_t)&uy_site_ldrb / UROV_Y_PAGE) {
        errno = EINVAL;
        return -1;
    }
    return page_open_at(reference, MAP_PRIVATE, (const void *)pc);
}

static void elimination_exec_case(const char *name, const struct page *reference,
                                  int repeats, enum ud_verdict expected)
{
    const void *site = (const void *)(uintptr_t)&uy_site_canary;
    const void *alias = reference->address + reference->entry;
    off_t offset = reference->file_offset + reference->entry;
    unsigned matches = 0, clean = 0, unknown = 0;
    unsigned accepted = 0, failed = 0, control_failed = 0;
    uint64_t total_ns = 0, max_ns = 0;
    off_t file_position = lseek(reference->fd, 0, SEEK_CUR);
    int probe_fds = probe_fd_count();

    ++g_cases;
    for (int i = 0; i < repeats; ++i) {
        struct ud_exclusive_observation obs;
        errno = EDOM;
        ud_observe_execution(site, alias, reference->fd, offset, &obs);
        REQUIRE(errno == EDOM, "%s execution changed errno", name);
        REQUIRE(obs.reservation_loss == expected ||
                (obs.reservation_loss == UD_UNKNOWN && obs.error == EAGAIN),
                "%s exec=%d expected=%d accepted=%u failed=%u control=%u error=%d",
                name, obs.reservation_loss, expected, obs.accepted, obs.target_failed,
                obs.control_failed, obs.error);
        matches += obs.reservation_loss == UD_MATCH;
        clean += obs.reservation_loss == UD_NO_MATCH;
        unknown += obs.reservation_loss == UD_UNKNOWN;
        accepted += obs.accepted;
        failed += obs.target_failed;
        control_failed += obs.control_failed;
        total_ns += obs.elapsed_ns;
        if (obs.elapsed_ns > max_ns) max_ns = obs.elapsed_ns;
    }
    REQUIRE(matches + clean > 0, "%s all execution observations were inconclusive", name);
    REQUIRE(lseek(reference->fd, 0, SEEK_CUR) == file_position, "%s changed file position", name);
    REQUIRE(probe_fds == probe_fd_count(), "%s leaked metadata fd", name);
    LOG("ELIM_EXEC name=%s n=%d expected=%d match=%u clean=%u unknown=%u accepted=%u "
        "failed=%u control_failed=%u total_ns=%llu max_ns=%llu",
        name, repeats, expected, matches, clean, unknown, accepted, failed, control_failed,
        (unsigned long long)total_ns, (unsigned long long)max_ns);
}

static void elimination_bridge_case(const char *name, const struct page *page, unsigned delta,
                                    enum ud_verdict expected_cross_page)
{
    const void *target = page->address + page->entry + delta;
    const void *control = (const uint8_t *)(uintptr_t)&ud_payload + delta;
    struct ud_store_observation obs, nop, indirect, cross_page;
    errno = EDOM;
    ud_observe_unreserved_status(target, control, page->fd,
                                 page->file_offset + page->entry + delta, &obs);
    REQUIRE(errno == EDOM && obs.verdict == UD_NO_MATCH && obs.completed == UD_STORE_TRIALS,
            "UY direct branch %s verdict=%d trials=%u error=%d",
            name, obs.verdict, obs.completed, obs.error);
    ud_observe_unreserved_nop_status(target, control, page->fd,
                                     page->file_offset + page->entry + delta, &nop);
    REQUIRE(errno == EDOM && nop.verdict == UD_NO_MATCH && nop.completed == UD_STORE_TRIALS &&
            !nop.unexpected_stores,
            "UY NOP branch %s verdict=%d trials=%u stores=%u error=%d",
            name, nop.verdict, nop.completed, nop.unexpected_stores, nop.error);
    ud_observe_unreserved_indirect_status(target, control, page->fd,
                                          page->file_offset + page->entry + delta, &indirect);
    REQUIRE(errno == EDOM && indirect.verdict == UD_NO_MATCH &&
            indirect.completed == UD_STORE_TRIALS && !indirect.unexpected_stores,
            "UY indirect branch %s verdict=%d trials=%u stores=%u error=%d",
            name, indirect.verdict, indirect.completed, indirect.unexpected_stores,
            indirect.error);
    ud_observe_unreserved_cross_page_status(target, control, page->fd,
                                            page->file_offset + page->entry + delta, &cross_page);
    REQUIRE(errno == EDOM && cross_page.verdict == expected_cross_page &&
            cross_page.completed == UD_STORE_TRIALS,
            "UY cross-page branch %s expected=%d verdict=%d trials=%u successes=%u error=%d",
            name, expected_cross_page, cross_page.verdict, cross_page.completed,
            cross_page.unexpected_stores, cross_page.error);
    LOG("ELIM_BRIDGE name=%s expected=%d verdict=%d trials=%u successes=%u elapsed_ns=%llu "
        "nop_expected=%d nop_verdict=%d nop_trials=%u nop_successes=%u nop_elapsed_ns=%llu "
        "indirect_verdict=%d indirect_trials=%u indirect_successes=%u indirect_elapsed_ns=%llu "
        "cross_page_expected=%d cross_page_verdict=%d cross_page_trials=%u cross_page_successes=%u "
        "cross_page_elapsed_ns=%llu",
        name, UD_NO_MATCH, obs.verdict, obs.completed, obs.unexpected_stores,
        (unsigned long long)obs.elapsed_ns, UD_NO_MATCH, nop.verdict, nop.completed,
        nop.unexpected_stores, (unsigned long long)nop.elapsed_ns, indirect.verdict,
        indirect.completed, indirect.unexpected_stores,
        (unsigned long long)indirect.elapsed_ns, expected_cross_page, cross_page.verdict,
        cross_page.completed, cross_page.unexpected_stores, (unsigned long long)cross_page.elapsed_ns);
}

static void elimination_each_cpu(const struct page *page, enum ud_verdict expected,
                                  int test_store)
{
    cpu_set_t available;
    unsigned tested = 0;
    if (sched_getaffinity(0, sizeof(available), &available)) {
        REQUIRE(0, "UY read worker affinity errno=%d", errno);
        return;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        cpu_set_t selected;
        char name[40];
        if (!CPU_ISSET(cpu, &available)) continue;
        CPU_ZERO(&selected);
        CPU_SET(cpu, &selected);
        if (sched_setaffinity(0, sizeof(selected), &selected)) {
            REQUIRE(0, "UY select worker cpu=%d errno=%d", cpu, errno);
            continue;
        }
        snprintf(name, sizeof(name), "active_cpu_%d", cpu);
        if (test_store) {
            store_case(name, page, 8, 3, expected);
            elimination_bridge_case(name, page, 8, UD_NO_MATCH);
        } else {
            elimination_exec_case(name, page, 3, expected);
        }
        ++tested;
    }
    REQUIRE(!sched_setaffinity(0, sizeof(available), &available) && tested > 0,
            "UY restore worker affinity");
}

/* Standalone observer path: no UROV control request or key input. */
static void elimination_observe_passive(int repeats)
{
    struct page reference, p;
    struct ud_exclusive_observation obs;
    struct ud_store_observation store;
    const void *site = (const void *)(uintptr_t)&uy_site_canary;
    size_t reader_offset = (uintptr_t)&uy_site_ldr % UROV_Y_PAGE;

    if (uy_open_exec_reference(&reference)) {
        REQUIRE(0, "UY open executable reference errno=%d", errno);
        return;
    }
    elimination_exec_case("unregistered", &reference, repeats, UD_NO_MATCH);
    ud_observe_execution(site, site, reference.fd, reference.file_offset + reference.entry, &obs);
    REQUIRE(obs.reservation_loss == UD_UNKNOWN && obs.error == EINVAL && obs.accepted == 0,
            "UY same-address reference accepted");
    ud_observe_execution((const void *)(uintptr_t)&uy_site_ldr,
                         reference.address + reader_offset, reference.fd,
                         reference.file_offset + (off_t)reader_offset, &obs);
    REQUIRE(obs.reservation_loss == UD_UNKNOWN && obs.error == EPROTO && obs.accepted == 0,
            "UY non-canary instructions accepted");
    page_close(&reference);

    if (page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UY open store probe page errno=%d", errno);
        return;
    }
    store_case("unregistered", &p, 8, repeats, UD_NO_MATCH);
    const void *at = p.address + p.entry + 8;
    const void *control = (const uint8_t *)(uintptr_t)&ud_payload + 8;
    off_t offset = p.file_offset + p.entry + 8;
    ud_observe_unreserved_store(at, at, p.fd, offset, &store);
    REQUIRE(store.verdict == UD_UNKNOWN && store.error == EINVAL && store.completed == 0,
            "UY store probe accepted same-address reference");
    ud_observe_unreserved_store(at, control, p.fd, offset + 1, &store);
    REQUIRE(store.verdict == UD_UNKNOWN && store.error == ESTALE && store.completed == 0,
            "UY store probe accepted wrong file offset");
    ud_observe_unreserved_nop_status(at, control, p.fd, offset + 1, &store);
    REQUIRE(store.verdict == UD_UNKNOWN && store.error == ESTALE && store.completed == 0,
            "UY NOP branch accepted wrong file offset");
    elimination_bridge_case("unregistered", &p, 8, UD_NO_MATCH);
    page_close(&p);
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

/* Verify the read value and the architectural reservation result. */
static void elimination_case(const char *name, const struct page *p, unsigned delta,
                             int repeats, enum ud_verdict expected_nonzero)
{
    const uint8_t *at = p->address + p->entry + delta;
    const uint8_t *reference = (const uint8_t *)(uintptr_t)&ud_payload + delta;
    const off_t offset = p->file_offset + p->entry + delta;
    struct ud_exclusive_observation ex = {0}, zero = {0}, nonzero = {0};
    struct ud_reader_observation rd = {0};
    unsigned exclusive_matches = 0, exclusive_clean = 0, exclusive_unknown = 0;
    unsigned zero_matches = 0, zero_clean = 0, zero_unknown = 0;
    unsigned nonzero_matches = 0, nonzero_clean = 0, nonzero_unknown = 0;
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
        ud_observe_zero_exclusive(at, reference, p->fd, offset, &zero);
        REQUIRE(errno == EDOM, "%s XZR probe changed errno", name);
        REQUIRE(zero.reservation_loss == UD_NO_MATCH ||
                (zero.reservation_loss == UD_UNKNOWN && zero.error == EAGAIN),
                "%s XZR verdict=%d accepted=%u failed=%u control=%u error=%d", name,
                zero.reservation_loss, zero.accepted, zero.target_failed,
                zero.control_failed, zero.error);
        zero_matches += zero.reservation_loss == UD_MATCH;
        zero_clean += zero.reservation_loss == UD_NO_MATCH;
        zero_unknown += zero.reservation_loss == UD_UNKNOWN;
        ud_observe_nonzero_exclusive(at, reference, p->fd, offset, &nonzero);
        REQUIRE(errno == EDOM, "%s nonzero XZR probe changed errno", name);
        REQUIRE(nonzero.reservation_loss == expected_nonzero ||
                (nonzero.reservation_loss == UD_UNKNOWN && nonzero.error == EAGAIN),
                "%s nonzero XZR verdict=%d accepted=%u failed=%u control=%u error=%d", name,
                nonzero.reservation_loss, nonzero.accepted, nonzero.target_failed,
                nonzero.control_failed, nonzero.error);
        nonzero_matches += nonzero.reservation_loss == UD_MATCH;
        nonzero_clean += nonzero.reservation_loss == UD_NO_MATCH;
        nonzero_unknown += nonzero.reservation_loss == UD_UNKNOWN;
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
    REQUIRE(!exclusive_matches, "%s unexpected adjacent reservation loss", name);
    REQUIRE(zero_clean > 0 && !zero_matches, "%s inconclusive XZR result matches=%u clean=%u",
            name, zero_matches, zero_clean);
    REQUIRE(expected_nonzero == UD_MATCH ? nonzero_matches > 0 && !nonzero_clean :
            nonzero_clean > 0 && !nonzero_matches,
            "%s inconclusive nonzero XZR result matches=%u clean=%u",
            name, nonzero_matches, nonzero_clean);
    REQUIRE(reader_matches == 0, "%s reader matched %u times", name, reader_matches);
    LOG("ELIM_CASE name=%s result=%s n=%d exclusive_match=%u exclusive_clean=%u "
        "exclusive_unknown=%u accepted=%u failed=%u control_failed=%u "
        "reader_match=%u reader_clean=%u reader_unknown=%u direct=0x%llx file=0x%llx "
        "zero_match=%u zero_clean=%u zero_unknown=%u "
        "nonzero_match=%u nonzero_clean=%u nonzero_unknown=%u",
        name, failures_before == g_fail ? "PASS" : "FAIL", repeats,
        exclusive_matches, exclusive_clean, exclusive_unknown, accepted, failed,
        control_failed, reader_matches, reader_clean, reader_unknown,
        (unsigned long long)rd.direct_value, (unsigned long long)rd.file_value,
        zero_matches, zero_clean, zero_unknown, nonzero_matches, nonzero_clean, nonzero_unknown);
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
    elimination_case("idle_unregistered", &p, 8, 3, UD_NO_MATCH);
    page_close(&p);
}

static void elimination_active(const char *key_hex, int repeats, unsigned mode)
{
    struct uy_ctx ctx;
    struct page p, reference;
    struct business business;
    pthread_t thread;
    int have_thread = 0;
    uint64_t generation = 0;
    uint64_t disk = 0;
    uint8_t disk64[64], direct[64];
    const uint8_t *at;
    struct ud_reader_observation rd;
    struct urov_y_request st = {0}, before = {0};
    enum ud_verdict expected_exec = mode == UROV_Y_MODE_PAGE_UXN ? UD_MATCH : UD_NO_MATCH;
    enum ud_verdict expected_nonzero = mode == UROV_Y_MODE_PAGE_AP ? UD_MATCH : UD_NO_MATCH;
    /* A failed native STXR must not write the sentinel. */
    enum ud_verdict expected_store = UD_NO_MATCH;
    enum ud_verdict expected_cross_page = UD_NO_MATCH;
    unsigned base_dirty = 0, base_anon = 0;
    const uint64_t fake = UINT64_C(0x8877665544332211);

    if (uy_init_key(&ctx, key_hex)) { REQUIRE(0, "UY key missing"); return; }
    if (sysconf(_SC_PAGESIZE) != 4096 || page_open(&p, MAP_SHARED)) {
        REQUIRE(0, "UY page open errno=%d", errno);
        return;
    }
    if (uy_open_exec_reference(&reference)) {
        REQUIRE(0, "UY open executable reference errno=%d", errno);
        page_close(&p);
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
    elimination_case("baseline", &p, 8, repeats, UD_NO_MATCH);
    elimination_exec_case("baseline", &reference, repeats, UD_NO_MATCH);
    store_case("baseline", &p, 8, repeats, UD_NO_MATCH);

    if (uy_register_page(&ctx, &p, 8, fake, mode, &generation)) goto out;

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
                if (mode != UROV_Y_MODE_SITE_BRK) {
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

    /* Only an actual data-abort path loses this reservation. */
    elimination_case("active_page", &p, 8, repeats, expected_nonzero);
    elimination_case("active_outside_window", &p, 96, repeats, expected_nonzero);

    REQUIRE(!uy_status(&ctx, &before) && before.state == UROV_Y_ACTIVE,
            "UY status before execution probe");
    elimination_exec_case("active_changed", &reference, repeats, expected_exec);
    if (mode == UROV_Y_MODE_PAGE_UXN || mode == UROV_Y_MODE_PAGE_AP)
        elimination_each_cpu(&reference, expected_exec, 0);
    int same_session = !uy_status(&ctx, &st) && st.state == UROV_Y_ACTIVE &&
        st.generation == before.generation && st.value == before.value &&
        st.hits == before.hits && st.replays == before.replays && st.failures == before.failures;
    REQUIRE(same_session, "UY session changed during execution probe");
    LOG("ELIM_EXEC_STATE unchanged=%d generation=%llu hits=%llu replays=%llu failures=%llu",
        same_session, (unsigned long long)st.generation, (unsigned long long)st.hits,
        (unsigned long long)st.replays, (unsigned long long)st.failures);

    before = st;
    store_case("active_changed", &p, 8, repeats, expected_store);
    store_case("active_outside_window", &p, 96, repeats, expected_store);
    elimination_bridge_case("active_changed", &p, 8, expected_cross_page);
    elimination_bridge_case("active_outside_window", &p, 96, expected_cross_page);
    if (mode == UROV_Y_MODE_PAGE_AP) elimination_each_cpu(&p, expected_store, 1);
    same_session = !uy_status(&ctx, &st) && st.state == UROV_Y_ACTIVE &&
        st.mode == before.mode && st.generation == before.generation && st.value == before.value &&
        st.hits == before.hits && st.failures == before.failures &&
        (mode == UROV_Y_MODE_PAGE_AP ? st.replays > before.replays : st.replays == before.replays);
    REQUIRE(same_session, "UY session changed during store probe");
    LOG("ELIM_STORE_STATE mode=%s preserved=%d generation=%llu hits=%llu failures=%llu "
        "replays_before=%llu replays_after=%llu",
        uy_mode_name(mode), same_session, (unsigned long long)st.generation,
        (unsigned long long)st.hits, (unsigned long long)st.failures,
        (unsigned long long)before.replays, (unsigned long long)st.replays);

    /* A detector that runs the registered business call window observes the
     * overlay: that is the feature, not a module fingerprint. Log it so the
     * report cannot hide it. */
    errno = EDOM;
    ud_observe_reader(at, p.fd, p.file_offset + p.entry + 8, uy_business_ldr, &rd);
    LOG("ELIM_FEATURE business_reader=%d direct=0x%llx reader=0x%llx file=0x%llx",
        rd.reader_diff, (unsigned long long)rd.direct_value,
        (unsigned long long)rd.reader_value, (unsigned long long)rd.file_value);
    REQUIRE(errno == EDOM && rd.reader_diff == UD_MATCH && rd.reader_value == fake,
            "UY business reader did not observe fake");

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
    elimination_case("active_after_set", &p, 8, repeats, expected_nonzero);
    REQUIRE(!uy_set_page(&ctx, generation + 1, disk), "UY SET identity errno=%d", errno);
    REQUIRE(uy_business_ldr(at) == disk, "UY identity SET not visible");
    elimination_case("active_equal_value", &p, 8, repeats, expected_nonzero);
    elimination_exec_case("active_equal_value", &reference, repeats, expected_exec);
    store_case("active_equal_value", &p, 8, repeats, expected_store);
    elimination_bridge_case("active_equal_value", &p, 8, expected_cross_page);

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
        if (mode != UROV_Y_MODE_SITE_BRK)
            REQUIRE(dirty == base_dirty && anon == base_anon,
                    "UY page mode left the page private after deactivate");
    }
    elimination_case("deactivated", &p, 8, repeats, UD_NO_MATCH);
    elimination_exec_case("deactivated", &reference, repeats, UD_NO_MATCH);
    store_case("deactivated", &p, 8, repeats, UD_NO_MATCH);
    elimination_bridge_case("deactivated", &p, 8, UD_NO_MATCH);

out:
    if (have_thread) {
        atomic_store_explicit(&business.stop, 1, memory_order_release);
        pthread_join(thread, NULL);
        REQUIRE(atomic_load(&business.errors) == 0 && atomic_load(&business.ops) > 0,
                "UY business failed");
        LOG("ELIM_BUSINESS ops=%llu errors=%d execution=original",
            (unsigned long long)atomic_load(&business.ops),
            atomic_load(&business.errors));
    }
    page_close(&reference);
    page_close(&p);
}

/* Keep the owner alive through unload. Legacy loaders need an authenticated
 * DEACTIVATE in this task before root can unload the now idle module. */
static void elimination_hold(const char *key_hex, unsigned mode, int quiesce)
{
    struct uy_ctx ctx;
    struct page p, reference;
    uint64_t generation = 0;
    uint64_t disk = 0;
    const uint8_t *at;
    unsigned base_dirty = 0, base_anon = 0;
    int restored = 0;

    if (uy_init_key(&ctx, key_hex)) { REQUIRE(0, "UY hold key missing"); return; }
    if (page_open(&p, MAP_SHARED)) { REQUIRE(0, "UY hold page errno=%d", errno); return; }
    if (uy_open_exec_reference(&reference)) {
        REQUIRE(0, "UY open executable reference errno=%d", errno);
        page_close(&p);
        return;
    }
    at = p.address + p.entry + 8U;
    (void)uy_mapping_private_kb((const void *)(uintptr_t)&uy_site_ldr, &base_dirty,
                                &base_anon);
    REQUIRE(!app_pread(p.fd, p.file_offset + p.entry + 8, (uint8_t *)&disk, 8), "UY hold pread");
    if (uy_register_page(&ctx, &p, 8, UINT64_C(0x8877665544332211), mode, &generation)) {
        page_close(&reference);
        page_close(&p);
        return;
    }
    REQUIRE(uy_business_ldr(at) == UINT64_C(0x8877665544332211), "UY hold not armed");
    elimination_exec_case("hold_active", &reference, 3,
                          mode == UROV_Y_MODE_PAGE_UXN ? UD_MATCH : UD_NO_MATCH);
    store_case("hold_active", &p, 8, 3, UD_NO_MATCH);
    LOG("ELIM_HOLD_READY pid=%d uid=%d mode=%s", getpid(), getuid(), uy_mode_name(mode));
    for (unsigned i = 0; i < 900; ++i) {
        unsigned dirty = 0, anon = 0;
        usleep(100000);
        /* Give the independent observer time to run while the owner is live. */
        if (quiesce && i == (mode == UROV_Y_MODE_SITE_BRK ? 19U : 119U)) {
            struct urov_y_request d = uy_req(UROV_Y_DEACTIVATE);

            d.session = 1;
            int rc = (int)uy_control(&ctx, UROV_Y_DEACTIVATE, &d);
            REQUIRE(!rc && d.state == UROV_Y_INACTIVE && uy_business_ldr(at) == disk,
                    "UY hold DEACTIVATE rc=%d errno=%d state=%u", rc, errno, d.state);
            if (rc) break;
            LOG("ELIM_HOLD_QUIESCED pid=%d mode=%s", getpid(), uy_mode_name(mode));
            /* No control calls during the harness's idle-module unload. */
            usleep(2000000);
        }
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
                       (mode == UROV_Y_MODE_SITE_BRK ||
                        (dirty == base_dirty && anon == base_anon));
            break;
        }
    }
    ++g_cases;
    REQUIRE(restored, "UY hold did not observe a restored site");
    if (restored) {
        elimination_exec_case("hold_restored", &reference, 3, UD_NO_MATCH);
        store_case("hold_restored", &p, 8, 3, UD_NO_MATCH);
    }
    page_close(&reference);
    page_close(&p);
}
