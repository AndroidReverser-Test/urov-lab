/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * UROV-X resident backend: a covert variant of the UROV read overlay.
 *
 * Differences from urov_backend.c, all motivated by DETECTION_RESULTS.md:
 *
 *  1. Control channel.  There is no fixed option/magic and no unauthenticated
 *     state echo.  The prctl selector words and the MAC key are derived from a
 *     per-load secret; a request without a valid SipHash-2-4 MAC never reaches
 *     the dispatcher, and the hook returns without touching the syscall, so the
 *     caller observes exactly the native -EINVAL of an unknown prctl option.
 *     The legacy __NR_kcmp channel is not installed at all.
 *
 *  2. Read-site binding.  Registration names the reader instruction PCs that
 *     are allowed to observe the fake bytes.  Every other EL0 data load of the
 *     protected page is emulated from the pinned original page, i.e. it returns
 *     the same bytes a normally readable mapping would return.  A generic
 *     "read memory, compare with the installed file" integrity scan therefore
 *     sees no divergence and the overlay still changes the return value of the
 *     designated load.
 *
 *  3. Transparent mapping lifecycle.  The VMA is not modified at all (the old
 *     code set a wrong VM_DONTCOPY constant, which surfaced as smaps rr=1).
 *     Only vm_page_prot and the leaf PTE are touched, and both are restored.
 *     mprotect/munmap/mremap/mmap(MAP_FIXED) overlapping the protected page
 *     silently end the session and then run natively; there is no -EBUSY probe.
 *
 *  4. Fail-safe for unauthorized readers.  If an unauthorized load is outside
 *     the audited decoder subset (SIMD, atomics, unknown encodings), the page is
 *     restored and the instruction is retried through the native fault path
 *     instead of raising SIGSEGV, so the overlay can never turn a legal read of
 *     the page into a crash.
 */
#include <compiler.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/compiler.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <hook.h>
#include <syscall.h>
#include <pgtable.h>

#include "decode.h"
#include "emulate.h"
#include "urov_x_abi.h"
#include "urov_x_backend.h"

/* Device BTF offsets, identical to urov_backend.c. mm is cross-checked against
 * get_task_mm() before a session is published; mm_users is only used to notice
 * that an app-owned session outlived its process. */
#define UROV_TASK_MM_OFF 1440UL
#define UROV_MM_PGD_OFF 56UL
#define UROV_MM_USERS_OFF 68UL
#ifndef __NR_mmap
#define __NR_mmap 222
#endif
#define UROV_VMA_START_OFF 0UL
#define UROV_VMA_END_OFF 8UL
#define UROV_VMA_PROT_OFF 24UL
#define UROV_VMA_FLAGS_OFF 32UL
#define UROV_VMA_FILE_OFF 136UL

#define UROV_X_USER_LIMIT (1ULL << 52)

#define UROV_VM_READ 0x00000001UL
#define UROV_VM_WRITE 0x00000002UL
#define UROV_VM_EXEC 0x00000004UL
#define UROV_VM_MAYWRITE 0x00000020UL
#define UROV_VM_PFNMAP 0x00000400UL
#define UROV_VM_IO 0x00002000UL
#define UROV_VM_HUGETLB 0x00400000UL
#define UROV_VM_MIXEDMAP 0x10000000UL

#define UROV_SIGSEGV 11
#define UROV_SEGV_ACCERR 2

#define UX_OFF 0
#define UX_LIVE 1

/* Fine-grained retry bound for the seqlock snapshot. */
#define UROV_FAKE_RETRY 1000000U
/* Bounded spin for the control lock taken from fault / syscall-hook context. */
#define UROV_CTRL_SPIN 1000000UL

_Static_assert(UROV_X_FAKE_MAX == URO_FAKE_MAX, "UAPI and core fake widths");

typedef void *(*get_task_mm_t)(void *task);
typedef void (*mmput_t)(void *mm);
typedef void *(*find_vma_t)(void *mm, unsigned long addr);
typedef long (*pin_user_t)(unsigned long start, unsigned long nr_pages, void **pages, unsigned int flags);
typedef void (*unpin_user_t)(void *page);
typedef void (*mmap_write_lock_t)(void *mm);
typedef void (*mmap_write_unlock_t)(void *mm);
typedef void (*flush_tlb_mm_t)(void *mm);
typedef void (*force_sig_fault_t)(int sig, int code, void *addr);
typedef long (*copy_nofault_t)(void *dst, const void *src, unsigned long n);

extern uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

struct ux_session {
    void *mm;
    void *page;
    uint64_t base;
    uint64_t pte_saved;
    uint64_t pte_protected;
    uint64_t prot_saved;
    uint64_t fake[4];
    uint64_t sites[UROV_X_MAX_SITES];
    uint64_t generation;
    uint64_t hits;
    uint64_t failures;
    uint32_t overlay_offset;
    uint32_t overlay_len;
    uint32_t site_count;
    uint32_t fake_seq;
    uint8_t original[UROV_X_PAGE];
} __attribute__((aligned(64)));

static struct ux_session g_sess;
static uint8_t g_selftest_ws[UROV_X_PAGE];
static int g_state;          /* UX_OFF or UX_LIVE */
static int g_handlers;
static int g_ctrl_busy;
static int g_ready;
static int g_verbose;
static volatile uint32_t g_failure_logged;
static struct urov_x_keys g_keys;

static void *f_do_mem_abort;
static get_task_mm_t f_get_task_mm;
static mmput_t f_mmput;
static find_vma_t f_find_vma;
static mmap_write_lock_t f_mmap_write_lock;
static mmap_write_unlock_t f_mmap_write_unlock;
static flush_tlb_mm_t f_flush_tlb_mm;
static pin_user_t f_pin_user;
static unpin_user_t f_unpin_user;
static force_sig_fault_t f_force_sig_fault;
static copy_nofault_t f_copy_in, f_copy_out;

static int g_abort_hooked;
static int g_prctl_hooked;
static int g_clone_hooked;
static int g_clone3_hooked;
static int g_wrapper_mode;
/* >0 while a fork/clone-with-copy is in flight: the protected page has been
 * temporarily restored so the child's copied PTE and VMA are native. */
static int g_suspend_depth;

#define UX_GATE_NUM 4
static int g_gate_hooked[UX_GATE_NUM];

/* --------------------------------------------------------------- utilities */

static int prefix(const char *text, const char *head, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (!text[i] || text[i] != head[i]) return 0;
    return 1;
}

static void *mm_of_task(void *task)
{
    return *(void **)((char *)task + UROV_TASK_MM_OFF);
}

static uint64_t mm_pgd(void *mm)
{
    return *(uint64_t *)((char *)mm + UROV_MM_PGD_OFF);
}

static int mm_has_live_user(void *mm)
{
    int users;
    if (!mm) return 0;
    users = __atomic_load_n((int *)((char *)mm + UROV_MM_USERS_OFF), __ATOMIC_ACQUIRE);
    return users > 1;
}

static uint64_t *pte_of(void *mm, uint64_t address)
{
    uint64_t pgd = mm_pgd(mm);
    if (!pgd) return 0;
    return pgtable_entry(pgd, address);
}

static int ctrl_try_lock(void)
{
    int expected = 0;
    return __atomic_compare_exchange_n(&g_ctrl_busy, &expected, 1, 0,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static void ctrl_unlock(void)
{
    __atomic_store_n(&g_ctrl_busy, 0, __ATOMIC_RELEASE);
}

/* Sleepable paths (control syscalls, mapping gates, unload) wait for the very
 * short control section instead of failing the operation. */
static int ctrl_lock_wait(void)
{
    unsigned long i;
    for (i = 0; i < UROV_CTRL_SPIN; ++i) {
        if (ctrl_try_lock()) return 1;
        __asm__ volatile("yield" ::: "memory");
    }
    return 0;
}

static int overlay_live(void)
{
    return __atomic_load_n(&g_state, __ATOMIC_ACQUIRE) == UX_LIVE;
}

static int session_owned(void)
{
    return overlay_live() && mm_of_task(current) == g_sess.mm;
}

static unsigned request_fake_len(const struct urov_x_request *q)
{
    return q->length ? q->length : 8U;
}

static void request_fake_words(const struct urov_x_request *q, uint64_t words[4])
{
    words[0] = q->value;
    words[1] = q->value_hi[0];
    words[2] = q->value_hi[1];
    words[3] = q->value_hi[2];
}

static void fake_publish(const uint64_t words[4])
{
    uint32_t seq = __atomic_load_n(&g_sess.fake_seq, __ATOMIC_RELAXED);

    __atomic_store_n(&g_sess.fake_seq, seq + 1U, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    g_sess.fake[0] = words[0];
    g_sess.fake[1] = words[1];
    g_sess.fake[2] = words[2];
    g_sess.fake[3] = words[3];
    __atomic_store_n(&g_sess.fake_seq, seq + 2U, __ATOMIC_RELEASE);
}

static int fake_snapshot(uint64_t words[4], unsigned *len)
{
    unsigned tries;
    for (tries = 0; tries < UROV_FAKE_RETRY; ++tries) {
        uint32_t seq = __atomic_load_n(&g_sess.fake_seq, __ATOMIC_ACQUIRE);
        if (seq & 1U) {
            __asm__ volatile("yield" ::: "memory");
            continue;
        }
        words[0] = __atomic_load_n(&g_sess.fake[0], __ATOMIC_RELAXED);
        words[1] = __atomic_load_n(&g_sess.fake[1], __ATOMIC_RELAXED);
        words[2] = __atomic_load_n(&g_sess.fake[2], __ATOMIC_RELAXED);
        words[3] = __atomic_load_n(&g_sess.fake[3], __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&g_sess.fake_seq, __ATOMIC_RELAXED) == seq) {
            *len = g_sess.overlay_len;
            return 0;
        }
    }
    return -EAGAIN;
}

static int site_match(uint64_t pc)
{
    uint32_t n = g_sess.site_count;
    uint32_t i;
    if (n > UROV_X_MAX_SITES) return 0;
    for (i = 0; i < n; ++i)
        if (g_sess.sites[i] == pc) return 1;
    return 0;
}

static void session_count_failure(uint64_t far, uint64_t esr, uint32_t opcode, int result)
{
    uint32_t seen;
    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    if (!g_verbose) return;
    seen = __atomic_load_n(&g_failure_logged, __ATOMIC_RELAXED);
    if (seen < 8 && __atomic_compare_exchange_n(&g_failure_logged, &seen, seen + 1, 0,
                                                __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        pr_info("urov-x: emulation failure far=%llx esr=%llx opcode=%x result=%d\n",
                (unsigned long long)far, (unsigned long long)esr, opcode, result);
}

/* ------------------------------------------------------------- VMA / PTE */

/* Exactly one page, read-only executable file mapping. Writable, COW, PFN,
 * device and special mappings stay rejected so the pinned page is the page the
 * PTE refers to. The VMA flags are never modified. */
static long validate_vma(void *vma, uint64_t address)
{
    unsigned long start, end, flags;
    void *file;
    if (!vma) return -EFAULT;
    start = *(unsigned long *)((char *)vma + UROV_VMA_START_OFF);
    end = *(unsigned long *)((char *)vma + UROV_VMA_END_OFF);
    flags = *(unsigned long *)((char *)vma + UROV_VMA_FLAGS_OFF);
    file = *(void **)((char *)vma + UROV_VMA_FILE_OFF);
    if (start != address || end != address + UROV_X_PAGE) return -EINVAL;
    if ((flags & (UROV_VM_READ | UROV_VM_EXEC)) != (UROV_VM_READ | UROV_VM_EXEC))
        return -EINVAL;
    if (flags & (UROV_VM_WRITE | UROV_VM_MAYWRITE | UROV_VM_PFNMAP |
                 UROV_VM_HUGETLB | UROV_VM_IO | UROV_VM_MIXEDMAP))
        return -EINVAL;
    if (!file) return -EINVAL;
    return 0;
}

/* Restore the VMA protection template and the one leaf permission bit. Runs
 * with the target mm's write lock held. */
static void restore_page(void *mm, uint64_t address, uint64_t prot_saved)
{
    uint64_t *ptep;
    uint64_t pte;
    void *vma;
    uint64_t pgd;

    if (!mm) return;
    pgd = mm_pgd(mm);
    if (!pgd) return;
    vma = f_find_vma(mm, address);
    if (vma && *(unsigned long *)((char *)vma + UROV_VMA_START_OFF) == address &&
        *(unsigned long *)((char *)vma + UROV_VMA_END_OFF) == address + UROV_X_PAGE)
        *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF) = prot_saved;
    ptep = pgtable_entry(pgd, address);
    if (!ptep) return;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (pte & 1ULL)
        __atomic_store_n(ptep, pte | PTE_USER, __ATOMIC_RELEASE);
}

/* Wait for handlers that already matched the session. They are pure and
 * bounded, so a short yield loop is enough. */
static void drain_handlers(void)
{
    unsigned long spins = 0;
    while (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE) && spins++ < 100000000UL)
        __asm__ volatile("yield" ::: "memory");
}

/* End the session and release its references. Must be called with the control
 * lock held (or from module exit) and is idempotent. */
static void release_session(void)
{
    void *mm;
    uint64_t base, prot;

    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UX_LIVE) return;
    mm = g_sess.mm;
    base = g_sess.base;
    prot = g_sess.prot_saved;

    if (mm) {
        f_mmap_write_lock(mm);
        restore_page(mm, base, prot);
        f_flush_tlb_mm(mm);
        f_mmap_write_unlock(mm);
    }
    /* No new fault can be produced from the page after the flush. In-flight
     * handlers only read the still allocated session object. */
    __atomic_store_n(&g_state, UX_OFF, __ATOMIC_RELEASE);
    g_suspend_depth = 0;
    drain_handlers();
    if (g_sess.page) {
        f_unpin_user(g_sess.page);
        g_sess.page = 0;
    }
    if (mm) f_mmput(mm);
    memset(&g_sess, 0, sizeof(g_sess));
}

/* Reap a session whose owner process (and therefore every thread of it) is
 * gone. Called from sleepable control paths only. */
static void reap_dead_session(void)
{
    if (overlay_live() && !mm_has_live_user(g_sess.mm))
        release_session();
}

/* ------------------------------------------------------------ fault handler */

static void commit_model(struct pt_regs *regs, const struct uro_regs *model)
{
    int i;
    for (i = 0; i < 31; ++i) regs->regs[i] = model->x[i];
    regs->sp = model->sp;
    regs->pc = model->pc;
}

/* An unauthorized reader hit an instruction we cannot emulate. Instead of
 * raising SIGSEGV (which a detector could look for), end the session, restore
 * the page and let the native fault path retry the instruction. */
static void unauthorized_fallback(void)
{
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
    if (ctrl_lock_wait()) {
        if (overlay_live()) release_session();
        ctrl_unlock();
    }
}

static void ux_abort_before(hook_fargs4_t *args, void *udata)
{
    uint64_t far = args->arg0;
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    struct uro_view view;
    struct uro_regs model;
    uint64_t fake_words[4];
    unsigned fake_len = 0;
    uint32_t opcode;
    int result, i, authorized;

    (void)udata;
    if (!overlay_live()) return;
    if (!regs || compat_user_mode(regs)) return;
    /* EL0 data abort, read, permission fault at the 4K leaf. */
    if (((esr >> 26) & 0x3fUL) != 0x24UL || (esr & (1UL << 6)) ||
        (esr & 0x3fUL) != 15UL) return;
    if (mm_of_task(current) != g_sess.mm || far < g_sess.base ||
        far - g_sess.base >= UROV_X_PAGE) return;

    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (!overlay_live() || mm_of_task(current) != g_sess.mm ||
        far < g_sess.base || far - g_sess.base >= UROV_X_PAGE) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }

    authorized = site_match(regs->pc);

    if (regs->pc >= g_sess.base && regs->pc - g_sess.base <= UROV_X_PAGE - 4U) {
        uint64_t at = regs->pc - g_sess.base;
        opcode = (uint32_t)g_sess.original[at] |
                 ((uint32_t)g_sess.original[at + 1] << 8) |
                 ((uint32_t)g_sess.original[at + 2] << 16) |
                 ((uint32_t)g_sess.original[at + 3] << 24);
    } else if (f_copy_in(&opcode, (const void *)regs->pc, sizeof(opcode))) {
        session_count_failure(far, esr, 0, -EFAULT);
        if (authorized) {
            if (f_force_sig_fault) f_force_sig_fault(UROV_SIGSEGV, UROV_SEGV_ACCERR, (void *)far);
            args->ret = 0;
            args->skip_origin = 1;
            __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        } else {
            unauthorized_fallback();
        }
        return;
    }

    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = regs->pc;
    model.pstate = regs->pstate;

    view.original = g_sess.original;
    view.base = g_sess.base;
    view.user_limit = UROV_X_USER_LIMIT;
    view.overlay_offset = g_sess.overlay_offset;
    view.overlay_len = g_sess.overlay_len;
    if (authorized) {
        if (fake_snapshot(fake_words, &fake_len)) {
            session_count_failure(far, esr, opcode, -EAGAIN);
            if (f_force_sig_fault) f_force_sig_fault(UROV_SIGSEGV, UROV_SEGV_ACCERR, (void *)far);
            args->ret = 0;
            args->skip_origin = 1;
            __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
            return;
        }
        view.overlay_len = fake_len;
        view.fake = (const uint8_t *)fake_words;
    } else {
        /* Same window, same length, but the "fake" bytes are the pinned
         * original bytes: the emulation is bit-for-bit a native read. */
        view.fake = g_sess.original + g_sess.overlay_offset;
    }

    result = uro_emulate(&view, opcode, esr, far, &model);
    if (result == URO_OK) {
        commit_model(regs, &model);
        __atomic_fetch_add(&g_sess.hits, 1, __ATOMIC_RELAXED);
        args->ret = 0;
        args->skip_origin = 1;
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }

    if (!authorized) {
        unauthorized_fallback();
        return;
    }
    /* A configured read site that cannot be emulated must fail closed: never
     * return the original bytes as if the overlay had applied. */
    session_count_failure(far, esr, opcode, result);
    if (f_force_sig_fault) f_force_sig_fault(UROV_SIGSEGV, UROV_SEGV_ACCERR, (void *)far);
    args->ret = 0;
    args->skip_origin = 1;
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------------- control ops */

static int site_ok(uint64_t site)
{
    uint32_t opcode;
    struct uro_regs regs;
    struct uro_load load;

    if ((site & 3ULL) || site < UROV_X_PAGE || site >= UROV_X_USER_LIMIT) return 0;
    if (f_copy_in(&opcode, (const void *)site, sizeof(opcode))) return 0;
    memset(&regs, 0, sizeof(regs));
    regs.pc = site;
    return uro_decode(opcode, &regs, &load) == 0;
}

static long do_register(struct urov_x_request *q)
{
    void *task = current;
    void *mm;
    void *vma;
    void *page = 0;
    uint64_t *ptep;
    uint64_t pte, newpte;
    uint64_t words[4];
    unsigned len = request_fake_len(q);
    unsigned i;
    long pinned;
    long ret;

    if (q->reserved) return -EINVAL;
    if (q->site_count == 0U || q->site_count > UROV_X_MAX_SITES) return -EINVAL;
    if (q->address & (UROV_X_PAGE - 1)) return -EINVAL;
    if (q->address < UROV_X_PAGE || q->address >= UROV_X_USER_LIMIT) return -EINVAL;
    if (len < 8U || len > UROV_X_FAKE_MAX || (len & 7U)) return -EINVAL;
    if (q->offset > UROV_X_PAGE - len) return -EINVAL;
    for (i = 0; i < q->site_count; ++i)
        if (!site_ok(q->sites[i])) return -EINVAL;
    if (overlay_live()) return -EBUSY;
    drain_handlers();
    if (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE)) return -EBUSY;

    mm = f_get_task_mm(task);
    if (!mm) return -EOPNOTSUPP;
    if (mm_of_task(task) != mm) {
        f_mmput(mm);
        return -EOPNOTSUPP;
    }
    if (!mm_has_live_user(mm)) {
        f_mmput(mm);
        return -EOPNOTSUPP;
    }

    pinned = f_pin_user(q->address, 1, &page, 0);
    if (pinned != 1 || !page) {
        f_mmput(mm);
        return -EFAULT;
    }

    f_mmap_write_lock(mm);
    vma = f_find_vma(mm, q->address);
    ret = validate_vma(vma, q->address);
    if (ret) goto unlock;
    ptep = pte_of(mm, q->address);
    if (!ptep) { ret = -EFAULT; goto unlock; }
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (!(pte & 1ULL) || (pte & 3ULL) != 3ULL || !(pte & PTE_USER) ||
        !(pte & PTE_RDONLY) || (pte & PTE_UXN) || (pte & PTE_CONT) ||
        (pte & PTE_SPECIAL)) {
        ret = -EOPNOTSUPP;
        goto unlock;
    }
    if (f_copy_in(g_sess.original, (const void *)q->address, UROV_X_PAGE)) {
        ret = -EFAULT;
        goto unlock;
    }
    g_sess.mm = mm;
    g_sess.page = page;
    g_sess.base = q->address;
    g_sess.overlay_offset = q->offset;
    g_sess.overlay_len = len;
    g_sess.pte_saved = pte;
    g_sess.prot_saved = *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF);
    for (i = 0; i < q->site_count; ++i) g_sess.sites[i] = q->sites[i];
    g_sess.site_count = q->site_count;
    request_fake_words(q, words);
    g_sess.fake[0] = words[0];
    g_sess.fake[1] = words[1];
    g_sess.fake[2] = words[2];
    g_sess.fake[3] = words[3];
    g_sess.fake_seq = 0;
    g_sess.generation = 1;
    g_sess.hits = 0;
    g_sess.failures = 0;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);

    /* Publish the complete session before the page can fault. vm_page_prot keeps
     * a rebuilt PTE non-readable at EL0, but no VMA flag is changed, so maps
     * and smaps report the ordinary r-x/-s mapping. */
    g_sess.pte_protected = (pte & ~(uint64_t)PTE_USER) | PTE_AF;
    *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF) = g_sess.prot_saved & ~(uint64_t)PTE_USER;
    __atomic_store_n(&g_state, UX_LIVE, __ATOMIC_RELEASE);
    newpte = g_sess.pte_protected;
    __atomic_store_n(ptep, newpte, __ATOMIC_RELEASE);
    f_flush_tlb_mm(mm);
    ret = 0;
    q->session = 1;
    q->generation = 1;
    q->offset = g_sess.overlay_offset;
    q->length = len;
    q->value = words[0];
    q->value_hi[0] = words[1];
    q->value_hi[1] = words[2];
    q->value_hi[2] = words[3];
    q->state = UROV_X_ACTIVE;
    f_mmap_write_unlock(mm);
    return 0;
unlock:
    f_mmap_write_unlock(mm);
    if (page) f_unpin_user(page);
    f_mmput(mm);
    return ret;
}

static long do_set(struct urov_x_request *q)
{
    uint64_t words[4];
    unsigned len;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    len = request_fake_len(q);
    if (len != g_sess.overlay_len) return -EINVAL;
    request_fake_words(q, words);
    fake_publish(words);
    g_sess.generation++;
    q->generation = g_sess.generation;
    q->offset = g_sess.overlay_offset;
    q->length = len;
    q->value = words[0];
    q->value_hi[0] = words[1];
    q->value_hi[1] = words[2];
    q->value_hi[2] = words[3];
    q->state = UROV_X_ACTIVE;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

static long do_status(struct urov_x_request *q, int with_counters)
{
    if (!session_owned() || q->session != 1) {
        /* No ownership hint for any other mm: a foreign caller cannot tell an
         * idle module from one that serves somebody else. */
        q->session = 0;
        q->generation = 0;
        q->offset = 0;
        q->length = 0;
        q->value = 0;
        q->value_hi[0] = 0;
        q->value_hi[1] = 0;
        q->value_hi[2] = 0;
        q->site_count = 0;
        q->hits = 0;
        q->failures = 0;
        q->state = UROV_X_INACTIVE;
        return 0;
    }
    q->generation = g_sess.generation;
    q->offset = g_sess.overlay_offset;
    q->length = g_sess.overlay_len;
    q->value = g_sess.fake[0];
    q->value_hi[0] = g_sess.fake[1];
    q->value_hi[1] = g_sess.fake[2];
    q->value_hi[2] = g_sess.fake[3];
    q->site_count = g_sess.site_count;
    q->hits = with_counters ? __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED) : 0;
    q->failures = with_counters ? __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED) : 0;
    q->state = UROV_X_ACTIVE;
    return 0;
}

static long do_deactivate(struct urov_x_request *q)
{
    if (q->session != 1 && q->session != 0) return -ENOENT;
    if (overlay_live() && !session_owned()) return -ENOENT;
    release_session();
    q->session = 0;
    q->generation = 0;
    q->offset = 0;
    q->length = 0;
    q->value = 0;
    q->value_hi[0] = 0;
    q->value_hi[1] = 0;
    q->value_hi[2] = 0;
    q->site_count = 0;
    q->hits = 0;
    q->failures = 0;
    q->state = UROV_X_INACTIVE;
    return 0;
}

static long dispatch(struct urov_x_request *q, unsigned cmd)
{
    long ret;

    if (!g_ready) return -EOPNOTSUPP;
    if (!ctrl_try_lock()) return -EBUSY;
    reap_dead_session();
    switch (cmd) {
    case UROV_X_QUERY: ret = do_status(q, 0); break;
    case UROV_X_REGISTER: ret = do_register(q); break;
    case UROV_X_SET: ret = do_set(q); break;
    case UROV_X_STATUS: ret = do_status(q, 1); break;
    case UROV_X_DEACTIVATE: ret = do_deactivate(q); break;
    default: ret = -EINVAL; break;
    }
    ctrl_unlock();
    return ret;
}

/* ------------------------------------------------------- control channel */

static uint64_t sys_arg(hook_fargs6_t *args, int n)
{
    if (g_wrapper_mode) {
        struct pt_regs *regs = (struct pt_regs *)args->arg0;
        return regs ? regs->regs[n] : 0;
    }
    return args->args[n];
}

static void ux_prctl_before(hook_fargs6_t *args, void *udata)
{
    struct urov_x_request q;
    void *user;
    unsigned long size;
    unsigned cmd;
    long ret;

    (void)udata;
    /* No fixed selector: both words come from the per-load secret. A caller
     * without the secret falls through to the untouched native syscall, which
     * returns -EINVAL exactly as if this module were not loaded. */
    if ((uint32_t)sys_arg(args, 0) != (uint32_t)g_keys.option) return;
    if (sys_arg(args, 1) != g_keys.magic) return;
    user = (void *)sys_arg(args, 3);
    size = (unsigned long)sys_arg(args, 4);
    cmd = (unsigned)sys_arg(args, 2);
    if (!user || size != sizeof(q)) return;
    if (f_copy_in(&q, user, sizeof(q))) return;
    if (q.size != sizeof(q) || q.version != UROV_X_ABI_VERSION ||
        q.op != (uint16_t)cmd) return;
    if (q.mac != urov_x_request_mac(g_keys.mac, &q)) return;
    ret = dispatch(&q, cmd);
    if (f_copy_out(user, &q, sizeof(q))) ret = -EFAULT;
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* Re-enable the EL0 data-read fault after a fork window. Runs with the mm
 * write lock held. */
static void reprotect_locked(void *mm)
{
    uint64_t *ptep;
    uint64_t pte;
    void *vma;

    vma = f_find_vma(mm, g_sess.base);
    if (!vma || *(unsigned long *)((char *)vma + UROV_VMA_START_OFF) != g_sess.base ||
        *(unsigned long *)((char *)vma + UROV_VMA_END_OFF) != g_sess.base + UROV_X_PAGE)
        return;
    *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF) = g_sess.prot_saved & ~(uint64_t)PTE_USER;
    ptep = pte_of(mm, g_sess.base);
    if (!ptep) return;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (!(pte & 1ULL)) return;
    __atomic_store_n(ptep, (pte & ~(uint64_t)PTE_USER) | PTE_AF, __ATOMIC_RELEASE);
}

/* A fork copies the VMA and its PTE. Without this window the child would
 * inherit a page that faults for data reads but has no session of its own,
 * which would recirculate through the native fault path. The parent's page is
 * native for the duration of the clone syscall, so the child gets a normal
 * mapping; the overlay is re-established when the syscall returns. */
static int suspend_overlay(void)
{
    int took = 0;

    if (!overlay_live()) return 0;
    if (mm_of_task(current) != g_sess.mm) return 0;
    if (!ctrl_lock_wait()) return 0;
    if (overlay_live() && mm_of_task(current) == g_sess.mm) {
        if (g_suspend_depth == 0) {
            void *mm = g_sess.mm;
            uint64_t base = g_sess.base;
            uint64_t prot = g_sess.prot_saved;
            f_mmap_write_lock(mm);
            restore_page(mm, base, prot);
            f_flush_tlb_mm(mm);
            f_mmap_write_unlock(mm);
        }
        g_suspend_depth++;
        took = 1;
    }
    ctrl_unlock();
    return took;
}

static void resume_overlay(void)
{
    if (!ctrl_lock_wait()) return;
    if (!g_suspend_depth) {
        ctrl_unlock();
        return;
    }
    g_suspend_depth--;
    if (g_suspend_depth == 0 && overlay_live() && mm_of_task(current) == g_sess.mm) {
        void *mm = g_sess.mm;
        f_mmap_write_lock(mm);
        reprotect_locked(mm);
        f_flush_tlb_mm(mm);
        f_mmap_write_unlock(mm);
    }
    ctrl_unlock();
}

#define UROV_CLONE_VM 0x00000100ULL

static void ux_clone_before(hook_fargs6_t *args, void *udata)
{
    /* Per-invocation flag consumed by the matching after callback; never rely
     * on the transit frame being zeroed. */
    args->local.data0 = 0;
    if (udata) {
        uint64_t flags = 0;
        /* If clone_args cannot be read the syscall will fail; suspending is
         * harmless, so treat it as a copying clone. */
        if (!f_copy_in(&flags, (const void *)sys_arg(args, 0), sizeof(flags)) &&
            (flags & UROV_CLONE_VM))
            return;
    } else if (sys_arg(args, 0) & UROV_CLONE_VM) {
        return;
    }
    if (suspend_overlay()) args->local.data0 = 1;
}

static void ux_clone_after(hook_fargs6_t *args, void *udata)
{
    (void)udata;
    if (!args->local.data0) return;
    args->local.data0 = 0;
    resume_overlay();
}

/* ---------------------------------------------------------- mapping gates */

enum ux_gate_kind {
    UX_GATE_MPROTECT,
    UX_GATE_MUNMAP,
    UX_GATE_MREMAP,
    UX_GATE_MMAP,
};

static const int g_gate_nrs[UX_GATE_NUM] = {
    __NR_mprotect, __NR_munmap, __NR_mremap, __NR_mmap,
};

/* A mapping change that overlaps the protected page silently ends the session
 * and then runs natively. This removes the former -EBUSY probe (a mapping
 * operation that behaves differently only while the module is active). */
static void ux_gate_before(hook_fargs6_t *args, void *udata)
{
    uint64_t start, len, end, base;
    int kind = (int)(uintptr_t)udata;

    if (!overlay_live()) return;
    if (kind == UX_GATE_MMAP && !(sys_arg(args, 3) & 0x10ULL)) return;
    if (mm_of_task(current) != g_sess.mm) return;
    start = sys_arg(args, 0);
    len = sys_arg(args, 1);
    if (!len) return;
    end = start + len;
    if (end < start) end = ~0ULL;
    base = g_sess.base;
    if (end <= base || start >= base + UROV_X_PAGE) return;
    if (ctrl_lock_wait()) {
        release_session();
        ctrl_unlock();
    }
}

/* -------------------------------------------------------------------- init */

static void *lookup(const char *name)
{
    return (void *)kallsyms_lookup_name(name);
}

static long parse_args(const char *args, uint8_t key[16], int *have_key)
{
    const char *p = args;

    while (p && *p) {
        const char *v;
        unsigned n = 0;
        while (*p == ' ') ++p;
        if (!*p) break;
        if (prefix(p, "key=", 4)) {
            v = p + 4;
            while (v[n] && v[n] != ' ') ++n;
            if (urov_x_parse_key(v, n, key)) return -EINVAL;
            *have_key = 1;
        } else if (prefix(p, "verbose", 7) && (p[7] == 0 || p[7] == ' ')) {
            g_verbose = 1;
        } else {
            return -EINVAL;
        }
        while (*p && *p != ' ') ++p;
    }
    return 0;
}

long urov_x_backend_init(const char *args)
{
    uint8_t key[16];
    int have_key = 0;
    unsigned int checks = 0;
    long ret;
    int i;

    memset(key, 0, sizeof(key));
    ret = parse_args(args, key, &have_key);
    if (ret) return ret;
    if (!have_key) return -EINVAL;
    urov_x_derive(key, &g_keys);
    memset(key, 0, sizeof(key));

    if (!kallsyms_lookup_name) return -ENOSYS;
    if (uro_core_selftest(g_selftest_ws, &checks) || checks != URO_CORE_CHECKS) return -EINVAL;

    f_do_mem_abort = lookup("do_mem_abort");
    f_get_task_mm = (get_task_mm_t)lookup("get_task_mm");
    f_mmput = (mmput_t)lookup("mmput");
    f_find_vma = (find_vma_t)lookup("find_vma");
    f_mmap_write_lock = (mmap_write_lock_t)lookup("mmap_write_lock");
    f_mmap_write_unlock = (mmap_write_unlock_t)lookup("mmap_write_unlock");
    f_flush_tlb_mm = (flush_tlb_mm_t)lookup("flush_tlb_mm");
    f_pin_user = (pin_user_t)lookup("pin_user_pages_unlocked");
    f_unpin_user = (unpin_user_t)lookup("unpin_user_page");
    f_force_sig_fault = (force_sig_fault_t)lookup("force_sig_fault");
    f_copy_in = (copy_nofault_t)lookup("copy_from_user_nofault");
    f_copy_out = (copy_nofault_t)lookup("copy_to_user_nofault");
    g_wrapper_mode = has_syscall_wrapper ? 1 : 0;

    if (!f_do_mem_abort || !f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_flush_tlb_mm ||
        !f_pin_user || !f_unpin_user || !f_force_sig_fault ||
        !f_copy_in || !f_copy_out)
        return -EOPNOTSUPP;

    ret = hook_wrap(f_do_mem_abort, 3, ux_abort_before, 0, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-x: hook do_mem_abort failed: %ld\n", ret);
        return -EOPNOTSUPP;
    }
    g_abort_hooked = 1;

    /* The per-syscall function-pointer hook is used deliberately: the global
     * syscall dispatcher gates its callbacks on the caller's uid (su allowlist),
     * so hook_syscalln() would never run for an untrusted app. */
    ret = fp_hook_syscalln(__NR_prctl, 6, ux_prctl_before, 0, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-x: hook prctl failed: %ld\n", ret);
        goto unwind_abort;
    }
    g_prctl_hooked = 1;

    for (i = 0; i < UX_GATE_NUM; ++i) {
        ret = fp_hook_syscalln(g_gate_nrs[i], 6, ux_gate_before, 0, (void *)(uintptr_t)i);
        if (ret) {
            if (g_verbose) pr_info("urov-x: hook gate %d failed: %ld\n", g_gate_nrs[i], ret);
            break;
        }
        g_gate_hooked[i] = 1;
    }
    if (i != UX_GATE_NUM) {
        while (i-- > 0) {
            fp_unhook_syscalln(g_gate_nrs[i], ux_gate_before, 0);
            g_gate_hooked[i] = 0;
        }
        if (g_prctl_hooked) {
            fp_unhook_syscalln(__NR_prctl, ux_prctl_before, 0);
            g_prctl_hooked = 0;
        }
        goto unwind_abort;
    }

    /* Optional: keep fork children free of an inherited protected page. Both
     * hooks are best effort; a failure only leaves the old inheritance caveat. */
    ret = fp_hook_syscalln(__NR_clone, 6, ux_clone_before, ux_clone_after, (void *)0);
    g_clone_hooked = ret ? 0 : 1;
#ifdef __NR_clone3
    ret = fp_hook_syscalln(__NR_clone3, 6, ux_clone_before, ux_clone_after, (void *)1);
    g_clone3_hooked = ret ? 0 : 1;
#endif

    g_ready = 1;
    if (g_verbose) pr_info("urov-x: backend ready\n");
    return 0;

unwind_abort:
    if (g_abort_hooked) {
        hook_unwrap(f_do_mem_abort, ux_abort_before, 0);
        g_abort_hooked = 0;
    }
    return -EOPNOTSUPP;
}

long urov_x_backend_exit(void)
{
    int i;

    g_ready = 0;
    if (ctrl_lock_wait()) {
        release_session();
        ctrl_unlock();
    }
    for (i = 0; i < UX_GATE_NUM; ++i) {
        if (!g_gate_hooked[i]) continue;
        fp_unhook_syscalln(g_gate_nrs[i], ux_gate_before, 0);
        g_gate_hooked[i] = 0;
    }
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, ux_prctl_before, 0);
        g_prctl_hooked = 0;
    }
    if (g_clone3_hooked) {
        fp_unhook_syscalln(__NR_clone3, ux_clone_before, ux_clone_after);
        g_clone3_hooked = 0;
    }
    if (g_clone_hooked) {
        fp_unhook_syscalln(__NR_clone, ux_clone_before, ux_clone_after);
        g_clone_hooked = 0;
    }
    if (g_abort_hooked) {
        hook_unwrap(f_do_mem_abort, ux_abort_before, 0);
        g_abort_hooked = 0;
    }
    memset(&g_keys, 0, sizeof(g_keys));
    return 0;
}

void urov_x_status_get(struct ux_status *out)
{
    if (!out) return;
    out->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    out->active = overlay_live() ? 1U : 0U;
    out->sites = overlay_live() ? g_sess.site_count : 0U;
    out->hooks = (g_abort_hooked ? 1U : 0U) | (g_prctl_hooked ? 2U : 0U) |
                 ((g_gate_hooked[0] && g_gate_hooked[1] && g_gate_hooked[2] &&
                   g_gate_hooked[3]) ? 4U : 0U) |
                 (g_clone_hooked ? 8U : 0U) | (g_clone3_hooked ? 16U : 0U);
    out->core_checks = URO_CORE_CHECKS;
}
