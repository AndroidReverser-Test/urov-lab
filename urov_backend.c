/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resident UROV backend, linked into the loadable KPM itself.
 *
 * The module installs its own kernel entry points instead of relying on a
 * patched host kernel:
 *   - do_mem_abort(): intercepts the EL0 read permission fault produced by
 *     clearing PTE.AP[1] (raw execute-only mapping), emulates the faulting
 *     general-purpose load and returns the overlaid bytes.
 *   - __NR_kcmp: control channel. The test process passes a 128-byte request;
 *     normal kcmp calls (different magic) are left untouched.
 *   - mprotect/munmap/mremap/madvise: reject range changes that would break the
 *     registered mapping while a session is active.
 *
 * Only the calling process's own mm can be registered. One session exists at a
 * time; registration, update, status and deactivation are serialized by a
 * single control flag, while the fault path is lock-free and allocation-free.
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
#include "urov_abi.h"
#include "urov_backend.h"

/* Offsets from the matching device BTF (see DESIGN.md section 4.1). The mm
 * pointer is cross-checked against get_task_mm(current) before a session is
 * published; a mismatch refuses registration instead of guessing. */
#define UROV_TASK_MM_OFF 1440UL
#define UROV_MM_PGD_OFF 56UL
/* asm-generic only maps __NR_mmap under __BITS_PER_LONG == 64. */
#ifndef __NR_mmap
#define __NR_mmap 222
#endif
#define UROV_VMA_START_OFF 0UL
#define UROV_VMA_END_OFF 8UL
#define UROV_VMA_PROT_OFF 24UL
#define UROV_VMA_FLAGS_OFF 32UL
#define UROV_VMA_PGOFF_OFF 128UL
#define UROV_VMA_FILE_OFF 136UL

#define UROV_USER_LIMIT (1ULL << 52)

#define UROV_VM_READ 0x00000001UL
#define UROV_VM_WRITE 0x00000002UL
#define UROV_VM_EXEC 0x00000004UL
#define UROV_VM_MAYWRITE 0x00000020UL
#define UROV_VM_MAYSHARE 0x00000080UL
#define UROV_VM_PFNMAP 0x00000400UL
#define UROV_VM_IO 0x00002000UL
#define UROV_VM_HUGETLB 0x00400000UL
#define UROV_VM_MIXEDMAP 0x10000000UL
#define UROV_VM_DONTCOPY 0x00010000UL

#define UROV_SIGSEGV 11
#define UROV_SEGV_ACCERR 2

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

struct urov_session {
    void *mm;
    void *page;
    uint64_t base;
    uint64_t pte_saved;
    uint64_t prot_saved;
    uint64_t flags_saved;
    uint64_t fake;
    uint64_t generation;
    uint64_t hits;
    uint64_t failures;
    uint32_t overlay_offset;
    uint32_t pad;
    uint8_t original[UROV_PAGE_BYTES];
} __attribute__((aligned(64)));

static struct urov_session g_sess;
static uint8_t g_selftest_ws[UROV_PAGE_BYTES];
static int g_active;
static int g_handlers;
static int g_ctrl_busy;
static int g_ready;
static volatile uint32_t g_failure_logged;

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

static int g_notify_hooked;
static int g_abort_hooked;

#define UROV_GATE_NUM 5
static int g_gate_hooked[UROV_GATE_NUM];
static int g_wrapper_mode;

static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static void *mm_of_task(void *task)
{
    return *(void **)((char *)task + UROV_TASK_MM_OFF);
}

static uint64_t mm_pgd(void *mm)
{
    return *(uint64_t *)((char *)mm + UROV_MM_PGD_OFF);
}

static uint64_t *pte_of(void *mm, uint64_t address)
{
    uint64_t pgd = mm_pgd(mm);
    if (!pgd) return 0;
    return pgtable_entry(pgd, address);
}

static uint64_t caps_now(void)
{
    uint64_t caps = UROV_CAP_GPR | UROV_CAP_PAIR | UROV_CAP_RAW_XOM | UROV_CAP_RESIDENT;
    if (g_gate_hooked[0] && g_gate_hooked[1] && g_gate_hooked[2] &&
        g_gate_hooked[3] && g_gate_hooked[4])
        caps |= UROV_CAP_MM_GATES;
    if (g_ready) caps |= UROV_CAP_READY;
    return caps;
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

static int session_active(void)
{
    return __atomic_load_n(&g_active, __ATOMIC_ACQUIRE);
}

static void session_count_failure(uint64_t far, uint64_t esr, uint32_t opcode, int result)
{
    uint32_t seen;
    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    seen = __atomic_load_n(&g_failure_logged, __ATOMIC_RELAXED);
    if (seen < 8 && __atomic_compare_exchange_n(&g_failure_logged, &seen, seen + 1, 0,
                                                __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        pr_info("urov: emulation failure far=%llx esr=%llx opcode=%x result=%d\n",
                (unsigned long long)far, (unsigned long long)esr, opcode, result);
}

/* ---------------------------------------------------------------- VMA setup */

static long validate_vma(void *vma, uint64_t address)
{
    unsigned long start, end, flags, pgoff;
    void *file;
    if (!vma) return -EFAULT;
    start = *(unsigned long *)((char *)vma + UROV_VMA_START_OFF);
    end = *(unsigned long *)((char *)vma + UROV_VMA_END_OFF);
    flags = *(unsigned long *)((char *)vma + UROV_VMA_FLAGS_OFF);
    pgoff = *(unsigned long *)((char *)vma + UROV_VMA_PGOFF_OFF);
    file = *(void **)((char *)vma + UROV_VMA_FILE_OFF);
    if (start != address || end != address + UROV_PAGE_BYTES) return -EINVAL;
    if ((flags & (UROV_VM_READ | UROV_VM_EXEC | UROV_VM_MAYSHARE)) !=
        (UROV_VM_READ | UROV_VM_EXEC | UROV_VM_MAYSHARE)) return -EINVAL;
    if (flags & (UROV_VM_WRITE | UROV_VM_MAYWRITE | UROV_VM_PFNMAP |
                 UROV_VM_HUGETLB | UROV_VM_IO | UROV_VM_MIXEDMAP)) return -EINVAL;
    if (!file || pgoff) return -EINVAL;
    return 0;
}

/* ------------------------------------------------------------- publish/exit */

/* Restore the one PTE bit and the VMA reconstruction template. Runs with the
 * target mm's write lock held. */
static long restore_locked(void *mm, uint64_t address)
{
    uint64_t *ptep;
    uint64_t pte;
    void *vma;
    uint64_t pgd = mm_pgd(mm);

    uint64_t flags;

    if (!pgd) return -EOPNOTSUPP;
    vma = f_find_vma(mm, address);
    if (vma && *(unsigned long *)((char *)vma + UROV_VMA_START_OFF) == address &&
        *(unsigned long *)((char *)vma + UROV_VMA_END_OFF) == address + UROV_PAGE_BYTES) {
        *(unsigned long *)((char *)vma + UROV_VMA_PROT_OFF) = g_sess.prot_saved;
        flags = *(unsigned long *)((char *)vma + UROV_VMA_FLAGS_OFF);
        flags = (flags & ~(uint64_t)UROV_VM_DONTCOPY) |
                (g_sess.flags_saved & (uint64_t)UROV_VM_DONTCOPY);
        *(unsigned long *)((char *)vma + UROV_VMA_FLAGS_OFF) = flags;
    } else {
        return 0;
    }

    ptep = pgtable_entry(pgd, address);
    if (!ptep) return 0;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    /* Restore the one permission bit. The mapping gates keep this VMA and its
     * address stable, so a page migrated within the same VMA is fine. */
    if (pte & 1ULL)
        __atomic_store_n(ptep, pte | PTE_USER, __ATOMIC_RELEASE);
    return 0;
}

/* Wait for fault handlers that already matched the session. Handlers are pure
 * and bounded, so a short yield loop is enough; control paths never rewrite or
 * free the session while one is still reading it. */
static void drain_handlers(void)
{
    unsigned long spins = 0;
    while (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE) && spins++ < 100000000UL)
        __asm__ volatile("yield" ::: "memory");
}

/* Deactivate the session. Returns 0 if no session existed. */
static long session_stop(void)
{
    void *mm = g_sess.mm;
    if (!mm || !session_active()) return 0;
    f_mmap_write_lock(mm);
    restore_locked(mm, g_sess.base);
    f_flush_tlb_mm(mm);
    f_mmap_write_unlock(mm);
    /* No fault can be generated from the page after the flush. In-flight
     * handlers only read the (still allocated) session object. */
    __atomic_store_n(&g_active, 0, __ATOMIC_RELEASE);
    drain_handlers();
    g_sess.mm = 0;
    if (g_sess.page) {
        f_unpin_user(g_sess.page);
        g_sess.page = 0;
    }
    f_mmput(mm);
    return 0;
}

/* ------------------------------------------------------------ fault handler */

static int in_session(uint64_t far)
{
    return mm_of_task(current) == g_sess.mm && far >= g_sess.base &&
           far - g_sess.base < UROV_PAGE_BYTES;
}

static void urov_abort_before(hook_fargs4_t *args, void *udata)
{
    uint64_t far = args->arg0;
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    struct uro_view view;
    struct uro_regs model;
    uint64_t fake;
    uint32_t opcode;
    int result, i;

    (void)udata;
    if (!session_active()) return;
    if (!regs || compat_user_mode(regs)) return;
    /* EL0 data abort, read, permission fault at the 4K leaf. */
    if (((esr >> 26) & 0x3fUL) != 0x24UL || (esr & (1UL << 6)) || (esr & 0x3fUL) != 15UL)
        return;
    if (!in_session(far)) return;

    /* Count the handler so control paths can drain it before they rewrite or
     * release the session. The session can only be replaced after it was
     * deactivated, and the re-check below observes that transition. */
    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (!session_active() || !in_session(far)) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }

    if (regs->pc >= g_sess.base && regs->pc - g_sess.base <= UROV_PAGE_BYTES - 4U) {
        uint64_t at = regs->pc - g_sess.base;
        opcode = (uint32_t)g_sess.original[at] |
                 ((uint32_t)g_sess.original[at + 1] << 8) |
                 ((uint32_t)g_sess.original[at + 2] << 16) |
                 ((uint32_t)g_sess.original[at + 3] << 24);
    } else if (f_copy_in(&opcode, (const void *)regs->pc, sizeof(opcode))) {
        session_count_failure(far, esr, 0, -EFAULT);
        if (f_force_sig_fault) f_force_sig_fault(UROV_SIGSEGV, UROV_SEGV_ACCERR, (void *)far);
        goto handled;
    }

    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = regs->pc;
    model.pstate = regs->pstate;

    view.original = g_sess.original;
    view.base = g_sess.base;
    view.user_limit = UROV_USER_LIMIT;
    view.overlay_offset = g_sess.overlay_offset;
    fake = __atomic_load_n(&g_sess.fake, __ATOMIC_ACQUIRE);

    result = uro_emulate(&view, opcode, esr, far, fake, &model);
    if (result == URO_OK) {
        for (i = 0; i < 31; ++i) regs->regs[i] = model.x[i];
        regs->sp = model.sp;
        regs->pc = model.pc;
        __atomic_fetch_add(&g_sess.hits, 1, __ATOMIC_RELAXED);
    } else {
        /* The address belongs to the session but the instruction or context is
         * outside the audited subset. Never return the original bytes: stop
         * the process instead of silently lying about the access. */
        session_count_failure(far, esr, opcode, result);
        if (f_force_sig_fault) f_force_sig_fault(UROV_SIGSEGV, UROV_SEGV_ACCERR, (void *)far);
    }
handled:
    args->ret = 0;
    args->skip_origin = 1;
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* ----------------------------------------------------- control channel glue */

static uint64_t sys_arg(hook_fargs4_t *args, int n)
{
    if (g_wrapper_mode) {
        struct pt_regs *regs = (struct pt_regs *)args->arg0;
        return regs ? regs->regs[n] : 0;
    }
    return args->args[n];
}

static int request_validate(const struct urov_request *q)
{
    if (q->size != sizeof(*q) || q->version != UROV_ABI_VERSION) return -EINVAL;
    if (q->reserved0 || q->reserved[0] || q->reserved[1] || q->reserved[2]) return -EINVAL;
    if (q->flags & ~UROV_F_RAW_XOM) return -EINVAL;
    return 0;
}

static long do_register(struct urov_request *q)
{
    void *task = current;
    void *mm;
    void *vma;
    void *page = 0;
    uint64_t *ptep;
    uint64_t pte, newpte;
    long pinned;
    long ret;

    if (q->address & (UROV_PAGE_BYTES - 1)) return -EINVAL;
    if (q->address < UROV_PAGE_BYTES || q->address >= UROV_USER_LIMIT) return -EINVAL;
    if (q->offset > UROV_PAGE_BYTES - 8U) return -EINVAL;
    if (session_active()) return -EBUSY;
    drain_handlers();
    if (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE)) return -EBUSY;

    mm = f_get_task_mm(task);
    if (!mm) return -EOPNOTSUPP;
    if (mm_of_task(task) != mm) {
        pr_info("urov: task->mm offset mismatch, refusing registration\n");
        f_mmput(mm);
        return -EOPNOTSUPP;
    }

    /* Fault the page in and hold a pin for the session. GUP must run before
     * the mmap write lock is taken (it acquires mmap_lock itself). */
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
    if (f_copy_in(g_sess.original, (const void *)q->address, UROV_PAGE_BYTES)) {
        ret = -EFAULT;
        goto unlock;
    }
    g_sess.mm = mm;
    g_sess.page = page;
    g_sess.base = q->address;
    g_sess.overlay_offset = q->offset;
    g_sess.pte_saved = pte;
    g_sess.prot_saved = *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF);
    g_sess.flags_saved = *(uint64_t *)((char *)vma + UROV_VMA_FLAGS_OFF);
    g_sess.fake = q->value;
    g_sess.generation = 1;
    g_sess.hits = 0;
    g_sess.failures = 0;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);

    /* Publish the complete session before the page can fault. The VMA template
     * is updated first so a rebuilt PTE keeps AP[1] clear. */
    *(uint64_t *)((char *)vma + UROV_VMA_PROT_OFF) = g_sess.prot_saved & ~(uint64_t)PTE_USER;
    *(uint64_t *)((char *)vma + UROV_VMA_FLAGS_OFF) = g_sess.flags_saved | UROV_VM_DONTCOPY;
    __atomic_store_n(&g_active, 1, __ATOMIC_RELEASE);
    newpte = (pte & ~(uint64_t)PTE_USER) | PTE_AF;
    __atomic_store_n(ptep, newpte, __ATOMIC_RELEASE);
    f_flush_tlb_mm(mm);
    ret = 0;
    q->session = 1;
    q->generation = 1;
    q->state = UROV_ACTIVE;
    q->caps = caps_now();
    if (f_mmap_write_unlock) f_mmap_write_unlock(mm);
    return 0;
unlock:
    f_mmap_write_unlock(mm);
    if (page) f_unpin_user(page);
    f_mmput(mm);
    return ret;
}

static long do_set(struct urov_request *q)
{
    if (!session_active() || q->session != 1) return -ENOENT;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    __atomic_store_n(&g_sess.fake, q->value, __ATOMIC_RELEASE);
    g_sess.generation++;
    q->generation = g_sess.generation;
    q->value = g_sess.fake;
    q->state = UROV_ACTIVE;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

static long do_status(struct urov_request *q)
{
    if (!session_active() || q->session != 1) return -ENOENT;
    q->generation = g_sess.generation;
    q->value = __atomic_load_n(&g_sess.fake, __ATOMIC_ACQUIRE);
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    q->state = UROV_ACTIVE;
    q->caps = caps_now();
    return 0;
}

static long do_deactivate(struct urov_request *q)
{
    if (q->session != 1 && q->session != 0) return -ENOENT;
    session_stop();
    q->session = 0;
    q->generation = 0;
    q->state = UROV_INACTIVE;
    q->caps = caps_now();
    return 0;
}

static long do_query(struct urov_request *q)
{
    q->caps = caps_now();
    q->state = session_active() ? UROV_ACTIVE : UROV_INACTIVE;
    q->session = session_active() ? 1 : 0;
    q->generation = session_active() ? g_sess.generation : 0;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

static long notify_dispatch(unsigned int cmd, struct urov_request *user, unsigned long size)
{
    struct urov_request q;
    long ret;

    if (!user || size != sizeof(q)) return -EINVAL;
    if (f_copy_in(&q, user, sizeof(q))) return -EFAULT;
    if (q.op != (uint16_t)cmd) return -EINVAL;
    ret = request_validate(&q);
    if (ret) return ret;
    if (!g_ready) return -EOPNOTSUPP;
    if (!ctrl_try_lock()) return -EBUSY;
    switch (cmd) {
    case UROV_NOTIFY_QUERY: ret = do_query(&q); break;
    case UROV_NOTIFY_REGISTER: ret = do_register(&q); break;
    case UROV_NOTIFY_SET: ret = do_set(&q); break;
    case UROV_NOTIFY_STATUS: ret = do_status(&q); break;
    case UROV_NOTIFY_DEACTIVATE: ret = do_deactivate(&q); break;
    default: ret = -EINVAL; break;
    }
    ctrl_unlock();
    if (f_copy_out(user, &q, sizeof(q))) return -EFAULT;
    return ret;
}

static void urov_notify_before(hook_fargs4_t *args, void *udata)
{
    uint64_t magic = sys_arg(args, 0);
    unsigned int cmd;
    long ret;

    (void)udata;
    if (magic != UROV_NOTIFY_MAGIC) return;
    cmd = (unsigned int)sys_arg(args, 1);
    ret = notify_dispatch(cmd, (struct urov_request *)sys_arg(args, 2),
                          (unsigned long)sys_arg(args, 3));
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* ----------------------------------------------------------------- mapping gates */

enum urov_gate_kind {
    UROV_GATE_MPROTECT,
    UROV_GATE_MUNMAP,
    UROV_GATE_MREMAP,
    UROV_GATE_MADVISE,
    UROV_GATE_MMAP,
};

static const int g_gate_nrs[UROV_GATE_NUM] = {
    __NR_mprotect, __NR_munmap, __NR_mremap, __NR_madvise, __NR_mmap,
};

static void urov_gate_before(hook_fargs4_t *args, void *udata)
{
    uint64_t start, len, end, base = g_sess.base;
    int kind = (int)(uintptr_t)udata;

    if (!session_active()) return;
    if (mm_of_task(current) != g_sess.mm) return;
    if (kind == UROV_GATE_MMAP && !(sys_arg(args, 3) & 0x10ULL)) return;
    start = sys_arg(args, 0);
    len = sys_arg(args, 1);
    if (!len) return;
    end = start + len;
    if (end < start) end = ~0ULL;
    if (end <= base || start >= base + UROV_PAGE_BYTES) return;
    args->ret = (uint64_t)(long)-EBUSY;
    args->skip_origin = 1;
}

/* -------------------------------------------------------------------- init */

static void *lookup(const char *name)
{
    return (void *)kallsyms_lookup_name(name);
}

long urov_backend_init(const char *args)
{
    unsigned int checks = 0;
    long ret;
    int i;

    if (args && *args && !str_eq(args, "active")) return -EINVAL;
    if (!kallsyms_lookup_name) return -ENOSYS;
    if (uro_core_selftest(g_selftest_ws, &checks) || checks != 4114) return -EINVAL;

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

    pr_info("urov: abort=%lx task_mm=%lx mmput=%lx mmap=%lx/%lx tlb=%lx sig=%lx copy=%lx/%lx wrapper=%d\n",
            (unsigned long)f_do_mem_abort, (unsigned long)f_get_task_mm, (unsigned long)f_mmput,
            (unsigned long)f_mmap_write_lock, (unsigned long)f_mmap_write_unlock,
            (unsigned long)f_flush_tlb_mm, (unsigned long)f_force_sig_fault,
            (unsigned long)f_copy_in, (unsigned long)f_copy_out, g_wrapper_mode);
    if (!f_do_mem_abort || !f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_flush_tlb_mm ||
        !f_pin_user || !f_unpin_user ||
        !f_force_sig_fault || !f_copy_in || !f_copy_out)
        return -EOPNOTSUPP;

    ret = hook_wrap(f_do_mem_abort, 3, urov_abort_before, 0, 0);
    if (ret) {
        pr_info("urov: hook do_mem_abort failed: %ld\n", ret);
        return -EOPNOTSUPP;
    }
    g_abort_hooked = 1;

    ret = fp_hook_syscalln(UROV_NOTIFY_NR, 6, urov_notify_before, 0, 0);
    if (ret) {
        pr_info("urov: hook notify syscall %d failed: %ld\n", UROV_NOTIFY_NR, ret);
        goto unwind_abort;
    }
    g_notify_hooked = 1;

    for (i = 0; i < UROV_GATE_NUM; ++i) {
        ret = fp_hook_syscalln(g_gate_nrs[i], 6, urov_gate_before, 0, (void *)(uintptr_t)i);
        if (ret) {
            pr_info("urov: hook gate syscall %d failed: %ld\n", g_gate_nrs[i], ret);
            break;
        }
        g_gate_hooked[i] = 1;
    }
    if (i != UROV_GATE_NUM) {
        while (i-- > 0) {
            fp_unhook_syscalln(g_gate_nrs[i], urov_gate_before, 0);
            g_gate_hooked[i] = 0;
        }
        fp_unhook_syscalln(UROV_NOTIFY_NR, urov_notify_before, 0);
        g_notify_hooked = 0;
        goto unwind_abort;
    }

    g_ready = 1;
    pr_info("urov: resident backend ready, notify nr=%d\n", UROV_NOTIFY_NR);
    return 0;

unwind_abort:
    if (g_abort_hooked) {
        hook_unwrap(f_do_mem_abort, urov_abort_before, 0);
        g_abort_hooked = 0;
    }
    return -EOPNOTSUPP;
}

long urov_backend_exit(void)
{
    int i;
    if (session_active()) session_stop();
    g_ready = 0;
    for (i = 0; i < UROV_GATE_NUM; ++i) {
        if (!g_gate_hooked[i]) continue;
        fp_unhook_syscalln(g_gate_nrs[i], urov_gate_before, 0);
        g_gate_hooked[i] = 0;
    }
    if (g_notify_hooked) {
        fp_unhook_syscalln(UROV_NOTIFY_NR, urov_notify_before, 0);
        g_notify_hooked = 0;
    }
    if (g_abort_hooked) {
        hook_unwrap(f_do_mem_abort, urov_abort_before, 0);
        g_abort_hooked = 0;
    }
    return 0;
}

void urov_backend_get_status(struct urov_backend_status *out)
{
    if (!out) return;
    out->caps = caps_now();
    out->generation = session_active() ? g_sess.generation : 0;
    out->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    out->active = session_active() ? 1U : 0U;
    out->hooks = (g_abort_hooked ? 1U : 0U) | (g_notify_hooked ? 2U : 0U) |
                 ((g_gate_hooked[0] && g_gate_hooked[1] && g_gate_hooked[2] && g_gate_hooked[3] && g_gate_hooked[4]) ? 4U : 0U);
    out->core_checks = 4114;
    out->last_error = 0;
}
