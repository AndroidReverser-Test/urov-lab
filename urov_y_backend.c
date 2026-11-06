/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * UROV-Y resident backend: three ways to bind the overlay to a reader site.
 *
 * The two detector classes that remained against UROV-X (see
 * KEYLESS_DETECTION_RESULTS.md) are:
 *
 *   A. any data load of the protected page is emulated from EL1, and the
 *      exception return invalidates the local exclusive monitor, so an
 *      LDXR/LDRB/STXR sequence can observe the read;
 *   B. the registered reader PC observes different bytes than a direct load
 *      of the same immutable RX address.
 *
 * SITE_BRK removes the data abort entirely by replacing the 4-byte site
 * instruction with BRK on a private COW page (A impossible, B handled by the
 * caller window).  PAGE_UXN removes the code-page feature by making the site
 * page EL0 execute-never and emulating the fetch.  PAGE_AP instead clears
 * only AP[1] on the target page: fetch (including a BTI/RET canary) stays
 * native, while every data read is emulated with the same caller-window rules.
 * Because a synchronous abort still returns through ERET, PAGE_AP also
 * bridges the immediately adjacent LDXR/LDAXR; load; STXR/STLXR shape and
 * performs the store/status itself -- but only after checking that the LDXR's
 * destination register still holds the value at its base address, i.e. that
 * the LDXR actually executed.  A skipped LDXR leaves the STXR native and it
 * fails, exactly as it would without the overlay.
 *
 * Honest residuals are documented in ELIMINATION_DESIGN.md: BRK dirties the
 * site code page; PAGE_UXN makes the site page unexecutable at EL0; PAGE_AP
 * keeps a data abort, so the monitor bridge only covers the adjacent shape
 * and the read still costs one synchronous exception.
 */
#include <common.h>
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

#include "emulate.h"
#include "urov_y_abi.h"
#include "urov_y_backend.h"
#include "urov_y_compat.h"

#ifndef __NR_mmap
#define __NR_mmap 222
#endif

static inline void uy_flush_icache_all(void)
{
    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("ic ialluis");
    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("isb" : : : "memory");
}

#define UY_USER_LIMIT (1ULL << 52)

#define UY_VM_SHARED 0x00000008UL
#define UY_VM_READ 0x00000001UL
#define UY_VM_WRITE 0x00000002UL
#define UY_VM_EXEC 0x00000004UL
#define UY_VM_MAYWRITE 0x00000020UL
#define UY_VM_PFNMAP 0x00000400UL
#define UY_VM_IO 0x00002000UL
#define UY_VM_HUGETLB 0x00400000UL
#define UY_VM_MIXEDMAP 0x10000000UL

#define UY_SIGSEGV 11
#define UY_SEGV_ACCERR 2

#define UY_BRK_EC 0x3cUL
#define UY_BRK_BASE 0xd4200000U

/* EL0 instruction abort taken to EL1: EC 0x20, and the FSC field of a
 * permission fault is 0b0011LL (0x0c..0x0f). */
#define UY_EC_IABT_LOW 0x20UL
/* EL0 data abort taken to EL1: EC 0x24.  ESR.WnR distinguishes a read from a
 * write; only read permission faults are ours. */
#define UY_EC_DABT_LOW 0x24UL
#define UY_ESR_WNR (1UL << 6)
#define UY_FSC_PERM_MASK 0x3cUL
#define UY_FSC_PERM 0x0cUL

/* A64 control instructions that a trap page may legitimately execute. */
#define UY_RET_X30 0xd65f03c0U
#define UY_FLOW_MASK 0xfffffc1fU
#define UY_RET_BASE 0xd65f0000U
#define UY_BR_BASE 0xd61f0000U
#define UY_BLR_BASE 0xd63f0000U
#define UY_B_IMM26 0x14000000U
#define UY_BL_IMM26 0x94000000U
#define UY_IMM26_MASK 0xfc000000U
#define UY_NOP 0xd503201fU
#define UY_BTI_C 0xd503245fU
#define UY_BTI_J 0xd503249fU
#define UY_BTI_JC 0xd50324dfU

#define UY_FOLL_WRITE 0x01U

/* VM_FAULT_ERROR | VM_FAULT_RETRY | VM_FAULT_COMPLETED. A fault that returns
 * any of these bits may not have installed a PTE or may have dropped its lock. */
#define UY_FAULT_INCOMPLETE 0x4c73U

#define UY_STATE_OFF 0
#define UY_STATE_LIVE 1

/* Fine-grained retry bound for the seqlock snapshot. */
#define UY_FAKE_RETRY 1000000U
/* Bounded spin for the control lock taken from fault / syscall-hook context. */
#define UY_CTRL_SPIN 1000000UL
/* Entries kept for the module lifetime so a stale BRK is always emulated. */
#define UY_TRAP_SLOTS 8U

_Static_assert(UROV_Y_FAKE_MAX == URO_FAKE_MAX, "UAPI and core fake widths");
_Static_assert(UROV_Y_FAKE_PAGE == UROV_Y_PAGE, "overlay is at most one page");
_Static_assert(UROV_Y_MAX_SITES <= UY_TRAP_SLOTS, "trap table covers one session");

/* struct user_fpsimd_state as consumed by the kernel's FPSIMD helpers:
 * 32 16-byte vector registers followed by fpsr/fpcr (uapi/asm/sigcontext.h).
 * Its BTF layout is validated at load time before any vector load is served. */
struct uy_fpstate {
    uint8_t vregs[32][16];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t reserved[2];
};
_Static_assert(sizeof(struct uy_fpstate) == UY_FPSIMD_BYTES, "FPSIMD image size");

typedef void (*fpsimd_preserve_t)(void);
typedef void (*fpsimd_update_t)(void *state);

typedef void *(*get_task_mm_t)(void *task);
typedef void (*mmput_t)(void *mm);
typedef void *(*find_vma_t)(void *mm, unsigned long addr);
typedef void (*mmap_write_fn)(void *);
typedef void (*flush_tlb_mm_t)(void *mm);
typedef int (*force_sig_fault_t)(int sig, int code, void *addr);
typedef long (*copy_nofault_t)(void *dst, const void *src, unsigned long n);
typedef int (*access_remote_vm_t)(void *mm, unsigned long addr, void *buf,
                                  int len, unsigned int gup_flags);

extern uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

struct uy_site {
    uint64_t pc;
    uint64_t page;
    uint32_t writable;
    uint32_t original;
    uint32_t trap;
    uint32_t armed;
    uint32_t pad;
};

struct uy_session {
    void *mm;
    uint64_t base;
    uint64_t fake[4];
    uint64_t generation;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;
    uint64_t caller_start[UROV_Y_MAX_CALLERS];
    uint64_t caller_end[UROV_Y_MAX_CALLERS];
    uint32_t overlay_offset;
    uint32_t overlay_len;
    uint32_t site_count;
    uint32_t caller_count;
    uint32_t mode;
    uint32_t fake_seq;
    uint32_t ap_armed;
    uint32_t pad;
    struct uy_site sites[UROV_Y_MAX_SITES];
    uint8_t original[UROV_Y_PAGE];
    /* Published overlay image: overlay_len bytes, seqlock-protected. */
    uint8_t fake_page[UROV_Y_PAGE];
} __attribute__((aligned(64)));

/* Module-lifetime record of every PC that once carried our BRK. Kept after a
 * session ends so that a stale instruction-cache line anywhere in the system
 * is still emulated with the original instruction instead of SIGTRAP. */
struct uy_trap {
    uint64_t pc;
    uint32_t original;
    uint32_t valid;
};

static struct uy_session g_sess;
static struct uy_layout g_layout;
static struct uy_trap g_traps[UY_TRAP_SLOTS];
static uint8_t g_selftest_ws[UROV_Y_PAGE];
/* Staging area for a REGISTER/SET overlay image.  The caller's buffer is
 * copied here first, outside the seqlock, because access_remote_vm() may fault
 * pages in and must not run while readers spin on the sequence word. */
static uint8_t g_fake_stage[UROV_Y_PAGE];
static int g_state;
static int g_handlers;
static int g_ctrl_busy;
static int g_ready;
static int g_verbose;
static int g_suspend;
static int g_armed;
static volatile uint32_t g_failure_logged;
static struct urov_x_keys g_keys;
static uint16_t g_imm;
static uint32_t g_trap_insn;
static unsigned g_write_gup_flags;
static int g_use_rwsem;

static void *f_brk_handler;
static void *f_do_mem_abort;
static void *f_handle_mm_fault;
static get_task_mm_t f_get_task_mm;
static mmput_t f_mmput;
static find_vma_t f_find_vma;
static mmap_write_fn f_mmap_write_lock;
static mmap_write_fn f_mmap_write_unlock;
static flush_tlb_mm_t f_flush_tlb_mm;
static force_sig_fault_t f_force_sig_fault;
static copy_nofault_t f_copy_in, f_copy_out;
static access_remote_vm_t f_access_vm;
static fpsimd_preserve_t f_fp_preserve;
static fpsimd_update_t f_fp_update;

static int g_brk_hooked;
static int g_prctl_hooked;
static int g_clone_hooked;
static int g_clone3_hooked;
static int g_wrapper_mode;
static int g_page_hooked;
static int g_mmf_hooked;
static int g_degraded;
/* FPSIMD state can only be driven when both kernel helpers resolved and BTF
 * described task_struct.thread.uw.fpsimd_state.  Otherwise a vector load from
 * the target page keeps the historical fail-closed SIGSEGV. */
static int g_fp_ready;

#define UY_GATE_NUM 6
static int g_gate_hooked[UY_GATE_NUM];

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
    return __atomic_load_n((void **)((char *)task + g_layout.task_mm), __ATOMIC_RELAXED);
}

static uint64_t mm_pgd(void *mm)
{
    return __atomic_load_n((uint64_t *)((char *)mm + g_layout.mm_pgd), __ATOMIC_RELAXED);
}

static int mm_has_live_user(void *mm)
{
    int users;
    if (!mm) return 0;
    users = __atomic_load_n((int *)((char *)mm + g_layout.mm_users), __ATOMIC_ACQUIRE);
    return users > 1;
}

static void uy_mmap_write_lock(void *mm)
{
    f_mmap_write_lock(g_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
}

static void uy_mmap_write_unlock(void *mm)
{
    f_mmap_write_unlock(g_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
}

static uint64_t *pte_of(void *mm, uint64_t address)
{
    uint64_t pgd = mm_pgd(mm);
    if (!pgd) return 0;
    return pgtable_entry(pgd, address);
}

/* UROV_Y_PAGE is a 32-bit constant; a plain ~(UROV_Y_PAGE - 1) would mask the
 * upper half of a user address away. */
static uint64_t page_base(uint64_t address)
{
    return address & ~((uint64_t)UROV_Y_PAGE - 1U);
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

static int ctrl_lock_wait(void)
{
    unsigned long i;
    for (i = 0; i < UY_CTRL_SPIN; ++i) {
        if (ctrl_try_lock()) return 1;
        __asm__ volatile("yield" ::: "memory");
    }
    return 0;
}

static int overlay_live(void)
{
    return __atomic_load_n(&g_state, __ATOMIC_ACQUIRE) == UY_STATE_LIVE;
}

static int page_mode_live(void)
{
    return overlay_live() && g_sess.mode == UROV_Y_MODE_PAGE_UXN;
}

static int ap_mode_live(void)
{
    return overlay_live() && g_sess.mode == UROV_Y_MODE_PAGE_AP;
}

static int session_owned(void)
{
    return overlay_live() && mm_of_task(current) == g_sess.mm;
}

static unsigned request_fake_len(const struct urov_y_request *q)
{
    return q->length ? q->length : 8U;
}

/* Copy the requested overlay image into the staging area.  A request either
 * carries the legacy inline 8..32-byte value or points at length bytes of user
 * memory; the pointer is only read here, during the control transaction. */
static long fake_stage_request(const struct urov_y_request *q, void *mm, unsigned len)
{
    unsigned i;

    if (q->fake_addr) {
        if (!mm) return -EINVAL;
        if (f_access_vm(mm, q->fake_addr, g_fake_stage, (int)len, 0) != (int)len)
            return -EFAULT;
        return 0;
    }
    if (len > UROV_Y_FAKE_MAX) return -EINVAL;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8U ? q->value : q->value_hi[(i - 8U) / 8U];
        g_fake_stage[i] = (uint8_t)(word >> (8U * (i & 7U)));
    }
    return 0;
}

/* Publish the staged image.  The 4 KiB copy and the mirrored status words are
 * inside the sequence write; readers only ever copy the handful of bytes the
 * faulting instruction touches, so a concurrent SET stalls them for ~1 us. */
static void fake_publish(unsigned len)
{
    uint32_t seq = __atomic_load_n(&g_sess.fake_seq, __ATOMIC_RELAXED);
    unsigned i;

    __atomic_store_n(&g_sess.fake_seq, seq + 1U, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    for (i = 0; i < len; ++i)
        g_sess.fake_page[i] = g_fake_stage[i];
    for (i = 0; i < 4U; ++i) {
        uint64_t value = 0;
        unsigned b;
        for (b = 0; b < 8U && 8U * i + b < len; ++b)
            value |= (uint64_t)g_fake_stage[8U * i + b] << (8U * b);
        g_sess.fake[i] = value;
    }
    __atomic_store_n(&g_sess.fake_seq, seq + 2U, __ATOMIC_RELEASE);
}

/* Merge the overlay into the bytes of [off, off+total) of the target page,
 * where off is the page-relative address of the load.  total <= 32 because the
 * widest single A64 read is an LDP Q pair.  Returns 0 on success and a negative
 * value when the sequence word never settled (fail closed, never original). */
static int fake_merge(uint64_t off, unsigned total, uint8_t *out)
{
    unsigned tries;
    for (tries = 0; tries < UY_FAKE_RETRY; ++tries) {
        uint32_t seq = __atomic_load_n(&g_sess.fake_seq, __ATOMIC_ACQUIRE);
        uint32_t foff, flen;
        unsigned i;
        if (seq & 1U) {
            __asm__ volatile("yield" ::: "memory");
            continue;
        }
        foff = g_sess.overlay_offset;
        flen = g_sess.overlay_len;
        if (flen < 8U || flen > UROV_Y_FAKE_PAGE || (flen & 7U) ||
            foff > UROV_Y_FAKE_PAGE - flen)
            return -EINVAL;
        for (i = 0; i < total; ++i) {
            uint64_t pos = off + i;
            if (pos >= foff && pos - foff < flen)
                out[i] = g_sess.fake_page[pos - foff];
            else
                out[i] = g_sess.original[pos];
        }
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&g_sess.fake_seq, __ATOMIC_RELAXED) == seq)
            return 0;
    }
    return -EAGAIN;
}

static void session_count_failure(uint64_t pc, int result)
{
    uint32_t seen;
    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    if (!g_verbose) return;
    seen = __atomic_load_n(&g_failure_logged, __ATOMIC_RELAXED);
    if (seen < 8 && __atomic_compare_exchange_n(&g_failure_logged, &seen, seen + 1, 0,
                                                __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        pr_info("urov-y: site emulation failure pc=%llx result=%d\n",
                (unsigned long long)pc, result);
}

/* -------------------------------------------------------- trap bookkeeping */

static struct uy_trap *trap_lookup(uint64_t pc)
{
    unsigned i;
    for (i = 0; i < UY_TRAP_SLOTS; ++i)
        if (__atomic_load_n(&g_traps[i].pc, __ATOMIC_ACQUIRE) == pc) return &g_traps[i];
    return 0;
}

static struct uy_trap *trap_install(uint64_t pc, uint32_t original)
{
    unsigned i;
    struct uy_trap *slot = 0;

    for (i = 0; i < UY_TRAP_SLOTS; ++i)
        if (__atomic_load_n(&g_traps[i].pc, __ATOMIC_ACQUIRE) == pc) return &g_traps[i];
    for (i = 0; i < UY_TRAP_SLOTS; ++i) {
        if (!__atomic_load_n(&g_traps[i].pc, __ATOMIC_ACQUIRE)) { slot = &g_traps[i]; break; }
    }
    if (!slot) {
        /* Reuse a slot that the session being registered does not name. The
         * previous owner was already disarmed with a system-wide I-cache
         * invalidation, so any stale line for it is gone. */
        for (i = 0; i < UY_TRAP_SLOTS; ++i) {
            unsigned j;
            int busy = 0;
            uint64_t old = __atomic_load_n(&g_traps[i].pc, __ATOMIC_ACQUIRE);
            if (!old) continue;
            for (j = 0; j < g_sess.site_count && j < UROV_Y_MAX_SITES; ++j)
                if (g_sess.sites[j].pc == old) busy = 1;
            if (!busy) { slot = &g_traps[i]; break; }
        }
    }
    if (!slot) return 0;
    __atomic_store_n(&slot->original, original, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&slot->pc, pc, __ATOMIC_RELEASE);
    return slot;
}

/* -------------------------------------------------------- site patch/unpatch */

/* A site must be inside an executable mapping. The BRK mode additionally needs
 * a private, COW-capable mapping because it writes the instruction into the
 * process' page; the PAGE_UXN mode only changes the leaf PTE, so a shared
 * file mapping is fine there and every byte stays untouched.
 * *writable receives VM_WRITE, which is what the BRK PTE must reflect. */
static int validate_site_vma(void *vma, uint64_t pc, int page_mode, int *writable)
{
    unsigned long start, end, flags;
    if (!vma) return -EFAULT;
    start = *(unsigned long *)((char *)vma + g_layout.vma_start);
    end = *(unsigned long *)((char *)vma + g_layout.vma_end);
    flags = *(unsigned long *)((char *)vma + g_layout.vma_flags);
    if (g_verbose)
        pr_info("urov-y: site vma pc=%llx start=%lx end=%lx flags=%lx\n",
                (unsigned long long)pc, start, end, flags);
    if (pc < start || pc + 4U > end) return -EFAULT;
    if (!(flags & UY_VM_EXEC)) return -EOPNOTSUPP;
    if (!page_mode) {
        if (flags & UY_VM_SHARED) return -EOPNOTSUPP;
        if (!(flags & UY_VM_MAYWRITE)) return -EOPNOTSUPP;
    }
    if (flags & (UY_VM_PFNMAP | UY_VM_IO | UY_VM_HUGETLB | UY_VM_MIXEDMAP))
        return -EOPNOTSUPP;
    if (writable) *writable = (flags & UY_VM_WRITE) ? 1 : 0;
    return 0;
}

/* A target page is only ever read by the backend: SITE_BRK writes the reader
 * instruction on its site page, PAGE_UXN flips UXN on a site page, and PAGE_AP
 * flips AP[1] on the target leaf PTE.  None of them changes the target's VMA
 * or its bytes, so binding one page inside an ordinary code mapping is safe as
 * long as the mapping itself cannot be made writable from under the session.
 *
 * Historically this check required the whole VMA to be exactly one page and
 * rejected VM_MAYWRITE, which excluded every normal app .text mapping (the
 * linker maps file-backed PT_LOAD segments MAP_PRIVATE, so the VMA is
 * multi-page and carries VM_MAYWRITE).  The relaxed shape below accepts:
 *
 *   - a page inside a private, file-backed, read-only executable VMA of any
 *     size (the normal linker .text / oat case);
 *   - the original dedicated one-page MAP_SHARED RX alias.
 *
 * A shared VMA stays restricted to the dedicated one-page, no-MAYWRITE shape:
 * another mapping of a writable file could change the page cache under us.
 * A private page has no other writer, and the mmap/mprotect/munmap/mremap/
 * madvise/MAP_FIXED gates end the session before such a change can happen.
 * VM_WRITE itself is always rejected, so a page that is currently writable
 * (for example after a failed execmod restore) can never be registered. */
static int validate_target_vma(void *vma, uint64_t address)
{
    unsigned long start, end, flags;
    void *file;
    if (!vma) return -EFAULT;
    start = *(unsigned long *)((char *)vma + g_layout.vma_start);
    end = *(unsigned long *)((char *)vma + g_layout.vma_end);
    flags = *(unsigned long *)((char *)vma + g_layout.vma_flags);
    file = *(void **)((char *)vma + g_layout.vma_file);
    if (address < start || address >= end || end - address < UROV_Y_PAGE) return -EINVAL;
    if ((flags & (UY_VM_READ | UY_VM_EXEC)) != (UY_VM_READ | UY_VM_EXEC)) return -EINVAL;
    if (flags & (UY_VM_WRITE | UY_VM_PFNMAP | UY_VM_HUGETLB |
                 UY_VM_IO | UY_VM_MIXEDMAP)) return -EINVAL;
    if (!file) return -EINVAL;
    if (flags & UY_VM_SHARED) {
        if (start != address || end != address + UROV_Y_PAGE) return -EINVAL;
        if (flags & UY_VM_MAYWRITE) return -EINVAL;
    }
    return 0;
}

/* Align the site PTE with the VMA's own protection: a normal RX code page stays
 * read-only, so a user store faults exactly as it did before the session. The
 * COW fault used to install the private page leaves the PTE writable, hence the
 * restore after every write. */
static void site_set_prot(void *mm, uint64_t page, int writable)
{
    uint64_t *ptep = pte_of(mm, page);
    uint64_t pte;
    if (!ptep) return;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (!(pte & 1ULL)) return;
    if (writable)
        pte = (pte | PTE_DBM | PTE_AF) & ~(uint64_t)PTE_RDONLY;
    else
        pte = (pte | PTE_RDONLY | PTE_AF) & ~(uint64_t)PTE_DBM;
    __atomic_store_n(ptep, pte, __ATOMIC_RELEASE);
    if (f_flush_tlb_mm) f_flush_tlb_mm(mm);
    else flush_tlb_all();
}

/* ------------------------------------------------------ page (UXN) arming */

/* A present, non-contiguous 4K leaf PTE. A contiguous run shares one
 * permission check, so changing a single entry would be wrong; such pages are
 * rejected instead of silently breaking the neighbouring entries. */
static int page_pte_leaf(void *mm, uint64_t page, uint64_t **slot, uint64_t *out)
{
    uint64_t *ptep = pte_of(mm, page);
    uint64_t pte;

    if (!ptep) return -EAGAIN;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if ((pte & (PTE_VALID | PTE_TYPE_MASK)) != (PTE_VALID | PTE_TYPE_PAGE))
        return -EAGAIN;
    if (pte & (PTE_CONT | PTE_SPECIAL | PTE_DEVMAP | PTE_PROT_NONE))
        return -EOPNOTSUPP;
    *slot = ptep;
    *out = pte;
    return 0;
}

/* A present, user leaf PTE, the only kind a site page may be. */
static int page_pte_present(void *mm, uint64_t page, uint64_t **slot, uint64_t *out)
{
    int ret = page_pte_leaf(mm, page, slot, out);
    if (ret) return ret;
    if (!(*out & PTE_USER)) return -EOPNOTSUPP;
    return 0;
}

/* Toggle EL0 execute-never on a site page. The caller either holds the mmap
 * write lock (arm/disarm) or is completing the fault that just installed this
 * exact PTE. Returns 1 when the entry changed, 0 when it was already in the
 * requested state, negative on a page that cannot be trapped. */
static int page_set_uxn(void *mm, uint64_t page, int set)
{
    uint64_t *ptep;
    uint64_t pte;
    int ret = page_pte_present(mm, page, &ptep, &pte);

    if (ret) return ret;
    if (set) {
        if (pte & PTE_UXN) return 0;
        pte |= PTE_UXN;
    } else {
        if (!(pte & PTE_UXN)) return 0;
        pte &= ~(uint64_t)PTE_UXN;
    }
    __atomic_store_n(ptep, pte, __ATOMIC_RELEASE);
    return 1;
}

/* Toggle EL0 data permission (AP[1]) on the target page.  With AP[2] (read-
 * only) held, clearing AP[1] makes every EL0 data read of this page take a
 * permission abort, while EL0 instruction fetch is governed by UXN alone and
 * stays native.  The caller holds the mmap write lock, or is completing the
 * fault that installed this PTE. */
static int page_set_ap(void *mm, uint64_t page, int set)
{
    uint64_t *ptep;
    uint64_t pte;
    int ret = page_pte_leaf(mm, page, &ptep, &pte);

    if (ret) return ret;
    if (set) {
        if (pte & PTE_USER) return 0;
        pte |= PTE_USER;
    } else {
        if (!(pte & PTE_USER)) return 0;
        pte &= ~(uint64_t)PTE_USER;
    }
    __atomic_store_n(ptep, pte, __ATOMIC_RELEASE);
    return 1;
}

/* Registration already faulted the target page in and copied it, so arming
 * only needs to flip AP[1] under the mmap write lock.  A private .text page is
 * ordinary reclaimable file-backed memory, so a re-fault between the snapshot
 * and the lock can drop the PTE again; fault it back in and retry rather than
 * failing a registration that raced with reclaim. */
static long ap_arm_target(struct uy_session *s, void *mm)
{
    uint32_t word;
    int ret = -EAGAIN, tries;

    for (tries = 0; tries < 4; ++tries) {
        uy_mmap_write_lock(mm);
        ret = page_set_ap(mm, s->base, 0);
        if (ret > 0) flush_tlb_all();
        uy_mmap_write_unlock(mm);
        if (ret >= 0) {
            s->ap_armed = 1;
            return 0;
        }
        if (ret != -EAGAIN && ret != -EFAULT) return ret;
        if (f_access_vm(mm, s->base, &word, 4, 0) != 4) return -EFAULT;
    }
    return ret;
}

static void ap_disarm_target(struct uy_session *s, void *mm)
{
    int ret;

    if (!s->ap_armed) return;
    s->ap_armed = 0;
    if (!mm || !mm_has_live_user(mm)) return;
    uy_mmap_write_lock(mm);
    ret = page_set_ap(mm, s->base, 1);
    if (ret > 0) flush_tlb_all();
    uy_mmap_write_unlock(mm);
}

/* Fault the page in if needed, then install the trap bit. No byte of the code
 * page is touched: the page stays the clean file-backed page it was, so a
 * file-vs-memory comparison and smaps are both unchanged. */
static long site_arm_page(struct uy_site *s, void *mm)
{
    uint32_t word;
    int ret = -EAGAIN, tries;

    if (f_access_vm(mm, s->pc, &word, 4, 0) != 4) {
        if (g_verbose)
            pr_info("urov-y: page arm could not read site pc=%llx\n",
                    (unsigned long long)s->pc);
        return -EFAULT;
    }
    if (word != s->original) return -EAGAIN;
    uy_mmap_write_lock(mm);
    for (tries = 0; tries < 4; ++tries) {
        ret = page_set_uxn(mm, s->page, 1);
        if (g_verbose)
            pr_info("urov-y: page arm pc=%llx pte_flip=%d\n",
                    (unsigned long long)s->pc, ret);
        if (ret >= 0 || ret != -EAGAIN) break;
        /* Evicted between the read and the lock: fault it in again with the
         * write lock dropped, then retry. */
        uy_mmap_write_unlock(mm);
        if (f_access_vm(mm, s->pc, &word, 4, 0) != 4) return -EFAULT;
        uy_mmap_write_lock(mm);
    }
    if (ret >= 0) {
        flush_tlb_all();
        s->armed = 1;
        __atomic_fetch_add(&g_armed, 1, __ATOMIC_ACQ_REL);
        ret = 0;
    }
    uy_mmap_write_unlock(mm);
    return ret < 0 ? ret : 0;
}

static void site_disarm_page(struct uy_site *s, void *mm)
{
    int ret = 0;

    /* A dead owner's page tables are being torn down; there is nothing left to
     * restore and touching them from here is unsafe. */
    if (mm_has_live_user(mm)) {
        uy_mmap_write_lock(mm);
        ret = page_set_uxn(mm, s->page, 0);
        if (ret > 0) flush_tlb_all();
        uy_mmap_write_unlock(mm);
    }
    s->armed = 0;
    if (__atomic_load_n(&g_armed, __ATOMIC_ACQUIRE) > 0)
        __atomic_fetch_sub(&g_armed, 1, __ATOMIC_ACQ_REL);
}

/* ------------------------------------------------------ BRK site patching */

static long site_arm(struct uy_site *s, void *mm, uint64_t pc, int writable)
{
    uint32_t insn;
    struct uro_regs regs;
    struct uro_load load;
    int wrote;

    if (f_copy_in(&insn, (const void *)pc, 4)) return -EFAULT;
    memset(&regs, 0, sizeof(regs));
    regs.pc = pc;
    if (uro_decode(insn, &regs, &load)) return -EOPNOTSUPP;

    s->pc = pc;
    s->page = page_base(pc);
    s->writable = writable ? 1U : 0U;
    s->original = insn;
    s->trap = g_trap_insn;
    s->armed = 0;

    /* PAGE_AP arms the target page once; the site instruction and its page
     * are not touched at all.  Keep the per-site bookkeeping so status and
     * the clone window report the same shape as the other modes. */
    if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
        s->trap = 0;
        s->armed = 1;
        __atomic_fetch_add(&g_armed, 1, __ATOMIC_ACQ_REL);
        return 0;
    }

    if (g_sess.mode == UROV_Y_MODE_PAGE_UXN) return site_arm_page(s, mm);

    if (!trap_install(pc, insn)) return -ENOSPC;
    /* FOLL_FORCE turns a write fault on the read-only private mapping into the
     * normal COW path (the same mechanism ptrace uses to plant breakpoints), so
     * neither the file page nor the shared page cache is ever modified. */
    wrote = f_access_vm(mm, pc, &s->trap, 4, g_write_gup_flags);
    if (g_verbose)
        pr_info("urov-y: arm pc=%llx wrote=%d writable=%u\n",
                (unsigned long long)pc, wrote, s->writable);
    if (wrote != 4) return wrote < 0 ? wrote : -EFAULT;
    /* copy_to_user_page() handles D-cache maintenance via the kernel alias,
     * including when PAN prevents maintenance using the user VA. */
    uy_flush_icache_all();
    site_set_prot(mm, s->page, (int)s->writable);
    s->armed = 1;
    __atomic_fetch_add(&g_armed, 1, __ATOMIC_ACQ_REL);
    return 0;
}

/* Restore the original instruction. The write goes through the kernel's
 * temporary mapping of the session mm's page (__access_remote_vm), so it works
 * from any task and any mm, including the unload path of a foreign process.
 * The kernel's copy_to_user_page() cleans the D-cache line to the point of
 * coherency through that kernel alias; uy_flush_icache_all() then broadcasts
 * IC IALLUIS, so no instruction cache anywhere keeps the BRK. */
static void site_disarm(struct uy_site *s, void *mm)
{
    if (!s->armed) return;
    if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
        s->armed = 0;
        if (__atomic_load_n(&g_armed, __ATOMIC_ACQUIRE) > 0)
            __atomic_fetch_sub(&g_armed, 1, __ATOMIC_ACQ_REL);
        return;
    }
    if (g_sess.mode == UROV_Y_MODE_PAGE_UXN) {
        site_disarm_page(s, mm);
        return;
    }
    if (f_access_vm(mm, s->pc, &s->original, 4, g_write_gup_flags) == 4)
        uy_flush_icache_all();
    site_set_prot(mm, s->page, (int)s->writable);
    s->armed = 0;
    __atomic_fetch_sub(&g_armed, 1, __ATOMIC_ACQ_REL);
}

/* ------------------------------------------------------------ emulation core */

static int caller_allowed(uint64_t lr)
{
    uint32_t n = g_sess.caller_count;
    uint32_t i;
    if (n == 0U) return 1;
    if (n > UROV_Y_MAX_CALLERS) return 0;
    for (i = 0; i < n; ++i)
        if (lr >= g_sess.caller_start[i] && lr < g_sess.caller_end[i]) return 1;
    return 0;
}

/* libc routines such as memcpy/memcmp/strlen are leaf functions, so the LR at
 * their loads is the business return address and caller_allowed() matches
 * directly.  A library routine that calls an internal helper (for example
 * zlib's crc32 -> crc32_body) leaves the immediate LR pointing inside the
 * library, outside the business window.  Walk the AArch64 frame-pointer chain
 * once to find a saved LR in a window.  A missing frame pointer, a non-user
 * address or a non-monotonic record simply ends the walk, so code compiled
 * without frame pointers keeps the old immediate-LR behaviour.  The stack is
 * read with the same nofault helper the handler already uses for site
 * instructions; a malicious app can only lie about its own caller window. */
static int caller_allowed_deep(struct pt_regs *regs)
{
    uint64_t fp;
    unsigned i;

    if (caller_allowed(regs->regs[30])) return 1;
    fp = regs->regs[29];
    for (i = 0; i < 16; ++i) {
        uint64_t frame[2];
        if (fp < UROV_Y_PAGE || fp > UY_USER_LIMIT - sizeof(frame) || (fp & 7U))
            return 0;
        if (f_copy_in(frame, (const void *)(uintptr_t)fp, sizeof(frame)))
            return 0;
        if (caller_allowed(frame[1])) return 1;
        if (frame[0] <= fp || frame[0] > UY_USER_LIMIT - sizeof(frame) ||
            (frame[0] & 7U))
            return 0;
        fp = frame[0];
    }
    return 0;
}

/* Commit a decoded GPR load whose source bytes are already in `bytes`. */
static void uy_commit(struct uro_regs *m, const struct uro_load *d, const uint8_t *bytes)
{
    uint64_t values[2] = { 0, 0 };
    unsigned element, byte;

    for (element = 0; element < d->count; ++element) {
        uint64_t value = 0;
        for (byte = 0; byte < d->size; ++byte)
            value |= (uint64_t)bytes[element * d->size + byte] << (byte * 8U);
        if (d->sign_extend && d->size < 8U &&
            (value & (UINT64_C(1) << (d->size * 8U - 1U))))
            value |= (~UINT64_C(0)) << (d->size * 8U);
        if (d->dest_bits == 32) value &= UINT64_C(0xffffffff);
        values[element] = value;
    }
    if (d->rt != 31U) m->x[d->rt] = values[0];
    if (d->count == 2U && d->rt2 != 31U) m->x[d->rt2] = values[1];
    if (d->writeback) {
        if (d->rn == 31U) m->sp = d->wb;
        else m->x[d->rn] = d->wb;
    }
    m->pc += 4U;
}

static void commit_model(struct pt_regs *regs, const struct uro_regs *model)
{
    int i;
    for (i = 0; i < 31; ++i) regs->regs[i] = model->x[i];
    regs->sp = model->sp;
    regs->pc = model->pc;
}

static void force_segv(uint64_t far)
{
    if (f_force_sig_fault) f_force_sig_fault(UY_SIGSEGV, UY_SEGV_ACCERR, (void *)far);
}

/* Install the merged bytes of one SIMD&FP load into the caller's vector
 * register(s).  The kernel's own FPSIMD preserve/update pair is used instead of
 * touching the vector registers directly: preserve writes the live register
 * file (or keeps the authoritative saved copy while the task's state is marked
 * foreign) into task_struct.thread.uw.fpsimd_state, this function patches only
 * the destination register there, and update adopts that image, reloads the
 * registers, rebinds them to this CPU and clears the foreign flag before the
 * exception returns to EL0.  A scalar load zero-extends the rest of its V
 * register, as the architecture specifies.  No allocation, no sleeping. */
static int uy_fp_commit(const struct uro_load *d, const uint8_t *bytes)
{
    struct uy_fpstate *state;
    unsigned i;

    if (!g_fp_ready || !f_fp_preserve || !f_fp_update) return -EOPNOTSUPP;
    if (d->rt > 31U || (d->count == 2U && d->rt2 > 31U)) return -EOPNOTSUPP;
    state = (struct uy_fpstate *)((char *)current + g_layout.task_fpsimd);
    f_fp_preserve();
    for (i = 0; i < 16U; ++i)
        state->vregs[d->rt][i] = i < d->size ? bytes[i] : 0;
    if (d->count == 2U) {
        for (i = 0; i < 16U; ++i)
            state->vregs[d->rt2][i] = i < d->size ? bytes[d->size + i] : 0;
    }
    f_fp_update(state);
    return 0;
}

/* Emulate the registered load at `pc`: either merge the fake bytes or read the
 * real memory (both are the same code path as before). On success the model is
 * committed to `regs`. A negative return is a fail-closed condition; *bad then
 * names the address whose access would have raised the original fault. */
static int uy_emulate_load(struct pt_regs *regs, uint64_t pc, uint32_t opcode,
                           int *fake, uint64_t *bad)
{
    struct uro_regs model;
    struct uro_load load;
    uint64_t total;
    uint8_t bytes[32];
    int use_fake = 0;

    *bad = 0;
    for (unsigned i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = pc;
    model.pstate = regs->pstate;

    if ((model.pstate & (UINT64_C(31) | (UINT64_C(1) << 20) | (UINT64_C(1) << 21))) ||
        (pc & 3U) || pc >= UY_USER_LIMIT - 4U)
        return -1;
    if (uro_decode(opcode, &model, &load)) return -2;
    /* A vector load has no GPR destination to fall back on, so without the
     * native FPSIMD helpers the honest answer is the old fail-closed signal. */
    if (load.vector && !g_fp_ready) return -6;
    total = (uint64_t)load.size * load.count;
    if (total == 0U || total > sizeof(bytes) || load.address < UROV_Y_PAGE ||
        load.address >= UY_USER_LIMIT ||
        (load.writeback && (load.wb < UROV_Y_PAGE || load.wb >= UY_USER_LIMIT)))
        return -3;
    if (overlay_live() && load.address >= g_sess.base &&
        load.address - g_sess.base > UROV_Y_PAGE - total)
        return -3;

    if (overlay_live() && mm_of_task(current) == g_sess.mm &&
        !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
        caller_allowed_deep(regs) &&
        load.address >= g_sess.base &&
        load.address - g_sess.base <= UROV_Y_PAGE - total) {
        if (fake_merge(load.address - g_sess.base, (unsigned)total, bytes)) return -4;
        use_fake = 1;
    }
    if (!use_fake) {
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP && overlay_live() &&
            load.address >= g_sess.base &&
            load.address - g_sess.base <= UROV_Y_PAGE - total) {
            /* The target page is the only page AP[1] removed; read its
             * immutable registration snapshot instead of asking uaccess to
             * walk the very permission we cleared. */
            uint64_t off = load.address - g_sess.base;
            unsigned i;
            for (i = 0; i < (unsigned)total; ++i) bytes[i] = g_sess.original[off + i];
        } else if (f_copy_in(bytes, (const void *)load.address, (unsigned long)total)) {
            /* The site instruction would have taken a normal data abort here
             * (unmapped or unreadable address). Forward that as SIGSEGV; it is
             * not an overlay failure. */
            *bad = load.address;
            return -5;
        }
    }

    if (load.vector) {
        /* Commit the vector state first; a refused helper leaves every GPR and
         * PC untouched, which is what fail-closed promises. */
        if (uy_fp_commit(&load, bytes)) return -6;
        if (load.writeback) {
            if (load.rn == 31U) model.sp = load.wb;
            else model.x[load.rn] = load.wb;
        }
        model.pc += 4U;
    } else {
        uy_commit(&model, &load, bytes);
    }
    commit_model(regs, &model);
    if (use_fake)
        __atomic_fetch_add(&g_sess.hits, 1, __ATOMIC_RELAXED);
    else if (overlay_live() && mm_of_task(current) == g_sess.mm)
        __atomic_fetch_add(&g_sess.replays, 1, __ATOMIC_RELAXED);
    *fake = use_fake;
    return 0;
}

/* ------------------------------------------------------- exclusive bridge */

/* A synchronous permission abort returns through ERET, and ERET returns the
 * local exclusive monitor to Open Access.  A native load would not.  The one
 * shape that a same-thread detector can use without touching the protected
 * page with an exclusive instruction is an immediate
 *
 *     ldaxr/ldxr  Xt, [Xn]
 *     ldr/ldrb    ..., [target]     <- our permission abort
 *     stlxr/stxr  Ws, Xt, [Xn]
 *
 * If that exact neighbour pair is present, the handler performs the store and
 * retires the STXR itself, so the caller observes the success it would have
 * observed without the trap.
 *
 * Adjacency alone is not proof that the LDXR was executed: a branch can jump
 * straight to the trapped load, and then the native STXR must fail (no
 * reservation) even though the three instruction words still line up.  The
 * only architectural trace an executed LDXR leaves for us is its destination
 * register: after `ldxr Xt, [Xn]` the register holds the word at [Xn].  A
 * skipped LDXR leaves the caller's pre-load value there, and any write to
 * [Xn] between the pair makes a native STXR fail as well.  So the bridge is
 * armed only when Rt still equals the memory the LDXR would have read; if it
 * does not, the STXR is left in the instruction stream and fails natively.
 *
 * This is deliberately a neighbour-pair bridge, not a general LL/SC emulator:
 * a detector that moves the store across a branch, or preloads Rt with the
 * exact value at [Xn] before jumping over the LDXR, is outside this contract
 * and remains a documented residual (ELIMINATION_DESIGN.md section 11). */
struct uy_llsc {
    int valid;
    int wide;
    unsigned status;
    unsigned base_reg;
    unsigned value_reg;
    uint64_t address;
};

static int uy_is_ldxr(uint32_t insn, unsigned *rn, unsigned *rt, int *wide)
{
    uint32_t base = insn & 0xfffffc00U;

    if (base != 0xc85f7c00U && base != 0x885f7c00U &&
        base != 0xc85ffc00U && base != 0x885ffc00U)
        return 0;
    *rn = (insn >> 5) & 31U;
    *rt = insn & 31U;
    *wide = (base & 0x40000000U) != 0;
    return 1;
}

static int uy_is_stxr(uint32_t insn, unsigned *rn, unsigned *rt, unsigned *status, int *wide)
{
    uint32_t base = insn & 0xffe0fc00U;

    if (base != 0x88007c00U && base != 0xc8007c00U &&
        base != 0x8800fc00U && base != 0xc800fc00U)
        return 0;
    *rn = (insn >> 5) & 31U;
    *rt = insn & 31U;
    *status = (insn >> 16) & 31U;
    *wide = (base & 0x40000000U) != 0;
    return 1;
}

static void uy_llsc_prepare(struct pt_regs *regs, uint64_t pc, struct uy_llsc *out)
{
    uint32_t prev, next;
    uint64_t loaded = 0;
    unsigned lrn, lrt, srn, srt, srs;
    int wide, lwide;

    memset(out, 0, sizeof(*out));
    if (pc < 4U || f_copy_in(&prev, (const void *)(pc - 4U), 4U) ||
        f_copy_in(&next, (const void *)(pc + 4U), 4U))
        return;
    if (!uy_is_ldxr(prev, &lrn, &lrt, &lwide) ||
        !uy_is_stxr(next, &srn, &srt, &srs, &wide))
        return;
    if (lrn != srn || lrt != srt || lwide != wide) return;
    out->address = lrn == 31U ? regs->sp : regs->regs[lrn];
    out->base_reg = lrn;
    out->value_reg = lrt;
    out->status = srs;
    out->wide = wide;
    if (out->address < UROV_Y_PAGE || out->address >= UY_USER_LIMIT - 8U) return;

    /* Do not retire a store the caller did not earn.  If the LDXR really
     * executed, Rt is exactly the value it loaded; the extra nofault read is
     * the same kind of access the handler already performs for the site
     * instruction.  Failure to read (unmapped, raced unmap, or [Xn] on the
     * protected page) leaves the bridge unarmed and the STXR native. */
    if (lrt == 31U) return;
    if (f_copy_in(&loaded, (const void *)out->address, wide ? 8U : 4U)) return;
    if (lwide) {
        if (regs->regs[lrt] != loaded) return;
    } else if ((uint32_t)regs->regs[lrt] != (uint32_t)loaded) {
        return;
    }
    out->valid = 1;
}

/* Run after the faulting load has been committed to `regs`: if that load
 * overwrote the LDXR value register, the native STXR would store the new
 * value, and so must we. */
static void uy_llsc_commit(struct pt_regs *regs, uint64_t pc, const struct uy_llsc *s)
{
    uint64_t value, base;

    if (!s->valid) return;
    /* If the emulated load overwrote the STXR base register, native execution
     * would use a different address; do not invent a success at the old one. */
    base = s->base_reg == 31U ? regs->sp : regs->regs[s->base_reg];
    if (base != s->address) return;
    value = s->value_reg == 31U ? 0 : regs->regs[s->value_reg];
    if (s->wide) {
        if (f_copy_out((void *)(uintptr_t)s->address, &value, 8U)) return;
    } else {
        uint32_t value32 = (uint32_t)value;
        if (f_copy_out((void *)(uintptr_t)s->address, &value32, 4U)) return;
    }
    if (s->status != 31U) regs->regs[s->status] = 0;
    regs->pc = pc + 8U;
    __atomic_fetch_add(&g_sess.llsc, 1, __ATOMIC_RELAXED);
}

/* brk_handler(unused, esr, regs) and do_el0_brk64(esr, regs) both use the
 * same EL0 syndrome and register frame. udata selects the two-argument ABI. */
static void uy_brk_before(hook_fargs3_t *args, void *udata)
{
    uint64_t esr = udata ? args->arg0 : args->arg1;
    struct pt_regs *regs = (struct pt_regs *)(udata ? args->arg1 : args->arg2);
    struct uy_trap *t;
    uint64_t pc, bad = 0;
    int fake = 0, result;

    if (!regs) return;
    if (((esr >> 26) & 0x3fUL) != UY_BRK_EC) return;
    if ((esr & 0xffffUL) != (uint64_t)g_imm) return;
    if (!user_mode(regs)) return;
    if (compat_user_mode(regs)) return;

    pc = regs->pc;
    t = trap_lookup(pc);
    if (!t) {
        /* Arm64 ELR points at the BRK, but tolerate a +4 convention too. */
        t = trap_lookup(pc - 4U);
        if (t) pc = t->pc;
    }
    if (!t) return;
    if (t->pc != pc) pc = t->pc;

    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    result = uy_emulate_load(regs, pc, t->original, &fake, &bad);
    if (result == -5) {
        /* The original instruction would have faulted; forward that. */
        force_segv(bad);
    } else if (result) {
        session_count_failure(pc, result);
        force_segv(pc);
    }
    args->ret = 0;
    args->skip_origin = 1;
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* --------------------------------------------------------- page (UXN) trap */

static struct uy_site *site_by_pc(uint64_t pc)
{
    unsigned i;
    for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
        if (g_sess.sites[i].pc == pc) return &g_sess.sites[i];
    return 0;
}

static struct uy_site *site_by_page(uint64_t page)
{
    unsigned i;
    for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
        if (g_sess.sites[i].page == page) return &g_sess.sites[i];
    return 0;
}

/* Prepare the instruction that follows the emulated site load. When the
 * neighbouring instruction is a plain RET the branch is taken here, which keeps
 * the cost of one site call at a single instruction abort. */
static void page_next_insn(struct pt_regs *regs, uint64_t pc)
{
    uint32_t next;

    if (page_base(pc + 4U) != page_base(pc)) return;
    if (f_copy_in(&next, (const void *)(pc + 4U), 4U)) return;
    if (next == UY_RET_X30) regs->pc = regs->regs[30];
}

/* Emulate one control instruction fetched from a trap page. The trap page is
 * expected to hold only the registered load plus RET/BR/BL/NOP/BTI. */
static int page_flow(struct pt_regs *regs, uint32_t insn)
{
    uint64_t pc = regs->pc;
    uint64_t target;
    unsigned rn;

    if ((insn & UY_FLOW_MASK) == UY_RET_BASE || (insn & UY_FLOW_MASK) == UY_BR_BASE) {
        rn = (insn >> 5) & 31U;
        regs->pc = regs->regs[rn == 31U ? 30U : rn];
        return 0;
    }
    if ((insn & UY_FLOW_MASK) == UY_BLR_BASE) {
        rn = (insn >> 5) & 31U;
        target = regs->regs[rn == 31U ? 30U : rn];
        regs->regs[30] = pc + 4U;
        regs->pc = target;
        return 0;
    }
    if ((insn & UY_IMM26_MASK) == UY_B_IMM26 || (insn & UY_IMM26_MASK) == UY_BL_IMM26) {
        int64_t off = (int64_t)(insn & 0x03ffffffU);
        if (off & 0x02000000LL) off |= ~(int64_t)0x03ffffffLL;
        if ((insn & UY_IMM26_MASK) == UY_BL_IMM26) regs->regs[30] = pc + 4U;
        regs->pc = pc + (uint64_t)(off << 2);
        return 0;
    }
    if (insn == UY_NOP || insn == UY_BTI_C || insn == UY_BTI_J || insn == UY_BTI_JC) {
        regs->pc = pc + 4U;
        return 0;
    }
    return -EOPNOTSUPP;
}

/* The trap page executed an instruction this backend cannot emulate. Never
 * kill the application: detach the trap from that page so the retried fetch
 * runs natively, count the failure, and let the next control request release
 * the half-armed session. */
static void page_degrade(uint64_t pc)
{
    uint64_t page = page_base(pc);
    unsigned i;
    int ret;

    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    if (g_verbose)
        pr_info("urov-y: cannot emulate trapped pc=%llx, detaching page %llx\n",
                (unsigned long long)pc, (unsigned long long)page);
    if (mm_of_task(current) == g_sess.mm) {
        /* Exception context: no mmap lock here, best effort. */
        ret = page_set_uxn(g_sess.mm, page, 0);
        if (ret > 0) flush_tlb_all();
    }
    for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i) {
        if (g_sess.sites[i].page != page || !g_sess.sites[i].armed) continue;
        g_sess.sites[i].armed = 0;
        if (__atomic_load_n(&g_armed, __ATOMIC_ACQUIRE) > 0)
            __atomic_fetch_sub(&g_armed, 1, __ATOMIC_ACQ_REL);
    }
    __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
}

/* EL0 instruction abort (EC 0x20), permission fault at the 4K leaf. */
static void uy_page_abort(uint64_t far, uint64_t esr, struct pt_regs *regs,
                          hook_fargs4_t *args)
{
    struct uy_site *s;
    uint64_t pc, bad = 0;
    uint32_t insn;
    int fake = 0, result;

    if (((esr >> 26) & 0x3fUL) != UY_EC_IABT_LOW) return;
    if ((esr & UY_FSC_PERM_MASK) != UY_FSC_PERM) return;
    if (mm_of_task(current) != g_sess.mm) return;
    pc = regs->pc;
    if (far != pc) return;

    /* Pin the session for the whole emulation: release_session() drains this
     * counter before it clears the sites, so g_sess cannot vanish mid-way. */
    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (!page_mode_live() || mm_of_task(current) != g_sess.mm) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }

    s = site_by_pc(pc);
    if (s) {
        result = uy_emulate_load(regs, pc, s->original, &fake, &bad);
        if (result == -5) {
            force_segv(bad);
        } else if (result) {
            session_count_failure(pc, result);
            force_segv(pc);
        } else {
            page_next_insn(regs, pc);
        }
        args->ret = 0;
        args->skip_origin = 1;
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }

    if (!site_by_page(page_base(pc))) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }
    if (f_copy_in(&insn, (const void *)(uintptr_t)pc, 4)) {
        page_degrade(pc);
    } else if (page_flow(regs, insn)) {
        page_degrade(pc);
    }
    args->ret = 0;
    args->skip_origin = 1;
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* EL0 data abort (EC 0x24) on the AP[1]-protected target page.  Every load of
 * that page arrives here; the caller window still selects fake versus the
 * registration snapshot, and the immediate LDXR/STXR bridge below hides the
 * one side effect the older data-page detector observed -- only when the
 * adjacent LDXR demonstrably executed (its result is still in Rt). */
static void uy_ap_abort(uint64_t far, uint64_t esr, struct pt_regs *regs,
                        hook_fargs4_t *args)
{
    uint64_t pc = regs->pc, bad = 0;
    struct uy_llsc ll;
    uint32_t opcode;
    int fake = 0, result;

    (void)esr;
    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (!ap_mode_live() || mm_of_task(current) != g_sess.mm ||
        far < g_sess.base || far - g_sess.base >= UROV_Y_PAGE) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }
    if (f_copy_in(&opcode, (const void *)(uintptr_t)pc, 4U)) {
        force_segv(far);
    } else {
        uy_llsc_prepare(regs, pc, &ll);
        result = uy_emulate_load(regs, pc, opcode, &fake, &bad);
        if (result == -5) {
            /* The original load would have faulted; forward that. */
            force_segv(bad);
        } else if (result) {
            session_count_failure(pc, result);
            force_segv(far);
        } else {
            uy_llsc_commit(regs, pc, &ll);
        }
    }
    args->ret = 0;
    args->skip_origin = 1;
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* Single do_mem_abort hook for the two page modes: UXN traps a fetch, AP[1]
 * traps a data read.  Everything else falls through to the native handler. */
static void uy_abort_before(hook_fargs4_t *args, void *udata)
{
    uint64_t far = args->arg0;
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    unsigned ec;

    (void)udata;
    if (!g_page_hooked || !regs || !user_mode(regs) || compat_user_mode(regs)) return;
    ec = (unsigned)((esr >> 26) & 0x3fUL);

    if (ap_mode_live()) {
        if (ec == UY_EC_DABT_LOW && !(esr & UY_ESR_WNR) &&
            (esr & UY_FSC_PERM_MASK) == UY_FSC_PERM &&
            mm_of_task(current) == g_sess.mm &&
            far >= g_sess.base && far - g_sess.base < UROV_Y_PAGE)
            uy_ap_abort(far, esr, regs, args);
        return;
    }
    if (!page_mode_live()) return;
    uy_page_abort(far, esr, regs, args);
}

/* A fault-in just (re)created the site page PTE from the VMA protection, which
 * is executable. Re-apply the execute-never bit so a page that was evicted or
 * dropped does not silently lose its trap. Covers the user fault path and
 * get_user_pages based readers such as /proc/self/mem. */
static void uy_mm_fault_after(hook_fargs4_t *args, void *udata)
{
    /* The four- and five-argument wrappers share this prefix. */
    void *vma = (void *)args->arg0;
    uint64_t page = page_base(args->arg1);
    int ret = 0;

    (void)udata;
    if (!g_mmf_hooked || (args->ret & UY_FAULT_INCOMPLETE) || !overlay_live() || !vma) return;
    if (mm_of_task(current) != g_sess.mm) return;
    if (__atomic_load_n((void **)((char *)vma + g_layout.vma_mm), __ATOMIC_RELAXED) != g_sess.mm) return;

    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (mm_of_task(current) == g_sess.mm) {
        if (ap_mode_live() && page == g_sess.base)
            ret = page_set_ap(g_sess.mm, page, 0);
        else if (page_mode_live() && site_by_page(page))
            ret = page_set_uxn(g_sess.mm, page, 1);
    }
    if (ret > 0) flush_tlb_all();
    __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------------- control ops */

static int site_ok(uint64_t site, uint64_t target)
{
    uint32_t opcode;
    struct uro_regs regs;
    struct uro_load load;

    if ((site & 3ULL) || site < UROV_Y_PAGE || site >= UY_USER_LIMIT) return 0;
    if (page_base(site) == target) return 0;
    if (f_copy_in(&opcode, (const void *)site, sizeof(opcode))) return 0;
    memset(&regs, 0, sizeof(regs));
    regs.pc = site;
    /* SITE_BRK/PAGE_UXN emulate the site itself and can only commit a GPR
     * destination.  Vector sites stay rejected there; the PAGE_AP target-page
     * trap is selected by the faulting address, not by a site instruction, so
     * it is the only mode that serves SIMD&FP loads. */
    if (uro_decode(opcode, &regs, &load) || load.vector) return 0;
    return 1;
}

static void release_session(void)
{
    void *mm;
    unsigned i;

    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UY_STATE_LIVE) return;
    mm = g_sess.mm;
    __atomic_store_n(&g_state, UY_STATE_OFF, __ATOMIC_RELEASE);
    {
        unsigned long spins = 0;
        while (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE) && spins++ < 100000000UL)
            __asm__ volatile("yield" ::: "memory");
    }
    if (mm) {
        for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
            site_disarm(&g_sess.sites[i], mm);
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP)
            ap_disarm_target(&g_sess, mm);
    }
    __atomic_store_n(&g_armed, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_suspend, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_degraded, 0, __ATOMIC_RELEASE);
    if (mm) f_mmput(mm);
    memset(&g_sess, 0, sizeof(g_sess));
}

static void reap_dead_session(void)
{
    if (overlay_live() && !mm_has_live_user(g_sess.mm)) release_session();
}

static long do_register(struct urov_y_request *q)
{
    void *task = current;
    void *mm;
    void *vma;
    uint64_t *ptep;
    uint64_t pte;
    unsigned len = request_fake_len(q);
    unsigned i;
    uint32_t mode = q->mode ? q->mode : UROV_Y_MODE_SITE_BRK;
    int site_writable[UROV_Y_MAX_SITES];
    unsigned tries;
    long ret;

    if (q->flags || q->reserved || q->caller_count > UROV_Y_MAX_CALLERS) return -EINVAL;
    if (mode != UROV_Y_MODE_SITE_BRK && mode != UROV_Y_MODE_PAGE_UXN &&
        mode != UROV_Y_MODE_PAGE_AP) return -EINVAL;
    if (mode != UROV_Y_MODE_SITE_BRK && (!g_page_hooked || !g_mmf_hooked))
        return -EOPNOTSUPP;
    if (q->site_count == 0U || q->site_count > UROV_Y_MAX_SITES) return -EINVAL;
    if (q->address & (UROV_Y_PAGE - 1U)) return -EINVAL;
    if (q->address < UROV_Y_PAGE || q->address >= UY_USER_LIMIT) return -EINVAL;
    if (len < 8U || len > UROV_Y_FAKE_PAGE || (len & 7U)) return -EINVAL;
    if (q->offset > UROV_Y_PAGE - len) return -EINVAL;
    for (i = 0; i < q->site_count; ++i)
        if (!site_ok(q->sites[i], q->address)) return -EINVAL;
    for (i = 0; i < q->caller_count; ++i)
        if (q->caller_start[i] >= q->caller_end[i] ||
            q->caller_end[i] > UY_USER_LIMIT) return -EINVAL;
    if (overlay_live()) return -EBUSY;
    {
        unsigned long spins = 0;
        while (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE) && spins++ < 100000000UL)
            __asm__ volatile("yield" ::: "memory");
    }
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

    /* Fault the target in and take a first snapshot before taking the mmap
     * write lock.  copy_from_user_nofault() does not fault pages in, so a
     * demand-paged .text page needs access_remote_vm() here; doing it under
     * the write lock would recurse into handle_mm_fault. */
    if (f_access_vm(mm, q->address, g_sess.original, UROV_Y_PAGE, 0) !=
        (int)UROV_Y_PAGE) {
        memset(g_sess.original, 0, UROV_Y_PAGE);
        f_mmput(mm);
        return -EFAULT;
    }
    /* Stage the overlay image while no reader can see the session yet. */
    ret = fake_stage_request(q, mm, len);
    if (ret) {
        memset(g_sess.original, 0, UROV_Y_PAGE);
        memset(g_fake_stage, 0, len);
        f_mmput(mm);
        return ret;
    }

    ret = -EAGAIN;
    for (tries = 0; tries < 4; ++tries) {
        uy_mmap_write_lock(mm);
        vma = f_find_vma(mm, q->address);
        ret = validate_target_vma(vma, q->address);
        if (!ret) {
            ptep = pte_of(mm, q->address);
            if (!ptep) {
                ret = -EAGAIN;
            } else {
                pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
                if (!(pte & 1ULL) || (pte & 3ULL) != 3ULL) {
                    ret = -EAGAIN;
                } else if (!(pte & PTE_USER) || !(pte & PTE_RDONLY) ||
                           (pte & PTE_UXN) || (pte & PTE_CONT) ||
                           (pte & PTE_SPECIAL) || (pte & PTE_PROT_NONE) ||
                           (pte & PTE_DEVMAP)) {
                    ret = -EOPNOTSUPP;
                }
            }
        }
        for (i = 0; !ret && i < q->site_count; ++i) {
            site_writable[i] = 0;
            ret = validate_site_vma(f_find_vma(mm, q->sites[i]), q->sites[i],
                                    mode != UROV_Y_MODE_SITE_BRK, &site_writable[i]);
        }
        if (!ret && f_copy_in(g_sess.original, (const void *)q->address, UROV_Y_PAGE))
            ret = -EAGAIN;
        uy_mmap_write_unlock(mm);
        if (ret != -EAGAIN) break;
        /* The page was evicted between the snapshot and the write lock. */
        if (f_access_vm(mm, q->address, g_sess.original, UROV_Y_PAGE, 0) !=
            (int)UROV_Y_PAGE) {
            ret = -EFAULT;
            break;
        }
    }
    if (g_verbose)
        pr_info("urov-y: validate ret=%ld addr=%llx sites=%u callers=%u\n", ret,
                (unsigned long long)q->address, q->site_count, q->caller_count);
    if (ret) {
        memset(g_sess.original, 0, UROV_Y_PAGE);
        f_mmput(mm);
        return ret;
    }

    g_sess.mm = mm;
    g_sess.base = q->address;
    g_sess.overlay_offset = q->offset;
    g_sess.overlay_len = len;
    g_sess.site_count = q->site_count;
    g_sess.caller_count = q->caller_count;
    g_sess.mode = mode;
    g_sess.ap_armed = 0;
    for (i = 0; i < q->site_count; ++i) {
        g_sess.sites[i].pc = q->sites[i];
        g_sess.sites[i].armed = 0;
    }
    for (i = 0; i < q->caller_count; ++i) {
        g_sess.caller_start[i] = q->caller_start[i];
        g_sess.caller_end[i] = q->caller_end[i];
    }
    g_sess.fake_seq = 0;
    fake_publish(len);
    g_sess.generation = 1;
    g_sess.hits = 0;
    g_sess.replays = 0;
    g_sess.failures = 0;
    g_sess.llsc = 0;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);

    /* Arm the AP[1] target first; the sites themselves are untouched in that
     * mode.  For the other modes each site is armed first.  Registration is a
     * cooperative transaction: the caller must not read the target from
     * another thread until REGISTER returns, which is also the existing
     * PAGE_UXN assumption. */
    if (mode == UROV_Y_MODE_PAGE_AP)
        ret = ap_arm_target(&g_sess, mm);
    for (i = 0; !ret && i < q->site_count; ++i) {
        ret = site_arm(&g_sess.sites[i], mm, q->sites[i], site_writable[i]);
        if (g_verbose)
            pr_info("urov-y: arm[%u] pc=%llx ret=%ld\n", i,
                    (unsigned long long)q->sites[i], ret);
        if (ret) break;
    }
    if (ret) {
        unsigned j;
        for (j = 0; j < i; ++j) site_disarm(&g_sess.sites[j], mm);
        if (mode == UROV_Y_MODE_PAGE_AP && g_sess.ap_armed)
            ap_disarm_target(&g_sess, mm);
        memset(&g_sess, 0, sizeof(g_sess));
        f_mmput(mm);
        return ret;
    }

    __atomic_store_n(&g_state, UY_STATE_LIVE, __ATOMIC_RELEASE);
    q->session = 1;
    q->generation = 1;
    q->offset = g_sess.overlay_offset;
    q->length = len;
    q->mode = mode;
    q->flags = 0;
    q->value = g_sess.fake[0];
    q->value_hi[0] = g_sess.fake[1];
    q->value_hi[1] = g_sess.fake[2];
    q->value_hi[2] = g_sess.fake[3];
    q->state = UROV_Y_ACTIVE;
    return 0;
}

static long do_set(struct urov_y_request *q)
{
    unsigned len;
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (q->reserved) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    len = request_fake_len(q);
    if (len != g_sess.overlay_len) return -EINVAL;
    ret = fake_stage_request(q, g_sess.mm, len);
    if (ret) {
        memset(g_fake_stage, 0, len);
        return ret;
    }
    fake_publish(len);
    memset(g_fake_stage, 0, len);
    g_sess.generation++;
    q->generation = g_sess.generation;
    q->offset = g_sess.overlay_offset;
    q->length = len;
    q->value = g_sess.fake[0];
    q->value_hi[0] = g_sess.fake[1];
    q->value_hi[1] = g_sess.fake[2];
    q->value_hi[2] = g_sess.fake[3];
    q->state = UROV_Y_ACTIVE;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

static long do_status(struct urov_y_request *q, int with_counters)
{
    if (!session_owned() || q->session != 1) {
        q->session = 0;
        q->generation = 0;
        q->offset = 0;
        q->length = 0;
        q->value = 0;
        q->value_hi[0] = 0;
        q->value_hi[1] = 0;
        q->value_hi[2] = 0;
        q->site_count = 0;
        q->caller_count = 0;
        q->hits = 0;
        q->replays = 0;
        q->failures = 0;
        q->mode = 0;
        q->flags = 0;
        q->state = UROV_Y_INACTIVE;
        return 0;
    }
    q->generation = g_sess.generation;
    q->offset = g_sess.overlay_offset;
    q->length = g_sess.overlay_len;
    q->mode = g_sess.mode;
    q->flags = 0;
    q->value = g_sess.fake[0];
    q->value_hi[0] = g_sess.fake[1];
    q->value_hi[1] = g_sess.fake[2];
    q->value_hi[2] = g_sess.fake[3];
    q->site_count = g_sess.site_count;
    q->caller_count = g_sess.caller_count;
    q->hits = with_counters ? __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED) : 0;
    q->replays = with_counters ? __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED) : 0;
    q->failures = with_counters ? __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED) : 0;
    q->state = UROV_Y_ACTIVE;
    return 0;
}

static long do_deactivate(struct urov_y_request *q)
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
    q->caller_count = 0;
    q->hits = 0;
    q->replays = 0;
    q->failures = 0;
    q->state = UROV_Y_INACTIVE;
    return 0;
}

static long dispatch(struct urov_y_request *q, unsigned cmd)
{
    long ret;

    if (!g_ready) return -EOPNOTSUPP;
    if (!ctrl_try_lock()) return -EBUSY;
    reap_dead_session();
    switch (cmd) {
    case UROV_Y_QUERY: ret = do_status(q, 0); break;
    case UROV_Y_REGISTER: ret = do_register(q); break;
    case UROV_Y_SET: ret = do_set(q); break;
    case UROV_Y_STATUS: ret = do_status(q, 1); break;
    case UROV_Y_DEACTIVATE: ret = do_deactivate(q); break;
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

static void uy_prctl_before(hook_fargs6_t *args, void *udata)
{
    struct urov_y_request q;
    void *user;
    unsigned long size;
    unsigned cmd;
    long ret;

    (void)udata;
    if ((uint32_t)sys_arg(args, 0) != (uint32_t)g_keys.option) return;
    if (sys_arg(args, 1) != g_keys.magic) return;
    user = (void *)sys_arg(args, 3);
    size = (unsigned long)sys_arg(args, 4);
    cmd = (unsigned)sys_arg(args, 2);
    if (!user || size != sizeof(q)) return;
    if (f_copy_in(&q, user, sizeof(q))) return;
    if (q.size != sizeof(q) || q.version != UROV_Y_ABI_VERSION ||
        q.op != (uint16_t)cmd) return;
    if (q.mac != urov_y_request_mac(g_keys.mac, &q)) return;
    ret = dispatch(&q, cmd);
    if (f_copy_out(user, &q, sizeof(q))) ret = -EFAULT;
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* ----------------------------------------------------------- clone window */

#define UY_CLONE_VM 0x00000100ULL

static void uy_clone_before(hook_fargs6_t *args, void *udata)
{
    uint64_t flags = 0;

    args->local.data0 = 0;
    if (!overlay_live()) return;
    if (mm_of_task(current) != g_sess.mm) return;
    if (udata) {
        if (!f_copy_in(&flags, (const void *)sys_arg(args, 0), sizeof(flags)) &&
            (flags & UY_CLONE_VM))
            return;
    } else if (sys_arg(args, 0) & UY_CLONE_VM) {
        return;
    }
    if (!ctrl_lock_wait()) return;
    if (overlay_live() && mm_of_task(current) == g_sess.mm &&
        !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        unsigned i;
        __atomic_store_n(&g_suspend, 1, __ATOMIC_RELEASE);
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
            ap_disarm_target(&g_sess, g_sess.mm);
        } else {
            for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
                site_disarm(&g_sess.sites[i], g_sess.mm);
        }
        args->local.data0 = 1;
    }
    ctrl_unlock();
}

static void uy_clone_after(hook_fargs6_t *args, void *udata)
{
    unsigned i;

    (void)udata;
    if (!args->local.data0) return;
    args->local.data0 = 0;
    if (!ctrl_lock_wait()) return;
    if (overlay_live() && __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
            (void)ap_arm_target(&g_sess, g_sess.mm);
        } else {
            for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i) {
                struct uy_site *s = &g_sess.sites[i];
                if (s->armed) continue;
                (void)site_arm(s, g_sess.mm, s->pc, (int)s->writable);
            }
        }
        __atomic_store_n(&g_suspend, 0, __ATOMIC_RELEASE);
    }
    ctrl_unlock();
}

/* ---------------------------------------------------------- mapping gates */

enum uy_gate_kind {
    UY_GATE_MPROTECT,
    UY_GATE_MUNMAP,
    UY_GATE_MREMAP,
    UY_GATE_MMAP,
    UY_GATE_MADVISE,
    UY_GATE_EXECVE,
};

static const int g_gate_nrs[UY_GATE_NUM] = {
    __NR_mprotect, __NR_munmap, __NR_mremap, __NR_mmap, __NR_madvise, __NR_execve,
};

/* True when [start, start+len) intersects the target page or any site page.
 * A zero length is not a range. */
static int gate_range_overlaps(uint64_t start, uint64_t len)
{
    uint64_t end = start + len;
    uint64_t base = g_sess.base;
    unsigned i;

    if (!len) return 0;
    if (end < start) end = ~0ULL;
    if (start < base + UROV_Y_PAGE && end > base) return 1;
    for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i) {
        uint64_t p = g_sess.sites[i].page;
        if (start < p + UROV_Y_PAGE && end > p) return 1;
    }
    return 0;
}

/* A mapping change that overlaps the target page or any patched site page
 * silently ends the session (restoring the site instructions) and then runs
 * natively, so no mapping syscall has a module-specific errno.  mremap with
 * MREMAP_FIXED also installs the moved range at the destination, so that
 * range has to be checked as well. */
static void uy_gate_before(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;

    if (!overlay_live()) return;
    if (mm_of_task(current) != g_sess.mm) return;
    if (kind == UY_GATE_MMAP && !(sys_arg(args, 3) & 0x10ULL)) return;

    if (kind == UY_GATE_EXECVE) {
        if (ctrl_lock_wait()) {
            release_session();
            ctrl_unlock();
        }
        return;
    }

    if (!gate_range_overlaps(sys_arg(args, 0), sys_arg(args, 1))) {
        if (kind != UY_GATE_MREMAP || !(sys_arg(args, 3) & 0x2ULL)) return;
        if (!gate_range_overlaps(sys_arg(args, 4), sys_arg(args, 2))) return;
    }
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

static int supported_pagetables(void)
{
    uint64_t tcr;
    unsigned t0sz, t1sz;

    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    t0sz = tcr & 63U;
    t1sz = (tcr >> 16) & 63U;

    /* 4 KiB TG0/TG1, no LPA2, and matching walk depths. KernelPatch's
     * pgtable_entry() uses the TTBR1 depth for the supplied PGD as well. */
    return !(tcr & (3ULL << 14)) && ((tcr >> 30) & 3U) == 2U &&
           !(tcr & (1ULL << 59)) && t0sz >= 16U && t1sz >= 16U &&
           t0sz <= 39U && t1sz <= 39U && (60U - t0sz) / 9U == (60U - t1sz) / 9U;
}

static long resolve_kernel(int *brk_argc, int *mmf_argc)
{
    const char *vma_name = "find_vma", *fault_name = "handle_mm_fault";
    uintptr_t start = (uintptr_t)lookup("__start_BTF");
    uintptr_t end = (uintptr_t)lookup("__stop_BTF");
    struct kclf_btf btf;
    unsigned foll_force;

    if (kver < VERSION(5, 4, 0) || kver >= VERSION(7, 0, 0) || !supported_pagetables()) {
        pr_info("urov-y: unsupported kernel or page tables (kver=%x)\n", kver);
        return -EOPNOTSUPP;
    }
    if (!start || end <= start || end - start > 64UL * 1024 * 1024 ||
        kclf_btf_open(&btf, (const void *)start, end - start) || uy_layout_from_btf(&g_layout, &btf)) {
        pr_info("urov-y: live BTF missing or incompatible MM/register layout\n");
        return -EOPNOTSUPP;
    }

    foll_force = uy_foll_force(&btf, kver >= VERSION(6, 3, 0) ? 0x08U : 0x10U);
    g_write_gup_flags = UY_FOLL_WRITE | foll_force;
    f_brk_handler = lookup("do_el0_brk64");
    *brk_argc = f_brk_handler ? 2 : 3;
    if (!f_brk_handler) f_brk_handler = lookup("brk_handler");

    f_do_mem_abort = lookup("do_mem_abort");
    f_handle_mm_fault = lookup(fault_name);
    *mmf_argc = f_handle_mm_fault ? uy_mm_fault_argc(&btf, fault_name, 4) : 0;
    if (!*mmf_argc) {
        fault_name = "do_handle_mm_fault";
        f_handle_mm_fault = lookup(fault_name);
        *mmf_argc = f_handle_mm_fault ? uy_mm_fault_argc(&btf, fault_name, 0) : 0;
    }

    f_get_task_mm = (get_task_mm_t)lookup("get_task_mm");
    f_mmput = (mmput_t)lookup("mmput");
    f_find_vma = (find_vma_t)lookup(vma_name);
    if (!f_find_vma) {
        vma_name = "__find_vma";
        f_find_vma = (find_vma_t)lookup(vma_name);
    }
    f_mmap_write_lock = (mmap_write_fn)lookup("mmap_write_lock");
    f_mmap_write_unlock = (mmap_write_fn)lookup("mmap_write_unlock");
    g_use_rwsem = !f_mmap_write_lock || !f_mmap_write_unlock;
    if (g_use_rwsem && g_layout.mmap_lock >= 0) {
        f_mmap_write_lock = (mmap_write_fn)lookup("down_write");
        f_mmap_write_unlock = (mmap_write_fn)lookup("up_write");
    }

    f_flush_tlb_mm = (flush_tlb_mm_t)lookup("flush_tlb_mm");
    f_force_sig_fault = (force_sig_fault_t)lookup("force_sig_fault");
    f_copy_in = (copy_nofault_t)lookup("copy_from_user_nofault");
    if (!f_copy_in) f_copy_in = (copy_nofault_t)lookup("probe_user_read");
    f_copy_out = (copy_nofault_t)lookup("copy_to_user_nofault");
    f_access_vm = (access_remote_vm_t)lookup("access_remote_vm");
    if (!f_access_vm) f_access_vm = (access_remote_vm_t)lookup("__access_remote_vm");

    /* The large-transfer path needs the kernel's own FPSIMD state handling:
     * fpsimd_signal_preserve_current_state() saves the live vector registers
     * (and syncs an SVE task's state down to FPSIMD), and
     * fpsimd_update_current_state() adopts the patched image and reloads it.
     * Without both, or without the BTF layout of thread.uw.fpsimd_state, a
     * SIMD&FP load keeps failing closed instead of returning original bytes. */
    f_fp_preserve = (fpsimd_preserve_t)lookup("fpsimd_signal_preserve_current_state");
    f_fp_update = (fpsimd_update_t)lookup("fpsimd_update_current_state");
    g_fp_ready = f_fp_preserve && f_fp_update && g_layout.task_fpsimd >= 0;

    if (!f_brk_handler || !f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_force_sig_fault ||
        !f_copy_in || !f_copy_out || !f_access_vm || !foll_force) {
        pr_info("urov-y: required BRK/MM/uaccess ABI unavailable\n");
        return -EOPNOTSUPP;
    }
    if (g_verbose)
        pr_info("urov-y: kver=%x BTF task.mm=%d mm.pgd=%d mm.users=%d vma.flags=%d vma.file=%d "
                "task.fpsimd=%d fpsimd=%d lookup=%s lock=%s mm_fault=%s/%d brk_args=%d "
                "foll_force=0x%x\n",
                kver, g_layout.task_mm, g_layout.mm_pgd, g_layout.mm_users,
                g_layout.vma_flags, g_layout.vma_file, g_layout.task_fpsimd,
                g_fp_ready, vma_name, g_use_rwsem ? "rwsem" : "mmap",
                *mmf_argc ? fault_name : "none", *mmf_argc, *brk_argc, foll_force);
    return 0;
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

long urov_y_backend_init(const char *args)
{
    uint8_t key[16];
    uint64_t kdf_key[2];
    int have_key = 0;
    unsigned int checks = 0;
    long ret;
    int i, brk_argc, mmf_argc;

    memset(key, 0, sizeof(key));
    ret = parse_args(args, key, &have_key);
    if (ret) return ret;
    if (!have_key) return -EINVAL;
    kdf_key[0] = urov_x_load64(key);
    kdf_key[1] = urov_x_load64(key + 8);
    urov_x_derive(key, &g_keys);
    g_imm = (uint16_t)(urov_x_kdf(kdf_key, 5U) & 0xffffU);
    if (g_imm < 2U) g_imm = (uint16_t)(g_imm ^ 0x8000U);
    g_trap_insn = UY_BRK_BASE | ((uint32_t)g_imm << 5);
    memset(key, 0, sizeof(key));
    memset(kdf_key, 0, sizeof(kdf_key));

    if (!kallsyms_lookup_name) return -ENOSYS;
    if (uro_core_selftest(g_selftest_ws, &checks) || checks != URO_CORE_CHECKS) return -EINVAL;

    ret = resolve_kernel(&brk_argc, &mmf_argc);
    if (ret) return ret;
    g_wrapper_mode = has_syscall_wrapper ? 1 : 0;

    ret = hook_wrap(f_brk_handler, brk_argc, uy_brk_before, 0,
                    (void *)(uintptr_t)(brk_argc == 2));
    if (ret) {
        if (g_verbose) pr_info("urov-y: hook brk_handler failed: %ld\n", ret);
        return -EOPNOTSUPP;
    }
    g_brk_hooked = 1;

    ret = fp_hook_syscalln(__NR_prctl, 6, uy_prctl_before, 0, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-y: hook prctl failed: %ld\n", ret);
        goto unwind_brk;
    }
    g_prctl_hooked = 1;

    for (i = 0; i < UY_GATE_NUM; ++i) {
        ret = fp_hook_syscalln(g_gate_nrs[i], 6, uy_gate_before, 0, (void *)(uintptr_t)i);
        if (ret) {
            if (g_verbose) pr_info("urov-y: hook gate %d failed: %ld\n", g_gate_nrs[i], ret);
            break;
        }
        g_gate_hooked[i] = 1;
    }
    if (i != UY_GATE_NUM) {
        while (i-- > 0) {
            fp_unhook_syscalln(g_gate_nrs[i], uy_gate_before, 0);
            g_gate_hooked[i] = 0;
        }
        goto unwind_prctl;
    }

    ret = fp_hook_syscalln(__NR_clone, 6, uy_clone_before, uy_clone_after, (void *)0);
    g_clone_hooked = ret ? 0 : 1;
#ifdef __NR_clone3
    ret = fp_hook_syscalln(__NR_clone3, 6, uy_clone_before, uy_clone_after, (void *)1);
    g_clone3_hooked = ret ? 0 : 1;
#endif

    /* Both page modes require the abort hook and the PTE rearm hook. */
    if (f_do_mem_abort && mmf_argc) {
        ret = hook_wrap(f_do_mem_abort, 3, uy_abort_before, 0, 0);
        g_page_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-y: hook do_mem_abort failed: %ld\n", ret);
    }
    if (g_page_hooked) {
        ret = hook_wrap(f_handle_mm_fault, mmf_argc, 0, uy_mm_fault_after, 0);
        g_mmf_hooked = ret ? 0 : 1;
        if (ret) {
            if (g_verbose) pr_info("urov-y: hook MM fault handler failed: %ld\n", ret);
            hook_unwrap(f_do_mem_abort, uy_abort_before, 0);
            g_page_hooked = 0;
        }
    }
    g_ready = 1;

    if (g_verbose)
        pr_info("urov-y: backend ready brk_imm=%x trap=%x page_mode=%d\n",
                (unsigned)g_imm, (unsigned)g_trap_insn, g_page_hooked && g_mmf_hooked);
    return 0;

unwind_prctl:
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, uy_prctl_before, 0);
        g_prctl_hooked = 0;
    }
unwind_brk:
    if (g_brk_hooked) {
        hook_unwrap(f_brk_handler, uy_brk_before, 0);
        g_brk_hooked = 0;
    }
    return -EOPNOTSUPP;
}

long urov_y_copy_to_user(void *dst, const void *src, unsigned long len)
{
    return f_copy_out(dst, src, len);
}

long urov_y_backend_exit(void)
{
    int i;

    if (g_verbose)
        pr_info("urov-y: exit live=%d armed=%d handlers=%d\n", overlay_live(),
                __atomic_load_n(&g_armed, __ATOMIC_ACQUIRE),
                __atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE));
    /* Always unwound here: site restore uses __access_remote_vm() on the
     * session mm and a broadcast I-cache invalidate, so it is safe from the
     * unload task even while the owner keeps running. */
    g_ready = 0;
    if (ctrl_lock_wait()) {
        release_session();
        ctrl_unlock();
    }
    for (i = 0; i < UY_GATE_NUM; ++i) {
        if (!g_gate_hooked[i]) continue;
        fp_unhook_syscalln(g_gate_nrs[i], uy_gate_before, 0);
        g_gate_hooked[i] = 0;
    }
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, uy_prctl_before, 0);
        g_prctl_hooked = 0;
    }
    if (g_clone3_hooked) {
        fp_unhook_syscalln(__NR_clone3, uy_clone_before, uy_clone_after);
        g_clone3_hooked = 0;
    }
    if (g_clone_hooked) {
        fp_unhook_syscalln(__NR_clone, uy_clone_before, uy_clone_after);
        g_clone_hooked = 0;
    }
    if (g_brk_hooked) {
        hook_unwrap(f_brk_handler, uy_brk_before, 0);
        g_brk_hooked = 0;
    }
    if (g_page_hooked) {
        hook_unwrap(f_do_mem_abort, uy_abort_before, 0);
        g_page_hooked = 0;
    }
    if (g_mmf_hooked) {
        hook_unwrap(f_handle_mm_fault, 0, uy_mm_fault_after);
        g_mmf_hooked = 0;
    }
    memset(g_traps, 0, sizeof(g_traps));
    memset(&g_keys, 0, sizeof(g_keys));
    return 0;
}

void urov_y_reap(void)
{
    if (!g_ready) return;
    if (ctrl_lock_wait()) {
        reap_dead_session();
        ctrl_unlock();
    }
}

void urov_y_status_get(struct uy_status *out)
{
    unsigned i;

    if (!out) return;
    out->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    out->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    out->llsc = __atomic_load_n(&g_sess.llsc, __ATOMIC_RELAXED);
    out->active = overlay_live() ? 1U : 0U;
    out->sites = overlay_live() ? g_sess.site_count : 0U;
    out->armed = 0;
    if (overlay_live()) {
        for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
            out->armed += g_sess.sites[i].armed ? 1U : 0U;
    }
    out->hooks = (g_brk_hooked ? 1U : 0U) | (g_prctl_hooked ? 2U : 0U) |
                 ((g_gate_hooked[0] && g_gate_hooked[1] && g_gate_hooked[2] &&
                   g_gate_hooked[3] && g_gate_hooked[4] && g_gate_hooked[5]) ? 4U : 0U) |
                 (g_clone_hooked ? 8U : 0U) | (g_clone3_hooked ? 16U : 0U) |
                 (g_page_hooked ? 32U : 0U) | (g_mmf_hooked ? 64U : 0U);
    out->mode = overlay_live() ? g_sess.mode : 0U;
    out->degraded = __atomic_load_n(&g_degraded, __ATOMIC_ACQUIRE) ? 1U : 0U;
    out->core_checks = URO_CORE_CHECKS;
    out->imm = (uint32_t)g_imm;
    out->fpsimd = g_fp_ready ? 1U : 0U;
    out->overlay_len = overlay_live() ? g_sess.overlay_len : 0U;
    out->abi = UROV_Y_ABI_VERSION;
}
