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
typedef int (*access_remote_vm_task_t)(void *task, void *mm, unsigned long addr, void *buf,
                                       int len, unsigned int gup_flags);
typedef void *(*kvmalloc_node_t)(uint64_t size, unsigned int flags, int node);
typedef void (*kvfree_t)(const void *addr);
typedef void *(*vmalloc_t)(unsigned long size);
typedef void (*vfree_t)(const void *addr);
typedef long (*kernel_read_t)(void *file, void *buf, unsigned long count,
                              int64_t *pos);
typedef void *(*filp_open_t)(const char *path, int flags, unsigned short mode);
typedef int (*filp_close_t)(void *file, void *owner);

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

/* One page of a session.  `image` is the published read view: whole-page
 * SRC_FILE/SRC_USER bytes, or for a partial SRC_USER window the page's
 * original bytes with that window replaced.  `snapshot` keeps what the
 * mapping held at registration time and serves the transparent (foreign
 * caller) path; it exists only when the session needs replay.  Images are
 * swapped by SET/SET_PAGE under per-page `seq`, so a reader either sees the
 * old or the new whole-page view, never a torn one. */
struct uy_page {
    uint64_t base;
    uint8_t *image;
    uint8_t *snapshot;
    uint8_t *retired;    /* previous image, freed after the handlers drain */
    uint32_t index;      /* descriptor index before sorting */
    uint32_t flags;      /* UROV_Y_PAGE_SRC_* */
    uint32_t fake_off;
    uint32_t fake_len;
    uint32_t seq;
    uint32_t armed;
    uint32_t changed;    /* this session cleared AP[1] on the leaf PTE */
};

struct uy_session {
    void *mm;
    uint64_t generation;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;
    uint64_t caller_start[UROV_Y_MAX_CALLERS];
    uint64_t caller_end[UROV_Y_MAX_CALLERS];
    struct uy_page *pages;     /* page_count entries, sorted by base */
    uint8_t *arena;            /* page_count * UROV_Y_PAGE image bytes */
    uint8_t *snapshots;        /* page_count * UROV_Y_PAGE snapshot bytes, or NULL */
    uint64_t arena_bytes;
    uint64_t snapshot_bytes;
    uint32_t page_count;
    uint32_t site_count;
    uint32_t caller_count;
    uint32_t mode;
    uint32_t ap_armed;
    uint32_t pad;
    struct uy_site sites[UROV_Y_MAX_SITES];
};

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
/* Staging area for a v7 REGISTER/SET overlay image.  The caller's buffer is
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
static uint32_t g_max_pages = UROV_Y_MAX_PAGES;
static uint64_t g_max_image_bytes = UINT64_C(8) << 20;
static uint32_t g_caps;

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
static access_remote_vm_task_t f_access_vm_task;
static fpsimd_preserve_t f_fp_preserve;
static fpsimd_update_t f_fp_update;
static kvmalloc_node_t f_kvmalloc_node;
static kvfree_t f_kvfree;
static vmalloc_t f_vmalloc;
static vfree_t f_vfree;
static kernel_read_t f_kernel_read;

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

static int uy_access_vm(void *mm, unsigned long addr, void *buf,
                        int len, unsigned int flags)
{
    if (f_access_vm) return f_access_vm(mm, addr, buf, len, flags);
    /* Old public access_remote_vm() supplies a NULL task to this variant.
     * Passing current here would associate a foreign mm with the unload task. */
    return f_access_vm_task(0, mm, addr, buf, len, flags);
}

/* For sleepable control only. Early 5.x has probe_user_read() but may lack a
 * nofault write helper. Use ordinary writable GUP, never FOLL_FORCE, for a
 * reply to the caller; the exception path must never use this fallback. */
static long uy_copy_control_reply(void *dst, const void *src, unsigned long len)
{
    uint64_t addr = (uintptr_t)dst;
    void *mm;
    int copied;

    if (f_copy_out) return f_copy_out(dst, src, len);
    if (!addr || addr >= UY_USER_LIMIT || len > UY_USER_LIMIT - addr || len > 0x7fffffffU)
        return -EFAULT;
    mm = f_get_task_mm(current);
    if (!mm) return -EFAULT;
    copied = uy_access_vm(mm, addr, (void *)src, (int)len, UY_FOLL_WRITE);
    f_mmput(mm);
    return copied == (int)len ? 0 : -EFAULT;
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

/* Sleepable contexts only (registration, SET, unload).  kvmalloc() keeps
 * small quotas out of the vmalloc address space; vmalloc() is the fallback
 * when the running kernel does not expose kvmalloc_node/kvfree. */
static void *uy_alloc(unsigned long bytes)
{
    void *p;

    if (!bytes) return 0;
    if (f_kvmalloc_node) {
        p = f_kvmalloc_node((uint64_t)bytes, 0xcc0U /* GFP_KERNEL */, -1);
        if (p) return p;
    }
    if (f_vmalloc) return f_vmalloc(bytes);
    return 0;
}

static void uy_free(void *p)
{
    if (!p) return;
    if (f_kvfree) f_kvfree(p);
    else if (f_vfree) f_vfree(p);
}

/* Bounded wait for in-flight fault handlers.  Every caller runs in a
 * sleepable control path; the fault path itself never waits on this side. */
static int drain_handlers(void)
{
    unsigned long spins = 0;

    while (__atomic_load_n(&g_handlers, __ATOMIC_ACQUIRE)) {
        if (spins++ > 100000000UL) return -EBUSY;
        __asm__ volatile("yield" ::: "memory");
    }
    return 0;
}

/* The page table walker returns the leaf that covers this aligned page.  The
 * array is sorted by base, so a miss is a genuine "not part of the session". */
static struct uy_page *page_find(uint64_t page)
{
    uint32_t lo = 0, hi = g_sess.page_count;

    if (!g_sess.pages || !g_sess.page_count) return 0;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t base = g_sess.pages[mid].base;
        if (page < base) hi = mid;
        else if (page > base) lo = mid + 1;
        else return &g_sess.pages[mid];
    }
    return 0;
}

static struct uy_page *page_by_index(uint32_t index)
{
    uint32_t i;

    for (i = 0; i < g_sess.page_count; ++i)
        if (g_sess.pages[i].index == index) return &g_sess.pages[i];
    return 0;
}

/* Copy one segment of the published read view.  `replay` selects the
 * registration snapshot (transparent path); otherwise the image is already
 * the merged whole-page view, so no per-byte window arithmetic is needed.
 * The sequence word makes a concurrent SET/SET_PAGE all-or-nothing. */
static int page_view(struct uy_page *p, uint64_t off, unsigned total,
                     uint8_t *out, int replay)
{
    unsigned tries;

    for (tries = 0; tries < UY_FAKE_RETRY; ++tries) {
        uint32_t seq = __atomic_load_n(&p->seq, __ATOMIC_ACQUIRE);
        const uint8_t *src;

        if (seq & 1U) {
            __asm__ volatile("yield" ::: "memory");
            continue;
        }
        src = replay ? p->snapshot : __atomic_load_n(&p->image, __ATOMIC_RELAXED);
        if (!src) return -EINVAL;
        memcpy(out, src + off, total);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&p->seq, __ATOMIC_RELAXED) == seq) return 0;
    }
    return -EAGAIN;
}

static int range_covered(uint64_t address, unsigned total)
{
    uint64_t done = 0;

    while (done < total) {
        uint64_t cur = address + done;
        uint64_t off = cur - page_base(cur);
        unsigned seg = (unsigned)(UROV_Y_PAGE - off);

        if (seg > total - done) seg = (unsigned)(total - done);
        if (page_find(page_base(cur))) return 1;
        done += seg;
    }
    return 0;
}

/* Read [address, address+total) into `out`, using the page images for every
 * registered segment and nofault uaccess for the rest.  Returns 1 when at
 * least one segment was served by the session, 0 when the whole range was
 * native memory, and a negative fail-closed code otherwise.  Cross-page
 * access is just this loop; a 64-byte LD1 can span two 4 KiB pages. */
static int read_range(uint64_t address, unsigned total, int allow_fake,
                      uint8_t *out, uint64_t *bad)
{
    uint64_t done = 0;
    int covered = 0;

    while (done < total) {
        uint64_t cur = address + done;
        uint64_t off = cur - page_base(cur);
        unsigned seg = (unsigned)(UROV_Y_PAGE - off);
        struct uy_page *p;

        if (seg > total - done) seg = (unsigned)(total - done);
        p = page_find(page_base(cur));
        if (p) {
            covered = 1;
            if (page_view(p, off, seg, out + done, !allow_fake)) return -4;
        } else if (f_copy_in(out + done, (const void *)(uintptr_t)cur, seg)) {
            *bad = cur;
            return -5;
        }
        done += seg;
    }
    return covered;
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
        if (uy_access_vm(mm, q->fake_addr, g_fake_stage, (int)len, 0) != (int)len)
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

/* The first SET of a session retires the page's registration image, which is
 * a slice of the shared arena rather than a separate allocation.  Only images
 * allocated by SET_PAGE/SET may be handed to kvfree later. */
static int image_in_arena(const void *img)
{
    uintptr_t p = (uintptr_t)img;
    uintptr_t base = (uintptr_t)g_sess.arena;

    return img && g_sess.arena && p >= base && p < base + g_sess.arena_bytes;
}

static void free_retired(struct uy_page *p)
{
    if (p->retired && !image_in_arena(p->retired)) uy_free(p->retired);
    p->retired = 0;
}

/* Publish a new whole-page image for one page.  The sequence word covers the
 * image pointer and the window metadata; the previous image stays allocated
 * until every handler that could still hold it has returned. */
static void page_swap_image(struct uy_page *p, uint8_t *image, uint32_t off,
                            uint32_t len)
{
    uint8_t *old = p->image;
    uint32_t seq = __atomic_load_n(&p->seq, __ATOMIC_RELAXED);

    __atomic_store_n(&p->seq, seq + 1U, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&p->image, image, __ATOMIC_RELEASE);
    p->fake_off = off;
    p->fake_len = len;
    __atomic_store_n(&p->seq, seq + 2U, __ATOMIC_RELEASE);

    if (drain_handlers() == 0) {
        free_retired(p);
        p->retired = old;
    } else if (!p->retired) {
        /* Cannot prove the old image is unused; keep it for the next release
         * instead of freeing it under a running handler. */
        p->retired = old;
    }
}

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < 8U; ++i) value |= (uint64_t)p[i] << (8U * i);
    return value;
}

/* The legacy `value`/`value_hi` words describe page 0's window: up to 32
 * bytes starting at fake_off, zero-padded past fake_len. */
static void page_status_words(struct urov_y_request *q, struct uy_page *p)
{
    uint8_t bytes[32];
    unsigned n;

    memset(bytes, 0, sizeof(bytes));
    n = p->fake_len < sizeof(bytes) ? p->fake_len : (unsigned)sizeof(bytes);
    if (p->image && n) memcpy(bytes, p->image + p->fake_off, n);
    q->value = load_le64(bytes);
    q->value_hi[0] = load_le64(bytes + 8);
    q->value_hi[1] = load_le64(bytes + 16);
    q->value_hi[2] = load_le64(bytes + 24);
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

static int page_update_bits(void *mm, uint64_t page, uint64_t set, uint64_t clear,
                            uint64_t required, uint64_t forbidden)
{
    unsigned attempt;

    for (attempt = 0; attempt < 4; ++attempt) {
        uint64_t *ptep, old, next;
        int ret = page_pte_leaf(mm, page, &ptep, &old);

        if (ret) return ret;
        if ((old & required) != required || (old & forbidden)) return -EOPNOTSUPP;
        next = (old | set) & ~clear;
        if (old == next) return 0;
        /* Reclaim, hardware AF and per-VMA fault paths can update a leaf
         * independently of the mmap lock. Don't overwrite a newer PTE. */
        if (__atomic_compare_exchange_n(ptep, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
    }
    return -EAGAIN;
}

/* Some kernels leave a writable leaf after forced COW of an RX mapping. */
static void site_set_prot(void *mm, uint64_t page, int writable)
{
    int ret;

    uy_mmap_write_lock(mm);
    ret = page_update_bits(mm, page, PTE_AF | (writable ? PTE_DBM : PTE_RDONLY),
                           writable ? PTE_RDONLY : PTE_DBM, PTE_USER, 0);
    if (ret > 0) {
        if (f_flush_tlb_mm) f_flush_tlb_mm(mm);
        else flush_tlb_all();
    }
    uy_mmap_write_unlock(mm);
}

/* Toggle EL0 execute-never on a site page. The caller either holds the mmap
 * write lock (arm/disarm) or is completing the fault that just installed this
 * exact PTE. Returns 1 when the entry changed, 0 when it was already in the
 * requested state, negative on a page that cannot be trapped. */
static int page_set_uxn(void *mm, uint64_t page, int set)
{
    return page_update_bits(mm, page, set ? PTE_UXN : 0, set ? 0 : PTE_UXN, PTE_USER, 0);
}

/* Toggle EL0 data permission (AP[1]) on the target page.  With AP[2] (read-
 * only) held, clearing AP[1] makes every EL0 data read of this page take a
 * permission abort, while EL0 instruction fetch is governed by UXN alone and
 * stays native.  The caller holds the mmap write lock, or is completing the
 * fault that installed this PTE. */
static int page_set_ap(void *mm, uint64_t page, int set)
{
    return page_update_bits(mm, page, set ? PTE_USER : 0, set ? 0 : PTE_USER, PTE_RDONLY, PTE_UXN);
}

static int page_pte_ok(void *mm, uint64_t base);

/* Registration already faulted every target page in and copied it, so arming
 * only needs to flip AP[1] under one mmap write lock and a single TLB flush.
 * A private .text page is ordinary reclaimable file-backed memory, so a
 * re-fault between the snapshot and the lock can drop a PTE again; fault all
 * pages back in and retry rather than failing a registration that raced with
 * reclaim.  Any partial attempt is rolled back before returning. */
static long ap_arm_pages(struct uy_session *s, void *mm)
{
    uint32_t i;
    int ret = -EAGAIN, tries;

    for (tries = 0; tries < 4; ++tries) {
        int failed = 0;

        uy_mmap_write_lock(mm);
        for (i = 0; i < s->page_count; ++i) {
            struct uy_page *p = &s->pages[i];
            ret = validate_target_vma(f_find_vma(mm, p->base), p->base);
            if (!ret) ret = page_pte_ok(mm, p->base);
            if (!ret) ret = page_set_ap(mm, p->base, 0);
            if (ret < 0) {
                failed = 1;
                break;
            }
            if (ret > 0) p->changed = 1;
            p->armed = 1;
        }
        if (!failed) {
            flush_tlb_all();
            s->ap_armed = 1;
            __atomic_store_n(&g_armed, (int)s->page_count, __ATOMIC_RELEASE);
            uy_mmap_write_unlock(mm);
            return 0;
        }
        while (i-- > 0) {
            struct uy_page *p = &s->pages[i];
            if (!p->changed) continue;
            (void)page_set_ap(mm, p->base, 1);
            p->changed = 0;
        }
        flush_tlb_all();
        uy_mmap_write_unlock(mm);
        if (ret != -EAGAIN && ret != -EFAULT) return ret;
        for (i = 0; i < s->page_count; ++i) {
            uint32_t word;
            if (uy_access_vm(mm, s->pages[i].base, &word, 4, 0) != 4) return -EFAULT;
        }
    }
    return ret < 0 ? ret : -EAGAIN;
}

static void ap_disarm_pages(struct uy_session *s, void *mm)
{
    uint32_t i;

    if (!s->ap_armed) return;
    s->ap_armed = 0;
    __atomic_store_n(&g_armed, 0, __ATOMIC_RELEASE);
    if (!mm || !mm_has_live_user(mm)) return;
    uy_mmap_write_lock(mm);
    for (i = 0; i < s->page_count; ++i) {
        struct uy_page *p = &s->pages[i];
        p->armed = 0;
        if (!p->changed) continue;
        (void)page_set_ap(mm, p->base, 1);
        p->changed = 0;
    }
    flush_tlb_all();
    uy_mmap_write_unlock(mm);
}

/* Fault the page in if needed, then install the trap bit. No byte of the code
 * page is touched: the page stays the clean file-backed page it was, so a
 * file-vs-memory comparison and smaps are both unchanged. */
static long site_arm_page(struct uy_site *s, void *mm)
{
    uint32_t word;
    int ret = -EAGAIN, tries;

    if (uy_access_vm(mm, s->pc, &word, 4, 0) != 4) {
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
        if (uy_access_vm(mm, s->pc, &word, 4, 0) != 4) return -EFAULT;
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
    wrote = uy_access_vm(mm, pc, &s->trap, 4, g_write_gup_flags);
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
    if (uy_access_vm(mm, s->pc, &s->original, 4, g_write_gup_flags) == 4)
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

/* LD1/LD2/LD3/LD4: distribute one contiguous byte range into up to four
 * destination V registers, de-interleaving for LD2/LD3/LD4.  The memory
 * offset of (repeat r, element e, structure s) is
 * ((r * elements + e) * selem + s) * esize and the register offset is
 * e * esize, which is exactly the ARM ARM formula.  A 64-bit datasize
 * zero-extends the upper half of every destination register. */
static int uy_fp_commit_multi(const struct uro_load *d, const uint8_t *bytes)
{
    struct uy_fpstate *state;
    unsigned nregs = d->nregs * d->selem;
    unsigned r, s, e, i;

    if (!g_fp_ready || !f_fp_preserve || !f_fp_update) return -EOPNOTSUPP;
    if (d->nregs < 1U || d->nregs > 4U || d->selem < 1U || d->selem > 4U ||
        nregs > 4U || d->esize < 1U || d->esize > 16U ||
        d->elements < 1U || d->elements > 16U || d->size > 16U)
        return -EOPNOTSUPP;
    for (i = 0; i < nregs; ++i)
        if (d->dst[i] > 31U) return -EOPNOTSUPP;

    state = (struct uy_fpstate *)((char *)current + g_layout.task_fpsimd);
    f_fp_preserve();
    for (r = 0; r < d->nregs; ++r) {
        for (s = 0; s < d->selem; ++s) {
            unsigned dst = d->dst[r * d->selem + s];
            for (e = 0; e < d->elements; ++e) {
                uint64_t src = ((uint64_t)(r * d->elements + e) * d->selem + s) * d->esize;
                memcpy(&state->vregs[dst][e * d->esize], bytes + src, d->esize);
            }
            if (d->size < 16U)
                memset(&state->vregs[dst][d->size], 0, 16U - d->size);
        }
    }
    f_fp_update(state);
    return 0;
}

/* Emulate one load at `pc`: serve the bytes from the registered page images
 * (fake or registration snapshot) plus nofault uaccess for segments outside
 * the session.  `far` is the data-abort address for the PAGE_AP path (0 and
 * check_far==0 for the instruction-trap modes) and must fall inside the
 * decoded access range.  On success the model is committed to `regs`. A
 * negative return is a fail-closed condition; *bad then names the address
 * whose access would have raised the original fault. */
static int uy_emulate_load(struct pt_regs *regs, uint64_t pc, uint32_t opcode,
                           uint64_t far, int check_far, int *fake, uint64_t *bad)
{
    struct uro_regs model;
    struct uro_load load;
    uint64_t total;
    uint8_t bytes[64];
    int use_fake = 0, covered;
    unsigned i;

    *bad = 0;
    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
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
    total = load.total;
    if (!total || total > sizeof(bytes) || load.address < UROV_Y_PAGE ||
        load.address >= UY_USER_LIMIT ||
        (load.writeback && (load.wb < UROV_Y_PAGE || load.wb >= UY_USER_LIMIT)))
        return -3;
    if (!overlay_live() || mm_of_task(current) != g_sess.mm) return -3;
    if (check_far && (far < load.address || far - load.address >= total)) return -3;

    covered = range_covered(load.address, (unsigned)total);
    if (!covered) {
        /* A site-mode instruction that does not touch its target page keeps
         * the historical fail-closed answer.  PAGE_AP can only get here when
         * the access starts outside every registered page, which is a legal
         * native read. */
        if (g_sess.mode != UROV_Y_MODE_PAGE_AP) return -3;
        if (f_copy_in(bytes, (const void *)(uintptr_t)load.address, (unsigned long)total)) {
            *bad = load.address;
            return -5;
        }
    } else {
        int allow_fake = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
                         caller_allowed_deep(regs);
        int ret = read_range(load.address, (unsigned)total, allow_fake, bytes, bad);

        if (ret < 0) return ret;
        use_fake = allow_fake;
    }

    if (load.multi) {
        if (uy_fp_commit_multi(&load, bytes)) return -6;
        if (load.writeback) {
            if (load.rn == 31U) model.sp = load.wb;
            else model.x[load.rn] = load.wb;
        }
        model.pc += 4U;
    } else if (load.vector) {
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
    if (covered && use_fake)
        __atomic_fetch_add(&g_sess.hits, 1, __ATOMIC_RELAXED);
    else if (covered)
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
    if (!f_copy_out || pc < 4U || f_copy_in(&prev, (const void *)(pc - 4U), 4U) ||
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
    result = uy_emulate_load(regs, pc, t->original, 0, 0, &fake, &bad);
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
        result = uy_emulate_load(regs, pc, s->original, 0, 0, &fake, &bad);
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
        !page_find(page_base(far))) {
        __atomic_fetch_sub(&g_handlers, 1, __ATOMIC_RELEASE);
        return;
    }
    if (f_copy_in(&opcode, (const void *)(uintptr_t)pc, 4U)) {
        force_segv(far);
    } else {
        uy_llsc_prepare(regs, pc, &ll);
        result = uy_emulate_load(regs, pc, opcode, far, 1, &fake, &bad);
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
            page_find(page_base(far)))
            uy_ap_abort(far, esr, regs, args);
        return;
    }
    if (!page_mode_live()) return;
    uy_page_abort(far, esr, regs, args);
}

static void uy_mm_fault_before(hook_fargs4_t *args, void *udata)
{
    const char *vma = (const char *)args->arg0;

    (void)udata;
    /* Newer handle_mm_fault() can drop the VMA lock and invalidate the
     * pointer. Capture its mm while the caller's protection still holds. */
    args->local.data0 = vma && overlay_live() ?
        (uintptr_t)__atomic_load_n((void *const *)(vma + g_layout.vma_mm), __ATOMIC_RELAXED) : 0;
}

/* A fault-in just (re)created the site page PTE from the VMA protection, which
 * is executable. Re-apply the execute-never bit so a page that was evicted or
 * dropped does not silently lose its trap. Covers the user fault path and
 * get_user_pages based readers such as /proc/self/mem. */
static void uy_mm_fault_after(hook_fargs4_t *args, void *udata)
{
    /* The three-, four-, five- and eight-register wrappers share this prefix. */
    void *mm = (void *)args->local.data0;
    uint64_t page = page_base(args->arg1);
    int ret = 0;

    (void)udata;
    if (!g_mmf_hooked || (args->ret & UY_FAULT_INCOMPLETE) || !mm ||
        !overlay_live() || mm != mm_of_task(current))
        return;

    __atomic_fetch_add(&g_handlers, 1, __ATOMIC_ACQ_REL);
    if (mm == g_sess.mm) {
        if (ap_mode_live() && page_find(page))
            ret = page_set_ap(mm, page, 0);
        else if (page_mode_live() && site_by_page(page))
            ret = page_set_uxn(mm, page, 1);
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

static void session_free_storage(void)
{
    uint32_t i;

    if (g_sess.pages) {
        for (i = 0; i < g_sess.page_count; ++i) {
            free_retired(&g_sess.pages[i]);
            g_sess.pages[i].image = 0;
            g_sess.pages[i].snapshot = 0;
        }
        uy_free(g_sess.pages);
        g_sess.pages = 0;
    }
    uy_free(g_sess.arena);
    g_sess.arena = 0;
    g_sess.arena_bytes = 0;
    uy_free(g_sess.snapshots);
    g_sess.snapshots = 0;
    g_sess.snapshot_bytes = 0;
}

static void release_session(void)
{
    void *mm;
    unsigned i;

    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UY_STATE_LIVE) return;
    mm = g_sess.mm;
    __atomic_store_n(&g_state, UY_STATE_OFF, __ATOMIC_RELEASE);
    (void)drain_handlers();
    if (mm) {
        for (i = 0; i < g_sess.site_count && i < UROV_Y_MAX_SITES; ++i)
            site_disarm(&g_sess.sites[i], mm);
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP)
            ap_disarm_pages(&g_sess, mm);
    }
    __atomic_store_n(&g_armed, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_suspend, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_degraded, 0, __ATOMIC_RELEASE);
    session_free_storage();
    if (mm) f_mmput(mm);
    memset(&g_sess, 0, sizeof(g_sess));
}

static void reap_dead_session(void)
{
    if (overlay_live() && !mm_has_live_user(g_sess.mm)) release_session();
}

static void sort_descs(struct uy_page_desc *d, uint32_t n)
{
    uint32_t gap, i;

    for (gap = n / 2; gap; gap /= 2) {
        for (i = gap; i < n; ++i) {
            struct uy_page_desc tmp = d[i];
            uint32_t j = i;
            while (j >= gap && d[j - gap].base > tmp.base) {
                d[j] = d[j - gap];
                j -= gap;
            }
            d[j] = tmp;
        }
    }
}

/* PAGE_AP is the only mode that may arm more than one page, and it is also
 * the only mode whose fault handler serves LD1/LD2 and cross-page loads. */
static int page_pte_ok(void *mm, uint64_t base)
{
    uint64_t *ptep;
    uint64_t pte;
    int ret = page_pte_leaf(mm, base, &ptep, &pte);

    if (ret) return ret;
    if (!(pte & PTE_USER) || !(pte & PTE_RDONLY) || (pte & PTE_UXN))
        return -EOPNOTSUPP;
    return 0;
}

/* Look up and use vm_file while its VMA is protected. The access_remote_vm
 * snapshot must run separately since GUP takes the mmap lock itself. */
static long page_read_file(void *mm, uint64_t base, void *image)
{
    const uint64_t max_pos = UINT64_C(0x7fffffffffffffff);
    void *vma, *file;
    uint64_t pgoff, delta;
    int64_t pos;
    long ret;

    if (!f_kernel_read || !g_layout.vma_pgoff_ok) return -EOPNOTSUPP;
    uy_mmap_write_lock(mm);
    vma = f_find_vma(mm, base);
    ret = validate_target_vma(vma, base);
    if (ret) goto out;
    file = *(void **)((char *)vma + g_layout.vma_file);
    pgoff = *(unsigned long *)((char *)vma + g_layout.vma_pgoff);
    delta = base - *(unsigned long *)((char *)vma + g_layout.vma_start);
    if (!file || pgoff > ((max_pos - delta - UROV_Y_PAGE) >> UROV_Y_PAGE_SHIFT)) {
        ret = -EINVAL;
        goto out;
    }
    pos = (int64_t)((pgoff << UROV_Y_PAGE_SHIFT) + delta);
    ret = f_kernel_read(file, image, UROV_Y_PAGE, &pos) == (long)UROV_Y_PAGE ? 0 : -EIO;
out:
    uy_mmap_write_unlock(mm);
    return ret;
}

/* Snapshot the mapped bytes, then overlay the file, user buffer or v7 words. */
static long page_build_image(struct uy_page *p, const struct uy_page_desc *d,
                             void *mm, int legacy_inline)
{
    uint32_t off = d->fake_off;
    uint32_t len = d->fake_len ? d->fake_len : UROV_Y_PAGE;
    uint32_t i;

    if (uy_access_vm(mm, p->base, p->image, UROV_Y_PAGE, 0) != (int)UROV_Y_PAGE) {
        if (g_verbose) pr_info("urov-y: image snapshot base=%llx failed\n", (unsigned long long)p->base);
        return -EFAULT;
    }
    if (p->snapshot) memcpy(p->snapshot, p->image, UROV_Y_PAGE);

    if (legacy_inline) {
        if (len > UROV_Y_FAKE_MAX || off > UROV_Y_PAGE - len) return -EINVAL;
        for (i = 0; i < len; ++i) p->image[off + i] = g_fake_stage[i];
        p->fake_off = off;
        p->fake_len = len;
        return 0;
    }
    if (d->flags & UROV_Y_PAGE_SRC_FILE) {
        long ret = page_read_file(mm, p->base, p->image);

        if (ret) return ret;
        p->fake_off = 0;
        p->fake_len = UROV_Y_PAGE;
        return 0;
    }
    if (uy_access_vm(mm, d->fake_addr, g_fake_stage, (int)len, 0) != (int)len) {
        if (g_verbose) pr_info("urov-y: fake read addr=%llx len=%u failed\n",
                (unsigned long long)d->fake_addr, len);
        return -EFAULT;
    }
    for (i = 0; i < len; ++i) p->image[off + i] = g_fake_stage[i];
    p->fake_off = off;
    p->fake_len = len;
    return 0;
}

static long do_register(struct urov_y_request *q)
{
    void *task = current;
    void *mm;
    struct uy_page_desc *descs = 0;
    uint64_t desc_bytes = 0;
    uint8_t *arena = 0, *snapshots = 0;
    uint64_t arena_bytes = 0, snapshot_bytes = 0;
    uint32_t mode = q->mode ? q->mode : UROV_Y_MODE_SITE_BRK;
    uint32_t n = 0, i;
    int legacy_inline = 0, need_snapshot, site_writable[UROV_Y_MAX_SITES];
    long ret;

    if (q->flags || q->reserved || q->reserved2 || q->caller_count > UROV_Y_MAX_CALLERS)
        return -EINVAL;
    if (mode != UROV_Y_MODE_SITE_BRK && mode != UROV_Y_MODE_PAGE_UXN &&
        mode != UROV_Y_MODE_PAGE_AP)
        return -EINVAL;
    if (mode == UROV_Y_MODE_SITE_BRK && !g_brk_hooked) return -EOPNOTSUPP;
    if (mode != UROV_Y_MODE_SITE_BRK && (!g_page_hooked || !g_mmf_hooked))
        return -EOPNOTSUPP;
    if (q->site_count > UROV_Y_MAX_SITES) return -EINVAL;
    for (i = 0; i < q->caller_count; ++i)
        if (q->caller_start[i] >= q->caller_end[i] ||
            q->caller_end[i] > UY_USER_LIMIT || q->caller_start[i] < UROV_Y_PAGE)
            return -EINVAL;
    if (overlay_live()) return -EBUSY;
    if (drain_handlers()) return -EBUSY;

    mm = f_get_task_mm(task);
    if (!mm) return -EOPNOTSUPP;
    if (mm_of_task(task) != mm || !mm_has_live_user(mm)) {
        f_mmput(mm);
        return -EOPNOTSUPP;
    }

    if (q->page_count) {
        if (mode != UROV_Y_MODE_PAGE_AP) {
            ret = -EOPNOTSUPP;
            goto fail_mm;
        }
        if (q->page_count > g_max_pages) {
            ret = -EINVAL;
            goto fail_mm;
        }
        if (q->page_stride != UROV_Y_PAGE_DESC_SIZE) {
            ret = -EINVAL;
            goto fail_mm;
        }
        if (!q->pages_addr || q->pages_addr >= UY_USER_LIMIT) {
            ret = -EINVAL;
            goto fail_mm;
        }
        n = q->page_count;
        desc_bytes = (uint64_t)n * UROV_Y_PAGE_DESC_SIZE;
        if (q->pages_addr > UY_USER_LIMIT - desc_bytes) {
            ret = -EINVAL;
            goto fail_mm;
        }
        descs = uy_alloc((unsigned long)desc_bytes);
        if (!descs) {
            ret = -ENOMEM;
            goto fail_mm;
        }
    } else {
        /* v7 single-page compatibility form. */
        unsigned len = request_fake_len(q);

        if (!q->address || q->address & (UROV_Y_PAGE - 1U) ||
            q->address < UROV_Y_PAGE || q->address >= UY_USER_LIMIT) {
            ret = -EINVAL;
            goto fail_mm;
        }
        if (len < 8U || len > UROV_Y_FAKE_PAGE || (len & 7U)) {
            ret = -EINVAL;
            goto fail_mm;
        }
        if (q->offset > UROV_Y_PAGE - len) {
            ret = -EINVAL;
            goto fail_mm;
        }
        if (mode != UROV_Y_MODE_PAGE_AP && q->site_count == 0) {
            ret = -EINVAL;
            goto fail_mm;
        }
        for (i = 0; i < q->site_count; ++i)
            if (!site_ok(q->sites[i], q->address)) {
                ret = -EINVAL;
                goto fail_mm;
            }
        n = 1;
        descs = uy_alloc(sizeof(*descs));
        if (!descs) {
            ret = -ENOMEM;
            goto fail_mm;
        }
        memset(descs, 0, sizeof(*descs));
        descs[0].base = q->address;
        descs[0].fake_addr = q->fake_addr;
        descs[0].flags = UROV_Y_PAGE_SRC_USER;
        descs[0].fake_off = q->offset;
        descs[0].fake_len = len;
        descs[0].reserved = 0;
        legacy_inline = q->fake_addr ? 0 : 1;
        ret = fake_stage_request(q, mm, len);
        if (ret) {
            uy_free(descs);
            f_mmput(mm);
            return ret;
        }
    }

    if (q->page_count) {
        /* Copy the descriptor array in bounded chunks. */
        uint64_t done = 0;
        while (done < desc_bytes) {
            unsigned chunk = desc_bytes - done > 4096U ? 4096U : (unsigned)(desc_bytes - done);
            if (uy_access_vm(mm, q->pages_addr + done, (uint8_t *)descs + done,
                            (int)chunk, 0) != (int)chunk) {
                ret = -EFAULT;
                goto fail;
            }
            done += chunk;
        }
        for (i = 0; i < n; ++i) {
            struct uy_page_desc *d = &descs[i];
            uint32_t len;
            if (d->reserved || !d->base || (d->base & (UROV_Y_PAGE - 1U)) ||
                d->base < UROV_Y_PAGE || d->base >= UY_USER_LIMIT - UROV_Y_PAGE) {
                ret = -EINVAL;
                goto fail;
            }
            if ((d->flags & (UROV_Y_PAGE_SRC_USER | UROV_Y_PAGE_SRC_FILE)) == 0 ||
                (d->flags & ~(UROV_Y_PAGE_SRC_USER | UROV_Y_PAGE_SRC_FILE))) {
                ret = -EINVAL;
                goto fail;
            }
            len = d->fake_len ? d->fake_len : UROV_Y_PAGE;
            if (d->flags & UROV_Y_PAGE_SRC_FILE) {
                if (d->fake_off || d->fake_len || !f_kernel_read || !g_layout.vma_pgoff_ok) {
                    ret = -EOPNOTSUPP;
                    goto fail;
                }
            } else {
                if (!d->fake_addr || d->fake_addr >= UY_USER_LIMIT ||
                    (d->fake_len && (d->fake_off > UROV_Y_PAGE - len)))
                    { ret = -EINVAL; goto fail; }
                if (d->fake_len && (d->fake_len < 8U || (d->fake_len & 7U))) {
                    ret = -EINVAL;
                    goto fail;
                }
                if (!d->fake_len && d->fake_off) {
                    ret = -EINVAL;
                    goto fail;
                }
            }
            d->reserved = i; /* internal: pre-sort index for SET_PAGE */
        }
        sort_descs(descs, n);
        for (i = 1; i < n; ++i)
            if (descs[i - 1].base + UROV_Y_PAGE > descs[i].base) {
                ret = -EINVAL;
                goto fail;
            }
    }

    need_snapshot = q->page_count == 0 || mode != UROV_Y_MODE_PAGE_AP ||
                    q->caller_count > 0 ||
                    (q->session_flags & UROV_Y_F_REPLAY_SNAPSHOT) != 0;
    arena_bytes = (uint64_t)n * UROV_Y_PAGE;
    snapshot_bytes = need_snapshot ? arena_bytes : 0;
    if (arena_bytes + snapshot_bytes > g_max_image_bytes) {
        ret = -ENOMEM;
        goto fail;
    }
    g_sess.pages = uy_alloc((unsigned long)n * sizeof(struct uy_page));
    arena = uy_alloc((unsigned long)arena_bytes);
    snapshots = snapshot_bytes ? uy_alloc((unsigned long)snapshot_bytes) : 0;
    if (!g_sess.pages || !arena || (snapshot_bytes && !snapshots)) {
        ret = -ENOMEM;
        goto fail;
    }
    memset(g_sess.pages, 0, (unsigned long)n * sizeof(struct uy_page));
    memset(arena, 0, (unsigned long)arena_bytes);
    if (snapshots) memset(snapshots, 0, (unsigned long)snapshot_bytes);
    g_sess.arena = arena;
    g_sess.arena_bytes = arena_bytes;
    g_sess.snapshots = snapshots;
    g_sess.snapshot_bytes = snapshot_bytes;
    g_sess.page_count = n;
    g_sess.mm = mm;
    g_sess.mode = mode;
    g_sess.caller_count = q->caller_count;
    for (i = 0; i < q->caller_count; ++i) {
        g_sess.caller_start[i] = q->caller_start[i];
        g_sess.caller_end[i] = q->caller_end[i];
    }

    for (i = 0; i < n; ++i) {
        struct uy_page *p = &g_sess.pages[i];
        const struct uy_page_desc *d = &descs[i];

        p->base = d->base;
        p->index = d->reserved;
        p->flags = d->flags;
        p->image = arena + (uint64_t)i * UROV_Y_PAGE;
        if (snapshots) p->snapshot = snapshots + (uint64_t)i * UROV_Y_PAGE;
        p->seq = 0;
        uy_mmap_write_lock(mm);
        ret = validate_target_vma(f_find_vma(mm, p->base), p->base);
        uy_mmap_write_unlock(mm);
        if (ret) goto fail_armed;
        ret = page_build_image(p, d, mm, legacy_inline);
        if (ret) goto fail_armed;
    }

    /* Validate every page again under one mmap write lock and arm the AP[1]
     * target pages there.  The image build above only touched kernel memory. */
    if (mode == UROV_Y_MODE_PAGE_AP) {
        ret = ap_arm_pages(&g_sess, mm);
        if (ret) goto fail_armed;
    } else {
        if (q->site_count == 0) {
            ret = -EINVAL;
            goto fail_armed;
        }
        for (i = 0; i < q->site_count; ++i) {
            site_writable[i] = 0;
            uy_mmap_write_lock(mm);
            ret = validate_site_vma(f_find_vma(mm, q->sites[i]), q->sites[i],
                                    mode != UROV_Y_MODE_SITE_BRK, &site_writable[i]);
            uy_mmap_write_unlock(mm);
            if (ret) goto fail_armed;
            g_sess.sites[i].pc = q->sites[i];
            g_sess.sites[i].armed = 0;
        }
        g_sess.site_count = q->site_count;
        for (i = 0; i < q->site_count; ++i) {
            ret = site_arm(&g_sess.sites[i], mm, q->sites[i], site_writable[i]);
            if (ret) goto fail_armed;
        }
    }

    g_sess.generation = 1;
    g_sess.hits = 0;
    g_sess.replays = 0;
    g_sess.failures = 0;
    g_sess.llsc = 0;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_state, UY_STATE_LIVE, __ATOMIC_RELEASE);

    q->session = 1;
    q->generation = 1;
    q->mode = mode;
    q->flags = 0;
    q->page_count = n;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, &g_sess.pages[0]);
    q->offset = g_sess.pages[0].fake_off;
    q->length = g_sess.pages[0].fake_len;
    q->state = UROV_Y_ACTIVE;
    uy_free(descs);
    return 0;

fail_mm:
    f_mmput(mm);
    uy_free(descs);
    memset(&g_sess, 0, sizeof(g_sess));
    if (g_verbose) pr_info("urov-y: register rejected ret=%ld\n", ret);
    return ret;

fail_armed:
    if (mode == UROV_Y_MODE_PAGE_AP) {
        if (g_sess.ap_armed) ap_disarm_pages(&g_sess, mm);
    } else {
        unsigned j;
        for (j = 0; j < i && j < g_sess.site_count; ++j)
            if (g_sess.sites[j].armed) site_disarm(&g_sess.sites[j], mm);
    }
fail:
    session_free_storage();
    g_sess.page_count = 0;
    f_mmput(mm);
    uy_free(descs);
    memset(&g_sess, 0, sizeof(g_sess));
    pr_info("urov-y: register failed ret=%ld pages=%u\n", ret, n);
    return ret;
}

static long do_set(struct urov_y_request *q)
{
    struct uy_page *p;
    uint8_t *image;
    unsigned len, off, i;
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (q->reserved || g_sess.page_count != 1) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    p = &g_sess.pages[0];
    len = request_fake_len(q);
    if (len != p->fake_len) return -EINVAL;
    off = p->fake_off;
    ret = fake_stage_request(q, g_sess.mm, len);
    if (ret) {
        memset(g_fake_stage, 0, len);
        return ret;
    }
    image = uy_alloc(UROV_Y_PAGE);
    if (!image) {
        memset(g_fake_stage, 0, len);
        return -ENOMEM;
    }
    if (p->snapshot) memcpy(image, p->snapshot, UROV_Y_PAGE);
    else memcpy(image, p->image, UROV_Y_PAGE);
    for (i = 0; i < len; ++i) image[off + i] = g_fake_stage[i];
    memset(g_fake_stage, 0, len);
    page_swap_image(p, image, off, len);
    g_sess.generation++;
    q->generation = g_sess.generation;
    q->state = UROV_Y_ACTIVE;
    q->page_count = 1;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    page_status_words(q, p);
    q->offset = p->fake_off;
    q->length = p->fake_len;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

/* v8: replace one page's image in place (page number in reserved[31:0]).
 * SRC_FILE pages re-read the backing file; SRC_USER pages need either the
 * registration snapshot (partial window) or a whole-page image. */
static long do_set_page(struct urov_y_request *q)
{
    struct uy_page *p;
    uint8_t *image;
    uint32_t index = (uint32_t)q->reserved;
    unsigned len, off, i;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (!g_sess.page_count || q->flags) return -EINVAL;
    p = page_by_index(index);
    if (!p) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;

    if (p->flags & UROV_Y_PAGE_SRC_FILE) {
        long ret;

        image = uy_alloc(UROV_Y_PAGE);
        if (!image) return -ENOMEM;
        ret = page_read_file(g_sess.mm, p->base, image);
        if (ret) {
            uy_free(image);
            return ret;
        }
        page_swap_image(p, image, 0, UROV_Y_PAGE);
    } else {
        len = q->length ? q->length : UROV_Y_PAGE;
        off = q->offset;
        if (len < 8U || len > UROV_Y_PAGE || (len & 7U) || off > UROV_Y_PAGE - len)
            return -EINVAL;
        if (!q->fake_addr || q->fake_addr >= UY_USER_LIMIT) return -EINVAL;
        if (uy_access_vm(g_sess.mm, q->fake_addr, g_fake_stage, (int)len, 0) != (int)len)
            return -EFAULT;
        image = uy_alloc(UROV_Y_PAGE);
        if (!image) {
            memset(g_fake_stage, 0, len);
            return -ENOMEM;
        }
        if (p->snapshot) {
            memcpy(image, p->snapshot, UROV_Y_PAGE);
        } else if (len == UROV_Y_PAGE) {
            memset(image, 0, UROV_Y_PAGE);
        } else {
            /* Without the registration snapshot the bytes under the old
             * window are gone; a partial rewrite cannot be reconstructed. */
            memset(g_fake_stage, 0, len);
            uy_free(image);
            return -EOPNOTSUPP;
        }
        for (i = 0; i < len; ++i) image[off + i] = g_fake_stage[i];
        memset(g_fake_stage, 0, len);
        page_swap_image(p, image, off, len);
    }

    g_sess.generation++;
    q->generation = g_sess.generation;
    q->state = UROV_Y_ACTIVE;
    q->page_count = g_sess.page_count;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, &g_sess.pages[0]);
    q->offset = g_sess.pages[0].fake_off;
    q->length = g_sess.pages[0].fake_len;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    return 0;
}

static uint32_t armed_pages(void)
{
    uint32_t i, n = 0;

    for (i = 0; i < g_sess.page_count; ++i)
        if (g_sess.pages[i].armed) ++n;
    return n;
}

static void status_inactive(struct urov_y_request *q)
{
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
    q->page_count = 0;
    q->page_stride = UROV_Y_PAGE_SHIFT;
    q->session_flags = g_caps;
    q->reserved = 0;
    q->reserved2 = 0;
    q->state = UROV_Y_INACTIVE;
}

static long do_status(struct urov_y_request *q, int with_counters)
{
    struct uy_page *p0;

    if (!session_owned() || q->session != 1) {
        status_inactive(q);
        return 0;
    }
    p0 = &g_sess.pages[0];
    q->generation = g_sess.generation;
    q->mode = g_sess.mode;
    q->flags = 0;
    q->page_count = g_sess.page_count;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    q->reserved = armed_pages();
    q->reserved2 = 0;
    page_status_words(q, p0);
    q->offset = p0->fake_off;
    q->length = p0->fake_len;
    q->site_count = g_sess.site_count;
    q->caller_count = g_sess.caller_count;
    q->hits = with_counters ? __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED) : 0;
    q->replays = with_counters ? __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED) : 0;
    q->failures = with_counters ? __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED) : 0;
    q->state = UROV_Y_ACTIVE;
    return 0;
}

static long do_query(struct urov_y_request *q)
{
    long ret = do_status(q, 0);

    if (ret) return ret;
    /* Capacity report: max page quota and the base page shift. */
    q->page_count = g_max_pages;
    q->page_stride = UROV_Y_PAGE_SHIFT;
    q->session_flags = g_caps;
    q->reserved = 0;
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
    q->mode = 0;
    q->flags = 0;
    q->page_count = 0;
    q->page_stride = UROV_Y_PAGE_SHIFT;
    q->session_flags = g_caps;
    q->reserved = 0;
    q->reserved2 = 0;
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
    case UROV_Y_QUERY: ret = do_query(q); break;
    case UROV_Y_REGISTER: ret = do_register(q); break;
    case UROV_Y_SET: ret = do_set(q); break;
    case UROV_Y_SET_PAGE: ret = do_set_page(q); break;
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
    if (uy_copy_control_reply(user, &q, sizeof(q))) ret = -EFAULT;
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
            ap_disarm_pages(&g_sess, g_sess.mm);
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
            (void)ap_arm_pages(&g_sess, g_sess.mm);
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

/* True when [start, start+len) intersects any target page or site page.
 * A zero length is not a range.  The page array is sorted, so the first
 * candidate is found by binary search and only its predecessor can also
 * overlap a range that starts inside the previous page. */
static int gate_range_overlaps(uint64_t start, uint64_t len)
{
    uint64_t end = start + len;
    uint32_t lo = 0, hi = g_sess.page_count;
    unsigned i;

    if (!len) return 0;
    if (end < start) end = ~0ULL;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_sess.pages[mid].base < start) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_sess.page_count) {
        uint64_t p = g_sess.pages[lo].base;
        if (start < p + UROV_Y_PAGE && end > p) return 1;
    }
    if (lo > 0) {
        uint64_t p = g_sess.pages[lo - 1].base;
        if (start < p + UROV_Y_PAGE && end > p) return 1;
    }
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

static void resolve_allocators(void)
{
    f_kvmalloc_node = (kvmalloc_node_t)lookup("kvmalloc_node");
    if (!f_kvmalloc_node) f_kvmalloc_node = (kvmalloc_node_t)lookup("kvmalloc_node_noprof");
    f_kvfree = (kvfree_t)lookup("kvfree");
    if (!f_kvfree) f_kvmalloc_node = 0;
    f_vmalloc = (vmalloc_t)lookup("vmalloc");
    if (!f_vmalloc) f_vmalloc = (vmalloc_t)lookup("vmalloc_noprof");
    f_vfree = (vfree_t)lookup("vfree");
    if (!f_vfree) f_vmalloc = 0;
}

static int uy_read_exact(void *file, void *buf, size_t bytes, int64_t *pos)
{
    uint8_t *dst = buf;

    while (bytes) {
        long n = f_kernel_read(file, dst, bytes, pos);

        if (n <= 0 || (size_t)n > bytes) return -EIO;
        dst += n;
        bytes -= (size_t)n;
    }
    return 0;
}

static long open_detached_btf(struct kclf_btf *btf, const char *path, void **storage)
{
    filp_open_t open = (filp_open_t)lookup("filp_open");
    filp_close_t close = (filp_close_t)lookup("filp_close");
    uintptr_t start = (uintptr_t)lookup("__start_notes");
    uintptr_t end = (uintptr_t)lookup("__stop_notes");
    struct uy_btf_pack pack;
    int64_t pos = 0;
    void *file;
    long ret;

    if (!open || !close || !f_kernel_read || !start || end <= start || end - start > 65536U)
        return -EOPNOTSUPP;
    file = open(path, 0 /* O_RDONLY */, 0);
    if ((uintptr_t)file >= (uintptr_t)-4095L) return (long)file;
    ret = uy_read_exact(file, &pack, sizeof(pack), &pos);
    if (ret) goto out;
    if (!uy_btf_pack_matches(&pack, (const void *)start, end - start)) {
        pr_info("urov-y: detached BTF header or kernel build ID mismatch\n");
        ret = -EINVAL;
        goto out;
    }
    *storage = uy_alloc(pack.bytes);
    if (!*storage) {
        ret = -ENOMEM;
        goto out;
    }
    ret = uy_read_exact(file, *storage, pack.bytes, &pos);
    if (!ret && uy_btf_open(btf, *storage, pack.bytes)) ret = -EINVAL;
out:
    close(file, 0);
    return ret;
}

static long resolve_symbols(const struct kclf_btf *btf, int *brk_argc, int *mmf_argc)
{
    const char *brk_name = "do_el0_brk64", *vma_name = "find_vma";
    const char *fault_name = "handle_mm_fault", *access_name = "access_remote_vm";
    const char *read_name = "copy_from_user_nofault", *write_name = "copy_to_user_nofault";
    void *access;
    int access_argc;
    unsigned foll_force;

    foll_force = uy_foll_force(btf, kver >= VERSION(6, 3, 0) ? 0x08U : 0x10U);
    g_write_gup_flags = foll_force ? UY_FOLL_WRITE | foll_force : 0;
    f_brk_handler = lookup(brk_name);
    *brk_argc = f_brk_handler && uy_symbol_abi(btf, brk_name, "vsr") ? 2 : 0;
    if (!*brk_argc) {
        brk_name = "brk_handler";
        f_brk_handler = lookup(brk_name);
        *brk_argc = f_brk_handler && uy_symbol_abi(btf, brk_name, "ilsr") ? 3 : 0;
    }
    if (!g_write_gup_flags) *brk_argc = 0;

    if (uy_symbol_abi(btf, "do_mem_abort", "vlsr"))
        f_do_mem_abort = lookup("do_mem_abort");
    f_handle_mm_fault = lookup(fault_name);
    *mmf_argc = f_handle_mm_fault ? uy_mm_fault_argc(btf, fault_name, 1) : 0;
    if (!*mmf_argc) {
        fault_name = "do_handle_mm_fault";
        f_handle_mm_fault = lookup(fault_name);
        *mmf_argc = f_handle_mm_fault ? uy_mm_fault_argc(btf, fault_name, 0) : 0;
    }

    f_get_task_mm = (get_task_mm_t)lookup("get_task_mm");
    f_mmput = (mmput_t)lookup("mmput");
    f_find_vma = (find_vma_t)lookup(vma_name);
    if (!f_find_vma || !uy_symbol_abi(btf, vma_name, "aml")) {
        vma_name = "__find_vma";
        f_find_vma = (find_vma_t)lookup(vma_name);
    }
    if (!f_find_vma || !uy_symbol_abi(btf, vma_name, "aml")) {
        vma_name = "vma_lookup";
        f_find_vma = (find_vma_t)lookup(vma_name);
    }
    if (f_find_vma && !uy_symbol_abi(btf, vma_name, "aml")) f_find_vma = 0;

    f_mmap_write_lock = (mmap_write_fn)lookup("mmap_write_lock");
    f_mmap_write_unlock = (mmap_write_fn)lookup("mmap_write_unlock");
    g_use_rwsem = !f_mmap_write_lock || !f_mmap_write_unlock ||
                  !uy_symbol_abi(btf, "mmap_write_lock", "vm") ||
                  !uy_symbol_abi(btf, "mmap_write_unlock", "vm");
    if (g_use_rwsem) {
        f_mmap_write_lock = g_layout.mmap_lock < 0 ? 0 : (mmap_write_fn)lookup("down_write");
        f_mmap_write_unlock = g_layout.mmap_lock < 0 ? 0 : (mmap_write_fn)lookup("up_write");
    }

    f_flush_tlb_mm = (flush_tlb_mm_t)lookup("flush_tlb_mm");
    if (uy_symbol_abi(btf, "force_sig_fault", "iiip"))
        f_force_sig_fault = (force_sig_fault_t)lookup("force_sig_fault");

    f_copy_in = (copy_nofault_t)lookup(read_name);
    if (!f_copy_in || !uy_symbol_abi(btf, read_name, "lppl")) {
        read_name = "probe_user_read";
        f_copy_in = (copy_nofault_t)lookup(read_name);
    }
    if (f_copy_in && !uy_symbol_abi(btf, read_name, "lppl")) f_copy_in = 0;
    f_copy_out = (copy_nofault_t)lookup(write_name);
    if (!f_copy_out || !uy_symbol_abi(btf, write_name, "lppl")) {
        write_name = "probe_user_write";
        f_copy_out = (copy_nofault_t)lookup(write_name);
    }
    if (f_copy_out && !uy_symbol_abi(btf, write_name, "lppl")) f_copy_out = 0;

    access = lookup(access_name);
    access_argc = access ? uy_access_vm_argc(btf, access_name, 1) : 0;
    if (!access_argc) {
        access_name = "__access_remote_vm";
        access = lookup(access_name);
        access_argc = access ? uy_access_vm_argc(btf, access_name, 0) : 0;
    }
    if (access_argc == 5) f_access_vm = (access_remote_vm_t)access;
    if (access_argc == 6) f_access_vm_task = (access_remote_vm_task_t)access;

    /* Without both FPSIMD helpers and the saved-state layout, vector loads
     * fail closed. In particular, don't substitute a raw register save. */
    f_fp_preserve = (fpsimd_preserve_t)lookup("fpsimd_signal_preserve_current_state");
    f_fp_update = (fpsimd_update_t)lookup("fpsimd_update_current_state");
    g_fp_ready = f_fp_preserve && f_fp_update && g_layout.task_fpsimd >= 0 &&
                 uy_symbol_abi(btf, "fpsimd_signal_preserve_current_state", "v") &&
                 uy_symbol_abi(btf, "fpsimd_update_current_state", "vf");

    if (!f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_force_sig_fault ||
        !f_copy_in || !access_argc || (!*brk_argc && !(f_do_mem_abort && *mmf_argc))) {
        pr_info("urov-y: required MM/uaccess/signal or trap ABI unavailable\n");
        return -EOPNOTSUPP;
    }
    if (g_verbose)
        pr_info("urov-y: kver=%x vma=%s lock=%s mm_fault=%s/%d brk=%s/%d "
                "access=%s/%d read=%s write=%s fpsimd=%d foll_force=0x%x\n",
                kver, vma_name, g_use_rwsem ? "rwsem" : "mmap",
                *mmf_argc ? fault_name : "none", *mmf_argc,
                *brk_argc ? brk_name : "none", *brk_argc, access_name, access_argc,
                read_name, f_copy_out ? write_name : "control-gup", g_fp_ready, foll_force);
    return 0;
}

static long resolve_kernel(const char *btf_path, int *brk_argc, int *mmf_argc)
{
    struct kclf_btf btf;
    void *storage = 0;
    long ret = 0;

    if (kver < VERSION(5, 4, 0) || kver >= VERSION(7, 0, 0) || !supported_pagetables()) {
        pr_info("urov-y: unsupported kernel or page tables (kver=%x)\n", kver);
        return -EOPNOTSUPP;
    }
    resolve_allocators();
    if (!f_kvmalloc_node && !f_vmalloc) return -EOPNOTSUPP;
    f_kernel_read = (kernel_read_t)lookup("kernel_read");
    if (btf_path[0]) {
        ret = open_detached_btf(&btf, btf_path, &storage);
    } else {
        uintptr_t start = (uintptr_t)lookup("__start_BTF");
        uintptr_t end = (uintptr_t)lookup("__stop_BTF");

        if (!start || end <= start || end - start > UY_BTF_MAX ||
            uy_btf_open(&btf, (const void *)start, end - start))
            ret = -EOPNOTSUPP;
    }
    if (ret) {
        pr_info("urov-y: cannot open %s BTF (%ld); matching layout is required\n",
                btf_path[0] ? "detached" : "live", ret);
    } else if (uy_layout_from_btf(&g_layout, &btf)) {
        pr_info("urov-y: incompatible MM/register layout in %s BTF\n",
                btf_path[0] ? "detached" : "live");
        ret = -EOPNOTSUPP;
    } else {
        if (g_verbose)
            pr_info("urov-y: btf=%s task.mm=%d mm.pgd=%d mm.users=%d mmap_lock=%d "
                    "vma.flags=%d task.fpsimd=%d\n", btf_path[0] ? "detached" : "live",
                    g_layout.task_mm, g_layout.mm_pgd, g_layout.mm_users, g_layout.mmap_lock,
                    g_layout.vma_flags, g_layout.task_fpsimd);
        ret = resolve_symbols(&btf, brk_argc, mmf_argc);
    }
    uy_free(storage);
    return ret;
}

static int parse_u32(const char *v, unsigned n, uint32_t *out)
{
    uint32_t value = 0;
    unsigned i;

    if (!n) return -1;
    for (i = 0; i < n; ++i) {
        if (v[i] < '0' || v[i] > '9') return -1;
        if (value > (0xffffffffU - 9U) / 10U) return -1;
        value = value * 10U + (uint32_t)(v[i] - '0');
    }
    *out = value;
    return 0;
}

#define UY_BTF_PATH_MAX 192U

static long parse_args(const char *args, uint8_t key[16], int *have_key,
                       char btf_path[UY_BTF_PATH_MAX])
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
        } else if (prefix(p, "btf=", 4)) {
            v = p + 4;
            while (v[n] && v[n] != ' ') ++n;
            if (btf_path[0] || v[0] != '/' || n < 2 || n >= UY_BTF_PATH_MAX)
                return -EINVAL;
            memcpy(btf_path, v, n);
            btf_path[n] = 0;
        } else if (prefix(p, "max_pages=", 10)) {
            uint32_t value;
            v = p + 10;
            while (v[n] && v[n] != ' ') ++n;
            if (parse_u32(v, n, &value) || value == 0 || value > UROV_Y_MAX_PAGES)
                return -EINVAL;
            g_max_pages = value;
        } else if (prefix(p, "max_kb=", 7)) {
            uint32_t value;
            v = p + 7;
            while (v[n] && v[n] != ' ') ++n;
            if (parse_u32(v, n, &value) || value < 64U || value > 64U * 1024U)
                return -EINVAL;
            g_max_image_bytes = (uint64_t)value << 10;
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
    char btf_path[UY_BTF_PATH_MAX] = {0};
    uint64_t kdf_key[2];
    int have_key = 0;
    unsigned int checks = 0;
    long ret;
    int i, brk_argc, mmf_argc;

    memset(key, 0, sizeof(key));
    ret = parse_args(args, key, &have_key, btf_path);
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

    ret = resolve_kernel(btf_path, &brk_argc, &mmf_argc);
    if (ret) return ret;
    g_wrapper_mode = has_syscall_wrapper ? 1 : 0;

    if (brk_argc) {
        ret = hook_wrap(f_brk_handler, brk_argc, uy_brk_before, 0,
                        (void *)(uintptr_t)(brk_argc == 2));
        g_brk_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-y: hook BRK handler failed: %ld\n", ret);
    }

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
        ret = hook_wrap(f_handle_mm_fault, mmf_argc, uy_mm_fault_before, uy_mm_fault_after, 0);
        g_mmf_hooked = ret ? 0 : 1;
        if (ret) {
            if (g_verbose) pr_info("urov-y: hook MM fault handler failed: %ld\n", ret);
            hook_unwrap(f_do_mem_abort, uy_abort_before, 0);
            g_page_hooked = 0;
        }
    }
    if (!g_clone_hooked || (!g_brk_hooked && !g_page_hooked)) {
        urov_y_backend_exit();
        return -EOPNOTSUPP;
    }
    if (g_page_hooked) {
        g_caps = UROV_Y_CAP_MULTI | UROV_Y_CAP_CROSS;
        if (g_fp_ready)
            g_caps |= UROV_Y_CAP_LD1 | UROV_Y_CAP_LD2 | UROV_Y_CAP_LD3 | UROV_Y_CAP_LD4;
        if (f_kernel_read && g_layout.vma_pgoff_ok) g_caps |= UROV_Y_CAP_SRC_FILE;
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
    return uy_copy_control_reply(dst, src, len);
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
        hook_unwrap(f_handle_mm_fault, uy_mm_fault_before, uy_mm_fault_after);
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
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    out->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    out->llsc = __atomic_load_n(&g_sess.llsc, __ATOMIC_RELAXED);
    out->active = overlay_live() ? 1U : 0U;
    out->sites = overlay_live() ? g_sess.site_count : 0U;
    out->armed = overlay_live() ? armed_pages() : 0U;
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
    out->overlay_len = overlay_live() && g_sess.page_count ? g_sess.pages[0].fake_len : 0U;
    out->abi = UROV_Y_ABI_VERSION;
    out->page_count = overlay_live() ? g_sess.page_count : 0U;
    out->page_shift = UROV_Y_PAGE_SHIFT;
    out->caps = g_caps;
}
