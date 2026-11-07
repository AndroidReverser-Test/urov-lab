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
 * PAGE_AP does not emulate arbitrary stores.  Because the exception return
 * clears the exclusive reservation, an adjacent LDXR;load;STXR whose LDXR
 * result is still in Rt is completed in the handler (see uy_llsc_prepare);
 * every other store stays native.
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
#include "urov_y_readers.h"

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

/* Only level-3 permission faults can come from our leaf PTE edits. */
#define UY_EC_IABT_LOW 0x20UL
/* EL0 data abort taken to EL1: EC 0x24.  ESR.WnR distinguishes a read from a
 * write; only read permission faults are ours. */
#define UY_EC_DABT_LOW 0x24UL
#define UY_ESR_WNR (1UL << 6)
#define UY_ESR_S1PTW (1UL << 7)
#define UY_ESR_CM (1UL << 8)
#define UY_ESR_EA (1UL << 9)
#define UY_ESR_FNV (1UL << 10)
#define UY_ESR_ISS2 (UINT64_C(0xffffff) << 32)
#define UY_FSC_MASK 0x3fUL
#define UY_FSC_PERM_LEAF 0x0fUL

/* A64 control instructions that a trap page may legitimately execute. */
#define UY_RET_X30 0xd65f03c0U
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

_Static_assert(UROV_Y_FAKE_MAX == URO_FAKE_MAX, "UAPI and core fake widths");
_Static_assert(UROV_Y_FAKE_PAGE == UROV_Y_PAGE, "overlay is at most one page");

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

/* AArch64 load/store-exclusive encodings (ARM ARM C6.2).  The access size is
 * [31:30]; [29:21] and [15:10] are fixed, while Rs/Rn/Rt are variable.  STXR
 * carries the status register in Rs, so its match mask excludes [20:16]. */
#define UY_EXCL_LD_MASK 0x3ffffc00U
#define UY_EXCL_LDXR 0x085f7c00U
#define UY_EXCL_LDAXR 0x085ffc00U
#define UY_EXCL_ST_MASK 0x3fe0fc00U
#define UY_EXCL_STXR 0x08007c00U
#define UY_EXCL_STLXR 0x0800fc00U

/* One adjacent LDXR;load;STXR triple that the PAGE_AP handler may complete
 * itself.  The plan is built from the registers as they were at the fault,
 * before the load is emulated, and committed only after emulation succeeds. */
struct uy_llsc {
    uint64_t base;
    uint64_t value;
    unsigned size;
    unsigned data_reg;
    unsigned base_reg;
    unsigned status_reg;
    unsigned acquire;
    unsigned release;
    unsigned valid;
};

typedef void (*fpsimd_preserve_t)(void);
typedef void (*fpsimd_update_t)(const void *state);
typedef void (*void_fn)(void);

typedef void *(*get_task_mm_t)(void *task);
typedef void (*mmput_t)(void *mm);
typedef void *(*find_vma_t)(void *mm, unsigned long addr);
typedef void (*mmap_write_fn)(void *);
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
typedef void (*msleep_t)(unsigned int msecs);
typedef void *(*filp_open_t)(const char *path, int flags, unsigned short mode);
typedef int (*filp_close_t)(void *file, void *owner);

extern uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

struct uy_site {
    uint64_t pc;
    uint64_t page;
    uint32_t original;
    uint32_t armed;
};

/* Readers access only the immutable snapshot or the published image. SET
 * builds into spare, then waits for readers of the previous image before
 * making that image the new spare. */
struct uy_page {
    uint64_t base;
    uint8_t *image;
    uint8_t *snapshot;
    uint8_t *spare;
    uint32_t index;      /* descriptor index before sorting */
    uint32_t flags;      /* UROV_Y_PAGE_SRC_* */
    uint32_t fake_off;
    uint32_t fake_len;
    uint32_t armed;
};

struct uy_session {
    void *mm;
    uint64_t generation;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;      /* adjacent LL/SC stores completed by the AP bridge */
    uint64_t caller_start[UROV_Y_MAX_CALLERS];
    uint64_t caller_end[UROV_Y_MAX_CALLERS];
    struct uy_page *pages;     /* page_count entries, sorted by base */
    uint8_t *arena;            /* image, spare and snapshot for each page */
    uint32_t page_count;
    uint32_t site_count;
    uint32_t caller_count;
    uint32_t mode;
    struct uy_site sites[UROV_Y_MAX_SITES];
};

static struct uy_session g_sess;
static struct uy_layout g_layout;
static uint8_t g_selftest_ws[UROV_Y_PAGE];
static int g_state;
static uint64_t g_readers = UY_READER_CLOSED;
static void *g_owner;
static int g_ctrl_busy;
static int g_ready;
static int g_verbose;
static int g_suspend;
static volatile uint32_t g_failure_logged;
static struct urov_x_keys g_keys;
static uint16_t g_imm;
static uint32_t g_trap_insn;
static unsigned g_write_gup_flags;
static int g_use_rwsem;
static uint32_t g_max_pages = UROV_Y_MAX_PAGES;
static uint64_t g_max_image_bytes = UINT64_C(8) << 20;
static uint32_t g_caps;
static uint32_t g_page_size;
static uint32_t g_page_shift;
static uint64_t g_user_limit;

static void *f_brk_handler;
static void *f_do_mem_abort;
static void *f_handle_mm_fault;
static get_task_mm_t f_get_task_mm;
static mmput_t f_mmput;
static find_vma_t f_find_vma;
static mmap_write_fn f_mmap_write_lock;
static mmap_write_fn f_mmap_write_unlock;
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
static msleep_t f_msleep;
static void_fn f_rcu_lock, f_rcu_unlock;
static void_fn f_sync_tasks;

static int g_brk_hooked;
static int g_prctl_hooked;
static int g_clone_hooked;
static int g_clone3_hooked;
static int g_wrapper_mode;
static int g_page_hooked;
static int g_mmf_hooked;
static int g_degraded;
static int g_abort_has_iss2;
/* FPSIMD state can only be driven when both kernel helpers resolved and BTF
 * described task_struct.thread.uw.fpsimd_state.  Otherwise a vector load from
 * the target page keeps the historical fail-closed SIGSEGV. */
static int g_fp_ready;

#define UY_GATE_NUM 9
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

static int uy_user_range(uint64_t addr, uint64_t bytes)
{
    return addr >= g_page_size && addr < g_user_limit && bytes <= g_user_limit - addr;
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
    if (!uy_user_range(addr, len) || len > 0x7fffffffU)
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

static uint64_t page_base(uint64_t address)
{
    return address & ~((uint64_t)g_page_size - 1U);
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

static uint64_t session_get_mm(void *mm)
{
    uint64_t ref;

    if (!mm || mm != __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE)) return 0;
    ref = uy_reader_enter(&g_readers);
    if (ref && mm != g_sess.mm) {
        uy_reader_exit(&g_readers, ref);
        return 0;
    }
    return ref;
}

static uint64_t session_get(void)
{
    return session_get_mm(mm_of_task(current));
}

/* Do not spin on a preempted reader, or proceed after a timeout. Only the
 * inactive epoch is drained during a SET, so continuous reads can proceed. */
static void drain_readers(uint64_t mask)
{
    while (__atomic_load_n(&g_readers, __ATOMIC_ACQUIRE) & mask)
        f_msleep(1);
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

/* The caller holds a session reader reference. Each page image stays intact
 * for that reference, even if SET publishes a replacement concurrently. */
static void page_view(struct uy_page *p, uint64_t off, unsigned total,
                      uint8_t *out, int replay)
{
    const uint8_t *src = replay ? p->snapshot : __atomic_load_n(&p->image, __ATOMIC_ACQUIRE);

    memcpy(out, src + off, total);
}

static int range_covered(uint64_t address, unsigned total)
{
    uint64_t done = 0;

    while (done < total) {
        uint64_t cur = address + done;
        uint64_t off = cur - page_base(cur);
        unsigned seg = (unsigned)(g_page_size - off);

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
 * access is just this loop; a 64-byte LD1 can span two pages. */
static int read_range(uint64_t address, unsigned total, int allow_fake,
                      uint8_t *out, uint64_t *bad)
{
    uint64_t done = 0;
    int covered = 0;

    while (done < total) {
        uint64_t cur = address + done;
        uint64_t off = cur - page_base(cur);
        unsigned seg = (unsigned)(g_page_size - off);
        struct uy_page *p;

        if (seg > total - done) seg = (unsigned)(total - done);
        p = page_find(page_base(cur));
        if (p) {
            covered = 1;
            page_view(p, off, seg, out + done, !allow_fake);
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

static int overlay_live(void)
{
    return __atomic_load_n(&g_state, __ATOMIC_ACQUIRE) == UY_STATE_LIVE;
}

static int session_owned(void)
{
    return overlay_live() && mm_of_task(current) == g_sess.mm;
}

static unsigned request_fake_len(const struct urov_y_request *q)
{
    return q->length ? q->length : 8U;
}

static long copy_user_image(void *mm, uint64_t addr, uint8_t *dst, unsigned len)
{
    if (!uy_user_range(addr, len)) return -EINVAL;
    return uy_access_vm(mm, addr, dst, (int)len, 0) == (int)len ? 0 : -EFAULT;
}

static long copy_request_image(const struct urov_y_request *q, void *mm, uint8_t *dst,
                               unsigned len)
{
    unsigned i;

    if (q->fake_addr) return copy_user_image(mm, q->fake_addr, dst, len);
    if (len > UROV_Y_FAKE_MAX) return -EINVAL;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8U ? q->value : q->value_hi[(i - 8U) / 8U];
        dst[i] = (uint8_t)(word >> (8U * (i & 7U)));
    }
    return 0;
}

static void page_swap_image(struct uy_page *p, uint32_t off, uint32_t len)
{
    uint8_t *old = __atomic_exchange_n(&p->image, p->spare, __ATOMIC_ACQ_REL);

    drain_readers(uy_readers_flip(&g_readers));
    p->spare = old;
    p->fake_off = off;
    p->fake_len = len;
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

/* -------------------------------------------------------- site patch/unpatch */

/* A site must be inside an executable mapping. The BRK mode additionally needs
 * a private, COW-capable mapping because it writes the instruction into the
 * process' page; the PAGE_UXN mode only changes the leaf PTE, so a shared
 * file mapping is fine there and every byte stays untouched. */
static int validate_site_vma(void *vma, uint64_t pc, int page_mode)
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
    if (!(flags & UY_VM_EXEC) || (flags & UY_VM_WRITE)) return -EOPNOTSUPP;
    if (!page_mode) {
        if (flags & UY_VM_SHARED) return -EOPNOTSUPP;
        if (!(flags & UY_VM_MAYWRITE)) return -EOPNOTSUPP;
    }
    if (flags & (UY_VM_PFNMAP | UY_VM_IO | UY_VM_HUGETLB | UY_VM_MIXEDMAP))
        return -EOPNOTSUPP;
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
    if (address < start || address >= end || end - address < g_page_size) return -EINVAL;
    if ((flags & (UY_VM_READ | UY_VM_EXEC)) != (UY_VM_READ | UY_VM_EXEC)) return -EINVAL;
    if (flags & (UY_VM_WRITE | UY_VM_PFNMAP | UY_VM_HUGETLB |
                 UY_VM_IO | UY_VM_MIXEDMAP)) return -EINVAL;
    if (!file) return -EINVAL;
    if (flags & UY_VM_SHARED) {
        if (start != address || end != address + g_page_size) return -EINVAL;
        if (flags & UY_VM_MAYWRITE) return -EINVAL;
    }
    return 0;
}

/* ------------------------------------------------------ page (UXN) arming */

/* A present, non-contiguous leaf PTE. A contiguous run shares one
 * permission check, so changing a single entry would be wrong; such pages are
 * rejected instead of silently breaking the neighbouring entries. */
static int page_pte_leaf(void *mm, uint64_t page, uint64_t **slot, uint64_t *out)
{
    uint64_t *ptep = pte_of(mm, page);
    uint64_t pte;

    if (!ptep) return -ENOENT;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (!(pte & PTE_VALID)) return -ENOENT;
    if ((pte & (PTE_VALID | PTE_TYPE_MASK)) != (PTE_VALID | PTE_TYPE_PAGE))
        return -EOPNOTSUPP;
    if (pte & (PTE_CONT | PTE_SPECIAL | PTE_DEVMAP | PTE_PROT_NONE))
        return -EOPNOTSUPP;
    *slot = ptep;
    *out = pte;
    return 0;
}

static int page_update_bits_locked(void *mm, uint64_t page, uint64_t set, uint64_t clear,
                                   uint64_t required, uint64_t forbidden, uint32_t *arm)
{
    unsigned attempt;

    for (attempt = 0; attempt < 4; ++attempt) {
        uint64_t *ptep, old, next;
        int ret = page_pte_leaf(mm, page, &ptep, &old);

        if (ret) return ret;
        if ((old & required) != required || (old & forbidden)) return -EOPNOTSUPP;
        next = (old | set) & ~clear;
        if (old == next) return 0;
        /* Make replay available before another CPU can see the new PTE. */
        if (arm) __atomic_store_n(arm, 1, __ATOMIC_RELEASE);
        /* Reclaim, hardware AF and per-VMA fault paths can update a leaf
         * independently of the mmap lock. Don't overwrite a newer PTE. */
        if (__atomic_compare_exchange_n(ptep, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
        if (arm) __atomic_store_n(arm, 0, __ATOMIC_RELEASE);
    }
    return -EAGAIN;
}

/* A newer kernel may detach an empty PTE table even while the fault caller
 * holds a read lock. RCU keeps that table's memory valid during the walk
 * and CAS. On non-preemptible RCU kernels this IRQ-off region is sufficient. */
static int page_update_bits(void *mm, uint64_t page, uint64_t set, uint64_t clear,
                            uint64_t required, uint64_t forbidden, uint32_t *arm)
{
    uint64_t daif = 0;
    int ret;

    if (f_rcu_lock) f_rcu_lock();
    else __asm__ volatile("mrs %0, daif; msr daifset, #2" : "=r"(daif) :: "memory");
    ret = page_update_bits_locked(mm, page, set, clear, required, forbidden, arm);
    if (f_rcu_unlock) f_rcu_unlock();
    else __asm__ volatile("msr daif, %0" :: "r"(daif) : "memory");
    return ret;
}

/* Toggle EL0 execute-never on a site page. The caller either holds the mmap
 * write lock (arm/disarm) or is completing the fault that just installed this
 * exact PTE. Returns 1 when the entry changed, 0 when it was already in the
 * requested state, negative on a page that cannot be trapped. */
static int page_set_uxn(void *mm, uint64_t page, int set)
{
    return page_update_bits(mm, page, set ? PTE_UXN : 0, set ? 0 : PTE_UXN,
                            PTE_USER, set ? PTE_GP : 0, 0);
}

/* Toggle EL0 data permission (AP[1]) on the target page.  With AP[2] (read-
 * only) held, clearing AP[1] makes every EL0 data read of this page take a
 * permission abort, while EL0 instruction fetch is governed by UXN alone and
 * stays native.  The caller holds the mmap write lock, or is completing the
 * fault that installed this PTE. */
static int page_set_ap(void *mm, uint64_t page, int set)
{
    return page_update_bits(mm, page, set ? PTE_USER : 0, set ? 0 : PTE_USER,
                            PTE_RDONLY, PTE_UXN | PTE_DBM, 0);
}

/* Registration already copied every target page. If reclaim drops a PTE
 * before arming, return EAGAIN after the common session rollback. */
static long ap_arm_pages(struct uy_session *s, void *mm)
{
    uint32_t i;
    int ret = 0;

    uy_mmap_write_lock(mm);
    for (i = 0; i < s->page_count; ++i) {
        struct uy_page *p = &s->pages[i];

        ret = validate_target_vma(f_find_vma(mm, p->base), p->base);
        if (!ret)
            ret = page_update_bits(mm, p->base, 0, PTE_USER,
                                   PTE_USER | PTE_RDONLY, PTE_UXN | PTE_DBM, &p->armed);
        if (ret < 0) break;
    }
    if (i) flush_tlb_all();
    uy_mmap_write_unlock(mm);
    return ret == -ENOENT ? -EAGAIN : ret < 0 ? ret : 0;
}

static int ap_disarm_pages(struct uy_session *s, void *mm)
{
    uint32_t i;
    int rc = 0;

    if (!mm_has_live_user(mm)) return 0;
    uy_mmap_write_lock(mm);
    for (i = 0; i < s->page_count; ++i) {
        struct uy_page *p = &s->pages[i];
        int ret;

        if (!__atomic_load_n(&p->armed, __ATOMIC_ACQUIRE)) continue;
        ret = page_set_ap(mm, p->base, 1);
        if (ret < 0 && ret != -ENOENT) {
            rc = ret;
            continue;
        }
        /* Retain replay for stale faults until the broadcast TLBI finishes. */
        __atomic_store_n(&p->armed, 2, __ATOMIC_RELEASE);
    }
    flush_tlb_all();
    for (i = 0; i < s->page_count; ++i)
        if (__atomic_load_n(&s->pages[i].armed, __ATOMIC_RELAXED) == 2)
            __atomic_store_n(&s->pages[i].armed, 0, __ATOMIC_RELEASE);
    uy_mmap_write_unlock(mm);
    return rc;
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
        ret = validate_site_vma(f_find_vma(mm, s->pc), s->pc, 1);
        if (!ret)
            ret = page_update_bits(mm, s->page, PTE_UXN, 0, PTE_USER, PTE_UXN | PTE_GP,
                                   &s->armed);
        if (g_verbose)
            pr_info("urov-y: page arm pc=%llx pte_flip=%d\n",
                    (unsigned long long)s->pc, ret);
        if (ret != -EAGAIN && ret != -ENOENT) break;
        /* Evicted between the read and the lock: fault it in again with the
         * write lock dropped, then retry. */
        uy_mmap_write_unlock(mm);
        if (uy_access_vm(mm, s->pc, &word, 4, 0) != 4) return -EFAULT;
        if (word != s->original) return -EAGAIN;
        uy_mmap_write_lock(mm);
    }
    if (ret >= 0) {
        flush_tlb_all();
        ret = 0;
    }
    uy_mmap_write_unlock(mm);
    return ret < 0 ? ret : 0;
}

static int site_disarm_page(struct uy_site *s, void *mm)
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
    return ret == -ENOENT || ret >= 0 ? 0 : ret;
}

/* ------------------------------------------------------ BRK site patching */

static long site_arm(struct uy_site *s, void *mm)
{
    uint32_t word;
    int ret;
    unsigned i;

    if (g_sess.mode == UROV_Y_MODE_PAGE_UXN) {
        /* Several sites can share one execute trap. */
        for (i = 0; &g_sess.sites[i] != s; ++i)
            if (g_sess.sites[i].page == s->page) return 0;
        return site_arm_page(s, mm);
    }
    if (uy_access_vm(mm, s->pc, &word, sizeof(word), 0) != sizeof(word))
        return -EFAULT;
    if (word != s->original) return -EAGAIN;
    uy_mmap_write_lock(mm);
    ret = validate_site_vma(f_find_vma(mm, s->pc), s->pc, 0);
    uy_mmap_write_unlock(mm);
    if (ret) return ret;
    /* FOLL_FORCE turns a write fault on the read-only private mapping into the
     * normal COW path (the same mechanism ptrace uses to plant breakpoints), so
     * neither the file page nor the shared page cache is ever modified. */
    word = g_trap_insn;
    ret = uy_access_vm(mm, s->pc, &word, sizeof(word), g_write_gup_flags);
    if (g_verbose)
        pr_info("urov-y: arm pc=%llx wrote=%d\n", (unsigned long long)s->pc, ret);
    if (ret != sizeof(word)) return ret < 0 ? ret : -EFAULT;
    /* copy_to_user_page() handles D-cache maintenance via the kernel alias,
     * including when PAN prevents maintenance using the user VA. */
    uy_flush_icache_all();
    __atomic_store_n(&s->armed, 1, __ATOMIC_RELEASE);
    return 0;
}

/* Restore the original instruction. The write goes through the kernel's
 * temporary mapping of the session mm's page (__access_remote_vm), so it works
 * from any task and any mm, including the unload path of a foreign process.
 * The kernel's copy_to_user_page() cleans the D-cache line to the point of
 * coherency through that kernel alias; uy_flush_icache_all() then broadcasts
 * IC IALLUIS, so no instruction cache anywhere keeps the BRK. */
static int site_disarm(struct uy_site *s, void *mm)
{
    uint32_t word;
    int ret;

    if (!__atomic_load_n(&s->armed, __ATOMIC_ACQUIRE) || !mm_has_live_user(mm)) return 0;
    if (g_sess.mode == UROV_Y_MODE_PAGE_UXN) {
        ret = site_disarm_page(s, mm);
    } else {
        ret = uy_access_vm(mm, s->pc, &word, sizeof(word), 0);
        if (ret != sizeof(word)) return -EFAULT;
        if (word == g_trap_insn) {
            word = s->original;
            ret = uy_access_vm(mm, s->pc, &word, sizeof(word), g_write_gup_flags);
            if (ret != sizeof(word)) return -EFAULT;
        }
        uy_flush_icache_all();
        ret = 0;
    }
    if (!ret) __atomic_store_n(&s->armed, 0, __ATOMIC_RELEASE);
    return ret;
}

/* ------------------------------------------------------------ emulation core */

/* XPACLRI is a NOP on CPUs without pointer authentication. Strip only the
 * comparison value; user x30 and the saved frame are never changed. */
static uint64_t strip_insn_pac(uint64_t addr)
{
    register uint64_t lr asm("x30") = addr;

    asm("hint #7" : "+r" (lr));
    return lr;
}

static int caller_allowed(uint64_t lr)
{
    uint32_t n = g_sess.caller_count;
    uint32_t i;
    if (n == 0U) return 1;
    if (n > UROV_Y_MAX_CALLERS) return 0;
    if (!uy_user_range(lr, 1)) lr = strip_insn_pac(lr);
    if (lr & 3U) return 0;
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
        if (fp < regs->sp || !uy_user_range(fp, sizeof(frame)) || (fp & 15U))
            return 0;
        if (f_copy_in(frame, (const void *)(uintptr_t)fp, sizeof(frame)))
            return 0;
        if (caller_allowed(frame[1])) return 1;
        if (frame[0] <= fp) return 0;
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

static int uy_fp_snapshot(struct uy_fpstate *state)
{
    const char *task = (const char *)current;
    uint64_t pfr;

    if (!g_fp_ready) return -EOPNOTSUPP;
    /* Leave tasks with live SVE/SME context to the native signal path. */
    if (g_layout.task_sve_state >= 0) {
        if (*(void *const *)(task + g_layout.task_sve_state)) return -EOPNOTSUPP;
    } else {
        __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr));
        if ((pfr >> 32) & 15U) return -EOPNOTSUPP;
    }
    if (g_layout.task_sme_state >= 0) {
        if (*(void *const *)(task + g_layout.task_sme_state)) return -EOPNOTSUPP;
    } else {
        __asm__ volatile("mrs %0, id_aa64pfr1_el1" : "=r"(pfr));
        if ((pfr >> 24) & 15U) return -EOPNOTSUPP;
    }
    f_fp_preserve();
    memcpy(state, task + g_layout.task_fpsimd, sizeof(*state));
    return 0;
}

/* Patch a private aligned image before giving it to the kernel's update
 * helper. The scheduler may still save to the task's own buffer on older
 * kernels; writing directly into that buffer before update can lose data. */
static int uy_fp_commit(const struct uro_load *d, const uint8_t *bytes)
{
    struct uy_fpstate state __attribute__((aligned(16)));
    unsigned i;

    if (d->rt > 31U || (d->count == 2U && d->rt2 > 31U)) return -EOPNOTSUPP;
    if (uy_fp_snapshot(&state)) return -EOPNOTSUPP;
    for (i = 0; i < 16U; ++i)
        state.vregs[d->rt][i] = i < d->size ? bytes[i] : 0;
    if (d->count == 2U) {
        for (i = 0; i < 16U; ++i)
            state.vregs[d->rt2][i] = i < d->size ? bytes[d->size + i] : 0;
    }
    f_fp_update(&state);
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
    struct uy_fpstate state __attribute__((aligned(16)));
    unsigned nregs = d->nregs * d->selem;
    unsigned r, s, e, i;

    if (d->nregs < 1U || d->nregs > 4U || d->selem < 1U || d->selem > 4U ||
        nregs > 4U || d->esize < 1U || d->esize > 16U ||
        d->elements < 1U || d->elements > 16U || d->size > 16U)
        return -EOPNOTSUPP;
    for (i = 0; i < nregs; ++i)
        if (d->dst[i] > 31U) return -EOPNOTSUPP;

    if (uy_fp_snapshot(&state)) return -EOPNOTSUPP;
    for (r = 0; r < d->nregs; ++r) {
        for (s = 0; s < d->selem; ++s) {
            unsigned dst = d->dst[r * d->selem + s];
            for (e = 0; e < d->elements; ++e) {
                uint64_t src = ((uint64_t)(r * d->elements + e) * d->selem + s) * d->esize;
                memcpy(&state.vregs[dst][e * d->esize], bytes + src, d->esize);
            }
            if (d->size < 16U)
                memset(&state.vregs[dst][d->size], 0, 16U - d->size);
        }
    }
    f_fp_update(&state);
    return 0;
}

/* Fetch one instruction word from the faulting thread's address space.  A
 * registered target page may have AP[1] cleared, so prefer its immutable
 * snapshot, exactly as the AP handler does for the faulting instruction. */
static int uy_read_insn(uint64_t pc, uint32_t *out)
{
    struct uy_page *page;

    if (!uy_user_range(pc, sizeof(*out)) || (pc & 3U)) return -1;
    page = page_find(page_base(pc));
    if (page) {
        memcpy(out, page->snapshot + (pc - page->base), sizeof(*out));
        return 0;
    }
    return f_copy_in(out, (const void *)(uintptr_t)pc, sizeof(*out)) ? -1 : 0;
}

static int uy_is_ldxr(uint32_t insn, unsigned *size, unsigned *rt, unsigned *rn)
{
    if ((insn & UY_EXCL_LD_MASK) != UY_EXCL_LDXR &&
        (insn & UY_EXCL_LD_MASK) != UY_EXCL_LDAXR)
        return 0;
    *size = insn >> 30;
    *rt = insn & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

static int uy_is_stxr(uint32_t insn, unsigned *size, unsigned *rs, unsigned *rt, unsigned *rn)
{
    if ((insn & UY_EXCL_ST_MASK) != UY_EXCL_STXR &&
        (insn & UY_EXCL_ST_MASK) != UY_EXCL_STLXR)
        return 0;
    *size = insn >> 30;
    *rs = (insn >> 16) & 31U;
    *rt = insn & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

/* Decide whether the faulting load sits in an adjacent
 * LDXR/LDAXR; load; STXR/STLXR sequence whose STXR can be retired here.
 *
 * The ERET that resumes EL0 clears the local exclusive monitor, so the
 * original STXR would always fail.  Completing it in the handler restores the
 * native outcome, but only when the LDXR result is still in Rt: after a
 * successful LDXR the data register equals [Xn].  A skipped LDXR normally
 * leaves a different value, which is not bridged.  A caller that pre-reads
 * [Xn] can forge that evidence, but the bridge additionally requires the
 * store value to equal the bytes already in memory, so even that path only
 * changes the status word and never memory. */
static void uy_llsc_prepare(const struct uro_regs *regs, uint64_t pc,
                            const struct uro_load *load, struct uy_llsc *out)
{
    uint32_t before, after;
    unsigned lsize, lrt, lrn, ssize, srt, srn, srs;
    uint64_t mem = 0, mask;

    memset(out, 0, sizeof(*out));
    if (!f_copy_out || !load || load->vector || load->multi || load->count != 1U)
        return;
    if (pc < 4U || !uy_user_range(pc - 4U, 4U) || !uy_user_range(pc + 4U, 4U))
        return;
    if (uy_read_insn(pc - 4U, &before) || uy_read_insn(pc + 4U, &after))
        return;
    if (!uy_is_ldxr(before, &lsize, &lrt, &lrn) ||
        !uy_is_stxr(after, &ssize, &srs, &srt, &srn))
        return;
    if (lsize != ssize || lrt != srt || lrn != srn) return;
    if (lrt == 31U || lrn == 31U || srn == 31U) return;
    /* The intervening load must not rewrite the value the STXR stores or the
     * base it addresses; a pre/post-index form that writes Xn is equally
     * unreproducible. */
    if (load->rt == lrt || load->rt == lrn ||
        (load->count == 2U && (load->rt2 == lrt || load->rt2 == lrn)))
        return;
    if (load->writeback && load->rn == lrn) return;
    if (regs->x[lrn] & ((UINT64_C(1) << lsize) - 1U)) return;
    if (f_copy_in(&mem, (const void *)(uintptr_t)regs->x[lrn], 1U << lsize))
        return;
    mask = lsize == 3U ? ~UINT64_C(0) : ((UINT64_C(1) << (8U << lsize)) - 1U);
    /* LDXR Wt/Bt/Ht zero-extend into Xt, so the full register must match the
     * zero-extended memory value.  This also rejects a caller that pre-fills
     * the high half of Xt to imitate an executed LDXR. */
    if (regs->x[lrt] != (mem & mask)) return;

    out->base = regs->x[lrn];
    out->value = regs->x[lrt];
    out->size = 1U << lsize;
    out->data_reg = lrt;
    out->base_reg = lrn;
    out->status_reg = srs;
    out->acquire = (before & (1U << 15)) != 0;
    out->release = (after & (1U << 15)) != 0;
    out->valid = 1;
}

/* Commit a prepared bridge after uy_emulate_load() advanced PC past the
 * faulting load.  The store is the STXR's own (same address, width and value),
 * so a failure to write leaves PC on the STXR and the native instruction runs
 * instead. */
static void uy_llsc_commit(struct pt_regs *regs, uint64_t fault_pc,
                           const struct uy_llsc *plan)
{
    if (!plan->valid || regs->pc != fault_pc + 4U) return;
    if (!uy_user_range(plan->base, plan->size) ||
        plan->base + plan->size < plan->base)
        return;
    if (f_copy_out((void *)(uintptr_t)plan->base, &plan->value, plan->size))
        return;
    if (plan->acquire) __asm__ volatile("dmb ishld" ::: "memory");
    if (plan->release) __asm__ volatile("dmb ishst" ::: "memory");
    if (plan->status_reg != 31U) regs->regs[plan->status_reg] = 0;
    regs->pc += 4U;
    __atomic_fetch_add(&g_sess.llsc, 1, __ATOMIC_RELAXED);
}

/* Emulate one load at `pc`: serve the bytes from the registered page images
 * (fake or registration snapshot) plus nofault uaccess for segments outside
 * the session.  `far` is the data-abort address for the PAGE_AP path (0 and
 * check_far==0 for the instruction-trap modes) and must fall inside the
 * decoded access range.  On success the model is committed to `regs`. A
 * negative return is a fail-closed condition; *bad then names the address
 * whose access would have raised the original fault.  When `llsc` is not NULL
 * the function also records, before committing any register, whether an
 * adjacent exclusive sequence can be completed by the caller. */
static int uy_emulate_load(struct pt_regs *regs, uint64_t pc, uint32_t opcode,
                           uint64_t far, int check_far, uint64_t *bad,
                           struct uy_llsc *llsc)
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
        (pc & 3U) || !uy_user_range(pc, 4))
        return -1;
    if (uro_decode(opcode, &model, &load)) return -2;
    /* A vector load has no GPR destination to fall back on, so without the
     * native FPSIMD helpers the honest answer is the old fail-closed signal. */
    if (load.vector && !g_fp_ready) return -6;
    total = load.total;
    if (!total || total > sizeof(bytes) || !uy_user_range(load.address, total) ||
        (load.writeback && !uy_user_range(load.wb, 1)))
        return -3;
    if (check_far && (far < load.address || far - load.address >= total)) return -3;
    if (llsc) {
        memset(llsc, 0, sizeof(*llsc));
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP &&
            !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE))
            uy_llsc_prepare(&model, pc, &load, llsc);
    }

    covered = range_covered(load.address, (unsigned)total);
    if (!covered) {
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
    return 0;
}

/* ---------------------------------------------------------- exception hooks */

static struct uy_site *site_by_pc(uint64_t pc)
{
    unsigned i;

    for (i = 0; i < g_sess.site_count; ++i)
        if (g_sess.sites[i].pc == pc) return &g_sess.sites[i];
    return 0;
}

static struct uy_site *armed_site_page(uint64_t page)
{
    unsigned i;

    for (i = 0; i < g_sess.site_count; ++i) {
        struct uy_site *s = &g_sess.sites[i];
        if (s->page == page && __atomic_load_n(&s->armed, __ATOMIC_ACQUIRE)) return s;
    }
    return 0;
}

static int emulate_or_signal(struct pt_regs *regs, uint32_t opcode, uint64_t far,
                             int check_far, struct uy_llsc *llsc)
{
    uint64_t bad = 0, pc = regs->pc;
    int result = uy_emulate_load(regs, pc, opcode, far, check_far, &bad, llsc);

    if (!result) return 0;
    session_count_failure(pc, result);
    force_segv(result == -5 ? bad : far);
    return result;
}

/* brk_handler(unused, esr, regs) and do_el0_brk64(esr, regs) share the
 * syndrome format. The PC is the address of the BRK, per AArch64 ELR. */
static void uy_brk_before(hook_fargs3_t *args, void *udata)
{
    uint64_t esr = udata ? args->arg0 : args->arg1;
    struct pt_regs *regs = (struct pt_regs *)(udata ? args->arg1 : args->arg2);
    struct uy_site *site;
    uint64_t ref;

    if (!regs || !user_mode(regs) || compat_user_mode(regs) ||
        ((esr >> 26) & 0x3fUL) != UY_BRK_EC || (esr & 0xffffUL) != g_imm)
        return;
    ref = session_get();
    if (!ref) return;
    site = g_sess.mode == UROV_Y_MODE_SITE_BRK ? site_by_pc(regs->pc) : 0;
    if (site) {
        (void)emulate_or_signal(regs, site->original, site->pc, 0, 0);
        args->ret = 0;
        args->skip_origin = 1;
    }
    uy_reader_exit(&g_readers, ref);
}

static int page_flow(struct pt_regs *regs, uint32_t insn)
{
    if (insn == UY_RET_X30) {
        regs->pc = regs->regs[30];
        return 0;
    }
    if (insn == UY_NOP || insn == UY_BTI_C || insn == UY_BTI_J || insn == UY_BTI_JC) {
        regs->pc += 4U;
        return 0;
    }
    return -EOPNOTSUPP;
}

static void uy_abort_before(hook_fargs4_t *args, void *udata)
{
    uint64_t far = args->arg0;
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    unsigned ec = (esr >> 26) & 0x3fUL;
    uint32_t opcode;
    uint64_t ref;

    (void)udata;
    if (!regs || !user_mode(regs) || compat_user_mode(regs) ||
        (ec != UY_EC_IABT_LOW && ec != UY_EC_DABT_LOW) ||
        (esr & (UY_FSC_MASK | UY_ESR_FNV | UY_ESR_S1PTW | UY_ESR_EA)) != UY_FSC_PERM_LEAF ||
        (g_abort_has_iss2 && (esr & UY_ESR_ISS2)) ||
        !uy_user_range(far, 1))
        return;
    ref = session_get();
    if (!ref) return;

    if (g_sess.mode == UROV_Y_MODE_PAGE_AP && ec == UY_EC_DABT_LOW &&
        !(esr & (UY_ESR_WNR | UY_ESR_CM))) {
        struct uy_page *page = page_find(page_base(far));
        struct uy_page *code = page_find(page_base(regs->pc));
        uint64_t fault_pc = regs->pc;
        struct uy_llsc llsc;
        int emulated = -1;

        memset(&llsc, 0, sizeof(llsc));
        if (!page || !__atomic_load_n(&page->armed, __ATOMIC_ACQUIRE)) goto out;
        if ((regs->pc & 3U) || !uy_user_range(regs->pc, sizeof(opcode))) {
            session_count_failure(regs->pc, -EFAULT);
            force_segv(far);
        } else if (code) {
            /* Instruction fetch still uses the original RX bytes, but
             * data uaccess to that same code page can fault on AP[1]. */
            memcpy(&opcode, code->snapshot + (fault_pc - code->base), sizeof(opcode));
            emulated = emulate_or_signal(regs, opcode, far, 1, &llsc);
        } else if (f_copy_in(&opcode, (const void *)(uintptr_t)regs->pc, sizeof(opcode))) {
            session_count_failure(regs->pc, -EFAULT);
            force_segv(far);
        } else {
            emulated = emulate_or_signal(regs, opcode, far, 1, &llsc);
        }
        /* The exception return already cleared the local exclusive monitor;
         * the bridge only restores an outcome the native sequence would have
         * had.  It is attempted after the load committed, and only when the
         * load succeeded. */
        if (!emulated) uy_llsc_commit(regs, fault_pc, &llsc);
    } else if (g_sess.mode == UROV_Y_MODE_PAGE_UXN && ec == UY_EC_IABT_LOW &&
               far == regs->pc && armed_site_page(page_base(far))) {
        struct uy_site *site = site_by_pc(far);

        if (site) {
            (void)emulate_or_signal(regs, site->original, far, 0, 0);
        } else if ((regs->pstate & ((UINT64_C(1) << 20) | (UINT64_C(1) << 21))) ||
                   f_copy_in(&opcode, (const void *)(uintptr_t)far, sizeof(opcode)) ||
                   page_flow(regs, opcode)) {
            session_count_failure(far, -EOPNOTSUPP);
            __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
            force_segv(far);
        }
    } else {
        goto out;
    }
    args->ret = 0;
    args->skip_origin = 1;
out:
    uy_reader_exit(&g_readers, ref);
}

static void uy_mm_fault_before(hook_fargs4_t *args, void *udata)
{
    const char *vma = (const char *)args->arg0;

    (void)udata;
    /* Newer handle_mm_fault() can drop the VMA lock and invalidate the
     * pointer. Capture its mm while the caller's protection still holds. */
    args->local.data0 = vma && overlay_live() ?
        (uintptr_t)__atomic_load_n((void *const *)(vma + g_layout.vma_mm), __ATOMIC_RELAXED) : 0;
    args->local.data1 = args->arg1;
}

/* A fault-in just (re)created the site page PTE from the VMA protection, which
 * is executable. Re-apply the execute-never bit so a page that was evicted or
 * dropped does not silently lose its trap. Covers the user fault path and
 * get_user_pages based readers such as /proc/self/mem. */
static void uy_mm_fault_after(hook_fargs4_t *args, void *udata)
{
    /* The three-, four-, five- and eight-register wrappers share this prefix. */
    void *mm = (void *)args->local.data0;
    uint64_t page = page_base(args->local.data1);
    uint64_t ref;
    int ret = 0;

    (void)udata;
    if ((args->ret & UY_FAULT_INCOMPLETE) || !uy_user_range(page, g_page_size)) return;
    ref = session_get_mm(mm);
    if (!ref) return;
    if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
            struct uy_page *p = page_find(page);
            if (p && __atomic_load_n(&p->armed, __ATOMIC_ACQUIRE))
                ret = page_set_ap(mm, page, 0);
        } else if (g_sess.mode == UROV_Y_MODE_PAGE_UXN && armed_site_page(page)) {
            ret = page_set_uxn(mm, page, 1);
        }
    }
    if (ret > 0) flush_tlb_all();
    if (ret < 0 && ret != -ENOENT)
        __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
    uy_reader_exit(&g_readers, ref);
}

/* ------------------------------------------------------------- control ops */

static long prepare_site(struct uy_site *s, void *mm, uint64_t pc, uint64_t target,
                         int page_mode)
{
    struct uro_regs regs;
    struct uro_load load;
    int ret;

    if ((pc & 3U) || !uy_user_range(pc, 4) || page_base(pc) == target) return -EINVAL;
    uy_mmap_write_lock(mm);
    ret = validate_site_vma(f_find_vma(mm, pc), pc, page_mode);
    uy_mmap_write_unlock(mm);
    if (ret) return ret;
    if (uy_access_vm(mm, pc, &s->original, 4, 0) != 4) return -EFAULT;
    memset(&regs, 0, sizeof(regs));
    regs.pc = pc;
    if (uro_decode(s->original, &regs, &load) || load.vector) return -EOPNOTSUPP;
    s->pc = pc;
    s->page = page_base(pc);
    return 0;
}

static void session_free_storage(void)
{
    void *mm = g_sess.mm;

    uy_free(g_sess.pages);
    uy_free(g_sess.arena);
    memset(&g_sess, 0, sizeof(g_sess));
    __atomic_store_n(&g_owner, 0, __ATOMIC_RELEASE);
    if (mm) f_mmput(mm);
}

/* Keep the read handlers available for replay until the traps are restored.
 * First stop PTE rearm and wait out any rearm that was already in progress. */
static int release_session(int wait_brk_tasks)
{
    void *mm;
    unsigned i;
    int ret = 0;

    if (!overlay_live()) return 0;
    mm = g_sess.mm;
    __atomic_store_n(&g_suspend, 1, __ATOMIC_RELEASE);
    drain_readers(uy_readers_flip(&g_readers));
    if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
        ret = ap_disarm_pages(&g_sess, mm);
    } else {
        for (i = 0; i < g_sess.site_count; ++i) {
            int err = site_disarm(&g_sess.sites[i], mm);
            if (err) ret = err;
        }
    }
    if (ret) {
        __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
        return ret;
    }
    if (wait_brk_tasks && g_sess.mode == UROV_Y_MODE_SITE_BRK && mm_has_live_user(mm) && f_sync_tasks)
        f_sync_tasks();
    drain_readers(uy_readers_close(&g_readers));
    __atomic_store_n(&g_state, UY_STATE_OFF, __ATOMIC_RELEASE);
    session_free_storage();
    __atomic_store_n(&g_degraded, 0, __ATOMIC_RELEASE);
    return 0;
}

static void reap_dead_session(void)
{
    if (overlay_live() && !mm_has_live_user(g_sess.mm)) (void)release_session(0);
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
    if (!file || pgoff > ((max_pos - delta - g_page_size) >> g_page_shift)) {
        ret = -EINVAL;
        goto out;
    }
    pos = (int64_t)((pgoff << g_page_shift) + delta);
    ret = f_kernel_read(file, image, g_page_size, &pos) == (long)g_page_size ? 0 : -EIO;
out:
    uy_mmap_write_unlock(mm);
    return ret;
}

static int valid_window(unsigned off, unsigned len)
{
    return len >= 8U && !(len & 7U) && len <= g_page_size && off <= g_page_size - len;
}

static long validate_page_desc(const struct uy_page_desc *d)
{
    unsigned len = d->fake_len ? d->fake_len : g_page_size;

    if (d->reserved || page_base(d->base) != d->base || !uy_user_range(d->base, g_page_size))
        return -EINVAL;
    if (d->flags == UROV_Y_PAGE_SRC_FILE) {
        if (d->fake_addr || d->fake_off || d->fake_len) return -EINVAL;
        return (g_caps & UROV_Y_CAP_SRC_FILE) ? 0 : -EOPNOTSUPP;
    }
    if (d->flags != UROV_Y_PAGE_SRC_USER || !valid_window(d->fake_off, len) ||
        !uy_user_range(d->fake_addr, len))
        return -EINVAL;
    return 0;
}

static long page_build_image(struct uy_page *p, const struct uy_page_desc *d,
                             void *mm, const struct urov_y_request *legacy)
{
    long ret = copy_user_image(mm, p->base, p->snapshot, g_page_size);

    if (ret) return ret;
    p->fake_off = d->fake_off;
    p->fake_len = d->fake_len ? d->fake_len : g_page_size;
    if (d->flags == UROV_Y_PAGE_SRC_FILE)
        return page_read_file(mm, p->base, p->image);
    memcpy(p->image, p->snapshot, g_page_size);
    if (legacy)
        return copy_request_image(legacy, mm, p->image + p->fake_off, p->fake_len);
    return copy_user_image(mm, d->fake_addr, p->image + p->fake_off, p->fake_len);
}

static long do_register(struct urov_y_request *q)
{
    void *mm;
    struct uy_page_desc *descs;
    uint64_t desc_bytes;
    uint32_t mode = q->mode ? q->mode : UROV_Y_MODE_SITE_BRK;
    uint32_t n = q->page_count ? q->page_count : 1;
    unsigned i;
    long ret;

    if (q->flags || q->reserved || q->reserved2 ||
        (q->session_flags & ~UROV_Y_F_REPLAY_SNAPSHOT) ||
        q->site_count > UROV_Y_MAX_SITES || q->caller_count > UROV_Y_MAX_CALLERS)
        return -EINVAL;
    if (mode != UROV_Y_MODE_SITE_BRK && mode != UROV_Y_MODE_PAGE_UXN &&
        mode != UROV_Y_MODE_PAGE_AP)
        return -EINVAL;
    if (mode == UROV_Y_MODE_SITE_BRK && !g_brk_hooked) return -EOPNOTSUPP;
    if (mode != UROV_Y_MODE_SITE_BRK && (!g_page_hooked || !g_mmf_hooked))
        return -EOPNOTSUPP;
    if (q->page_count && mode != UROV_Y_MODE_PAGE_AP) return -EOPNOTSUPP;
    if (mode != UROV_Y_MODE_PAGE_AP && !q->site_count) return -EINVAL;
    if (n > g_max_pages) return -EINVAL;
    for (i = 0; i < q->caller_count; ++i)
        if (q->caller_start[i] >= q->caller_end[i] ||
            !uy_user_range(q->caller_start[i], q->caller_end[i] - q->caller_start[i]))
            return -EINVAL;
    if (overlay_live()) return -EBUSY;

    desc_bytes = (uint64_t)n * sizeof(*descs);
    if (q->page_count &&
        (q->page_stride != sizeof(*descs) || !uy_user_range(q->pages_addr, desc_bytes)))
        return -EINVAL;
    descs = uy_alloc((unsigned long)desc_bytes);
    if (!descs) return -ENOMEM;
    mm = f_get_task_mm(current);
    if (!mm || mm != mm_of_task(current) || !mm_has_live_user(mm)) {
        if (mm) f_mmput(mm);
        uy_free(descs);
        return -EOPNOTSUPP;
    }
    g_sess.mm = mm;
    __atomic_store_n(&g_owner, mm, __ATOMIC_RELEASE);

    if (q->page_count) {
        ret = copy_user_image(mm, q->pages_addr, (uint8_t *)descs, (unsigned)desc_bytes);
        if (ret) goto fail;
        for (i = 0; i < n; ++i) {
            ret = validate_page_desc(&descs[i]);
            if (ret) goto fail;
            descs[i].reserved = i; /* preserve the caller's descriptor index */
        }
        sort_descs(descs, n);
        for (i = 1; i < n; ++i) {
            if (descs[i - 1].base == descs[i].base) {
                ret = -EINVAL;
                goto fail;
            }
        }
    } else {
        unsigned len = request_fake_len(q);

        if (page_base(q->address) != q->address || !uy_user_range(q->address, g_page_size) ||
            !valid_window(q->offset, len) ||
            (q->fake_addr ? !uy_user_range(q->fake_addr, len) : len > UROV_Y_FAKE_MAX)) {
            ret = -EINVAL;
            goto fail;
        }
        descs[0] = (struct uy_page_desc) {
            .base = q->address, .flags = UROV_Y_PAGE_SRC_USER,
            .fake_off = q->offset, .fake_len = len,
        };
    }

    g_sess.pages = uy_alloc(n * sizeof(*g_sess.pages));
    g_sess.arena = uy_alloc(3UL * n * g_page_size);
    if (!g_sess.pages || !g_sess.arena) {
        ret = -ENOMEM;
        goto fail;
    }
    memset(g_sess.pages, 0, n * sizeof(*g_sess.pages));
    g_sess.page_count = n;
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
        p->image = g_sess.arena + 3UL * i * g_page_size;
        p->spare = p->image + g_page_size;
        p->snapshot = p->spare + g_page_size;
        uy_mmap_write_lock(mm);
        ret = validate_target_vma(f_find_vma(mm, p->base), p->base);
        uy_mmap_write_unlock(mm);
        if (ret) goto fail;
        ret = page_build_image(p, d, mm, q->page_count ? 0 : q);
        if (ret) goto fail;
    }

    if (mode != UROV_Y_MODE_PAGE_AP) {
        for (i = 0; i < q->site_count; ++i) {
            unsigned j;
            for (j = 0; j < i; ++j) {
                if (q->sites[i] == q->sites[j]) {
                    ret = -EINVAL;
                    goto fail;
                }
            }
            ret = prepare_site(&g_sess.sites[i], mm, q->sites[i], q->address,
                               mode == UROV_Y_MODE_PAGE_UXN);
            if (ret) goto fail;
        }
        g_sess.site_count = q->site_count;
    }

    /* From the first PTE/BRK edit on, a racing reader must have a valid
     * replay view. Enable fake values only after the complete set is armed. */
    g_sess.generation = 1;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_suspend, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&g_state, UY_STATE_LIVE, __ATOMIC_RELEASE);
    uy_readers_open(&g_readers);
    if (mode == UROV_Y_MODE_PAGE_AP) {
        ret = ap_arm_pages(&g_sess, mm);
    } else {
        for (i = 0; i < g_sess.site_count; ++i) {
            ret = site_arm(&g_sess.sites[i], mm);
            if (ret) break;
        }
    }
    if (ret) {
        int restore = release_session(1);
        uy_free(descs);
        return restore ? restore : ret;
    }
    __atomic_store_n(&g_suspend, 0, __ATOMIC_RELEASE);

    q->session = 1;
    q->generation = g_sess.generation;
    q->mode = mode;
    q->page_count = n;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, &g_sess.pages[0]);
    q->offset = g_sess.pages[0].fake_off;
    q->length = g_sess.pages[0].fake_len;
    q->state = UROV_Y_ACTIVE;
    uy_free(descs);
    return 0;

fail:
    session_free_storage();
    uy_free(descs);
    if (g_verbose) pr_info("urov-y: register rejected ret=%ld pages=%u\n", ret, n);
    return ret;
}

static void set_reply(struct urov_y_request *q)
{
    struct uy_page *p = &g_sess.pages[0];

    q->generation = ++g_sess.generation;
    q->state = UROV_Y_ACTIVE;
    q->page_count = g_sess.page_count;
    q->page_stride = UROV_Y_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, p);
    q->offset = p->fake_off;
    q->length = p->fake_len;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
}

static long do_set(struct urov_y_request *q)
{
    struct uy_page *p;
    unsigned len = request_fake_len(q);
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return -EBUSY;
    if (q->reserved || q->reserved2 || q->flags || g_sess.page_count != 1) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    p = &g_sess.pages[0];
    if (len != p->fake_len || p->flags != UROV_Y_PAGE_SRC_USER) return -EINVAL;
    memcpy(p->spare, p->snapshot, g_page_size);
    ret = copy_request_image(q, g_sess.mm, p->spare + p->fake_off, len);
    if (ret) return ret;
    page_swap_image(p, p->fake_off, len);
    set_reply(q);
    return 0;
}

static long do_set_page(struct urov_y_request *q)
{
    struct uy_page *p;
    unsigned len = q->length ? q->length : g_page_size;
    unsigned off = q->offset;
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return -EBUSY;
    if (q->flags || q->reserved2 || q->reserved >> 32) return -EINVAL;
    p = page_by_index((uint32_t)q->reserved);
    if (!p) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;

    if (p->flags == UROV_Y_PAGE_SRC_FILE) {
        ret = page_read_file(g_sess.mm, p->base, p->spare);
        off = 0;
        len = g_page_size;
    } else {
        if (!valid_window(off, len)) return -EINVAL;
        memcpy(p->spare, p->snapshot, g_page_size);
        ret = copy_user_image(g_sess.mm, q->fake_addr, p->spare + off, len);
    }
    if (ret) return ret;
    page_swap_image(p, off, len);
    set_reply(q);
    return 0;
}

static uint32_t armed_pages(void)
{
    uint32_t i, n = 0;

    for (i = 0; i < g_sess.page_count; ++i)
        if (__atomic_load_n(&g_sess.pages[i].armed, __ATOMIC_ACQUIRE)) ++n;
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
    q->page_stride = g_page_shift;
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
    q->page_stride = g_page_shift;
    q->session_flags = g_caps;
    q->reserved = 0;
    return 0;
}

static long do_deactivate(struct urov_y_request *q)
{
    int ret;

    if (q->session != 1 && q->session != 0) return -ENOENT;
    if (overlay_live() && !session_owned()) return -ENOENT;
    ret = release_session(1);
    if (ret) return ret;
    status_inactive(q);
    return 0;
}

static long dispatch(struct urov_y_request *q, unsigned cmd)
{
    long ret;

    if (!ctrl_try_lock()) return -EBUSY;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) {
        ctrl_unlock();
        return -EOPNOTSUPP;
    }
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
    if (sys_arg(args, 1) != UROV_Y_PRCTL_MAGIC) return;
    user = (void *)sys_arg(args, 3);
    size = (unsigned long)sys_arg(args, 4);
    if (sys_arg(args, 2) > 0xffffU) return;
    cmd = (unsigned)sys_arg(args, 2);
    if (size != sizeof(q) || !uy_user_range((uintptr_t)user, sizeof(q))) return;
    if (f_copy_in(&q, user, sizeof(q))) return;
    if (q.size != sizeof(q) || q.version != UROV_Y_ABI_VERSION ||
        q.op != (uint16_t)cmd) return;
    if (q.mac != urov_y_request_mac(g_keys.mac, &q)) return;
    ret = dispatch(&q, cmd);
    q.fake_addr = 0;
    q.pages_addr = 0;
    if (uy_copy_control_reply(user, &q, sizeof(q))) ret = -EFAULT;
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* ---------------------------------------------------------- mapping gates */

#define UY_CLONE_VM 0x00000100ULL
#define UY_CLONE_VFORK 0x00004000ULL
#define UY_MAP_FIXED 0x10ULL
#define UY_MREMAP_FIXED 0x2ULL

enum uy_gate_kind {
    UY_GATE_MPROTECT,
    UY_GATE_MUNMAP,
    UY_GATE_MREMAP,
    UY_GATE_MMAP,
    UY_GATE_MADVISE,
    UY_GATE_EXECVE,
    UY_GATE_EXECVEAT,
    UY_GATE_PKEY_MPROTECT,
    UY_GATE_REMAP_FILE_PAGES,
};

static const int g_gate_nrs[UY_GATE_NUM] = {
    __NR_mprotect, __NR_munmap, __NR_mremap, __NR_mmap, __NR_madvise, __NR_execve,
    __NR_execveat, __NR_pkey_mprotect, __NR_remap_file_pages,
};

static int caller_is_owner(void)
{
    void *mm = mm_of_task(current);

    return mm && mm == __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE);
}

static void gate_error(hook_fargs6_t *args, long ret)
{
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* End the session before a fork or vfork can copy a patched mapping. A
 * thread that merely shares the mm keeps the same session. */
static void uy_clone_before(hook_fargs6_t *args, void *udata)
{
    uint64_t flags;
    int ret = 0;

    if (!caller_is_owner()) return;
    flags = sys_arg(args, 0);
    if (udata && f_copy_in(&flags, (const void *)(uintptr_t)flags, sizeof(flags)))
        flags = 0;
    if ((flags & UY_CLONE_VM) && !(flags & UY_CLONE_VFORK)) return;
    if (!ctrl_try_lock()) {
        gate_error(args, -EBUSY);
        return;
    }
    if (session_owned()) ret = release_session(1);
    ctrl_unlock();
    if (ret) gate_error(args, ret);
}

/* Only called while holding the control lock. A tagged mapping argument
 * may refer to the same page as an untagged registration address. */
static int gate_range_overlaps(uint64_t start, uint64_t len)
{
    uint64_t end;
    uint32_t lo = 0, hi = g_sess.page_count;
    unsigned i;

    if (!len) return 0;
    start &= (UINT64_C(1) << 56) - 1;
    end = start + len;
    if (end < start) end = ~UINT64_C(0);
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_sess.pages[mid].base < start) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_sess.page_count && end > g_sess.pages[lo].base) return 1;
    if (lo > 0 && start < g_sess.pages[lo - 1].base + g_page_size) return 1;
    for (i = 0; i < g_sess.site_count; ++i) {
        uint64_t p = g_sess.sites[i].page;
        if (start < p + g_page_size && end > p) return 1;
    }
    return 0;
}

/* A protected mapping is restored before the native syscall runs. If a
 * concurrent control transaction owns the session, the mutator must retry
 * instead of proceeding underneath it. */
static void uy_gate_before(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;
    int ret = 0;

    if (!caller_is_owner()) return;
    if (kind == UY_GATE_MMAP && !(sys_arg(args, 3) & UY_MAP_FIXED)) return;
    if (!ctrl_try_lock()) {
        gate_error(args, -EBUSY);
        return;
    }
    if (session_owned() &&
        (kind == UY_GATE_EXECVE || kind == UY_GATE_EXECVEAT ||
         gate_range_overlaps(sys_arg(args, 0), sys_arg(args, 1)) ||
         (kind == UY_GATE_MREMAP && (sys_arg(args, 3) & UY_MREMAP_FIXED) &&
          gate_range_overlaps(sys_arg(args, 4), sys_arg(args, 2)))))
        ret = release_session(1);
    ctrl_unlock();
    if (ret) gate_error(args, ret);
}

/* -------------------------------------------------------------------- init */

static void *lookup(const char *name)
{
    return (void *)kallsyms_lookup_name(name);
}

static int resolve_geometry(void)
{
    struct uy_geometry geom;
    uint64_t tcr, sctlr;

    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    if ((sctlr & (3ULL << 24)) || uy_geometry_from_tcr(&geom, tcr)) return -EOPNOTSUPP;
    g_page_shift = geom.page_shift;
    g_page_size = 1U << g_page_shift;
    g_user_limit = UINT64_C(1) << geom.user_va_bits;
    return 0;
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
    if (!file || (uintptr_t)file >= (uintptr_t)-4095L) return file ? (long)file : -ENOMEM;
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
    const char *fp_name = "fpsimd_save_and_flush_current_state";
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
    /* Only inspect extended syndrome bits if the entry takes a full ESR. */
    g_abort_has_iss2 = uy_btf_signature(btf, kclf_btf_func_proto(btf, "do_mem_abort"), "vllr");
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
        f_find_vma = uy_btf_signature(btf, kclf_btf_func_proto(btf, vma_name), "aml") ?
                     (find_vma_t)lookup(vma_name) : 0;
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

    /* Newer update_current_state() only updates the saved state. Use the
     * save-and-flush helper when present so the EL0 return reloads it. */
    f_fp_preserve = (fpsimd_preserve_t)lookup(fp_name);
    if (!f_fp_preserve || !uy_symbol_abi(btf, fp_name, "v")) {
        fp_name = "fpsimd_signal_preserve_current_state";
        f_fp_preserve = (fpsimd_preserve_t)lookup(fp_name);
    }
    f_fp_update = (fpsimd_update_t)lookup("fpsimd_update_current_state");
    g_fp_ready = f_fp_preserve && f_fp_update && g_layout.task_fpsimd >= 0 &&
                 uy_symbol_abi(btf, fp_name, "v") &&
                 uy_symbol_abi(btf, "fpsimd_update_current_state", "vf");

    if (!f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_force_sig_fault ||
        !f_copy_in || !access_argc || (!*brk_argc && !(f_do_mem_abort && *mmf_argc))) {
        pr_info("urov-y: required MM/uaccess/signal or trap ABI unavailable\n");
        return -EOPNOTSUPP;
    }
    if (g_verbose)
        pr_info("urov-y: kver=%x vma=%s lock=%s mm_fault=%s/%d brk=%s/%d "
                "access=%s/%d read=%s write=%s fpsimd=%s foll_force=0x%x page_shift=%u\n",
                kver, vma_name, g_use_rwsem ? "rwsem" : "mmap",
                *mmf_argc ? fault_name : "none", *mmf_argc,
                *brk_argc ? brk_name : "none", *brk_argc, access_name, access_argc,
                read_name, f_copy_out ? write_name : "control-gup",
                g_fp_ready ? fp_name : "none", foll_force, g_page_shift);
    return 0;
}

static long resolve_kernel(const char *btf_path, int *brk_argc, int *mmf_argc)
{
    struct kclf_btf btf;
    void *storage = 0;
    long ret = 0;

    if (kver < VERSION(5, 4, 0) || kver >= VERSION(7, 0, 0) || resolve_geometry()) {
        pr_info("urov-y: unsupported kernel or page tables (kver=%x)\n", kver);
        return -EOPNOTSUPP;
    }
    resolve_allocators();
    if (!f_kvmalloc_node && !f_vmalloc) return -EOPNOTSUPP;
    f_msleep = (msleep_t)lookup("msleep");
    if (!f_msleep) return -EOPNOTSUPP;
    f_rcu_lock = (void_fn)lookup("__rcu_read_lock");
    f_rcu_unlock = (void_fn)lookup("__rcu_read_unlock");
    if (!f_rcu_lock || !f_rcu_unlock) f_rcu_lock = f_rcu_unlock = 0;
    f_sync_tasks = (void_fn)lookup("synchronize_rcu_tasks");
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
    if (g_max_pages > g_max_image_bytes / (3U * g_page_size))
        g_max_pages = (uint32_t)(g_max_image_bytes / (3U * g_page_size));
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

    ret = fp_hook_syscalln(__NR_clone, 6, uy_clone_before, 0, (void *)0);
    g_clone_hooked = ret ? 0 : 1;
#ifdef __NR_clone3
    ret = fp_hook_syscalln(__NR_clone3, 6, uy_clone_before, 0, (void *)1);
    g_clone3_hooked = ret ? 0 : 1;
    if (!g_clone3_hooked) {
        urov_y_backend_exit();
        return -EOPNOTSUPP;
    }
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
    if (g_brk_hooked) g_caps |= UROV_Y_CAP_SITE_BRK;
    if (g_page_shift == 14U) g_caps |= UROV_Y_CAP_16K;
    if (g_page_hooked) {
        g_caps |= UROV_Y_CAP_MULTI | UROV_Y_CAP_CROSS |
                  UROV_Y_CAP_PAGE_AP | UROV_Y_CAP_PAGE_UXN;
        if (g_fp_ready)
            g_caps |= UROV_Y_CAP_LD1 | UROV_Y_CAP_LD2 | UROV_Y_CAP_LD3 | UROV_Y_CAP_LD4;
        if (f_kernel_read && g_layout.vma_pgoff_ok) g_caps |= UROV_Y_CAP_SRC_FILE;
    }
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);

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
    /* A legacy KPM loader can call ctl0 inside an RCU read-side section. */
    return f_copy_out ? f_copy_out(dst, src, len) : -EOPNOTSUPP;
}

long urov_y_backend_exit(void)
{
    int i, ret;

    if (g_verbose)
        pr_info("urov-y: exit live=%d\n", overlay_live());
    __atomic_store_n(&g_ready, 0, __ATOMIC_RELEASE);
    while (!ctrl_try_lock()) f_msleep(1);
    /* KernelPatch 0.12.0 can invoke exit inside rcu_read_lock(). A Tasks
     * grace period here can self-deadlock. Complete DEACTIVATE in the owner
     * before unloading on such hosts; this is only best-effort restoration. */
    ret = release_session(0);
    ctrl_unlock();
    if (ret) {
        __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);
        return ret;
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
        fp_unhook_syscalln(__NR_clone3, uy_clone_before, 0);
        g_clone3_hooked = 0;
    }
    if (g_clone_hooked) {
        fp_unhook_syscalln(__NR_clone, uy_clone_before, 0);
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
    memset(&g_keys, 0, sizeof(g_keys));
    return 0;
}

long urov_y_status_get(struct uy_status *out)
{
    uint32_t i, gates = 1;

    if (!out) return -EINVAL;
    if (!ctrl_try_lock()) return -EBUSY;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) {
        ctrl_unlock();
        return -EOPNOTSUPP;
    }
    memset(out, 0, sizeof(*out));
    out->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    out->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    out->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
    out->llsc = __atomic_load_n(&g_sess.llsc, __ATOMIC_RELAXED);
    out->active = overlay_live();
    if (out->active) {
        out->sites = g_sess.site_count;
        out->armed = armed_pages();
        for (i = 0; i < out->sites; ++i)
            out->armed += __atomic_load_n(&g_sess.sites[i].armed, __ATOMIC_ACQUIRE);
        out->mode = g_sess.mode;
        out->overlay_len = g_sess.pages[0].fake_len;
        out->page_count = g_sess.page_count;
    }
    for (i = 0; i < UY_GATE_NUM; ++i) gates &= g_gate_hooked[i];
    out->hooks = (g_brk_hooked ? 1U : 0U) | (g_prctl_hooked ? 2U : 0U) |
                 (gates ? 4U : 0U) |
                 (g_clone_hooked ? 8U : 0U) | (g_clone3_hooked ? 16U : 0U) |
                 (g_page_hooked ? 32U : 0U) | (g_mmf_hooked ? 64U : 0U);
    out->degraded = __atomic_load_n(&g_degraded, __ATOMIC_ACQUIRE) ? 1U : 0U;
    out->core_checks = URO_CORE_CHECKS;
    out->imm = (uint32_t)g_imm;
    out->fpsimd = g_page_hooked && g_fp_ready;
    out->abi = UROV_Y_ABI_VERSION;
    out->page_shift = g_page_shift;
    out->caps = g_caps;
    ctrl_unlock();
    return 0;
}
