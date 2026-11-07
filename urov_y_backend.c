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
 * clears the exclusive reservation, an adjacent LDXR;load;STXR is completed
 * in the handler (see uy_llsc_prepare), but only when the LDXR result is still
 * in Rt and no direct branch in any executable mapping of the process, or
 * indirect branch target left in a GPR, reaches the LDXR..load span.  Every
 * other store stays native.
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
/* VM_LOCKED is 0x2000 and VM_IO is 0x4000 in every supported kernel (4.x-6.x).
 * 2.11.0 and earlier defined UY_VM_IO as 0x2000, i.e. they rejected VM_LOCKED:
 * an app could call mlock() on its own RX page and make REGISTER fail with
 * EINVAL.  Locking only pins a page against reclaim and does not change the
 * leaf PTE, so 2.12.0 accepts VM_LOCKED and rejects only the real VM_IO. */
#define UY_VM_LOCKED 0x00002000UL
#define UY_VM_IO 0x00004000UL
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

#define UY_FAULT_WRITE 0x01U
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
typedef void *(*find_task_by_vpid_t)(int pid);
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
    /* Registration-time VMA identity.  A fork copies the VMA with
     * vm_area_dup(), so the child keeps the same vm_file pointer, pgoff and
     * range; a foreign process that opens the same file again has a different
     * struct file.  handle_mm_fault uses this to re-arm a forked child's copy
     * without ever arming an unrelated mapping. */
    void *vma_file;
    uint64_t vma_pgoff;
    uint64_t vma_start;
    uint64_t vma_end;
};

struct uy_session {
    void *mm;
    uint64_t tgid;      /* owner thread group: only its execve replaces the mm */
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
/* Page bases of the last session, kept after release so an orphaned trap (a
 * forked child that never read the page while the session was live) can be
 * restored instead of turning into a signal.  Only the bases are needed and
 * they are never dereferenced as pages, so the storage is a fixed array. */
#define UY_RETIRED_MAX 64U
static uint64_t g_retired[UY_RETIRED_MAX];
static uint32_t g_retired_count;
static uint32_t g_retired_mode;

static void *f_brk_handler;
static void *f_do_mem_abort;
static void *f_handle_mm_fault;
static get_task_mm_t f_get_task_mm;
static mmput_t f_mmput;
static find_task_by_vpid_t f_find_task_by_vpid;
static find_vma_t f_find_vma;
static mmap_write_fn f_mmap_write_lock;
static mmap_write_fn f_mmap_write_unlock;
static mmap_write_fn f_mmap_read_lock;
static mmap_write_fn f_mmap_read_unlock;
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
static int g_vm_readv_hooked;
static int g_clone_hooked;
static int g_clone3_hooked;
static int g_wrapper_mode;
static int g_page_hooked;
static int g_mmf_hooked;
static int g_degraded;
static int g_abort_has_iss2;
/* Kernel-assisted reads (access_remote_vm/__access_remote_vm) are overlaid by
 * a function hook.  The hook target is the implementation entry when it
 * exists, so both /proc/<pid>/mem and access_process_vm() are covered. */
static void *f_kread;
static int g_kread_argc;
static int g_kread_hooked;
/* Set to `current` only while the module itself calls the access helper.  The
 * kernel-read hook must never rewrite the module's own snapshot/image reads. */
static void *g_internal_access;
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

/* Same-mm kernel-assisted readers are identified by the calling task's own
 * pid/tgid.  Both offsets come from the validated task_struct layout. */
static uint64_t uy_task_pid(void)
{
    return g_layout.task_pid >= 0 ?
        (uint64_t)*(const uint32_t *)((const char *)current + g_layout.task_pid) : 0;
}

static uint64_t uy_task_tgid(void)
{
    return g_layout.task_tgid >= 0 ?
        (uint64_t)*(const uint32_t *)((const char *)current + g_layout.task_tgid) : 0;
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
    void *prev;
    int ret;

    /* Registration, site arming and control replies read/write the very pages
     * the kernel-read hook rewrites.  Mark the task while the module's own
     * call is in flight so the after hook leaves that buffer alone. */
    prev = __atomic_exchange_n(&g_internal_access, current, __ATOMIC_ACQ_REL);
    if (f_access_vm) ret = f_access_vm(mm, addr, buf, len, flags);
    /* Old public access_remote_vm() supplies a NULL task to this variant.
     * Passing current here would associate a foreign mm with the unload task. */
    else ret = f_access_vm_task(0, mm, addr, buf, len, flags);
    __atomic_store_n(&g_internal_access, prev, __ATOMIC_RELEASE);
    return ret;
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

static int overlay_live(void);

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

/* A reader that inherited the leaf trap but not the mm binding (a forked
 * child of the owner).  It is served from the same immutable image while the
 * session lives; the reader epoch keeps that image alive across a release. */
static uint64_t session_get_any(void)
{
    uint64_t ref;

    if (!overlay_live()) return 0;
    ref = uy_reader_enter(&g_readers);
    if (ref && !overlay_live()) {
        uy_reader_exit(&g_readers, ref);
        return 0;
    }
    return ref;
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

/* A leaf PTE that only this module produces: present, read-only for EL0
 * (AP[2]=1) and without EL0 read permission (AP[1]=0).  The kernel never
 * creates that pair for a readable VMA - execute-only mappings have no
 * VM_READ and PROT_NONE pages carry PTE_PROT_NONE - so the signature both
 * identifies a trap a forked child inherited and keeps an unrelated
 * permission fault from being "repaired" into a readable page. */
static int uy_leaf_signature(uint64_t pte)
{
    if ((pte & (PTE_VALID | PTE_TYPE_MASK)) != (PTE_VALID | PTE_TYPE_PAGE)) return 0;
    if (pte & (PTE_CONT | PTE_SPECIAL | PTE_DEVMAP | PTE_PROT_NONE)) return 0;
    return !(pte & PTE_USER) && (pte & PTE_RDONLY);
}

static int uy_trap_leaf(void *mm, uint64_t far)
{
    uint64_t *ptep;
    uint64_t pte;

    if (!mm) return 0;
    ptep = pte_of(mm, page_base(far));
    if (!ptep) return 0;
    pte = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    return uy_leaf_signature(pte);
}

/* Restore AP[1] on a trap whose session is gone and let the faulting
 * instruction retry, so an orphaned trap can never become a signal. */
static int uy_repair_trap(void *mm, uint64_t far)
{
    uint64_t *ptep;
    uint64_t old;

    if (!mm) return 0;
    ptep = pte_of(mm, page_base(far));
    if (!ptep) return 0;
    old = __atomic_load_n(ptep, __ATOMIC_ACQUIRE);
    if (!uy_leaf_signature(old)) return 0;
    if (!__atomic_compare_exchange_n(ptep, &old, old | PTE_USER, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;
    flush_tlb_all();
    return 1;
}

static int uy_retired_has(uint64_t page)
{
    uint32_t i;

    for (i = 0; i < g_retired_count; ++i)
        if (g_retired[i] == page) return 1;
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
 * (for example after a failed execmod restore) can never be registered.
 *
 * VM_LOCKED is deliberately accepted since 2.12.0.  2.11.0 and earlier used
 * 0x2000 for VM_IO, which is VM_LOCKED on every supported kernel, so an app
 * could call mlock() on its own RX page and make REGISTER fail with EINVAL.
 * Locking does not change the leaf PTE the trap edits; it only pins the page
 * against reclaim, which even shrinks the fault-in re-arm window. */
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

/* Remember what identifies this mapping.  fork() duplicates the VMA through
 * vm_area_dup(), so a child keeps the same struct file pointer, pgoff and
 * range; a different process that maps the same file gets its own struct
 * file.  handle_mm_fault uses this to re-arm only a copy of the registered
 * mapping. */
static void uy_capture_vma(struct uy_page *p, void *vma)
{
    p->vma_file = vma ? *(void **)((char *)vma + g_layout.vma_file) : 0;
    p->vma_pgoff = vma && g_layout.vma_pgoff_ok ?
        *(unsigned long *)((char *)vma + g_layout.vma_pgoff) : 0;
    p->vma_start = vma ? *(unsigned long *)((char *)vma + g_layout.vma_start) : 0;
    p->vma_end = vma ? *(unsigned long *)((char *)vma + g_layout.vma_end) : 0;
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

/* Re-apply the data trap after a protection change that kept the page
 * readable and executable.  Linux often returns early when the new
 * protection equals the current one, so the common mprotect(RX) hardening
 * call does not even change the PTE; this covers the calls that do. */
static void ap_rearm_range(void *mm, uint64_t start, uint64_t len)
{
    uint64_t end = start + len;
    uint32_t i;
    int changed = 0;

    if (end < start) end = ~UINT64_C(0);
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uy_page *p = &g_sess.pages[i];
        int ret;

        if (p->base < start || p->base + g_page_size > end) continue;
        if (!__atomic_load_n(&p->armed, __ATOMIC_ACQUIRE)) continue;
        ret = page_set_ap(mm, p->base, 0);
        if (ret > 0) changed = 1;
    }
    if (changed) flush_tlb_all();
}

/* A fork of the session owner copies the trapped leaf PTE.  The child is not
 * bound to the session mm, so handle_mm_fault cannot use session_get_mm();
 * the VMA identity captured before the fault proves this mm carries a copy of
 * the registered mapping. */
static int ap_shadow_rearm(void *mm, uint64_t page, uint64_t file, uint64_t pgoff,
                           uint64_t start, uint64_t end)
{
    struct uy_page *p = page_find(page);
    int ret;

    if (!p || !mm || mm == g_sess.mm) return 0;
    if (file != (uint64_t)(uintptr_t)p->vma_file || pgoff != p->vma_pgoff ||
        start != p->vma_start || end != p->vma_end)
        return 0;
    ret = page_set_ap(mm, page, 0);
    return ret > 0 ? 1 : 0;
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

/* A direct branch can enter the load without executing the LDXR.  Retiring
 * the STXR on such a path would report a success the hardware never produced.
 * 2.7.0 scanned only the faulting page; the 2.8.0 cross-page probe puts the
 * branch in another page, so the map covers every executable VMA of the
 * session mm, and stays complete for the whole session:
 *
 *   - REGISTER decodes every VM_EXEC VMA before the first AP page is armed;
 *   - a code page that was not resident is scanned by the fault hook when it
 *     first becomes present, before the faulting task returns to EL0;
 *   - a resident but unreadable (execute-only) page marks the map incomplete;
 *   - executable mappings created later are scanned from the mmap/mprotect/
 *     mremap after hooks, and a range that cannot be added also marks the map
 *     incomplete.  An incomplete map never bridges.
 *
 * Read-path cost is one bit test.  The region list is append-only: an older
 * region keeps a reused address range, so marking and lookup never disagree
 * even when code is unmapped and a new mapping reuses its address. */

#define UY_CODE_MAX_REGIONS 1024U
#define UY_CODE_BITMAP_MAX (16U << 20)
#define UY_CODE_ARENA_MAX (24U << 20)
#define UY_CODE_SCAN_MAX (64U << 20)
#define UY_BRANCH_CHUNK 4096U

struct uy_code_region {
    uint64_t start;
    uint64_t end;
    uint64_t bitmap_off;
};

struct uy_code_map {
    struct uy_code_region region[UY_CODE_MAX_REGIONS];
    uint8_t *arena;
    uint64_t arena_size;
    uint64_t arena_used;
    uint32_t count;
    uint32_t valid;
    uint32_t complete;
    /* Odd while a scan is extending the map.  The fault path reads it on both
     * sides of the bit test, so a concurrent scan makes that trial decline
     * instead of trusting a partially updated map. */
    uint32_t seq;
};

static struct uy_code_map g_code;
static uint32_t g_code_buf[UY_BRANCH_CHUNK / 4U];
static int g_scan_lock;

static int uy_branch_target(uint32_t insn, uint64_t at, uint64_t *target)
{
    int64_t off;

    if ((insn & 0x7c000000U) == 0x14000000U) {          /* B, BL */
        off = (int64_t)(insn & 0x03ffffffU) << 2;
        if (off & 0x08000000LL) off -= 0x10000000LL;
    } else if ((insn & 0xff000010U) == 0x54000000U) {   /* B.cond */
        off = (int64_t)((insn >> 5) & 0x7ffffU) << 2;
        if (off & 0x00100000LL) off -= 0x00200000LL;
    } else if ((insn & 0x7e000000U) == 0x34000000U) {   /* CBZ, CBNZ */
        off = (int64_t)((insn >> 5) & 0x7ffffU) << 2;
        if (off & 0x00100000LL) off -= 0x00200000LL;
    } else if ((insn & 0x7e000000U) == 0x36000000U) {   /* TBZ, TBNZ */
        off = (int64_t)((insn >> 5) & 0x3fffU) << 2;
        if (off & 0x00008000LL) off -= 0x00010000LL;
    } else {
        return 0;
    }
    *target = at + (uint64_t)off;
    return 1;
}

static void uy_read_lock(void *mm)
{
    if (f_mmap_read_lock) f_mmap_read_lock(mm);
    else f_mmap_write_lock(mm);
}

static void uy_read_unlock(void *mm)
{
    if (f_mmap_read_unlock) f_mmap_read_unlock(mm);
    else f_mmap_write_unlock(mm);
}

static void uy_scan_lock(void)
{
    while (__atomic_exchange_n(&g_scan_lock, 1, __ATOMIC_ACQUIRE))
        f_msleep(1);
}

static void uy_scan_unlock(void)
{
    __atomic_store_n(&g_scan_lock, 0, __ATOMIC_RELEASE);
}

static void uy_scan_begin(void)
{
    __atomic_add_fetch(&g_code.seq, 1, __ATOMIC_ACQ_REL);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void uy_scan_end(void)
{
    __atomic_add_fetch(&g_code.seq, 1, __ATOMIC_RELEASE);
}

static void uy_code_free(void)
{
    uint8_t *arena = g_code.arena;

    memset(&g_code, 0, sizeof(g_code));
    if (arena) uy_free(arena);
}

static int uy_code_region_read(void *vma, uint64_t *start, uint64_t *end, uint64_t *flags)
{
    *start = *(uint64_t *)((char *)vma + g_layout.vma_start);
    *end = *(uint64_t *)((char *)vma + g_layout.vma_end);
    *flags = *(uint64_t *)((char *)vma + g_layout.vma_flags);
    return (*end > *start && *start < g_user_limit) ? 0 : -1;
}

static struct uy_code_region *uy_code_region_find(uint64_t addr)
{
    uint32_t i, n = __atomic_load_n(&g_code.count, __ATOMIC_ACQUIRE);

    for (i = 0; i < n; ++i) {
        struct uy_code_region *r = &g_code.region[i];

        if (addr >= r->start && addr < r->end) return r;
    }
    return 0;
}

/* The fault path finds the first region that covers an address.  A scan may
 * use its own region as a fast path only when no earlier region overlaps the
 * scanned range; otherwise mark() must follow the same first-match rule. */
static int uy_code_range_overlaps(uint64_t start, uint64_t end,
                                  const struct uy_code_region *self)
{
    uint32_t i, n = __atomic_load_n(&g_code.count, __ATOMIC_ACQUIRE);

    for (i = 0; i < n; ++i) {
        const struct uy_code_region *r = &g_code.region[i];

        if (r == self) continue;
        if (start < r->end && end > r->start) return 1;
    }
    return 0;
}

/* The scan knows its source region, so a same-VMA target is one comparison;
 * cross-VMA targets fall back to the list walk. */
static void uy_code_mark(uint64_t target, const struct uy_code_region *src)
{
    const struct uy_code_region *r = src;
    uint64_t off;

    if (!r || target < r->start || target >= r->end) r = uy_code_region_find(target);
    if (!r) return;
    off = (target - r->start) >> 2;
    /* Concurrent deferred scans may set adjacent bits in the same byte. */
    __atomic_fetch_or(&g_code.arena[r->bitmap_off + (off >> 3)],
                      (uint8_t)(1U << (off & 7U)), __ATOMIC_RELAXED);
}

static int uy_code_hit(uint64_t addr)
{
    struct uy_code_region *r = uy_code_region_find(addr);
    uint64_t off;

    if (!r) return 0;
    off = (addr - r->start) >> 2;
    return (g_code.arena[r->bitmap_off + (off >> 3)] >> (off & 7U)) & 1U;
}

/* Distinguish a page the fault hook will scan later (no leaf yet) from a
 * resident page the module cannot read (execute-only). */
static int uy_page_present(void *mm, uint64_t addr)
{
    uint64_t *ptep = pte_of(mm, page_base(addr));

    return ptep && (__atomic_load_n(ptep, __ATOMIC_ACQUIRE) & PTE_VALID) != 0;
}

/* Scan one resident page.  0 = read, 1 = not present (deferred to the fault
 * hook), -1 = present but unreadable.  The caller supplies the decode buffer:
 * the build and the mmap/mprotect after hooks are serialized, while deferred
 * fault scans on different CPUs must not share one. */
static int uy_code_scan_page_buf(void *mm, uint64_t page, const struct uy_code_region *src,
                                 uint32_t *buf, unsigned bytes)
{
    uint64_t at;
    int result = 0;

    for (at = page; at < page + g_page_size; at += bytes) {
        uint64_t left = page + g_page_size - at;
        unsigned n = (left > bytes ? bytes : (unsigned)left) >> 2;
        unsigned k;

        if (f_copy_in(buf, (const void *)(uintptr_t)at, n * 4U)) {
            if (uy_page_present(mm, at)) return -1;
            if (!result) result = 1;
            continue;
        }
        for (k = 0; k < n; ++k) {
            uint64_t target;
            if (uy_branch_target(buf[k], at + 4U * k, &target))
                uy_code_mark(target, src);
        }
    }
    return result;
}

static int uy_code_scan_page(void *mm, uint64_t page, const struct uy_code_region *src)
{
    return uy_code_scan_page_buf(mm, page, src, g_code_buf, UY_BRANCH_CHUNK);
}

static void uy_code_scan_range(void *mm, uint64_t start, uint64_t end,
                               const struct uy_code_region *src)
{
    uint64_t page;

    for (page = page_base(start); page < end; page += g_page_size) {
        int ret = uy_code_scan_page(mm, page, src);
        if (ret < 0) {
            __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
            return;
        }
    }
}

static int uy_code_collect(uint64_t *bytes)
{
    uint64_t addr = 0, total = 0;
    unsigned n = 0, iter;

    for (iter = 0; iter < 65536U; ++iter) {
        void *vma = f_find_vma(g_sess.mm, (unsigned long)addr);
        uint64_t start, end, flags;

        if (!vma) break;
        if (uy_code_region_read(vma, &start, &end, &flags) || end <= addr ||
            start >= g_user_limit)
            break;
        if (flags & UY_VM_EXEC) {
            uint64_t size = ((end - start) >> 2) / 8U + 1U;

            if (n == UY_CODE_MAX_REGIONS || total + size > UY_CODE_BITMAP_MAX)
                return -E2BIG;
            total += size;
            g_code.region[n].start = start;
            g_code.region[n].end = end;
            ++n;
        }
        addr = end;
        if (addr >= g_user_limit) break;
    }
    g_code.count = n;
    *bytes = total;
    return 0;
}

static void uy_code_build(void)
{
    uint64_t bytes = 0, off = 0, addr = 0, arena;
    unsigned i, iter, pages = 0;

    uy_code_free();
    __atomic_store_n(&g_code.complete, 1, __ATOMIC_RELEASE);
    uy_read_lock(g_sess.mm);
    if (uy_code_collect(&bytes)) goto done;
    arena = bytes + bytes / 2U + 65536U;
    if (arena > UY_CODE_ARENA_MAX) arena = UY_CODE_ARENA_MAX;
    if (arena < bytes) arena = bytes;
    g_code.arena = uy_alloc(arena);
    if (!g_code.arena) goto done;
    g_code.arena_size = arena;
    memset(g_code.arena, 0, arena);
    for (i = 0; i < g_code.count; ++i) {
        g_code.region[i].bitmap_off = off;
        off += ((g_code.region[i].end - g_code.region[i].start) >> 2) / 8U + 1U;
    }
    g_code.arena_used = off;
    for (iter = 0; iter < 65536U; ++iter) {
        void *vma = f_find_vma(g_sess.mm, (unsigned long)addr);
        uint64_t start, end, flags;

        if (!vma) break;
        if (uy_code_region_read(vma, &start, &end, &flags) || end <= addr ||
            start >= g_user_limit)
            break;
        if (flags & UY_VM_EXEC) {
            struct uy_code_region *src = uy_code_region_find(start);
            uint64_t page;

            if (src && uy_code_range_overlaps(start, end, src)) src = 0;
            for (page = page_base(start); page < end; page += g_page_size) {
                if (uy_code_scan_page(g_sess.mm, page, src) < 0) {
                    __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
                    break;
                }
                ++pages;
            }
        }
        addr = end;
        if (addr >= g_user_limit) break;
    }
    __atomic_store_n(&g_code.valid, 1, __ATOMIC_RELEASE);
done:
    if (g_verbose)
        pr_info("urov-y: codemap regions=%u pages=%u arena=%llu complete=%u\n",
                g_code.count, pages, (unsigned long long)g_code.arena_size,
                __atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE));
    uy_read_unlock(g_sess.mm);
}

/* A later mapping (mmap/mprotect/mremap) may contain a direct branch into a
 * span of the reader code.  Scan it before the syscall returns to EL0;
 * non-resident pages of the new range are left to the fault hook.  A
 * mprotect/mremap range can span several VMAs, so walk each one. */
static void uy_code_add_range(void *mm, uint64_t start, uint64_t len)
{
    uint64_t end, cur;
    void *vma;
    uint64_t vs, ve, flags;
    struct uy_code_region *src;
    uint64_t seg_end, need;

    if (!len) return;
    end = start + len;
    if (end < start || end - start > UY_CODE_SCAN_MAX) {
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
        return;
    }
    uy_scan_lock();
    if (!overlay_live() || __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE))
        goto out;
    uy_read_lock(mm);
    cur = start;
    while (cur < end) {
        vma = f_find_vma(mm, (unsigned long)cur);
        if (!vma || uy_code_region_read(vma, &vs, &ve, &flags)) break;
        if (cur < vs) cur = vs;
        if (cur >= end) break;
        seg_end = ve < end ? ve : end;
        if (seg_end <= cur) break;
        if (flags & UY_VM_EXEC) {
            src = uy_code_region_find(cur);
            if (!src || src->end < seg_end) {
                need = ((seg_end - cur) >> 2) / 8U + 1U;
                if (g_code.count == UY_CODE_MAX_REGIONS ||
                    g_code.arena_used + need > g_code.arena_size) {
                    __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
                    break;
                }
                src = &g_code.region[g_code.count];
                src->start = cur;
                src->end = seg_end;
                src->bitmap_off = g_code.arena_used;
                memset(g_code.arena + g_code.arena_used, 0, need);
                g_code.arena_used += need;
                __atomic_store_n(&g_code.count, g_code.count + 1, __ATOMIC_RELEASE);
            }
            if (src && uy_code_range_overlaps(cur, seg_end, src)) src = 0;
            uy_scan_begin();
            uy_code_scan_range(mm, cur, seg_end, src);
            uy_scan_end();
        }
        cur = seg_end;
    }
    uy_read_unlock(mm);
out:
    uy_scan_unlock();
}

/* A file-backed code page that REGISTER saw non-resident became present.  The
 * fault hook runs under the fault's mmap read lock, so the page and its VMA
 * are stable and the scan finishes before the task returns to EL0. */
static void uy_code_scan_fault_page(void *mm, uint64_t page)
{
    void *vma;
    uint64_t vs, ve, flags, file;
    struct uy_code_region *src;
    uint32_t buf[128]; /* 512 bytes: fault context, may run on several CPUs */

    vma = f_find_vma(mm, (unsigned long)page);
    if (!vma || uy_code_region_read(vma, &vs, &ve, &flags)) return;
    file = *(uint64_t *)((char *)vma + g_layout.vma_file);
    if (!(flags & UY_VM_EXEC) || !file || page < vs || page + g_page_size > ve)
        return;
    src = uy_code_region_find(page);
    if (!src) {
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
        return;
    }
    if (uy_code_range_overlaps(page, page + g_page_size, src)) src = 0;
    uy_scan_begin();
    if (uy_code_scan_page_buf(mm, page, src, buf, sizeof(buf)) < 0)
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
    uy_scan_end();
}

static int uy_llsc_skipped(uint64_t ldxr_pc, uint64_t pc)
{
    uint64_t at;
    uint32_t seq1, seq2;

    if (!__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE))
        return 1;
    seq1 = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);
    if (seq1 & 1U) return 1;
    for (at = ldxr_pc + 4U; at <= pc; at += 4U) {
        if (uy_code_hit(at)) return 1;
    }
    seq2 = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);
    /* A scan that ran while the bits were read may have marked the very slot
     * that was just tested.  Decline instead of assuming it was absent. */
    return seq1 != seq2;
}

/* An indirect branch to the load or to a gap instruction leaves that address
 * in the branch register.  At the fault the load has not executed yet, so the
 * GPR file still holds it.  A normal sequence never needs such a value.
 *
 * Authenticated branches (BRAA/BLRAA/RETAA) leave a signed pointer, and MTE
 * adds a top-byte tag; either hides the real address from a raw comparison.
 * The AArch64 PAC field and the MTE tag both live above the configured user
 * VA, so compare the raw value and the masked value.  The masked test is
 * conservative: an unrelated register whose low VA bits equal a span address
 * only makes the bridge decline. */
static int uy_llsc_indirect(const struct uro_regs *regs, uint64_t ldxr_pc, uint64_t pc)
{
    uint64_t mask = g_user_limit - 1U;
    unsigned i;

    for (i = 0; i <= 30; ++i) {
        uint64_t value = regs->x[i];

        if (value >= ldxr_pc + 4U && value <= pc) return 1;
        value &= mask;
        if (value >= ldxr_pc + 4U && value <= pc) return 1;
    }
    return 0;
}

/* Decide whether the faulting load sits in an LDXR/LDAXR; load; STXR/STLXR
 * sequence that the handler can complete.
 *
 * The ERET that resumes EL0 clears the local exclusive monitor, so the original
 * STXR would always fail.  Completing it in the handler restores the native
 * outcome, but only when the LDXR result is still in Rt (execution evidence)
 * and control reached the load sequentially.  A caller that pre-reads [Xn] can
 * forge the register value, but a direct branch into the LDXR..load span is
 * now found in every executable mapping of the process, and an indirect
 * branch that leaves that span in a GPR is rejected.  The store value must
 * still equal memory, so the bridge never changes bytes. */
static void uy_llsc_prepare(const struct uro_regs *regs, uint64_t pc,
                            const struct uro_load *load, struct uy_llsc *out)
{
    uint32_t after, ldxr_insn = 0;
    unsigned lsize = 0, lrt = 0, lrn = 0, ssize, srt, srn, srs;
    uint64_t mem = 0, mask, ldxr_pc = 0;
    unsigned gap;

    memset(out, 0, sizeof(*out));
    if (!f_copy_out || !load || load->vector || load->multi || load->count != 1U)
        return;
    if (pc < 4U || !uy_user_range(pc - 4U, 4U) || !uy_user_range(pc + 4U, 4U))
        return;
    if (uy_read_insn(pc + 4U, &after) || !uy_is_stxr(after, &ssize, &srs, &srt, &srn))
        return;
    /* The LDXR may be separated from the load by a few NOPs. */
    for (gap = 0; gap < 4U; ++gap) {
        uint64_t at = pc - 4U - 4U * gap;
        uint32_t insn;

        if (at < 4U || uy_read_insn(at, &insn)) break;
        if (uy_is_ldxr(insn, &lsize, &lrt, &lrn)) {
            ldxr_pc = at;
            ldxr_insn = insn;
            break;
        }
        if (insn != UY_NOP) break;
    }
    if (!ldxr_pc) return;
    if (uy_llsc_skipped(ldxr_pc, pc)) return;
    if (uy_llsc_indirect(regs, ldxr_pc, pc)) return;
    if (lsize != ssize || lrn != srn) return;
    if (lrn == 31U || srn == 31U) return;
    /* XZR is a valid exclusive-data register on both sides.  A sequence that
     * uses XZR on only one side is not reproducible: the load result and the
     * stored value would have to come from different places. */
    if ((lrt == 31U) != (srt == 31U)) return;
    /* The intervening load must not rewrite the value the STXR stores or the
     * base it addresses; a pre/post-index form that writes Xn is equally
     * unreproducible.  A load that discards into XZR changes no register. */
    if ((lrt != 31U && load->rt == lrt) || load->rt == lrn ||
        (load->count == 2U && ((lrt != 31U && load->rt2 == lrt) || load->rt2 == lrn)))
        return;
    if (load->writeback && load->rn == lrn) return;
    if (regs->x[lrn] & ((UINT64_C(1) << lsize) - 1U)) return;
    if (f_copy_in(&mem, (const void *)(uintptr_t)regs->x[lrn], 1U << lsize))
        return;
    mask = lsize == 3U ? ~UINT64_C(0) : ((UINT64_C(1) << (8U << lsize)) - 1U);
    if (lrt == 31U) {
        /* LDXR XZR;...;STXR XZR discards the loaded word and stores zero.
         * Only complete it when the destination already holds zero, so the
         * emulated store is a no-op and a missed skip path cannot change a
         * byte.  Detector scratch is zero-initialised. */
        if (mem != 0) return;
    } else if (regs->x[lrt] != (mem & mask)) {
        /* LDXR Wt/Bt/Ht zero-extend into Xt, so the full register must match
         * the zero-extended memory value.  This also rejects a caller that
         * pre-fills the high half of Xt to imitate an executed LDXR. */
        return;
    }

    out->base = regs->x[lrn];
    out->value = lrt == 31U ? 0 : regs->x[lrt];
    out->size = 1U << lsize;
    out->data_reg = lrt;
    out->base_reg = lrn;
    out->status_reg = srs;
    out->acquire = (ldxr_insn & (1U << 15)) != 0;
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
    if (plan->acquire) __asm__ volatile("dmb ishld" : : : "memory");
    if (plan->release) __asm__ volatile("dmb ishst" : : : "memory");
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
    int ap_read;
    uint32_t opcode;
    uint64_t ref;

    (void)udata;
    if (!regs || !user_mode(regs) || compat_user_mode(regs) ||
        (ec != UY_EC_IABT_LOW && ec != UY_EC_DABT_LOW) ||
        (esr & (UY_FSC_MASK | UY_ESR_FNV | UY_ESR_S1PTW | UY_ESR_EA)) != UY_FSC_PERM_LEAF ||
        (g_abort_has_iss2 && (esr & UY_ESR_ISS2)) ||
        !uy_user_range(far, 1))
        return;
    ap_read = ec == UY_EC_DABT_LOW && !(esr & (UY_ESR_WNR | UY_ESR_CM));
    ref = session_get();
    if (!ref) {
        void *reader = mm_of_task(current);

        /* A forked child inherits a copy of the trapped leaf PTE but not the
         * session mm.  While the session lives that copy is served from the
         * same immutable image, so a child that reads the code page sees the
         * registered view instead of the live bytes.  Once the session is
         * gone the orphaned trap is turned back into an ordinary readable
         * PTE and the instruction retries, so no reader can take a signal
         * because of a trap left behind. */
        if (!ap_read || !uy_trap_leaf(reader, far)) return;
        /* Take the reader reference before touching the page array: release
         * frees it only after both reader epochs are drained. */
        ref = session_get_any();
        if (ref) {
            if (g_sess.mode == UROV_Y_MODE_PAGE_AP && page_find(page_base(far)))
                goto serve;
            uy_reader_exit(&g_readers, ref);
        }
        if (g_retired_mode == UROV_Y_MODE_PAGE_AP && uy_retired_has(page_base(far)) &&
            uy_repair_trap(reader, far)) {
            args->ret = 0;
            args->skip_origin = 1;
        }
        return;
    }

serve:
    if (g_sess.mode == UROV_Y_MODE_PAGE_AP && ap_read) {
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
     * pointer. Capture its mm and the mapping identity while the caller's
     * protection still holds. */
    args->local.data0 = vma && overlay_live() ?
        (uintptr_t)__atomic_load_n((void *const *)(vma + g_layout.vma_mm), __ATOMIC_RELAXED) : 0;
    args->local.data1 = args->arg1;
    args->local.data2 = args->arg2; /* FAULT_FLAG_* for the deferred code scan */
    args->local.data3 = vma ? (uintptr_t)*(void **)(vma + g_layout.vma_file) : 0;
    args->local.data4 = vma && g_layout.vma_pgoff_ok ?
        *(unsigned long *)(vma + g_layout.vma_pgoff) : 0;
    args->local.data5 = vma ? *(unsigned long *)(vma + g_layout.vma_start) : 0;
    args->local.data6 = vma ? *(unsigned long *)(vma + g_layout.vma_end) : 0;
}

/* A fault-in just (re)created the site page PTE from the VMA protection, which
 * is executable. Re-apply the execute-never bit so a page that was evicted or
 * dropped does not silently lose its trap. Covers the user fault path and
 * get_user_pages based readers such as /proc/self/mem.
 *
 * The same hook re-arms a forked child's copy of a registered PAGE_AP page:
 * the child is a distinct mm, so it is recognised by the mapping identity
 * captured in the before hook rather than by session_get_mm().
 *
 * A file-backed code page that REGISTER saw non-resident was not in the
 * branch map.  The first fault that makes it present scans it here, before
 * the faulting task can return to EL0 and execute a branch from it. */
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
    if (!ref) {
        if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) && overlay_live() &&
            g_sess.mode == UROV_Y_MODE_PAGE_AP)
            ret = ap_shadow_rearm(mm, page, args->local.data3, args->local.data4,
                                  args->local.data5, args->local.data6);
        if (ret > 0)
            flush_tlb_all();
        else if (ret < 0 && ret != -ENOENT)
            __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
        return;
    }
    if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        if (g_sess.mode == UROV_Y_MODE_PAGE_AP) {
            struct uy_page *p = page_find(page);
            if (p && __atomic_load_n(&p->armed, __ATOMIC_ACQUIRE))
                ret = page_set_ap(mm, page, 0);
            else if (!p && !(args->local.data2 & UY_FAULT_WRITE) &&
                     __atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE))
                uy_code_scan_fault_page(mm, page);
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
    unsigned i, n = g_sess.page_count;

    uy_code_free();
    /* Remember the page bases (not the images) so an orphaned trap in a
     * forked child can still be recognised and restored after the session is
     * gone.  The array is only ever compared by address. */
    g_retired_count = n < UY_RETIRED_MAX ? n : UY_RETIRED_MAX;
    if (g_retired_count && g_sess.pages)
        for (i = 0; i < g_retired_count; ++i) g_retired[i] = g_sess.pages[i].base;
    g_retired_mode = g_sess.mode;
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

/* The page image is always copied from the caller's SRC_USER buffer.  The
 * old SRC_FILE path (kernel_read(vm_file, ...)) was removed in 2.8.0; the
 * caller now provides the clean page explicitly. */
static int valid_window(unsigned off, unsigned len)
{
    return len >= 8U && !(len & 7U) && len <= g_page_size && off <= g_page_size - len;
}

static long validate_page_desc(const struct uy_page_desc *d)
{
    unsigned len = d->fake_len ? d->fake_len : g_page_size;

    if (d->reserved || page_base(d->base) != d->base || !uy_user_range(d->base, g_page_size))
        return -EINVAL;
    /* SRC_FILE was the only source that borrowed vm_file.  It is gone in
     * 2.8.0: the caller supplies the clean page through SRC_USER. */
    if (d->flags == UROV_Y_PAGE_SRC_FILE)
        return -EINVAL;
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
    /* PAGE_AP promises that no reader observes the live bytes.  That is only
     * true when both kernel-assisted read paths are covered: the
     * __access_remote_vm hook (/proc/<pid>/mem, ptrace, access_process_vm)
     * and the per-pid mm resolution used by process_vm_readv.  Fail closed
     * instead of silently leaving a readable path. */
    if (mode == UROV_Y_MODE_PAGE_AP && (!g_kread_hooked || !f_find_task_by_vpid)) {
        if (g_verbose)
            pr_info("urov-y: PAGE_AP needs kread=%d find_task=%d\n",
                    g_kread_hooked, f_find_task_by_vpid ? 1 : 0);
        return -EOPNOTSUPP;
    }
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
    g_sess.tgid = uy_task_tgid();
    __atomic_store_n(&g_owner, mm, __ATOMIC_RELEASE);
    g_retired_count = 0;
    g_retired_mode = 0;

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
        {
            void *vma = f_find_vma(mm, p->base);

            ret = validate_target_vma(vma, p->base);
            if (!ret) uy_capture_vma(p, vma);
        }
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
        /* Resolve the whole process's direct-branch targets before the first
         * AP page is armed, so the read path only tests bitmap bits. */
        uy_code_build();
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
    if (p->flags != UROV_Y_PAGE_SRC_USER) return -EOPNOTSUPP;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;

    if (!valid_window(off, len)) return -EINVAL;
    memcpy(p->spare, p->snapshot, g_page_size);
    ret = copy_user_image(g_sess.mm, q->fake_addr, p->spare + off, len);
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

/* ----------------------------------------------- process_vm_readv overlay */

/* process_vm_readv copies the target mm's pages through GUP and never takes
 * the EL0 data abort that serves the overlay, so a same-process reader would
 * otherwise see the live bytes while an EL0 load sees the image.  The syscall
 * table entry is already part of the module's control-plane hook set; its
 * after hook rewrites only the bytes that overlap a registered page.  The
 * caller's buffer was filled by the kernel a moment earlier, so the copy is
 * bounded by the syscall's own return value and by the iovec array it
 * validated.
 *
 * The walk covers every iovec count Linux accepts (UIO_MAXIOV = 1024).  A
 * fixed-size array cannot grow to that bound on the KPM stack, so one entry
 * at a time is copied and only the entries that carry bytes are touched.
 * The target pid is resolved to a task and accepted when that task shares
 * the session mm: the caller's own tid/tgid and a CLONE_VM sibling are the
 * same address space, while a truly foreign mm keeps the bytes GUP
 * produced.  No ABI field, status bit or counter is added. */
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

#define UY_VM_IOV_MAX 1024U
#define UY_VM_CHUNK 256U

struct uy_iovec {
    uint64_t base;
    uint64_t len;
};

/* One local/remote segment of a same-mm read.  Only the registered segments
 * are rewritten; everything else keeps the bytes the kernel copied.  A forked
 * child is a distinct mm, so its copy is only rewritten while the leaf PTE at
 * that page still carries this module's trap. */
static void uy_vm_overlay(uint64_t local, uint64_t remote, uint64_t len, int allow_fake,
                          void *mm, int owner)
{
    uint8_t bytes[UY_VM_CHUNK];

    while (len) {
        struct uy_page *p;
        uint64_t page = page_base(remote);
        unsigned off = (unsigned)(remote - page);
        unsigned seg = g_page_size - off;

        if ((uint64_t)seg > len) seg = (unsigned)len;
        if (seg > sizeof(bytes)) seg = (unsigned)sizeof(bytes);
        p = page_find(page);
        if (p && (owner || uy_trap_leaf(mm, page))) {
            page_view(p, off, seg, bytes, !allow_fake);
            if (f_copy_out((void *)(uintptr_t)local, bytes, seg)) return;
        }
        local += seg;
        remote += seg;
        len -= seg;
    }
}

static int uy_iov_load(uint64_t vec, uint64_t index, struct uy_iovec *out)
{
    uint64_t at = vec + index * sizeof(*out);

    return f_copy_in(out, (const void *)(uintptr_t)at, sizeof(*out));
}

static void uy_vm_readv_after(hook_fargs6_t *args, void *udata)
{
    struct uy_iovec l, r;
    struct pt_regs *regs;
    uint64_t pid, lvec, liovcnt, rvec, riovcnt, ref, left;
    uint64_t li = 0, ri = 0, loff = 0, roff = 0;
    void *mm, *task;
    int allow, have_l = 0, have_r = 0, owner;

    (void)udata;
    if ((long)args->ret <= 0 || !f_copy_out) return;
    /* The remote address space decides, not the caller's: another process (or
     * another thread group) reading the owner through process_vm_readv must
     * see the same image as the owner's own loads. */
    pid = sys_arg(args, 0);
    if (pid == uy_task_pid() || pid == uy_task_tgid()) {
        mm = mm_of_task(current);
    } else {
        if (!f_find_task_by_vpid || !f_rcu_lock) return;
        f_rcu_lock();
        task = f_find_task_by_vpid((int)pid);
        mm = task ? mm_of_task(task) : 0;
        f_rcu_unlock();
    }
    if (!mm || mm != __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE)) {
        /* A forked child keeps a copy of the trap but not the session mm; its
         * kernel-assisted reads are served per page while that copy exists. */
        if (!mm || !overlay_live() || g_sess.mode != UROV_Y_MODE_PAGE_AP) return;
    }
    lvec = sys_arg(args, 1);
    liovcnt = sys_arg(args, 2);
    rvec = sys_arg(args, 3);
    riovcnt = sys_arg(args, 4);
    if (!liovcnt || !riovcnt || liovcnt > UY_VM_IOV_MAX || riovcnt > UY_VM_IOV_MAX)
        return;
    if (!uy_user_range(lvec, liovcnt * sizeof(struct uy_iovec)) ||
        !uy_user_range(rvec, riovcnt * sizeof(struct uy_iovec)))
        return;

    owner = mm == g_sess.mm;
    ref = owner ? session_get_mm(mm) : session_get_any();
    if (!ref) return;
    regs = g_wrapper_mode ? (struct pt_regs *)args->arg0 : 0;
    /* The caller window only exists for the owner's own threads; a foreign
     * reader gets the snapshot unless the session overlays every caller. */
    allow = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
            (g_sess.caller_count == 0U ||
             (owner && regs && caller_allowed_deep(regs)));
    left = (uint64_t)(long)args->ret;
    while (left && li < liovcnt && ri < riovcnt) {
        uint64_t lrem, rrem, seg;

        if (!have_l) {
            if (uy_iov_load(lvec, li, &l)) goto out;
            have_l = 1;
        }
        if (!have_r) {
            if (uy_iov_load(rvec, ri, &r)) goto out;
            have_r = 1;
        }
        lrem = l.len - loff;
        rrem = r.len - roff;
        seg = lrem < rrem ? lrem : rrem;
        if (!seg) {
            if (!lrem) { ++li; loff = 0; have_l = 0; }
            if (!rrem) { ++ri; roff = 0; have_r = 0; }
            continue;
        }
        if (seg > left) seg = left;
        uy_vm_overlay(l.base + loff, r.base + roff, seg, allow, mm, owner);
        loff += seg;
        roff += seg;
        left -= seg;
    }
out:
    uy_reader_exit(&g_readers, ref);
}

/* --------------------------------------------- kernel-assisted read overlay */

/* /proc/<pid>/mem, ptrace(PTRACE_PEEKDATA) and every other access_remote_vm()
 * caller copy through GUP, never through the EL0 data abort.  A single after
 * hook on the implementation entry rewrites the kernel buffer the caller is
 * about to hand back, so those readers see the registered image too.  The
 * function is already resolved for the control plane; the hook adds no
 * syscall entry, ABI field or counter. */
static void uy_kread_overlay(uint64_t remote, void *buf, uint64_t len, int allow_fake,
                             void *mm, int owner)
{
    uint8_t *out = buf;

    while (len) {
        uint64_t page = page_base(remote);
        unsigned off = (unsigned)(remote - page);
        unsigned seg = g_page_size - off;
        struct uy_page *p;

        if ((uint64_t)seg > len) seg = (unsigned)len;
        p = page_find(page);
        if (p && (owner || uy_trap_leaf(mm, page))) page_view(p, off, seg, out, !allow_fake);
        remote += seg;
        out += seg;
        len -= seg;
    }
}

static void uy_kread_after(hook_fargs6_t *args, void *udata)
{
    void *mm;
    void *buf;
    uint64_t remote, len, ref;
    unsigned long flags;
    int allow, owner;

    (void)udata;
    if ((long)args->ret <= 0) return;
    /* The module's own snapshots, site words and control replies must never be
     * rewritten by this hook. */
    if (__atomic_load_n(&g_internal_access, __ATOMIC_ACQUIRE) == current) return;
    if (g_kread_argc == 6) {
        mm = (void *)args->arg1;
        remote = args->arg2;
        buf = (void *)args->arg3;
        flags = (unsigned long)args->arg5;
    } else {
        mm = (void *)args->arg0;
        remote = args->arg1;
        buf = (void *)args->arg2;
        flags = (unsigned long)args->arg4;
    }
    if (!mm || !buf || (flags & 0x1U) /* FOLL_WRITE */) return;
    len = (uint64_t)(long)args->ret;
    if (!len || !uy_user_range(remote, len)) return;
    owner = mm == __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE);
    if (!owner && (!overlay_live() || g_sess.mode != UROV_Y_MODE_PAGE_AP)) return;
    ref = owner ? session_get_mm(mm) : session_get_any();
    if (!ref) return;
    /* A forked child gets the snapshot (a foreign mm has no caller window the
     * owner could vouch for); an owner-side reader keeps the normal rule. */
    allow = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
            g_sess.caller_count == 0U;
    uy_kread_overlay(remote, buf, len, allow, mm, owner);
    uy_reader_exit(&g_readers, ref);
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

/* End the session before a fork or vfork can copy a patched instruction or an
 * execute-never page.  A thread that merely shares the mm keeps the session.
 *
 * PAGE_AP leaves no byte, no VMA flag and no execute permission changed, so a
 * forked child only inherits a copy of the trapped leaf PTE.  That copy is
 * served by the abort hook (see uy_abort_before) while the session lives, so
 * fork()/vfork() no longer end the overlay. */
static void uy_clone_before(hook_fargs6_t *args, void *udata)
{
    uint64_t flags;
    int ret = 0;

    if (!caller_is_owner()) return;
    if (overlay_live() && g_sess.mode == UROV_Y_MODE_PAGE_AP) return;
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

#define UY_PROT_READ 0x1U
#define UY_PROT_WRITE 0x2U
#define UY_PROT_EXEC 0x4U

/* Linux's madvise() accepts a bounded set of advice values and rejects the
 * rest before touching the VMA.  2.11.0 ran its range gate first, so
 * madvise(page, len, -1) ended the whole session and only then let Linux
 * return EINVAL.  An invalid advice must pass through untouched. */
static int uy_advice_valid(uint64_t advice)
{
    if (advice <= 25U) return 1;              /* MADV_NORMAL .. MADV_COLLAPSE */
    return advice == 100U || advice == 101U;  /* MADV_HWPOISON, SOFT_OFFLINE */
}

/* A protection change that keeps the page readable and executable cannot be
 * used to read the live bytes, so PAGE_AP stays armed and the after hook
 * re-applies the trap on the changed PTEs. */
static int uy_prot_keeps_rx(uint64_t prot)
{
    return (prot & (UY_PROT_READ | UY_PROT_EXEC)) == (UY_PROT_READ | UY_PROT_EXEC) &&
           !(prot & UY_PROT_WRITE);
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
    if (kind == UY_GATE_MADVISE) {
        /* The advice itself never changes page permissions.  With PAGE_AP a
         * zapped PTE is re-armed by the fault path, so the session survives;
         * BRK/UXN have no per-page rearm and keep the old teardown. */
        if (!uy_advice_valid(sys_arg(args, 2))) return;
        if (overlay_live() && g_sess.mode == UROV_Y_MODE_PAGE_AP) return;
    }
    if ((kind == UY_GATE_MPROTECT || kind == UY_GATE_PKEY_MPROTECT) &&
        uy_prot_keeps_rx(sys_arg(args, 2)) && overlay_live() &&
        g_sess.mode == UROV_Y_MODE_PAGE_AP)
        return;
    if (!ctrl_try_lock()) {
        gate_error(args, -EBUSY);
        return;
    }
    if (session_owned()) {
        int release;

        if (kind == UY_GATE_EXECVE || kind == UY_GATE_EXECVEAT) {
            /* A vfork child shares the owner's mm but execs into a new one;
             * the parent keeps the armed mapping.  Only the owner thread
             * group's own exec replaces the address space of the session. */
            release = uy_task_tgid() == g_sess.tgid;
        } else {
            release = gate_range_overlaps(sys_arg(args, 0), sys_arg(args, 1)) ||
                      (kind == UY_GATE_MREMAP && (sys_arg(args, 3) & UY_MREMAP_FIXED) &&
                       gate_range_overlaps(sys_arg(args, 4), sys_arg(args, 2)));
        }
        if (release) ret = release_session(1);
    }
    ctrl_unlock();
    if (ret) gate_error(args, ret);
}

/* An executable mapping created or made executable after REGISTER was not in
 * the branch map.  Scan the new range before the caller can return to EL0 and
 * branch from it.  A syscall the before hook refused (negative return) has no
 * new mapping.
 *
 * The same after hook re-applies the PAGE_AP trap on a protection change that
 * kept the page readable and executable: Linux rewrites the leaf PTEs from the
 * VMA protection, which restores AP[1]. */
static void uy_gate_after(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;
    long ret = (long)args->ret;
    uint64_t start, len;

    if (ret < 0 || !session_owned()) return;
    if ((kind == UY_GATE_MPROTECT || kind == UY_GATE_PKEY_MPROTECT) &&
        g_sess.mode == UROV_Y_MODE_PAGE_AP && uy_prot_keeps_rx(sys_arg(args, 2)))
        ap_rearm_range(g_sess.mm, sys_arg(args, 0), sys_arg(args, 1));
    if (!__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE)) return;
    switch (kind) {
    case UY_GATE_MMAP:
        if (!(sys_arg(args, 2) & 0x4U)) return; /* PROT_EXEC */
        start = (uint64_t)ret;
        len = sys_arg(args, 1);
        break;
    case UY_GATE_MPROTECT:
    case UY_GATE_PKEY_MPROTECT:
        if (!(sys_arg(args, 2) & 0x4U)) return;
        start = sys_arg(args, 0);
        len = sys_arg(args, 1);
        break;
    case UY_GATE_MREMAP:
        start = (uint64_t)ret;
        len = sys_arg(args, 2);
        break;
    default:
        return;
    }
    if (!start || !len || start >= g_user_limit) return;
    uy_code_add_range(g_sess.mm, start, len);
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
    /* Optional: resolve a pid that names another thread in the same mm.
     * find_task_by_vpid(pid_t) is a stable built-in entry; BTF may encode
     * pid_t as a typedef, so the raw symbol is used after a kallsyms hit.
     * A missing symbol keeps the old pid/tgid-only gate. */
    f_find_task_by_vpid = (find_task_by_vpid_t)lookup("find_task_by_vpid");
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
    f_mmap_read_lock = (mmap_write_fn)lookup("mmap_read_lock");
    f_mmap_read_unlock = (mmap_write_fn)lookup("mmap_read_unlock");
    if (!f_mmap_read_lock || !f_mmap_read_unlock ||
        !uy_symbol_abi(btf, "mmap_read_lock", "vm") ||
        !uy_symbol_abi(btf, "mmap_read_unlock", "vm")) {
        f_mmap_read_lock = 0;
        f_mmap_read_unlock = 0;
    }
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

    /* Hook the implementation entry so /proc/<pid>/mem and
     * access_process_vm() (ptrace) are covered together; the public wrapper is
     * only a fallback when the implementation symbol is unavailable. */
    f_kread = 0;
    g_kread_argc = 0;
    {
        void *impl = lookup("__access_remote_vm");
        int impl_argc = impl ? uy_access_vm_argc(btf, "__access_remote_vm", 0) : 0;

        if (impl_argc) {
            f_kread = impl;
            g_kread_argc = impl_argc;
        } else if (f_access_vm) {
            f_kread = (void *)f_access_vm;
            g_kread_argc = 5;
        } else if (f_access_vm_task) {
            f_kread = (void *)f_access_vm_task;
            g_kread_argc = 6;
        }
    }

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
                "access=%s/%d read=%s write=%s find_task=%s fpsimd=%s foll_force=0x%x "
                "page_shift=%u\n",
                kver, vma_name, g_use_rwsem ? "rwsem" : "mmap",
                *mmf_argc ? fault_name : "none", *mmf_argc,
                *brk_argc ? brk_name : "none", *brk_argc, access_name, access_argc,
                read_name, f_copy_out ? write_name : "control-gup",
                f_find_task_by_vpid ? "task" : "none",
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

    /* Same-mm kernel-assisted reads must observe the same view as EL0 loads.
     * This is an after hook on the existing syscall-table control plane; it
     * adds no control ABI, status bit or counter. */
    ret = fp_hook_syscalln(__NR_process_vm_readv, 6, 0, uy_vm_readv_after, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-y: hook process_vm_readv failed: %ld\n", ret);
        goto unwind_prctl;
    }
    g_vm_readv_hooked = 1;

    /* Kernel-assisted reads: one function hook covers /proc/<pid>/mem,
     * ptrace and every other access_remote_vm() caller. */
    if (f_kread) {
        ret = hook_wrap(f_kread, g_kread_argc, 0, uy_kread_after, 0);
        g_kread_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-y: hook kernel read failed: %ld\n", ret);
    } else if (g_verbose) {
        pr_info("urov-y: no access_remote_vm symbol; kernel reads stay uncovered\n");
    }

    for (i = 0; i < UY_GATE_NUM; ++i) {
        ret = fp_hook_syscalln(g_gate_nrs[i], 6, uy_gate_before, uy_gate_after,
                               (void *)(uintptr_t)i);
        if (ret) {
            if (g_verbose) pr_info("urov-y: hook gate %d failed: %ld\n", g_gate_nrs[i], ret);
            break;
        }
        g_gate_hooked[i] = 1;
    }
    if (i != UY_GATE_NUM) {
        while (i-- > 0) {
            fp_unhook_syscalln(g_gate_nrs[i], uy_gate_before, uy_gate_after);
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
    }
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);

    if (g_verbose)
        pr_info("urov-y: backend ready brk_imm=%x trap=%x page_mode=%d kread=%d/%d\n",
                (unsigned)g_imm, (unsigned)g_trap_insn, g_page_hooked && g_mmf_hooked,
                g_kread_hooked, g_kread_argc);
    return 0;

unwind_prctl:
    if (g_kread_hooked) {
        hook_unwrap(f_kread, 0, uy_kread_after);
        g_kread_hooked = 0;
    }
    if (g_vm_readv_hooked) {
        fp_unhook_syscalln(__NR_process_vm_readv, 0, uy_vm_readv_after);
        g_vm_readv_hooked = 0;
    }
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
        fp_unhook_syscalln(g_gate_nrs[i], uy_gate_before, uy_gate_after);
        g_gate_hooked[i] = 0;
    }
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, uy_prctl_before, 0);
        g_prctl_hooked = 0;
    }
    if (g_vm_readv_hooked) {
        fp_unhook_syscalln(__NR_process_vm_readv, 0, uy_vm_readv_after);
        g_vm_readv_hooked = 0;
    }
    if (g_kread_hooked) {
        hook_unwrap(f_kread, 0, uy_kread_after);
        g_kread_hooked = 0;
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
                 (g_page_hooked ? 32U : 0U) | (g_mmf_hooked ? 64U : 0U) |
                 (g_kread_hooked ? 128U : 0U);
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
