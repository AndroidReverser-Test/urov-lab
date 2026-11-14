/* SPDX-License-Identifier: GPL-2.0-or-later */
/* UROV-Z PAGE_AP / all-callers backend, derived from UROV-Y 2.28.0. */
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
#include "abi.h"
#include "backend.h"
#include "compat.h"
#include "runtime_compat.h"
#include "readers.h"
#include "page_index.h"
#include "short_lock.h"
#include "buffer_budget.h"
#include "window.h"
#include "prewin.h"
#include "insn_scan.h"
#include "kclf/embedded.h"

/* Per-load performance counters compile out in the normal build. Health
 * events remain available. Both are lifetime totals, including past sessions. */
#ifndef UROV_Z_DIAGNOSTICS
#define UROV_Z_DIAGNOSTICS 0
#endif
static struct uz_perf g_perf;
static struct uz_health g_health;
static struct uz_compat_info g_compat;
#define UZ_HEALTH_ADD(field) __atomic_fetch_add(&g_health.field, 1, __ATOMIC_RELAXED)
#if UROV_Z_DIAGNOSTICS
#define UZ_PERF_ADD(field, n) __atomic_fetch_add(&g_perf.field, (uint64_t)(n), __ATOMIC_RELAXED)
#else
#define UZ_PERF_ADD(field, n) ((void)(n))
#endif

/* Ordinary RX reads need no scheduler/debug replay hook. Retirement of
 * scheduler trampolines is not safe on the stock test host. */
#ifndef UROV_Z_NATIVE_STEP
#define UROV_Z_NATIVE_STEP 0
#endif

#ifndef __NR_mmap
#define __NR_mmap 222
#endif

static inline void uz_flush_icache_all(void)
{
    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("ic ialluis");
    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("isb" : : : "memory");
}

#define UZ_VM_SHARED 0x00000008UL
#define UZ_VM_READ 0x00000001UL
#define UZ_VM_WRITE 0x00000002UL
#define UZ_VM_EXEC 0x00000004UL
#define UZ_VM_MAYWRITE 0x00000020UL
#define UZ_VM_PFNMAP 0x00000400UL
/* VM_LOCKED is 0x2000 and VM_IO is 0x4000 in every supported kernel (4.x-6.x).
 * 2.11.0 and earlier defined UZ_VM_IO as 0x2000, i.e. they rejected VM_LOCKED:
 * an app could call mlock() on its own RX page and make REGISTER fail with
 * EINVAL.  Locking only pins a page against reclaim and does not change the
 * leaf PTE, so 2.12.0 accepts VM_LOCKED and rejects only the real VM_IO. */
#define UZ_VM_LOCKED 0x00002000UL
#define UZ_VM_IO 0x00004000UL
#define UZ_VM_HUGETLB 0x00400000UL
#define UZ_VM_MIXEDMAP 0x10000000UL

#define UZ_SIGSEGV 11
#define UZ_SEGV_ACCERR 2

/* Only level-3 permission faults can come from our leaf PTE edits. */
#define UZ_EC_IABT_LOW 0x20UL
/* EL0 data abort taken to EL1: EC 0x24.  ESR.WnR distinguishes a read from a
 * write; only read permission faults are ours. */
#define UZ_EC_DABT_LOW 0x24UL
#define UZ_ESR_WNR (1UL << 6)
#define UZ_ESR_S1PTW (1UL << 7)
#define UZ_ESR_CM (1UL << 8)
#define UZ_ESR_EA (1UL << 9)
#define UZ_ESR_FNV (1UL << 10)
#define UZ_ESR_ISS2 (UINT64_C(0xffffff) << 32)
#define UZ_FSC_MASK 0x3fUL
#define UZ_FSC_PERM_LEAF 0x0fUL

/* A64 control instructions that a trap page may legitimately execute. */
#define UZ_RET_X30 0xd65f03c0U
#define UZ_NOP 0xd503201fU
#define UZ_BTI_C 0xd503245fU
#define UZ_BTI_J 0xd503249fU
#define UZ_BTI_JC 0xd50324dfU

#define UZ_FOLL_WRITE 0x01U
/* enum in mm.h: LONGTERM and PIN are the two callers that require the exact
 * pinned user page, so the GUP overlay leaves them alone. */

/* Linux user protection bits (uapi/asm-generic/mman-common.h). Execute-only
 * mappings are kernel/CPU dependent; never infer VM_READ from VM_EXEC. */
#define UZ_PROT_READ 0x1U
#define UZ_PROT_WRITE 0x2U
#define UZ_PROT_EXEC 0x4U

#define UZ_FAULT_WRITE 0x01U
/* VM_FAULT_ERROR | VM_FAULT_RETRY | VM_FAULT_COMPLETED. A fault that returns
 * any of these bits may not have installed a PTE or may have dropped its lock. */
#define UZ_FAULT_INCOMPLETE 0x4c73U

#define UZ_STATE_OFF 0
#define UZ_STATE_LIVE 1

_Static_assert(UROV_Z_FAKE_MAX == URO_FAKE_MAX, "UAPI and core fake widths");
_Static_assert(UROV_Z_FAKE_PAGE == UROV_Z_PAGE, "overlay is at most one page");

/* struct uz_fpstate is the shared FPSIMD image defined by window.h.
 * Its BTF layout is validated at load time before any vector load is served. */
_Static_assert(sizeof(struct uz_fpstate) == UZ_FPSIMD_BYTES, "FPSIMD image size");

/* AArch64 load/store-exclusive encodings (ARM ARM C6.2).  The access size is
 * [31:30]; [29:21] and [15:10] are fixed, while Rs/Rn/Rt are variable.  STXR
 * carries the status register in Rs, so its match mask excludes [20:16]. */
#define UZ_EXCL_LD_MASK 0x3ffffc00U
#define UZ_EXCL_LDXR 0x085f7c00U
#define UZ_EXCL_LDAXR 0x085ffc00U
#define UZ_EXCL_ST_MASK 0x3fe0fc00U
#define UZ_EXCL_STXR 0x08007c00U
#define UZ_EXCL_STLXR 0x0800fc00U

/* One LDXR;load;<window>;STXR sequence that the PAGE_AP handler may complete
 * itself.  The skeleton is built from the registers as they were at the fault,
 * before the load is emulated; the window is then modeled on the post-load
 * register file and committed only when the modeled STXR outcome is the one the
 * hardware would have produced without the trap.
 *
 * 2.20.0 models the whole window instead of a fixed data-processing whitelist:
 * every instruction whose architectural effect is reproducible here is executed
 * against a private register copy, with plain loads read through the same
 * image/snapshot view and plain stores recorded for the commit.  A window that
 * contains an instruction this code cannot reproduce, a control-flow transfer
 * out of the window, a store to the monitored word, CLREX or a second exclusive
 * makes the plan decline, and the native instructions then run unchanged: the
 * hardware reports its own result, which for those shapes is the same failure it
 * reports without the module. */
#define UZ_LLSC_WIN_MAX 64U      /* instructions executed after the sampled load */
/* Straight-line block bound for the linear read-before proof.  2.26.0 raises
 * it from 4096 (16 KiB) to 16384 (64 KiB): the bound is a kernel-work guard,
 * not a property of the architecture, and an App that pads a longer run of
 * register-only instructions in front of its sampled load must not be able to
 * turn the bound itself into an observable failure. */
#define UZ_LLSC_PRE_SCAN 16384U
/* 2.28.0: after the LDXR has been located, walk its immediate predecessors
 * (fall-through order) and stop at the first control-flow instruction.  An
 * indirect branch whose recovered target lands in (ldxr_pc, fault_pc] proves
 * that the sampled load was entered past the exclusive load, so the plan must
 * decline instead of reporting a reservation the hardware never had.
 *
 * The 2.27.0 bound of 64 instructions was itself observable: 64 NOPs between
 * the branch and the LDXR pushed the branch out of the walk, the walk then
 * accepted the dead LDXR, and the bridge reported a success the hardware
 * never produced.  2.28.0 walks to the nearest control-flow instruction or
 * the start of the containing executable VMA, whichever comes first, and
 * declines if the work bound is reached without finding one.  The bound is a
 * kernel-work guard, not a proof of the whole function; the cross-function
 * indirect entry that remains outside any linear walk is documented in
 * docs/DESIGN.md. */
#define UZ_LLSC_ENTRY_SCAN UZ_LLSC_PRE_SCAN
#define UZ_LLSC_MEM_MAX 4U       /* gap stores recorded and replayed at commit */
#define UZ_LLSC_BYTES_MAX 64U    /* widest single access the decoder produces */

/* A negative proof is reusable only if ALL words it inspected still match.
 * Existing hooks do not provide a complete native-code epoch (ptrace, shared
 * aliases and external writers are examples), so do not trust a PC/opcode or
 * image generation alone. This bounded owner-only memo validates whole pages
 * on each hit, including an unreadable boundary when that ended the scan.
 * It stores no page/VMA pointers and no register-dependent positive plans.
 * Eight non-waiting leases allow concurrent readers; busy/allocation failure
 * falls back to the block walker. Storage is allocated before readers open,
 * and freed only after they drain. Total extra storage is about 1 MiB. */
#define UZ_LLSC_MEMO_SLOTS 8U
struct uz_insn_memo {
    uint32_t busy, words;
    void *mm;
    uint64_t pc, guard;
    uint32_t saved[UZ_LLSC_PRE_SCAN];
    uint32_t probe[UZ_LLSC_PRE_SCAN];
};
static struct uz_insn_memo *g_insn_memo;

struct uz_llsc_pstore {
    uint64_t address;
    unsigned len;
    uint8_t bytes[UZ_LLSC_BYTES_MAX];
};

struct uz_llsc {
    uint64_t base;
    uint64_t value;
    uint64_t value2;     /* second half of LDXP/STXP */
    uint64_t stxr_pc;
    unsigned size;       /* bytes per register half (LDXP uses 4 or 8) */
    unsigned data_reg;
    unsigned data_reg2;
    unsigned store_reg;  /* STXR data register (single exclusive) */
    unsigned base_reg;
    unsigned status_reg;
    unsigned pair;       /* LDXP/LDAXP;...;STXP/STLXP */
    unsigned acquire;
    unsigned release;
    unsigned valid;
    unsigned win;        /* the window was modeled to its STXR */
    unsigned npend;      /* stores recorded by the window walk */
    unsigned fp_valid;   /* `fp` holds the FPSIMD state at the modeled STXR */
    struct uz_llsc_pstore pend[UZ_LLSC_MEM_MAX];
    struct uro_regs model;   /* architectural state at the modeled STXR */
    struct uz_fpstate fp;    /* snapshot taken only for an FP-carrying window */
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
typedef void *(*alloc_pages_t)(unsigned int gfp, unsigned int order, int nid,
                               void *nodemask);
typedef void (*put_page_t)(void *page);
typedef void (*copy_highpage_t)(void *to, void *from);
typedef void *(*vmalloc_to_page_t)(const void *addr);

/* Readers access only the immutable snapshot or the published image. SET
 * builds into spare, then waits for readers of the previous image before
 * making that image the new spare. */
struct uz_page {
    struct uz_short_lock image_lock;
    uint64_t base;
    uint8_t *image;
    uint8_t *snapshot;
    uint8_t *spare;
    /* Deferred native replay (an undecodable store, e.g. an SVE/SME or
     * single-lane SIMD store): the live bytes before the store and the bytes
     * observed after it.  Both are private kernel pages, never mapped into the
     * process. */
    uint8_t *pre;
    uint8_t *post;
    uint32_t index;      /* descriptor index before sorting */
    uint32_t flags;      /* UROV_Z_PAGE_SRC_* */
    uint32_t fake_off;
    uint32_t fake_len;
    uint32_t armed;      /* an AP[1]=0 trap is installed in the leaf PTE */
    uint32_t want;       /* the current VMA allows EL0 reads: trap desired */
    uint32_t dead;       /* a real store reached the page: overlay is stale */
    uint32_t gone;       /* the registered mapping was unmapped/replaced */
    uint32_t replay;     /* a native replay owns pre/post for this page */
    /* A writer outside this module obtained write access through the kernel
     * (uaccess fault, fast/slow GUP, process_vm_writev).  The live bytes are
     * snapshotted into ext_pre before the write and merged into the image on
     * the next read instead of retiring the page. */
    uint8_t *ext_pre;
    uint8_t *ext_buf;
    uint64_t ext_addr;
    uint32_t ext;
    uint32_t ext_busy;
    /* Registration-time VMA identity.  A fork copies the VMA with
     * vm_area_dup(), so the child keeps the same vm_file pointer, pgoff and
     * range; a foreign process that opens the same file again has a different
     * struct file.  handle_mm_fault uses this to re-arm a forked child's copy
     * without ever arming an unrelated mapping. */
    void *vma_file;
    uint64_t vma_pgoff;
    uint64_t vma_start;
    uint64_t vma_end;
    uint64_t file_page; /* immutable registration-time file page offset */
};

struct uz_session {
    void *mm;
    uint64_t tgid;      /* owner thread group: only its execve replaces the mm */
    uint64_t generation;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint64_t llsc;      /* LL/SC stores completed by the AP bridge */
    struct uz_page *pages;     /* stable slots: never move a live descriptor */
    struct uz_page_index *index;
    struct uz_page_index *index_spare;
    uint8_t *arena;            /* image, spare and snapshot for each page */
    uint32_t page_count;
};

/* A forked child gets its own COW copy of every registered page.  Reads are
 * served from the owner's image until the child writes; the first child write
 * allocates one private image page so the child's bytes never leak into the
 * parent's image (and vice versa).
 *
 * 2.17.0 snapshots the image at fork time (copy_mm) instead of at the child's
 * first write, so an owner SET after the fork can no longer change what the
 * child observes.  The pool is sized from the registered page count when the
 * session is created; a child that finds no free slot keeps the owner image
 * (fail closed, no new bytes). */
struct uz_shadow {
    void *mm;
    void *mm_ref;       /* one get_task_mm reference per child, first slot only */
    struct uz_page page; /* independent identity, arming and write state */
    uint32_t used;
};

#define UZ_SHADOW_CAP 4096U
#define UZ_SHADOW_BYTES_MAX (UINT64_C(16) << 20)

static struct uz_session g_sess;
static struct uz_shadow *g_shadow;
static uint8_t *g_shadow_arena;
static uint32_t g_shadow_max;
static uint32_t g_shadow_used;
static struct uz_layout g_layout;
static uint8_t g_selftest_ws[UROV_Z_PAGE];
static int g_state;
static uint64_t g_readers = UZ_READER_CLOSED;
static void *g_owner;
static int g_ctrl_busy;
static int g_ready;
static int g_verbose;
static int g_experimental_writes;
static int g_loader_enabled = UROV_Z_WITH_KCLF;
static uint32_t g_fork_copies = 4U;
static unsigned g_page_buffers = 3U;
static struct uz_buffer_budget g_buffers = {.limit = UINT64_C(64) << 20};
static struct uz_short_lock g_buffer_lock;
static int g_suspend;
static volatile uint32_t g_failure_logged;
static struct uz_keys g_keys;
static unsigned g_write_gup_flags;
static int g_use_rwsem;
static int g_read_use_rwsem;

static void *f_pin_remote;
static int g_pin_hooked;
static int g_pin_ok;
/* Slow GUP is the fallback for a leaf that cannot be pinned fast.  Its after
 * hook re-arms the AP[1] trap the write fault had to drop, once the page
 * array has been returned to the caller. */
static void *f_gup_slow;
static int g_gup_slow_hooked;
static int g_gup_slow_argc;
static unsigned g_foll_pin, g_foll_longterm;
static unsigned g_foll_get, g_foll_fast_only;
static _Bool (*f_grab_page_bool)(void *, unsigned);
static int (*f_grab_page_int)(void *, unsigned);
static int (*f_grab_folio)(void *, int, unsigned);
static void *(*f_grab_folio_page)(void *, int, unsigned);
static void (*f_unpin_page)(void *);
static int g_pin_argc;
static int g_pin_internal;
/* Pre-FOLL_PIN process_vm_readv() uses ordinary GUP references. Its public
 * get_user_pages_remote entry must never use pin/unpin accounting. */
static int g_remote_get;
#define UZ_READV_SLOTS 64U
struct uz_readv_rec {
    void *task;
    uint32_t active;
    uint32_t allow;
    uint64_t reader;
};
static struct uz_readv_rec g_readv_slot[UZ_READV_SLOTS];
static uint32_t g_max_pages = UROV_Z_MAX_PAGES;
static uint64_t g_max_image_bytes = UINT64_C(8) << 20;
static uint32_t g_caps;
static uint32_t g_page_size;
static uint32_t g_page_shift;
static uint64_t g_user_limit;
/* Page bases of the last session, kept after release so an orphaned trap (a
 * forked child that never read the page while the session was live) can be
 * restored instead of turning into a signal.  Only the bases are needed and
 * they are never dereferenced as pages, so the storage is a fixed array. */
#define UZ_RETIRED_MAX UROV_Z_MAX_PAGES
static uint64_t g_retired[UZ_RETIRED_MAX];
static uint32_t g_retired_count;

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

static int g_prctl_hooked;
static int g_vm_readv_hooked;
static int g_copymm_hooked;
static int g_clone_hooked, g_clone3_hooked;
static void *f_copy_mm;
static int g_wrapper_mode;
static int g_page_hooked;
static int g_mmf_hooked;
static int g_degraded;
static int g_abort_has_iss2;
/* GUP fast is the one user-page pin path that bypasses both the EL0 data
 * abort and the kernel access_remote_vm hook (vmsplice is the standard
 * reader).  The after hook substitutes a private page holding the image. */
static void *f_gup_fast;
static int g_gup_internal;
static struct uz_page_allocator g_page_allocator;
static put_page_t f_put_page;
static copy_highpage_t f_copy_highpage;
static vmalloc_to_page_t f_vmalloc_to_page;
static int g_gup_hooked;
/* Kernel-assisted reads (access_remote_vm/__access_remote_vm) are overlaid by
 * a function hook.  The hook target is the implementation entry when it
 * exists, so both /proc/<pid>/mem and access_process_vm() are covered. */
static void *f_kread;
static int g_kread_argc;
static int g_kread_hooked;
/* Set to `current` only while the module itself calls the access helper.  The
 * kernel-read hook must never rewrite the module's own snapshot/image reads. */
#define UZ_INTERNAL_SLOTS 64U
static void *g_internal_access[UZ_INTERNAL_SLOTS];

static int uz_internal_current(void)
{
    unsigned i;
    for (i = 0; i < UZ_INTERNAL_SLOTS; ++i)
        if (__atomic_load_n(&g_internal_access[i], __ATOMIC_ACQUIRE) == current) return 1;
    return 0;
}
/* FPSIMD state can only be driven when both kernel helpers resolved and BTF
 * described task_struct.thread.uw.fpsimd_state.  Otherwise a vector load from
 * the target page keeps the historical fail-closed SIGSEGV. */
static int g_fp_ready;
/* FEAT_FP16 makes the half-precision FMOV forms legal.  A device without it
 * would take an undefined-instruction exception natively, so the window model
 * must not silently complete those forms there. */
static int g_fp16;

#define UZ_GATE_NUM 9
static int g_gate_hooked[UZ_GATE_NUM];

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
static uint64_t uz_task_pid(void)
{
    return g_layout.task_pid >= 0 ?
        (uint64_t)*(const uint32_t *)((const char *)current + g_layout.task_pid) : 0;
}

static uint64_t uz_task_tgid(void)
{
    return g_layout.task_tgid >= 0 ?
        (uint64_t)*(const uint32_t *)((const char *)current + g_layout.task_tgid) : 0;
}

static int uz_user_range(uint64_t addr, uint64_t bytes)
{
    return addr >= g_page_size && addr < g_user_limit && bytes <= g_user_limit - addr;
}

static uint64_t mm_pgd(void *mm)
{
    return __atomic_load_n((uint64_t *)((char *)mm + g_layout.mm_pgd), __ATOMIC_RELAXED);
}

#include "pt_access.h"

static int mm_has_live_user(void *mm)
{
    int users;
    if (!mm) return 0;
    users = __atomic_load_n((int *)((char *)mm + g_layout.mm_users), __ATOMIC_ACQUIRE);
    return users > 1;
}

static int uz_access_vm(void *mm, unsigned long addr, void *buf,
                        int len, unsigned int flags)
{
    unsigned slot;
    int ret;

    /* Registration, page arming and control replies read/write the very pages
     * the kernel-read hook rewrites.  Mark the task while the module's own
     * call is in flight so the after hook leaves that buffer alone. */
    for (slot = 0; slot < UZ_INTERNAL_SLOTS; ++slot) {
        void *empty = 0;
        if (__atomic_compare_exchange_n(&g_internal_access[slot], &empty, current, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) break;
    }
    if (slot == UZ_INTERNAL_SLOTS) return -EBUSY;
    if (f_access_vm) ret = f_access_vm(mm, addr, buf, len, flags);
    /* Old public access_remote_vm() supplies a NULL task to this variant.
     * Passing current here would associate a foreign mm with the unload task. */
    else ret = f_access_vm_task(0, mm, addr, buf, len, flags);
    __atomic_store_n(&g_internal_access[slot], 0, __ATOMIC_RELEASE);
    return ret;
}

/* Statically linked KCLF only; each nested call owns a separate task slot.
 * uz_access_vm releases its slot on every return, including partial reads.
 * No task/PID-wide or userspace exemption survives this synchronous call. */
int urov_z_read_current_real(unsigned long addr, void *buf, int len)
{
    void *mm;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) return -EOPNOTSUPP;
    if (len < 0 || !uz_user_range(addr, (uint64_t)len)) return -EFAULT;
    mm = mm_of_task(current);
    if (!mm) return -ESRCH;
    return uz_access_vm(mm, addr, buf, len, 0);
}

/* For sleepable control only. Early 5.x has probe_user_read() but may lack a
 * nofault write helper. Use ordinary writable GUP, never FOLL_FORCE, for a
 * reply to the caller; the exception path must never use this fallback. */
static long uz_copy_control_reply(void *dst, const void *src, unsigned long len)
{
    uint64_t addr = (uintptr_t)dst;
    void *mm;
    int copied;

    if (f_copy_out) return f_copy_out(dst, src, len);
    if (!uz_user_range(addr, len) || len > 0x7fffffffU)
        return -EFAULT;
    mm = f_get_task_mm(current);
    if (!mm) return -EFAULT;
    copied = uz_access_vm(mm, addr, (void *)src, (int)len, UZ_FOLL_WRITE);
    f_mmput(mm);
    return copied == (int)len ? 0 : -EFAULT;
}

static void uz_mmap_write_lock(void *mm)
{
    f_mmap_write_lock(g_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
    /* All module write-lock callers are serialized by g_ctrl_busy. */
    g_mmap_writer_mm = mm;
    __atomic_store_n(&g_mmap_writer, current, __ATOMIC_RELEASE);
}

static void uz_mmap_write_unlock(void *mm)
{
    __atomic_store_n(&g_mmap_writer, 0, __ATOMIC_RELEASE);
    f_mmap_write_unlock(g_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
}

static uint64_t page_base(uint64_t address)
{
    return address & ~((uint64_t)g_page_size - 1U);
}

/* Sleepable contexts only (registration, SET, unload).  kvmalloc() keeps
 * small quotas out of the vmalloc address space; vmalloc() is the fallback
 * when the running kernel does not expose kvmalloc_node/kvfree. */
static uint64_t uz_irq_save(void)
{
    uint64_t flags;
    __asm__ volatile("mrs %0, daif; msr daifset, #2" : "=r"(flags) :: "memory");
    return flags;
}

static void uz_irq_restore(uint64_t flags)
{
    __asm__ volatile("msr daif, %0" :: "r"(flags) : "memory");
}

static void *uz_alloc_buffer(unsigned long bytes, int vm_only)
{
    void *p = 0;
    int slot;
    uint64_t irq = uz_irq_save();
    (void)uz_short_lock_take(&g_buffer_lock);
    slot = uz_buffer_reserve(&g_buffers, bytes, g_page_size ? g_page_size : 4096U);
    uz_short_lock_drop(&g_buffer_lock);
    uz_irq_restore(irq);
    if (slot < 0) return 0;

    if (!vm_only && f_kvmalloc_node)
        p = f_kvmalloc_node((uint64_t)bytes, 0xcc0U /* GFP_KERNEL */, -1);
    if (!p && f_vmalloc) p = f_vmalloc(bytes);
    irq = uz_irq_save();
    (void)uz_short_lock_take(&g_buffer_lock);
    if (p) g_buffers.records[slot].ptr = p;
    else uz_buffer_cancel(&g_buffers, (unsigned)slot);
    uz_short_lock_drop(&g_buffer_lock);
    uz_irq_restore(irq);
    return p;
}

static void *uz_alloc(unsigned long bytes)
{
    return uz_alloc_buffer(bytes, 0);
}

static void uz_free(void *p)
{
    int slot;
    uint64_t irq;
    if (!p) return;
    irq = uz_irq_save();
    (void)uz_short_lock_take(&g_buffer_lock);
    slot = uz_buffer_find(&g_buffers, p);
    if (slot >= 0) g_buffers.records[slot].ptr = 0; /* claim this free */
    uz_short_lock_drop(&g_buffer_lock);
    uz_irq_restore(irq);
    if (slot < 0) return; /* never free an unowned pointer */
    if (f_kvfree) f_kvfree(p);
    else if (f_vfree) f_vfree(p);
    /* Keep the reservation until the native free has completed. */
    irq = uz_irq_save();
    (void)uz_short_lock_take(&g_buffer_lock);
    uz_buffer_cancel(&g_buffers, (unsigned)slot);
    uz_short_lock_drop(&g_buffer_lock);
    uz_irq_restore(irq);
}

static int overlay_live(void);
static void uz_rearm_written(void *mm, uint64_t address, unsigned len);
static void uz_write_enter(void);
static void uz_write_leave(void);
static int uz_write_live(void *mm, uint64_t address, const uint8_t *data, unsigned len);
static void uz_retire_written_page(void *mm, struct uz_page *p, uint64_t address);
static void uz_code_invalidate(void);

static uint64_t session_get_mm(void *mm)
{
    uint64_t ref;

    if (!mm || mm != __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE)) return 0;
    ref = uz_reader_enter(&g_readers);
    if (ref && mm != g_sess.mm) {
        uz_reader_exit(&g_readers, ref);
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
    ref = uz_reader_enter(&g_readers);
    if (ref && !overlay_live()) {
        uz_reader_exit(&g_readers, ref);
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

/* The reader reference pins this immutable index across lookup. A mremap may
 * publish a new address ordering, but cannot move the returned descriptor or
 * change which image/snapshot buffers belong to that slot. */
static struct uz_page *page_find(uint64_t page)
{
    const struct uz_page_index *index = __atomic_load_n(&g_sess.index, __ATOMIC_ACQUIRE);
    uint32_t slot = uz_index_find(index, page);

    return slot < g_sess.page_count &&
           __atomic_load_n(&g_sess.pages[slot].base, __ATOMIC_ACQUIRE) == page &&
           !__atomic_load_n(&g_sess.pages[slot].gone, __ATOMIC_ACQUIRE) ?
           &g_sess.pages[slot] : 0;
}

static struct uz_page *page_by_index(uint32_t index)
{
    uint32_t i;

    for (i = 0; i < g_sess.page_count; ++i)
        if (g_sess.pages[i].index == index &&
            !__atomic_load_n(&g_sess.pages[i].gone, __ATOMIC_ACQUIRE))
            return &g_sess.pages[i];
    return 0;
}

/* A leaf PTE that only this module produces: present, without EL0 data
 * permission (AP[1]=0).  The kernel never creates that encoding for a
 * readable VMA - execute-only mappings have no VM_READ and PROT_NONE pages
 * carry PTE_PROT_NONE - so the signature both identifies a trap a forked
 * child inherited and keeps an unrelated permission fault from being
 * "repaired" into a readable page.  AP[2] is deliberately not part of the
 * signature: a store absorbed by 2.15.0 keeps the COW-writable leaf and the
 * trap, so the module now owns both the read-only and the writable form. */
static int uz_leaf_signature(uint64_t pte)
{
    if ((pte & (PTE_VALID | PTE_TYPE_MASK)) != (PTE_VALID | PTE_TYPE_PAGE)) return 0;
    if (pte & (PTE_SPECIAL | PTE_DEVMAP | PTE_PROT_NONE)) return 0;
    return !(pte & PTE_USER);
}

static int uz_trap_leaf(void *mm, uint64_t far)
{
    uint64_t pte;

    return !uz_pte_read(mm, page_base(far), &pte) && uz_leaf_signature(pte);
}

/* Restore AP[1] on a trap whose session is gone and let the faulting
 * instruction retry, so an orphaned trap can never become a signal. */
static int uz_repair_trap(void *mm, uint64_t far)
{
    struct uz_pte_op op = {.write = 1, .set = PTE_USER, .forbidden = PTE_USER};
    void *vma;
    int held, rc = 0;

    if (!mm) return 0;
    held = uz_mm_guard(mm);
    if (held < 0) return 0;
    vma = f_find_vma(mm, far);
    if (!vma || far < *(uint64_t *)((char *)vma + g_layout.vma_start) ||
        !(*(unsigned long *)((char *)vma + g_layout.vma_flags) & UZ_VM_READ)) goto out;
    rc = uz_pte_access_locked(mm, page_base(far), &op) > 0;
out:
    uz_mm_unguard(mm, held);
    return rc;
}

static int uz_retired_has(uint64_t page)
{
    uint32_t i;

    for (i = 0; i < g_retired_count; ++i)
        if (g_retired[i] == page) return 1;
    return 0;
}

/* Only kernel-buffer copies/publication run under this lock. No allocator,
 * uaccess, mmap lock or sleeping helper is allowed inside the critical
 * section. IRQ exclusion prevents a preempted holder from blocking readers. */
struct uz_image_guard { uint64_t irq, acquired; };

#if UROV_Z_DIAGNOSTICS
static uint64_t uz_clock_ticks(void)
{
    uint64_t ticks;
    __asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(ticks) :: "memory");
    return ticks;
}

static void uz_perf_max(uint64_t *field, uint64_t value)
{
    uint64_t old = __atomic_load_n(field, __ATOMIC_RELAXED);
    while (old < value && !__atomic_compare_exchange_n(field, &old, value, 1,
                                                       __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
}
#endif

static struct uz_image_guard uz_image_lock(struct uz_page *p)
{
    struct uz_image_guard guard = {.irq = uz_irq_save(), .acquired = 0};
    uint64_t waits;
#if UROV_Z_DIAGNOSTICS
    uint64_t start = uz_clock_ticks();
#endif
    waits = uz_short_lock_take(&p->image_lock);
    UZ_PERF_ADD(image_locks, 1);
    UZ_PERF_ADD(image_contended, waits != 0);
    UZ_PERF_ADD(image_spins, waits);
#if UROV_Z_DIAGNOSTICS
    guard.acquired = uz_clock_ticks();
    uz_perf_max(&g_perf.image_wait_max, guard.acquired - start);
#endif
    return guard;
}

static void uz_image_unlock(struct uz_page *p, struct uz_image_guard guard)
{
#if UROV_Z_DIAGNOSTICS
    uz_perf_max(&g_perf.image_hold_max, uz_clock_ticks() - guard.acquired);
#endif
    uz_short_lock_drop(&p->image_lock);
    uz_irq_restore(guard.irq);
}

static void page_view(struct uz_page *p, uint64_t off, unsigned total,
                      uint8_t *out, int replay)
{
    struct uz_image_guard guard = uz_image_lock(p);
    memcpy(out, (replay ? p->snapshot : p->image) + off, total);
    uz_image_unlock(p, guard);
}

/* SET, native snapshots and store publication share a single copy boundary.
 * Readers no longer fall back to a concurrently changing snapshot after a
 * bounded seqlock retry, and SET cannot lose a write outside its new window. */
static void page_store_bytes(struct uz_page *p, uint64_t off,
                             const uint8_t *bytes, unsigned len)
{
    struct uz_image_guard guard = uz_image_lock(p);
    memcpy(p->image + off, bytes, len);
    memcpy(p->snapshot + off, bytes, len);
    uz_image_unlock(p, guard);
}

/* ------------------------------------------- foreign-writer absorption */

/* Snapshot the live bytes before a writer outside this module can change them
 * and remember that the page needs a merge.  Called from the uaccess fault,
 * the fast-GUP and the slow-GUP paths, all of which have just proved that the
 * writer owns a writable translation of this page.  A user-mode uaccess read
 * is used here on purpose: at this point the leaf is EL1-writable and (for the
 * fault paths) already carries the COW's AP[1], so it succeeds without taking
 * the mmap lock from inside a fault or GUP callback.  The drain, which runs
 * with the trap armed, uses the GUP path instead. */
static int uz_ext_capture(void *mm, struct uz_page *p, uint64_t va)
{
    if (!mm || !p || !g_page_size) return 0;
    if (!g_experimental_writes) { uz_retire_written_page(mm, p, va); return 0; }
    if (!p->ext_pre || !p->ext_buf) return 0;
    if (__atomic_load_n(&p->ext, __ATOMIC_ACQUIRE)) return 1;
    if (f_copy_in(p->ext_pre, (const void *)(uintptr_t)va, g_page_size))
        return 0;
    p->ext_addr = va;
    __atomic_store_n(&p->ext, 1, __ATOMIC_RELEASE);
    if (g_verbose) pr_info("urov-z: ext capture page=%llx va=%llx\n",
                           (unsigned long long)p->base, (unsigned long long)va);
    return 1;
}

/* Merge the bytes an external writer left in the live page into the overlay
 * image (and snapshot) instead of declaring the page dead.  The reader that
 * needs the page calls this before taking a view, so a write is published at
 * most one access late and the page keeps returning the image afterwards.
 * ext_buf/ext_pre are private to this path; a concurrent drain on another CPU
 * simply skips because the owner will publish the same bytes. */
static void uz_ext_drain(void *mm, struct uz_page *p)
{
    unsigned off = 0, changed = 0;

    if (!mm || !__atomic_load_n(&p->ext, __ATOMIC_ACQUIRE)) return;
    if (!__atomic_load_n(&p->ext_buf, __ATOMIC_ACQUIRE)) return;
    if (__atomic_exchange_n(&p->ext_busy, 1, __ATOMIC_ACQ_REL)) return;
    if (uz_access_vm(mm, (unsigned long)p->ext_addr, p->ext_buf,
                     (int)g_page_size, 0) != (int)g_page_size) {
        if (g_verbose) pr_info("urov-z: ext drain read failed page=%llx\n",
                               (unsigned long long)p->base);
        goto out;
    }
    while (off < g_page_size) {
        unsigned start;

        if (p->ext_buf[off] == p->ext_pre[off]) {
            ++off;
            continue;
        }
        start = off;
        while (off < g_page_size && p->ext_buf[off] != p->ext_pre[off]) ++off;
        page_store_bytes(p, start, p->ext_buf + start, off - start);
        changed += off - start;
    }
    memcpy(p->ext_pre, p->ext_buf, g_page_size);
    __atomic_store_n(&p->ext, 0, __ATOMIC_RELEASE);
    if (g_verbose) pr_info("urov-z: ext drain page=%llx changed=%u\n",
                           (unsigned long long)p->base, changed);
out:
    __atomic_store_n(&p->ext_busy, 0, __ATOMIC_RELEASE);
}

/* GUP pin accounting.  pin_user_pages_remote() returns pages that the caller
 * releases with unpin_user_page(), i.e. a GUP_PIN_COUNTING_BIAS subtraction.
 * Moving that bias from the live page to the overlay page keeps both
 * refcounts exactly where their owners expect them. */

static struct uz_readv_rec *uz_readv_rec_find(void *task, int create)
{
    uint32_t i;

    for (i = 0; i < UZ_READV_SLOTS; ++i) {
        struct uz_readv_rec *r = &g_readv_slot[i];

        if (__atomic_load_n(&r->active, __ATOMIC_ACQUIRE) == 2U && r->task == task) return r;
    }
    if (!create) return 0;
    for (i = 0; i < UZ_READV_SLOTS; ++i) {
        struct uz_readv_rec *r = &g_readv_slot[i];
        uint32_t expect = 0;

        if (!__atomic_load_n(&r->active, __ATOMIC_ACQUIRE) &&
            __atomic_compare_exchange_n(&r->active, &expect, 1, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            r->task = task;
            r->allow = 1;
            r->reader = 0;
            __atomic_store_n(&r->active, 2, __ATOMIC_RELEASE);
            return r;
        }
    }
    UZ_HEALTH_ADD(readv_slots_full);
    return 0;
}

static void uz_readv_rec_clear(void *task)
{
    struct uz_readv_rec *r = uz_readv_rec_find(task, 0);

    if (!r) return;
    uint64_t ref = r->reader;
    r->reader = 0;
    r->task = 0;
    r->allow = 0;
    __atomic_store_n(&r->active, 0, __ATOMIC_RELEASE);
    if (ref) uz_reader_exit(&g_readers, ref);
}

static struct uz_shadow *uz_shadow_find(void *mm, uint32_t index)
{
    uint32_t i;

    for (i = 0; i < g_shadow_max; ++i)
        if (__atomic_load_n(&g_shadow[i].used, __ATOMIC_ACQUIRE) == 1 &&
            g_shadow[i].mm == mm && g_shadow[i].page.index == index)
            return &g_shadow[i];
    return 0;
}

static struct uz_shadow *uz_shadow_get(void *mm, uint32_t index)
{
    struct uz_shadow *sh = uz_shadow_find(mm, index);
    struct uz_page *p;
    uint32_t i;

    if (sh || !mm || mm == g_sess.mm || !g_shadow_arena || !g_shadow_max)
        return sh;
    p = page_by_index(index);
    if (!p) return 0;
    for (i = 0; i < g_shadow_max; ++i) {
        uint32_t unused = 0;
        if (__atomic_compare_exchange_n(&g_shadow[i].used, &unused, 2, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) break;
    }
    if (i == g_shadow_max) return 0;
    sh = &g_shadow[i];
    sh->page.image = g_shadow_arena + 2ULL * (uint64_t)i * g_page_size;
    sh->page.snapshot = sh->page.image + g_page_size;
    {
        struct uz_image_guard guard = uz_image_lock(p);
        memcpy(sh->page.image, p->image, g_page_size);
        memcpy(sh->page.snapshot, p->snapshot, g_page_size);
        uz_image_unlock(p, guard);
    }
    sh->page.base = __atomic_load_n(&p->base, __ATOMIC_ACQUIRE);
    sh->page.index = index;
    sh->page.flags = p->flags;
    sh->page.fake_off = p->fake_off;
    sh->page.fake_len = p->fake_len;
    sh->page.armed = __atomic_load_n(&p->armed, __ATOMIC_ACQUIRE);
    sh->page.want = __atomic_load_n(&p->want, __ATOMIC_ACQUIRE);
    sh->page.dead = __atomic_load_n(&p->dead, __ATOMIC_ACQUIRE);
    sh->page.vma_file = p->vma_file;
    sh->page.vma_pgoff = p->vma_pgoff;
    sh->page.vma_start = p->vma_start;
    sh->page.vma_end = p->vma_end;
    sh->page.file_page = p->file_page;
    sh->mm = mm;
    __atomic_store_n(&sh->used, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_shadow_used, 1, __ATOMIC_RELAXED);
    return sh;
}

static void uz_shadow_store(struct uz_shadow *sh, unsigned off,
                            const uint8_t *bytes, unsigned len)
{
    page_store_bytes(&sh->page, off, bytes, len);
}

static void uz_shadow_view(struct uz_shadow *sh, unsigned off, unsigned total,
                           uint8_t *out, int replay)
{
    page_view(&sh->page, off, total, out, replay);
}

static void uz_shadow_free_all(void)
{
    uint32_t i;
    if (g_shadow && g_shadow_max) {
        for (i = 0; i < g_shadow_max; ++i)
            if (g_shadow[i].mm_ref) f_mmput(g_shadow[i].mm_ref);
        memset(g_shadow, 0, (size_t)g_shadow_max * sizeof(*g_shadow));
    }
    g_shadow_used = 0;
}

static int uz_child_known(void *mm)
{
    uint32_t i;
    for (i = 0; i < g_shadow_max; ++i)
        if (__atomic_load_n(&g_shadow[i].used, __ATOMIC_ACQUIRE) == 1 &&
            g_shadow[i].mm == mm) return 1;
    return 0;
}

static int uz_child_live(void)
{
    uint32_t i;
    for (i = 0; i < g_shadow_max; ++i)
        if (g_shadow[i].mm_ref && mm_has_live_user(g_shadow[i].mm_ref)) return 1;
    return 0;
}

static void page_view_mm(void *mm, struct uz_page *p, uint64_t off, unsigned total,
                         uint8_t *out, int replay)
{
    struct uz_shadow *sh = mm && mm != g_sess.mm ? uz_shadow_find(mm, p->index) : 0;

    if (sh) uz_shadow_view(sh, (unsigned)off, total, out, replay);
    else page_view(p, off, total, out, replay);
}

/* Parent and child have independent stable mapping slots. Syscall gates
 * move/retire child slots, so fault resolution never walks a parent's VMA or
 * reads a VMA pointer after handle_mm_fault may have dropped its lock. */
static struct uz_page *uz_page_for_fault(void *mm, uint64_t addr)
{
    uint32_t i;
    if (mm == g_sess.mm) return page_find(page_base(addr));
    if (!mm) return 0;
    for (i = 0; i < g_shadow_max; ++i) {
        struct uz_shadow *sh = &g_shadow[i];
        struct uz_page *p = &sh->page;
        if (__atomic_load_n(&sh->used, __ATOMIC_ACQUIRE) == 1 && sh->mm == mm &&
            !__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) &&
            __atomic_load_n(&p->base, __ATOMIC_ACQUIRE) == page_base(addr)) return p;
    }
    return 0;
}

/* Mirror a successful write of [address, address+len) into every registered
 * page it covers.  The live bytes are written by the caller through the
 * kernel's GUP path; this only keeps the read view consistent.  Cross-page
 * stores are split at page boundaries. */
static void uz_image_store(uint64_t address, const uint8_t *bytes, unsigned len)
{
    uint64_t done = 0;

    while (done < len) {
        uint64_t cur = address + done;
        uint64_t page = page_base(cur);
        unsigned off = (unsigned)(cur - page);
        unsigned seg = g_page_size - off;
        struct uz_page *p;

        if (seg > len - done) seg = len - (unsigned)done;
        p = page_find(page);
        if (p) page_store_bytes(p, off, bytes + done, seg);
        done += seg;
    }
}

static void uz_shadow_store_range(void *mm, uint64_t address,
                                  const uint8_t *bytes, unsigned len)
{
    uint64_t done = 0;

    while (done < len) {
        uint64_t cur = address + done;
        uint64_t page = page_base(cur);
        unsigned off = (unsigned)(cur - page);
        unsigned seg = g_page_size - off;
        struct uz_page *p;
        struct uz_shadow *sh;

        if (seg > len - done) seg = len - (unsigned)done;
        p = uz_page_for_fault(mm, cur);
        sh = p ? uz_shadow_get(mm, p->index) : 0;
        if (sh) uz_shadow_store(sh, off, bytes + done, seg);
        done += seg;
    }
}

/* Read [address, address+total) into `out`, using the page images for every
 * registered segment and nofault uaccess for the rest.  Returns 1 when at
 * least one segment was served by the session, 0 when the whole range was
 * native memory, and a negative fail-closed code otherwise.  Cross-page
 * access is just this loop; a 64-byte LD1 can span two pages. */
static int read_range(void *mm, uint64_t address, unsigned total, int allow_fake,
                      uint8_t *out, uint64_t *bad)
{
    uint64_t done = 0;
    int covered = 0;

    while (done < total) {
        uint64_t cur = address + done;
        uint64_t off = cur - page_base(cur);
        unsigned seg = (unsigned)(g_page_size - off);
        struct uz_page *p;

        if (seg > total - done) seg = (unsigned)(total - done);
        p = uz_page_for_fault(mm, cur);
        if (p && !__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) {
            struct uz_vma_view vma;
            int rc = uz_vma_read(mm, cur, &vma);
            if (rc == -EAGAIN) return -EAGAIN;
            if (rc || !(vma.flags & UZ_VM_READ) ||
                !__atomic_load_n(&p->want, __ATOMIC_ACQUIRE) ||
                vma.file != (uint64_t)(uintptr_t)p->vma_file ||
                (g_layout.vma_pgoff_ok && vma.pgoff +
                 ((page_base(cur) - vma.start) >> g_page_shift) != p->file_page)) {
                *bad = cur;
                return -5;
            }
            covered = 1;
            uz_ext_drain(mm, p);
            page_view_mm(mm, p, off, seg, out + done, !allow_fake);
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
    return __atomic_load_n(&g_state, __ATOMIC_ACQUIRE) == UZ_STATE_LIVE;
}

static int session_owned(void)
{
    return overlay_live() && mm_of_task(current) == g_sess.mm;
}

static unsigned request_fake_len(const struct urov_z_request *q)
{
    return q->length ? q->length : 8U;
}

static long copy_user_image(void *mm, uint64_t addr, uint8_t *dst, unsigned len)
{
    if (!uz_user_range(addr, len)) return -EINVAL;
    return uz_access_vm(mm, addr, dst, (int)len, 0) == (int)len ? 0 : -EFAULT;
}

static long copy_request_image(const struct urov_z_request *q, void *mm, uint8_t *dst,
                               unsigned len)
{
    unsigned i;

    if (q->fake_addr) return copy_user_image(mm, q->fake_addr, dst, len);
    if (len > UROV_Z_FAKE_MAX) return -EINVAL;
    for (i = 0; i < len; ++i) {
        uint64_t word = i < 8U ? q->value : q->value_hi[(i - 8U) / 8U];
        dst[i] = (uint8_t)(word >> (8U * (i & 7U)));
    }
    return 0;
}

static void page_swap_image(struct uz_page *p, uint32_t off, uint32_t len)
{
    struct uz_image_guard guard = uz_image_lock(p);
    uint8_t *old;
    /* User input is already in spare's new window. Merge the latest native
     * snapshot around it at the same serialization point as publication. */
    memcpy(p->spare, p->snapshot, off);
    memcpy(p->spare + off + len, p->snapshot + off + len, g_page_size - off - len);
    old = __atomic_exchange_n(&p->image, p->spare, __ATOMIC_ACQ_REL);
    p->fake_off = off;
    p->fake_len = len;
    uz_image_unlock(p, guard);
    /* Never hold the image lock while waiting on readers. */
    drain_readers(uz_readers_flip(&g_readers));
    p->spare = old;
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
static void page_status_words(struct urov_z_request *q, struct uz_page *p)
{
    uint8_t bytes[32];
    unsigned n;

    memset(bytes, 0, sizeof(bytes));
    n = p->fake_len < sizeof(bytes) ? p->fake_len : (unsigned)sizeof(bytes);
    if (p->image && n) page_view(p, p->fake_off, n, bytes, 0);
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
        pr_info("urov-z: load emulation failure pc=%llx result=%d\n",
                (unsigned long long)pc, result);
}

/* -------------------------------------------------------- PAGE_AP transitions */

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
    if ((flags & (UZ_VM_READ | UZ_VM_EXEC)) != (UZ_VM_READ | UZ_VM_EXEC)) return -EINVAL;
    if (flags & (UZ_VM_WRITE | UZ_VM_PFNMAP | UZ_VM_HUGETLB |
                 UZ_VM_IO | UZ_VM_MIXEDMAP)) return -EINVAL;
    if (!file) return -EINVAL;
    if (flags & UZ_VM_SHARED) {
        if (start != address || end != address + g_page_size) return -EINVAL;
        if (flags & UZ_VM_MAYWRITE) return -EINVAL;
    }
    return 0;
}

/* Remember what identifies this mapping.  fork() duplicates the VMA through
 * vm_area_dup(), so a child keeps the same struct file pointer, pgoff and
 * range; a different process that maps the same file gets its own struct
 * file.  handle_mm_fault uses this to re-arm only a copy of the registered
 * mapping. */
static void uz_capture_vma(struct uz_page *p, void *vma)
{
    p->vma_file = vma ? *(void **)((char *)vma + g_layout.vma_file) : 0;
    p->vma_pgoff = vma && g_layout.vma_pgoff_ok ?
        *(unsigned long *)((char *)vma + g_layout.vma_pgoff) : 0;
    p->vma_start = vma ? *(unsigned long *)((char *)vma + g_layout.vma_start) : 0;
    p->vma_end = vma ? *(unsigned long *)((char *)vma + g_layout.vma_end) : 0;
    p->file_page = p->vma_pgoff + ((p->base - p->vma_start) >> g_page_shift);
}

/* All PTE updates run under the native PTL; CAS additionally preserves
 * hardware AF/DBM updates. No unlocked leaf pointer survives this call. */
static int page_update_bits(void *mm, uint64_t page, uint64_t set, uint64_t clear,
                            uint64_t required, uint64_t forbidden, uint32_t *arm)
{
    struct uz_pte_op op = {.set = set, .clear = clear, .required = required,
        .forbidden = forbidden, .arm = arm, .write = 1};
    return uz_pte_access(mm, page, &op);
}

/* The same AP[1] transition on a leaf whose write/COW state may already have
 * changed.  A successful PAGE_AP store lets Linux perform its normal COW, so
 * the leaf can be writable when the trap has to be reinstalled; AP[1] is
 * independent of AP[2] and EL1 writes are unaffected.  Disarming must also
 * work on that leaf, otherwise release_session() could no longer restore it. */
static int page_set_ap_any(void *mm, uint64_t page, int set)
{
    return page_update_bits(mm, page, set ? PTE_USER : 0, set ? 0 : PTE_USER,
                            0, 0, 0);
}

/* The default RX contract ends for a page once a real writer reaches it.
 * Keep a tombstone until session teardown, including if the lock is busy:
 * a later abort retries restoration instead of consuming stale image data. */
static void uz_retire_written_page(void *mm, struct uz_page *p, uint64_t address)
{
    if (mm == g_sess.mm) uz_code_invalidate();
    if (!__atomic_exchange_n(&p->dead, 1, __ATOMIC_ACQ_REL)) UZ_HEALTH_ADD(retired_writes);
    __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
    if (page_set_ap_any(mm, page_base(address), 1) >= 0)
        __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
}

/* Registration already copied every target page. If reclaim drops a PTE
 * before arming, return EAGAIN after the common session rollback. */
static long ap_arm_pages(struct uz_session *s, void *mm)
{
    uint32_t i;
    int ret = 0;

    uz_mmap_write_lock(mm);
    for (i = 0; i < s->page_count; ++i) {
        struct uz_page *p = &s->pages[i];

        ret = validate_target_vma(f_find_vma(mm, p->base), p->base);
        if (!ret) {
            p->want = 1;
            p->dead = 0;
            ret = page_update_bits(mm, p->base, 0, PTE_USER,
                                   PTE_USER | PTE_RDONLY, PTE_UXN | PTE_DBM, &p->armed);
        }
        if (ret < 0) break;
    }
    if (i) flush_tlb_all();
    uz_mmap_write_unlock(mm);
    return ret == -ENOENT ? -EAGAIN : ret < 0 ? ret : 0;
}

static int ap_disarm_pages(struct uz_session *s, void *mm)
{
    uint32_t i;
    int rc = 0;

    if (!mm_has_live_user(mm)) return 0;
    uz_mmap_write_lock(mm);
    for (i = 0; i < s->page_count; ++i) {
        struct uz_page *p = &s->pages[i];
        int ret;

        __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
        if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) ||
            !__atomic_load_n(&p->armed, __ATOMIC_ACQUIRE)) continue;
        ret = page_set_ap_any(mm, p->base, 1);
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
    uz_mmap_write_unlock(mm);
    return rc;
}

/* Apply a successful mprotect()/pkey_mprotect() to the registered pages it
 * covers.
 *
 * A protection change is not a reason to end the session.  After
 * mprotect(PROT_WRITE) a private file leaf may already be COW-writable, and a
 * shared writable leaf is writable too; either form still carries the
 * AP[1]=0 trap because AP[1] only governs EL0.  A store then faults and is
 * absorbed by the write handoff (see uz_store_emulate), so the image stays
 * live and `dead` is no longer produced by a writable protection.
 *
 * When the new protection removes EL0 read permission, the kernel has already
 * installed its own PTE (PROT_NONE or the execute-only AP[1]=0 encoding).  The
 * page is only suspended, never modified: reads must keep faulting exactly as
 * they do without the module.  A later readable protection re-arms it.
 *
 * A leaf that cannot carry the trap at all (special/devmap/contiguous) falls
 * back to the live view for that page, which is the pre-2.14 behaviour for
 * that one page. */
static void ap_protection_update(void *mm, uint64_t start, uint64_t len, uint64_t prot)
{
    uint64_t end = start + len;
    uint32_t i;
    int changed = 0;
    int readable = (prot & (UZ_PROT_READ | UZ_PROT_WRITE)) != 0;

    if (end < start) end = ~UINT64_C(0);
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uz_page *p = &g_sess.pages[i];
        int ret;

        /* A successful mprotect rounds its length up to a whole page. */
        if (p->base < start || p->base >= end) continue;
        if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
        if (!g_experimental_writes && (prot & UZ_PROT_WRITE)) {
            uz_retire_written_page(mm, p, p->base);
            continue;
        }
        if (!readable) {
            __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
            continue;
        }
        __atomic_store_n(&p->want, 1, __ATOMIC_RELEASE);
        if (__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) continue;
        ret = page_set_ap_any(mm, p->base, 0);
        if (ret >= 0) {
            if (ret > 0) changed = 1;
            /* page_update_bits() only records `armed` when it changed the
             * entry; an already-trapped equal PTE also needs the flag. */
            __atomic_store_n(&p->armed, 1, __ATOMIC_RELEASE);
            continue;
        }
        if (ret == -ENOENT) {
            /* Not resident: handle_mm_fault re-arms when it faults in. */
            continue;
        }
        /* A leaf shape that cannot carry the trap (special/devmap/contiguous
         * or a lost CAS race): this page keeps the live view. */
        __atomic_store_n(&p->dead, 1, __ATOMIC_RELEASE);
        __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
    }
    if (changed) flush_tlb_all();
}

/* A fork of the session owner copies the trapped leaf PTE.  The child is not
 * bound to the session mm, so handle_mm_fault cannot use session_get_mm();
 * the VMA identity captured before the fault proves this mm carries a copy of
 * the registered mapping. */
static int uz_rearm_checked(void *mm, struct uz_page *p, uint64_t page,
                            const struct uz_vma_view *captured)
{
    struct uz_vma_view now;
    struct uz_pte_op op = {.clear = PTE_USER, .write = 1};
    int held, ret;

    if (!p || !mm) return 0;
    if (__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&p->replay, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&p->want, __ATOMIC_ACQUIRE)) return 0;
    UZ_HEALTH_ADD(rearm_attempts);
    ret = -ESTALE;
    if (__atomic_load_n(&p->base, __ATOMIC_ACQUIRE) != page ||
        !uz_mapping_matches(captured, page, g_page_shift, (uintptr_t)p->vma_file,
                            p->file_page, p->vma_start, p->vma_end, g_layout.vma_pgoff_ok))
        goto record;
    held = uz_mm_guard(mm);
    if (held < 0) { ret = held; goto record; }
    ret = uz_vma_read_locked(mm, page, &now);
    if (!ret && !uz_mapping_matches(&now, page, g_page_shift, (uintptr_t)p->vma_file,
                                    p->file_page, p->vma_start, p->vma_end, g_layout.vma_pgoff_ok))
        ret = -ESTALE;
    if (!ret && !(now.flags & UZ_VM_READ)) ret = -EACCES;
    if (!ret && !g_experimental_writes && (now.flags & UZ_VM_WRITE)) {
        if (!__atomic_exchange_n(&p->dead, 1, __ATOMIC_ACQ_REL)) UZ_HEALTH_ADD(retired_writes);
        __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
        op.set = PTE_USER;
        op.clear = 0;
    } else {
        op.arm = &p->armed;
    }
    if (!ret) {
        ret = uz_pte_access_locked(mm, page, &op);
        if (ret >= 0 && !op.arm) __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
    }
    uz_mm_unguard(mm, held);
record:
    if (ret >= 0) UZ_HEALTH_ADD(rearm_ok);
    else {
        __atomic_store_n(&g_health.last_rearm_error, ret, __ATOMIC_RELAXED);
        if (ret == -EAGAIN) UZ_HEALTH_ADD(rearm_busy);
        else if (ret == -ENOENT) UZ_HEALTH_ADD(rearm_missing);
        else if (ret == -ESTALE) UZ_HEALTH_ADD(rearm_identity);
        else UZ_HEALTH_ADD(rearm_rejected);
    }
    return ret;
}

static int ap_shadow_rearm(void *mm, uint64_t page, uint64_t file, uint64_t pgoff,
                           uint64_t start, uint64_t end)
{
    const struct uz_vma_view captured = {.start = start, .end = end, .file = file, .pgoff = pgoff};
    return uz_rearm_checked(mm, uz_page_for_fault(mm, page), page, &captured);
}

/* Fault the page in if needed, then install the trap bit. No byte of the code
 * page is touched: the page stays the clean file-backed page it was, so a
 * file-vs-memory comparison and smaps are both unchanged. */

/* ------------------------------------------------------------ emulation core */

/* XPACLRI is a NOP on CPUs without pointer authentication. Strip only the
 * comparison value; user x30 and the saved frame are never changed. */

/* Commit a decoded GPR load whose source bytes are already in `bytes`. */
static void uz_commit(struct uro_regs *m, const struct uro_load *d, const uint8_t *bytes)
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
    if (f_force_sig_fault) f_force_sig_fault(UZ_SIGSEGV, UZ_SEGV_ACCERR, (void *)far);
}

static int uz_fp_snapshot(struct uz_fpstate *state)
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
static int uz_fp_commit(const struct uro_load *d, const uint8_t *bytes)
{
    struct uz_fpstate state __attribute__((aligned(16)));
    unsigned i;

    if (d->rt > 31U || (d->count == 2U && d->rt2 > 31U)) return -EOPNOTSUPP;
    if (uz_fp_snapshot(&state)) return -EOPNOTSUPP;
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
static int uz_fp_commit_multi(const struct uro_load *d, const uint8_t *bytes)
{
    struct uz_fpstate state __attribute__((aligned(16)));
    unsigned nregs = d->nregs * d->selem;
    unsigned r, s, e, i;

    if (d->nregs < 1U || d->nregs > 4U || d->selem < 1U || d->selem > 4U ||
        nregs > 4U || d->esize < 1U || d->esize > 16U ||
        d->elements < 1U || d->elements > 16U || d->size > 16U)
        return -EOPNOTSUPP;
    for (i = 0; i < nregs; ++i)
        if (d->dst[i] > 31U) return -EOPNOTSUPP;

    if (uz_fp_snapshot(&state)) return -EOPNOTSUPP;
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

/* Fetch real instructions, never the fake data image. Owner aliases outside
 * the registered VA range use native memory; only a known child needs file
 * identity resolution, and it must use its own COW snapshot even at the same
 * VA as the parent. Callers hold a session reader reference. */
static int uz_fetch_insns(void *mm, uint64_t pc, void *out, unsigned bytes)
{
    struct uz_page *page;

    if (!bytes || !uz_user_range(pc, bytes) || (pc & 3U) || (bytes & 3U) ||
        bytes > g_page_size - (pc & (g_page_size - 1U))) return -1;
    UZ_PERF_ADD(insn_fetches, 1);
    page = uz_page_for_fault(mm, pc);
    if (page) {
        page_view_mm(mm, page, pc & (g_page_size - 1U), bytes, out, 1);
        return 0;
    }
    UZ_PERF_ADD(insn_nofault, 1);
    return f_copy_in(out, (const void *)(uintptr_t)pc, bytes) ? -1 : 0;
}

static int uz_read_insn(uint64_t pc, uint32_t *out)
{
    return uz_fetch_insns(mm_of_task(current), pc, out, sizeof(*out));
}

static struct uz_insn_memo *uz_insn_memo_acquire(void *mm, uint64_t pc)
{
    unsigned i, first = (unsigned)(((uintptr_t)current >> 6) ^ (pc >> 2));

    if (!g_insn_memo || mm != g_sess.mm) return 0;
    for (i = 0; i < UZ_LLSC_MEMO_SLOTS; ++i) {
        struct uz_insn_memo *memo = &g_insn_memo[(first + i) % UZ_LLSC_MEMO_SLOTS];
        uint32_t expected = 0;

        if (__atomic_compare_exchange_n(&memo->busy, &expected, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return memo;
    }
    return 0;
}

static int uz_insn_memo_match(struct uz_insn_memo *memo, void *mm, uint64_t pc)
{
    unsigned done = 0, bytes;
    uint64_t start;

    if (!memo || !memo->words || memo->mm != mm || memo->pc != pc) return 0;
    bytes = memo->words * 4U;
    start = pc - bytes;
    while (done < bytes) {
        uint64_t at = start + done;
        unsigned n = g_page_size - (unsigned)(at & (g_page_size - 1U));

        if (n > bytes - done) n = bytes - done;
        if (uz_fetch_insns(mm, at, (uint8_t *)memo->probe + done, n) ||
            memcmp((uint8_t *)memo->probe + done, (uint8_t *)memo->saved + done, n))
            goto changed;
        done += n;
    }
    if (memo->guard) {
        uint32_t word;

        /* A previously absent page may have been mapped or faulted in. Never
         * cache its failure without checking that exact word again. */
        if (!uz_fetch_insns(mm, memo->guard, &word, sizeof(word))) goto changed;
    }
    UZ_PERF_ADD(cache_bytes, bytes);
    return 1;
changed:
    memo->words = 0;
    UZ_PERF_ADD(cache_invalidations, 1);
    return 0;
}

static void uz_insn_memo_release(struct uz_insn_memo *memo)
{
    if (memo) __atomic_store_n(&memo->busy, 0, __ATOMIC_RELEASE);
}

static int uz_is_ldxr(uint32_t insn, unsigned *size, unsigned *rt, unsigned *rn)
{
    if ((insn & UZ_EXCL_LD_MASK) != UZ_EXCL_LDXR &&
        (insn & UZ_EXCL_LD_MASK) != UZ_EXCL_LDAXR)
        return 0;
    *size = insn >> 30;
    *rt = insn & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

static int uz_is_stxr(uint32_t insn, unsigned *size, unsigned *rs, unsigned *rt, unsigned *rn)
{
    if ((insn & UZ_EXCL_ST_MASK) != UZ_EXCL_STXR &&
        (insn & UZ_EXCL_ST_MASK) != UZ_EXCL_STLXR)
        return 0;
    *size = insn >> 30;
    *rs = (insn >> 16) & 31U;
    *rt = insn & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

/* Pair exclusives: size[31:30], 001000, R=1 for LDXP/LDAXP (bit 22), R=0
 * for STXP/STLXP, Rt2[14:10], acquire/release in bit 15, Rn[9:5], Rt[4:0].
 * bit 21 is fixed one. */
static int uz_is_ldxp(uint32_t insn, unsigned *size, unsigned *rt, unsigned *rt2,
                      unsigned *rn)
{
    if ((insn & 0x3f600000U) != 0x08600000U) return 0;
    *size = insn >> 30;
    *rt = insn & 31U;
    *rt2 = (insn >> 10) & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

static int uz_is_stxp(uint32_t insn, unsigned *size, unsigned *rs, unsigned *rt,
                      unsigned *rt2, unsigned *rn)
{
    if ((insn & 0x3f600000U) != 0x08200000U) return 0;
    *size = insn >> 30;
    *rs = (insn >> 16) & 31U;
    *rt = insn & 31U;
    *rt2 = (insn >> 10) & 31U;
    *rn = (insn >> 5) & 31U;
    return 1;
}

/* CLREX and the exception-generating instructions both destroy the local
 * monitor; the read-before proof and the native single step have to recognise
 * them before anything else looks at the encoding. */
static inline int uz_is_clrex(uint32_t insn)
{
    return (insn & 0xfffff0ffU) == 0xd503305fU;
}

static inline int uz_is_exception_insn(uint32_t insn)
{
    unsigned op = insn & 0xffe0001fU;

    return op == 0xd4000001U || op == 0xd4000002U || op == 0xd4000003U ||
           op == 0xd4200000U || op == 0xd4400000U;
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

#define UZ_CODE_MAX_REGIONS 1024U
#define UZ_CODE_BITMAP_MAX (16U << 20)
#define UZ_CODE_ARENA_MAX (24U << 20)
#define UZ_CODE_SCAN_MAX (64U << 20)
#define UZ_BRANCH_CHUNK 4096U

struct uz_code_region {
    uint64_t start;
    uint64_t end;
    uint64_t bitmap_off;
};

struct uz_code_map {
    struct uz_code_region region[UZ_CODE_MAX_REGIONS];
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

static struct uz_code_map g_code;
static uint32_t g_code_buf[UZ_BRANCH_CHUNK / 4U];
static int g_scan_lock;

static int uz_branch_target(uint32_t insn, uint64_t at, uint64_t *target)
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

static void uz_read_lock(void *mm)
{
    if (f_mmap_read_lock)
        f_mmap_read_lock(g_read_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
    else uz_mmap_write_lock(mm);
}

static void uz_read_unlock(void *mm)
{
    if (f_mmap_read_unlock)
        f_mmap_read_unlock(g_read_use_rwsem ? (char *)mm + g_layout.mmap_lock : mm);
    else uz_mmap_write_unlock(mm);
}

static void uz_scan_lock(void)
{
    while (__atomic_exchange_n(&g_scan_lock, 1, __ATOMIC_ACQUIRE))
        f_msleep(1);
}

static void uz_scan_unlock(void)
{
    __atomic_store_n(&g_scan_lock, 0, __ATOMIC_RELEASE);
}

static void uz_scan_begin(void)
{
    __atomic_add_fetch(&g_code.seq, 1, __ATOMIC_ACQ_REL);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static void uz_scan_end(void)
{
    __atomic_add_fetch(&g_code.seq, 1, __ATOMIC_RELEASE);
}

static void uz_code_free(void)
{
    uint8_t *arena = g_code.arena;

    memset(&g_code, 0, sizeof(g_code));
    if (arena) uz_free(arena);
}

static int uz_code_region_read(void *vma, uint64_t *start, uint64_t *end, uint64_t *flags)
{
    *start = *(uint64_t *)((char *)vma + g_layout.vma_start);
    *end = *(uint64_t *)((char *)vma + g_layout.vma_end);
    *flags = *(uint64_t *)((char *)vma + g_layout.vma_flags);
    return (*end > *start && *start < g_user_limit) ? 0 : -1;
}

static struct uz_code_region *uz_code_region_find(uint64_t addr)
{
    uint32_t i, n = __atomic_load_n(&g_code.count, __ATOMIC_ACQUIRE);

    for (i = 0; i < n; ++i) {
        struct uz_code_region *r = &g_code.region[i];

        if (addr >= r->start && addr < r->end) return r;
    }
    return 0;
}

/* The fault path finds the first region that covers an address.  A scan may
 * use its own region as a fast path only when no earlier region overlaps the
 * scanned range; otherwise mark() must follow the same first-match rule. */
static int uz_code_range_overlaps(uint64_t start, uint64_t end,
                                  const struct uz_code_region *self)
{
    uint32_t i, n = __atomic_load_n(&g_code.count, __ATOMIC_ACQUIRE);

    for (i = 0; i < n; ++i) {
        const struct uz_code_region *r = &g_code.region[i];

        if (r == self) continue;
        if (start < r->end && end > r->start) return 1;
    }
    return 0;
}

/* The scan knows its source region, so a same-VMA target is one comparison;
 * cross-VMA targets fall back to the list walk. */
static void uz_code_mark(uint64_t target, const struct uz_code_region *src)
{
    const struct uz_code_region *r = src;
    uint64_t off;

    if (!r || target < r->start || target >= r->end) r = uz_code_region_find(target);
    if (!r) return;
    off = (target - r->start) >> 2;
    /* Concurrent deferred scans may set adjacent bits in the same byte. */
    __atomic_fetch_or(&g_code.arena[r->bitmap_off + (off >> 3)],
                      (uint8_t)(1U << (off & 7U)), __ATOMIC_RELAXED);
}

static int uz_code_hit(uint64_t addr)
{
    struct uz_code_region *r = uz_code_region_find(addr);
    uint64_t off;

    if (!r) return 0;
    off = (addr - r->start) >> 2;
    return (g_code.arena[r->bitmap_off + (off >> 3)] >> (off & 7U)) & 1U;
}

/* Distinguish a page the fault hook will scan later (no leaf yet) from a
 * resident page the module cannot read (execute-only). */
static int uz_page_present(void *mm, uint64_t addr)
{
    uint64_t pte;
    return !uz_pte_read(mm, page_base(addr), &pte);
}

/* Scan one resident page.  0 = read, 1 = not present (deferred to the fault
 * hook), -1 = present but unreadable.  The caller supplies the decode buffer:
 * the build and the mmap/mprotect after hooks are serialized, while deferred
 * fault scans on different CPUs must not share one. */
static int uz_code_scan_page_buf(void *mm, uint64_t page, const struct uz_code_region *src,
                                 uint32_t *buf, unsigned bytes)
{
    struct uz_page *tp = page_find(page);
    uint64_t at;
    int result = 0;

    for (at = page; at < page + g_page_size; at += bytes) {
        uint64_t left = page + g_page_size - at;
        unsigned n = (left > bytes ? bytes : (unsigned)left) >> 2;
        unsigned k;

        /* copy_from_user_nofault() uses an unprivileged load under PAN and
         * therefore faults on the module's own AP[1]=0 leaf.  The immutable
         * snapshot is the same code and is readable from the kernel. */
        if (tp) {
            page_view(tp, at - page, n * 4U, (uint8_t *)buf, 1);
        } else if (f_copy_in(buf, (const void *)(uintptr_t)at, n * 4U)) {
            if (uz_page_present(mm, at)) return -1;
            if (!result) result = 1;
            continue;
        }
        for (k = 0; k < n; ++k) {
            uint64_t target;
            if (uz_branch_target(buf[k], at + 4U * k, &target))
                uz_code_mark(target, src);
        }
    }
    return result;
}

static int uz_code_scan_page(void *mm, uint64_t page, const struct uz_code_region *src)
{
    return uz_code_scan_page_buf(mm, page, src, g_code_buf, UZ_BRANCH_CHUNK);
}

static void uz_code_scan_range(void *mm, uint64_t start, uint64_t end,
                               const struct uz_code_region *src)
{
    uint64_t page;

    for (page = page_base(start); page < end; page += g_page_size) {
        int ret = uz_code_scan_page(mm, page, src);
        if (ret < 0) {
            __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
            return;
        }
    }
}

static int uz_code_collect(uint64_t *bytes)
{
    uint64_t addr = 0, total = 0;
    unsigned n = 0, iter;

    for (iter = 0; iter < 65536U; ++iter) {
        void *vma = f_find_vma(g_sess.mm, (unsigned long)addr);
        uint64_t start, end, flags;

        if (!vma) break;
        if (uz_code_region_read(vma, &start, &end, &flags) || end <= addr ||
            start >= g_user_limit)
            break;
        if (flags & UZ_VM_EXEC) {
            uint64_t size = ((end - start) >> 2) / 8U + 1U;

            if (n == UZ_CODE_MAX_REGIONS || total + size > UZ_CODE_BITMAP_MAX)
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

static void uz_code_build(void)
{
    uint64_t bytes = 0, off = 0, addr = 0, arena;
    unsigned i, iter, pages = 0;

    uz_code_free();
    __atomic_store_n(&g_code.complete, 1, __ATOMIC_RELEASE);
    uz_read_lock(g_sess.mm);
    if (uz_code_collect(&bytes)) goto done;
    arena = bytes + bytes / 2U + 65536U;
    if (arena > UZ_CODE_ARENA_MAX) arena = UZ_CODE_ARENA_MAX;
    if (arena < bytes) arena = bytes;
    g_code.arena = uz_alloc(arena);
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
        if (uz_code_region_read(vma, &start, &end, &flags) || end <= addr ||
            start >= g_user_limit)
            break;
        if (flags & UZ_VM_EXEC) {
            struct uz_code_region *src = uz_code_region_find(start);
            uint64_t page;

            if (src && uz_code_range_overlaps(start, end, src)) src = 0;
            for (page = page_base(start); page < end; page += g_page_size) {
                if (uz_code_scan_page(g_sess.mm, page, src) < 0) {
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
        pr_info("urov-z: codemap regions=%u pages=%u arena=%llu complete=%u\n",
                g_code.count, pages, (unsigned long long)g_code.arena_size,
                __atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE));
    uz_read_unlock(g_sess.mm);
}

/* A later mapping (mmap/mprotect/mremap) may contain a direct branch into a
 * span of the reader code.  Scan it before the syscall returns to EL0;
 * non-resident pages of the new range are left to the fault hook.  A
 * mprotect/mremap range can span several VMAs, so walk each one. */
static void uz_code_add_range(void *mm, uint64_t start, uint64_t len)
{
    uint64_t end, cur;
    void *vma;
    uint64_t vs, ve, flags;
    struct uz_code_region *src;
    uint64_t seg_end, need;

    if (!len) return;
    end = start + len;
    if (end < start || end - start > UZ_CODE_SCAN_MAX) {
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
        return;
    }
    uz_scan_lock();
    if (!overlay_live() || __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE))
        goto out;
    uz_read_lock(mm);
    cur = start;
    while (cur < end) {
        vma = f_find_vma(mm, (unsigned long)cur);
        if (!vma || uz_code_region_read(vma, &vs, &ve, &flags)) break;
        if (cur < vs) cur = vs;
        if (cur >= end) break;
        seg_end = ve < end ? ve : end;
        if (seg_end <= cur) break;
        if (flags & UZ_VM_EXEC) {
            src = uz_code_region_find(cur);
            if (!src || src->end < seg_end) {
                need = ((seg_end - cur) >> 2) / 8U + 1U;
                if (g_code.count == UZ_CODE_MAX_REGIONS ||
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
            if (src && uz_code_range_overlaps(cur, seg_end, src)) src = 0;
            uz_scan_begin();
            uz_code_scan_range(mm, cur, seg_end, src);
            uz_scan_end();
        }
        cur = seg_end;
    }
    uz_read_unlock(mm);
out:
    uz_scan_unlock();
}

/* Existing bitmaps are immutable to readers. Relocation invalidates their
 * address interpretation; do not shift region metadata underneath a proof. */
static void uz_code_mremap(uint64_t old, uint64_t old_len, uint64_t new,
                           uint64_t new_len)
{
    (void)old_len;
    (void)new_len;
    if (old != new) __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
}

static void uz_code_invalidate(void)
{
    __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
}

/* A file-backed code page that REGISTER saw non-resident became present.  The
 * fault hook runs under the fault's mmap read lock, so the page and its VMA
 * are stable and the scan finishes before the task returns to EL0. */
static void uz_code_scan_fault_page(void *mm, uint64_t page)
{
    struct uz_vma_view vma;
    struct uz_code_region *src;
    uint32_t buf[128]; /* 512 bytes: fault context, may run on several CPUs */

    if (uz_vma_read(mm, page, &vma) || !(vma.flags & UZ_VM_EXEC) ||
        !vma.file || page + g_page_size > vma.end) {
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
        return;
    }
    src = uz_code_region_find(page);
    if (!src) {
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
        return;
    }
    if (uz_code_range_overlaps(page, page + g_page_size, src)) src = 0;
    uz_scan_begin();
    if (uz_code_scan_page_buf(mm, page, src, buf, sizeof(buf)) < 0)
        __atomic_store_n(&g_code.complete, 0, __ATOMIC_RELEASE);
    uz_scan_end();
}

static int uz_llsc_skipped(uint64_t ldxr_pc, uint64_t pc)
{
    uint64_t at;
    uint32_t seq1, seq2;

    if (!__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE) ||
        !__atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE))
        return 1;
    seq1 = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);
    if (seq1 & 1U) return 1;
    for (at = ldxr_pc + 4U; at <= pc; at += 4U) {
        if (uz_code_hit(at)) return 1;
    }
    seq2 = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);
    /* A scan that ran while the bits were read may have marked the very slot
     * that was just tested.  Decline instead of assuming it was absent. */
    return seq1 != seq2;
}

/* The later skipped() proof already declines an unusable branch map. Move
 * only that stable decision ahead of the expensive backwards walk. This is
 * deliberately after sample->excl: an exclusive load at PC creates its own
 * reservation and does not depend on the read-before proof. */
static int uz_llsc_map_unusable(void)
{
    uint32_t before = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);
    uint32_t valid = __atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE);
    uint32_t complete = __atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE);
    uint32_t after = __atomic_load_n(&g_code.seq, __ATOMIC_ACQUIRE);

    return !(before & 1U) && before == after && (!valid || !complete);
}

/* A gap store is only recorded, never written while the window is being
 * modeled, so a later load in the same window has to observe it.  Forward the
 * recorded bytes over the freshly read ones, in issue order. */
static void uz_win_forward(const struct uz_llsc *plan, uint64_t address,
                           uint8_t *bytes, unsigned len)
{
    unsigned i, j;

    for (i = 0; i < plan->npend; ++i) {
        const struct uz_llsc_pstore *rec = &plan->pend[i];

        for (j = 0; j < len; ++j) {
            uint64_t cur = address + j;

            if (cur >= rec->address && cur - rec->address < rec->len)
                bytes[j] = rec->bytes[cur - rec->address];
        }
    }
}

/* Read one gap load into the model through the same image/snapshot view the
 * sampled load used, so a window that re-reads the registered page sees exactly
 * what the app would have seen.  Returns 0 to decline. */
static int uz_win_load(struct uro_regs *model, uint32_t insn, void *mm, int allow_fake,
                       const struct uz_llsc *plan)
{
    struct uro_load d;
    uint8_t bytes[UZ_LLSC_BYTES_MAX];
    uint64_t bad = 0;

    if (uro_decode(insn, model, &d)) return 0;
    /* An exclusive load inside the window re-establishes the reservation on its
     * own address, so it cannot be modeled as an ordinary read.  Either
     * uz_win_xload() handled it above with the same width, or the walk has to
     * decline and let the native single step follow it exactly. */
    if (d.excl) return 0;
    if (d.vector || d.multi || !d.total || d.total > sizeof(bytes)) return 0;
    if (!uz_user_range(d.address, d.total) || d.address + d.total < d.address) return 0;
    /* A writeback that also names a destination is unpredictable enough that the
     * model would have to guess the hardware's choice. */
    if (d.writeback && ((d.rt != 31U && d.rn == d.rt) ||
                        (d.count == 2U && d.rt2 != 31U && d.rn == d.rt2)))
        return 0;
    if (read_range(mm, d.address, (unsigned)d.total, allow_fake, bytes, &bad) < 0)
        return 0;
    uz_win_forward(plan, d.address, bytes, (unsigned)d.total);
    uz_commit(model, &d, bytes);
    return 1;
}

/* LDXR/LDAXR inside the window re-establishes the reservation on its own
 * address.  Model it exactly: read the word, update the destination and move the
 * monitored address.  A single exclusive replaces a pair reservation, so the
 * plan becomes a single one. */
static int uz_win_xload(struct uro_regs *model, uint32_t insn, void *mm, int allow_fake,
                        unsigned monsize, uint64_t *mon, struct uz_llsc *plan)
{
    unsigned size = 0, rt = 0, rn = 0;
    uint64_t value = 0, bad = 0;

    if (!uz_is_ldxr(insn, &size, &rt, &rn)) return 0;
    /* A reservation of a different width cannot be the one the STXR observes. */
    if ((1U << size) != monsize) return 0;
    if (rn == 31U || (model->x[rn] & (UINT64_C(1) << size) - 1U) != 0U) return 0;
    if (read_range(mm, model->x[rn], 1U << size, allow_fake, (uint8_t *)&value, &bad) < 0)
        return 0;
    uz_win_forward(plan, model->x[rn], (uint8_t *)&value, 1U << size);
    if (rt != 31U) model->x[rt] = value & uz_win_mask(8U << size);
    *mon = model->x[rn];
    plan->pair = 0;
    model->pc += 4U;
    return 1;
}

/* Record one gap store for the commit and advance the model.  Nothing is
 * written here: a window that turns out not to be completable must leave the
 * app's memory exactly as it was before the native instructions run. */
static int uz_win_store(struct uro_regs *model, uint32_t insn, struct uz_llsc *plan,
                        void *mm, uint64_t mon, unsigned monsize)
{
    struct uro_store st;
    struct uz_llsc_pstore *rec;
    uint64_t done = 0;
    unsigned i, j;

    if (!g_write_gup_flags) return 0;
    if (uro_decode_store(insn, model, &st)) return 0;
    if (st.vector || st.zva || !st.total || st.total > UZ_LLSC_BYTES_MAX) return 0;
    if (!uz_user_range(st.address, st.total) || st.address + st.total < st.address)
        return 0;
    if (plan->npend == UZ_LLSC_MEM_MAX) return 0;
    /* A store that overlaps the monitored word clears the local monitor, so the
     * native STXR would fail: leave the whole window native. */
    if (st.address < mon + (UINT64_C(1) << monsize) &&
        mon < st.address + st.total)
        return 0;
    /* An illegal store must keep its native SIGSEGV instead of being absorbed. */
    while (done < st.total) {
        uint64_t at = st.address + done;
        struct uz_vma_view vma;
        if (uz_vma_read(mm, at, &vma) || !(vma.flags & UZ_VM_WRITE)) return 0;
        done = ((at | (g_page_size - 1U)) + 1U) - st.address;
        if (done > st.total) done = st.total;
    }
    rec = &plan->pend[plan->npend];
    rec->address = st.address;
    rec->len = (unsigned)st.total;
    for (i = 0; i < st.count; ++i) {
        uint64_t value = st.rt[i] == 31U ? 0 : model->x[st.rt[i]];

        for (j = 0; j < st.size; ++j)
            rec->bytes[(uint64_t)i * st.size + j] = (uint8_t)(value >> (8U * j));
    }
    ++plan->npend;
    if (st.writeback) {
        if (st.rn == 31U) model->sp = st.wb;
        else model->x[st.rn] = st.wb;
    }
    model->pc += 4U;
    return 1;
}

/* Walk LDXR;load;<window>;STXR on the post-load register file and stop at the
 * exclusive store that consumes the reservation.  `plan->win` is set only when
 * the modeled sequence provably ends in the successful STXR the untrapped
 * hardware would have executed.  Any other shape declines, which leaves the
 * native instructions to produce the native result. */
static void uz_llsc_walk(struct pt_regs *regs, uint64_t fault_pc, struct uz_llsc *plan)
{
    struct uro_regs model;
    uint64_t mon = plan->base;
    uint64_t start = fault_pc + 4U;
    uint64_t limit = start + (uint64_t)UZ_LLSC_WIN_MAX * 4U;
    uint64_t at = start;
    void *mm = mm_of_task(current);
    int allow_fake;
    unsigned steps, i;

    plan->win = 0;
    plan->npend = 0;
    if (!plan->valid || !f_copy_out || !mm) return;
    if (!uz_user_range(start, 4U) || regs->pc != start) return;
    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = start;
    model.pstate = regs->pstate;
    allow_fake = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE);

    for (steps = 0; steps < UZ_LLSC_WIN_MAX; ++steps) {
        uint32_t insn;
        unsigned size = 0, rs = 0, rt = 0, rt2 = 0, rn = 0;

        if (at < start || at + 4U > limit || (at & 3U)) return;
        if (uz_read_insn(at, &insn)) return;
        model.pc = at;
        if (uz_is_stxp(insn, &size, &rs, &rt, &rt2, &rn)) {
            uint64_t total = 2U * (UINT64_C(1) << size);

            if (!plan->pair || (UINT64_C(1) << size) != plan->size) return;
            if (uz_win_base(&model, rn) != mon || (mon & (total - 1U))) return;
            plan->status_reg = rs;
            plan->release = (insn >> 15) & 1U;
            plan->stxr_pc = at;
            plan->base = mon;
            plan->value = uz_win_gpr(&model, rt);
            plan->value2 = uz_win_gpr(&model, rt2);
            /* Copied field by field: a struct assignment makes the compiler
             * emit a memcpy call the KPM loader cannot resolve. */
            for (i = 0; i < 31; ++i) plan->model.x[i] = model.x[i];
            plan->model.sp = model.sp;
            plan->model.pc = model.pc;
            plan->model.pstate = model.pstate;
            plan->win = 1;
            return;
        }
        if (uz_is_stxr(insn, &size, &rs, &rt, &rn)) {
            uint64_t total = UINT64_C(1) << size;

            /* plan->size is in bytes; the encoding carries log2. */
            if (plan->pair || total != plan->size) return;
            if (uz_win_base(&model, rn) != mon || (mon & (total - 1U))) return;
            plan->store_reg = rt;
            plan->status_reg = rs;
            plan->release = (insn >> 15) & 1U;
            plan->stxr_pc = at;
            plan->base = mon;
            plan->value = uz_win_gpr(&model, rt);
            /* Copied field by field: a struct assignment makes the compiler
             * emit a memcpy call the KPM loader cannot resolve. */
            for (i = 0; i < 31; ++i) plan->model.x[i] = model.x[i];
            plan->model.sp = model.sp;
            plan->model.pc = model.pc;
            plan->model.pstate = model.pstate;
            plan->win = 1;
            return;
        }
        if (uz_is_ldxp(insn, &size, &rt, &rt2, &rn)) return;
        if (uz_win_xload(&model, insn, mm, allow_fake, plan->size, &mon, plan)) {
            at = model.pc;
            continue;
        }
        if (uz_win_load(&model, insn, mm, allow_fake, plan)) {
            at = model.pc;
            continue;
        }
        if (uz_win_store(&model, insn, plan, mm, mon, plan->size)) {
            at = model.pc;
            continue;
        }
        if (uz_win_branch(&model, insn, at)) {
            at = model.pc;
            continue;
        }
        if (uz_win_fp_insn(insn, g_fp16)) {
            if (!plan->fp_valid) {
                if (uz_fp_snapshot(&plan->fp)) return;
                plan->fp_valid = 1;
            }
            if (!uz_win_fp_move(&model, &plan->fp, insn, g_fp16)) return;
            at += 4U;
            continue;
        }
        if (((insn & 0xffff0000U) == 0xd53b0000U ||
             (insn & 0xffff0000U) == 0xd51b0000U)) {
            if (uz_win_sysreg_fp(insn) && !plan->fp_valid) {
                if (uz_fp_snapshot(&plan->fp)) return;
                plan->fp_valid = 1;
            }
            if (!uz_win_sysreg(&model, &plan->fp, insn)) return;
            at += 4U;
            continue;
        }
        if (uz_win_simd_insn(insn) || uz_win_simd_permute_insn(insn)) {
            if (!plan->fp_valid) {
                if (uz_fp_snapshot(&plan->fp)) return;
                plan->fp_valid = 1;
            }
            if (uz_win_simd_insn(insn)) {
                if (!uz_win_simd(&model, &plan->fp, insn)) return;
            } else if (!uz_win_simd_permute(&plan->fp, insn)) {
                return;
            }
            at += 4U;
            continue;
        }
        if (uz_win_alu(&model, insn)) {
            at += 4U;
            continue;
        }
        return;
    }
}

/* What the read-before proof needs to know about the faulting instruction.  An
 * ordinary load consumes the reservation an earlier exclusive load created; an
 * exclusive load creates its own. */
struct uz_sample {
    unsigned excl;      /* 0 none, 1 LDXR/LDAXR, 2 LDXP/LDAXP */
    unsigned acquire;
    unsigned size;      /* bytes per element of an exclusive load */
    uint64_t address;   /* address the faulting instruction accessed */
};

/* The live user register file the single-step path works on. */
static uint64_t uz_pt_gpr(const struct pt_regs *regs, unsigned reg)
{
    return reg == 31U ? regs->sp : regs->regs[reg];
}

/* True when the instruction transfers control to a value held in a register
 * (BR, BLR, RET and the pointer-authenticated forms).  All of them read Xn
 * and branch to it; a failed authentication faults before the sampled load
 * and is therefore not part of this window. */
static int uz_is_indirect_branch(uint32_t insn, unsigned *rn)
{
    if ((insn & 0xfe000000U) != 0xd6000000U) return 0;
    *rn = (insn >> 5) & 31U;
    return 1;
}

/* RET x30 is the compiler's function-boundary encoding.  It is the one
 * indirect branch whose unknown target must not turn every function prologue
 * into a false failure: its target is the caller of the *previous* function,
 * not a transfer into the current LDXR window.  RET xN with N != 30 is not a
 * boundary; it is treated like BR/BLR and its target is recovered at the
 * branch. */
static int uz_is_ret_x30(uint32_t insn)
{
    return insn == UZ_RET_X30;
}

/* 2.28.0 entry proof: the exclusive load must not have been skipped by an
 * indirect transfer into the linear span.  Direct targets in the span are
 * already rejected by uz_llsc_skipped(); this walk covers the one shape the
 * branch-target map cannot see.  It stops at the first control-flow
 * instruction, because anything further back is not on the fall-through path:
 * a real branch there would have left the block, and an unrelated function's
 * trailing RET (the normal layout immediately before a leaf function) must not
 * be misread as an entry into this function.  In the phantom shape the padding
 * in front of the LDXR was not executed, so the value of the branch register
 * at the branch is the value that branch used; the walk rewinds the padding
 * from the LDXR entry to each BR/BLR so a dead write to the branch register
 * cannot substitute a harmless-looking value.  `st` is the register state at
 * the LDXR entry; `cur` follows it back to the instruction being inspected.
 * `floor` is the start of the containing executable VMA; the walk never
 * crosses it.
 *
 * A branch beyond the 2.27.0 64-instruction window is just as visible as one
 * immediately before the LDXR, so the walk uses the same 16,384-instruction
 * budget as the read-before proof and declines if it is exhausted.  Declining
 * is the one-sided direction: it can only turn a would-be false success into
 * the native failure, never manufacture a reservation.  An indirect branch
 * with an unknown target is declined for the same reason, including RET xN:
 * a RET whose xN was clobbered between the branch and the sampled load cannot
 * be distinguished from a RET that jumped into the span. */
static int uz_llsc_entry_skipped(uint64_t ldxr_pc, uint64_t pc,
                                 const struct uz_pre_state *st, uint64_t floor,
                                 struct uz_insn_cursor *cursor, void *mm)
{
    struct uz_pre_state cur;
    uint64_t at = ldxr_pc;
    unsigned scanned, i;
    int rewind_ok = 1;

    for (i = 0; i < 31U; ++i) cur.val[i] = st->val[i];
    cur.sp = st->sp;
    cur.known = st->known;

    for (scanned = 0; scanned < UZ_LLSC_ENTRY_SCAN; ++scanned) {
        uint32_t insn;
        unsigned rn;
        uint64_t target;

        if (at < 4U || at < floor + 4U) return 0;
        at -= 4U;
        if (!uz_user_range(at, 4U) ||
            uz_insn_back_read(cursor, at, &insn, uz_fetch_insns, mm)) return 1;
        if (uz_is_indirect_branch(insn, &rn)) {
            /* Rn == 31 names XZR here, not SP: the transfer targets zero. */
            if (rn == 31U) return 0;
            /* RET x30 is the previous function's boundary.  Use the LDXR-entry
             * state; the instructions between the boundary and the LDXR are
             * this function's prologue, not dead padding. */
            if (uz_is_ret_x30(insn)) {
                if (!uz_pre_known(st, rn)) return 1;
                target = uz_pre_value(st, rn);
                return target > ldxr_pc && target <= pc;
            }
            /* BR/BLR/RET xN: recover the register value at the branch, not at
             * the LDXR.  A dead padding write between the branch and the LDXR
             * must not be allowed to change the target the branch actually
             * used. */
            if (!rewind_ok || !uz_pre_known(&cur, rn)) return 1;
            target = uz_pre_value(&cur, rn);
            return target > ldxr_pc && target <= pc;
        }
        /* A direct branch cannot add an entry the branch-target map misses. */
        if ((insn & 0xfc000000U) == 0x14000000U ||      /* B */
            (insn & 0xfc000000U) == 0x94000000U ||      /* BL */
            (insn & 0xff000010U) == 0x54000000U ||      /* B.cond */
            (insn & 0x7e000000U) == 0x34000000U ||      /* CBZ/CBNZ */
            (insn & 0x7e000000U) == 0x36000000U)        /* TBZ/TBNZ */
            return 0;
        if (uz_is_exception_insn(insn)) return 0;
        if (rewind_ok && uz_pre_step(insn, &cur)) rewind_ok = 0;
    }
    /* The budget ran out before a control-flow instruction: the branch that
     * could have skipped the LDXR may be further back.  Decline. */
    return 1;
}

/* Linear read-before proof.  Walk backwards from the faulting instruction to
 * the most recent load-exclusive, rewinding the register value table one
 * instruction at a time (uz_pre_step).  When the exclusive load is reached the
 * base register's recovered value is the address the hardware reserved; a
 * later exclusive store to it has to be completed by the handler because the
 * exception return that served the sampled read already cleared the hardware
 * monitor.
 *
 * 2.25.0 only required that the base register was never written.  2.26.0 asks
 * for its value instead, so an in-place write that provably left it unchanged
 * (ADD s,s,#0, an add/sub/eor chain whose net effect is zero, a value copied
 * through another still-known register) no longer loses the reservation.
 *
 * 2.27.0 decodes the exclusive instruction first, then rewinds with the
 * natural-alignment invariant of its access size: a mask write that can only
 * clear the low log2(size) bits of the base is the identity for every address
 * the hardware could have reserved, even though it is not invertible for an
 * arbitrary input.  It also rejects the one entry shape the branch-target map
 * cannot see (uz_llsc_entry_skipped).
 *
 * The sampled access itself does not participate: it has not committed at the
 * fault, so it may overwrite the LDXR destination, sample a pair or vector
 * register, or write back over the base.  Only the LDXR base matters. */
static void uz_llsc_prepare(const struct uro_regs *regs, uint64_t pc,
                            const struct uz_sample *sample, struct uz_llsc *out)
{
    struct uz_pre_state st;
    struct uz_insn_cursor cursor;
    struct uz_insn_memo *memo;
    uint32_t insn = 0;
    unsigned scanned, words = 0, lsize = 0, lrn = 0, pair = 0, acquire = 0;
    uint64_t ldxr_pc = 0, at, base, floor = 0, guard = 0;
    void *mm = mm_of_task(current);

    memset(out, 0, sizeof(*out));
    if (!f_copy_out || !sample) return;
    UZ_PERF_ADD(llsc_prepares, 1);
    if (sample->excl) {
        /* The faulting instruction is the reservation: no walk is needed and
         * no earlier exclusive load can still be live. */
        out->base = sample->address;
        out->size = sample->size;
        out->pair = sample->excl == 2U;
        out->acquire = sample->acquire;
        out->valid = 1;
        return;
    }
    if (uz_llsc_map_unusable()) {
        UZ_PERF_ADD(map_declines, 1);
        return;
    }
    if (pc < 4U || !uz_user_range(pc - 4U, 4U)) return;
    memo = uz_insn_memo_acquire(mm, pc);
    if (uz_insn_memo_match(memo, mm, pc)) {
        UZ_PERF_ADD(cache_hits, 1);
        uz_insn_memo_release(memo);
        return;
    }
    UZ_PERF_ADD(cache_misses, 1);

    /* First pass: locate the reservation instruction and its access size.
     * The value proof needs the alignment that a load-exclusive that reached
     * the sampled access must have had, and that is only known after the
     * instruction is decoded. */
    at = pc - 4U;
    uz_insn_cursor_reset(&cursor);
    UZ_PERF_ADD(scan_calls, 1);
    for (scanned = 0; scanned < UZ_LLSC_PRE_SCAN; ++scanned) {
        unsigned size_enc, rt, rt2, rs, rn;

        if (at < 4U || !uz_user_range(at, 4U)) goto scan_done;
        if (uz_insn_back_read(&cursor, at, &insn, uz_fetch_insns, mm)) {
            guard = at;
            goto scan_done;
        }
        ++words;
        if (memo) memo->probe[UZ_LLSC_PRE_SCAN - words] = insn;
        if (uz_is_ldxr(insn, &size_enc, &rt, &rn)) {
            ldxr_pc = at;
            lsize = 1U << size_enc;
            lrn = rn;
            pair = 0;
            acquire = (insn >> 15) & 1U;
            break;
        }
        if (uz_is_ldxp(insn, &size_enc, &rt, &rt2, &rn)) {
            ldxr_pc = at;
            lsize = 1U << size_enc;
            lrn = rn;
            pair = 1;
            acquire = (insn >> 15) & 1U;
            break;
        }
        /* CLREX, an exclusive store and an exception are the only instructions
         * in between that can clear the monitor; a branch target inside the
         * span is rejected below by uz_llsc_skipped(). */
        if (uz_is_stxr(insn, &size_enc, &rs, &rt, &rn) ||
            uz_is_stxp(insn, &size_enc, &rs, &rt, &rt2, &rn) ||
            uz_is_clrex(insn) || uz_is_exception_insn(insn))
            goto scan_done;
        at -= 4U;
    }
scan_done:
    UZ_PERF_ADD(scan_words, words);
    if (memo && !ldxr_pc) {
        memo->mm = mm;
        memo->pc = pc;
        memo->guard = guard;
        memo->words = words;
        memcpy(memo->saved, memo->probe + UZ_LLSC_PRE_SCAN - words, words * 4U);
    }
    uz_insn_memo_release(memo);
    if (!ldxr_pc) return;

    /* The entry walk never crosses the start of the executable VMA that holds
     * the LDXR.  Reaching that start is a legitimate fall-through entry (the
     * loader enters the mapping there); crossing it would let the walk read an
     * unrelated mapping or walk off the user address space. */
    {
        struct uz_vma_view vma;
        if (uz_vma_read(mm, ldxr_pc, &vma) || !(vma.flags & UZ_VM_EXEC)) return;
        floor = vma.start;
    }

    /* Second pass: rewind with the alignment invariant.  A mask write that can
     * only clear the low log2(size) bits of the base is the identity for every
     * value the hardware could have reserved. */
    uz_pre_reset(&st, regs);
    uz_insn_cursor_reset(&cursor);
    for (at = pc - 4U; at > ldxr_pc; at -= 4U) {
        if (uz_insn_back_read(&cursor, at, &insn, uz_fetch_insns, mm)) return;
        if (uz_pre_step_aligned(insn, &st, lsize - 1U)) return;
    }
    /* The rewind must still know the base.  A class it could not invert leaves
     * it unknown and the plan declines; the native instructions then report
     * exactly the result the hardware would have reported without the module. */
    if (!uz_pre_known(&st, lrn)) return;
    base = uz_pre_value(&st, lrn);
    /* lsize is already in bytes, so the mask is the access size minus one. */
    if (base & (lsize - 1U)) return;
    if (uz_llsc_skipped(ldxr_pc, pc)) return;
    uz_insn_cursor_reset(&cursor);
    if (uz_llsc_entry_skipped(ldxr_pc, pc, &st, floor, &cursor, mm)) return;

    out->base = base;
    out->size = lsize;
    out->base_reg = lrn;
    out->pair = pair;
    out->acquire = acquire;
    out->valid = 1;
}

/* Commit a walked window: replay the gap stores the walk recorded, perform the
 * STXR's own store, publish it into the image and hand the app the modeled
 * registers, a zero status register and PC past the STXR.  A commit that cannot
 * finish leaves PC on the instruction after the sampled load, so the native
 * instructions run instead of a partially modeled window. */
static void uz_llsc_commit(struct pt_regs *regs, uint64_t fault_pc,
                           const struct uz_llsc *plan)
{
    uint64_t values[2];
    uint64_t base;
    unsigned total, i;

    if (!plan->valid || regs->pc != fault_pc + 4U) return;
    if (plan->pair) {
        base = plan->base;
        values[0] = plan->value;
        values[1] = plan->value2;
        total = plan->size * 2U;
    } else if (plan->win) {
        base = plan->base;
        values[0] = plan->value;
        values[1] = 0;
        total = plan->size;
    } else {
        return;
    }
    if (!total || !uz_user_range(base, total) || base + total < base) return;
    {
        void *mm = mm_of_task(current);

        uz_write_enter();
        /* Both shapes replay the gap stores the walk recorded; for a pair plan
         * the walk never records any, so the loop is simply empty. */
        for (i = 0; i < plan->npend; ++i) {
            if (uz_write_live(mm, plan->pend[i].address, plan->pend[i].bytes,
                              plan->pend[i].len)) {
                uz_write_leave();
                return;
            }
            uz_rearm_written(mm, plan->pend[i].address, plan->pend[i].len);
        }
        if (f_copy_out((void *)(uintptr_t)base, values, total)) {
            uz_write_leave();
            return;
        }
        /* The STXR/STXP may legitimately write a registered page.  The write
         * already reached the live bytes through GUP; publish the same bytes so
         * the next read of the page still sees one coherent view. */
        if (mm == g_sess.mm)
            uz_image_store(base, (const uint8_t *)values, total);
        else if (mm)
            uz_shadow_store_range(mm, base, (const uint8_t *)values, total);
        if (mm && uz_page_for_fault(mm, base))
            uz_rearm_written(mm, base, total);
        uz_write_leave();
    }
    if (plan->acquire) __asm__ volatile("dmb ishld" : : : "memory");
    if (plan->release) __asm__ volatile("dmb ishst" : : : "memory");
    for (i = 0; i < 31; ++i) regs->regs[i] = plan->model.x[i];
    regs->sp = plan->model.sp;
    regs->pstate = plan->model.pstate;
    if (plan->fp_valid) f_fp_update(&plan->fp);
    if (plan->status_reg != 31U) regs->regs[plan->status_reg] = 0;
    regs->pc = plan->stxr_pc + 4U;
    __atomic_fetch_add(&g_sess.llsc, 1, __ATOMIC_RELAXED);
}

/* ------------------------------------------------------- store absorption */

/* One store instruction is visible to EL0 in two places: the live page (which
 * a detector can read through instruction fetch, smaps and the page cache)
 * and the overlay image.  The write fault therefore cannot simply be handed
 * to Linux: that would replace the trapped leaf and retire the page's image.
 *
 * Instead the handler decodes the store, performs the same bytes on the live
 * page through the kernel's own GUP write path (which keeps the normal COW,
 * dirty accounting and page-cache semantics), publishes those bytes into the
 * image and snapshot, and retires the instruction.  The AP[1]=0 trap stays;
 * the next read is still served from the image.  Failure falls back to the
 * pre-2.15 behaviour for that page: restore AP[1], mark it dead and let the
 * native store run.
 */
static int uz_store_bytes(const struct uro_store *st, const struct pt_regs *regs,
                          const struct uz_fpstate *fp, uint8_t *out)
{
    unsigned i, j;

    if (st->zva) {
        memset(out, 0, st->size);
        return 0;
    }
    for (i = 0; i < st->count; ++i) {
        uint8_t *dst = out + (uint64_t)i * st->size;
        unsigned rt = st->rt[i];

        if (st->vector) {
            if (!fp || rt > 31U) return -1;
            memcpy(dst, fp->vregs[rt], st->size);
            continue;
        }
        if (rt > 30U) {
            memset(dst, 0, st->size);
            continue;
        }
        for (j = 0; j < st->size; ++j)
            dst[j] = (uint8_t)(regs->regs[rt] >> (8U * j));
    }
    return 0;
}

/* Read the bytes a reader would see for [address, address+len): image for
 * registered segments, nofault uaccess for the rest.  Only used by the write
 * emulator, where the faulting page is always registered. */
static int uz_read_logical(void *mm, uint64_t address, uint8_t *out, unsigned len)
{
    uint64_t done = 0;

    (void)mm;

    while (done < len) {
        uint64_t cur = address + done;
        uint64_t page = page_base(cur);
        unsigned off = (unsigned)(cur - page);
        unsigned seg = g_page_size - off;
        struct uz_page *p;

        if (seg > len - done) seg = len - (unsigned)done;
        p = uz_page_for_fault(mm, cur);
        if (p) page_view_mm(mm, p, off, seg, out + done, 0);
        else if (f_copy_in(out + done, (const void *)(uintptr_t)cur, seg))
            return -1;
        done += seg;
    }
    return 0;
}

/* Complete a write on the live bytes through the kernel's COW/GUP path and,
 * for the owning mm, publish the same bytes into every registered page. */
static int uz_write_live(void *mm, uint64_t address, const uint8_t *data, unsigned len)
{
    uint64_t done = 0;

    if (!g_write_gup_flags) return -1;
    while (done < len) {
        uint64_t cur = address + done;
        uint64_t page = page_base(cur);
        unsigned off = (unsigned)(cur - page);
        unsigned seg = g_page_size - off;

        if (seg > len - done) seg = len - (unsigned)done;
        if (uz_access_vm(mm, cur, (void *)(uintptr_t)(data + done), (int)seg,
                         g_write_gup_flags) != (int)seg)
            return -1;
        {
            struct uz_page *p = uz_page_for_fault(mm, cur);

            if (p) {
                if (mm == g_sess.mm) {
                    page_store_bytes(p, off, data + done, seg);
                } else {
                    struct uz_shadow *sh = uz_shadow_get(mm, p->index);

                    if (sh) uz_shadow_store(sh, off, data + done, seg);
                }
            }
        }
        done += seg;
    }
    return 0;
}

/* A GUP/COW write can install a writable leaf with AP[1] set.  Re-assert the
 * trap immediately; the fault hook is not guaranteed to run for every GUP
 * path, and a forked child's split VMA can miss the shadow rearm check. */
static void uz_rearm_written(void *mm, uint64_t address, unsigned len)
{
    uint64_t done = 0;
    int changed = 0;

    while (done < len) {
        uint64_t cur = address + done;
        uint64_t page = page_base(cur);
        unsigned seg = g_page_size - (unsigned)(cur - page);
        struct uz_page *p;

        if (seg > len - done) seg = len - (unsigned)done;
        p = uz_page_for_fault(mm, cur);
        if (p && !__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) {
            int ret = page_set_ap_any(mm, page, 0);

            if (ret > 0) changed = 1;
        }
        done += seg;
    }
    if (changed) flush_tlb_all();
}

static uint64_t uz_atomic_mask(unsigned size)
{
    return size >= 8U ? ~UINT64_C(0) : ((UINT64_C(1) << (size * 8U)) - 1U);
}

static int64_t uz_atomic_signed(uint64_t value, unsigned size)
{
    if (size >= 8U) return (int64_t)value;
    if (value & (UINT64_C(1) << (size * 8U - 1U)))
        value |= ~((UINT64_C(1) << (size * 8U)) - 1U);
    return (int64_t)value;
}

static uint64_t uz_atomic_apply(unsigned op, uint64_t old, uint64_t src, unsigned size)
{
    uint64_t mask = uz_atomic_mask(size);
    int64_t a, b;

    src &= mask;
    switch (op) {
    case URO_ATOMIC_ADD: return (old + src) & mask;
    case URO_ATOMIC_CLR: return old & ~src & mask;
    case URO_ATOMIC_EOR: return (old ^ src) & mask;
    case URO_ATOMIC_SET: return (old | src) & mask;
    case URO_ATOMIC_SWP: return src;
    case URO_ATOMIC_SMAX:
        a = uz_atomic_signed(old, size); b = uz_atomic_signed(src, size);
        return (uint64_t)(a > b ? a : b) & mask;
    case URO_ATOMIC_SMIN:
        a = uz_atomic_signed(old, size); b = uz_atomic_signed(src, size);
        return (uint64_t)(a < b ? a : b) & mask;
    case URO_ATOMIC_UMAX:
        return (old > src ? old : src) & mask;
    case URO_ATOMIC_UMIN:
        return (old < src ? old : src) & mask;
    default: return old;
    }
}

static void uz_atomic_reg(struct pt_regs *regs, unsigned reg, uint64_t value,
                          unsigned size)
{
    if (reg == 31U) return;
    regs->regs[reg] = size >= 8U ? value : value & uz_atomic_mask(size);
}

/* Decode and complete one LSE atomic RMW.  CAS failure is a normal outcome:
 * the old value is written back to Rs and nothing is stored. */
static int uz_atomic_emulate(struct pt_regs *regs, uint64_t far, void *mm,
                              uint32_t opcode, const struct uro_regs *model)
{
    struct uro_atomic a;
    uint8_t old[16], newb[16];
    uint64_t mask, o0, o1, n0, n1, src, expect, expect2;
    unsigned i;

    if (uro_decode_atomic(opcode, model, &a) || a.address != far) return -1;
    if (!uz_user_range(a.address, a.total)) return -1;
    for (i = 0; i < (a.count == 2U ? 2U : 1U); ++i) {
        uint64_t at = a.address + (uint64_t)i * a.size;
        struct uz_vma_view vma;
        if (uz_vma_read(mm, at, &vma) || !(vma.flags & UZ_VM_WRITE)) return -1;
    }
    mask = uz_atomic_mask(a.size);
    /* One trapped store at a time: the read below and the write at the end must
     * not interleave with another emulated RMW, or one update is lost. */
    uz_write_enter();
    if (uz_read_logical(mm, a.address, old, (unsigned)a.total)) goto out;
    o0 = 0; o1 = 0;    for (i = 0; i < a.size; ++i) {
        o0 |= (uint64_t)old[i] << (8U * i);
        if (a.count == 2U)
            o1 |= (uint64_t)old[a.size + i] << (8U * i);
    }

    if (a.op == URO_ATOMIC_CAS) {
        expect = a.rs == 31U ? 0 : (regs->regs[a.rs] & mask);
        expect2 = a.rs2 == 31U ? 0 : (regs->regs[a.rs2] & mask);
        if (a.count == 1U ? (o0 != expect) : (o0 != expect || o1 != expect2)) {
            /* CAS writes the observed old value back to the expected pair. */
            uz_atomic_reg(regs, a.rs, o0, a.size);
            if (a.count == 2U) uz_atomic_reg(regs, a.rs2, o1, a.size);
            if (a.acquire) __asm__ volatile("dmb ishld" : : : "memory");
            regs->pc += 4U;
            uz_write_leave();
            return 0;
        }
        n0 = a.rt == 31U ? 0 : (regs->regs[a.rt] & mask);
        n1 = a.rt2 == 31U ? 0 : (regs->regs[a.rt2] & mask);
    } else {
        src = a.rs == 31U ? 0 : (regs->regs[a.rs] & mask);
        n0 = uz_atomic_apply(a.op, o0, src, a.size);
        n1 = 0;
    }

    for (i = 0; i < a.size; ++i) {
        newb[i] = (uint8_t)(n0 >> (8U * i));
        if (a.count == 2U)
            newb[a.size + i] = (uint8_t)(n1 >> (8U * i));
    }
    if (uz_write_live(mm, a.address, newb, (unsigned)a.total)) goto out;
    uz_rearm_written(mm, a.address, (unsigned)a.total);
    if (a.return_old) {
        if (a.op == URO_ATOMIC_CAS) {
            uz_atomic_reg(regs, a.rs, o0, a.size);
            if (a.count == 2U) uz_atomic_reg(regs, a.rs2, o1, a.size);
        } else {
            uz_atomic_reg(regs, a.rt, o0, a.size);
        }
    }
    if (a.acquire) __asm__ volatile("dmb ishld" : : : "memory");
    if (a.release) __asm__ volatile("dmb ishst" : : : "memory");
    regs->pc += 4U;
    uz_flush_icache_all();
    uz_write_leave();
    return 0;
out:
    uz_write_leave();
    return -1;
}

/* A store-exclusive to a trapped page cannot succeed after the exception
 * return: the PE clears the local monitor.  Report the native failure and
 * retire the instruction without touching the page, so the overlay survives
 * instead of being retired by an STXR/STXP probe. */
static int uz_exclusive_store_emulate(struct pt_regs *regs, uint64_t far)
{
    uint32_t insn;
    unsigned size, rs, rt, rt2, rn;
    uint64_t total;

    if ((regs->pc & 3U) || uz_read_insn(regs->pc, &insn)) return -1;
    if (uz_is_stxr(insn, &size, &rs, &rt, &rn)) {
        total = 1U << size;
        if (regs->regs[rn] != far || regs->regs[rn] & (total - 1U)) return -1;
    } else if (uz_is_stxp(insn, &size, &rs, &rt, &rt2, &rn)) {
        total = 2U << size;
        if (regs->regs[rn] != far || regs->regs[rn] & (total - 1U)) return -1;
    } else {
        return -1;
    }
    if (rs != 31U) regs->regs[rs] = 1;
    regs->pc += 4U;
    return 0;
}

static int uz_store_emulate(struct pt_regs *regs, uint64_t far, struct uz_page *wp,
                            void *mm)
{
    struct uz_fpstate fp;
    struct uro_regs model;
    struct uro_store st;
    uint32_t opcode;
    uint8_t data[64];
    uint64_t done;
    unsigned i;

    (void)wp;
    if ((regs->pc & 3U) || uz_read_insn(regs->pc, &opcode))
        return -1;
    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = regs->pc;
    model.pstate = regs->pstate;
    /* LSE RMW and pair/single exclusive stores are not ordinary stores, and
     * some of their encodings can resemble a normal store.  Try them first. */
    {
        struct uro_atomic probe;

        if (!uro_decode_atomic(opcode, &model, &probe)) {
            if (!uz_atomic_emulate(regs, far, mm, opcode, &model))
                return 0;
            return -1;
        }
    }
    if ((opcode & 0xffffffe0U) == 0xd50b7420U) {
        uint64_t dczid, sctlr;

        __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
        __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
        if (!(sctlr & (UINT64_C(1) << 14)) ||
            uro_decode_zva(opcode, &model, dczid, &st)) return -1;
    } else if (uro_decode_store(opcode, &model, &st)) {
        if (!uz_exclusive_store_emulate(regs, far))
            return 0;
        return -1;
    }
    if (!st.total || st.total > sizeof(data) || far < st.address ||
        far - st.address >= (st.zva ? st.total : 1U))
        return -1;
    if (!uz_user_range(st.address, st.total))
        return -1;
    /* Validate every page the access touches before changing any byte. */
    for (done = 0; done < st.total; ) {
        uint64_t at = st.address + done;
        struct uz_vma_view vma;
        if (uz_vma_read(mm, at, &vma) || !(vma.flags & UZ_VM_WRITE)) return -1;
        done = ((at | (g_page_size - 1U)) + 1U) - st.address;
        if (done > st.total) done = st.total;
    }
    if (!g_write_gup_flags)
        return -1;
    if (st.vector && !st.zva && uz_fp_snapshot(&fp))
        return -1;
    if (uz_store_bytes(&st, regs, st.vector && !st.zva ? &fp : 0, data))
        return -1;
    uz_write_enter();
    if (uz_write_live(mm, st.address, data, (unsigned)st.total)) {
        uz_write_leave();
        return -1;
    }
    uz_rearm_written(mm, st.address, (unsigned)st.total);
    uz_write_leave();

    if (st.writeback) {
        if (st.rn == 31U) regs->sp = st.wb;
        else regs->regs[st.rn] = st.wb;
    }
    regs->pc += 4U;
    uz_flush_icache_all();
    return 0;
}

/* ------------------------------------------------ deferred native replay */

/* Every EL0 write to a registered page takes the AP[1] trap and is completed
 * here, so one lock around the read-modify-write and its publication makes two
 * concurrent LSE atomics behave like the single hardware instruction they
 * replace.  Without it both could read the same image value and lose one
 * update.  The kernel's GUP write path can sleep, so the wait is a short yield
 * loop followed by an msleep; writers are rare and never held for long. */
static int g_write_busy;

static void uz_write_enter(void)
{
    unsigned spins = 0;

    while (__atomic_exchange_n(&g_write_busy, 1, __ATOMIC_ACQ_REL)) {
        if (spins++ < 512U) __asm__ volatile("yield" : : : "memory");
        else f_msleep(1);
    }
}

static void uz_write_leave(void)
{
    __atomic_store_n(&g_write_busy, 0, __ATOMIC_RELEASE);
}

/* The store decoder covers every ordinary A64 store, but not the SIMD
 * single-lane forms, STTR, the SVE/SME store classes or future shapes.  Letting
 * the page go native on such a store was the last write-side fingerprint.
 *
 * 2.17.0 instead lets the hardware execute the unknown store itself:
 *
 *   1. snapshot the live page, restore AP[1] on its leaf, and invalidate that
 *      translation on this CPU only, so other CPUs keep the trap entry;
 *   2. arm AArch64 software step for this task (SPSR.SS + MDSCR_EL1.SS) and let
 *      the kernel's native page-fault path resolve any COW;
 *   3. the retried store runs at EL0 and the software-step exception (EC 0x32)
 *      is taken before the next instruction; the handler diffs the live page
 *      against the snapshot, publishes the changed bytes into the image and
 *      restores the AP[1] trap.
 *
 * The diff is taken from the page itself, so no instruction encoding is needed
 * and SVE/SME stores are covered by the same path.  A task migration between
 * the fault and the step is covered by re-arming MDSCR_EL1.SS in __switch_to;
 * a step that can no longer be delivered (the native fault turned into a
 * signal) is finished by the next data abort of that task. */
#define UZ_REPLAY_MAX 2U
#define UZ_REPLAY_PAGES 2U
#define UZ_REPLAY_TRIES 3U
#define UZ_MDSCR_SS (UINT64_C(1) << 0)
#define UZ_PSR_SS (UINT64_C(1) << 21)
#define UZ_EC_SOFTSTP_LOW 0x32UL

struct uz_replay {
    void *mm;
    void *task;
    uint64_t pc;
    uint64_t page[UZ_REPLAY_PAGES];
    uint32_t index[UZ_REPLAY_PAGES];
    uint32_t npages;
    uint32_t tries;
    uint32_t used;
};

static struct uz_replay g_replay[UZ_REPLAY_MAX];
static int g_replay_active;
static int g_step_active;
static int g_replay_block;
static int g_ss_ok;
static void *f_debug_exception;
static void *f_switch_to;
static int g_dbg_hooked;
static int g_switch_hooked;
/* A step that had to be cancelled still owes the app exactly one consumed
 * software-step exception; remember which task it belongs to. */
static void *g_step_orphan_mm;
static void *g_step_orphan_task;

static inline uint64_t uz_mdscr_read(void)
{
    uint64_t value;

    __asm__ volatile("mrs %0, mdscr_el1" : "=r"(value));
    return value;
}

static inline void uz_mdscr_write(uint64_t value)
{
    __asm__ volatile("msr mdscr_el1, %0" : : "r"(value));
    __asm__ volatile("isb" : : : "memory");
}

static void uz_tlb_flush_local(uint64_t va)
{
    __asm__ volatile("dsb ishst" : : : "memory");
    __asm__ volatile("tlbi vae1, %0" : : "r"(va >> 12) : "memory");
    __asm__ volatile("dsb ish" : : : "memory");
    __asm__ volatile("isb" : : : "memory");
}

static struct uz_replay *uz_replay_current(void)
{
    uint32_t i;

    for (i = 0; i < UZ_REPLAY_MAX; ++i) {
        struct uz_replay *r = &g_replay[i];

        if (!__atomic_load_n(&r->used, __ATOMIC_ACQUIRE)) continue;
        if (r->mm != mm_of_task(current) || r->task != current) continue;
        return r;
    }
    return 0;
}

/* Publish the bytes the native store changed in one page. */
static void uz_replay_publish(struct uz_replay *r, uint32_t n)
{
    struct uz_page *p = page_by_index(r->index[n]);
    unsigned off = 0, len = (unsigned)g_page_size;

    if (!p || !p->pre || !p->post ||
        f_copy_in(p->post, (const void *)(uintptr_t)r->page[n], len)) return;
    while (off < len) {
        unsigned start;

        if (p->post[off] == p->pre[off]) {
            ++off;
            continue;
        }
        start = off;
        while (off < len && p->post[off] != p->pre[off]) ++off;
        if (r->mm == g_sess.mm) {
            page_store_bytes(p, start, p->post + start, off - start);
        } else {
            struct uz_shadow *sh = uz_shadow_get(r->mm, p->index);

            if (sh) uz_shadow_store(sh, start, p->post + start, off - start);
        }
    }
}

/* Finish a replay: optionally publish the store's bytes, then put the AP[1]
 * trap back on every page the instruction touched. */
static void uz_replay_end(struct uz_replay *r, int publish)
{
    uint32_t i;
    int changed = 0;

    for (i = 0; i < r->npages; ++i) {
        struct uz_page *p = page_by_index(r->index[i]);

        if (!p) continue;
        if (publish) uz_replay_publish(r, i);
        __atomic_store_n(&p->replay, 0, __ATOMIC_RELEASE);
    }
    for (i = 0; i < r->npages; ++i) {
        struct uz_page *p = page_by_index(r->index[i]);

        if (!p) continue;
        if (page_set_ap_any(r->mm, r->page[i], 0) > 0) changed = 1;
    }
    if (changed) flush_tlb_all();
    memset(r, 0, sizeof(*r));
    __atomic_sub_fetch(&g_replay_active, 1, __ATOMIC_RELEASE);
}

/* A replay whose step can no longer be delivered must still consume the step
 * exception the kernel will raise for this task, or it would become a
 * SIGTRAP. */
static void uz_replay_cancel(void)
{
    struct uz_replay *r = uz_replay_current();

    if (!r) return;
    uz_replay_end(r, 0);
    g_step_orphan_mm = mm_of_task(current);
    g_step_orphan_task = current;
}

static int uz_replay_begin(struct pt_regs *regs, void *mm, struct uz_page *p, uint64_t far)
{
    struct uz_replay *r;
    uint64_t page = page_base(far);
    uint32_t i;
    int fresh = 0;

    if (!g_ss_ok || !mm || !p || !p->pre || !p->post || (regs->pstate & UZ_PSR_SS) ||
        __atomic_load_n(&g_replay_block, __ATOMIC_ACQUIRE) ||
        (uz_mdscr_read() & UZ_MDSCR_SS))
        return -1;
    r = uz_replay_current();
    if (r) {
        if (r->pc != regs->pc) return -1;
        for (i = 0; i < r->npages; ++i)
            if (r->page[i] == page) return 1; /* origin still has to COW */
        if (r->npages == UZ_REPLAY_PAGES || r->tries >= UZ_REPLAY_TRIES) return -1;
    } else {
        for (i = 0; i < UZ_REPLAY_MAX; ++i)
            if (!__atomic_load_n(&g_replay[i].used, __ATOMIC_ACQUIRE)) break;
        if (i == UZ_REPLAY_MAX) return -1;
        r = &g_replay[i];
        r->mm = mm;
        r->task = current;
        r->pc = regs->pc;
        r->npages = 0;
        r->tries = 0;
        __atomic_store_n(&r->used, 1, __ATOMIC_RELEASE);
        __atomic_add_fetch(&g_replay_active, 1, __ATOMIC_RELEASE);
        fresh = 1;
    }
    if (__atomic_exchange_n(&p->replay, 1, __ATOMIC_ACQ_REL)) {
        if (g_verbose) pr_info("urov-z: replay page busy\n");
        goto fail;
    }
    if (page_set_ap_any(mm, page, 1) < 0) {
        if (g_verbose) pr_info("urov-z: replay leaf restore failed\n");
        __atomic_store_n(&p->replay, 0, __ATOMIC_RELEASE);
        goto fail;
    }
    uz_tlb_flush_local(page);
    if (f_copy_in(p->pre, (const void *)(uintptr_t)page, g_page_size)) {
        if (g_verbose) pr_info("urov-z: replay pre read failed\n");
        if (page_set_ap_any(mm, page, 0) > 0) flush_tlb_all();
        __atomic_store_n(&p->replay, 0, __ATOMIC_RELEASE);
        goto fail;
    }
    r->index[r->npages] = p->index;
    r->page[r->npages] = page;
    ++r->npages;
    ++r->tries;
    uz_mdscr_write(uz_mdscr_read() | UZ_MDSCR_SS);
    regs->pstate |= UZ_PSR_SS;
    return 0;
fail:
    if (fresh) {
        memset(r, 0, sizeof(*r));
        __atomic_sub_fetch(&g_replay_active, 1, __ATOMIC_RELEASE);
    }
    return -1;
}

/* Does the current task already own a replay for `pc` on this page?  A retry
 * that faults again on the same instruction and page is the kernel's write
 * protection (COW) still in the way, not a second undecodable store. */
static int uz_replay_owns(uint64_t pc, uint32_t index)
{
    struct uz_replay *r = uz_replay_current();
    uint32_t i;

    if (!r || r->pc != pc) return 0;
    for (i = 0; i < r->npages; ++i)
        if (r->index[i] == index) return 1;
    return 0;
}

/* Software-step exception for the current task.  Returns 1 when the exception
 * belongs to a replay and must be consumed. */
static int uz_replay_step(struct pt_regs *regs)
{
    struct uz_replay *r = uz_replay_current();
    void *mm = mm_of_task(current);

    if (!r) {
        if (!g_step_orphan_task || g_step_orphan_mm != mm || g_step_orphan_task != current)
            return 0;
        g_step_orphan_mm = 0;
        g_step_orphan_task = 0;
        uz_mdscr_write(uz_mdscr_read() & ~UZ_MDSCR_SS);
        regs->pstate &= ~UZ_PSR_SS;
        return 1;
    }
    uz_replay_end(r, 1);
    uz_mdscr_write(uz_mdscr_read() & ~UZ_MDSCR_SS);
    regs->pstate &= ~UZ_PSR_SS;
    return 1;
}

/* Wait for all replays to finish before the session is torn down.  A new
 * replay is refused while the wait runs, so this terminates unless a task is
 * stuck inside the kernel; in that case the caller fails closed. */
static int uz_replay_quiesce(void)
{
    unsigned i;

    __atomic_store_n(&g_replay_block, 1, __ATOMIC_RELEASE);
    for (i = 0; i < 4000U; ++i) {
        if (!__atomic_load_n(&g_replay_active, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&g_step_active, __ATOMIC_ACQUIRE)) return 0;
        f_msleep(1);
    }
    return -1;
}

static void uz_replay_unblock(void)
{
    __atomic_store_n(&g_replay_block, 0, __ATOMIC_RELEASE);
}

/* ------------------------------------- native single-step for a read window */

/* The byte-level model stops at shapes it does not reproduce (FP arithmetic,
 * SIMD permutes, SVE/SME data processing, long runs).  Instead the handler lets
 * the CPU execute the window natively, one instruction at a time, and stops
 * before the consuming exclusive store.  Every debug exception has already
 * cleared the hardware reservation, so a matching STXR/STXP is completed by the
 * handler exactly as the modeled path does.  There is no instruction-class or
 * length limit: only exclusive stores and exception-generating instructions
 * need attention, and those are handled by uz_step_next()/uz_step_prev(). */
struct uz_step {
    void *mm;
    void *task;
    uint64_t base;
    uint64_t next_pc;
    uint64_t stxr_pc;
    unsigned size;
    unsigned status_reg;
    unsigned store_reg;
    unsigned release;
    unsigned acquire;    /* the emulated exclusive load was LDAXR/LDAXP */
    unsigned steps;
    unsigned valid;      /* no monitor-clearing event seen since the reservation */
    unsigned started;    /* next_pc names an instruction that has executed */
    unsigned pair;       /* the reservation is an LDXP/STXP pair */
    unsigned data_reg;   /* pair LDXP destinations (for diagnostics) */
    unsigned data_reg2;
    uint32_t used;
};
static struct uz_step g_step[2];

static struct uz_step *uz_step_current(void)
{
    uint32_t i;

    for (i = 0; i < 2U; ++i) {
        struct uz_step *s = &g_step[i];

        if (!__atomic_load_n(&s->used, __ATOMIC_ACQUIRE)) continue;
        if (s->mm != mm_of_task(current) || s->task != current) continue;
        return s;
    }
    return 0;
}

static void uz_step_arm(struct pt_regs *regs)
{
    uz_mdscr_write(uz_mdscr_read() | UZ_MDSCR_SS);
    regs->pstate |= UZ_PSR_SS;
}

static void uz_step_disarm(struct pt_regs *regs)
{
    uz_mdscr_write(uz_mdscr_read() & ~UZ_MDSCR_SS);
    regs->pstate &= ~UZ_PSR_SS;
}

static void uz_step_end(struct uz_step *s)
{
    memset(s, 0, sizeof(*s));
    __atomic_sub_fetch(&g_step_active, 1, __ATOMIC_RELEASE);
}

static void uz_step_cancel(void)
{
    struct uz_step *s = uz_step_current();

    if (!s) return;
    uz_mdscr_write(uz_mdscr_read() & ~UZ_MDSCR_SS);
    uz_step_end(s);
}

/* Interpret the instruction that the previous software step executed.  LDXR
 * moves the modeled reservation to its own address; CLREX, another exclusive
 * operation, and an exception clear it.  A plain store to the monitored word
 * does not clear the local monitor on this core (measured: a same-PE store or
 * LSE atomic to the watched word still lets the native STXR succeed), so the
 * window may run those natively without invalidation. */
static void uz_step_prev(struct pt_regs *regs, struct uz_step *s)
{
    uint32_t insn;
    unsigned size, rs, rt, rt2, rn;

    if (!s->started) return;
    if (uz_read_insn(s->next_pc, &insn)) {
        s->valid = 0;
        return;
    }
    if (uz_is_ldxp(insn, &size, &rt, &rt2, &rn)) {
        /* Rn == 31 names SP, which is a legal exclusive base. */
        s->pair = 1;
        s->base = uz_pt_gpr(regs, rn);
        s->size = 1U << size;
        s->data_reg = rt;
        s->data_reg2 = rt2;
        s->valid = 1;
        return;
    }
    if (uz_is_ldxr(insn, &size, &rt, &rn)) {
        uint64_t base;

        (void)rt;
        /* LDXR has no writeback; the retired base is the address. */
        base = uz_pt_gpr(regs, rn);
        size = 1U << size;
        s->pair = 0;
        if (base != s->base || size != s->size) {
            s->base = base;
            s->size = size;
        }
        s->valid = 1;
        return;
    }
    if (uz_is_stxr(insn, &size, &rs, &rt, &rn) ||
        uz_is_stxp(insn, &size, &rs, &rt, &rt2, &rn) ||
        uz_is_clrex(insn) || uz_is_exception_insn(insn)) {
        s->valid = 0;
    }
}

/* Complete the STXR the native run stopped in front of. */
static int uz_step_force(struct pt_regs *regs, struct uz_step *s)
{
    uint32_t insn;
    uint64_t value;
    unsigned size, rs, rt, rn;
    void *mm;

    if (uz_read_insn(s->stxr_pc, &insn) ||
        !uz_is_stxr(insn, &size, &rs, &rt, &rn))
        return -1;
    if ((1U << size) != s->size || uz_pt_gpr(regs, rn) != s->base ||
        !uz_user_range(s->base, s->size))
        return -1;
    value = rt == 31U ? 0 : regs->regs[rt];
    mm = mm_of_task(current);
    uz_write_enter();
    if (f_copy_out((void *)(uintptr_t)s->base, &value, s->size)) {
        uz_write_leave();
        return -1;
    }
    if (mm == g_sess.mm)
        uz_image_store(s->base, (const uint8_t *)&value, s->size);
    else if (mm)
        uz_shadow_store_range(mm, s->base, (const uint8_t *)&value, s->size);
    if (mm && uz_page_for_fault(mm, s->base))
        uz_rearm_written(mm, s->base, s->size);
    uz_write_leave();
    if (s->acquire) __asm__ volatile("dmb ishld" : : : "memory");
    if (s->release) __asm__ volatile("dmb ishst" : : : "memory");
    if (s->status_reg != 31U) regs->regs[s->status_reg] = 0;
    regs->pc = s->stxr_pc + 4U;
    __atomic_fetch_add(&g_sess.llsc, 1, __ATOMIC_RELAXED);
    return 0;
}

/* Complete the STXP that consumes an LDXP pair reservation. */
static int uz_step_force_pair(struct pt_regs *regs, struct uz_step *s)
{
    uint32_t insn;
    uint64_t values[2];
    unsigned size, rs, rt, rt2, rn, total;
    void *mm;

    if (uz_read_insn(s->stxr_pc, &insn) ||
        !uz_is_stxp(insn, &size, &rs, &rt, &rt2, &rn))
        return -1;
    if ((1U << size) != s->size || uz_pt_gpr(regs, rn) != s->base)
        return -1;
    total = s->size * 2U;
    if (!uz_user_range(s->base, total) || s->base + total < s->base) return -1;
    values[0] = rt == 31U ? 0 : regs->regs[rt];
    values[1] = rt2 == 31U ? 0 : regs->regs[rt2];
    mm = mm_of_task(current);
    uz_write_enter();
    if (f_copy_out((void *)(uintptr_t)s->base, values, total)) {
        uz_write_leave();
        return -1;
    }
    if (mm == g_sess.mm)
        uz_image_store(s->base, (const uint8_t *)values, total);
    else if (mm)
        uz_shadow_store_range(mm, s->base, (const uint8_t *)values, total);
    if (mm && uz_page_for_fault(mm, s->base))
        uz_rearm_written(mm, s->base, total);
    uz_write_leave();
    if (s->acquire) __asm__ volatile("dmb ishld" : : : "memory");
    if (s->release) __asm__ volatile("dmb ishst" : : : "memory");
    if (s->status_reg != 31U) regs->regs[s->status_reg] = 0;
    regs->pc = s->stxr_pc + 4U;
    __atomic_fetch_add(&g_sess.llsc, 1, __ATOMIC_RELAXED);
    return 0;
}

/* Validate the instruction at PC and either arm one step, force the consuming
 * exclusive store, or decline.  Everything except an exclusive store or an
 * exception-generating instruction runs natively. */
static int uz_step_next(struct pt_regs *regs, struct uz_step *s)
{
    uint32_t insn;
    unsigned size, rs, rt, rt2, rn;

    if (uz_read_insn(regs->pc, &insn)) return -1;
    if (uz_is_stxr(insn, &size, &rs, &rt, &rn)) {
        if (s->pair) return -1;
        if ((1U << size) != s->size || uz_pt_gpr(regs, rn) != s->base) return -1;
        /* A prior store/CLREX/exception cleared the reservation.  Let the
         * native STXR execute and report the failure the untrapped hardware
         * would have reported; faking success here would be a new feature. */
        if (!s->valid) return -1;
        s->stxr_pc = regs->pc;
        s->status_reg = rs;
        s->store_reg = rt;
        s->release = (insn >> 15) & 1U;
        return uz_step_force(regs, s) ? -1 : 1;
    }
    if (uz_is_stxp(insn, &size, &rs, &rt, &rt2, &rn)) {
        if (!s->pair) return -1;
        if ((1U << size) != s->size || uz_pt_gpr(regs, rn) != s->base)
            return -1;
        if (!s->valid) return -1;
        s->stxr_pc = regs->pc;
        s->status_reg = rs;
        s->release = (insn >> 15) & 1U;
        return uz_step_force_pair(regs, s) ? -1 : 1;
    }
    /* Any other instruction may run natively.  A target-page load faults and
     * is completed by the abort path, which calls uz_step_resume(); LDXR and
     * CLREX are interpreted by uz_step_prev() after they retire; a store,
     * atomic or vector instruction neither changes the modeled reservation on
     * this core nor needs decoding.  This is what removes the old fail-closed
     * classes (SIMD/SVE/SME stores, undecodable encodings, long windows). */
    if (uz_is_exception_insn(insn)) return -1;
    s->next_pc = regs->pc;
    s->started = 1;
    uz_step_arm(regs);
    return 0;
}

/* Arm the first step, or complete an STXR that is already at PC. */
static int uz_step_begin(struct pt_regs *regs, const struct uz_llsc *plan)
{
    struct uz_step *s = 0;
    unsigned i;
    int rc;

    if (!g_ss_ok || !plan->valid || !plan->size ||
        (regs->pstate & UZ_PSR_SS) || uz_step_current() || uz_replay_current())
        return -1;
    for (i = 0; i < 2U; ++i) {
        if (!__atomic_load_n(&g_step[i].used, __ATOMIC_ACQUIRE)) {
            s = &g_step[i];
            break;
        }
    }
    if (!s) return -1;
    s->mm = mm_of_task(current);
    s->task = current;
    s->base = plan->base;
    s->size = plan->size;
    s->valid = 1;
    s->started = 0;
    s->pair = plan->pair;
    s->acquire = plan->acquire;
    __atomic_store_n(&s->used, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&g_step_active, 1, __ATOMIC_RELEASE);
    rc = uz_step_next(regs, s);
    if (rc < 0) {
        uz_step_end(s);
        return -1;
    }
    if (rc > 0) {
        uz_step_end(s);
        return 0;
    }
    return 0;
}

/* Software-step exception for a native read window.  Returns 1 when the
 * exception belongs to this mechanism and must be consumed. */
static int uz_step_handle(struct pt_regs *regs)
{
    struct uz_step *s = uz_step_current();
    int rc;

    if (!s) return 0;
    uz_step_disarm(regs);
    uz_step_prev(regs, s);
    /* Nothing left to complete once the reservation is gone (CLREX, an
     * exclusive store that already ran, an exception, or a retired window):
     * stop stepping instead of following the task one instruction at a time
     * until its next exclusive store.  This is pure overhead reduction - the
     * modeled outcome of a later STXR is failure either way. */
    if (!s->valid) {
        uz_step_end(s);
        return 1;
    }
    rc = uz_step_next(regs, s);
    if (rc) uz_step_end(s);
    return 1;
}

/* Re-arm after a trapped read from a registered page interrupted the replay.
 * The load has already been committed to pt_regs, so validation resumes at the
 * following instruction. */
static int uz_step_resume(struct pt_regs *regs)
{
    struct uz_step *s = uz_step_current();
    int rc;

    if (!s) return -1;
    uz_step_prev(regs, s);
    if (!s->valid) {
        uz_step_end(s);
        return 1;
    }
    rc = uz_step_next(regs, s);
    if (rc) uz_step_end(s);
    return rc;
}

/* Software-step exception (EC 0x32) for a task with a deferred replay: publish
 * the bytes the native store changed and re-arm the AP[1] trap.  The kernel
 * would otherwise turn our step into a SIGTRAP. */
static void uz_dbg_before(hook_fargs3_t *args, void *udata)
{
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;

    (void)udata;
    if (!regs || !user_mode(regs) || compat_user_mode(regs) ||
        ((esr >> 26) & 0x3fUL) != UZ_EC_SOFTSTP_LOW)
        return;
    if (uz_step_handle(regs)) {
        args->ret = 0;
        args->skip_origin = 1;
        return;
    }
    if (!uz_replay_step(regs)) return;
    args->ret = 0;
    args->skip_origin = 1;
}

/* MDSCR_EL1.SS is per CPU while SPSR_EL1.SS is per task.  If the replaying
 * task migrates between the fault and its retry, re-arm the hardware bit on
 * the CPU that is about to run it. */
static void uz_switch_after(hook_fargs2_t *args, void *udata)
{
    void *mm;
    struct uz_step *step;

    (void)args;
    (void)udata;
    step = uz_step_current();
    if (!__atomic_load_n(&g_replay_active, __ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&g_step_active, __ATOMIC_ACQUIRE) && !g_step_orphan_task)
        return;
    mm = mm_of_task(current);
    if (!mm) return;
    if (uz_replay_current() || step ||
        (g_step_orphan_task == current && g_step_orphan_mm == mm))
        uz_mdscr_write(uz_mdscr_read() | UZ_MDSCR_SS);
}

/* Snapshot every registered page into the child's private shadow at fork
 * time, so a later owner SET cannot change what the child observes and a child
 * write never leaks into the parent image. */
static void uz_copy_mm_after(hook_fargs2_t *args, void *udata)
{
    void *tsk = (void *)args->arg1;
    void *parent, *child;
    uint64_t ref;
    uint32_t i;

    (void)udata;
    if ((long)args->ret) return;
    if (!overlay_live() ||         __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE))
        return;
    parent = mm_of_task(current);
    if (!parent || parent != __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE)) return;
    child = tsk ? mm_of_task(tsk) : 0;
    if (!child || child == parent) return;
    ref = session_get_mm(parent);
    if (!ref) return;
    if ((uint64_t)g_shadow_used + g_sess.page_count <= g_shadow_max) {
        void *held = f_get_task_mm(tsk);
        for (i = 0; i < g_sess.page_count; ++i) {
            struct uz_page *p = &g_sess.pages[i];
            struct uz_shadow *sh;

            if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
            sh = uz_shadow_get(child, p->index);
            if (!sh) break;
            if (held) { sh->mm_ref = held; held = 0; }
            if (!sh->page.want || sh->page.dead) continue;
            /* File-backed RX VMAs need not copy their PTEs at fork. Populate
             * then arm the child's leaf before the task can run. */
            if (uz_access_vm(child, p->base, sh->page.snapshot, (int)g_page_size, 0) !=
                (int)g_page_size) {
                __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
                continue;
            }
            uz_mmap_write_lock(child);
            if (page_set_ap_any(child, p->base, 0) < 0)
                __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
            uz_mmap_write_unlock(child);
        }
        flush_tlb_all();
        if (held) f_mmput(held);
    }
    uz_reader_exit(&g_readers, ref);
}

/* Emulate one load at `pc`: serve the bytes from the registered page images
 * (fake or registration snapshot) plus nofault uaccess for segments outside
 * the session.  `far` is the data-abort address for the PAGE_AP path (0 and
 * check_far==0 for the instruction-trap modes) and must fall inside the
 * decoded access range.  On success the model is committed to `regs`. A
 * negative return is a fail-closed condition; *bad then names the address
 * whose access would have raised the original fault.  When `llsc` is not NULL
 * the function also records, before committing any register, whether a
 * bounded exclusive sequence can be completed by the caller. */
/* LDTR/LDTRB/LDTRH/LDTRSW are the unprivileged forms of the unscaled load.
 * At EL0 they perform exactly the same access as LDUR/LDURB/LDURH/LDURSW, so
 * a trapped read can be completed through the ordinary encoding instead of
 * becoming a synthetic SIGSEGV that an app could use as a read-trap signal.
 * Only the mode bits 11:10 differ; the address and writeback rules are the
 * same and the decoder already rejects every other unprivileged combination. */
static uint32_t uz_unprivileged_alias(uint32_t insn)
{
    unsigned cls = insn & 0x3f000000U;

    if (cls != 0x38000000U && cls != 0x3c000000U) return 0;
    if ((insn & (1U << 21)) || ((insn >> 10) & 3U) != 2U) return 0;
    return insn & ~0x00000c00U;
}

static int uz_emulate_load(struct pt_regs *regs, uint64_t pc, uint32_t opcode,
                           uint64_t far, int check_far, uint64_t *bad,
                           struct uz_llsc *llsc)
{
    struct uro_regs model;
    struct uro_load load;
    uint64_t total;
    uint8_t bytes[64];
    int use_fake = 0, covered;
    unsigned i;
    void *mm = mm_of_task(current);
    struct uz_page *read_page;

    *bad = 0;
    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp;
    model.pc = pc;
    model.pstate = regs->pstate;

    /* LSE RMW can report a read ESR. Share the one opcode/model with the load
     * decoder; a successful atomic still cancels native step at the caller. */
    if (!uz_atomic_emulate(regs, far, mm, opcode, &model)) return 1;
    {
        uint64_t reject = UINT64_C(31) | (UINT64_C(1) << 20);

        if (!uz_step_current()) reject |= UINT64_C(1) << 21;
        if ((model.pstate & reject) || (pc & 3U) || !uz_user_range(pc, 4))
            return -1;
    }
    if (uro_decode(opcode, &model, &load)) {
        uint32_t alias = uz_unprivileged_alias(opcode);

        if (!alias || uro_decode(alias, &model, &load)) return -2;
    }
    /* A vector load has no GPR destination to fall back on, so without the
     * native FPSIMD helpers the honest answer is the old fail-closed signal. */
    if (load.vector && !g_fp_ready) return -6;
    total = load.total;
    if (!total || total > sizeof(bytes) || !uz_user_range(load.address, total) ||
        (load.writeback && !uz_user_range(load.wb, 1)))
        return -3;
    if (check_far && (far < load.address || far - load.address >= total)) return -3;
    UZ_PERF_ADD(loads, 1);
    if (llsc) {
        struct uz_sample sample;

        memset(&sample, 0, sizeof(sample));
        memset(llsc, 0, sizeof(*llsc));
        sample.address = load.address;
        if (load.excl) {
            /* The trapped instruction is itself the exclusive load, so the
             * reservation it creates has to be carried into the handler. */
            sample.excl = load.excl;
            sample.acquire = load.acquire;
            sample.size = load.size;
        }
        if (            !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE))
            uz_llsc_prepare(&model, pc, &sample, llsc);
    }

    use_fake = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE);
    if (total <= g_page_size - (load.address & (g_page_size - 1U)) &&
        (read_page = uz_page_for_fault(mm, load.address)) != NULL &&
        !__atomic_load_n(&read_page->dead, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&read_page->want, __ATOMIC_ACQUIRE)) {
        /* Resolve again after the proof; mremap may have published a new
         * index. Descriptor slots and their buffers remain stable. */
        uz_ext_drain(mm, read_page);
        page_view_mm(mm, read_page, load.address & (g_page_size - 1U),
                     (unsigned)total, bytes, !use_fake);
        covered = 1;
        UZ_PERF_ADD(single_page, 1);
    } else {
        /* Locate and copy each segment once. No registers are committed until
         * every segment (including any native neighbour) has succeeded. */
        covered = read_range(mm, load.address, (unsigned)total, use_fake, bytes, bad);
        if (covered < 0) return covered;
    }

    if (load.multi) {
        if (uz_fp_commit_multi(&load, bytes)) return -6;
        if (load.writeback) {
            if (load.rn == 31U) model.sp = load.wb;
            else model.x[load.rn] = load.wb;
        }
        model.pc += 4U;
    } else if (load.vector) {
        /* Commit the vector state first; a refused helper leaves every GPR and
         * PC untouched, which is what fail-closed promises. */
        if (uz_fp_commit(&load, bytes)) return -6;
        if (load.writeback) {
            if (load.rn == 31U) model.sp = load.wb;
            else model.x[load.rn] = load.wb;
        }
        model.pc += 4U;
    } else {
        uz_commit(&model, &load, bytes);
    }
    commit_model(regs, &model);
    if (covered && use_fake)
        __atomic_fetch_add(&g_sess.hits, 1, __ATOMIC_RELAXED);
    else if (covered)
        __atomic_fetch_add(&g_sess.replays, 1, __ATOMIC_RELAXED);
    return 0;
}

/* ---------------------------------------------------------- exception hooks */

static int emulate_or_signal(struct pt_regs *regs, uint32_t opcode, uint64_t far,
                             int check_far, struct uz_llsc *llsc)
{
    uint64_t bad = 0, pc = regs->pc;
    int result = uz_emulate_load(regs, pc, opcode, far, check_far, &bad, llsc);

    if (result == -EAGAIN) {
        UZ_HEALTH_ADD(fault_retries);
        return 1; /* mmap writer: retry with unchanged regs */
    }
    if (result >= 0) return result;
    session_count_failure(pc, result);
    force_segv(result == -5 ? bad : far);
    return result;
}

static void uz_abort_before(hook_fargs4_t *args, void *udata)
{
    uint64_t far = args->arg0;
    uint64_t esr = args->arg1;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    unsigned ec = (esr >> 26) & 0x3fUL;
    int ap_read;
    uint32_t opcode;
    uint64_t ref;
    uint64_t access_flags = 0;

    (void)udata;
    if (!regs || !user_mode(regs) || compat_user_mode(regs) ||
        ec != UZ_EC_DABT_LOW ||
        (esr & (UZ_FSC_MASK | UZ_ESR_FNV | UZ_ESR_S1PTW | UZ_ESR_EA)) != UZ_FSC_PERM_LEAF ||
        (g_abort_has_iss2 && (esr & UZ_ESR_ISS2)) ||
        !uz_user_range(far, 1))
        return;
    /* A pending deferred replay expects at most a retry of the same
     * instruction (a cross-page store faulting on its next page).  Any other
     * fault means the native retry cannot complete, so finish the replay
     * before the new fault is handled. */
    if (__atomic_load_n(&g_replay_active, __ATOMIC_ACQUIRE)) {
        struct uz_replay *rp = uz_replay_current();

        if (rp && rp->pc != regs->pc) uz_replay_cancel();
    }
    ap_read = ec == UZ_EC_DABT_LOW && !(esr & (UZ_ESR_WNR | UZ_ESR_CM));
    /* A registered read is the only fault that may interrupt a native replay:
     * it is committed and the step is re-armed.  Anything else (a write, an
     * instruction abort or a read outside the session) ends the replay. */
    if (__atomic_load_n(&g_step_active, __ATOMIC_ACQUIRE) &&
        !(ap_read))
        uz_step_cancel();
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
        if (!ap_read && !(ec == UZ_EC_DABT_LOW && (esr & UZ_ESR_WNR)))
            return;
        /* Take the reader reference before touching the page array: release
         * frees it only after both reader epochs are drained. */
        ref = session_get_any();
        if (ref) {
            if (uz_page_for_fault(reader, far))
                goto serve;
            uz_reader_exit(&g_readers, ref);
            /* The mapping was retired (munmap/MAP_FIXED) or moved while a
             * forked child still holds the inherited trap leaf.  Restore the
             * child's PTE and retry natively instead of turning it into a
             * SIGSEGV. */
            if (uz_repair_trap(reader, far)) {
                args->ret = 0;
                args->skip_origin = 1;
                return;
            }
        }
        if (uz_retired_has(page_base(far)) &&
            uz_repair_trap(reader, far)) {
            args->ret = 0;
            args->skip_origin = 1;
        }
        return;
    }

serve:
    {
        void *mm = mm_of_task(current);
        struct uz_page *page = uz_page_for_fault(mm, far);
        struct uz_vma_view vma;
        int rc;
        if (!page) goto out;
        rc = uz_vma_read(mm, far, &vma);
        if (rc == -EAGAIN) {
            UZ_HEALTH_ADD(fault_retries);
            /* Retry the faulting instruction after the queued mmap writer
             * has progressed. Neither PC nor destination registers change. */
            args->ret = 0;
            args->skip_origin = 1;
            goto out;
        }
        if (rc || !uz_mapping_matches(&vma, page_base(far), g_page_shift,
                (uintptr_t)page->vma_file, page->file_page, page->vma_start,
                page->vma_end, g_layout.vma_pgoff_ok)) goto out;
        access_flags = vma.flags;
        if (ap_read && !(access_flags & UZ_VM_READ)) goto out;
        if ((!g_experimental_writes && (access_flags & UZ_VM_WRITE)) ||
            __atomic_load_n(&page->dead, __ATOMIC_ACQUIRE)) {
            int restored;
            if (!__atomic_exchange_n(&page->dead, 1, __ATOMIC_ACQ_REL))
                UZ_HEALTH_ADD(retired_writes);
            restored = page_set_ap_any(mm, page_base(far), 1);
            __atomic_store_n(&page->want, 0, __ATOMIC_RELEASE);
            if (restored >= 0) __atomic_store_n(&page->armed, 0, __ATOMIC_RELEASE);
            /* Once AP[1] is already native, a store may still need Linux's
             * normal COW/permission handling. Consuming an unchanged PTE
             * would retry the same AP[2] fault forever. */
            if (restored > 0 || restored == -EAGAIN) {
                if (restored == -EAGAIN) UZ_HEALTH_ADD(fault_retries);
                args->ret = 0;
                args->skip_origin = 1;
            }
            goto out;
        }
    }
    /* A store that the VMA would accept natively is absorbed: its bytes are
     * applied to the live page through the kernel's COW path and published
     * into the image, while the AP[1] trap stays installed.  A store the
     * decoder cannot reproduce is executed by the hardware itself under
     * software step (uz_replay_begin).  Only when that mechanism is not
     * available does the pre-2.17 handoff run: restore AP[1], mark this page
     * dead, and let Linux execute the original store.
     *
     * A store to a VMA that is not writable is left alone: the native outcome
     * is SIGSEGV, and it must stay SIGSEGV (a detector must not be able to
     * kill the overlay with an illegal write it catches). */
    if (ec == UZ_EC_DABT_LOW &&
        (esr & UZ_ESR_WNR) && !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        void *mm = mm_of_task(current);
        struct uz_page *wp = uz_page_for_fault(mm, far);

        if (wp && mm && __atomic_load_n(&wp->armed, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&wp->dead, __ATOMIC_ACQUIRE)) {
            unsigned long flags = (unsigned long)access_flags;

            if (flags & UZ_VM_WRITE) {
                int rp;

                if (uz_replay_owns(regs->pc, wp->index)) goto out;
                if (!uz_store_emulate(regs, far, wp, mm)) {
                    args->ret = 0;
                    args->skip_origin = 1;
                    goto out;
                }
                /* The store is retried natively: restore AP[1] on this CPU and
                 * let the kernel resolve any COW.  No skip_origin here. */
                rp = uz_replay_begin(regs, mm, wp, far);
                if (rp >= 0) goto out;
                uz_replay_cancel();
            }
            if (flags & UZ_VM_WRITE) {
                /* Keep the child's copy writable-native rather than touching
                 * the owner's session state. */
                if (page_set_ap_any(mm, page_base(far), 1) >= 0) {
                    __atomic_store_n(&wp->dead, 1, __ATOMIC_RELEASE);
                    __atomic_store_n(&wp->armed, 0, __ATOMIC_RELEASE);
                    flush_tlb_all();
                }
            }
        }
        goto out;
    }

    if (ap_read) {
        void *mm = mm_of_task(current);
        struct uz_page *page = uz_page_for_fault(mm, far);
        uint64_t fault_pc = regs->pc;
        struct uz_llsc llsc;
        int emulated = -1;

        memset(&llsc, 0, sizeof(llsc));
        if (!page || !__atomic_load_n(&page->armed, __ATOMIC_ACQUIRE)) {
            uz_step_cancel();
            goto out;
        }
        if (uz_fetch_insns(mm, fault_pc, &opcode, sizeof(opcode))) {
            session_count_failure(regs->pc, -EFAULT);
            force_segv(far);
        } else {
            emulated = emulate_or_signal(regs, opcode, far, 1, &llsc);
        }
        /* The exception return already cleared the local exclusive monitor;
         * the bridge only restores an outcome the native sequence would have
         * had.  It is attempted after the load committed, and only when the
         * load succeeded. */
        if (emulated == 1) {
            uz_step_cancel();
        } else if (!emulated && uz_step_current()) {
            (void)uz_step_resume(regs);
        } else if (!emulated) {
            int stepped;

            uz_llsc_walk(regs, fault_pc, &llsc);
            if (llsc.win) {
                uz_llsc_commit(regs, fault_pc, &llsc);
            } else {
                stepped = uz_step_begin(regs, &llsc);
                (void)stepped;
            }
        } else {
            uz_step_cancel();
        }
    } else {
        goto out;
    }
    args->ret = 0;
    args->skip_origin = 1;
out:
    uz_reader_exit(&g_readers, ref);
}

static void uz_mm_fault_before(hook_fargs4_t *args, void *udata)
{
    const char *vma = (const char *)args->arg0;

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
    /* A non-NULL pt_regs marks a user-mode uaccess fault; GUP passes NULL.
     * Only the uaccess form may have its trap re-armed here: doing that for a
     * GUP fault would make the retry loop forever. */
    {
        int argc = (int)(uintptr_t)udata;

        if (argc == 5)
            args->local.data7 = (uintptr_t)((hook_fargs8_t *)args)->arg4;
        else if (argc == 4)
            args->local.data7 = (uintptr_t)args->arg3;
        else
            args->local.data7 = 0;
    }
}

/* A fault-in just (re)created the target page PTE from the VMA protection.
 * Re-apply the AP[1] trap so a page that was evicted or
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
static void uz_mm_fault_after(hook_fargs4_t *args, void *udata)
{
    /* The three-, four-, five- and eight-register wrappers share this prefix. */
    void *mm = (void *)args->local.data0;
    uint64_t page = page_base(args->local.data1);
    uint64_t ref;
    int ret = 0;

    (void)udata;
    if ((args->ret & UZ_FAULT_INCOMPLETE) || !uz_user_range(page, g_page_size)) return;
    ref = session_get_mm(mm);
    if (!ref) {
        ref = session_get_any();
        if (!ref) return;
        if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) && overlay_live()) {
            struct uz_page *p = uz_page_for_fault(mm, page);
            /* Child foreign writes have no external-writer capture buffers.
             * Preserve native semantics instead of rearming a stale image. */
            if (p && (args->local.data2 & UZ_FAULT_WRITE) && !uz_internal_current())
                uz_retire_written_page(mm, p, page);
            else
                ret = ap_shadow_rearm(mm, page, args->local.data3, args->local.data4,
                                      args->local.data5, args->local.data6);
        }
        if (ret > 0)
            flush_tlb_all();
        else if (ret < 0 && ret != -ENOENT)
            __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
        uz_reader_exit(&g_readers, ref);
        return;
    }
    if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
        {
            struct uz_page *p = page_find(page);
            if (p && __atomic_load_n(&p->replay, __ATOMIC_ACQUIRE)) {
                /* A deferred native replay owns this leaf: the store is about
                 * to be retried and the step handler re-arms the trap. */
                ret = 0;
            } else if (p && (args->local.data2 & UZ_FAULT_WRITE) &&
                       !uz_internal_current()) {
                /* A writer outside the module faulted the page in for write:
                 * read()/O_DIRECT into the mapping, process_vm_writev or a
                 * remote writer.  The live page is the destination and must
                 * keep receiving the bytes, so the trap cannot stay dropped
                 * forever; snapshot the live bytes first, then re-arm AP[1].
                 * A uaccess write retries through the PTE while EL1 still has
                 * write permission (AP[2] clear), so it cannot loop here.  A
                 * GUP write keeps the leaf until uz_gup_slow_after() has the
                 * page array, which is where the trap is put back. */
                if (g_verbose)
                    pr_info("urov-z: foreign write fault page=%llx regs=%d\n",
                            (unsigned long long)page, args->local.data7 ? 1 : 0);
                if (mm == g_sess.mm) {
                    (void)uz_ext_capture(mm, p, page);
                    if (args->local.data7 && !__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) {
                        uint64_t pte;

                        if (!uz_pte_read(mm, page, &pte) && !(pte & PTE_RDONLY)) {
                            ret = ap_shadow_rearm(mm, page, args->local.data3,
                                args->local.data4, args->local.data5, args->local.data6);
                        }
                    }
                } else if (page_set_ap_any(mm, page, 1) > 0) {
                    ret = 1;
                }
            } else if (p && __atomic_load_n(&p->want, __ATOMIC_ACQUIRE) &&
                !__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) {
                ret = ap_shadow_rearm(mm, page, args->local.data3,
                    args->local.data4, args->local.data5, args->local.data6);
            }
            else if (!p && !(args->local.data2 & UZ_FAULT_WRITE) &&
                     __atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE))
                uz_code_scan_fault_page(mm, page);
        }
    }
    if (ret > 0) flush_tlb_all();
    if (ret < 0 && ret != -ENOENT)
        __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
    uz_reader_exit(&g_readers, ref);
}

/* ------------------------------------------------------------- control ops */

static void session_free_storage(void)
{
    void *mm = g_sess.mm;
    unsigned i, n = g_sess.page_count;

    uz_code_free();
    uz_free(g_insn_memo);
    g_insn_memo = 0;
    /* Remember the page bases (not the images) so an orphaned trap in a
     * forked child can still be recognised and restored after the session is
     * gone.  The array is only ever compared by address. */
    g_retired_count = n < UZ_RETIRED_MAX ? n : UZ_RETIRED_MAX;
    if (g_retired_count && g_sess.pages)
        for (i = 0; i < g_retired_count; ++i) g_retired[i] = g_sess.pages[i].base;
    uz_shadow_free_all();
    uz_free(g_shadow_arena);
    g_shadow_arena = 0;
    uz_free(g_shadow);
    g_shadow = 0;
    g_shadow_max = 0;
    uz_free(g_sess.pages);
    uz_free(g_sess.index);
    uz_free(g_sess.index_spare);
    uz_free(g_sess.arena);
    memset(&g_sess, 0, sizeof(g_sess));
    __atomic_store_n(&g_owner, 0, __ATOMIC_RELEASE);
    if (mm) f_mmput(mm);
}

/* Keep the read handlers available for replay until the traps are restored.
 * First stop PTE rearm and wait out any rearm that was already in progress. */
static int release_session(void)
{
    void *mm;
    int ret = 0;

    if (!overlay_live()) return 0;
    /* Child snapshots retain their mm. Do not remove their fault handler
     * until they have exited or exec'd into a different address space. */
    if (uz_child_live()) return -EBUSY;
    /* A deferred native replay still owns an AP[1]-restored leaf and a pending
     * software step.  Refuse to tear the page array down underneath it; the
     * normal case drains in a few microseconds. */
    if (uz_replay_quiesce()) {
        uz_replay_unblock();
        return -EBUSY;
    }
    mm = g_sess.mm;
    __atomic_store_n(&g_suspend, 1, __ATOMIC_RELEASE);
    drain_readers(uz_readers_flip(&g_readers));
    ret = ap_disarm_pages(&g_sess, mm);
    if (ret) {
        __atomic_store_n(&g_degraded, 1, __ATOMIC_RELEASE);
        uz_replay_unblock();
        return ret;
    }
    drain_readers(uz_readers_close(&g_readers));
    __atomic_store_n(&g_state, UZ_STATE_OFF, __ATOMIC_RELEASE);
    session_free_storage();
    __atomic_store_n(&g_degraded, 0, __ATOMIC_RELEASE);
    uz_replay_unblock();
    return 0;
}

static void reap_dead_session(void)
{
    if (overlay_live() && !mm_has_live_user(g_sess.mm)) (void)release_session();
}

static void sort_descs(struct uz_page_desc *d, uint32_t n)
{
    uint32_t gap, i;

    for (gap = n / 2; gap; gap /= 2) {
        for (i = gap; i < n; ++i) {
            struct uz_page_desc tmp = d[i];
            uint32_t j = i;
            while (j >= gap && d[j - gap].base > tmp.base) {
                d[j] = d[j - gap];
                j -= gap;
            }
            d[j] = tmp;
        }
    }
}

/* The caller supplies the image through SRC_USER. */
static int valid_window(unsigned off, unsigned len)
{
    return len >= 8U && !(len & 7U) && len <= g_page_size && off <= g_page_size - len;
}

static long validate_page_desc(const struct uz_page_desc *d)
{
    unsigned len = d->fake_len ? d->fake_len : g_page_size;

    if (d->reserved || page_base(d->base) != d->base || !uz_user_range(d->base, g_page_size))
        return -EINVAL;
    if (d->flags != UROV_Z_PAGE_SRC_USER || !valid_window(d->fake_off, len) ||
        !uz_user_range(d->fake_addr, len))
        return -EINVAL;
    return 0;
}

static long page_build_image(struct uz_page *p, const struct uz_page_desc *d,
                             void *mm, const struct urov_z_request *legacy)
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

static long do_register(struct urov_z_request *q)
{
    void *mm;
    struct uz_page_desc *descs;
    uint64_t desc_bytes;
    uint32_t n = q->page_count ? q->page_count : 1;
    unsigned i;
    long ret;

    if (q->flags || q->reserved || q->reserved2 || q->session_flags)
        return -EINVAL;
    if (!g_page_hooked || !g_mmf_hooked) return -EOPNOTSUPP;
    if (n > g_max_pages) return -EINVAL;
    if (overlay_live()) return -EBUSY;

    desc_bytes = (uint64_t)n * sizeof(*descs);
    if (q->page_count &&
        (q->page_stride != sizeof(*descs) || !uz_user_range(q->pages_addr, desc_bytes)))
        return -EINVAL;
    descs = uz_alloc((unsigned long)desc_bytes);
    if (!descs) return -ENOMEM;
    mm = f_get_task_mm(current);
    if (!mm || mm != mm_of_task(current) || !mm_has_live_user(mm)) {
        if (mm) f_mmput(mm);
        uz_free(descs);
        return -EOPNOTSUPP;
    }
    g_sess.mm = mm;
    g_sess.tgid = uz_task_tgid();
    __atomic_store_n(&g_owner, mm, __ATOMIC_RELEASE);
    g_retired_count = 0;

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

        if (page_base(q->address) != q->address || !uz_user_range(q->address, g_page_size) ||
            !valid_window(q->offset, len) ||
            (q->fake_addr ? !uz_user_range(q->fake_addr, len) : len > UROV_Z_FAKE_MAX)) {
            ret = -EINVAL;
            goto fail;
        }
        descs[0] = (struct uz_page_desc) {
            .base = q->address, .flags = UROV_Z_PAGE_SRC_USER,
            .fake_off = q->offset, .fake_len = len,
        };
    }

    g_sess.pages = uz_alloc(n * sizeof(*g_sess.pages));
    g_sess.index = uz_alloc(sizeof(*g_sess.index) + n * sizeof(struct uz_page_key));
    g_sess.index_spare = uz_alloc(sizeof(*g_sess.index) + n * sizeof(struct uz_page_key));
    /* RX needs image/spare/snapshot only. The four write/replay buffers are
     * allocated solely for experimental sessions. vmalloc preserves page
     * alignment and vmalloc_to_page compatibility for GUP copies. */
    g_sess.arena = uz_alloc_buffer((unsigned long)g_page_buffers * n * g_page_size,
                                   f_vmalloc != 0);
    /* Each child page has an image and snapshot. Reserve the configured
     * number of descriptor sets, subject to both caps. A capped pool may
     * hold fewer complete children; clone admission checks the actual size. */
    {
        uint64_t slots = (uint64_t)n * g_fork_copies;

        if (slots > UZ_SHADOW_BYTES_MAX / (2U * g_page_size)) {
            slots = UZ_SHADOW_BYTES_MAX / (2U * g_page_size);
            if (slots < 2U) slots = 2U;
        }
        if (slots > UZ_SHADOW_CAP) slots = UZ_SHADOW_CAP;
        g_shadow_max = (uint32_t)slots;
    }
    if (g_shadow_max) {
        g_shadow = uz_alloc((unsigned long)g_shadow_max * sizeof(*g_shadow));
        g_shadow_arena = uz_alloc_buffer((unsigned long)(2ULL * g_shadow_max * g_page_size),
                                         f_vmalloc != 0);
    }
    if (g_shadow) memset(g_shadow, 0, (size_t)g_shadow_max * sizeof(*g_shadow));
    g_shadow_used = 0;
    if (!g_sess.pages || !g_sess.arena || (g_shadow_max && (!g_shadow || !g_shadow_arena)) ||
        !g_sess.index || !g_sess.index_spare) {
        ret = -ENOMEM;
        goto fail;
    }
    memset(g_sess.pages, 0, n * sizeof(*g_sess.pages));
    g_sess.page_count = n;
    g_sess.index->count = n;
    for (i = 0; i < n; ++i) {
        struct uz_page *p = &g_sess.pages[i];
        const struct uz_page_desc *d = &descs[i];

        p->base = d->base;
        g_sess.index->keys[i].base = d->base;
        g_sess.index->keys[i].slot = i;
        p->index = d->reserved;
        p->flags = d->flags;
        p->image = g_sess.arena + (unsigned long)g_page_buffers * i * g_page_size;
        p->spare = p->image + g_page_size;
        p->snapshot = p->spare + g_page_size;
        if (g_experimental_writes) {
            p->pre = p->snapshot + g_page_size;
            p->post = p->pre + g_page_size;
            p->ext_pre = p->post + g_page_size;
            p->ext_buf = p->ext_pre + g_page_size;
        }
        uz_mmap_write_lock(mm);
        {
            void *vma = f_find_vma(mm, p->base);

            ret = validate_target_vma(vma, p->base);
            if (!ret) uz_capture_vma(p, vma);
        }
        uz_mmap_write_unlock(mm);
        if (ret) goto fail;
        ret = page_build_image(p, d, mm, q->page_count ? 0 : q);
        if (ret) goto fail;
    }

    /* Optional acceleration: lack of memory must not reduce coverage. */
    g_insn_memo = uz_alloc(UZ_LLSC_MEMO_SLOTS * sizeof(*g_insn_memo));
    if (g_insn_memo)
        memset(g_insn_memo, 0, UZ_LLSC_MEMO_SLOTS * sizeof(*g_insn_memo));

    /* From the first AP[1] edit on, a racing reader must have a valid
     * replay view. Enable fake values only after the complete set is armed. */
    g_sess.generation = 1;
    __atomic_store_n(&g_failure_logged, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_suspend, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&g_state, UZ_STATE_LIVE, __ATOMIC_RELEASE);
    uz_readers_open(&g_readers);
    uz_code_build();
    ret = ap_arm_pages(&g_sess, mm);
    if (ret) {
        int restore = release_session();
        uz_free(descs);
        return restore ? restore : ret;
    }
    __atomic_store_n(&g_suspend, 0, __ATOMIC_RELEASE);

    q->session = 1;
    q->generation = g_sess.generation;
    q->page_count = n;
    q->page_stride = UROV_Z_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, &g_sess.pages[0]);
    q->offset = g_sess.pages[0].fake_off;
    q->length = g_sess.pages[0].fake_len;
    q->state = UROV_Z_ACTIVE;
    uz_free(descs);
    return 0;

fail:
    session_free_storage();
    uz_free(descs);
    if (g_verbose) pr_info("urov-z: register rejected ret=%ld pages=%u\n", ret, n);
    return ret;
}

static void set_reply(struct urov_z_request *q)
{
    struct uz_page *p = &g_sess.pages[0];

    q->generation = ++g_sess.generation;
    q->state = UROV_Z_ACTIVE;
    q->page_count = g_sess.page_count;
    q->page_stride = UROV_Z_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    page_status_words(q, p);
    q->offset = p->fake_off;
    q->length = p->fake_len;
    q->hits = __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED);
    q->replays = __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED);
}

static long do_set(struct urov_z_request *q)
{
    struct uz_page *p;
    unsigned len = request_fake_len(q);
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return -EBUSY;
    if (q->reserved || q->reserved2 || q->flags || g_sess.page_count != 1) return -EINVAL;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;
    p = &g_sess.pages[0];
    if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) return -ESTALE;
    if (len != p->fake_len || p->flags != UROV_Z_PAGE_SRC_USER) return -EINVAL;
    uz_ext_drain(g_sess.mm, p);
    ret = copy_request_image(q, g_sess.mm, p->spare + p->fake_off, len);
    if (ret) return ret;
    page_swap_image(p, p->fake_off, len);
    set_reply(q);
    return 0;
}

static long do_set_page(struct urov_z_request *q)
{
    struct uz_page *p;
    unsigned len = q->length ? q->length : g_page_size;
    unsigned off = q->offset;
    long ret;

    if (!session_owned() || q->session != 1) return -ENOENT;
    if (__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return -EBUSY;
    if (q->flags || q->reserved2 || q->reserved >> 32) return -EINVAL;
    p = page_by_index((uint32_t)q->reserved);
    if (!p) return -EINVAL;
    if (__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) return -ESTALE;
    if (p->flags != UROV_Z_PAGE_SRC_USER) return -EOPNOTSUPP;
    if (q->expected_generation != g_sess.generation) return -EAGAIN;

    if (!valid_window(off, len)) return -EINVAL;
    uz_ext_drain(g_sess.mm, p);
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
        if (!__atomic_load_n(&g_sess.pages[i].gone, __ATOMIC_ACQUIRE) &&
            __atomic_load_n(&g_sess.pages[i].armed, __ATOMIC_ACQUIRE)) ++n;
    return n;
}

static void status_inactive(struct urov_z_request *q)
{
    q->session = 0;
    q->generation = 0;
    q->offset = 0;
    q->length = 0;
    q->value = 0;
    q->value_hi[0] = 0;
    q->value_hi[1] = 0;
    q->value_hi[2] = 0;
    q->hits = 0;
    q->replays = 0;
    q->failures = 0;
    q->flags = 0;
    q->page_count = 0;
    q->page_stride = g_page_shift;
    q->session_flags = g_caps;
    q->reserved = 0;
    q->reserved2 = 0;
    q->state = UROV_Z_INACTIVE;
}

static long do_status(struct urov_z_request *q, int with_counters)
{
    struct uz_page *p0;

    if (!session_owned() || q->session != 1) {
        status_inactive(q);
        return 0;
    }
    p0 = &g_sess.pages[0];
    q->generation = g_sess.generation;
    q->flags = 0;
    q->page_count = g_sess.page_count;
    q->page_stride = UROV_Z_PAGE_DESC_SIZE;
    q->session_flags = g_caps;
    q->reserved = armed_pages();
    q->reserved2 = 0;
    page_status_words(q, p0);
    q->offset = p0->fake_off;
    q->length = p0->fake_len;
    q->hits = with_counters ? __atomic_load_n(&g_sess.hits, __ATOMIC_RELAXED) : 0;
    q->replays = with_counters ? __atomic_load_n(&g_sess.replays, __ATOMIC_RELAXED) : 0;
    q->failures = with_counters ? __atomic_load_n(&g_sess.failures, __ATOMIC_RELAXED) : 0;
    q->state = UROV_Z_ACTIVE;
    return 0;
}

static long do_query(struct urov_z_request *q)
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

static long do_deactivate(struct urov_z_request *q)
{
    int ret;

    if (q->session != 1 && q->session != 0) return -ENOENT;
    if (overlay_live() && !session_owned()) return -ENOENT;
    ret = release_session();
    if (ret) return ret;
    status_inactive(q);
    return 0;
}

static long dispatch(struct urov_z_request *q, unsigned cmd)
{
    long ret;

    if (!ctrl_try_lock()) return -EBUSY;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) {
        ctrl_unlock();
        return -EOPNOTSUPP;
    }
    reap_dead_session();
    switch (cmd) {
    case UROV_Z_QUERY: ret = do_query(q); break;
    case UROV_Z_REGISTER: ret = do_register(q); break;
    case UROV_Z_SET: ret = do_set(q); break;
    case UROV_Z_SET_PAGE: ret = do_set_page(q); break;
    case UROV_Z_STATUS: ret = do_status(q, 1); break;
    case UROV_Z_DEACTIVATE: ret = do_deactivate(q); break;
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

static void uz_prctl_before(hook_fargs6_t *args, void *udata)
{
    struct urov_z_request q;
    void *user;
    unsigned long size;
    unsigned cmd;
    long ret;

    (void)udata;
    if ((uint32_t)sys_arg(args, 0) != (uint32_t)g_keys.option) return;
    if (sys_arg(args, 1) != UROV_Z_PRCTL_MAGIC) return;
    user = (void *)sys_arg(args, 3);
    size = (unsigned long)sys_arg(args, 4);
    if (sys_arg(args, 2) > 0xffffU) return;
    cmd = (unsigned)sys_arg(args, 2);
    if (size != sizeof(q) || !uz_user_range((uintptr_t)user, sizeof(q))) return;
    if (f_copy_in(&q, user, sizeof(q))) return;
    if (q.size != sizeof(q) || q.version != UROV_Z_ABI_VERSION ||
        q.op != (uint16_t)cmd) return;
    if (q.mac != urov_z_request_mac(g_keys.mac, &q)) return;
    if (uz_copy_control_reply(user, &q, sizeof(q))) {
        args->ret = (uint64_t)-EFAULT;
        args->skip_origin = 1;
        return;
    }
    ret = dispatch(&q, cmd);
    q.fake_addr = 0;
    q.pages_addr = 0;
    if (uz_copy_control_reply(user, &q, sizeof(q))) ret = -EFAULT;
    args->ret = (uint64_t)ret;
    args->skip_origin = 1;
}

/* ----------------------------------------------- process_vm_readv overlay */

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif

#define UZ_VM_IOV_MAX 1024U
#define UZ_VM_CHUNK 256U

struct uz_iovec {
    uint64_t base;
    uint64_t len;
};

/* Resolve the address space process_vm_readv() acts on.  The caller's own
 * tid/tgid map to the current mm; any other pid is resolved under RCU exactly
 * like the kernel does. */
static void *uz_readv_mm(uint64_t pid)
{
    void *task, *mm;

    if (pid == uz_task_pid() || pid == uz_task_tgid()) return mm_of_task(current);
    if (!f_find_task_by_vpid || !f_rcu_lock) return 0;
    f_rcu_lock();
    task = f_find_task_by_vpid((int)pid);
    mm = task ? mm_of_task(task) : 0;
    f_rcu_unlock();
    return mm;
}

static void uz_vm_readv_before(hook_fargs6_t *args, void *udata)
{
    struct uz_readv_rec *rec;
    uint64_t ref;
    void *mm;
    (void)udata;
    if (!g_pin_ok) return;
    ref = session_get_any();
    if (!ref) return;
    mm = uz_readv_mm(sys_arg(args, 0));
    if (!mm) {
        uz_reader_exit(&g_readers, ref);
        return;
    }
    rec = uz_readv_rec_find(current, 1);
    if (!rec) {
        uz_reader_exit(&g_readers, ref);
        args->ret = (uint64_t)-EBUSY;
        args->skip_origin = 1;
        return;
    }
    rec->reader = ref;
    rec->allow = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE);
}

/* Every replacement is a fresh order-0 page. PIN uses Linux's grab/unpin
 * helpers; legacy GET transfers the allocator's single ordinary reference.
 * The syscall reader protects source buffers until the native copy finishes. */
static void uz_pin_after(hook_fargs8_t *args, void *udata)
{
    unsigned first = g_pin_argc == 8 ? 1U : 0U;
    void *mm = (void *)args->args[first];
    uint64_t start = args->args[first + 1U];
    unsigned int flags = (unsigned int)args->args[first + 3U];
    void **pages = (void **)args->args[first + 4U];
    long got = (long)args->ret;
    struct uz_readv_rec *rec;
    unsigned i;

    (void)udata;
    if (got <= 0 || !pages || !g_pin_ok) return;
    if (flags & (UZ_FOLL_WRITE | g_foll_longterm)) return;
    if (g_pin_internal && !g_remote_get && !(flags & g_foll_pin)) return;
    if (!overlay_live() || __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return;
    if (!mm) return;
    rec = uz_readv_rec_find(current, 0);
    if (!rec) return;    /* not inside a process_vm_readv() of this task */
    if ((unsigned long)got > (unsigned long)args->args[first + 2U])
        got = (long)args->args[first + 2U];
    for (i = 0; i < (unsigned)got; ++i) {
        uint64_t base = (start & ~((uint64_t)g_page_size - 1U)) +
                        (uint64_t)i * g_page_size;
        struct uz_page *p;
        struct uz_shadow *sh = 0;
        uint8_t *view;
        void *src, *copy;

        p = (mm == g_sess.mm) ? page_find(base) : uz_page_for_fault(mm, base);
        if (!p || __atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) continue;
        /* A forked child only has the overlay while its inherited leaf still
         * carries the trap; otherwise the native page is the honest answer. */
        if (mm != g_sess.mm && !uz_trap_leaf(mm, base)) continue;
        uz_ext_drain(mm, p);
        if (mm != g_sess.mm) sh = uz_shadow_find(mm, p->index);
        copy = uz_alloc_order0(&g_page_allocator);
        if (!copy) { UZ_HEALTH_ADD(gup_alloc_failures); goto failed; }
        {
            struct uz_page *source = sh ? &sh->page : p;
            struct uz_image_guard guard = uz_image_lock(source);
            view = rec->allow ? (sh ? sh->page.image : p->image)
                              : (sh ? sh->page.snapshot : p->snapshot);
            src = f_vmalloc_to_page ? f_vmalloc_to_page(view) : 0;
            if (src) f_copy_highpage(copy, src);
            uz_image_unlock(source, guard);
        }
        if (!src) { f_put_page(copy); goto failed; }
        if (g_remote_get) {
            f_put_page(pages[i]);
        } else {
            if ((f_grab_page_bool && !f_grab_page_bool(copy, g_foll_pin)) ||
                (f_grab_page_int && f_grab_page_int(copy, g_foll_pin)) ||
                (f_grab_folio && f_grab_folio(copy, 1, g_foll_pin)) ||
                (f_grab_folio_page && !f_grab_folio_page(copy, 1, g_foll_pin))) {
                f_put_page(copy);
                goto failed;
            }
            f_put_page(copy);
            f_unpin_page(pages[i]);
        }
        pages[i] = copy;
    }
    return;
failed:
    for (i = 0; i < (unsigned)got; ++i) {
        if (pages[i]) {
            if (g_remote_get) f_put_page(pages[i]);
            else f_unpin_page(pages[i]);
        }
        pages[i] = 0;
    }
    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    args->ret = (uint64_t)-ENOMEM;
}

static void uz_vm_readv_after(hook_fargs6_t *args, void *udata)
{
    (void)args;
    (void)udata;
    uz_readv_rec_clear(current);
}

/* Slow-GUP fallback: a foreign write fault had to drop the AP[1] trap so the
 * kernel could finish its COW.  Once __get_user_pages() returns the pages the
 * caller will write through the page pointer, re-arm the EL0 trap; the write
 * itself is captured into ext_pre and merged on the next read. */
static void uz_gup_slow_after(hook_fargs8_t *args, void *udata)
{
    unsigned first = g_gup_slow_argc == 8 ? 1U : 0U;
    void *mm = (void *)args->args[first];
    uint64_t start = args->args[first + 1U];
    unsigned int flags = (unsigned int)args->args[first + 3U];
    long got = (long)args->ret;
    unsigned i;
    uint64_t ref;
    int changed = 0;

    (void)udata;
    if (got <= 0 || !g_gup_slow_hooked) return;
    if (!(flags & UZ_FOLL_WRITE) || (flags & g_foll_longterm)) return;
    if (!overlay_live() || __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) return;
    if (!mm || mm != g_sess.mm) return;
    if (uz_internal_current()) return;
    if ((unsigned long)got > (unsigned long)args->args[first + 2U])
        got = (long)args->args[first + 2U];
    ref = session_get_mm(mm);
    if (!ref) return;
    for (i = 0; i < (unsigned)got; ++i) {
        uint64_t base = (start & ~((uint64_t)g_page_size - 1U)) +
                        (uint64_t)i * g_page_size;
        struct uz_page *p = page_find(base);
        int ret;

        if (!p || __atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
        if (!__atomic_load_n(&p->armed, __ATOMIC_ACQUIRE)) continue;
        (void)uz_ext_capture(mm, p, base);
        if (__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) continue;
        ret = page_set_ap_any(mm, base, 0);
        if (ret > 0) changed = 1;
    }
    if (changed) flush_tlb_all();
    uz_reader_exit(&g_readers, ref);
}

/* --------------------------------------------- kernel-assisted read overlay */

/* /proc/<pid>/mem, ptrace(PTRACE_PEEKDATA) and every other access_remote_vm()
 * caller copy through GUP, never through the EL0 data abort.  A single after
 * hook on the implementation entry rewrites the kernel buffer the caller is
 * about to hand back, so those readers see the registered image too.  The
 * function is already resolved for the control plane; the hook adds no
 * syscall entry, ABI field or counter. */
static void uz_kread_overlay(uint64_t remote, void *buf, uint64_t len, int allow_fake,
                             void *mm, int owner)
{
    uint8_t *out = buf;

    while (len) {
        uint64_t page = page_base(remote);
        unsigned off = (unsigned)(remote - page);
        unsigned seg = g_page_size - off;
        struct uz_page *p;

        if ((uint64_t)seg > len) seg = (unsigned)len;
        p = uz_page_for_fault(mm, remote);
        if (p && !__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE) &&
            (owner || uz_trap_leaf(mm, page))) {
            uz_ext_drain(mm, p);
            page_view_mm(mm, p, off, seg, out, !allow_fake);
        }
        remote += seg;
        out += seg;
        len -= seg;
    }
}

static void uz_kwrite_overlay(uint64_t remote, const void *buf, uint64_t len,
                              void *mm, int owner)
{
    const uint8_t *src = buf;

    while (len) {
        uint64_t page = page_base(remote);
        unsigned off = (unsigned)(remote - page);
        unsigned seg = g_page_size - off;
        struct uz_page *p;

        if ((uint64_t)seg > len) seg = (unsigned)len;
        p = uz_page_for_fault(mm, remote);
        if (p && (owner || uz_trap_leaf(mm, page))) {
            if (!g_experimental_writes) {
                uz_retire_written_page(mm, p, remote);
            } else if (mm == g_sess.mm) {
                page_store_bytes(p, off, src, seg);
            } else {
                struct uz_shadow *sh = uz_shadow_get(mm, p->index);

                if (sh) uz_shadow_store(sh, off, src, seg);
            }
        }
        remote += seg;
        src += seg;
        len -= seg;
    }
}

static void uz_kread_after(hook_fargs6_t *args, void *udata)
{
    void *mm;
    void *buf;
    uint64_t remote, len, ref;
    unsigned long flags;
    int allow, owner;

    (void)udata;
    len = uz_access_vm_result(args->ret, g_kread_argc == 6 ? args->arg4 : args->arg3);
    if (!len) return;
    /* The module's own snapshots and control replies must never be
     * rewritten by this hook. */
    if (uz_internal_current()) return;
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
    if (!mm || !buf) return;
    if (!len || !uz_user_range(remote, len)) return;
    owner = mm == __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE);
    if (!owner && (!overlay_live())) return;
    ref = owner ? session_get_mm(mm) : session_get_any();
    if (!ref) return;
    if (flags & 0x1U /* FOLL_WRITE */) {
        /* A kernel-assisted writer (ptrace POKE, /proc/<pid>/mem) bypasses
         * the EL0 store fault.  The live page already holds the bytes by the
         * time the hook runs; publish the same bytes into the image so a
         * following read observes the write exactly as it would natively.
         * A forked child has its own COW copy, so its bytes go to the child's
         * shadow and never into the parent's image. */
        if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE)) {
            uz_write_enter();
            uz_kwrite_overlay(remote, buf, len, mm, owner);
            uz_write_leave();
        }
        uz_reader_exit(&g_readers, ref);
        return;
    }

    allow = !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
            1;
    uz_kread_overlay(remote, buf, len, allow, mm, owner);
    uz_reader_exit(&g_readers, ref);
}

/* --------------------------------------------------------------- GUP reads */

/* vmsplice() (and any other get_user_pages_fast() reader) pins the live user
 * pages and never enters the EL0 abort handler or access_remote_vm().  Replace
 * the pages covering a registered page with private copies of the image.  The
 * caller owns the reference the GUP call just took, so handing it a fresh
 * page keeps the normal put_page() lifetime; the returned copy is fully
 * populated before the reader can touch it. */
static void uz_gup_after(hook_fargs4_t *args, void *udata)
{
    unsigned long start = (unsigned long)args->arg0;
    unsigned long nr = (unsigned long)args->arg1;
    unsigned int flags = (unsigned int)args->arg2;
    void **pages = (void **)args->arg3;
    /* The function returns int in W0; upper X0 bits do not sign-extend it. */
    int got = (int32_t)(uint32_t)args->ret;
    void *mm;
    uint64_t ref;
    int owner, writer;
    unsigned i;

    (void)udata;
    if (got <= 0 || !pages || !uz_page_allocator_ready(&g_page_allocator) || !f_put_page ||
        !f_copy_highpage || !f_vmalloc_to_page)
        return;
    /* PIN/LONGTERM require the exact user page.  PIN/LONGTERM are also used by
     * the kernel's own long-term pins, which must never see a replacement. */
    if ((flags & (g_foll_longterm | g_foll_pin | g_foll_fast_only)) ||
        (g_gup_internal && !(flags & g_foll_get)) ||
        (start & (g_page_size - 1U)) || !overlay_live() ||
                __atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE))
        return;
    mm = mm_of_task(current);
    if (!mm) return;
    owner = mm == __atomic_load_n(&g_owner, __ATOMIC_ACQUIRE);
    ref = owner ? session_get_mm(mm) : session_get_any();
    if (!ref) return;
    /* A registered page is a data source for vmsplice()/pipe and that path asks
     * GUP without FOLL_WRITE.  FOLL_WRITE marks a real write destination (for
     * example read() or O_DIRECT into a writable mapping): the bytes must reach
     * the live page, so that page goes native instead of being intercepted by
     * the replacement copy.  The kernel's own FOLL_WRITE fault-in has already
     * installed a writable leaf, so the trap is gone for that page anyway. */
    writer = (flags & UZ_FOLL_WRITE) != 0;
    if ((unsigned long)got > nr) got = (int)nr;
    for (i = 0; i < (unsigned)got; ++i) {
        uint64_t va = (uint64_t)start + (uint64_t)i * g_page_size;
        uint64_t page = page_base(va);
        struct uz_page *p = uz_page_for_fault(mm, va);
        struct uz_shadow *sh = 0;
        void *src, *fake;
        int allow_fake = 1;

        if (!p) continue;
        if (!owner && !uz_trap_leaf(mm, page)) continue;
        if (!writer && __atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) continue;
        if (writer) {
            if (!g_experimental_writes) {
                uz_retire_written_page(mm, p, page);
                continue;
            }
            /* This page is a real write destination.  Keep the AP[1] trap and
             * let the writer reach the live page through the kernel mapping;
             * the next reader merges the written bytes into the image instead
             * of retiring the page.  The caller writes through the pinned
             * page, never through the PTE, so re-arming here is safe. */
            if (owner && mm == g_sess.mm) {
                (void)uz_ext_capture(mm, p, page);
                if (page_set_ap_any(mm, page, 0) > 0) flush_tlb_all();
            } else if (!owner && page_set_ap_any(mm, page, 0) > 0) {
                flush_tlb_all();
            }
            continue;
        }
        uz_ext_drain(mm, p);
        if (!owner) sh = uz_shadow_find(mm, p->index);
        fake = uz_alloc_order0(&g_page_allocator);
        if (!fake) { UZ_HEALTH_ADD(gup_alloc_failures); goto failed; }
        {
            struct uz_page *source = sh ? &sh->page : p;
            struct uz_image_guard guard = uz_image_lock(source);
            src = f_vmalloc_to_page(sh ? sh->page.image :
                                    (allow_fake ? p->image : p->snapshot));
            if (src) f_copy_highpage(fake, src);
            uz_image_unlock(source, guard);
        }
        if (!src) { f_put_page(fake); goto failed; }
        if (pages[i]) f_put_page(pages[i]);
        pages[i] = fake;
        /* A source-side GUP does not write, but keep the trap authoritative:
         * if anything dropped it, restore it before the caller returns. */
        if (__atomic_load_n(&p->armed, __ATOMIC_ACQUIRE) &&
            !__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE) &&
            !uz_trap_leaf(mm, page) && page_set_ap_any(mm, page, 0) > 0)
            flush_tlb_all();
    }
    uz_reader_exit(&g_readers, ref);
    return;
failed:
    /* The caller must not silently receive native bytes on allocation
     * failure. Drop both original and already substituted ordinary refs. */
    for (i = 0; i < (unsigned)got; ++i) {
        if (pages[i]) f_put_page(pages[i]);
        pages[i] = 0;
    }
    __atomic_fetch_add(&g_sess.failures, 1, __ATOMIC_RELAXED);
    args->ret = (uint64_t)-ENOMEM;
    uz_reader_exit(&g_readers, ref);
}

/* ---------------------------------------------------------- mapping gates */

#define UZ_CLONE_VM 0x00000100ULL
#define UZ_CLONE_VFORK 0x00004000ULL
#ifndef __NR_clone3
#define __NR_clone3 435
#endif

/* Serialise a non-CLONE_VM fork with control updates until copy_mm has
 * snapshotted and retained the child's mm. Descendant forks are deliberately
 * rejected; their lifetime cannot be delegated to the owner session. */
static void uz_clone_before(hook_fargs6_t *args, void *udata)
{
    uint64_t ref, flags;
    void *mm;
    int err = 0;
    args->local.data7 = 0;
    ref = session_get_any();
    if (!ref) return;
    mm = mm_of_task(current);
    if (mm != g_sess.mm && !uz_child_known(mm)) goto out;
    flags = sys_arg(args, 0);
    if (udata) {
        if (sys_arg(args, 1) < 64U || f_copy_in(&flags, (void *)(uintptr_t)flags, 8))
            goto out; /* Linux validates the original clone3 structure. */
    }
    if (flags & UZ_CLONE_VM) goto out;
    if (mm != g_sess.mm) err = -EOPNOTSUPP;
    else if (!ctrl_try_lock()) err = -EBUSY;
    else {
        args->local.data7 = 1;
        if (!g_copymm_hooked || !g_fork_copies) err = -EOPNOTSUPP;
        else if ((uint64_t)g_shadow_used + g_sess.page_count > g_shadow_max) err = -ENOSPC;
    }
    if (err) { args->ret = (uint64_t)err; args->skip_origin = 1; }
out:
    uz_reader_exit(&g_readers, ref);
}

static void uz_clone_after(hook_fargs6_t *args, void *udata)
{
    (void)udata;
    if (args->local.data7) ctrl_unlock();
}
#define UZ_MAP_FIXED 0x10ULL
#define UZ_MAP_FIXED_NOREPLACE 0x100000ULL
#define UZ_MREMAP_MAYMOVE 0x1ULL
#define UZ_MREMAP_FIXED 0x2ULL
#define UZ_MREMAP_DONTUNMAP 0x4ULL

enum uz_gate_kind {
    UZ_GATE_MPROTECT,
    UZ_GATE_MUNMAP,
    UZ_GATE_MREMAP,
    UZ_GATE_MMAP,
    UZ_GATE_MADVISE,
    UZ_GATE_EXECVE,
    UZ_GATE_EXECVEAT,
    UZ_GATE_PKEY_MPROTECT,
    UZ_GATE_REMAP_FILE_PAGES,
};

static const int g_gate_nrs[UZ_GATE_NUM] = {
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

/* Only called while holding the control lock. A tagged mapping argument
 * may refer to the same page as an untagged registration address. */
static int gate_range_overlaps(uint64_t start, uint64_t len)
{
    uint64_t end;
    uint32_t i;

    if (!len) return 0;
    start &= (UINT64_C(1) << 56) - 1;
    end = start + len;
    if (end < start) end = ~UINT64_C(0);
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uz_page *p = &g_sess.pages[i];
        uint64_t base = __atomic_load_n(&p->base, __ATOMIC_ACQUIRE);
        if (!__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) &&
            base < end && start < base + g_page_size) return 1;
    }
    return 0;
}

static int child_range_overlaps(void *mm, uint64_t start, uint64_t len)
{
    uint32_t i;
    uint64_t end;
    if (!len) return 0;
    start &= (UINT64_C(1) << 56) - 1;
    end = start + len;
    if (end < start) end = ~UINT64_C(0);
    for (i = 0; i < g_shadow_max; ++i) {
        struct uz_shadow *sh = &g_shadow[i];
        uint64_t base = __atomic_load_n(&sh->page.base, __ATOMIC_ACQUIRE);
        if (__atomic_load_n(&sh->used, __ATOMIC_ACQUIRE) == 1 && sh->mm == mm &&
            !__atomic_load_n(&sh->page.gone, __ATOMIC_ACQUIRE) &&
            base < end && start < base + g_page_size) return 1;
    }
    return 0;
}

static int caller_is_managed(void)
{
    uint64_t ref = session_get_any();
    void *mm = mm_of_task(current);
    int managed;
    if (!ref) return 0;
    managed = mm == g_sess.mm || uz_child_known(mm);
    uz_reader_exit(&g_readers, ref);
    return managed;
}

/* Linux's madvise() accepts a bounded set of advice values and rejects the
 * rest before touching the VMA.  2.11.0 ran its range gate first, so
 * madvise(page, len, -1) ended the whole session and only then let Linux
 * return EINVAL.  An invalid advice must pass through untouched. */
static int uz_advice_valid(uint64_t advice)
{
    if (advice <= 25U) return 1;              /* MADV_NORMAL .. MADV_COLLAPSE */
    return advice == 100U || advice == 101U;  /* MADV_HWPOISON, SOFT_OFFLINE */
}

/* Linux validates the address range before it takes the mmap lock or changes
 * any VMA.  A syscall that Linux is going to reject with EINVAL must not end
 * the session first: 2.12.0 checked the overlap before this validation, so
 * mprotect(page + 1, 1, PROT_READ) returned EINVAL and still disarmed the
 * whole overlay.  The checks below mirror the pre-mm-lock rejection paths for
 * the gate syscalls; a rejected call is passed through untouched. */
static int uz_mapping_range_ok(uint64_t start, uint64_t len)
{
    start &= (UINT64_C(1) << 56) - 1;
    if (start & (g_page_size - 1U)) return 0;
    if (start >= g_user_limit) return 0;
    if (len > g_user_limit - start) return 0;
    return 1;
}

#define UZ_PROT_SEM 0x8U
#define UZ_PROT_GROWSDOWN 0x01000000U
#define UZ_PROT_GROWSUP 0x02000000U
#define UZ_PROT_BTI 0x10U
#define UZ_PROT_MTE 0x20U
#define UZ_PROT_MASK (UZ_PROT_READ | UZ_PROT_WRITE | UZ_PROT_EXEC | UZ_PROT_SEM | \
                      UZ_PROT_GROWSDOWN | UZ_PROT_GROWSUP | UZ_PROT_BTI | UZ_PROT_MTE)

static int uz_gate_args_invalid(int kind, uint64_t a0, uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4)
{
    switch (kind) {
    case UZ_GATE_MPROTECT:
    case UZ_GATE_PKEY_MPROTECT:
        return !uz_mapping_range_ok(a0, a1) || (a2 & ~(uint64_t)UZ_PROT_MASK);
    case UZ_GATE_MUNMAP:
    case UZ_GATE_MADVISE:
        return !uz_mapping_range_ok(a0, a1);
    case UZ_GATE_MREMAP:
        if (!uz_mapping_range_ok(a0, a1)) return 1;
        if (a3 & ~(UZ_MREMAP_MAYMOVE | UZ_MREMAP_FIXED | UZ_MREMAP_DONTUNMAP)) return 1;
        if ((a3 & UZ_MREMAP_FIXED) && !(a3 & UZ_MREMAP_MAYMOVE)) return 1;
        if ((a3 & UZ_MREMAP_FIXED) && !uz_mapping_range_ok(a4, a2)) return 1;
        return 0;
    case UZ_GATE_MMAP:
        if (!uz_mapping_range_ok(a0, a1)) return 1;
        /* Linux rejects the two fixed flags together before it unmaps
         * anything; keeping that call away from the session is required. */
        if ((a3 & (UZ_MAP_FIXED | UZ_MAP_FIXED_NOREPLACE)) ==
            (UZ_MAP_FIXED | UZ_MAP_FIXED_NOREPLACE))
            return 1;
        return 0;
    case UZ_GATE_REMAP_FILE_PAGES:
        if (!uz_mapping_range_ok(a0, a1) || a1 < g_page_size ||
            (a1 & (g_page_size - 1U)) ||
            (a2 & ~(uint64_t)(UZ_PROT_READ | UZ_PROT_WRITE | UZ_PROT_EXEC)))
            return 1;
        return 0;
    default:
        return 0;
    }
}

/* A page whose mapping was removed or replaced cannot be served from the old
 * image any more.  Only that page is retired; the rest of the session (and
 * every other registered page) stays live. */
static void uz_range_gone(void *mm, uint64_t start, uint64_t len)
{
    uint64_t end = start + len;
    uint64_t ref;
    uint32_t i;

    if (!mm || !len || end < start) return;
    ref = session_get_mm(mm);
    if (!ref) return;
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uz_page *p = &g_sess.pages[i];

        if (p->base < start || p->base >= end) continue;
        __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&p->gone, 1, __ATOMIC_RELEASE);
    }
    uz_reader_exit(&g_readers, ref);
}

/* Caller owns the control lock and holds no reader reference while draining. */
static void uz_publish_page_index(void)
{
    struct uz_page_index *next = g_sess.index_spare;
    struct uz_page_index *old;
    uint32_t i;

    next->count = 0;
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uz_page *p = &g_sess.pages[i];
        if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
        next->keys[next->count].base = __atomic_load_n(&p->base, __ATOMIC_ACQUIRE);
        next->keys[next->count++].slot = i;
    }
    uz_index_sort(next);
    old = uz_index_publish(&g_sess.index, next);
    drain_readers(uz_readers_flip(&g_readers));
    g_sess.index_spare = old;
}

/* mremap() can keep, move or resize the registered pages without changing
 * their contents.  A no-op mremap (equal length, flags 0) is the standard
 * keyless "revoke" call: Linux returns the original address, so the session
 * must simply stay armed.  For a real move, the trapped leaves move with the
 * page tables; update the page bases and the captured VMA range, retire pages
 * that were dropped, and rebuild the branch map for the new addresses. */
static void uz_mremap_update(void *mm, uint64_t old, uint64_t old_len,
                             uint64_t new_len, uint64_t flags, uint64_t moved_to)
{
    uint64_t old_end = old + old_len;
    uint64_t new_end = moved_to + new_len;
    uint64_t ref;
    uint32_t i;
    int moved = 0;

    if (!mm || !old_len || !new_len || old_end < old || new_end < moved_to) return;
    if (flags & UZ_MREMAP_DONTUNMAP) return; /* refused by the before gate */
    ref = session_get_mm(mm);
    if (!ref) return;
    /* The destination of MREMAP_FIXED replaced any mapping that was not part
     * of the moved range.  Retire those pages first so a moved page that
     * lands in the destination is not mistaken for an old target. */
    if (moved_to != old) {
        for (i = 0; i < g_sess.page_count; ++i) {
            struct uz_page *p = &g_sess.pages[i];

            if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
            if (p->base >= moved_to && p->base < new_end &&
                !(p->base >= old && p->base < old_end)) {
                __atomic_store_n(&p->gone, 1, __ATOMIC_RELEASE);
                __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
            }
        }
    }
    for (i = 0; i < g_sess.page_count; ++i) {
        struct uz_page *p = &g_sess.pages[i];

        if (__atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
        if (p->base < old || p->base >= old_end) continue;
        {
            uint64_t off = p->base - old;

            if (off >= new_len) {
                __atomic_store_n(&p->gone, 1, __ATOMIC_RELEASE);
                __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
                continue;
            }
            if (moved_to != old) {
                __atomic_store_n(&p->base, moved_to + off, __ATOMIC_RELEASE);
                moved = 1;
            }
        }
    }
    uz_reader_exit(&g_readers, ref);
    uz_publish_page_index();
    if (moved) {
        /* Moving code invalidates the global LL/SC entry proof. Keep the
         * old arena alive for in-flight readers and disable that proof. */
        if (__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE))
            uz_code_mremap(old, old_len, moved_to, new_len);
    }
}

/* A protected mapping is restored before the native syscall runs. If a
 * concurrent control transaction owns the session, the mutator must retry
 * instead of proceeding underneath it. */
static void uz_gate_before_impl(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;
    int ret = 0;

    if (!caller_is_owner()) return;
    if (kind == UZ_GATE_MMAP && !(sys_arg(args, 3) & UZ_MAP_FIXED)) return;
    if (uz_gate_args_invalid(kind, sys_arg(args, 0), sys_arg(args, 1),
                             sys_arg(args, 2), sys_arg(args, 3), sys_arg(args, 4)))
        return;
    if (overlay_live() &&         (kind == UZ_GATE_MUNMAP || kind == UZ_GATE_MREMAP ||
         (kind == UZ_GATE_MMAP && (sys_arg(args, 3) & UZ_MAP_FIXED)))) {
        /* A mapping change is handled after Linux returns: it may fail, keep
         * the same VMA (the equal-length mremap revocation), or move the
         * trapped leaves.  None of those may tear down the whole session
         * before the native syscall has decided. */
        args->local.data0 = sys_arg(args, 0);
        args->local.data1 = sys_arg(args, 1);
        args->local.data2 = sys_arg(args, 2);
        args->local.data3 = sys_arg(args, 3);
        args->local.data4 = sys_arg(args, 4);
        args->local.data5 = 1;
        return;
    }
    if (kind == UZ_GATE_MADVISE) {

        if (!uz_advice_valid(sys_arg(args, 2))) return;
        if (overlay_live()) return;
    }
    if (kind == UZ_GATE_REMAP_FILE_PAGES) {
        /* remap_file_pages() rejects a private VMA before it changes any PTE;
         * that call must not be able to end the session on its way to EINVAL.
         * A successful shared remap changes which file offsets the range maps,
         * so the pages it covers are retired after the syscall instead of
         * releasing the whole session. */
        struct uz_vma_view vma;
        if (!overlay_live() || uz_vma_read(g_sess.mm, sys_arg(args, 0), &vma) ||
            !(vma.flags & UZ_VM_SHARED)) return;
        args->local.data0 = sys_arg(args, 0);
        args->local.data1 = sys_arg(args, 1);
        args->local.data5 = 1;
        return;
    }
    if ((kind == UZ_GATE_MPROTECT || kind == UZ_GATE_PKEY_MPROTECT) &&
        overlay_live()) {
        /* 2.14.0: protection is virtual for the overlay.  The syscall still
         * changes the VMA/PTE exactly as Linux wants; the after hook updates
         * the trap state.  Nothing here may release the session: a
         * protection-only change never makes the live bytes readable, and
         * mprotect() calls that Linux rejects must not end the overlay. */
        return;
    }
    if (!args->local.data6 && !ctrl_try_lock()) {
        gate_error(args, -EBUSY);
        return;
    }
    if (session_owned()) {
        int release;

        if (kind == UZ_GATE_EXECVE || kind == UZ_GATE_EXECVEAT) {
            /* A vfork child shares the owner's mm but execs into a new one;
             * the parent keeps the armed mapping.  Only the owner thread
             * group's own exec replaces the address space of the session. */
            release = uz_task_tgid() == g_sess.tgid;
        } else {
            release = gate_range_overlaps(sys_arg(args, 0), sys_arg(args, 1)) ||
                      (kind == UZ_GATE_MREMAP && (sys_arg(args, 3) & UZ_MREMAP_FIXED) &&
                       gate_range_overlaps(sys_arg(args, 4), sys_arg(args, 2)));
        }
        if (release) ret = release_session();
    }
    if (!args->local.data6) ctrl_unlock();
    if (ret) gate_error(args, ret);
}

/* A forked child mprotect()s its private copy of the registered pages.  Linux
 * rewrites the leaf from the new VMA protection and clears AP[1]; re-assert
 * the trap so the child keeps reading the overlay.  The owner's own
 * ap_protection_update() cannot be used here: want/dead are session-wide and
 * must not be changed by a child. */
static void uz_child_protection_update(void *mm, uint64_t start, uint64_t len,
                                       uint64_t prot)
{
    uint64_t end = start + len, cur;
    uint64_t ref;
    int changed = 0;

    if (!mm || mm == g_sess.mm || !len || end < start) return;
    ref = session_get_any();
    if (!ref) return;
    /* The child may have moved or split its copy of the mapping, so walk the
     * mprotect range and resolve each page by file identity. */
    for (cur = start & ~((uint64_t)g_page_size - 1U); cur < end; cur += g_page_size) {
        struct uz_page *p = uz_page_for_fault(mm, cur);

        if (!p || __atomic_load_n(&p->gone, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&p->replay, __ATOMIC_ACQUIRE))
            continue;
        if (!g_experimental_writes && (prot & UZ_PROT_WRITE)) {
            uz_retire_written_page(mm, p, cur);
            continue;
        }
        if (!(prot & (UZ_PROT_READ | UZ_PROT_WRITE))) {
            __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
        } else {
            int ret;
            __atomic_store_n(&p->want, 1, __ATOMIC_RELEASE);
            if (__atomic_load_n(&p->dead, __ATOMIC_ACQUIRE)) continue;
            ret = page_set_ap_any(mm, cur, 0);
            if (ret >= 0) __atomic_store_n(&p->armed, 1, __ATOMIC_RELEASE);
            if (ret > 0) changed = 1;
        }
    }
    if (changed) flush_tlb_all();
    uz_reader_exit(&g_readers, ref);
}

/* Successful child mapping changes only retire/move that child's slots.
 * File identity is immutable; a parent move/unmap never changes it. */
static void uz_child_mapping_update(void *mm, int kind, hook_fargs6_t *args)
{
    uint64_t start = sys_arg(args, 0), len = sys_arg(args, 1), end = start + len;
    uint64_t dst = args->ret, new_len = sys_arg(args, 2), ref;
    uint32_t i;

    if (kind != UZ_GATE_MUNMAP && kind != UZ_GATE_MREMAP && kind != UZ_GATE_MMAP &&
        kind != UZ_GATE_REMAP_FILE_PAGES)
        return;
    if (kind == UZ_GATE_MMAP && !(sys_arg(args, 3) & UZ_MAP_FIXED)) return;
    if (!len || end < start) return;
    ref = session_get_any();
    if (!ref) return;
    for (i = 0; i < g_shadow_max; ++i) {
        struct uz_shadow *sh = &g_shadow[i];
        struct uz_page *p = &sh->page;
        uint64_t base;
        int retire;

        if (__atomic_load_n(&sh->used, __ATOMIC_ACQUIRE) != 1 || sh->mm != mm ||
            __atomic_load_n(&p->gone, __ATOMIC_ACQUIRE)) continue;
        base = __atomic_load_n(&p->base, __ATOMIC_ACQUIRE);
        retire = base >= start && base < end;
        if (kind == UZ_GATE_MREMAP) {
            if (retire && base - start < new_len) {
                __atomic_store_n(&p->base, dst + (base - start), __ATOMIC_RELEASE);
                continue;
            }
            if (dst != start && base >= dst && base - dst < new_len) retire = 1;
        }
        if (retire) {
            __atomic_store_n(&p->want, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&p->armed, 0, __ATOMIC_RELEASE);
            __atomic_store_n(&p->gone, 1, __ATOMIC_RELEASE);
        }
    }
    uz_reader_exit(&g_readers, ref);
}

/* An executable mapping created or made executable after REGISTER was not in
 * the branch map.  Scan the new range before the caller can return to EL0 and
 * branch from it.  A syscall the before hook refused (negative return) has no
 * new mapping.
 *
 * The same after hook re-applies the PAGE_AP trap on a protection change that
 * kept the page readable and executable: Linux rewrites the leaf PTEs from the
 * VMA protection, which restores AP[1]. */
static void uz_gate_after_impl(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;
    long ret = (long)args->ret;
    uint64_t start, len;

    if (ret < 0) return;
    if (!session_owned()) {
        uz_child_mapping_update(mm_of_task(current), kind, args);
        if (overlay_live() &&             !__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE) &&
            (kind == UZ_GATE_MPROTECT || kind == UZ_GATE_PKEY_MPROTECT)) {
            void *mm = mm_of_task(current);

            if (mm) uz_child_protection_update(mm, sys_arg(args, 0),
                                               sys_arg(args, 1), sys_arg(args, 2));
        }
        return;
    }
    if (args->local.data5 && overlay_live()) {
        uint64_t a0 = args->local.data0, a1 = args->local.data1;
        uint64_t a2 = args->local.data2, a3 = args->local.data3;

        args->local.data5 = 0;
        if (kind == UZ_GATE_MUNMAP && ret == 0)
            uz_range_gone(g_sess.mm, a0, a1);
        else if (kind == UZ_GATE_MMAP)
            uz_range_gone(g_sess.mm, a0, a1);
        else if (kind == UZ_GATE_MREMAP)
            uz_mremap_update(g_sess.mm, a0, a1, a2, a3, (uint64_t)ret);
        else if (kind == UZ_GATE_REMAP_FILE_PAGES)
            uz_range_gone(g_sess.mm, a0, a1);
    }
    if ((kind == UZ_GATE_MPROTECT || kind == UZ_GATE_PKEY_MPROTECT)) {
        if (!__atomic_load_n(&g_suspend, __ATOMIC_ACQUIRE))
            ap_protection_update(g_sess.mm, sys_arg(args, 0), sys_arg(args, 1),
                                 sys_arg(args, 2));
    }
    if (!__atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE)) return;
    switch (kind) {
    case UZ_GATE_MMAP:
        if (!(sys_arg(args, 2) & 0x4U)) return; /* PROT_EXEC */
        start = (uint64_t)ret;
        len = sys_arg(args, 1);
        break;
    case UZ_GATE_MPROTECT:
    case UZ_GATE_PKEY_MPROTECT:
        if (!(sys_arg(args, 2) & 0x4U)) return;
        start = sys_arg(args, 0);
        len = sys_arg(args, 1);
        break;
    case UZ_GATE_MREMAP:
        start = (uint64_t)ret;
        len = sys_arg(args, 2);
        break;
    default:
        return;
    }
    if (!start || !len || start >= g_user_limit) return;
    uz_code_add_range(g_sess.mm, start, len);
}

/* Mapping mutations and their rearm/metadata updates are one transaction.
 * SET and DEACTIVATE cannot free or publish over the after-hook's page walk.
 * Wait before the native call: libc treats unexpected mprotect EBUSY as fatal. */
static void uz_gate_before(hook_fargs6_t *args, void *udata)
{
    int kind = (int)(uintptr_t)udata;
    args->local.data5 = 0;
    args->local.data6 = 0;
    if ((caller_is_owner() || caller_is_managed()) &&
        kind != UZ_GATE_EXECVE && kind != UZ_GATE_EXECVEAT) {
        while (!ctrl_try_lock()) f_msleep(1);
        args->local.data6 = 1;
        if (kind == UZ_GATE_MREMAP && overlay_live() &&
            ((sys_arg(args, 3) & UZ_MREMAP_DONTUNMAP) || !sys_arg(args, 1))) {
            void *mm = mm_of_task(current);
            uint64_t start = sys_arg(args, 0), len = sys_arg(args, 1);
            uint64_t dest = sys_arg(args, 4), size = sys_arg(args, 2);
            int overlaps = mm == g_sess.mm ? gate_range_overlaps(start, len ? len : g_page_size) :
                child_range_overlaps(mm, start, len ? len : g_page_size);
            if (sys_arg(args, 3) & UZ_MREMAP_FIXED)
                overlaps |= mm == g_sess.mm ? gate_range_overlaps(dest, size) :
                    child_range_overlaps(mm, dest, size);
            if (overlaps) {
                /* Duplicating a managed mapping needs a new independently
                 * owned slot. Do not let an inherited trap escape tracking. */
                gate_error(args, -EOPNOTSUPP);
                return;
            }
        }
    }
    uz_gate_before_impl(args, udata);
}

static void uz_gate_after(hook_fargs6_t *args, void *udata)
{
    int locked = args->local.data6 != 0;
    if (!locked && caller_is_managed() && (long)args->ret >= 0) {
        while (!ctrl_try_lock()) f_msleep(1);
        locked = 1;
    }
    uz_gate_after_impl(args, udata);
    if (locked) ctrl_unlock();
}

/* -------------------------------------------------------------------- init */

static void *lookup(const char *name)
{
    return (void *)kallsyms_lookup_name(name);
}

static int resolve_geometry(void)
{
    struct uz_geometry geom;
    uint64_t tcr, sctlr;

    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    if ((sctlr & (3ULL << 24)) || uz_geometry_from_tcr(&geom, tcr)) return -EOPNOTSUPP;
    {
        uint64_t mmfr3, tcr2;
        __asm__ volatile("mrs %0, S3_0_C0_C7_3" : "=r"(mmfr3));
        if (mmfr3 & 15U) {
            __asm__ volatile("mrs %0, S3_0_C2_C0_3" : "=r"(tcr2));
            if (tcr2 & 0x3eU) return -EOPNOTSUPP;
        }
    }
    g_page_shift = geom.page_shift;
    g_page_size = 1U << g_page_shift;
    g_pt_levels = (geom.user_va_bits - 4U) / (g_page_shift - 3U);
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

static int uz_read_exact(void *file, void *buf, size_t bytes, int64_t *pos)
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
    struct uz_btf_pack pack;
    int64_t pos = 0;
    void *file;
    long ret;

    if (!open || !close || !f_kernel_read || !start || end <= start || end - start > 65536U)
        return -EOPNOTSUPP;
    file = open(path, 0 /* O_RDONLY */, 0);
    if (!file || (uintptr_t)file >= (uintptr_t)-4095L) return file ? (long)file : -ENOMEM;
    ret = uz_read_exact(file, &pack, sizeof(pack), &pos);
    if (ret) goto out;
    if (!uz_btf_pack_matches(&pack, (const void *)start, end - start)) {
        pr_info("urov-z: detached BTF header or kernel build ID mismatch\n");
        ret = -EINVAL;
        goto out;
    }
    *storage = uz_alloc(pack.bytes);
    if (!*storage) {
        ret = -ENOMEM;
        goto out;
    }
    ret = uz_read_exact(file, *storage, pack.bytes, &pos);
    if (!ret && uz_btf_open(btf, *storage, pack.bytes)) ret = -EINVAL;
out:
    close(file, 0);
    return ret;
}

/* Diagnostic counts describe checked public interfaces, including optional
 * candidates. They are not a count of installed hooks. Private entries still
 * require their full BTF signature and never use this fallback. */
static int uz_public_abi(const struct kclf_btf *btf, const char *name, const char *shape)
{
    int ok = uz_symbol_abi(btf, name, shape);
    if (lookup(name)) {
        if (!ok) ++g_compat.public_abi_rejected;
        else if (kclf_btf_func_proto(btf, name)) ++g_compat.public_abi_strict;
        else {
            ++g_compat.public_abi_fallback;
            if (g_verbose) pr_info("urov-z: public ABI fallback %s\n", name);
        }
    }
    return ok;
}

static void uz_record_flag(const struct kclf_btf *btf, const char *name,
                            unsigned value, unsigned bit)
{
    unsigned evidence = uz_btf_enum_flag(btf, name, ~0U);
    if (!value) g_compat.foll_unavailable |= bit;
    else if (evidence == ~0U) g_compat.foll_version |= bit;
    else g_compat.foll_btf |= bit;
}

static long resolve_symbols(const struct kclf_btf *btf, int *mmf_argc)
{
    const char *vma_name = "find_vma";
    const char *fault_name = "handle_mm_fault", *access_name = "access_remote_vm";
    const char *read_name = "copy_from_user_nofault", *write_name = "copy_to_user_nofault";
    const char *fp_name = "fpsimd_save_and_flush_current_state";
    const char *pin_name = "pin_user_pages_remote";
    const char *gup_name = "get_user_pages_fast";
    const char *alloc_name = "none";
    void *access;
    int access_argc;
    unsigned foll_force;

    foll_force = uz_foll_force(btf, kver >= VERSION(6, 3, 0) ? 0x08U : 0x10U);
    g_write_gup_flags = foll_force ? UZ_FOLL_WRITE | foll_force : 0;
    if (uz_public_abi(btf, "do_mem_abort", "vlsr"))
        f_do_mem_abort = lookup("do_mem_abort");
    /* Only inspect extended syndrome bits if the entry takes a full ESR. */
    g_abort_has_iss2 = uz_btf_signature(btf, kclf_btf_func_proto(btf, "do_mem_abort"), "vllr");
    f_handle_mm_fault = lookup(fault_name);
    *mmf_argc = f_handle_mm_fault ? uz_mm_fault_argc(btf, fault_name, 1) : 0;
    if (!*mmf_argc) {
        fault_name = "do_handle_mm_fault";
        f_handle_mm_fault = lookup(fault_name);
        *mmf_argc = f_handle_mm_fault ? uz_mm_fault_argc(btf, fault_name, 0) : 0;
    }

    f_get_task_mm = (get_task_mm_t)lookup("get_task_mm");
    f_mmput = (mmput_t)lookup("mmput");
    /* Optional: resolve a pid that names another thread in the same mm.
     * find_task_by_vpid(pid_t) is a stable built-in entry; BTF may encode
     * pid_t as a typedef, so the raw symbol is used after a kallsyms hit.
     * A missing symbol keeps the old pid/tgid-only gate. */
    f_find_task_by_vpid = (find_task_by_vpid_t)lookup("find_task_by_vpid");
    f_find_vma = (find_vma_t)lookup(vma_name);
    if (!f_find_vma || !uz_public_abi(btf, vma_name, "aml")) {
        vma_name = "__find_vma";
        f_find_vma = uz_btf_signature(btf, kclf_btf_func_proto(btf, vma_name), "aml") ?
                     (find_vma_t)lookup(vma_name) : 0;
    }
    if (!f_find_vma || !uz_public_abi(btf, vma_name, "aml")) {
        vma_name = "vma_lookup";
        f_find_vma = (find_vma_t)lookup(vma_name);
    }
    if (f_find_vma && !uz_public_abi(btf, vma_name, "aml")) f_find_vma = 0;

    f_mmap_write_lock = (mmap_write_fn)lookup("mmap_write_lock");
    f_mmap_write_unlock = (mmap_write_fn)lookup("mmap_write_unlock");
    f_mmap_read_lock = (mmap_write_fn)lookup("mmap_read_lock");
    f_mmap_read_unlock = (mmap_write_fn)lookup("mmap_read_unlock");
    if (!f_mmap_read_lock || !f_mmap_read_unlock ||
        !uz_public_abi(btf, "mmap_read_lock", "vm") ||
        !uz_public_abi(btf, "mmap_read_unlock", "vm")) {
        f_mmap_read_lock = 0;
        f_mmap_read_unlock = 0;
        /* mmap_read_* are inline on many 5.x/6.x builds. Do not serialize
         * instruction scans with a write lock merely because their wrappers
         * have no kallsyms entry. Both halves must use the same ABI. */
        if (g_layout.mmap_lock >= 0 &&
            uz_public_abi(btf, "down_read", "vp") &&
            uz_public_abi(btf, "up_read", "vp")) {
            f_mmap_read_lock = (mmap_write_fn)lookup("down_read");
            f_mmap_read_unlock = (mmap_write_fn)lookup("up_read");
            if (!f_mmap_read_lock || !f_mmap_read_unlock)
                f_mmap_read_lock = f_mmap_read_unlock = 0;
            else
                g_read_use_rwsem = 1;
        }
    }
    g_use_rwsem = !f_mmap_write_lock || !f_mmap_write_unlock ||
                  !uz_public_abi(btf, "mmap_write_lock", "vm") ||
                  !uz_public_abi(btf, "mmap_write_unlock", "vm");
    if (g_use_rwsem) {
        f_mmap_write_lock = g_layout.mmap_lock < 0 || !uz_public_abi(btf, "down_write", "vp") ?
            0 : (mmap_write_fn)lookup("down_write");
        f_mmap_write_unlock = g_layout.mmap_lock < 0 || !uz_public_abi(btf, "up_write", "vp") ?
            0 : (mmap_write_fn)lookup("up_write");
    }

    /* Never recursively block on mmap_lock from fault/GUP callbacks. A try
     * lock can fail while a native caller already owns a read lock and a
     * writer is queued; report/retry that condition instead of deadlocking. */
    if (uz_public_abi(btf, "mmap_read_trylock", "bm"))
        f_mmap_tryread_bool = (_Bool (*)(void *))lookup("mmap_read_trylock");
    if (!f_mmap_tryread_bool && g_layout.mmap_lock >= 0 &&
        uz_public_abi(btf, "down_read_trylock", "ip")) {
        f_mmap_tryread = (int (*)(void *))lookup("down_read_trylock");
    }
    /* Resolve before selecting the map-lock path: this helper opens its own
     * RCU section, which must have a matching native unlock. */
    if (uz_public_abi(btf, "__rcu_read_lock", "v") &&
        uz_public_abi(btf, "__rcu_read_unlock", "v")) {
        f_rcu_lock = (void_fn)lookup("__rcu_read_lock");
        f_rcu_unlock = (void_fn)lookup("__rcu_read_unlock");
    }
    if (!f_rcu_lock || !f_rcu_unlock) f_rcu_lock = f_rcu_unlock = 0;
    /* The complete native callback owns both sides of PTL/RCU/lockdep,
     * including the 6.5+ PMD attachment recheck. Its stable ABI works with
     * split locks, RT spinlocks and vendor RCU backports without rebuilding
     * a kernel-config-specific unlock sequence in the module. */
    if (uz_apply_pt_abi(btf, "apply_to_existing_page_range"))
        f_apply_pt = (int (*)(void *, unsigned long, unsigned long, uz_pte_fn, void *))
            lookup("apply_to_existing_page_range");
    /* A raw __rcu_read_unlock cannot balance DEBUG_LOCK_ALLOC. This fallback
     * is only usable with a validated non-RT raw unlock and PREEMPT_RCU. */
    if (!f_apply_pt && uz_native_pt_abi(btf) && f_rcu_lock && f_rcu_unlock &&
        !lookup("rcu_lock_map")) {
        f_map_pt_lock = (uint64_t *(*)(void *, uint64_t *, unsigned long, void **))
            lookup("__pte_offset_map_lock");
        f_pt_unlock = (void (*)(void *))lookup("_raw_spin_unlock");
        if (!f_pt_unlock) f_map_pt_lock = 0;
    }
    if (!f_apply_pt && !f_map_pt_lock && kver < VERSION(5, 8, 0) &&
        !lookup("__pte_offset_map_lock") && !lookup("pte_free_defer")) {
        if (uz_apply_pt_abi(btf, "apply_to_page_range")) {
            f_apply_pt = (int (*)(void *, unsigned long, unsigned long, uz_pte_fn, void *))
                lookup("apply_to_page_range");
            g_apply_pt_create = f_apply_pt != 0;
        }
    }
    if ((!f_mmap_tryread && !f_mmap_tryread_bool) || !f_mmap_read_lock || !f_mmap_read_unlock ||
        (!f_map_pt_lock && !f_apply_pt)) {
        pr_info("urov-z: native PTL/mmap guard ABI unavailable; refusing unlocked PTE access\n");
        return -EOPNOTSUPP;
    }
    if (g_verbose)
        pr_info("urov-z: ptl=%s mmap_guard=tryread levels=%u\n",
            f_map_pt_lock ? "map-lock-rcu" : g_apply_pt_create ? "apply-checked" : "apply-existing",
            g_pt_levels);
    if (uz_contpte_abi(btf))
        f_contpte_unfold = (uz_contpte_unfold_fn)lookup("__contpte_try_unfold");
    if (g_verbose)
        pr_info("urov-z: contiguous PTE write=%s\n", f_contpte_unfold ? "native-unfold" : "unsupported");

    if (uz_public_abi(btf, "force_sig_fault", "iiip"))
        f_force_sig_fault = (force_sig_fault_t)lookup("force_sig_fault");

    f_copy_in = (copy_nofault_t)lookup(read_name);
    if (!f_copy_in || !uz_public_abi(btf, read_name, "lppl")) {
        read_name = "probe_user_read";
        f_copy_in = (copy_nofault_t)lookup(read_name);
    }
    if (f_copy_in && !uz_public_abi(btf, read_name, "lppl")) f_copy_in = 0;
    f_copy_out = (copy_nofault_t)lookup(write_name);
    if (!f_copy_out || !uz_public_abi(btf, write_name, "lppl")) {
        write_name = "probe_user_write";
        f_copy_out = (copy_nofault_t)lookup(write_name);
    }
    if (f_copy_out && !uz_public_abi(btf, write_name, "lppl")) f_copy_out = 0;

    access = lookup(access_name);
    access_argc = access ? uz_access_vm_argc(btf, access_name, 1) : 0;
    if (!access_argc) {
        access_name = "__access_remote_vm";
        access = lookup(access_name);
        access_argc = access ? uz_access_vm_argc(btf, access_name, 0) : 0;
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
        int impl_argc = impl ? uz_access_vm_argc(btf, "__access_remote_vm", 0) : 0;

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

    /* GUP fast is the vmsplice/pipe path.  The page replacement needs a page
     * allocator, a page-to-virt copy helper and vmalloc_to_page for the image
     * pages; if any is missing the overlay stays on the older read paths. */
    g_foll_get = uz_btf_enum_flag(btf, "FOLL_GET", kver < VERSION(6, 3, 0) ? 0x04U : 0);
    g_foll_fast_only = uz_btf_enum_flag(btf, "FOLL_FAST_ONLY",
                                     kver < VERSION(6, 3, 0) ? 0x80000U : 0);
    /* LTO can also bypass get_user_pages_fast(). The shared entry has a
     * 64-bit page count and also accepts PIN / FAST_ONLY callers. Exclude
     * both: their accounting or atomic context is outside this overlay. */
    g_gup_internal = 0;
    if (g_foll_get && g_foll_fast_only) {
        gup_name = "internal_get_user_pages_fast";
        if (!uz_btf_signature(btf, kclf_btf_func_proto(btf, gup_name), "illiD") ||
            !(f_gup_fast = lookup(gup_name))) {
            gup_name = "gup_fast_fallback";
            f_gup_fast = uz_btf_signature(btf, kclf_btf_func_proto(btf, gup_name), "illiD") ?
                         lookup(gup_name) : 0;
        }
        g_gup_internal = f_gup_fast != 0;
    }
    if (!f_gup_fast) {
        gup_name = "get_user_pages_fast";
        f_gup_fast = uz_public_abi(btf, gup_name, "iliiD") ? lookup(gup_name) : 0;
    }
    {
        static const char *const policy_names[] = {
            "alloc_pages_noprof", "alloc_pages", "alloc_pages_current"
        };
        static const char *const names[] = {
            "__alloc_pages_nodemask", "__alloc_pages_noprof", "__alloc_pages"
        };
        unsigned i;
        for (i = 0; i < sizeof(policy_names) / sizeof(policy_names[0]); ++i) {
            if (!uz_btf_signature(btf, kclf_btf_func_proto(btf, policy_names[i]), "Pii"))
                continue;
            g_page_allocator.policy = (void *(*)(unsigned, unsigned))lookup(policy_names[i]);
            if (g_page_allocator.policy) { alloc_name = policy_names[i]; break; }
        }
        g_page_allocator.node_id_offset = uz_pgdat_node_offset(btf);
        if (g_page_allocator.node_id_offset >= 0)
            g_page_allocator.first_online = (void *(*)(void))lookup("first_online_pgdat");
        /* The four-argument entry's preferred_nid must name a real node.
         * Resolve it for each allocation; do not cache a CPU/node from init. */
        for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            if (g_page_allocator.policy || !g_page_allocator.first_online) break;
            if (!uz_btf_signature(btf, kclf_btf_func_proto(btf, names[i]), "Piiip")) continue;
            g_page_allocator.node = (alloc_pages_t)lookup(names[i]);
            if (g_page_allocator.node) { alloc_name = names[i]; break; }
        }
    }
    f_put_page = (put_page_t)lookup("put_page");
    f_copy_highpage = (copy_highpage_t)lookup("copy_highpage");
    f_vmalloc_to_page = (vmalloc_to_page_t)lookup("vmalloc_to_page");
    if (f_put_page && !uz_public_abi(btf, "put_page", "vp")) f_put_page = 0;
    if (f_copy_highpage && !uz_public_abi(btf, "copy_highpage", "vpp"))
        f_copy_highpage = 0;
    if (f_vmalloc_to_page && !uz_public_abi(btf, "vmalloc_to_page", "pp"))
        f_vmalloc_to_page = 0;
    if (!uz_page_allocator_ready(&g_page_allocator) || !f_put_page ||
        !f_copy_highpage || !f_vmalloc_to_page || !f_vmalloc)
        f_gup_fast = 0;

    g_foll_pin = uz_btf_enum_flag(btf, "FOLL_PIN",
        kver < VERSION(6, 3, 0) ? 0x40000U : 0);
    g_foll_longterm = uz_btf_enum_flag(btf, "FOLL_LONGTERM",
        kver < VERSION(6, 3, 0) ? 0x10000U : 0x100U);
    if (g_gup_internal && !g_foll_pin) f_gup_fast = 0;
    f_unpin_page = (void (*)(void *))lookup("unpin_user_page");
    if (!uz_public_abi(btf, "unpin_user_page", "vp")) f_unpin_page = 0;
    if (uz_btf_signature(btf, kclf_btf_func_proto(btf, "try_grab_page"), "bPi"))
        f_grab_page_bool = (_Bool (*)(void *, unsigned))lookup("try_grab_page");
    if (uz_btf_signature(btf, kclf_btf_func_proto(btf, "try_grab_page"), "iPi"))
        f_grab_page_int = (int (*)(void *, unsigned))lookup("try_grab_page");
    if (!f_grab_page_bool && !f_grab_page_int && uz_folio_grab_abi(btf))
        f_grab_folio = (int (*)(void *, int, unsigned))lookup("try_grab_folio");
    if (!f_grab_page_bool && !f_grab_page_int && uz_folio_page_grab_abi(btf))
        f_grab_folio_page = (void *(*)(void *, int, unsigned))lookup("try_grab_folio");
    /* 5.x may inline try_grab_page but retain its compound helper. For our
     * fresh order-0 page it has the same NULL/success convention. */
    if (!f_grab_page_bool && !f_grab_page_int && !f_grab_folio && !f_grab_folio_page &&
        uz_btf_signature(btf, kclf_btf_func_proto(btf, "try_grab_compound_head"), "PPii"))
        f_grab_folio_page = (void *(*)(void *, int, unsigned))lookup("try_grab_compound_head");
    /* Android LTO can inline the public wrapper into process_vm_readv.
     * Resolve the reference family separately from the shared/public entry.
     * PIN-capable shared entries also serve GET, so filter those callers. */
    {
        void *shared = lookup("__get_user_pages_remote");
        void *pin = lookup("pin_user_pages_remote");
        void *get = lookup("get_user_pages_remote");
        int evidence = pin || lookup("unpin_user_page") ||
            kclf_btf_func_proto(btf, "pin_user_pages_remote") ||
            kclf_btf_func_proto(btf, "unpin_user_page") ||
            /* All-ones means absent; invalid/conflicting enum evidence
             * must also prevent a legacy GET fallback. */
            uz_btf_enum_flag(btf, "FOLL_PIN", ~0U) != ~0U;
        struct uz_remote_gup_choice choice = uz_remote_gup_select(
            shared ? uz_remote_gup_argc(btf, "__get_user_pages_remote") : 0,
            pin ? uz_remote_gup_argc(btf, "pin_user_pages_remote") : 0,
            get ? uz_remote_gup_argc(btf, "get_user_pages_remote") : 0, evidence);
        g_pin_argc = choice.argc;
        g_pin_internal = choice.entry == UZ_REMOTE_SHARED;
        g_remote_get = choice.get_refs;
        pin_name = g_pin_internal ? "__get_user_pages_remote" :
                   choice.entry == UZ_REMOTE_PIN ? "pin_user_pages_remote" :
                   choice.entry == UZ_REMOTE_GET ? "get_user_pages_remote" : "none";
        f_pin_remote = g_pin_internal ? shared : choice.entry == UZ_REMOTE_PIN ? pin :
                       choice.entry == UZ_REMOTE_GET ? get : 0;
    }
    f_gup_slow = lookup("__get_user_pages");
    g_gup_slow_argc = f_gup_slow ? uz_remote_gup_argc(btf, "__get_user_pages") : 0;
    if (!g_gup_slow_argc) f_gup_slow = 0;

    /* Deferred native replay: do_debug_exception consumes the software-step
     * exception and __switch_to re-arms MDSCR_EL1.SS after a migration.  Both
     * are required; without them an undecodable store keeps the pre-2.17
     * per-page handoff instead of a replay that could lose its step. */
    f_debug_exception = lookup("do_debug_exception");
    if (f_debug_exception && !uz_public_abi(btf, "do_debug_exception", "vllr"))
        f_debug_exception = 0;
    f_switch_to = lookup("__switch_to");
    if (f_switch_to && !uz_public_abi(btf, "__switch_to", "ptt"))
        f_switch_to = 0;
    /* Snapshot the image at fork time.  copy_mm() is the arm64 fork helper
     * (dup_mm is inlined into it on this kernel). */
    f_copy_mm = lookup("copy_mm");
    if (f_copy_mm && !uz_public_abi(btf, "copy_mm", "ilt"))
        f_copy_mm = 0;

    /* Newer update_current_state() only updates the saved state. Use the
     * save-and-flush helper when present so the EL0 return reloads it. */
    f_fp_preserve = (fpsimd_preserve_t)lookup(fp_name);
    if (!f_fp_preserve || !uz_public_abi(btf, fp_name, "v")) {
        fp_name = "fpsimd_signal_preserve_current_state";
        f_fp_preserve = (fpsimd_preserve_t)lookup(fp_name);
    }
    f_fp_update = (fpsimd_update_t)lookup("fpsimd_update_current_state");
    g_fp_ready = f_fp_preserve && f_fp_update && g_layout.task_fpsimd >= 0 &&
                 uz_public_abi(btf, fp_name, "v") &&
                 uz_public_abi(btf, "fpsimd_update_current_state", "vf");
    g_compat.fault_entry = *mmf_argc ? fault_name : "none";
    g_compat.remote_entry = f_pin_remote ? pin_name : "none";
    g_compat.fast_entry = f_gup_fast ? gup_name : "none";
    g_compat.fp_entry = g_fp_ready ? fp_name : "none";
    g_compat.fault_args = (uint32_t)*mmf_argc;
    g_compat.remote_args = (uint32_t)g_pin_argc;
    g_compat.loader_enabled = (uint32_t)g_loader_enabled;
    g_compat.foll_get = g_foll_get;
    g_compat.foll_pin = g_foll_pin;
    g_compat.foll_longterm = g_foll_longterm;
    g_compat.foll_fast_only = g_foll_fast_only;
    g_compat.foll_force = foll_force;
    uz_record_flag(btf, "FOLL_GET", g_foll_get, 1U);
    uz_record_flag(btf, "FOLL_PIN", g_foll_pin, 2U);
    uz_record_flag(btf, "FOLL_LONGTERM", g_foll_longterm, 4U);
    uz_record_flag(btf, "FOLL_FAST_ONLY", g_foll_fast_only, 8U);
    uz_record_flag(btf, "FOLL_FORCE", foll_force, 16U);
    {
        uint64_t pfr = 0;

        __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr));
        g_fp16 = ((pfr >> 16) & 0xfU) == 1U;
    }

    if (!f_get_task_mm || !f_mmput || !f_find_vma ||
        !f_mmap_write_lock || !f_mmap_write_unlock || !f_force_sig_fault ||
        !f_copy_in || !access_argc || !(f_do_mem_abort && *mmf_argc)) {
        pr_info("urov-z: required MM/uaccess/signal or trap ABI unavailable\n");
        return -EOPNOTSUPP;
    }
    if (g_verbose)
        pr_info("urov-z: kver=%x vma=%s lock=%s mm_fault=%s/%d "
                "access=%s/%d read=%s write=%s find_task=%s fpsimd=%s foll_force=0x%x "
                "page_shift=%u\n",
                kver, vma_name, g_use_rwsem ? "rwsem" : "mmap",
                *mmf_argc ? fault_name : "none", *mmf_argc,
                access_name, access_argc,
                read_name, f_copy_out ? write_name : "control-gup",
                f_find_task_by_vpid ? "task" : "none",
                g_fp_ready ? fp_name : "none", foll_force, g_page_shift);
    if (g_verbose)
        pr_info("urov-z: remote GUP entry=%s/%d internal=%d refs=%s\n",
                pin_name, g_pin_argc, g_pin_internal, g_remote_get ? "GET" : "PIN");
    if (g_verbose)
        pr_info("urov-z: fast GUP entry=%s internal=%d\n", gup_name, g_gup_internal);
    if (g_verbose)
        pr_info("urov-z: alloc=%s slow_gup=%d grab=%s read_lock=%s\n",
                alloc_name, g_gup_slow_argc,
                f_grab_folio ? "folio-int" : f_grab_folio_page ? "page/folio-ptr" :
                (f_grab_page_bool || f_grab_page_int) ? "page" : "none",
                f_mmap_read_lock ? (g_read_use_rwsem ? "rwsem" : "mmap") : "write-fallback");
    if (g_verbose)
        pr_info("urov-z: gup_fast=%d alloc_pages=%d put_page=%d copy_highpage=%d "
                "vmalloc_to_page=%d pin_remote=%d gup_slow=%d page_ref=%d/%d\n",
                f_gup_fast ? 1 : 0, uz_page_allocator_ready(&g_page_allocator),
                f_put_page ? 1 : 0, f_copy_highpage ? 1 : 0,
                f_vmalloc_to_page ? 1 : 0, f_pin_remote ? 1 : 0,
                f_gup_slow ? 1 : 0, g_layout.page_ref_ok, g_layout.page_ref);
    return 0;
}

static long resolve_kernel(const char *btf_path, int *mmf_argc)
{
    struct kclf_btf btf;
    void *storage = 0;
    long ret = 0;

    if (kver < VERSION(5, 4, 0) || kver >= VERSION(7, 0, 0) || resolve_geometry()) {
        pr_info("urov-z: unsupported kernel or page tables (kver=%x)\n", kver);
        return -EOPNOTSUPP;
    }
    resolve_allocators();
    if (!f_kvmalloc_node && !f_vmalloc) return -EOPNOTSUPP;
    f_msleep = (msleep_t)lookup("msleep");
    if (!f_msleep) return -EOPNOTSUPP;
    f_kernel_read = (kernel_read_t)lookup("kernel_read");
    if (btf_path[0]) {
        ret = open_detached_btf(&btf, btf_path, &storage);
    } else {
        uintptr_t start = (uintptr_t)lookup("__start_BTF");
        uintptr_t end = (uintptr_t)lookup("__stop_BTF");

        if (!start || end <= start || end - start > UZ_BTF_MAX ||
            uz_btf_open(&btf, (const void *)start, end - start))
            ret = -EOPNOTSUPP;
    }
    if (ret) {
        pr_info("urov-z: cannot open %s BTF (%ld); matching layout is required\n",
                btf_path[0] ? "detached" : "live", ret);
    } else if (uz_layout_from_btf(&g_layout, &btf)) {
        pr_info("urov-z: incompatible MM/register layout in %s BTF\n",
                btf_path[0] ? "detached" : "live");
        ret = -EOPNOTSUPP;
    } else {
        g_compat.btf_source = btf_path[0] ? "detached-build-id" : "live";
        if (g_verbose)
            pr_info("urov-z: btf=%s task.mm=%d mm.pgd=%d mm.users=%d mmap_lock=%d "
                    "vma.flags=%d task.fpsimd=%d\n", btf_path[0] ? "detached" : "live",
                    g_layout.task_mm, g_layout.mm_pgd, g_layout.mm_users, g_layout.mmap_lock,
                    g_layout.vma_flags, g_layout.task_fpsimd);
        ret = resolve_symbols(&btf, mmf_argc);
#if UROV_Z_WITH_KCLF
        if (!ret && g_loader_enabled) ret = urov_kclf_set_btf(&btf);
        if (!ret && g_loader_enabled) ret = urov_kclf_preflight();
#endif
    }
    uz_free(storage);
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

#define UZ_BTF_PATH_MAX 192U

static long parse_args(const char *args, uint8_t key[16], int *have_key,
                       char btf_path[UZ_BTF_PATH_MAX])
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
            if (uz_parse_key(v, n, key)) return -EINVAL;
            *have_key = 1;
        } else if (prefix(p, "verbose", 7) && (p[7] == 0 || p[7] == ' ')) {
            g_verbose = 1;
        } else if (prefix(p, "writes=", 7)) {
            v = p + 7;
            while (v[n] && v[n] != ' ') ++n;
            if (n == 2 && !memcmp(v, "rx", 2)) g_experimental_writes = 0;
            else if (n == 12 && !memcmp(v, "experimental", 12)) g_experimental_writes = 1;
            else return -EINVAL;
        } else if (prefix(p, "loader=", 7)) {
            v = p + 7;
            while (v[n] && v[n] != ' ') ++n;
            if (n == 3 && !memcmp(v, "off", 3)) g_loader_enabled = 0;
            else if (n == 2 && !memcmp(v, "on", 2) && UROV_Z_WITH_KCLF) g_loader_enabled = 1;
            else return -EINVAL;
        } else if (prefix(p, "fork_copies=", 12)) {
            uint32_t value;
            v = p + 12;
            while (v[n] && v[n] != ' ') ++n;
            if (parse_u32(v, n, &value) || value > 4U) return -EINVAL;
            g_fork_copies = value;
        } else if (prefix(p, "buffer_kb=", 10)) {
            uint32_t value;
            v = p + 10;
            while (v[n] && v[n] != ' ') ++n;
            if (parse_u32(v, n, &value) || value < 64U || value > 256U * 1024U)
                return -EINVAL;
            g_buffers.limit = (uint64_t)value << 10;
        } else if (prefix(p, "btf=", 4)) {
            v = p + 4;
            while (v[n] && v[n] != ' ') ++n;
            if (btf_path[0] || v[0] != '/' || n < 2 || n >= UZ_BTF_PATH_MAX)
                return -EINVAL;
            memcpy(btf_path, v, n);
            btf_path[n] = 0;
        } else if (prefix(p, "max_pages=", 10)) {
            uint32_t value;
            v = p + 10;
            while (v[n] && v[n] != ' ') ++n;
            if (parse_u32(v, n, &value) || value == 0 || value > UROV_Z_MAX_PAGES)
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

long urov_z_backend_init(const char *args)
{
    uint8_t key[16];
    char btf_path[UZ_BTF_PATH_MAX] = {0};
    int have_key = 0;
    unsigned int checks = 0;
    long ret;
    int i, mmf_argc;

    memset(key, 0, sizeof(key));
    ret = parse_args(args, key, &have_key, btf_path);
    if (ret) return ret;
    if (!have_key) return -EINVAL;
    uz_derive(key, &g_keys);
    memset(key, 0, sizeof(key));

    if (!kallsyms_lookup_name) return -ENOSYS;
    /* The pre-window proof may only name the EL0 cache-maintenance encodings
     * that this core actually lets EL0 execute.  SCTLR_EL1.UCI (bit 26)
     * enables DC CVAC/CVAU/CIVAC/CVAP/CVADP and IC IVAU/IALLU, .DZE (bit 14)
     * enables DC ZVA.  If a bit is clear the encoding traps at EL0, so the
     * proof has to keep declining it. */
    {
        uint64_t sctlr;

        __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
        uz_pre_uci = (unsigned)((sctlr >> 26) & 1U);
        uz_pre_dze = (unsigned)((sctlr >> 14) & 1U);
        if (g_verbose)
            pr_info("urov-z: el0 cache ops uci=%u dze=%u\n", uz_pre_uci, uz_pre_dze);
    }
    if (uro_core_selftest(g_selftest_ws, &checks) || checks != URO_CORE_CHECKS) return -EINVAL;

    ret = resolve_kernel(btf_path, &mmf_argc);
    if (ret) return ret;
    ret = uz_linear_init((const int64_t *)lookup("memstart_addr"));
    if (ret) {
        pr_info("urov-z: unable to validate the arm64 linear map before hooks\n");
        return ret;
    }
    if (g_max_pages > g_max_image_bytes / (7U * g_page_size))
        g_max_pages = (uint32_t)(g_max_image_bytes / (7U * g_page_size));
    if (!g_max_pages) return -EINVAL;
    /* Preserve the advertised legacy quota when writes is switched inactive;
     * the RX allocation saving must not silently increase default workloads. */
    g_page_buffers = g_experimental_writes ? 7U : 3U;
    g_wrapper_mode = has_syscall_wrapper ? 1 : 0;

    ret = fp_hook_syscalln(__NR_prctl, 6, uz_prctl_before, 0, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-z: hook prctl failed: %ld\n", ret);
        goto unwind_prctl;
    }
    g_prctl_hooked = 1;

    /* Retain a session reader for the complete native readv copy. */
    ret = fp_hook_syscalln(__NR_process_vm_readv, 6, uz_vm_readv_before, uz_vm_readv_after, 0);
    if (ret) {
        if (g_verbose) pr_info("urov-z: hook process_vm_readv failed: %ld\n", ret);
        goto unwind_prctl;
    }
    g_vm_readv_hooked = 1;

    /* Kernel-assisted reads: one function hook covers /proc/<pid>/mem,
     * ptrace and every other access_remote_vm() caller. */
    if (f_kread) {
        ret = hook_wrap(f_kread, g_kread_argc, 0, uz_kread_after, 0);
        g_kread_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook kernel read failed: %ld\n", ret);
    } else if (g_verbose) {
        pr_info("urov-z: access_remote_vm overlay unavailable\n");
    }
    if (f_gup_fast) {
        ret = hook_wrap((void *)f_gup_fast, 4, 0, uz_gup_after, 0);
        g_gup_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook GUP fast failed: %ld\n", ret);
    } else if (g_verbose) {
        pr_info("urov-z: no GUP-fast overlay; vmsplice reads live bytes\n");
    }

    if (f_pin_remote) {
        ret = hook_wrap(f_pin_remote, g_pin_argc, 0, uz_pin_after, 0);
        g_pin_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook remote GUP failed: %ld\n", ret);
    }
    if (f_gup_slow) {
        ret = hook_wrap(f_gup_slow, g_gup_slow_argc, 0, uz_gup_slow_after, 0);
        g_gup_slow_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook __get_user_pages failed: %ld\n", ret);
    }
    g_pin_ok = g_pin_hooked && uz_page_allocator_ready(&g_page_allocator) && f_put_page && f_vmalloc &&
               f_copy_highpage && f_vmalloc_to_page &&
               (g_remote_get || (g_foll_pin && f_unpin_page &&
                (f_grab_page_bool || f_grab_page_int || f_grab_folio || f_grab_folio_page)));
    if (g_verbose && !g_pin_ok)
        pr_info("urov-z: process_vm_readv overlay unavailable "
                "(pin=%d ref=%d v2p=%d)\n", g_pin_hooked, g_foll_pin != 0,
                f_vmalloc_to_page ? 1 : 0);

    for (i = 0; i < UZ_GATE_NUM; ++i) {
        ret = fp_hook_syscalln(g_gate_nrs[i], 6, uz_gate_before, uz_gate_after,
                               (void *)(uintptr_t)i);
        if (ret) {
            if (g_verbose) pr_info("urov-z: hook gate %d failed: %ld\n", g_gate_nrs[i], ret);
            break;
        }
        g_gate_hooked[i] = 1;
    }
    if (i != UZ_GATE_NUM) {
        while (i-- > 0) {
            fp_unhook_syscalln(g_gate_nrs[i], uz_gate_before, uz_gate_after);
            g_gate_hooked[i] = 0;
        }
        goto unwind_prctl;
    }

    /* PAGE_AP requires the abort hook and the PTE rearm hook. */
    if (f_do_mem_abort && mmf_argc) {
        ret = hook_wrap(f_do_mem_abort, 3, uz_abort_before, 0, 0);
        g_page_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook do_mem_abort failed: %ld\n", ret);
    }
    if (g_page_hooked) {
        ret = hook_wrap(f_handle_mm_fault, mmf_argc, uz_mm_fault_before, uz_mm_fault_after,
                        (void *)(uintptr_t)mmf_argc);
        g_mmf_hooked = ret ? 0 : 1;
        if (ret) {
            if (g_verbose) pr_info("urov-z: hook MM fault handler failed: %ld\n", ret);
            hook_unwrap(f_do_mem_abort, uz_abort_before, 0);
            g_page_hooked = 0;
        }
    }
    if (!g_page_hooked) {
        urov_z_backend_exit();
        return -EOPNOTSUPP;
    }
    /* Deferred native replay needs the software-step consumer and the
     * migration re-arm.  A failure here only keeps the pre-2.17 store
     * handoff; init still succeeds. */
    if (UROV_Z_NATIVE_STEP && f_debug_exception) {
        ret = hook_wrap(f_debug_exception, 3, uz_dbg_before, 0, 0);
        g_dbg_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook debug exception failed: %ld\n", ret);
    }
    if (UROV_Z_NATIVE_STEP && f_switch_to) {
        ret = hook_wrap(f_switch_to, 2, 0, uz_switch_after, 0);
        g_switch_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook __switch_to failed: %ld\n", ret);
    }
    if (f_copy_mm) {
        ret = hook_wrap(f_copy_mm, 2, 0, uz_copy_mm_after, 0);
        g_copymm_hooked = ret ? 0 : 1;
        if (ret && g_verbose) pr_info("urov-z: hook copy_mm failed: %ld\n", ret);
    }
    ret = fp_hook_syscalln(__NR_clone, 6, uz_clone_before, uz_clone_after, 0);
    g_clone_hooked = ret ? 0 : 1;
    ret = fp_hook_syscalln(__NR_clone3, 6, uz_clone_before, uz_clone_after, (void *)1);
    g_clone3_hooked = ret ? 0 : 1;
    if (!g_clone_hooked || !g_clone3_hooked) {
        urov_z_backend_exit();
        return -EOPNOTSUPP;
    }
    g_ss_ok = g_dbg_hooked && g_switch_hooked;
    if (g_page_shift == 14U) g_caps |= UROV_Z_CAP_16K;
    if (g_page_hooked) {
        g_caps |= UROV_Z_CAP_MULTI | UROV_Z_CAP_CROSS |
                  UROV_Z_CAP_PAGE_AP;
        if (g_fp_ready)
            g_caps |= UROV_Z_CAP_LD1 | UROV_Z_CAP_LD2 | UROV_Z_CAP_LD3 | UROV_Z_CAP_LD4;
    }
    if (g_kread_hooked) g_caps |= UROV_Z_CAP_REMOTE_VM;
    if (g_pin_ok) g_caps |= UROV_Z_CAP_READV;
    if (g_gup_hooked) g_caps |= UROV_Z_CAP_GUP;
    if (g_ss_ok) g_caps |= UROV_Z_CAP_STEP;
    if (g_copymm_hooked && g_fork_copies) g_caps |= UROV_Z_CAP_FORK_SNAPSHOT;
    __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);

    if (g_verbose)
        pr_info("urov-z: mdscr at init=%llx step_hooks=%d/%d\n",
                (unsigned long long)uz_mdscr_read(), g_dbg_hooked, g_switch_hooked);
    if (g_verbose)
        pr_info("urov-z: PAGE_AP all-callers ready caps=%x\n", g_caps);
    return 0;

unwind_prctl:
    g_pin_ok = 0;
    if (g_gup_slow_hooked) {
        hook_unwrap(f_gup_slow, 0, uz_gup_slow_after);
        g_gup_slow_hooked = 0;
    }
    if (g_pin_hooked) {
        hook_unwrap(f_pin_remote, 0, uz_pin_after);
        g_pin_hooked = 0;
    }
    if (g_gup_hooked) {
        hook_unwrap((void *)f_gup_fast, 0, uz_gup_after);
        g_gup_hooked = 0;
    }
    if (g_kread_hooked) {
        hook_unwrap(f_kread, 0, uz_kread_after);
        g_kread_hooked = 0;
    }
    if (g_vm_readv_hooked) {
        fp_unhook_syscalln(__NR_process_vm_readv, uz_vm_readv_before, uz_vm_readv_after);
        g_vm_readv_hooked = 0;
    }
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, uz_prctl_before, 0);
        g_prctl_hooked = 0;
    }
    return -EOPNOTSUPP;
}

long urov_z_copy_to_user(void *dst, const void *src, unsigned long len)
{
    /* A legacy KPM loader can call ctl0 inside an RCU read-side section. */
    return f_copy_out ? f_copy_out(dst, src, len) : -EOPNOTSUPP;
}

long urov_z_backend_exit(void)
{
    int i, ret;

    if (g_verbose)
        pr_info("urov-z: exit live=%d\n", overlay_live());
    __atomic_store_n(&g_ready, 0, __ATOMIC_RELEASE);
    while (!ctrl_try_lock()) f_msleep(1);
    /* KernelPatch 0.12.0 can invoke exit inside rcu_read_lock(). A Tasks
     * grace period here can self-deadlock. Complete DEACTIVATE in the owner
     * before unloading on such hosts; this is only best-effort restoration. */
    ret = release_session();
    ctrl_unlock();
    if (ret) {
        __atomic_store_n(&g_ready, 1, __ATOMIC_RELEASE);
        return ret;
    }
    if (g_clone_hooked) {
        fp_unhook_syscalln(__NR_clone, uz_clone_before, uz_clone_after);
        g_clone_hooked = 0;
    }
    if (g_clone3_hooked) {
        fp_unhook_syscalln(__NR_clone3, uz_clone_before, uz_clone_after);
        g_clone3_hooked = 0;
    }
    for (i = 0; i < UZ_GATE_NUM; ++i) {
        if (!g_gate_hooked[i]) continue;
        fp_unhook_syscalln(g_gate_nrs[i], uz_gate_before, uz_gate_after);
        g_gate_hooked[i] = 0;
    }
    if (g_prctl_hooked) {
        fp_unhook_syscalln(__NR_prctl, uz_prctl_before, 0);
        g_prctl_hooked = 0;
    }
    if (g_vm_readv_hooked) {
        fp_unhook_syscalln(__NR_process_vm_readv, uz_vm_readv_before, uz_vm_readv_after);
        g_vm_readv_hooked = 0;
    }
    g_pin_ok = 0;
    if (g_gup_slow_hooked) {
        hook_unwrap(f_gup_slow, 0, uz_gup_slow_after);
        g_gup_slow_hooked = 0;
    }
    if (g_pin_hooked) {
        hook_unwrap(f_pin_remote, 0, uz_pin_after);
        g_pin_hooked = 0;
    }
    if (g_kread_hooked) {
        hook_unwrap(f_kread, 0, uz_kread_after);
        g_kread_hooked = 0;
    }
    if (g_gup_hooked) {
        hook_unwrap((void *)f_gup_fast, 0, uz_gup_after);
        g_gup_hooked = 0;
    }
    if (g_page_hooked) {
        hook_unwrap(f_do_mem_abort, uz_abort_before, 0);
        g_page_hooked = 0;
    }
    if (g_mmf_hooked) {
        hook_unwrap(f_handle_mm_fault, uz_mm_fault_before, uz_mm_fault_after);
        g_mmf_hooked = 0;
    }
    if (g_copymm_hooked) {
        hook_unwrap(f_copy_mm, 0, uz_copy_mm_after);
        g_copymm_hooked = 0;
    }
    if (g_switch_hooked) {
        hook_unwrap(f_switch_to, 0, uz_switch_after);
        g_switch_hooked = 0;
    }
    if (g_dbg_hooked) {
        hook_unwrap(f_debug_exception, uz_dbg_before, 0);
        g_dbg_hooked = 0;
    }
    g_ss_ok = 0;
    memset(&g_keys, 0, sizeof(g_keys));
    return 0;
}

/* KPM ctl0 is authenticated by the host. A mode is fixed for the entire
 * session, including all child snapshots and pending readers. */
long urov_z_set_writes(int experimental)
{
    long ret = 0;
    if (experimental != 0 && experimental != 1) return -EINVAL;
    if (!ctrl_try_lock()) return -EBUSY;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) ret = -EOPNOTSUPP;
    else if (overlay_live() || g_sess.mm) ret = -EBUSY;
    else {
        g_experimental_writes = experimental;
        g_page_buffers = experimental ? 7U : 3U;
    }
    ctrl_unlock();
    return ret;
}

long urov_z_set_resources(const char *args)
{
    uint32_t value;
    int fork_option;
    uint64_t irq;
    long ret = 0;
    if (!args) return -EINVAL;
    fork_option = prefix(args, "fork_copies=", 12);
    if (!fork_option && !prefix(args, "buffer_kb=", 10)) return -EINVAL;
    args += fork_option ? 12 : 10;
    if (parse_u32(args, (unsigned)strlen(args), &value) ||
        (fork_option ? value > 4U : value < 64U || value > 256U * 1024U)) return -EINVAL;
    if (!ctrl_try_lock()) return -EBUSY;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) ret = -EOPNOTSUPP;
    else if (overlay_live() || g_sess.mm) ret = -EBUSY;
    else if (fork_option) {
        g_fork_copies = value;
        if (value && g_copymm_hooked) g_caps |= UROV_Z_CAP_FORK_SNAPSHOT;
        else g_caps &= ~UROV_Z_CAP_FORK_SNAPSHOT;
    } else {
        irq = uz_irq_save();
        (void)uz_short_lock_take(&g_buffer_lock);
        if (g_buffers.used > ((uint64_t)value << 10)) ret = -EBUSY;
        else g_buffers.limit = (uint64_t)value << 10;
        uz_short_lock_drop(&g_buffer_lock);
        uz_irq_restore(irq);
    }
    ctrl_unlock();
    return ret;
}

long urov_z_status_get(struct uz_status *out)
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
        out->armed = armed_pages();
        out->overlay_len = g_sess.pages[0].fake_len;
        out->page_count = g_sess.page_count;
    }
    for (i = 0; i < UZ_GATE_NUM; ++i) gates &= g_gate_hooked[i];
    out->hooks = (g_prctl_hooked ? 2U : 0U) |
                 (gates ? 4U : 0U) |
                 (g_page_hooked ? 32U : 0U) | (g_mmf_hooked ? 64U : 0U) |
                 (g_kread_hooked ? 128U : 0U);
    out->degraded = __atomic_load_n(&g_degraded, __ATOMIC_ACQUIRE) ? 1U : 0U;
    out->core_checks = URO_CORE_CHECKS;
    out->fpsimd = g_page_hooked && g_fp_ready;
    out->abi = UROV_Z_ABI_VERSION;
    out->page_shift = g_page_shift;
    out->caps = g_caps;
    out->experimental_writes = (uint32_t)g_experimental_writes;
    out->native_ptl = f_map_pt_lock ? 2U : 1U;
    if (g_apply_pt_create) out->native_ptl = 3U;
    out->contpte = f_contpte_unfold != 0;
    out->readv_refs = !g_pin_ok ? 0U : g_remote_get ? 1U : 2U;
    out->loader_enabled = (uint32_t)g_loader_enabled;
    ctrl_unlock();
    return 0;
}

long urov_z_perf_get(struct uz_perf *out)
{
    if (!out) return -EINVAL;
    if (!ctrl_try_lock()) return -EBUSY;
    memset(out, 0, sizeof(*out));
    out->enabled = UROV_Z_DIAGNOSTICS;
    out->code_valid = __atomic_load_n(&g_code.valid, __ATOMIC_ACQUIRE);
    out->code_complete = __atomic_load_n(&g_code.complete, __ATOMIC_ACQUIRE);
#define UZ_PERF_READ(field) out->field = __atomic_load_n(&g_perf.field, __ATOMIC_RELAXED)
    UZ_PERF_READ(loads);
    UZ_PERF_READ(llsc_prepares);
    UZ_PERF_READ(map_declines);
    UZ_PERF_READ(scan_calls);
    UZ_PERF_READ(scan_words);
    UZ_PERF_READ(insn_fetches);
    UZ_PERF_READ(insn_nofault);
    UZ_PERF_READ(identity_lookups);
    UZ_PERF_READ(identity_compares);
    UZ_PERF_READ(single_page);
    UZ_PERF_READ(cache_hits);
    UZ_PERF_READ(cache_misses);
    UZ_PERF_READ(cache_invalidations);
    UZ_PERF_READ(cache_bytes);
    UZ_PERF_READ(image_locks);
    UZ_PERF_READ(image_contended);
    UZ_PERF_READ(image_spins);
    UZ_PERF_READ(image_wait_max);
    UZ_PERF_READ(image_hold_max);
#if UROV_Z_DIAGNOSTICS
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(out->clock_hz));
#endif
#undef UZ_PERF_READ
    ctrl_unlock();
    return 0;
}

long urov_z_health_get(struct uz_health *out)
{
    if (!out) return -EINVAL;
    memset(out, 0, sizeof(*out));
#define UZ_HEALTH_READ(field) out->field = __atomic_load_n(&g_health.field, __ATOMIC_RELAXED)
    UZ_HEALTH_READ(mmap_busy);
    UZ_HEALTH_READ(fault_retries);
    UZ_HEALTH_READ(rearm_attempts);
    UZ_HEALTH_READ(rearm_ok);
    UZ_HEALTH_READ(rearm_busy);
    UZ_HEALTH_READ(rearm_missing);
    UZ_HEALTH_READ(rearm_rejected);
    UZ_HEALTH_READ(rearm_identity);
    UZ_HEALTH_READ(retired_writes);
    UZ_HEALTH_READ(readv_slots_full);
    UZ_HEALTH_READ(gup_alloc_failures);
    UZ_HEALTH_READ(last_rearm_error);
#undef UZ_HEALTH_READ
    return 0;
}

long urov_z_memory_get(struct uz_memory *out)
{
    uint64_t irq;
    if (!out) return -EINVAL;
    if (!ctrl_try_lock()) return -EBUSY;
    memset(out, 0, sizeof(*out));
    irq = uz_irq_save();
    (void)uz_short_lock_take(&g_buffer_lock);
    out->limit = g_buffers.limit;
    out->used = g_buffers.used;
    out->peak = g_buffers.peak;
    out->denied = g_buffers.denied;
    uz_short_lock_drop(&g_buffer_lock);
    uz_irq_restore(irq);
    out->page_buffers = g_page_buffers;
    out->shadow_slots = g_shadow_max;
    out->shadow_used = __atomic_load_n(&g_shadow_used, __ATOMIC_RELAXED);
    out->fork_copies = g_fork_copies;
    ctrl_unlock();
    return 0;
}

long urov_z_compat_get(struct uz_compat_info *out)
{
    if (!out) return -EINVAL;
    if (!__atomic_load_n(&g_ready, __ATOMIC_ACQUIRE)) return -EOPNOTSUPP;
    *out = g_compat; /* immutable after preflight; all names are literals */
    return 0;
}

int urov_z_loader_enabled(void)
{
    return g_loader_enabled;
}
