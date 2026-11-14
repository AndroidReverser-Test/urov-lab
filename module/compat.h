/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_COMPAT_H
#define UROV_Z_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#if __STDC_HOSTED__
#include <string.h>
#else
#include <linux/string.h>
#endif

/* Use the raw reader so the same KPM also loads on hosts without KP BTF exports. */
#include "btf.h"

struct uz_layout {
    int task_mm;
    int task_pid;
    int task_tgid;
    int mm_pgd;
    int mm_users;
    int mmap_lock;
    int vma_start;
    int vma_end;
    int vma_mm;
    int vma_flags;
    int vma_file;
    int vma_pgoff;
    int vma_pgoff_ok;
    /* offsetof(task_struct, thread.uw.fpsimd_state); -1 when the running
     * kernel's BTF does not describe the FPSIMD layout we can drive. */
    int task_fpsimd;
    int task_sve_state;
    int task_sme_state;
    /* offsetof(struct page, _refcount.counter) (or refcount.counter on newer
     * sources); -1 when BTF does not describe struct page.  The overlay hands
     * an image page back through pin_user_pages_remote(), which the caller
     * releases with unpin_user_page() (a GUP_PIN_COUNTING_BIAS subtraction),
     * so the substitution has to move that bias between the two pages. */
    int page_ref;
    int page_ref_ok;
};

struct uz_geometry {
    unsigned page_shift;
    unsigned user_va_bits;
};

/* KernelPatch's walker uses the kernel translation depth for any PGD.
 * Arm64 4K and 16K non-LPA2 descriptors both carry <=48-bit output addresses. */
static int uz_geometry_from_tcr(struct uz_geometry *out, uint64_t tcr)
{
    unsigned tg0 = (tcr >> 14) & 3U, tg1 = (tcr >> 30) & 3U;
    unsigned t0sz = tcr & 63U, t1sz = (tcr >> 16) & 63U;
    unsigned shift, stride;

    if ((tcr & (UINT64_C(1) << 59)) || ((tcr >> 32) & 7U) > 5U ||
        t0sz < 16U || t0sz > 39U || t1sz < 16U || t1sz > 39U)
        return -1;
    if (tg0 == 0U && tg1 == 2U) shift = 12;
    else if (tg0 == 2U && tg1 == 1U) shift = 14;
    else return -1;
    stride = shift - 3;
    if ((60U - t0sz) / stride != (60U - t1sz) / stride) return -1;
    out->page_shift = shift;
    out->user_va_bits = 64U - t0sz;
    return 0;
}

/* Direct member lookup (no recursion, so it is one scan of one type). */
static int uz_btf_member(const struct kclf_btf *btf, const struct kclf_btf_type *type,
                         const char *name, uint32_t *type_id)
{
    const struct kclf_btf_member *member;
    unsigned kind, i, n;

    if (!type) return -1;
    kind = (type->info >> 24) & 31;
    if (kind != 4 && kind != 5) return -1;
    member = (const void *)(type + 1);
    n = type->info & 0xffff;
    for (i = 0; i < n; i++) {
        uint32_t bitoff = (type->info >> 31) ? (member[i].offset & 0xffffff)
                                             : member[i].offset;
        if ((bitoff & 7) || ((type->info >> 31) && (member[i].offset >> 24)) ||
            bitoff / 8 >= type->size)
            continue;
        if (member[i].name && !strcmp(kclf_btf_name(btf, member[i].name), name)) {
            if (type_id) *type_id = member[i].type;
            return (int)(bitoff / 8);
        }
    }
    return -1;
}

/* uapi struct user_fpsimd_state: 32 16-byte vregs, then fpsr/fpcr.  The
 * register file update helper takes a pointer to it, so its layout has to be
 * verified rather than assumed. */
static int uz_fpsimd_layout(const struct kclf_btf *btf,
                            const struct kclf_btf_type *state)
{
    return uz_btf_member(btf, state, "vregs", 0) == 0 &&
           uz_btf_member(btf, state, "fpsr", 0) == 512 &&
           uz_btf_member(btf, state, "fpcr", 0) == 516;
}

/* Size of uapi struct user_fpsimd_state as mirrored by struct uz_fpstate. */
#define UZ_FPSIMD_BYTES 528U

/* Only follow aggregates and verify each containment boundary. */
static int uz_fpsimd_member(const struct kclf_btf *btf,
                            const struct kclf_btf_type *container)
{
    const struct kclf_btf_type *state;
    uint32_t id;
    int off = uz_btf_member(btf, container, "fpsimd_state", &id);

    if (off < 0) return -1;
    state = kclf_btf_resolve(btf, id);
    if (!state || ((state->info >> 24) & 31) != 4 || state->size != UZ_FPSIMD_BYTES ||
        strcmp(kclf_btf_name(btf, state->name), "user_fpsimd_state") ||
        UZ_FPSIMD_BYTES > container->size - (unsigned)off || !uz_fpsimd_layout(btf, state))
        return -1;
    return off;
}

static int uz_fpsimd_offset(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *task = kclf_btf_find(btf, "task_struct", 0);
    const struct kclf_btf_type *thread, *uw;
    uint32_t thread_type = 0, uw_type = 0;
    int thread_off, uw_off, fp_off;
    unsigned i, n;

    thread_off = uz_btf_member(btf, task, "thread", &thread_type);
    if (thread_off < 0) return -1;
    thread = kclf_btf_resolve(btf, thread_type);
    if (!thread || ((thread->info >> 24) & 31) != 4 ||
        thread->size > task->size - (unsigned)thread_off)
        return -1;
    uw_off = uz_btf_member(btf, thread, "uw", &uw_type);
    if (uw_off >= 0) {
        uw = kclf_btf_resolve(btf, uw_type);
        fp_off = uz_fpsimd_member(btf, uw);
        if (fp_off >= 0 && uw->size <= thread->size - (unsigned)uw_off &&
            !((thread_off + uw_off + fp_off) & 15))
            return thread_off + uw_off + fp_off;
    }
    /* Older/renamed layouts: accept a direct member, or any anonymous member
     * one level deep that itself holds user_fpsimd_state. */
    fp_off = uz_fpsimd_member(btf, thread);
    if (fp_off >= 0)
        return (thread_off + fp_off) & 15 ? -1 : thread_off + fp_off;
    n = thread->info & 0xffff;
    for (i = 0; i < n; i++) {
        const struct kclf_btf_member *member = (const void *)(thread + 1);
        uint32_t bitoff = (thread->info >> 31) ? (member[i].offset & 0xffffff)
                                               : member[i].offset;
        const struct kclf_btf_type *sub;
        int sub_off;
        if (member[i].name || (bitoff & 7) ||
            ((thread->info >> 31) && (member[i].offset >> 24)) || bitoff / 8 >= thread->size)
            continue;
        sub = kclf_btf_resolve(btf, member[i].type);
        sub_off = uz_fpsimd_member(btf, sub);
        if (sub_off >= 0 && sub->size <= thread->size - bitoff / 8 &&
            !((thread_off + (int)(bitoff / 8) + sub_off) & 15))
            return thread_off + (int)(bitoff / 8) + sub_off;
    }
    return -1;
}

static int uz_task_thread_ptr(const struct kclf_btf *btf, const char *name)
{
    const struct kclf_btf_type *task = kclf_btf_find(btf, "task_struct", 0);
    const struct kclf_btf_type *thread, *type;
    uint32_t id;
    int thread_off = uz_btf_member(btf, task, "thread", &id);
    int off;

    if (thread_off < 0) return -1;
    thread = kclf_btf_resolve(btf, id);
    if (!thread || thread->size > task->size - (unsigned)thread_off) return -1;
    off = uz_btf_member(btf, thread, name, &id);
    if (off < 0 || ((thread_off + off) & 7) || thread->size - (unsigned)off < 8) return -1;
    type = kclf_btf_resolve(btf, id);
    return type && ((type->info >> 24) & 31U) == 2U ? thread_off + off : -1;
}

static int uz_layout_from_btf(struct uz_layout *layout, const struct kclf_btf *btf)
{
    const struct kclf_btf_type *sem = kclf_btf_find(btf, "rw_semaphore", 0);
    const struct kclf_btf_type *page = kclf_btf_find(btf, "page", 0);

    layout->task_mm = kclf_btf_member_range(btf, "task_struct", "mm", 8, 8);
    layout->task_pid = kclf_btf_member_range(btf, "task_struct", "pid", 4, 4);
    layout->task_tgid = kclf_btf_member_range(btf, "task_struct", "tgid", 4, 4);
    layout->mm_pgd = kclf_btf_member_range(btf, "mm_struct", "pgd", 8, 8);
    layout->mm_users = kclf_btf_member_range(btf, "mm_struct", "mm_users", 4, 4);
    layout->vma_start = kclf_btf_member_range(btf, "vm_area_struct", "vm_start", 8, 8);
    layout->vma_end = kclf_btf_member_range(btf, "vm_area_struct", "vm_end", 8, 8);
    layout->vma_mm = kclf_btf_member_range(btf, "vm_area_struct", "vm_mm", 8, 8);
    layout->vma_flags = kclf_btf_member_range(btf, "vm_area_struct", "vm_flags", 8, 8);
    if (layout->vma_flags < 0)
        layout->vma_flags = kclf_btf_member_range(btf, "vm_area_struct", "__vm_flags", 8, 8);
    layout->vma_file = kclf_btf_member_range(btf, "vm_area_struct", "vm_file", 8, 8);
    layout->vma_pgoff = kclf_btf_member_range(btf, "vm_area_struct", "vm_pgoff", 8, 8);
    layout->vma_pgoff_ok = layout->vma_pgoff >= 0;
    layout->task_fpsimd = uz_fpsimd_offset(btf);
    layout->task_sve_state = uz_task_thread_ptr(btf, "sve_state");
    layout->task_sme_state = uz_task_thread_ptr(btf, "sme_state");
    /* struct page's refcount has been named _refcount (<= 6.5) and refcount
     * (>= 6.6); both wrap an atomic_t whose only member is `counter`. */
    layout->page_ref = -1;
    if (page) {
        uint32_t ref_type = 0;
        int ref_off = uz_btf_member(btf, page, "_refcount", &ref_type);

        if (ref_off < 0) ref_off = uz_btf_member(btf, page, "refcount", &ref_type);
        if (ref_off >= 0) {
            const struct kclf_btf_type *atomic = kclf_btf_resolve(btf, ref_type);
            int cnt_off = uz_btf_member(btf, atomic, "counter", 0);

            if (cnt_off >= 0 && atomic->size >= (unsigned)cnt_off + 4U &&
                page->size >= (unsigned)(ref_off + cnt_off) + 4U)
                layout->page_ref = ref_off + cnt_off;
        }
    }
    layout->page_ref_ok = layout->page_ref >= 0;
    layout->mmap_lock = -1;
    if (sem && sem->size >= 16 && sem->size <= 512) {
        layout->mmap_lock = kclf_btf_member_range(btf, "mm_struct", "mmap_lock", sem->size, 8);
        if (layout->mmap_lock < 0)
            layout->mmap_lock = kclf_btf_member_range(btf, "mm_struct", "mmap_sem", sem->size, 8);
    }

    /* Only the AArch64 user register prefix is used by the hooks. */
    if (kclf_btf_member_range(btf, "pt_regs", "regs", 31 * 8, 8) != 0 ||
        kclf_btf_member_range(btf, "pt_regs", "sp", 8, 8) != 248 ||
        kclf_btf_member_range(btf, "pt_regs", "pc", 8, 8) != 256 ||
        kclf_btf_member_range(btf, "pt_regs", "pstate", 8, 8) != 264)
        return -1;

    return layout->task_mm < 0 || layout->mm_pgd < 0 || layout->mm_users < 0 ||
           layout->vma_start < 0 || layout->vma_end < 0 || layout->vma_mm < 0 ||
           layout->vma_flags < 0 || layout->vma_file < 0 ? -1 : 0;
}

/* Resolve every pointer level, including typedef/const wrappers. */
static int uz_btf_pointer_to(const struct kclf_btf *btf, uint32_t id,
                             const char *name, unsigned depth)
{
    const struct kclf_btf_type *type = kclf_btf_resolve(btf, id);

    while (depth--) {
        if (!type || ((type->info >> 24) & 31U) != 2U) return 0;
        type = kclf_btf_resolve(btf, type->size);
    }
    return type && ((type->info >> 24) & 31U) == 4U &&
           !strcmp(kclf_btf_name(btf, type->name), name);
}

/* Function shapes: v=void, i=32-bit integer/enum, l=64-bit integer,
 * s=either scalar width (ESR), p=pointer, m=mm, t=task, a=VMA, r=pt_regs.
 * P=page*, D=page**, A=VMA**, I=int*, N=pglist_data*.
 * Check all argument slots before using an internal or backported entry. */
static int uz_btf_arg_is(const struct kclf_btf *btf, uint32_t id, char shape)
{
    const struct kclf_btf_type *type = kclf_btf_resolve(btf, id);
    unsigned kind = type ? (type->info >> 24) & 31 : 0;

    switch (shape) {
    case 'v': return !id;
    case 'b': return kclf_btf_is_bool(type);
    case 'i': return (kind == 1 || kind == 6 || kind == 19) && type->size == 4;
    case 'l': return kind == 1 && type->size == 8;
    case 's': return kind == 1 && (type->size == 4 || type->size == 8);
    case 'p': return kind == 2;
    case 'm': return kclf_btf_points_to(btf, type, "mm_struct");
    case 't': return kclf_btf_points_to(btf, type, "task_struct");
    case 'a': return kclf_btf_points_to(btf, type, "vm_area_struct");
    case 'r': return kclf_btf_points_to(btf, type, "pt_regs");
    case 'f': return kclf_btf_points_to(btf, type, "user_fpsimd_state");
    case 'o': return kclf_btf_points_to(btf, type, "folio");
    case 'P': return uz_btf_pointer_to(btf, id, "page", 1);
    case 'D': return uz_btf_pointer_to(btf, id, "page", 2);
    case 'A': return uz_btf_pointer_to(btf, id, "vm_area_struct", 2);
    case 'N': return uz_btf_pointer_to(btf, id, "pglist_data", 1);
    case 'I':
        if (kind != 2U) return 0;
        type = kclf_btf_resolve(btf, type->size);
        return type && ((type->info >> 24) & 31U) == 1U && type->size == 4U;
    default: return 0;
    }
}

static int uz_btf_signature(const struct kclf_btf *btf, const struct kclf_btf_type *proto,
                            const char *shape)
{
    const uint32_t *params;
    unsigned i, argc;

    if (!proto) return 0;
    argc = proto->info & 0xffff;
    if (strlen(shape + 1) != argc || !uz_btf_arg_is(btf, proto->size, shape[0])) return 0;
    params = (const void *)(proto + 1);
    for (i = 0; i < argc; ++i)
        if (!uz_btf_arg_is(btf, params[2 * i + 1], shape[i + 1])) return 0;
    return 1;
}

static int uz_symbol_abi(const struct kclf_btf *btf, const char *name, const char *shape)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    /* Stable named interfaces can be present in kallsyms without a FUNC
     * record (e.g. due to LTO or detached BTF from DWARF). */
    return !proto || uz_btf_signature(btf, proto, shape);
}

static int uz_mm_fault_argc(const struct kclf_btf *btf, const char *name, int public)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    /* The public entry has a stable (vma, address) prefix. In the absence
     * of a prototype preserve all eight argument registers, including a
     * possible vendor sequence word. Never guess the private entry's ABI. */
    if (!proto) return public ? 8 : 0;
    if (uz_btf_signature(btf, proto, "iali")) return 3;
    if (uz_btf_signature(btf, proto, "ialir")) return 4;
    if (uz_btf_signature(btf, proto, "ialisr")) return 5;
    return 0;
}

static int uz_access_vm_argc(const struct kclf_btf *btf, const char *name, int public)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    if (!proto) return public ? 5 : 0;
    if (uz_btf_signature(btf, proto, "imlpii")) return 5;
    if (!public && uz_btf_signature(btf, proto, "itmlpii")) return 6;
    return 0;
}

/* Remote and slow GUP dropped the leading task argument during 5.x, then
 * the vmas argument during 6.x. Internal entries require a complete
 * prototype; never infer their ABI from the version or symbol name. */
static int uz_remote_gup_argc(const struct kclf_btf *btf, const char *name)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    if (uz_btf_signature(btf, proto, "ltmlliDAI")) return 8;
    if (uz_btf_signature(btf, proto, "lmlliDAI")) return 7;
    if (uz_btf_signature(btf, proto, "lmlliDI")) return 6;
    return 0;
}

/* Prefer NUMA-policy alloc_pages[_current/_noprof](gfp, order). If these
 * wrappers are inline, the low-level allocator requires a real online node,
 * NOT NUMA_NO_NODE (-1). BTF proves the accessor and the node_id field. */
static int uz_pgdat_node_offset(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *pgdat = kclf_btf_find(btf, "pglist_data", 0);
    const struct kclf_btf_type *type;
    uint32_t id = 0;
    int off = uz_btf_member(btf, pgdat, "node_id", &id);

    if (off < 0 || (off & 3) || pgdat->size - (unsigned)off < 4U ||
        !uz_btf_signature(btf, kclf_btf_func_proto(btf, "first_online_pgdat"), "N"))
        return -1;
    type = kclf_btf_resolve(btf, id);
    return type && ((type->info >> 24) & 31U) == 1U && type->size == 4U ? off : -1;
}

/* AArch64 pte_t/pmd_t wrap one 64-bit descriptor. A by-value pte_t has the
 * same register ABI as uz_pte_word, but must not be mistaken for a pointer. */
static int uz_btf_pt_value(const struct kclf_btf *btf, uint32_t id, const char *field)
{
    const struct kclf_btf_type *type = kclf_btf_resolve(btf, id), *word;
    uint32_t member = 0;
    if (!type || ((type->info >> 24) & 31U) != 4U || type->size != 8U ||
        (type->info & 0xffffU) != 1U || uz_btf_member(btf, type, field, &member) != 0)
        return 0;
    word = kclf_btf_resolve(btf, member);
    return word && ((word->info >> 24) & 31U) == 1U && word->size == 8U;
}

static int uz_btf_pt_word(const struct kclf_btf *btf, uint32_t id, const char *field)
{
    const struct kclf_btf_type *type = kclf_btf_resolve(btf, id);
    return type && ((type->info >> 24) & 31U) == 2U &&
           uz_btf_pt_value(btf, type->size, field);
}

static int uz_contpte_abi(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, "__contpte_try_unfold");
    const uint32_t *params;
    if (!proto || (proto->info & 0xffffU) != 4U || proto->size) return 0;
    params = (const void *)(proto + 1);
    return uz_btf_arg_is(btf, params[1], 'm') && uz_btf_arg_is(btf, params[3], 'l') &&
           uz_btf_pt_word(btf, params[5], "pte") && uz_btf_pt_value(btf, params[7], "pte");
}

static int uz_btf_raw_lock_zero(const struct kclf_btf *btf,
                               const struct kclf_btf_type *type,
                               const struct kclf_btf_type *raw, unsigned depth)
{
    const struct kclf_btf_member *member;
    unsigned i, kind;
    if (!type || !depth || type->size < raw->size) return 0;
    kind = (type->info >> 24) & 31U;
    if (kind != 4U && kind != 5U) return 0;
    member = (const void *)(type + 1);
    for (i = 0; i < (type->info & 0xffffU); ++i) {
        const struct kclf_btf_type *sub;
        if (member[i].offset) continue;
        sub = kclf_btf_resolve(btf, member[i].type);
        if (!sub || sub->size > type->size) continue;
        if (member[i].name) {
            if (!strcmp(kclf_btf_name(btf, member[i].name), "rlock") && sub == raw) return 1;
        } else if (uz_btf_raw_lock_zero(btf, sub, raw, depth - 1U)) return 1;
    }
    return 0;
}

/* apply_to_* takes a pte_fn_t callback. Validate the callback itself, not
 * merely the five outer argument widths (older vendor APIs may add a token). */
static int uz_apply_pt_abi(const struct kclf_btf *btf, const char *name)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name), *cb;
    const uint32_t *params;
    if (!uz_btf_signature(btf, proto, "imllpp")) return 0;
    params = (const void *)(proto + 1);
    cb = kclf_btf_resolve(btf, params[7]);
    if (!cb || ((cb->info >> 24) & 31U) != 2U) return 0;
    cb = kclf_btf_resolve(btf, cb->size);
    if (!cb || ((cb->info >> 24) & 31U) != 13U || !uz_btf_signature(btf, cb, "iplp")) return 0;
    params = (const void *)(cb + 1);
    return uz_btf_pt_word(btf, params[1], "pte");
}

/* Non-RT spinlock_t starts with raw_spinlock_t. The map-lock helper takes
 * spinlock_t**, while spin_unlock lowers to _raw_spin_unlock(&lock->rlock).
 * Never cast an RT mutex-backed spinlock to a raw lock. */
static int uz_native_pt_abi(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *spin = kclf_btf_find(btf, "spinlock", 0);
    const struct kclf_btf_type *raw = kclf_btf_find(btf, "raw_spinlock", 0);
    const struct kclf_btf_type *map = kclf_btf_func_proto(btf, "__pte_offset_map_lock");
    const struct kclf_btf_type *unlock = kclf_btf_func_proto(btf, "_raw_spin_unlock");
    const uint32_t *params, *unlock_params;
    if (!uz_btf_signature(btf, map, "pmplp") || !uz_btf_signature(btf, unlock, "vp") ||
        !spin || !raw || !raw->size || raw->size > spin->size) return 0;
    params = (const void *)(map + 1);
    unlock_params = (const void *)(unlock + 1);
    return uz_btf_pt_word(btf, map->size, "pte") && uz_btf_pt_word(btf, params[3], "pmd") &&
           uz_btf_pointer_to(btf, params[7], "spinlock", 2) &&
           uz_btf_pointer_to(btf, unlock_params[1], "raw_spinlock", 1) &&
           uz_btf_raw_lock_zero(btf, spin, raw, 8);
}

/* Earlier 5.x/6.x try_grab_folio takes page* and returns folio* (NULL on
 * failure). Later kernels take folio* and return int (zero on success).
 * Do not collapse these incompatible return conventions into one cast. */
static int uz_folio_page_grab_abi(const struct kclf_btf *btf)
{
    return uz_btf_signature(btf, kclf_btf_func_proto(btf, "try_grab_folio"), "oPii");
}

/* Newer GUP uses try_grab_folio() instead of try_grab_page(). Only a newly
 * allocated order-0 page is passed to this adapter, and BTF must prove that
 * the folio begins with a complete struct page before it can be cast. */
static int uz_embeds_page_zero(const struct kclf_btf *btf,
                               const struct kclf_btf_type *container,
                               const struct kclf_btf_type *page, unsigned depth)
{
    const struct kclf_btf_member *member;
    unsigned i, kind;

    if (!container || !depth || container->size < page->size) return 0;
    kind = (container->info >> 24) & 31U;
    if (kind != 4U && kind != 5U) return 0;
    member = (const void *)(container + 1);
    for (i = 0; i < (container->info & 0xffffU); ++i) {
        const struct kclf_btf_type *sub;

        /* Both offset and bitfield width must be zero. */
        if (member[i].offset) continue;
        sub = kclf_btf_resolve(btf, member[i].type);
        if (!sub || sub->size > container->size) continue;
        if (member[i].name) {
            if (!strcmp(kclf_btf_name(btf, member[i].name), "page") && sub == page)
                return 1;
        } else if (uz_embeds_page_zero(btf, sub, page, depth - 1U)) {
            return 1;
        }
    }
    return 0;
}

static int uz_folio_grab_abi(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *page = kclf_btf_find(btf, "page", 0);

    return page && page->size &&
           uz_embeds_page_zero(btf, kclf_btf_find(btf, "folio", 0), page, 8) &&
           uz_btf_signature(btf, kclf_btf_func_proto(btf, "try_grab_folio"), "ioii");
}

/* Root can supply detached BTF when CONFIG_DEBUG_INFO_BTF is disabled.
 * Require an exact GNU build ID match before opening the trusted BTF. */
#define UZ_BTF_MAX (64U * 1024U * 1024U)
#define UZ_BUILD_ID_MAX 64U

struct uz_btf_pack {
    char magic[8]; /* "UZBTF01" including NUL */
    uint32_t bytes;
    uint32_t id_len;
    uint8_t build_id[UZ_BUILD_ID_MAX];
};

_Static_assert(sizeof(struct uz_btf_pack) == 80, "detached BTF header ABI");

static int uz_btf_pack_matches(const struct uz_btf_pack *pack, const void *notes, size_t len)
{
    const uint8_t *p = notes;

    if (memcmp(pack->magic, "UZBTF01", sizeof(pack->magic)) ||
        pack->bytes < sizeof(struct kclf_btf_header) || pack->bytes > UZ_BTF_MAX ||
        !pack->id_len || pack->id_len > UZ_BUILD_ID_MAX || !p)
        return 0;
    /* The arm64 GNU build-ID is a 4-byte aligned ELF note. */
    while (len >= 12) {
        uint32_t hdr[3];
        size_t name_pad, desc_pad;

        memcpy(hdr, p, sizeof(hdr));
        p += sizeof(hdr);
        len -= sizeof(hdr);
        name_pad = ((size_t)hdr[0] + 3U) & ~(size_t)3U;
        desc_pad = ((size_t)hdr[1] + 3U) & ~(size_t)3U;
        if (name_pad > len || desc_pad > len - name_pad) return 0;
        if (hdr[2] == 3 && hdr[0] == 4 && !memcmp(p, "GNU", 4) &&
            hdr[1] == pack->id_len && !memcmp(p + name_pad, pack->build_id, hdr[1]))
            return 1;
        p += name_pad + desc_pad;
        len -= name_pad + desc_pad;
    }
    return 0;
}

static int uz_btf_open(struct kclf_btf *btf, const void *data, size_t bytes)
{
    size_t offset = 0;

    if (kclf_btf_open(btf, data, bytes) || !btf->type_len) return -1;
    while (offset < btf->type_len) {
        size_t size = kclf_btf_record((const void *)(btf->types + offset), btf->type_len - offset);

        if (!size) return -1;
        offset += size;
    }
    return 0;
}

/* FOLL_FORCE was a macro before 6.3 and may still be absent from BTF on newer
 * builds. Prefer the live enum when a kernel emits it, including backports. */
static unsigned uz_foll_force(const struct kclf_btf *btf, unsigned fallback)
{
    size_t offset = 0, size;
    unsigned force = 0;

    while (offset < btf->type_len) {
        const struct kclf_btf_type *type = (const void *)(btf->types + offset);
        const uint32_t *values = (const void *)(type + 1);
        unsigned i, count;

        size = kclf_btf_record(type, btf->type_len - offset);
        if (!size) break;
        offset += size;
        if (((type->info >> 24) & 31) != 6) continue;
        count = type->info & 0xffff;
        for (i = 0; i < count; ++i) {
            unsigned flag = values[2 * i + 1];
            if (strcmp(kclf_btf_name(btf, values[2 * i]), "FOLL_FORCE")) continue;
            if ((flag != 0x08U && flag != 0x10U) || (force && force != flag))
                return 0;
            force = flag;
        }
    }
    return force ? force : fallback;
}


static unsigned uz_btf_enum_flag(const struct kclf_btf *btf,
                                 const char *name, unsigned fallback)
{
    size_t offset = 0;
    unsigned found = 0;
    while (offset < btf->type_len) {
        const struct kclf_btf_type *type = (const void *)(btf->types + offset);
        const uint32_t *values = (const void *)(type + 1);
        size_t size = kclf_btf_record(type, btf->type_len - offset);
        unsigned i;
        if (!size) return 0;
        offset += size;
        if (((type->info >> 24) & 31U) != 6U) continue;
        for (i = 0; i < (type->info & 0xffffU); ++i) {
            unsigned value = values[2U * i + 1U];
            if (strcmp(kclf_btf_name(btf, values[2U * i]), name)) continue;
            if (!value || (value & (value - 1U)) || (found && found != value)) return 0;
            found = value;
        }
    }
    return found ? found : fallback;
}

#endif
