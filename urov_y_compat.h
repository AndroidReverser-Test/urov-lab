/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Y_COMPAT_H
#define UROV_Y_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#if __STDC_HOSTED__
#include <string.h>
#else
#include <linux/string.h>
#endif

/* Use the raw reader so the same KPM also loads on hosts without KP BTF exports. */
#include "../kclf/kclf_btf.h"

struct uy_layout {
    int task_mm;
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
};

struct uy_geometry {
    unsigned page_shift;
    unsigned user_va_bits;
};

/* KernelPatch's walker uses the kernel translation depth for any PGD.
 * Arm64 4K and 16K non-LPA2 descriptors both carry <=48-bit output addresses. */
static int uy_geometry_from_tcr(struct uy_geometry *out, uint64_t tcr)
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
static int uy_btf_member(const struct kclf_btf *btf, const struct kclf_btf_type *type,
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
static int uy_fpsimd_layout(const struct kclf_btf *btf,
                            const struct kclf_btf_type *state)
{
    return uy_btf_member(btf, state, "vregs", 0) == 0 &&
           uy_btf_member(btf, state, "fpsr", 0) == 512 &&
           uy_btf_member(btf, state, "fpcr", 0) == 516;
}

/* Size of uapi struct user_fpsimd_state as mirrored by struct uy_fpstate. */
#define UY_FPSIMD_BYTES 528U

/* Only follow aggregates and verify each containment boundary. */
static int uy_fpsimd_member(const struct kclf_btf *btf,
                            const struct kclf_btf_type *container)
{
    const struct kclf_btf_type *state;
    uint32_t id;
    int off = uy_btf_member(btf, container, "fpsimd_state", &id);

    if (off < 0) return -1;
    state = kclf_btf_resolve(btf, id);
    if (!state || ((state->info >> 24) & 31) != 4 || state->size != UY_FPSIMD_BYTES ||
        strcmp(kclf_btf_name(btf, state->name), "user_fpsimd_state") ||
        UY_FPSIMD_BYTES > container->size - (unsigned)off || !uy_fpsimd_layout(btf, state))
        return -1;
    return off;
}

static int uy_fpsimd_offset(const struct kclf_btf *btf)
{
    const struct kclf_btf_type *task = kclf_btf_find(btf, "task_struct", 0);
    const struct kclf_btf_type *thread, *uw;
    uint32_t thread_type = 0, uw_type = 0;
    int thread_off, uw_off, fp_off;
    unsigned i, n;

    thread_off = uy_btf_member(btf, task, "thread", &thread_type);
    if (thread_off < 0) return -1;
    thread = kclf_btf_resolve(btf, thread_type);
    if (!thread || ((thread->info >> 24) & 31) != 4 ||
        thread->size > task->size - (unsigned)thread_off)
        return -1;
    uw_off = uy_btf_member(btf, thread, "uw", &uw_type);
    if (uw_off >= 0) {
        uw = kclf_btf_resolve(btf, uw_type);
        fp_off = uy_fpsimd_member(btf, uw);
        if (fp_off >= 0 && uw->size <= thread->size - (unsigned)uw_off &&
            !((thread_off + uw_off + fp_off) & 15))
            return thread_off + uw_off + fp_off;
    }
    /* Older/renamed layouts: accept a direct member, or any anonymous member
     * one level deep that itself holds user_fpsimd_state. */
    fp_off = uy_fpsimd_member(btf, thread);
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
        sub_off = uy_fpsimd_member(btf, sub);
        if (sub_off >= 0 && sub->size <= thread->size - bitoff / 8 &&
            !((thread_off + (int)(bitoff / 8) + sub_off) & 15))
            return thread_off + (int)(bitoff / 8) + sub_off;
    }
    return -1;
}

static int uy_task_thread_ptr(const struct kclf_btf *btf, const char *name)
{
    const struct kclf_btf_type *task = kclf_btf_find(btf, "task_struct", 0);
    const struct kclf_btf_type *thread, *type;
    uint32_t id;
    int thread_off = uy_btf_member(btf, task, "thread", &id);
    int off;

    if (thread_off < 0) return -1;
    thread = kclf_btf_resolve(btf, id);
    if (!thread || thread->size > task->size - (unsigned)thread_off) return -1;
    off = uy_btf_member(btf, thread, name, &id);
    if (off < 0 || ((thread_off + off) & 7) || thread->size - (unsigned)off < 8) return -1;
    type = kclf_btf_resolve(btf, id);
    return type && ((type->info >> 24) & 31U) == 2U ? thread_off + off : -1;
}

static int uy_layout_from_btf(struct uy_layout *layout, const struct kclf_btf *btf)
{
    const struct kclf_btf_type *sem = kclf_btf_find(btf, "rw_semaphore", 0);

    layout->task_mm = kclf_btf_member_range(btf, "task_struct", "mm", 8, 8);
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
    layout->task_fpsimd = uy_fpsimd_offset(btf);
    layout->task_sve_state = uy_task_thread_ptr(btf, "sve_state");
    layout->task_sme_state = uy_task_thread_ptr(btf, "sme_state");
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

/* Function shapes: v=void, i=32-bit integer/enum, l=64-bit integer,
 * s=either scalar width (ESR), p=pointer, m=mm, t=task, a=VMA, r=pt_regs.
 * Check all argument slots before using an internal or backported entry. */
static int uy_btf_arg_is(const struct kclf_btf *btf, uint32_t id, char shape)
{
    const struct kclf_btf_type *type = kclf_btf_resolve(btf, id);
    unsigned kind = type ? (type->info >> 24) & 31 : 0;

    switch (shape) {
    case 'v': return !id;
    case 'i': return (kind == 1 || kind == 6 || kind == 19) && type->size == 4;
    case 'l': return kind == 1 && type->size == 8;
    case 's': return kind == 1 && (type->size == 4 || type->size == 8);
    case 'p': return kind == 2;
    case 'm': return kclf_btf_points_to(btf, type, "mm_struct");
    case 't': return kclf_btf_points_to(btf, type, "task_struct");
    case 'a': return kclf_btf_points_to(btf, type, "vm_area_struct");
    case 'r': return kclf_btf_points_to(btf, type, "pt_regs");
    case 'f': return kclf_btf_points_to(btf, type, "user_fpsimd_state");
    default: return 0;
    }
}

static int uy_btf_signature(const struct kclf_btf *btf, const struct kclf_btf_type *proto,
                            const char *shape)
{
    const uint32_t *params;
    unsigned i, argc;

    if (!proto) return 0;
    argc = proto->info & 0xffff;
    if (strlen(shape + 1) != argc || !uy_btf_arg_is(btf, proto->size, shape[0])) return 0;
    params = (const void *)(proto + 1);
    for (i = 0; i < argc; ++i)
        if (!uy_btf_arg_is(btf, params[2 * i + 1], shape[i + 1])) return 0;
    return 1;
}

static int uy_symbol_abi(const struct kclf_btf *btf, const char *name, const char *shape)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    /* Stable named interfaces can be present in kallsyms without a FUNC
     * record (e.g. due to LTO or detached BTF from DWARF). */
    return !proto || uy_btf_signature(btf, proto, shape);
}

static int uy_mm_fault_argc(const struct kclf_btf *btf, const char *name, int public)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    /* The public entry has a stable (vma, address) prefix. In the absence
     * of a prototype preserve all eight argument registers, including a
     * possible vendor sequence word. Never guess the private entry's ABI. */
    if (!proto) return public ? 8 : 0;
    if (uy_btf_signature(btf, proto, "iali")) return 3;
    if (uy_btf_signature(btf, proto, "ialir")) return 4;
    if (uy_btf_signature(btf, proto, "ialisr")) return 5;
    return 0;
}

static int uy_access_vm_argc(const struct kclf_btf *btf, const char *name, int public)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);

    if (!proto) return public ? 5 : 0;
    if (uy_btf_signature(btf, proto, "imlpii")) return 5;
    if (!public && uy_btf_signature(btf, proto, "itmlpii")) return 6;
    return 0;
}

/* Root can supply detached BTF when CONFIG_DEBUG_INFO_BTF is disabled.
 * Require an exact GNU build ID match before opening the trusted BTF. */
#define UY_BTF_MAX (64U * 1024U * 1024U)
#define UY_BUILD_ID_MAX 64U

struct uy_btf_pack {
    char magic[8]; /* "UYBTF01" including NUL */
    uint32_t bytes;
    uint32_t id_len;
    uint8_t build_id[UY_BUILD_ID_MAX];
};

_Static_assert(sizeof(struct uy_btf_pack) == 80, "detached BTF header ABI");

static int uy_btf_pack_matches(const struct uy_btf_pack *pack, const void *notes, size_t len)
{
    const uint8_t *p = notes;

    if (memcmp(pack->magic, "UYBTF01", sizeof(pack->magic)) ||
        pack->bytes < sizeof(struct kclf_btf_header) || pack->bytes > UY_BTF_MAX ||
        !pack->id_len || pack->id_len > UY_BUILD_ID_MAX || !p)
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

static int uy_btf_open(struct kclf_btf *btf, const void *data, size_t bytes)
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
static unsigned uy_foll_force(const struct kclf_btf *btf, unsigned fallback)
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

#endif
