/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Y_COMPAT_H
#define UROV_Y_COMPAT_H

#include <stdint.h>
#include <stddef.h>

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
};

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
        if ((bitoff & 7) || bitoff / 8 >= type->size) continue;
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
static int uy_fpsimd_layout(const struct kclf_btf *btf)
{
    if (kclf_btf_member_range(btf, "user_fpsimd_state", "vregs", 512, 16) != 0 ||
        kclf_btf_member_range(btf, "user_fpsimd_state", "fpsr", 4, 4) != 512 ||
        kclf_btf_member_range(btf, "user_fpsimd_state", "fpcr", 4, 4) != 516)
        return -1;
    return 0;
}

/* Size of uapi struct user_fpsimd_state as mirrored by struct uy_fpstate. */
#define UY_FPSIMD_BYTES 528U

/* walk task_struct.thread -> (<=2 named levels) -> user_fpsimd_state */
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
    if (!thread) return -1;
    uw_off = uy_btf_member(btf, thread, "uw", &uw_type);
    if (uw_off >= 0) {
        uw = kclf_btf_resolve(btf, uw_type);
        fp_off = uy_btf_member(btf, uw, "fpsimd_state", 0);
        if (fp_off >= 0) {
            if ((unsigned)(uw_off + fp_off) + UY_FPSIMD_BYTES > thread->size)
                return -1;
            return thread_off + uw_off + fp_off;
        }
    }
    /* Older/renamed layouts: accept a direct member, or any anonymous member
     * one level deep that itself holds user_fpsimd_state. */
    fp_off = uy_btf_member(btf, thread, "fpsimd_state", 0);
    if (fp_off >= 0)
        return (unsigned)fp_off + UY_FPSIMD_BYTES > thread->size ? -1 : thread_off + fp_off;
    n = (((thread->info >> 24) & 31) == 4 || ((thread->info >> 24) & 31) == 5)
            ? (thread->info & 0xffff) : 0;
    for (i = 0; i < n; i++) {
        const struct kclf_btf_member *member = (const void *)(thread + 1);
        uint32_t bitoff = (thread->info >> 31) ? (member[i].offset & 0xffffff)
                                               : member[i].offset;
        const struct kclf_btf_type *sub;
        int sub_off;
        if ((bitoff & 7) || bitoff / 8 >= thread->size) continue;
        sub = kclf_btf_resolve(btf, member[i].type);
        sub_off = uy_btf_member(btf, sub, "fpsimd_state", 0);
        if (sub_off >= 0) {
            if (bitoff / 8 + (unsigned)sub_off + UY_FPSIMD_BYTES > thread->size)
                return -1;
            return thread_off + (int)(bitoff / 8) + sub_off;
        }
    }
    return -1;
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
    layout->vma_file = kclf_btf_member_range(btf, "vm_area_struct", "vm_file", 8, 8);
    layout->vma_pgoff = kclf_btf_member_range(btf, "vm_area_struct", "vm_pgoff", 8, 8);
    layout->vma_pgoff_ok = layout->vma_pgoff >= 0;
    layout->task_fpsimd = uy_fpsimd_layout(btf) ? -1 : uy_fpsimd_offset(btf);
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

/* 5.15 vendor kernels can pass an extra sequence word before regs. The hook
 * must preserve every argument when it calls the original fault handler. */
static int uy_mm_fault_argc(const struct kclf_btf *btf, const char *name, int fallback)
{
    const struct kclf_btf_type *proto = kclf_btf_func_proto(btf, name);
    const struct kclf_btf_type *type;
    const uint32_t *params;
    unsigned argc;

    if (!proto) return fallback;
    argc = proto->info & 0xffff;
    if (argc != 4 && argc != 5) return 0;
    params = (const void *)(proto + 1);
    if (!kclf_btf_points_to(btf, kclf_btf_resolve(btf, params[1]), "vm_area_struct") ||
        !kclf_btf_points_to(btf, kclf_btf_resolve(btf, params[argc * 2 - 1]), "pt_regs"))
        return 0;
    type = kclf_btf_resolve(btf, params[3]);
    if (!type || ((type->info >> 24) & 31) != 1 || type->size != 8) return 0;
    type = kclf_btf_resolve(btf, proto->size);
    if (!type || ((type->info >> 24) & 31) != 1 || type->size != 4) return 0;
    return (int)argc;
}

/* FOLL_FORCE was a macro before 6.3 and may still be absent from BTF on newer
 * builds. Prefer the live enum when a kernel emits it, including backports. */
static unsigned uy_foll_force(const struct kclf_btf *btf, unsigned fallback)
{
    size_t offset = 0, size;

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
            if (!strcmp(kclf_btf_name(btf, values[2 * i]), "FOLL_FORCE"))
                return flag == 0x08U || flag == 0x10U ? flag : 0;
        }
    }
    return fallback;
}

#endif
