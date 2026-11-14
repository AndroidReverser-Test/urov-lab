/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KCLF_COMPAT_PROFILE_H
#define KCLF_COMPAT_PROFILE_H

#include "kclf_btf.h"

/* A value-only snapshot: detached BTF storage may be freed immediately after
 * this is filled. Never retain type, member or string pointers in the loader. */
struct kclf_compat_profile {
    int mm_off, vma_start, vma_end, mmap_lock, regs_size;
    int signal_abi, cancel_abi;
};

static inline int kclf_compat_profile_read(struct kclf_compat_profile *p, const struct kclf_btf *b)
{
    const struct kclf_btf_type *t;

    memset(p, 0, sizeof(*p));
    p->mmap_lock = -1;
    p->signal_abi = kclf_btf_signal_abi(b);
    if (p->signal_abi == -2) return -1;
    p->cancel_abi = kclf_btf_cancel_abi(b);
    p->mm_off = kclf_btf_member_range(b, "task_struct", "mm", 8, 8);
    p->vma_start = kclf_btf_member_range(b, "vm_area_struct", "vm_start", 8, 8);
    p->vma_end = kclf_btf_member_range(b, "vm_area_struct", "vm_end", 8, 8);
    t = kclf_btf_find(b, "rw_semaphore", 0);
    if (t && t->size >= 16 && t->size <= 512) {
        p->mmap_lock = kclf_btf_member_range(b, "mm_struct", "mmap_lock", t->size, 8);
        if (p->mmap_lock < 0)
            p->mmap_lock = kclf_btf_member_range(b, "mm_struct", "mmap_sem", t->size, 8);
    }
    t = kclf_btf_find(b, "pt_regs", 0);
    if (t && (t->size < 288 || t->size > 512 || (t->size & 15) ||
        kclf_btf_member_range(b, "pt_regs", "regs", 248, 8) != 0 ||
        kclf_btf_member_range(b, "pt_regs", "sp", 8, 8) != 248 ||
        kclf_btf_member_range(b, "pt_regs", "pc", 8, 8) != 256 ||
        kclf_btf_member_range(b, "pt_regs", "pstate", 8, 8) != 264 ||
        kclf_btf_member_range(b, "pt_regs", "orig_x0", 8, 8) != 272 ||
        kclf_btf_member_range(b, "pt_regs", "syscallno", 4, 4) != 280))
        return -1;
    if (t) p->regs_size = t->size;
    t = kclf_btf_find(b, "thread_info", 0);
    if (t && kclf_btf_member_range(b, "thread_info", "flags", 8, 8) != 0)
        return -1;
    return 0;
}
#endif
