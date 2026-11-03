/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_UROV_LAB_H
#define _LINUX_UROV_LAB_H
#include <linux/types.h>
struct mm_struct;
struct pt_regs;
#ifdef CONFIG_UROV_LAB
bool urov_handle_abort(unsigned long far, unsigned long esr, struct pt_regs *regs);
/* Caller holds mmap_lock; the active record is published under its write side. */
bool urov_range_busy(struct mm_struct *mm, unsigned long start, unsigned long end);
bool urov_mm_busy(struct mm_struct *mm);
void urov_mm_release(struct mm_struct *mm);
#else
static inline bool urov_handle_abort(unsigned long f, unsigned long e, struct pt_regs *r) { return false; }
static inline bool urov_range_busy(struct mm_struct *m, unsigned long s, unsigned long e) { return false; }
static inline bool urov_mm_busy(struct mm_struct *m) { return false; }
static inline void urov_mm_release(struct mm_struct *m) { }
#endif
#endif
