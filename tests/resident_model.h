/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_RESIDENT_H
#define UROV_RESIDENT_H
#include <stdint.h>
#include <stddef.h>
#include "../urov_abi.h"

/* Host fixture interfaces only. */
enum { UROV_R_INIT, UROV_R_QUEUE, UROV_R_DRAIN, UROV_R_INSPECT };
struct pt_regs;
struct task_struct;
struct callback_head { struct callback_head *next; void (*func)(struct callback_head *); };
typedef struct { unsigned long pte; } pte_t;
struct urov_kernel_api {
    long (*copy_in)(void *, const void *, unsigned long);
    long (*copy_out)(void *, const void *, unsigned long);
    void *(*get_mm)(struct task_struct *);
    void (*mmput)(void *);
    long (*pin)(unsigned long, unsigned long, void **, unsigned int);
    void (*unpin)(void **, unsigned long);
    void *(*find_vma)(void *, unsigned long);
    void (*down_write)(void *);
    void (*up_write)(void *);
    int (*apply_ptes)(void *, unsigned long, unsigned long,
                      int (*)(pte_t *, unsigned long, void *), void *);
    void (*rcu_lock)(void);
    void (*rcu_unlock)(void);
    void (*sync_rcu)(void);
    void (*sleep_ms)(unsigned int);
    int (*task_add)(struct task_struct *, struct callback_head *, int);
    int (*native_fault)(unsigned long, unsigned long, struct pt_regs *);
    uint64_t memstart;
    unsigned int allow_raw_xom;
};
struct urov_resident_status {
    uint32_t ready, hooks, pending, active;
    int32_t error;
    uint32_t checks;
    uint64_t sessions, caps;
};
#endif
