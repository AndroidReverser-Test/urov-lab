/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_SHORT_LOCK_H
#define UROV_Z_SHORT_LOCK_H

#include <stdint.h>

/* Caller excludes local IRQ/preemption in the kernel. Only bounded kernel
 * buffer operations belong in this lock; never allocate, fault or wait for
 * an epoch here. The relaxed wait avoids repeatedly writing a busy line. */
struct uz_short_lock { unsigned busy; };

#ifndef UZ_LOCK_RELAX
#define UZ_LOCK_RELAX() __asm__ volatile("yield" ::: "memory")
#endif

static inline uint64_t uz_short_lock_take(struct uz_short_lock *lock)
{
    uint64_t waits = 0;
    for (;;) {
        unsigned expected = 0;
        if (__atomic_compare_exchange_n(&lock->busy, &expected, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return waits;
        do {
            if (waits != (~UINT64_C(0))) ++waits;
            UZ_LOCK_RELAX();
        } while (__atomic_load_n(&lock->busy, __ATOMIC_RELAXED));
    }
}

static inline void uz_short_lock_drop(struct uz_short_lock *lock)
{
    __atomic_store_n(&lock->busy, 0, __ATOMIC_RELEASE);
}
#endif
