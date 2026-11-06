/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Y_READERS_H
#define UROV_Y_READERS_H

#include <stdint.h>

/* The open bit, current epoch and both reference counts share one atomic
 * word. A reader cannot enter an old epoch after the writer flips it, or
 * enter at all after close. Writers are serialized by the control lock. */
#define UY_READER_MASK ((UINT64_C(1) << 31) - 1)
#define UY_READER_EPOCH (UINT64_C(1) << 62)
#define UY_READER_CLOSED (UINT64_C(1) << 63)

static inline uint64_t uy_reader_enter(uint64_t *state)
{
    uint64_t old = __atomic_load_n(state, __ATOMIC_ACQUIRE);

    while (!(old & UY_READER_CLOSED)) {
        uint64_t ref = old & UY_READER_EPOCH ? UINT64_C(1) << 31 : 1;

        if ((old & (UY_READER_MASK * ref)) == UY_READER_MASK * ref) return 0;
        if (__atomic_compare_exchange_n(state, &old, old + ref, 1,
                                        __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
            return ref;
    }
    return 0;
}

static inline void uy_reader_exit(uint64_t *state, uint64_t ref)
{
    __atomic_fetch_sub(state, ref, __ATOMIC_RELEASE);
}

static inline void uy_readers_open(uint64_t *state)
{
    __atomic_store_n(state, 0, __ATOMIC_RELEASE);
}

static inline uint64_t uy_readers_flip(uint64_t *state)
{
    uint64_t old = __atomic_fetch_xor(state, UY_READER_EPOCH, __ATOMIC_ACQ_REL);

    return old & UY_READER_EPOCH ? UY_READER_MASK << 31 : UY_READER_MASK;
}

static inline uint64_t uy_readers_close(uint64_t *state)
{
    __atomic_fetch_or(state, UY_READER_CLOSED, __ATOMIC_ACQ_REL);
    return UY_READER_MASK | (UY_READER_MASK << 31);
}

#endif
