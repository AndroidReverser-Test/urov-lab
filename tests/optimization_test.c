/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define UZ_LOCK_RELAX() sched_yield()
#include "../module/short_lock.h"
#include "../module/buffer_budget.h"
#include "../module/mapping_identity.h"

static struct uz_short_lock locks[2], budget_lock;
static struct uz_buffer_budget budget;
static uint64_t generations[2], images[2][64];
static unsigned finished;

static void *isolated(void *unused)
{
    (void)unused;
    (void)uz_short_lock_take(&locks[1]);
    __atomic_store_n(&finished, 1U, __ATOMIC_RELEASE);
    uz_short_lock_drop(&locks[1]);
    return NULL;
}

static void *publisher(void *opaque)
{
    uintptr_t id = (uintptr_t)opaque;
    for (unsigned round = 0; round < 20000; ++round) {
        unsigned p = (unsigned)(id + round) & 1U;
        (void)uz_short_lock_take(&locks[p]);
        for (unsigned i = 0; i < 64; ++i) assert(images[p][i] == generations[p]);
        ++generations[p];
        for (unsigned i = 0; i < 64; ++i) images[p][i] = generations[p];
        uz_short_lock_drop(&locks[p]);
    }
    return NULL;
}

static void test_locks(void)
{
    pthread_t threads[4];
    (void)uz_short_lock_take(&locks[0]);
    assert(!pthread_create(&threads[0], NULL, isolated, NULL));
    /* Page 1 must complete while page 0 remains locked. alarm catches a
     * regression to a global lock without silently hanging the test suite. */
    assert(!pthread_join(threads[0], NULL));
    assert(__atomic_load_n(&finished, __ATOMIC_ACQUIRE));
    uz_short_lock_drop(&locks[0]);
    for (uintptr_t i = 0; i < 4; ++i)
        assert(!pthread_create(&threads[i], NULL, publisher, (void *)i));
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(generations[0] == 40000 && generations[1] == 40000);
    puts("PASS page locks: independent progress, 80000 consistent concurrent publications");
}

static void *allocator(void *opaque)
{
    uintptr_t id = (uintptr_t)opaque;
    for (unsigned i = 0; i < 10000; ++i) {
        int slot;
        (void)uz_short_lock_take(&budget_lock);
        slot = uz_buffer_reserve(&budget, 100 + id, 4096);
        assert(budget.used <= budget.limit);
        if (slot >= 0) budget.records[slot].ptr = (void *)(id + 1);
        uz_short_lock_drop(&budget_lock);
        if (slot < 0) continue;
        sched_yield(); /* model allocation/lifetime outside the short lock */
        (void)uz_short_lock_take(&budget_lock);
        assert(uz_buffer_find(&budget, (void *)(id + 1)) == slot);
        uz_buffer_cancel(&budget, (unsigned)slot);
        uz_short_lock_drop(&budget_lock);
    }
    return NULL;
}

static void test_budget(void)
{
    struct uz_buffer_budget b = {.limit = 3 * 4096};
    pthread_t threads[8];
    assert(uz_buffer_reserve(&b, 1, 4096) == 0 && b.used == 4096);
    assert(uz_buffer_reserve(&b, 4097, 4096) == 1 && b.used == b.limit);
    assert(uz_buffer_reserve(&b, 1, 4096) < 0);
    assert(uz_buffer_find(&b, NULL) < 0);
    b.records[1].ptr = &b;
    assert(uz_buffer_find(&b, &b) == 1);
    uz_buffer_cancel(&b, 1); /* failed allocation or completed native free */
    uz_buffer_cancel(&b, 1); /* repeated cancellation cannot underflow */
    assert(b.used == 4096 && b.peak == 12288);
    uz_buffer_cancel(&b, 0);
    assert(!b.used);
    assert(uz_buffer_reserve(&b, UINT64_MAX, 4096) < 0);
    assert(uz_buffer_reserve(&b, 0, 4096) < 0);
    assert(uz_buffer_reserve(&b, 1, 0) < 0);
    assert(uz_buffer_reserve(&b, 1, 3) < 0);
    assert(b.denied == 5);
    b.denied = UINT64_MAX;
    assert(uz_buffer_reserve(&b, 0, 1) < 0 && b.denied == UINT64_MAX);
    b.limit = UINT64_MAX;
    for (unsigned i = 0; i < UZ_BUFFER_SLOTS; ++i)
        assert(uz_buffer_reserve(&b, 1, 16384) == (int)i);
    assert(uz_buffer_reserve(&b, 1, 16384) < 0);
    for (unsigned i = 0; i < UZ_BUFFER_SLOTS; ++i) uz_buffer_cancel(&b, i);
    assert(!b.used);
    budget.limit = 4 * 4096;
    for (uintptr_t i = 0; i < 8; ++i)
        assert(!pthread_create(&threads[i], NULL, allocator, (void *)i));
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
    assert(!budget.used && budget.peak <= budget.limit);
    puts("PASS buffer budget: rounding, overflow, failure release, saturation, 80000 concurrent reservations");
}

static void test_identity(void)
{
    for (unsigned shift = 12; shift <= 14; shift += 2) {
        uint64_t ps = UINT64_C(1) << shift, page = 9 * ps;
        struct uz_vma_view v = {.start = 8 * ps, .end = 12 * ps, .file = 42, .pgoff = 5};
#define MATCH() uz_mapping_matches(&v, page, shift, 42, 6, 8 * ps, 12 * ps, 1)
        assert(MATCH());
        v.start = page; v.pgoff = 6; /* VMA split */
        assert(MATCH());
        v.start += 20 * ps; v.end += 20 * ps; page += 20 * ps; /* move */
        assert(MATCH());
        v.file = 43; assert(!MATCH()); v.file = 42;
        ++v.pgoff; assert(!MATCH()); --v.pgoff;
        ++page; assert(!MATCH()); --page;
        v.end = page; assert(!MATCH());
        v.end = page + ps - 1; assert(!MATCH());
        v.end = page + ps; assert(MATCH());
        --v.start; assert(!MATCH()); ++v.start;
        v.start -= ps; v.pgoff = UINT64_MAX; assert(!MATCH());
        v = (struct uz_vma_view){.start = 8 * ps, .end = 12 * ps, .file = 42, .pgoff = 5};
        page = 9 * ps;
        assert(uz_mapping_matches(&v, page, shift, 42, 0, v.start, v.end, 0));
        assert(!uz_mapping_matches(&v, page, shift, 42, 0, v.start + ps, v.end, 0));
        assert(!uz_mapping_matches(&v, page, 16, 42, 6, v.start, v.end, 1));
        assert(!uz_mapping_matches(&v, page, shift, 0, 6, v.start, v.end, 1));
#undef MATCH
    }
    puts("PASS mapping identity: 4K/16K split/move, replacement, bounds, overflow, missing pgoff");
}

int main(void)
{
    alarm(60);
    test_identity();
    test_budget();
    test_locks();
    return 0;
}
