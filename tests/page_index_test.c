/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include "../module/page_index.h"
#include "../module/readers.h"

enum { COUNT = 33, ROUNDS = 10000 };
static uint64_t readers;
static struct uz_page_index *published;
static unsigned stop, reads;

static void fill(struct uz_page_index *idx, unsigned generation)
{
    idx->count = COUNT;
    for (unsigned i = 0; i < COUNT; ++i) {
        idx->keys[i].base = ((uint64_t)generation << 32) + (COUNT - i) * 4096U;
        idx->keys[i].slot = i;
    }
    uz_index_sort(idx);
}
static void check(const struct uz_page_index *idx)
{
    uint64_t high = idx->keys[0].base & UINT64_C(0xffffffff00000000);
    assert(idx->count == COUNT);
    for (unsigned i = 0; i < COUNT; ++i) {
        assert(idx->keys[i].base == high + (i + 1U) * 4096U);
        assert(uz_index_find(idx, idx->keys[i].base) == COUNT - i - 1U);
    }
    assert(uz_index_find(idx, high) == UINT32_MAX);
    assert(uz_index_find(idx, high + (COUNT + 1U) * 4096U) == UINT32_MAX);
}
static void *reader(void *unused)
{
    (void)unused;
    do {
        uint64_t ref = uz_reader_enter(&readers);
        if (!ref) continue;
        const struct uz_page_index *idx = __atomic_load_n(&published, __ATOMIC_ACQUIRE);
        check(idx);
        sched_yield(); /* hold a retired table while the writer publishes */
        check(idx);
        __atomic_add_fetch(&reads, 1U, __ATOMIC_RELAXED);
        uz_reader_exit(&readers, ref);
    } while (!__atomic_load_n(&stop, __ATOMIC_ACQUIRE));
    return NULL;
}
int main(void)
{
    pthread_t threads[4];
    size_t bytes = sizeof(*published) + COUNT * sizeof(struct uz_page_key);
    struct uz_page_index *spare = malloc(bytes);
    published = malloc(bytes);
    assert(spare && published);
    fill(published, 0);
    uz_readers_open(&readers);
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_create(&threads[i], NULL, reader, NULL));
    for (unsigned i = 1; i <= ROUNDS; ++i) {
        fill(spare, i);
        struct uz_page_index *old = uz_index_publish(&published, spare);
        uint64_t mask = uz_readers_flip(&readers);
        while (__atomic_load_n(&readers, __ATOMIC_ACQUIRE) & mask) sched_yield();
        spare = old;
    }
    __atomic_store_n(&stop, 1U, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 4; ++i) assert(!pthread_join(threads[i], NULL));
    assert(reads);
    check(published);
    free(spare);
    free(published);
    printf("PASS immutable page index: %u publications, %u concurrent reads, stable slots and grace periods\n",
           ROUNDS, reads);
    return 0;
}
