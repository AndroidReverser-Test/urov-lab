/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UZ_INTEGRATION_SHARED_H
#define UZ_INTEGRATION_SHARED_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#define TEST_DIR "/data/user/0/com.example.urovzinject/files"
#define TEST_MAGIC UINT64_C(0x555a494e54454731)
#define PAYLOAD_COOKIE UINT64_C(0x444f4242594b434c)
enum test_action { INSPECT = 0, HOOK = 1, OVERLAY = 2, DEACTIVATE = 3, UNHOOK = 4 };

struct test_context {
    uint64_t magic;
    int pid;
    int tid;
    char key[33];
    int (*target)(int, int);
    uint32_t (*direct_crc)(void);
    int (*action)(int);
    uint64_t cookie;
    unsigned constructors;
    unsigned probe_constructors;
    uint32_t probe_crc;
    int probe_result;
    int hooked;
    int overlaid;
    int seen_a, seen_b, original_result;
    uint32_t baseline_crc;
    uint64_t overlay_hits, overlay_failures;
    uint32_t armed;
};

/* Test-only rendezvous: this file is created by this App before injection.
 * It contains no key and is accessible only inside the App's sandbox. */
static inline struct test_context *test_find_context(void)
{
    unsigned long long address = 0;
    FILE *f = fopen(TEST_DIR "/context.txt", "r");
    if (!f) return NULL;
    int n = fscanf(f, "%llx", &address);
    fclose(f);
    if (n != 1 || !address) return NULL;
    struct test_context *ctx = (struct test_context *)(uintptr_t)address;
    if (ctx->magic != TEST_MAGIC || ctx->pid != getpid()) return NULL;
    return ctx;
}
#endif
