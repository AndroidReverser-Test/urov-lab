/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UZ_INTEGRATION_SHARED_H
#define UZ_INTEGRATION_SHARED_H
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include "../test_config.h"
#define TEST_TARGETS 10
#define TEST_MAGIC UINT64_C(0x555a494e54454732)
#define PAYLOAD_COOKIE UINT64_C(0x444f4242594b434c)
enum test_action { INSPECT, HOOK, OVERLAY, DEACTIVATE, UNHOOK };
typedef int (*test_target)(int, int);
struct test_context {
    uint64_t magic;
    int pid, tid;
    test_target targets[TEST_TARGETS];
    uint32_t (*direct_crc)(void);
    int (*action)(int);
    uint64_t cookie;
    unsigned constructors, probe_constructors;
    uint32_t probe_crc;
    unsigned probe_ok;
    int hooked, overlaid;
    int seen_a[TEST_TARGETS], seen_b[TEST_TARGETS], original_result[TEST_TARGETS];
    uint32_t baseline_crc;
    uint64_t overlay_hits, overlay_failures;
    uint32_t armed, registered_pages;
};
/* Immutable process-local rendezvous set before injection. libc's environment
 * is shared across Android linker namespaces; no dependency on the host's
 * classloader namespace and no address/command/result files are needed. */
#define TEST_CONTEXT_ENV "UROV_LAB_CONTEXT_V2"
static inline struct test_context *test_find_context(void)
{
    const char *text = getenv(TEST_CONTEXT_ENV);
    if (!text || !*text) return NULL;
    char *end;
    uintptr_t address = (uintptr_t)strtoull(text, &end, 16);
    if (*end || !address) return NULL;
    struct test_context *ctx = (struct test_context *)address;
    return ctx && ctx->magic == TEST_MAGIC && ctx->pid == getpid() ? ctx : NULL;
}
static inline int test_expected(unsigned i, int hooked)
{
    int a = 3 + (int)i, b = 4 + 2 * (int)i;
    return hooked ? (a + 10) * 7 + b * 3 + 17 * (int)i + 1000 : a * 7 + b + 17 * (int)i;
}
#endif
