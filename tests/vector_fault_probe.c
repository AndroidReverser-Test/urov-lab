/* SPDX-License-Identifier: GPL-2.0-or-later */
/* No KPM dependency: isolate SIMD register preservation across a first-touch
 * page fault, rather than infer the cause from a libc memcpy mismatch. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned difference(const volatile uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 64; ++i) if (a[i] != b[i]) return i;
    return 64;
}
static int vector_store_first_touch(void)
{
    _Alignas(16) uint8_t input[64], saved[64];
    unsigned i, mode, prefault, cross, failures = 0;
    for (i = 0; i < 64; ++i) ((volatile uint8_t *)input)[i] = (uint8_t)(i * 37U + 19U);
    for (mode = 0; mode < 2; ++mode) for (prefault = 0; prefault < 2; ++prefault)
    for (cross = 0; cross < 2; ++cross) {
        int fd = -1, flags = MAP_PRIVATE | MAP_ANONYMOUS;
        uint8_t *mapping, *dest;
        unsigned memory_diff, registers_diff;
        if (mode) {
            fd = memfd_create("urov-vector-fault", MFD_CLOEXEC);
            if (fd < 0 || ftruncate(fd, 8192)) { perror("memfd"); if (fd >= 0) close(fd); return 1; }
            flags = MAP_SHARED;
        }
        mapping = mmap(NULL, 8192, PROT_READ | PROT_WRITE, flags, fd, 0);
        if (fd >= 0) close(fd);
        if (mapping == MAP_FAILED) { perror("mmap"); return 1; }
        dest = mapping + (cross ? 4096 - 32 : 0);
        for (i = 0; i < 64; ++i) ((volatile uint8_t *)saved)[i] = 0;
        if (prefault) { ((volatile uint8_t *)mapping)[0] = 0; ((volatile uint8_t *)mapping)[4096] = 0; }
        __asm__ volatile(
            "ldp q0, q1, [%0]\n ldp q2, q3, [%0, #32]\n"
            "stp q0, q1, [%1]\n stp q2, q3, [%1, #32]\n"
            "stp q0, q1, [%2]\n stp q2, q3, [%2, #32]\n"
            : : "r"(input), "r"(dest), "r"(saved) : "v0", "v1", "v2", "v3", "memory");
        memory_diff = difference(dest, input);
        registers_diff = difference(saved, input);
        printf("vector_fault backing=%s prefault=%u cross_page=%u memory_diff=%u registers_diff=%u\n",
               mode ? "memfd" : "anonymous", prefault, cross, memory_diff, registers_diff);
        if (memory_diff != 64 || registers_diff != 64) ++failures;
        munmap(mapping, 8192);
    }
    printf("vector_fault failures=%u overlay=NOT_ENABLED\n", failures);
    return failures ? 1 : 0;
}

/* Snapshot all four Q registers using only GPRs and scalar stores. Taking
 * both snapshots this way makes the destination store's instruction class
 * independent of the instruction class used to record the live lanes. */
#define CAPTURE_Q_LANES(buffer)                                  \
    "umov x9, v0.d[0]\n umov x10, v0.d[1]\n"                    \
    "stp x9, x10, [%[" #buffer "], #0]\n"                        \
    "umov x9, v1.d[0]\n umov x10, v1.d[1]\n"                    \
    "stp x9, x10, [%[" #buffer "], #16]\n"                       \
    "umov x9, v2.d[0]\n umov x10, v2.d[1]\n"                    \
    "stp x9, x10, [%[" #buffer "], #32]\n"                       \
    "umov x9, v3.d[0]\n umov x10, v3.d[1]\n"                    \
    "stp x9, x10, [%[" #buffer "], #48]\n"

static int scalar_first_touch(void)
{
    _Alignas(16) uint8_t expected[64], before[64], after[64];
    const unsigned marker = 0xa5;
    const long page_size = sysconf(_SC_PAGESIZE);
    unsigned i, memfd, warm, failures = 0;
    if (page_size <= 0) { fprintf(stderr, "Could not determine page size\n"); return 1; }
    for (i = 0; i < sizeof(expected); ++i)
        ((volatile uint8_t *)expected)[i] = (uint8_t)(i * 37U + 19U);

    for (memfd = 0; memfd < 2; ++memfd) for (warm = 0; warm < 2; ++warm) {
        int fd = -1, flags = MAP_PRIVATE | MAP_ANONYMOUS;
        uint8_t *target;
        unsigned before_diff, after_diff, observed;
        if (memfd) {
            fd = memfd_create("urov-scalar-first-touch", MFD_CLOEXEC);
            if (fd < 0) { perror("memfd_create"); return 1; }
            if (ftruncate(fd, page_size)) { perror("ftruncate"); close(fd); return 1; }
            flags = MAP_SHARED;
        }
        target = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE, flags, fd, 0);
        if (fd >= 0) close(fd);
        if (target == MAP_FAILED) { perror("mmap"); return 1; }
        for (i = 0; i < sizeof(before); ++i) {
            ((volatile uint8_t *)before)[i] = 0;
            ((volatile uint8_t *)after)[i] = 0;
        }
        if (warm) *(volatile uint8_t *)target = 0x5a;
        __asm__ volatile(
            "ldp q0, q1, [%[src]]\n ldp q2, q3, [%[src], #32]\n"
            CAPTURE_Q_LANES(before)
            "strb %w[marker], [%[target]]\n"
            CAPTURE_Q_LANES(after)
            : : [src] "r"(expected), [before] "r"(before), [after] "r"(after),
                [marker] "r"(marker), [target] "r"(target)
            : "x9", "x10", "v0", "v1", "v2", "v3", "memory");
        observed = *(volatile uint8_t *)target;
        before_diff = difference(before, expected);
        after_diff = difference(after, expected);
        printf("scalar_first_touch backing=%s prefault=%u before_first_diff=%u "
               "after_first_diff=%u target_byte=%u expected_byte=%u\n",
               memfd ? "memfd" : "anonymous", warm, before_diff, after_diff, observed, marker);
        if (before_diff != sizeof(before) || after_diff != sizeof(after) || observed != marker)
            ++failures;
        if (munmap(target, (size_t)page_size)) { perror("munmap"); return 1; }
    }
    printf("scalar_first_touch failures=%u overlay=NOT_ENABLED\n", failures);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 1) return vector_store_first_touch();
    if (argc == 2 && !strcmp(argv[1], "--scalar-first-touch")) return scalar_first_touch();
    fprintf(stderr, "Usage: %s [--scalar-first-touch]\n", argv[0]);
    return 2;
}
