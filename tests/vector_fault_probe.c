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
int main(void)
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
