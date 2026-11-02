/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolates unexpected copy corruption seen before any overlay was installed.
 * Changes only this process's new mapping. Never adjusts system protections. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
static void *(*volatile libc_copy)(void *, const void *, size_t) = memcpy;
static unsigned mismatch(const volatile uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0; i < 4096; ++i) if (a[i] != b[i]) return i;
    return 4096;
}
int main(void)
{
    uint8_t source[4096];
    unsigned i, diff, failures = 0;
    int prefault;
    for (i = 0; i < 4096; ++i) ((volatile uint8_t *)source)[i] = (uint8_t)(i * 37U + 19U);
    for (prefault = 0; prefault <= 1; ++prefault) {
        int fd = memfd_create("urov-copy-probe", MFD_CLOEXEC);
        uint8_t *p;
        if (fd < 0 || ftruncate(fd, 4096)) { perror("memfd"); if (fd >= 0) close(fd); return 1; }
        p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        close(fd);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        if (prefault) ((volatile uint8_t *)p)[0] = 0;
        libc_copy(p, source, 4096);
        diff = mismatch(p, source);
        printf("libc_copy prefault=%d result=%s first_diff=%u\n", prefault,
               diff == 4096 ? "PASS" : "FAIL", diff);
        if (diff != 4096) ++failures;
        for (i = 0; i < 4096; ++i) ((volatile uint8_t *)p)[i] = source[i];
        diff = mismatch(p, source);
        printf("scalar_copy prefault=%d result=%s\n", prefault, diff == 4096 ? "PASS" : "FAIL");
        if (diff != 4096) ++failures;
        munmap(p, 4096);
    }
    printf("copy_probe failures=%u overlay=NOT_ENABLED\n", failures);
    return failures ? 1 : 0;
}
