/* SPDX-License-Identifier: GPL-2.0-or-later
 * Register a page, announce readiness, then wait while the supervisor unloads
 * the KPM. After the module is gone the page must be readable again through the
 * native path (the module exit restores AP[1] before unhooking). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../urov_abi.h"

static uint8_t *code;

static long notify(unsigned int cmd, struct urov_request *q)
{
    errno = 0;
    return syscall(UROV_NOTIFY_NR, (long)UROV_NOTIFY_MAGIC, (long)cmd, q, (long)sizeof(*q));
}

static int make_page(void)
{
    static const uint8_t insns[] = { 0x5f, 0x24, 0x03, 0xd5, 0x40, 0x05, 0x80, 0x52,
                                     0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5 };
    uint8_t *rw;
    int fd, ro;
    char path[64];
    unsigned i;
    fd = memfd_create("urov-hold", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, 4096)) return -1;
    rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) return -1;
    for (i = 0; i < 4096; ++i) rw[i] = (uint8_t)(i * 11U + 7U);
    for (i = 0; i < sizeof(insns); ++i) rw[i] = insns[i];
    __builtin___clear_cache((char *)rw, (char *)rw + 4096);
    munmap(rw, 4096);
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return -1;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ro = open(path, O_RDONLY | O_CLOEXEC);
    if (ro < 0) return -1;
    code = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, ro, 0);
    close(ro);
    close(fd);
    return code == MAP_FAILED ? -1 : 0;
}

int main(int argc, char **argv)
{
    struct urov_request q;
    unsigned seconds = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 5;
    uint64_t before;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (make_page()) { perror("make_page"); return 2; }
    memset(&q, 0, sizeof(q));
    q.size = sizeof(q); q.version = UROV_ABI_VERSION; q.op = UROV_NOTIFY_REGISTER;
    q.address = (uintptr_t)code; q.offset = 4; q.value = UINT64_C(0x8877665544332211);
    q.flags = UROV_F_RAW_XOM;
    if (notify(UROV_NOTIFY_REGISTER, &q)) { perror("register"); return 2; }
    __asm__ volatile("ldr %0, [%1]" : "=r"(before) : "r"(code + 4) : "memory");
    printf("READY session=%llu value=%llx exec=%d\n", (unsigned long long)q.session,
           (unsigned long long)before, ((int (*)(void))code)());
    sleep(seconds);
    printf("AFTER value=%llx exec=%d\n", (unsigned long long)*(volatile uint64_t *)(code + 4),
           ((int (*)(void))code)());
    return 0;
}
