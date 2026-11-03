/* SPDX-License-Identifier: GPL-2.0-or-later
 * Keep readers running in the protected page while a supervisor unloads the
 * KPM. exit must restore the PTE before unhooking; readers then continue
 * natively on the original bytes. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../urov_abi.h"

static uint8_t *code;
static uint64_t original_value;
static const uint64_t fake = UINT64_C(0x8877665544332211);
static atomic_int stop;
static atomic_ulong loops;
static atomic_int errors;

static void segv(int sig, siginfo_t *si, void *ctx)
{
    (void)sig; (void)ctx;
    fprintf(stderr, "FAIL SIGSEGV addr=%p code=%d\n", si->si_addr, si->si_code);
    _exit(70);
}

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
    fd = memfd_create("urov-hold2", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0 || ftruncate(fd, 4096)) return -1;
    rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) return -1;
    for (i = 0; i < 4096; ++i) rw[i] = (uint8_t)(i * 11U + 7U);
    for (i = 0; i < sizeof(insns); ++i) rw[i] = insns[i];
    for (i = 0; i < 8; ++i) original_value |= (uint64_t)rw[4 + i] << (i * 8);
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

static void *reader(void *opaque)
{
    unsigned cpu = (unsigned)(uintptr_t)opaque;
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET((int)cpu, &one);
    (void)sched_setaffinity(0, sizeof(one), &one);
    while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
        uint64_t v;
        __asm__ volatile("ldr %0, [%1]" : "=r"(v) : "r"(code + 4) : "memory");
        if (v != fake && v != original_value) {
            atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed);
            break;
        }
        if (((int (*)(void))code)() != 42) {
            atomic_fetch_add_explicit(&errors, 1, memory_order_relaxed);
            break;
        }
        atomic_fetch_add_explicit(&loops, 1, memory_order_relaxed);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct urov_request q;
    struct sigaction sa;
    pthread_t t[4];
    unsigned seconds = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 10;
    int i;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    if (make_page()) { perror("make_page"); return 2; }
    memset(&q, 0, sizeof(q));
    q.size = sizeof(q); q.version = UROV_ABI_VERSION; q.op = UROV_NOTIFY_REGISTER;
    q.address = (uintptr_t)code; q.offset = 4; q.value = fake; q.flags = UROV_F_RAW_XOM;
    if (notify(UROV_NOTIFY_REGISTER, &q)) { perror("register"); return 2; }
    for (i = 0; i < 4; ++i) pthread_create(&t[i], NULL, reader, (void *)(uintptr_t)i);
    printf("READY readers=4\n");
    sleep(seconds);
    atomic_store_explicit(&stop, 1, memory_order_relaxed);
    for (i = 0; i < 4; ++i) pthread_join(t[i], NULL);
    printf("AFTER loops=%lu errors=%d exec=%d value=%llx\n", atomic_load(&loops),
           atomic_load(&errors), ((int (*)(void))code)(),
           (unsigned long long)*(volatile uint64_t *)(code + 4));
    return atomic_load(&errors) ? 1 : 0;
}
