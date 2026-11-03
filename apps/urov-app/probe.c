/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Capability probe for an ordinary (untrusted_app) process.
 *
 * It answers the questions that decide the app-facing page/control design:
 *   1. does app seccomp allow prctl()/ioctl() with attacker-chosen arguments?
 *   2. can the app reopen a sealed memfd through /proc/self/fd?
 *   3. can it map its own data file or its own installed native library
 *      PROT_READ|PROT_EXEC (SELinux execute/mmap permission)?
 *   4. what does the VMA of its own code look like in /proc/self/maps?
 *
 * No KPM is required for this probe. Each risky execution runs in a forked
 * child with a 5 s alarm so a SIGSYS/SIGSEGV cannot take down the activity.
 */
#define _GNU_SOURCE
#include <android/log.h>
#include <android/native_activity.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <link.h>

#define TAG "urovprobe"
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#ifndef __NR_prctl
#define __NR_prctl 167
#endif
#ifndef __NR_ioctl
#define __NR_ioctl 29
#endif

#define PROBE_PRCTL_OPTION 0x55524f56UL
#define PROBE_MAGIC 0x55524f5653595343ULL

/* A leaf, position-independent function that the app can find by dlsym().
 * It must not use a literal pool so that executing it from a one-page alias
 * of the library file only needs that page. */
__attribute__((noinline, used, visibility("default")))
uint64_t urov_payload(uint64_t x)
{
    return x ^ 0x1122334455667788ULL;
}

static const uint32_t probe_code[] = {
    0x52800540, /* mov w0, #42 */
    0xd65f03c0, /* ret */
    0xd503201f, /* nop */
};

typedef int (*child_fn)(void);

static int run_child(const char *name, child_fn fn)
{
    pid_t pid;
    int status;
    pid = fork();
    if (pid < 0) {
        LOG("%s: fork errno=%d", name, errno);
        return -1;
    }
    if (pid == 0) {
        int rc;
        alarm(5);
        rc = fn();
        _exit(rc ? 1 : 0);
    }
    if (waitpid(pid, &status, 0) != pid) {
        LOG("%s: waitpid errno=%d", name, errno);
        return -1;
    }
    if (WIFSIGNALED(status)) {
        LOG("%s: child killed sig=%d", name, WTERMSIG(status));
        return -1;
    }
    LOG("%s: child exit=%d", name, WEXITSTATUS(status));
    return WEXITSTATUS(status);
}

static int sys_prctl(void)
{
    long rc;
    errno = 0;
    rc = syscall(__NR_prctl, PROBE_PRCTL_OPTION, PROBE_MAGIC, 1L, 0L, 0L);
    LOG("prctl: rc=%ld errno=%d", rc, errno);
    return 0;
}

static int sys_ioctl(void)
{
    long rc;
    errno = 0;
    rc = syscall(__NR_ioctl, -1L, 0x5552L, 0L);
    LOG("ioctl: rc=%ld errno=%d", rc, errno);
    return 0;
}

static const void *g_exec_code;
static uint64_t g_exec_arg;

static int exec_child(void)
{
    uint64_t (*fn)(uint64_t) = (uint64_t (*)(uint64_t))g_exec_code;
    uint64_t got = fn(g_exec_arg);
    LOG("exec: got=0x%llx arg=0x%llx %s", (unsigned long long)got,
        (unsigned long long)g_exec_arg, got == 42 ? "OK" : "MISMATCH");
    return got == 42 ? 0 : 1;
}

/* ------------------------------------------------------------ memfd probe */

static int memfd_probe(void)
{
    uint8_t *rw;
    int fd, ro;
    char path[64];
    void *rx = MAP_FAILED;
    int rc = 0;

    fd = (int)syscall(__NR_memfd_create, "urovprobe", 3U /* CLOEXEC|ALLOW_SEALING */);
    if (fd < 0) {
        LOG("memfd: create errno=%d", errno);
        return -1;
    }
    if (ftruncate(fd, 4096)) {
        LOG("memfd: ftruncate errno=%d", errno);
        close(fd);
        return -1;
    }
    rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (rw == MAP_FAILED) {
        LOG("memfd: rw mmap errno=%d", errno);
        close(fd);
        return -1;
    }
    memcpy(rw, probe_code, sizeof(probe_code));
    __builtin___clear_cache((char *)rw, (char *)rw + 4096);
    munmap(rw, 4096);
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL))
        LOG("memfd: F_ADD_SEALS errno=%d", errno);

    errno = 0;
    rx = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    LOG("memfd: rx mmap on RW fd=%p errno=%d", rx, errno);
    if (rx != MAP_FAILED) {
        g_exec_code = rx;
        g_exec_arg = 0;
        rc |= run_child("memfd rx exec", exec_child);
        munmap(rx, 4096);
    }

    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    errno = 0;
    ro = open(path, O_RDONLY | O_CLOEXEC);
    LOG("memfd: open /proc/self/fd errno=%d (fd=%d)", errno, ro);
    if (ro >= 0) {
        errno = 0;
        rx = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, ro, 0);
        LOG("memfd: ro rx mmap=%p errno=%d", rx, errno);
        if (rx != MAP_FAILED) munmap(rx, 4096);
        close(ro);
    }
    close(fd);
    return rc ? -1 : 0;
}

/* --------------------------------------------------------- app data probe */

static int datafile_probe(const char *dir)
{
    char path[512];
    uint8_t page[4096];
    int fd;
    void *rx;
    int rc;

    if (!dir) {
        LOG("datafile: no internalDataPath");
        return -1;
    }
    snprintf(path, sizeof(path), "%s/urovprobe.bin", dir);
    memset(page, 0, sizeof(page));
    memcpy(page, probe_code, sizeof(probe_code));

    unlink(path);
    fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (fd < 0) {
        LOG("datafile: create errno=%d path=%s", errno, path);
        return -1;
    }
    if (write(fd, page, sizeof(page)) != (ssize_t)sizeof(page)) {
        LOG("datafile: write errno=%d", errno);
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG("datafile: reopen errno=%d", errno);
        unlink(path);
        return -1;
    }
    errno = 0;
    rx = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    LOG("datafile: MAP_SHARED RX mmap=%p errno=%d", rx, errno);
    if (rx == MAP_FAILED) {
        errno = 0;
        rx = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
        LOG("datafile: MAP_PRIVATE RX mmap=%p errno=%d", rx, errno);
    }
    close(fd);
    unlink(path);
    if (rx == MAP_FAILED) return -1;
    rc = 0;
    {
        uint64_t (*fn)(uint64_t) = (uint64_t (*)(uint64_t))rx;
        uint64_t got = fn(0);
        LOG("datafile: exec got=0x%llx want=0x2a %s", (unsigned long long)got,
            got == 42 ? "OK" : "MISMATCH");
        if (got != 42) rc = -1;
    }
    munmap(rx, 4096);
    return rc;
}

/* ---------------------------------------------------------- own lib probe */

struct vma_info {
    unsigned long start, end;
    char perms[8];
    char path[512];
};

static int find_vma(const void *addr, struct vma_info *out)
{
    FILE *f = fopen("/proc/self/maps", "re");
    char line[1024];
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8], path[512] = "";
        int n;
        n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511c", &start, &end, perms, path);
        if (n < 3) continue;
        if ((unsigned long)addr >= start && (unsigned long)addr < end) {
            out->start = start;
            out->end = end;
            strncpy(out->perms, perms, sizeof(out->perms) - 1);
            out->perms[sizeof(out->perms) - 1] = 0;
            if (n >= 4) {
                char *p = path;
                while (*p == ' ') ++p;
                strncpy(out->path, p, sizeof(out->path) - 1);
                out->path[sizeof(out->path) - 1] = 0;
                p = strchr(out->path, '\n');
                if (p) *p = 0;
            } else {
                out->path[0] = 0;
            }
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int own_lib_probe(void)
{
    Dl_info info;
    struct vma_info vma;
    const void *p = (const void *)&urov_payload;
    int rc = 0;

    memset(&info, 0, sizeof(info));
    if (!dladdr(p, &info) || !info.dli_fbase || !info.dli_fname) {
        LOG("ownlib: dladdr failed");
        return -1;
    }
    LOG("ownlib: payload=%p base=%p name=%s", p, info.dli_fbase, info.dli_fname);
    if (find_vma(p, &vma) == 0) {
        LOG("ownlib: vma=%lx-%lx perms=%s size=%lu path=%s",
            vma.start, vma.end, vma.perms, vma.end - vma.start, vma.path);
    } else {
        LOG("ownlib: vma not found");
    }

    /* Map a one-page RX alias of the library file at the payload's file
     * offset, without going through /proc/self/fd. */
    {
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)info.dli_fbase;
        unsigned long vaddr = (unsigned long)p - (unsigned long)info.dli_fbase;
        unsigned long file_off = 0;
        int found = 0, i;
        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) == 0) {
            const Elf64_Phdr *ph = (const Elf64_Phdr *)((const char *)eh + eh->e_phoff);
            for (i = 0; i < eh->e_phnum; ++i) {
                if (ph[i].p_type != PT_LOAD) continue;
                if (vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_memsz) {
                    file_off = ph[i].p_offset + (vaddr - ph[i].p_vaddr);
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            LOG("ownlib: PT_LOAD not found for vaddr=%lx", vaddr);
            return -1;
        }
        LOG("ownlib: vaddr=%lx file_off=%lx page_off=%lx in_page=%lx", vaddr, file_off,
            file_off & ~0xfffUL, file_off & 0xfffUL);
        {
            int fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                LOG("ownlib: open errno=%d", errno);
                return -1;
            }
            errno = 0;
            void *alias = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
                               (off_t)(file_off & ~0xfffUL));
            LOG("ownlib: one-page RX alias=%p errno=%d", alias, errno);
            close(fd);
            if (alias != MAP_FAILED) {
                unsigned long in_page = file_off & 0xfffUL;
                if (in_page + 32 <= 4096) {
                    uint64_t (*fn)(uint64_t) = (uint64_t (*)(uint64_t))
                        ((char *)alias + in_page);
                    uint64_t got = fn(0x1234);
                    LOG("ownlib: alias exec got=0x%llx want=0x%llx %s",
                        (unsigned long long)got,
                        (unsigned long long)(0x1234ULL ^ 0x1122334455667788ULL),
                        got == (0x1234ULL ^ 0x1122334455667788ULL) ? "OK" : "MISMATCH");
                    if (got != (0x1234ULL ^ 0x1122334455667788ULL)) rc = -1;
                } else {
                    LOG("ownlib: payload crosses page boundary");
                }
                munmap(alias, 4096);
            }
        }
    }
    return rc;
}

static void log_status(void)
{
    FILE *f = fopen("/proc/self/status", "re");
    char line[256];
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "Seccomp:", 8) || !strncmp(line, "NoNewPrivs:", 11) ||
            !strncmp(line, "Uid:", 4))
            LOG("status: %s", line);
    }
    fclose(f);
}

static void log_context(void)
{
    char ctx[128] = { 0 };
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, ctx, sizeof(ctx) - 1);
        if (n > 0) LOG("context=%s", ctx);
        close(fd);
    } else {
        LOG("context: open errno=%d", errno);
    }
}

void ANativeActivity_onCreate(ANativeActivity *activity, void *saved_state, size_t saved_size)
{
    int rc = 0;
    (void)saved_state;
    (void)saved_size;
    LOG("=== probe begin pid=%d uid=%d ===", (int)getpid(), (int)getuid());
    log_status();
    log_context();

    rc |= run_child("prctl channel", sys_prctl);
    rc |= run_child("ioctl channel", sys_ioctl);
    memfd_probe();
    rc |= datafile_probe(activity->internalDataPath);
    rc |= own_lib_probe();

    LOG("=== probe done rc=%d ===", rc);
    ANativeActivity_finish(activity);
}
