/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Serial management test of the preflight KPM, NOT an overlay test. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#define _KP_KTYPES_H_
#include "uapi/scdefs.h"
#undef _KP_KTYPES_H_
#include "version"

static long word(long cmd)
{
    return ((long)((MAJOR << 16) | (MINOR << 8) | PATCH) << 32) |
           (0x1158L << 16) | (cmd & 0xffffL);
}
static long norm(long ret) { return ret == -1 ? -(long)errno : ret; }
static long ctl(const char *key, const char *cmd, char *out, int len)
{
    errno = 0;
    return norm(syscall(__NR_supercall, key, word(SUPERCALL_KPM_CONTROL),
                        "urov-lab-check", cmd, out, len));
}
static long load(const char *key, const char *path, const char *args)
{
    errno = 0;
    return norm(syscall(__NR_supercall, key, word(SUPERCALL_KPM_LOAD), path, args, NULL));
}
static long unload(const char *key)
{
    errno = 0;
    return norm(syscall(__NR_supercall, key, word(SUPERCALL_KPM_UNLOAD), "urov-lab-check", NULL));
}
static int number(const char *s, long min, long max, long *value)
{
    char *end;
    long n;
    errno = 0; n = strtol(s, &end, 10);
    if (errno || !s[0] || *end || n < min || n > max) return -1;
    *value = n; return 0;
}
static int read_key(int fd, char *key, size_t cap)
{
    size_t n = 0;
    char c;
    for (;;) {
        ssize_t got = read(fd, &c, 1);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -1;
        if (!got || c == '\n') break;
        if (c == '\0' || n + 1 >= cap) return -1;
        key[n++] = c;
    }
    if (n && key[n - 1] == '\r') --n;
    key[n] = 0;
    return n ? 0 : -1;
}
int main(int argc, char **argv)
{
    char key[128] = { 0 }, output[1024];
    const char *path = NULL;
    long fd = -1, cycles = 3, n, result;
    int i, loaded = 0, rc = 1;
    void *inaccessible = MAP_FAILED;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--module") && i + 1 < argc) path = argv[++i];
        else if (!strcmp(argv[i], "--key-fd") && i + 1 < argc) {
            if (number(argv[++i], 0, 1024, &fd)) goto usage;
        } else if (!strcmp(argv[i], "--cycles") && i + 1 < argc) {
            if (number(argv[++i], 1, 100, &cycles)) goto usage;
        } else goto usage;
    }
    if (!path || path[0] != '/' || fd < 0) goto usage;
    if (read_key((int)fd, key, sizeof(key))) { fprintf(stderr, "Invalid key input\n"); goto done; }
    errno = 0;
    result = norm(syscall(__NR_supercall, key, word(SUPERCALL_HELLO)));
    if (result != SUPERCALL_HELLO_MAGIC) { fprintf(stderr, "KP authorization unavailable\n"); goto done; }
    memset(output, 0, sizeof(output));
    result = ctl(key, "status", output, sizeof(output));
    if (result != -ENOENT) { fprintf(stderr, "Expected absent module; refusing ownership conflict result=%ld\n", result); goto done; }
    inaccessible = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (inaccessible == MAP_FAILED) goto done;
#define EXPECT(expr, value) do { result = (expr); if (result != (value)) { \
    fprintf(stderr, "FAIL line=%d result=%ld expected=%ld\n", __LINE__, result, (long)(value)); goto done; } } while (0)
    EXPECT(load(key, path, "invalid-preflight-argument"), -EINVAL);
    EXPECT(ctl(key, "status", output, sizeof(output)), -ENOENT);
    for (n = 0; n < cycles; ++n) {
        EXPECT(load(key, path, "inspect"), 0); loaded = 1;
        memset(output, 0xa5, sizeof(output));
        EXPECT(ctl(key, "status", output, sizeof(output)), 0);
        if (!memchr(output, 0, sizeof(output)) || !strstr(output, "mode=preflight active=0 backend=none core=pass ") ||
            !strstr(output, "loader_contract=unverified") || !strstr(output, "checks=4114 ")) {
            fprintf(stderr, "FAIL status schema\n"); goto done;
        }
        if (n == 0) printf("module_status %s", output);
        EXPECT(ctl(key, "selftest", output, sizeof(output)), 0);
        EXPECT(ctl(key, "register", output, sizeof(output)), -EOPNOTSUPP);
        EXPECT(ctl(key, "unknown", output, sizeof(output)), -EINVAL);
        output[0] = 'Z';
        EXPECT(ctl(key, "status", output, 1), -ENOSPC);
        if (output[0] != 'Z') { fprintf(stderr, "FAIL short output modified\n"); goto done; }
        EXPECT(ctl(key, "status", NULL, 1024), -EINVAL);
        EXPECT(ctl(key, "status", inaccessible, 1024), -EFAULT);
        EXPECT(unload(key), 0); loaded = 0;
        EXPECT(ctl(key, "status", output, sizeof(output)), -ENOENT);
        printf("cycle=%ld preflight_load_core_status_rejections_unload=PASS\n", n + 1);
    }
    /* No callbacks/references escape this module. Disregarding this artificial
     * veto is safe here, but would be unsafe for an active fault handler. */
    EXPECT(load(key, path, "veto-test"), 0); loaded = 1;
    EXPECT(unload(key), -EBUSY);
    result = ctl(key, "status", output, sizeof(output));
    if (result == -ENOENT) {
        loaded = 0;
        printf("loader_exit_veto=NOT_RETAINED result=-EBUSY module_after=absent activation_gate=FAIL\n");
    } else if (result == -EBUSY) {
        errno = 0;
        EXPECT(norm(syscall(__NR_supercall, key, word(SUPERCALL_KPM_INFO),
                           "urov-lab-check", output, (long)sizeof(output))) > 0 ? 0 : -1, 0);
        if (!strstr(output, "lifecycle=2") || !strstr(output, "state=retained")) {
            fprintf(stderr, "FAIL retained loader state\n"); goto done;
        }
        printf("loader_exit_veto=RETAINED lifecycle=2 business_ctl=BLOCKED\n");
        EXPECT(unload(key), 0); loaded = 0;
    } else if (result == 0) {
        printf("loader_exit_veto=RETAINED other_lifecycle_guarantees=UNVERIFIED\n");
        EXPECT(ctl(key, "allow-exit", output, sizeof(output)), 0);
        EXPECT(unload(key), 0); loaded = 0;
    } else {
        fprintf(stderr, "FAIL unclear veto state result=%ld\n", result); goto done;
    }
    printf("PASS cycles=%ld scope=preflight_only overlay=NOT_IMPLEMENTED\n", cycles);
    rc = 0;
done:
    if (loaded) {
        (void)ctl(key, "allow-exit", output, sizeof(output));
        result = unload(key);
        fprintf(stderr, "cleanup_unload=%ld\n", result);
        if (result) rc = 1;
    }
    if (inaccessible != MAP_FAILED) munmap(inaccessible, 4096);
    for (i = 0; i < (int)sizeof(key); ++i) ((volatile char *)key)[i] = 0;
    return rc;
usage:
    fprintf(stderr, "Usage: %s --module /absolute/urov-lab-check.kpm --key-fd FD [--cycles 1..100]\n", argv[0]);
    goto done;
}
