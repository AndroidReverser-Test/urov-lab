/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "control.h"
#include "../test_config.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
static uint64_t milliseconds(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
/* KPM control uses kpatch's authenticated supercall ABI directly. Only module
 * loading needs a root child to exec the device's kpatch and open its file.
 * In particular, never fork the owner mm while an overlay/probe is active.
 * The tested Android process keeps its original credentials. ABI from
 * KernelPatch user/supercall.h and patch/include/uapi/scdefs.h (>=0.10.5).
 * No shell expansion and no malloc/stdio in the child after fork. */
int test_kpatch(const char *key, const char *operation, const char *argument, char *out, size_t capacity)
{
    if (!key || !*key || strlen(key) >= 64 || capacity < 2) return -EINVAL;
    out[0] = 0;
    const long version = (0x0a05L << 32) | (0x1158L << 16);
    if (!strcmp(operation, "ctl0")) {
        long result = syscall(45, key, version | 0x1022, "urov-z", argument, out, (long)capacity);
        out[capacity - 1] = 0;
        return result < 0 ? -errno : 0;
    }
    if (!strcmp(operation, "num")) {
        long result = syscall(45, key, version | 0x1030);
        if (result < 0) return -errno;
        snprintf(out, capacity, "%ld", result);
        return 0;
    }
    if (!strcmp(operation, "list")) {
        long result = syscall(45, key, version | 0x1031, out, (int)capacity);
        out[capacity - 1] = 0;
        return result < 0 ? -errno : 0;
    }
    char *argv[9] = {"/data/local/tmp/kpatch", (char *)key, "kpm", (char *)operation, NULL};
    if (!strcmp(operation, "load")) { argv[4] = (char *)argument; argv[5] = "key=" UROV_TEST_KEY; }
    else return -EINVAL;
    struct { uint32_t uid, to_uid; char scontext[96]; } profile = {0};
    profile.uid = getuid();
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC)) return -errno;
    pid_t child = fork();
    if (child < 0) { int rc = -errno; close(pipes[0]); close(pipes[1]); return rc; }
    if (!child) {
        close(pipes[0]);
        if (dup2(pipes[1], STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0) _exit(125);
        close(pipes[1]);
        long command = (0x0a05L << 32) | (0x1158L << 16) | 0x1010;
        if (syscall(45, key, command, &profile) != 0) _exit(126);
        execve(argv[0], argv, environ);
        _exit(127);
    }
    close(pipes[1]);
    fcntl(pipes[0], F_SETFL, O_NONBLOCK);
    size_t used = 0;
    int status = 0, done = 0, rc = 0;
    uint64_t deadline = milliseconds() + 60000;
    while (!done) {
        struct pollfd p = {pipes[0], POLLIN, 0};
        (void)poll(&p, 1, 50);
        char buffer[1024];
        ssize_t n;
        while ((n = read(pipes[0], buffer, sizeof(buffer))) > 0) {
            size_t count = (size_t)n < capacity - used - 1 ? (size_t)n : capacity - used - 1;
            memcpy(out + used, buffer, count); used += count;
            if (count != (size_t)n) rc = -ENOSPC;
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) done = 1;
        else if (waited < 0 && errno != EINTR) { rc = -errno; break; }
        if (!done && milliseconds() >= deadline) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
            rc = -ETIMEDOUT;
            break;
        }
    }
    char buffer[1024];
    ssize_t n;
    while ((n = read(pipes[0], buffer, sizeof(buffer))) > 0) {
        size_t count = (size_t)n < capacity - used - 1 ? (size_t)n : capacity - used - 1;
        memcpy(out + used, buffer, count); used += count;
        if (count != (size_t)n) rc = -ENOSPC;
    }
    out[used] = 0;
    close(pipes[0]);
    return rc ? rc : WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}
