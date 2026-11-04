/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "urov_detect.h"
#include "../urov_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static struct urov_request query(uint64_t nonce)
{
    struct urov_request q = {0};
    q.size = sizeof(q);
    q.version = UROV_ABI_VERSION;
    q.op = UROV_QUERY;
    q.request_id = nonce;
    return q;
}

static long probe(uint64_t magic, struct urov_request *q)
{
    return syscall(__NR_prctl, (long)UROV_PRCTL_OPTION, (long)magic,
                   (long)UROV_NOTIFY_QUERY, q, (long)sizeof(*q));
}

void ud_probe_control(struct ud_control *out)
{
    const uint64_t mask = UROV_CAP_GPR | UROV_CAP_PAIR | UROV_CAP_RAW_XOM |
                          UROV_CAP_READY | UROV_CAP_RESIDENT | UROV_CAP_PRCTL;
    struct urov_request a = query(UINT64_C(0x2736ae9105b48cd2)), before = a;
    struct urov_request first = {0};
    int saved = errno, native_error;
    long rc;
    memset(out, 0, sizeof(*out));
    out->verdict = UD_UNKNOWN;
    out->scope = UD_SCOPE_UNKNOWN;
    errno = 0;
    rc = probe(UROV_PRCTL_MAGIC ^ 1U, &a);
    native_error = errno;
    /* A wrong magic must reach the native, unknown prctl option. */
    if (rc != -1 || native_error != EINVAL || memcmp(&a, &before, sizeof(a))) {
        out->error = native_error ? native_error : EPROTO;
        goto done;
    }
    for (unsigned i = 0; i < 2; ++i) {
        a = query(before.request_id + i + 1U);
        before = a;
        errno = 0;
        rc = probe(UROV_PRCTL_MAGIC, &a);
        if (rc == -1 && errno == EINVAL && !memcmp(&a, &before, sizeof(a))) {
            if (i == 0) out->verdict = UD_NO_MATCH;
            else out->error = EAGAIN; /* unloaded between the two queries */
            goto done;
        }
        if (rc || a.size != sizeof(a) || a.version != UROV_ABI_VERSION ||
            a.op != UROV_QUERY || a.request_id != before.request_id ||
            (a.caps & mask) != mask || a.state > UROV_ACTIVE ||
            (a.state == UROV_ACTIVE && (a.session != 1 || !a.generation ||
             a.length < 8 || a.length > 32 || (a.length & 7U))) ||
            (a.state == UROV_ACTIVE && (a.offset > UROV_PAGE_BYTES - a.length || a.last_error)) ||
            (a.state == UROV_INACTIVE && (a.session || a.generation || a.length || a.offset ||
             (a.last_error && a.last_error != -EBUSY)))) {
            out->error = rc ? errno : EPROTO;
            goto done;
        }
        if (i && a.caps != out->caps) { out->error = EAGAIN; goto done; }
        out->caps = a.caps;
        if (!i) first = a;
    }
    out->verdict = UD_MATCH;
    if (first.state == a.state && first.session == a.session && first.generation == a.generation &&
        first.offset == a.offset && first.length == a.length && first.last_error == a.last_error) {
        out->scope = a.state == UROV_ACTIVE ? UD_SCOPE_SELF :
                     (a.last_error == -EBUSY ? UD_SCOPE_OTHER : UD_SCOPE_IDLE);
        out->generation = a.generation;
        out->offset = a.offset;
        out->length = a.length;
    } else out->error = EAGAIN;
done:
    errno = saved;
}

static int has_flag(const char *line, const char *flag)
{
    size_t n = strlen(flag);
    for (const char *p = line; *p; ++p) {
        if ((p == line || p[-1] == ' ') && !strncmp(p, flag, n) &&
            (p[n] == ' ' || p[n] == '\n' || p[n] == '\0')) return 1;
    }
    return 0;
}

int ud_mapping_at(const char *proc_file, const void *address, struct ud_mapping *out)
{
    int saved = errno, error = ENOENT, found = 0;
    FILE *f;
    char line[1024];
    size_t consumed = 0;
    memset(out, 0, sizeof(*out));
    out->dontcopy = out->maywrite = out->randomread = -1;
    /* Restrict the interface to read-only process metadata. */
    if (strcmp(proc_file, "/proc/self/maps") && strcmp(proc_file, "/proc/self/smaps")) {
        errno = saved;
        return EINVAL;
    }
    f = fopen(proc_file, "re");
    if (!f) { error = errno; errno = saved; return error; }
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        unsigned long long offset, inode;
        unsigned ma, mi;
        char perms[5];
        consumed += strlen(line);
        if (consumed > 2U * 1024U * 1024U) { error = EOVERFLOW; break; }
        if (sscanf(line, "%lx-%lx %4s %llx %x:%x %llu", &start, &end, perms,
                   &offset, &ma, &mi, &inode) == 7) {
            if (found) break;
            if ((uintptr_t)address >= start && (uintptr_t)address < end) {
                found = 1;
                out->start = start; out->end = end;
                out->offset = offset; out->inode = inode;
                out->dev_major = ma; out->dev_minor = mi;
                out->readable = perms[0] == 'r';
                out->writable = perms[1] == 'w';
                out->executable = perms[2] == 'x';
                out->shared = perms[3] == 's';
                if (!strcmp(proc_file, "/proc/self/maps")) { error = 0; break; }
            }
        } else if (found && !strncmp(line, "VmFlags:", 8)) {
            out->dontcopy = has_flag(line + 8, "dc");
            out->maywrite = has_flag(line + 8, "mw");
            out->randomread = has_flag(line + 8, "rr");
            error = 0;
            break;
        }
    }
    if (ferror(f)) error = EIO;
    fclose(f);
    errno = saved;
    return error;
}

/* Explicit LDRB prevents clang/libc from selecting unsupported SIMD, acquire
 * or cross-page loads from the target. memcpy/memcmp are used ONLY on buffers
 * already copied to our normal stack. */
static void scalar_copy(uint8_t *out, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned value;
        __asm__ volatile("ldrb %w0, [%1]" : "=r"(value) : "r"(p + i) : "memory");
        out[i] = (uint8_t)value;
    }
}

static int file_copy(int fd, off_t offset, uint8_t *out, size_t n)
{
    size_t at = 0;
    for (unsigned i = 0; i < 4 && at < n; ++i) {
        ssize_t got = pread(fd, out + at, n - at, offset + (off_t)at);
        if (got > 0) at += (size_t)got;
        else if (got == 0 || errno != EINTR) return got < 0 ? errno : EIO;
    }
    return at == n ? 0 : EINTR;
}

static int same_mapping(const struct ud_mapping *a, const struct ud_mapping *b)
{
    return a->start == b->start && a->end == b->end && a->offset == b->offset &&
        a->inode == b->inode && a->dev_major == b->dev_major &&
        a->dev_minor == b->dev_minor && a->readable == b->readable &&
        a->writable == b->writable && a->executable == b->executable;
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

void ud_check_views(const void *address, size_t length, int backing_fd,
                    off_t backing_offset, struct ud_views *out)
{
    struct ud_mapping map, after;
    struct stat st, st_after;
    uint8_t direct[UD_MAX_BYTES], direct_after[UD_MAX_BYTES];
    uint8_t disk[UD_MAX_BYTES], disk_after[UD_MAX_BYTES];
    uint8_t first_direct[UD_MAX_BYTES], first_disk[UD_MAX_BYTES];
    int saved = errno, error;
    long page_size = sysconf(_SC_PAGESIZE);
    memset(out, 0, sizeof(*out));
    out->file_diff = UD_UNKNOWN;
    out->first_file_diff = SIZE_MAX;
    if (!address || !length || length > UD_MAX_BYTES || page_size <= 0 ||
        length > (size_t)page_size - (uintptr_t)address % (size_t)page_size) {
        out->error_file = EINVAL;
        goto done;
    }
    error = ud_mapping_at("/proc/self/maps", address, &map);
    if (error || !map.readable || map.writable || !map.executable ||
        length > map.end - (uintptr_t)address) {
        out->error_file = error ? error : EACCES;
        goto done;
    }
    if (backing_fd < 0 || backing_offset < 0) { out->error_file = EBADF; goto done; }
    else if (fstat(backing_fd, &st)) { out->error_file = errno; goto done; }
    else if (!S_ISREG(st.st_mode) || map.inode != (uint64_t)st.st_ino ||
             map.dev_major != major(st.st_dev) || map.dev_minor != minor(st.st_dev) ||
             map.offset > INT64_MAX - ((uintptr_t)address - map.start) ||
             (uint64_t)backing_offset != map.offset + (uintptr_t)address - map.start ||
             st.st_size < backing_offset || (uint64_t)(st.st_size - backing_offset) < length)
        { out->error_file = ESTALE; goto done; }
    for (unsigned i = 0; i < UD_REPEATS; ++i) {
        /* The syscall sees only our normal stack destination and a retained
         * regular-file fd. Never pass the protected address to kernel uaccess,
         * /proc/self/mem, process_vm_readv, write or writev. */
        error = file_copy(backing_fd, backing_offset, disk, length);
        if (error) { out->error_file = error; goto done; }
        scalar_copy(direct, address, length);
        error = file_copy(backing_fd, backing_offset, disk_after, length);
        if (error) { out->error_file = error; goto done; }
        scalar_copy(direct_after, address, length);
        if (memcmp(direct, direct_after, length) || memcmp(disk, disk_after, length) ||
            (i && (memcmp(direct, first_direct, length) ||
                   memcmp(disk, first_disk, length)))) {
            out->error_file = EAGAIN;
            goto done;
        }
        if (!i) {
            memcpy(first_direct, direct, length);
            memcpy(first_disk, disk, length);
        }
        ++out->completed;
    }
    error = ud_mapping_at("/proc/self/maps", address, &after);
    if (error || !same_mapping(&map, &after)) {
        out->error_file = error ? error : EAGAIN;
        goto done;
    }
    if (fstat(backing_fd, &st_after)) { out->error_file = errno; goto done; }
    if (!same_file(&st, &st_after)) { out->error_file = EAGAIN; goto done; }
    out->file_diff = memcmp(first_direct, first_disk, length) ? UD_MATCH : UD_NO_MATCH;
    for (size_t i = 0; i < length; ++i) {
        if (out->file_diff != UD_UNKNOWN && first_direct[i] != first_disk[i] &&
            out->first_file_diff == SIZE_MAX) out->first_file_diff = i;
    }
done:
    errno = saved;
}
