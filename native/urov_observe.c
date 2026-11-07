/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "urov_observe.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

struct sample_identity {
    struct ud_mapping mapping;
    struct stat file;
};

static int identity(const void *address, size_t size, int fd, off_t offset,
                    struct sample_identity *out)
{
    struct ud_mapping *m = &out->mapping;
    struct stat *s = &out->file;
    long ps = sysconf(_SC_PAGESIZE);
    int error;
    if (!address || !size || ps <= 0 || offset < 0 ||
        size > (size_t)ps - (uintptr_t)address % (size_t)ps) return EINVAL;
    error = ud_mapping_at("/proc/self/maps", address, m);
    if (error) return error;
    if (!m->readable || m->writable || !m->executable ||
        size > m->end - (uintptr_t)address) return EACCES;
    if (fstat(fd, s)) return errno;
    if (!S_ISREG(s->st_mode) || m->inode != (uint64_t)s->st_ino ||
        m->dev_major != major(s->st_dev) || m->dev_minor != minor(s->st_dev) ||
        m->offset > INT64_MAX - ((uintptr_t)address - m->start) ||
        (uint64_t)offset != m->offset + (uintptr_t)address - m->start ||
        s->st_size < offset || (uint64_t)(s->st_size - offset) < size) return ESTALE;
    return 0;
}

static int unchanged(const struct sample_identity *a, const struct sample_identity *b)
{
    const struct ud_mapping *x = &a->mapping, *y = &b->mapping;
    const struct stat *s = &a->file, *t = &b->file;
    return x->start == y->start && x->end == y->end && x->offset == y->offset &&
        x->inode == y->inode && x->dev_major == y->dev_major && x->dev_minor == y->dev_minor &&
        x->readable == y->readable && x->writable == y->writable &&
        x->executable == y->executable && x->shared == y->shared &&
        s->st_dev == t->st_dev && s->st_ino == t->st_ino && s->st_size == t->st_size &&
        s->st_mtim.tv_sec == t->st_mtim.tv_sec && s->st_mtim.tv_nsec == t->st_mtim.tv_nsec &&
        s->st_ctim.tv_sec == t->st_ctim.tv_sec && s->st_ctim.tv_nsec == t->st_ctim.tv_nsec;
}

static uint64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

/* No calls, barriers, syscalls, retry loops or unrelated memory accesses can
 * appear inside this 12-byte window. ERET clears the local exclusive monitor.
 * Intervening loads may also clear it on some implementations: calibrate using
 * exactly this instruction sequence on the same backing-file byte.
 */
__attribute__((noinline))
static unsigned exclusive_once(const void *address, uint64_t *scratch, unsigned *byte)
{
    uint64_t old;
    unsigned value, failed;
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "stxr %w2, %0, [%3]\n"
                     : "=&r"(old), "=&r"(value), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = value;
    return failed;
}

__attribute__((noinline))
static unsigned spaced_exclusive_once(const void *address, uint64_t *scratch, unsigned *byte)
{
    uint64_t old;
    unsigned value, failed;
    /* The NOP distinguishes this from the original adjacent-only bridge. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "nop\n"
                     "ldrb %w1, [%4]\n"
                     "stxr %w2, %0, [%3]\n"
                     : "=&r"(old), "=&r"(value), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = value;
    return failed;
}

static const uint64_t scratch_initial = UINT64_C(0x5a5a5a5aa5a5a5a5);

enum unreserved_branch {
    UNRESERVED_TO_LOAD,     /* direct branch to the LDRB */
    UNRESERVED_TO_NOP,      /* direct branch to a NOP in the LDXR gap */
    UNRESERVED_INDIRECT,    /* ADR + BR to the LDRB, target left in x9 */
};

/* Keep an unreachable LDXR in the bridge's look-behind and skip it with the
 * requested control-flow shape.  The load is the branch target (or the NOP
 * before it for the spaced shape), so the handler can only retire the STXR
 * if it really observed an LDXR. */
__attribute__((noinline))
static int unreserved_store_once(const void *address, uint64_t *scratch,
                                 uint64_t store_value, enum unreserved_branch branch,
                                 unsigned *byte)
{
    uint64_t value = store_value;
    unsigned status;

    *scratch = scratch_initial;
    if (branch == UNRESERVED_TO_NOP) {
        __asm__ volatile("clrex\n"
                         "b 1f\n"
                         "ldxr %0, [%3]\n"
                         "1: nop\n"
                         "ldrb %w2, [%4]\n"
                         "stxr %w1, %0, [%3]\n"
                         : "+&r"(value), "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address) : "memory");
    } else if (branch == UNRESERVED_INDIRECT) {
        /* The direct-branch scan cannot resolve this; the target address is
         * still in x9 when the LDRB faults. */
        __asm__ volatile("clrex\n"
                         "adr x9, 1f\n"
                         "br x9\n"
                         "ldxr %0, [%3]\n"
                         "1: ldrb %w2, [%4]\n"
                         "stxr %w1, %0, [%3]\n"
                         : "+&r"(value), "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address) : "x9", "memory");
    } else {
        __asm__ volatile("clrex\n"
                         "b 1f\n"
                         "ldxr %0, [%3]\n"
                         "1: ldrb %w2, [%4]\n"
                         "stxr %w1, %0, [%3]\n"
                         : "+&r"(value), "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address) : "memory");
    }
    uint64_t observed = *scratch;
    if (status == 1 && observed == scratch_initial) return 0;
    if (status == 0 && observed == store_value) return 1;
    return -1;
}

static void observe_unreserved_store(const void *address, const void *reference,
                                     int backing_fd, off_t offset, uint64_t store_value,
                                     enum unreserved_branch branch,
                                     struct ud_store_observation *out)
{
    struct sample_identity target, control, after;
    uint64_t scratch;
    uint8_t file_byte;
    unsigned target_byte = 0;
    int saved = errno;
    uint64_t begin = now_ns();

    memset(out, 0, sizeof(*out));
    out->verdict = UD_UNKNOWN;
    if (address == reference) { out->error = EINVAL; goto done; }
    out->error = identity(address, 1, backing_fd, offset, &target);
    if (out->error) goto done;
    out->error = identity(reference, 1, backing_fd, offset, &control);
    if (out->error) goto done;
    ssize_t got = pread(backing_fd, &file_byte, 1, offset);
    if (got != 1) { out->error = got < 0 ? errno : EIO; goto done; }

    for (unsigned i = 0; i < UD_STORE_TRIALS; ++i) {
        unsigned a, b, c;
        int before = unreserved_store_once(reference, &scratch, store_value, branch, &a);
        int tested = unreserved_store_once(address, &scratch, store_value, branch, &b);
        int after_control = unreserved_store_once(reference, &scratch, store_value, branch, &c);
        if (before != 0 || after_control != 0 || tested < 0 ||
            a != file_byte || c != file_byte || (i && b != target_byte) ||
            (store_value != scratch_initial && b != file_byte)) {
            out->error = EAGAIN;
            goto done;
        }
        target_byte = b;
        ++out->completed;
        out->unexpected_stores += tested == 1;
    }

    out->error = identity(address, 1, backing_fd, offset, &after);
    if (out->error) goto done;
    if (!unchanged(&target, &after)) { out->error = EAGAIN; goto done; }
    out->error = identity(reference, 1, backing_fd, offset, &after);
    if (out->error) goto done;
    if (!unchanged(&control, &after)) { out->error = EAGAIN; goto done; }
    if (out->unexpected_stores == UD_STORE_TRIALS) out->verdict = UD_MATCH;
    else if (out->unexpected_stores == 0) out->verdict = UD_NO_MATCH;
    else out->error = EAGAIN;
done:
    out->elapsed_ns = now_ns() - begin;
    errno = saved;
}

void ud_observe_unreserved_store(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset,
                             UINT64_C(0xc3175ed9246ab08f), UNRESERVED_TO_LOAD, out);
}

void ud_observe_unreserved_status(const void *address, const void *reference,
                                  int backing_fd, off_t offset,
                                  struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_TO_LOAD, out);
}

void ud_observe_unreserved_nop_status(const void *address, const void *reference,
                                      int backing_fd, off_t offset,
                                      struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_TO_NOP, out);
}

void ud_observe_unreserved_indirect_status(const void *address, const void *reference,
                                           int backing_fd, off_t offset,
                                           struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_INDIRECT, out);
}

static uint64_t scalar_word(const void *address)
{
    uint64_t value;
    __asm__ volatile("ldr %0, [%1]" : "=r"(value) : "r"(address) : "memory");
    return value;
}

static int check_canary(const void *address, const void *reference, int fd, off_t offset)
{
    /* Little-endian encodings of BTI C and RET x30. */
    const uint64_t canary = UINT64_C(0xd65f03c0d503245f);
    uint64_t file;
    ssize_t got = pread(fd, &file, sizeof(file), offset);
    if (got != (ssize_t)sizeof(file)) return got < 0 ? errno : EIO;
    if (file != canary || scalar_word(address) != canary ||
        scalar_word(reference) != canary) return EPROTO;
    return 0;
}

__attribute__((noinline))
static unsigned execution_once(const void *address, uint64_t *scratch, unsigned *byte)
{
    uint64_t old;
    unsigned failed;
    /* The only callable code in this window is the verified two-word canary.
     * BTI JC also accepts a branch type left over by an emulated return. */
    __asm__ volatile("ldxr %0, [%2]\n"
                     "blr %3\n"
                     "hint #38\n"
                     "stxr %w1, %0, [%2]\n"
                     : "=&r"(old), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "x30", "memory");
    *byte = 0;
    return failed;
}

enum reservation_probe { READ_ADJACENT, READ_SPACED, EXECUTE_CANARY };

static void observe_reservation(const void *address, const void *reference,
                                int backing_fd, off_t offset, enum reservation_probe probe,
                                struct ud_exclusive_observation *out)
{
    struct sample_identity target, control, after;
    int execute = probe == EXECUTE_CANARY;
    size_t size = execute ? sizeof(uint64_t) : 1U;
    unsigned (*sample)(const void *, uint64_t *, unsigned *) = exclusive_once;
    if (execute) sample = execution_once;
    if (probe == READ_SPACED) sample = spaced_exclusive_once;
    /* Keep the scratch away from normal stack writes and compiler spills.
     * The caller does not share this stack storage with other threads.
     */
    _Alignas(2048) uint64_t scratch[256] = {0};
    int saved = errno, error;
    long ps = sysconf(_SC_PAGESIZE);
    uint64_t begin = now_ns();
    unsigned baseline_byte = 0;
    memset(out, 0, sizeof(*out));
    out->reservation_loss = UD_UNKNOWN;
    error = identity(address, size, backing_fd, offset, &target);
    if (error) { out->error = error; goto done; }
    error = identity(reference, size, backing_fd, offset, &control);
    if (error) { out->error = error; goto done; }
    if (ps <= 0 || (uintptr_t)address / (uintptr_t)ps ==
                   (uintptr_t)reference / (uintptr_t)ps ||
        (execute && (((uintptr_t)address | (uintptr_t)reference) & 7U))) {
        out->error = EINVAL; goto done;
    }
    if (execute) {
        error = check_canary(address, reference, backing_fd, offset);
        if (error) { out->error = error; goto done; }
    }
    /* Warm both addresses and the exclusive code, outside the measured window. */
    for (unsigned i = 0; i < 8; ++i) {
        unsigned a, b;
        (void)sample(reference, scratch, &a);
        (void)sample(address, scratch, &b);
        if (a != b || (i && a != baseline_byte)) { out->error = EAGAIN; goto done; }
        baseline_byte = a;
    }
    for (unsigned epoch = 0; epoch < UD_OBSERVE_EPOCHS; ++epoch) {
        unsigned accepted = 0, failures = 0;
        for (unsigned attempt = 0; attempt < UD_OBSERVE_TRIALS * 2U &&
                                   accepted < UD_OBSERVE_TRIALS; ++attempt) {
            unsigned a, b, c;
            unsigned before = sample(reference, scratch, &a);
            unsigned tested = sample(address, scratch, &b);
            unsigned after_control = sample(reference, scratch, &c);
            if (a != baseline_byte || b != a || c != a) { out->error = EAGAIN; goto done; }
            if (before || after_control) { ++out->control_failed; continue; }
            ++accepted;
            failures += !!tested;
        }
        out->accepted += accepted;
        out->target_failed += failures;
        if (accepted != UD_OBSERVE_TRIALS) { out->error = EAGAIN; goto done; }
        /* Any intermediate pattern is uncertainty, rather than a threshold. */
        if (failures != 0 && failures != UD_OBSERVE_TRIALS) { out->error = EAGAIN; goto done; }
        ++out->epochs;
    }
    if (out->control_failed > 8U) { out->error = EAGAIN; goto done; }
    error = identity(address, size, backing_fd, offset, &after);
    if (error || !unchanged(&target, &after)) { out->error = error ? error : EAGAIN; goto done; }
    error = identity(reference, size, backing_fd, offset, &after);
    if (error || !unchanged(&control, &after)) { out->error = error ? error : EAGAIN; goto done; }
    if (execute) {
        error = check_canary(address, reference, backing_fd, offset);
        if (error) { out->error = error; goto done; }
    }
    if (out->target_failed == UD_OBSERVE_EPOCHS * UD_OBSERVE_TRIALS)
        out->reservation_loss = UD_MATCH;
    else if (out->target_failed == 0) out->reservation_loss = UD_NO_MATCH;
    else out->error = EAGAIN;
done:
    out->elapsed_ns = now_ns() - begin;
    errno = saved;
}

void ud_observe_exclusive(const void *address, const void *reference,
                          int backing_fd, off_t offset,
                          struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_ADJACENT, out);
}

void ud_observe_spaced_exclusive(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_SPACED, out);
}

void ud_observe_execution(const void *address, const void *reference,
                          int backing_fd, off_t offset,
                          struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, EXECUTE_CANARY, out);
}

void ud_observe_reader(const void *address, int backing_fd, off_t offset,
                       ud_plain_reader reader, struct ud_reader_observation *out)
{
    struct sample_identity before, after;
    int saved = errno, error;
    memset(out, 0, sizeof(*out));
    out->reader_diff = UD_UNKNOWN;
    if (!reader || ((uintptr_t)address & 7U)) { out->error = EINVAL; goto done; }
    error = identity(address, 8, backing_fd, offset, &before);
    if (error) { out->error = error; goto done; }
    for (unsigned i = 0; i < UD_REPEATS; ++i) {
        uint64_t file_a, file_b, direct_a, direct_b, site_a, site_b;
        ssize_t got = pread(backing_fd, &file_a, 8, offset);
        if (got != 8) { out->error = got < 0 ? errno : EIO; goto done; }
        direct_a = scalar_word(address);
        site_a = reader(address);
        direct_b = scalar_word(address);
        site_b = reader(address);
        got = pread(backing_fd, &file_b, 8, offset);
        if (got != 8) { out->error = got < 0 ? errno : EIO; goto done; }
        if (file_a != file_b || direct_a != direct_b || site_a != site_b ||
            (i && (out->file_value != file_a || out->direct_value != direct_a ||
                   out->reader_value != site_a))) { out->error = EAGAIN; goto done; }
        out->file_value = file_a;
        out->direct_value = direct_a;
        out->reader_value = site_a;
        ++out->completed;
    }
    error = identity(address, 8, backing_fd, offset, &after);
    if (error || !unchanged(&before, &after)) { out->error = error ? error : EAGAIN; goto done; }
    if (out->direct_value != out->file_value) { out->error = EPROTO; goto done; }
    out->reader_diff = out->reader_value != out->direct_value ? UD_MATCH : UD_NO_MATCH;
done:
    errno = saved;
}
