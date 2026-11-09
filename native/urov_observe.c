/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "urov_observe.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

struct sample_identity {
    struct ud_mapping mapping;
    struct stat file;
};

static int identity_with_exec(const void *address, size_t size, int fd, off_t offset,
                              bool executable, struct sample_identity *out)
{
    struct ud_mapping *m = &out->mapping;
    struct stat *s = &out->file;
    long ps = sysconf(_SC_PAGESIZE);
    int error;
    if (!address || !size || ps <= 0 || offset < 0 ||
        size > (size_t)ps - (uintptr_t)address % (size_t)ps) return EINVAL;
    error = ud_mapping_at("/proc/self/maps", address, m);
    if (error) return error;
    if (!m->readable || m->writable || !!m->executable != executable ||
        size > m->end - (uintptr_t)address) return EACCES;
    if (fstat(fd, s)) return errno;
    if (!S_ISREG(s->st_mode) || m->inode != (uint64_t)s->st_ino ||
        m->dev_major != major(s->st_dev) || m->dev_minor != minor(s->st_dev) ||
        m->offset > INT64_MAX - ((uintptr_t)address - m->start) ||
        (uint64_t)offset != m->offset + (uintptr_t)address - m->start ||
        s->st_size < offset || (uint64_t)(s->st_size - offset) < size) return ESTALE;
    return 0;
}

static int identity(const void *address, size_t size, int fd, off_t offset,
                    struct sample_identity *out)
{
    return identity_with_exec(address, size, fd, offset, true, out);
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

static int read_live(const uint8_t *address, uint8_t *bytes, size_t size)
{
    /* A count above the legacy 64-entry module cap, with zero-length tail
     * entries so the transfer itself is still exactly size bytes. */
    struct iovec local[65] = {{ .iov_base = bytes, .iov_len = size }};
    struct iovec remote = { .iov_base = (void *)address, .iov_len = size };
    ssize_t got = process_vm_readv(getpid(), local, sizeof(local) / sizeof(local[0]),
                                   &remote, 1, 0);

    if (got < 0) return errno;
    return (size_t)got == size ? 0 : EIO;
}

void ud_observe_live(const uint8_t *address, size_t size, int backing_fd, off_t offset,
                     ud_bytes_reader reader, struct ud_live_observation *out)
{
    struct sample_identity before, after;
    uint8_t user_again[UD_LIVE_MAX_BYTES], kernel_again[UD_LIVE_MAX_BYTES];
    int saved = errno;
    uint64_t begin = now_ns();

    memset(out, 0, sizeof(*out));
    out->verdict = UD_UNKNOWN;
    if (!reader || size > UD_LIVE_MAX_BYTES) {
        out->error = EINVAL;
        goto done;
    }
    out->error = identity(address, size, backing_fd, offset, &before);
    if (out->error) goto done;
    out->error = read_live(address, out->kernel_bytes, size);
    if (out->error) goto done;
    reader(out->user_bytes, address, size);
    reader(user_again, address, size);
    out->error = read_live(address, kernel_again, size);
    if (out->error) goto done;
    out->error = identity(address, size, backing_fd, offset, &after);
    if (out->error) goto done;
    if (!unchanged(&before, &after) || memcmp(out->user_bytes, user_again, size) ||
        memcmp(out->kernel_bytes, kernel_again, size)) {
        out->error = EAGAIN;
        goto done;
    }
    out->verdict = memcmp(out->user_bytes, out->kernel_bytes, size) ? UD_MATCH : UD_NO_MATCH;
done:
    out->elapsed_ns = now_ns() - begin;
    errno = saved;
}

static int read_redirected(const uint8_t *address, uint8_t *live, uint8_t *post, size_t size)
{
    void *redirect = post;
    struct iovec local[2] = {
        { .iov_base = &local[1].iov_base, .iov_len = sizeof(redirect) },
        { .iov_base = live, .iov_len = size },
    };
    struct iovec remote[2] = {
        { .iov_base = &redirect, .iov_len = sizeof(redirect) },
        { .iov_base = (void *)address, .iov_len = size },
    };
    /* The kernel uses the imported local[1] and fills live. The 2.16.0
     * after-hook rereads local[1] from userspace and fills post instead. */
    ssize_t got = process_vm_readv(getpid(), local, 2, remote, 2, 0);
    if (got != (ssize_t)(sizeof(redirect) + size)) return got < 0 ? errno : EIO;
    return local[1].iov_base == redirect ? 0 : EPROTO;
}

void ud_observe_readv_redirect(const uint8_t *address, const uint8_t *reference, size_t size,
                               int backing_fd, off_t offset, ud_bytes_reader reader,
                               struct ud_readv_observation *out)
{
    struct sample_identity target, control, after;
    uint8_t expected[UD_LIVE_MAX_BYTES], marker[UD_LIVE_MAX_BYTES];
    uint8_t live[UD_LIVE_MAX_BYTES], post[UD_LIVE_MAX_BYTES];
    uint8_t user[UD_LIVE_MAX_BYTES];
    int saved = errno;
    bool untouched = true, stable_post = true;
    uint64_t begin = now_ns();

    memset(out, 0, sizeof(*out));
    out->reader_diff = out->post_copy = UD_UNKNOWN;
    if (!reader || size > UD_LIVE_MAX_BYTES) { out->error = EINVAL; goto done; }
    out->error = identity(address, size, backing_fd, offset, &target);
    if (out->error) goto done;
    out->error = identity_with_exec(reference, size, backing_fd, offset, false, &control);
    if (out->error) goto done;
    ssize_t got = pread(backing_fd, expected, size, offset);
    if (got != (ssize_t)size) { out->error = got < 0 ? errno : EIO; goto done; }

    for (unsigned i = 0; i < UD_REPEATS; ++i) {
        memset(marker, (i & 1U) ? 0xa5 : 0x5a, size);
        memcpy(post, marker, size);
        out->error = read_redirected(reference, live, post, size);
        if (out->error) goto done;
        if (memcmp(expected, live, size) || memcmp(post, marker, size)) {
            out->error = ESTALE;
            goto done;
        }
        reader(user, address, size);
        out->error = read_redirected(address, live, post, size);
        if (out->error) goto done;
        if (i && (memcmp(user, out->user_bytes, size) || memcmp(live, out->live_bytes, size))) {
            out->error = EAGAIN;
            goto done;
        }
        untouched &= !memcmp(post, marker, size);
        if (i) {
            stable_post &= !memcmp(post, out->post_bytes, size);
        } else {
            memcpy(out->user_bytes, user, size);
            memcpy(out->live_bytes, live, size);
            memcpy(out->post_bytes, post, size);
        }
    }
    if (!untouched && !stable_post) { out->error = EAGAIN; goto done; }
    out->error = identity(address, size, backing_fd, offset, &after);
    if (out->error) goto done;
    if (!unchanged(&target, &after)) { out->error = EAGAIN; goto done; }
    out->error = identity_with_exec(reference, size, backing_fd, offset, false, &after);
    if (out->error) goto done;
    if (!unchanged(&control, &after)) { out->error = EAGAIN; goto done; }
    out->post_copy = untouched ? UD_NO_MATCH : UD_MATCH;
    out->reader_diff = memcmp(out->user_bytes, out->live_bytes, size) ? UD_MATCH : UD_NO_MATCH;
done:
    out->elapsed_ns = now_ns() - begin;
    errno = saved;
}

/* No calls, barriers, syscalls, retry loops or unrelated memory accesses can
 * appear inside this 12-byte window. ERET clears the local exclusive monitor.
 * Intervening loads may also clear it on some implementations: calibrate using
 * exactly this instruction sequence on the same backing-file byte.
 */
__attribute__((noinline))
static unsigned exclusive_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
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
static unsigned spaced_exclusive_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
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

__attribute__((noinline))
static unsigned post_load_nop_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned value, failed;
    /* Y 2.11.0 requires STXR at the faulting PC + 4. Keep the NOP after
     * LDRB, where the bridge does not look past it. Both exclusives use only
     * scratch; LDRB is the sole access to the sampled address. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "nop\n"
                     "stxr %w2, %0, [%3]\n"
                     : "=&r"(old), "=&r"(value), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = value;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_alu_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
    uint64_t value;
    unsigned sample, failed;
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "add %0, %0, #1\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(value), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned pre_load_alu_once(const void *address, uint64_t *scratch, unsigned *byte,
                                  uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned sample, failed;
    /* The 2.20 lookback accepts only NOPs between LDXR and the fault. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "eor %0, %0, #1\n"
                     "ldrb %w1, [%4]\n"
                     "eor %0, %0, #1\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_fp_once(const void *address, uint64_t *scratch, unsigned *byte,
                                   uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned sample, failed;
    /* FMOV transfers bits unchanged and is outside the 2.20 window model. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "fmov d0, %0\n"
                     "fmov %0, d0\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "v0", "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned pre_load_gpr_once(const void *address, uint64_t *scratch, unsigned *byte,
                                  uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned sample, failed;
    /* The 2.21 lookback rejects writes to GPRs other than the LDXR destination. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "mov x9, %0\n"
                     "ldrb %w1, [%4]\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "x9", "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_simd_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    uint64_t old;
    unsigned sample, failed, v0_low;
    /* SIMD EOR is outside the 2.21 window model.  V0 starts at 0xff so the
     * post-sequence lane read also proves that a model completing the STXR
     * commits the same architectural FPSIMD result as the native instruction. */
    __asm__ volatile("movi v0.16b, #0xff\n"
                     "ldxr %0, [%4]\n"
                     "ldrb %w1, [%5]\n"
                     "eor v0.16b, v0.16b, v0.16b\n"
                     "stxr %w2, %0, [%4]\n"
                     "umov %w3, v0.b[0]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed), "=&r"(v0_low)
                     : "r"(scratch), "r"(address) : "v0", "memory");
    *byte = sample;
    *aux = v0_low;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_fparith_once(const void *address, uint64_t *scratch, unsigned *byte,
                                       uint64_t *aux)
{
    (void)aux;
    uint64_t old, other = 0;
    unsigned sample, failed;
    /* Scalar FP arithmetic is outside the byte-level window model, and the
     * local BL/RET forces the native replay to follow control flow.  The
     * operand and result are irrelevant to the reservation probe. */
    __asm__ volatile("movi v0.16b, #0\n"
                     "ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "ldrb w10, [%4, #1]\n"
                     "str xzr, [%5]\n"
                     "mrs x10, cntvct_el0\n"
                     "prfm pldl1keep, [%4]\n"
                     "dmb ish\n"
                     "isb\n"
                     "bl 1f\n"
                     "stxr %w2, %0, [%3]\n"
                     "b 2f\n"
                     "1: fadd d0, d0, d0\n"
                     "ret\n"
                     "2:\n"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address), "r"(&other)
                     : "v0", "x10", "x30", "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_call_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned sample, failed;
    /* Only the local RET executes in the call. No callee reads or writes data. */
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "bl 1f\n"
                     "stxr %w2, %0, [%3]\n"
                     "b 2f\n"
                     "1: ret\n"
                     "2:\n"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "x30", "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_permute_once(const void *address, uint64_t *scratch, unsigned *byte,
                                       uint64_t *aux)
{
    (void)aux;
    uint64_t old;
    unsigned sample, failed;
    /* REV64 uses a different encoding class from the modeled three-same SIMD. */
    __asm__ volatile("movi v0.16b, #0\n"
                     "ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "rev64 v0.16b, v0.16b\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "v0", "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned post_load_csel_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    uint64_t old;
    unsigned sample, failed;
    /* Either arm of CSEL preserves the value. UROV-Y 2.19's LL/SC bridge
     * declines flag-reading instructions, leaving STXR to the hardware. */
    (void)aux;
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "csel %0, %0, %0, eq\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = sample;
    return failed;
}

/* A plain LDR in the gap. The loaded word is what the STXR stores, so the
 * recorded scratch value proves the load read the address the app named, at the
 * width the app used. */
__attribute__((noinline))
static unsigned post_load_load_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    uint64_t old, loaded;
    unsigned sample, failed;

    aux[0] = UINT64_C(0x53495752414c4c44);
    __asm__ volatile("ldxr %0, [%4]\n"
                     "ldrb %w1, [%5]\n"
                     "ldr %2, [%6]\n"
                     "stxr %w3, %2, [%4]"
                     : "=&r"(old), "=&r"(sample), "=&r"(loaded), "=&r"(failed)
                     : "r"(scratch), "r"(address), "r"(aux) : "memory");
    *byte = sample;
    return failed;
}

/* A plain STR in the gap. The private word receives the sampled byte, so the
 * observer can tell whether the window's store actually ran. */
__attribute__((noinline))
static unsigned post_load_store_once(const void *address, uint64_t *scratch, unsigned *byte,
                                     uint64_t *aux)
{
    uint64_t old;
    unsigned sample, failed;

    uint64_t value;

    aux[0] = UINT64_C(0x1230);
    __asm__ volatile("ldxr %0, [%4]\n"
                     "ldrb %w1, [%5]\n"
                     "ldr %2, [%6]\n"
                     "orr %2, %2, #1\n"
                     "str %2, [%6]\n"
                     "stxr %w3, %0, [%4]"
                     : "=&r"(old), "=&r"(sample), "=&r"(value), "=&r"(failed)
                     : "r"(scratch), "r"(address), "r"(aux) : "memory");
    *byte = sample;
    return failed;
}

/* A conditional branch in the gap, taken from the sampled byte. Both runs read
 * the same byte, so both must reach the same value. */
__attribute__((noinline))
static unsigned post_load_branch_once(const void *address, uint64_t *scratch, unsigned *byte,
                                      uint64_t *aux)
{
    uint64_t old;
    unsigned sample, failed;

    (void)aux;
    __asm__ volatile("ldxr %0, [%3]\n"
                     "ldrb %w1, [%4]\n"
                     "cbnz %w1, 1f\n"
                     "orr %0, %0, #1\n"
                     "1:\n"
                     "stxr %w2, %0, [%3]"
                     : "=&r"(old), "=&r"(sample), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = sample;
    return failed;
}

/* A second LDXR in the gap re-establishes the reservation on the same word, so
 * the STXR still succeeds natively. */
__attribute__((noinline))
static unsigned post_load_xload_once(const void *address, uint64_t *scratch, unsigned *byte,
                                     uint64_t *aux)
{
    uint64_t old, again;
    unsigned sample, failed;

    (void)aux;
    __asm__ volatile("ldxr %0, [%4]\n"
                     "ldrb %w1, [%5]\n"
                     "ldxr %2, [%4]\n"
                     "stxr %w3, %0, [%4]"
                     : "=&r"(old), "=&r"(sample), "=&r"(again), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = sample;
    return failed;
}

__attribute__((noinline))
static unsigned zero_exclusive_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
    unsigned value, failed;
    __asm__ volatile("ldxr xzr, [%2]\n"
                     "ldrb %w0, [%3]\n"
                     "stxr %w1, xzr, [%2]\n"
                     : "=&r"(value), "=&r"(failed)
                     : "r"(scratch), "r"(address) : "memory");
    *byte = value;
    return failed;
}

static const uint64_t scratch_initial = UINT64_C(0x5a5a5a5aa5a5a5a5);

static unsigned nonzero_exclusive_once(const void *address, uint64_t *scratch, unsigned *byte,
                                        uint64_t *aux)
{
    *scratch = scratch_initial;
    unsigned status = zero_exclusive_once(address, scratch, byte, aux);
    return *scratch == (status ? scratch_initial : 0) ? status : 2U;
}

enum unreserved_branch {
    UNRESERVED_TO_LOAD,     /* direct branch to the LDRB */
    UNRESERVED_TO_NOP,      /* direct branch to a NOP in the LDXR gap */
    UNRESERVED_INDIRECT,    /* ADR + BR to the LDRB, target left in x9 */
    UNRESERVED_CROSS_PAGE,
    UNRESERVED_GAP_CLREX,   /* LDXR executes; CLREX clears it before the STXR */
    UNRESERVED_GAP_SVC,     /* LDXR executes; SVC takes an exception in between */
};

/* Keep an unreachable LDXR in the bridge's look-behind and skip it with the
 * requested control-flow shape. CLREX makes a native STXR fail in every case. */
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
    } else if (branch == UNRESERVED_CROSS_PAGE) {
        /* Align the skipped LDXR so the branch is outside the faulting PC's
         * page on both supported page sizes. B does not leave a target in a
         * GPR for the bridge's indirect-branch check. */
        __asm__ volatile("clrex\n"
                         "b 1f\n"
                         ".p2align 14\n"
                         "ldxr %0, [%3]\n"
                         "1: ldrb %w2, [%4]\n"
                         "stxr %w1, %0, [%3]\n"
                         : "+&r"(value), "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address) : "memory");
    } else if (branch == UNRESERVED_GAP_SVC) {
        /* An exception in the gap. The kernel may clobber the caller-saved
         * registers, so the monitored address and the loaded word live in
         * callee-saved registers across the SVC. */
        __asm__ volatile("stp x19, x20, [sp, #-16]!\n"
                         "mov x19, %2\n"
                         "mov x20, %3\n"
                         "ldxr x21, [x19]\n"
                         "ldrb %w1, [x20]\n"
                         "mov x8, #172\n"
                         "svc #0\n"
                         "stxr %w0, x21, [x19]\n"
                         "ldp x19, x20, [sp], #16\n"
                         : "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address)
                         : "x21", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                           "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                           "x30", "memory");
    } else if (branch == UNRESERVED_GAP_CLREX) {
        /* The LDXR really executes; CLREX in the gap then clears the
         * reservation, so the architecture reports STXR failure. */
        __asm__ volatile("ldxr %0, [%3]\n"
                         "ldrb %w2, [%4]\n"
                         "clrex\n"
                         "stxr %w1, %0, [%3]\n"
                         : "+&r"(value), "=&r"(status), "=&r"(*byte)
                         : "r"(scratch), "r"(address) : "memory");
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
    if (branch == UNRESERVED_CROSS_PAGE) {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size != 4096 && page_size != 16384) {
            out->error = EOPNOTSUPP;
            goto done;
        }
    }
    out->error = identity(address, 1, backing_fd, offset, &target);
    if (out->error) goto done;
    bool exec_reference = branch != UNRESERVED_GAP_CLREX && branch != UNRESERVED_GAP_SVC;

    out->error = identity_with_exec(reference, 1, backing_fd, offset, exec_reference, &control);
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
    out->error = identity_with_exec(reference, 1, backing_fd, offset, exec_reference, &after);
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

void ud_observe_unreserved_cross_page_status(const void *address, const void *reference,
                                             int backing_fd, off_t offset,
                                             struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_CROSS_PAGE, out);
}

void ud_observe_gap_clrex_status(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_GAP_CLREX, out);
}

void ud_observe_gap_svc_status(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_store_observation *out)
{
    observe_unreserved_store(address, reference, backing_fd, offset, scratch_initial,
                             UNRESERVED_GAP_SVC, out);
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
static unsigned execution_once(const void *address, uint64_t *scratch, unsigned *byte,
                                    uint64_t *aux)
{
    (void)aux;
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

enum reservation_probe {
    READ_ADJACENT, READ_SPACED, READ_POST_LOAD_NOP, READ_POST_LOAD_ALU, READ_PRE_LOAD_ALU,
    READ_POST_LOAD_FP, READ_PRE_LOAD_GPR, READ_POST_LOAD_SIMD, READ_POST_LOAD_CSEL,
    READ_POST_LOAD_LOAD, READ_POST_LOAD_STORE, READ_POST_LOAD_BRANCH, READ_POST_LOAD_XLOAD,
    READ_POST_LOAD_CALL, READ_POST_LOAD_PERMUTE, READ_POST_LOAD_FPARITH,
    READ_ZERO, READ_NONZERO, EXECUTE_CANARY
};

typedef unsigned (*probe_fn)(const void *, uint64_t *, unsigned *, uint64_t *);

static void observe_reservation(const void *address, const void *reference,
                                int backing_fd, off_t offset, enum reservation_probe probe,
                                struct ud_exclusive_observation *out)
{
    struct sample_identity target, control, after;
    int execute = probe == EXECUTE_CANARY;
    bool ap_probe = probe == READ_POST_LOAD_NOP || probe == READ_POST_LOAD_ALU ||
                    probe == READ_PRE_LOAD_ALU || probe == READ_POST_LOAD_FP ||
                    probe == READ_PRE_LOAD_GPR || probe == READ_POST_LOAD_SIMD ||
                    probe == READ_POST_LOAD_CSEL || probe == READ_POST_LOAD_LOAD ||
                    probe == READ_POST_LOAD_STORE || probe == READ_POST_LOAD_BRANCH ||
                    probe == READ_POST_LOAD_XLOAD || probe == READ_POST_LOAD_CALL ||
                    probe == READ_POST_LOAD_PERMUTE || probe == READ_POST_LOAD_FPARITH;
    /* The value-producing probes store an input-derived word through the STXR;
     * comparing it with the control run proves the modeled window computed the
     * same registers and memory as the native instructions. */
    bool valued = probe == READ_POST_LOAD_SIMD ||
                  probe == READ_POST_LOAD_CSEL || probe == READ_POST_LOAD_LOAD ||
                  probe == READ_POST_LOAD_STORE || probe == READ_POST_LOAD_BRANCH ||
                  probe == READ_POST_LOAD_XLOAD;
    size_t size = execute ? sizeof(uint64_t) : 1U;
    probe_fn sample = exclusive_once;
    if (execute) sample = execution_once;
    if (probe == READ_SPACED) sample = spaced_exclusive_once;
    if (probe == READ_POST_LOAD_NOP) sample = post_load_nop_once;
    if (probe == READ_POST_LOAD_ALU) sample = post_load_alu_once;
    if (probe == READ_PRE_LOAD_ALU) sample = pre_load_alu_once;
    if (probe == READ_POST_LOAD_FP) sample = post_load_fp_once;
    if (probe == READ_PRE_LOAD_GPR) sample = pre_load_gpr_once;
    if (probe == READ_POST_LOAD_SIMD) sample = post_load_simd_once;
    if (probe == READ_POST_LOAD_CSEL) sample = post_load_csel_once;
    if (probe == READ_POST_LOAD_LOAD) sample = post_load_load_once;
    if (probe == READ_POST_LOAD_STORE) sample = post_load_store_once;
    if (probe == READ_POST_LOAD_BRANCH) sample = post_load_branch_once;
    if (probe == READ_POST_LOAD_XLOAD) sample = post_load_xload_once;
    if (probe == READ_POST_LOAD_CALL) sample = post_load_call_once;
    if (probe == READ_POST_LOAD_PERMUTE) sample = post_load_permute_once;
    if (probe == READ_POST_LOAD_FPARITH) sample = post_load_fparith_once;
    if (probe == READ_ZERO) sample = zero_exclusive_once;
    if (probe == READ_NONZERO) sample = nonzero_exclusive_once;
    /* Keep the scratch away from normal stack writes and compiler spills.
     * The caller does not share this stack storage with other threads.
     */
    _Alignas(2048) uint64_t scratch[256] = {0};
    _Alignas(64) uint64_t aux[2] = {0, 0};
    int saved = errno, error;
    long ps = sysconf(_SC_PAGESIZE);
    uint64_t begin = now_ns();
    unsigned control_byte = 0, target_byte = 0;
    memset(out, 0, sizeof(*out));
    out->reservation_loss = UD_UNKNOWN;
    error = identity(address, size, backing_fd, offset, &target);
    if (error) { out->error = error; goto done; }
    /* UROV-Y cannot register a non-executable reference as a target page. */
    error = identity_with_exec(reference, size, backing_fd, offset, !ap_probe, &control);
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
        unsigned control_status = sample(reference, scratch, &a, aux);
        unsigned target_status = sample(address, scratch, &b, aux);
        if (control_status > 1U || target_status > 1U) { out->error = EPROTO; goto done; }
        if ((!ap_probe && a != b) ||
            (i && (a != control_byte || b != target_byte))) {
            out->error = EAGAIN; goto done;
        }
        control_byte = a;
        target_byte = b;
    }
    for (unsigned epoch = 0; epoch < UD_OBSERVE_EPOCHS; ++epoch) {
        unsigned accepted = 0, failures = 0;
        for (unsigned attempt = 0; attempt < UD_OBSERVE_TRIALS * 2U &&
                                   accepted < UD_OBSERVE_TRIALS; ++attempt) {
            unsigned a, b, c;
            unsigned before = sample(reference, scratch, &a, aux);
            uint64_t control_value = scratch[0], control_aux = aux[0];
            unsigned tested = sample(address, scratch, &b, aux);
            uint64_t target_value = scratch[0], target_aux = aux[0];
            unsigned after_control = sample(reference, scratch, &c, aux);
            if (valued && !out->value_seen && !before && !tested && !after_control) {
                /* The store probe keeps its result in the private aux word. */
                bool aux_value = probe == READ_POST_LOAD_STORE ||
                                 probe == READ_POST_LOAD_SIMD;

                out->value_seen = 1;
                out->control_value = aux_value ? control_aux : control_value;
                out->target_value = aux_value ? target_aux : target_value;
                out->value_match = out->target_value == out->control_value;
            }
            if (before > 1U || tested > 1U || after_control > 1U) {
                out->error = EPROTO; goto done;
            }
            if (a != control_byte || b != target_byte || c != control_byte) {
                out->error = EAGAIN; goto done;
            }
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
    error = identity_with_exec(reference, size, backing_fd, offset, !ap_probe, &after);
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

void ud_observe_ap_reservation(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_NOP, out);
}

void ud_observe_ap_alu(const void *address, const void *reference, int backing_fd,
                       off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_ALU, out);
}

void ud_observe_ap_pre_alu(const void *address, const void *reference, int backing_fd,
                           off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_PRE_LOAD_ALU, out);
}

void ud_observe_ap_fp(const void *address, const void *reference, int backing_fd,
                      off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_FP, out);
}

void ud_observe_ap_v221(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v221_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_NOP, &out->baseline);
    observe_reservation(address, reference, backing_fd, offset, READ_PRE_LOAD_GPR, &out->pre_gpr);
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_SIMD, &out->simd);
    out->verdict = UD_UNKNOWN;
    if (out->baseline.reservation_loss == UD_NO_MATCH &&
        out->pre_gpr.reservation_loss == out->simd.reservation_loss)
        out->verdict = out->pre_gpr.reservation_loss;
}

void ud_observe_ap_v222(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v222_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_CALL, &out->leaf_call);
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_PERMUTE, &out->permute);
    out->verdict = out->leaf_call.reservation_loss == out->permute.reservation_loss ?
                   out->leaf_call.reservation_loss : UD_UNKNOWN;
}

void ud_observe_ap_v223(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v223_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_FPARITH,
                        &out->fparith);
    out->verdict = out->fparith.reservation_loss;
}

void ud_observe_ap_csel(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_CSEL, out);
}

void ud_observe_ap_load(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_LOAD, out);
}

void ud_observe_ap_store(const void *address, const void *reference, int backing_fd,
                         off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_STORE, out);
}

void ud_observe_ap_branch(const void *address, const void *reference, int backing_fd,
                          off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_BRANCH, out);
}

void ud_observe_ap_xload(const void *address, const void *reference, int backing_fd,
                         off_t offset, struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_POST_LOAD_XLOAD, out);
}

void ud_observe_zero_exclusive(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_ZERO, out);
}

void ud_observe_nonzero_exclusive(const void *address, const void *reference,
                                  int backing_fd, off_t offset,
                                  struct ud_exclusive_observation *out)
{
    observe_reservation(address, reference, backing_fd, offset, READ_NONZERO, out);
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
