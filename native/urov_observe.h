/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_OBSERVE_H
#define UROV_OBSERVE_H
#include "urov_detect.h"

#define UD_OBSERVE_EPOCHS 3U
#define UD_OBSERVE_TRIALS 32U

struct ud_exclusive_observation {
    enum ud_verdict reservation_loss;
    int error;
    unsigned epochs, accepted, target_failed, control_failed;
    uint64_t elapsed_ns;
};

struct ud_reader_observation {
    enum ud_verdict reader_diff;
    int error;
    unsigned completed;
    uint64_t direct_value, reader_value, file_value;
};

typedef uint64_t (*ud_plain_reader)(const void *);

/* NO control ABI, secret, prctl, signals, target writes, or mapping operations.
 * Both addresses MUST be retained immutable readable executable file mappings
 * of the SAME byte in backing_fd, in different virtual pages. Keep their
 * lifetimes and the file stable throughout the call. Run on a worker thread.
 *
 * The only exclusive accesses are to a private stack scratch word. The target
 * is read with ordinary LDRB. Three epochs each require 32 accepted triplets:
 * successful reference -> target -> successful reference. More than eight
 * discarded control triplets, an uncertain control,
 * partial target pattern or metadata change yields UNKNOWN, never a finding.
 * MATCH identifies repeatable read-associated exclusive reservation loss,
 * NOT a unique UROV fingerprint. Debug/watchpoint/virtualization mechanisms and
 * implementation-specific exclusive failures remain alternative explanations.
 * NO_MATCH cannot exclude an idle module, another mm, or an unsampled page.
 */
void ud_observe_exclusive(const void *address, const void *reference,
                          int backing_fd, off_t offset,
                          struct ud_exclusive_observation *out);

/* Observe instruction fetch on an app-owned canary. Both addresses must be
 * 8-byte aligned, callable immutable RX entries for the same file bytes in
 * different virtual pages. The entry must contain exactly BTI C; RET (x30).
 * Supply a known entry on the reader page and a normal alias of that entry.
 * The code is checked against the file before either address is called.
 *
 * The same paired trials and lifetime contract apply as above. MATCH
 * identifies repeatable execution-associated reservation loss. The canary
 * accesses no data, so the finding is independent of the overlay's value or
 * caller window. Do not use this API to branch to arbitrary code addresses.
 */
void ud_observe_execution(const void *address, const void *reference,
                          int backing_fd, off_t offset,
                          struct ud_exclusive_observation *out);

/* reader MUST be a caller-owned, side-effect-free plain 64-bit load routine
 * from the actual business read site; address must be 8-byte aligned. Caller
 * must know this routine's normal semantics and retain its code. This API does
 * not discover/call arbitrary instruction addresses. A mismatch means a stable
 * PC-dependent read inconsistency; it does not identify the module by name.
 * Negative results cover only this site and these eight bytes.
 */
void ud_observe_reader(const void *address, int backing_fd, off_t offset,
                       ud_plain_reader reader, struct ud_reader_observation *out);
#endif
