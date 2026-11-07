/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_OBSERVE_H
#define UROV_OBSERVE_H
#include "urov_detect.h"

#define UD_OBSERVE_EPOCHS 3U
#define UD_OBSERVE_TRIALS 32U
#define UD_STORE_TRIALS 32U
#define UD_LIVE_MAX_BYTES 64U

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

struct ud_store_observation {
    enum ud_verdict verdict;
    int error;
    unsigned completed, unexpected_stores;
    uint64_t elapsed_ns;
};

typedef uint64_t (*ud_plain_reader)(const void *);
typedef void (*ud_bytes_reader)(uint8_t *out, const uint8_t *address, size_t size);

struct ud_live_observation {
    enum ud_verdict verdict;
    int error;
    uint8_t user_bytes[UD_LIVE_MAX_BYTES], kernel_bytes[UD_LIVE_MAX_BYTES];
    uint64_t elapsed_ns;
};

/* Compare the actual reader with a kernel copy of this process's mapped page.
 * The kernel copy uses 65 local iovecs: a count above the legacy 64-entry
 * module cap, and still one valid transfer because the remaining entries are
 * zero length. Enable only on Android profiles verified to allow
 * process_vm_readv. Retain the immutable RX mapping, fd and side-effect-free
 * reader for the call. Use a worker and sample at most 64 bytes within one
 * page. MATCH requires two stable but different views. UNKNOWN covers read
 * errors and unstable samples. Use the returned bytes only for MATCH or
 * NO_MATCH.
 */
void ud_observe_live(const uint8_t *address, size_t size, int backing_fd, off_t offset,
                     ud_bytes_reader reader, struct ud_live_observation *out);

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

/* Same paired controls as ud_observe_exclusive, with a NOP between LDXR and
 * LDRB. UROV-Y 2.6.0+ recognizes this spacing in its PAGE_AP bridge. */
void ud_observe_spaced_exclusive(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_exclusive_observation *out);

/* Same paired controls as ud_observe_exclusive. The scratch word is zero
 * and both exclusives use XZR, a shape the UROV-Y 2.9.0 bridge rejects.
 * A MATCH indicates reservation loss, including when the read bytes agree.
 */
void ud_observe_zero_exclusive(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_exclusive_observation *out);

/* Same controls as ud_observe_exclusive, with XZR and a nonzero private
 * scratch word. Check the STXR status and the scratch value together.
 * The UROV-Y 2.10.0 PAGE_AP bridge only emulates XZR stores to zero words. */
void ud_observe_nonzero_exclusive(const void *address, const void *reference,
                                  int backing_fd, off_t offset,
                                  struct ud_exclusive_observation *out);

/* Same retained RX mappings, offset and worker-thread requirements as above.
 * CLREX clears the reservation and a branch skips the LDXR next to the LDRB.
 * MATCH requires an unexpected STXR success AND a changed private scratch
 * word in every target trial, with native failure on both reference trials.
 * The read byte must agree with the file throughout. Mixed results or bad
 * controls yield UNKNOWN. This tests the PAGE_AP bridge's store semantics
 * on the sampled page. The only write address is private stack storage.
 */
void ud_observe_unreserved_store(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_store_observation *out);

/* Same CLREX and skipped LDXR, with Rt set to the current private scratch
 * value before the probe. MATCH requires the target STXR to report success
 * and leave scratch unchanged in every trial, with both controls failing
 * the STXR. unexpected_stores counts reported successes in this variant.
 * The reference byte must match the file. The target byte must stay stable.
 */
void ud_observe_unreserved_status(const void *address, const void *reference,
                                  int backing_fd, off_t offset,
                                  struct ud_store_observation *out);

/* Same status and mapping contract. The branch skips LDXR by landing on a
 * NOP immediately before LDRB. This is the regression probe for the UROV-Y
 * 2.6.0 PAGE_AP bridge, which matched this shape; a consistent MATCH means a
 * store was retired without a reservation. */
void ud_observe_unreserved_nop_status(const void *address, const void *reference,
                                      int backing_fd, off_t offset,
                                      struct ud_store_observation *out);

/* Same contract, but the skipped LDXR is reached through ADR + BR.  The
 * target address remains in x9 when LDRB faults; a handler that retires the
 * STXR here has neither resolved the direct branch nor checked the register
 * file.  This is the regression probe for the indirect-branch gate. */
void ud_observe_unreserved_indirect_status(const void *address, const void *reference,
                                           int backing_fd, off_t offset,
                                           struct ud_store_observation *out);

/* Same contract, with a direct branch from another code page. On 4/16 KiB
 * systems this tests the one-page branch scan in the UROV-Y 2.8.0 PAGE_AP
 * bridge. MATCH requires all 32 target STXRs to report success without a
 * reservation, with native failure on both controls in every trial. */
void ud_observe_unreserved_cross_page_status(const void *address, const void *reference,
                                             int backing_fd, off_t offset,
                                             struct ud_store_observation *out);

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
