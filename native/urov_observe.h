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
    /* Every probe stores its own private scratch word through the STXR.  The
     * last target/control pair is compared so a modeled window that produces a
     * different value than the native sequence cannot hide behind a preserved
     * reservation.  value_seen is set when the probe has a stable value. */
    unsigned value_seen, value_match;
    uint64_t target_value, control_value;
    uint64_t elapsed_ns;
};

struct ud_store_observation {
    enum ud_verdict verdict;
    int error;
    unsigned completed, unexpected_stores;
    uint64_t elapsed_ns;
};

struct ud_ap_v221_observation {
    enum ud_verdict verdict;
    struct ud_exclusive_observation baseline, pre_gpr, simd;
};

struct ud_ap_v222_observation {
    enum ud_verdict verdict;
    struct ud_exclusive_observation leaf_call, permute;
};

struct ud_ap_v223_observation {
    enum ud_verdict verdict;
    struct ud_exclusive_observation fparith, pre_mov, pre_long;
    struct ud_store_observation self_store, neon_self;
};

/* One-shot read-window probe with a 6000-instruction loop between the sampled
 * load and the STXR.  Returns the STXR status; 0 is the native success. */
unsigned ud_deep_window_status(const void *address, uint64_t *scratch, unsigned *byte);

struct ud_reader_observation {
    enum ud_verdict reader_diff;
    int error;
    unsigned completed;
    uint64_t direct_value, reader_value, file_value;
};

typedef uint64_t (*ud_plain_reader)(const void *);

struct ud_live_observation {
    enum ud_verdict verdict;
    int error;
    uint8_t user_bytes[UD_LIVE_MAX_BYTES], kernel_bytes[UD_LIVE_MAX_BYTES];
    uint64_t elapsed_ns;
};

struct ud_readv_observation {
    enum ud_verdict reader_diff, post_copy;
    int error;
    uint8_t user_bytes[UD_LIVE_MAX_BYTES], live_bytes[UD_LIVE_MAX_BYTES];
    uint8_t post_bytes[UD_LIVE_MAX_BYTES];
    uint64_t elapsed_ns;
};

/* Test UROV-Y 2.16.0's process_vm_readv after-hook using two iovecs. Linux
 * imports the destinations before copying; the first destination changes the
 * second iovec in userspace, so the hook rereads a different destination.
 * Both destinations are writable private scratch. No target page is changed.
 *
 * Retain the immutable RX mapping, a separate read-only non-executable alias
 * of the same file bytes, the backing fd and the side-effect-free business
 * reader. Run on a worker and only where process_vm_readv is known to be
 * allowed. The sample fits within one page and UD_LIVE_MAX_BYTES.
 *
 * A stable unexpected write is post_copy=MATCH. A stable difference between
 * the business and live bytes is reader_diff=MATCH. Use live_bytes only when
 * reader_diff is known, and post_bytes only when post_copy=MATCH.
 */
void ud_observe_readv_redirect(const uint8_t *address, const uint8_t *reference, size_t size,
                               int backing_fd, off_t offset, ud_bytes_reader reader,
                               struct ud_readv_observation *out);

/* Compare the actual reader with a kernel copy of this process's mapped page.
 * The kernel copy uses 65 local iovecs: a count above the legacy 64-entry
 * module cap, and still one valid transfer because the remaining entries are
 * zero length. Enable only on Android profiles verified to allow
 * process_vm_readv. UROV-Y 2.11.0 covers this count too; matching views cannot
 * establish integrity there. Retain the immutable RX mapping, fd and side-effect-free
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

/* Same lifetime, file identity and paired trials. The target is RX; the
 * reference must be a read-only, non-executable alias of the same file byte
 * in another page, so UROV-Y cannot register it. LDXR; LDRB; NOP; STXR puts
 * a NOP at the faulting PC + 4, outside the 2.11.0 PAGE_AP store bridge.
 * The two bytes may differ (e.g. a legitimate COW patch) but each must remain
 * stable. A MATCH describes reservation loss for this read, independent of
 * the returned byte. This does not test SITE_BRK or PAGE_UXN instruction fetch. */
void ud_observe_ap_reservation(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_exclusive_observation *out);

/* Same contract as ud_observe_ap_reservation. A register-only ADD after
 * LDRB falls outside the 2.16.0 single and paired LL/SC bridges. */
void ud_observe_ap_alu(const void *address, const void *reference, int backing_fd,
                       off_t offset, struct ud_exclusive_observation *out);

/* Same paired controls. A reversible integer operation before LDRB prevents
 * the 2.20.0 lookback from finding the reservation. The FP register transfer
 * after LDRB is outside its forward window model. Both sequences write only
 * the original value of private scratch. Require agreement of the two probes
 * when using them as evidence of a read trap. */
void ud_observe_ap_pre_alu(const void *address, const void *reference, int backing_fd,
                           off_t offset, struct ud_exclusive_observation *out);
void ud_observe_ap_fp(const void *address, const void *reference, int backing_fd,
                      off_t offset, struct ud_exclusive_observation *out);

/* Same mapping and worker contract as ud_observe_ap_reservation. The 2.21
 * model bridges the NOP baseline but declines a write to a second GPR before
 * LDRB and a SIMD EOR after LDRB. 2.22.0 models both, and the SIMD sequence
 * preloads V0 with 0xff and reads lane0 back after the STXR so a modeled
 * window must also commit the architectural FPSIMD result. MATCH requires all
 * target reservations lost for both declined shapes and none lost for the
 * baseline; the SIMD observation's value_match compares the post-sequence V0
 * lane with the native control run. Mixed results, invalid
 * mappings and unstable controls yield UNKNOWN. */
void ud_observe_ap_v221(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v221_observation *out);

/* Same worker and mapping contract as ud_observe_ap_reservation. A local
 * BL/RET and a SIMD REV64 each fall outside the 2.22.0 forward window.
 * Both paired probes must agree. MATCH indicates repeatable read-associated
 * reservation loss even when the returned byte equals the file. Other
 * sources of exceptions can produce the same symptom. */
void ud_observe_ap_v222(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v222_observation *out);

/* A scalar FADD between the target read and STXR is outside the byte-level
 * window model.  UROV-Y 2.23.0 executes the straight-line window natively
 * under software step and completes the STXR, so the paired probe must return
 * NO_MATCH in the AP mode. */
void ud_observe_ap_v223(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_ap_v223_observation *out);

/* Same paired controls as ud_observe_ap_reservation. LDRB overwrites the
 * LDXR destination, so the 2.23.0 precheck declines both the model and native
 * stepping. STXR can only store zero back to the private zero scratch word.
 * MATCH identifies a repeatable read trap even when the sampled byte matches
 * the file. Check only stable, owned mappings and treat UNKNOWN as unverified. */
void ud_observe_ap_overwrite_ldxr(const void *address, const void *reference, int backing_fd,
                                  off_t offset, struct ud_exclusive_observation *out);

/* LDXR; LDP Wt,Wt2; STXR. Y 2.24.0 can emulate the pair load without
 * repairing the exclusive reservation. Both addresses must be 8-byte aligned
 * in stable RX and R-only aliases of the same file offset, respectively.
 * MATCH requires every target STXR to fail with successful bracketing controls. */
void ud_observe_ap_pair_load(const void *address, const void *reference, int backing_fd,
                             off_t offset, struct ud_exclusive_observation *out);

/* Same paired controls and caller obligations as ud_observe_ap_reservation.
 * ADD #0 writes the LDXR base register without changing the address. This
 * defeats the conservative 2.25.0 PAGE_AP read-before write-set proof. */
void ud_observe_ap_base_write(const void *address, const void *reference,
                              int backing_fd, off_t offset,
                              struct ud_exclusive_observation *out);

/* Same RX/R-only alias contract. AND #-8 leaves the aligned scratch address
 * unchanged but the 2.26.0 pre-window cannot invert the mask. MATCH reports
 * repeatable target-only reservation loss. No target writes or control calls. */
void ud_observe_ap_aligned_base(const void *address, const void *reference,
                                int backing_fd, off_t offset, struct ud_exclusive_observation *out);

/* 2.25.0 sampled-access shapes and pre-load classes, indexed by variant:
 *   0 LDP Wt,Wt2        4 LDR from private storage before the sampled load
 *   1 LDR Q (128-bit)   5 STR to private storage before the sampled load
 *   2 LD1 two structures 6 LDADD on private storage before the sampled load
 *   3 FADD before load  7 ADD (extended register) before the sampled load
 *   8 LDXP; LDRB; ADD; STXP
 * Every variant samples the same file byte through a legal read of the
 * registered page and retires every instruction before the STXR without
 * clearing the local monitor, so the native STXR succeeds. NO_MATCH is the
 * expected result while the module serves the page; MATCH is a read-trap
 * feature, not a value difference. Same mapping, worker and lifetime contract
 * as ud_observe_ap_reservation. */
unsigned ud_observe_ap_v225_count(void);
void ud_observe_ap_v225(const void *address, const void *reference, int backing_fd,
                        off_t offset, unsigned variant,
                        struct ud_exclusive_observation *out);

/* 2.26.0 pre-window elimination probes, indexed by variant:
 *   0 ADD/SUB chain on the LDXR base (net zero)
 *   1 ADR of a span address in a live GPR (no branch uses it)
 *   2 MRS x9, TPIDR_EL0
 *   3 DC ZVA on private storage
 *   4 DC CVAC on private storage
 *   5 5000 NOPs between the LDXR and the sampled load
 * Every variant is a legal EL0 instruction stream that leaves the local
 * monitor and the reserved address alone, so the native STXR succeeds and the
 * sampled byte matches the file.  NO_MATCH is the expected result while the
 * module serves the page; MATCH is a residual pre-window feature.  Same
 * mapping, worker and lifetime contract as ud_observe_ap_reservation. */
unsigned ud_observe_ap_v226_count(void);
void ud_observe_ap_v226(const void *address, const void *reference, int backing_fd,
                        off_t offset, unsigned variant,
                        struct ud_exclusive_observation *out);

/* Read one byte with LDXR and immediately CLREX the reservation.  Returns 0 and
 * the byte through *out; a module that does not decode the exclusive load turns
 * this into SIGSEGV. Only for a retained, readable, app-owned page. */
int ud_read_exclusive_byte(const void *address, unsigned *out);

/* Same contract as ud_observe_ap_reservation. CSEL reads NZCV and preserves
 * the scratch value. The UROV-Y 2.19.0 single LL/SC bridge declines this gap. */
void ud_observe_ap_csel(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_exclusive_observation *out);

/* Same paired controls. 2.20.0 models the whole LL/SC window, so the following
 * gap shapes must preserve the reservation natively and under the module, and
 * the value the STXR writes must match the control run:
 *   - a plain LDR from a private word whose value the STXR stores;
 *   - a plain STR that leaves the sampled byte in a private word;
 *   - a conditional branch whose direction is taken from the sampled byte;
 *   - a second LDXR that re-establishes the reservation on the same word. */
void ud_observe_ap_load(const void *address, const void *reference, int backing_fd,
                        off_t offset, struct ud_exclusive_observation *out);
void ud_observe_ap_store(const void *address, const void *reference, int backing_fd,
                         off_t offset, struct ud_exclusive_observation *out);
void ud_observe_ap_branch(const void *address, const void *reference, int backing_fd,
                          off_t offset, struct ud_exclusive_observation *out);
void ud_observe_ap_xload(const void *address, const void *reference, int backing_fd,
                         off_t offset, struct ud_exclusive_observation *out);
void ud_observe_ap_xpair(const void *address, const void *reference, int backing_fd,
                         off_t offset, struct ud_exclusive_observation *out);

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

/* Same contract, but the LDXR really executes and CLREX clears the reservation
 * between the sampled load and the STXR. The architecture makes that STXR fail,
 * so a window model must leave it native: unexpected_stores must stay 0 with
 * the module loaded exactly as it is without it. This isolates the deliberate
 * fail-closed boundary from a hidden reservation-loss feature. */
void ud_observe_gap_clrex_status(const void *address, const void *reference,
                                 int backing_fd, off_t offset,
                                 struct ud_store_observation *out);

/* Same contract, with an SVC #0 (an exception) between the sampled load and the
 * STXR. An exception entry clears the local monitor, so the native outcome is
 * again failure and the module must preserve it. */
void ud_observe_gap_svc_status(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_store_observation *out);

/* The LDXR executes, then a plain store to the monitored private word clears
 * the reservation.  The native STXR must fail; a bridge that completes it
 * reports success and raises unexpected_stores.  The second form uses a
 * single-lane SIMD store outside the scalar decoder's guaranteed set, covering
 * the store shapes the native-step path used to decline. */
void ud_observe_gap_self_store(const void *address, const void *reference,
                               int backing_fd, off_t offset,
                               struct ud_store_observation *out);
void ud_observe_gap_neon_self_store(const void *address, const void *reference,
                                    int backing_fd, off_t offset,
                                    struct ud_store_observation *out);

/* Same contract, but the skipped LDXR is reached through ADR + BR.  The
 * target address remains in x9 when LDRB faults; a handler that retires the
 * STXR here has neither resolved the direct branch nor checked the register
 * file.  This is the regression probe for the indirect-branch gate. */
void ud_observe_unreserved_indirect_status(const void *address, const void *reference,
                                           int backing_fd, off_t offset,
                                           struct ud_store_observation *out);

/* RX target and R-only reference at the same regular-file offset. CLREX and
 * a BTI-compatible indirect jump skip LDXR. MATCH requires every target STXR
 * to report success AND change private scratch, with both bracketing controls
 * failing without a write. The target and reference are only read by LDRB. */
void ud_observe_ap_phantom_store(const void *address, const void *reference,
                                 int backing_fd, off_t offset, struct ud_store_observation *out);

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
