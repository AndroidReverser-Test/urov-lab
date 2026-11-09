/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef URO_LAB_DECODE_H
#define URO_LAB_DECODE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct uro_regs {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct uro_load {
    uint64_t address;
    unsigned size;
    unsigned count;
    unsigned rt;
    unsigned rt2;
    unsigned dest_bits;
    int sign_extend;
    int writeback;
    unsigned rn;
    uint64_t wb;
    /* Bytes touched by the whole instruction: size * count for every scalar
     * and pair form, rpt * selem * datasize for a multiple-structure load. */
    uint64_t total;
    /* 1 for a SIMD&FP register load.  rt/rt2 then name V registers 0..31 and
     * there is no sign extension or W-register truncation; a scalar load
     * (size < 16) zeroes the remaining bytes of the destination V register.
     * Only the generic GPR emulator in emulate.c rejects this class; the
     * urov-y target-page backend commits it through the task's FPSIMD state. */
    unsigned vector;
    /* LD1/LD2/LD3/LD4 (multiple structures).  nregs is the repeat count
     * (1..4, only LD1 uses more than one), selem the number of interleaved
     * structures (1..4), esize the element width in bytes, elements the
     * number of elements per register and dst[] the concrete destination
     * V registers in (repeat, structure) order.  A non-multi load leaves
     * multi/nregs/selem/esize/elements/dst[] zero. */
    unsigned multi;
    unsigned nregs;
    unsigned selem;
    unsigned esize;
    unsigned elements;
    unsigned dst[4];
    /* Load-exclusive forms read like any other load but additionally create a
     * reservation on `address`.  1 is LDXR/LDAXR (one element of `size`
     * bytes), 2 is LDXP/LDAXP (`count` is two and the reservation covers
     * size * 2 bytes).  The urov-y PAGE_AP backend needs this to reproduce the
     * reservation a trapped read would otherwise have left behind. */
    unsigned excl;
    unsigned acquire;
};

/* Decode only: no memory access or architectural register changes.
 * Return 0 on success, -1 on unsupported/invalid encoding or address overflow.
 * Failure leaves *out unchanged. size is bytes per element; count is the
 * number of loaded destination registers (1..4 for the multiple-structure
 * forms, 1 or 2 otherwise).  rn==31 means SP; rt/rt2==31 means discard for
 * GPR loads, while a SIMD&FP load always names a real V register.
 * address/wb preserve top-byte tags.
 * Caller must validate mappings, tags, complete access range and fault identity.
 * Caller must perform sign extension then W-register truncation/zero extension
 * for GPR loads, and the FPSIMD state update for SIMD&FP loads.
 */
int uro_decode(uint32_t insn, const struct uro_regs *regs, struct uro_load *out);

/* Store counterpart used by the PAGE_AP write handoff.  Every accepted
 * instruction writes one contiguous range, split into `count` equal-sized
 * segments, each taken from one register (rt[i]) or one V register when
 * `vector` is set.  `zva` marks DC ZVA, which writes 64 zero bytes and reads
 * only the address register.  Decode only: no mapping check and no access. */
struct uro_store {
    uint64_t address;
    unsigned size;
    unsigned count;
    unsigned rt[4];
    unsigned vector;
    unsigned zva;
    unsigned writeback;
    unsigned rn;
    uint64_t wb;
    uint64_t total;
};

/* Return 0 on a supported store, -1 on a load or an unsupported encoding. */
int uro_decode_store(uint32_t insn, const struct uro_regs *regs,
                     struct uro_store *out);

/* LSE atomic read-modify-write (LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/
 * LDUMAX/LDUMIN, SWP, CAS/CASP), including the no-return ST* forms.  The
 * PAGE_AP write handler executes the same operation on the image/live page.
 * `size` is the number of bytes per register (1, 2, 4 or 8); `count` is 2
 * for CASP only.  `rs`/`rs2` are the source (or CAS expected) registers and
 * `rt`/`rt2` the old-value (or CAS desired) registers.  `return_old` is clear
 * for the ST* forms, which write without a result register. */
enum uro_atomic_op {
    URO_ATOMIC_ADD,
    URO_ATOMIC_CLR,
    URO_ATOMIC_EOR,
    URO_ATOMIC_SET,
    URO_ATOMIC_SMAX,
    URO_ATOMIC_SMIN,
    URO_ATOMIC_UMAX,
    URO_ATOMIC_UMIN,
    URO_ATOMIC_SWP,
    URO_ATOMIC_CAS,
};

struct uro_atomic {
    uint64_t address;
    unsigned size;
    unsigned count;
    unsigned op;
    unsigned rs;
    unsigned rs2;
    unsigned rt;
    unsigned rt2;
    unsigned return_old;
    unsigned acquire;
    unsigned release;
    uint64_t total;
};

/* Return 0 on a supported atomic RMW, -1 otherwise. */
int uro_decode_atomic(uint32_t insn, const struct uro_regs *regs,
                      struct uro_atomic *out);

#endif
