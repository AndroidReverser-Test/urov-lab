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

#endif
