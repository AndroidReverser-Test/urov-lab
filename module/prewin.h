/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_PREWIN_H
#define UROV_Z_PREWIN_H
/* The read-before value model used by backend.c. Everything here is pure: it
 * rewinds instruction words the caller supplies and never reads memory or
 * kernel state.  uz_pre_step() rewinds one retired instruction; the backend
 * calls it once per slot between the sampled load and the most recent
 * load-exclusive. */
#include "decode.h"
#include "window.h"

/* A page-aligned, non-wrapping value used as every register when the
 * read-before proof classifies a pre-window instruction: the decoders compute
 * an address from it, and both under- and overflow must be impossible. */
#define UZ_PRE_PROBE_ADDR (UINT64_C(1) << 32)

/* SCTLR_EL1.UCI (bit 26) and .DZE (bit 14) as the backend reads them at load
 * time.  The EL0 cache-maintenance encodings and DC ZVA are only legal while
 * those bits are set; an encoding that would trap has to stay declined,
 * because its exception clears the local monitor and a signal handler that
 * skips it would otherwise turn the bridge into a new feature.  The standalone
 * test keeps both enabled, matching the Android target (bionic's
 * __clear_cache uses DC CVAU/IC IVAU at EL0). */
static unsigned uz_pre_uci = 1;
static unsigned uz_pre_dze = 1;

/* ------------------------------------------- read-before value proof (2.26)
 *
 * 2.25.0 rejected every pre-window write to the LDXR base register, so
 *   LDXR x9,[s]; ADD s,s,#0; LDRB w0,[t]; STXR w8,x9,[s]
 * declined even though the reserved address never moved: the native STXR
 * succeeded without the module and failed with it in the reference tests.
 *
 * 2.26.0 rewinds the window with a value proof instead of a write set.  It
 * starts at the faulting load, where every general register is known, and
 * carries a table of "the value this register would read right now".  For
 * each retired instruction it removes every register the instruction writes;
 * a register whose pre-value is an exact function of its post-value (add/
 * subtract/eor of a known operand, or an in-place identity) keeps that
 * recovered value, everything else becomes unknown.  When the walk reaches
 * the most recent load-exclusive, the base register's recovered value is the
 * address that load reserved.
 *
 * The proof is sound in the direction that matters: a value is only reported
 * as known when the inverse is exact for every possible pre-value of the
 * written register.  A 32-bit arithmetic write, an AND/ORR mask that merely
 * happens to leave the current value unchanged, a load, a call result or any
 * class without an exact inverse becomes unknown instead of guessed.  The
 * address is the input to the exclusive monitor; a guess here would let the
 * bridge fake a success at an address the hardware never reserved, which
 * would be a new feature.  An unknown value only makes the plan decline,
 * which is exactly the native failure path.
 *
 * 2.27.0 adds one more exact class on top of that rule.  A load-exclusive that
 * reached the sampled access must have used a naturally aligned address, so
 * the base register's low log2(size) bits are known zero.  A logical mask
 * that can only name those bits is the identity for every address the
 * hardware could have reserved, so its post-value is exact even though the
 * same instruction is not invertible for an arbitrary input.  The backend
 * passes that known-zero mask (uz_pre_step_aligned); a zero mask reproduces
 * the 2.26.0 behaviour exactly.
 */
struct uz_pre_state {
    uint64_t val[31];
    uint64_t sp;
    uint32_t known;   /* bit r: val[r] holds the value read here; bit 31: sp */
};

static uint32_t uz_pre_bit(unsigned reg)
{
    return 1U << reg;   /* reg is 0..31; 31 names SP */
}

static int uz_pre_known(const struct uz_pre_state *st, unsigned reg)
{
    return (st->known & uz_pre_bit(reg)) != 0U;
}

static uint64_t uz_pre_value(const struct uz_pre_state *st, unsigned reg)
{
    return reg == 31U ? st->sp : st->val[reg];
}

static void uz_pre_put(struct uz_pre_state *st, unsigned reg, uint64_t value)
{
    if (reg == 31U) st->sp = value;
    else st->val[reg] = value;
    st->known |= uz_pre_bit(reg);
}

static void uz_pre_forget(struct uz_pre_state *st, unsigned reg)
{
    st->known &= ~uz_pre_bit(reg);
}

/* Recover the value that `reg` held before one instruction that wrote it,
 * using the values its sources still hold.  Returns 1 only when the inverse is
 * exact for every pre-value the register could have had; 0 otherwise.
 *
 * `zero_mask` names the bits a pre-value is architecturally known to have
 * clear.  The only caller that passes a non-zero mask is the exclusive window:
 * a load-exclusive that reached the sampled access reserved a naturally
 * aligned address, so the low log2(size) bits of the base register are zero.
 * For a logical mask that only names those bits, the pre-value is fixed even
 * though the instruction is not invertible for an arbitrary input: AND/BIC
 * are the identity (the cleared bits are already zero), and ORR/ORN set
 * exactly the mask bits, so `post & ~mask` recovers the pre-value.  With
 * zero_mask == 0 the old all-inputs rule is unchanged. */
static int uz_pre_invert(uint32_t insn, unsigned reg, struct uz_pre_state *st,
                         uint64_t zero_mask)
{
    uint64_t after = uz_pre_value(st, reg);

    /* Add/subtract (immediate).  Only a 64-bit in-place update is exact: a
     * 32-bit write zero-extends and loses the pre-value's high half. */
    if ((insn & 0x1f000000U) == 0x11000000U) {
        unsigned sf = insn >> 31;
        unsigned sub = (insn >> 30) & 1U;
        unsigned setf = (insn >> 29) & 1U;
        unsigned sh = (insn >> 22) & 1U;
        unsigned imm = (insn >> 10) & 0xfffU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        uint64_t delta = (uint64_t)imm << (sh ? 12 : 0);

        if (!sf || rd != rn || rd != reg || (rd == 31U && setf)) return 0;
        uz_pre_put(st, rd, sub ? after + delta : after - delta);
        return 1;
    }

    /* Add/subtract (shifted register).  The other operand must not be the
     * destination: a shift of the destination itself loses shifted-out bits. */
    if ((insn & 0x1f200000U) == 0x0b000000U) {
        unsigned sf = insn >> 31;
        unsigned sub = (insn >> 30) & 1U;
        unsigned type = (insn >> 22) & 3U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned amount = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        uint64_t other;

        if (!sf || type == 3U || rd != rn || rd != reg || rd == 31U || rm == rd)
            return 0;
        if (rm == 31U) {
            other = 0;
        } else if (uz_pre_known(st, rm)) {
            other = uz_win_shift(uz_pre_value(st, rm), type, amount, 64U);
        } else {
            return 0;
        }
        uz_pre_put(st, rd, sub ? after + other : after - other);
        return 1;
    }

    /* Logical (shifted register).  EOR/EON inverts exactly against the other
     * shifted operand; AND/ORR only when that operand is its identity. */
    if ((insn & 0x1f000000U) == 0x0a000000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned type = (insn >> 22) & 3U;
        unsigned invert = (insn >> 21) & 1U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned amount = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        uint64_t other;

        if (!sf || rd == 31U || rd != reg) return 0;
        if (rd == rn && rm != rd) {
            if (rm == 31U) {
                other = 0;
            } else if (uz_pre_known(st, rm)) {
                other = uz_win_shift(uz_pre_value(st, rm), type, amount, 64U);
            } else {
                return 0;
            }
            if (invert) other = ~other;
            if (opc == 2U) {
                uz_pre_put(st, rd, after ^ other);
                return 1;
            }
            /* AND/BIC are the identity when the cleared bits are known zero;
             * ORR/ORN set exactly the mask bits, which the aligned pre-value
             * is known to have clear, so clearing them again is exact. */
            if ((opc == 0U || opc == 3U) && (~other & ~zero_mask) == 0) {
                uz_pre_put(st, rd, after);
                return 1;
            }
            if (opc == 1U && (other & ~zero_mask) == 0) {
                uz_pre_put(st, rd, after & ~other);
                return 1;
            }
            return 0;
        }
        if (rd == rm && amount == 0U && rd != rn) {
            if (rn == 31U) {
                other = 0;
            } else if (uz_pre_known(st, rn)) {
                other = uz_pre_value(st, rn);
            } else {
                return 0;
            }
            if (opc == 2U) {
                uz_pre_put(st, rd, after ^ other);
                return 1;
            }
            if ((opc == 0U || opc == 3U) && (~other & ~zero_mask) == 0) {
                uz_pre_put(st, rd, after);
                return 1;
            }
            if (opc == 1U && (other & ~zero_mask) == 0) {
                uz_pre_put(st, rd, after & ~other);
                return 1;
            }
            return 0;
        }
        return 0;
    }

    /* Logical (immediate): EOR inverts exactly, AND/ORR only for the identity
     * element (all ones / zero). */
    if ((insn & 0x1f800000U) == 0x12000000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned n = (insn >> 22) & 1U;
        unsigned immr = (insn >> 16) & 0x3fU;
        unsigned imms = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        uint64_t wmask = 0, tmask = 0;

        if (!sf || rd == 31U || rd != rn || rd != reg) return 0;
        if (!uz_win_bitmask(n, imms, immr, 64U, &wmask, &tmask)) return 0;
        if (opc == 2U) {
            uz_pre_put(st, rd, after ^ wmask);
            return 1;
        }
        /* AND/ANDS only clear: the identity when every cleared bit is known
         * zero.  ORR sets exactly the mask bits, which the aligned pre-value
         * is known to have clear, so clearing them again is exact. */
        if ((opc == 0U || opc == 3U) && (~wmask & ~zero_mask) == 0) {
            uz_pre_put(st, rd, after);
            return 1;
        }
        if (opc == 1U && (wmask & ~zero_mask) == 0) {
            uz_pre_put(st, rd, after & ~wmask);
            return 1;
        }
        return 0;
    }
    return 0;
}

/* GPR write set of one instruction that already retired in front of the
 * sampled access.  The linear read-before proof only needs to know which
 * registers a rewound instruction wrote; an instruction it cannot classify
 * returns -1 and the plan declines.  Nothing else about the instruction
 * matters: it ran to completion before the fault, and a faulting instruction
 * can never reach this scan.
 *
 * The accepted classes are what an EL0 task can execute on this target:
 * integer data processing (immediate and register forms, extended-register
 * add/subtract, add/subtract with carry, pointer-authentication hints), loads
 * and stores in every scalar/pair/SIMD/multiple/literal form, the
 * pointer-authenticated loads, LSE atomics and the acquire/release accesses,
 * SIMD&FP data processing plus its transfers into a general register, MRS and
 * the EL0-writable MSR, the UCI-gated EL0 cache maintenance and DZE-gated
 * DC ZVA, direct and conditional branches, NOP/BTI/barriers and prefetch.
 * CLREX, the exclusive stores, the exception-generating instructions, calls,
 * indirect branches, TLBI/AT and the invalidate-only cache forms are rejected
 * by the caller or by the class check, because they clear the local monitor
 * or leave the linear block.  Bit 31 of the mask records a write to SP. */
static int uz_pre_writes(uint32_t insn, uint32_t *mask)
{
    /* A register file with a large page-aligned value everywhere keeps the
     * decoders' address arithmetic away from both under- and overflow, so a
     * pre-window instruction is classified by encoding alone. */
    struct uro_regs probe;
    struct uro_load load;
    struct uro_store store;
    struct uro_atomic atomic;
    uint32_t set = 0;
    unsigned dst, imm;

    *mask = 0;
    memset(&probe, 0, sizeof(probe));
    for (dst = 0; dst < 31U; ++dst) probe.x[dst] = UZ_PRE_PROBE_ADDR;
    probe.sp = UZ_PRE_PROBE_ADDR;
    probe.pc = UZ_PRE_PROBE_ADDR;

    if (insn == UZ_NOP || insn == UZ_BTI_C || insn == UZ_BTI_J || insn == UZ_BTI_JC ||
        (insn & 0xfffff0ffU) == 0xd503309fU ||      /* DMB */
        (insn & 0xfffff0ffU) == 0xd50330bfU ||      /* DSB */
        (insn & 0xfffff0ffU) == 0xd50330dfU)        /* ISB */
        return 0;
    if ((insn & 0xfffff01fU) == 0xd503201fU) {      /* HINT #imm */
        imm = (insn >> 5) & 0x7fU;
        /* XPACLRI and the PAC/AUT forms that sign or strip x30; the four
         * *1716 forms sign x17.  A core without FEAT_PAuth runs them as NOPs,
         * so this stays the conservative direction. */
        if (imm == 7U || (imm >= 24U && imm <= 31U)) set = 1U << 30;
        else if (imm == 8U || imm == 10U || imm == 12U || imm == 14U) set = 1U << 17;
        *mask = set;
        return 0;
    }
    /* MRS/MSR of the user-visible state the window model carries exactly.  Any
     * other system-register encoding traps at EL0, so it cannot be accepted
     * here: the exception it takes would have cleared the monitor. */
    if (uz_win_sysreg_ok(insn)) {
        unsigned rt = insn & 31U;

        /* MRS -> Rt; Rt == 31 discards and must not be read as SP. */
        if (((insn >> 21) & 1U) && rt != 31U) *mask = 1U << rt;
        return 0;
    }
    /* EL0 cache maintenance.  Only the encodings gated by SCTLR_EL1.UCI are
     * named, and only while the backend saw that bit set: TLBI/AT and the
     * invalidate forms trap at EL0, and accepting them would let a signal
     * handler that skips the trap turn the bridge into a new feature.  None of
     * the accepted forms writes a general register or clears the local
     * monitor. */
    if (uz_pre_uci) {
        switch (insn & 0xffffffe0U) {
        case 0xd50b7a20U:   /* DC CVAC */
        case 0xd50b7b20U:   /* DC CVAU */
        case 0xd50b7e20U:   /* DC CIVAC */
        case 0xd50b7c20U:   /* DC CVAP */
        case 0xd50b7d20U:   /* DC CVADP */
        case 0xd50b7520U:   /* IC IVAU */
            return 0;
        default:
            break;
        }
        if (insn == 0xd508751fU) return 0;              /* IC IALLU */
    }
    /* DC ZVA is also decoded as a store by uro_decode_store(); the DZE gate has
     * to be applied here, before that decoder can accept it. */
    if ((insn & 0xffffffe0U) == 0xd50b7420U) return uz_pre_dze ? 0 : -1;
    /* LDRAA/LDRAB (pointer-authenticated loads) write only Rt.  The value
     * comes from memory and cannot be inverted, but the write set is exact;
     * a failed authentication delivers a signal and is the caller's problem,
     * exactly as for any other faulting pre-window instruction.  Checked
     * before the prefetch masks, which overlap. */
    if ((insn & 0xffe00c00U) == 0xf8200400U || (insn & 0xffe00c00U) == 0xf8a00400U) {
        unsigned rt = insn & 31U;

        if (rt != 31U) *mask = 1U << rt;
        return 0;
    }
    /* Direct and conditional branches write no general register and leave the
     * local monitor alone.  A branch that diverts control into the span is
     * rejected by uz_llsc_skipped() from the branch-target map, so the linear
     * span really is the executed path.  BL (bit 31 set) transfers into a
     * callee whose body is not part of this proof, and BR/BLR/RET name a
     * dynamic target; both stay declined. */
    if (!(insn & (1U << 31)) && (insn & 0x7c000000U) == 0x14000000U) return 0;
    if ((insn & 0xff000010U) == 0x54000000U) return 0;   /* B.cond */
    if ((insn & 0x7e000000U) == 0x34000000U) return 0;   /* CBZ/CBNZ */
    if ((insn & 0x7e000000U) == 0x36000000U) return 0;   /* TBZ/TBNZ */
    /* Prefetch hints read an address and write nothing. */
    if ((insn & 0xffc00000U) == 0xf9800000U || (insn & 0xffe00000U) == 0xf8a00000U ||
        (insn & 0xffe00000U) == 0xf8800000U)
        return 0;

    dst = uz_win_dst(insn);
    if (dst != 34U) {
        if (dst < 31U) set = 1U << dst;
        else if (dst == 33U) set = 1U << 31;
        *mask = set;
        return 0;
    }
    /* Add/subtract (extended register) and add/subtract with carry: the window
     * model does not reproduce them, but both only write Rd (or SP). */
    if ((insn & 0x1f200000U) == 0x0b200000U ||
        (insn & 0x1fe00000U) == 0x1a000000U) {
        dst = insn & 31U;
        if (dst != 31U) set = 1U << dst;
        else if (!(insn & (1U << 29))) set = 1U << 31;
        *mask = set;
        return 0;
    }
    /* Conditional compare (register) only writes the flags. */
    if ((insn & 0x3fe00010U) == 0x1a400000U) return 0;

    /* LSE atomic read-modify-write. */
    if (!uro_decode_atomic(insn, &probe, &atomic)) {
        if (atomic.op == URO_ATOMIC_CAS) {
            if (atomic.rs != 31U) set |= 1U << atomic.rs;
            if (atomic.count == 2U && atomic.rs2 != 31U) set |= 1U << atomic.rs2;
        } else if (atomic.return_old && atomic.rt != 31U) {
            set |= 1U << atomic.rt;
        }
        *mask = set;
        return 0;
    }
    /* Loads, including the exclusive forms: destinations plus any writeback. */
    if (!uro_decode(insn, &probe, &load)) {
        if (!load.vector && !load.multi) {
            if (load.rt != 31U) set |= 1U << load.rt;
            if (load.count == 2U && load.rt2 != 31U) set |= 1U << load.rt2;
        }
        if (load.writeback) {
            if (load.rn == 31U) set |= 1U << 31;
            else set |= 1U << load.rn;
        }
        *mask = set;
        return 0;
    }
    /* Stores: only a writeback base register changes. */
    if (!uro_decode_store(insn, &probe, &store)) {
        if (store.writeback) {
            if (store.rn == 31U) set |= 1U << 31;
            else set |= 1U << store.rn;
        }
        *mask = set;
        return 0;
    }
    /* SIMD&FP data processing and the transfers into a general register. */
    if (uz_win_fp_group(insn)) {
        dst = (unsigned)uz_win_fp_gpr_dst(insn);
        if (dst < 31U) *mask = 1U << dst;
        return 0;
    }
    return -1;
}

/* Rewind one retired instruction: apply its write set to the value table.
 * Every written register keeps its exact pre-value when uz_pre_invert() can
 * recover it; otherwise it becomes unknown.  A class this code cannot place
 * makes the whole plan decline (fail closed, native outcome).
 *
 * `zero_mask` is passed through to the logical inverse; see uz_pre_invert().
 * uz_pre_step() keeps the historical no-alignment-assumption entry point for
 * the standalone differential test. */
static int uz_pre_step_aligned(uint32_t insn, struct uz_pre_state *st,
                               uint64_t zero_mask)
{
    uint32_t mask;
    unsigned r;

    if (uz_pre_writes(insn, &mask)) return -1;
    if (!mask) return 0;
    for (r = 0; r < 32U; ++r) {
        if (!(mask & uz_pre_bit(r))) continue;
        if (!uz_pre_invert(insn, r, st, zero_mask)) uz_pre_forget(st, r);
    }
    return 0;
}

static inline int uz_pre_step(uint32_t insn, struct uz_pre_state *st)
{
    return uz_pre_step_aligned(insn, st, 0);
}

/* Start the table at the faulting load: every general register still holds
 * the value the load read, because the load has not committed yet. */
static void uz_pre_reset(struct uz_pre_state *st, const struct uro_regs *regs)
{
    unsigned i;

    for (i = 0; i < 31U; ++i) st->val[i] = regs->x[i];
    st->sp = regs->sp;
    st->known = ~0U;
}

#endif
