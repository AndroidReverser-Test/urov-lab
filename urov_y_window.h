/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Y_WINDOW_H
#define UROV_Y_WINDOW_H
/* The LL/SC window model shared by urov-y_backend.c and the host test
 * (tests/urov_window_test.c).  Everything here is pure: it reads and writes
 * only the caller's struct uro_regs, never memory, never kernel state.  The
 * backend drives it from uy_llsc_walk(); the test drives it with instruction
 * words whose native result it computes independently. */
#include "decode.h"

#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif

/* struct user_fpsimd_state as consumed by the kernel's FPSIMD helpers: 32
 * 16-byte vector registers followed by fpsr/fpcr (uapi/asm/sigcontext.h).
 * Shared by the backend's live FPSIMD snapshot and the pure window model. */
struct uy_fpstate {
    uint8_t vregs[32][16];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t reserved[2];
};

#ifndef UY_NOP
#define UY_NOP 0xd503201fU
#endif
#ifndef UY_BTI_C
#define UY_BTI_C 0xd503245fU
#endif
#ifndef UY_BTI_J
#define UY_BTI_J 0xd503249fU
#endif
#ifndef UY_BTI_JC
#define UY_BTI_JC 0xd50324dfU
#endif
/* ------------------------------------------------------ LL/SC window model
 *
 * The AP[1] read trap costs the local exclusive monitor before the handler
 * runs, so a real LDXR;load;<gap>;STXR sequence would report a failure the
 * hardware never produced.  2.19.0 modeled a fixed whitelist of register-only
 * data processing in the gap.  A gap may however hold any instruction whose
 * architectural effect is reproducible here: plain loads, plain stores,
 * flag-setting and flag-reading data processing, address generation and
 * in-window branches.  2.20.0 therefore models the whole window on a private
 * register copy, reads gap loads through the same image/snapshot view as the
 * sampled load, records gap stores for the commit, and stops at the STXR whose
 * base is still the monitored address.  2.21.0 adds the FPSIMD FMOV transfers
 * (D/S/H and the .D[1] lane), MRS/MSR of NZCV/FPCR/FPSR, the read-only
 * TPIDR_EL0/TPIDRRO_EL0/CNTFRQ_EL0/CTR_EL0/DCZID_EL0 values, and the pre-load
 * destination-chain verifier.  2.22.0 generalizes that verifier to a shadow GPR
 * file (a copied value may feed the chain through another register) and adds
 * the three-same integer SIMD families, so one vector instruction between the
 * sampled load and its STXR no longer collapses the window.
 *
 * Everything the model cannot reproduce makes the walk decline, and the native
 * instructions then run: CLREX, a second exclusive, a monitor-clobbering store,
 * an exception, a call, an unmodeled system register, SIMD/FP data processing
 * outside FMOV and the integer three-same families, SVE/SME, or a transfer out
 * of the bounded window.  For CLREX, a
 * second exclusive and an exception the native outcome is the failure the
 * unmodified hardware would also report, so declining there reproduces the
 * architecture rather than hiding it.
 */

static unsigned uy_win_nzcv(uint64_t pstate, unsigned bit)
{
    return (unsigned)((pstate >> (28U + bit)) & 1U);
}

static void uy_win_set_nzcv(struct uro_regs *model, unsigned n, unsigned z,
                            unsigned c, unsigned v)
{
    model->pstate = (model->pstate & ~(UINT64_C(0xf) << 28)) |
                    ((uint64_t)(n & 1U) << 31) | ((uint64_t)(z & 1U) << 30) |
                    ((uint64_t)(c & 1U) << 29) | ((uint64_t)(v & 1U) << 28);
}

/* AArch64 condition evaluation (ARM ARM C1.2.4).  Cond 1111 behaves as AL. */
static int uy_win_cond(uint64_t pstate, unsigned cond)
{
    unsigned n = uy_win_nzcv(pstate, 3), z = uy_win_nzcv(pstate, 2);
    unsigned c = uy_win_nzcv(pstate, 1), v = uy_win_nzcv(pstate, 0);
    int result;

    if (cond == 15U) return 1;
    switch (cond >> 1) {
    case 0: result = (int)z; break;
    case 1: result = (int)c; break;
    case 2: result = (int)n; break;
    case 3: result = (int)v; break;
    case 4: result = (int)(c && !z); break;
    case 5: result = (int)(n == v); break;
    case 6: result = (int)(!z && (n == v)); break;
    default: result = 1; break;
    }
    return (cond & 1U) ? !result : result;
}

static uint64_t uy_win_mask(unsigned bits)
{
    return bits >= 64U ? ~UINT64_C(0) : ((UINT64_C(1) << bits) - 1U);
}

/* XZR reads as zero; SP is a separate field and never addressed through x[]. */
static uint64_t uy_win_gpr(const struct uro_regs *model, unsigned reg)
{
    return reg == 31U ? 0 : model->x[reg];
}

/* Base register of a memory access: Rn == 31 names SP, never XZR. */
static uint64_t uy_win_base(const struct uro_regs *model, unsigned reg)
{
    return reg == 31U ? model->sp : model->x[reg];
}

static int64_t uy_win_sx(uint64_t value, unsigned bits)
{
    uint64_t sign = UINT64_C(1) << (bits - 1U);

    return (int64_t)((value ^ sign) - sign);
}

static uint64_t uy_win_ror(uint64_t value, unsigned amount, unsigned bits)
{
    uint64_t mask = uy_win_mask(bits);

    value &= mask;
    amount &= bits - 1U;
    if (!amount) return value;
    return ((value >> amount) | (value << (bits - amount))) & mask;
}

static uint64_t uy_win_shift(uint64_t value, unsigned type, unsigned amount, unsigned bits)
{
    uint64_t mask = uy_win_mask(bits);

    value &= mask;
    if (!amount) return value;
    if (type == 0U) return (value << amount) & mask;
    if (type == 1U) return value >> amount;
    if (type == 2U && bits == 64U) return (uint64_t)((int64_t)value >> amount);
    if (type == 2U) return (uint64_t)((int64_t)(int32_t)value >> amount);
    return uy_win_ror(value, amount, bits);
}

static void uy_win_addsub_flags(struct uro_regs *model, uint64_t a, uint64_t b,
                                uint64_t result, unsigned bits, unsigned sub)
{
    uint64_t sign = UINT64_C(1) << (bits - 1U);
    uint64_t mask = uy_win_mask(bits);
    unsigned n = (result & sign) != 0U;
    unsigned z = (result & mask) == 0U;
    unsigned c = sub ? ((a & mask) >= (b & mask)) : ((result & mask) < (a & mask));
    unsigned v = sub ? ((((a ^ b) & (a ^ result)) & sign) != 0U) :
                       ((((~(a ^ b)) & (a ^ result)) & sign) != 0U);

    uy_win_set_nzcv(model, n, z, c, v);
}

/* DecodeBitMasks (ARM ARM C1.3.4) for the logical-immediate and bitfield
 * classes.  Every caller passes the same N/imms/immr fields; the result is
 * reported in both masks even when only one is used. */
static int uy_win_bitmask(unsigned n, unsigned imms, unsigned immr, unsigned bits,
                          uint64_t *wmask, uint64_t *tmask)
{
    unsigned len = 0, esize, levels, i;
    unsigned combined = (n << 6) | (~imms & 0x3fU);
    unsigned s, r, diff;
    uint64_t welem, telem, rotated;

    for (i = 0; i < 7U; ++i)
        if ((combined >> i) & 1U) len = i;
    if (!len) return 0;
    esize = 1U << len;
    if (esize > bits) return 0;
    /* The 32-bit forms are only defined for a 32-bit element size. */
    if (bits == 32U && esize < 32U) return 0;
    levels = esize - 1U;
    s = imms & levels;
    r = immr & levels;
    diff = (s - r) & levels;
    welem = s == levels ? uy_win_mask(esize) : uy_win_mask(s + 1U);
    telem = uy_win_mask(diff + 1U);
    rotated = uy_win_ror(welem, r, esize);
    *wmask = 0;
    *tmask = 0;
    for (i = 0; i < bits; i += esize) {
        *wmask |= rotated << i;
        *tmask |= telem << i;
    }
    *wmask &= uy_win_mask(bits);
    *tmask &= uy_win_mask(bits);
    return 1;
}

static uint64_t uy_win_rev_bytes(uint64_t value, unsigned granule, unsigned bits)
{
    uint64_t out = 0;
    unsigned bytes = bits / 8U;
    unsigned step = granule / 8U;
    unsigned i, j;

    for (i = 0; i < bytes; i += step) {
        for (j = 0; j < step; ++j)
            out |= ((value >> (8U * (i + j))) & 0xffU) << (8U * (i + step - 1U - j));
    }
    return out;
}

static uint64_t uy_win_bitrev(uint64_t value, unsigned bits)
{
    uint64_t out = 0;
    unsigned i;

    for (i = 0; i < bits; ++i)
        out = (out << 1) | ((value >> i) & 1U);
    return out;
}

static unsigned uy_win_clz(uint64_t value, unsigned bits)
{
    unsigned count = 0;
    uint64_t mask = UINT64_C(1) << (bits - 1U);

    while (count < bits && !(value & mask)) {
        mask >>= 1;
        ++count;
    }
    return count;
}

static unsigned uy_win_cls(uint64_t value, unsigned bits)
{
    unsigned sign = (unsigned)((value >> (bits - 1U)) & 1U);
    unsigned count = 0;
    int i;

    for (i = (int)bits - 2; i >= 0; --i) {
        if ((unsigned)((value >> (unsigned)i) & 1U) != sign) break;
        ++count;
    }
    return count;
}

/* One integer data-processing instruction of the window.  Returns 0 when the
 * class is not modeled; the caller then leaves the window native. */
static int uy_win_alu(struct uro_regs *model, uint32_t insn)
{
    /* NOP, BTI landing pads, HINT #imm and the DMB/DSB/ISB barriers change no
     * register, no monitored address and no memory.  PACIASP/AUTIASP and the
     * other pointer-authentication instructions do not match these masks. */
    if (insn == UY_NOP || insn == UY_BTI_C || insn == UY_BTI_J || insn == UY_BTI_JC)
        return 1;
    if ((insn & 0xfffff01fU) == 0xd503201fU) return 1;
    if ((insn & 0xfffff0ffU) == 0xd503309fU) return 1;
    if ((insn & 0xfffff0ffU) == 0xd50330bfU) return 1;
    if ((insn & 0xfffff0ffU) == 0xd50330dfU) return 1;

    /* Add/subtract (immediate).  Rn==31 is SP when S is clear. */
    if ((insn & 0x1f000000U) == 0x11000000U) {
        unsigned sf = insn >> 31;
        unsigned sub = (insn >> 30) & 1U;
        unsigned setf = (insn >> 29) & 1U;
        unsigned sh = (insn >> 22) & 1U;
        unsigned imm = (insn >> 10) & 0xfffU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        if (sh && !sf) return 0;
        if (rn == 31U && setf) return 0;
        a = (rn == 31U ? model->sp : model->x[rn]) & mask;
        b = ((uint64_t)imm << (sh ? 12 : 0)) & mask;
        result = (sub ? a - b : a + b) & mask;
        if (setf) uy_win_addsub_flags(model, a, b, result, bits, sub);
        if (rd == 31U) {
            if (!setf) model->sp = result;
        } else {
            model->x[rd] = result;
        }
        return 1;
    }

    /* Add/subtract (shifted register). */
    if ((insn & 0x1f200000U) == 0x0b000000U) {
        unsigned sf = insn >> 31;
        unsigned sub = (insn >> 30) & 1U;
        unsigned setf = (insn >> 29) & 1U;
        unsigned type = (insn >> 22) & 3U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned amount = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        if (type == 3U || (!sf && amount > 31U)) return 0;
        a = uy_win_gpr(model, rn) & mask;
        b = uy_win_shift(uy_win_gpr(model, rm), type, amount, bits);
        result = (sub ? a - b : a + b) & mask;
        if (setf) uy_win_addsub_flags(model, a, b, result, bits, sub);
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Logical (shifted register), including ANDS and the inverted forms. */
    if ((insn & 0x1f000000U) == 0x0a000000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned type = (insn >> 22) & 3U;
        unsigned invert = (insn >> 21) & 1U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned amount = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        if (!sf && amount > 31U) return 0;
        a = uy_win_gpr(model, rn) & mask;
        b = uy_win_shift(uy_win_gpr(model, rm), type, amount, bits);
        if (invert) b = ~b & mask;
        if (opc == 0U || opc == 3U) result = a & b;
        else if (opc == 1U) result = a | b;
        else result = a ^ b;
        result &= mask;
        if (opc == 3U) {
            uint64_t sign = UINT64_C(1) << (bits - 1U);

            uy_win_set_nzcv(model, (result & sign) != 0U, result == 0U, 0U, 0U);
        }
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Logical (immediate). */
    if ((insn & 0x1f800000U) == 0x12000000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned n = (insn >> 22) & 1U;
        unsigned immr = (insn >> 16) & 0x3fU;
        unsigned imms = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), wmask, tmask, a, result;

        if (!uy_win_bitmask(n, imms, immr, bits, &wmask, &tmask)) return 0;
        a = uy_win_gpr(model, rn) & mask;
        if (opc == 0U || opc == 3U) result = a & wmask;
        else if (opc == 1U) result = a | wmask;
        else result = a ^ wmask;
        result &= mask;
        if (opc == 3U) {
            uint64_t sign = UINT64_C(1) << (bits - 1U);

            uy_win_set_nzcv(model, (result & sign) != 0U, result == 0U, 0U, 0U);
        }
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Move wide (MOVN/MOVZ/MOVK). */
    if ((insn & 0x1f800000U) == 0x12800000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned hw = (insn >> 21) & 3U;
        unsigned imm = (insn >> 5) & 0xffffU;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), field = (uint64_t)imm << (hw * 16U);
        uint64_t result;

        if (opc == 1U || (!sf && hw > 1U)) return 0;
        if (opc == 0U) result = ~field & mask;
        else if (opc == 2U) result = field & mask;
        else {
            uint64_t keep = uy_win_gpr(model, rd) & ~(UINT64_C(0xffff) << (hw * 16U));

            result = (keep | field) & mask;
        }
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Bitfield (SBFM/UBFM/BFM): sign/zero extend, UBFX, and the LSL/LSR/ASR
     * immediate forms the compiler emits for plain shifts. */
    if ((insn & 0x1f800000U) == 0x13000000U) {
        unsigned sf = insn >> 31;
        unsigned opc = (insn >> 29) & 3U;
        unsigned n = (insn >> 22) & 1U;
        unsigned immr = (insn >> 16) & 0x3fU;
        unsigned imms = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), field, src, result;
        unsigned width, lsb;

        if (opc == 3U || imms >= bits || immr >= bits) return 0;
        /* N must repeat the width bit: N=0 only in the 32-bit forms. */
        if (n != sf) return 0;
        /* imms >= immr is the extract form (UBFX/SBFX/UXTB/ASR): the field
         * starts at source bit immr and is imms-immr+1 bits wide.
         * imms < immr is the insert form (UBFIZ/SBFIZ/LSL): the field is
         * imms+1 bits wide and its least-significant bit lands at
         * (-immr mod datasize).  A rotating copy of the source already puts
         * every bit where the instruction puts it, so one mask selects the
         * whole result. */
        if (imms >= immr) {
            width = imms - immr + 1U;
            field = uy_win_mask(width);
        } else {
            width = imms + 1U;
            lsb = bits - immr;
            field = uy_win_mask(width) << lsb;
        }
        src = uy_win_gpr(model, rn) & mask;
        result = uy_win_ror(src, immr, bits) & field & mask;
        if (opc == 1U) {
            /* BFM keeps the bits outside the field: BFI/BFXIL. */
            result |= uy_win_gpr(model, rd) & ~field & mask;
        }
        if (opc == 0U && imms >= immr) {
            /* SBFM sign-extends from the field's top bit (SBFX/SXTB/ASR). */
            uint64_t sign = UINT64_C(1) << imms;

            if (result & sign) result |= ~uy_win_mask(imms + 1U);
            result &= mask;
        }
        /* SBFM's insert form (SBFIZ) has a field-dependent sign bit that is not
         * covered by this proof: leave it native. */
        if (opc == 0U && imms < immr) return 0;
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Extract (EXTR): the rotate-immediate form. */
    if ((insn & 0x1f800000U) == 0x13800000U) {
        unsigned sf = insn >> 31;
        unsigned n = (insn >> 22) & 1U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned lsb = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), hi, lo, result;

        if ((sf && !n) || (!sf && n) || (!sf && lsb > 31U)) return 0;
        hi = uy_win_gpr(model, rn) & mask;
        lo = uy_win_gpr(model, rm) & mask;
        result = lsb ? ((lo >> lsb) | (hi << (bits - lsb))) & mask : lo;
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Conditional select (CSEL/CSINC/CSINV/CSNEG).  These read NZCV, which the
     * model carries in SPSR bits [31:28] and commits back through ERET. */
    if ((insn & 0x1fe00000U) == 0x1a800000U) {
        unsigned sf = insn >> 31;
        unsigned op = (insn >> 30) & 1U;
        unsigned op2 = (insn >> 10) & 3U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned cond = (insn >> 12) & 15U;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        a = uy_win_gpr(model, rn) & mask;
        b = uy_win_gpr(model, rm) & mask;
        /* op selects the invert/negate pair, op2 the select/increment pair:
         * CSEL 0/0, CSINC 0/1, CSINV 1/0, CSNEG 1/1. */
        if (uy_win_cond(model->pstate, cond)) {
            result = a;
        } else if (!op) {
            result = op2 ? (b + 1U) & mask : b;
        } else {
            result = op2 ? (UINT64_C(0) - b) & mask : ~b & mask;
        }
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Conditional compare (CCMP/CCMN): the flags are either the comparison or
     * the encoding's own NZCV field, selected by the same condition. */
    if ((insn & 0x3fe00010U) == 0x3a400000U) {
        unsigned op = insn >> 30 & 1U;
        unsigned immf = (insn >> 11) & 1U;
        unsigned cond = (insn >> 12) & 15U;
        unsigned rn = (insn >> 5) & 31U;
        unsigned bits = (insn >> 31) ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        if (!uy_win_cond(model->pstate, cond)) {
            uy_win_set_nzcv(model, (insn >> 3) & 1U, (insn >> 2) & 1U,
                            (insn >> 1) & 1U, insn & 1U);
            return 1;
        }
        a = uy_win_gpr(model, rn) & mask;
        if (immf) b = (uint64_t)((insn >> 16) & 0x1fU);
        else b = uy_win_gpr(model, (insn >> 16) & 31U) & mask;
        result = (op ? a - b : a + b) & mask;
        uy_win_addsub_flags(model, a, b, result, bits, op);
        return 1;
    }

    /* Data-processing (1 source): RBIT/REV16/REV32/REV/CLZ/CLS. */
    if ((insn & 0x5fe00000U) == 0x5ac00000U) {
        unsigned sf = insn >> 31;
        unsigned opcode = (insn >> 10) & 0x3fU;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), src, result;

        src = uy_win_gpr(model, rn) & mask;
        switch (opcode) {
        case 0: result = uy_win_bitrev(src, bits); break;
        case 1: result = uy_win_rev_bytes(src, 16U, bits); break;
        case 2: result = uy_win_rev_bytes(src, 32U, bits); break;
        case 3:
            if (!sf) return 0;
            result = uy_win_rev_bytes(src, bits, bits);
            break;
        case 4: result = uy_win_clz(src, bits); break;
        case 5: result = uy_win_cls(src, bits); break;
        default: return 0;
        }
        if (rd != 31U) model->x[rd] = result & mask;
        return 1;
    }

    /* Data-processing (2 source): UDIV/SDIV and the variable shifts. */
    if ((insn & 0x5fe00000U) == 0x1ac00000U) {
        unsigned sf = insn >> 31;
        unsigned opcode = (insn >> 10) & 0x3fU;
        unsigned rm = (insn >> 16) & 31U;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), a, b, result;

        a = uy_win_gpr(model, rn) & mask;
        b = uy_win_gpr(model, rm) & mask;
        switch (opcode) {
        case 2: result = b ? (a / b) & mask : 0; break;
        case 3:
            if (!b) {
                result = 0;
            } else if (bits == 64U) {
                int64_t sa = (int64_t)a, sb = (int64_t)b;

                if (sb == -1 && sa == (int64_t)UINT64_C(0x8000000000000000))
                    result = a;
                else
                    result = (uint64_t)(sa / sb);
            } else {
                int32_t sa = (int32_t)a, sb = (int32_t)b;

                if (sb == -1 && sa == (int32_t)0x80000000)
                    result = a;
                else
                    result = (uint32_t)(sa / sb);
            }
            break;
        case 8: result = uy_win_shift(a, 0U, (unsigned)(b & (bits - 1U)), bits); break;
        case 9: result = uy_win_shift(a, 1U, (unsigned)(b & (bits - 1U)), bits); break;
        case 10: result = uy_win_shift(a, 2U, (unsigned)(b & (bits - 1U)), bits); break;
        case 11: result = uy_win_shift(a, 3U, (unsigned)(b & (bits - 1U)), bits); break;
        default: return 0;
        }
        if (rd != 31U) model->x[rd] = result & mask;
        return 1;
    }

    /* Data-processing (3 source): MADD/MSUB, including MUL (Ra==XZR). */
    if ((insn & 0x1f000000U) == 0x1b000000U) {
        unsigned sf = insn >> 31;
        unsigned op54 = (insn >> 29) & 3U;
        unsigned op31 = (insn >> 21) & 7U;
        unsigned sub = (insn >> 15) & 1U;
        unsigned ra = (insn >> 10) & 31U;
        unsigned rm = (insn >> 16) & 31U;
        unsigned rn = (insn >> 5) & 31U;
        unsigned rd = insn & 31U;
        unsigned bits = sf ? 64U : 32U;
        uint64_t mask = uy_win_mask(bits), product, addend, result;

        if (op54 != 0U || op31 != 0U) return 0;
        product = (uy_win_gpr(model, rn) * uy_win_gpr(model, rm)) & mask;
        addend = uy_win_gpr(model, ra) & mask;
        result = (sub ? addend - product : addend + product) & mask;
        if (rd != 31U) model->x[rd] = result;
        return 1;
    }

    /* Address generation (ADR/ADRP). */
    if ((insn & 0x1f000000U) == 0x10000000U) {
        unsigned op = insn >> 31;
        unsigned rd = insn & 31U;
        unsigned long long imm = ((unsigned long long)((insn >> 5) & 0x7ffffU) << 2) |
                                 ((insn >> 29) & 3U);
        uint64_t offset = (uint64_t)uy_win_sx(imm, 21);
        uint64_t base = op ? (model->pc & ~UINT64_C(0xfff)) : model->pc;

        if (op) offset <<= 12;
        if (rd != 31U) model->x[rd] = base + offset;
        return 1;
    }

    return 0;
}

/* One in-window control-flow instruction.  Only transfers that stay inside the
 * bounded window are modeled; a call leaves the window and is declined. */
static int uy_win_branch(struct uro_regs *model, uint32_t insn, uint64_t at)
{
    uint64_t target;

    if ((insn & 0xfc000000U) == 0x14000000U) {            /* B */
        target = at + (uint64_t)uy_win_sx((uint64_t)(insn & 0x03ffffffU) << 2, 28);
        model->pc = target;
        return 1;
    }
    if ((insn & 0xfc000000U) == 0x94000000U) {            /* BL */
        target = at + (uint64_t)uy_win_sx((uint64_t)(insn & 0x03ffffffU) << 2, 28);
        model->x[30] = at + 4U;
        model->pc = target;
        return 1;
    }
    if ((insn & 0xfffffc1fU) == 0xd63f0000U) {            /* BLR */
        unsigned rn = (insn >> 5) & 31U;

        target = uy_win_gpr(model, rn);
        model->x[30] = at + 4U;
        model->pc = target;
        return 1;
    }
    if ((insn & 0xfffffc1fU) == 0xd61f0000U) {            /* BR */
        model->pc = uy_win_gpr(model, (insn >> 5) & 31U);
        return 1;
    }
    if ((insn & 0xfffffc1fU) == 0xd65f0000U) {            /* RET */
        model->pc = uy_win_gpr(model, (insn >> 5) & 31U);
        return 1;
    }
    if ((insn & 0xff000010U) == 0x54000000U) {            /* B.cond */
        target = at + (uint64_t)uy_win_sx((uint64_t)((insn >> 5) & 0x7ffffU) << 2, 21);
        model->pc = uy_win_cond(model->pstate, insn & 15U) ? target : at + 4U;
        return 1;
    }
    if ((insn & 0x7e000000U) == 0x34000000U) {            /* CBZ/CBNZ */
        unsigned nz = (insn >> 24) & 1U;
        unsigned rt = insn & 31U;
        uint64_t value = uy_win_gpr(model, rt);

        if (!(insn >> 31)) value &= 0xffffffffU;
        target = at + (uint64_t)uy_win_sx((uint64_t)((insn >> 5) & 0x7ffffU) << 2, 21);
        model->pc = (value == 0) != (nz != 0U) ? target : at + 4U;
        return 1;
    }
    if ((insn & 0x7e000000U) == 0x36000000U) {            /* TBZ/TBNZ */
        unsigned nz = (insn >> 24) & 1U;
        unsigned bit = ((insn >> 26) & 0x20U) | ((insn >> 19) & 0x1fU);
        unsigned rt = insn & 31U;
        unsigned set = (unsigned)((uy_win_gpr(model, rt) >> bit) & 1U);

        target = at + (uint64_t)uy_win_sx((uint64_t)((insn >> 5) & 0x3fffU) << 2, 16);
        model->pc = (set != 0U) == (nz != 0U) ? target : at + 4U;
        return 1;
    }
    return 0;
}

/* Destination of one uy_win_alu() instruction:
 *   0..30  GPR number
 *   31     discard (XZR/WZR)
 *   32     no GPR destination (NOP, barrier, CCMP/CCMN, flags-only ADDS)
 *   33     SP (add/sub immediate with Rd==31 and S==0)
 *   34     not an instruction uy_win_alu() accepts.
 * Used by the pre-load verifier, which may only prove an in-place update of
 * the LDXR destination and must reject SP or any other register write. */
static inline unsigned uy_win_dst(uint32_t insn)
{
    unsigned rd = insn & 31U;

    if (insn == UY_NOP || insn == UY_BTI_C || insn == UY_BTI_J || insn == UY_BTI_JC)
        return 32U;
    if ((insn & 0xfffff01fU) == 0xd503201fU) return 32U;  /* HINT #imm */
    if ((insn & 0xfffff0ffU) == 0xd503309fU) return 32U;  /* DMB */
    if ((insn & 0xfffff0ffU) == 0xd50330bfU) return 32U;  /* DSB */
    if ((insn & 0xfffff0ffU) == 0xd50330dfU) return 32U;  /* ISB */
    if ((insn & 0x3fe00010U) == 0x3a400000U) return 32U;  /* CCMP/CCMN */

    if ((insn & 0x1f000000U) == 0x11000000U) {           /* add/sub immediate */
        unsigned setf = (insn >> 29) & 1U;

        if (rd == 31U) return setf ? 32U : 33U;
        return rd;
    }
    if ((insn & 0x1f200000U) == 0x0b000000U) return rd;   /* add/sub shifted */
    if ((insn & 0x1f000000U) == 0x0a000000U) return rd;   /* logical shifted */
    if ((insn & 0x1f800000U) == 0x12000000U) return rd;   /* logical immediate */
    if ((insn & 0x1f800000U) == 0x12800000U) return rd;   /* move wide */
    if ((insn & 0x1f800000U) == 0x13000000U) return rd;   /* bitfield */
    if ((insn & 0x1f800000U) == 0x13800000U) return rd;   /* extract */
    if ((insn & 0x1fe00000U) == 0x1a800000U) return rd;   /* conditional select */
    if ((insn & 0x5fe00000U) == 0x5ac00000U) return rd;   /* 1 source */
    if ((insn & 0x5fe00000U) == 0x1ac00000U) return rd;   /* 2 source */
    if ((insn & 0x1f000000U) == 0x1b000000U) return rd;   /* 3 source */
    if ((insn & 0x1f000000U) == 0x10000000U) return rd;   /* ADR/ADRP */
    return 34U;
}

/* Instructions whose result depends on the incoming NZCV.  The pre-load
 * verifier cannot reconstruct the flags from before the LDXR, so it rejects
 * them; post-load CSEL/CCMP are modeled against the current SPSR. */
static inline int uy_win_reads_flags(uint32_t insn)
{
    if ((insn & 0x1fe00000U) == 0x1a800000U) return 1;   /* CSEL/CSINC/... */
    if ((insn & 0x3fe00010U) == 0x3a400000U) return 1;   /* CCMP/CCMN */
    return 0;
}

/* GPR operands read by one uy_win_alu() instruction.  Bit r means x[r] is
 * read (XZR is never a register); 0xffffffff marks a class this helper cannot
 * enumerate, which the pre-load verifier declines.  SP is not bit-mapped: an
 * accepted pre-window never rewrites SP, so the fault-time SP is also the value
 * the original instruction read. */
static inline uint32_t uy_win_srcs(uint32_t insn)
{
    unsigned opc = (insn >> 29) & 3U;
    unsigned rn = (insn >> 5) & 31U;
    unsigned rm = (insn >> 16) & 31U;
    unsigned ra = (insn >> 10) & 31U;
    unsigned rd = insn & 31U;
    uint32_t mask = 0;

    if (insn == UY_NOP || insn == UY_BTI_C || insn == UY_BTI_J || insn == UY_BTI_JC)
        return 0;
    if ((insn & 0xfffff01fU) == 0xd503201fU) return 0;   /* HINT #imm */
    if ((insn & 0xfffff0ffU) == 0xd503309fU) return 0;   /* DMB */
    if ((insn & 0xfffff0ffU) == 0xd50330bfU) return 0;   /* DSB */
    if ((insn & 0xfffff0ffU) == 0xd50330dfU) return 0;   /* ISB */

    if ((insn & 0x1f000000U) == 0x11000000U) {           /* add/sub immediate */
        if (rn != 31U) mask |= 1U << rn;
        return mask;
    }
    if ((insn & 0x1f200000U) == 0x0b000000U) {           /* add/sub shifted */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x1f000000U) == 0x0a000000U) {           /* logical shifted */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x1f800000U) == 0x12000000U)             /* logical immediate */
        return rn == 31U ? 0 : 1U << rn;
    if ((insn & 0x1f800000U) == 0x12800000U) {           /* move wide */
        if (opc == 3U && rd != 31U) mask |= 1U << rd;     /* MOVK keeps Rd */
        return mask;
    }
    if ((insn & 0x1f800000U) == 0x13000000U) {           /* bitfield */
        if (rn != 31U) mask |= 1U << rn;
        if (opc == 1U && rd != 31U) mask |= 1U << rd;     /* BFM keeps Rd */
        return mask;
    }
    if ((insn & 0x1f800000U) == 0x13800000U) {           /* extract */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x1fe00000U) == 0x1a800000U) {           /* cond select */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x3fe00010U) == 0x3a400000U) {           /* ccmp/ccmn */
        if (rn != 31U) mask |= 1U << rn;
        if (!((insn >> 11) & 1U) && rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x5fe00000U) == 0x5ac00000U)             /* 1 source */
        return rn == 31U ? 0 : 1U << rn;
    if ((insn & 0x5fe00000U) == 0x1ac00000U) {           /* 2 source */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        return mask;
    }
    if ((insn & 0x1f000000U) == 0x1b000000U) {           /* 3 source */
        if (rn != 31U) mask |= 1U << rn;
        if (rm != 31U) mask |= 1U << rm;
        if (ra != 31U) mask |= 1U << ra;
        return mask;
    }
    if ((insn & 0x1f000000U) == 0x10000000U) return 0;   /* ADR/ADRP */
    return 0xffffffffU;
}

static inline uint64_t uy_win_fp_get(const struct uy_fpstate *fp, unsigned reg,
                              unsigned off, unsigned bytes)
{
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < bytes; ++i)
        value |= (uint64_t)fp->vregs[reg][off + i] << (8U * i);
    return value;
}

static inline void uy_win_fp_put(struct uy_fpstate *fp, unsigned reg, unsigned off,
                          unsigned bytes, uint64_t value)
{
    unsigned i;

    for (i = 0; i < bytes; ++i)
        fp->vregs[reg][off + i] = (uint8_t)(value >> (8U * i));
}

/* FMOV between one GPR and one scalar/128-bit-lane FPSIMD register.  These
 * move bits unchanged: they do not convert, set flags or touch memory.  The
 * scalar forms zero the unused bytes of the destination V register; the
 * .D[1]/S[1] lane forms preserve the other lane. */
static inline int uy_win_fp_move(struct uro_regs *model, struct uy_fpstate *fp,
                                 uint32_t insn, int have_fp16)
{
    if ((insn & 0xfffffc00U) == 0x9e670000U) {           /* FMOV Dd, Xn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t v = uy_win_gpr(model, rn);

        uy_win_fp_put(fp, rd, 0, 8, v);
        uy_win_fp_put(fp, rd, 8, 8, 0);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x9e660000U) {           /* FMOV Xd, Dn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;

        if (rd != 31U) model->x[rd] = uy_win_fp_get(fp, rn, 0, 8);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x1e270000U) {           /* FMOV Sd, Wn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t v = uy_win_gpr(model, rn) & 0xffffffffU;

        uy_win_fp_put(fp, rd, 0, 4, v);
        uy_win_fp_put(fp, rd, 4, 12, 0);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x1e260000U) {           /* FMOV Wd, Sn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;

        if (rd != 31U) model->x[rd] = uy_win_fp_get(fp, rn, 0, 4);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x1ee70000U) {           /* FMOV Hd, Wn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t v = uy_win_gpr(model, rn) & 0xffffU;

        if (!have_fp16) return 0;
        uy_win_fp_put(fp, rd, 0, 2, v);
        uy_win_fp_put(fp, rd, 2, 14, 0);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x1ee60000U) {           /* FMOV Wd, Hn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;

        if (!have_fp16) return 0;
        if (rd != 31U) model->x[rd] = uy_win_fp_get(fp, rn, 0, 2);
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x9eaf0000U) {           /* FMOV Vd.D[1], Xn */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;

        uy_win_fp_put(fp, rd, 8, 8, uy_win_gpr(model, rn));
        return 1;
    }
    if ((insn & 0xfffffc00U) == 0x9eae0000U) {           /* FMOV Xd, Vn.D[1] */
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;

        if (rd != 31U) model->x[rd] = uy_win_fp_get(fp, rn, 8, 8);
        return 1;
    }
    return 0;
}

/* True when the instruction is one of the FP moves above; the backend uses
 * this to take the FPSIMD snapshot only for a window that actually needs it. */
static inline int uy_win_fp_insn(uint32_t insn, int have_fp16)
{
    switch (insn & 0xfffffc00U) {
    case 0x9e670000U:
    case 0x9e660000U:
    case 0x1e270000U:
    case 0x1e260000U:
    case 0x9eaf0000U:
    case 0x9eae0000U:
        return 1;
    case 0x1ee70000U:
    case 0x1ee60000U:
        return have_fp16;
    default:
        return 0;
    }
}

/* General-register destination of a SIMD&FP instruction, for the pre-load
 * verifier.  Only the transfers below name a general register; every other
 * instruction in the SIMD&FP data-processing groups writes vector registers
 * alone, so 32 is returned for it - including encodings this helper does not
 * enumerate, because an encoding that traps at EL0 can never appear in an
 * executed pre-load span.  The GPR destination is always bits[4:0], which is
 * what makes the returned number trustworthy for this one purpose. */
static inline int uy_win_fp_gpr_dst(uint32_t insn)
{
    unsigned op;

    switch (insn & 0xfffffc00U) {
    case 0x9e660000U:                    /* FMOV Xd, Dn */
    case 0x1e260000U:                    /* FMOV Wd, Sn */
    case 0x1ee60000U:                    /* FMOV Wd, Hn */
    case 0x9eae0000U:                    /* FMOV Xd, Vn.D[1] */
        return (int)(insn & 31U);
    default:
        break;
    }
    if (uy_win_fp_insn(insn, 1)) return 32;
    /* UMOV/SMOV element to general register (aliases of MOV Wd/Xd, Vn.<T>[i]).
     * Bit 31 is fixed zero, bit 30 is the Q size, imm5 is [20:16]. */
    if ((insn & 0xbfe0fc00U) == 0x0e003c00U ||
        (insn & 0xbfe0fc00U) == 0x0e002c00U)
        return (int)(insn & 31U);
    /* Scalar FP -> integer conversion, including the FP16 forms. */
    if ((insn & 0x5f20fc00U) == 0x1e200000U) {
        op = (insn >> 16) & 0x1fU;
        if (op == 2U || op == 3U) return 32;   /* SCVTF / UCVTF */
        return (int)(insn & 31U);
    }
    return 32;
}

/* True for a SIMD&FP data-processing encoding group (bits[28:25] are 0111 or
 * 1111): the scalar and vector arithmetic, permutation, immediate, copy and
 * conversion instructions.  Loads, stores, branches, system instructions and
 * integer data processing use other groups. */
static inline int uy_win_fp_group(uint32_t insn)
{
    return (insn & 0x1e000000U) == 0x0e000000U ||
           (insn & 0x1e000000U) == 0x1e000000U;
}

/* ------------------------------- Advanced SIMD integer data processing
 *
 * 2.21.0 stopped the whole window at the first SIMD/FP data-processing
 * instruction.  A detector could therefore put a single vector instruction
 * between its sampled load and the STXR and read the reservation loss even
 * though the module modeled every scalar instruction.  The three-same integer
 * families below are pure register operations on the FPSIMD file, so they can
 * be replayed bit-exactly: logical (AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF), integer
 * add/sub, the compare family, min/max, multiply/accumulate and the register
 * shifts.  Everything else (FP arithmetic and conversion, permutes, immediate
 * forms, memory) still declines, which leaves the native instructions in
 * charge.
 *
 * Only the low 8 bytes of a Q=0 destination are written; the architecture
 * clears the upper 64 bits of the register, which the model does as well. */

static inline uint64_t uy_win_vec_lane(const uint8_t *v, unsigned lane, unsigned bytes)
{
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < bytes; ++i)
        value |= (uint64_t)v[lane * bytes + i] << (8U * i);
    return value;
}

static inline void uy_win_vec_put(uint8_t *v, unsigned lane, unsigned bytes, uint64_t value)
{
    unsigned i;

    for (i = 0; i < bytes; ++i)
        v[lane * bytes + i] = (uint8_t)(value >> (8U * i));
}

/* Bitmask of an element of `bytes` bytes; bytes == 8 yields all ones. */
static inline uint64_t uy_win_vec_mask(unsigned bytes)
{
    return bytes >= 8U ? ~UINT64_C(0) : (UINT64_C(1) << (8U * bytes)) - 1U;
}

static inline int64_t uy_win_vec_sx(uint64_t value, unsigned bytes)
{
    return (int64_t)((value ^ (UINT64_C(1) << (8U * bytes - 1U))) -
                     (UINT64_C(1) << (8U * bytes - 1U)));
}

/* True for the encodings uy_win_simd() handles.  Derived from the assembler
 * output for every accepted mnemonic; see tests/urov_window_test.c. */
static inline int uy_win_simd_insn(uint32_t insn)
{
    unsigned opcode;
    unsigned size;
    unsigned u;

    if ((insn & 0x9f200000U) != 0x0e200000U) return 0;   /* three same */
    opcode = (insn >> 11) & 0x1fU;
    size = (insn >> 22) & 3U;
    u = (insn >> 29) & 1U;

    switch (opcode) {
    case 3:                                              /* logical */
    case 6:                                              /* CMGT/CMHI */
    case 7:                                              /* CMGE/CMHS */
    case 8:                                              /* SSHL/USHL */
    case 16:                                             /* ADD/SUB */
    case 17:                                             /* CMEQ/CMTST */
        return 1;
    case 12:                                             /* SMAX/UMAX */
    case 13:                                             /* SMIN/UMIN */
    case 18:                                             /* MLA/MLS */
        return size < 3U;                                /* no 64-bit lanes */
    case 19:                                             /* MUL */
        return !u && size < 3U;
    default:
        return 0;
    }
}

/* Replay one three-same integer instruction on the FPSIMD mirror.  Returns 0
 * for every encoding outside the accepted set; the caller then declines the
 * whole window and the native instructions run unchanged. */
static inline int uy_win_simd(struct uro_regs *model, struct uy_fpstate *fp, uint32_t insn)
{
    unsigned q = (insn >> 30) & 1U;
    unsigned u = (insn >> 29) & 1U;
    unsigned size = (insn >> 22) & 3U;
    unsigned opcode = (insn >> 11) & 0x1fU;
    unsigned rm = (insn >> 16) & 31U;
    unsigned rn = (insn >> 5) & 31U;
    unsigned rd = insn & 31U;
    unsigned bytes = q ? 16U : 8U;
    unsigned esize = 1U << size;
    unsigned lanes = bytes / esize;
    uint8_t *d = fp->vregs[rd];
    const uint8_t *n = fp->vregs[rn];
    const uint8_t *m = fp->vregs[rm];
    uint64_t mask = uy_win_vec_mask(esize);
    unsigned i, b;

    (void)model;
    if (!uy_win_simd_insn(insn)) return 0;

    if (opcode == 3U) {                                  /* logical */
        for (b = 0; b < bytes; ++b) {
            uint8_t dn = n[b], dm = m[b], dd = d[b];

            if (!u) {
                if (size == 0U) d[b] = dn & dm;
                else if (size == 1U) d[b] = dn & (uint8_t)~dm;
                else if (size == 2U) d[b] = dn | dm;
                else d[b] = dn | (uint8_t)~dm;
            } else if (size == 0U) {
                d[b] = dn ^ dm;
            } else if (size == 1U) {                     /* BSL: Vd selects */
                d[b] = (uint8_t)((dd & dn) | (~dd & dm));
            } else if (size == 2U) {                     /* BIT: 1 -> Vn */
                d[b] = (uint8_t)((dn & dm) | (dd & ~dm));
            } else {                                     /* BIF: 0 -> Vn */
                d[b] = (uint8_t)((dn & ~dm) | (dd & dm));
            }
        }
        goto done;
    }

    if (opcode == 16U) {                                 /* add/sub */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);

            uy_win_vec_put(d, i, esize, (u ? a - c : a + c) & mask);
        }
        goto done;
    }
    if (opcode == 17U) {                                 /* CMEQ/CMTST */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);
            uint64_t hit = u ? (a == c) : ((a & c) != 0U);

            uy_win_vec_put(d, i, esize, hit ? mask : 0);
        }
        goto done;
    }
    if (opcode == 6U || opcode == 7U) {                  /* compare */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);
            int hit;

            if (opcode == 6U)
                hit = u ? (a > c) : (uy_win_vec_sx(a, esize) > uy_win_vec_sx(c, esize));
            else
                hit = u ? (a >= c) : (uy_win_vec_sx(a, esize) >= uy_win_vec_sx(c, esize));
            uy_win_vec_put(d, i, esize, hit ? mask : 0);
        }
        goto done;
    }
    if (opcode == 12U || opcode == 13U) {                /* max/min */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);
            int take_n;

            if (opcode == 12U)
                take_n = u ? (a > c) : (uy_win_vec_sx(a, esize) > uy_win_vec_sx(c, esize));
            else
                take_n = u ? (a < c) : (uy_win_vec_sx(a, esize) < uy_win_vec_sx(c, esize));
            uy_win_vec_put(d, i, esize, take_n ? a : c);
        }
        goto done;
    }
    if (opcode == 19U) {                                 /* MUL */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);

            uy_win_vec_put(d, i, esize, (a * c) & mask);
        }
        goto done;
    }
    if (opcode == 18U) {                                 /* MLA/MLS */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            uint64_t c = uy_win_vec_lane(m, i, esize);
            uint64_t acc = uy_win_vec_lane(d, i, esize);

            uy_win_vec_put(d, i, esize, (u ? acc - a * c : acc + a * c) & mask);
        }
        goto done;
    }
    if (opcode == 8U) {                                  /* SSHL/USHL */
        for (i = 0; i < lanes; ++i) {
            uint64_t a = uy_win_vec_lane(n, i, esize);
            int shift = (int)(int8_t)uy_win_vec_lane(m, i, esize);
            unsigned bits = esize * 8U;
            uint64_t result;

            if (shift >= 0) {
                result = (unsigned)shift >= bits ? 0 : (a << (unsigned)shift) & mask;
            } else if (u) {
                result = (unsigned)(-shift) >= bits ? 0 : a >> (unsigned)(-shift);
            } else if ((unsigned)(-shift) >= bits) {
                result = (uint64_t)(uy_win_vec_sx(a, esize) < 0 ? -1 : 0);
            } else {
                result = (uint64_t)(uy_win_vec_sx(a, esize) >> (unsigned)(-shift));
            }
            uy_win_vec_put(d, i, esize, result & mask);
        }
        goto done;
    }
    return 0;

done:
    if (!q) {
        for (b = 8U; b < 16U; ++b) d[b] = 0;
    }
    return 1;
}

/* Two-register byte-reversal permutes: REV64, REV32 and REV16.  They are pure
 * lane shuffles and write no FPSR.  Q=0 writes the low 64 bits and clears the
 * high half, as for the three-same family above. */
static inline int uy_win_simd_permute_insn(uint32_t insn)
{
    unsigned opcode, u, size;

    if ((insn & 0x9f200c00U) != 0x0e200800U) return 0;
    opcode = (insn >> 12) & 0x1fU;
    u = (insn >> 29) & 1U;
    size = (insn >> 22) & 3U;
    if (size != 0U) return 0;
    return (opcode == 0U) || (opcode == 1U && u == 0U);
}

static inline int uy_win_simd_permute(struct uy_fpstate *fp, uint32_t insn)
{
    unsigned q = (insn >> 30) & 1U;
    unsigned u = (insn >> 29) & 1U;
    unsigned opcode = (insn >> 12) & 0x1fU;
    unsigned rn = (insn >> 5) & 31U;
    unsigned rd = insn & 31U;
    unsigned bytes = q ? 16U : 8U;
    uint8_t out[16];
    const uint8_t *n = fp->vregs[rn];
    unsigned i, b;

    if (!uy_win_simd_permute_insn(insn)) return 0;
    for (i = 0; i < bytes; ++i) {
        unsigned unit;

        if (opcode == 0U)
            unit = u ? 4U : 8U;                            /* REV32 / REV64 */
        else
            unit = 2U;                                     /* REV16 */
        b = (i / unit) * unit + (unit - 1U - (i % unit));
        out[i] = n[b];
    }
    for (b = 0; b < bytes; ++b) fp->vregs[rd][b] = out[b];
    if (!q) {
        for (b = 8U; b < 16U; ++b) fp->vregs[rd][b] = 0;
    }
    return 1;
}

/* MRS/MSR of the user-visible state the window can carry exactly.  NZCV is
 * the SPSR copy; FPCR/FPSR live in the FPSIMD image; the MRS forms of
 * TPIDR_EL0/TPIDRRO_EL0/CNTFRQ_EL0/CTR_EL0/DCZID_EL0 return what the running
 * task sees.  Writes to TPIDR_EL0, counter reads (CNTVCT_EL0) and random
 * numbers are deliberately not modeled: the first needs a deferred write, and
 * the others are timing observations rather than reproducible state. */
static inline int uy_win_sysreg(struct uro_regs *model, struct uy_fpstate *fp, uint32_t insn)
{
    unsigned rt = insn & 31U;
    uint64_t value;

    if ((insn & 0xffff0000U) != 0xd53b0000U && (insn & 0xffff0000U) != 0xd51b0000U)
        return 0;
    /* Rt is bits[4:0]; the register identity is bits[15:5].  2.26.0 masks Rt
     * off, so an MRS/MSR that names any destination register is modeled
     * instead of only the Rt==0 forms the earlier tests happened to use. */
    switch (insn & 0x0000ffe0U) {
    case 0x4200U:                                        /* NZCV */
        if ((insn >> 21) & 1U) {
            if (rt != 31U) model->x[rt] = model->pstate & (UINT64_C(0xf) << 28);
        } else {
            value = uy_win_gpr(model, rt);
            model->pstate = (model->pstate & ~(UINT64_C(0xf) << 28)) |
                            (value & (UINT64_C(0xf) << 28));
        }
        return 1;
    case 0x4400U:                                        /* FPCR */
        if ((insn >> 21) & 1U) {
            if (rt != 31U) model->x[rt] = fp->fpcr;
        } else {
            fp->fpcr = (uint32_t)uy_win_gpr(model, rt);
        }
        return 1;
    case 0x4420U:                                        /* FPSR */
        if ((insn >> 21) & 1U) {
            if (rt != 31U) model->x[rt] = fp->fpsr;
        } else {
            fp->fpsr = (uint32_t)uy_win_gpr(model, rt);
        }
        return 1;
    case 0xd040U:                                        /* TPIDR_EL0 */
        if (!((insn >> 21) & 1U)) return 0;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(value));
        if (rt != 31U) model->x[rt] = value;
        return 1;
    case 0xd060U:                                        /* TPIDRRO_EL0 */
        if (!((insn >> 21) & 1U)) return 0;
        __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(value));
        if (rt != 31U) model->x[rt] = value;
        return 1;
    case 0xe000U:                                        /* CNTFRQ_EL0 */
        if (!((insn >> 21) & 1U)) return 0;
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(value));
        if (rt != 31U) model->x[rt] = value;
        return 1;
    case 0x0020U:                                        /* CTR_EL0 */
        if (!((insn >> 21) & 1U)) return 0;
        __asm__ volatile("mrs %0, ctr_el0" : "=r"(value));
        if (rt != 31U) model->x[rt] = value;
        return 1;
    case 0x00e0U:                                        /* DCZID_EL0 */
        if (!((insn >> 21) & 1U)) return 0;
        __asm__ volatile("mrs %0, dczid_el0" : "=r"(value));
        if (rt != 31U) model->x[rt] = value;
        return 1;
    default:
        return 0;
    }
}

/* Whether uy_win_sysreg() needs the FPSIMD image (FPCR/FPSR). */
static inline int uy_win_sysreg_fp(uint32_t insn)
{
    uint32_t key = insn & 0x0000ffe0U;

    return ((insn & 0xffff0000U) == 0xd53b0000U ||
            (insn & 0xffff0000U) == 0xd51b0000U) &&
           (key == 0x4400U || key == 0x4420U);
}

/* Static form of the same whitelist, for the read-before proof.  Every other
 * system-register encoding traps at EL0, and an instruction that traps delivers
 * an exception, which clears the local monitor; the proof therefore has to
 * decline those instead of assuming a register write. */
static inline int uy_win_sysreg_ok(uint32_t insn)
{
    if ((insn & 0xffff0000U) != 0xd53b0000U && (insn & 0xffff0000U) != 0xd51b0000U)
        return 0;
    switch (insn & 0x0000ffe0U) {
    case 0x4200U:                        /* NZCV */
    case 0x4400U:                        /* FPCR */
    case 0x4420U:                        /* FPSR */
    case 0xd040U:                        /* TPIDR_EL0 */
        return 1;                        /* readable and writable at EL0 */
    case 0xd060U:                        /* TPIDRRO_EL0 */
    case 0xe000U:                        /* CNTFRQ_EL0 */
    case 0xe040U:                        /* CNTVCT_EL0 */
    case 0x0020U:                        /* CTR_EL0 */
    case 0x00e0U:                        /* DCZID_EL0 */
        return (insn >> 21) & 1U;        /* read-only */
    default:
        return 0;
    }
}

#endif
