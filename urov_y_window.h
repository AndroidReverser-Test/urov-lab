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
 * base is still the monitored address.
 *
 * Everything the model cannot reproduce makes the walk decline, and the native
 * instructions then run: CLREX, a second exclusive, a monitor-clobbering store,
 * an exception, a call, a system register access, SIMD&FP, or a transfer out of
 * the bounded window.  For CLREX, a second exclusive and an exception the
 * native outcome is the failure the unmodified hardware would also report, so
 * declining there reproduces the architecture rather than hiding it.
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
    if ((insn & 0xfc000000U) == 0x94000000U) return 0;    /* BL: a call */
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

#endif
