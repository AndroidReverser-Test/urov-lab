/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "decode.h"

#define URO_U64_MAX (~(uint64_t)0)

static int add_magnitude(uint64_t base, uint64_t magnitude, int negative,
                         uint64_t *result)
{
    if (negative) {
        if (base < magnitude)
            return -1;
        *result = base - magnitude;
    } else {
        if (magnitude > URO_U64_MAX - base)
            return -1;
        *result = base + magnitude;
    }
    return 0;
}

/* Two's-complement displacement, without signed shifts or signed overflow. */
static int add_immediate(uint64_t base, unsigned field, unsigned bits,
                         unsigned scale, uint64_t *result)
{
    unsigned sign = 1U << (bits - 1);
    unsigned mask = (1U << bits) - 1U;
    int negative = (field & sign) != 0;
    uint64_t magnitude = negative ? ((~field + 1U) & mask) : field;
    return add_magnitude(base, magnitude << scale, negative, result);
}

static int base_value(const struct uro_regs *regs, unsigned rn, uint64_t *base)
{
    *base = rn == 31 ? regs->sp : regs->x[rn];
    /* CheckSPAlignment tests SP itself, not the effective address. */
    return rn == 31 && (*base & 15U) ? -1 : 0;
}

static int single_type(uint32_t insn, struct uro_load *load)
{
    unsigned size_log2 = insn >> 30;
    unsigned opc = (insn >> 22) & 3U;
    load->size = 1U << size_log2;
    load->count = 1;
    if (opc == 1) {
        load->dest_bits = size_log2 == 3 ? 64 : 32;
        return 0;
    }
    if (opc == 2 && size_log2 < 3) {
        load->sign_extend = 1;
        load->dest_bits = 64;
        return 0;
    }
    if (opc == 3 && size_log2 < 2) {
        load->sign_extend = 1;
        load->dest_bits = 32;
        return 0;
    }
    return -1; /* Stores, prefetches, and reserved size/opc combinations. */
}

static int register_offset(uint32_t insn, const struct uro_regs *regs,
                            uint64_t base, unsigned shift, uint64_t *address)
{
    unsigned rm = (insn >> 16) & 31U;
    unsigned option = (insn >> 13) & 7U;
    uint64_t value = rm == 31 ? 0 : regs->x[rm];
    uint64_t magnitude;
    int negative = 0;
    switch (option) {
    case 2: /* UXTW */
        value &= 0xffffffffU;
        break;
    case 3: /* LSL (UXTX) */
        break;
    case 6: /* SXTW */
        value &= 0xffffffffU;
        negative = (value & 0x80000000U) != 0;
        if (negative)
            value = ((~value) + 1U) & 0xffffffffU;
        break;
    case 7: /* SXTX */
        negative = (value >> 63) != 0;
        if (negative)
            value = (~value) + 1U;
        break;
    default:
        return -1;
    }
    magnitude = value;
    if (magnitude > (URO_U64_MAX >> shift))
        return -1;
    return add_magnitude(base, magnitude << shift, negative, address);
}

/* SIMD&FP load element width.  opc[0] is the load bit, so a store is rejected
 * and keeps its native fault; opc[1] selects the 128-bit form and is only
 * allocated together with size == 0.  scale is the log2 of the access size,
 * which is what the imm12/S forms scale their offsets by. */
static int simd_size(uint32_t insn, unsigned *size, unsigned *scale)
{
    unsigned size_log2 = insn >> 30;
    unsigned opc = (insn >> 22) & 3U;

    if (!(opc & 1U))
        return -1;
    if (opc & 2U) {
        if (size_log2 != 0)
            return -1;
        *size = 16;
        *scale = 4;
    } else {
        *size = 1U << size_log2;
        *scale = size_log2;
    }
    return 0;
}

int uro_decode(uint32_t insn, const struct uro_regs *regs, struct uro_load *out)
{
    struct uro_load load = { 0 };
    uint64_t base;
    unsigned mode, opc;
    if (!regs || !out || (regs->pc & 3U))
        return -1;

    load.rt = insn & 31U;
    load.rt2 = 31;
    load.rn = (insn >> 5) & 31U;
    if ((insn & 0x3f000000U) == 0x39000000U) {
        /* GPR load/store unsigned scaled imm12; bit 26 excludes SIMD. */
        uint64_t offset = (uint64_t)((insn >> 10) & 4095U) << (insn >> 30);
        if (single_type(insn, &load) || base_value(regs, load.rn, &base) ||
            add_magnitude(base, offset, 0, &load.address))
            return -1;
    } else if ((insn & 0x3f000000U) == 0x38000000U) {
        if (single_type(insn, &load) || base_value(regs, load.rn, &base))
            return -1;
        if (insn & (1U << 21)) {
            /* Register-offset form requires bits 11:10 == 10. */
            if ((insn & 0x00000c00U) != 0x00000800U ||
                register_offset(insn, regs, base,
                                (insn & (1U << 12)) ? insn >> 30 : 0U,
                                &load.address))
                return -1;
        } else {
            mode = (insn >> 10) & 3U;
            if (mode == 2)
                return -1; /* LDTR unprivileged family is not supported. */
            load.writeback = mode != 0;
            if (load.writeback && load.rn != 31 && load.rn == load.rt)
                return -1; /* Constrained-unpredictable writeback overlap. */
            if (add_immediate(base, (insn >> 12) & 511U, 9, 0, &load.wb))
                return -1;
            load.address = mode == 1 ? base : load.wb;
            if (!load.writeback)
                load.wb = 0;
        }
    } else if ((insn & 0x3f000000U) == 0x18000000U) {
        /* GPR literal loads, signed imm19 scaled by four. */
        opc = insn >> 30;
        if (opc == 3)
            return -1; /* PRFM */
        load.size = opc == 1 ? 8 : 4;
        load.count = 1;
        load.dest_bits = opc == 0 ? 32 : 64;
        load.sign_extend = opc == 2;
        load.rn = 31; /* No base register is read for literal addressing. */
        if (add_immediate(regs->pc, (insn >> 5) & 0x7ffffU, 19, 2, &load.address))
            return -1;
    } else if ((insn & 0x3e000000U) == 0x28000000U) {
        /* GPR pair; fixed bit 26==0 excludes all FP/SIMD variants. */
        opc = insn >> 30;
        mode = (insn >> 23) & 3U;
        if (!(insn & (1U << 22)) || opc == 3 || (opc == 1 && mode == 0))
            return -1;
        load.size = opc == 2 ? 8 : 4;
        load.count = 2;
        load.dest_bits = opc == 0 ? 32 : 64;
        load.sign_extend = opc == 1;
        load.rt2 = (insn >> 10) & 31U;
        load.writeback = mode == 1 || mode == 3;
        if (load.rt == load.rt2 ||
            (load.writeback && load.rn != 31 &&
             (load.rn == load.rt || load.rn == load.rt2)) ||
            base_value(regs, load.rn, &base))
            return -1;
        if (add_immediate(base, (insn >> 15) & 127U, 7,
                          load.size == 8 ? 3 : 2, &load.wb))
            return -1;
        load.address = mode == 1 ? base : load.wb;
        if (!load.writeback)
            load.wb = 0;
    } else if ((insn & 0x3f000000U) == 0x3d000000U) {
        /* SIMD&FP load, unsigned imm12 scaled by the access size.  A vector
         * load is the form bionic takes over for >=16-byte memcpy and for
         * memcmp/strlen over larger ranges (LDR Q / LDP Q). */
        unsigned scale;
        load.vector = 1;
        load.count = 1;
        if (simd_size(insn, &load.size, &scale))
            return -1;
        load.dest_bits = load.size * 8U;
        if (base_value(regs, load.rn, &base) ||
            add_magnitude(base, (uint64_t)((insn >> 10) & 4095U) << scale, 0,
                          &load.address))
            return -1;
    } else if ((insn & 0x3f000000U) == 0x3c000000U) {
        /* SIMD&FP load, unscaled/pre/post index or register offset.  The S
         * bit scales a register offset by the access size, i.e. by 16 for the
         * 128-bit form whose size field is zero. */
        unsigned scale;
        load.vector = 1;
        load.count = 1;
        if (simd_size(insn, &load.size, &scale) ||
            base_value(regs, load.rn, &base))
            return -1;
        load.dest_bits = load.size * 8U;
        if (insn & (1U << 21)) {
            if ((insn & 0x00000c00U) != 0x00000800U ||
                register_offset(insn, regs, base,
                                (insn & (1U << 12)) ? scale : 0U, &load.address))
                return -1;
        } else {
            mode = (insn >> 10) & 3U;
            if (mode == 2)
                return -1; /* LDTR unprivileged family is not supported. */
            load.writeback = mode != 0;
            if (add_immediate(base, (insn >> 12) & 511U, 9, 0, &load.wb))
                return -1;
            load.address = mode == 1 ? base : load.wb;
            if (!load.writeback)
                load.wb = 0;
        }
    } else if ((insn & 0x3f000000U) == 0x1c000000U) {
        /* SIMD&FP literal: opc 00/01/10 load 4/8/16 bytes, 11 is PRFM.
         * Kept for a literal pool that happens to live on the target page. */
        opc = insn >> 30;
        if (opc == 3)
            return -1;
        load.vector = 1;
        load.count = 1;
        load.size = opc == 2 ? 16U : (opc == 1 ? 8U : 4U);
        load.dest_bits = load.size * 8U;
        load.rn = 31;
        if (add_immediate(regs->pc, (insn >> 5) & 0x7ffffU, 19, 2, &load.address))
            return -1;
    } else if ((insn & 0x3e000000U) == 0x2c000000U) {
        /* SIMD&FP pair; opc 00/01/10 stores 4/8/16-byte elements. */
        opc = insn >> 30;
        mode = (insn >> 23) & 3U;
        if (!(insn & (1U << 22)) || opc == 3)
            return -1;
        load.vector = 1;
        load.count = 2;
        load.size = opc == 2 ? 16U : (opc == 1 ? 8U : 4U);
        load.dest_bits = load.size * 8U;
        load.rt2 = (insn >> 10) & 31U;
        load.writeback = mode == 1 || mode == 3;
        if (load.rt == load.rt2 || base_value(regs, load.rn, &base))
            return -1;
        if (add_immediate(base, (insn >> 15) & 127U, 7,
                          load.size == 16 ? 4U : (load.size == 8 ? 3U : 2U),
                          &load.wb))
            return -1;
        load.address = mode == 1 ? base : load.wb;
        if (!load.writeback)
            load.wb = 0;
    } else {
        return -1;
    }

    /* Even a non-writing-back load must not wrap its last accessed byte. */
    if ((uint64_t)(load.size * load.count - 1U) > URO_U64_MAX - load.address)
        return -1;
    *out = load;
    return 0;
}
