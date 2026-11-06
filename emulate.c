/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "emulate.h"

static int valid_user(uint64_t address, uint64_t limit)
{
    return address >= URO_PAGE_SIZE && address < limit;
}

int uro_emulate(const struct uro_view *v, uint32_t opcode, uint64_t esr,
                uint64_t far, struct uro_regs *r)
{
    struct uro_load d;
    uint64_t values[2] = { 0, 0 };
    uint64_t offset, total;
    unsigned element, byte;
    const uint64_t forbidden_iss = (UINT64_C(1) << 14) | /* acquire */
        (UINT64_C(7) << 11) | /* unhandled syndrome extensions */
        (UINT64_C(1) << 10) | (UINT64_C(1) << 9) |
        (UINT64_C(1) << 8) | (UINT64_C(1) << 7) | (UINT64_C(1) << 6);

    if (!v || !r || !v->original || !v->fake ||
        v->overlay_len < 8U || v->overlay_len > URO_FAKE_MAX ||
        (v->overlay_len & 7U) ||
        v->overlay_offset > URO_PAGE_SIZE - v->overlay_len ||
        v->user_limit < 2U * URO_PAGE_SIZE ||
        v->user_limit > (UINT64_C(1) << 56) ||
        (v->user_limit & (v->user_limit - 1U)) ||
        !valid_user(v->base, v->user_limit) || (v->base & (URO_PAGE_SIZE - 1U)) ||
        v->base > v->user_limit - URO_PAGE_SIZE)
        return URO_BAD_CONFIG;
    if ((esr >> 32) || ((esr >> 26) & 63U) != 0x24U ||
        !(esr & (UINT64_C(1) << 25)) || (esr & 63U) != 15U ||
        (esr & forbidden_iss))
        return URO_NOT_MINE;
    if (far < v->base || far - v->base >= URO_PAGE_SIZE)
        return URO_NOT_MINE;
    /* EL0t/A64 only; reject illegal-state and software single-step contexts.
     * NZCV is intentionally preserved. Endian/TCR/debug ownership are caller
     * responsibilities, not inferable from this synthetic register prefix. */
    if ((r->pstate & (UINT64_C(31) | (UINT64_C(1) << 20) | (UINT64_C(1) << 21))) ||
        !valid_user(r->pc, v->user_limit) || (r->pc & 3U) ||
        r->pc >= v->user_limit - 4U)
        return URO_BAD_CONTEXT;
    if (uro_decode(opcode, r, &d))
        return URO_UNSUPPORTED;
    /* decode.c also knows the SIMD&FP load forms the urov-y target-page
     * backend commits through the task's FPSIMD state.  This shared GPR
     * emulator (urov-x/urov-lab) has no vector register file in its model, so
     * it keeps rejecting them exactly as before. */
    if (d.vector || d.multi)
        return URO_UNSUPPORTED;
    total = d.total;
    if (d.address < v->base || d.address - v->base > URO_PAGE_SIZE - total ||
        (d.writeback && !valid_user(d.wb, v->user_limit)))
        return URO_BAD_RANGE;
    if (far < d.address || far - d.address >= total)
        return URO_BAD_FAR;
    if (esr & (UINT64_C(1) << 24)) {
        unsigned sas = (unsigned)((esr >> 22) & 3U);
        if (d.count != 1 || d.writeback || (1U << sas) != d.size ||
            ((esr >> 16) & 31U) != d.rt ||
            ((esr >> 21) & 1U) != (unsigned)d.sign_extend ||
            ((esr >> 15) & 1U) != (unsigned)(d.dest_bits == 64))
            return URO_BAD_SYNDROME;
    }
    offset = d.address - v->base;
    for (element = 0; element < d.count; ++element) {
        uint64_t value = 0;
        for (byte = 0; byte < d.size; ++byte) {
            uint64_t pos = offset + element * d.size + byte;
            uint8_t b;
            if (pos >= v->overlay_offset &&
                pos - v->overlay_offset < v->overlay_len)
                b = v->fake[pos - v->overlay_offset];
            else
                b = v->original[pos];
            value |= (uint64_t)b << (byte * 8U);
        }
        if (d.sign_extend && d.size < 8U &&
            (value & (UINT64_C(1) << (d.size * 8U - 1U))))
            value |= (~UINT64_C(0)) << (d.size * 8U);
        if (d.dest_bits == 32)
            value &= UINT64_C(0xffffffff);
        values[element] = value;
    }
    /* No failing validation, helper call, or source-byte read follows the
     * first commit. Caller owns the stable destination register buffer. */
    if (d.rt != 31U)
        r->x[d.rt] = values[0];
    if (d.count == 2U && d.rt2 != 31U)
        r->x[d.rt2] = values[1];
    if (d.writeback) {
        if (d.rn == 31U)
            r->sp = d.wb;
        else
            r->x[d.rn] = d.wb;
    }
    r->pc += 4U;
    return URO_OK;
}
