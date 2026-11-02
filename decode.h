/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef URO_LAB_DECODE_H
#define URO_LAB_DECODE_H

#include <stdint.h>

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
};

/* Decode only: no memory access or architectural register changes.
 * Return 0 on success, -1 on unsupported/invalid encoding or address overflow.
 * Failure leaves *out unchanged. size is bytes per element; count is 1 or 2.
 * rn==31 means SP; rt/rt2==31 means discard. address/wb preserve top-byte tags.
 * Caller must validate mappings, tags, complete access range and fault identity.
 * Caller must perform sign extension then W-register truncation/zero extension.
 */
int uro_decode(uint32_t insn, const struct uro_regs *regs, struct uro_load *out);

#endif
