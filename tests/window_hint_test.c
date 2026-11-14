/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include "../module/window.h"

/* Exercise the complete HINT space: new architectural HINT assignments must
 * remain unsupported until their side effects are explicitly modeled. */
int main(void)
{
    struct uro_regs initial = { { 0 }, 0x20000, 0x10000, 0xa0000000U };
    unsigned checks = 0;

    for (unsigned i = 0; i < 31; ++i)
        initial.x[i] = UINT64_C(0x123456789abcdef0) + i;
    for (unsigned hint = 0; hint < 128; ++hint) {
        uint32_t insn = 0xd503201fU | (hint << 5);
        struct uro_regs actual = initial;
        int expected = hint == 0 || hint == 0x22 || hint == 0x24 || hint == 0x26;

        if (uz_win_alu(&actual, insn) != expected ||
            uz_win_dst(insn) != (expected ? 32U : 34U) ||
            uz_win_srcs(insn) != (expected ? 0U : UINT32_MAX) ||
            memcmp(&actual, &initial, sizeof(actual))) {
            printf("FAIL hint=%u insn=%08x\n", hint, insn);
            return 1;
        }
        ++checks;
    }
    /* DSB/DMB/ISB options, including SB's encoding, must not disappear. */
    const uint32_t barriers[] = { 0xd503309fU, 0xd50330bfU, 0xd50330dfU, 0xd50330ffU };
    for (unsigned i = 0; i < sizeof(barriers) / sizeof(barriers[0]); ++i) {
        for (unsigned option = 0; option < 16; ++option) {
            struct uro_regs actual = initial;
            uint32_t insn = barriers[i] | (option << 8);
            if (uz_win_alu(&actual, insn) || uz_win_dst(insn) != 34U ||
                uz_win_srcs(insn) != UINT32_MAX ||
                memcmp(&actual, &initial, sizeof(actual))) {
                printf("FAIL barrier=%08x option=%u\n", barriers[i], option);
                return 1;
            }
            ++checks;
        }
    }
    /* FMOV S/H zero the remainder of the 128-bit destination. In particular
     * the 12/14-byte clear must not shift a 64-bit value by >=64 bits. */
    const uint32_t moves[] = { 0x1e270020U, 0x1ee70020U };
    const unsigned widths[] = { 4, 2 };
    for (unsigned i = 0; i < 2; ++i) {
        struct uro_regs actual = initial;
        struct uz_fpstate fp, expected;
        memset(&fp, 0xa5, sizeof(fp));
        expected = fp;
        for (unsigned byte = 0; byte < 16; ++byte)
            expected.vregs[0][byte] = byte < widths[i] ?
                (uint8_t)(initial.x[1] >> (8U * byte)) : 0;
        if (!uz_win_fp_move(&actual, &fp, moves[i], 1) ||
            memcmp(&actual, &initial, sizeof(actual)) || memcmp(&fp, &expected, sizeof(fp))) {
            printf("FAIL fmov=%08x\n", moves[i]);
            return 1;
        }
    }
    printf("PASS hint_barrier_checks=%u\n", checks);
    puts("PASS fmov_zero_fill=2");
    return 0;
}
