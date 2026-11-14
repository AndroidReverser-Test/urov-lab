/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdio.h>
#include <string.h>
#include "../module/insn_scan.h"
#include "../module/emulate.h"

static uint32_t code[32768];
static unsigned calls, page_size, unreadable_below;
static int fetch(void *context, uint64_t pc, void *out, unsigned bytes)
{
    (void)context;
    ++calls;
    if (pc + bytes > sizeof(code) || pc / page_size != (pc + bytes - 1) / page_size)
        return -1;
    if (pc < unreadable_below) {
        memset(out, 0xff, bytes); /* A failed copy need not preserve the buffer. */
        return -1;
    }
    memcpy(out, (unsigned char *)code + pc, bytes);
    return 0;
}
#define CHECK(x) do { if (!(x)) { printf("FAIL line=%d\n", __LINE__); return 1; } } while (0)
int main(void)
{
    struct uz_insn_cursor cursor;
    unsigned checks;
    uint32_t word;
    unsigned char workspace[URO_PAGE_SIZE];

    CHECK(!uro_core_selftest(workspace, &checks) && checks == URO_CORE_CHECKS);
    for (unsigned i = 0; i < sizeof(code) / sizeof(code[0]); ++i) code[i] = i ^ 0x5a5a1234U;
    for (page_size = 4096; page_size <= 16384; page_size *= 4) {
        for (unsigned top = 65536; top < 66048; top += 4) {
            uz_insn_cursor_reset(&cursor);
            calls = 0;
            for (unsigned n = 0; n < 16384; ++n) {
                uint64_t at = top - 4U * n;
                CHECK(!uz_insn_back_read(&cursor, at, &word, fetch, NULL));
                CHECK(word == code[at / 4U]);
            }
            CHECK(calls <= 129); /* Same 64 KiB bound, at most 129 blocks. */
        }
    }
    page_size = 4096;
    unreadable_below = 0x118;
    uz_insn_cursor_reset(&cursor);
    CHECK(!uz_insn_back_read(&cursor, 0x11c, &word, fetch, NULL) && word == code[0x11c / 4]);
    CHECK(!uz_insn_back_read(&cursor, 0x118, &word, fetch, NULL) && word == code[0x118 / 4]);
    CHECK(uz_insn_back_read(&cursor, 0x114, &word, fetch, NULL) != 0);
    CHECK(uz_insn_back_read(&cursor, 0x11d, &word, fetch, NULL) != 0);
    CHECK(uz_insn_back_read(&cursor, UINT64_MAX - 3U, &word, fetch, NULL) != 0);
    /* Reset between exceptions/passes must observe a changed instruction. */
    code[0x118 / 4] = 0xd5033f5fU;
    uz_insn_cursor_reset(&cursor);
    CHECK(!uz_insn_back_read(&cursor, 0x118, &word, fetch, NULL) && word == 0xd5033f5fU);
    printf("PASS core=%u block_walks=256 words=4194304 fallback=PASS reset=PASS\n", checks);
    return 0;
}
