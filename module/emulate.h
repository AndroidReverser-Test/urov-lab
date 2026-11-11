/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef URO_LAB_EMULATE_H
#define URO_LAB_EMULATE_H
#include "decode.h"

/* KernelPatch's freestanding stdint.h supplies types but no literal macros. */
#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif

#define URO_PAGE_SIZE 4096U
#define URO_FAKE_MAX 32U
#define URO_READ_ESR ((UINT64_C(0x24) << 26) | (UINT64_C(1) << 25) | 15U)
/* Exact number of assertions performed by uro_core_selftest(). Keep the KPM
 * load gate and the host tests in sync with this value. */
#define URO_CORE_CHECKS 4152U

enum uro_result {
    URO_OK = 0,
    URO_NOT_MINE = 1,
    URO_BAD_CONFIG = -1,
    URO_BAD_CONTEXT = -2,
    URO_UNSUPPORTED = -3,
    URO_BAD_RANGE = -4,
    URO_BAD_FAR = -5,
    URO_BAD_SYNDROME = -6
};

/* Trusted caller-owned immutable buffer, NOT a userspace pointer/UAPI.
 * Caller proves mm/VMA/PTE identity, instruction-fetch stability, endian,
 * memory type and object lifetime before calling. No OS state is read here.
 * fake points at a validated snapshot of overlay_len little-endian bytes;
 * it must stay stable for the duration of the call (8, 16, 24 or 32 bytes). */
struct uro_view {
    const uint8_t *original;
    const uint8_t *fake;
    uint64_t base;
    uint64_t user_limit; /* Exclusive, verified architectural limit. */
    unsigned overlay_offset;
    unsigned overlay_len;
};

/* One value snapshot per entire instruction, including both pair elements.
 * Only changes *regs on URO_OK; never accesses the described user address.
 * NOT_MINE is only for a nonmatching fault/range. A negative result for an
 * owned fault must not be converted to successful native data access. */
int uro_emulate(const struct uro_view *view, uint32_t opcode, uint64_t esr,
                uint64_t far, struct uro_regs *regs);

/* Deterministic freestanding checks; workspace must be a separate writable
 * 4096-byte buffer. No allocation, logging, OS callbacks, or persistent state.
 * Returns 0, or the first failed assertion's source line. */
int uro_core_selftest(uint8_t *workspace, unsigned *checks);
#endif
