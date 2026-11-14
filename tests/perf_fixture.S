/* SPDX-License-Identifier: GPL-2.0-or-later */
.text
.p2align 4
ret
.global perf_read
.type perf_read,%function
perf_read:
    clrex
    ldr x0, [x0]
    ret
.global perf_block
.type perf_block,%function
perf_block:
    clrex
    ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    ret
/* The gap is longer than historical small-window optimizations. */
.global perf_llsc_long
.type perf_llsc_long,%function
perf_llsc_long:
    ldxr x2, [x0]
    .rept 8192
    nop
    .endr
    ldr x3, [x1]
    add x2, x2, #1
    stxr w4, x2, [x0]
    mov w0, w4
    ret
.global perf_llsc_clrex
.type perf_llsc_clrex,%function
perf_llsc_clrex:
    ldxr x2, [x0]
    clrex
    ldr x3, [x1]
    stxr w4, x2, [x0]
    mov w0, w4
    ret
.global perf_llsc_skip
.type perf_llsc_skip,%function
perf_llsc_skip:
    clrex
    adr x5, 1f
    br x5
    nop
    ldxr x2, [x0]
1:  ldr x3, [x1]
    stxr w4, x2, [x0]
    mov w0, w4
    ret
.arch_extension lse
.global perf_ldadd
.type perf_ldadd,%function
perf_ldadd:
    ldadd x1, x2, [x0]
    mov x0, x2
    ret
/* This entire page is mutable reader code, separate from the target pages.
 * Switching the NOP to LDXR changes the proof without changing the sampled
 * opcode/PC. Restore it after each trial. */
.p2align 14
.global perf_mutable
.global perf_patch_word
.type perf_mutable,%function
perf_mutable:
    clrex
    mov x2, #5
perf_patch_word:
    nop
    ldr x3, [x1]
    add x2, x2, #1
    stxr w4, x2, [x0]
    mov w0, w4
    ret
.p2align 14
.global perf_pages
.type perf_pages,%function
perf_pages:
    .fill 64, 1, 0x11
.global perf_self
.type perf_self,%function
perf_self:
    ldrb w0, [x0]
    ret
    .fill 1048576-(.-perf_pages), 1, 0x11
.size perf_pages, .-perf_pages
.section .note.GNU-stack,"",%progbits
