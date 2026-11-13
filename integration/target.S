/* SPDX-License-Identifier: GPL-2.0-or-later */
.section .text.uzfixture,"ax",%progbits
.macro TARGET index
    /* Separate runtime pages on both 4 KiB and 16 KiB Android kernels. */
    .balign 16384
    .global uz_test_target_\index
    .type uz_test_target_\index,%function
uz_test_target_\index:
    .rept 8
    nop
    .endr
    mov w2, #\index
    b uz_test_impl
    .size uz_test_target_\index, .-uz_test_target_\index
.endm
TARGET 0
TARGET 1
TARGET 2
TARGET 3
TARGET 4
TARGET 5
TARGET 6
TARGET 7
TARGET 8
TARGET 9
.balign 16384
.text
.global uz_read_block
.hidden uz_read_block
.type uz_read_block,%function
uz_read_block:
    /* One supported data-read fault for 64 contiguous bytes. */
    ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    ret
.size uz_read_block, .-uz_read_block
.global uz_test_sleep
.type uz_test_sleep,%function
uz_test_sleep:
    /* Cooperative boundary: no userspace lock, x16 dead after SVC. */
    mov x1, #0
    mov x8, #101
    svc #0
    ret
.size uz_test_sleep, .-uz_test_sleep
.section .note.GNU-stack,"",%progbits
