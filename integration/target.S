/* SPDX-License-Identifier: GPL-2.0-or-later */
.section .text.uzfixture,"ax",%progbits
.balign 16384
.global uz_test_target
.type uz_test_target,%function
uz_test_target:
    /* A simple, relocatable prologue for the Dobby test. */
    .rept 8
    nop
    .endr
    b uz_test_impl
.size uz_test_target, .-uz_test_target
.balign 16384

.text
.global uz_test_sleep
.type uz_test_sleep,%function
uz_test_sleep:
    /* Cooperative injection boundary: x16 is dead after SVC and no user
     * lock is held. KCLF cannot promise this for arbitrary app threads. */
    mov x1, #0
    mov x8, #101
    svc #0
    ret
.size uz_test_sleep, .-uz_test_sleep
.section .note.GNU-stack,"",%progbits
