/* SPDX-License-Identifier: GPL-2.0-or-later */
.text
.p2align 4
.global uz_read8
.hidden uz_read8
.type uz_read8,%function
uz_read8:
    ldrb w0, [x0]
    ret
.global uz_read64
.hidden uz_read64
.type uz_read64,%function
uz_read64:
    ldr x0, [x0]
    ret
.global uz_read_pair
.hidden uz_read_pair
.type uz_read_pair,%function
uz_read_pair:
    ldp x2, x3, [x0]
    stp x2, x3, [x1]
    ret
.global uz_read_quad
.hidden uz_read_quad
.type uz_read_quad,%function
uz_read_quad:
    ldr q0, [x0]
    str q0, [x1]
    ret
.global uz_read_ld2
.hidden uz_read_ld2
.type uz_read_ld2,%function
uz_read_ld2:
    ld2 {v0.16b, v1.16b}, [x0]
    stp q0, q1, [x1]
    ret
.global uz_read_ld4
.hidden uz_read_ld4
.type uz_read_ld4,%function
uz_read_ld4:
    ld4 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    ret
/* A separately aligned .text fixture is valid on 4 KiB and 16 KiB kernels. */
.p2align 14
.global uz_fixture
.hidden uz_fixture
.type uz_fixture,%function
uz_fixture:
    mov w0, #1235
    ret
.fill 64-(.-uz_fixture), 1, 0x11
.global uz_self_read
.hidden uz_self_read
.type uz_self_read,%function
uz_self_read:
    ldrb w0, [x0]
    ret
.fill 32768-(.-uz_fixture), 1, 0x11
.size uz_fixture, .-uz_fixture
.p2align 14
.section .note.GNU-stack,"",%progbits
