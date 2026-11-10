/* Differential test for the urov-y read-before value proof.
 *
 * The backend rewinds the instructions between a sampled load and the most
 * recent load-exclusive.  A register that the instruction under test writes
 * must be recovered exactly when the inverse is exact, and must be left
 * unknown otherwise.  Every encoding below was checked against the assembler.
 *
 * Build: .\kpms\urov-lab\build.ps1  ->  out/urov_prewin_test
 * Run:   aarch64 host (or qemu) ./urov_prewin_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "urov_y_prewin.h"

static unsigned cases;
static unsigned failures;
static struct uro_regs model;
static struct uy_pre_state st;

#define BIT(reg) (1U << (reg))
#define SP_BIT (1U << 31)

static void fail(const char *name, const char *what)
{
    ++failures;
    printf("FAIL %-36s %s\n", name, what);
}

/* ---- write-set classification ---------------------------------------- */

static void check_mask(const char *name, uint32_t insn, uint32_t want)
{
    uint32_t mask = 0;
    int rc = uy_pre_writes(insn, &mask);

    ++cases;
    if (rc < 0) {
        if (want != UINT32_MAX) fail(name, "declined, expected a write set");
        return;
    }
    if (want == UINT32_MAX) {
        fail(name, "classified, expected a decline");
        return;
    }
    if (mask != want) {
        printf("FAIL %-36s mask=%08x want=%08x\n", name, mask, (unsigned)want);
        ++failures;
    }
}

/* ---- exact inverse --------------------------------------------------- */

/* Run the instruction forward on the architectural model, then rewind it and
 * require the tracked value of `reg` to come back exactly. */
static void check_inverse(const char *name, uint32_t insn, unsigned reg,
                          uint64_t a, uint64_t b, uint64_t c)
{
    struct uro_regs post;

    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.x[3] = c;
    model.sp = a;
    model.pc = 0x400000;
    post = model;
    if (!uy_win_alu(&post, insn)) {
        ++cases;
        fail(name, "not modeled by the forward window");
        return;
    }
    uy_pre_reset(&st, &post);
    ++cases;
    if (uy_pre_step(insn, &st)) {
        fail(name, "declined by the rewind");
        return;
    }
    if (!uy_pre_known(&st, reg)) {
        fail(name, "value left unknown");
        return;
    }
    if (uy_pre_value(&st, reg) != a) {
        printf("FAIL %-36s pre=%016llx want=%016llx\n", name,
               (unsigned long long)uy_pre_value(&st, reg), (unsigned long long)a);
        ++failures;
    }
}

/* 2.27.0: the exclusive base is naturally aligned, so a mask write that can
 * only clear the low alignment bits is the identity even though it is not
 * invertible for an arbitrary input. */
static void check_inverse_zero(const char *name, uint32_t insn, unsigned reg,
                               uint64_t a, uint64_t b, uint64_t c, uint64_t zero_mask)
{
    struct uro_regs post;

    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.x[3] = c;
    model.sp = a;
    model.pc = 0x400000;
    post = model;
    if (!uy_win_alu(&post, insn)) {
        ++cases;
        fail(name, "not modeled by the forward window");
        return;
    }
    uy_pre_reset(&st, &post);
    ++cases;
    if (uy_pre_step_aligned(insn, &st, zero_mask)) {
        fail(name, "declined by the aligned rewind");
        return;
    }
    if (!uy_pre_known(&st, reg)) {
        fail(name, "value left unknown");
        return;
    }
    if (uy_pre_value(&st, reg) != a) {
        printf("FAIL %-36s pre=%016llx want=%016llx\n", name,
               (unsigned long long)uy_pre_value(&st, reg), (unsigned long long)a);
        ++failures;
    }
}

static void check_unknown_zero(const char *name, uint32_t insn, unsigned reg,
                               uint64_t a, uint64_t b, uint64_t c, uint64_t zero_mask)
{
    struct uro_regs post;

    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.x[3] = c;
    model.sp = a;
    model.pc = 0x400000;
    post = model;
    (void)uy_win_alu(&post, insn);
    uy_pre_reset(&st, &post);
    ++cases;
    if (uy_pre_step_aligned(insn, &st, zero_mask)) return;
    if (uy_pre_known(&st, reg)) fail(name, "guessed a pre-value");
}

/* The inverse must not guess: after the rewind the register stays unknown. */
static void check_unknown(const char *name, uint32_t insn, unsigned reg,
                          uint64_t a, uint64_t b, uint64_t c)
{
    struct uro_regs post;

    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.x[3] = c;
    model.sp = a;
    model.pc = 0x400000;
    post = model;
    (void)uy_win_alu(&post, insn);
    uy_pre_reset(&st, &post);
    ++cases;
    if (uy_pre_step(insn, &st)) return;              /* declining is fine */
    if (uy_pre_known(&st, reg)) fail(name, "guessed a pre-value");
}

/* Apply a sequence forward and rewind it in reverse order; `reg` must return
 * to its original value. */
static void check_chain(const char *name, const uint32_t *insns, unsigned n,
                        unsigned reg, uint64_t a, uint64_t b)
{
    struct uro_regs post;
    unsigned i;

    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.pc = 0x400000;
    post = model;
    for (i = 0; i < n; ++i) {
        if (!uy_win_alu(&post, insns[i])) {
            ++cases;
            fail(name, "sequence not modeled forward");
            return;
        }
    }
    uy_pre_reset(&st, &post);
    for (i = n; i > 0; --i) {
        if (uy_pre_step(insns[i - 1], &st)) {
            ++cases;
            fail(name, "sequence declined by the rewind");
            return;
        }
    }
    ++cases;
    if (!uy_pre_known(&st, reg) || uy_pre_value(&st, reg) != a) {
        fail(name, "chain did not rewind to the original value");
    }
}

int main(void)
{
    static const uint32_t add0[] = { 0x91000021U };
    static const uint32_t movself[] = { 0xaa0103e1U };
    static const uint32_t add8sub8[] = { 0x91002021U, 0xd1002021U };
    static const uint32_t eorpair[] = { 0xd2400021U, 0xd2400021U };

    /* Write sets: one row per class the rewind must place. */
    check_mask("add x1,x1,#0", 0x91000021U, BIT(1));
    check_mask("add x1,x1,#8", 0x91002021U, BIT(1));
    check_mask("sub x1,x1,#8", 0xd1002021U, BIT(1));
    check_mask("add x1,x1,#1,lsl#12", 0x91400421U, BIT(1));
    check_mask("eor x1,x1,#1", 0xd2400021U, BIT(1));
    check_mask("and x1,x1,#-1(imm)", 0x9240fc21U, BIT(1));
    check_mask("mov x1,x1", 0xaa0103e1U, BIT(1));
    check_mask("add x1,x1,x2", 0x8b020021U, BIT(1));
    check_mask("sub x1,x1,x2,lsl#3", 0xcb020c21U, BIT(1));
    check_mask("eor x1,x1,x2,ror#8", 0xcac22021U, BIT(1));
    check_mask("and x1,x1,x2", 0x8a020021U, BIT(1));
    check_mask("mov x1,x2", 0xaa0203e1U, BIT(1));
    check_mask("and x1,x1,#-8", 0x927df021U, BIT(1));
    check_mask("add w1,w1,#0", 0x11000021U, BIT(1));
    check_mask("mov sp,sp", 0x910003ffU, SP_BIT);
    check_mask("ldr x1,[x2]", 0xf9400041U, BIT(1));
    check_mask("ldr x1,[x2],#8", 0xf8408441U, BIT(1) | BIT(2));
    check_mask("str x2,[x1],#8", 0xf8008422U, BIT(1));
    check_mask("ldp x1,x2,[x3]", 0xa9400861U, BIT(1) | BIT(2));
    check_mask("stp x1,x2,[sp,#-16]!", 0xa9bf0be1U, SP_BIT);
    check_mask("ldadd x1,x2,[x3]", 0xf8210062U, BIT(2));
    check_mask("cas x1,x2,[x3]", 0xc8a17c62U, BIT(1));
    check_mask("fmov x1,d0", 0x9e660001U, BIT(1));
    check_mask("dc zva,x1", 0xd50b7421U, 0);
    check_mask("dc cvac,x1", 0xd50b7a21U, 0);
    check_mask("ic iallu", 0xd508751fU, 0);
    check_mask("dc ivac (EL1)", 0xd5087620U, UINT32_MAX);
    check_mask("ic ivau,x1", 0xd50b7521U, 0);

    /* The two SCTLR gates the backend fills from the live control register. */
    uy_pre_uci = 0;
    check_mask("dc cvac with UCI=0", 0xd50b7a21U, UINT32_MAX);
    uy_pre_uci = 1;
    uy_pre_dze = 0;
    check_mask("dc zva with DZE=0", 0xd50b7421U, UINT32_MAX);
    uy_pre_dze = 1;
    check_mask("ldraa x1,[x2]", 0xf8200441U, BIT(1));
    check_mask("b.ne", 0x54000001U, 0);
    check_mask("cbz x1", 0xb4000001U, 0);
    check_mask("tbz w1,#3", 0x36180001U, 0);
    check_mask("bl", 0x94000000U, UINT32_MAX);
    check_mask("br x1", 0xd61f0020U, UINT32_MAX);
    check_mask("ret", 0xd65f03c0U, UINT32_MAX);
    check_mask("mrs x1,tpidr_el0", 0xd53bd041U, BIT(1));
    check_mask("msr tpidr_el0,x1", 0xd51bd041U, 0);
    check_mask("paciasp", 0xd503233fU, BIT(30));
    check_mask("nop", 0xd503201fU, 0);
    check_mask("adr x1", 0x10000001U, BIT(1));
    check_mask("movz x1,#1", 0xd2800021U, BIT(1));
    check_mask("csel x1,x2,x3,eq", 0x9a830041U, BIT(1));
    check_mask("udiv x1,x2,x3", 0x9ac30841U, BIT(1));

    /* Exact inverses. */
    check_inverse("inverse add x1,x1,#0", 0x91000021U, 1, 0x1234567890ULL, 5, 6);
    check_inverse("inverse add x1,x1,#8", 0x91002021U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse sub x1,x1,#8", 0xd1002021U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse add x1,x1,#1,lsl#12", 0x91400421U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse eor x1,x1,#1", 0xd2400021U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse and x1,x1,#-1", 0x9240fc21U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse mov x1,x1", 0xaa0103e1U, 1, 0x70000000ULL, 5, 6);
    check_inverse("inverse add x1,x1,x2", 0x8b020021U, 1, 0x70000000ULL, 0x1234, 6);
    check_inverse("inverse sub x1,x1,x2,lsl#3", 0xcb020c21U, 1, 0x70000000ULL, 3, 6);
    check_inverse("inverse eor x1,x1,x2,ror#8", 0xcac22021U, 1, 0x70000000ULL,
                  0x1122334455667788ULL, 6);
    check_inverse("inverse mov sp,sp", 0x910003ffU, 31, 0x70000000ULL, 5, 6);

    /* The inverse must not guess. */
    check_unknown("unknown and x1,x1,#-8", 0x927df021U, 1, 0x70000000ULL, 5, 6);
    check_unknown("unknown and x1,x1,x2", 0x8a020021U, 1, 0x70000000ULL, 0xf, 6);
    check_unknown("unknown mov x1,x2", 0xaa0203e1U, 1, 0x70000000ULL, 5, 6);
    check_unknown("unknown add w1,w1,#0", 0x11000021U, 1, 0x70000000ULL, 5, 6);
    check_unknown("unknown ldr x1,[x2]", 0xf9400041U, 1, 0x70000000ULL, 5, 6);
    check_unknown("unknown movz x1,#1", 0xd2800021U, 1, 0x70000000ULL, 5, 6);
    check_unknown("unknown csel x1,x2,x3", 0x9a830041U, 1, 0x70000000ULL, 5, 6);

    /* 2.27.0 aligned-mask proof: identity only while the mask is confined to
     * the bits a naturally aligned exclusive base must have clear. */
    check_inverse_zero("aligned and x1,x1,#-8", 0x927df021U, 1, 0x70000000ULL, 5, 6, 7);
    check_inverse_zero("aligned and x1,x1,x2=~7", 0x8a020021U, 1, 0x70000000ULL,
                       ~UINT64_C(7), 6, 7);
    check_inverse_zero("aligned orr x1,x1,x2=7", 0xaa020021U, 1, 0x70000000ULL, 7, 6, 7);
    check_inverse_zero("aligned eor x1,x1,x2", 0xca020021U, 1, 0x70000000ULL, 0x1234, 6, 7);
    check_unknown_zero("aligned and x1,x1,x2=~15", 0x8a020021U, 1, 0x70000000ULL,
                       ~UINT64_C(15), 6, 7);
    check_unknown_zero("aligned orr x1,x1,x2=8", 0xaa020021U, 1, 0x70000000ULL, 8, 6, 7);
    check_unknown_zero("and #-8 with 4-byte alignment", 0x927df021U, 1, 0x70000000ULL, 5, 6, 3);

    /* Multi-instruction rewinds. */
    check_chain("chain add#0", add0, 1, 1, 0x70000000ULL, 5);
    check_chain("chain add8/sub8", add8sub8, 2, 1, 0x70000000ULL, 5);
    check_chain("chain eor1/eor1", eorpair, 2, 1, 0x70000000ULL, 5);
    check_chain("chain mov self", movself, 1, 1, 0x70000000ULL, 5);

    printf("prewin cases=%u failures=%u\n", cases, failures);
    return failures ? 1 : 0;
}
