/* Differential test for the urov-y LL/SC window model.
 *
 * Every case names an instruction, its exact encoding (checked against the
 * assembler) and the result the architecture requires.  The model is driven
 * through uy_win_alu()/uy_win_branch() exactly as urov_y_backend.c does, and the
 * expected value is computed independently here, so a decode or flag mistake
 * fails this test instead of silently corrupting a real window.
 *
 * Build: .\kpms\urov-lab\build.ps1  ->  out/urov_window_test
 * Run:   adb push out/urov_window_test /data/local/tmp/ && adb shell /data/local/tmp/urov_window_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "urov_y_window.h"

static struct uro_regs model;
static unsigned cases;
static unsigned failures;

#define PSR_N (UINT64_C(1) << 31)
#define PSR_Z (UINT64_C(1) << 30)
#define PSR_C (UINT64_C(1) << 29)
#define PSR_V (UINT64_C(1) << 28)

static void reset(uint64_t a, uint64_t b, uint64_t c)
{
    memset(&model, 0, sizeof(model));
    model.x[1] = a;
    model.x[2] = b;
    model.x[3] = c;
    model.pstate = 0;
}

static void check(const char *name, uint32_t insn, uint64_t want, unsigned reg)
{
    int handled = uy_win_alu(&model, insn);
    uint64_t got = model.x[reg];

    ++cases;
    if (!handled) { printf("FAIL %-30s not modeled\n", name); ++failures; return; }
    if (got != want) {
        printf("FAIL %-30s insn=%08x got=%016llx want=%016llx\n", name, insn,
               (unsigned long long)got, (unsigned long long)want);
        ++failures;
        return;
    }
    printf("ok   %-30s %016llx\n", name, (unsigned long long)got);
}

static void check_nzcv(const char *name, uint32_t insn, unsigned wn, unsigned wz,
                       unsigned wc, unsigned wv)
{
    int handled = uy_win_alu(&model, insn);
    unsigned n = (unsigned)((model.pstate >> 31) & 1U), z = (unsigned)((model.pstate >> 30) & 1U);
    unsigned c = (unsigned)((model.pstate >> 29) & 1U), v = (unsigned)((model.pstate >> 28) & 1U);

    ++cases;
    if (!handled || n != wn || z != wz || c != wc || v != wv) {
        printf("FAIL %-30s nzcv=%u%u%u%u want=%u%u%u%u handled=%d\n", name, n, z, c, v,
               wn, wz, wc, wv, handled);
        ++failures;
        return;
    }
    printf("ok   %-30s %u%u%u%u\n", name, n, z, c, v);
}

static void check_branch(const char *name, uint32_t insn, uint64_t at, uint64_t want)
{
    int handled = uy_win_branch(&model, insn, at);

    ++cases;
    if (!handled || model.pc != want) {
        printf("FAIL %-30s pc=%llx want=%llx handled=%d\n", name,
               (unsigned long long)model.pc, (unsigned long long)want, handled);
        ++failures;
        return;
    }
    printf("ok   %-30s %llx\n", name, (unsigned long long)model.pc);
}

static void check_declined(const char *name, uint32_t insn)
{
    int handled = uy_win_alu(&model, insn);

    ++cases;
    if (handled) { printf("FAIL %-30s accepted\n", name); ++failures; return; }
    printf("ok   %-30s declined\n", name);
}

static uint64_t bitrev(uint64_t v, unsigned bits)
{
    uint64_t out = 0;
    unsigned i;

    for (i = 0; i < bits; ++i) out = (out << 1) | ((v >> i) & 1U);
    return out;
}

static struct uy_fpstate fp;

static void fp_reset(void)
{
    memset(&fp, 0, sizeof(fp));
}

static void check_fp(const char *name, uint32_t insn, unsigned reg, unsigned off,
                     unsigned bytes, uint64_t want)
{
    uint64_t got = 0;
    unsigned i;

    ++cases;
    if (!uy_win_fp_move(&model, &fp, insn, 1)) {
        printf("FAIL %-30s not modeled\n", name);
        ++failures;
        return;
    }
    for (i = 0; i < bytes; ++i)
        got |= (uint64_t)fp.vregs[reg][off + i] << (8U * i);
    if (got != want) {
        printf("FAIL %-30s got=%016llx want=%016llx\n", name,
               (unsigned long long)got, (unsigned long long)want);
        ++failures;
        return;
    }
    printf("ok   %-30s %016llx\n", name, (unsigned long long)got);
}

static void check_fp_to_gpr(const char *name, uint32_t insn, uint64_t want)
{
    ++cases;
    if (!uy_win_fp_move(&model, &fp, insn, 1) || model.x[0] != want) {
        printf("FAIL %-30s got=%016llx want=%016llx\n", name,
               (unsigned long long)model.x[0], (unsigned long long)want);
        ++failures;
        return;
    }
    printf("ok   %-30s %016llx\n", name, (unsigned long long)model.x[0]);
}

static void check_dst(const char *name, uint32_t insn, unsigned want)
{
    unsigned got = uy_win_dst(insn);

    ++cases;
    if (got != want) {
        printf("FAIL %-30s dst=%u want=%u\n", name, got, want);
        ++failures;
        return;
    }
    printf("ok   %-30s %u\n", name, got);
}

static void check_sysreg(const char *name, uint32_t insn, uint64_t want, int read_nzcv)
{
    ++cases;
    if (!uy_win_sysreg(&model, &fp, insn)) {
        printf("FAIL %-30s not modeled\n", name);
        ++failures;
        return;
    }
    if (read_nzcv ? model.x[0] != want : (model.pstate & (UINT64_C(0xf) << 28)) != want) {
        printf("FAIL %-30s got=%016llx want=%016llx\n", name,
               (unsigned long long)(read_nzcv ? model.x[0] : model.pstate),
               (unsigned long long)want);
        ++failures;
        return;
    }
    printf("ok   %-30s\n", name);
}

static void check_sysreg_fpsr(const char *name, uint32_t insn, uint32_t want)
{
    ++cases;
    if (!uy_win_sysreg(&model, &fp, insn) || fp.fpsr != want) {
        printf("FAIL %-30s fpsr=%08x want=%08x\n", name, fp.fpsr, want);
        ++failures;
        return;
    }
    printf("ok   %-30s\n", name);
}

int main(void)
{
    const uint64_t A = UINT64_C(0x1122334455667788);
    const uint64_t B = UINT64_C(0x8877665544332211);

    /* Bitfield extracts/inserts: UBFX/UBFIZ/LSL/LSR/ASR/UXTB/SXTB/SBFX/BFI/BFXIL.
     * Encodings taken from `llvm-mc -triple=aarch64`. */
    reset(A, 0, 0);
    check("ubfx x0,x1,#4,#8", 0xd3442c20U, (A >> 4) & 0xffU, 0);
    reset(A, 0, 0);
    check("ubfiz x0,x1,#4,#8", 0xd37c1c20U, (A & 0xffU) << 4, 0);
    reset(A, 0, 0);
    check("lsl x0,x1,#4", 0xd37cec20U, A << 4, 0);
    reset(A, 0, 0);
    check("lsr x0,x1,#4", 0xd344fc20U, A >> 4, 0);
    reset(A, 0, 0);
    check("asr x0,x1,#4", 0x9344fc20U, (uint64_t)((int64_t)A >> 4), 0);
    reset(A, 0, 0);
    check("uxtb w0,w1", 0x53001c20U, A & 0xffU, 0);
    reset(A, 0, 0);
    check("sxtb w0,w1", 0x13001c20U, (uint64_t)(uint32_t)(int32_t)(int8_t)(A & 0xffU), 0);
    reset(A, 0, 0);
    check("sbfx x0,x1,#4,#8", 0x93442c20U, (uint64_t)(int64_t)(int8_t)((A >> 4) & 0xffU), 0);
    reset(A, 0, 0);
    check("bfi x0,x1,#4,#8", 0xb37c1c20U, (A & 0xffU) << 4, 0);
    reset(B, 0, 0);
    check("bfxil x0,x1,#4,#8", 0xb3442c20U, (B >> 4) & 0xffU, 0);

    /* Logical (immediate) and EXTR. */
    reset(A, 0, 0);
    check("and x0,x1,#0xff", 0x92401c20U, A & 0xffU, 0);
    reset(A, 0, 0);
    check("and #0xffff0000ffff0000", 0x92103c20U, A & UINT64_C(0xffff0000ffff0000), 0);
    reset(A, 0, 0);
    check("orr x0,x1,#0x3f", 0xb2401420U, A | 0x3fU, 0);
    reset(A, B, 0);
    check("extr x0,x1,x2,#8", 0x93c22020U, (B >> 8) | (A << 56), 0);

    /* Data-processing (3/2/1 source). */
    reset(A, B, B);
    check("madd x0,x1,x2,x3", 0x9b020c20U, A * B + B, 0);
    reset(A, B, 0);
    check("msub x0,x1,x2,x3", 0x9b028c20U, 0 - A * B, 0);
    reset(A, B, 0);
    check("udiv x0,x1,x2", 0x9ac20820U, A / B, 0);
    reset(A, B, 0);
    check("sdiv x0,x1,x2", 0x9ac20c20U, (uint64_t)((int64_t)A / (int64_t)B), 0);
    reset(A, B, 0);
    check("lslv x0,x1,x2", 0x9ac22020U, A << (B & 63), 0);
    reset(A, B, 0);
    check("rorv x0,x1,x2", 0x9ac22c20U,
          (A >> (B & 63)) | (A << ((64 - (B & 63)) & 63)), 0);
    reset(A, 0, 0);
    check("rbit x0,x1", 0xdac00020U, bitrev(A, 64), 0);
    reset(A, 0, 0);
    check("rev16 w0,w1", 0x5ac00420U,
          ((A & 0xffU) << 8) | ((A >> 8) & 0xffU) |
          (((A >> 16) & 0xffU) << 24) | (((A >> 24) & 0xffU) << 16), 0);
    reset(A, 0, 0);
    check("rev32 x0,x1", 0xdac00820U,
          ((A & 0xffU) << 24) | (((A >> 8) & 0xffU) << 16) |
          (((A >> 16) & 0xffU) << 8) | ((A >> 24) & 0xffU) |
          ((((A >> 32) & 0xffU) << 24) | (((A >> 40) & 0xffU) << 16) |
           (((A >> 48) & 0xffU) << 8) | ((A >> 56) & 0xffU)) << 32, 0);
    reset(A, 0, 0);
    {
        uint64_t want = 0;
        unsigned i;

        for (i = 0; i < 8; ++i) want |= ((A >> (8 * i)) & 0xffU) << (8 * (7 - i));
        check("rev x0,x1", 0xdac00c20U, want, 0);
    }
    reset(A, 0, 0);
    check("clz x0,x1", 0xdac01020U, 3U, 0);
    reset(UINT64_C(0xf123456789abcdef), 0, 0);
    check("cls x0,x1", 0xdac01420U, 3U, 0);
    reset(UINT64_C(0x00000000f1234567), 0, 0);
    check("clz x0,x1 (w value)", 0xdac01020U, 32U, 0);

    /* Add/subtract, move wide and the SP forms. */
    reset(A, B, 0);
    check("add x0,x1,#0x123", 0x91048c20U, A + 0x123U, 0);
    reset(A, B, 0);
    check("add x0,x1,x2,lsl#5", 0x8b021420U, A + (B << 5), 0);
    reset(A, B, 0);
    check("subs x0,x1,x2,asr#3", 0xeb820c20U, A - (uint64_t)((int64_t)B >> 3), 0);
    reset(A, 0, 0);
    model.x[0] = A;
    check("movk x0,#0xabcd,lsl#16", 0xf2b579a0U,
          (A & ~UINT64_C(0xffff0000)) | UINT64_C(0xabcd0000), 0);
    reset(A, 0, 0);
    check("movz x0,#0x1234,lsl#32", 0xd2c24680U, UINT64_C(0x123400000000), 0);
    reset(A, 0, 0);
    check("movn x0,#0xf", 0x928001e0U, ~UINT64_C(0xf), 0);
    reset(0, 0, 0);
    model.sp = UINT64_C(0x7000);
    check("add x0,sp,#0x20", 0x910083e0U, UINT64_C(0x7020), 0);
    reset(0, 0, 0);
    model.sp = UINT64_C(0x7000);
    model.x[0] = 1;
    {
        int handled = uy_win_alu(&model, 0x910083ffU); /* add sp, sp, #0x20 */

        ++cases;
        if (!handled || model.sp != UINT64_C(0x7020)) {
            printf("FAIL %-30s sp=%llx handled=%d\n", "add sp,sp,#0x20",
                   (unsigned long long)model.sp, handled);
            ++failures;
        } else {
            printf("ok   %-30s %016llx\n", "add sp,sp,#0x20",
                   (unsigned long long)model.sp);
        }
    }

    /* Conditional select family: op selects the invert/negate pair. */
    reset(A, B, 0);
    model.pstate = PSR_Z;
    check("csel x0,x1,x2,eq (Z=1)", 0x9a820020U, A, 0);
    reset(A, B, 0);
    model.pstate = PSR_Z;
    check("csinc x0,x1,x2,ne (Z=1)", 0x9a821420U, B + 1, 0);
    reset(A, B, 0);
    check("csinv x0,x1,x2,lt (N=0,V=0)", 0xda82b020U, ~B, 0);
    reset(A, B, 0);
    model.pstate = PSR_Z;
    check("csneg x0,x1,x2,gt (Z=1)", 0xda82c420U, 0 - B, 0);

    /* Conditional compare: true -> the comparison, false -> the NZCV field. */
    reset(A, B, 0);
    model.pstate = PSR_Z;
    check_nzcv("ccmp x1,#4,#0,eq (Z=1)", 0xfa440820U, 0, 0, 1, 0);
    reset(A, B, 0);
    check_nzcv("ccmn x1,x2,#8,ne (Z=0)", 0xba421028U, 1, 0, 0, 0);
    reset(A, B, 0);
    check_nzcv("ccmp false keeps nzcv", 0xfa440821U, 0, 0, 0, 1);

    /* ADR/ADRP use the model PC. */
    reset(A, 0, 0);
    model.pc = 0x1000;
    check("adr x0,#0", 0x10000000U, 0x1000, 0);
    reset(A, 0, 0);
    model.pc = 0x1234;
    check("adrp x0,0", 0x90000000U, 0x1000, 0);

    /* NOP/BTI/HINT #0/barriers are accepted and change nothing. */
    reset(A, 0, 0);
    check("nop", UY_NOP, 0, 0);
    reset(A, 0, 0);
    check("bti c", UY_BTI_C, 0, 0);
    reset(A, 0, 0);
    check("dmb ish", 0xd5033bbfU, 0, 0);
    reset(A, 0, 0);
    check("isb", 0xd5033fdfU, 0, 0);

    /* Branches: taken and not taken, and an unmodeled class must decline. */
    reset(A, 0, 0);
    model.pstate = PSR_Z;
    check_branch("b.eq taken (Z=1)", 0x54000040U, 0x2000, 0x2008);
    reset(A, 0, 0);
    check_branch("b.eq not taken (Z=0)", 0x54000040U, 0x2000, 0x2004);
    reset(A, 0, 0);
    check_branch("cbz x1 nonzero", 0xb4000041U, 0x2000, 0x2004);
    reset(0, 0, 0);
    check_branch("cbz x1 zero", 0xb4000041U, 0x2000, 0x2008);
    reset(A, 0, 0);
    check_branch("tbnz w1,#3 set", 0x37180041U, 0x2000, 0x2008);
    reset(A, 0, 0);
    check_declined("mrs x0,midr_el1", 0xd5380000U);
    reset(A, 0, 0);
    check_declined("clrex", 0xd5033f5fU);
    reset(A, 0, 0);
    check_declined("svc #0", 0xd4000001U);

    /* FP/SIMD moves: bit-exact transfers, scalar writes zero the rest of Vd,
     * lane writes preserve the other lane. */
    reset(A, 0, 0);
    fp_reset();
    check_fp("fmov d0,x1", 0x9e670020U, 0, 0, 8, A);
    reset(0, 0, 0);
    fp_reset();
    fp.vregs[1][0] = 0x88; fp.vregs[1][6] = 0x77;
    check_fp_to_gpr("fmov x0,d1", 0x9e660020U, UINT64_C(0x0077000000000088));
    reset(A, 0, 0);
    fp_reset();
    fp.vregs[0][0] = 0x5a;
    check_fp("fmov v0.d[1],x1", 0x9eaf0020U, 0, 8, 8, A);
    reset(0, 0, 0);
    fp_reset();
    fp.vregs[1][8] = 0x44;
    check_fp_to_gpr("fmov x0,v1.d[1]", 0x9eae0020U, UINT64_C(0x44));
    reset(A, 0, 0);
    fp_reset();
    check_fp("fmov s0,w1", 0x1e270020U, 0, 0, 4, A & 0xffffffffU);
    reset(0, 0, 0);
    fp_reset();
    fp.vregs[1][0] = 0x21;
    check_fp_to_gpr("fmov w0,s1", 0x1e260020U, 0x21);
    reset(A, 0, 0);
    fp_reset();
    check_fp("fmov h0,w1", 0x1ee70020U, 0, 0, 2, A & 0xffffU);
    reset(0, 0, 0);
    fp_reset();
    fp.vregs[1][0] = 0x66;
    check_fp_to_gpr("fmov w0,h1", 0x1ee60020U, 0x66);

    /* MRS/MSR of NZCV and FPCR/FPSR. */
    reset(0, 0, 0);
    fp_reset();
    model.pstate = PSR_N | PSR_C;
    check_sysreg("mrs x0,nzcv", 0xd53b4200U, PSR_N | PSR_C, 1);
    reset(0, 0, 0);
    fp_reset();
    model.x[0] = PSR_Z | PSR_V;
    check_sysreg("msr nzcv,x0", 0xd51b4200U, PSR_Z | PSR_V, 0);
    reset(0, 0, 0);
    fp_reset();
    fp.fpcr = 0x12345678U;
    check_sysreg("mrs x0,fpcr", 0xd53b4400U, 0x12345678U, 1);
    reset(0, 0, 0);
    fp_reset();
    model.x[0] = 0x9abcdef0U;
    check_sysreg_fpsr("msr fpsr,x0", 0xd51b4420U, 0x9abcdef0U);
    reset(0, 0, 0);
    check_dst("add x0,x1,#1", 0x91000420U, 0);
    check_dst("add sp,sp,#16", 0x910043ffU, 33);
    check_dst("adds xzr,x1,#1", 0xb100043fU, 32);
    check_dst("nop", UY_NOP, 32);
    check_dst("mrs x0,nzcv", 0xd53b4200U, 34);

    printf("cases=%u failures=%u\n", cases, failures);
    return failures ? 1 : 0;
}
