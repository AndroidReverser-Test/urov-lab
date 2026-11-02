/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compiled with KCFI only to compare genuine compiler-generated type metadata.
 * NEVER registered, installed, or called by this preflight module. */
struct pt_regs;
int uro_fault_signature(unsigned long far, unsigned long esr, struct pt_regs *regs)
{
    (void)far; (void)esr; (void)regs;
    return 1;
}
