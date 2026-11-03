/* SPDX-License-Identifier: GPL-2.0-or-later */
/* NO activation backend: no fault hooks, PTE writes, pinning or async work.
 * This builds a deliberately separate urov-lab-check.kpm, not urov-lab.kpm. */
#include <compiler.h>
#include <common.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "emulate.h"

KPM_NAME("urov-lab-check");
KPM_VERSION("0.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("TEST");
KPM_DESCRIPTION("Read-only UROV preflight and kernel emulation-core selftest; NO overlay backend");

struct pt_regs;
extern int uro_fault_signature(unsigned long, unsigned long, struct pt_regs *);
typedef long (*copy_kernel_fn)(void *, const void *, size_t);
typedef long (*copy_user_fn)(void __user *, const void *, size_t);
struct check_fault_info {
    unsigned long fn;
    int sig, code;
    unsigned long name;
};
_Static_assert(sizeof(struct check_fault_info) == 24, "Unexpected local ABI");

static uint8_t scratch[URO_PAGE_SIZE];
static unsigned self_checks;
static int kernel_match, slot_match, type_match;
static unsigned symbols;
static copy_user_fn copy_out;
static int exit_veto;

static int contains(const char *text, const char *word)
{
    size_t i, j;
    for (i = 0; text[i]; ++i) {
        for (j = 0; word[j] && text[i + j] == word[j]; ++j) { }
        if (!word[j]) return 1;
    }
    return 0;
}
static long check_init(const char *args, const char *event, void *reserved)
{
    static const char *const required[] = {
        "get_task_mm", "mmput", "pin_user_pages_unlocked", "unpin_user_pages",
        "apply_to_existing_page_range", "down_write", "up_write",
        "synchronize_rcu", "synchronize_rcu_tasks", "synchronize_rcu_tasks_rude",
        "copy_from_user_nofault", "copy_to_kernel_nofault"
    };
    copy_kernel_fn copy_in;
    unsigned long table, native, banner;
    struct check_fault_info entry;
    char text[256] = { 0 };
    uint32_t native_type = 0, our_type = 0;
    unsigned i;
    (void)event; (void)reserved;
    if (!kfunc(strcmp) || !kfunc(snprintf) || !kallsyms_lookup_name) return -ENOSYS;
    if (args && args[0] && strcmp(args, "inspect") && strcmp(args, "veto-test")) return -EINVAL;
    exit_veto = args && !strcmp(args, "veto-test");
    if (endian != little) return -EOPNOTSUPP;
    if (uro_core_selftest(scratch, &self_checks)) return -EINVAL;
    copy_out = (copy_user_fn)kallsyms_lookup_name("copy_to_user_nofault");
    copy_in = (copy_kernel_fn)kallsyms_lookup_name("copy_from_kernel_nofault");
    if (!copy_out || !copy_in) return -EOPNOTSUPP;
    for (i = 0; i < sizeof(required) / sizeof(required[0]); ++i)
        if (kallsyms_lookup_name(required[i])) symbols |= 1U << i;
    banner = kallsyms_lookup_name("linux_banner");
    if (banner && !copy_in(text, (const void *)banner, sizeof(text) - 1))
        kernel_match = contains(text, "6.1.134-android14-11-g66e758f7d0c0-ab13748739");
    if (kernel_match) {
        table = kallsyms_lookup_name("fault_info");
        native = kallsyms_lookup_name("do_page_fault");
        if (table && native && !copy_in(&entry,
            (const void *)(table + 15U * sizeof(entry)), sizeof(entry)))
            slot_match = entry.fn == native && entry.sig == 11 && entry.code == 2;
        if (native && !copy_in(&native_type, (const void *)(native - 4), 4) &&
            !copy_in(&our_type, (const char *)(uintptr_t)&uro_fault_signature - 4, 4))
            type_match = native_type != 0 && native_type == our_type;
    }
    return 0;
}
static long check_ctl(const char *args, char __user *out, int outlen)
{
    char message[640];
    unsigned long mmfr1, sctlr;
    int len;
    if (!args) return -EINVAL;
    if (!strcmp(args, "register")) return -EOPNOTSUPP;
    if (!strcmp(args, "allow-exit")) {
        __atomic_store_n(&exit_veto, 0, __ATOMIC_RELEASE);
        return 0;
    }
    if (strcmp(args, "status") && strcmp(args, "selftest")) return -EINVAL;
    if (!out || outlen <= 0) return -EINVAL;
    __asm__ volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
    __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    len = snprintf(message, sizeof(message),
        "abi=1 mode=preflight active=0 backend=none core=pass checks=%u "
        "kernel=0x%x kp=0x%x kernel_match=%d slot_match=%d kcfi_type_match=%d "
        "symbols=0x%x cpu_pan=%lu cpu_epan=%lu "
        "entry_writable=unverified loader_contract=unverified "
        "reason=activation_backend_not_available\n",
        self_checks, kver, kpver, kernel_match, slot_match, type_match,
        symbols, (mmfr1 >> 20) & 15UL, (sctlr >> 57) & 1UL);
    if (len < 0 || len >= (int)sizeof(message)) return -EOVERFLOW;
    if (outlen <= len) return -ENOSPC;
    return copy_out(out, message, (size_t)len + 1);
}
static long check_exit(void *reserved)
{
    (void)reserved;
    /* No pointers or resources escaped this module's synchronous callbacks. */
    return __atomic_exchange_n(&exit_veto, 0, __ATOMIC_ACQ_REL) ? -EBUSY : 0;
}
KPM_INIT(check_init);
KPM_CTL0(check_ctl);
KPM_EXIT(check_exit);
