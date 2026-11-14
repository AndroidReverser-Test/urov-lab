/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_KCLF_EMBEDDED_H
#define UROV_KCLF_EMBEDDED_H

struct kclf_btf;
/* Called before overlay hooks are installed. BTF is borrowed only for the
 * duration of set_btf; the loader retains an independently owned profile. */
int urov_kclf_set_btf(const struct kclf_btf *btf);
int urov_kclf_preflight(void);
long urov_kclf_init(void);
long urov_kclf_control(const char *args, char *out, int len);
long urov_kclf_exit(void);

/* Sleepable kernel-internal loader read. No EL0 bypass is exposed. */
int urov_z_read_current_real(unsigned long addr, void *buf, int len);
#endif
