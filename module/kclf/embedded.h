/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_KCLF_EMBEDDED_H
#define UROV_KCLF_EMBEDDED_H

long urov_kclf_init(void);
long urov_kclf_control(const char *args, char *out, int len);
long urov_kclf_exit(void);

/* Sleepable kernel-internal loader read. No EL0 bypass is exposed. */
int urov_z_read_current_real(unsigned long addr, void *buf, int len);
#endif
