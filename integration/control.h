/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UZ_TEST_CONTROL_H
#define UZ_TEST_CONTROL_H
#include <stddef.h>
int test_kpatch(const char *key, const char *operation, const char *argument, char *out, size_t capacity);
#endif
