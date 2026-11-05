/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef CRC_PATCH_FIXTURE_H
#define CRC_PATCH_FIXTURE_H

#include <sys/types.h>
#include "../../urov_y_abi.h"

#define CRC_PAYLOAD_SIZE 12U
#define CRC_PATCH_OFFSET 4U
#define CRC_STABLE_OFFSET 8U
#define CRC_ORIGINAL_RETURN 0x1234
#define CRC_PATCHED_RETURN 0x1235
#define CRC_MOV_W0(value) (UINT32_C(0x52800000) | ((uint32_t)(value) << 5))

int urov_crc_patch_private(void *page, int *written);
int urov_crc_remap(void *page, int patched_fd, off_t patched_offset);
long urov_crc_control(const char *key, struct urov_y_request *request);

#endif
