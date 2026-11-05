/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/mman.h>
#include "crc_patch_fixture.h"
#include "uy_fixture_control.h"

/* Both mutation paths accept only the dedicated CRC test instruction. The
 * writable private alias is isolated from the library's linker mapping. */
static int original_word(const void *page)
{
    uint32_t word;
    if (!page || (uintptr_t)page % UROV_Y_PAGE) return EINVAL;
    memcpy(&word, (const uint8_t *)page + CRC_PATCH_OFFSET, sizeof(word));
    return word == CRC_MOV_W0(CRC_ORIGINAL_RETURN) ? 0 : EPROTO;
}

int urov_crc_patch_private(void *page, int *written)
{
    uint32_t word = CRC_MOV_W0(CRC_PATCHED_RETURN);
    int error = original_word(page);
    *written = 0;
    if (error) return error;
    char *instruction = (char *)page + CRC_PATCH_OFFSET;
    if (mprotect(page, UROV_Y_PAGE, PROT_READ | PROT_WRITE)) return errno;
    memcpy(instruction, &word, sizeof(word));
    *written = 1;
    __builtin___clear_cache(instruction, instruction + sizeof(word));
    if (mprotect(page, UROV_Y_PAGE, PROT_READ | PROT_EXEC)) return errno;
    return 0;
}

int urov_crc_remap(void *page, int patched_fd, off_t patched_offset)
{
    uint32_t word;
    int error = original_word(page);
    if (error) return error;
    if (patched_offset < 0 || patched_offset % UROV_Y_PAGE) return EINVAL;
    ssize_t got = pread(patched_fd, &word, sizeof(word), patched_offset + CRC_PATCH_OFFSET);
    if (got != sizeof(word)) return got < 0 ? errno : EIO;
    if (word != CRC_MOV_W0(CRC_PATCHED_RETURN)) return EPROTO;
    if (mmap(page, UROV_Y_PAGE, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED,
             patched_fd, patched_offset) == MAP_FAILED) return errno;
    return 0;
}

long urov_crc_control(const char *key, struct urov_y_request *request)
{
    struct uy_ctx ctx;
    if (uy_init_key(&ctx, key)) { errno = EINVAL; return -1; }
    return uy_control(&ctx, request->op, request);
}
