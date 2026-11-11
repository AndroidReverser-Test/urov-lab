/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUERY also releases a dead owner's session in a sleepable syscall context. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../module/abi.h"

int main(int argc, char **argv)
{
    uint8_t key[16];
    struct uz_keys keys;
    struct urov_z_request q = {.size = sizeof(q), .version = UROV_Z_ABI_VERSION,
                               .op = UROV_Z_QUERY};
    if (argc != 2 || uz_parse_key(argv[1], (unsigned)strlen(argv[1]), key)) {
        fprintf(stderr, "Usage: %s <32-hex-module-key>\n", argv[0]);
        return 2;
    }
    uz_derive(key, &keys);
    q.mac = urov_z_request_mac(keys.mac, &q);
    long rc = syscall(__NR_prctl, (unsigned long)keys.option,
                      (unsigned long)UROV_Z_PRCTL_MAGIC, (unsigned long)q.op,
                      &q, (unsigned long)sizeof(q));
    if (rc < 0) { perror("QUERY"); return 1; }
    printf("QUERY state=%u max_pages=%u shift=%u caps=0x%" PRIx64 "\n",
           q.state, q.page_count, q.page_stride, q.session_flags);
    return 0;
}
