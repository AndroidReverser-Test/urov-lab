/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "urov/urov.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct urov_client client = {0};
    struct urov_info info;
    int ret;
    if (argc != 2 || urov_client_init(&client, argv[1])) {
        fprintf(stderr, "Usage: %s <32-hex-module-key>\n", argv[0]);
        return 2;
    }
    ret = urov_query(&client, &info);
    urov_client_destroy(&client);
    if (ret) {
        fprintf(stderr, "QUERY: %s (%d)\n", strerror(-ret), ret);
        return 1;
    }
    printf("QUERY state=%u max_pages=%u shift=%u caps=0x%" PRIx64 "\n",
           info.state, info.max_pages, info.page_shift, info.capabilities);
    return 0;
}
