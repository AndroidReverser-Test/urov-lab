/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Test utility, sharing the deterministic credential with both test Apps. */
#include "../test_config.h"
#include <stdio.h>
#include <urov/urov.h>
int main(void)
{
    struct urov_client client;
    struct urov_info info;
    int rc = urov_client_init(&client, UROV_TEST_KEY);
    if (!rc) rc = urov_query(&client, &info);
    if (rc) fprintf(stderr, "QUERY failed: %d\n", rc);
    else printf("QUERY state=%u max_pages=%u shift=%u caps=0x%llx\n",
                info.state, info.max_pages, info.page_shift, (unsigned long long)info.capabilities);
    urov_client_destroy(&client);
    return rc ? 1 : 0;
}
