/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Foreign-process control probe for the urov-lab KPM.
 *
 * Run as a different process (root shell is fine) while another process owns
 * an active session.  It checks that:
 *   - QUERY from a non-owner does not expose or adopt the owner's session;
 *   - SET / DEACTIVATE from a non-owner are rejected;
 *   - after the owner dies, the next control request reaps the stale session.
 *
 * The legacy __NR_kcmp channel is used because this helper runs outside the
 * app seccomp sandbox; the app-facing channel is exercised by the app test.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../urov_abi.h"

static long notify(unsigned int cmd, struct urov_request *q)
{
    errno = 0;
    return syscall(UROV_NOTIFY_NR, (long)UROV_NOTIFY_MAGIC, (long)cmd, q,
                   (long)sizeof(*q));
}

static struct urov_request request(unsigned int op)
{
    struct urov_request q;
    memset(&q, 0, sizeof(q));
    q.size = sizeof(q);
    q.version = UROV_ABI_VERSION;
    q.op = (uint16_t)op;
    return q;
}

int main(int argc, char **argv)
{
    struct urov_request q;
    long rc;

    if (argc < 2) {
        fprintf(stderr, "usage: %s query|set <generation> <value>|deactivate\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "query")) {
        q = request(UROV_NOTIFY_QUERY);
        rc = notify(UROV_NOTIFY_QUERY, &q);
        printf("query rc=%ld errno=%d caps=0x%llx state=%u session=%llu gen=%llu "
               "last_error=%d\n",
               rc, errno, (unsigned long long)q.caps, q.state,
               (unsigned long long)q.session, (unsigned long long)q.generation,
               q.last_error);
        return rc ? 1 : 0;
    }
    if (!strcmp(argv[1], "set")) {
        q = request(UROV_NOTIFY_SET);
        q.session = 1;
        q.expected_generation = argc > 2 ? strtoull(argv[2], NULL, 0) : 1;
        q.length = 8;
        q.value = argc > 3 ? strtoull(argv[3], NULL, 0) : 0x1111222233334444ULL;
        rc = notify(UROV_NOTIFY_SET, &q);
        printf("set rc=%ld errno=%d gen=%llu\n", rc, errno,
               (unsigned long long)q.generation);
        return rc ? 1 : 0;
    }
    if (!strcmp(argv[1], "deactivate")) {
        q = request(UROV_NOTIFY_DEACTIVATE);
        q.session = 1;
        rc = notify(UROV_NOTIFY_DEACTIVATE, &q);
        printf("deactivate rc=%ld errno=%d state=%u\n", rc, errno, q.state);
        return rc ? 1 : 0;
    }
    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 2;
}
