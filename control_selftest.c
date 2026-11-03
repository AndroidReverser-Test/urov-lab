/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include "control_core.h"

/* Keep the fixture freestanding; the default KPM has no libc memset import. */
static void new_request(struct urov_request *q, uint16_t op)
{
    volatile unsigned char *bytes = (volatile unsigned char *)q;
    unsigned int i;
    for (i = 0; i < sizeof(*q); ++i) bytes[i] = 0;
    q->size = sizeof(*q);
    q->version = UROV_ABI_VERSION;
    q->op = op;
}

static void registration(struct urov_request *q)
{
    new_request(q, UROV_REGISTER);
    q->address = 0x10000;
    q->offset = 4;
    q->value = 42;
    q->request_id = 100;
}

int urov_control_selftest(unsigned int *checks)
{
    struct urov_control_record record;
    struct urov_request q;
    unsigned int i;
    const uint64_t ready = UROV_CAP_READY | UROV_CAP_MM_GATES;
    const uint64_t max_generation = ~(uint64_t)0;
    if (!checks) return __LINE__;
    *checks = 0;
#define CHECK(expr) do { ++*checks; if (!(expr)) return __LINE__; } while (0)
#define DECIDE(r, owner, caps) urov_control_decide(&q, (r), (owner), (caps), 7, 3)
    new_request(&q, UROV_QUERY);
    q.caps = ready;
    CHECK(DECIDE(0, 0, UROV_CAP_MODEL_CORE) == UROV_CTL_REPLIED);
    CHECK(q.caps == UROV_CAP_MODEL_CORE && q.state == UROV_INACTIVE && !q.session &&
          !q.generation && !q.hits && !q.failures && !q.last_error);
    q.size--;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    ++q.size; ++q.version;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    --q.version; q.flags = 2;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    q.flags = 0; q.reserved0 = 1;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    q.reserved0 = 0;
    for (i = 0; i < 3; ++i) {
        q.reserved[i] = 1;
        CHECK(DECIDE(0, 0, ready) == -EINVAL);
        q.reserved[i] = 0;
    }
    q.op = 0;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    q.op = UROV_DEACTIVATE + 1;
    CHECK(DECIDE(0, 0, ready) == -EINVAL);
    q.op = UROV_STATUS;
    CHECK(DECIDE(0, 1, ready) == -ENOENT);
    q.op = UROV_SET;
    CHECK(DECIDE(0, 1, ready) == -ENOENT);
    q.op = UROV_DEACTIVATE; q.session = 444; q.state = UROV_ACTIVE;
    CHECK(DECIDE(0, 0, ready) == UROV_CTL_REPLIED && q.state == UROV_INACTIVE && !q.session);

    registration(&q);
    CHECK(DECIDE(0, 1, UROV_CAP_MODEL_CORE) == -EOPNOTSUPP);
    CHECK(DECIDE(0, 1, UROV_CAP_READY) == -EOPNOTSUPP);
    CHECK(DECIDE(0, 1, UROV_CAP_MM_GATES) == -EOPNOTSUPP);
    q.request_id = 0;
    CHECK(DECIDE(0, 1, ready) == -EINVAL);
    q.request_id = 100; q.session = 9;
    CHECK(DECIDE(0, 1, ready) == -EINVAL);
    q.session = 0; q.expected_generation = 1;
    CHECK(DECIDE(0, 1, ready) == -EINVAL);
    q.expected_generation = 0; ++q.address;
    CHECK(DECIDE(0, 1, ready) == -EINVAL);
    --q.address; q.offset = UROV_PAGE_BYTES - 7;
    CHECK(DECIDE(0, 1, ready) == -EINVAL);
    q.offset = UROV_PAGE_BYTES - 8;
    CHECK(DECIDE(0, 1, ready) == UROV_CTL_REGISTER);
    registration(&q);
    CHECK(DECIDE(0, 1, ready) == UROV_CTL_REGISTER);
    urov_record_begin(&record, 12, &q);
    urov_record_report(&q, &record, 0, 0);
    CHECK(q.session == 12 && q.generation == 1 && q.state == UROV_ACTIVE && q.value == 42);

    /* Lost REGISTER reply: repeat the original request or recover a handle
     * by registration ID; a non-owner must learn neither handle nor value. */
    registration(&q);
    CHECK(DECIDE(&record, 0, ready) == -EBUSY && !q.session);
    ++q.value;
    CHECK(DECIDE(&record, 1, ready) == -EBUSY && !q.session);
    --q.value; q.flags = UROV_F_RAW_XOM;
    CHECK(DECIDE(&record, 1, ready) == -EBUSY);
    q.flags = 0;
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.session == 12 && q.generation == 1);
    new_request(&q, UROV_STATUS); q.request_id = 99;
    CHECK(DECIDE(&record, 1, ready) == -ESTALE);
    ++q.request_id;
    CHECK(DECIDE(&record, 0, ready) == -EPERM && !q.session);
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.session == 12 &&
          q.address == 0x10000 && q.offset == 4 && q.hits == 7 && q.failures == 3);
    new_request(&q, UROV_QUERY); q.session = 123;
    CHECK(DECIDE(&record, 0, ready) == UROV_CTL_REPLIED && !q.session && !q.hits &&
          q.state == UROV_INACTIVE && record.state == UROV_ACTIVE);

    new_request(&q, UROV_SET); q.session = 12; q.value = 99; q.expected_generation = 1;
    CHECK(DECIDE(&record, 1, ready) == -EINVAL);
    q.request_id = 101;
    CHECK(DECIDE(&record, 0, ready) == -EPERM && record.value == 42);
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.generation == 2 &&
          __atomic_load_n(&record.value, __ATOMIC_ACQUIRE) == 99);
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.generation == 2);
    q.value = 44;
    CHECK(DECIDE(&record, 1, ready) == -EINVAL && record.value == 99);
    q.value = 99; ++q.expected_generation;
    CHECK(DECIDE(&record, 1, ready) == -EINVAL && record.generation == 2);
    ++q.request_id; --q.expected_generation;
    CHECK(DECIDE(&record, 1, ready) == -EAGAIN && record.last_set_id == 101);
    registration(&q);
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.generation == 2 && q.value == 99);

    record.generation = max_generation;
    new_request(&q, UROV_SET); q.request_id = 103; q.session = 12; q.expected_generation = max_generation;
    CHECK(DECIDE(&record, 1, ready) == -EOVERFLOW && record.generation == max_generation &&
          record.last_set_id == 101 && record.value == 99);
    record.state = UROV_RETAINED; record.error = -ESTALE;
    CHECK(DECIDE(&record, 1, ready) == -EBUSY);
    q.op = UROV_STATUS;
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_REPLIED && q.state == UROV_RETAINED &&
          q.last_error == -ESTALE && q.value == 99);
    q.op = UROV_DEACTIVATE; q.session++;
    CHECK(DECIDE(&record, 1, ready) == -ESTALE);
    q.session--;
    CHECK(DECIDE(&record, 0, ready) == -EPERM);
    CHECK(DECIDE(&record, 1, ready) == UROV_CTL_DEACTIVATE && record.state == UROV_RETAINED);
    /* A fresh record after completed cleanup cannot replay the previous SET. */
    registration(&q);
    urov_record_begin(&record, 13, &q);
    CHECK(record.id == 13 && record.generation == 1 && record.value == 42 && !record.error &&
          !record.last_set_id && !record.last_set_expected && !record.last_set_value);
#undef DECIDE
#undef CHECK
    return 0;
}
