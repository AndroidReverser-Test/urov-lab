/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include "control_core.h"

void urov_record_begin(struct urov_control_record *r, uint64_t id, const struct urov_request *q)
{
    r->id = id;
    r->registration_id = q->request_id;
    r->address = q->address;
    r->initial_value = q->value;
    r->flags = q->flags;
    r->value = q->value;
    r->generation = 1;
    r->last_set_id = 0;
    r->last_set_expected = 0;
    r->last_set_value = 0;
    r->offset = q->offset;
    r->state = UROV_ACTIVE;
    r->error = 0;
}

void urov_record_report(struct urov_request *q, const struct urov_control_record *r,
                        uint64_t hits, uint64_t failures)
{
    q->session = r->id;
    q->address = r->address;
    q->offset = r->offset;
    q->value = __atomic_load_n(&r->value, __ATOMIC_ACQUIRE);
    q->generation = r->generation;
    q->state = r->state;
    q->last_error = r->error;
    q->hits = hits;
    q->failures = failures;
}

static void report_inactive(struct urov_request *q)
{
    q->session = 0;
    q->generation = 0;
    q->hits = 0;
    q->failures = 0;
    q->state = UROV_INACTIVE;
    q->last_error = 0;
}

static int same_registration(const struct urov_request *q, const struct urov_control_record *r)
{
    return q->request_id == r->registration_id && q->address == r->address &&
           q->offset == r->offset && q->value == r->initial_value && q->flags == r->flags &&
           q->session == 0 && q->expected_generation == 0;
}

static int set_value(const struct urov_request *q, struct urov_control_record *r)
{
    if (r->state != UROV_ACTIVE) return -EBUSY;
    if (!q->request_id) return -EINVAL;
    if (q->request_id == r->last_set_id) {
        if (q->expected_generation != r->last_set_expected || q->value != r->last_set_value)
            return -EINVAL;
        return 0;
    }
    if (q->expected_generation != r->generation) return -EAGAIN;
    if (r->generation == ~(uint64_t)0) return -EOVERFLOW;

    r->last_set_id = q->request_id;
    r->last_set_expected = q->expected_generation;
    r->last_set_value = q->value;
    __atomic_store_n(&r->value, q->value, __ATOMIC_RELEASE);
    ++r->generation;
    return 0;
}

int urov_control_decide(struct urov_request *q, struct urov_control_record *r, int owner,
                        uint64_t caps, uint64_t hits, uint64_t failures)
{
    const uint64_t registration_caps = UROV_CAP_READY | UROV_CAP_MM_GATES;
    int result;
    if (!q || q->size != sizeof(*q) || q->version != UROV_ABI_VERSION ||
        q->reserved0 || q->reserved[0] || q->reserved[1] || q->reserved[2] ||
        (q->flags & ~UROV_F_RAW_XOM) || q->op < UROV_QUERY || q->op > UROV_DEACTIVATE)
        return -EINVAL;

    q->caps = caps;
    if (q->op == UROV_QUERY || (!r && q->op == UROV_DEACTIVATE)) {
        report_inactive(q);
        return UROV_CTL_REPLIED;
    }
    if (q->op == UROV_REGISTER) {
        if (!r) {
            if ((caps & registration_caps) != registration_caps) return -EOPNOTSUPP;
            if (!q->request_id || q->session || q->expected_generation ||
                q->address < UROV_PAGE_BYTES || (q->address & (UROV_PAGE_BYTES - 1)) ||
                q->offset > UROV_PAGE_BYTES - sizeof(uint64_t)) return -EINVAL;
            return UROV_CTL_REGISTER;
        }
        if (!owner || !same_registration(q, r)) return -EBUSY;
        urov_record_report(q, r, hits, failures);
        return UROV_CTL_REPLIED;
    }
    if (!r) return -ENOENT;
    if (!owner) return -EPERM;
    if (q->session != r->id && !(q->op == UROV_STATUS && !q->session &&
                                 q->request_id == r->registration_id)) return -ESTALE;
    if (q->op == UROV_DEACTIVATE) return UROV_CTL_DEACTIVATE;
    if (q->op == UROV_SET) {
        result = set_value(q, r);
        if (result) return result;
    }
    urov_record_report(q, r, hits, failures);
    return UROV_CTL_REPLIED;
}
