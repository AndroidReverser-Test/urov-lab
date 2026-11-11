/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include "urov/urov.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "UROV requires little-endian AArch64 userspace"
#endif

#define UROV_CLIENT_READY UINT32_C(0x555a4131)

static void erase(void *ptr, size_t bytes)
{
    volatile unsigned char *p = ptr;
    while (bytes--) *p++ = 0;
}

int urov_client_init_bytes(struct urov_client *client, const uint8_t key[16])
{
    struct urov_client next = {0};
    if (!client || !key) return -EINVAL;
    uz_derive(key, &next.private_keys);
    next.private_ready = UROV_CLIENT_READY;
    *client = next;
    erase(&next, sizeof(next));
    return 0;
}

int urov_client_init(struct urov_client *client, const char *hex_key)
{
    uint8_t key[16] = {0};
    int ret = -EINVAL;
    if (client && hex_key && !uz_parse_key(hex_key, (unsigned)strnlen(hex_key, 33), key))
        ret = urov_client_init_bytes(client, key);
    erase(key, sizeof(key));
    return ret;
}

void urov_client_destroy(struct urov_client *client)
{
    if (client) erase(client, sizeof(*client));
}

void urov_request_init(struct urov_z_request *request, unsigned op)
{
    if (!request) return;
    memset(request, 0, sizeof(*request));
    request->size = sizeof(*request);
    request->version = UROV_Z_ABI_VERSION;
    request->op = (uint16_t)op;
}

int urov_call(const struct urov_client *client, struct urov_z_request *request)
{
    struct urov_z_request wire;
    long ret;
    if (!client || client->private_ready != UROV_CLIENT_READY || !request)
        return -EINVAL;
    if (request->op < UROV_Z_QUERY || request->op > UROV_Z_SET_PAGE) return -EINVAL;
    wire = *request;
    wire.size = sizeof(wire);
    wire.version = UROV_Z_ABI_VERSION;
    wire.mac = urov_z_request_mac(client->private_keys.mac, &wire);
    ret = syscall(__NR_prctl, (unsigned long)client->private_keys.option,
                  (unsigned long)UROV_Z_PRCTL_MAGIC, (unsigned long)wire.op,
                  &wire, (unsigned long)sizeof(wire));
    if (ret < 0) return -errno;
    if (ret) return -EPROTO;
    *request = wire;
    return 0;
}

static void status_reply(const struct urov_z_request *q, struct urov_status *out)
{
    *out = (struct urov_status){
        .session = q->session, .generation = q->generation,
        .capabilities = q->session_flags, .hits = q->hits,
        .replays = q->replays, .failures = q->failures,
        .state = q->state, .page_count = q->page_count,
        .armed_pages = q->op == UROV_Z_STATUS ? (uint32_t)q->reserved : 0,
        .first_page_offset = q->offset, .first_page_length = q->length,
    };
}

static int call_status(const struct urov_client *client, struct urov_z_request *q,
                       struct urov_status *out)
{
    int ret;
    if (!out) return -EINVAL; /* validate before a mutation can commit */
    ret = urov_call(client, q);
    if (!ret) status_reply(q, out);
    return ret;
}

int urov_query(const struct urov_client *client, struct urov_info *out)
{
    struct urov_z_request q;
    int ret;
    if (!out) return -EINVAL;
    urov_request_init(&q, UROV_Z_QUERY);
    ret = urov_call(client, &q);
    if (!ret) *out = (struct urov_info){
        .capabilities = q.session_flags, .session = q.session,
        .generation = q.generation, .state = q.state,
        .max_pages = q.page_count, .page_shift = q.page_stride,
        .abi_version = q.version,
    };
    return ret;
}

int urov_get_status(const struct urov_client *client, struct urov_status *out)
{
    struct urov_z_request q;
    urov_request_init(&q, UROV_Z_STATUS);
    q.session = 1;
    return call_status(client, &q, out);
}

int urov_register_pages(const struct urov_client *client,
                        const struct urov_page *pages, size_t count,
                        struct urov_status *out)
{
    struct urov_z_request q;
    struct uz_page_desc *descs;
    int ret;
    if (!out || !pages || !count || count > UROV_Z_MAX_PAGES) return -EINVAL;
    descs = calloc(count, sizeof(*descs));
    if (!descs) return -ENOMEM;
    for (size_t i = 0; i < count; ++i) {
        descs[i].base = (uintptr_t)pages[i].base;
        descs[i].fake_addr = (uintptr_t)pages[i].image;
        descs[i].fake_off = pages[i].offset;
        descs[i].fake_len = pages[i].length;
        descs[i].flags = UROV_Z_PAGE_SRC_USER;
    }
    urov_request_init(&q, UROV_Z_REGISTER);
    q.page_count = (uint32_t)count;
    q.page_stride = sizeof(*descs);
    /* Android may tag calloc pointers even when the caller supplied untagged
     * image addresses. The wire ABI requires an untagged descriptor address. */
    q.pages_addr = (uintptr_t)descs & UINT64_C(0x00ffffffffffffff);
    ret = call_status(client, &q, out);
    free(descs);
    return ret;
}

static int inline_bytes(struct urov_z_request *q, const void *bytes, size_t length)
{
    const uint8_t *p = bytes;
    if (!p || length < 8 || length > UROV_Z_FAKE_MAX || (length & 7U)) return -EINVAL;
    q->length = (uint32_t)length;
    q->value = uz_load64(p);
    for (size_t i = 8; i < length; i += 8) q->value_hi[(i - 8) / 8] = uz_load64(p + i);
    return 0;
}

int urov_register_inline(const struct urov_client *client, const void *base,
                         uint32_t offset, const void *bytes, size_t length,
                         struct urov_status *out)
{
    struct urov_z_request q;
    int ret;
    urov_request_init(&q, UROV_Z_REGISTER);
    q.address = (uintptr_t)base;
    q.offset = offset;
    ret = inline_bytes(&q, bytes, length);
    return ret ? ret : call_status(client, &q, out);
}

int urov_set_page(const struct urov_client *client, uint32_t index,
                  uint64_t expected_generation, uint32_t offset,
                  const void *image, uint32_t length, struct urov_status *out)
{
    struct urov_z_request q;
    urov_request_init(&q, UROV_Z_SET_PAGE);
    q.session = 1;
    q.expected_generation = expected_generation;
    q.reserved = index;
    q.offset = offset;
    q.fake_addr = (uintptr_t)image;
    q.length = length;
    return call_status(client, &q, out);
}

int urov_set_inline(const struct urov_client *client, uint64_t expected_generation,
                    const void *bytes, size_t length, struct urov_status *out)
{
    struct urov_z_request q;
    int ret;
    urov_request_init(&q, UROV_Z_SET);
    q.session = 1;
    q.expected_generation = expected_generation;
    ret = inline_bytes(&q, bytes, length);
    return ret ? ret : call_status(client, &q, out);
}

int urov_deactivate(const struct urov_client *client)
{
    struct urov_z_request q;
    urov_request_init(&q, UROV_Z_DEACTIVATE);
    q.session = 1;
    return urov_call(client, &q);
}
