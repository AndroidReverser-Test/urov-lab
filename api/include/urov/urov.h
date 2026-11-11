/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_USER_API_H
#define UROV_USER_API_H

#include <stddef.h>
#include <stdint.h>
#include "abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UROV_API_VERSION 1U

/* Initialize once; share read-only between threads. Fields are private to the
 * implementation. Destroy only after all calls have completed. Not a handle
 * to a kernel session: session ownership follows the caller's address space. */
struct urov_client {
    struct uz_keys private_keys;
    uint32_t private_ready;
};

struct urov_info {
    uint64_t capabilities;
    uint64_t session;
    uint64_t generation;
    uint32_t state;
    uint32_t max_pages;
    uint32_t page_shift;
    uint32_t abi_version;
};

struct urov_status {
    uint64_t session;
    uint64_t generation;
    uint64_t capabilities;
    uint64_t hits;
    uint64_t replays;
    uint64_t failures;
    uint32_t state;
    uint32_t page_count;
    uint32_t armed_pages; /* meaningful for urov_get_status() only */
    uint32_t first_page_offset;
    uint32_t first_page_length;
};

struct urov_page {
    const void *base;  /* page-aligned RX file mapping, untagged address */
    const void *image; /* bytes copied into [offset, offset + length) */
    uint32_t offset;
    uint32_t length;   /* 0 means a full runtime page, with offset == 0 */
};

/* All int-returning calls return 0 or a negative errno. They do not retry:
 * EBUSY and EAGAIN remain visible to the caller. Output objects are unchanged
 * on failure. EFAULT on final copy-out can follow a committed operation;
 * query status before retrying a mutation. errno itself is unspecified. */
int urov_client_init(struct urov_client *client, const char *hex_key);
int urov_client_init_bytes(struct urov_client *client, const uint8_t key[16]);
void urov_client_destroy(struct urov_client *client);

int urov_query(const struct urov_client *client, struct urov_info *out);
int urov_get_status(const struct urov_client *client, struct urov_status *out);
int urov_register_pages(const struct urov_client *client,
                        const struct urov_page *pages, size_t count,
                        struct urov_status *out);
int urov_register_inline(const struct urov_client *client, const void *base,
                         uint32_t offset, const void *bytes, size_t length,
                         struct urov_status *out);
int urov_set_page(const struct urov_client *client, uint32_t index,
                  uint64_t expected_generation, uint32_t offset,
                  const void *image, uint32_t length, struct urov_status *out);
int urov_set_inline(const struct urov_client *client, uint64_t expected_generation,
                    const void *bytes, size_t length, struct urov_status *out);
int urov_deactivate(const struct urov_client *client);

/* Low-level escape hatch for ABI tests. Start with a fresh zeroed request for
 * EVERY call; never reuse response fields as mutation input. call() supplies
 * size, version and MAC, and copies the reply back only on success. */
void urov_request_init(struct urov_z_request *request, unsigned op);
int urov_call(const struct urov_client *client, struct urov_z_request *request);

#ifdef __cplusplus
}
#endif
#endif
