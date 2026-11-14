/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../module/runtime_compat.h"
#include "../module/decode.h"

static int pgdat[4], calls, last_nid;
static char result_page;
static int absent, fail_policy;
static void *first_online(void) { return absent ? NULL : pgdat; }
static void *alloc_policy(unsigned gfp, unsigned order)
{
    assert(!gfp && !order);
    ++calls;
    return fail_policy ? NULL : &result_page;
}
static void *alloc_node(unsigned gfp, unsigned order, int nid, void *mask)
{
    assert(!gfp && !order && !mask && nid >= 0);
    last_nid = nid;
    ++calls;
    return &result_page;
}

int main(void)
{
    struct uz_remote_gup_choice c;
    for (int argc = 6; argc <= 8; ++argc) {
        c = uz_remote_gup_select(0, 0, argc, 0);
        assert(c.entry == UZ_REMOTE_GET && c.argc == argc && c.get_refs);
        c = uz_remote_gup_select(argc, 0, argc, 0);
        assert(c.entry == UZ_REMOTE_SHARED && c.argc == argc && c.get_refs);
        c = uz_remote_gup_select(argc, argc, argc, 1);
        assert(c.entry == UZ_REMOTE_SHARED && c.argc == argc && !c.get_refs);
        c = uz_remote_gup_select(0, argc, argc, 1);
        assert(c.entry == UZ_REMOTE_PIN && c.argc == argc && !c.get_refs);
        c = uz_remote_gup_select(0, 0, argc, 1); /* broken PIN, valid GET */
        assert(c.entry == UZ_REMOTE_NONE && !c.argc && !c.get_refs);
        c = uz_remote_gup_select(argc, 0, 0, 0); /* no proven reference API */
        assert(c.entry == UZ_REMOTE_NONE && !c.argc && !c.get_refs);
    }
    puts("PASS remote GUP selection: 18 public/shared GET/PIN, backport and missing-ABI cases");

    struct uz_page_allocator a = {0};
    assert(!uz_page_allocator_ready(&a) && !uz_alloc_order0(&a));
    a.node = alloc_node;
    a.first_online = first_online;
    a.node_id_offset = 2 * sizeof(int);
    assert(uz_page_allocator_ready(&a));
    pgdat[2] = 3;
    assert(uz_alloc_order0(&a) == &result_page && last_nid == 3 && calls == 1);
    pgdat[2] = 7;
    assert(uz_alloc_order0(&a) == &result_page && last_nid == 7 && calls == 2);
    pgdat[2] = -1;
    assert(!uz_alloc_order0(&a) && calls == 2);
    absent = 1;
    assert(!uz_alloc_order0(&a) && calls == 2);
    a.policy = alloc_policy;
    assert(uz_alloc_order0(&a) == &result_page && calls == 3);
    fail_policy = 1;
    assert(!uz_alloc_order0(&a) && calls == 4); /* no bypass of policy failure */
    a.policy = NULL;
    a.node_id_offset = -1;
    assert(!uz_page_allocator_ready(&a) && !uz_alloc_order0(&a));
    puts("PASS allocator: runtime online node, no -1, policy preference and unavailable/failure paths");

    assert(!uz_access_vm_result(UINT64_C(0xfffffff2), 4096));
    assert(!uz_access_vm_result(UINT64_C(0xfffffffffffffff2), 4096));
    assert(!uz_access_vm_result(4097, 4096));
    assert(!uz_access_vm_result(1, UINT32_MAX));
    assert(!uz_access_vm_result(0, 4096));
    assert(!uz_access_vm_result(1, 0));
    assert(uz_access_vm_result(37, 4096) == 37);
    assert(uz_access_vm_result(UINT64_C(0xabcdef1200000025), 4096) == 37);
    puts("PASS remote VM: negative W0/X0, partial copy, bounds and unspecified upper bits");

    struct uro_regs regs = {0};
    struct uro_store store, before;
    memset(&before, 0x5a, sizeof(before));
    unsigned checks = 0;
    for (unsigned bs = 0; bs < 16; ++bs) {
        for (unsigned prohibited = 0; prohibited < 2; ++prohibited) {
            for (unsigned offset = 0; offset < 128; ++offset) {
                regs.x[0] = 0x10000 + offset;
                store = before;
                int rc = uro_decode_zva(0xd50b7420U, &regs, bs | (prohibited << 4), &store);
                if (prohibited || bs > 9) {
                    assert(rc && !memcmp(&store, &before, sizeof(store)));
                } else {
                    unsigned size = 4U << bs;
                    assert(!rc && store.zva && store.total == size && store.count == 1);
                    assert(store.address == (regs.x[0] & ~(uint64_t)(size - 1U)));
                }
                ++checks;
            }
        }
    }
    assert(uro_decode_store(0xd50b7420U, &regs, &store)); /* no guessed geometry */
    assert(uro_decode_zva(0xd503201fU, &regs, 4, &store));
    assert(uro_decode_zva(0xd50b7420U, &regs, 0x24, &store));
    assert(!uro_decode_zva(0xd50b743fU, &regs, 4, &store) && !store.address);
    printf("PASS DC ZVA: %u geometry/alignment/DZP cases, reserved size, XZR and no default size\n", checks);
    return 0;
}
