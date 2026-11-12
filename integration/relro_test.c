/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kclf_elf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    struct ke_object o;
    memset(&o, 0, sizeof(o));
    o.bias = 0x100000;
    o.phnum = 1;
    o.ph[0] = (struct ke_phdr){.type=1, .flags=6, .vaddr=0x8ae0, .memsz=0x230};
    assert(!ke_contains(&o, o.bias + 0x8ae0, 0x520, 2));
    assert(ke_relro_contains(&o, o.bias + 0x8ae0, 0x520, 4096));
    assert(ke_relro_contains(&o, o.bias + 0x8ae0, 0x230, 4096));
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, 0x521, 4096));
    assert(!ke_relro_contains(&o, o.bias + 0x8910, 1, 4096));
    assert(!ke_relro_contains(&o, o.bias + 0x8d10, 1, 4096));
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, 0, 4096));
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, 1, 12345));
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, UINT64_MAX, 4096));
    o.ph[0].flags = 4;
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, 1, 4096));
    o.ph[0].flags = 6;
    assert(ke_relro_contains(&o, o.bias + 0x8ae0, 0x3520, 16384));
    assert(!ke_relro_contains(&o, o.bias + 0x8ae0, 0x3521, 16384));
    o.bias = UINT64_MAX - 0x100;
    assert(!ke_relro_contains(&o, UINT64_MAX - 1, 1, 4096));
    o.bias = 0;
    o.ph[0].vaddr = UINT64_MAX - 0xfff;
    o.ph[0].memsz = 0x100;
    assert(!ke_relro_contains(&o, o.ph[0].vaddr, 1, 4096));
    puts("RELRO PASS checks=14 (padding, bounds, permissions, overflow, 4K/16K)");
    return 0;
}
