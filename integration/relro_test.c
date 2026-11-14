/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kclf_elf.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static int read_file(void *ctx, u64 offset, void *out, unsigned long n)
{
    FILE *f = ctx;
    return fseek(f, (long)offset, SEEK_SET) || fread(out, 1, n, f) != n;
}

/* Optional real payload paths make linker flag/layout changes exercise the
 * same parser and validation used by the manual loader, before device use. */
static void check_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    struct ke_io io = { .ctx = f, .limit = UINT64_C(1) << 48, .read = read_file };
    struct ke_object o;
    long size;
    unsigned shift, i, count = 0;
    assert(f);
    assert(!fseek(f, 0, SEEK_END));
    size = ftell(f);
    assert(size > 0);
    for (shift = 12; shift <= 14; shift += 2) {
        assert(!ke_headers(&io, 0, &o));
        assert(!ke_file_layout(&io, &o, (u64)size, UINT64_C(1) << shift));
        o.bias = 0x100000;
        for (i = 0; i < o.phnum; i++) {
            const struct ke_phdr *p = &o.ph[i];
            if (p->type != 0x6474e552U || !p->memsz) continue;
            assert(ke_relro_contains(&o, o.bias + p->vaddr, p->memsz, UINT64_C(1) << shift));
            count++;
        }
    }
    assert(count);
    fclose(f);
    printf("RELRO FILE PASS 4K/16K %s\n", path);
}

int main(int argc, char **argv)
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
    /* NDK 26 / LLD libuzpayload.so with max/common-page-size=16384:
     * RW LOAD ends 0x4a598, RELRO ends 0x4c000, next data LOAD 0x4e598.
     * A 4K runtime must accept the two-page link-time padding as well. */
    memset(&o, 0, sizeof(o));
    o.bias = 0x100000;
    o.phnum = 3;
    o.ph[0] = (struct ke_phdr){.type=1, .flags=5, .vaddr=0, .memsz=0x42a00, .align=0x4000};
    o.ph[1] = (struct ke_phdr){.type=1, .flags=6, .vaddr=0x46a00, .memsz=0x3b98, .align=0x4000};
    o.ph[2] = (struct ke_phdr){.type=1, .flags=6, .vaddr=0x4e598, .memsz=0x1038, .align=0x4000};
    assert(!ke_contains(&o, o.bias + 0x46a00, 0x5600, 2));
    assert(ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    assert(ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 16384));
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x5601, 4096));
    o.ph[1].align = 0x1000;
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    o.ph[1].align = 0x4000;
    o.bias += 0x1000;
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    o.bias -= 0x1000;
    o.ph[2].vaddr = 0x4b800; /* a writable page in the proposed padding */
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    o.ph[2].flags = 5; /* executable neighbour must not lose EXEC either */
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    o.ph[2].vaddr = 0x4c000; /* immediately after protection end is fine */
    assert(ke_relro_contains(&o, o.bias + 0x46a00, 0x5600, 4096));
    o.ph[2].vaddr = 0x4b800; /* partial final protection page overlaps */
    assert(!ke_relro_contains(&o, o.bias + 0x46a00, 0x4e00, 4096));
    puts("RELRO PASS checks=24 (link/runtime padding, LOAD collisions, bounds, 4K/16K)");
    for (int i = 1; i < argc; i++) check_file(argv[i]);
    return 0;
}
