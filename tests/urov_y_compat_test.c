/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../urov_y_compat.h"

struct fixture {
    uint32_t words[256];
    char strings[256];
    unsigned types, words_used, strings_used;
};

static unsigned add_name(struct fixture *f, const char *name)
{
    unsigned off = f->strings_used;
    size_t bytes = strlen(name) + 1;

    assert(bytes <= sizeof(f->strings) - off);
    memcpy(f->strings + off, name, bytes);
    f->strings_used += (unsigned)bytes;
    return off;
}

static unsigned add_type(struct fixture *f, const char *name, unsigned kind, unsigned n, unsigned size)
{
    assert(f->words_used + 3 <= sizeof(f->words) / sizeof(f->words[0]));
    f->words[f->words_used++] = name ? add_name(f, name) : 0;
    f->words[f->words_used++] = (kind << 24) | n;
    f->words[f->words_used++] = size;
    return ++f->types;
}

static void add_func(struct fixture *f, const char *name, unsigned result,
                     unsigned count, const unsigned *args)
{
    unsigned i, proto = add_type(f, NULL, 13, count, result);

    assert(f->words_used + 2 * count <= sizeof(f->words) / sizeof(f->words[0]));
    for (i = 0; i < count; ++i) {
        f->words[f->words_used++] = 0;
        f->words[f->words_used++] = args[i];
    }
    add_type(f, name, 12, 0, proto);
}

static struct kclf_btf fixture_btf(const struct fixture *f)
{
    const struct kclf_btf btf = {
        .types = (const unsigned char *)f->words,
        .type_len = f->words_used * sizeof(uint32_t),
        .strings = f->strings,
        .str_len = f->strings_used,
    };

    return btf;
}

static void test_signatures(void)
{
    struct fixture f = {.strings_used = 1};
    struct kclf_btf btf;
    unsigned i = add_type(&f, "int", 1, 0, 4);
    f.words[f.words_used++] = 32;
    unsigned l = add_type(&f, "long", 1, 0, 8);
    f.words[f.words_used++] = 64;
    unsigned a = add_type(&f, "vm_area_struct", 4, 0, 8);
    unsigned ap = add_type(&f, NULL, 2, 0, a);
    unsigned r = add_type(&f, "pt_regs", 4, 0, 272);
    unsigned rp = add_type(&f, NULL, 2, 0, r);
    unsigned m = add_type(&f, "mm_struct", 4, 0, 8);
    unsigned mp = add_type(&f, NULL, 2, 0, m);
    unsigned t = add_type(&f, "task_struct", 4, 0, 8);
    unsigned tp = add_type(&f, NULL, 2, 0, t);
    unsigned p = add_type(&f, NULL, 2, 0, 0);

    add_func(&f, "fault54", i, 3, (unsigned[]){ap, l, i});
    add_func(&f, "fault61", i, 4, (unsigned[]){ap, l, i, rp});
    add_func(&f, "fault515", i, 5, (unsigned[]){ap, l, i, l, rp});
    add_func(&f, "fault_bad", i, 4, (unsigned[]){ap, l, l, rp});
    add_func(&f, "remote5", i, 5, (unsigned[]){mp, l, p, i, i});
    add_func(&f, "remote6", i, 6, (unsigned[]){tp, mp, l, p, i, i});
    add_func(&f, "remote_bad", i, 6, (unsigned[]){mp, tp, l, p, i, i});
    add_func(&f, "brk618", 0, 2, (unsigned[]){l, rp});
    add_func(&f, "abort54", 0, 3, (unsigned[]){l, i, rp});
    add_func(&f, "abort61", 0, 3, (unsigned[]){l, l, rp});
    btf = fixture_btf(&f);

    assert(uy_mm_fault_argc(&btf, "fault54", 1) == 3);
    assert(uy_mm_fault_argc(&btf, "fault61", 1) == 4);
    assert(uy_mm_fault_argc(&btf, "fault515", 0) == 5);
    assert(!uy_mm_fault_argc(&btf, "fault_bad", 1));
    assert(uy_mm_fault_argc(&btf, "missing", 1) == 8);
    assert(!uy_mm_fault_argc(&btf, "missing", 0));
    assert(uy_access_vm_argc(&btf, "remote5", 1) == 5);
    assert(uy_access_vm_argc(&btf, "remote6", 0) == 6);
    assert(!uy_access_vm_argc(&btf, "remote6", 1));
    assert(!uy_access_vm_argc(&btf, "remote_bad", 0));
    assert(!uy_access_vm_argc(&btf, "missing", 0));
    assert(uy_symbol_abi(&btf, "brk618", "vsr"));
    assert(!uy_symbol_abi(&btf, "brk618", "ilsr"));
    assert(uy_symbol_abi(&btf, "abort54", "vlsr"));
    assert(uy_symbol_abi(&btf, "abort61", "vlsr"));
    puts("BTF: fault 3/4/5 arguments, public fallback, remote VM 5/6 arguments, BRK/abort ABIs PASS");
}

static void test_gup_flags(void)
{
    const char names[] = "\0FOLL_FORCE";
    uint32_t records[] = {0, (6U << 24) | 1, 4, 1, 8,
                          0, (6U << 24) | 1, 4, 1, 16};
    struct kclf_btf btf = {
        .types = (const unsigned char *)records, .type_len = 0,
        .strings = names, .str_len = sizeof(names),
    };

    assert(uy_foll_force(&btf, 0x10) == 0x10);
    btf.type_len = sizeof(records) / 2;
    assert(uy_foll_force(&btf, 0x10) == 8);
    btf.type_len = sizeof(records);
    assert(!uy_foll_force(&btf, 0x10));
    puts("GUP: version fallback, BTF override and conflicting values PASS");
}

static void test_build_id(void)
{
    const uint32_t notes[] = {0, 1, 1, 0, 4, 5, 3, 0x00554e47U, 0x67452301U, 0x89};
    struct uy_btf_pack pack = {"UYBTF01", 1024, 5, {1, 0x23, 0x45, 0x67, 0x89}};

    assert(uy_btf_pack_matches(&pack, notes, sizeof(notes)));
    assert(!uy_btf_pack_matches(&pack, notes, sizeof(notes) - 1));
    pack.build_id[4] ^= 1;
    assert(!uy_btf_pack_matches(&pack, notes, sizeof(notes)));
    pack.build_id[4] ^= 1;
    pack.bytes = UY_BTF_MAX + 1U;
    assert(!uy_btf_pack_matches(&pack, notes, sizeof(notes)));
    puts("Detached BTF: exact build ID, mismatch, truncated note and oversized package PASS");
}

static void test_geometry(void)
{
    struct uy_geometry geom;
    /* 4K/39-bit, 16K/47-bit, and 4K kernel/user walk depth mismatch. */
    uint64_t arm4k = (UINT64_C(2) << 30) | (UINT64_C(25) << 16) | 25;
    uint64_t arm16k = (UINT64_C(1) << 30) | (UINT64_C(17) << 16) | (2U << 14) | 17;
    uint64_t different_depths = (arm4k & ~UINT64_C(63)) | 16;

    assert(!uy_geometry_from_tcr(&geom, arm4k) && geom.page_shift == 12 && geom.user_va_bits == 39);
    assert(!uy_geometry_from_tcr(&geom, arm16k) && geom.page_shift == 14 && geom.user_va_bits == 47);
    assert(uy_geometry_from_tcr(&geom, different_depths));
    assert(uy_geometry_from_tcr(&geom, arm16k | (UINT64_C(1) << 59)));
    assert(uy_geometry_from_tcr(&geom, arm16k | (UINT64_C(6) << 32)));
    assert(uy_geometry_from_tcr(&geom, arm16k ^ (2U << 14)));
    puts("TCR: 4 KiB, 16 KiB, mismatched depths, LPA2 and mismatched granules PASS");
}

static void test_saved_btf(const char *path, const char *fault, int expected_args,
                           int expected_pgd, int expected_vma_flags)
{
    struct uy_layout layout;
    struct kclf_btf btf;
    FILE *file = fopen(path, "rb");
    long size;
    void *data;

    assert(file && !fseek(file, 0, SEEK_END));
    size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    data = malloc((size_t)size);
    assert(data && fread(data, 1, (size_t)size, file) == (size_t)size);
    fclose(file);

    assert(uy_btf_open(&btf, data, (size_t)size - 1));
    assert(!uy_btf_open(&btf, data, (size_t)size));
    assert(!uy_layout_from_btf(&layout, &btf));
    assert(layout.mm_pgd == expected_pgd && layout.vma_flags == expected_vma_flags);
    assert(layout.task_fpsimd >= 0 && layout.mmap_lock >= 0 && layout.vma_pgoff_ok);
    assert(uy_mm_fault_argc(&btf, fault, 0) == expected_args);
    assert(uy_symbol_abi(&btf, "do_mem_abort", "vlsr"));
    assert(uy_foll_force(&btf, 0x10) == 0x10);
    printf("%s: MM, VMA and FPSIMD layouts; %s/%d PASS\n", path, fault, expected_args);
    free(data);
}

int main(int argc, char **argv)
{
    test_signatures();
    test_gup_flags();
    test_build_id();
    test_geometry();
    if (argc > 3) {
        fprintf(stderr, "Usage: %s [fuxi-5.15.74.btf [oriole-6.1.134.btf]]\n", argv[0]);
        return 2;
    }
    if (argc >= 2)
        test_saved_btf(argv[1], "do_handle_mm_fault", 5, 64, 80);
    if (argc == 3)
        test_saved_btf(argv[2], "handle_mm_fault", 4, 56, 32);
    return 0;
}
