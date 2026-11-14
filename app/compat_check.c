/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../module/compat.h"
#include "compat_inspect.h"

struct fixture {
    uint32_t words[512];
    char strings[512];
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
    add_func(&f, "abort54", 0, 3, (unsigned[]){l, i, rp});
    add_func(&f, "abort61", 0, 3, (unsigned[]){l, l, rp});
    btf = fixture_btf(&f);

    assert(uz_mm_fault_argc(&btf, "fault54", 1) == 3);
    assert(uz_mm_fault_argc(&btf, "fault61", 1) == 4);
    assert(uz_mm_fault_argc(&btf, "fault515", 0) == 5);
    assert(!uz_mm_fault_argc(&btf, "fault_bad", 1));
    assert(uz_mm_fault_argc(&btf, "missing", 1) == 8);
    assert(!uz_mm_fault_argc(&btf, "missing", 0));
    assert(uz_access_vm_argc(&btf, "remote5", 1) == 5);
    assert(uz_access_vm_argc(&btf, "remote6", 0) == 6);
    assert(!uz_access_vm_argc(&btf, "remote6", 1));
    assert(!uz_access_vm_argc(&btf, "remote_bad", 0));
    assert(!uz_access_vm_argc(&btf, "missing", 0));
    assert(uz_symbol_abi(&btf, "abort54", "vlsr"));
    assert(uz_symbol_abi(&btf, "abort61", "vlsr"));
    puts("BTF: fault 3/4/5 arguments, public fallback, remote VM 5/6 arguments, abort ABIs PASS");
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

    assert(uz_foll_force(&btf, 0x10) == 0x10);
    assert(uz_btf_enum_flag(&btf, "FOLL_FORCE", 0x10) == 0x10);
    btf.type_len = sizeof(records) / 2;
    assert(uz_foll_force(&btf, 0x10) == 8);
    assert(uz_btf_enum_flag(&btf, "FOLL_FORCE", 0x10) == 8);
    btf.type_len = sizeof(records);
    assert(!uz_foll_force(&btf, 0x10));
    assert(!uz_btf_enum_flag(&btf, "FOLL_FORCE", 0x10));
    puts("GUP: version fallback, BTF override and conflicting values PASS");
}

static void test_gup_signatures(void)
{
    struct fixture f = {.strings_used = 1};
    unsigned i = add_type(&f, "int", 1, 0, 4);
    f.words[f.words_used++] = 32;
    unsigned l = add_type(&f, "long", 1, 0, 8);
    f.words[f.words_used++] = 64;
    unsigned m = add_type(&f, "mm_struct", 4, 0, 8);
    unsigned mp = add_type(&f, NULL, 2, 0, m);
    unsigned t = add_type(&f, "task_struct", 4, 0, 8);
    unsigned tp = add_type(&f, NULL, 2, 0, t);
    unsigned p = add_type(&f, NULL, 2, 0, 0);
    unsigned pg = add_type(&f, "page", 4, 0, 64);
    unsigned pgp = add_type(&f, NULL, 2, 0, pg);
    unsigned pgpp = add_type(&f, NULL, 2, 0, pgp);
    unsigned a = add_type(&f, "vm_area_struct", 4, 0, 8);
    unsigned ap = add_type(&f, NULL, 2, 0, a);
    unsigned app = add_type(&f, NULL, 2, 0, ap);
    unsigned ip = add_type(&f, NULL, 2, 0, i);
    unsigned lp = add_type(&f, NULL, 2, 0, l);
    add_func(&f, "pin8", l, 8, (unsigned[]){tp, mp, l, l, i, pgpp, app, ip});
    add_func(&f, "pin7", l, 7, (unsigned[]){mp, l, l, i, pgpp, app, ip});
    add_func(&f, "pin6", l, 6, (unsigned[]){mp, l, l, i, pgpp, ip});
    add_func(&f, "pin_bad", l, 6, (unsigned[]){mp, l, l, l, pgpp, ip});
    add_func(&f, "pin8_bad_order", l, 8, (unsigned[]){mp, tp, l, l, i, pgpp, app, ip});
    add_func(&f, "pin8_bad_width", l, 8, (unsigned[]){tp, mp, l, i, i, pgpp, app, ip});
    add_func(&f, "pin_bad_pages", l, 6, (unsigned[]){mp, l, l, i, pgp, ip});
    add_func(&f, "pin_void_pages", l, 6, (unsigned[]){mp, l, l, i, p, ip});
    add_func(&f, "pin_bad_vmas", l, 7, (unsigned[]){mp, l, l, i, pgpp, ap, ip});
    add_func(&f, "pin_bad_locked", l, 6, (unsigned[]){mp, l, l, i, pgpp, lp});
    add_func(&f, "fast_public", i, 4, (unsigned[]){l, i, i, p});
    add_func(&f, "fast_internal", i, 4, (unsigned[]){l, l, i, p});
    struct kclf_btf btf = fixture_btf(&f);
    assert(uz_remote_gup_argc(&btf, "pin8") == 8);
    assert(uz_remote_gup_argc(&btf, "pin7") == 7);
    assert(uz_remote_gup_argc(&btf, "pin6") == 6);
    assert(!uz_remote_gup_argc(&btf, "pin_bad"));
    assert(!uz_remote_gup_argc(&btf, "pin8_bad_order"));
    assert(!uz_remote_gup_argc(&btf, "pin8_bad_width"));
    assert(!uz_remote_gup_argc(&btf, "pin_bad_pages"));
    assert(!uz_remote_gup_argc(&btf, "pin_void_pages"));
    assert(!uz_remote_gup_argc(&btf, "pin_bad_vmas"));
    assert(!uz_remote_gup_argc(&btf, "pin_bad_locked"));
    assert(!uz_remote_gup_argc(&btf, "missing"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fast_public"), "iliip"));
    assert(!uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fast_public"), "illip"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fast_internal"), "illip"));
    puts("GUP ABI: 6/7/8 arguments, task/mm order, page**/VMA**/int*, missing prototypes and count widths PASS");
}

static void test_allocator_abi(void)
{
    for (unsigned variant = 0; variant < 8; ++variant) {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned l = add_type(&f, "long", 1, 0, 8);
        f.words[f.words_used++] = 64;
        unsigned pgdat = add_type(&f, "pglist_data", 4, 1, variant == 2 ? 10 : 16);
        f.words[f.words_used++] = add_name(&f, "node_id");
        f.words[f.words_used++] = variant == 1 ? l : i;
        f.words[f.words_used++] = variant == 3 ? 40 : 64;
        unsigned nodep = add_type(&f, NULL, 2, 0, pgdat);
        unsigned page = add_type(&f, "page", 4, 0, 64);
        unsigned pagep = add_type(&f, NULL, 2, 0, page);
        unsigned p = add_type(&f, NULL, 2, 0, 0);
        if (variant != 4)
            add_func(&f, "first_online_pgdat", variant == 5 ? pagep : nodep,
                     variant == 6 ? 1 : 0, (unsigned[]){i});
        add_func(&f, "alloc_pages", pagep, 2, (unsigned[]){i, i});
        add_func(&f, "__alloc_pages_nodemask", pagep, 4, (unsigned[]){i, i, i, p});
        add_func(&f, "__alloc_pages_noprof", pagep, 4, (unsigned[]){i, i, i, p});
        add_func(&f, "bad_alloc", pagep, 3, (unsigned[]){i, i, i});
        add_func(&f, "try_grab_folio", variant == 7 ? i : nodep, 3,
                 (unsigned[]){pagep, i, i});
        struct kclf_btf btf = fixture_btf(&f);
        assert((uz_pgdat_node_offset(&btf) == 8) == (variant == 0 || variant == 7));
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "alloc_pages"), "Pii"));
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "__alloc_pages_nodemask"), "Piiip"));
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "__alloc_pages_noprof"), "Piiip"));
        assert(!uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "bad_alloc"), "Piiip"));
        assert(!uz_folio_page_grab_abi(&btf)); /* wrong return pointee or int */
    }
    {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned page = add_type(&f, "page", 4, 0, 64);
        unsigned pp = add_type(&f, NULL, 2, 0, page);
        unsigned folio = add_type(&f, "folio", 4, 0, 128);
        unsigned fp = add_type(&f, NULL, 2, 0, folio);
        add_func(&f, "try_grab_folio", fp, 3, (unsigned[]){pp, i, i});
        struct kclf_btf btf = fixture_btf(&f);
        assert(uz_folio_page_grab_abi(&btf));
        assert(!uz_folio_grab_abi(&btf));
    }
    puts("Allocator ABI: policy/node entry, online pgdat layout, old/new folio conventions PASS");
}

static void test_ptl_abi(void)
{
    for (unsigned variant = 0; variant < 12; ++variant) {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned l = add_type(&f, "long", 1, 0, 8);
        f.words[f.words_used++] = 64;
        unsigned m = add_type(&f, "mm_struct", 4, 0, 8);
        unsigned mp = add_type(&f, NULL, 2, 0, m);
        unsigned p = add_type(&f, NULL, 2, 0, 0);
        unsigned pte = add_type(&f, NULL, 4, 1, 8);
        f.words[f.words_used++] = add_name(&f, "pte");
        f.words[f.words_used++] = variant == 1 ? i : l;
        f.words[f.words_used++] = 0;
        unsigned ptet = add_type(&f, "pte_t", 8, 0, pte);
        unsigned ptep = add_type(&f, NULL, 2, 0, ptet);
        unsigned pmd = add_type(&f, NULL, 4, 1, 8);
        f.words[f.words_used++] = add_name(&f, variant == 2 ? "bad" : "pmd");
        f.words[f.words_used++] = l;
        f.words[f.words_used++] = 0;
        unsigned pmdp = add_type(&f, NULL, 2, 0, pmd);
        unsigned raw = add_type(&f, "raw_spinlock", 4, 0, 8);
        unsigned rawp = add_type(&f, NULL, 2, 0, raw);
        unsigned spin = add_type(&f, "spinlock", 4, 1, 16);
        f.words[f.words_used++] = add_name(&f, "rlock");
        f.words[f.words_used++] = variant == 10 ? p : raw;
        f.words[f.words_used++] = variant == 6 ? 64 : 0;
        unsigned sp = add_type(&f, NULL, 2, 0, spin);
        unsigned spp = add_type(&f, NULL, 2, 0, variant == 5 ? rawp : sp);
        add_func(&f, "__pte_offset_map_lock", variant == 3 ? mp : ptep, 4,
                 (unsigned[]){mp, pmdp, l, variant == 4 ? sp : spp});
        add_func(&f, "_raw_spin_unlock", 0, 1, (unsigned[]){variant == 9 ? sp : rawp});
        unsigned cb = add_type(&f, NULL, 13, variant == 7 ? 4 : 3, i);
        unsigned argv[] = {variant == 11 ? p : ptep, l, p, p};
        for (unsigned a = 0; a < (variant == 7 ? 4U : 3U); ++a) {
            f.words[f.words_used++] = 0;
            f.words[f.words_used++] = argv[a];
        }
        unsigned cbp = add_type(&f, NULL, 2, 0, variant == 8 ? p : cb);
        add_func(&f, "apply_to_page_range", i, 5, (unsigned[]){mp, l, l, cbp, p});
        struct kclf_btf btf = fixture_btf(&f);
        assert(uz_native_pt_abi(&btf) == (variant == 0 || variant == 7 || variant == 8 || variant == 11));
        assert(uz_apply_pt_abi(&btf, "apply_to_page_range") ==
               (variant != 1 && variant != 7 && variant != 8 && variant != 11));
    }
    puts("PTL ABI: 12 native/callback cases, descriptor pointees, lock indirection and RT rejection PASS");
}

static void test_folio_grab(void)
{
    for (unsigned variant = 0; variant < 9; ++variant) {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned l = add_type(&f, "long", 1, 0, 8);
        f.words[f.words_used++] = 64;
        unsigned page = add_type(&f, "page", 4, 0, 64);
        unsigned container = variant == 8 ? add_type(&f, NULL, 5, 1, 64) : 0;
        unsigned folio = container ? 0 : add_type(&f, "folio", 4, 1, variant == 2 ? 32 : 72);
        f.words[f.words_used++] = add_name(&f, "page");
        f.words[f.words_used++] = variant == 7 ? i : page;
        f.words[f.words_used++] = variant == 1 ? 64 : 0;
        if (container) {
            folio = add_type(&f, "folio", 4, 1, 72);
            f.words[f.words_used++] = 0;
            f.words[f.words_used++] = container;
            f.words[f.words_used++] = 0;
        }
        unsigned fp = add_type(&f, NULL, 2, 0, variant == 3 ? page : folio);
        if (variant != 5)
            add_func(&f, "try_grab_folio", variant == 4 ? 0 : i, 3,
                     (unsigned[]){fp, variant == 6 ? l : i, i});
        struct kclf_btf btf = fixture_btf(&f);
        assert(!!uz_folio_grab_abi(&btf) == (variant == 0 || variant == 8));
    }
    puts("Folio GUP: complete page at offset zero, pointer/result/count ABI and missing helper PASS");
}

static void test_contpte_abi(void)
{
    for (unsigned variant = 0; variant < 12; ++variant) {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned l = add_type(&f, "long", 1, 0, 8);
        f.words[f.words_used++] = 64;
        unsigned m = add_type(&f, "mm_struct", 4, 0, 8);
        unsigned mp = add_type(&f, NULL, 2, 0, m);
        unsigned pte = add_type(&f, NULL, variant == 3 ? 5 : 4, 1, variant == 4 ? 16 : 8);
        f.words[f.words_used++] = add_name(&f, variant == 5 ? "pmd" : "pte");
        f.words[f.words_used++] = variant == 6 ? i : l;
        f.words[f.words_used++] = variant == 7 ? 8 : 0;
        unsigned word = add_type(&f, "pte_t", 8, 0, pte);
        unsigned ptep = add_type(&f, NULL, 2, 0, word);
        unsigned qualified = add_type(&f, NULL, 10, 0, word);
        if (variant != 11)
            add_func(&f, "__contpte_try_unfold", variant == 8 ? i : 0,
                variant == 9 ? 3 : 4, (unsigned[]){variant == 1 ? ptep : mp,
                    variant == 2 ? i : l, ptep, variant == 10 ? ptep : qualified});
        struct kclf_btf btf = fixture_btf(&f);
        assert(uz_contpte_abi(&btf) == (variant == 0));
    }
    puts("Contiguous PTE ABI: 12 by-value/typedef, wrong pointer/width/offset/kind and absent-helper cases PASS");
}

static void test_fast_gup_abi(void)
{
    for (unsigned variant = 0; variant < 6; ++variant) {
        struct fixture f = {.strings_used = 1};
        unsigned i = add_type(&f, "int", 1, 0, 4);
        f.words[f.words_used++] = 32;
        unsigned l = add_type(&f, "long", 1, 0, 8);
        f.words[f.words_used++] = 64;
        unsigned page = add_type(&f, variant == 1 ? "folio" : "page", 4, 0, 64);
        unsigned p = add_type(&f, NULL, 2, 0, page);
        unsigned pp = add_type(&f, NULL, 2, 0, p);
        unsigned ppp = add_type(&f, NULL, 2, 0, pp);
        unsigned pages = variant == 2 ? p : variant == 3 ? ppp : pp;
        add_func(&f, "fast", variant == 4 ? l : i, 4,
            (unsigned[]){l, variant == 5 ? l : i, i, pages});
        add_func(&f, "fast_internal", variant == 4 ? l : i, 4,
            (unsigned[]){l, variant == 5 ? i : l, i, pages});
        add_func(&f, "try_grab_compound_head", variant == 4 ? i : p, 3,
            (unsigned[]){p, variant == 5 ? l : i, i});
        struct kclf_btf btf = fixture_btf(&f);
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fast"), "iliiD") == (variant == 0));
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fast_internal"), "illiD") == (variant == 0));
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "try_grab_compound_head"), "PPii") ==
               (variant == 0 || variant == 2 || variant == 3));
    }
    puts("Fast GUP ABI: page** and int/long counts; 5.x compound grab pointee/result/count PASS");
}

static void test_build_id(void)
{
    const uint32_t notes[] = {0, 1, 1, 0, 4, 5, 3, 0x00554e47U, 0x67452301U, 0x89};
    struct uz_btf_pack pack = {"UZBTF01", 1024, 5, {1, 0x23, 0x45, 0x67, 0x89}};

    assert(uz_btf_pack_matches(&pack, notes, sizeof(notes)));
    assert(!uz_btf_pack_matches(&pack, notes, sizeof(notes) - 1));
    pack.build_id[4] ^= 1;
    assert(!uz_btf_pack_matches(&pack, notes, sizeof(notes)));
    pack.build_id[4] ^= 1;
    pack.bytes = UZ_BTF_MAX + 1U;
    assert(!uz_btf_pack_matches(&pack, notes, sizeof(notes)));
    puts("Detached BTF: exact build ID, mismatch, truncated note and oversized package PASS");
}

static void test_geometry(void)
{
    struct uz_geometry geom;
    /* 4K/39-bit, 16K/47-bit, and 4K kernel/user walk depth mismatch. */
    uint64_t arm4k = (UINT64_C(2) << 30) | (UINT64_C(25) << 16) | 25;
    uint64_t arm16k = (UINT64_C(1) << 30) | (UINT64_C(17) << 16) | (2U << 14) | 17;
    uint64_t different_depths = (arm4k & ~UINT64_C(63)) | 16;

    assert(!uz_geometry_from_tcr(&geom, arm4k) && geom.page_shift == 12 && geom.user_va_bits == 39);
    assert(!uz_geometry_from_tcr(&geom, arm16k) && geom.page_shift == 14 && geom.user_va_bits == 47);
    assert(uz_geometry_from_tcr(&geom, different_depths));
    assert(uz_geometry_from_tcr(&geom, arm16k | (UINT64_C(1) << 59)));
    assert(uz_geometry_from_tcr(&geom, arm16k | (UINT64_C(6) << 32)));
    assert(uz_geometry_from_tcr(&geom, arm16k ^ (2U << 14)));
    puts("TCR: 4 KiB, 16 KiB, mismatched depths, LPA2 and mismatched granules PASS");
}

static void *read_saved_btf(const char *path, struct kclf_btf *btf, struct uz_layout *layout)
{
    FILE *file = fopen(path, "rb");
    long size;
    void *data;

    assert(file && !fseek(file, 0, SEEK_END));
    size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    data = malloc((size_t)size);
    assert(data && fread(data, 1, (size_t)size, file) == (size_t)size);
    fclose(file);

    assert(uz_btf_open(btf, data, (size_t)size - 1));
    assert(!uz_btf_open(btf, data, (size_t)size));
    assert(!uz_layout_from_btf(layout, btf));
    assert(layout->task_fpsimd >= 0 && layout->mmap_lock >= 0 && layout->vma_pgoff_ok);
    assert(uz_pgdat_node_offset(btf) >= 0);
    assert(uz_native_pt_abi(btf) || uz_apply_pt_abi(btf, "apply_to_existing_page_range"));
    return data;
}

static void test_saved_btf(const char *path, const char *fault, int expected_args,
                           int expected_pgd, int expected_vma_flags)
{
    struct uz_layout layout;
    struct kclf_btf btf;
    void *data = read_saved_btf(path, &btf, &layout);

    assert(layout.mm_pgd == expected_pgd && layout.vma_flags == expected_vma_flags);
    assert(uz_mm_fault_argc(&btf, fault, 0) == expected_args);
    assert(uz_symbol_abi(&btf, "do_mem_abort", "vlsr"));
    assert(uz_foll_force(&btf, 0x10) == 0x10);
    assert(uz_remote_gup_argc(&btf, "pin_user_pages_remote") == 7);
    if (expected_args == 5) {
        assert(uz_remote_gup_argc(&btf, "__get_user_pages_remote") == 7);
        assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "internal_get_user_pages_fast"), "illiD"));
    }
    printf("%s: MM, VMA and FPSIMD layouts; %s/%d PASS\n", path, fault, expected_args);
    free(data);
}

/* Check the ABI paths used by the public Android 6.12 and 6.18 GKI builds. */
static void test_gki_btf(const char *path)
{
    struct uz_layout layout;
    struct kclf_btf btf;
    void *data = read_saved_btf(path, &btf, &layout);
    const char *save = "fpsimd_save_and_flush_current_state";

    if (!kclf_btf_func_proto(&btf, save)) save = "fpsimd_signal_preserve_current_state";
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, save), "v"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "fpsimd_update_current_state"), "vf"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "do_mem_abort"), "vllr"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "vmalloc_noprof"), "pl"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "down_write"), "vp"));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "up_write"), "vp"));
    assert(uz_mm_fault_argc(&btf, "handle_mm_fault", 0) == 4);
    assert(uz_access_vm_argc(&btf, "access_remote_vm", 0) == 5);
    assert(uz_foll_force(&btf, 0) == 8);
    assert(uz_remote_gup_argc(&btf, "pin_user_pages_remote") == 6);
    assert(uz_remote_gup_argc(&btf, "__get_user_pages") == 6);
    assert(uz_folio_grab_abi(&btf));
    assert(uz_native_pt_abi(&btf));
    assert(uz_apply_pt_abi(&btf, "apply_to_existing_page_range"));
    assert(uz_contpte_abi(&btf));
    assert(uz_btf_signature(&btf, kclf_btf_func_proto(&btf, "gup_fast_fallback"), "illiD"));
    assert(uz_btf_enum_flag(&btf, "FOLL_PIN", 0) == 0x80000U);
    assert(uz_btf_enum_flag(&btf, "FOLL_FAST_ONLY", 0) == 0x100000U);
    assert(uz_btf_enum_flag(&btf, "FOLL_GET", 0) == 2U);
    printf("%s: MM/VMA/FPSIMD layouts (pgd=%d mmap_lock=%d fpsimd=%d), "
           "handle_mm_fault/4 %s rwsem vmalloc_noprof PASS\n",
           path, layout.mm_pgd, layout.mmap_lock, layout.task_fpsimd, save);
    free(data);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--inspect")) return inspect_main(argc, argv);
    test_signatures();
    test_gup_signatures();
    test_folio_grab();
    test_allocator_abi();
    test_ptl_abi();
    test_contpte_abi();
    test_fast_gup_abi();
    test_gup_flags();
    test_build_id();
    test_geometry();
    if (argc > 1 && !strcmp(argv[1], "--gki")) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --gki gki-6.x.btf [gki-6.x.btf ...]\n", argv[0]);
            return 2;
        }
        for (int i = 2; i < argc; ++i) test_gki_btf(argv[i]);
        return 0;
    }
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
