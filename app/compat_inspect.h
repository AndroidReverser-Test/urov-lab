/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef UROV_Z_COMPAT_INSPECT_H
#define UROV_Z_COMPAT_INSPECT_H

#include <ctype.h>
#include "../module/runtime_compat.h"
#include "../module/kclf/kclf_compat_profile.h"

/* Inspection is separate from fixture assertions: arbitrary valid BTF need
 * not have Pixel/Xiaomi offsets. A completed report is not a runtime pass. */
static char *inspect_read(const char *path, size_t *bytes)
{
    FILE *f = fopen(path, "rb");
    char *data = NULL;
    size_t used = 0, cap = 0;
    if (!f) { perror(path); return NULL; }
    for (;;) {
        if (used == cap) {
            size_t next = cap ? cap * 2 : 65536;
            char *grown;
            if (next > UZ_BTF_MAX) {
                if (fgetc(f) != EOF || ferror(f)) goto fail;
                break;
            }
            grown = realloc(data, next + 1);
            if (!grown) goto fail;
            data = grown; cap = next;
        }
        used += fread(data + used, 1, cap - used, f);
        if (ferror(f)) goto fail;
        if (feof(f)) break;
    }
    fclose(f);
    data[used] = 0;
    *bytes = used;
    return data;
fail:
    fprintf(stderr, "%s: read/allocation failed or input exceeds %u bytes\n", path, UZ_BTF_MAX);
    fclose(f); free(data);
    return NULL;
}

/* Accept one name per line or ordinary /proc/kallsyms output, including
 * hidden zero addresses. Name presence does not prove lookup addresses. */
static int inspect_symbol(const char *symbols, const char *name)
{
    size_t len = strlen(name);
    const char *p = symbols;
    if (!p) return -1;
    while ((p = strstr(p, name))) {
        if ((p == symbols || isspace((unsigned char)p[-1])) &&
            (!p[len] || isspace((unsigned char)p[len]))) return 1;
        p += len;
    }
    return 0;
}

static const char *inspect_present(const char *symbols, const char *name)
{
    int value = inspect_symbol(symbols, name);
    return value < 0 ? "unknown" : value ? "present" : "absent";
}

static int inspect_main(int argc, char **argv)
{
    struct kclf_btf btf;
    struct uz_layout layout;
    struct kclf_compat_profile loader;
    char *data = NULL, *symbols = NULL;
    const char *symbol_path = NULL, *version = NULL;
    size_t bytes;
    unsigned major = 0, minor = 0, patch = 0;
    int result = 2, layout_ok, known = 0, older = 0;
    static const struct { const char *name, *shape; int stable; } apis[] = {
        {"do_mem_abort", "vlsr", 1}, {"find_vma", "aml", 1},
        {"mmap_read_lock", "vm", 1}, {"mmap_read_unlock", "vm", 1},
        {"mmap_read_trylock", "bm", 1}, {"down_read_trylock", "ip", 1},
        {"down_read", "vp", 1}, {"up_read", "vp", 1},
        {"down_write", "vp", 1}, {"up_write", "vp", 1},
        {"__rcu_read_lock", "v", 1}, {"__rcu_read_unlock", "v", 1},
        {"force_sig_fault", "iiip", 1}, {"copy_from_user_nofault", "lppl", 1},
        {"copy_to_user_nofault", "lppl", 1},
        {"internal_get_user_pages_fast", "illiD", 0}, {"gup_fast_fallback", "illiD", 0},
        {"get_user_pages_fast", "iliiD", 1}, {"alloc_pages", "Pii", 0},
        {"alloc_pages_noprof", "Pii", 0}, {"__alloc_pages", "Piiip", 0},
        {"__alloc_pages_noprof", "Piiip", 0}, {"__alloc_pages_nodemask", "Piiip", 0},
        {"put_page", "vp", 1}, {"copy_highpage", "vpp", 1},
        {"vmalloc_to_page", "pp", 1}, {"unpin_user_page", "vp", 1},
        {"try_grab_page", "bPi", 0}, {"try_grab_page", "iPi", 0},
        {"try_grab_compound_head", "PPii", 0}, {"copy_mm", "ilt", 1},
        {"fpsimd_save_and_flush_current_state", "v", 1},
        {"fpsimd_signal_preserve_current_state", "v", 1},
        {"fpsimd_update_current_state", "vf", 1}
    };
    if (argc < 3) goto usage;
    for (int i = 3; i < argc; ++i) {
        if (!strcmp(argv[i], "--symbols") && i + 1 < argc && !symbol_path) symbol_path = argv[++i];
        else if (!strcmp(argv[i], "--kernel") && i + 1 < argc && !version) version = argv[++i];
        else goto usage;
    }
    if (version) {
        char tail;
        if (sscanf(version, "%u.%u.%u%c", &major, &minor, &patch, &tail) != 3 ||
            major > 255 || minor > 255 || patch > 65535) goto usage;
        known = major >= 5 && major < 7 && (major != 5 || minor >= 4);
        older = major < 6 || (major == 6 && minor < 3);
    }
    data = inspect_read(argv[2], &bytes);
    if (!data) goto out;
    if (uz_btf_open(&btf, data, bytes)) {
        fprintf(stderr, "invalid BTF: %s\n", argv[2]); goto out;
    }
    if (symbol_path && !(symbols = inspect_read(symbol_path, &bytes))) goto out;
    layout_ok = !uz_layout_from_btf(&layout, &btf);
    printf("scope=static-btf symbol_addresses=unverified kernel=%s layout=%s\n",
           version ? version : "unknown", layout_ok ? "supported" : "unsupported");
    if (layout_ok)
        printf("layout task.mm=%d mm.pgd=%d mm.users=%d mmap_lock=%d vma.flags=%d fpsimd=%d pgoff=%d\n",
               layout.task_mm, layout.mm_pgd, layout.mm_users, layout.mmap_lock,
               layout.vma_flags, layout.task_fpsimd, layout.vma_pgoff_ok);
    for (unsigned i = 0; i < sizeof(apis) / sizeof(apis[0]); ++i) {
        const struct kclf_btf_type *proto = kclf_btf_func_proto(&btf, apis[i].name);
        int strict = uz_btf_signature(&btf, proto, apis[i].shape);
        printf("abi %s shape=%s symbol=%s evidence=%s\n", apis[i].name, apis[i].shape,
               inspect_present(symbols, apis[i].name), strict ? "btf" :
               proto ? "rejected" : apis[i].stable ? "public-fallback" : "unavailable");
    }
    printf("pt apply_existing=%d/%s apply_legacy=%d/%s map_lock=%d/%s unfold=%d/%s\n",
           uz_apply_pt_abi(&btf, "apply_to_existing_page_range"), inspect_present(symbols, "apply_to_existing_page_range"),
           uz_apply_pt_abi(&btf, "apply_to_page_range"), inspect_present(symbols, "apply_to_page_range"),
           uz_native_pt_abi(&btf), inspect_present(symbols, "__pte_offset_map_lock"),
           uz_contpte_abi(&btf), inspect_present(symbols, "__contpte_try_unfold"));
    {
        static const char *const names[] = {"handle_mm_fault", "do_handle_mm_fault", "access_remote_vm", "__access_remote_vm"};
        for (unsigned i = 0; i < 4; ++i) {
            int n = i < 2 ? uz_mm_fault_argc(&btf, names[i], i == 0) : uz_access_vm_argc(&btf, names[i], i == 2);
            printf("entry %s argc=%d symbol=%s evidence=%s\n", names[i], n,
                   inspect_present(symbols, names[i]), !n ? "rejected" :
                   kclf_btf_func_proto(&btf, names[i]) ? "btf" : "public-fallback");
        }
    }
    {
        const char *names[] = {"__get_user_pages_remote", "pin_user_pages_remote", "get_user_pages_remote"};
        int counts[3], evidence;
        struct uz_remote_gup_choice choice;
        for (unsigned i = 0; i < 3; ++i) {
            counts[i] = inspect_symbol(symbols, names[i]) != 0 ? uz_remote_gup_argc(&btf, names[i]) : 0;
            printf("gup %s argc=%d symbol=%s\n", names[i], counts[i], inspect_present(symbols, names[i]));
        }
        evidence = inspect_symbol(symbols, "pin_user_pages_remote") > 0 ||
            inspect_symbol(symbols, "unpin_user_page") > 0 ||
            kclf_btf_func_proto(&btf, "pin_user_pages_remote") || kclf_btf_func_proto(&btf, "unpin_user_page") ||
            uz_btf_enum_flag(&btf, "FOLL_PIN", ~0U) != ~0U;
        choice = uz_remote_gup_select(counts[0], counts[1], counts[2], evidence);
        printf("gup candidate=%d argc=%d refs=%s symbols_checked=%d folio_int=%d folio_ptr=%d node_id=%d\n",
               choice.entry, choice.argc, !choice.argc ? "none" : choice.get_refs ? "GET" : "PIN",
               symbols != NULL, uz_folio_grab_abi(&btf), uz_folio_page_grab_abi(&btf), uz_pgdat_node_offset(&btf));
    }
    {
        const char *names[] = {"FOLL_GET", "FOLL_PIN", "FOLL_LONGTERM", "FOLL_FAST_ONLY", "FOLL_FORCE"};
        unsigned fallbacks[] = {older ? 4U : 0U, older ? 0x40000U : 0U,
            older ? 0x10000U : 0x100U, older ? 0x80000U : 0U, older ? 0x10U : 8U};
        for (unsigned i = 0; i < 5; ++i) {
            unsigned raw = uz_btf_enum_flag(&btf, names[i], ~0U);
            unsigned fallback = known ? fallbacks[i] : 0;
            unsigned value = i == 4 ? uz_foll_force(&btf, fallback) : uz_btf_enum_flag(&btf, names[i], fallback);
            printf("flag %s=0x%x evidence=%s\n", names[i], value,
                   !value ? "unavailable" : raw == ~0U ? "version" : "btf");
        }
    }
    printf("kclf_profile=%s refault_atomic=0 hot_unload=0 runtime=unverified\n",
           kclf_compat_profile_read(&loader, &btf) ? "unsupported" : "supported");
    puts("Inspection only: runtime geometry, helper addresses, hook installation and behavior require device validation.");
    result = layout_ok ? 0 : 3;
out:
    free(symbols); free(data);
    return result;
usage:
    fprintf(stderr, "Usage: %s --inspect BTF [--symbols names-or-kallsyms.txt] [--kernel M.m.p]\n", argv[0]);
    return 2;
}
#endif
