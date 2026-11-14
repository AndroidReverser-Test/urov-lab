/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../kclf_compat_profile.h"

static uint32_t words[1024];
static char names[1024];
static unsigned used, named, ids, checks;
static unsigned add_proto, cancel_proto, notify_type, regs_type;
static const char *lock_name;

#define CHECK(condition) do { checks++; if (!(condition)) { \
    fprintf(stderr, "check %u failed at line %d: %s\n", checks, __LINE__, #condition); return 1; \
} } while (0)

static uint32_t str(const char *s)
{
    unsigned off = named;
    size_t n = strlen(s) + 1;
    memcpy(names + named, s, n);
    named += (unsigned)n;
    return off;
}

static unsigned type(const char *name, unsigned kind, unsigned n, unsigned size)
{
    words[used++] = name ? str(name) : 0;
    words[used++] = (kind << 24) | n;
    words[used++] = size;
    return ++ids;
}

static void member(const char *name, unsigned id, unsigned byte)
{
    words[used++] = str(name);
    words[used++] = id;
    words[used++] = byte * 8;
}

/* Independent fixtures model the real 5.4 bool, 5.8 int and 5.11+ enum
 * notify ABIs, and both function/object task_work cancellation signatures. */
static struct kclf_btf fixture(unsigned notify_kind, int cancel_object)
{
    unsigned integer, boolean, task, task_ptr, work, work_ptr, sem, nr, proto, func_ptr;
    struct kclf_btf b;
    used = ids = 0;
    named = 1;
    memset(words, 0, sizeof(words));
    memset(names, 0, sizeof(names));
    integer = type("int", 1, 0, 4); words[used++] = (1U << 24) | 32;
    boolean = type("_Bool", 1, 0, 1); words[used++] = (4U << 24) | 8;
    task = type("task_struct", 4, 1, 4096); member("mm", 0, 120);
    task_ptr = type(0, 2, 0, task);
    work = type("callback_head", 4, 0, 16);
    work_ptr = type(0, 2, 0, work);
    sem = type("rw_semaphore", 4, 0, 40);
    type("mm_struct", 4, 1, 1024); member(lock_name, sem, 256);
    type("vm_area_struct", 4, 2, 160); member("vm_start", 0, 8); member("vm_end", 0, 16);
    regs_type = used;
    type("pt_regs", 4, 6, 336);
    member("regs", 0, 0); member("sp", 0, 248); member("pc", 0, 256);
    member("pstate", 0, 264); member("orig_x0", 0, 272); member("syscallno", integer, 280);
    type("thread_info", 4, 1, 48); member("flags", 0, 0);
    notify_type = used;
    if (notify_kind == 6) {
        nr = type("task_work_notify_mode", 6, 3, 4);
        words[used++] = str("TWA_NONE"); words[used++] = 0;
        words[used++] = str("TWA_RESUME"); words[used++] = 1;
        words[used++] = str("TWA_SIGNAL"); words[used++] = 2;
    } else nr = notify_kind == 1 ? integer : boolean;
    add_proto = used;
    proto = type(0, 13, 3, integer);
    words[used++] = 0; words[used++] = task_ptr;
    words[used++] = 0; words[used++] = work_ptr;
    words[used++] = 0; words[used++] = nr;
    type("task_work_add", 12, 0, proto);
    proto = type(0, 13, 1, 0); words[used++] = 0; words[used++] = work_ptr;
    func_ptr = type(0, 2, 0, proto);
    cancel_proto = used;
    proto = type(0, 13, 2, cancel_object ? boolean : work_ptr);
    words[used++] = 0; words[used++] = task_ptr;
    words[used++] = 0; words[used++] = cancel_object ? work_ptr : func_ptr;
    type("task_work_cancel", 12, 0, proto);
    b.types = (const unsigned char *)words; b.type_len = used * sizeof(*words);
    b.strings = names; b.str_len = named;
    return b;
}

int main(void)
{
    struct kclf_compat_profile p, retained;
    struct kclf_btf b;
    unsigned kind, object;
    for (kind = 0; kind <= 6; kind += kind ? 5 : 1) {
        for (object = 0; object <= 1; object++) {
            lock_name = object ? "mmap_sem" : "mmap_lock";
            b = fixture(kind, (int)object);
            CHECK(kclf_compat_profile_read(&p, &b) == 0);
            CHECK(p.mm_off == 120 && p.vma_start == 8 && p.vma_end == 16);
            CHECK(p.mmap_lock == 256 && p.regs_size == 336);
            CHECK(p.signal_abi == (kind == 6 ? 1 : kind == 1 ? -1 : 0));
            CHECK(p.cancel_abi == (object ? 2 : 1));
            /* The snapshot outlives both detached type and string storage. */
            retained = p;
            memset(words, 0xa5, sizeof(words)); memset(names, 0xa5, sizeof(names));
            CHECK(retained.mm_off == 120 && retained.regs_size == 336);
        }
    }
    lock_name = "mmap_lock";
    b = fixture(6, 1);
    words[notify_type + 8] = 3; /* incompatible vendor TWA_SIGNAL value */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[add_proto + 2] = 0; /* void return, incompatible despite valid notify */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[add_proto + 4] = 1; /* integer task argument */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[add_proto + 6] = 1; /* integer callback argument */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[regs_type + 2] = 280; /* undersized exception frame */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[regs_type + 11] = 264 * 8; /* pc at wrong offset */
    CHECK(kclf_compat_profile_read(&p, &b) < 0);
    b = fixture(6, 1);
    words[cancel_proto + 6] = 1;
    CHECK(kclf_compat_profile_read(&p, &b) == 0 && p.cancel_abi == -1);
    /* A bad cancellation prototype stays explicit: a separately resolved
     * cancel_match can still be usable, but callers may never guess this ABI. */
    {
        uint32_t blob[2048] = {0};
        struct kclf_btf_header *h = (void *)blob;
        unsigned size;
        b = fixture(6, 0);
        h->magic = 0xeb9f; h->version = 1; h->hdr_len = sizeof(*h);
        h->type_len = (uint32_t)b.type_len; h->str_off = h->type_len; h->str_len = named;
        size = h->hdr_len + h->type_len + h->str_len;
        memcpy((char *)blob + h->hdr_len, words, b.type_len);
        memcpy((char *)blob + h->hdr_len + h->str_off, names, named);
        CHECK(kclf_btf_open(&b, blob, size) == 0);
        CHECK(kclf_compat_profile_read(&p, &b) == 0 && p.cancel_abi == 1);
        CHECK(kclf_btf_open(&b, blob, size - 1) < 0);
    }
    printf("KCLF compatibility profile: %u checks passed\n", checks);
    return 0;
}
