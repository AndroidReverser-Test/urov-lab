/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host regression model for the standalone design. Its entry points use
 * injected helpers and synthetic mappings. Never link it into an active KPM. */
#ifndef UROV_HOST_TEST
#error "The resident lifecycle model requires the host test harness"
#endif
#include <hook.h>
#include <linux/errno.h>
#include "resident_model.h"
#include "resident_profile.h"
#include "../emulate.h"

#define API_CALLS
#define GET(p, type, member) (*(uint64_t *)((char *)(p) + O_##type##_##member))
#define GET32(p, type, member) (*(uint32_t *)((char *)(p) + O_##type##_##member))
#define PTR(p, type, member) ((void *)(uintptr_t)GET(p, type, member))
#define PAGE 4096UL
#define LIMIT (1UL << 39)
#define PA_MASK 0x0000fffffffff000UL
#define USER (1UL << 6)
#define RDONLY (1UL << 7)
#define UXN (1UL << 54)
#define PXN (1UL << 53)
#define PTE_FORBIDDEN ((1UL << 52) | (1UL << 56) | (1UL << 57))
#define VM_OWNED (1UL | 0x20000UL | 0x40000UL | 0x40000000UL)
#define VM_FORBIDDEN (2UL | 0x20UL | 0x100UL | 0x200UL | 0x400UL | 0x1000UL | \
                      0x4000UL | 0x400000UL | 0x10000000UL | (1UL << 32) | (1UL << 37))

/* Native arm64 pt_regs starts with struct user_pt_regs. No trailing fields
 * are read or written. BTF verifies the offsets before this image is used. */
struct pt_regs { uint64_t regs[31], sp, pc, pstate; };
static struct urov_kernel_api api;
static struct urov_resident_status status;
static uint32_t attached, job_busy, draining, inflight;
static void *gate_mm;
static struct {
    void *mm, *page;
    struct uro_view view;
    uint64_t id, registration, initial, flags, value, generation;
    uint64_t last_id, last_expected, last_value;
    uint64_t original_flags, original_prot, pfn, hits, failures;
    uint32_t active, state;
    int error;
    uint8_t bytes[PAGE];
} session;
static struct {
    struct callback_head work;
    struct urov_submit message;
    void *user;
} job;

static void bytecopy(void *dst, const void *src, unsigned long n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
}
static struct task_struct *this_task(void)
{
    return urov_test_current_task();
}
static void *this_mm(void) { return PTR(this_task(), task_struct, mm); }
static void *linear(uint64_t phys) { return (void *)(phys - api.memstart - (1UL << 39)); }
static void tlb_sync(void)
{
    /* Conservative system-wide flush avoids guessing ASID generation or KPTI.
     * Only registration/restoration uses this, never SET or the fault path. */
    urov_test_tlb_sync();
}
static uint64_t caps(void)
{
    uint64_t sctlr, result = UROV_CAP_GPR | UROV_CAP_PAIR | UROV_CAP_TASK_WORK | UROV_CAP_RESIDENT;
    sctlr = urov_test_sctlr();
    if (sctlr & (1UL << 57)) result |= UROV_CAP_EPAN;
    if (api.allow_raw_xom) result |= UROV_CAP_RAW_XOM;
    if (status.ready) result |= UROV_CAP_READY | UROV_CAP_MM_GATES;
    return result;
}
static API_CALLS void vma_write(void *vma)
{
    void *mm = PTR(vma, vm_area_struct, vm_mm);
    uint32_t seq = GET32(mm, mm_struct, mm_lock_seq);
    if (GET32(vma, vm_area_struct, vm_lock_seq) != seq) {
        void *lock = (char *)PTR(vma, vm_area_struct, vm_lock) + O_vma_lock_lock;
        api.down_write(lock);
        __atomic_store_n(&GET32(vma, vm_area_struct, vm_lock_seq), seq, __ATOMIC_RELEASE);
        api.up_write(lock);
    }
}
static API_CALLS void mmap_unlock(void *mm)
{
    uint32_t seq = GET32(mm, mm_struct, mm_lock_seq);
    __atomic_store_n(&GET32(mm, mm_struct, mm_lock_seq), seq + 1, __ATOMIC_RELEASE);
    api.up_write((char *)mm + O_mm_struct_mmap_lock);
}
static int overlap(uint64_t start, uint64_t end)
{
    return start < session.view.base + PAGE && end > session.view.base;
}

/* Before/after counters cover operations that started BEFORE publication of
 * gate_mm, including sleepable UFFD/madvise/mremap entry points. Registration
 * publishes the gate, executes a full barrier, then refuses any in-flight
 * operation. Operations starting afterwards observe the gate and are denied.
 * No lock acquired here can invert mmap_lock ordering. */
static void gate_before(hook_fargs0_t *f, void *which)
{
    uint64_t *a = f->args;
    void *mm = NULL, *vma = NULL, *protected;
    uint64_t start = 0, end = ~0UL;
    unsigned int kind = (unsigned int)(uintptr_t)which;
    __atomic_add_fetch(&inflight, 1, __ATOMIC_SEQ_CST);
    protected = __atomic_load_n(&gate_mm, __ATOMIC_SEQ_CST);
    if (!protected) return;
    switch (kind) {
    case 0: /* do_mas_munmap(mas, mm, start, len, uf, downgrade) */
        mm = (void *)a[1]; start = a[2]; end = start + a[3];
        if (end < start) end = ~0UL;
        break;
    case 1: /* mprotect_fixup(tlb, vma, prev, start, end, flags) */
        vma = (void *)a[1]; start = a[3]; end = a[4]; break;
    case 2: /* mlock_fixup(vma, prev, start, end, flags) */
        vma = (void *)a[0]; start = a[2]; end = a[3]; break;
    case 3: /* do_madvise(mm, start, len, behavior) */
        mm = (void *)a[0]; start = a[1] & ((1UL << 56) - 1); end = start + a[2];
        if (end < start) end = ~0UL;
        break;
    case 4: /* __arm64_sys_mremap; reject all moves in the active mm */
        mm = this_mm(); break;
    case 5: /* userfaultfd_ioctl(file, cmd, arg), also covers remote owners */
        mm = PTR(PTR((void *)a[0], file, private_data), userfaultfd_ctx, mm); break;
    case 6: /* vma_merge; adjacent operations must not merge this VMA */
        mm = (void *)a[0]; break;
    case 7: /* madvise_set_anon_name (prctl VMA naming) uses mmap write lock */
        mm = (void *)a[0]; break;
    }
    if (vma) mm = PTR(vma, vm_area_struct, vm_mm);
    if (mm != protected || !overlap(start, end)) return;
    if (kind == 2 && a[1]) *(void **)a[1] = vma;
    f->ret = kind == 6 ? 0 : (uint64_t)-EBUSY;
    f->skip_origin = 1;
}
static void gate_after(hook_fargs0_t *f, void *which)
{
    (void)f; (void)which;
    __atomic_sub_fetch(&inflight, 1, __ATOMIC_SEQ_CST);
}

/* Reject block/huge/contiguous mappings BEFORE invoking the native walker,
 * whose apply_to_pte_range contains BUG_ON(pmd_huge()). mmap_lock is held. */
static int leaf_present(void *mm, uint64_t address)
{
    uint64_t *table = PTR(mm, mm_struct, pgd), entry;
    unsigned int shifts[] = { 30, 21 };
    unsigned int i;
    for (i = 0; i < 2; ++i) {
        entry = __atomic_load_n(&table[(address >> shifts[i]) & 511], __ATOMIC_ACQUIRE);
        if ((entry & 3) != 3) return -EOPNOTSUPP;
        table = linear(entry & PA_MASK);
    }
    entry = __atomic_load_n(&table[(address >> 12) & 511], __ATOMIC_ACQUIRE);
    return (entry & 3) == 3 && !(entry & PTE_FORBIDDEN) ? 0 : -EOPNOTSUPP;
}
struct pte_change { int enable, visited; };
static int change_leaf(pte_t *pte, unsigned long address, void *data)
{
    struct pte_change *change = data;
    uint64_t old, next;
    if (address != session.view.base || change->visited++) return -EINVAL;
    old = __atomic_load_n(&pte->pte, __ATOMIC_ACQUIRE);
    do {
        if ((old & 3) != 3 || (old & PTE_FORBIDDEN) || (old & PA_MASK) >> 12 != session.pfn ||
            !(old & RDONLY) || (old & UXN) || !(old & PXN) || ((old >> 2) & 7) != 0)
            return -ESTALE;
        if (change->enable && !(old & USER)) return -EOPNOTSUPP;
        next = change->enable ? old & ~USER : old | USER;
    } while (!__atomic_compare_exchange_n(&pte->pte, &old, next, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    return 0;
}
static API_CALLS int permission(void *vma, int enable)
{
    struct pte_change change = { .enable = enable };
    int rc = leaf_present(session.mm, session.view.base);
    (void)vma;
    if (rc) return rc;
    rc = api.apply_ptes(session.mm, session.view.base, PAGE, change_leaf, &change);
    if (!rc && change.visited != 1) rc = -EFAULT;
    if (!rc) tlb_sync();
    return rc;
}
static int validate_vma(void *vma, uint64_t address)
{
    void *file, *inode, *sb;
    uint64_t flags;
    uint32_t seals;
    if (!vma || GET(vma, vm_area_struct, vm_start) != address ||
        GET(vma, vm_area_struct, vm_end) != address + PAGE ||
        GET(vma, vm_area_struct, vm_pgoff)) return -EINVAL;
    flags = GET(vma, vm_area_struct, vm_flags);
    if ((flags & VM_FORBIDDEN) || (flags & (1 | 4 | 0x80)) != (1 | 4 | 0x80)) return -EINVAL;
    file = PTR(vma, vm_area_struct, vm_file);
    if (!file) return -EINVAL;
    inode = PTR(file, file, f_inode); sb = PTR(inode, inode, i_sb);
    if (GET(sb, super_block, s_magic) != 0x01021994 || GET(inode, inode, i_size) != PAGE) return -EINVAL;
    seals = *(uint32_t *)((char *)inode - O_shmem_inode_info_vfs_inode + O_shmem_inode_info_seals);
    return (seals & 15) == 15 ? 0 : -EPERM;
}
static API_CALLS void release_storage(void)
{
    void *mm = session.mm;
    if (session.page) api.unpin(&session.page, 1);
    session.page = NULL; session.mm = NULL;
    if (mm) api.mmput(mm);
}
static API_CALLS long activate(struct urov_request *q)
{
    void *mm, *vma;
    long rc;
    uint64_t page_address;
    if (!status.ready || !this_mm()) return -EOPNOTSUPP;
    if (!(caps() & UROV_CAP_EPAN) && (!(q->flags & UROV_F_RAW_XOM) || !api.allow_raw_xom))
        return -EOPNOTSUPP;
    if (!q->request_id || q->session || q->expected_generation || q->address < PAGE ||
        q->address >= LIMIT - PAGE || (q->address & (PAGE - 1)) || q->offset > PAGE - 8)
        return -EINVAL;
    if (status.sessions == ~0UL) return -EOVERFLOW;
    mm = api.get_mm(this_task());
    if (!mm) return -ESRCH;
    session.mm = mm; session.page = NULL;
    session.view.base = q->address; session.view.overlay_offset = q->offset;
    session.view.original = session.bytes; session.view.user_limit = LIMIT;
    __atomic_store_n(&gate_mm, mm, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&inflight, __ATOMIC_SEQ_CST)) { rc = -EBUSY; goto clear; }
    rc = api.pin(q->address, 1, &session.page, 0);
    if (rc != 1) { session.page = NULL; rc = rc < 0 ? rc : -EFAULT; goto clear; }
    api.down_write((char *)mm + O_mm_struct_mmap_lock);
    vma = api.find_vma(mm, q->address);
    rc = validate_vma(vma, q->address);
    if (rc) goto unlock;
    /* vmemmap = -(1 << (39 - (12 - 6))) - (memstart >> 12)*64.
     * Both VA_BITS and sizeof(struct page) are checked by the pinned profile. */
    page_address = (uint64_t)session.page;
    if (page_address & 63) { rc = -EOPNOTSUPP; goto unlock; }
    session.pfn = ((page_address + (1UL << 33)) >> 6) + (api.memstart >> 12);
    rc = leaf_present(mm, q->address);
    if (rc) goto unlock;
    bytecopy(session.bytes, linear(session.pfn << 12), PAGE);
    session.original_flags = GET(vma, vm_area_struct, vm_flags);
    session.original_prot = GET(vma, vm_area_struct, vm_page_prot);
    session.id = ++status.sessions; session.registration = q->request_id;
    session.initial = session.value = q->value; session.flags = q->flags;
    session.generation = 1; session.last_id = 0; session.state = UROV_ACTIVE;
    session.error = 0; session.hits = 0; session.failures = 0;
    vma_write(vma);
    GET(vma, vm_area_struct, vm_page_prot) = session.original_prot & ~USER;
    GET(vma, vm_area_struct, vm_flags) = (session.original_flags | (VM_OWNED & ~1UL)) & ~1UL;
    __atomic_store_n(&session.active, 1, __ATOMIC_RELEASE);
    rc = permission(vma, 1);
    if (rc) {
        GET(vma, vm_area_struct, vm_page_prot) = session.original_prot;
        GET(vma, vm_area_struct, vm_flags) = session.original_flags;
        __atomic_store_n(&session.active, 0, __ATOMIC_RELEASE);
    }
unlock:
    mmap_unlock(mm);
    if (!rc) return 0;
    api.sync_rcu();
clear:
    __atomic_store_n(&gate_mm, NULL, __ATOMIC_SEQ_CST);
    release_storage();
    return rc;
}
static API_CALLS long deactivate(void)
{
    void *vma, *mm = session.mm;
    long rc;
    if (!__atomic_load_n(&session.active, __ATOMIC_ACQUIRE)) return 0;
    api.down_write((char *)mm + O_mm_struct_mmap_lock);
    vma = api.find_vma(mm, session.view.base);
    if (!vma || GET(vma, vm_area_struct, vm_start) != session.view.base ||
        GET(vma, vm_area_struct, vm_end) != session.view.base + PAGE) {
        rc = -ESTALE; goto unlock;
    }
    vma_write(vma);
    rc = permission(vma, 0);
    if (!rc) {
        GET(vma, vm_area_struct, vm_page_prot) = session.original_prot;
        GET(vma, vm_area_struct, vm_flags) =
            (GET(vma, vm_area_struct, vm_flags) & ~VM_OWNED) | (session.original_flags & VM_OWNED);
    }
unlock:
    mmap_unlock(mm);
    if (rc) { session.state = UROV_RETAINED; session.error = (int)rc; return rc; }
    __atomic_store_n(&session.active, 0, __ATOMIC_RELEASE);
    api.sync_rcu();
    __atomic_store_n(&gate_mm, NULL, __ATOMIC_SEQ_CST);
    release_storage();
    session.state = UROV_INACTIVE;
    return 0;
}
static void report(struct urov_request *q)
{
    q->session = session.id; q->address = session.view.base; q->offset = session.view.overlay_offset;
    q->value = __atomic_load_n(&session.value, __ATOMIC_ACQUIRE); q->generation = session.generation;
    q->state = session.state; q->last_error = session.error;
    q->hits = __atomic_load_n(&session.hits, __ATOMIC_RELAXED);
    q->failures = __atomic_load_n(&session.failures, __ATOMIC_RELAXED);
}
static API_CALLS long request(struct urov_request *q)
{
    long rc;
    if (q->size != sizeof(*q) || q->version != UROV_ABI_VERSION || q->reserved0 ||
        q->reserved[0] || q->reserved[1] || q->reserved[2] || (q->flags & ~UROV_F_RAW_XOM) ||
        q->op < UROV_QUERY || q->op > UROV_DEACTIVATE) return -EINVAL;
    q->caps = caps();
    if (q->op == UROV_QUERY) {
        q->state = UROV_INACTIVE; q->session = q->generation = q->hits = q->failures = 0;
        q->last_error = status.error; return 0;
    }
    if (q->op == UROV_REGISTER) {
        if (session.active) {
            if (session.mm != this_mm() || q->request_id != session.registration ||
                q->address != session.view.base || q->offset != session.view.overlay_offset ||
                q->value != session.initial || q->flags != session.flags || q->session ||
                q->expected_generation) return -EBUSY;
            report(q); return 0;
        }
        rc = activate(q);
        if (!rc) report(q);
        return rc;
    }
    if (!session.active) {
        if (q->op == UROV_DEACTIVATE) { q->state = UROV_INACTIVE; return 0; }
        return -ENOENT;
    }
    if (session.mm != this_mm()) return -EPERM;
    if (q->session != session.id && !(q->op == UROV_STATUS && !q->session &&
        q->request_id == session.registration)) return -ESTALE;
    if (q->op == UROV_STATUS) { report(q); return 0; }
    if (q->op == UROV_DEACTIVATE) {
        rc = deactivate(); if (!rc) q->state = UROV_INACTIVE; return rc;
    }
    if (session.state != UROV_ACTIVE) return -EBUSY;
    if (!q->request_id) return -EINVAL;
    if (q->request_id == session.last_id) {
        if (q->expected_generation != session.last_expected || q->value != session.last_value) return -EINVAL;
    } else {
        if (q->expected_generation != session.generation) return -EAGAIN;
        if (session.generation == ~0UL) return -EOVERFLOW;
        session.last_id = q->request_id; session.last_value = q->value;
        session.last_expected = q->expected_generation;
        __atomic_store_n(&session.value, q->value, __ATOMIC_RELEASE);
        ++session.generation;
    }
    report(q); return 0;
}
static API_CALLS void task_request(struct callback_head *head)
{
    (void)head;
    job.message.result = __atomic_load_n(&attached, __ATOMIC_ACQUIRE) ?
        (int32_t)request(&job.message.request) : -ESHUTDOWN;
    /* Publish the completion token separately and last. A short copy of the
     * response cannot make incomplete result fields look successful. */
    if (!api.copy_out(job.user, &job.message, __builtin_offsetof(struct urov_submit, completed))) {
        uint32_t done = UROV_COMPLETED;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        api.copy_out((char *)job.user + __builtin_offsetof(struct urov_submit, completed),
                     &done, sizeof(done));
    }
    __atomic_store_n(&job_busy, 0, __ATOMIC_RELEASE);
}
static API_CALLS long queue_request(void *user, unsigned long size)
{
    uint32_t expected = 0;
    long rc;
    if (!user || ((uintptr_t)user & 7) || size != sizeof(job.message)) return -EINVAL;
    if (!__atomic_load_n(&attached, __ATOMIC_ACQUIRE) || __atomic_load_n(&draining, __ATOMIC_ACQUIRE))
        return -ESHUTDOWN;
    if (!__atomic_compare_exchange_n(&job_busy, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -EBUSY;
    if (!__atomic_load_n(&attached, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&draining, __ATOMIC_ACQUIRE)) { rc = -ESHUTDOWN; goto fail; }
    rc = api.copy_in(&job.message, user, size);
    if (rc) goto fail;
    job.message.result = -EINPROGRESS; job.message.completed = 0;
    rc = api.copy_out((char *)user + __builtin_offsetof(struct urov_submit, completed),
                      &job.message.completed, sizeof(job.message.completed));
    if (rc) goto fail;
    rc = api.copy_out((char *)user + __builtin_offsetof(struct urov_submit, result),
                      &job.message.result, sizeof(job.message.result));
    if (rc) goto fail;
    job.user = user; job.work.next = NULL; job.work.func = task_request;
    rc = api.task_add(this_task(), &job.work, 1); /* TWA_RESUME */
    if (!rc) return 0;
fail:
    __atomic_store_n(&job_busy, 0, __ATOMIC_RELEASE);
    return rc;
}

API_CALLS int urov_resident_fault(unsigned long far, unsigned long esr, struct pt_regs *regs)
{
    struct uro_regs model;
    uint32_t opcode;
    unsigned int i;
    int rc = 1;
    if ((regs->pstate & 15) || (esr >> 26) != 0x24 || (esr & 64) || (esr & 63) != 15)
        return api.native_fault(far, esr, regs);
    api.rcu_lock();
    if (!__atomic_load_n(&session.active, __ATOMIC_ACQUIRE) || session.mm != this_mm() ||
        far < session.view.base || far - session.view.base >= PAGE) {
        api.rcu_unlock(); return api.native_fault(far, esr, regs);
    }
    if (regs->pc >= session.view.base && regs->pc - session.view.base <= PAGE - 4) {
        bytecopy(&opcode, session.bytes + (regs->pc - session.view.base), 4);
    } else if (api.copy_in(&opcode, (void *)regs->pc, 4)) goto failed;
    for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
    model.sp = regs->sp; model.pc = regs->pc; model.pstate = regs->pstate;
    if (uro_emulate(&session.view, opcode, esr, far,
        __atomic_load_n(&session.value, __ATOMIC_ACQUIRE), &model) != URO_OK) goto failed;
    for (i = 0; i < 31; ++i) regs->regs[i] = model.x[i];
    regs->sp = model.sp; regs->pc = model.pc;
    __atomic_add_fetch(&session.hits, 1, __ATOMIC_RELAXED);
    rc = 0;
    goto done;
failed:
    __atomic_add_fetch(&session.failures, 1, __ATOMIC_RELAXED);
    /* Returning 1 to do_mem_abort uses the native SIGSEGV path. Never call
     * do_page_fault on an owned unsupported instruction to grant data access. */
done:
    api.rcu_unlock();
    return rc;
}

API_CALLS long urov_resident_entry(unsigned int operation, void *data, unsigned long size)
{
    unsigned int i;
    long rc;
    if (operation == UROV_R_INIT) {
        if (!data || size != sizeof(api)) return -EINVAL;
        if (__atomic_load_n(&job_busy, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&draining, __ATOMIC_ACQUIRE)) return -EBUSY;
        return -EOPNOTSUPP;
    }
    if (operation == UROV_R_QUEUE) return queue_request(data, size);
    if (operation == UROV_R_INSPECT) {
        if (!data || size != sizeof(status)) return -EINVAL;
        status.pending = __atomic_load_n(&job_busy, __ATOMIC_ACQUIRE);
        status.active = __atomic_load_n(&session.active, __ATOMIC_ACQUIRE);
        status.caps = caps(); bytecopy(data, &status, size); return 0;
    }
    if (operation != UROV_R_DRAIN) return -EINVAL;
    if (__atomic_exchange_n(&draining, 1, __ATOMIC_ACQ_REL)) return -EBUSY;
    __atomic_store_n(&attached, 0, __ATOMIC_RELEASE);
    /* Native RCU, not the legacy KP synchronize_rcu wrapper. */
    api.sync_rcu();
    for (i = 0; i < 1000 && __atomic_load_n(&job_busy, __ATOMIC_ACQUIRE); ++i) api.sleep_ms(1);
    rc = __atomic_load_n(&job_busy, __ATOMIC_ACQUIRE) ? -EBUSY : deactivate();
    status.error = (int)rc;
    __atomic_store_n(&draining, 0, __ATOMIC_RELEASE);
    return rc;
}
