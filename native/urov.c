// SPDX-License-Identifier: GPL-2.0-or-later
/* Built into the matching Android kernel, never a loadable object. */
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/userfaultfd_k.h>
#include <linux/urov.h>
#include <asm/cpufeature.h>
#include <asm/esr.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include "emulate.h"
#include "urov_abi.h"

struct urov_session {
	struct mm_struct *mm; /* mm_count only; never pins mm_users until exit */
	struct page *page;
	struct uro_view view;
	u64 id, registration_id, initial_value, flags;
	u64 value __aligned(8), generation;
	u64 last_set_id, last_set_expected, last_set_value;
	unsigned long original_flags;
	pgprot_t original_prot;
	atomic64_t hits, failures;
	u32 state;
	int error;
	u8 bytes[UROV_PAGE_BYTES];
};

static DEFINE_MUTEX(urov_lock);
static DEFINE_STATIC_KEY_FALSE(urov_active);
static struct urov_session __rcu *urov_current;
static u64 next_id;
static bool core_ready;

static struct urov_session *locked_session(void)
{
	return rcu_dereference_protected(urov_current, lockdep_is_held(&urov_lock));
}

bool urov_range_busy(struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct urov_session *s;
	bool busy = false;
	rcu_read_lock();
	s = rcu_dereference(urov_current);
	if (s && s->mm == mm && start < s->view.base + PAGE_SIZE && end > s->view.base)
		busy = true;
	rcu_read_unlock();
	return busy;
}

bool urov_mm_busy(struct mm_struct *mm)
{
	return urov_range_busy(mm, 0, ULONG_MAX);
}

static u64 capabilities(void)
{
	u64 caps = UROV_CAP_GPR | UROV_CAP_PAIR | UROV_CAP_MM_GATES;
	if (cpus_have_const_cap(ARM64_HAS_EPAN)) caps |= UROV_CAP_EPAN;
	if (IS_ENABLED(CONFIG_UROV_LAB_RAW_XOM)) caps |= UROV_CAP_RAW_XOM;
	if (core_ready) caps |= UROV_CAP_READY;
	return caps;
}

/* mmap write lock makes VMA identity stable. Only the USER permission bit is
 * changed. PFN, AF, dirty, BTI and cache attributes are never reconstructed. */
static int change_permission(struct urov_session *s, struct vm_area_struct *vma, bool enable)
{
	struct mm_struct *mm = s->mm;
	unsigned long address = s->view.base;
	pgd_t *pgd = pgd_offset(mm, address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte, updated;
	spinlock_t *ptl;
	int ret = 0;

	if (pgd_none(*pgd) || pgd_bad(*pgd)) return -EFAULT;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) return -EFAULT;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || pud_bad(*pud) || pud_sect(*pud)) return -EOPNOTSUPP;
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || pmd_bad(*pmd) || pmd_trans_huge(*pmd) || pmd_sect(*pmd))
		return -EOPNOTSUPP;
	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = READ_ONCE(*ptep);
	if (!pte_present(pte) || pte_special(pte) || (pte_val(pte) & PTE_CONT)) {
		ret = -EAGAIN;
		goto out;
	}
	if (enable && (pte_pfn(pte) != page_to_pfn(s->page) ||
	    !(pte_val(pte) & PTE_USER) || !(pte_val(pte) & PTE_RDONLY) ||
	    (pte_val(pte) & PTE_UXN) || !(pte_val(pte) & PTE_PXN))) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	/* ptep_modify_prot_start preserves concurrent hardware AF/dirty updates. */
	pte = ptep_modify_prot_start(vma, address, ptep);
	updated = __pte(enable ? pte_val(pte) & ~PTE_USER : pte_val(pte) | PTE_USER);
	ptep_modify_prot_commit(vma, address, ptep, pte, updated);
out:
	pte_unmap_unlock(ptep, ptl);
	if (!ret) flush_tlb_range(vma, address, address + PAGE_SIZE);
	return ret;
}

static void destroy_session(struct urov_session *s)
{
	unpin_user_page(s->page);
	mmdrop(s->mm);
	kfree(s);
}

/* No mapping is restored from exit_mmap: its last userspace user is gone.
 * This runs before native teardown takes mmap_lock or releases page tables. */
void urov_mm_release(struct mm_struct *mm)
{
	struct urov_session *s;
	mutex_lock(&urov_lock);
	s = locked_session();
	if (s && s->mm == mm) {
		RCU_INIT_POINTER(urov_current, NULL);
		synchronize_rcu();
		static_branch_disable(&urov_active);
		destroy_session(s);
	}
	mutex_unlock(&urov_lock);
}

static int deactivate(struct urov_session *s)
{
	struct vm_area_struct *vma;
	int ret;
	/* A concurrent final mmput will run our exit_mmap integration. Do not
	 * wait for it while holding urov_lock, nor touch its torn-down VMAs. */
	if (!mmget_not_zero(s->mm)) return -EBUSY;
	mmap_write_lock(s->mm);
	vma = vma_lookup(s->mm, s->view.base);
	if (!vma || vma->vm_start != s->view.base || vma->vm_end != s->view.base + PAGE_SIZE) {
		ret = -ESTALE;
		goto unlock;
	}
	/* Set the reconstruction template first; gates remain installed on
	 * failure, so retry/exit can finish without a dangling exception path. */
	vma_start_write(vma);
	vma->vm_page_prot = s->original_prot;
	ret = change_permission(s, vma, false);
	if (!ret) {
		const unsigned long owned = VM_READ | VM_DONTCOPY | VM_DONTEXPAND | VM_NOHUGEPAGE;
		vm_flags_reset(vma, (vma->vm_flags & ~owned) | (s->original_flags & owned));
	}
unlock:
	mmap_write_unlock(s->mm);
	/* mmput must be outside urov_lock: it may be the last reference and
	 * synchronously re-enter urov_mm_release(). The caller drops it later. */
	if (ret) { s->state = UROV_RETAINED; s->error = ret; return ret; }
	rcu_assign_pointer(urov_current, NULL);
	synchronize_rcu();
	static_branch_disable(&urov_active);
	return 0;
}

static int validate_vma(struct vm_area_struct *vma, unsigned long address)
{
	struct inode *inode;
	unsigned int seals;
	const unsigned long forbidden = VM_WRITE | VM_MAYWRITE | VM_HUGETLB | VM_PFNMAP |
		VM_MIXEDMAP | VM_IO | VM_GROWSDOWN | VM_GROWSUP | VM_MTE;
	if (!vma || vma->vm_start != address || vma->vm_end != address + PAGE_SIZE ||
	    !vma->vm_file || vma->vm_pgoff || (vma->vm_flags & forbidden) ||
    	    (vma->vm_flags & (VM_READ | VM_EXEC | VM_MAYSHARE)) != (VM_READ | VM_EXEC | VM_MAYSHARE))
		return -EINVAL;
	if (userfaultfd_missing(vma) || userfaultfd_wp(vma) || userfaultfd_minor(vma))
		return -EOPNOTSUPP;
	inode = file_inode(vma->vm_file);
	if (inode->i_sb->s_magic != TMPFS_MAGIC || i_size_read(inode) != PAGE_SIZE)
		return -EINVAL;
	seals = READ_ONCE(SHMEM_I(inode)->seals);
	if ((seals & (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) !=
	    (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return -EPERM;
	return 0;
}

static int register_self(struct urov_request *q)
{
	struct urov_session *s;
	struct vm_area_struct *vma;
	long pinned;
	int ret;
	bool epan = cpus_have_const_cap(ARM64_HAS_EPAN);
	if (!core_ready || !current->mm || is_compat_task()) return -EOPNOTSUPP;
	if (!epan && (!(q->flags & UROV_F_RAW_XOM) || !IS_ENABLED(CONFIG_UROV_LAB_RAW_XOM)))
		return -EOPNOTSUPP;
	if (!q->request_id || q->session || q->expected_generation ||
	    q->address < PAGE_SIZE || !PAGE_ALIGNED(q->address) ||
	    q->address >= TASK_SIZE - PAGE_SIZE || q->offset > PAGE_SIZE - 8)
		return -EINVAL;
	if (next_id == U64_MAX) return -EOVERFLOW;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) return -ENOMEM;
	s->mm = current->mm;
	s->view.original = s->bytes;
	s->view.base = q->address;
	s->view.user_limit = TASK_SIZE;
	s->view.overlay_offset = q->offset;
	s->id = ++next_id;
	s->registration_id = q->request_id;
	s->initial_value = s->value = q->value;
	s->flags = q->flags;
	s->generation = 1;
	s->state = UROV_ACTIVE;
	atomic64_set(&s->hits, 0);
	atomic64_set(&s->failures, 0);
	/* GUP may take mmap_lock internally. Revalidate every field afterwards. */
	pinned = pin_user_pages_unlocked(q->address, 1, &s->page, 0);
	if (pinned != 1) { ret = pinned < 0 ? pinned : -EFAULT; goto free; }
	mmap_write_lock(s->mm);
	vma = vma_lookup(s->mm, q->address);
	ret = validate_vma(vma, q->address);
	if (ret) goto unlock;
	if (PageCompound(s->page) || PageHighMem(s->page)) { ret = -EOPNOTSUPP; goto unlock; }
	memcpy(s->bytes, page_address(s->page), PAGE_SIZE);
	s->original_flags = vma->vm_flags;
	s->original_prot = vma->vm_page_prot;
	vma_start_write(vma);
	mmgrab(s->mm);
	/* Complete immutable context precedes both the PTE restriction and the
	 * first possible exception. Lookup never exposes an incomplete record. */
	static_branch_enable(&urov_active);
	rcu_assign_pointer(urov_current, s);
	vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) & ~PTE_USER);
	vm_flags_set(vma, VM_DONTCOPY | VM_DONTEXPAND | VM_NOHUGEPAGE);
	vm_flags_clear(vma, VM_READ);
	ret = change_permission(s, vma, true);
	if (ret) {
		vma->vm_page_prot = s->original_prot;
		vm_flags_reset(vma, s->original_flags);
		rcu_assign_pointer(urov_current, NULL);
	}
	mmap_write_unlock(s->mm);
	if (!ret) return 0;
	synchronize_rcu();
	static_branch_disable(&urov_active);
	mmdrop(s->mm);
	goto unpin;
unlock:
	mmap_write_unlock(s->mm);
unpin:
	unpin_user_page(s->page);
free:
	kfree(s);
	return ret;
}

static void report(struct urov_request *q, struct urov_session *s)
{
	q->caps = capabilities();
	q->session = s->id;
	q->address = s->view.base;
	q->offset = s->view.overlay_offset;
	q->value = s->value;
	q->generation = s->generation;
	q->state = s->state;
	q->last_error = s->error;
	q->hits = atomic64_read(&s->hits);
	q->failures = atomic64_read(&s->failures);
}

/* Kernel callers are trusted; USER requests are copied/validated here. The
 * bridge is called only from KP v2's sleepable, counted callback context. */
long urov_backend_v1(unsigned int call, void *request, unsigned long size)
{
	struct urov_request q;
	struct urov_session *s, *destroy = NULL;
	struct mm_struct *drop_users = NULL;
	long ret = 0;
	if (call == UROV_BACKEND_PROBE) return core_ready ? UROV_ABI_VERSION : -EOPNOTSUPP;
	if (call != UROV_BACKEND_USER && call != UROV_BACKEND_DRAIN) return -EINVAL;
	if (call == UROV_BACKEND_USER) {
		if (!request || size != sizeof(q)) return -EINVAL;
		if (copy_from_user(&q, (void __user *)request, sizeof(q))) return -EFAULT;
		if (q.size != sizeof(q) || q.version != UROV_ABI_VERSION || q.reserved0 ||
		    q.reserved[0] || q.reserved[1] || q.reserved[2] || (q.flags & ~UROV_F_RAW_XOM))
			return -EINVAL;
		if (q.op < UROV_QUERY || q.op > UROV_DEACTIVATE) return -EINVAL;
	}
	mutex_lock(&urov_lock);
	s = locked_session();
	if (call == UROV_BACKEND_DRAIN) {
		if (s) goto drain;
		goto unlock;
	}
	q.caps = capabilities();
	if (q.op == UROV_QUERY) {
		q.state = UROV_INACTIVE;
		q.session = q.generation = q.hits = q.failures = 0;
		q.last_error = 0;
		goto unlock;
	}
	if (q.op == UROV_REGISTER) {
		if (s) {
			if (s->mm == current->mm && s->registration_id == q.request_id &&
			    s->view.base == q.address && s->view.overlay_offset == q.offset &&
			    s->initial_value == q.value && s->flags == q.flags && !q.session &&
			    !q.expected_generation) report(&q, s);
			else ret = -EBUSY;
		} else {
			ret = register_self(&q);
			if (!ret) report(&q, locked_session());
		}
		goto unlock;
	}
	if (!s) {
		/* Deactivation is idempotent; an absent handle never restores a PTE. */
		if (q.op == UROV_DEACTIVATE) { q.state = UROV_INACTIVE; goto unlock; }
		ret = -ENOENT; goto unlock;
	}
	if (s->mm != current->mm) { ret = -EPERM; goto unlock; }
	if (q.session != s->id && !(q.op == UROV_STATUS && !q.session && q.request_id == s->registration_id)) {
		ret = -ESTALE; goto unlock;
	}
	if (q.op == UROV_STATUS) { report(&q, s); goto unlock; }
	if (q.op == UROV_SET) {
		if (s->state != UROV_ACTIVE) { ret = -EBUSY; goto unlock; }
		if (!q.request_id) { ret = -EINVAL; goto unlock; }
		if (q.request_id == s->last_set_id) {
			if (q.value != s->last_set_value || q.expected_generation != s->last_set_expected)
				ret = -EINVAL;
		} else if (q.expected_generation != s->generation) ret = -EAGAIN;
		else if (s->generation == U64_MAX) ret = -EOVERFLOW;
		else {
			s->last_set_id = q.request_id;
			s->last_set_expected = q.expected_generation;
			s->last_set_value = q.value;
			smp_store_release(&s->value, q.value);
			++s->generation;
		}
		if (!ret) report(&q, s);
		goto unlock;
	}
drain:
	ret = deactivate(s);
	/* deactivate took exactly one temporary mm_users on every path except
	 * EBUSY. Keep it past mutex_unlock to avoid exit_mmap lock recursion. */
	if (ret != -EBUSY) drop_users = s->mm;
	if (!ret) {
		destroy = s;
		if (call == UROV_BACKEND_USER) q.state = UROV_INACTIVE;
	}
unlock:
	mutex_unlock(&urov_lock);
	if (destroy) destroy_session(destroy);
	if (drop_users) mmput(drop_users);
	if (!ret && call == UROV_BACKEND_USER && copy_to_user((void __user *)request, &q, sizeof(q)))
		ret = -EFAULT; /* REGISTER/SET may have committed: retry by request_id. */
	return ret;
}
EXPORT_SYMBOL_GPL(urov_backend_v1);

bool urov_handle_abort(unsigned long far, unsigned long esr, struct pt_regs *regs)
{
	struct urov_session *s;
	struct uro_regs model;
	u32 opcode;
	unsigned int i;
	int result;
	bool failed = false;
	if (!static_branch_unlikely(&urov_active) || !user_mode(regs) ||
	    ESR_ELx_EC(esr) != ESR_ELx_EC_DABT_LOW || (esr & ESR_ELx_WNR) ||
	    (esr & ESR_ELx_FSC) != (ESR_ELx_FSC_PERM | 3)) return false;
	rcu_read_lock();
	s = rcu_dereference(urov_current);
	if (!s || s->mm != current->mm || far < s->view.base || far - s->view.base >= PAGE_SIZE) {
		rcu_read_unlock(); return false;
	}
	if (regs->pc >= s->view.base && regs->pc - s->view.base <= PAGE_SIZE - 4) {
		unsigned int at = regs->pc - s->view.base;
		opcode = s->bytes[at] | (u32)s->bytes[at + 1] << 8 |
			(u32)s->bytes[at + 2] << 16 | (u32)s->bytes[at + 3] << 24;
	} else if (copy_from_user_nofault(&opcode, (void __user *)regs->pc, sizeof(opcode))) {
		failed = true; goto finish;
	}
	for (i = 0; i < 31; ++i) model.x[i] = regs->regs[i];
	model.sp = regs->sp; model.pc = regs->pc; model.pstate = regs->pstate;
	result = uro_emulate(&s->view, opcode, esr, far, smp_load_acquire(&s->value), &model);
	if (result != URO_OK) { failed = true; goto finish; }
	for (i = 0; i < 31; ++i) regs->regs[i] = model.x[i];
	regs->sp = model.sp; regs->pc = model.pc;
finish:
	if (failed) atomic64_inc(&s->failures);
	else atomic64_inc(&s->hits);
	rcu_read_unlock();
	if (failed) force_sig_fault(SIGSEGV, SEGV_ACCERR, (void __user *)far);
	return true;
}

static int __init urov_init(void)
{
	u8 *scratch = kmalloc(PAGE_SIZE, GFP_KERNEL);
	unsigned int checks;
	int ret;
	if (!scratch) return -ENOMEM;
	ret = uro_core_selftest(scratch, &checks);
	kfree(scratch);
	core_ready = !ret && checks == 4114;
	return core_ready ? 0 : -EINVAL;
}
late_initcall(urov_init);
