/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Regression harness for the proposed lifecycle and request protocol. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UROV_HOST_TEST 1
#define _KP_HOOK_H_ 1
typedef struct {
    void *chain;
    int skip_origin;
    struct { uint64_t data[8]; } local;
    uint64_t ret;
    uint64_t args[12];
} hook_fargs0_t;

struct task_struct;
static struct task_struct *urov_test_current_task(void);
static void urov_test_tlb_sync(void);
static uint64_t urov_test_sctlr(void);
#include "resident_model.c"


static _Atomic unsigned long assertions;
#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        abort(); \
    } \
    atomic_fetch_add_explicit(&assertions, 1, memory_order_relaxed); \
} while (0)

static _Alignas(64) unsigned char fake_task[8192], fake_mm[4096], other_mm[4096];
static struct callback_head *queued;
static _Thread_local unsigned int rcu_depth;
static unsigned int copies_in, copies_out, pins, mmputs, syncs, native_faults, tlbs;
static unsigned int mm_lock_depth;
static unsigned int fail_in_at, fail_out_at;
static int queue_error, partial_copy_error;
static uint64_t mock_sctlr;
static pthread_barrier_t *pin_entered, *pin_release;

static struct task_struct *urov_test_current_task(void) { return (void *)fake_task; }
static void urov_test_tlb_sync(void) { ++tlbs; }
static uint64_t urov_test_sctlr(void) { return mock_sctlr; }
static void barrier(pthread_barrier_t *b)
{
    int rc = pthread_barrier_wait(b);
    CHECK(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}
static long mock_copy_in(void *dst, const void *src, unsigned long n)
{
    if (++copies_in == fail_in_at) return -EFAULT;
    memcpy(dst, src, n);
    return 0;
}
static long mock_copy_out(void *dst, const void *src, unsigned long n)
{
    if (++copies_out == fail_out_at) {
        /* A faulting copy can have changed a tail before reporting failure.
         * Completion must not be part of a payload copied in the same call. */
        if (partial_copy_error && n) {
            unsigned long tail = n < 4 ? n : 4;
            memcpy((char *)dst + n - tail, (const char *)src + n - tail, tail);
        }
        return -EFAULT;
    }
    memcpy(dst, src, n);
    return 0;
}
static int mock_task_add(struct task_struct *task, struct callback_head *head, int notify)
{
    CHECK(task == (void *)fake_task);
    CHECK(notify == 1);
    if (queue_error) return queue_error;
    CHECK(queued == NULL);
    queued = head;
    return 0;
}
static void *mock_get_mm(struct task_struct *task)
{
    CHECK(task == (void *)fake_task);
    return PTR(fake_task, task_struct, mm);
}
static void mock_mmput(void *mm)
{
    CHECK(mm == fake_mm || mm == other_mm);
    ++mmputs;
}
static void mock_mmap_lock(void *lock)
{
    CHECK(lock == fake_mm + O_mm_struct_mmap_lock && !mm_lock_depth);
    ++mm_lock_depth;
}
static void mock_mmap_unlock(void *lock)
{
    CHECK(lock == fake_mm + O_mm_struct_mmap_lock && mm_lock_depth == 1);
    --mm_lock_depth;
}
static void *mock_missing_vma(void *mm, unsigned long address)
{
    CHECK(mm == fake_mm && address == session.view.base && mm_lock_depth == 1);
    return NULL;
}
static long mock_pin(unsigned long address, unsigned long count, void **pages, unsigned int flags)
{
    CHECK(address == 0x400000 && count == 1 && flags == 0);
    CHECK(pages == &session.page);
    ++pins;
    if (pin_entered) barrier(pin_entered);
    if (pin_release) barrier(pin_release);
    return -ECANCELED; /* Admission tests never touch native/fake page tables. */
}
static void mock_sync_rcu(void) { CHECK(rcu_depth == 0); ++syncs; }
static void mock_rcu_lock(void) { ++rcu_depth; }
static void mock_rcu_unlock(void) { CHECK(rcu_depth != 0); --rcu_depth; }
static void mock_sleep(unsigned int milliseconds) { CHECK(milliseconds == 1); }
static int mock_native_fault(unsigned long far, unsigned long esr, struct pt_regs *regs)
{
    (void)far; (void)esr; (void)regs;
    CHECK(rcu_depth == 0);
    ++native_faults;
    return 123;
}
static void reset_backend(void)
{
    CHECK(rcu_depth == 0);
    memset(&api, 0, sizeof(api)); memset(&status, 0, sizeof(status));
    memset(&session, 0, sizeof(session)); memset(&job, 0, sizeof(job));
    memset(fake_task, 0, sizeof(fake_task)); memset(fake_mm, 0, sizeof(fake_mm));
    memset(other_mm, 0, sizeof(other_mm));
    attached = 1; job_busy = 0; draining = 0; inflight = 0;
    gate_mm = NULL; queued = NULL; mock_sctlr = 0;
    copies_in = copies_out = pins = mmputs = syncs = native_faults = tlbs = mm_lock_depth = 0;
    fail_in_at = fail_out_at = 0; queue_error = partial_copy_error = 0;
    pin_entered = pin_release = NULL;
    GET(fake_task, task_struct, mm) = (uintptr_t)fake_mm;
    api.copy_in = mock_copy_in; api.copy_out = mock_copy_out;
    api.task_add = mock_task_add; api.get_mm = mock_get_mm; api.mmput = mock_mmput;
    api.pin = mock_pin; api.rcu_lock = mock_rcu_lock; api.rcu_unlock = mock_rcu_unlock;
    api.sync_rcu = mock_sync_rcu; api.sleep_ms = mock_sleep;
    api.native_fault = mock_native_fault; api.allow_raw_xom = 1;
    api.down_write = mock_mmap_lock; api.up_write = mock_mmap_unlock;
    api.find_vma = mock_missing_vma;
    /* Simulate an already attached controller to a published resident image. */
    status.ready = 1;
    status.checks = 4114;
    status.hooks = 255;
}
static struct urov_request make_request(unsigned int op)
{
    struct urov_request q = { .size = sizeof(q), .version = UROV_ABI_VERSION, .op = (uint16_t)op };
    return q;
}
static struct urov_submit make_submit(unsigned int op)
{
    struct urov_submit m = { .request = make_request(op), .result = -EINPROGRESS };
    return m;
}
static void run_queued(void)
{
    struct callback_head *work = queued;
    CHECK(work == &job.work && job_busy == 1);
    queued = NULL;
    work->func(work);
    CHECK(job_busy == 0 && rcu_depth == 0);
}
static void seed_session(void)
{
    session.active = 1; session.mm = fake_mm; session.id = 17;
    session.registration = 1; session.initial = session.value = 0x8877665544332211ULL;
    session.flags = UROV_F_RAW_XOM; session.generation = 1; session.state = UROV_ACTIVE;
    session.view.base = 0x400000; session.view.overlay_offset = 4;
    session.view.original = session.bytes; session.view.user_limit = LIMIT;
}

static void test_wire_and_queue(void)
{
    struct urov_submit m;
    CHECK(sizeof(struct urov_request) == 128 && sizeof(struct urov_submit) == 136);
    CHECK(offsetof(struct urov_submit, result) == 128);
    CHECK(offsetof(struct urov_submit, completed) == 132);
    reset_backend();
    m = make_submit(UROV_QUERY);
    CHECK(queue_request(NULL, sizeof(m)) == -EINVAL);
    CHECK(queue_request((unsigned char *)&m + 1, sizeof(m)) == -EINVAL);
    CHECK(queue_request(&m, sizeof(m) - 1) == -EINVAL);
    CHECK(queue_request(&m, sizeof(m)) == 0);
    CHECK(m.completed == 0 && m.result == -EINPROGRESS && job_busy == 1);
    CHECK(queue_request(&m, sizeof(m)) == -EBUSY);
    run_queued();
    CHECK(m.completed == UROV_COMPLETED && m.result == 0);
    CHECK(m.request.caps & UROV_CAP_TASK_WORK);
    CHECK(m.request.caps & UROV_CAP_RESIDENT);
    CHECK(m.request.caps & UROV_CAP_READY);
    CHECK(m.request.state == UROV_INACTIVE);

    m = make_submit(UROV_QUERY); fail_in_at = copies_in + 1;
    CHECK(queue_request(&m, sizeof(m)) == -EFAULT && job_busy == 0 && queued == NULL);
    fail_in_at = 0; fail_out_at = copies_out + 1;
    CHECK(queue_request(&m, sizeof(m)) == -EFAULT && job_busy == 0 && queued == NULL);
    fail_out_at = 0; queue_error = -ESRCH;
    CHECK(queue_request(&m, sizeof(m)) == -ESRCH && job_busy == 0 && queued == NULL);
    queue_error = 0;
    attached = 0;
    CHECK(queue_request(&m, sizeof(m)) == -ESHUTDOWN);
    attached = 1; draining = 1;
    CHECK(queue_request(&m, sizeof(m)) == -ESHUTDOWN);
    draining = 0;
}
static void test_request_validation(void)
{
    struct urov_request q;
    unsigned int i;
    reset_backend();
#define BAD(change) do { q = make_request(UROV_QUERY); change; CHECK(request(&q) == -EINVAL); } while (0)
    BAD(q.size--); BAD(q.version++); BAD(q.reserved0 = 1);
    BAD(q.flags = 2); BAD(q.op = 0); BAD(q.op = UROV_DEACTIVATE + 1);
    for (i = 0; i < 3; ++i) BAD(q.reserved[i] = 1);
#undef BAD
    q = make_request(UROV_STATUS); CHECK(request(&q) == -ENOENT);
    q = make_request(UROV_DEACTIVATE); CHECK(request(&q) == 0 && q.state == UROV_INACTIVE);
    q = make_request(UROV_REGISTER); q.flags = UROV_F_RAW_XOM;
    CHECK(request(&q) == -EINVAL && pins == 0);
}
static void test_replay_and_generation(void)
{
    struct urov_request q, retry;
    reset_backend(); seed_session();
    q = make_request(UROV_REGISTER); q.flags = session.flags; q.request_id = session.registration;
    q.address = session.view.base; q.offset = session.view.overlay_offset; q.value = session.initial;
    retry = q;
    CHECK(request(&q) == 0 && q.session == 17 && q.generation == 1);
    q = retry; ++q.value; CHECK(request(&q) == -EBUSY);
    q = make_request(UROV_SET); q.session = 17; q.request_id = 2;
    q.expected_generation = 1; q.value = 0x1020304050607080ULL; retry = q;
    CHECK(request(&q) == 0 && q.generation == 2 && session.value == retry.value);
    q = retry; CHECK(request(&q) == 0 && q.generation == 2);
    q = retry; ++q.value; CHECK(request(&q) == -EINVAL && session.generation == 2);
    q = retry; ++q.request_id; CHECK(request(&q) == -EAGAIN && session.generation == 2);
    q = retry; q.request_id = 0; CHECK(request(&q) == -EINVAL);
    q = make_request(UROV_STATUS); q.request_id = session.registration;
    CHECK(request(&q) == 0 && q.session == 17 && q.value == retry.value);
    q = make_request(UROV_STATUS); q.session = 18; CHECK(request(&q) == -ESTALE);
    GET(fake_task, task_struct, mm) = (uintptr_t)other_mm;
    q = make_request(UROV_STATUS); q.session = 17; CHECK(request(&q) == -EPERM);
    GET(fake_task, task_struct, mm) = (uintptr_t)fake_mm;
    session.generation = UINT64_MAX;
    q = make_request(UROV_SET); q.session = 17; q.request_id = 5; q.expected_generation = UINT64_MAX;
    CHECK(request(&q) == -EOVERFLOW && session.value == retry.value);
    session.state = UROV_RETAINED;
    CHECK(request(&q) == -EBUSY);
}
static void test_response_copy_failure(void)
{
    struct urov_submit m;
    struct urov_request saved, status_q;
    reset_backend(); seed_session();
    m = make_submit(UROV_SET); m.request.session = 17; m.request.request_id = 2;
    m.request.expected_generation = 1; m.request.value = 0x123456789abcdef0ULL;
    saved = m.request;
    /* Simulate reusing a userspace buffer with an old success marker. */
    m.completed = UROV_COMPLETED;
    CHECK(queue_request(&m, sizeof(m)) == 0 && m.completed == 0);
    fail_out_at = copies_out + 1; partial_copy_error = 1;
    run_queued();
    CHECK(session.value == 0x123456789abcdef0ULL && session.generation == 2);
    /* A partial output is not a completed successful operation, even when
     * the backend committed. The caller recovers via STATUS/request_id. */
    CHECK(m.completed != UROV_COMPLETED);
    fail_out_at = 0;
    status_q = make_request(UROV_STATUS); status_q.session = 17;
    CHECK(request(&status_q) == 0 && status_q.generation == 2);
    CHECK(status_q.value == 0x123456789abcdef0ULL);
    m.request = saved;
    CHECK(queue_request(&m, sizeof(m)) == 0);
    run_queued();
    CHECK(m.completed == UROV_COMPLETED && !m.result);
    CHECK(m.request.generation == 2 && session.generation == 2);
}
static void test_drain_pending_work(void)
{
    struct urov_submit m;
    reset_backend();
    m = make_submit(UROV_QUERY);
    CHECK(queue_request(&m, sizeof(m)) == 0);
    CHECK(urov_resident_entry(UROV_R_DRAIN, NULL, 0) == -EBUSY);
    CHECK(attached == 0 && draining == 0 && job_busy == 1 && syncs == 1);
    CHECK(urov_resident_entry(UROV_R_INIT, &api, sizeof(api)) == -EBUSY);
    CHECK(attached == 0 && job_busy == 1);
    run_queued();
    CHECK(m.completed == UROV_COMPLETED && m.result == -ESHUTDOWN);
    CHECK(urov_resident_entry(UROV_R_DRAIN, NULL, 0) == 0);
    CHECK(urov_resident_entry(999, NULL, 0) == -EINVAL);
}
static void test_pte_identity_rejection(void)
{
    struct pte_change change = { .enable = 0 };
    uint64_t old;
    pte_t pte;
    reset_backend(); seed_session(); session.pfn = 0x12345;
    old = ((session.pfn + 1) << 12) | 3 | USER | RDONLY | PXN | (1UL << 10);
    pte.pte = old;
    CHECK(change_leaf(&pte, session.view.base, &change) == -ESTALE && pte.pte == old);
    change = (struct pte_change){ .enable = 1 };
    CHECK(change_leaf(&pte, session.view.base + PAGE, &change) == -EINVAL && pte.pte == old);
    change = (struct pte_change){ .enable = 1, .visited = 1 };
    CHECK(change_leaf(&pte, session.view.base, &change) == -EINVAL && pte.pte == old);
}
static void test_restoration_failure(void)
{
    struct urov_request q;
    reset_backend();
    seed_session();
    gate_mm = fake_mm;
    session.page = session.bytes;
    q = make_request(UROV_DEACTIVATE);
    q.session = session.id;
    CHECK(request(&q) == -ESTALE);
    CHECK(!mm_lock_depth && !tlbs && !mmputs);
    CHECK(session.state == UROV_RETAINED && session.active && session.error == -ESTALE);
    CHECK(gate_mm == fake_mm && session.mm == fake_mm && session.page == session.bytes);
    q = make_request(UROV_STATUS);
    q.session = session.id;
    CHECK(request(&q) == 0 && q.state == UROV_RETAINED && q.last_error == -ESTALE);
}
static void call_gate(hook_fargs0_t *f, unsigned int which, int denied, uint64_t result)
{
    CHECK(inflight == 0);
    gate_before(f, (void *)(uintptr_t)which);
    CHECK(inflight == 1 && !!f->skip_origin == denied);
    if (denied) CHECK(f->ret == result);
    gate_after(f, (void *)(uintptr_t)which);
    CHECK(inflight == 0);
}
/* Use the modeled do_madvise admission path for overlap/ordering tests. */
static void madvise_args(hook_fargs0_t *f, void *mm, unsigned long address)
{
    memset(f, 0, sizeof(*f));
    f->args[0] = (uintptr_t)mm; f->args[1] = address; f->args[2] = PAGE;
}
static void test_madvise_admission(void)
{
    hook_fargs0_t f;
    reset_backend(); seed_session(); gate_mm = fake_mm;
    madvise_args(&f, fake_mm, session.view.base | (0xabUL << 56));
    call_gate(&f, 3, 1, (uint64_t)-EBUSY);
    madvise_args(&f, other_mm, session.view.base);
    call_gate(&f, 3, 0, 0);
    madvise_args(&f, fake_mm, session.view.base + PAGE);
    call_gate(&f, 3, 0, 0);
}
static void test_fault_dispatch(void)
{
    struct pt_regs regs, before;
    uint32_t opcode = 0xf9400000U; /* LDR X0,[X0] */
    reset_backend(); seed_session();
    memcpy(session.bytes + 64, &opcode, 4);
    memset(&regs, 0, sizeof(regs)); regs.regs[0] = session.view.base + 4;
    regs.pc = session.view.base + 64; regs.sp = 0x1000000;
    CHECK(urov_resident_fault(session.view.base + 4, URO_READ_ESR, &regs) == 0);
    CHECK(regs.regs[0] == session.value && regs.pc == session.view.base + 68);
    CHECK(session.hits == 1 && session.failures == 0 && native_faults == 0 && rcu_depth == 0);
    regs.pstate = 5;
    CHECK(urov_resident_fault(session.view.base, URO_READ_ESR, &regs) == 123 && native_faults == 1);
    regs.pstate = 0;
    CHECK(urov_resident_fault(session.view.base + PAGE, URO_READ_ESR, &regs) == 123 && native_faults == 2);
    GET(fake_task, task_struct, mm) = (uintptr_t)other_mm;
    CHECK(urov_resident_fault(session.view.base + 4, URO_READ_ESR, &regs) == 123 && native_faults == 3);
    GET(fake_task, task_struct, mm) = (uintptr_t)fake_mm;
    opcode = 0xffffffffU; memcpy(session.bytes + 64, &opcode, 4);
    regs.pc = session.view.base + 64; regs.regs[0] = session.view.base + 4; before = regs;
    CHECK(urov_resident_fault(session.view.base + 4, URO_READ_ESR, &regs) == 1);
    CHECK(!memcmp(&before, &regs, sizeof(regs)) && session.failures == 1 && native_faults == 3);
}
static void *activation_worker(void *arg)
{
    struct urov_request *q = arg;
    long rc = activate(q);
    return (void *)(intptr_t)rc;
}
static void test_admission_interleavings(void)
{
    struct urov_request q;
    hook_fargs0_t f;
    pthread_t worker;
    pthread_barrier_t entered, release;
    void *result;
    reset_backend();
    q = make_request(UROV_REGISTER); q.request_id = 1; q.flags = UROV_F_RAW_XOM;
    q.address = 0x400000; q.offset = 4;
    madvise_args(&f, fake_mm, q.address);
    /* Mutation entered before pending publication: activation must not pin. */
    gate_before(&f, (void *)3); CHECK(inflight == 1 && !f.skip_origin);
    CHECK(activate(&q) == -EBUSY && pins == 0 && mmputs == 1 && gate_mm == NULL);
    gate_after(&f, (void *)3);
    CHECK(pthread_barrier_init(&entered, NULL, 2) == 0);
    CHECK(pthread_barrier_init(&release, NULL, 2) == 0);
    pin_entered = &entered; pin_release = &release;
    CHECK(pthread_create(&worker, NULL, activation_worker, &q) == 0);
    barrier(&entered);
    /* Mutation begins after pending publication, while registration pins. */
    CHECK(gate_mm == fake_mm && pins == 1);
    madvise_args(&f, fake_mm, q.address);
    call_gate(&f, 3, 1, (uint64_t)-EBUSY);
    barrier(&release);
    CHECK(pthread_join(worker, &result) == 0 && (intptr_t)result == -ECANCELED);
    CHECK(gate_mm == NULL && session.mm == NULL && mmputs == 2);
    pin_entered = pin_release = NULL;
    CHECK(pthread_barrier_destroy(&entered) == 0 && pthread_barrier_destroy(&release) == 0);
}

#define WORKERS 8
#define ROUNDS 128
static pthread_barrier_t producers;
static struct { struct urov_submit message; long result; } producer[WORKERS];
static void *queue_producer(void *arg)
{
    unsigned int i, id = (unsigned int)(uintptr_t)arg;
    for (i = 0; i < ROUNDS; ++i) {
        producer[id].message = make_submit(UROV_QUERY);
        barrier(&producers);
        producer[id].result = queue_request(&producer[id].message, sizeof(producer[id].message));
        barrier(&producers);
        barrier(&producers);
    }
    return NULL;
}
static void test_queue_contention(void)
{
    pthread_t threads[WORKERS];
    unsigned int i, round;
    reset_backend();
    CHECK(pthread_barrier_init(&producers, NULL, WORKERS + 1) == 0);
    for (i = 0; i < WORKERS; ++i) CHECK(pthread_create(&threads[i], NULL, queue_producer, (void *)(uintptr_t)i) == 0);
    for (round = 0; round < ROUNDS; ++round) {
        unsigned int winners = 0, winner = WORKERS;
        barrier(&producers); barrier(&producers);
        for (i = 0; i < WORKERS; ++i) {
            if (!producer[i].result) { ++winners; winner = i; }
            else CHECK(producer[i].result == -EBUSY);
        }
        CHECK(winners == 1 && winner < WORKERS);
        run_queued();
        CHECK(producer[winner].message.completed == UROV_COMPLETED && producer[winner].message.result == 0);
        barrier(&producers);
    }
    for (i = 0; i < WORKERS; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&producers) == 0);
}
int main(void)
{
    test_wire_and_queue(); test_request_validation(); test_replay_and_generation();
    test_response_copy_failure(); test_drain_pending_work(); test_pte_identity_rejection(); test_restoration_failure();
    test_madvise_admission(); test_fault_dispatch(); test_admission_interleavings(); test_queue_contention();
    printf("PASS resident_protocol_model assertions=%lu queue_rounds=%u contenders=%u "
           "scope=mocked_helpers_not_native_kernel\n", atomic_load(&assertions), ROUNDS, WORKERS);
    return 0;
}
