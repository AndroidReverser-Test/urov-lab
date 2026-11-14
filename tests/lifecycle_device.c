/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urov/urov.h>
#include "../test_config.h"

/* Run with writes=rx. Each session owns a private memfd RX mapping; all
 * mapping destinations stay inside its reserved address range. */
static struct urov_client client;
static struct urov_status status;
static size_t ps;
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "FAIL line=%d: %s errno=%d\n", __LINE__, #x, errno); exit(1); \
} } while (0)

struct fixture { unsigned char *reserve, *page[3], *image; int fd; };
static uint64_t word(unsigned byte) { return UINT64_C(0x0101010101010101) * byte; }
static uint64_t load_word(const void *p)
{
    uint64_t x;
    __asm__ volatile("ldr %0, [%1]" : "=r"(x) : "r"(p) : "memory");
    return x;
}
static int execute(void *p) { return ((int (*)(void))p)(); }
static int three_views(void *p, uint64_t expected, int result)
{
    uint64_t via_vm = 0, via_proc = 0;
    struct iovec local = {&via_vm, 8}, remote = {(char *)p + 128, 8};
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    int ok = fd >= 0 && load_word((char *)p + 128) == expected &&
        process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == 8 && via_vm == expected &&
        pread(fd, &via_proc, 8, (off_t)(uintptr_t)remote.iov_base) == 8 && via_proc == expected &&
        execute(p) == result;
    if (fd >= 0) close(fd);
    return ok;
}
static void create(struct fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->fd = (int)syscall(__NR_memfd_create, "urov-compat-rx", 1U);
    CHECK(f->fd >= 0 && !ftruncate(f->fd, (off_t)(3 * ps)));
    f->image = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(f->image != MAP_FAILED);
    for (unsigned i = 0; i < 3; ++i) {
        memset(f->image + i * ps, 0x21 + i, ps);
        uint32_t code[] = {0x52800000U | ((17U + i) << 5), 0xd65f03c0U};
        memcpy(f->image + i * ps, code, sizeof(code));
    }
    CHECK(pwrite(f->fd, f->image, 3 * ps, 0) == (ssize_t)(3 * ps));
    f->reserve = mmap(NULL, 8 * ps, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(f->reserve != MAP_FAILED);
    CHECK(mmap(f->reserve + 3 * ps, 3 * ps, PROT_READ | PROT_EXEC,
               MAP_PRIVATE | MAP_FIXED, f->fd, 0) == f->reserve + 3 * ps);
    struct urov_page desc[3];
    for (unsigned i = 0; i < 3; ++i) {
        f->page[i] = f->reserve + (3 + i) * ps;
        CHECK(three_views(f->page[i], word(0x21 + i), 17 + (int)i));
        memset(f->image + i * ps, 0x61 + i, ps);
        desc[i] = (struct urov_page){f->page[i], f->image + i * ps, 0, 0};
    }
    CHECK(!urov_register_pages(&client, desc, 3, &status));
    for (unsigned i = 0; i < 3; ++i)
        CHECK(three_views(f->page[i], word(0x61 + i), 17 + (int)i));
}
static void destroy(struct fixture *f)
{
    CHECK(!urov_get_status(&client, &status) && status.failures == 0);
    CHECK(!urov_deactivate(&client));
    CHECK(!munmap(f->reserve, 8 * ps));
    CHECK(!munmap(f->image, 3 * ps));
    close(f->fd);
}
static int set_page_retry(unsigned char *image)
{
    int rc = -EBUSY;
    /* Thread startup/exit may mprotect or madvise its stack in the same mm.
     * The public API deliberately exposes transaction contention. Only
     * retry EBUSY, which guarantees SET has not committed. */
    for (unsigned attempt = 0; attempt < 2000 && rc == -EBUSY; ++attempt) {
        rc = urov_set_page(&client, 0, status.generation, 0, image, (uint32_t)ps, &status);
        if (rc == -EBUSY) usleep(1000);
    }
    if (rc) fprintf(stderr, "SET returned %d\n", rc);
    return rc;
}
static void exchange(int tx, int rx, char command)
{
    char answer = 0;
    CHECK(write(tx, &command, 1) == 1 && read(rx, &answer, 1) == 1 && answer == command);
}
static sigjmp_buf fault_return;
static volatile sig_atomic_t fault_expected;
static void fault_handler(int sig)
{
    if (!fault_expected) _exit(100 + sig);
    siglongjmp(fault_return, 1);
}
static void child_run(struct fixture *f, int rx, int tx)
{
    char command;
    alarm(30);
    while (read(rx, &command, 1) == 1) {
        CHECK(three_views(f->page[0], word(0x61), 17));
        if (command == 'c') {
            struct sigaction action = {.sa_handler = fault_handler};
            sigemptyset(&action.sa_mask);
            CHECK(!sigaction(SIGSEGV, &action, NULL));
            CHECK(!mprotect(f->page[0], ps, PROT_NONE));
            fault_expected = 1;
            if (!sigsetjmp(fault_return, 1)) {
                (void)load_word(f->page[0] + 128);
                CHECK(0); /* no overlay may bypass PROT_NONE */
            }
            fault_expected = 0;
            CHECK(!mprotect(f->page[0], ps, PROT_READ | PROT_EXEC));
            CHECK(three_views(f->page[0], word(0x61), 17));
            CHECK(!madvise(f->page[0], ps, MADV_DONTNEED));
            CHECK(three_views(f->page[0], word(0x61), 17));
            void *to = f->reserve + ps;
            CHECK(mremap(f->page[0], ps, ps, MREMAP_MAYMOVE | MREMAP_FIXED, to) == to);
            f->page[0] = to;
            CHECK(three_views(to, word(0x61), 17));
            errno = 0;
            CHECK(mremap(to, ps, ps, MREMAP_MAYMOVE | MREMAP_FIXED | 4U,
                          f->reserve + 6 * ps) == MAP_FAILED && errno == EOPNOTSUPP);
            CHECK(three_views(to, word(0x61), 17));
            CHECK(mmap(to, ps, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
                       f->fd, (off_t)(2 * ps)) == to);
            CHECK(three_views(to, word(0x23), 19));
        }
        CHECK(write(tx, &command, 1) == 1);
        if (command == 'c') _exit(0);
    }
    _exit(9);
}
static void fork_lifecycle(void)
{
    struct fixture f;
    int to_child[2], to_parent[2], result;
    create(&f);
    CHECK(!pipe(to_child) && !pipe(to_parent));
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        close(to_child[1]); close(to_parent[0]);
        child_run(&f, to_child[0], to_parent[1]);
    }
    close(to_child[0]); close(to_parent[1]);
    CHECK(urov_deactivate(&client) == -EBUSY);
    CHECK(!mprotect(f.page[0], ps, PROT_NONE));
    exchange(to_child[1], to_parent[0], 'a');
    CHECK(!mprotect(f.page[0], ps, PROT_READ | PROT_EXEC));
    memset(f.image, 0x72, ps);
    CHECK(!urov_set_page(&client, 0, status.generation, 0, f.image, (uint32_t)ps, &status));
    CHECK(three_views(f.page[0], word(0x72), 17));
    exchange(to_child[1], to_parent[0], 'b');
    CHECK(!munmap(f.page[0], ps));
    exchange(to_child[1], to_parent[0], 'c');
    CHECK(waitpid(pid, &result, 0) == pid && WIFEXITED(result) && !WEXITSTATUS(result));
    CHECK(three_views(f.page[1], word(0x62), 18));
    close(to_child[1]); close(to_parent[0]);
    destroy(&f);
    puts("PASS fork: parent PROT_NONE/SET/unmap, independent child protection/refault/move/replacement");
}

struct reader_state { void *page; unsigned stop, failed, reads, alternate; };
static int uniform(const unsigned char *bytes, size_t len, unsigned a, unsigned b)
{
    if (bytes[0] != a && bytes[0] != b) return 0;
    for (size_t i = 1; i < len; ++i) if (bytes[i] != bytes[0]) return 0;
    return 1;
}
static void *reader(void *opaque)
{
    struct reader_state *r = opaque;
    unsigned a = r->alternate ? 0x61 : 0x62, b = r->alternate ? 0x72 : 0x62;
    unsigned char bytes[256];
    struct iovec local = {bytes, sizeof(bytes)}, remote = {(char *)r->page + 128, sizeof(bytes)};
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    do {
        uint64_t x = load_word(remote.iov_base);
        if (fd < 0 || (x != word(a) && x != word(b)) ||
            process_vm_readv(getpid(), &local, 1, &remote, 1, 0) != (ssize_t)sizeof(bytes) ||
            !uniform(bytes, sizeof(bytes), a, b) ||
            pread(fd, bytes, sizeof(bytes), (off_t)(uintptr_t)remote.iov_base) != (ssize_t)sizeof(bytes) ||
            !uniform(bytes, sizeof(bytes), a, b)) {
            __atomic_store_n(&r->failed, 1, __ATOMIC_RELEASE);
            break;
        }
        __atomic_add_fetch(&r->reads, 1U, __ATOMIC_RELAXED);
    } while (!__atomic_load_n(&r->stop, __ATOMIC_ACQUIRE));
    if (fd >= 0) close(fd);
    return NULL;
}
static void concurrent_changes(int moves)
{
    struct fixture f;
    struct reader_state r;
    pthread_t threads[4];
    create(&f);
    r = (struct reader_state){.page = f.page[moves ? 1 : 0], .alternate = !moves};
    for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_create(&threads[i], NULL, reader, &r));
    for (unsigned i = 0; i < 100; ++i) {
        if (moves) {
            void *to = f.reserve + (i & 1 ? 6 : 1) * ps;
            CHECK(mremap(f.page[0], ps, ps, MREMAP_MAYMOVE | MREMAP_FIXED, to) == to);
            f.page[0] = to;
        }
        memset(f.image, i & 1 ? 0x61 : 0x72, ps);
        CHECK(!set_page_retry(f.image));
        CHECK(three_views(f.page[0], word(i & 1 ? 0x61 : 0x72), 17));
    }
    __atomic_store_n(&r.stop, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 4; ++i) CHECK(!pthread_join(threads[i], NULL));
    CHECK(!r.failed && r.reads);
    destroy(&f);
    printf("PASS %s: 100 SETs, 4 readers, %u three-channel checks\n",
           moves ? "partial mremap and stable slots" : "atomic image publication", r.reads);
}
static void rx_retirement(void)
{
    struct fixture f;
    create(&f);
    CHECK(!mprotect(f.page[0], ps, PROT_READ | PROT_WRITE | PROT_EXEC));
    CHECK(three_views(f.page[0], word(0x21), 17));
    *(volatile uint64_t *)(void *)(f.page[0] + 128) = word(0x44);
    CHECK(!mprotect(f.page[0], ps, PROT_READ | PROT_EXEC));
    CHECK(three_views(f.page[0], word(0x44), 17));
    CHECK(urov_set_page(&client, 0, status.generation, 0, f.image, (uint32_t)ps, &status) == -ESTALE);
    uint64_t changed = word(0x55);
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0 && pwrite(fd, &changed, 8, (off_t)(uintptr_t)(f.page[1] + 128)) == 8);
    close(fd);
    CHECK(three_views(f.page[1], changed, 18));
    CHECK(three_views(f.page[2], word(0x63), 19));
    destroy(&f);
    puts("PASS RX retirement: mprotect and kernel write restore native reads; SET rejects stale pages");
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(180);
    ps = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(ps == 4096 || ps == 16384);
    CHECK(!urov_client_init(&client, UROV_TEST_KEY));
    struct urov_info info;
    CHECK(!urov_query(&client, &info) && info.state == UROV_Z_INACTIVE);
    fork_lifecycle();
    concurrent_changes(1);
    concurrent_changes(0);
    rx_retirement();
    printf("PASS lifecycle: %u parent assertions, runtime page size %zu\n", checks, ps);
    return 0;
}
