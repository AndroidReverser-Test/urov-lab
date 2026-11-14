/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <urov/urov.h>
#include "../test_config.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line=%d: %s errno=%d\n", __LINE__, #x, errno); exit(1); } } while (0)
static uint64_t load(const void *p)
{
    uint64_t value;
    __asm__ volatile("ldr %0, [%1]" : "=r"(value) : "r"(p) : "memory");
    return value;
}
static void *thread_read(void *page)
{
    CHECK(load((char *)page + 128) == UINT64_C(0x6262626262626262));
    return NULL;
}
int main(int argc, char **argv)
{
    struct urov_client client;
    struct urov_info info;
    struct urov_status status;
    struct urov_page desc[3];
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    int budget = argc == 2 && !strcmp(argv[1], "--budget");
    int nofork = argc == 2 && !strcmp(argv[1], "--nofork");
    int hold = argc == 2 && !strcmp(argv[1], "--hold");
    int fd, ret;
    unsigned char *image, *page;
    CHECK(argc == 1 || budget || nofork || hold);
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(30);
    CHECK(ps == 4096 || ps == 16384);
    CHECK(!urov_client_init(&client, UROV_TEST_KEY));
    CHECK(!urov_query(&client, &info) && info.state == UROV_Z_INACTIVE);
    fd = (int)syscall(__NR_memfd_create, "urov-resource-test", 1U);
    CHECK(fd >= 0 && !ftruncate(fd, (off_t)(3 * ps)));
    image = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(image != MAP_FAILED);
    memset(image, 0x21, 3 * ps);
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t code[] = {0x52800220U, 0xd65f03c0U}; /* mov w0, #17; ret */
        memcpy(image + i * ps, code, sizeof(code));
    }
    CHECK(pwrite(fd, image, 3 * ps, 0) == (ssize_t)(3 * ps));
    page = mmap(NULL, 3 * ps, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    CHECK(page != MAP_FAILED);
    memset(image, 0x62, 3 * ps);
    for (unsigned i = 0; i < 3; ++i)
        desc[i] = (struct urov_page){page + i * ps, image + i * ps, 0, 0};
    ret = urov_register_pages(&client, desc, 3, &status);
    if (budget) {
        CHECK(ret == -ENOMEM);
        CHECK(!urov_query(&client, &info) && info.state == UROV_Z_INACTIVE);
        CHECK(load(page + 128) == UINT64_C(0x2121212121212121));
        puts("PASS budget rejection: registration rolled back, native view preserved");
    } else {
        CHECK(!ret);
        CHECK(load(page + 128) == UINT64_C(0x6262626262626262));
        CHECK(((int (*)(void))(void *)page)() == 17);
        if (nofork) {
            pthread_t t;
            pid_t pid;
            CHECK(!pthread_create(&t, NULL, thread_read, page));
            CHECK(!pthread_join(t, NULL));
            errno = 0;
            pid = fork();
            if (!pid) _exit(0);
            if (pid > 0) { int result; waitpid(pid, &result, 0); }
            CHECK(pid == -1 && errno == EOPNOTSUPP);
            puts("PASS fork_copies=0: thread reads work, independent fork rejected");
        }
        if (hold) { puts("READY resource session: 3 pages"); sleep(5); }
        CHECK(!urov_deactivate(&client));
        CHECK(load(page + 128) == UINT64_C(0x2121212121212121));
        puts("PASS resource session: overlay and execution, complete release");
    }
    CHECK(!munmap(page, 3 * ps) && !munmap(image, 3 * ps));
    close(fd);
    return 0;
}
