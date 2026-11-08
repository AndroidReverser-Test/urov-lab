#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/system/bin/linker64";
    long page = sysconf(_SC_PAGESIZE);
    setvbuf(stdout, NULL, _IONBF, 0);
    int fd = open(path, O_RDONLY);
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    errno = 0;
    int rc = mprotect(p, (size_t)page, PROT_READ | PROT_WRITE);
    printf("mprotect RW rc=%d errno=%d\n", rc, errno);
    ((volatile unsigned char *)p)[page - 1] = 0;
    printf("store ok\n");
    errno = 0;
    rc = mprotect(p, (size_t)page, PROT_READ | PROT_EXEC);
    printf("mprotect RX after store rc=%d errno=%d\n", rc, errno);
    return 0;
}
