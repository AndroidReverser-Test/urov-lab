/* Host-side probe: does mprotect(RW) on a private file mapping keep the PTE
 * read-only (COW) or make it writable (page-cache write)?  Run on device. */
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
    unsigned char before[64], after[64];
    if (fd < 0) { perror("open"); return 1; }
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    if (pread(fd, before, sizeof(before), 0) != (ssize_t)sizeof(before)) { perror("pread1"); return 1; }
    errno = 0;
    int rc = mprotect(p, (size_t)page, PROT_READ | PROT_WRITE);
    printf("mprotect(RW) rc=%d errno=%d\n", rc, errno);
    unsigned char *q = p;
    unsigned char old = q[0];
    q[0] = (unsigned char)(old ^ 0xa5);
    int werr = errno;
    if (pread(fd, after, sizeof(after), 0) != (ssize_t)sizeof(after)) { perror("pread2"); return 1; }
    printf("write ok errno=%d old=%02x new=%02x file_before=%02x file_after=%02x cow=%d\n",
           werr, old, q[0], before[0], after[0], !memcmp(before, after, sizeof(before)));
    mprotect(p, (size_t)page, PROT_READ);
    errno = 0;
    q[0] = old;
    printf("write_on_R errno=%d\n", errno);
    mprotect(p, (size_t)page, PROT_NONE);
    errno = 0;
    volatile unsigned char x = q[0];
    printf("read_on_NONE x=%02x errno=%d\n", x, errno);
    return 0;
}
