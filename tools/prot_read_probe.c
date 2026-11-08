#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static sigjmp_buf jb;
static void segv(int s, siginfo_t *i, void *c) { (void)s; (void)i; (void)c; siglongjmp(jb, 1); }

static void probe(const char *name, int prot)
{
    long page = sysconf(_SC_PAGESIZE);
    int fd = open("/system/bin/linker64", O_RDONLY);
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    struct sigaction sa = {0}, old;
    sa.sa_sigaction = segv; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old);
    errno = 0;
    int rc = mprotect(p, (size_t)page, prot);
    char sm[64] = "";
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (f && fgets(line, sizeof(line), f)) {
        unsigned long a, b;
        if (sscanf(line, "%lx-%lx %63s", &a, &b, sm) == 3 && (unsigned long)p >= a && (unsigned long)p < b)
            break;
    }
    if (f) fclose(f);
    int faulted = 0;
    unsigned char v = 0;
    if (!sigsetjmp(jb, 1)) v = *(volatile unsigned char *)p;
    else faulted = 1;
    printf("%-12s prot=%x rc=%d errno=%d perms=%s read_faulted=%d v=%02x\n",
           name, prot, rc, errno, sm, faulted, v);
    sigaction(SIGSEGV, &old, NULL);
    munmap(p, (size_t)page);
    close(fd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    probe("none", PROT_NONE);
    probe("write", PROT_WRITE);
    probe("exec", PROT_EXEC);
    probe("w+x", PROT_WRITE | PROT_EXEC);
    probe("read", PROT_READ);
    return 0;
}
