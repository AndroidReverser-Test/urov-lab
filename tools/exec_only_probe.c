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

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/system/bin/linker64";
    long page = sysconf(_SC_PAGESIZE);
    setvbuf(stdout, NULL, _IONBF, 0);
    int fd = open(path, O_RDONLY);
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    struct sigaction sa = {0}, old;
    sa.sa_sigaction = segv; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old);
    printf("mprotect X rc=%d\n", mprotect(p, (size_t)page, PROT_EXEC));
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    while (f && fgets(line, sizeof(line), f)) {
        unsigned long a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 && (unsigned long)p >= a && (unsigned long)p < b) {
            printf("maps: %s", line);
            break;
        }
    }
    if (f) fclose(f);
    int faulted = 0;
    if (!sigsetjmp(jb, 1)) {
        volatile unsigned char v = *(volatile unsigned char *)p;
        printf("read succeeded v=%02x\n", v);
    } else faulted = 1;
    printf("read faulted=%d\n", faulted);
    sigaction(SIGSEGV, &old, NULL);
    return 0;
}
