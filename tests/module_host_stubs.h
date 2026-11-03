/* Host substitutes for allocation/I/O/locks only. Tests include the actual
 * kernel/patch/module/module.c including its real ELF load and rollback paths. */
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define __user
#define unlikely(x) (x)
static _Thread_local unsigned int rcu_depth;
static inline void rcu_read_lock(void) { ++rcu_depth; }
static inline void rcu_read_unlock(void) { assert(rcu_depth); --rcu_depth; }
#define _KP_KPMODULE_H_
#define _KP_RELO_H_
#define KPM_ARGS_LEN 1024
#define KPM_LOAD_ERROR_MESSAGE_LEN 192
#define KPM_LOAD_RESULT_MAGIC 0x12345678U
typedef long (*mod_initcall_t)(const char *, const char *, void *);
typedef long (*mod_ctl0call_t)(const char *, char *, int);
typedef long (*mod_ctl1call_t)(void *, void *, void *);
typedef long (*mod_exitcall_t)(void *);
typedef long (*mod_eventcall_t)(const char *, const char *, void *);
struct kpm_load_result { unsigned int magic, size; long code; char message[192]; };
struct list_head { struct list_head *next, *prev; };
#define INIT_LIST_HEAD(h) ((h)->next = (h)->prev = (h))
#define list_for_each_entry(p,h,m) \
    for (struct list_head *node_ = (h)->next; node_ != (h) && ((p) = (void *)((char *)node_ - offsetof(__typeof__(*(p)),m)), 1); node_ = node_->next)
#define list_add_tail(n,h) do { (n)->prev=(h)->prev; (n)->next=(h); (h)->prev->next=(n); (h)->prev=(n); } while (0)
#define list_del(n) do { (n)->prev->next=(n)->next; (n)->next->prev=(n)->prev; } while (0)
#include <stddef.h>
typedef pthread_mutex_t spinlock_t;
#define spin_lock_init(p) assert(!pthread_mutex_init(p,NULL))
#define spin_lock(p) assert(!pthread_mutex_lock(p))
#define spin_unlock(p) assert(!pthread_mutex_unlock(p))
#define KP_EXPORT_SYMBOL(x)
#define logki(...) ((void)0)
#define logkd(...) ((void)0)
#define logke(...) ((void)0)
#define logkfi(...) ((void)0)
#define logkfd(...) ((void)0)
#define logkfe(...) ((void)0)
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define PTR_ERR(p) ((long)(p))
static unsigned long page_size = 4096;
static atomic_int executable_allocations;
static inline void *vmalloc(size_t n) { return malloc(n); }
static inline void kvfree(void *p) { free(p); }
static inline void *kp_malloc_exec(size_t n) {
    void *p=malloc(n); if(p) atomic_fetch_add(&executable_allocations,1); return p;
}
static inline void kp_free_exec(void *p) {
    if(p) atomic_fetch_sub(&executable_allocations,1);
    free(p);
}
static inline void flush_icache_all(void) { }
static inline unsigned long symbol_lookup_name(const char *name) { (void)name; return 0; }
static inline void *memdup_user(const void *p, size_t n) { void *q=malloc(n); if(q) memcpy(q,p,n); return q; }
static inline int compat_copy_to_user(void *dest,const void *src,size_t n) { memcpy(dest,src,n); return (int)n; }
struct file { int unused; };
static struct file test_file;
static int test_file_present, test_file_closes;
static loff_t test_file_length;
static inline struct file *filp_open(const char *p,int flags,int mode) { (void)p;(void)flags;(void)mode;return test_file_present ? &test_file : (void *)-ENOENT; }
static inline loff_t vfs_llseek(struct file *f,loff_t o,int w) { (void)f;(void)o;return w == SEEK_END ? test_file_length : 0; }
static inline long kernel_read(struct file *f,void *p,size_t n,loff_t *o) { (void)f;(void)p;(void)n;(void)o;return -EINVAL; }
static inline void filp_close(struct file *f,void *unused) { (void)f;(void)unused;++test_file_closes; }
struct module;
static inline int apply_relocate(Elf64_Shdr *s,const char *t,unsigned int i,unsigned int r,struct module *m) { (void)s;(void)t;(void)i;(void)r;(void)m;return -ENOEXEC; }
#define apply_relocate_add apply_relocate
