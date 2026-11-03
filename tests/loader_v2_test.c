/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#define UROV_MODULE_HOST_TEST
#include "../../../kernel/patch/module/module.c"

static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cv = PTHREAD_COND_INITIALIZER;
static int entered, released;
static atomic_int block_init, block_control, veto, init_error, exits, events, legacy_context;
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line=%d: %s\n",__LINE__,#x); abort(); } } while(0)
static void barrier(void)
{
    pthread_mutex_lock(&barrier_lock); entered=1; pthread_cond_broadcast(&barrier_cv);
    while(!released) pthread_cond_wait(&barrier_cv,&barrier_lock);
    pthread_mutex_unlock(&barrier_lock);
}
static void reset_barrier(void) { pthread_mutex_lock(&barrier_lock); entered=released=0; pthread_mutex_unlock(&barrier_lock); }
static void wait_entered(void) { pthread_mutex_lock(&barrier_lock); while(!entered)pthread_cond_wait(&barrier_cv,&barrier_lock); pthread_mutex_unlock(&barrier_lock); }
static void release_barrier(void) { pthread_mutex_lock(&barrier_lock); released=1;pthread_cond_broadcast(&barrier_cv);pthread_mutex_unlock(&barrier_lock); }
static long init_cb(const char *a,const char *e,void *r) { (void)a;(void)e;(void)r; if(atomic_load(&block_init))barrier(); return atomic_load(&init_error); }
static long exit_cb(void *r) { (void)r;atomic_fetch_add(&exits,1);return atomic_exchange(&veto,0)?-EBUSY:0; }
static long control_cb(const char *a,char *out,int len)
{
    if (rcu_depth != (unsigned int)atomic_load(&legacy_context)) return -EDEADLK;
    if(atomic_load(&block_control))barrier();
    if(strcmp(a,"first-private-argument"))return -EINVAL;
    if(out && len>=3) memcpy(out,"OK",3);
    return 0;
}
static long event_cb(const char *e,const char *a,void *r) { (void)e;(void)a;(void)r;atomic_fetch_add(&events,1);return 0; }

/* The fixture's sections contain real host function pointers. No relocation
 * stubs execute and no synthetic implementation of the loader is tested. */
static long load_fixture(const char *name)
{
    _Alignas(Elf64_Ehdr) unsigned char elf[2048]={0};
    Elf64_Ehdr *h=(void *)elf;
    Elf64_Shdr *s=(void *)(elf+sizeof(*h));
    const char names[]="\0.shstrtab\0.kpm.info\0.kpm.init\0.kpm.exit\0.kpm.ctl0\0.kpm.event\0.symtab\0.strtab\0";
    const char *section_names[]={"", ".shstrtab", ".kpm.info", ".kpm.init", ".kpm.exit", ".kpm.ctl0", ".kpm.event", ".symtab", ".strtab"};
    char info[128];
    size_t at=sizeof(*h)+9*sizeof(*s), offset=0;
    mod_initcall_t init=init_cb;mod_exitcall_t exit=exit_cb;mod_ctl0call_t ctl=control_cb;mod_eventcall_t event=event_cb;
    memcpy(h->e_ident,ELFMAG,SELFMAG);h->e_type=ET_REL;h->e_machine=EM_AARCH64;
    h->e_shoff=sizeof(*h);h->e_shentsize=sizeof(*s);h->e_shnum=9;h->e_shstrndx=1;
    for(unsigned i=1;i<9;++i) {
        for(offset=0;offset<sizeof(names);++offset) if(!strcmp(names+offset,section_names[i]))break;
        s[i].sh_name=offset;s[i].sh_addralign=8;s[i].sh_type=SHT_PROGBITS;
        if(i>=2&&i<=6)s[i].sh_flags=SHF_ALLOC;
    }
#define SECTION(i,p,n) do { at=(at+7)&~(size_t)7;s[i].sh_offset=at;s[i].sh_size=(n);memcpy(elf+at,(p),(n));at+=(n); }while(0)
    SECTION(1,names,sizeof(names));
    int n=snprintf(info,sizeof(info),"name=%s",name)+1;
    memcpy(info+n,"version=1\0",10);n+=10;SECTION(2,info,(size_t)n);
    if (!atomic_load(&legacy_context)) {
        const char context[] = "context=sleepable-v2";
        memcpy(info+n,context,sizeof(context));n+=sizeof(context);
        /* Rewrite the info section while it is still the final section. */
        at=s[2].sh_offset;SECTION(2,info,(size_t)n);
    }
    SECTION(3,&init,sizeof(init));SECTION(4,&exit,sizeof(exit));SECTION(5,&ctl,sizeof(ctl));SECTION(6,&event,sizeof(event));
    Elf64_Sym symbol={0};SECTION(7,&symbol,sizeof(symbol));s[7].sh_type=SHT_SYMTAB;s[7].sh_link=8;s[7].sh_entsize=sizeof(symbol);
    SECTION(8,"",1);s[8].sh_type=SHT_STRTAB;s[1].sh_type=SHT_STRTAB;
    return load_module(elf,(int)at,"","host-test",NULL);
}
static void *control_thread(void *unused) { (void)unused;return (void *)(intptr_t)module_control0("race","first-private-argument",NULL,0); }
static void *load_thread(void *unused) { (void)unused;return (void *)(intptr_t)load_fixture("loading"); }
int main(void)
{
    char info[1024], reply[16];pthread_t thread;void *result;
    module_init();CHECK(kpm_lifecycle_v2()==2);
    CHECK(load_module_path("fixture", "", NULL)==-ENOENT);
    test_file_present=1;test_file_length=0;
    CHECK(load_module_path("fixture", "", NULL)==-ENOEXEC);CHECK(test_file_closes==1);
    test_file_length=-EIO;
    CHECK(load_module_path("fixture", "", NULL)==-EIO);CHECK(test_file_closes==2);
    test_file_length=0x80000000LL;
    CHECK(load_module_path("fixture", "", NULL)==-ENOEXEC);CHECK(test_file_closes==3);
    test_file_present=0;
    atomic_store(&veto,1);CHECK(!load_fixture("veto"));CHECK(unload_module("veto",NULL)==-EBUSY);
    CHECK(get_module_nums()==1);CHECK(atomic_load(&executable_allocations)==1);
    CHECK(get_module_info("veto",info,sizeof(info))>0 && strstr(info,"state=retained"));
    CHECK(module_control0("veto","first-private-argument",reply,sizeof(reply))==-EBUSY);
    CHECK(load_fixture("veto")==-EEXIST);CHECK(atomic_load(&executable_allocations)==1);
    CHECK(!unload_module("veto",NULL));CHECK(!atomic_load(&executable_allocations));

    atomic_store(&init_error,-EINVAL);atomic_store(&veto,1);
    CHECK(load_fixture("rollback")==-EINVAL);CHECK(get_module_nums()==1);
    CHECK(get_module_info("rollback",info,sizeof(info))>0 && strstr(info,"init_errno=-22") && strstr(info,"cleanup_errno=-16"));
    CHECK(!unload_module("rollback",NULL));CHECK(!atomic_load(&executable_allocations));atomic_store(&init_error,0);

    CHECK(!load_fixture("race"));atomic_store(&block_control,1);reset_barrier();
    CHECK(!pthread_create(&thread,NULL,control_thread,NULL));wait_entered();
    CHECK(module_control0("race","different-private-argument",reply,sizeof(reply))==-EBUSY);
    CHECK(unload_module("race",NULL)==-EBUSY);
    CHECK(get_module_info("race",info,sizeof(info))>0 && strstr(info,"state=stopping"));
    CHECK(module_control0("race","first-private-argument",reply,sizeof(reply))==-EBUSY);
    release_barrier();CHECK(!pthread_join(thread,&result));CHECK((intptr_t)result==0);
    CHECK(!unload_module("race",NULL));CHECK(!atomic_load(&executable_allocations));atomic_store(&block_control,0);

    atomic_store(&block_init,1);reset_barrier();CHECK(!pthread_create(&thread,NULL,load_thread,NULL));wait_entered();
    CHECK(load_fixture("loading")==-EEXIST);CHECK(unload_module("loading",NULL)==-EBUSY);
    CHECK(get_module_info("loading",info,sizeof(info))>0 && strstr(info,"state=loading"));
    release_barrier();CHECK(!pthread_join(thread,&result));CHECK((intptr_t)result==0);atomic_store(&block_init,0);
    CHECK(notify_modules_event("event","",NULL)==1);CHECK(atomic_load(&events)==1);
    CHECK(!unload_module("loading",NULL));CHECK(get_module_nums()==0);
    CHECK(!atomic_load(&executable_allocations));
    atomic_store(&legacy_context,1);CHECK(!load_fixture("legacy"));
    CHECK(!module_control0("legacy","first-private-argument",reply,sizeof(reply)));
    CHECK(get_module_info("legacy",info,sizeof(info))>0 && strstr(info,"callback_context=legacy-rcu"));
    CHECK(!unload_module("legacy",NULL));CHECK(!atomic_load(&executable_allocations));
    printf("PASS loader_v2_checks=%u real_loader=1 retention=1 rollback=1 ctl_unload_race=1 duplicate_loading=1\n",checks);
    return 0;
}
