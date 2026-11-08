/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * urov-y 2.17.0 residual-feature fixtures.
 *
 *   v217-store   an undecodable store (ST1 single lane) is executed by the
 *                hardware under software step and its bytes are published into
 *                the image; the overlay stays armed.
 *   v217-atomic  concurrent LSE RMW instructions on one registered page do not
 *                lose updates.
 *   v217-fork    a forked child keeps the fork-time image across an owner SET,
 *                its own mremap/mprotect and its own store.
 *   v217-gup     a fast-GUP FOLL_WRITE writer reaches the live page instead of
 *                being intercepted by the replacement page.
 *   v217-remap   a rejected shared remap_file_pages does not end the session.
 *   v217-crc     a production-style CRC of the patched .text page reads the
 *                file bytes through every reader path.
 */

static void *v217_anon_page(size_t page_size)
{
    void *p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static int v217_arm(const struct uy_ctx *ctx, const void *page, const void *image,
                    uint32_t length, uint64_t *generation)
{
    struct urov_y_request q = uy_req(UROV_Y_REGISTER);
    int rc;

    q.address = (uintptr_t)page;
    q.fake_addr = (uintptr_t)image;
    q.length = length;
    q.mode = UROV_Y_MODE_PAGE_AP;
    rc = (int)uy_control(ctx, UROV_Y_REGISTER, &q);
    if (!rc) *generation = q.generation;
    return rc ? errno : 0;
}

static int v217_set_image(const struct uy_ctx *ctx, uint64_t generation,
                          const void *image, uint32_t length)
{
    struct urov_y_request q = uy_req(UROV_Y_SET);
    q.session = 1;
    q.expected_generation = generation;
    q.fake_addr = (uintptr_t)image;
    q.length = length;
    return (int)uy_control(ctx, UROV_Y_SET, &q) ? errno : 0;
}

static int v217_pipe_read(const void *source, uint8_t *out, size_t n)
{
    struct iovec iov = { .iov_base = (void *)source, .iov_len = n };
    int fds[2];
    ssize_t got;
    int error;

    if (pipe2(fds, O_CLOEXEC)) return errno;
    got = vmsplice(fds[1], &iov, 1, 0);
    if (got == (ssize_t)n) got = read(fds[0], out, n);
    error = got == (ssize_t)n ? 0 : (got < 0 ? errno : EIO);
    close(fds[1]);
    close(fds[0]);
    return error;
}

/* /proc/self/mem is readable only while the app's SELinux domain allows it;
 * EACCES is reported separately so the fixture can skip that reader path. */
static int v217_mem_read(const void *source, uint8_t *out, size_t n)
{
    int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    ssize_t got;

    if (fd < 0) return errno;
    got = pread(fd, out, n, (off_t)(uintptr_t)source);
    close(fd);
    return got == (ssize_t)n ? 0 : (got < 0 ? errno : EIO);
}

static int v217_readv_read(const void *source, uint8_t *out, size_t n)
{
    struct iovec l = { .iov_base = out, .iov_len = n };
    struct iovec r = { .iov_base = (void *)source, .iov_len = n };

    return syscall(__NR_process_vm_readv, getpid(), &l, 1UL, &r, 1UL, 0UL) == (ssize_t)n
               ? 0 : EIO;
}

/* ST1 single-lane is not in the 2.16 store decoder. */
static void v217_lane_store(uint8_t *address)
{
    __asm__ volatile("movi v0.16b, #0x5a\n"
                     "st1 {v0.b}[3], [%0]\n"
                     :: "r"(address) : "v0", "memory");
}

struct v217_add {
    uint8_t *address;
    unsigned count;
};

static void *v217_add_thread(void *arg)
{
    struct v217_add *w = arg;
    unsigned i;

    for (i = 0; i < w->count; ++i)
        __asm__ volatile("mov x1, #1\n\tldadd x1, x2, [%0]"
                         :: "r"(w->address) : "x1", "x2", "memory");
    return NULL;
}

static int v217_skip_error(int error)
{
    return error == EACCES || error == EPERM || error == ENOENT;
}

static void v217_store(const struct uy_ctx *ctx, const struct page *reference,
                       size_t page_size)
{
    uint8_t *image = v217_anon_page(page_size);
    uint8_t *file_page = v217_anon_page(page_size);
    uint8_t view[64], buf[64];
    struct urov_y_request st;
    uint64_t generation = 0;
    int error = 0, mem_error, pipe_error, iov_error;

    ++g_cases;
    if (!image || !file_page ||
        app_pread(reference->fd, reference->file_offset, file_page, page_size)) {
        REQUIRE(0, "v217 store fixture setup errno=%d", errno);
        goto out;
    }
    memcpy(image, file_page, page_size);
    image[0] ^= 0xff;
    error = v217_arm(ctx, reference->address, image, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 store register errno=%d", error);
    if (error) goto out;
    copy_scalar(view, reference->address, sizeof(view));
    REQUIRE(!memcmp(view, image, sizeof(view)), "v217 store clean view");
    REQUIRE(!mprotect(reference->address, page_size, PROT_READ | PROT_WRITE),
            "v217 store mprotect(RW) errno=%d", errno);
    v217_lane_store(reference->address + 8);
    image[8] = 0x5a;
    copy_scalar(view, reference->address, sizeof(view));
    REQUIRE(!memcmp(view, image, sizeof(view)), "v217 store replay view=%02x want=%02x",
            view[8], image[8]);
    pipe_error = v217_pipe_read(reference->address, buf, sizeof(buf));
    REQUIRE(!pipe_error && !memcmp(buf, image, sizeof(buf)),
            "v217 store pipe view errno=%d", pipe_error);
    mem_error = v217_mem_read(reference->address, buf, sizeof(buf));
    if (v217_skip_error(mem_error))
        LOG("V217_STORE mem skipped errno=%d", mem_error);
    else
        REQUIRE(!mem_error && !memcmp(buf, image, sizeof(buf)),
                "v217 store /proc/self/mem view errno=%d", mem_error);
    iov_error = v217_readv_read(reference->address, buf, sizeof(buf));
    REQUIRE(!iov_error && !memcmp(buf, image, sizeof(buf)),
            "v217 store process_vm_readv view errno=%d", iov_error);
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE && !st.failures,
            "v217 store state=%u failures=%llu", st.state,
            (unsigned long long)st.failures);
    LOG("V217_STORE view=%02x image=%02x pipe=%d mem=%d iov=%d active=%u armed=%llu",
        view[8], image[8], pipe_error, mem_error, iov_error, st.state,
        (unsigned long long)st.reserved);
    REQUIRE(!uy_deactivate(ctx), "v217 store deactivate errno=%d", errno);
    copy_scalar(view, reference->address, sizeof(view));
    REQUIRE(view[0] == file_page[0] && view[8] == 0x5a,
            "v217 store deactivated view=%02x/%02x", view[0], view[8]);
out:
    if (image) munmap(image, page_size);
    if (file_page) munmap(file_page, page_size);
}

static void v217_atomic(const struct uy_ctx *ctx, const struct page *reference,
                        size_t page_size, int repeats)
{
    enum { THREADS = 4 };
    pthread_t th[THREADS];
    struct v217_add work;
    struct urov_y_request st;
    uint8_t *image = v217_anon_page(page_size);
    uint8_t view[8];
    uint64_t generation = 0, value = 0, initial = 0, want = 0;
    int error = 0, i, registered = 0, ran = 0;

    ++g_cases;
    if (!image || app_pread(reference->fd, reference->file_offset, image, page_size)) {
        REQUIRE(0, "v217 atomic fixture setup errno=%d", errno);
        goto out;
    }
    memcpy(&initial, image + 64, sizeof(initial));
    error = v217_arm(ctx, reference->address, image, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 atomic register errno=%d", error);
    if (error) goto out;
    registered = 1;
    if (mprotect(reference->address, page_size, PROT_READ | PROT_WRITE)) {
        REQUIRE(0, "v217 atomic mprotect(RW) errno=%d", errno);
        goto deactivate;
    }
    work.address = reference->address + 64;
    work.count = (unsigned)repeats;
    for (i = 0; i < THREADS; ++i) pthread_create(&th[i], NULL, v217_add_thread, &work);
    for (i = 0; i < THREADS; ++i) pthread_join(th[i], NULL);
    ran = 1;
    want = initial + (uint64_t)THREADS * (uint64_t)repeats;
    copy_scalar(view, reference->address + 64, sizeof(view));
    memcpy(&value, view, sizeof(value));
    REQUIRE(value == want, "v217 atomic value=%llu want=%llu",
            (unsigned long long)value, (unsigned long long)want);
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE && !st.failures,
            "v217 atomic state=%u failures=%llu", st.state,
            (unsigned long long)st.failures);
    LOG("V217_ATOMIC initial=%llu value=%llu want=%llu failures=%llu active=%u",
        (unsigned long long)initial, (unsigned long long)value,
        (unsigned long long)want, (unsigned long long)st.failures, st.state);
deactivate:
    if (!registered) goto out;
    REQUIRE(!uy_deactivate(ctx), "v217 atomic deactivate errno=%d", errno);
    if (ran) {
        copy_scalar(view, reference->address + 64, sizeof(view));
        memcpy(&value, view, sizeof(value));
        REQUIRE(value == want, "v217 atomic live value=%llu want=%llu",
                (unsigned long long)value, (unsigned long long)want);
    }
out:
    if (image) munmap(image, page_size);
}

static void v217_fork(const struct uy_ctx *ctx, const struct page *reference,
                      size_t page_size)
{
    uint8_t *image = v217_anon_page(page_size);
    uint8_t *newer = v217_anon_page(page_size);
    uint8_t *file_page = v217_anon_page(page_size);
    uint8_t view[64];
    struct urov_y_request st;
    uint64_t generation = 0;
    int fd[2], error = 0, status = 0;
    pid_t pid;

    ++g_cases;
    if (!image || !newer || !file_page ||
        app_pread(reference->fd, reference->file_offset, file_page, page_size)) {
        REQUIRE(0, "v217 fork fixture setup errno=%d", errno);
        goto out;
    }
    memcpy(image, file_page, page_size);
    memcpy(newer, file_page, page_size);
    image[0] = 0xaa;
    newer[0] = 0xbb;
    error = v217_arm(ctx, reference->address, image, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 fork register errno=%d", error);
    if (error) goto out;
    if (pipe(fd)) {
        REQUIRE(0, "v217 fork pipe errno=%d", errno);
        goto deactivate;
    }
    pid = fork();
    if (pid == 0) {
        uint8_t child[64];
        uint8_t *moved;
        char byte;
        int fail = 0;

        close(fd[1]);
        copy_scalar(child, reference->address, sizeof(child));
        if (child[0] != 0xaa) fail |= 1;
        if (read(fd[0], &byte, 1) != 1) fail |= 2;
        copy_scalar(child, reference->address, sizeof(child));
        if (child[0] != 0xaa) fail |= 4;
        moved = mremap(reference->address, page_size, page_size, MREMAP_MAYMOVE);
        if (moved == MAP_FAILED) {
            fail |= 8;
        } else {
            copy_scalar(child, moved, sizeof(child));
            if (child[0] != 0xaa) fail |= 16;
            if (mprotect(moved, page_size, PROT_READ | PROT_WRITE) ||
                (moved[32] = 0x77, 0)) fail |= 32;
            copy_scalar(child, moved, sizeof(child));
            if (child[0] != 0xaa || child[32] != 0x77) fail |= 64;
        }
        close(fd[0]);
        _exit(fail);
    }
    close(fd[0]);
    {
        int set_error = v217_set_image(ctx, generation, newer, (uint32_t)page_size);

        if (set_error) error = set_error;
    }
    if (write(fd[1], "x", 1) != 1) error = EIO;
    close(fd[1]);
    if (waitpid(pid, &status, 0) != pid) status = -1;
    REQUIRE(!error, "v217 fork owner SET errno=%d", error);
    REQUIRE(WIFEXITED(status) && !WEXITSTATUS(status),
            "v217 fork child status=0x%x", status);
    copy_scalar(view, reference->address, sizeof(view));
    REQUIRE(view[0] == 0xbb && view[32] == file_page[32],
            "v217 fork owner view=%02x child_byte=%02x", view[0], view[32]);
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE,
            "v217 fork session state=%u", st.state);
    LOG("V217_FORK child=%d owner=%02x child_byte=%02x active=%u",
        WIFEXITED(status) ? WEXITSTATUS(status) : -1, view[0], view[32], st.state);
deactivate:
    REQUIRE(!uy_deactivate(ctx), "v217 fork deactivate errno=%d", errno);
out:
    if (image) munmap(image, page_size);
    if (newer) munmap(newer, page_size);
    if (file_page) munmap(file_page, page_size);
}

static void v217_gup(const struct uy_ctx *ctx, const struct page *reference,
                     size_t page_size)
{
    uint8_t *image = v217_anon_page(page_size);
    uint8_t *file_page = v217_anon_page(page_size);
    uint8_t *ref = v217_anon_page(page_size);
    uint8_t view[64];
    struct urov_y_request st;
    uint64_t generation = 0;
    char exe[256];
    ssize_t n, got;
    int dfd = -1, error = 0;

    ++g_cases;
    if (!image || !file_page || !ref ||
        app_pread(reference->fd, reference->file_offset, file_page, page_size)) {
        REQUIRE(0, "v217 gup fixture setup errno=%d", errno);
        goto out;
    }
    memcpy(image, file_page, page_size);
    image[0] ^= 0xff;
    n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) {
        LOG("V217_GUP skipped readlink errno=%d", errno);
        goto out;
    }
    exe[n] = '\0';
    dfd = open(exe, O_RDONLY | O_CLOEXEC);
    if (dfd < 0) {
        LOG("V217_GUP skipped open errno=%d", errno);
        goto out;
    }
    got = pread(dfd, ref, page_size, 0);
    close(dfd);
    dfd = -1;
    if (got != (ssize_t)page_size) {
        LOG("V217_GUP skipped pread rc=%zd errno=%d", got, errno);
        goto out;
    }
    error = v217_arm(ctx, reference->address, image, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 gup register errno=%d", error);
    if (error) goto out;
    if (mprotect(reference->address, page_size, PROT_READ | PROT_WRITE)) {
        REQUIRE(0, "v217 gup mprotect(RW) errno=%d", errno);
        goto deactivate;
    }
    dfd = open(exe, O_RDONLY | O_DIRECT | O_CLOEXEC);
    if (dfd < 0) {
        LOG("V217_GUP skipped O_DIRECT errno=%d", errno);
        goto deactivate;
    }
    got = pread(dfd, reference->address, page_size, 0);
    if (got != (ssize_t)page_size) {
        LOG("V217_GUP skipped O_DIRECT pread rc=%zd errno=%d", got, errno);
        goto deactivate;
    }
    copy_scalar(view, reference->address, sizeof(view));
    REQUIRE(!memcmp(view, ref, sizeof(view)),
            "v217 gup write did not reach the live page");
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE,
            "v217 gup session state=%u", st.state);
    LOG("V217_GUP live_matches=%d active=%u", !memcmp(view, ref, sizeof(view)), st.state);
    /* 2.18.0 must keep the page overlaid after the external write.  Install a
     * new image and confirm the EL0 read follows it; a retired ("dead") page
     * would keep returning the live bytes written above. */
    memcpy(image, ref, page_size);
    image[0] ^= 0x5a;
    image[1] ^= 0xa5;
    error = v217_set_image(ctx, generation, image, (uint32_t)page_size);
    REQUIRE(!error, "v217 gup set errno=%d", error);
    if (!error) {
        copy_scalar(view, reference->address, sizeof(view));
        REQUIRE(!memcmp(view, image, sizeof(view)), "v217 gup overlay retired");
        LOG("V217_GUP overlay_alive=%d", !memcmp(view, image, sizeof(view)));
    }
deactivate:
    REQUIRE(!uy_deactivate(ctx), "v217 gup deactivate errno=%d", errno);
out:
    if (dfd >= 0) close(dfd);
    if (image) munmap(image, page_size);
    if (file_page) munmap(file_page, page_size);
    if (ref) munmap(ref, page_size);
}

static sigjmp_buf v217_jmp;

static void v217_sigsys(int sig)
{
    (void)sig;
    siglongjmp(v217_jmp, 1);
}

static void v217_remap(const struct uy_ctx *ctx, size_t page_size)
{
    struct sigaction sa, old;
    uint8_t *image = v217_anon_page(page_size);
    uint8_t view[8];
    struct urov_y_request st;
    uint64_t generation = 0;
    struct page shared;
    int error = 0;
    long rc;

    ++g_cases;
    if (!image) {
        REQUIRE(0, "v217 remap fixture setup errno=%d", errno);
        return;
    }
    if (page_open_at(&shared, MAP_SHARED, (const void *)(uintptr_t)&dobby_crc_payload)) {
        LOG("V217_REMAP skipped shared open errno=%d", errno);
        goto out;
    }
    memset(image, 0, page_size);
    image[0] = 0xdd;
    error = v217_arm(ctx, shared.address, image, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 remap register errno=%d", error);
    if (error) goto close_shared;
    copy_scalar(view, shared.address, sizeof(view));
    REQUIRE(view[0] == 0xdd, "v217 remap clean view=%02x", view[0]);
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = v217_sigsys;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSYS, &sa, &old);
    errno = 0;
    if (sigsetjmp(v217_jmp, 1) == 0)
        rc = syscall(__NR_remap_file_pages, shared.address, page_size, 0UL,
                     (unsigned long)(shared.file_offset / 4096) + 1UL, 0UL);
    else {
        rc = -1;
        errno = ENOSYS;
    }
    sigaction(SIGSYS, &old, NULL);
    if (errno == ENOSYS) {
        LOG("V217_REMAP skipped seccomp");
        REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE,
                "v217 remap seccomp skip state=%u", st.state);
        REQUIRE(!uy_deactivate(ctx), "v217 remap deactivate errno=%d", errno);
        goto close_shared;
    }
    /* This kernel rejects the call after the module gate; the gate must not
     * have released the session on the way to EINVAL. */
    REQUIRE(rc != 0, "v217 remap unexpectedly succeeded");
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE,
            "v217 remap ended the session rc=%ld errno=%d state=%u", rc, errno, st.state);
    copy_scalar(view, shared.address, sizeof(view));
    REQUIRE(view[0] == 0xdd, "v217 remap rejected call lost the view=%02x", view[0]);
    LOG("V217_REMAP rc=%ld errno=%d active=%u view=%02x", rc, errno, st.state, view[0]);
    REQUIRE(!uy_deactivate(ctx), "v217 remap deactivate errno=%d", errno);
close_shared:
    page_close(&shared);
out:
    if (image) munmap(image, page_size);
}

/* Production-style CRC of the Dobby-patched .text page: every reader path must
 * return the file bytes while the code still executes the patched body. */
static void v217_crc(const struct uy_ctx *ctx, int repeats)
{
    const void *text = (const void *)(uintptr_t)&dobby_crc_payload;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    struct urov_y_request st;
    uint8_t *buf = NULL;
    uint8_t file[DOBBY_CRC_BYTES], user[DOBBY_CRC_BYTES];
    uint32_t file_crc, user_crc, mem_crc = 0, pipe_crc, iov_crc;
    uint64_t generation = 0;
    int error = 0, child_status = 0, fd[2], mem_error;
    pid_t pid;

    ++g_cases;
    pthread_mutex_lock(&dobby_crc_lock);
    if (dobby_setup_error < 0) dobby_setup_error = dobby_crc_setup((void *)text, page_size);
    if (dobby_setup_error) {
        REQUIRE(0, "v217 crc Dobby setup errno=%d", dobby_setup_error);
        goto out;
    }
    /* dobby_file_page holds the clean page; the payload starts at offset 0 of
     * its page (dobby_crc_setup verified the alignment). */
    memcpy(file, dobby_file_page, sizeof(file));
    file_crc = (uint32_t)crc32(0, file, sizeof(file));
    error = v217_arm(ctx, text, dobby_file_page, (uint32_t)page_size, &generation);
    REQUIRE(!error, "v217 crc register errno=%d", error);
    if (error) goto close_reference;
    buf = v217_anon_page(page_size);
    if (!buf) {
        REQUIRE(0, "v217 crc buffer errno=%d", errno);
        goto deactivate;
    }
        /* The live .text VMA keeps PROT_EXEC throughout: SELinux denies restoring
     * EXEC after a writable mapping (execmod), so protection cycles run on the
     * private alias in the crc-ap-text matrix instead. */
    copy_scalar(user, text, sizeof(user));
    memcpy(buf, user, sizeof(user));
    user_crc = (uint32_t)crc32(0, buf, sizeof(user));
    REQUIRE(!memcmp(user, file, sizeof(user)), "v217 crc direct view");
    {
        uint8_t pipebuf[DOBBY_CRC_BYTES], membuf[DOBBY_CRC_BYTES], iovbuf[DOBBY_CRC_BYTES];
        int pipe_error = v217_pipe_read(text, pipebuf, sizeof(pipebuf));
        int iov_error = v217_readv_read(text, iovbuf, sizeof(iovbuf));

        mem_error = v217_mem_read(text, membuf, sizeof(membuf));
        if (v217_skip_error(mem_error)) {
            memcpy(membuf, file, sizeof(membuf));
            mem_crc = file_crc;
            LOG("V217_CRC mem skipped errno=%d", mem_error);
        } else {
            REQUIRE(!mem_error, "v217 crc mem errno=%d", mem_error);
            mem_crc = (uint32_t)crc32(0, membuf, sizeof(membuf));
        }
        REQUIRE(!pipe_error, "v217 crc pipe errno=%d", pipe_error);
        REQUIRE(!iov_error, "v217 crc readv errno=%d", iov_error);
        pipe_crc = (uint32_t)crc32(0, pipebuf, sizeof(pipebuf));
        iov_crc = (uint32_t)crc32(0, iovbuf, sizeof(iovbuf));
        REQUIRE(pipe_crc == file_crc && mem_crc == file_crc && iov_crc == file_crc,
                "v217 crc digest user=%08x mem=%08x pipe=%08x iov=%08x file=%08x",
                user_crc, mem_crc, pipe_crc, iov_crc, file_crc);
    }
    LOG("V217_CRC stage=readers");
    /* A forked child inherits the trap and must read the fork-time image. */
    if (!pipe(fd)) {
        pid = fork();
        if (pid == 0) {
            uint8_t child[DOBBY_CRC_BYTES];
            char byte;
            int fail = 0;

            close(fd[1]);
            if (read(fd[0], &byte, 1) != 1) fail |= 1;
            copy_scalar(child, text, sizeof(child));
            if (memcmp(child, file, sizeof(child))) fail |= 2;
            close(fd[0]);
            _exit(fail);
        }
        close(fd[0]);
        if (write(fd[1], "x", 1) != 1) child_status = -1;
        close(fd[1]);
        if (waitpid(pid, &child_status, 0) != pid) child_status = -1;
        REQUIRE(WIFEXITED(child_status) && !WEXITSTATUS(child_status),
                "v217 crc child status=0x%x", child_status);
    }
    LOG("V217_CRC stage=child");
    REQUIRE(dobby_crc_payload() == DOBBY_HOOKED, "v217 crc execute=%04x", dobby_crc_payload());
    REQUIRE(!uy_status(ctx, &st) && st.state == UROV_Y_ACTIVE && !st.failures,
            "v217 crc state=%u failures=%llu", st.state, (unsigned long long)st.failures);
    LOG("V217_CRC file=%08x user=%08x mem=%08x pipe=%08x iov=%08x child=%d active=%u "
        "execute=%04x samples=%d",
        file_crc, user_crc, mem_crc, pipe_crc, iov_crc,
        WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1, st.state,
        dobby_crc_payload(), repeats);
deactivate:
    REQUIRE(!uy_deactivate(ctx), "v217 crc deactivate errno=%d", errno);
close_reference:
    if (buf) munmap(buf, page_size);
out:
    pthread_mutex_unlock(&dobby_crc_lock);
}

static void v217_fixture(const char *mode, const char *key, int repeats)
{
    const char *shape = mode + sizeof("v217-") - 1;
    const void *text = (const void *)(uintptr_t)&dobby_crc_payload;
    size_t page_size;
    struct page reference;
    struct uy_ctx ctx;

    if (uy_init_key(&ctx, key)) {
        REQUIRE(0, "v217 key missing");
        return;
    }
    if (!strcmp(shape, "crc")) {
        v217_crc(&ctx, repeats);
        return;
    }
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_lock(&dobby_crc_lock);
    if (page_size != UROV_Y_PAGE || page_open_at(&reference, MAP_PRIVATE, text)) {
        REQUIRE(0, "v217 fixture page errno=%d", errno);
        pthread_mutex_unlock(&dobby_crc_lock);
        return;
    }
    if (!strcmp(shape, "store")) v217_store(&ctx, &reference, page_size);
    else if (!strcmp(shape, "atomic")) v217_atomic(&ctx, &reference, page_size, repeats);
    else if (!strcmp(shape, "fork")) v217_fork(&ctx, &reference, page_size);
    else if (!strcmp(shape, "gup")) v217_gup(&ctx, &reference, page_size);
    else if (!strcmp(shape, "remap")) v217_remap(&ctx, page_size);
    else REQUIRE(0, "v217 unknown mode %s", shape);
    page_close(&reference);
    pthread_mutex_unlock(&dobby_crc_lock);
}
