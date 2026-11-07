# UROV-Y 2.12.0 读取特征消除方案

本文是 `urov-y` 2.12.0 的设计说明。目标只有一个：把
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 与
[APP_READ_INTEGRITY_AUDIT.md](APP_READ_INTEGRITY_AUDIT.md) 里 `2.11.0` 仍然成立、
且普通 App（`untrusted_app`、`CapEff=0`、`Seccomp=2`）能在本进程内使用的特征点全部
消掉，并且不引入新的可观测特征。只改 `urov-y`，不碰 `urov-lab` 基础版与 `urov-x`。

## 1. 威胁模型

生产环境的代码段 CRC 校验只有两种信息来源：

1. **读者看到的字节**：直接 `LDR`/`LDP`/`LD1` 循环、`memcpy`/`memcmp`/`crc32`
   库函数、`process_vm_readv`、`/proc/*/mem`、`ptrace`（后两条在本机
   `untrusted_app` 下受 dumpable/SELinux 限制，但 App 可以 `PR_SET_DUMPABLE`）。
2. **读者能观察到的副作用**：映射属性、页表统计、异常、独占监视器、耗时、崩溃。

因此“消除特征”= 让 **每一条读路径** 都返回注册镜像，同时让 **会话不再被 App
的常规动作打断**。CRC 校验本身无法区分“镜像等于文件”和“镜像被伪造”，这正是要
利用的点。

## 2. 2.11.0 仍成立的特征点（本轮输入）

按 `APP_READ_INTEGRITY_RESULTS.md` §2.11.0「残余」与「如何阻止与恢复」：

| # | 特征点 | App 侧用法 | 2.11.0 行为 |
| --- | --- | --- | --- |
| F1 | 内核辅助读未覆盖 | `open("/proc/self/mem")`+`pread`，或 `ptrace`/跨进程 `process_vm_readv` | GUP 复制真实页，与 EL0 视图不同 |
| F2 | `mlock` 拒绝注册 | 先 `mlock` 自有 RX 页，再让 owner 注册 | `validate_target_vma()` 拒绝 `VM_LOCKED`（`UY_VM_IO=0x2000` 实际是 `VM_LOCKED`），`REGISTER` 返回 `EINVAL` |
| F3 | 无效 `madvise` 撤销会话 | `madvise(page, page_size, -1)` | 门控在 Linux 校验 advice 之前恢复整个会话，随后返回 `EINVAL` |
| F4 | 重叠 `mprotect` 撤销会话 | `mprotect(page, page_size, PROT_READ\|PROT_EXEC)`（同权限） | 门控直接 `release_session()`，CRC 回到真实字节 |
| F5 | `fork`/`vfork` 撤销会话 | `fork()` 后父进程再读，或子进程读 | 非 `CLONE_VM` 的 clone 先恢复映射再 `fork`，会话消失 |
| F6 | `vfork`+`execve` 撤销会话 | `posix_spawn`/`fork`+`exec` 之后父进程读 | 子进程 `execve` 时 `mm` 仍是 owner `mm`，`execve` 门控恢复会话 |
| F7 | 无 `find_task_by_vpid` 时回退 | 兄弟 tid 读 | 符号缺失时回退到 tid/tgid 门控，兄弟 tid 看到真实页 |
| F8 | 每次读一次同步异常 | 计时/`perf` | 保留：`PAGE_AP` 的架构代价 |
| F9 | 桥的 store 不是硬件独占写 | 独占监视器细节 | 保留：`ERET` 清本地监视器，无法在 handler 内重放 |
| F10 | PTE 重装窗口 | 与回收竞争的多线程读 | 收窄到 `handle_mm_fault` 返回 EL0 之前 |
| F11 | `caller_count>0` 窗口内外不同 | 换调用栈读 | 保留：按调用窗口选择镜像是 API 语义，生产用 `caller_count=0` |

`F8`/`F9`/`F11` 是体系结构或 API 语义，不能再消；本方案消除 `F1`–`F7`，并把 `F10`
收窄（见 §5 诚实清单）。

## 3. 方案总览

一句话：**把“读者”从“EL0 数据异常”扩展为“本会话 mm 的任何读”，把“会话生命周期”
从“App 一碰映射就结束”扩展为“只在映射真的不可覆盖时结束”。**

### 3.1 统一内核读路径（消 F1、F7）

新增一个函数 hook：`__access_remote_vm(mm, addr, buf, len, gup_flags)`（5 参；
新内核的 6 参 `(task, mm, addr, buf, len, flags)` 同样支持）。它在 `after` 回调里：

- 只在 `ret > 0`、`!(gup_flags & FOLL_WRITE)`、`mm` 属于会话时改写 `buf`；
- 只改写落在已登记页上的片段，字节来自 `page_view()`；
- 视图选择沿用既有语义：`caller_count==0` 或窗口内取镜像，否则回放快照；
- 模块自己的 `access_remote_vm` 调用（注册、装/卸陷阱、控制回包）通过
  `current` 标记绕过该 hook，避免读自己的镜像。

这一条 hook 覆盖 `/proc/self/mem`、`/proc/<pid>/mem`、`ptrace(PTRACE_PEEKDATA)`、
`access_process_vm()` 的所有调用者，以及驱动里用 `access_remote_vm()` 的读。
`process_vm_readv` 走 `pin_user_pages`，不经过该函数，所以保留原来的 syscall
after hook，但把判定从“**调用者** mm 是 owner”改为“**目标** mm 是 owner”：
外部进程读 owner 的内存同样改写。目标 pid 不是自身时仍用
`find_task_by_vpid()` + RCU 解析；该符号在 2.12.0 是 `PAGE_AP` 注册的硬要求，
缺失时 `REGISTER` 返回 `EOPNOTSUPP`，不再静默回退（消 F7）。

### 3.2 `mlock` 不再是门槛（消 F2）

`VM_LOCKED` 与 `VM_IO` 在 4.x–6.x 都分别是 `0x2000`/`0x4000`；2.11.0 的
`UY_VM_IO` 写成了 `0x2000`，于是 `mlock` 过的页被当作 I/O 映射拒绝。2.12.0 把
常量改回真实 `VM_IO=0x4000`，显式定义 `UY_VM_LOCKED=0x2000` 并**接受**它：
`mlock` 只影响回收，不影响叶子 PTE 的权限位，陷阱在锁定页上照常工作。
`mlock` 过的页反而更不容易被换出，`F10` 的窗口更小。

### 3.3 `madvise` 只在真正可能拆映射时结束（消 F3）

`madvise` 的 advice 先按 Linux 的取值范围校验（`MADV_NORMAL..MADV_COLLAPSE` 与
`MADV_HWPOISON`/`MADV_SOFT_OFFLINE`）。无效 advice 直接放行给 Linux 返回
`EINVAL`，**不碰会话**。有效 advice：

- `PAGE_AP`：不结束会话。`MADV_DONTNEED`/`MADV_FREE` 只会让 PTE 变成非 present，
  下一次读触发 `handle_mm_fault`，其 after hook 重新清 `AP[1]`；其余 advice 不改
  页表权限。
- `SITE_BRK`/`PAGE_UXN`：仍按原逻辑恢复，因为 `MADV_DONTNEED` 会丢掉 COW 的
  `BRK` 页，而这两种模式没有按页重装路径。

### 3.4 同权限 `mprotect` 保活（消 F4）

`mprotect`/`pkey_mprotect` 在 `PAGE_AP` 下先看新权限：含 `PROT_READ`、含
`PROT_EXEC`、不含 `PROT_WRITE` 且与登记页重叠时，不再 `release_session()`；after
hook 对该范围内仍满足 `validate_target_vma()` 的页重新清 `AP[1]` 并刷 TLB。
Linux 对“权限没变”的 `mprotect` 通常直接返回、不改 PTE，所以常见硬化调用
（`mprotect(RX)`）连重装都不需要。变成可写或去掉 `PROT_READ`/`PROT_EXEC` 时仍
结束会话：可写页上的读不会进异常，**没有存指令解码就无法覆盖**（见 §5）。

### 3.5 `fork` 继承与 `execve` 区分（消 F5、F6）

`PAGE_AP` 的 `clone` 不再恢复会话：

- 线程（`CLONE_VM`）本来就共享 `mm`。
- `fork` 的子进程拿到的是**同一批叶子 PTE 的拷贝**（`AP[1]` 已清），所以子进程
  第一次读就会进同一个异常入口；此时 `current->mm` 不是会话 `mm`，2.12.0 用
  “陷阱签名”识别它：`far` 所在叶子 PTE 是 present、可读、`AP[2]=1`、`AP[1]=0`。
  正常内核不会给可读 VMA 造出这种 PTE（XOM 的 VMA 没有 `VM_READ`，`PROT_NONE`
  有 `PTE_PROT_NONE`），所以它只可能是本模块留下的。识别后按 `caller_count`
  语义返回镜像；会话结束后同样的签名走“修复”路径：把 `AP[1]` 置回并让原指令
  重试一次，避免留下崩溃。
- `fork` 时未驻留的页没有 PTE 可继承，子进程缺页时由 `handle_mm_fault` after
  hook 重装陷阱。识别条件是 VMA 身份（`vm_file` 指针、`vm_pgoff`、`vm_start`、
  `vm_end` 与登记时一致）：`fork` 的 VMA 由 `vm_area_dup()` 复制，`vm_file`
  指针相同；外部进程重新 `open` 同一文件得到的是不同的 `struct file`。
- 会话结束后子进程可能仍留着陷阱 PTE。`release_session` 把登记页的**基址**
  （不含镜像）留在 64 项退役表里；之后该页上的同形状 permission abort 会把
  `AP[1]` 置回并让原指令重试一次，因此孤儿陷阱不会变成信号。退役表只按地址
  比较，永不释放，避免与故障路径的释放竞争。
- 同一套识别也用在两条内核读路径上：fork 子进程对自己的
  `/proc/self/mem`/`process_vm_readv` 读取只有在该页仍带陷阱时才改写，因此子
  进程也不会从 GUP 看到真实字节。
- `CLONE_VM|CLONE_VFORK` 的 `vfork` 子进程共享 `mm`，`execve` 时只替换子进程的
  `mm`，父进程的映射不变。`execve` 门控因此只在**执行者属于 owner 线程组**
  （`task->tgid == 会话 tgid`）时恢复会话；`posix_spawn` 之类的
  `vfork`+`exec` 不再带走父进程的覆盖。
- `SITE_BRK`/`PAGE_UXN` 仍按原逻辑在 clone 时恢复：子进程继承 `BRK`/`UXN` 后
  没有会话可服务，会直接收到信号。

### 3.6 输出面

- ABI 仍为 v8，288 字节请求、`ctl0` 文本、计数器、返回码不变。
- `hooks` 增加一位 `0x80` 表示内核读 hook，测试脚本同步检查 `hooks=0xff`。
- 不新增 syscall hook；新增的是 `__access_remote_vm` 函数 hook，与既有
  `do_mem_abort`/`handle_mm_fault`/`do_el0_brk64` 同属控制面。
- 不新增文件、线程、定时器、`/proc` 节点或返回码。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 `prctl` 指纹 | 没有新命令、没有新 selector；未认证请求仍是原生 `EINVAL` |
| 新的 VMA/`smaps` 差异 | 只改叶子 PTE；`mprotect`/`madvise` 门控不写 VMA；`vm_page_prot` 未动 |
| 新的代码字差异 | `PAGE_AP` 不改代码页；`fork` 继承的是 PTE 拷贝 |
| 新的崩溃 | 会话结束后残留陷阱走“修复+重试”；`fork` 子进程有会话时按镜像返回 |
| 新的错误码 | `madvise` 无效 advice 现在透传 Linux 的 `EINVAL`（与未加载模块一致）；门控冲突仍是 `EBUSY` |
| 新的 hook 计数 | `hooks` 只是 root 侧诊断文本，App 不可见 |
| 新的映射身份 | 不 split VMA、不额外 mmap、不改 `vm_file` |

## 5. 诚实清单（2.12.0 仍不做的事）

1. `PAGE_AP` 每次数据读仍一次同步异常；`F8` 是架构代价，除非改为“存指令也模拟
   + 写保护页”。
2. 桥的 store 仍是内核 nofault 普通写，不是硬件独占写（`F9`）。
3. `mprotect` 把页变成**可写**时仍结束会话：可写页上的读不触发权限异常，且
   `PAGE_AP` 不解码 store，不能把页保持只读。`fork` 子进程把自己的拷贝改成
   可写同样会失去该子进程的覆盖（父进程不受影响）。
4. `munmap`/`mremap`/`MAP_FIXED` 覆盖/owner 自己 `execve` 仍结束会话：映射本身
   消失或被替换。
5. `PTE` 重装窗口仍在，但只存在于“页被回收后重新 fault-in”的
   `handle_mm_fault` 内部，且 after hook 在返回 EL0 之前重装；只有另一个 CPU 上
   恰好同时读该页的线程能看到。
6. 孤儿陷阱的修复依赖模块仍加载；卸载后残留陷阱会变成信号。修复只按“退役基址 +
   陷阱 PTE 形状”识别，arm64 生产内核没有 XOM（可读 VMA 之外也没有同形 PTE），
   但若有内核把 XOM 实现成 `AP[1]=0, AP[2]=1` 且外部进程恰好在同一虚拟地址上
   有这种页，该页会被误置回可读；正常 Android 布局下不可达。
7. `caller_count>0` 的窗口语义不变（`F11`）；生产覆盖请用 `caller_count=0`。
8. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；`seccomp` 仍可由 App 自己
   拒绝 `prctl` 控制面（那是进程策略，不是模块特征）。

## 6. 验证计划与结果

在 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch `0xc00`
上，用现有测试 App 的四个矩阵复跑，并把断言改成“特征已消除”。构建
`urov-y.kpm 13ca0c0c...`、`urovdetect.apk 4494e72c...`，全部 PASS：

| 矩阵 | 新增/改写的断言 | 结果 |
| --- | --- | --- |
| `crc` 9 项 ×2 | `CRC_LOCK_GUARD` 由 `EINVAL` 改为“锁定页注册成功、业务窗口仍读到镜像、页仍 RX、注销后恢复”；`crc_revoke` 改为 `madvise(-1)` 仍 `EINVAL` 但会话 **ACTIVE**，再由认证 `DEACTIVATE` 恢复 | 16 次运行 PASS；`CRC_LOCK_GUARD` 12/12、`CRC_RESTORE` 10/10 |
| `dobby-detect` 24×3 | `DOBBY_DETECT_KMEM` 比对 `/proc/self/mem` 与 EL0 视图；`DOBBY_DETECT_FORK_KMEM` 比对 fork 子进程自己的 `/proc/self/mem`；`DOBBY_DETECT_RESTORE` 断言会话存活、镜像仍生效；`DOBBY_DETECT_LOCK` 断言锁定页注册成功且覆盖生效 | PASS；`accepted_crc=24/24`×3、`views=0/72`、KMEM 18/18 一致、FORK_KMEM 3/3、LOCK 3/3、RESTORE 3/3 |
| `eliminate` 6×2 | `w-active` 的断言不变（`exclusive_match=0`、`zero_match=0`、`bridge=0`） | PASS，14 次运行；`site_call_ns=285/286` |
| `multipage` 5×1 | `MP_AUDIT` 的 `mprotect(RX)` 改为“会话保持、仍读到镜像”；`fork` 子进程改为 `child_overlay=1` 且父会话 ACTIVE；新增 `MP_PROD` 生产式 24 页五路径 CRC | PASS，6 次运行；`MP_PROD paths=5 child_overlay=1` |

数据目录：
[dobby-detect-20261108-010644](results/dobby-detect-20261108-010644/summary.json) ·
[crc-20261108-010719](results/crc-20261108-010719/summary.json) ·
[eliminate-20261108-010801](results/eliminate-20261108-010801/summary.json) ·
[multipage-20261108-010925](results/multipage-20261108-010925/summary.json)。
全部矩阵前后 boot ID 一致，增量内核日志无 `BUG:`/`WARNING:`/`Oops`/panic/RCU
stall/hung task，测试后 `kpm list` 为空。完整日志与复跑命令见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.12.0 节。
