# UROV-Y 2.17.0：任意写形状、fork 快照与并发原子

本文是 `urov-y` 2.17.0 的设计说明。目标是消掉
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 2.16.0 节
“残余（2.16.0）”里除读取计时之外的全部特征点，同时不引入新的 App 可观察
特征。只改 `urov-y`、测试 App/夹具与构建脚本，`urov-lab`、`urov-x` 不动；
ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.16.0 仍成立的特征

| # | 2.16.0 行为 | 普通 App 的用法 | 2.16.0 证据 |
| --- | --- | --- | --- |
| G1 | 未解码 store（SIMD 单 lane、STTR、SVE/SME 等）让该页 `dead`：恢复 AP[1]，此后该页读真实字节 | 对注册页 `mprotect(RW)` 后执行一条解码器不支持的 store，再读 | 2.16 设计 §6.2；`uy_store_emulate` 失败后的 per-page handoff |
| G2 | 原子 RMW 的读-算-写不是硬件单指令原子；同页并发写可能丢更新 | 多线程对注册页做 `LDADD`/`CAS`，比较最终值 | 2.16 设计 §6.5 |
| G3 | fork 子进程自己的 `mremap`/`munmap` 不重建影子地址；子进程覆盖失效 | `fork` 后子进程移动/拆分自己的拷贝，再读 | 2.16 设计 §6.3 |
| G4 | 子进程影子在第一次写时才从 owner 当时的镜像创建；owner 在 fork 后、子进程首写前 `SET` 会让子进程看到新镜像 | fork，owner `SET`，子进程再读 | 2.16 设计 §6.4 |
| G5 | fast-GUP 的 `FOLL_WRITE` 被当作源页：替换页会截获写者；且内核 GUP 先把叶子改成可写，AP[1] 陷阱丢失，之后该页读活页 | `mprotect(RW)` 后 `read()`/`O_DIRECT` 读进注册页，再读 | 2.16 设计 §6.6；本轮复现并发现 GUP 重试死循环 |
| G6 | shared VMA 的 `remap_file_pages` 在门控里先结束整个会话，再让 Linux 返回 `EINVAL` | 对注册的 shared RX 页调用 `remap_file_pages` | 2.16 设计 §6.7 |
| G7 | 已分配 pkey/POE 的 `pkey_mprotect`、root 可见性 | 需要 POE 硬件/改 KernelPatch 核心 | 2.16 设计 §6.8、§6.9 |

本轮处理 G1–G6；G7 的 root 可见性仍需要改 KernelPatch 核心，超出“只改
`urov-y`”的范围；pkey/POE 在本机不存在（Pixel 6，无 POE，App 的 seccomp 也
直接拒绝 syscall 288/234），只做结构论证并在真机上验证拒绝路径不碰会话。

## 2. 威胁模型

生产 CRC 仍只有两类输入：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程
   的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在本轮消除范围（题目允许保留）；root 通过 `kpm list`/`ctl0 status`
看到模块同样不在普通 App 的 CRC 输入集合内。其余普通 App 可无密钥复现的稳定
字节差异/恢复路径逐项处理。

## 3. 方案

### 3.1 G1：解码器之外的 store 由硬件执行

`uy_store_emulate()` 覆盖普通/SIMD/多结构/LSE/`DC ZVA` store，但单 lane
SIMD、`STTR`、SVE/SME 与将来的形状无法解码。2.16 让这些页 `dead`，这是最后
一个写侧指纹。

2.17.0 增加**延迟原生重放**：

1. 写异常无法解码时，把活页复制到该页的 `pre` 私有页，恢复叶子 PTE 的
   AP[1]，只在本 CPU 上 `tlbi vae1`（其他 CPU 的 TLB 仍保留陷阱项）；
2. 为该 task 打开 AArch64 software step（`SPSR_EL1.SS` +
   `MDSCR_EL1.SS`），**不**跳过原始缺页处理：内核按正常写缺页完成 COW，
   指令重试并在 EL0 原生执行；
3. 原 Store 退休后取下一条指令前产生 Software Step 异常（EC 0x32）。
   `do_debug_exception` 的 before hook 识别该 task 的重放记录，把活页与
   `pre` 逐字节比较，只把变化的字节发布进 image（owner）或影子（子进程），
   再恢复 AP[1] 陷阱并清掉 SS。

store 的字节由硬件写入，插件只做 diff，因此**不需要新增任何指令解码**：
SVE/SME 与将来任意写形状走同一条路径。`pre`/`post`/`image`/`snapshot`/`spare`
每页各一份私有内核页，都不在进程映射里。

迁移/抢占：`__switch_to` 的 after hook 在切换回带重放记录的 task 时重新置
`MDSCR_EL1.SS`；若重试过程中原缺页变成信号，下一次数据异常或该 task 的
Software Step 会把记录收尾（`uy_replay_cancel` 记一个 orphan，保证仍消费一次
step，不会变成 SIGTRAP）。重放期间同一页被另一个 task 写入时，diff 可能带上
对方的字节；这些字节本来也是 App 自己写入的，发布后视图仍一致。

### 3.2 G2：并发 RMW 串行化

`PAGE_AP` 下所有 EL0 写都会命中 AP[1] 陷阱并由插件完成，因此“读-算-写”之间
只要插件自己串行化，就不再丢更新。新增一个可睡眠的全局写锁
（短 yield 后 `msleep`），覆盖：

- `uy_atomic_emulate()` 的 image 读、活页写与发布；
- `uy_store_emulate()` 的活页写、重新装陷阱与发布；
- `uy_llsc_commit()` 的独占 store 提交；
- 内核辅助写（`__access_remote_vm` 的 `FOLL_WRITE` 发布）。

锁只在写异常/写回调里持有，读路径不取锁；内核 GUP 写路径可能睡眠，所以用
msleep 等待而不是自旋。两个并发 `LDADD` 因此得到与单条硬件指令相同的最终值。

### 3.3 G3/G4：fork 快照与按文件身份解析

影子池从固定 32 项改成**按注册页数在 REGISTER 时分配**的数组 + vmalloc
arena：默认 4 个 fork 世代，受 16 MiB 上限约束；每项按 owner 页的 descriptor
index 索引，不再用虚拟地址。

- **fork 快照**：hook `copy_mm()` 的 after。owner 的 fork 完成后，为子进程
  的每个注册页立即创建影子并从**当时**的 image 复制。这样 owner 之后的
  `SET` 不会改变子进程看到的视图。
- **子进程 mremap/mprotect**：新增 `uy_page_by_identity()`。子进程移动或拆分
  自己的拷贝后，地址不再等于 `p->base`；用 VMA 的 `vm_file` + 文件页偏移
  （`vm_pgoff` 与页内偏移）匹配回 owner 页。`uy_page_for_fault()` 在
  `page_find()` 失败时走这条路径，读、写、`mprotect` 重装陷阱与
  `handle_mm_fault` 重装都改用它。
- 影子按 owner index 查找，所以子进程移动后的读写仍落在同一份影子；子进程
  的写只更新影子，owner 的 image 不受影响。

### 3.4 G5：fast-GUP 写者不再被截获

2.16 的 GUP after hook 对所有 fast-GUP 返回页做替换，注释假设
`vmsplice` 会带 `FOLL_WRITE`。本轮在真机上测得该内核的 `vmsplice` 是
`flags=0`（纯源页），而 `read()`/`O_DIRECT` 的目的页才是 `FOLL_WRITE`。

2.17.0 分两种：

- `FOLL_WRITE`：这是真实写目的页，**不替换**返回页，让内核的写落到活页；
  owner 页标记 `dead`（此后按原生字节读）。写者不再被替换页截获，也不会
  因为“写永远到不了活页”而出现数据丢失。
- 无 `FOLL_WRITE`：仍替换为 image 副本（vmsplice/pipe 源页），并在返回前检查
  陷阱是否还在；不在则补装 AP[1]。

实现 G5 时还发现并修掉一个 2.16 就存在的**死循环**：`FOLL_WRITE` 的 slow
GUP 会反复 `faultin_page()`，而 `handle_mm_fault` after hook 每次都把 AP[1]
重新清零，导致 GUP 重试永不成功（`read()`/`O_DIRECT` 落入注册页即挂死）。
2.17.0 在 `handle_mm_fault` 的 after hook 里区分写缺页来源：

- 插件自己的 GUP 写（`g_internal_access == current`）保持原行为；
- 外部写者（fast-GUP `FOLL_WRITE`、`process_vm_writev`）的写缺页不重装
  AP[1]，让这次写完成，并把该页标记 `dead`。

这样既没有挂死，也没有“替换页截获写者”的语义。

### 3.5 G6：`remap_file_pages` 只退役页，不结束会话

门控改为：参数合法且 VMA 为 shared 时不再在 syscall 前 `release_session()`，
只记录范围；syscall 成功（`rc == 0`）后像 `munmap` 一样只退役覆盖的页，
会话与其余页保持 ACTIVE。Linux 在改任何 PTE 之前返回 `EINVAL` 的私有 VMA
调用仍然直接透传。

本机 ext4/f2fs 的普通文件 VMA 没有 `->remap_pages`，实测该 syscall 总是
`EINVAL`；但 2.16 会在返回 `EINVAL` 前拆掉整个会话，2.17.0 不会。测试 App
的 seccomp 直接对该 syscall 投递 SIGSYS，因此这条路径由 root 探针
（`tests/v217_probe.c`）覆盖；App 内验证 seccomp 拒绝时会话保持 ACTIVE。

### 3.6 pkey/POE（G7 的一半）

`pkey_mprotect` 在 `PAGE_AP` 下仍只透传并重装陷阱：AP[1]=0 对 EL0 数据访问是
强于 pkey/POE 的权限，PTE 的 CAS 只改 AP[1]，不会破坏内核写入的 permission
index；EL1 的内核访问不受 POE 影响。真实的 POE 硬件不可用（Pixel 6 无
POE，App 的 seccomp 拒绝 syscall 288），所以本轮不声明已验证 POE 的正向
行为，只保证拒绝/透传路径不碰会话。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 不新增/移动 VMA；fork 快照只在插件私有内存里复制；`remap_file_pages` 退役页是 Linux 自己的行为 |
| 新的代码字/页表权限 | 仍只改叶 PTE 的 AP[1]；重放期间只在本 CPU 失效翻译，其他 CPU 仍保留陷阱项 |
| 新的崩溃 | 非法写仍原生 SIGSEGV；`PROT_NONE` 仍原生 SIGSEGV；拿不到 software step 时退回 2.16 的按页 handoff；GUP 死循环已修 |
| 新的返回码/ABI | `mprotect`/`mmap`/`mremap`/`munmap`/`read`/`remap_file_pages` 返回值仍来自 Linux；ABI v8、请求布局、`ctl0` 文本、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；`copy_mm`、`__switch_to`、`do_debug_exception` 都是函数 hook |
| 新的写语义 | 解码得到的 store 仍由内核 COW/GUP 路径完成同一批字节；未解码 store 由硬件执行；原子 RMW 只在插件侧串行化 |
| 新的读视图 | 读路径未变；`dead` 只由外部写者（它确实写了活页）或 GUP 写完触发，与原生写语义一致 |
| 新的计时台阶 | 每次 EL0 数据读仍一次同步异常；未解码 store 多一次 software step 与一次整页 diff，只在写异常上出现，且计时不在本轮消除范围 |

## 5. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB /
`6.1.134-android14-11` / KernelPatch `0xc00`。App 在 `untrusted_app`，
`CapEff=0`、`Seccomp=2`、SELinux Enforcing。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| v217 App 2×6 | PASS；store/atomic/fork/gup/remap/crc 六种模式各 2 轮 | results/v217-* |
| v217 root 探针 | PASS；store/atomic/fork/gup/remap 五种，remap `rc=-1 errno=22 active=1` | results/v217-* |
| 读防御 8×1 | PASS | results/read-defense-v216-*、read-defense-* |
| CRC 5×1 | PASS | results/crc-* |
| Dobby 24×1 | PASS；`accepted_crc=24/24` | results/dobby-detect-* |
| 消除 3×1 | PASS；`ELIM_PROT_STORE shapes=16` | results/eliminate-* |
| 多页 3×1 | PASS | results/multipage-* |

详细数字见本轮结果节。

## 6. 残余（2.17.0）

1. **计时**：每次 EL0 数据读仍一次同步异常；未解码 store 多一次 Software
   Step 与整页 diff。属 `PAGE_AP` 的架构代价，按题目允许保留。
2. **重放窗口**：未解码 store 的重试期间，该页在本 CPU 上是可读的，其他 CPU
   只在本 CPU 失效后仍保留陷阱 TLB 项；若其他 CPU 恰好在此期间发生 TLB miss
   并重新走页表，理论上能看到一次活页字节。窗口是单条指令级，不是稳定的
   字节特征；这是“用硬件执行未知形状”与“零窗口”之间的取舍。
3. **pkey/POE**：本机无 POE，只验证了拒绝/透传路径，未验证正向 POE 权限
   变化。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍能看到模块与会话；隐藏它需要
   改 KernelPatch 核心，超出“只改 `urov-y`”的范围。
5. **外部写者让页 `dead`**：`/proc/self/mem` 之外的外部写者（`O_DIRECT`
   读进注册页、`process_vm_writev`）按原生语义写活页后，该页不再被覆盖；这
   与“App 自己写了代码页”一致，不是覆盖存在的指纹。
6. **execve/进程退出**：替换/销毁地址空间仍结束会话；旧代码已不存在，不构成
   读值不一致。

普通 App 仍可利用 `process_vm_readv` 后置钩子对 iovec 的二次读取检测覆盖，见 §8。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_v217_device.py --serial $Serial --key $KpKey --repeats 64 --cycles 2
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```

## 8. 普通 App 的无密钥检测与校验

### 8.1 双 iovec 读回

Linux 在 `process_vm_readv()` 复制数据前导入两个 iovec 数组。`urov-y` 2.17.0 的
`uy_vm_readv_after()` 在 Linux 完成复制后，再从用户态读取 iovec，并按调用窗口
向覆盖范围对应的目的地址写回 `image` 或 `snapshot`。
[Android 内核源码](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1-sp/mm/process_vm_access.c#275) ·
[模块后置钩子](urov_y_backend.c#L4262)

对自身 PID 发起两段复制。第一段把 `post` 指针写入用户态的 `local[1].iov_base`。
第二段仍按 Linux 已导入的描述符把目标页字节写入 `live`。后置钩子读到更新后的
`local[1]`，于是把覆盖字节写进 `post`。两处目的地址和 iovec 数组都在探针私有的
可写内存中。
[读回实现](native/urov_observe.c#L115)

```c
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <sys/uio.h>
#include <unistd.h>

static int read_redirected(const uint8_t *address, uint8_t *live,
                           uint8_t *post, size_t size)
{
    void *redirect = post;
    struct iovec local[2] = {
        { .iov_base = &local[1].iov_base, .iov_len = sizeof(redirect) },
        { .iov_base = live, .iov_len = size },
    };
    struct iovec remote[2] = {
        { .iov_base = &redirect, .iov_len = sizeof(redirect) },
        { .iov_base = (void *)address, .iov_len = size },
    };

    ssize_t got = process_vm_readv(getpid(), local, 2, remote, 2, 0);
    if (got != (ssize_t)(sizeof(redirect) + size)) return got < 0 ? errno : EIO;
    return local[1].iov_base == redirect ? 0 : EPROTO;
}
```

### 8.2 接入与判定

App 调用 `ud_observe_readv_redirect()`，传入目标 RX 地址、同一文件及偏移的只读
非执行别名、样本长度、backing fd、文件偏移，以及业务实际使用且无副作用的读取
函数。每个样本为 1–64 字节，限制在一页内。调用期间持有 fd 和两份映射，探针
前后核对设备号、inode、偏移、权限、映射范围和文件元数据。仅在已确认允许
`process_vm_readv` 的 Android 配置上启用，并在后台线程低频采样。
[接口](native/urov_observe.h#L42)

每次复核做三轮。各轮交替以 `0x5a`、`0xa5` 填充 `post`，先采样只读别名，要求
`live` 等于 `pread()` 取得的文件字节且 `post` 保留填充值。随后采样业务读值和
目标活页，要求两份字节各自跨轮稳定。探针分别返回两个判定。
[判定实现](native/urov_observe.c#L133)

| 判定 | 含义 |
| --- | --- |
| `post_copy == UD_MATCH` | `post` 被稳定写回。镜像和活页字节相同也能观察到这个信号。 |
| `reader_diff == UD_MATCH` | 业务读值与 `live_bytes` 稳定分叉。 |
| `UD_NO_MATCH` | 该项在本次样本中未发现异常。结论限于采样范围、读点和时刻。 |
| `UD_UNKNOWN` | 系统调用失败或短读、对照异常、映射或样本不稳定。保留不确定状态，避免据此放行完整性校验或中断正常业务。 |

对现有 ELF `.text`，在有效样本中只用 `live_bytes` 和可信发布版本的字节或摘要
做完整性比较。这样仅 Dobby 改码时也能发现代码变化，并可用 `post_copy` 区分额外
的读回覆盖。探针不改目标代码、权限或会话。AP 模式的 `LDXR; LDRB; ADD; STXR`
可作为辅助证据，独占结果混合时单独记为 `UD_UNKNOWN`。
[测试夹具](apps/urov-detect/read_defense_fixture.inc#L154)

对 App 自己装载的独立位置无关代码，可以用 `MAP_PRIVATE | MAP_ANONYMOUS`
创建 RW 映射，初始化后切为 RX。目标没有 `vm_file`，三种模式的 `REGISTER`
均拒绝该映射。对于既有文件映射，等长 `mremap` 在夹具中只撤销了 BRK 和 UXN
会话，AP 会话继续返回镜像。BRK 的一次撤销约耗时 108 ms。对正常业务，现有
ELF 采用活页校验避开伪造，彻底撤销 AP 会话需授权控制面。
[目标页校验](urov_y_backend.c#L1076) ·
[撤销复测](results/read-defense-20261108-171543/summary.json)

### 8.3 真机复测

Pixel 6、Android 16、ARM64、4 KiB 页，`urov-y` 2.17.0。检测在
`untrusted_app`、`CapEff=0`、`Seccomp=2`、SELinux Enforcing 下运行。密钥和
`prctl` 仅由夹具用于注册、撤销和核对会话，检测入口不接收控制面参数。

| 状态 | 额外写回 | 业务读值与活页分叉 |
| --- | ---: | ---: |
| 无活动覆盖，含模块空闲、仅 Dobby 改码及撤销后 | 0 / 9,984 | 0 / 9,984 |
| 覆盖活动，镜像与活页相同 | 3,072 / 3,072 | 0 / 3,072 |
| 覆盖活动，原版镜像掩盖 Dobby 改码 | 3,072 / 3,072 | 3,072 / 3,072 |

BRK、UXN、AP 调用窗口和 AP 全调用者各启动 6 个测试进程，每阶段采样 128 次。
16,128 次活页读回与夹具真值一致，主探针 `UNKNOWN=0`。按业务读值比较原版字节时，
3,072 次被掩盖的改码均通过，改用活页校验后均被拒绝。匿名 RX 注册尝试 24/24 次
返回 `EINVAL`，测试代码仍返回原始执行结果。
[复测汇总](results/read-defense-v216-20261108-171301/summary.json)

后台业务线程共完成 11,182,592 次迭代，错误为 0，UI 心跳最大间隔 21 ms。对
32 字节样本，各阶段平均复核耗时为 2.91–3.69 ms。首轮干净对照曾出现一次
独占指令混合结果，夹具现将该类 `EAGAIN` 记为不确定，保留对主探针的严格断言。
两组完整复测前后 boot ID 一致，增量内核日志无故障记录，模块均已卸载。
[首轮日志](results/read-defense-v216-20261108-171007/read-defense-v216-brk-3-8217.log) ·
[夹具判定](apps/urov-detect/read_defense_fixture.inc#L199)

在仓库根目录按 §7 构建模块，然后运行以下测试。`--read-defense-v216` 是双 iovec
夹具的历史参数名，本次加载的模块版本为 2.17.0。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 128 --cycles 6
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 24 --cycles 2 --skip-install
```
