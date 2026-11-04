# UROV-LAB 普通 app 使用方案与真机验收

> 检测复核更正（2026-11-04）：当前源码把 `0x10000` 命名为 VM_DONTCOPY，
> 真机实际出现的是 VM_RAND_READ / `rr`，不是 `dc`；旧 fork 用例不能证明 VMA
> 未继承。普通 App 的 `/proc/self/mem` 被拒绝，向 pipe 直接 write raw-XOM 地址
> 还会持续重试。本文保留历史验收记录，这些相关结论以
> [DETECTION_RESULTS.md](DETECTION_RESULTS.md) 的源码复核和新实测为准。

日期：2026-11-04。设备：Pixel 6 / Android 16（`BP31.250610.009`，内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`，4 KiB 基础页）。
模块：`urov-lab.kpm`，由 root 通过 `kpatch kpm load` 加载；普通 app 只作为使用方。

本文承接 [APP_DOMAIN_LIMITS.md](APP_DOMAIN_LIMITS.md) 记录的旧限制，给出并验证了
一套让 **untrusted_app** 在自己的 mm 内伪造指定代码段数据读取值的方案。结论先行：

- 普通 app 通过 **`__NR_prctl` 控制通道**完成 QUERY/REGISTER/SET/STATUS/DEACTIVATE，
  不再依赖被 app seccomp 拒绝的 `__NR_kcmp`。
- 注册对象是 app 自己的 **恰好一页、只读、可执行、文件后备的 `MAP_SHARED` 映射**。
  推荐来源是 app 自己已安装 native library 的一页 `MAP_SHARED` RX 别名；也可用
  app 私有目录中的一页 payload 文件。封存 memfd、`/proc/self/fd` 重开、`MAP_PRIVATE`
  都不再是必需或不被接受。
- 会话严格属于注册者 mm；其他 app 不能 SET/DEACTIVATE，注册冲突返回 `EBUSY`；
  owner 进程死亡后，下一次控制请求用 `mm_users == 1` 惰性回收，不会永久占住模块。
- 模块卸载、owner 退出、fork、mprotect/munmap/mremap/madvise/MAP_FIXED 都有明确
  的恢复或拒绝路径；失败一律 fail-closed，不返回原字节冒充成功。
- 真机测试 app（`com.example.urovapp`，NativeActivity）在 `untrusted_app`、
  Seccomp mode 2 下通过：自身 lib 代码页别名 + 私有 payload 页各跑一轮，覆盖
  1/2/4/8 字节 load、LDP、部分重叠、更新、并发读、映射门控、SIMD fail-closed、
  注销恢复；普通 `prctl` 透传不受影响。

## 1. 旧限制与本轮对应关系

| 旧限制（2026-11-03） | 本轮处理 |
|---|---|
| app seccomp 拒绝 `__NR_kcmp`（272），控制请求发不出 | 增加 `__NR_prctl` 通道，option/magic 双重匹配；app 实测可发 |
| SELinux 拒绝 sealed memfd 的 `/proc/self/fd` 只读重开 | app 不再需要 memfd；改用自己可执行的一页文件映射 |
| `validate_vma()` 只接受单页 `MAP_SHARED`、`pgoff=0` | 保留“单页、只读、可执行、文件后备、无 MAYWRITE”；允许任意 `pgoff`；`MAP_PRIVATE` 明确拒绝（原因见 2.2） |
| 单会话、单 mm，且可被其他进程 SET/DEACTIVATE | 保留单会话（跨 app 串行），但增加 mm 所有权检查与死 owner 惰性回收 |
| 模块装卸需要 root | 保持：root 负责加载/卸载；app 不需要 root，也不能自行装卸 |

仍未解决、明确不属于本轮目标的：全系统多会话并发、多页范围、32 字节以上窗口、
SIMD/FP/atomic/acquire load、跨页 load、内核辅助读取（`process_vm_readv`、
`/proc/pid/mem`、ptrace）的伪造。

## 2. 方案

### 2.1 控制通道：`__NR_prctl`

app 侧调用形式（`urov_abi.h`）：

```c
long r = syscall(__NR_prctl,
                 (long)UROV_PRCTL_OPTION,   /* 0x55524f56, 非原生 prctl option */
                 (long)UROV_PRCTL_MAGIC,    /* 0x55524f5653595343 */
                 (long)cmd, q, (long)sizeof(*q));
```

KPM 在 `__NR_prctl` 的 syscall 入口安装 before hook：

1. `arg0 == UROV_PRCTL_OPTION && arg1 == UROV_PRCTL_MAGIC` 才进入 UROV 分发；
2. 其他所有 `prctl` 原样放行，app 实测 `PR_SET_NAME`/`PR_GET_NAME` 正常；
3. 分发、128 字节请求校验、seqlock 更新、fault 后端全部复用原 `urov_request` ABI；
4. 原 `__NR_kcmp` 通道保留，供 root 验收程序和旧二进制使用，app 不依赖它。

选择 `prctl` 而不是 `ioctl`/设备节点/新 syscall 的原因：

- `prctl` 在 `untrusted_app` 的 seccomp allowlist 内；实测返回内核原生 `EINVAL`
  而不是 `SIGSYS`。`ioctl` 也可用（实测 `EBADF`），但它更热，且需要解释一个
  不存在的 fd；`prctl` 无 fd、无设备节点、无 SELinux 策略改动。
- 不需要新 syscall 号（app seccomp 通常直接 trap 未知号）。
- 只匹配两个 magic 才截获，正常 `prctl` 调用路径不受影响；hook 的固定开销是
  两次参数比较。

能力位新增 `UROV_CAP_PRCTL (1 << 11)`；`kpm ctl0 ... status` 输出同时给出
`prctl_option=0x55524f56`。QUERY 实测 `caps=0xeb7`（含 READY/RAW_XOM/FAKE16/
FAKE32/PRCTL/MM_GATES）。

### 2.2 页来源与 VMA 条件：一页只读可执行文件映射

app 不能使用旧测试的 sealed memfd 形状：

- `memfd_create` + RW 填充 + seal 后，`mmap(PROT_READ|PROT_EXEC, MAP_SHARED)`
  直接使用 O_RDWR fd 会得到 `EPERM`（`deny_write_access` 语义）；
- 通过 `/proc/self/fd/N` 重开只读 fd 被 `untrusted_app` SELinux 拒绝（`EACCES`）。

因此注册条件改为：

```text
恰好一页（start == address, end == address + 4096）
VMA 文件后备（vm_file != NULL）
VM_READ | VM_EXEC
无 VM_WRITE、VM_MAYWRITE、VM_PFNMAP、VM_HUGETLB、VM_IO、VM_MIXEDMAP
PTE present、user、read-only、UXN=0、非 PTE_CONT/PTE_SPECIAL
```

允许任意 `pgoff`（文件只是后备存储，页按 VA pin）；**不接受 `MAP_PRIVATE`**。
本机实测 `MAP_PRIVATE` 的只读文件映射 `vm_flags=0x75`，其中
`VM_MAYWRITE (0x20)` 仍被置位：该映射后续可以被 `mprotect` 或
`FOLL_FORCE` 远程写触发 COW，用户 PTE 会指向新页，而模块 pin 的是旧页，
两者身份不再一致，覆盖会静默失效。模块对 `VM_MAYWRITE` 一律 `EINVAL`；
app 测试也把这一点作为负向用例（`data_private_reject`，见第 4 节）。

app 可用的页来源（按推荐顺序）：

1. **自身已安装 native library 的一页 `MAP_SHARED` RX 别名**（本测试 app 的主路径）。
   通过 `dladdr()` 找到 lib 与函数，解析 ELF `PT_LOAD` 得到文件偏移，
   `open(dli_fname, O_RDONLY)` 后
   `mmap(page_off, 4096, PROT_READ|PROT_EXEC, MAP_SHARED, fd, page_off)`。
   使用 `MAP_SHARED` 而不是 `MAP_PRIVATE`，是因为 lib 的正常 text 映射是
   `MAP_PRIVATE`，私有别名可能被 `vma_merge` 合并成多页 VMA；共享别名
   `VM_SHARED` 不同，不能被合并，实测 VMA 恰好 4096 字节（`r-xs`）。
   lib 文件位于 `/data/app/...`，app 不可写，内容稳定；执行仍从原文件页取指。
2. **app 私有目录的一页 payload 文件**（测试与回退路径）。创建/写入 4096 字节，
   `open(O_RDONLY)`，`mmap(MAP_SHARED, PROT_READ|PROT_EXEC)`，随后 `unlink`；
   映射仍持有 inode。SELinux 实测允许（`app_data_file` 的 execute/mmap）。
   这是测试便利路径；正式使用应保证注册期间没有其他写者修改该文件。

注册事务（在调用者控制上下文，可睡眠）：

```text
pin_user_pages_unlocked(address, 1)          # 页仍为 RX 时 pin，必须恰好 1 页
mmap_write_lock
find_vma + 重新校验 VMA/PTE
copy_from_user_nofault(original_page, address, 4096)
发布完整 session（mm/page/base/offset/len/fake/original）
vma->vm_page_prot 清 PTE_USER；vma->vm_flags 置 VM_DONTCOPY
PTE 清 AP[1]（保留 PFN/AF/RDONLY/UXN）；flush_tlb_mm
mmap_write_unlock
```

要求“恰好一页”是为了让 `vm_page_prot` 修改只作用于这个专用 VMA：不做 VMA
split，不影响 app 正常代码页；注册/注销只在这条控制路径做 TLB flush，读取
热路径不碰 PTE。`VM_DONTCOPY` 只加在这个一页别名上，因此 fork 子进程失去的是
别名，不会失去 app 的正常 lib 映射，也不会在子进程里留下“XOM 但无处理器”的
fault 循环。

### 2.3 所有权、生命周期与跨 app 行为

- 会话只属于注册时的 `current->mm`；`do_set/do_status/do_deactivate` 要求
  `mm_of_task(current) == session.mm`，否则 `ENOENT`。
- 非 owner 的 QUERY 不暴露 owner 的 session：返回 `state=INACTIVE`、
  `session=0`；若确有活跃会话，`last_error=-EBUSY`。非 owner 的 REGISTER 若
  遇到活跃会话返回 `EBUSY`。
- owner 进程（及所有线程）消失后，`get_task_mm()` 留下的引用使 `mm_users`
  变成 1。下一次任意进程的控制请求在 `notify_dispatch()` 里检查该值，调用
  `session_stop()` 恢复 VMA/PTE、flush TLB、unpin、`mmput`，再继续本次请求。
  真机验证：kill app 后 root 的 foreign QUERY 立即把模块状态从 `active` 变回
  `inactive`，随后不重新加载模块即可再次注册。
- `execve`/正常退出：旧 mm 的引用同样在 `mm_users==1` 时被下一次控制请求回收。
- fork：目标页 VMA 带 `VM_DONTCOPY`；子进程不继承别名。app 自身正常 lib 映射
  不受影响。root 验收还覆盖了“fork 子进程读不到受保护页、不会 hang”的旧契约。
- 模块卸载：`urov_backend_exit()` 先 `session_stop()` 恢复页，再撤销
  `do_mem_abort`、kcmp、prctl、mapping gate 的 hook。实测卸载时 app 正在每秒
  读该页：卸载前读到 fake，卸载后同一地址读到原值，执行结果不变。
- 注册/更新/注销由单个控制忙标志串行化；fault 路径不取该锁。更新用 seqlock
  发布完整 32 字节 fake 向量，LDP 两半来自同一快照；注销先恢复权限并 flush，
  再置 inactive、drain 在途 handler，最后 unpin/mmput。

### 2.4 读取热路径（复用原后端）

`do_mem_abort` before hook：

1. 只处理 EL0 A64 data abort、read、permission fault（ESR 检查）；
2. `current->mm == session.mm` 且 FAR 在注册页内；
3. 取 PC 处 opcode：PC 在注册页时用 `original` 快照，否则
   `copy_from_user_nofault`；
4. 取一份 seqlock fake 快照；`uro_emulate()` 解码普通 GPR load（含 LDP、
   符号扩展、pre/post-index）并先把结果放进临时 model；
5. 全部成功才提交 GPR/SP/PC；失败（SIMD/FP、atomic/exclusive、认证 load、
   未知编码、长度非法等）`force_sig_fault(SIGSEGV)`，绝不返回原字节。
6. 成功/失败只做 relaxed 计数；不分配、不取全局锁、不 flush TLB、不打印。

同页未覆盖字节来自注册时的不可变 `original` 快照；覆盖区间按字节合并，支持
窗口两侧的部分重叠。

### 2.5 稳定性与效率要点

- 原始页在注册时 `pin_user_pages_unlocked`（FOLL_PIN），VMA/PTE 被 gate 保护，
  不会被 reclaim/COW 换掉；PTE 只清 AP[1]，不改 PFN/UXN/AF。
- `vm_page_prot` 同步清 `PTE_USER`：即使内核因迁移/重建生成新 PTE，仍保持
  execute-only；若未同步，重建后的可读 PTE 会静默绕过覆盖。
- 一次注册只改一页、一个 VMA、一个 PTE，控制路径 O(1)；更新只写 4 个 64-bit
  字 + seqlock。
- 读取热路径的无锁/无分配设计与原 root 版本一致；新增的 app 支持没有增加
  fault 路径分支（只是 prctl 控制入口和 owner 检查）。
- 真机 app 内 benchmark（同一地址 65536 次 `LDR X`，`CLOCK_MONOTONIC`）：
  - 普通 cache 命中：约 0.36–0.72 ns/次；
  - overlay 读：约 0.23–0.47 µs/次（229–465 µs / 1000 次）；
  - 约 475–1175× 的同步异常成本。这是“EL0 读取异常 + 软件模拟”的固有成本，
    不是 PTE 切换或全局锁造成的；高频读点应控制窗口大小/读取频率。

## 3. 特征与痕迹

**没有引入**：

- 设备节点、sysfs/proc 接口、ioctl 专用 fd；
- SELinux 策略修改、seccomp 修改、新 syscall 号；
- 对 app 代码页的写入、指令改写、单步、硬件断点；
- 常驻内核线程/定时器、每次读取的 PTE 切换或 TLB flush；
- 成功路径的 `printk`、伪数据/原代码日志；
- 持久化 payload 文件（测试路径 mmap 后立即 unlink）。

**仅注册者自己可见的痕迹**：

- 多出一个恰好一页的 RX 映射：lib 别名是 `r-xs`（同一已安装 lib 的第二个
  MAP_SHARED 映射），payload 页是 `r-xs` + `(deleted)`。注册/注销后 app 可
  立即 `munmap`，正常代码页的 `/proc/self/maps` 不变。
- 该一页 VMA 的 `VmFlags` 在 smaps 中多出 `dc`（`VM_DONTCOPY`）；这是 fork
  安全的必要代价，作用域仅限这个专用页。
- 活跃期间对该页的 `mprotect`/`madvise`/`munmap`/`mremap`/`MAP_FIXED` 返回
  `EBUSY`（owner 自己可观察到；第三方 app 没有会话，不受影响）。
- 覆盖窗口内的数据读要经过同步异常，可用时间差检测；这是机制本身，无法同时
  满足“任意读取点 + 取指原字节 + 读取伪造”而完全消除。
- `/proc/self/mem`、`process_vm_readv`、ptrace 等内核辅助读取仍看到原字节
  （设计非目标）；与直接 load 的差异可被有意的 app 用来检测。
- 内核 `dmesg` 有 init/unload 和限频的失败日志，`kpm list` 可看到模块；
  两者都需要 root，普通 app 不可读。payload 文件路径的 SELinux
  `avc: granted { execute }` 也可能出现在 dmesg；lib 别名使用已安装的
  `apk_data_file`，不产生额外策略决定。

**第三方 app 的可见性**：会话按 mm 隔离且控制请求带 owner 检查；其他 app 的
QUERY 看不到活跃会话，SET/DEACTIVATE 返回 `ENOENT`，REGISTER 返回 `EBUSY`。
全局 hook 只做常数时间 magic/会话检查，不暴露目标地址、伪值或计数值。

## 4. 测试 app 与真机结果

测试 app：`apps/urov-app`（NativeActivity，无 Java 代码，targetSdk 35，
`extractNativeLibs` 默认，安装后由 linker 从 `/data/app/.../lib/arm64/` 映射）。
运行上下文实测：

```text
I urovapp : context=u:r:untrusted_app:s0:c30,c257,c512,c768
I urovapp : uid=10286  Seccomp: 2
I urovapp : QUERY rc=0 caps=0xeb7 state=0
I urovapp : prctl passthrough name=urovapp
```

### 4.1 自身 lib 代码页别名

`urov_payload` 是测试 lib 内的一个 7 指令叶子函数（`bti c; mov/movk...; eor; ret`）。
app 用 `dladdr` + ELF `PT_LOAD` 求出它的文件偏移，建立一页 `MAP_SHARED` RX 别名，
在函数第 2 条指令处注册 16 字节窗口：

```text
lib_alias: page=0x7569724000 in_page=0x7f0 file_off=0x37f0
lib_alias vma=7569724000-7569725000 perms=r-xs size=4096 path=/data/app/.../liburovapp.so
lib_alias registered offset=2036 length=16 generation=1
lib_alias execution after register (fetch original)
lib_alias execution after SET
lib_alias bench ns_per_1k normal=357 overlay=227749 overhead=637x
lib_alias STATUS rc=0 hits=65923 failures=0
lib_alias mprotect gate errno=16
lib_alias unsupported SIMD access fails closed
lib_alias DEACTIVATE rc=0 state=0
lib_alias execution after restore
lib_alias mprotect after restore errno=0
```

验证点：

- 数据读 1/2/4/8 字节、窗口两侧部分重叠、LDP 两个字按同一快照返回正确（含跨窗口边界的混合字节）；
- 同一函数从受保护页取指仍返回原值（`exec=0x1122334455667788`），证明没有改
  代码页，也没有用 fake 取指；
- SET 后全部读切换到新 fake，旧 generation 的 SET 返回 `EAGAIN`；
- 4 个并发读线程 + 128 次更新，`loops=1242 errors=0`；
- SIMD `ldr q0` 被 fail-closed 为 SIGSEGV；`mprotect` 活跃期 `EBUSY`，
  注销后恢复 0；
- 注销后所有读回到原值，执行结果不变。

### 4.2 私有 payload 页（MAP_SHARED）

```text
data_shared vma=7569724000-7569725000 perms=r-xs size=4096 path=/data/data/.../files/urov_overlay.bin (deleted)
data_shared registered offset=8 length=16 generation=1
data_shared bench ns_per_1k normal=357 overlay=227710 overhead=637x
data_shared STATUS rc=0 hits=65923 failures=0
data_shared unsupported SIMD access fails closed
data_shared DEACTIVATE rc=0 state=0
```

### 4.3 `MAP_PRIVATE` 负向用例

```text
data_private_reject vma=7569724000-7569725000 perms=r-xp size=4096 path=... (deleted)
data_private_reject: rejected errno=22 as designed
```

模块拒绝 `VM_MAYWRITE` 的私有映射，不把它当成“稳定 pin 页”。

### 4.4 所有权、死 owner 回收、卸载

```text
--- foreign while app owns session ---
query rc=0 errno=0 caps=0xeb7 state=0 session=0 gen=0 last_error=-16
set rc=-1 errno=2
deactivate rc=-1 errno=2
mode=... state=active ...

--- kill owner, then query ---
query rc=0 errno=0 caps=0xeb7 state=0 session=0 gen=0 last_error=0
mode=... state=inactive gen=0 hits=0 failures=0
```

卸载时 app 仍在每秒读取：

```text
--- before unload ---
HOLD t=3 read=0x8877665544332211 exec=0x1122334455667788
--- after unload ---
HOLD t=4 read=0xf2aaacc1d28ef101 exec=0x1122334455667788
```

`read` 从 fake 回到原字节，`exec` 始终正确；模块 `kpm list` 为空，`dmesg`
无 BUG/WARNING/Oops/RCU stall。

### 4.5 root 回归

原 `urov_overlay_test`（`__NR_kcmp` 通道、sealed memfd）仍通过：

```text
PASS scope=standalone_active_overlay widths=8,16,24,32 ordinary_loads=1,2,4,8,ldp
execution=42 update=verified gates=verified fork=blocked fail_closed=verified
concurrency=verified restore=verified
```

`urov_hold2_test` 在模块卸载时有 4 个持续读线程：`loops=104777277 errors=0
exec=42 value=<原值>`。

### 4.6 复现命令

```powershell
# 构建 KPM、root 测试程序、app
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-app\build-app.ps1 -Source app.c

# 自动安装 app、加载模块、跑 3 轮、检查状态并卸载
.\kpms\urov-lab\tools\run_app_device.ps1 -Key <KEY> -Iterations 3
```

手工生命周期实验：

```sh
adb push kpms/urov-lab/out/urov-lab.kpm /data/local/tmp/
adb shell '/data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/urov-lab.kpm active'
adb push kpms/urov-lab/out/urov_foreign_test /data/local/tmp/
adb push kpms/urov-lab/apps/urov-app/out/urovapp-hold.apk /data/local/tmp/
adb install -r -g /data/local/tmp/urovapp-hold.apk
adb shell am start -n com.example.urovapp/android.app.NativeActivity
# 看到 HOLD active 后：
adb shell /data/local/tmp/urov_foreign_test query      # state=0, last_error=-16
adb shell /data/local/tmp/urov_foreign_test set 1 1   # errno=2
adb shell /data/local/tmp/urov_foreign_test deactivate # errno=2
adb shell am force-stop com.example.urovapp
adb shell /data/local/tmp/urov_foreign_test query      # 触发回收；之后状态 inactive
adb shell '/data/local/tmp/kpatch <KEY> kpm unload urov-lab'
```

## 5. 限制与后续工作

1. **单会话**：全模块同一时间一个活跃页/会话；多个 app 需要串行。所有权和死
   owner 回收保证不会永久占用，但并发使用仍是后续工作。可扩展为每 mm 槽位表。
2. **单页/32 字节窗口**：覆盖区间必须在一页内；32 字节窗口需多条指令读取。
   多页范围、VMA split、每页 pin/快照与跨页慢路径未实现。
3. **仅 GPR load**：SIMD/FP、SVE/SME、exclusive/atomic、acquire、LDRAA/LDRAB、
   MTE tag、跨页 load 仍 fail-closed。
4. **页来源约束**：必须是一页、只读、可执行、文件后备、无 `VM_MAYWRITE`；
   `MAP_PRIVATE` 被拒绝。页内容必须在注册期间保持稳定（推荐已安装 lib）。
5. **设备/BTF 绑定**：`task_struct.mm=1440`、`mm_struct.pgd=56`、
   `mm_users=68` 来自本机 BTF；注册时用 `get_task_mm` 与 `mm_users` 做运行时
   校验，不匹配会拒绝注册。换内核/设备需重新核对。
6. **仍需 root 装卸模块**：这是 KPM 的授权模型，不是 app 能绕过的。
7. **检测面**：同步异常时序、专用映射/`dc` 标志、内核辅助读取看原值，是机制
   现状；没有承诺对任意反作弊/反调试完全不可见。
8. **性能**：约 0.23–0.47 µs/次覆盖读，比普通 load 慢 475–1175×。适合低频、
   关键读取点；高频循环应避免。

## 6. 文件

| 路径 | 说明 |
|---|---|
| `urov_abi.h` | 新增 `UROV_PRCTL_OPTION`/`UROV_PRCTL_MAGIC`/`UROV_CAP_PRCTL`；请求结构不变 |
| `urov_backend.c` | prctl 控制 hook、单页文件映射校验、owner/惰性回收、注销清零 |
| `apps/urov-app/app.c` | 普通 app 验收程序（lib 别名 + payload 页 + 并发/门控/fail-closed） |
| `apps/urov-app/probe.c` | 2026-11-03 的能力探针（seccomp/SELinux/memfd/lib 别名） |
| `apps/urov-app/build-app.ps1` | NDK 编译、aapt2/zipalign/apksigner 打包，`-Hold` 生命周期变体 |
| `tests/urov_foreign_test.c` | 非 owner 控制/回收探针 |
| `tools/run_app_device.ps1` | 构建、安装、加载、多轮 app 验收、状态检查、卸载 |
| `results/app-final-*.txt` | 本轮 app/生命周期/内核日志原始记录 |
