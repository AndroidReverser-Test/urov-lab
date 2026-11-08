# UROV-Y 2.15.0：写入吸收与 XZR 桥接

本文是 `urov-y` 2.15.0 的设计说明。目标：把
[ELIMINATION_2_14_DESIGN.md](ELIMINATION_2_14_DESIGN.md) §5 中仍能被普通 App
稳定复现的**写入退役**与 **XZR 非零哨兵**两类特征消掉，同时不引入新的可观测
特征；只改 `urov-y` 与测试 App，`urov-lab`、`urov-x` 不动。ABI 仍为 v8。

## 1. 输入：2.14.0 仍成立的两类特征

2.14.0 已让保护切换、无效映射调用、`/proc/<pid>/mem`、`ptrace`、
`process_vm_readv` 和 EL0 读路径看到同一镜像。复核代码与真机后，普通 App
（`untrusted_app`、`CapEff=0`、`Seccomp=2`）仍有两个不需要密钥、稳定可重复的
特征：

| # | 2.14.0 行为 | App 侧用法 | 2.14.0 证据 |
| --- | --- | --- | --- |
| E5 | 第一次真实 store 把页 `dead`：`AP[1]` 被恢复，Linux 完成 COW，后续读走真实字节 | `mprotect(RW)` 后写一个字节（包括写回原值），再读同一页；读到 Dobby 改写后的真实代码 | `ELIM_PROT ... store_retired=1`；`st.reserved` 降为 0 |
| E6 | `LDXR XZR; LDRB; [NOP]; STXR XZR` 只在目标字为零时桥接；目标字非零时 `STXR` 必然失败 | 把 scratch 预置为非零，执行同一条序列；目标/对照的 `status` 不同即为 `MATCH` | `ELIM_CASE ... nonzero_match=3` |

E5 不是架构边界：异常处理可以先解码 store、由内核自己完成等价写入，再把
`AP[1]=0` 装回去。E6 也不是架构边界：`XZR` 没有寄存器值可作“执行存证”，但
控制流证据（LDXR 的固定 PC、全进程直接分支位图、故障时 GPR 中的间接分支目标）
仍然成立。

本轮只处理 E5/E6。2.14.0 §5 的其余条目——`munmap`/`mremap`/`MAP_FIXED`/
`execve` 生命周期、`fork` 子进程的私有拷贝、`LDXP/STXP`、非 `NOP/BTI` 间隔、
原子 RMW、`pkey_mprotect`/shared `remap_file_pages`——不在本轮范围内，仍按
§5 明列。

## 2. 威胁模型

生产代码段 CRC 的输入仍只有两类：

1. **读者看到的字节**：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`。
2. **读者能观察到的副作用**：映射属性、页表统计、异常、独占监视器、耗时、
   崩溃、系统调用返回值。

2.15.0 在 2.14.0 的读侧之上补齐“写侧不再把镜像打掉”，并让
`LDXR XZR` 的非零目标与零目标得到同一个原生结果。它不声称消除每次读一次的
同步异常、真实写入后的 COW 计时、生命周期操作或 root 可见性；这些要么是
架构代价，要么不在生产 CRC 的输入集合内。

## 3. 方案

### 3.1 写入吸收：解码、内核代写、镜像发布

`PAGE_AP` 的写异常不再直接交给 Linux。`uy_store_emulate()` 在
`do_mem_abort()` 的原生路径之前：

1. 从注册页快照（或 `copy_from_user_nofault`）取出故障指令，用
   `uro_decode_store()` 解码。支持：
   - GPR 单寄存器 `STRB/STRH/STR/STRX`，imm12、unscaled、pre/post-index、
     register-offset 形式；
   - GPR `STP`（4/8 字节元素）；
   - SIMD&FP 单寄存器 `STR B/H/S/D/Q`，含 pre/post-index；
   - SIMD&FP `STP`（4/8/16 字节元素）；
   - `ST1/ST2/ST3/ST4` 多结构 store（post-index 立即数/寄存器）；
   - `DC ZVA`（64 字节对齐的 64 字节清零）。
2. 校验故障地址就是解码出的首地址、整个访问不跨注册页、当前 VMA 有
   `VM_WRITE`，并且 `g_write_gup_flags` 可用。
3. 对每个段调用 `uy_access_vm(mm, addr, bytes, size, FOLL_WRITE|FOLL_FORCE)`。
   这是内核自己的 COW/GUP 写路径：私有文件页照常 COW，`smaps` 的
   `Private_Dirty`/`Anonymous` 与原生写入一致；共享可写叶照常写页缓存。
4. 把同一批字节发布到 `p->image` 和 `p->snapshot`。每个页新增内部 `seq`，
   写者发布奇数、复制、发布偶数；`page_view()` 读到奇数或前后不一致时重试，
   超时退回完整快照，读者不会看到半条 store。
5. 提交 base 寄存器写回（pre/post-index），`regs->pc += 4`，`IC IALLUIS`。
   原 store 不再执行，`AP[1]=0` 保持。

解码失败、跨页、VMA 不可写或内核代写失败时，退回 2.14.0 的处置：只把这一页
的 `AP[1]` 恢复、置 `dead=1`、不 `skip_origin`，让原生 store 继续。该页此后
走真实字节，其他页不受影响；这是 fail-closed 的残余，不是本轮新增能力。

### 3.2 可写陷阱叶：COW 之后仍保持 AP[1]=0

2.14.0 的 `page_set_ap()` 要求叶 PTE 带 `PTE_RDONLY`，因此第一次 COW 之后
的 writable 叶无法再装陷阱。2.15.0 新增 `page_set_ap_any()`：

- 装陷阱：清 `PTE_USER`（AP[1]=0），不要求 AP[2]，允许 COW 后的可写叶；
- 撤陷阱：置 `PTE_USER`，不要求 AP[2]，保证 `release_session()` 能恢复
  已被 store 改成可写的叶。

`uy_leaf_signature()` 相应接受 AP[2]=0/1 两种叶；`page_pte_leaf()` 仍拒绝
`PTE_CONT/PTE_SPECIAL/PTE_DEVMAP/PTE_PROT_NONE`。`ap_protection_update()` 与
`uy_mm_fault_after()` 改用 `page_set_ap_any()`：

- `mprotect(PROT_READ|PROT_WRITE)` 后叶仍是只读 COW 时直接装陷阱；
- 第一次吸收 store 触发 COW 后，`handle_mm_fault` 的 after hook 在返回 EL0
  前重新装 `AP[1]=0`；
- 真正无法承载陷阱的叶（special/devmap/contiguous）仍只退役该页。

### 3.3 内核辅助写：`/proc/<pid>/mem`、`ptrace` POKE

`__access_remote_vm` 的 after hook 原先只处理 `FOLL_WRITE` 之外的读。
2.15.0 在 `FOLL_WRITE` 且目标 mm 是 owner 时，把内核缓冲区里已经写下的字节
按页发布到 `image`/`snapshot`。这样紧随其后的 EL0 读能看到这次写，陷阱不被
退役；fork 子进程的私有 COW 拷贝不更新父镜像（仍按 §5 的残余处理）。

### 3.4 XZR 非零目标：控制流证据替代寄存器存证

`uy_llsc_prepare()` 对 `LDXR/LDAXR XZR; load; [NOP/BTI...]; STXR/STLXR XZR`
不再要求 `[Xn]` 当前为零。`XZR` 没有可比较的寄存器值，证明改为：

1. `LDXR` 位于故障 load 前 0–3 条 `NOP` 内；
2. `uy_llsc_skipped()`：全进程直接分支位图没有入口落在
   `[ldxr_pc+4, load_pc]`；
3. `uy_llsc_indirect()`：故障时 `x0..x30` 没有任何值（含去掉 MTE/PAC 高位后的
   值）落在同一区间；
4. 故障 load 不写 `Xn`、不写 `STXR` 的数据/状态寄存器；
5. `STXR` 自己的值等于 `XZR`（零），宽度/基址与 `LDXR` 一致。

提交时写 `STXR` 自己的零值、把状态寄存器置 0、`PC` 设为 `STXR+4`。这与
`LDXR` 确实执行时的原生结果一致；如果控制流绕过了 `LDXR`，第 2/3 条会拒绝。
零目标与非零目标因此得到同一个 `NO_MATCH`。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 写入走内核 COW/GUP，`Private_Dirty`/`Anonymous` 与原生首写一致；模块不改 VMA |
| 新的代码字差异 | 仍只改叶 PTE 的 AP[1]；store 写入的是 App 自己的值，镜像与原生页同步 |
| 新的崩溃 | 不支持的 store 仍退回 2.14 的“恢复 AP[1] + 原生 store”；非法写仍原生 SIGSEGV |
| 新的错误码/返回码 | `mprotect`/`mmap` 等返回值仍来自 Linux；模块不新增返回码 |
| 新的 hook/ABI/字段 | 没有新 hook；`hooks=0xff`、ABI v8、请求布局、`ctl0` 文本格式不变；`seq` 只在页内部 |
| 新的线程/定时器/文件 | 没有新增 |
| 新的写语义 | 写入的地址、宽度、值、写回和 COW 都由原指令与内核决定；模块只把同一批字节同步进镜像 |
| 新的计时台阶 | 读路径不变；首写多一次解码+GUP，原生首写本来就有 COW fault；`site_call_ns` 仍与 2.14 同量级 |
| XZR 误写 | 仍要求直接分支位图、GPR 目标、寄存器重叠和宽度/基址一致；不满足就保持原生失败 |

## 5. 残余（2.15.0 仍不做的事）

1. **生命周期**：`munmap`/`mremap`/`MAP_FIXED` 覆盖仍结束整个会话；`execve`
   仍按 owner 线程组结束；`fork` 子进程把自己的拷贝改成可写后，该子进程的
   私有 COW 页走真实字节。生产 CRC 只读代码段，不使用这些路径。
2. **不支持的写形状**：原子 RMW（`LDADD`/`SWP`/`CAS`/`CASP`）、
   `STXR/STLXR` 写注册页、SVE/SME store、跨页 store 仍退回 2.14 的按页退役。
3. **成对独占**：`LDXP/STXP`、`LDAXP/STLXP` 尚未桥接；非 `NOP/BTI` 间隔仍
   fail-closed。
4. **`pkey_mprotect` 的已分配 pkey/POE 权限**、shared VMA 的合法
   `remap_file_pages` 仍保守处理；本机 App seccomp 对 syscall 288 直接
   `SIGSYS`，无法从 `untrusted_app` 覆盖。
5. 每次数据读仍一次同步异常、每次写入仍一次 EL0 权限异常；计时/PMU 仍是
   架构边界。
6. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；`ctl0` 文本格式不变。

## 6. 验证计划与结果

在 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00` 上复跑四个矩阵，并新增写入形状断言：

| 矩阵 | 新增/改写的断言 | 结果 |
| --- | --- | --- |
| `dobby-detect` 48×3 | `accepted_crc_with_ap=48/48`、`ap=0/48`；`ELIM_PROT` 的 store 不再退役 | PASS |
| `crc` 5×2 | 16 次运行，`crc-ap-*` 的 mprotect(R/RW/RX) 与业务 CRC 全部等于镜像 | PASS |
| `eliminate` 3×1 | `ELIM_PROT ... store_absorbed=1`；`ELIM_PROT_STORE shapes=11`；`nonzero_match=0`；`ELIM_PROT_KWRITE` 在 SELinux 允许时 PASS | PASS |
| `multipage` 5×1 | 24 页/96 KiB 五条读路径与 fork 子进程 | PASS |

## 7. 构建与真机结果

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。App 在 `untrusted_app` 域，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。

```text
urov-y.kpm      5fa88121848de7818eede63ce2e71e021b2af47a4a0592609e76e124f88cc6be
urovdetect.apk 5104264ba4db14c1bfd460a52e49235188eba74dbd0a2fbbb34a3d7676767f2c
```

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 48×3 | PASS；3 个活动进程各 `ap=0/48`、`bytes_differ=0`、`accepted_crc_with_ap=48/48`；合计 `ap=0/144`、`accepted_crc_with_ap=144/144`、`views=0/144`、`xzr=0/144`、`cross_page=0/144` | [dobby-detect-20261108-122951](results/dobby-detect-20261108-122951/summary.json) |
| CRC 5×2 | PASS，16 次运行；`crc-ap-*` 的 `mprotect(R/RW/RX)` 三阶段普通 CRC 都等于镜像，`STATUS` 仍 ACTIVE | [crc-20261108-123036](results/crc-20261108-123036/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行；`ELIM_PROT ... store_absorbed=1`、`ELIM_PROT_STORE shapes=11 smaps=1 dirty_kb=4 anon_kb=4`、`nonzero_match=0`、`ELIM_PROT_KWRITE skipped errno=13`（SELinux 拒绝 App 写 `/proc/self/mem`）；`site_call_ns=305` | [eliminate-20261108-123118](results/eliminate-20261108-123118/summary.json) |
| 多页 5×1 | PASS，6 次运行；`mp-prod` 24 页/96 KiB、`paths=5`、`child_overlay=1` | [multipage-20261108-123233](results/multipage-20261108-123233/summary.json) |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

2.14.0 的对照：

| 阶段 | 2.14.0 | 2.15.0 |
| --- | --- | --- |
| `mprotect(RW)` 后写一个字节 | 该页 `dead`，后续读真实改码字节 | 会话 ACTIVE、`armed=1`，后续读仍等于镜像 + 该字节 |
| 写窗口内 8 字节 | 无（页已退役） | 读回镜像窗口的新值，状态仍 ACTIVE |
| `LDXR XZR` + 非零 scratch | `STXR` 失败，探针 `MATCH` | `STXR` 成功、scratch 置 0，探针 `NO_MATCH` |
| 写形状 | 仅相邻 LL/SC 桥 | `STRB/H/W/X`、`STP`、`STR` SIMD、`STP Q`、`ST1`、`DC ZVA`、pre/post-index 共 11 种 |
