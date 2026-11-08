# UROV-Y 2.13.0 读取特征消除方案

本文是 `urov-y` 2.13.0 的设计说明。目标只有一个：把
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.12.0 节里
**普通 App（`untrusted_app`、`CapEff=0`、`Seccomp=2`）无需密钥仍可稳定使用**的
两个读路径特征消掉，并且不引入新的可观测特征。只改 `urov-y`，不碰
`urov-lab` 基础版与 `urov-x`。

## 1. 输入：2.12.0 仍成立的两个特征

2.12.0 已经覆盖了 EL0 标量/向量读、libc 传输、同/跨 mm 的
`process_vm_readv`、`/proc/<pid>/mem`、`ptrace` 和 `access_process_vm()`；
`mlock`、无效 `madvise`、同权限 `mprotect(RX)`、`fork`/`vfork` 也不再结束
会话。复核后仍有两个普通 App 可以直接使用、且不需要任何模块密钥的特征：

| # | 2.12.0 行为 | App 侧用法 | 2.12.0 证据 |
| --- | --- | --- | --- |
| E1 | AP 桥只接受“故障 load 的 `PC+4` 就是 `STXR`”，因此 `LDXR; LDRB; NOP; STXR` 的目标 `STXR` 在 `ERET` 后失败 | 用 `LDXR` 读线程私有 scratch、`LDRB` 读目标字节、`NOP`、`STXR` 写回 scratch；目标失败而同一文件同一偏移的对照成功即 `MATCH` | `DOBBY_DETECT_AP match=48/48`；`accepted_crc_with_ap=0` |
| E2 | 映射门控先按范围重叠撤销会话，之后才交给 Linux 做参数校验；`mprotect(page+1, 1, PROT_READ)` 返回 `EINVAL`，但会话已经被拆掉 | 对已登记页调用非对齐 `mprotect`；返回 `EINVAL` 与未加载模块相同，随后 CRC 读到真实改码字节 | `DOBBY_DETECT_RESTORE ... inactive_after_keyless=1`；2.12.0 文档把这条列为“撤销本版 AP 的当前会话”的恢复方法 |

E1 是**架构性**的独占预约丢失：异常进入/返回会清本地监视器，原生的
`STXR` 必然失败。2.12.0 已经对紧邻和“load 前 NOP”的序列代写 store，但
没有向后看穿过 load 后的 `NOP`，所以检测器把 NOP 放在 load 与 `STXR`
之间即可稳定命中。E2 不是架构边界，而是门控顺序问题：Linux 在真正改
VMA 之前就会拒绝这个调用，模块却先拆了会话。

## 2. 威胁模型

生产环境的代码段 CRC 只有两类信息来源：

1. **读者看到的字节**：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`。
2. **读者能观察到的副作用**：映射属性、页表统计、异常、独占监视器、
   耗时、崩溃、系统调用返回值。

2.13.0 只处理“普通 App 不需要密钥就能稳定重复”的 E1/E2。它不试图消除
架构代价（每次读一次同步异常、`ERET` 清监视器）、生命周期操作（把页
改成可写、`munmap`、`execve`）或 root 可见性；这些要么无法在不改变
程序语义的前提下消除，要么需要新增可观测状态。

## 3. 方案

### 3.1 有界前向 LL/SC 窗口（消 E1）

`PAGE_AP` 的 fault handler 仍然只接管数据读异常，不改代码字、VMA 或
叶 PTE 的其它位。`uy_llsc_prepare()` 在故障 load 之后做**有界前向扫描**：

- 从 `PC+4` 开始最多看 8 条指令；
- 只允许 `NOP`、`BTI C`、`BTI J`、`BTI JC` 作为间隔；
- 遇到 `STXR/STLXR` 即候选；遇到任何其它指令（`CLREX`、`SVC`、另一次
  load/store、ALU 写寄存器等）立即放弃；
- 仍要求 `LDXR/LDAXR` 在 load 前 0–3 条 `NOP` 内、宽度相同、基址相同、
  `LDXR` 目的寄存器仍等于 `[Xn]`、`STXR` 待写值等于当前内存；
- 仍经过已有的“全进程直接分支位图”和“GPR 里仍有区间地址”门控；
- 提交时写入 `STXR` 自己的值、把状态寄存器置 0，并把 `PC` 设为
  `STXR+4`。间隔里的 `NOP/BTI` 不改变架构状态，跳过它们与原生执行等价。

为什么这能消 E1：检测器的 `LDXR; LDRB; NOP; STXR` 中，`LDXR` 已经在
故障前执行并建立了预约；唯一打断它的是模块制造的读异常。handler 现在
补做 `STXR` 本来会做的 no-op store 并报告成功，目标与对照都得到
`status=0`，探针只能报 `NO_MATCH`。这不是“伪造成功”：如果没有模块，
该序列的 `STXR` 会成功；模块只是恢复了异常返回抹掉的预约结果。

为什么不是新特征：

- 只对 `NOP/BTI` 间隔生效；任何可能清监视器或改寄存器的指令都让桥
  放弃，保持原生失败；
- 不新增 ABI、hook、`ctl0` 字段、文件、线程、定时器或返回码；
- 不改代码字、VMA、`smaps`、页表统计或合法映射语义；
- `llsc` 计数器仍只是 root 侧 `ctl0 status` 文本，App 不可见；
- 读取路径的额外工作只在 fault 内做一次有界扫描，正常读不增加分支。

### 3.2 映射门控参数预校验（消 E2）

`uy_gate_before()` 在拿控制锁、检查重叠、调用 `release_session()` **之前**
先做 Linux 在 mmap 锁之前会做的参数校验：

- `mprotect` / `pkey_mprotect`：地址页对齐、范围不越过 `TASK_SIZE`、
  `prot` 只含已知位；
- `munmap` / `madvise`：地址页对齐、范围不越过 `TASK_SIZE`；
- `mremap`：旧地址对齐、范围合法、flags 只含 `MAYMOVE|FIXED|DONTUNMAP`，
  `MREMAP_FIXED` 必须同时带 `MAYMOVE`，新地址对齐；
- `mmap(MAP_FIXED)`：地址对齐、范围合法。

参数非法时直接返回，让原生 syscall 按 Linux 的路径返回 `EINVAL`（或
`ENOMEM` 等），**不碰会话**。参数合法时保持 2.12.0 的策略：

- 同权限/仍为 `READ|EXEC`、不含 `WRITE` 的 `mprotect`：会话保活，after
  hook 重装陷阱；
- 改成可写、`munmap`、`mremap`、`MAP_FIXED` 覆盖、owner `execve`：仍结束
  会话（见 §5）。

为什么不是新特征：

- 只对 Linux 本来就会拒绝的调用跳过释放；对合法调用行为不变；
- 不改变任何 syscall 的返回码；`EINVAL` 仍由 Linux 返回；
- 不改 VMA、PTE、`smaps` 或映射身份；
- 没有新增 hook；`mprotect` 等 gate 的 before/after 仍是原有两个回调。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 `prctl` 指纹 | 没有新命令、selector 或请求布局；未认证请求仍是原生 `EINVAL` |
| 新的 VMA/`smaps` 差异 | 只改叶子 PTE 的 `AP[1]`；门控预校验不写 VMA |
| 新的代码字差异 | `PAGE_AP` 不改代码页；前向桥只改寄存器和 PC |
| 新的崩溃 | 非法映射调用现在直接透传，和未加载模块一致；合法调用仍走 2.12.0 的恢复/重装 |
| 新的错误码 | 非法参数由 Linux 返回原错误码；模块不新增返回码 |
| 新的 hook 计数 | 没有新 hook；`hooks=0xff` 与 2.12.0 相同 |
| 新的映射身份 | 不 split VMA、不额外 mmap、不改 `vm_file` |
| 新的 store 语义 | 只有 `LDXR` 结果仍在寄存器、值等于内存、且间隔全是 `NOP/BTI` 时才代写；写的是 `STXR` 自己的值 |
| 新的计时台阶 | fault 内多一次最多 8 条指令的有界扫描；实测 `site_call_ns=280`，与 2.12.0 的 285/286 同量级 |

## 5. 残余（2.13.0 仍不做的事）

1. `LDXR XZR; ...; STXR XZR` 且目标内存非零时仍不代写：`XZR` 没有可验证的
   执行存证，代写零可能改变未执行 `LDXR` 的内存。测试保留 `nonzero` 正
   对照，证明模块不会盲目写。
2. `LDXP/STXP` 成对独占、非 `NOP/BTI` 间隔、`CLREX`/`SVC` 间隔仍不桥；
   这些是 fail-closed 的残余，不是新增能力。
3. 每次数据读仍一次同步异常；桥的 store 仍是内核 nofault 普通写，不是
   硬件独占 store；计时仍可区分（架构边界）。
4. `mprotect` 把页改成**可写**、`munmap`/`mremap`/`MAP_FIXED` 覆盖、owner
   `execve`、进程退出仍结束会话：页本身可写或被替换，`PAGE_AP` 没有
   store 解码，无法在可写页上保持只读陷阱。
5. `fork` 子进程把自己的拷贝改成可写后，该子进程失去覆盖；孤儿陷阱修复
   只在模块仍加载时可用。
6. PTE 重装窗口仍在，限 `handle_mm_fault` 内部；`fork` 继承的陷阱不重建
   会话状态；`REGISTER` 之后新建匿名可执行页的间接分支仍按既有位图残余
   处理。
7. `caller_count>0` 的窗口语义不变；生产覆盖请用 `caller_count=0`。
8. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；`seccomp` 仍可由
   App 自己拒绝 `prctl` 控制面（进程策略，不是模块特征）。
9. `pkey_mprotect` 的 pkey 取值、`remap_file_pages` 的架构特定参数没有
   逐项镜像 Linux 校验；只有本文列出的常见预校验路径被覆盖。

## 6. 验证计划与结果

在 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00` 上，用现有测试 App 的四个矩阵复跑，并把 E1/E2 的断言改成“特征
已消除”：

| 矩阵 | 新增/改写的断言 | 结果 |
| --- | --- | --- |
| `dobby-detect` 48×3 | overlay 阶段的 AP 探针由 `MATCH` 改为 `NO_MATCH`；`DOBBY_DETECT_RESTORE` 断言非对齐 `mprotect` 后会话仍 ACTIVE、镜像仍在，再由认证 `DEACTIVATE` 结束 | PASS；3 个活动进程各 `ap=0/48`、`accepted_crc_with_ap=48/48`，合计 144/144；`active_after_keyless=1`、`inactive_after_deactivate=1`、`deactivate_errno=0` |
| `crc` 9 项 ×2 | 不改业务断言；确认门控预校验没有破坏 BRK/UXN/AP/AP-all/text/libc/big | PASS，16 次运行 |
| `eliminate` 3×1 | `w-active` 的 AP 探针由 `MATCH` 改为 `NO_MATCH`；保留 `nonzero` 正对照 | PASS，11 次运行、21 个 case、63 次观测；`exclusive_match=0`、`reader_match=0`、`ap_match=0`、6048 个 accepted triplets、0 个目标 store 失败 |
| `multipage` 5×1 | 不改断言；确认 24 页/96 KiB 五条读路径与 fork 子进程 | PASS，6 次运行；`mp-prod pages=24 bytes=98304 paths=5 child_overlay=1` |

构建与真机数据见
[APP_READ_INTEGRITY_RESULTS.md 的 2.13.0 节](APP_READ_INTEGRITY_RESULTS.md#2130-普通-app-的-ap-探针与无效映射门控消除)。
