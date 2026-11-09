# UROV-Y 2.25.0：全采样宽度与读前写集证明

本文记录 `urov-y` 2.25.0 相对 2.24.0 的变更。目标是清掉 2.24.0 残余清单里普通 App
可构造的读侧特征——包括 2.24.0 复测自己发现的成对读取（`LDP`）特征——同时不新增
hook、线程、定时器、PTE/VMA、代码字或 ABI 字段。只改 `urov-y`、测试 App/夹具、构建
与文档。计时仍按题目允许保留。

## 1. 输入：2.24.0 仍然成立的特征

2.24.0 的复核（`APP_READ_INTEGRITY_RESULTS.md` 顶部「2.24.0 普通 App 成对读取复测」）
用 `LDXR; LDP Wt,Wt2; STXR` 把 AP 全调用者模式从「采信 96/96」打成「检出 96/96」。
原因是 `uy_llsc_prepare()` 只在故障指令是**单个标量 load** 时才建立预约计划。同一
门槛把其它一切非单标量采样形状也留在外面：

| # | 2.24.0 行为 | 普通 App 的构造 |
| --- | --- | --- |
| H22 | 故障指令 `count != 1` 时不建计划：`LDP`/`LDPSW` 采样整页 | `LDXR X9,[scratch]; LDP W10,W11,[target]; STXR W8,X9,[scratch]` |
| H23 | 故障指令是 SIMD&FP load 或 `LD1` 多结构 load 时不建计划 | `LDXR X9,[scratch]; LDR Q0,[target]; STXR W8,X9,[scratch]` |
| H24 | 故障指令是 load-exclusive 时解码失败，走 fail-closed，读本身变成 `SIGSEGV` | `LDXR W0,[target]; CLREX` |
| H25 | 读前窗口只接受整数 ALU/NOP/`MRS`/`PRFM`：FP 算术、普通 load/store、LSE 原子、扩展寄存器加法都让计划放弃 | `LDXR X9,[s]; FADD D0,D0,D0; LDRB W0,[target]; STXR W8,X9,[s]` 等 5 种 |
| H26 | 成对预约只在「`LDXP; load; STXP` 中间全是 NOP/BTI」时成立 | `LDXP W9,W10,[s]; LDRB W0,[target]; ADD W9,W9,#0; STXP W8,W9,W10,[s]` |

H22 是上一轮真机矩阵直接测到的；H23–H26 是同一份代码在 2.24.0 结构上可构造、
但上一轮未补测的类别。2.25.0 一并处理。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮只处理普通 App 的
EL0 读值与独占监视器可观察到的特征。

## 3. 方案

### 3.1 采样指令不再参与计划条件

`uy_llsc_prepare()` 不再看故障指令的形状。它只从故障指令向前找最近的
`LDXR/LDAXR/LDXP/LDAXP`，用 3.2 的写集证明确认那个预约仍然有效。采样指令本身
对预约没有影响：它在故障点之前没有写完（目的寄存器与写回都发生在故障之后），
所以它写哪个寄存器、写多宽、是否向量都不改变被监视地址。

三种形状因此自然覆盖：

| 采样指令 | 解码与提交 | 预约来源 |
| --- | --- | --- |
| `LDP`/`LDPSW`/`LDP Q`（`count == 2`） | 既有 `uro_decode` + `uy_commit`/`uy_fp_commit` | 窗口前的 `LDXR`/`LDXP` |
| `LDR Q`、`LDP Q`、`LD1..LD4` | 既有 FPSIMD 提交路径 | 同上 |
| `LDXR/LDAXR/LDXP/LDAXP` 本身 | 新增：`decode.c` 把独占 load 解码成普通 load，并带上 `excl`/`acquire` | 故障指令自己 |

独占 load 是唯一需要特例的形状：它是**新的**预约来源，所以 `uy_llsc_prepare()`
直接用它的地址与宽度建计划（`sample->excl`）。`LDXP` 建的是成对预约。这样
`LDXR W0,[target]; CLREX` 不再 `SIGSEGV`，后续消费它的 `STXR` 也拿到原生结果。

### 3.2 读前证明：写集而不是指令白名单

2.24.0 的读前证明只重放整数 ALU 一类指令，其它形状一律放弃。放弃就是特征：原生
`STXR` 成功、模块让 `STXR` 失败。2.25.0 把证明改成**写集证明**：

> 从故障指令向前每条指令只要满足「(a) 不可能清本地监视器，(b) 不可能写 LDXR 基址
> 寄存器」，就接受。

只有这两件事和预约有关。其余架构效果都已经发生，且不改变被监视地址。逐类实现
（`uy_pre_writes()`）：

| 类别 | 是否可能清监视器 | 写集 |
| --- | --- | --- |
| 整数数据处理（立即数/寄存器/扩展寄存器/进位加法/条件比较） | 否 | `Rd`，或 `Rd==31 && S==0` 时的 SP |
| 普通 load（标量/成对/字面量/写回） | 否 | `Rt`、`Rt2`、写回 `Rn` |
| 普通 store（标量/成对/`ST1..ST4`/`DC ZVA` 之外的写回） | 否（同 PE store 不清，2.24.0 实测） | 写回 `Rn` |
| LSE 原子（`LDADD` 族/`SWP`/`CAS`/`CASP`） | 否（2.24.0 实测） | 读回 `Rt`/`Rs` |
| SIMD&FP 数据处理与置换 | 否 | 无 GPR；仅 `FMOV`/`UMOV`/`SMOV`/`FCVT*`/`FJCVTZS` 写 `Rd` |
| `MRS`/`MSR`（仅 EL0 可读写的白名单寄存器） | 否 | `MRS` 写 `Rt` |
| `NOP`/`BTI`/HINT/`DMB`/`DSB`/`ISB`/`PRFM` | 否 | 无；PAC/AUT hint 记 `x17`/`x30` |

反过来，四类指令必须让计划放弃，因为它们**真的**清本地监视器：

```
CLREX                      清本地监视器
STXR/STXP/STLXR/STLXP      成功或失败都清本地监视器
SVC/HVC/SMC/BRK/HLT        异常入口清本地监视器
窗口内任一条是分支目标      LDXR 可能没执行（uy_llsc_skipped）
```

还有一类是**可能**清监视器的：会在 EL0 触发异常但不一定执行的编码。它们要么被
上面拒掉，要么在 `uy_pre_writes()` 里返回未知而让计划放弃——因为一条真正执行过的
指令一定不会在该位置触发异常，而一条会触发异常的指令已经清掉了监视器。

`MRS`/`MSR` 因此改成**白名单**：只有 `NZCV`、`FPCR`、`FPSR`、`TPIDR_EL0`（读写）与
`TPIDRRO_EL0`、`CNTFRQ_EL0`、`CNTVCT_EL0`、`CTR_EL0`、`DCZID_EL0`（只读）接受。
其余系统寄存器编码在 EL0 上非法，接受它们会让「异常 + 信号处理器跳过该指令」的
构造伪造成功。

### 3.3 成对预约走同一条通道

2.24.0 的成对路径有自己的前置扫描：`LDXP; load; [NOP/BTI]*; STXP`，最多 8 个槽，
中间任何真实指令都让计划放弃。2.25.0 删除这条独立路径：

- 读前证明统一（3.2）；
- 前向窗口统一走 `uy_llsc_walk()`（字节模型）或原生单步；
- `uy_llsc_walk()` 新增 `STXP` 完成分支，`uy_step_begin()` 接受成对计划，
  `uy_step_force_pair()` 沿用；
- 提交时成对计划也提交模型寄存器（间隙指令的效果）。

`LDXP W9,W10,[s]; LDRB W0,[target]; ADD W9,W9,#0; STXP W8,W9,W10,[s]` 因此由字节模型
直接完成，而不再依赖「间隙里只能有 NOP」。

### 3.4 SP 作为独占基址

`LDXR Wt,[SP]` / `STXR Wt,Ws,[SP]` 是合法编码。2.24.0 直接拒绝 `Rn == 31`，于是
原生成功、模块失败。2.25.0 把基址取值统一为「`Rn == 31` 取 SP」，读前写集里的
SP 用第 31 位表示，单步与字节模型的比较也走同一个辅助函数。约定：

```c
static uint64_t uy_pt_gpr(const struct pt_regs *regs, unsigned reg);   /* 31 -> SP */
static uint64_t uy_win_base(const struct uro_regs *model, unsigned reg); /* 31 -> SP */
```

### 3.5 读前扫描上限

2.24.0 的线性证明最多回看 1024 条指令；App 只要在 `LDXR` 与采样读之间放 1025 条
纯寄存器指令就能让计划放弃。2.25.0 把上限提到 4096 条（16 KiB 直线代码）。

## 4. 不引入新特征

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍只操作 `PAGE_AP` 的 `AP[1]` |
| 新的读视图 | 采样读仍走原 `read_range(allow_fake)`；独占 load 也走同一视图 |
| 新的写语义 | 只执行 App 自己的 store；`STXR/STXP` 只在地址/宽度/值匹配时由内核完成 |
| 新的失败 | 计划只有在证明 LDXR 执行且中间无 CLREX/独占 store/异常/`uy_pre_writes()` 未知时才完成 |
| 新的寄存器/标志结果 | 单步由硬件执行；字节模型的写集证明不重算任何数据通路 |
| 新的崩溃/信号 | 独占 load 现在按普通读模拟，不再 fail-closed；异常指令仍交回原生 |
| 新的线程/定时器/文件/ABI | 没有；`hooks=0xff`、ABI v8、`ctl0` 状态格式不变 |
| 新的计时台阶 | 每次未建模窗口仍最多一次有界单步；读前扫描从 1024 提到 4096 条（纯读页内字节） |

## 5. 残余（2.25.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读一次同步异常；未建模窗口每条指令一次软件步
   异常；长窗口按指令数线性增加。按题目允许保留。
2. **caller-window 语义**：非 all-callers 会话下只有会话调用者看到 image，独立读者
   仍看到活页，`split` 可被观察到。这是登记时选择的作用域语义，不是监视器特征；
   all-callers 会话 `split=0`。
3. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；不在
   普通 App 的输入集合内。
4. **pkey/POE**：本机无 POE，只验证拒绝/透传。
5. **其他 PE 的 store / 异步信号 / 抢占**：本地监视器在异常返回时被清，其他 PE 的
   store 清全局监视器；模型只跟踪本线程可见的事件。跨线程写同一 scratch、抢占或
   异步信号可让原生 `STXR` 失败而模型仍完成。普通 App 只能靠计时/调度构造，归入
   计时或跨线程残余；生产 CRC 不在 LDXR/STXR 窗口内做跨线程写。
6. **同步故障 + 信号处理器跳过**：读前窗口里放一条会同步故障的指令（例如访问未映射
   地址的 `LDR`），再用 `SIGSEGV` 处理器把 PC 前移。异常入口会清本地监视器，于是
   原生 `STXR` 失败；模块的写集证明看不到「已经发生过一次异常」。2.25.0 只保证
   **不新增**这类形状（2.24.0 的白名单读前窗口同样无法证明它），并把这一类归入
   信号残余，而不是读值特征：它需要 App 自己装信号处理器并改写 PC。
7. **间接分支寄存器启发式**：`uy_llsc_indirect()` 在任一 GPR 仍指向窗口内部地址时
   让计划放弃。故意的 `ADR` 指向窗口会让计划放弃，从而让原生成功的 `STXR` 失败。
   换成「只看直接分支目标」会放过真正跳到窗口中段的形状，因此保留保守一侧。
8. **SVE/SME 目标页 load**：本机无 SVE/SME；有该扩展的设备需要按 2.24 的 §3.4 边界
   处理。
9. **读前窗口的未分类编码**：`DC ZVA`、`LDRAA/LDRAB`、SVE/SME 数据处理等不在
   `uy_pre_writes()` 的白名单里，仍让计划放弃。本机不启用这些编码（或需要 PAuth 的
   签名指针），因此不作为普通 App 的稳定特征。
10. **读前扫描上限**：超过 4096 条直线指令仍放弃，属有界内核工作量。
11. **单步生命周期**：计划成立后如果没有消费它的独占 store，任务会逐条单步到下一次
    系统调用或独占指令。这是计时开销，不是读值或状态特征。

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`c00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
`/proc/cpuinfo` 无 SVE/SME。模块 `urov-y.kpm` SHA-256
`1623c6e3eca92ec7f3c8eb5201615f53421cd1d9c96ed92e1f5fe9d5761a7bcc`（可重现），测试 APK
SHA-256 `2abc53ad81d0408c6dd3441ac983baa39f73d859613657178accf85455585367`（APK 的 zip
时间戳使重打包不同；原生库 `liburovdetect.so` 为
`59789f29ebacfa19017da66b8414b9a8feaed0ce40002f00454e7752b231d627`），窗口模型测试
SHA-256 `fa89b24004feffef6e965ecb5213a869efc36a6a61ce44e87c2c7e218dd9658c`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v225` 6 模式 ×3（每阶段 32 次） | PASS；21 次启动；AP-all overlay `split=0 evidence=0 accepted=32`，全部 9 个新探针 `0`，`xldr_bad=0 xldr_done=32` | [read-defense-v225-20261110-004656](results/read-defense-v225-20261110-004656/summary.json) |
| 生产 CRC 7 模式 ×1（每阶段 3 次） | PASS；`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235` | [crc-20261110-005321](results/crc-20261110-005321/summary.json) |
| 消除矩阵 3×1 | PASS；`site_call_ns=507`，全部 `ELIM_CASE` 通过 | [eliminate-20261110-005341](results/eliminate-20261110-005341/summary.json) |
| 多页 6 场景 ×1 | PASS | [multipage-20261110-005458](results/multipage-20261110-005458/summary.json) |
| 窗口模型差分测试 | PASS；`cases=145 failures=0` | `out/urov_window_test` |

AP-all overlay 的关键日志：

```text
READ_DEFENSE_V225_POLICY stage=overlay n=32 pre_alu=0 fp=0 ap=0 ap_unknown=0
    split=0 evidence=0 changed=0 unknown=0 accepted=32
READ_DEFENSE_V225_RESIDUAL stage=overlay n=32 leaf_call=0 permute=0 fp_arith=0
    pre_mov=0 pre_long=0 self_bad=0 neon_bad=0 self_done=32 neon_done=32
    deep_bad=0 deep_done=32
READ_DEFENSE_V225_BOUNDARY stage=overlay n=32 ap=0 ap_unknown=0 evidence=0
    unknown=0 accepted=32
READ_DEFENSE_V225_PROBE stage=overlay n=32 pair=0 vec=0 multi=0 pre_fp=0
    pre_load=0 pre_store=0 pre_lse=0 pre_ext=0 pair_gap=0 unknown=0
    trials=27648 xldr_bad=0 xldr_done=32
```

- **H22**：`LDP Wt,Wt2` 采样在 AP 全调用者模式仍是 `pair=0`；2.24.0 的对照见
  `--read-defense-v224`，同一份夹具在 2.25.0 上停在 `v224 LDP ... ap=0/3`
  （`results/read-defense-v224-20261110-005527`），即旧判定不再检出。
- **H23**：`LDR Q` 与 `LD1 {v0,v1}` 采样 `vec=0 multi=0`。
- **H24**：`LDXR` 读采样页不再崩溃。同一夹具在 2.24.0 上以
  `Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)` 终止（同上目录），2.25.0
  `xldr_bad=0 xldr_done=32`。
- **H25**：读前窗口的 FP 算术、普通 load/store、LSE 原子、扩展寄存器加法全部静默。
- **H26**：`LDXP; LDRB; ADD; STXP` 静默。
- 窗口模型测试新增 3 组分类用例（FP/SIMD 组、GPR 目标分类、SP 基址命名），
  `cases` 121 → 145。
- 会话结束 `kpm list` 为空，boot ID 不变，增量内核日志无 BUG/WARNING。

### 6.1 单步生命周期修复（实测发现）

把 2.25.0 的探针加到 32 次 ×3 轮后，真机在持续高强度 AP 矩阵约 4–5 分钟后出现过
内核 panic（`ro.boot.bootreason=kernel_panic`，产测镜像带 `softlockup_panic=1`）。
原因是 2.24.0 的单步在“预约已被 CLREX/独占 store/异常清掉”之后仍逐条跟随任务，
直到它下一次执行独占 store；新加的 `LDXR` 采样探针正好制造了大量这种尾巴。修复：
`uy_step_handle()`/`uy_step_resume()` 在 `uy_step_prev()` 发现 `valid == 0` 时立即结束
单步——此后任何 `STXR` 的建模结果都是失败，继续跟随没有意义。修复后同一矩阵
（21 次启动、6 模式 ×3 轮）连续通过，无 panic、无 boot ID 变化。这是纯开销与稳定性
修复，不改变任何读值或独占结果。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v225 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```
