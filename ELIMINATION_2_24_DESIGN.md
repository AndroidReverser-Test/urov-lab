# UROV-Y 2.24.0：线性读前证明与全放行原生单步

本文记录 `urov-y` 2.24.0 相对 2.23.0 的变更。目标是清掉 2.23.0 残余清单中普通 App
可构造的读侧特征，同时不新增 hook、线程、定时器、PTE/VMA、代码字或 ABI 字段。只改
`urov-y`、测试 App/夹具、构建与文档。计时仍按题目允许保留。

## 1. 输入：2.23.0 仍成立的两类残余

2.23.0 的字节模型和原生单步共用 `uy_llsc_prepare()` 的读前验证：

| # | 2.23.0 行为 | 普通 App 的构造 |
| --- | --- | --- |
| H19 | 值链要求 LDXR 结果在故障 load 前仍可重建；`LDRB Wt` 覆盖 `LDXR` 的 `Wt` 时整窗放弃 | `LDXR X9,[scratch]; LDRB W9,[target]; STXR W8,XZR,[scratch]` |
| H20 | 原生单步只允许能解码的普通 load/store、分支和寄存器指令；SIMD/SVE/SME 存储、未解码编码、重叠监视字的 store 和 4096 条上限都失败关闭 | 窗口内放一条 `ST1 {V0.B}[0]`、一条 LSE 原子、一条 4097 条指令的循环或一个未来编码 |
| H21 | 单步路径对 `LDXP/STXP` 一律放弃；`LDXR` 之后的第二个成对预约占满窗口时原生 `STXP` 失败 | `LDXR; LDRB; LDXP; STXP` |

H19 是 2.23.0 最新一轮实测发现的稳定特征（`READ_DEFENSE_V223_BOUNDARY`）。H20/H21
在 2.23.0 设计 §5.5 中作为单步失败关闭类别列出，但普通 App 可用短序列直接构造。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮只处理普通 App 的 EL0
读值与独占监视器可观察到的特征。

## 3. 方案

### 3.1 线性读前证明取代值链

`uy_llsc_prepare_single()` 不再要求 LDXR 的结果到达故障 load。新的证明是：

- 从故障 load 向前扫描，直到最近的 `LDXR/LDAXR`；
- 中间每一条都必须是 `uy_win_alu()` 接受的纯寄存器指令（整数 ALU、条件选择、
  ADR/ADRP、NOP/BTI、DMB/DSB/ISB、EL0 可读 `MRS`、`NZCV/FPCR/FPSR/TPIDR_EL0`
  的 `MSR`、`PRFM`）；任何 load/store、分支、原子、`CLREX`、未建模编码都停止；
- `uy_code_hit()` 拒绝块内分支目标，`uy_llsc_skipped()` 与 `uy_llsc_indirect()` 保留
  原有的直接/间接分支门控；
- LDXR 基址寄存器在故障前不得被重写，故障 load 也不得写它（写回同理），否则
  `regs->x[Rn]` 已不是被监视地址；
- 扫描上限 1024 条，止于基本块边界（分支目标）或非纯寄存器指令。

因此 LDXR 的执行由线性控制流证明，而不是由数据依赖证明。`LDRB W9` 覆盖 LDXR 的
`W9`、`MOV X9,#0` 之类不再让计划放弃。`LDXR XZR` 也不再要求 STXR 使用 `XZR`。
[线性读前证明](urov_y_backend.c#L2738) · [分支门控](urov_y_backend.c#L2364)

### 3.2 原生单步全放行

2.23.0 的单步路径逐条解码下一条指令，拒绝“可能改变监视器”的形状。本轮把窗口内
除独占存储和异常指令之外的**所有**指令交给 CPU 原生执行：

| 类别 | 处理 |
| --- | --- |
| 普通/向量/未解码指令、SIMD/SVE/SME 数据处理、未解码存储、LSE 原子 | 原生执行；不再要求解码 |
| 目标页 load | 仍由 `PAGE_AP` 数据异常模拟，`uy_step_resume()` 继续 |
| `LDXR/LDAXR` | 原生执行；退休后 `uy_step_prev()` 把模型监视地址移到它的基址 |
| `LDXP/LDAXP` | 原生执行；退休后把模型切到成对预约 |
| `STXR` 命中模型 | 在 `STXR` 前由内核完成同一地址/宽度的 store，`Ws=0`，`PC+=4` |
| `STXP` 命中模型 | 同上，两个半字一起完成 |
| 不命中的 `STXR/STXP` | 结束单步，让原生指令报告失败 |
| `CLREX #imm`（全部 imm4） | 原生执行；退休后清模型预约 |
| `SVC/HVC/SMC/BRK/HLT` | 结束单步，原生异常入口清硬件预约，后续 `STXR` 原生失败 |
| 非会话缺页、非法访问、信号 | 原有 `do_mem_abort` 取消单步，原生结果 |

不再有 `UY_STEP_MAX=4096` 上限：单步一直走到消费预约的独占存储、异常或任务退出。
App 自己写的长循环只会让它自己运行更久，和原生执行一样；内核 handler 每次只处理
一条已退休指令，不存在内核态死循环。

**同 PE store 不使本地监视器失效。** 2.23.0 的模型和注释假设“与监视字重叠的 store
清本地监视器”。真机测量（Pixel 6，`6.1.134`）表明这条假设不成立：

- `LDXR A; STR A; STXR A`：5000/5000 次 `STXR` 成功；
- `LDXR A; LDADD A; STXR A`：5000/5000 次成功；
- `LDXR A; LDADD B; STXR A`：5000/5000 次成功；
- `LDXR A; CLREX; STXR A`：5000/5000 次失败；
- `LDXR A; STXR B; STXR A`：第二个 `STXR` 1000/1000 次失败（失败的 `STXR` 也清
  本地监视器）。

因此 2.24.0 不再为“store 命中监视字”伪造失败，也不再需要 store 解码或硬件
watchpoint；窗口内的普通 store、单 lane SIMD store 和 LSE 原子都原生执行，`STXR`
仍按原生成功完成。测试 App 新增 `self_store/neon_self` 探针，要求模块在 store 后
**不产生**原生没有的失败。

[退休指令处理](urov_y_backend.c#L3636) · [单步决策](urov_y_backend.c#L3763) ·
[单步入口](urov_y_backend.c#L3807) · [成对完成](urov_y_backend.c#L3724)

### 3.3 成对独占

`uy_step_prev()` 对 `LDXP/LDAXP` 记录基址、半字宽度和两个目的寄存器，`STXP/STLXP`
在匹配时由 `uy_step_force_pair()` 一次写入两个半字、置 `Ws=0` 并发布 image/shadow。
不匹配的成对存储交回原生。这样 H21 的短窗口不再依赖 64 条字节模型。

### 3.4 为什么没有实现完整 AArch64 + SVE/SME 解释器

目标设备 Pixel 6 的 `/proc/cpuinfo` 没有 `sve` 或 `sme`；SVE/SME 指令在该机上是
未定义指令，原生和模块都产生 SIGILL，不存在可观测差异。单步让 CPU 原生执行
SVE/SVE 数据处理与存储，所以**本目标不需要解释器**。只有“SVE/SME load 命中被保护
数据页”才需要模拟向量寄存器；这要求读取任务的可变长 SVE/SME 状态并逐 lane 填充，
而模块现有 `uy_fp_snapshot()` 在检测到 `thread.sve_state/sme_state` 非空时本来就
拒绝建模。为无 SVE 的目标实现完整解释器只会新增状态、代码字和失败关闭类别，不会
消除本机可观测特征。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍只操作 `PAGE_AP` 的 `AP[1]` |
| 新的读视图 | 目标页 load 仍走原 `read_range(allow_fake)` 路径 |
| 新的写语义 | 只执行 App 自己的 store；`STXR/STXP` 只在地址/宽度/值匹配时由内核完成 |
| 新的失败 | 模型只在证明 LDXR 执行且无 `CLREX`/独占/异常时完成；store/原子不再被误判为清监视器 |
| 新的寄存器/标志结果 | 单步由硬件执行，handler 不重算数据通路；只有 `Ws=0` 是原生成功值 |
| 新的崩溃/信号 | 异常指令结束单步，原生异常/信号路径不变；非会话 fault 取消单步 |
| 新的线程/定时器/文件/ABI | 没有；`hooks=0xff`、ABI v8、`ctl0` 状态格式不变 |
| 新的计时台阶 | 每次未建模窗口仍最多一次有界单步；计时按题目允许保留 |

## 5. 残余（2.24.0）

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
6. **SVE/SME 目标页 load**：本机无 SVE/SME；有该扩展的设备需要按 §3.4 的边界处理。
7. **不命中/未来独占编码**：`STXR/STXP` 之外的独占形状若未建模，结束单步交回原生；
   原生监视器已被异常返回清掉，结果与无模块不同。当前 AArch64 的 EL0 独占只有
   `LDXR/LDAXR/LDXP/LDAXP/STXR/STLXR/STXP/STLXP/CLREX`，这些均已覆盖。
8. **读前窗口的保守类别**：线性证明只接受整数 ALU、NOP/BTI、DMB/DSB/ISB、EL0 可读
   `MRS`、`NZCV/FPCR/FPSR/TPIDR_EL0` 的 `MSR` 和 `PRFM`。读前窗口中的 FP/SIMD
   数据处理、普通 load/store、LSE 原子仍使计划放弃，原生 `STXR` 随后失败。2.23 的
   值链同样不接受这些形状；放宽它们需要判定每条指令是否写 LDXR 基址，否则可能把
   原生失败的 `STXR` 伪造成成功（例如 `UMOV Wn,Vm.B[0]` 重写基址）。本机测试 App
   的读前探针是整数 ALU（`pre_mov` 和 64 条 `pre_long`）。
9. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：与 2.18
   相同，不改变 owner 的读值视图。

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`c00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
`/proc/cpuinfo` 无 SVE/SME。模块 `urov-y.kpm` SHA-256
`e8faf18e5a27dab58062e786db1a950854f7975744daa549c8e64b38b956fcbc`，测试 APK SHA-256
`c96020ed682b1f20fa7a8f9b23a57b8f917f64d01f4d4b327ddc313ae49759b5`，窗口模型测试
SHA-256 `3bbedb7b56fd1ea104a2c25d4819f2d0f660389567d98358873fe8f1438553ba`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v224` 6 模式 ×3 | PASS；AP-all overlay `split=0`、`evidence=0`、`accepted=32`，`LDXR precheck ap=0`，`pre_mov=pre_long=0`，`self_bad=neon_bad=0`，`deep_bad=0` | [read-defense-v224-20261109-231802](results/read-defense-v224-20261109-231802/summary.json) |
| 生产 CRC 7 模式 ×3 | PASS；`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235` | [crc-20261109-232249](results/crc-20261109-232249/summary.json) |
| 消除矩阵 3×1 | PASS；全部 `ELIM_CASE` 通过 | [eliminate-20261109-232321](results/eliminate-20261109-232321/summary.json) |
| 多页 3×1 | PASS | [multipage-20261109-232434](results/multipage-20261109-232434/summary.json) |
| 窗口模型差分测试 | PASS；`cases=121 failures=0` | `out/urov_window_test` |

AP-all overlay 的关键日志：

```text
READ_DEFENSE_V224_POLICY stage=overlay n=32 ... split=0 evidence=0 accepted=32 ...
READ_DEFENSE_V224_RESIDUAL stage=overlay n=32 ... pre_mov=0 pre_long=0
    self_bad=0 neon_bad=0 self_done=32 neon_done=32 deep_bad=0 deep_done=32 ...
READ_DEFENSE_V224_BOUNDARY stage=overlay n=32 ap=0 ap_unknown=0 evidence=0 accepted=32 ...
READ_DEFENSE_KEYLESS2 stage=overlay n=32 load=0 store=0 branch=0 xload=0 xpair=0 ...
```

- **H19**：`READ_OVERWRITE_LDXR` 的 `LDXR W9` 被 `LDRB W9` 覆盖，AP-all 仍
  `ap=0`、`accepted=32`；2.23.0 为 `ap=3`、`evidence=3`。
- **H20**：`pre_long` 在 LDXR 与采样 load 之间放 64 条 `ADD`（旧值链上限 12）；
  `deep` 在采样 load 与 `STXR` 之间放 6000 条循环指令（旧单步上限 4096）；
  `self_store/neon_self` 在监视字上做标量/单 lane SIMD store；全部不再产生特征。
- **H21**：`READ_POST_LOAD_XPAIR` 在窗口内做第二次 `LDXP/STXP`；AP-all `xpair=0`。
- 干净、仅补丁、撤销后各阶段 `unknown=0`；会话结束 `kpm list` 为空，boot ID 不变，
  增量内核日志无 BUG/WARNING。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v224 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```
