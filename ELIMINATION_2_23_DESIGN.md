# UROV-Y 2.23.0：调用/REV 模型与原生单步回放

本文记录 `urov-y` 2.23.0 相对 2.22.0 的变更。目标是清掉 2.22.0 残余清单里
普通 App、无密钥、可在 `PAGE_AP` 下稳定构造的读侧特征，同时不新增 hook、线程、
定时器、PTE/VMA、代码字或 ABI 字段。只改 `urov-y`、测试 App/夹具、构建与文档。

## 1. 输入：2.22.0 仍成立的边界

2.22.0 的前向窗口只覆盖整数 GPR、分支、普通 load/store、`FMOV`、部分
`MRS/MSR` 与 Advanced SIMD 三同整数族。以下形状仍会让原生 `STXR` 成功、装模块后
失败，普通 App 可用有对照的短序列复现：

| # | 2.22.0 行为 | 普通 App 的构造 |
| --- | --- | --- |
| H14 | 前向窗口拒绝 `BL`；局部 `BL/RET` 使整窗放弃 | `LDXR; LDRB; BL 1f; STXR; ...; 1: RET` |
| H15 | SIMD 两寄存器 `REV64` 不在三同族内，整窗放弃 | `LDXR; LDRB; REV64 V0.16B,V0.16B; STXR` |
| H16 | 标量 FP 算术、SIMD 立即数/置换、SVE 数据处理不在字节模型内 | `LDXR; LDRB; FADD D0,D0,D0; STXR` |
| H17 | 窗口长度超过 64 条或跳出线性范围 | 长直链、循环、经调用进入的短函数 |
| H18 | 窗口内第二次读目标页、`MRS CNTVCT_EL0`、无关地址的普通 store | 上述指令与 H16 组合 |

这些形状只需要普通 EL0 指令、私有 scratch 和自有 RX 页，不需要密钥、root、
内核辅助读或额外映射。它们和 2.19/2.20/2.21/2.22 的探针属于同一类：
`PAGE_AP` 的读异常清掉本地独占监视器，而窗口模型没有覆盖该形状。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮只处理普通 App 的
EL0 读值与独占监视器可观察到的特征。

## 3. 方案

### 3.1 把调用与间接控制流纳入字节模型

`uy_win_branch()` 新增：

| 指令 | 语义 |
| --- | --- |
| `BL imm26` | `LR = PC+4`，`PC = PC + sign_extend(imm26<<2)` |
| `BLR Xn` | `LR = PC+4`，`PC = Xn` |
| `BR Xn` | `PC = Xn` |
| `RET Xn`（含 `RET X30`） | `PC = Xn` |

模型仍只走有界的 64 条窗口，仍要求目标地址在用户可读代码范围、每条指令可解码、
不产生未建模的 store/异常。H14 的局部 `BL/RET` 因此在私有寄存器副本上逐条执行：
`BL` 进入 `RET`，`RET` 回到 `STXR`，`STXR` 的地址、宽度和数据与故障现场逐位一致后
才提交。`BLR/BR` 的目标来自模型寄存器，目标代码同样逐条解码；不可解码即失败关闭。
[前向分支](urov_y_window.h) · [窗口遍历](urov_y_backend.c)

### 3.2 SIMD 两寄存器字节反转

`uy_win_simd_permute()` 在 FPSIMD 镜像上重放：

| 指令 | 语义 |
| --- | --- |
| `REV64 Vd.16B/8B, Vn` | 每个 8 字节双字内反转字节 |
| `REV32 Vd.16B/8B, Vn` | 每个 4 字节字内反转字节 |
| `REV16 Vd.16B/8B, Vn` | 每个 2 字节半字内反转字节 |

`Q=0` 只写低 64 位并按架构清零目的寄存器高 64 位；不写 FPSR、不访问内存。
H15 的 `REV64` 因此不再让整窗放弃。`ADDV/EXT/ZIP/UZP/TRN/TBL` 等仍不在字节模型内，
由 3.3 的原生回放承接。
[SIMD 置换](urov_y_window.h)

### 3.3 原生单步回放

FP 算术、SIMD 立即数/置换、SVE 数据处理和长窗口无法用少量整数代码逐位重放。
2.23.0 增加一条与已有 store replay 共用 `do_debug_exception` 钩子的回放路径：

1. 字节模型放弃后，`uy_step_begin()` 在私有 `struct uy_step` 里记录 LDXR 的地址、
   宽度和当前线程/mm；
2. 处理器执行下一条 EL0 指令，软件步异常（EC 0x32）在指令完成后进入
   `uy_step_handle()`；
3. handler 校验 PC 处下一条指令：若是消费预约的 `STXR`，由内核完成同一地址、宽度
   和值的 store，写回 `Ws=0`、`PC=STXR+4`，并像模型提交一样发布 image/shadow；
   否则校验该指令可原生执行，重新 arm `SPSR.SS + MDSCR_EL1.SS`；
4. 指令由 CPU 原生执行，所以 FP/SIMD/SVE 的架构结果、NZCV/FPSR、分支目标、调用
   返回地址都与原生一致；handler 只观察 PC 和下一条编码，不重算数据通路；
5. 目标页的第二次读会再次触发 `PAGE_AP`。handler 先按原路径完成该 load，再调用
   `uy_step_resume()` 继续步进；因此 H18 的多读窗口也被覆盖。

允许原生执行的指令类别：

- 所有可解码的普通 load，包括目标页 load；
- 不与监视字重叠的普通 store（重叠 store 会清监视器，必须让原生 `STXR` 失败）；
- 直接/条件/间接分支、`BL/BLR/BR/RET`；
- 整数 ALU、标量 FP 算术/转换、SIMD 数据处理、SVE 数据处理；
- 屏障、HINT/BTI、`PRFM`；
- EL0 可读 `MRS`，以及 `NZCV/FPCR/FPSR/TPIDR_EL0` 的 `MSR`。

失败关闭的类别：

- 重叠监视字的 store、`CLREX`、`LDXR/LDXP/STXR/STXP`、LSE 原子；
- `SVC/HVC/SMC`、会陷入的 `MSR`、SVE/SME 内存形式、不可解码编码；
- 非会话页的缺页/写 fault、信号、抢占或迁移导致的回放中断；
- 单次回放超过 4096 条指令。

这些情况下 handler 清除步进状态，让原生指令继续执行；原生 `STXR` 会按硬件结果
报告成功或失败。2.22.0 的字节模型仍优先，只有模型放弃时才进入单步回放，因此既有
被建模窗口的耗时和提交路径不变。
[回放状态机](urov_y_backend.c) · [步进校验](urov_y_backend.c) ·
[调试异常入口](urov_y_backend.c)

### 3.4 提交与失败关闭

单步路径在 `STXR` 前停下，提交顺序与模型路径一致：写 live page、发布
image/shadow、必要时重新武装写过的注册页、置 `Ws=0`、`PC=STXR+4`。写失败或地址/
宽度不匹配时清除步进状态，PC 停在 `STXR`，原生指令照常执行并给出原生结果。
模型路径的提交顺序、寄存器/NZCV/FPSIMD 写回和 `Ws=0` 语义不变。

### 3.5 覆盖范围

- `UY_LLSC_PRE_MAX=12`、`UY_LLSC_WIN_MAX=64` 不变；模型只扩指令类别，不扩窗口。
- 单步回放最多 4096 条指令，超过即失败关闭；它不改变模型窗口的 64 条上限。
- 没有新增内存访问、映射、PTE 或代码字；单步只执行 App 本来就要执行的指令。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍只操作 `PAGE_AP` 的 `AP[1]` |
| 新的读视图 | 单步只让原生指令执行；目标页 load 仍走原 `read_range(allow_fake)` 路径 |
| 新的写语义 | 只执行 App 自己的 store；重叠监视字的 store 明确拒绝；`STXR` 只在地址/宽度/值匹配时由内核完成 |
| 新的寄存器/标志结果 | 单步由硬件执行，handler 不重算 FP/SIMD/SVE 结果；模型路径仍逐位比对 |
| 新的 FPSIMD 副作用 | 单步不保存/恢复 FPSIMD；硬件直接修改任务状态 |
| 新的崩溃/信号 | 不可执行类别在步进前拒绝；非会话 fault、信号、异常均取消步进，交回原生路径 |
| 新的返回码/ABI | `Ws=0` 是原生成功值；ABI v8、`ctl0`、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；没有新增内核对象或 syscall 入口 |
| 新的计时台阶 | 每个未建模窗口最多一次有界单步；计时按题目允许保留 |

## 5. 残余（2.23.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读仍有一次同步异常；未建模窗口每条指令一次
   软件步异常；命中 LL/SC 窗口时多一次有界建模或单步。按题目允许保留。
2. **caller-window 语义**：非 all-callers 会话下，只有会话调用者看到 image，独立
   读者仍看到活页，`split` 可被观察到。这是登记时选择的作用域语义，不是监视器
   特征；all-callers 会话的 `split=0`。
3. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；
   不在普通 App 的输入集合内。
4. **pkey/POE**：本机无 POE，只验证拒绝/透传。
5. **单步失败关闭类别**：重叠监视字的 store、`CLREX`/其他独占、LSE 原子、
   `SVC`/异常、SVE/SME 内存形式、未解码编码、非会话缺页、信号/抢占、超过 4096 条
   指令。原生这些形状通常本身就使 `STXR` 失败或产生信号；模块不替它们伪造成功。
6. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：与
   2.18 相同，不改变 owner 的读值视图。
7. **读前预约证据。** 模型和单步都要求 `uy_llsc_prepare()` 提供有效预约。普通 App 可让
   `LDRB` 覆盖 `LDXR` 的目的寄存器。CPU 的预约仍可有效，但源码会拒绝这份读前证据。
   `PAGE_AP` 的异常于是使原生 `STXR` 失败，字节等值和全调用者会话也能用配对对照检出。
   [普通 App 复核](APP_READ_INTEGRITY_RESULTS.md#2230-普通-app-无密钥检测与隔离)

### 5.1 为什么不能做到“任意指令都零差异”

同一虚拟地址必须同时满足“取指看到补丁后的活页”和“数据读看到原文件字节”。AArch64
没有 I/D 分离的页表位，因此只能让数据读触发异常并由内核返回 image。任何异常入口
都会清本地独占监视器；内核无法在 `ERET` 前重新建立跨异常级的预约。于是要让
`LDXR; ...; STXR` 保持原生结果，只有两条路：

1. 在私有状态上重放窗口（有限指令集），或
2. 让 CPU 原生执行窗口，并在消费预约的 `STXR` 前由内核完成它（单步回放）。

两条路都要求对窗口的副作用有可判定的处理。对“任意指令、任意系统状态、任意异常”
做到零差异等价于在用户态异常处理里实现完整 AArch64 + SVE/SME 解释器，并精确复现
所有异常、信号和调试副作用，这超出单一 KPM 的可验证范围。2.23.0 对通过读前预约
验证的窗口，扩展了寄存器计算、调用、load 和无关 store 的处理。读前验证失败时，
原生 `STXR` 仍会在异常返回后执行，普通 App 可用上述短序列观测到差异。

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` /
KernelPatch `c00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、
SELinux Enforcing。模块 `urov-y.kpm` SHA-256
`d04e2b09a8942c204e7a1be0cb89a3b7a302b091d53c8187a588df442d5e6510`，测试 APK
SHA-256 `9bc601679db32f5491006c77d0eb4592cf89f861c02e2211cb7ca684bc8c8368`，
窗口模型测试 SHA-256
`3bbedb7b56fd1ea104a2c25d4819f2d0f660389567d98358873fe8f1438553ba`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v223` 6 模式 ×3 | PASS；AP-all overlay `pre_gpr=simd=leaf_call=permute=fp_arith=ap=0`、`baseline_ok=3/3`、`simd_value=3/3`、`evidence=0`、`accepted=3/3`；AP 调用窗口 `split=3`（caller-window 语义） | [read-defense-v223-20261109-215232](results/read-defense-v223-20261109-215232/summary.json) |
| 生产 CRC 7 模式 ×3 | PASS；`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235` | [crc-20261109-215256](results/crc-20261109-215256/summary.json) |
| Dobby 检测 8×1 | PASS；`ap=0/8`、`accepted_crc_old=8/8`、`accepted_crc_with_ap=8/8` | [dobby-detect-20261109-215317](results/dobby-detect-20261109-215317/summary.json) |
| 消除矩阵 3×1 | PASS；全部 `ELIM_CASE` 通过，`exclusive_match=0`、`ap_match=0` | [eliminate-20261109-215329](results/eliminate-20261109-215329/summary.json) |
| 多页 3×1 | PASS | [multipage-20261109-215442](results/multipage-20261109-215442/summary.json) |
| 窗口模型差分测试 | PASS；`cases=121 failures=0`（新增 BL/BLR/BR/RET 与 REV16/32/64 用例） | `out/urov_window_test` |

AP-all overlay 的 `READ_DEFENSE_V223_RESIDUAL` 逐阶段为
`leaf_call=0 permute=0 fp_arith=0`；`fp_arith` 探针本身包含
`LDRB` 两次目标页读、无关地址 `STR`、`MRS CNTVCT_EL0`、`PRFM`、`DMB/ISB`、
局部 `BL/RET` 与 `FADD D0,D0,D0`，覆盖 2.22.0 残余清单中的多类组合。所有阶段
`unknown=0`，会话结束后 `kpm list` 为空，boot ID 与测试前一致。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v223 --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```
