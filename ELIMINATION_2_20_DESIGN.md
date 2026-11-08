# UROV-Y 2.20.0：LL/SC 窗口的完整语义

本文记录 `urov-y` 2.20.0 相对 2.19.0 的变更。目标是在**不新增 App 可观察特征**的
前提下消掉 2.19.0 残余清单里唯一稳定、无密钥、普通 App 可复现的读侧特征：`PAGE_AP`
的读异常清掉本地独占监视器之后，只要 `LDXR` 与 `STXR` 之间出现任何不被 2.19 白名单
接受的指令（普通 load、普通 store、条件分支、读标志以外的数据加工……），`STXR` 就
按原生指令执行并失败——而同一序列在不装模块时是成功的。

只改 `urov-y`、测试 App/夹具、构建与文档；`urov-lab`、`urov-x` 不动；ABI 仍为 v8、
`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.19.0 仍成立的特征

2.19.0 把 STXR 前向窗口从 `NOP/BTI` 扩到寄存器-only 整数数据加工，其余形状仍交给
硬件。普通 App 不需要任何密钥就能构造出"原生成功、装模块后失败"的序列，因为
`LDXR` 执行后 `STXR` 之前插入一条普通指令是**编译器与手写锁代码的常态**：

| # | 2.19.0 行为 | 普通 App 的用法 | 2.19.0 证据 |
| --- | --- | --- | --- |
| H8 | `PAGE_AP` 的读异常清掉监视器；handler 只补完相邻、`NOP`/`BTI` 间隔和寄存器-only 数据加工 | `LDXR; LDRB; <load/store/branch/…>; STXR`：`STXR` 原生执行并失败 | 2.20 新增的 `READ_DEFENSE_KEYLESS2` 探针：`load=4/4 store=4/4 branch=4/4` |
| H9 | 同上 | `LDXR; LDRB; CSEL; STXR` 读 NZCV | 2.19 的 `READ_DEFENSE_KEYLESS`：`csel=16/16` |

同轮实测把另外两条**看似**属于残余的形状证明为架构本来的行为，因此不必消除：

| 形状 | 原生结果 | 依据 |
| --- | --- | --- |
| gap 里 `CLREX` | `STXR` 失败 | `CLREX` 的定义就是清本地监视器；探针 `clrex_bad=0`、`clrex_done=n` |
| gap 里 `SVC #0`（异常） | `STXR` 失败 | 异常入口清本地监视器；探针 `svc_bad=0`、`svc_done=n` |
| gap 里对同一地址的第二条 `LDXR` | `STXR` 成功 | 第二条 `LDXR` 重建预约；2.20 把它建模，探针 `xload=0/n` |

`xload` 在 2.19 上也是 0：`LDRB` 异常返回后第二条 `LDXR` 是在 EL0 重新执行的，
监视器本来就成立。它保留在矩阵里用于证明建模没有把成功改成失败。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：读者能拿到的字节（EL0 标量/向量 load、`memcpy`/`memcmp`/
`crc32`、`process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程
的读），以及读者能观察的副作用（映射属性、页表统计、异常、独占监视器、耗时、崩溃、
系统调用返回值）。计时不在消除范围；root 可见性不在普通 App 的输入集合内。

## 3. 方案：把"白名单"换成"窗口模型"

2.19.0 的结构是"先静态扫描出一个可接受的 gap，再在提交时重放这个 gap"。2.20.0 把它
换成**两段式窗口执行**：故障 load 提交之后，在一个私有寄存器副本上**逐条执行**
`LDXR..STXR` 之间的全部窗口指令，读完 gap 里的 load，把 gap 里的 store 记成待提交
项，最后在真正消费预约的 `STXR` 处停下；只有整条路径都被证明等同于原生执行时才提交。

### 3.1 前置证据（不变）

`uy_llsc_prepare_single()` 仍只收**故障前**的证据，与 2.19 相同：

1. `LDXR/LDAXR` 在故障 load 前 0–3 条 `NOP` 之内；
2. `LDXR` 的目的寄存器仍等于 `[Xn]` 的当前值（执行存证；`LDXR XZR` 走控制流存证）；
3. 全部可执行映射里没有直接分支进入 `LDXR..load`（`uy_llsc_skipped`）；
4. 没有 GPR 仍持有该区间地址（`uy_llsc_indirect`）；
5. 故障 load 不覆盖 `LDXR` 的基址/数据寄存器。

[证据收集](urov_y_backend.c#L2705) · [窗口建模](urov_y_backend.c#L2526)

### 3.2 窗口模型

`uy_llsc_walk()` 从故障 load 的下一条开始，在 `fault_pc+4 .. fault_pc+4+96` 的
24 条指令预算内逐条执行。模型覆盖的指令类别：

| 类别 | 指令 | 备注 |
| --- | --- | --- |
| 空操作 | `NOP`、`BTI C/J/JC`、`HINT #0`、`DMB`/`DSB`/`ISB` | 不改寄存器、不碰监视地址 |
| 加减 | `ADD/SUB` 立即数（含 `LSL #12`）、移位寄存器、`S` 形式、`SP` 形式 | NZCV 精确建模 |
| 逻辑 | `AND/ORR/EOR/ANDS` 及 `BIC/ORN/EON`（移位寄存器）、逻辑立即数 | 位掩码立即数用 `DecodeBitMasks` |
| 搬移/位域 | `MOVN/MOVZ/MOVK`、`SBFM/UBFM/BFM`、`EXTR` | 覆盖 `LSL/LSR/ASR` 立即数、符号/零扩展、`UBFX` |
| 条件 | `CSEL/CSINC/CSINV/CSNEG`、`CCMP/CCMN` | 读/写 NZCV，结果提交回 SPSR |
| 1/2/3 源 | `RBIT/REV16/REV32/REV/CLZ/CLS`、`UDIV/SDIV/LSLV/LSRV/ASRV/RORV`、`MADD/MSUB` | 含除零、`INT_MIN/-1`、32 位零扩展 |
| 地址 | `ADR/ADRP` | 用模型 PC |
| 分支 | `B`、`B.cond`、`CBZ/CBNZ`、`TBZ/TBNZ` | 目标仍在窗口内才接受，前向/回跳都由预算兜底 |
| 读 | `LDR/LDRB/LDRH/LDRSW/LDRSB/LDRSH/LDP`（GPR） | 经 `read_range`，与故障 load 用同一 image/snapshot 视图 |
| 写 | `STR/STRB/STRH/STP`（GPR） | 只记录 `(地址, 字节)`，提交时才写 |
| 独占读 | `LDXR/LDAXR` | 读同一视图，重建预约并把监视地址移到 `[Xn]` |

`STXR/STLXR` 是窗口的终点。只有下面全部成立时才把这次 store 当作原生结果提交：

- `STXR` 的宽度与 `LDXR` 相同；
- 基址寄存器不是 `SP`、地址 16 字节内对齐；
- `Rn` 当前**仍然等于**监视地址（gap 可以换用别的寄存器，只要值相同）；
- `LDXR XZR` 的窗口里 `STXR` 也必须丢弃数据（沿用 2.19 的窄证明）；
- 前面建模过的每条指令都没有拒绝。

[窗口执行](urov_y_backend.c#L2526) · [读](urov_y_backend.c#L2425) ·
[写记录](urov_y_backend.c#L2472) · [独占读](urov_y_backend.c#L2450)

### 3.3 提交

提交阶段按顺序做三件事，任何一步失败都**不**改变任务状态（PC 停在故障 load 之后，
原生指令照常执行并给出原生结果）：

1. `uy_write_enter()` 串行化写入；
2. 依次用 `uy_write_live()` 重放窗口里记录的 store（走内核 GUP/COW 写路径，写进活页
   并同步 image/shadow，随后 `uy_rearm_written()` 重装 `AP[1]=0`）；
3. 用 `f_copy_out()` 完成 `STXR` 自己的 store，发布到 image/shadow 并重装陷阱；
4. 写回模型寄存器、`SP`、`pstate`，把 `Ws` 置 0，`PC = STXR+4`，`llsc++`。

[提交](urov_y_backend.c#L2779)

### 3.4 失败关闭与原生等价

下列形状**不**提交，交给硬件执行，硬件给出它自己（也就是未装模块时）的结果：

| 形状 | 为什么不建模 | 原生结果 |
| --- | --- | --- |
| `CLREX` | 定义就是清监视器 | `STXR` 失败 |
| 异常（`SVC/HVC/SMC/BRK`） | 异常入口清监视器，且语义不可代替 | `STXR` 失败 |
| `LDXP/LDAXP/STXP/STLXP` | 成对预约的宽度/地址规则不同 | 见探针 |
| LSE 原子（`LDADD`/`SWP`/`CAS`…） | 与监视器的交互依赖实现 | 失败或按实现 |
| 与监视地址重叠的 store | 清监视器 | `STXR` 失败 |
| gap 里的 `BL/BLR/RET` | 需要执行任意被调用代码 | 不可建模 |
| 第 2 条宽度不同的 `LDXR` | 预约宽度不同 | 失败 |
| `MRS/MSR`（系统寄存器）、SIMD&FP、SVE/SME | 需要读系统寄存器或模拟浮点数据通路 | 成功 |
| 走出窗口区域 / 超过 24 条 | 预算 | 成功 |
| 写目标 VMA 不接受、地址越界 | 原生会 SIGSEGV | `SIGSEGV` |

前六类原生**同样失败**（`CLREX`、异常、`SVC` 已由探针在真机上确认），因此拒绝它们
不是隐藏特征，而是复现架构。真正遗留的是最后四类，见 §5。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍然只操作 `PAGE_AP` 的 `AP[1]` 陷阱 |
| 新的读视图 | gap 里的 load 走与故障 load 相同的 `read_range(allow_fake)`，窗口外读仍按 caller-window 返回 image/snapshot |
| 新的写语义 | gap 里的 store 用 App 自己的地址/宽度/值，经内核 GUP/COW 路径完成；被吸收的 store 与 2.15 起的行为一致 |
| 新的寄存器/标志结果 | 每条建模指令按架构语义执行；32 位写零扩展、`XZR`/`SP` 区分、NZCV 逐位建模、`S` 形式与 `CCMP` 的 NZCV 语义、`MOVK` 保留位、`EXTR` 拼接、除零与 `INT_MIN/-1` |
| 新的崩溃/信号 | 拒绝路径不写 PC、不改寄存器；窗口内 load 失败（原生会 fault）时不提交，原生照旧 fault |
| 新的返回码/ABI | `Ws=0` 是原生成功值；ABI v8、`ctl0`、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；没有新增内核对象或 syscall 入口 |
| 新的计时台阶 | 每次命中窗口多一次有界解码与最多 24 条指令的建模；计时按题目允许保留 |

结构体、计数器和 ABI 未变：`struct uy_llsc` 只是把 2.19 的 `gap[]` 换成"待提交 store
数组 + 终态寄存器副本"，没有跨调用状态。

## 5. 残余（2.20.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读仍有一次同步异常；未解码 store 仍有 Software
   Step 与整页 diff；命中 LL/SC 窗口时多一次有界建模。按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍保留
   陷阱项；跨 CPU TLB miss 的亚指令级竞态。与 2.18/2.19 相同，属于计时同级。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传；POE 硬件上 `pkey_mprotect` 与
   `AP[1]` 陷阱的交互无法在本机证实。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；不在
   普通 App 的输入集合内，也不属于单个 KPM 能改的范围。
5. **窗口模型的边界**：gap 里出现 `MRS/MSR`、SIMD&FP、SVE/SME、`BL/BLR/RET`、
   LSE 原子、成对独占或走出窗口区域时仍 fail-closed。这些形状在不装模块时通常
   成功，因此**仍是潜在特征**，但都不出现在编译器生成的锁序列里：一条 LL/SC 窗口
   里的浮点/系统寄存器/函数调用既不能出现在 C/C++ 的原子操作中，也不是任何
   `__atomic`/`pthread`/内核原子实现的产物。要把它们也消掉需要模拟 FP 数据通路、
   系统寄存器和被调用代码，超出"只改 `urov-y`、不改 ABI、不新增内核对象"的边界。
6. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：与 2.18
   相同，不改变 owner 的读值视图（读视图仍是 image）。

与 2.19 的残余清单逐条对照：第 1 条保留（允许），第 2 条归入计时同级，第 3、4、6 条
性质不变且不在普通 App 的输入集合内，第 5 条从"读标志的 CSEL + 任何 load/store/分支"
缩小为"浮点/系统寄存器/调用/原子"这一组。**编译器可生成的、无密钥、稳定的读侧
特征在本轮清零。**

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` /
KernelPatch `0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux
Enforcing。模块 `urov-y.kpm` SHA-256
`7b43e768a26b09b6c3fe230591281a31a1e7a894dd11555cdcbb089e4bcfd391`，测试 APK
SHA-256 `0d4d8ad5e7552bf8f054ae08226a37d49b492cd7b878f7bef592991dfb800b04`，
窗口模型测试 `urov_window_test` 的 SHA-256
`95d533b37977f0a8c0826b14c2ba8cbdc590ffc857158cfe8208dfe397d244d1`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v220` 6 模式 × 8 | PASS；覆盖阶段 `load=0 store=0 branch=0 xload=0 csel=0`、`value=32/32`、`clrex_bad=0`、`svc_bad=0`，`unknown=0` | [read-defense-v220-20261108-201133](results/read-defense-v220-20261108-201133/summary.json) |
| 生产 CRC 3×1（7 模式） | PASS | [crc-20261108-201226](results/crc-20261108-201226/summary.json) |
| Dobby 检测 8×1 | PASS；`accepted_crc_with_ap=8/8`、`ap=0/8`、`overlay` 的 `live=96964c4f` 等于文件摘要而执行仍是 `1235` | [dobby-detect-20261108-201206](results/dobby-detect-20261108-201206/summary.json) |
| 消除矩阵 3×1 | PASS；`ELIM_CASE` 全部 `exclusive_match=0`、`ap_match=0` | [eliminate-20261108-201254](results/eliminate-20261108-201254/summary.json) |
| 多页 3×1 | PASS | [multipage-20261108-201407](results/multipage-20261108-201407/summary.json) |
| 窗口模型差分测试 | PASS；`cases=56 failures=0` | `out/urov_window_test` |

单变量对照（同一 APK、同一页面，只换模块）：

| 模块 | `load` | `store` | `branch` | `csel` | `value_ok` |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2.19.0（`b173a91a…`） | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| 2.20.0 | 0/4 | 0/4 | 0/4 | 0/4 | 16/16 |

`value_ok` 是功能性对照：每个探针把窗口算出的值通过 `STXR` 写回私有字，再与
原生（未装模块的同一序列）比较。2.19 上只有 `xload` 一种形状能完成 STXR，所以
分母是 4；2.20 上四种形状全部完成，分母是 16，且分子相同，说明窗口模型算出的
寄存器与内存效果与原生一致。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v220 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```

`--read-defense-v219` 仍保留给 2.19.0 模块（它断言 AP 阶段 `csel=n`，在 2.20.0 上会
按设计失败）。2.20.0 的普通 App 检测入口是 `--read-defense-v220`。
