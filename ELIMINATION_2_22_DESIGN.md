# UROV-Y 2.22.0：影子 GPR 预链与整数 SIMD 窗口

本文记录 `urov-y` 2.22.0 相对 2.21.0 的变更。目标是清掉 2.21.0 测试面上仍能稳定
复现的两条无密钥、普通 App 可构造的读侧特征，并把 LL/SC 窗口的覆盖从“只写 LDXR
目标寄存器的整数链 + FMOV”扩到“可经任意影子寄存器的整数链 + 整数 SIMD 三同族”，
同时保持 ABI、hook 集合、控制面和读值语义不变。

只改 `urov-y`、测试 App/夹具、构建与文档；`urov-lab`、`urov-x` 不动；ABI 仍为 v8、
`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.21.0 仍成立的两条特征

2.21.0 的后向窗口只接受“写 LDXR 目标寄存器（或丢弃）、且结果依赖 LDXR 读值”的
整数链，前向窗口只覆盖 GPR、分支、普通 load/store 与 `FMOV`/`MRS`/`MSR`。测试 App 的
`READ_DEFENSE_V221_POLICY` 因此仍能在 `PAGE_AP` 下稳定得到两条“原生成功、装模块后
失败”的序列：

| # | 2.21.0 行为 | 普通 App 的构造 | 2.21.0 证据 |
| --- | --- | --- | --- |
| H12 | 后向链拒绝写第二个 GPR；`MOV X9,X0` 使 `LDXR` 回溯失败 | `LDXR x0,[scratch]; MOV x9,x0; LDRB w1,[target]; STXR w2,x0,[scratch]` | v221-guarded `pre_gpr=96/96` |
| H13 | 前向窗口遇到整数 SIMD 就停止；`EOR V0.16B` 使整窗放弃 | `LDXR x0,[scratch]; LDRB w1,[target]; EOR V0.16B,V0.16B,V0.16B; STXR w2,x0,[scratch]` | v221-guarded `simd=96/96` |

两条都只需要普通 EL0 指令、私有 scratch 和自有 RX 页，不需要密钥、root、内核辅助读
或额外映射。它们和 2.19 的 `CSEL`、2.20 的 load/store/branch、2.21 的 pre-ALU/FMOV
属于同一类：`PAGE_AP` 的读异常清掉本地独占监视器，而窗口模型没有覆盖该形状。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮只处理普通 App 的
EL0 读值与独占监视器可观察到的特征。

## 3. 方案

### 3.1 预加载影子寄存器链

`uy_llsc_pre_chain()` 不再要求每条 pre 指令都写 `LDXR` 的目标寄存器。它在私有影子
GPR 文件上按程序顺序重放整段 pre-window：

1. 第一次扫描拒绝写 SP、写不可解码类别、读 NZCV 的形状；
2. 第二次从 `LDXR` 读到的内存值出发，逐条执行 `uy_win_alu()`；
3. 源寄存器的取值规则：若早前的 pre 指令定义过它，用影子值；若它不在整段
   pre-window 的写集合里，故障现场的值就是 `LDXR` 之前的值，可直接使用；若它只在
   更晚的 pre 指令里被写，则该处的值不可重建，整段拒绝；
4. 整段从 `loaded` 与 `loaded ^ 1` 各重放一次，两次的 `LDXR` 目标寄存器终值必须
   不同，并且必须逐位等于故障现场；这条规则替代了“每条指令都消耗链值”的单点
   检查，既保留执行证据，又允许 `MOV X9,X0; ADD X0,X9,#1` 这类经旁路寄存器的链；
5. `SP`、目标页内存、故障 load 的基址寄存器和控制流仍不允许改写。

`uy_win_srcs()` 给出每条整数 ALU 指令读取的 GPR 位图（`MOVK`/`BFM` 也读目标），
对无法枚举的类别返回全 1，使 verifier 失败关闭。

### 3.2 整数 SIMD 三同族

`uy_win_simd()` 在 `struct uy_fpstate` 镜像上重放 Advanced SIMD 的 three-same
整数指令族：

| 类别 | 指令 | 语义 |
| --- | --- | --- |
| 逻辑 | `AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF` | 纯位运算；`BSL/BIT/BIF` 读旧 `Vd` 作选择子 |
| 加减 | `ADD/SUB` `.8B/.16B/.4H/.8H/.2S/.4S/.2D` | 每 lane 模 2^(8*size) |
| 比较 | `CMEQ/CMTST/CMGT/CMHI/CMGE/CMHS` | 有符号/无符号按 `U` 位，命中 lane 全 1 |
| 最值 | `SMAX/SMIN/UMAX/UMIN` | 8/16/32 位 lane（该族无 64 位 lane） |
| 乘加 | `MUL/MLA/MLS` | 8/16/32 位 lane，低半积 |
| 移位 | `SSHL/USHL` | 每 lane 取 `Vm` 低 8 位为有符号移位量 |

`Q=0` 时只写低 8 字节并按架构清零目的寄存器高 64 位。窗口只在第一次遇到 FP/SIMD
指令时懒取 `fpsimd_preserve_current_state()` + `task->thread.fpsimd_state` 快照，
提交时用 `fpsimd_update_current_state()` 写回，与 2.21 的 `FMOV` 路径完全一致。
整数 SIMD 不写 FPSR、不访问内存、不产生异常，因此不需要模拟 FP 数据通路。
`FP` 算术/转换、permute、立即数形式、SIMD load/store、`SVE/SME` 仍失败关闭。

### 3.3 未特权 load 的等价解码

`LDTR/LDTRB/LDTRH/LDTRSW` 是 unscaled load 的未特权形式，在 EL0 与
`LDUR/LDURB/LDURH/LDURSW` 的地址、宽度、写回和权限结果完全相同。共享解码器
`decode.c` 有意拒绝它们，因此被 AP 陷阱拦下的 `LDTRB` 会变成合成 `SIGSEGV`；普通
App 只要安装信号处理器，就能把这个信号当作读陷阱证据。2.22.0 在
`uy_emulate_load()` 里、且只在 `uro_decode()` 失败后，把该形态的 11:10 位（未特权
模式）清零后按普通 unscaled load 重新解码；`single_type()` 仍拒绝 store，其他未
解码形态继续 fail-closed。`urov-lab`/`urov-x` 与共享 `decode.c` 不变。

### 3.4 覆盖范围

`UY_LLSC_PRE_MAX=12`、`UY_LLSC_WIN_MAX=64` 不变。新增接受条件只放宽“已经发生过的
整数链如何取值”和“窗口里一条纯寄存器 SIMD 如何计算”，没有扩大窗口长度、没有新增
内存访问、没有改变 STXR 的定位规则。

### 3.5 提交与失败关闭

提交顺序不变：串行化写入、重放 gap store、完成 `STXR` 的 store、发布 image/shadow、
写回模型寄存器/NZCV、若有 FPSIMD 状态则 `fpsimd_update_current_state()`、置 `Ws=0`、
`PC=STXR+4`。任何一步失败都不写回模型，PC 停在故障 load 之后，原生指令照常执行
并给出原生结果。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍然只操作 `PAGE_AP` 的 `AP[1]` |
| 新的读视图 | pre-window 只重放已经执行过的整数指令；post-gap load 仍走 `read_range(allow_fake)`；窗口外仍按 caller-window 返回 image/snapshot |
| 新的写语义 | 只写 App 自己的 `STXR` 本来要写的地址、宽度和值；gap store 仍先记录、提交时才经内核 GUP/COW 完成 |
| 新的寄存器/标志结果 | 影子链逐条按架构语义重放并逐位比对终值；SIMD 指令是纯位/整数 lane 运算，Q=0 清零规则与架构一致；NZCV/FPCR/FPSR 走同一份 SPSR/FPSIMD 状态 |
| 新的 FPSIMD 副作用 | 整数 SIMD 不写 FPSR；快照/写回频次与 2.21 的 FMOV 相同；未命中窗口时不写回 |
| 新的崩溃/信号 | 不支持的形状不写 PC/寄存器；原生 `SIGSEGV`/`SIGILL` 保持不变；pre-window 证据不足时不桥接。`LDTR` 只在故障页 load 路径上按等价 `LDUR` 完成，地址/宽度/写回一致，store 仍被 `single_type()` 拒绝 |
| 新的返回码/ABI | `Ws=0` 是原生成功值；ABI v8、`ctl0`、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；没有新增内核对象或 syscall 入口 |
| 新的计时台阶 | 每次命中窗口多一次 ≤64 条指令的建模；SIMD 窗口多一次 FPSIMD 保存/恢复。计时按题目允许保留 |

## 5. 残余（2.22.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读仍有一次同步异常；未解码 store 仍有
   Software Step 与整页 diff；命中 LL/SC 窗口时多一次有界建模和一次 SIMD 重放。
   按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍保留
   陷阱项；跨 CPU TLB miss 的亚指令级竞态。与 2.18–2.21 相同，属于计时同级。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；不在
   普通 App 的输入集合内。
5. **窗口模型的架构边界**：`BL/BLR/RET`（需要执行任意被调用代码）、`SVE/SME`、
   FP 算术/转换与 SIMD permute/立即数/内存形式、gap 内 LSE 原子/成对独占、
   计数器/随机数 `MRS`、超过 64 条或走出窗口的形状仍 fail-closed。未特权
   `LDTR` 已在 3.3 中按等价 `LDUR` 完成；`LDRAA`、SVE 内存形式等其他未解码形状
   仍按原有语义失败关闭。它们在不装模块时通常成功，因此仍是**潜在**特征；但都不
   出现在编译器生成的 LL/SC 序列里，而且要在不改变执行语义、不新增
   VMA/代码字/hook 的前提下消除它们，需要模拟任意被调用代码或完整 SIMD/FP
   数据通路，超出“只改 `urov-y`、不新增特征”的边界。
6. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：与 2.18
   相同，不改变 owner 的读值视图。

与 2.21 的残余清单逐条对照：第 1、2、3、4、6 条性质不变；第 5 条中
**pre-load 影子 GPR 链**、**整数 SIMD 三同族**和**未特权 `LDTR` 解码**已被消除。
编译器可生成的、无密钥、稳定的读侧特征在 2.22.0 测试面上清零。

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.186-android14-11` /
KernelPatch `c00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux
Enforcing。模块 `urov-y.kpm` SHA-256
`ab90dab425c54b009784b7471258119ba151c99197bf8a653ec3e9b3eac4d064`，测试 APK
SHA-256 `3181b98c5a56ee05306f736aa6344111554ba54812878e7bd5c00cde0cfb8820`，窗口
模型测试 SHA-256
`c7b65f694402707c99a4151c23c92074faff920eaea47c0d64bab1afc7bb2184`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v222` 6 模式 ×32 ×3 | PASS；AP-all overlay `pre_gpr=simd=ap=0`、`baseline_ok=96/96`、`simd_value=96/96`、`evidence=0`、`accepted=96/96`；AP 调用窗口 `split=96 evidence=96 accepted=0`；`unknown=0` | [read-defense-v222-20261109-001128](results/read-defense-v222-20261109-001128/summary.json) |
| 生产 CRC 7 模式 ×3 | PASS；`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235` | [crc-20261109-000422](results/crc-20261109-000422/summary.json) |
| Dobby 检测 8×1 | PASS；`ap=0/8`、`accepted_crc_old=8/8`、`accepted_crc_with_ap=8/8` | [dobby-detect-20261109-000455](results/dobby-detect-20261109-000455/summary.json) |
| 消除矩阵 3×1 | PASS；全部 `ELIM_CASE` 通过，`exclusive_match=0`、`ap_match=0` | [eliminate-20261109-000616](results/eliminate-20261109-000616/summary.json) |
| 多页 3×1 | PASS | [multipage-20261109-000848](results/multipage-20261109-000848/summary.json) |
| 窗口模型差分测试 | PASS；`cases=113 failures=0`（新增 40 条 SIMD/源位图用例，期望值由设备原生指令产生） | `out/urov_window_test` |

AP-all overlay 的 `READ_DEFENSE_V222_POLICY` 日志为
`pre_alu=fp=ap=0 ap_unknown=0 baseline_ok=32 pre_gpr=0 simd=0 simd_value=32 split=0
evidence=0 accepted=32`（每次运行 32 样本，3 轮合计 96/96）；AP 调用窗口为
`split=32 evidence=32 accepted=0`。`simd` 探针在 `LDXR` 前
`MOVI V0.16B,#0xff`、`STXR` 后 `UMOV` 回读 lane0：`simd_value=32`
说明窗口既完成了 `STXR`，也把 EOR 后的 FPSIMD 状态写回得与原生一致。AP-all 阶段
另有 `LDTRB` 探针读到 image 字节（`READ_DEFENSE_V222_LDTR byte=24 want=24`），
说明未特权 load 不再以合成 `SIGSEGV` 暴露陷阱。所有阶段 `unknown=0`，会话结束后
`kpm list` 为空，前后 boot ID 一致。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v222 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```

`--read-defense-v221` / `--read-defense-v221-guarded` 保留给 2.21.0 模块。它们断言
`pre_gpr`/`simd` 的 MATCH 计数为 n，在 2.22.0 上会按设计失败。`--read-defense-v222`
复现本文的矩阵。
