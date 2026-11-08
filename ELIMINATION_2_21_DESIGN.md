# UROV-Y 2.21.0：预加载整数链与 FPSIMD 传送的完整窗口

本文记录 `urov-y` 2.21.0 相对 2.20.0 的变更。目标是清掉 2.20.0 测试面上仍能稳定
复现的两条无密钥、普通 App 可构造的读侧特征，并把 LL/SC 窗口的边界从“load 之后”
扩到“LDXR 之前”，同时保持 ABI、hook 集合、控制面和读值语义不变。

只改 `urov-y`、测试 App/夹具、构建与文档；`urov-lab`、`urov-x` 不动；ABI 仍为 v8、
`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.20.0 仍成立的两条特征

2.20.0 的窗口模型从故障 load 的 PC+4 开始，且向后只能越过最多三条 `NOP`。测试 App
的 `READ_DEFENSE_V220_POLICY` 因此仍能在 `PAGE_AP` 全调用者阶段稳定得到两条
“原生成功、装模块后失败”的序列：

| # | 2.20.0 行为 | 普通 App 的构造 | 2.20.0 证据 |
| --- | --- | --- | --- |
| H10 | 后向只接受 `NOP`；`LDXR; EOR; LDRB` 的 `EOR` 使 `LDXR` 回溯失败 | `LDXR x0,[scratch]; EOR x0,x0,#1; LDRB w1,[target]; EOR x0,x0,#1; STXR w2,x0,[scratch]` | v220 `pre_alu=32/32` |
| H11 | 窗口模型遇到 `FMOV` 就停止 | `LDXR x0,[scratch]; LDRB w1,[target]; FMOV d0,x0; FMOV x0,d0; STXR w2,x0,[scratch]` | v220 `fp=32/32` |

两条都只需要普通 EL0 指令、私有 scratch 和自有 RX 页，不需要密钥、root、内核辅助读
或额外映射。它们和 2.19 的 `ADD`、2.20 的 load/store/branch/CSEL 属于同一类：
`PAGE_AP` 的读异常清掉本地独占监视器，而 2.20 的模型没有覆盖“故障 load 之前”的
整数链，也没有覆盖 `FPSIMD` 数据通路。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮只处理普通 App 的
EL0 读值与独占监视器可观察到的特征。

## 3. 方案

### 3.1 预加载整数链：从 `LDXR` 重建到故障 load

`uy_llsc_prepare_single()` 的后向扫描从“最多三条 `NOP`”改为最多
`UY_LLSC_PRE_MAX=12` 条指令，并把扫描到的指令按“离 load 最近”到“离 `LDXR` 最近”
保存。找到 `LDXR/LDAXR` 后，`uy_llsc_pre_chain()` 从 `LDXR` 读到的内存值出发，
按程序顺序重放这段 pre-window，并要求：

1. 每条 pre 指令都是 `uy_win_alu()` 能精确建模的整数数据加工，或 `NOP`/屏障；
2. 它只能写 `LDXR` 的目标寄存器，或丢弃（`Rd==31`），不能写 `SP`、基址寄存器或
   任何其他 GPR；
3. 若它写目标寄存器，结果必须实际依赖 `LDXR` 读到的值：用两个不同输入各跑一次，
   结果相同（`MOVZ`、`AND #0` 等）就拒绝；
4. 不能读 NZCV（`CSEL/CCMP`）——`LDXR` 之前的标志无法从故障现场重建；
5. 重放结果必须逐位等于故障现场的目标寄存器。

因此 `LDXR; EOR; LDRB; EOR; STXR` 的 `EOR` 会被正向重放，`LDXR` 的执行证据和
监视地址仍然成立；pre-window 里的 `ADD/SUB/AND/ORR/EOR/MOV*` 等原地更新同样成立。
任何“先写别的寄存器再在窗口里读它”的形状仍然拒绝，避免用故障后的值猜测
`LDXR` 前的值。

### 3.2 故障 load 之后的 FPSIMD 传送

`uy_llsc_walk()` 在原有 GPR load/store/分支/整数 ALU 之外增加：

| 类别 | 指令 | 语义 |
| --- | --- | --- |
| 标量传送 | `FMOV Dd,Xn`、`FMOV Xd,Dn`、`FMOV Sd,Wn`、`FMOV Wd,Sn` | 位不变；标量写清零目标 V 寄存器未用字节 |
| 半精度传送 | `FMOV Hd,Wn`、`FMOV Wd,Hn` | 仅在 `ID_AA64PFR0_EL1.FP` 报告 FEAT_FP16 时接受 |
| 128 位 lane | `FMOV Vd.D[1],Xn`、`FMOV Xd,Vn.D[1]` | 只改/读高 64 位 lane，保留低 lane |
| 系统寄存器 | `MRS/MSR NZCV`、`MRS/MSR FPCR`、`MRS/MSR FPSR` | NZCV 走 SPSR；FPCR/FPSR 走 FPSIMD 镜像 |
| 只读系统寄存器 | `MRS TPIDR_EL0`、`TPIDRRO_EL0`、`CNTFRQ_EL0`、`CTR_EL0`、`DCZID_EL0` | 运行任务看到的常量/线程值，原样返回 |

FPSIMD 镜像只在窗口里第一次出现 FP 指令时通过 `fpsimd_preserve_current_state()` +
`task->thread.fpsimd_state` 取一次；提交时用 `fpsimd_update_current_state()` 写回。
`FMOV` 不做浮点运算、不读舍入模式、不产生异常，因此不需要模拟 FP 数据通路。
`SVE/SME` 活跃任务、`FMOV` 之外的 SIMD/FP 运算、需要任意被调用代码的
`BL/BLR/RET` 仍然 fail-closed。

### 3.3 窗口预算

`UY_LLSC_WIN_MAX` 从 24 条提高到 64 条（`fault_pc+4 .. +256` 字节）。提高上限只是
让更多本来就能逐条精确建模的指令走模型，没有改变接受条件；超出预算或走出窗口的
形状仍交给原生指令。pre-window 上限为 12 条，覆盖手写/编译器生成的短整数链。

### 3.4 提交与失败关闭

提交顺序不变：串行化写入、重放 gap store、完成 `STXR` 的 store、发布 image/shadow、
写回模型寄存器/NZCV、若有 FP 状态则 `fpsimd_update_current_state()`、置 `Ws=0`、
`PC=STXR+4`。任何一步失败都不写回模型，PC 停在故障 load 之后，原生指令照常执行
并给出原生结果。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍然只操作 `PAGE_AP` 的 `AP[1]` |
| 新的读视图 | pre-window 只重放已经执行过的整数指令；post-gap load 仍走 `read_range(allow_fake)`；窗口外仍按 caller-window 返回 image/snapshot |
| 新的写语义 | 只写 App 自己的 `STXR` 本来要写的地址、宽度和值；gap store 仍先记录、提交时才经内核 GUP/COW 完成 |
| 新的寄存器/标志结果 | 整数链逐条按架构语义重放并逐位比对；FPSIMD 传送是纯位移动；NZCV/FPCR/FPSR 走同一份 SPSR/FPSIMD 状态；H 形式只在 CPU 真正支持 FP16 时接受 |
| 新的崩溃/信号 | 不支持的形状不写 PC/寄存器；原生 `SIGSEGV`/`SIGILL` 保持不变；pre-window 证据不足时不桥接 |
| 新的返回码/ABI | `Ws=0` 是原生成功值；ABI v8、`ctl0`、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；没有新增内核对象或 syscall 入口 |
| 新的计时台阶 | 每次命中窗口多一次最多 64 条指令的建模；出现 FP 时多一次 FPSIMD 保存/恢复。计时按题目允许保留 |

## 5. 残余（2.21.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读仍有一次同步异常；未解码 store 仍有
   Software Step 与整页 diff；命中 LL/SC 窗口时多一次有界建模。按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍保留
   陷阱项；跨 CPU TLB miss 的亚指令级竞态。与 2.18/2.19/2.20 相同，属于计时同级。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；不在
   普通 App 的输入集合内。
5. **窗口模型的架构边界**：`BL/BLR/RET`（需要执行任意被调用代码）、`SVE/SME`、
   `FMOV` 之外的 SIMD/FP 数据通路、gap 内 LSE 原子/成对独占、计数器/随机数
   `MRS`、超过 64 条或走出窗口的形状仍 fail-closed。它们在不装模块时通常成功，
   因此仍是**潜在**特征；但都不出现在编译器生成的 LL/SC 序列里，而且要在不改变
   执行语义、不新增 VMA/代码字/hook 的前提下消除它们，需要模拟任意被调用代码或
   完整 SIMD/SVE 数据通路，超出“只改 `urov-y`、不新增特征”的边界。
6. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：与 2.18
   相同，不改变 owner 的读值视图。

与 2.20 的残余清单逐条对照：第 1、2、3、4、6 条性质不变；第 5 条中
**pre-load 整数链和 FPSIMD 传送**已被消除，窗口从 24 条扩到 64 条，新增
`MRS/MSR NZCV/FPCR/FPSR` 与只读系统寄存器。编译器可生成的、无密钥、稳定的
读侧特征在 2.21.0 测试面上清零。

## 6. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` /
KernelPatch `0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux
Enforcing。模块 `urov-y.kpm` SHA-256
`0bc084fdf7ef964ba96aff76ae819829ea78a094d1e290ed30ca616fcbfe2ffa`，测试 APK
SHA-256 `f6640b001d5602b2e89913703bd7ea2cbbc227bf7f1a2965884fd573417e12c5`，
窗口模型测试 SHA-256
`1b8331e04ee2be83594cb613779016246648cc9de3f253484c0fba1fe327d52f`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v221` 6 模式 × 32 | PASS；AP-all overlay `pre_alu=0 fp=0 ap=0 evidence=0 accepted=32/32`；AP 调用窗口 `split=32 evidence=32 accepted=0`；`unknown=0` | [read-defense-v221-20261108-225828](results/read-defense-v221-20261108-225828/summary.json) |
| 生产 CRC 7 模式 × 3 | PASS；`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235` | [crc-20261108-225256](results/crc-20261108-225256/summary.json) |
| Dobby 检测 8×1 | PASS；`ap=0/8`、`accepted_crc_with_ap=8/8`、`spaced=0`、`views=0/8` | [dobby-detect-20261108-225328](results/dobby-detect-20261108-225328/summary.json) |
| 消除矩阵 3×1 | PASS；全部 `ELIM_CASE` 通过，`exclusive_match=0`、`ap_match=0` | [eliminate-20261108-225350](results/eliminate-20261108-225350/summary.json) |
| 多页 3×1 | PASS | [multipage-20261108-225504](results/multipage-20261108-225504/summary.json) |
| 窗口模型差分测试 | PASS；`cases=73 failures=0`（新增 17 个 FP/sysreg/dst 用例） | `out/urov_window_test` |

AP-all overlay 的 `READ_DEFENSE_V221_POLICY` 日志为
`pre_alu=0 fp=0 ap=0 ap_unknown=0 evidence=0 accepted=8`；AP 调用窗口为
`split=8 evidence=8 accepted=0`。两种 AP 配置的
`READ_DEFENSE_KEYLESS2` 仍为 `load=store=branch=xload=0`、`value=32/32`、
`clrex_bad=svc_bad=0`。所有阶段 `unknown=0`，会话结束后 `kpm list` 为空，
前后 boot ID 一致。

生产 CRC 回归中 `crc-ap-all` 的 EL0、`process_vm_readv`、pipe 与 fork 子进程读均
等于文件摘要 `f50bcaf6`，执行仍是 Dobby 的 `1235`；Dobby 检测活动阶段
`accepted_crc_old=8/8`、`accepted_crc_with_ap=8/8`、`ap=0/8`。这两组数据说明
2.21.0 没有把“AP 覆盖已经生效”变成“读值仍是改码后的活页”。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v221 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```

`--read-defense-v220` 仍保留给 2.20.0 模块；它断言 AP 阶段的 `pre_alu/fp=n`，在
2.21.0 上会按设计失败。2.21.0 的普通 App 检测入口是 `--read-defense-v221`。
