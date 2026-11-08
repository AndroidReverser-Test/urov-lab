# UROV-Y 2.19.0：LL/SC 窗口的寄存器级补完

本文记录 `urov-y` 2.19.0 针对 2.18.0 残余 §6.5 的变更。目标是在**不新增
App 可观察特征**的前提下，消掉普通 App 无密钥可复现的最后一条稳定读侧特征：
`PAGE_AP` 的读异常清掉本地独占监视器后，`LDXR; LDRB; ADD; STXR` 仍能观察到
`STXR` 失败。

只改 `urov-y`、测试 App/夹具、构建与文档；`urov-lab`、`urov-x` 不动；ABI 仍为
v8，`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.18.0 仍成立的特征

2.18.0 已经消掉双 iovec 写回（H1）和外部写退役（H2），也保留了相邻/NOP/BTI
间隔的 LL/SC 补完。它仍成立的特征见
[ELIMINATION_2_18_DESIGN.md](ELIMINATION_2_18_DESIGN.md) §6，其中唯一能被普通
App 稳定、无密钥复现的是 §6.5：

| # | 2.18.0 行为 | 普通 App 的用法 | 2.18.0 证据 |
| --- | --- | --- | --- |
| H7 | `PAGE_AP` 的读异常会让本地独占监视器失效；handler 只补完相邻或 `NOP`、`BTI` 间隔的 `LDXR; load; STXR` | `LDXR; LDRB; ADD; STXR`：在 load 与 store 之间放一条寄存器 ALU，`STXR` 原生执行并失败 | 2.18 设计 §7.2；`READ_DEFENSE_V218 ... trap=96/96 accept=0/96` |

2.18.0 的其余残余（重放窗口、pkey/POE、root 可见性、子进程外部写、重放交叠、
不缺页 uaccess 写）不是稳定的字节视图特征，或需要 root/POE 硬件；本轮不改变
它们，理由见 §5。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围。root 可见性不在普通 App 的输入集合内。本轮只处理 H7。

## 3. 方案

### 3.1 把“只允许 NOP/BTI 间隔”扩成可证明的寄存器窗口

2.18.0 的 `uy_llsc_scan_after()` 从故障 load 的 PC+4 起逐条读指令，只接受
`STXR` 或 `NOP/BTI`。H7 的 ALU 探针在 `LDRB` 与 `STXR` 之间放
`ADD X9, X9, #1`，扫描在 gap 的第一条就拒绝，因此只剩原生失败路径。

2.19.0 保留同一条控制流与寄存器证据链，只把前向扫描的“间隔白名单”扩为
**寄存器-only 数据加工**：

- `ADD/SUB`（immediate，含 LSL #12；32/64 位，含 S）；
- `ADD/SUB`（shifted register，LSL/LSR/ASR；32/64 位，含 S）；
- `AND/ORR/EOR` 及其反码形式 `BIC/ORN/EON`（shifted register；含 `ANDS` 的
  N/Z 标志语义）；
- `MOVN/MOVZ/MOVK`；
- `NOP/BTI`。

其余形状仍然拒绝：load/store（含 exclusive/LSE）、分支、异常生成、system
register、`CLREX`、PC-relative 和读标志的条件选择。扫描上限为
`UY_LLSC_GAP_MAX=8` 条指令。拒绝时 `valid=0`，frame 仍走 2.18 的原生路径，
不会把无法证明的 store 提前退休。

### 3.2 在私有寄存器副本上重放 gap

故障点仍在 `LDRB`。handler 先按 2.18 的规则证明：

1. `LDXR/LDAXR` 在 load 前 0–3 条 `NOP` 内；
2. `LDXR` 的目的寄存器仍等于 `[Xn]` 的当前值（`XZR` 形状走控制流证据）；
3. 任何可执行映射都没有直接分支进入 `LDXR..load`；
4. 没有 GPR 仍持有该区间的地址（间接分支证据）；
5. `STXR` 的基址寄存器、宽度与 `LDXR` 一致。

然后 2.19.0 才新增两步：

1. 把 `regs` 复制到 `struct uro_regs model`，在副本上按顺序执行 gap 的每条
   指令。32 位写 Wd 时清零高 32 位；`Rd==31` 只丢弃；`ADD/SUB/ANDS` 的 S
   形式更新 NZCV；`MOVK` 保留目的寄存器其余位；`SP` 形式与读标志的指令不在
   白名单内。
2. 在 `STXR` 的 PC 处读取**当前** `Rn`、`Rt`、`Rs`：要求 `Rn` 仍等于
   `LDXR` 的监视地址，store 值取 `Rt`（`Rt==XZR` 取 0），宽度取 `STXR` 的
   size。只有 `copy_to_user` 成功后才把 model 的寄存器/NZCV 写回 `regs`，把
   `Rs` 置 0，并把 PC 设为 `STXR+4`。任何一步失败都不写回 model，gap 与
   `STXR` 按原生指令执行，`STXR` 继续报告原生失败。

关键点：store 的字节、宽度、基址和值都来自 App 自己的 `STXR` 与 gap 后的
寄存器状态，handler 不引入新的写入；gap 的寄存器和标志效果与原生执行一致。
[gap 解码](urov_y_backend.c) · [gap 重放](urov_y_backend.c) ·
[提交](urov_y_backend.c)

### 3.3 失败关闭与不变路径

- gap 中出现白名单外指令：`uy_llsc_prepare()` 返回 `valid=0`，不启动补完。
- 扫描越界、读不到指令、`Rn` 被 gap 改掉、store 地址不再等于监视地址：
  `uy_llsc_commit()` 直接返回，PC 停在 gap 的第一条，原生执行。
- `copy_to_user` 失败：同样不提交 model；保持 2.18 的 fail-closed。
- 非 AP 模式、非 LL/SC 读、`SET`/`SET_PAGE`/卸载/重放路径不变；pair
  `LDXP;...;STXP` 路径不变。
- 没有新增 hook、线程、定时器、文件、syscall、PTE/VMA/代码字改动；唯一的
  新增工作是 handler 内的最多 8 条指令解码和一份约 220 字节的栈上计划。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍然只操作 `PAGE_AP` 的 AP[1] 陷阱 |
| 新的读视图 | 读路径和 caller-window 判定不变；补完只发生在 `LDXR..STXR` 窗口内，普通读取仍按 image/snapshot 返回 |
| 新的写语义 | 只写 App 自己 `STXR` 本来要写的地址、宽度和值；`Rn` 不等于监视地址时拒绝；`copy_to_user` 失败时原生重试 |
| 新的寄存器/标志结果 | gap 与 `STXR` 的架构效果被逐条建模：32 位零扩展、XZR/SP、NZCV、MOVK 保留位；白名单排除读标志的指令，避免依赖未建模的 NZCV |
| 新的崩溃/信号 | 白名单外形状保持 2.18 的原生路径；补完失败不跳 PC、不改状态；`force_segv` 路径不变 |
| 新的返回码/ABI | `STXR` 的 `Ws=0` 是原生成功值；ABI v8、`ctl0`、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；没有新增内核对象或 syscall 入口 |
| 新的计时台阶 | 每次 AP 读多最多 8 条指令的 nofault 取指/解码；命中窗口时 gap 由 handler 建模而不是 EL0 执行。计时按题目允许保留 |

## 5. 残余（2.19.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读仍有一次同步异常；未解码 store 仍有
   Software Step 与整页 diff；命中 LL/SC 窗口时多一次有界扫描/建模。按题目
   允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍
   保留陷阱项；跨 CPU TLB miss 的亚指令级竞态。与 2.18 相同，属于计时同级。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心。
5. **非寄存器-only 的 LL/SC 窗口**：gap 含 load/store、分支、异常、system
   register、`CLREX` 或读标志指令时，2.19 仍不补完，`STXR` 报原生失败。这是
   有意的 fail-closed 边界：这些指令会引入额外内存/异常/控制流语义，静态
   建模无法保证“不新增特征”，因此不进入本轮白名单。它不是 2.19 新引入的
   行为，2.18 对这些形状同样失败；本轮把可证明的寄存器窗口从 NOP/BTI 扩到
   全部常见整数数据加工，覆盖了现场探针的 ALU 形状。
6. **子进程的外部写、外部写与未解码 store 重放的交叠、不缺页 uaccess 写**：
   与 2.18 相同，不改变 owner 的读值视图；见 2.18 设计 §6.6–§6.8。

## 6. 真机验证（本轮）

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` /
KernelPatch `0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、
SELinux Enforcing。模块 `urov-y.kpm` SHA-256
`b173a91ab631c08ab55dc84c18a8cbc653135969080affe0915236cbaf233208`，
测试 APK SHA-256 `b7c82bdecc8d25142ebc26759b0fc90f4c5ddaf7fd2be83531e783d54970e330`
（大小写以构建输出为准）。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| `--read-defense-v219` 6 模式 × 16 | PASS；AP-all overlay `split=0 trap=0 accept=16/16`；AP 调用窗口 `split=16 trap=0 accept=0/16` | `results/read-defense-v219-20261108-191009` |
| 生产 CRC 3×1（7 模式） | PASS；`crc-ap-all` `execute=1235`、`file=window=f50bcaf6` | `results/crc-20261108-191038` |
| Dobby 检测 8×1 | PASS；`accepted_crc_with_ap=8/8`、`ap=0/8` | `results/dobby-detect-20261108-191106` |
| 消除矩阵 3×1 | PASS；全部 `ELIM_CASE` 通过，`exclusive_match=0`、`ap_match=0`；`ELIM_PROT_STORE shapes=16` | `results/eliminate-20261108-191126` |
| 多页 3×1 | PASS（见结果目录） | `results/multipage-20261108-191239` |

App 的 `READ_DEFENSE_V219` 日志在活动 AP-all 阶段给出
`trap=0`、`target_failed=0`、`accept=n`；活动 AP 调用窗口仍按 caller-window
语义给出 `split=n`，说明补完没有把覆盖扩到窗口外。所有阶段 `unknown=0`，
会话结束后 `kpm list` 为空，前后 boot ID 一致，增量内核日志无
BUG/WARNING/Oops。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v219 --repeats 16 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
```

`--read-defense-v218` 仍保留给 2.18.0 模块；它断言 AP 的 `trap=n`，在 2.19.0
上会按设计失败。2.19.0 的普通 App 检测入口是 `--read-defense-v219`。
