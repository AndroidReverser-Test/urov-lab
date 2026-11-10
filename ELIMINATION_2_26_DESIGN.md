# UROV-Y 2.26.0：读前值证明与剩余特征清理

本文记录 `urov-y` 2.26.0 相对 2.25.0 的变更。目标是清掉
[2.25 普通 App 检测审计](KEYLESS_2_25_AUDIT.md) 在普通 App 可构造范围内留下的
读取侧特征，同时**不新增** hook、线程、定时器、PTE/VMA、代码字或 ABI 字段。
只改 `urov-y`、测试 App/夹具、构建与文档。计时仍按题目允许保留。

## 1. 输入：2.25.0 仍然成立的特征

2.25.0 的读前证明按**寄存器是否被写**判定，不看写后值。审计里给出的短探针是：

```asm
ldxr x9, [x1]        ; 预约
add  x1, x1, #0      ; 写基址寄存器，但地址不变
ldrb w10, [x0]       ; 采样读 -> AP[1] 异常
stxr w8, x9, [x1]    ; 原生成功，2.25 桥接拒绝后失败
```

| # | 2.25.0 行为 | 普通 App 的构造 |
| --- | --- | --- |
| R1 | 读前窗口内任何对 LDXR 基址寄存器的写都让计划放弃 | 上表的 `ADD #0`；`ADD #8; SUB #8`；`EOR #1; EOR #1` |
| R2 | `uy_llsc_indirect()`：任一 GPR 的值落在 LDXR..读点区间内就让计划放弃 | 把区间内一个地址 `ADR` 进任意存活寄存器，不做分支 |
| R3 | 未分类编码让计划放弃 | `DC ZVA`/`DC CVAC`/`IC IVAU`、`LDRAA/LDRAB`；`MRS Rt,TPIDR_EL0` 只有 Rt==0 被识别 |
| R4 | 读前扫描上限 4096 条 | 在读点前放 4097 条以上纯寄存器指令 |
| R5 | 短探针之外的残余 | 见 2.25 设计 §5：计时、caller-window、root、信号处理器、跨线程、SVE/SME 等 |

R1 是审计里唯一仍被真机短探针稳定打中的项（2.25 矩阵 `keyless225-ap-all` 为
`ap=8/8`）。R2–R4 是同一份代码上可构造但上一轮未加探针的类别。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围；root 可见性不在普通 App 的输入集合内。本轮处理普通 App 的
EL0 读值与独占监视器特征。

## 3. 方案

### 3.1 读前：从写集改成值证明

新增 [`urov_y_prewin.h`](urov_y_prewin.h)，把读前窗口从“被写寄存器集合”改成
“逐指令回推的寄存器值表”：

- 状态 [`struct uy_pre_state`](urov_y_prewin.h#L56)：31 个 GPR + SP 的值，加
  “已知”位图。初始值取自故障时的 `pt_regs`（采样 load 尚未提交）。
- 对窗口内每条已退休指令，[`uy_pre_step()`](urov_y_prewin.h#L408) 先用
  [`uy_pre_writes()`](urov_y_prewin.h#L250) 求出写集，再对每个被写寄存器尝试
  [`uy_pre_invert()`](urov_y_prewin.h#L92) 求**精确逆**；求不出就置为未知。
- 回推到最近的 `LDXR/LDXP` 时，基址寄存器的已知值就是该独占 load 实际预约的
  地址。这个地址直接作为 `plan->base`（[`uy_llsc_prepare()`](urov_y_backend.c#L2703)），
  不再要求它等于故障时的基址值；前向窗口里的 `STXR` 地址比较决定桥接是否完成。

精确逆只覆盖“对任意前值都成立”的类，写错一个都会变成新的假成功：

| 指令类 | 逆 | 条件 |
| --- | --- | --- |
| `ADD/SUB (immediate)`，64 位 | `pre = post ∓ delta` | `Rd == Rn`，`Rd != 31` 或 `S == 0` |
| `ADD/SUB (shifted register)`，64 位 | `pre = post ∓ shift(other)` | `Rd == Rn`，另一源已知且不是 Rd |
| `EOR/EON (shifted register)`，64 位 | `pre = post ^ other` | `Rd == Rn` 或 `Rd == Rm && shift==0` |
| `AND/BIC/ORR/ORN (shifted register)` | 仅恒等：另一源为全 1 / 0 | 同上 |
| `EOR (immediate)` | `pre = post ^ wmask` | `Rd == Rn`，64 位 |
| `AND (immediate)` / `ORR (immediate)` | 仅 `wmask` 为全 1 / 0 | `Rd == Rn`，64 位 |
| `MOV Rd, Rd`（`ORR Rd,XZR,Rd`） | 恒等 | 由上一行覆盖 |

反过来，32 位写（高半部被零扩展丢失）、`AND/ORR` 只对当前值恰好不变、
load/原子/`MRS`/`CSEL`/`MOVZ`/`BFM` 等没有精确逆的写，都只会把该寄存器置为
未知。未知只让计划放弃，原生指令照常执行并报告硬件本来就会报告的失败；这正是
2.25 的失败路径，所以不会产生新的“模块成功、原生失败”。

审计短探针因此变成：回推 `ADD x1,x1,#0` 得到 `x1` 未变，计划成立，`STXR`
由桥接按原值完成，`w8 = 0`。

### 3.2 控制流：用分支目标图，删除寄存器启发式

2.25 的 `uy_llsc_indirect()` 仅凭“某个 GPR 里有一个区间内地址”就让计划放弃，
但地址在寄存器里并不说明控制流真的跳过了 `LDXR`。2.26 删除该启发式，改由已有的
分支目标图 [`uy_llsc_skipped()`](urov_y_backend.c#L2765) 证明：

- `REGISTER` 时扫描本 mm 的全部可执行 VMA，之后新建/故障调入的可执行页继续补扫；
  扫描不完整时图标记 incomplete，桥接直接放弃；
- 区间 `(ldxr_pc, fault_pc]` 内只要有直接分支目标，就说明 `LDXR` 可能没执行，
  放弃；没有则说明这条线性块就是实际执行路径。

同时把**直接与条件分支**（`B`、`B.cond`、`CBZ/CBNZ`、`TBZ/TBNZ`）归为“无 GPR 写、
不清本地监视器”的类：一条实际执行的条件分支不跳走时不会破坏预约，原先却让计划
放弃。`BL/BLR/BR/RET` 仍拒绝：调用会把执行带出线性块，间接分支的目标无法静态证明。

### 3.3 编码分类补全

| 编码 | 2.25 | 2.26 |
| --- | --- | --- |
| `DC CVAC/CVAU/CIVAC/CVAP/CVADP`、`IC IVAU/IALLU` | 未分类，放弃 | 无 GPR 写；只在 `SCTLR_EL1.UCI` 置位时接受 |
| `DC ZVA` | store 解码器无条件接受 | 无 GPR 写；只在 `SCTLR_EL1.DZE` 置位时接受 |
| `TLBI/AT` 等 `SYS` | 未分类，放弃 | **仍放弃**：EL0 执行会异常，异常清监视器 |
| `LDRAA/LDRAB` | 直接放弃 | 只写 `Rt`，写集精确 |
| `MRS/MSR` | 掩码含 `Rt`，只有 `Rt==0` 命中 | 掩掉 `[4:0]`，任意 `Rt` 都识别 |
| `B/B.cond/CBZ/TBZ` | 未分类，放弃 | 无 GPR 写 |
| `BL/BLR/BR/RET` | 放弃 | 放弃（调用/间接目标不在线性证明内） |

`SCTLR_EL1.UCI`/`.DZE` 在模块初始化时读取并存入
[`uy_pre_uci`/`uy_pre_dze`](urov_y_prewin.h#L25)。只有这两个位真的置位时才接受
对应的编码；否则它们在 EL0 会陷入异常，而异常入口会清本地监视器，一个跳过该异常的
信号处理器就能把桥接变成新的特征。`MRS/MSR` 的 `Rt` 掩码修正在共享的
[`urov_y_window.h`](urov_y_window.h) 里，前向窗口模型同样受益。

### 3.4 扫描上限 4096 → 16384

[`UY_LLSC_PRE_SCAN`](urov_y_backend.c#L192) 从 4096 条（16 KiB）提到 16384 条
（64 KiB）。这是内核工作量上限，不是架构限制；App 用 4200 条 NOP 的探针覆盖旧上限。

## 4. 不引入新特征

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的代码字/页表权限/VMA | 不写代码、不改 PTE、不新增/移动 VMA；仍只操作 `PAGE_AP` 的 `AP[1]` |
| 新的 hook/线程/定时器/文件/ABI | 没有；`hooks=0xff`、ABI v8、`ctl0` 状态格式不变 |
| 新的读视图 | 采样读仍走原 `read_range(allow_fake)`；新增探针只走同一入口 |
| 新的写语义 | 只执行 App 自己的 store；`STXR/STXP` 只在地址/宽度/值匹配时由内核完成 |
| 新的失败 | 所有不可精确证明的形状仍是“放弃 → 原生执行”，与 2.25 相同 |
| 新的寄存器/标志结果 | 回推只用于“证明地址未变”，不重算任何数据通路；提交仍用窗口模型 |
| 新的崩溃/信号 | 未知编码、调用、间接分支、异常指令仍放弃；没有 fail-open |
| 新的计时台阶 | 每次未建模窗口仍最多一次有界单步；读前扫描上限提高只影响极长直线块 |

“不引入”靠的是逆变换的**方向性**：只有对任意前值都精确的逆才会被接受；任何
“对当前值恰好成立”的掩码/32 位/加载写都退化成未知并放弃。因此新接受的每个形状
都满足“原生 `STXR` 也成功”。

## 5. 残余边界（2.26.0）

1. **计时**：`PAGE_AP` 每次 EL0 数据读一次同步异常；未建模窗口每条指令一次软件步
   异常；长窗口按指令数线性增加。按题目允许保留。
2. **caller-window 语义**：非 all-callers 会话下只有会话调用者看到 image，独立读者
   仍看到活页，`split` 可被观察到。这是登记时选择的作用域语义；生产用 all-callers。
3. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改 KernelPatch 核心；
   不在普通 App 的输入集合内。
4. **同步故障 + 信号处理器跳过**：读前窗口里放一条会同步故障的指令，再用信号处理器
   把 PC 前移；异常入口清本地监视器，而回推看不到这次异常。2.26 与 2.25 一样只保证
   不新增这类形状，并把它归入信号残余。
5. **区间中段的间接进入**：没有硬件 trace 时无法证明 `LDXR` 真的执行。直接分支已由
   分支目标图覆盖；用间接分支跳进区间中段仍是残余（2.25 的寄存器启发式只能部分
   拦截，且它本身就是 R2 特征）。
6. **调用边界**：`BL/BLR` 之后的被调函数不在线性证明内；调用里清监视器或改基址时
   计划放弃，原生失败，因此一致；但“被调函数什么都没做”的构造仍会让计划放弃，
   而原生会成功。这是线性证明的边界。
7. **跨线程写监视地址**：其他 PE 对监视地址的 store 清全局监视器；回推只跟踪本线程。
   生产 CRC 不在 `LDXR/STXR` 窗口内做跨线程写。
8. **不可逆但值恰好不变的写**：32 位写基址、`AND/ORR` 掩码恰好不变、`LDR` 读回原值
   等；这些形状计划放弃，原生是否成功取决于具体值，属于残余。
9. **SVE/SME、POE**：本机无这些扩展；`SYS` 类之外未分类的编码仍放弃。
10. **扫描上限**：64 KiB 直线块之外仍放弃，属有界内核工作量。
11. **SITE_BRK / PAGE_UXN 模式**：BRK 代码字与 UXN 取指是这两个模式的定义特征，
    不是 `PAGE_AP` 生产配置的特征；2.26 不改这两个模式。

## 6. 验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`c00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。

模块 `urov-y.kpm` SHA-256
`a6c792563aaa388db2002e46b627b0206aed6fa42feaf1013d6a0fb7d7d38bcc`。

| 测试 | 结果 | 目录 |
| --- | --- | --- |
| 独立读前差分测试 `out/urov_prewin_test`（EL0，无需 KPM） | PASS；`cases=67 failures=0` | — |
| 独立窗口模型差分测试 `out/urov_window_test`（EL0，无需 KPM） | PASS；`cases=145 failures=0` | — |
| `--keyless-v226`（ap-all，8 次 ×1 轮） | PASS；overlay `trap=0/8 ap=0 split=0 crc_eligible=8 execute=1235`；六个 2.26 探针全 0 | [keyless226-20261110-213857](results/keyless226-20261110-213857/summary.json) |
| 生产 CRC 7 模式 ×1 | PASS；`crc-ap-all` `file=direct=window=f50bcaf6 execute=1235` | [crc-20261110-213919](results/crc-20261110-213919/summary.json) |
| `--read-defense-v225` 6 模式 ×1（8 次/阶段） | PASS；AP-all overlay `split=0 evidence=0 accepted=8/8`，9 个 2.25 探针全静默 | [read-defense-v225-20261110-213952](results/read-defense-v225-20261110-213952/summary.json) |

`--keyless-v226` 的 overlay 阶段直接证明：

- 2.25 短探针（`LDXR; ADD base,#0; LDRB; STXR`）不再丢预约：`ap=0`；
- 追加的六个形状 `chain/adr/mrs/zva/cvac/long` 全为 0，`unknown=0`；
- 同一会话里 `direct`、`business` 与文件 CRC 三者相等（keyless 夹具为 `96964c4f`），
  `execute=1235` 说明补丁代码仍在执行，即活内存校验被绕过而业务读未受影响；
  生产 CRC 夹具的同一结论见上表 `crc-ap-all` 行的 `f50bcaf6`。

新增探针（[`native/urov_observe.c`](native/urov_observe.c#L557)）：
`ADD/SUB` 值保持链、`ADR` 区间地址、`MRS x9,TPIDR_EL0`、`DC ZVA`、`DC CVAC`、
4200 条 NOP 长窗口。夹具日志见
[`keyless225_fixture.inc`](apps/urov-detect/keyless225_fixture.inc#L93) 的
`KEYLESS226_EXTRA`。

## 7. 结论

- 2.25 审计的 R1–R4 全部消除：overlay 阶段 `ap=0/8`，六个新探针全 0；同一夹具在
  2.25 上是 `ap=8/8`（[keyless225-20261110-212052](results/keyless225-20261110-212052/summary.json)）。
- 生产 CRC 配置下，`file`、`direct`、`business` 三种活页读在补丁继续执行
  （`execute=1235`）时同为 `f50bcaf6`：crc 代码段校验被绕过，业务读不受影响。
- 每个新接受类都由精确逆（§3.1）、分支目标图（§3.2）或 SCTLR 控制位（§3.3）
  证明；没有任何“原生失败、模块成功”的形状被引入。
- 剩余边界见 §5。普通 App 可构造、且不属于计时/作用域语义的，只剩信号处理器跳过
  同步异常、区间中段间接进入、调用边界、跨线程与不可逆值保持写；它们要么需要 App
  自建信号处理器/间接入口，要么只发生在“模块放弃、原生成功”的方向，都不在生产
  CRC 的输入构造里。`SITE_BRK`/`PAGE_UXN` 仍是独立实验模式。

## 8. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
adb push ./kpms/urov-lab/out/urov_prewin_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/urov_prewin_test
adb shell /data/local/tmp/urov_prewin_test
adb push ./kpms/urov-lab/out/urov_window_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/urov_window_test
adb shell /data/local/tmp/urov_window_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v226 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```
