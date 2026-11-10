# UROV-Y 2.28.0：VMA 边界入口证明与“无硬件 trace 不可判定”的收口

2.27.0 消除了 2.26.0 审计的两条无密钥探针，但
[KEYLESS_2_27_DETECTION.md](KEYLESS_2_27_DETECTION.md) 随即用一条新的
`CLREX; ADR; BR; 64×NOP; LDXR; BTI J; LDRB; STXR` 探针证明：入口回查的
64 条上限本身就是一个可观测特征。2.28.0 只改 `urov-y` 的入口证明，把
“同一函数内任意长度填充”这一类假成功消掉；同时把剩余差异逐项归入
“必须依赖硬件 trace 或跨 PE 监视器才能判定”的集合，并给出不可判定的
构造性证明。**“除读取计时外全部特征点都消除”在 EL1-only KPM 内是不可能
的**；本版的目标是把这个边界讲清楚，并把仍可消除的那一类消到只剩单向
的假失败。

## 1. 2.27.0 残留的入口上限

2.27.0 的入口证明从 `ldxr_pc - 4` 开始按 fall-through 反向走，最多
`UY_LLSC_ENTRY_SCAN = 64` 条指令，遇到第一条控制流指令就停：

```asm
clrex
adr     x9, 1f
br      x9              // 目标在 (ldxr_pc, fault_pc] 内
.rept 64
nop                     // 64 条填充正好耗尽回查预算
.endr
ldxr    x8, [x1]        // 实际没有执行
1: bti  j
ldrb    w10, [x0]       // 采样读，进入 AP 异常
stxr    w11, x8, [x1]
```

`uy_llsc_skipped()` 的直接分支目标图看不到 `BR` 的边；64 条 NOP 又把
`BR` 推到回查窗口之外，于是 `uy_llsc_entry_skipped()` 没有看到任何
控制流指令而接受计划。handler 把死代码里的 `LDXR` 当成已执行，软件写入
哨兵并返回 `STXR` 成功。没有模块时硬件没有预约，`STXR` 必须失败。方向
是“原生失败、模块成功”，也就是最危险的假成功方向。

2.27.0 的正式矩阵里，`ap-all` 的
`KEYLESS227_ENTRY match=32 writes=1024`，而短窗口
`short_match=0`：短探针已经被 2.27.0 拒绝，长探针只是把分支推出了 64 条
边界。这个边界是内核工作量守卫，不是架构性质；任何有限常数都能被更长的
填充绕开。

## 2. 2.28.0 的改动：走到 VMA 起点或预算耗尽

### 2.1 入口回查

`UY_LLSC_ENTRY_SCAN` 从 64 提高到与读前证明相同的
`UY_LLSC_PRE_SCAN = 16384`（64 KiB 指令窗口），并增加一个下界
`floor`：LDXR 所在可执行 VMA 的 `vm_start`。回查从 `ldxr_pc - 4` 开始，
每步检查：

1. 地址低于 `floor + 4`：已经走到映射起点，按合法的 fall-through 入口
   接受；
2. 读到间接分支：
   - `Rn == 31`（XZR）不是有效目标，接受；
   - `RET x30`：这是编译器生成的上一个函数边界，使用 LDXR 入口处的
     `x30`；目标已知且在 `(ldxr_pc, fault_pc]` 内拒绝，未知也拒绝；
   - `BR/BLR/RET xN`（N != 30）：这是当前窗口内的真实分支，不能拿
     LDXR 入口处的寄存器值代替分支点的值——死填充可以在分支之后写
     这个寄存器。回查用 `uy_pre_step` 从 LDXR 入口逐条回退填充指令，
     在分支点求值；填充里出现不可逆写（`rewind_ok=0`）时拒绝；
   - 目标已知且在 `(ldxr_pc, fault_pc]` 内：拒绝；目标未知：拒绝；
3. 读到直接 `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ`：交给已有的直接分支目标
   图，接受；
4. 读到异常指令：接受（异常指令之前的路径与本次窗口无关）；
5. 预算 16384 条耗尽仍未遇到控制流：拒绝。

回退只覆盖分支与 LDXR 之间的指令；遇到 `RET x30` 就按函数边界处理，
不再向当前函数的序言回退，因此正常函数的 `STP x29,x30`、`PACIASP` 等
序言不会被误当成死填充。

第 5 条是 2.28.0 与 2.27.0 的关键方向差异。2.27.0 在预算耗尽时接受，
于是“分支被推到 64 条之外”变成假成功；2.28.0 在预算耗尽时拒绝，最多
把“真实有效但前置直线代码超过 64 KiB”的窗口变成假失败。假失败不会在
硬件没有预约的地址上制造成功，和 2.27.0 对“目标未知”的处理一致。

未知目标拒绝会带来一类假失败：如果当前函数在 `LDXR` 之前调用过别的
函数，`x30` 已经指向函数内部，回推到函数入口前的上一条 `RET x30` 时
目标就是未知的，计划会放弃。2.28.0 接受这个方向，因为它不会制造假成功；
2.27.0 对未知目标本来也是拒绝，2.28.0 只是把回查范围扩大，可能让更多
“调用后紧接 LL/SC”的正常形状落入这个已知的假失败类（§4 第 13 项）。

### 2.2 不变的边界

- 仍然只操作 `PAGE_AP` 的 `AP[1]`，不写代码、不改 VMA、不新增/移动映射；
- 仍然只改变“是否代写 `STXR/STXP`”，采样读的假数据路径完全不变；
- 不新增 hook、线程、定时器、PTE/VMA 位、代码字、ABI 字段或读视图；
  `hooks=0xff`、ABI v8、`ctl0` 文本不变；
- 入口回查只读用户指令字节，使用现有的 `uy_read_insn()`/`f_copy_in()`，
  不改变异常现场的其他寄存器。

## 3. 2.28.0 消除了什么

| 形状 | 2.27.0 | 2.28.0 | 方向 |
| --- | --- | --- | --- |
| 短窗口 `BR` 跳过 LDXR（2.26 探针） | 拒绝 | 拒绝 | — |
| 64 条 NOP 填充（2.27 探针） | 接受 → 假成功 | 拒绝 | 消除 |
| 任意 ≤64 KiB 同函数填充 | 取决于 64 边界 | 拒绝 | 消除 |
| 死填充用可逆写改掉 `BR/BLR` 的分支寄存器 | 用 LDXR 入口值 → 可能假成功 | 回退到分支点 → 拒绝 | 消除 |
| 死填充用不可逆写改掉 `BR/BLR` 的分支寄存器 | 值未知 → 拒绝 | `rewind_ok=0` → 拒绝 | 不变 |
| 对齐掩码 `AND #~7` | 接受（正确） | 接受（正确） | 不变 |
| 直接分支跨页跳过 | 目标图拒绝 | 目标图拒绝 | 不变 |
| 跨函数间接进入 | 接受 → 假成功 | 接受 → 假成功 | **残留** |
| 循环回跳（STXR 后 `BR` 回 LDRB） | 接受 → 假成功 | 接受 → 假成功 | **残留** |
| 前置直线代码 >64 KiB | 接受（假成功风险） | 拒绝（假失败） | 单向收敛 |

同设备、同夹具的 2.28.0 矩阵（详见
[KEYLESS_2_28_AUDIT.md](KEYLESS_2_28_AUDIT.md)）中，`ap-all` 的
`KEYLESS227_ENTRY match=0 writes=0`、`short_match=0`，生产 CRC 仍是
`file=direct=window=f50bcaf6`、`execute=1235`。

## 4. 2.27.0 §3 残留清单在 2.28.0 的状态

| # | 2.27.0 残留 | 2.28.0 | 可观测方向 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | 对齐掩码导致预约丢失 | 已消除 | — | 2.27 的对齐逆 |
| 2 | 短窗口间接跳过 LDXR | 已消除 | — | 2.27 的入口证明 |
| 3 | 计时 | 保留 | 允许 | 题目明确允许 |
| 4 | caller-window 分裂 | 保留 | 设计语义 | 只在非 all-callers 模式出现；生产用 all-callers |
| 5 | root 可见性 | 保留 | 不在普通 App 输入集合 | — |
| 6 | LDXR 与采样读之间的同步故障（信号处理器跳过） | 仍残留 | 假成功 | 回推看不到已经发生的异常；需要按任务记录故障 PC，会引入新状态 |
| 7 | 调用边界（`BL/BLR`） | 仍残留 | 假失败 | 值回推不进入被调函数 |
| 8 | 跨线程/跨 PE 写监视地址 | 仍残留 | 假成功 | 全局监视器是硬件状态，软件无法原子观察 |
| 9 | 32 位写基址、load 回读等“值恰好不变” | 仍残留 | 假失败 | 没有精确逆，放弃 |
| 10 | SVE/SME、POE、未分类编码 | 仍残留 | 假失败/不支持 | 本机无这些扩展；未分类编码仍放弃 |
| 11 | >64 KiB 直线块之外 | 仍残留 | 假失败 | 有界内核工作量 |
| 12 | 跨函数间接进入、死填充 `RET x30`/直接分支截断、循环回跳 | 仍残留 | 假成功 | 线性回查没有执行历史 |
| 13 | 入口回查预算耗尽、调用后未知 `RET`、`BR/BLR` 回退失败 | 2.28 新增的假失败 | 假失败 | 单向收敛的代价，见 §2.1 |

第 6、8、12 项都可能让对手拿到“原生失败、模块成功”。第 7、9、10、11、
13 项是反方向的“原生成功、模块失败”。第 3、4、5 项是题目允许的计时、
作用域和 root 边界。第 10 项在本机没有对应硬件扩展（`/proc/cpuinfo` 无
`sve`、`sme`、`mte`、`bti`），但代码仍按“未分类即放弃”处理。

## 5. 为什么“除计时外全部消除”不可能

### 5.1 架构事实

1. AArch64 的本地独占监视器是每 PE 的硬件状态，没有非破坏性查询指令。
   `LDXR` 设置预约，`STXR/STXP` 消费它并返回成功/失败，`CLREX` 清除它。
2. Arm ARM DDI0487 §E2.10.4 “Context switch support” 规定
   **“An exception return clears the local monitor.”**
   （[QEMU 的 A64 `exception_return` 实现](https://qemu.googlesource.com/qemu/+/47ecb80041034b09b96490e4ee72d06232dfc919)）
   `PAGE_AP` 的每次采样读都必须经过 EL1 异常并 `ERET` 返回 EL0，因此采样读
   返回时，App 在 `LDXR` 处建立的预约已经不存在。即使异常入口保留了
   监视器，EL1 也没有一条“查询但不消费”的指令；任何 `STXR` 查询都会
   消费预约并写内存。
3. 本地监视器还会被其他 PE 对监视地址的写、`CLREX`、另一个独占操作和
   异常清除。这些事件没有一条会留在故障现场的 `pt_regs`、`ESR`、`FAR`
   或页表里。
4. KPM 运行在 EL1，不能使用 stage-2 翻译、hypervisor 的监视器虚拟化，
   也不能读取 ETM/BRBE 的 branch record；这些都需要更高的异常级或受控
   调试基础设施。

### 5.2 判定问题

在采样读的异常点，handler 要回答的唯一问题是：

> 如果没有模块，App 接下来这条 `STXR/STXP` 会不会成功？

这个答案不是故障现场寄存器/内存的函数，而是

- **LDXR 是否真的执行过**：取决于 `LDXR` 到采样读之间的实际控制流；
- **期间是否有其他 PE 写监视地址**：取决于并发执行；
- **期间是否有异常/CLREX/另一个独占操作**：取决于实际执行历史。

前两项都不在异常现场。静态回推只能看到指令字，不能看到“哪条分支真的
走了”；硬件单步/trace 只能在指令退休后看到，不能改变已经发生的并发写。

### 5.3 静态证明的构造性反例：循环回跳

下面这段代码在**同一个函数、同一个 VMA** 内，不需要跨函数，也不需要
大于 64 KiB 的填充：

```asm
    // x1 = 对齐的私有 scratch，x0 = 被覆盖页地址
loop:
    ldxr    x8, [x1]        // A：第一轮执行，后续轮被跳过
    ldrb    w10, [x0]       // B：采样读，每轮都进入 AP 异常
    stxr    w11, x8, [x1]   // C：模块代写成功
    ...
    adr     x9, loop_b      // loop_b 就是 B 的地址
    br      x9              // 下一轮从 B 开始，跳过 A
```

第一轮：A 执行，B 触发异常，2.28.0 的入口回查在 A 之前只看到函数序言/
上一个 `RET`，接受计划，C 被代写成功。随后 `BR` 回到 B。第二轮：A 没有
执行；B 触发异常时，回查仍然在 B 之前看到 A（死代码），`uy_llsc_skipped`
的直接目标图没有 `BR` 的边，入口回查也看不到 A 之后的这条回跳，于是再
次接受计划，C 再次被代写成功。原生执行在第二轮没有预约，C 必须失败。
App 只需比较两轮/多轮的 `STXR` 状态和哨兵，就能稳定区分。

这条反例说明：任何**有限线性回查**都能被“把跳过分支放到回查路径之外”
绕开；把回查扩展到整个 VMA 也不行，因为分支可以在 LDXR 之后、也可以在
另一个函数里。要判定 A 是否执行，必须知道实际分支历史；EL0 没有 branch
record，EL1 也没有可用的硬件 trace。

### 5.4 动态 trace 也消不掉跨 PE 写

即使假设 handler 能单步/记录本线程的每条指令，并维护一个软件影子
监视器，第 8 项仍然存在：

```asm
// 读者线程
ldxr    x8, [x1]
ldrb    w10, [x0]      // 采样读，进入 EL1
stxr    w11, x8, [x1]  // 原生会因写者而失败

// 写者线程（另一个 PE）
str     x9, [x1]       // 在 LDXR 与 STXR 之间执行
```

软件影子监视器只能在写者线程的 store **退休之后**通过 debug exception
看到它；读者的 `STXR` 可能在写者的 step 异常被处理之前就已经执行。硬件
全局监视器是原子比较并清除的，软件模型总有一个“写已发生、影子还没更新”
的窗口。写者可以重复几千次把这个窗口撞出来；读者用原生对照（无模块时
偶发失败、模块时稳定成功）就能区分。这不是“读取计时”特征，而是
`STXR` 状态这一架构结果上的语义差异。

### 5.5 定理与推论

**定理（非形式）**：设 M 是一个只通过 EL1 异常接管 EL0 数据读、并让
App 继续执行 `LDXR/STXR` 的 KPM。若 M 对某些读返回与活页不同的字节，
则存在一个普通 EL0 程序 A，使得 A 在 M 下的架构可见结果（寄存器、内存、
`STXR` 状态，不只是计时）与原生执行不同。

证明要点：M 必须在采样读异常点决定 `STXR` 的结果；该结果依赖 M 无法在
该点观测的执行历史和跨 PE 写。若 M 恒报成功，§5.3 的循环回跳或 §5.4 的
写者构造给出“原生失败、M 成功”；若 M 恒报失败，任何正常的
`LDXR; LDRB; STXR` 序列给出“原生成功、M 失败”；任何在两者之间做有限
静态/动态近似的实现，都能被上述构造推到错误的一侧。只有不接管读（失去
伪造能力）、或由更高异常级/硬件 trace 虚拟化监视器，才能避免。

**推论**：

- “消除除计时外的全部特征点”在 EL1-only KPM + `PAGE_AP` 架构下不可实现；
- 可实现的极限是：消除所有**已知可构造的假成功**，把剩余假成功压到
  “必须利用跨函数/循环间接进入或跨 PE 写”的构造，把假失败压到有界
  模型边界；
- 2.28.0 把 2.27.0 暴露的“64 条填充”这一类假成功消掉，并把同函数填充
  的边界从 64 条扩展到 64 KiB；剩余的第 6、8、12 项属于上述定理的
  不可判定核心。

## 6. 普通 App 能否用“指定指令”读到真值

结论：**EL0 没有这样的指令；审计探针读到的不是内存真值，而是监视器
状态。**

### 6.1 指令类逐项检查

| 指令类 | 是否返回目标页字节 | 说明 |
| --- | --- | --- |
| `LDR/LDRB/LDRH/LDRSW/LDUR/LDTR` | 是 | 都要过 stage-1 权限检查；`AP[1]=0` 必数据异常，由 `read_range` 从 image 取字节 |
| `LDP/LDNP/LDPSW` | 是 | 同上，按 `total` 覆盖 |
| `LD1/LD2/LD3/LD4`、跨页 | 是 | 同一异常路径，`read_range` 逐页组合；ABI v8 多页覆盖 |
| `LDXR/LDAXR/LDXP/LDAXP` | 是 | exclusive load 也是数据读，先取权限异常；旧值来自 image |
| `LDADD/SWP/CAS/CASP` 等 LSE | 是（旧值） | RMW 的读阶段同样异常；`uy_atomic_emulate` 从 image 取旧值 |
| `LDRAA/LDRAB` | 是 | 指针认证 load 仍是数据读；认证失败才走信号 |
| `DC ZVA` | 否 | 写零，不返回数据 |
| `DC CVAC/CVAU/CIVAC/CVAP/CVADP`、`IC IVAU/IALLU` | 否 | 维护 cache，不返回数据；只可能留下计时差（允许） |
| `PRFM` | 否 | 预取提示，不返回数据 |
| `MRS/MSR` | 否 | 系统寄存器，不读目标页；EL0 不可读的编码直接 trap |
| SVE/SME load/store | 是（若存在） | 仍是数据访问，过同一权限检查；本机 `/proc/cpuinfo` 无 `sve`/`sme` |
| MTE `LDG/STG/GMI` | 否 | 只访问 allocation tag，不返回数据字节；本机无 `mte` |
| `AT/TLBI/SYS` | 否 | EL0 执行会 trap |

本机 `Features` 为
`fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp`，
没有 `sve`、`sme`、`mte`、`bti`；因此“用 SVE/MTE 指定指令绕过”在本机
也没有硬件基础。

### 6.2 非指令通道

真值只可能从**不经过这条 PTE 的通道**漏出：

1. **同一物理页的别名映射。** `PAGE_AP` 只改注册 VMA 的叶 PTE；模块的
   `validate_target_vma()` 只接受私有文件映射或“单页、不可写、无
   `VM_MAYWRITE`”的共享映射；`fork` 的 PTE 副本由
   `uy_page_by_identity()`/`handle_mm_fault` 重新布防；
   `mremap/mprotect/munmap/madvise/MAP_FIXED` 由 gate 处理。私有 COW 页
   没有第二个可写别名；共享可写映射被拒绝。测试中 `r--` 数据别名和
   `--x` 执行别名登记均返回 `EINVAL`。
2. **内核代拷。** `process_vm_readv`、`/proc/*/mem`、`ptrace`、
   `vmsplice`/pipe、GUP、`io_uring` 注册缓冲等都会经过模块已有的
   `access_remote_vm`/GUP/`kread` 钩子；命中注册页时用 image/快照替换
   源页。App 自己读自己的页也走同一条 `read_range`。
3. **硬件引擎/DMA。** 把代码页导入 GPU、DMA 或安全世界需要系统权限或
   驱动接口，超出 `untrusted_app` 的能力；不在本轮威胁模型内。
4. **计时。** cache 维护、异常路径、页表遍历都能给出时间差；题目明确
   允许保留。

审计中的 `LDXR; ...; STXR` 探针没有读到真值；它只是用 `STXR` 的成功/
失败证明“这次读被接管了”。2.28.0 消除的是这个**检测**特征（在可判定
范围内），不是“读真值”通道；后者本来就不存在。

## 7. 生产 CRC 代码段校验

2.28.0 没有改采样读的数据路径。生产夹具 `crc-ap-all` 的 overlay 阶段：

```text
CRC_STAGE name=overlay n=8 execute=1235
    backing=0c7da8a0 direct=f50bcaf6 site=f50bcaf6 window=f50bcaf6
    bridge_match=0 bridge_clean=8 bridge_unknown=0 kernel=f50bcaf6
```

- 活页 `backing` 是 Dobby 改码后的 `0c7da8a0`，取指执行 `1235`（改码后）；
- EL0 直接读、`crc_copy_window` 业务读、独立 reader 和内核代读
  （`process_vm_readv`/pipe/GUP）都返回文件摘要 `f50bcaf6`；
- 7 种 CRC 模式（`crc-brk`、`crc-uxn`、`crc-ap`、`crc-ap-all`、
  `crc-ap-text`、`crc-ap-libc`、`crc-ap-big`）全部 PASS；
- `bridge_match=0/8`：没有触发 LL/SC 桥，说明生产 CRC 路径没有被入口
  证明的改动影响。

这就是“绕过实际生产环境 CRC 代码段校验”的目标：CRC 拿到发布文件字节，
执行仍是改码后的指令。

## 8. 不新增成功特征

本版唯一的可观测变化是 §4 第 13 项的有界假失败：入口回查预算耗尽、
调用后遇到未知 `RET`、或 `BR/BLR` 死填充里出现不可逆写导致无法回退时
拒绝，替代 2.27.0 在同样形状下可能给出的假成功。它属于模型边界，不是
新的读视图、写语义或成功路径。

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新代码字/PTE/VMA/映射 | 不写代码、不改 PTE/VMA；只改 handler 内的线性回查 |
| 新 hook/线程/定时器/文件/ABI | 没有；`hooks=0xff`、ABI v8、`ctl0` 状态格式不变 |
| 新读视图 | 采样读仍走原 `read_range(allow_fake)` |
| 新写语义 | 只执行 App 自己的 store；`STXR/STXP` 仍只在地址/宽度/值匹配时由内核完成 |
| 新失败方向 | 入口回查耗尽从“接受”改为“拒绝”，把一类假成功换成有界假失败；不制造假成功 |
| 新寄存器/标志结果 | 入口回查只读指令字，不修改 `pt_regs`；提交仍用窗口模型 |
| 新计时台阶 | 回查最多 16384 条指令，且只在 LL/SC 桥上发生；有界线性工作 |

## 9. 验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / 内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` / KernelPatch `c00` /
SELinux Enforcing。App 在 `untrusted_app`：`CapEff=0`、`Seccomp=2`。
构建 `urov-y.kpm 5e355713...`、`urovdetect.apk 82360af1...`。

| 测试 | 结果 | 目录 |
| --- | --- | --- |
| 独立对齐/逆变换差分 `urov_prewin_test` | PASS；`cases=74 failures=0` | [v228-standalone](results/v228-standalone-20261111-0005/standalone.log) |
| 独立窗口模型差分 `urov_window_test` | PASS；`cases=145 failures=0` | [v228-standalone](results/v228-standalone-20261111-0005/standalone.log) |
| `--keyless-v228-detect` 6 模式 ×5 轮 ×32 次 | PASS；`ap-all` `trap=0/32`、`entry match=0 writes=0`、`file=direct=business=96964c4f`、`execute=1235` | [keyless228-detect-20261111-001129](results/keyless228-detect-20261111-001129/summary.json) |
| `--keyless-v226` 6 个 2.26 前窗形状 ×8 | PASS；`chain=adr=mrs=zva=cvac=long=0` | [keyless226-20261111-000952](results/keyless226-20261111-000952/summary.json) |
| `--read-defense-v225` 6 模式 ×4 | PASS；`ap-all` `accept=4/4`、`evidence=0/4`、`value=16/16` | [read-defense-v225-20261111-001014](results/read-defense-v225-20261111-001014/summary.json) |
| 生产 CRC 7 模式 ×8 | PASS；`crc-ap-all` `file=direct=window=f50bcaf6 execute=1235`，桥接 `0/8` | [crc-20261111-001443](results/crc-20261111-001443/summary.json) |

完整 `--keyless-v228-detect --repeats 32 --cycles 5` 的逐阶段结果见
[KEYLESS_2_28_AUDIT.md](KEYLESS_2_28_AUDIT.md)；如果完整矩阵与本表快速
结果不一致，以完整矩阵和 `summary.json` 为准。

复跑：

```powershell
./kpms/urov-lab/build.ps1
adb push ./kpms/urov-lab/out/urov_prewin_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/urov_prewin_test
adb shell /data/local/tmp/urov_prewin_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v228-detect --repeats 32 --cycles 5
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v226 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v225 --repeats 4 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 8 --cycles 1
```

## 10. 结论

- 2.28.0 消除了 2.27.0 暴露的“64 条 NOP 填充”假成功，并把同函数填充的
  可判定范围扩展到 64 KiB；短窗口、对齐掩码和生产 CRC 路径不变。
- 普通 App 不能靠任何 EL0 指令读到注册页真值；审计探针读到的是监视器
  状态。真值只剩别名、内核代拷、硬件引擎三条非指令通道，分别由 VMA
  限制、已有 hook 和威胁模型排除。
- “除读取计时外全部特征点都消除”在 EL1-only KPM 内不可实现：`STXR`
  的结果依赖 `LDXR` 是否真的执行（§5.3 的循环回跳/跨函数构造）和跨 PE
  写（§5.4 的写者构造），这两项都不在异常现场，也没有非破坏性查询。
  2.28.0 把假成功收敛到第 6、8、12 项，把其余差异收敛到有界假失败；
  这是该架构下可验证的极限。
- 生产 CRC 仍被完整绕过：活页改码 `0c7da8a0`、执行 `1235`，而
  EL0/内核/pipe/GUP 读都返回文件摘要 `f50bcaf6`。
