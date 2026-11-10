# UROV-Y 2.27.0：无密钥读侧特征的收口与"读真值"边界

2.26.0 的两条无密钥探针（[KEYLESS_2_26_AUDIT.md](KEYLESS_2_26_AUDIT.md)）分别击中
`PAGE_AP` 的值证明和分支图：

1. **对齐掩码**：`LDXR x8,[x1]; AND x1,x1,#~7; LDRB w10,[x0]; STXR w11,x8,[x1]`。
   `AND` 对任意输入不可逆，值证明放弃；而采样读的异常返回清掉本地监视器，目标
   `STXR` 因此失败。无模块时硬件预约仍在，`STXR` 成功。方向是"原生成功、模块失败"。
2. **无预约写入**：`CLREX; ADR x9,1f; BR x9; LDXR x8,[x1]; 1: BTI J; LDRB w10,[x0];
   STXR w11,x8,[x1]`。`BR` 是间接分支，直接分支目标图没有这条边，回推却把
   `BTI J` 前的死代码 `LDXR` 当成已执行；桥接因此写入哨兵并报成功。无模块时没有预约，
   `STXR` 必须失败。方向是"原生失败、模块成功"。

2.27.0 只改 `urov-y` 的读侧证明与测试工具，不新增 hook、线程、定时器、PTE/VMA 位、
代码字、ABI 字段或新的读视图。目标是：把这两类**已被构造出来**的差异全部消掉，并把
仍然残留的差异压到"必须有硬件 trace 才能判定"的范围内，同时保持生产 CRC 的伪造读。

## 1. 架构约束：异常返回必然清本地监视器

Arm A-profile 架构在 "Context switch support" 中规定 **"An exception return clears the
local monitor"**（DDI0487 §E2.10.4；QEMU 的 A64 实现见
[exception_return](https://qemu.googlesource.com/qemu/+/47ecb80041034b09b96490e4ee72d06232dfc919)）。
`PAGE_AP` 的每一次被采样读都要经由 EL1 异常处理再 `ERET` 返回 EL0，因此：

- App 在 `LDXR` 之后建立的预约，在采样读的异常返回时已经不存在；
- 模块**不能**让 App 的 `STXR` 原生成功，只能由 handler 代写并给出状态；
- 代写是否正确，取决于"无模块时这条 `STXR` 是否会成功"。

无模块时的成功条件是：`LDXR` 确实执行；其间没有清监视器的事件（`CLREX`、另一个
exclusive、异常、其他 PE 对监视地址的写）；`STXR` 的地址/宽度与预约一致。模块能证明
后两条，也能证明"直接分支没有进入采样区间"；它**不能**证明第一条：

- EL0 没有分支记录/trace；`PMU` 只有计数，没有目标；
- 本地监视器没有非破坏性查询指令；任何 `STXR` 查询都会清掉预约；
- 线性指令流可以被打断：一个间接分支跳进 `(ldxr_pc, fault_pc]`，死代码里的 `LDXR`
  不会执行，但指令字仍然躺在回推路径上。

因此"对任意 App 构造都完全无差异"在纯软件、EL1 的 KPM 内是不可判定的。2.27.0 的策略是
**把可判定的类证明掉，把不可判定的类压到有界且单向的失败方向**。

## 2. 方案

### 2.1 对齐感知的值证明（消除对齐掩码探针）

新增 [`uy_pre_step_aligned()`](urov_y_prewin.h#L438) 和带 `zero_mask` 的
[`uy_pre_invert()`](urov_y_prewin.h#L111)。`uy_llsc_prepare()` 现在分两遍：

1. 第一遍只解码，找到最近的 `LDXR/LDXP` 及其访问宽度 `lsize`；
2. 第二遍从故障点回推，把 `zero_mask = lsize - 1` 传给逆变换。

架构规定 exclusive 访问的地址必须按访问宽度自然对齐，否则在 `LDXR` 处就取 alignment
fault，根本到不了采样读。所以预约基址的低 `log2(lsize)` 位必为 0。对该集合：

| 指令 | 2.26.0 | 2.27.0 |
| --- | --- | --- |
| `AND/ANDS Rd,Rn,#imm`，`Rd==Rn` | 仅 `wmask==~0` 恒等 | 被清位 ⊆ `zero_mask` 时恒等 |
| `BIC/BICS`（`AND` 的 `N=1` 形式） | 仅操作数为全 1 | 被清位 ⊆ `zero_mask` 时恒等 |
| `ORR Rd,Rn,#imm` | 仅 `wmask==0` | 置位 ⊆ `zero_mask` 时 `pre = post & ~wmask` |
| `ORN`（`ORR` 的 `N=1` 形式） | 恒等仅当操作数为 0 | 置位 ⊆ `zero_mask` 时 `pre = post & ~other` |
| `EOR/EON` | 精确逆 | 不变 |

`AND x1,x1,#~7` 对 8 字节 `LDXR` 就是恒等：被清的低 3 位本来就是 0。探针因此回到
"计划成立、桥接代写成功"，与原生一致。`zero_mask == 0` 时退化为 2.26.0 的行为，
独立差分测试仍覆盖旧的"不可逆即未知"方向。

### 2.2 入口证明（消除无预约写入探针）

新增 [`uy_llsc_entry_skipped()`](urov_y_backend.c#L2732)：

- 从 `ldxr_pc - 4` 开始按 fall-through 反向最多走
  [`UY_LLSC_ENTRY_SCAN = 64`](urov_y_backend.c#L210) 条指令；
- 遇到的**第一条控制流指令**决定结果：
  - `BR/BLR/RET/BRAA/...`（寄存器间接分支）：从回推得到的 LDXR 入口状态取 `Xn`。
    若目标落在 `(ldxr_pc, fault_pc]`，说明这条分支可能跳过了 `LDXR`，计划放弃；
    若目标正好是 `ldxr_pc`，`LDXR` 必执行，接受；目标在区间外则视为无关前驱
    （叶子函数前面紧邻的上一个函数的 `RET` 就是这种形状），接受；
  - 直接 `B/BL/B.cond/CBZ/TBZ`：交给已有的直接分支目标图
    [`uy_llsc_skipped()`](urov_y_backend.c#L2413)，这里不再重复；
  - `SVC/BRK/...`：与 2.26.0 一样放弃。
- 只走第一条控制流指令，不越过它继续回溯：再往前的指令不在本函数的 fall-through
  路径上，继续回溯会把无关函数的 `RET` 误读成入口。

这个证明是**单向**的：返回 1 只会让计划放弃、让 `STXR` 回到原生失败，绝不会在硬件
没有预约的地址上制造成功。反过来，如果一条实际有效的窗口因为分支目标未知而被放弃，
会出现"原生成功、模块失败"的假失败；这类形状与 >64 条填充、跨函数间接进入一起归入
§3 第 12 项。对审计探针：

- `BR x9` 的目标是 `BTI J`（2.26.0 采样区间内），入口证明放弃，`STXR` 原生执行并
  报告失败；无模块同样失败，探针静默。
- 有效形状（`ADD #0`、`AND #~7`、chain、ADR、MRS、ZVA、CVAC、长窗口）的 LDXR 前驱是
  上一个叶子函数的 `RET`，`x30` 指向调用者，不在采样区间内，计划照常成立。

### 2.3 不变的边界

- 仍然只操作 `PAGE_AP` 的 `AP[1]`，不写代码、不改 VMA、不新增/移动映射；
- 仍然走原来的 `read_range(allow_fake)`，新增证明只影响"是否代写 `STXR`"；
- 请求/状态布局、ABI v8、`hooks=0xff`、控制通道、6 个 hook 的语义不变；
- 采样读的假数据路径完全不变，生产 CRC 的 `file/direct/business` 仍应一致。

## 3. 已消除与仍残留

| # | 2.26.0 残余 | 2.27.0 | 说明 |
| --- | --- | --- | --- |
| 1 | 对齐掩码导致预约丢失 | **消除** | 对齐感知逆，见 §2.1 |
| 2 | 间接分支跳过 LDXR 导致假成功 | **消除（审计形状及其 ≤64 条内填充）** | 入口证明，见 §2.2 |
| 3 | 计时 | 保留 | 题目允许；两遍回推 + 入口走查只增加有界内核工作量 |
| 4 | caller-window 分裂 | 保留 | 登记时选择的作用域语义；生产用 all-callers |
| 5 | root 可见性 | 保留 | 不在普通 App 输入集合内 |
| 6 | 同步故障 + 信号处理器跳过 | 仍残留 | 数据故障发生在 LDXR 与采样读之间时会清监视器；回推看不到这次异常。需要按任务记录故障 PC 才能收口，会引入新的全局状态和误报面，本轮不做 |
| 7 | 调用边界（`BL/BLR`） | 仍残留 | 线性证明不进入被调函数；方向是"模块放弃、原生成功" |
| 8 | 跨线程写监视地址 | 仍残留 | 其他 PE 的 store 清全局监视器；回推只跟踪本线程 |
| 9 | 32 位写基址、加载回读等"值恰好不变" | 仍残留 | 没有精确逆，放弃；与 2.26.0 相同 |
| 10 | SVE/SME、POE、未分类编码 | 仍残留 | 本机无这些扩展；未分类编码仍放弃 |
| 11 | 64 KiB 直线块之外 | 仍残留 | 有界内核工作量 |
| 12 | 入口证明边界外（>64 条填充、跨函数间接进入、窗口内覆盖分支寄存器导致目标未知） | 仍残留 | 见 §1：没有硬件 trace 无法证明"LDXR 真的执行"；任何有限静态证明都能被更长的死代码前缀或另一个函数里的间接分支绕开。目标未知时 2.27.0 选择放弃（假失败方向），不再保留"目标未知却代写成功"的假成功方向 |

第 6、8、12 项都可能让对手再次拿到"原生失败、模块成功"：第 6 项需要 App 在窗口内
制造一次数据故障并用信号处理器跳过，第 8 项需要另一个线程/PE 在窗口内写监视地址，
第 12 项需要把跳过 LDXR 的分支藏到 64 条之外或另一个函数里。第 7、9 项是反方向的
"原生成功、模块失败"；第 3、4、5、10、11 项是题目允许的计时/作用域/root 与有界工作量。
第 12 项的构造代价是：在 App 自己的 inline asm 窗口前放 >64 条可逆填充，或在另一个
函数里用间接分支跳进窗口中部。生产 CRC 代码不会产生这种形状；普通 App 要主动构造它，
本身就需要精确知道窗口地址和模块的 64 条上限。

## 4. 是否能让普通 App 通过"指定指令"读到真值

结论：**EL0 没有这样的指令；审计探针读到的不是真值，只是监视器状态。**

逐类检查（A64，EL0）：

| 指令类 | 是否返回目标页字节 | 说明 |
| --- | --- | --- |
| `LDR/LDRB/LDRH/LDRSW/LDUR/LDTR` | 是 | 都要过 stage-1 权限检查；`AP[1]=0` 必数据异常，由 `read_range` 从 image 取字节 |
| `LDP/LDNP/LDPSW` | 是 | 同上，按 `total` 覆盖 |
| `LD1/LD2/LD3/LD4`、跨页 | 是 | 同一异常路径，`read_range` 逐页组合；v8 多页 ABI 覆盖 |
| `LDXR/LDAXR/LDXP/LDAXP` | 是 | exclusive load 也是数据读，先取权限异常；旧值来自 image |
| `LDADD/SWP/CAS/CASP` 等 LSE | 是（旧值） | RMW 的读阶段同样异常；`uy_atomic_emulate` 用 `uy_read_logical()` 从 image 取旧值 |
| `LDRAA/LDRAB` | 是 | 指针认证 load 仍是数据读；失败认证才走信号 |
| `DC ZVA` | 否 | 写零，不返回数据 |
| `DC CVAC/CVAU/CIVAC/CVAP/CVADP`、`IC IVAU/IALLU` | 否 | 维护 cache，不返回数据；只可能留下计时差（允许） |
| `PRFM` | 否 | 预取提示，不返回数据 |
| `MRS/MSR` | 否 | 系统寄存器，不读目标页；EL0 不可读的编码直接 trap |
| SVE/SME load/store | 是（若存在） | 仍是数据访问，过同一权限检查；本机无扩展 |
| MTE `LDG/STG/GMI` | 否 | 只访问 allocation tag，不返回数据字节 |
| `AT/TLBI/SYS` | 否 | EL0 执行会 trap |

因此"换一条指令读真值"不成立。真值只可能从**不经过这条 PTE 的通道**漏出：

1. **同一物理页的别名映射**。`PAGE_AP` 只改注册 VMA 的叶 PTE；如果 App 能让另一个
   VA 映射到同一物理页，就能绕过。模块的 `validate_target_vma()` 只接受私有文件映射
   或"单页、不可写、无 `VM_MAYWRITE`"的共享映射；`fork` 的 PTE 副本由
   `uy_page_by_identity()`/`handle_mm_fault` 重新布防；`mremap/mprotect/munmap/
   madvise/MAP_FIXED` 由 gate 处理。私有 COW 页没有第二个可写别名；共享可写映射被
   拒绝。因此普通 App 不能在注册页上造出这个别名。
2. **内核代拷**。`process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、GUP、
   `io_uring` 注册缓冲等都会经过模块已有的 `access_remote_vm`/GUP/`kread` 钩子；命中
   注册页时用 image/快照替换源页。App 自己读自己的页也走同一条 `read_range`。
3. **硬件引擎/DMA**。把代码页导入 GPU、DMA 或安全世界需要系统权限或驱动接口，超出
   `untrusted_app` 的能力；不在本轮威胁模型内。
4. **计时**。cache 维护、异常路径、页表遍历都能给出时间差；题目明确允许保留。

审计的两条探针都不属于上述任何一条真值通道：它们没有读到真值，只是用 `STXR` 的
成功/失败证明"这次读被接管了"。2.27.0 消除的是这个**检测**特征，不是"读真值"通道；
后者本来就不存在。

## 5. 不新增特征

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新代码字/PTE/VMA/映射 | 不写代码、不改 PTE/VMA；只改 handler 内的寄存器模型 |
| 新 hook/线程/定时器/文件/ABI | 没有；`hooks=0xff`、ABI v8、`ctl0` 状态格式不变 |
| 新读视图 | 采样读仍走原 `read_range(allow_fake)` |
| 新写语义 | 只执行 App 自己的 store；`STXR/STXP` 仍只在地址/宽度/值匹配时由内核完成 |
| 新失败 | 入口证明把"目标可证明落在采样区间"和"目标未知"都改成原生失败；对齐逆把"被掩码改写但地址未变"改成原生成功。前者可能对极端构造产生假失败（§3 第 12 项），但不会制造假成功 |
| 新寄存器/标志结果 | 对齐逆只用于证明基址未变；提交仍用窗口模型 |
| 新计时台阶 | 第二遍回推和 ≤64 条入口走查都是有界线性工作；只在 LL/SC 桥上发生 |

## 6. 验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / 内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` / KernelPatch `c00` / SELinux Enforcing。
App 在 `untrusted_app`：`CapEff=0`、`Seccomp=2`。模块 `urov-y.kpm` SHA-256
`ffe75cf7ac9c82e042c1b3488470ef773937de6a6c4d4941bc250fcf015324d4`。

| 测试 | 结果 | 目录 |
| --- | --- | --- |
| 独立对齐/逆变换差分 `urov_prewin_test` | PASS；`cases=74 failures=0` | — |
| 独立窗口模型差分 `urov_window_test` | PASS；`cases=145 failures=0` | — |
| `--keyless-v227-audit` 6 模式 ×3 轮 ×32 次 | PASS；ap-all overlay `trap=0/32`、`crc_eligible=32`、`execute=1235`、`file=direct=business=96964c4f`；`mask=0`、`phantom=0`（全 5 阶段） | [keyless227-audit-20261110-223759](results/keyless227-audit-20261110-223759/summary.json) |
| `--keyless-v226` 6 个 2.26 前窗形状 ×8 | PASS；`chain=adr=mrs=zva=cvac=long=0` | [keyless226-20261110-223925](results/keyless226-20261110-223925/summary.json) |
| `--read-defense-v225` 6 模式 ×8 | PASS；ap-all `accept=8/8`、`evidence=0/8`；全部 v225 采样形状静默 | [read-defense-v225-20261110-223946](results/read-defense-v225-20261110-223946/summary.json) |
| 生产 CRC 7 模式 ×8 | PASS；`crc-ap-all` `file=direct=window=f50bcaf6 execute=1235`，桥接 `0/8` | [crc-20261110-224045](results/crc-20261110-224045/summary.json) |

`--keyless-v227-audit` 的 ap-all 关键日志：

```
KEYLESS226_AUDIT stage=overlay mask=0 mask_unknown=0 mask_triplets=3072 mask_failed=0 phantom=0 phantom_unknown=0 phantom_trials=1024 phantom_writes=0
KEYLESS225_STAGE stage=overlay n=32 ap=0 ... split=0 trap=0 ... crc_eligible=32
    file=96964c4f direct=96964c4f business=96964c4f execute=1235
```

同一设备、同一夹具在 2.26.0 上是 `mask=32`、`phantom=32`（
[keyless226-audit-20261110-220249](results/keyless226-audit-20261110-220249/summary.json)），
在 2.27.0 上全部为 0；`ap`（非 all-callers）仍按作用域语义显示 `split=32`，
`brk/uxn` 仍显示各自的代码字/取指特征——这三类是设计定义的，不是本轮要消除的读侧
残余。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
adb push ./kpms/urov-lab/out/urov_prewin_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/urov_prewin_test
adb shell /data/local/tmp/urov_prewin_test
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v227-audit --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v226 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v225 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 8 --cycles 1
```

## 8. 结论

- 2.26 审计的两条无密钥探针在 2.27.0 上都不再命中：对齐掩码由精确的对齐逆消除，
  无预约写入由入口证明改回原生失败。
- 生产 CRC 的伪造读保持不变：ap-all 全调用者模式下 `file/direct/business` 三者相等，
  补丁代码仍在执行（`execute=1235`）。
- 普通 App 无法用任何 EL0 指令读到注册页的真值；审计探针读到的是监视器状态，不是
  内存内容。真值只剩别名、内核代拷、硬件引擎三条非指令通道，分别由 VMA 限制、已有
  hook 和威胁模型排除。
- 剩余的读侧差异（§3 第 6–12 项）全部属于"没有硬件 trace 就无法判定"或题目允许的
  计时/作用域/root 边界；其中第 6、8、12 项仍可能构造出"原生失败、模块成功"，但都
  需要 App 自己制造窗口内的数据故障、跨线程写，或 >64 条填充/跨函数间接进入，已在
  该文档和代码注释中逐项标注。

