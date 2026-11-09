# UROV-Y 读取完整性复核结果

本文按最新复核在前排列。

## 2.25.0 全采样宽度、读前写集证明与单步生命周期

`urov-y` 2.25.0 把「读值替换」从只支持单个标量采样读，扩展到普通 App 能用的全部
采样形状：`LDP`/`LDPSW`/`LDP Q`（`count == 2`）、`LDR Q`/`LDP Q`、`LD1..LD4` 多结构、
以及 `LDXR/LDAXR/LDXP/LDAXP` 本身。读前证明从「整数 ALU 白名单」换成**写集证明**：
只要一条指令不可能清本地监视器、也不可能写 LDXR 基址寄存器，就接受它。成对预约
不再要求间隙全是 NOP，`SP` 也可以作独占基址。设计与残余边界见
[ELIMINATION_2_25_DESIGN.md](ELIMINATION_2_25_DESIGN.md)。

2.24.0 复测自己发现的 `LDP` 特征（本文件下一节）因此消失：
`--read-defense-v224` 的旧判定在 2.25.0 上不再检出（同一夹具停在
`v224 LDP ... ap=0/3`），`--read-defense-v225` 则以「全部静默」为期望。

### 读值路径

`REGISTER` 仍只接受文件支持的 `r-x` 映射，保存活页为 `snapshot`、按 `SRC_USER`
叠加出 `image`。`PAGE_AP` 仍只清目标页叶 PTE 的 `AP[1]`；采样读由异常钩子解码并
回填。2.25.0 的差别只在预约模型：`decode.c` 现在把独占 load 解码成普通 load 并带上
`excl`，`uy_llsc_prepare()` 只在故障指令自己就是独占 load 时用它建计划，其余情况
只从故障指令向前找最近的独占 load。
[独占解码](decode.c#L243) · [读前证明](urov_y_backend.c#L2790) ·
[写集分类](urov_y_backend.c#L2659) · [成对完成](urov_y_backend.c#L2584)

### 无密钥探针

夹具为 2.25.0 新增 9 个变体（`READ_DEFENSE_V225_PROBE`，编号见
[urov_observe.h](native/urov_observe.h#L193)）：

| 变体 | 序列 | 2.24.0 | 2.25.0 |
| --- | --- | --- | --- |
| 0 `pair` | `LDXR; LDP Wt,Wt2; STXR` | `STXR` 全失败 | 静默 |
| 1 `vec` | `LDXR; LDR Q0; STXR` | 全失败 | 静默 |
| 2 `multi` | `LDXR; LD1 {V0,V1}; STXR` | 全失败 | 静默 |
| 3 `pre_fp` | `LDXR; FADD D0,D0,D0; LDRB; STXR` | 全失败 | 静默 |
| 4 `pre_load` | `LDXR; LDR W; LDRB; STXR` | 全失败 | 静默 |
| 5 `pre_store` | `LDXR; STR W; LDRB; STXR` | 全失败 | 静默 |
| 6 `pre_lse` | `LDXR; LDADD W; LDRB; STXR` | 全失败 | 静默 |
| 7 `pre_ext` | `LDXR; ADD Xt,Xn,Wm,UXTB; LDRB; STXR` | 全失败 | 静默 |
| 8 `pair_gap` | `LDXP W,W; LDRB; ADD; STXP` | 全失败 | 静默 |

另加 `ud_read_exclusive_byte()`：用 `LDXR Wt,[target]; CLREX` 读采样页的一个字节。
2.24.0 只解码普通 load，这条合法读直接变成 `SIGSEGV/SEGV_ACCERR`；2.25.0 返回与
普通读相同的字节（`xldr_bad=0`）。所有变体只采样同一文件字节，独占存储只写线程
私有 scratch，对照页是同文件同偏移的只读别名。

### 阻断与业务隔离

完整性校验、文件摘要、独立执行映射与 seccomp TSYNC 规则不变（见下文 2.24.0 节）。
2.25.0 没有新增 hook、线程、定时器、PTE/VMA 或代码字，ABI 仍为 v8、`hooks=0xff`。

### 真机结果（2026-11-10）

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `c00`。
App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
`/proc/cpuinfo` 无 SVE/SME。模块 `urov-y.kpm` SHA-256
`1623c6e3eca92ec7f3c8eb5201615f53421cd1d9c96ed92e1f5fe9d5761a7bcc`（重跑构建得到同一
字节），测试 APK SHA-256 `2abc53ad81d0408c6dd3441ac983baa39f73d859613657178accf85455585367`；
APK 的 zip 时间戳使重打包不再逐字节相同，其原生库 `liburovdetect.so` 为
`59789f29ebacfa19017da66b8414b9a8feaed0ce40002f00454e7752b231d627`。

6 种配置 ×3 轮，每阶段 32 次，共 21 次启动：

| 阶段 | 判定次数 | 接管证据 | 内容变化 | 采信 |
| --- | ---: | ---: | ---: | ---: |
| 干净页，含空载和卸载后 | 672 | 0 | 0 | 672 |
| 仅补丁和撤销后保留补丁 | 1,248 | 0 | 1,248 | 0 |
| 等值接管 | 576 | 0 | 0 | 576 |
| 伪造读取 | 576 | 480 | 0 | 96 |

伪造读取阶段的 576 次里，480 次来自 BRK/UXN 的读点证据和 AP **调用窗口**的
`split`（作用域语义），96 次是 AP 全调用者的 `accept`——即全调用者覆盖下
每一次伪造读都被采信，且没有任何新探针命中。

`READ_DEFENSE_V225_PROBE` 在全部 21 次启动、每个阶段都是
`pair=vec=multi=pre_fp=pre_load=pre_store=pre_lse=pre_ext=pair_gap=0`、
`unknown=0`、`xldr_bad=0`、`xldr_done=32`；`READ_DEFENSE_V225_RESIDUAL` 为
`leaf_call=permute=fp_arith=pre_mov=pre_long=self_bad=neon_bad=deep_bad=0`、
`self_done=neon_done=deep_done=32`。AP 全调用者 overlay 的
`READ_DEFENSE_V225_POLICY` 为 `split=0 evidence=0 accepted=32`，
`READ_DEFENSE_V225_BOUNDARY` 为 `ap=0 ap_unknown=0 evidence=0 accepted=32`。
BRK/UXN 模式仍按各自语义被检出（`split=32 evidence=32`）。
[真机矩阵](results/read-defense-v225-20261110-004656/summary.json)

同一夹具对 2.24.0 模块的结果作为对照：`--read-defense-v224` 在 AP 模式停在
`v224 LDP ... ap=0/3`（旧判定不再检出），而 `--read-defense-v225` 在 `identity`
阶段直接以 `Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR)` 终止（`LDXR` 采样读）。
[2.24.0 对照](results/read-defense-v224-20261110-005527) ·
[2.24.0 SIGSEGV 对照](results/read-defense-v225-20261110-004257)

生产 CRC 7 模式全部通过：`crc-ap-all` 的 `direct`、`window` 与文件摘要三方都是
`f50bcaf6`，而原映射执行仍是 Dobby 的 `1235`；`crc-ap`（调用窗口）与
`crc-ap-text`/`crc-ap-libc`/`crc-ap-big`（非文件支持的别名被拒绝）行为不变。
消除矩阵 3×1（`site_call_ns=507`）、多页 6 场景×1、窗口模型
`cases=145 failures=0` 全部通过。会话结束 `kpm list` 为空，boot ID 不变，
增量内核日志无 BUG/WARNING。
[生产 CRC](results/crc-20261110-005321/summary.json) ·
[消除](results/eliminate-20261110-005341/summary.json) ·
[多页](results/multipage-20261110-005458/summary.json)

本轮真机还暴露并修复了一个单步生命周期问题：预约被 `CLREX`/独占 store/异常清掉后，
2.24.0 仍逐条单步跟随任务直到它下一次执行独占 store。新探针制造的大量这种尾巴在
持续高强度矩阵下触发过内核 panic（产测镜像 `softlockup_panic=1`）。现在
`uy_step_prev()` 发现预约已失效就立即结束单步；修复后 21 次启动连续通过。
[设计 §6.1](ELIMINATION_2_25_DESIGN.md#61-单步生命周期修复实测发现)

在 `kpms/urov-lab` 目录复跑。

```powershell
.\build.ps1
.\apps\urov-detect\build.ps1
adb push .\out\urov_window_test /data/local/tmp/
adb shell /data/local/tmp/urov_window_test
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --read-defense-v225 --repeats 32 --cycles 3
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python .\tools\run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python .\tools\run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```

## 2.24.0 普通 App 成对读取复测

### 从登记到读值替换

`urov-y` 通过 ABI v8 接收带 MAC 的请求，一次服务一个调用进程的 `mm`。`REGISTER`
验证目标是文件支持的 `r-x` 映射，保存活页为 `snapshot`，用调用者提供的 `SRC_USER`
字节叠加出 `image`。模块检查 LR 和帧链来选择视图。调用窗口内返回 `image`，窗口外
返回 `snapshot`，`caller_count=0` 时所有读者都在窗口内。
[登记](urov_y_backend.c#L4600) · [镜像](urov_y_backend.c#L4586) ·
[调用窗口](urov_y_backend.c#L1710)

| 模式 | 读值如何改变 | 普通 App 可取的证据 |
| --- | --- | --- |
| `SITE_BRK` | 通过私有 COW 将登记的读指令改为 `BRK`，陷入内核后模拟原 load | 复核已知读点的发布指令字，或对比业务读者和独立读者 |
| `PAGE_UXN` | 设置读点页叶 PTE 的 UXN，接管取指异常并模拟已知指令 | 对已知的 `BTI; RET` canary 做取指预约对照，或比较读视图 |
| `PAGE_AP` | 清目标页叶 PTE 的 `AP[1]`。CPU 仍从活页取指，EL0 数据读由异常钩子解码并回填寄存器、推进 PC | 调用窗口模式可比较读视图。全调用者模式可用下述 `LDP` 探针 |

`process_vm_readv`、`/proc/*/mem`、ptrace、GUP/`vmsplice` 及 fork 继承的目标页均有
相应覆盖路径。`/proc/self/maps` 提供映射身份，无法直接读出叶 PTE 的 `AP[1]`。
2.24.0 的线性读前证明和原生单步补齐了许多以标量 load 为采样指令的旧探针。
[异常入口](urov_y_backend.c#L4096) · [读者钩子](urov_y_backend.c#L6473) ·
[2.24.0 设计](ELIMINATION_2_24_DESIGN.md)

### 无密钥探针

普通 `LDP Wt,Wt2` 在解码器里令 `load.count=2`，可以正常返回伪造值。
`uy_llsc_prepare()` 要求 `count == 1` 才建立预约计划，后续字节模型和原生单步都依赖
该计划。即使两个读视图返回相同字节，目标 `LDP` 经同步异常返回后，在本机仍会使
`STXR` 失败。该分支发生在 2.24.0 新增的线性证明之前。
[LDP 解码](decode.c#L250) · [读前门槛](urov_y_backend.c#L2807) ·
[单步入口](urov_y_backend.c#L3807)

```asm
ldxr x9, [x1]        // x1 = thread-private scratch
ldp  w10, w11, [x0]  // x0 = target or read-only reference
stxr w8, x9, [x1]    // on success write back the same scratch value
```

选择自有、稳定的文件 RX 页和同一 fd、同偏移的独立 `r--` 别名，预热 8 字节对齐的
采样范围。每轮用同一指令序列做 32 组「对照、目标、对照」，只统计两侧 `STXR` 均成功
的组。三轮共 96 组全失败才记录 `MATCH`，全部成功记 `NO_MATCH`。混合结果、对照失败
过多、映射身份变化或样本不足记 `UNKNOWN`。探针只对目标做数据读取，成功的独占存储
也只写回线程私有 scratch。普通 App 侧判定只用 `STXR` 状态、映射、发布参考和独立读
视图。密钥用于布置和核对实验真值，耗时用于度量开销。
[探针](native/urov_observe.c#L1217) · [测试 App 判定](apps/urov-detect/read_defense_fixture.inc#L308)

### 阻断与业务隔离

- 完整性校验在后台运行。出现读接管证据、内容变化或 `UNKNOWN` 时，把该页的活内存
  CRC 标成未验证。文件完整性另用保留的常规文件 fd 和签名清单摘要核对。文件校验
  的结论只适用于发布文件。采样页应避开 JIT、可卸载 SO 和合法热补丁。
- 可独立运行的 PIC 校验例程使用新建的文件 `PROT_EXEC` 映射，数据参考使用 `PROT_READ`
  别名。`validate_target_vma()` 同时要求 `VM_READ | VM_EXEC` 和 `vm_file`，所以这两种
  别名及匿名 RX 映射均被拒绝为目标。执行别名需使用无需从指令页取数据的自包含例程。
  该隔离依赖 `urov-y` 的 VMA 检查。Android 的系统级 XOM 有独立的支持范围。
  [目标验证](urov_y_backend.c#L1279) · [执行别名测试](apps/urov-detect/read_defense_fixture.inc#L851) ·
  [AOSP XOM 文档](https://source.android.com/docs/security/test/execute-only-memory)
- 对需要在原 RX 映射上预防新登记的专用进程，可在会话建立前安装现有的 seccomp TSYNC
  规则。ARM64 下仅固定 magic、`REGISTER`、288 字节长度都匹配的 `prctl` 返回 `EPERM`。
  该规则只适用于已同步过滤的线程，新线程继承。`NoNewPrivs` 和过滤器在进程生命周期
  内持续生效，应作为专用进程的显式策略。活动会话仍需授权撤销或由管理员卸载模块。
  [登记过滤器](apps/urov-detect/dobby_crc_fixture.inc#L157) ·
  [Linux seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)

探针结果只覆盖当前采样的页和执行时点。空载模块、其他 `mm` 和未采样页需要分别对待。
针对本版 `urov-y` 的这些检查和登记限制由当前内核执行。对内核任意改写的信任判断需要
独立于 App 的可信边界。已有普通 `.text` 的活动 `PAGE_AP` 覆盖可跨锁页、保护切换、等长
重映射和 fork 维持。业务运行期间适合隔离校验结论或使用独立映射，撤销原页覆盖需要
授权控制。[映射门控](urov_y_backend.c#L5812)

### 真机结果（2026-11-09）

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `c00`。
原版 2.24.0 KPM 配合重建的检测 APK。测试 App 运行在 `untrusted_app`，`CapEff=0`，
`Seccomp=2`，SELinux Enforcing。六种配置各启动 3 次，每阶段判定 32 次。

| 阶段 | 判定次数 | 接管证据 | 内容变化 | 采信 |
| --- | ---: | ---: | ---: | ---: |
| 干净页，含空载和卸载后 | 672 | 0 | 0 | 672 |
| 仅补丁和撤销后保留补丁 | 1,248 | 0 | 1,248 | 0 |
| 等值接管 | 576 | 576 | 0 | 0 |
| 伪造读取 | 576 | 576 | 0 | 0 |

`UNKNOWN=0`。两个 AP 配置的等值和伪造阶段中，`LDP` 有效三联对照的目标 `STXR`
共失败 36,864/36,864 次。全调用者伪造阶段中，业务读取、独立标量读和内核读都得到
文件字节，原映射执行返回 `0x1235`。旧判定采信 96/96，新判定检出 96/96、采信 0/96。
干净阶段 `LDP` 探针含映射和 fd 复核平均 3.52 ms，最长 4.10 ms。21 次启动中并发业务
线程执行 53,565,824 次迭代，函数返回和管道 I/O 均无错误。UI 心跳最大间隔 19 ms。
[检测矩阵](results/read-defense-v224-20261109-233738/summary.json)

18 次活动配置中，独立执行映射均返回 `0x1234`，只读参考均匹配文件。撤销原会话后，
对 `PROT_EXEC`、`PROT_READ` 和匿名 RX 目标分别尝试登记，各 18/18 次返回 `EINVAL`。
另做 3 次 TSYNC 复测，过滤器安装前可重登记，安装后调用线程和已有线程各 3/3 次收到
`EPERM`，状态保持 inactive。七种 CRC 回归通过。每轮结束模块列表为空，boot ID
一致，增量内核日志无异常。结果覆盖本机的测试页和业务夹具。
[登记过滤器复测](results/dobby-detect-20261109-234321/summary.json) ·
[CRC 回归](results/crc-20261109-234337/summary.json)

在 `kpms/urov-lab` 目录复跑。

```powershell
.\apps\urov-detect\build.ps1
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --read-defense-v224 --repeats 32 --cycles 3
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --skip-install --dobby-detection --repeats 12 --cycles 3
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 6 --cycles 1
```

## 2.24.0 线性读前证明与全放行原生单步

[2.24.0 设计](ELIMINATION_2_24_DESIGN.md) 清掉 2.23.0 残余清单中的读前值链（H19）、
单步失败关闭类别（H20）和单步成对独占（H21）。`uy_llsc_prepare_single()` 改为线性
基本块证明：不再要求 LDXR 的结果到达故障 load，只要 LDXR 与 load 之间是纯寄存器
指令、没有分支目标、LDXR 基址未被重写，就承认预约。因此
`LDXR X9; LDRB W9; STXR XZR` 不再被拒绝。[读前证明](urov_y_backend.c#L2738)

原生单步只保留三个约束：命中模型的 `STXR/STXP` 在退休前由内核完成；`LDXR/LDXP`
退休后移动模型预约；`CLREX` 和异常指令退休后清模型预约。其余指令（SIMD/SVE/SME
数据处理、单 lane SIMD/SVE/SME store、LSE 原子、未解码编码、长循环）全部由
CPU 原生执行，4096 条上限删除。[退休处理](urov_y_backend.c#L3636) ·
[单步决策](urov_y_backend.c#L3763) · [成对完成](urov_y_backend.c#L3724)

2.23.0 假设“与监视字重叠的同 PE store 清本地监视器”。本机实测不成立：
`LDXR A; STR A; STXR A`、`LDXR A; LDADD A; STXR A`、`LDXR A; LDADD B; STXR A`
各 5000/5000 次成功；`LDXR A; CLREX; STXR A` 5000/5000 次失败；
`LDXR A; STXR B; STXR A` 的第二个 `STXR` 1000/1000 次失败。2.24.0 因此不再把
store 当失败，新增 `self_store/neon_self` 探针要求模块在 store 后不产生原生没有的
失败。

### 真机复核（2026-11-09）

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `c00`。
App 在 `untrusted_app`、`CapEff=0`、`Seccomp=2`、SELinux Enforcing。`/proc/cpuinfo`
无 SVE/SME。模块 `urov-y.kpm` SHA-256
`e8faf18e5a27dab58062e786db1a950854f7975744daa549c8e64b38b956fcbc`，测试 APK SHA-256
`c96020ed682b1f20fa7a8f9b23a57b8f917f64d01f4d4b327ddc313ae49759b5`。

| 活动伪造阶段 | 旧判定采信 | LDXR 覆盖探针命中 | 新判定检出 | 新判定采信 |
| --- | ---: | ---: | ---: | ---: |
| BRK 调用窗口、全调用者（各） | 0/96 | 0/96 | 96/96 | 0/96 |
| UXN 调用窗口、全调用者（各） | 0/96 | 0/96 | 96/96 | 0/96 |
| AP 调用窗口 | 0/96 | 0/96 | 96/96 | 0/96 |
| AP 全调用者 | 96/96 | 0/96 | 0/96 | 96/96 |

六种配置各启动 3 次，每阶段 32 次。AP 全调用者 overlay 的
`READ_DEFENSE_V224_POLICY` 为 `split=0 evidence=0 accepted=32`，
`READ_DEFENSE_V224_BOUNDARY` 为 `ap=0 ap_unknown=0 evidence=0 accepted=32`，
`READ_DEFENSE_V224_RESIDUAL` 为
`pre_mov=0 pre_long=0 self_bad=0 neon_bad=0 self_done=32 neon_done=32 deep_bad=0 deep_done=32`，
`READ_DEFENSE_KEYLESS2` 为 `load=store=branch=xload=xpair=0`。BRK/UXN 的
`site_code/site_fetch` 证据和 AP 调用窗口的 `split` 仍是各自模式的诊断语义，不是
`PAGE_AP` 全调用者生产覆盖的特征。
[真机矩阵](results/read-defense-v224-20261109-231802/summary.json)

新增探针覆盖：

- `pre_long`：LDXR 与采样 load 之间 64 条 `ADD`，旧值链上限为 12；
- `deep`：采样 load 与 `STXR` 之间 6000 条循环指令，旧单步上限为 4096；
- `self_store/neon_self`：在监视字上做标量/单 lane SIMD store，要求 `STXR` 仍成功；
- `xpair`：窗口内第二次 `LDXP/STXP`，要求成对 `STXP` 成功；
- 原有 `load/store/branch/xload`、`CLREX`、`SVC` 和 `READ_OVERWRITE_LDXR`。

七种生产 CRC 模式全部通过，`crc-ap-all` 仍为
`direct=window=file=f50bcaf6`、`execute=1235`。消除矩阵 3×1、多页 3×1 和窗口模型
`cases=121 failures=0` 全部通过。会话结束 `kpm list` 为空，boot ID 不变，增量内核
日志无 BUG/WARNING。
[生产 CRC](results/crc-20261109-232249/summary.json) ·
[消除](results/eliminate-20261109-232321/summary.json) ·
[多页](results/multipage-20261109-232434/summary.json)

当时记录的残余包括计时、caller-window 作用域、root 可见性、跨 PE/异步信号、读前窗口的
非整数 ALU 类别和 SVE/SME 目标页 load（本机无 SVE/SME）。该矩阵的 AP 探针以标量
load 为采样指令，成对 load 的补测记录见上节。[设计 §5](ELIMINATION_2_24_DESIGN.md#5-残余2240)

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v224 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
```

## 2.23.0 普通 App 无密钥检测与隔离

`REGISTER` 校验 ABI v8 请求和 MAC，将会话绑定到调用进程的 `mm`。模块先将已映射页的
活字节保存到 `snapshot`，再用调用者提交的 `SRC_USER` 字节构造 `image`。`SITE_BRK`
将登记的读指令改成 `BRK`，`PAGE_UXN` 将读点页设为用户态不可执行，两者都从异常入口
模拟登记的 load。`PAGE_AP` 清除目标页叶 PTE 的 `AP[1]`，保留活页供 CPU 取指，数据读
进入 `do_mem_abort` 钩子。钩子模拟 load 并回填寄存器和 PC。允许的调用者读到 `image`，
窗口外走 `snapshot` 视图，空窗口覆盖所有调用者。`process_vm_readv`、`/proc/*/mem`、
ptrace、GUP/`vmsplice` 及 fork 后的读路径也有相应覆盖，因此这些路径与发布文件一致时，
仍可能有代码补丁在运行。
[会话和镜像](urov_y_backend.c#L4591) · [控制入口](urov_y_backend.c#L5004) ·
[数据异常](urov_y_backend.c#L4261) · [读者钩子](urov_y_backend.c#L6478)

### 检测读异常

[2.23.0 设计](ELIMINATION_2_23_DESIGN.md) 补齐了 `BL/RET`、SIMD `REV` 和 FP 等读后
窗口。源码中，64 条指令模型和最多 4096 条指令的单步回放都依赖同一份读前 `LDXR`
验证结果。把 `LDRB` 的目的寄存器与 `LDXR` 的目的寄存器设为同一个，CPU 仍可保留对
私有 scratch 的预约，但 `uy_llsc_prepare_single()` 会因 `load->rt == lrt` 拒绝。紧跟的
`STXR` 也无法命中 `LDXP/STXP` 配对路径。于是 `PAGE_AP` 仍能返回伪造字节，但无法代写
`STXR` 成功状态。这个构造没有等待单步预算耗尽的成本。
[读前验证](urov_y_backend.c#L2826) · [单步入口](urov_y_backend.c#L3823) ·
[探针实现](native/urov_observe.c#L217)

```asm
ldxr x9, [x1]         // x1 指向对齐且初值为零的线程私有 scratch
ldrb w9, [x0]         // x0 指向已预热的目标页或只读对照页
stxr w8, xzr, [x1]   // 成功时也只把零写回 scratch
```

在后台线程保留目标 `r-x` 映射、同文件同偏移的独立 `r--` 映射和原始文件 fd。热身后做
3 轮，每轮取 32 个前后对照均成功的样本。目标 96 次全失败才判定稳定的读异常，全部成功
记为本次未见该特征，混合结果、对照不稳或映射身份变化记为 `UNKNOWN`。`STXR` 状态用于
判定，耗时仅供测量。`SITE_BRK` 对照已知读点的发布指令字，`PAGE_UXN` 对照同文件 canary
的取指预约。两种模式也可用业务读者与独立读者分歧佐证。独占预约丢失的证据定位到当前
页的读路径，调试或异常也可能影响它，因此只对自有、稳定、已校准的页判定。
[配对采样](native/urov_observe.c#L828) ·
[测试 App 的判定](apps/urov-detect/read_defense_fixture.inc#L291)

### 防护范围

- 对有证据或 `UNKNOWN` 的结果，校验器将活页 CRC 标记为未验证。直接 `pread` 发布 ELF
  的常规文件 fd 并核对签名清单中的摘要，可单独判断文件完整性。文件结果与原映射的运行
  时完整性分别记录。检测线程只读取目标和对照页，独占写入只触及线程自己的 scratch。
- 可独立部署的校验例程，可从经过认证的文件创建新 `PROT_EXEC` 私有映射，数据引用走
  `r--` 映射或文件 fd。当前 `validate_target_vma()` 要求 `VM_READ | VM_EXEC` 同时存在并有
  `vm_file`，因此上述两种映射和无文件的匿名 RX 映射均不符合登记条件。只对具备相应 VMA
  形态、可独立执行且不从指令页加载数据的例程使用。Android 10 的系统级 XOM 与这里的
  VMA 登记门槛是两个不同机制。
  [目标校验](urov_y_backend.c#L1279) ·
  [执行映射对照](apps/urov-detect/read_defense_fixture.inc#L742) ·
  [AOSP XOM 说明](https://source.android.com/docs/security/test/execute-only-memory)
- 已登记的普通 `r-x` 业务映射仍可持续返回镜像。模块接受 `mlock`，能跨部分
  `mprotect`、`mremap` 和缺页重装，原地改权限或重映射会影响业务。主动撤销会话需要
  模块的授权控制路径，卸载需要 KernelPatch 管理权限。
  [映射生命周期](urov_y_backend.c#L5817) · [撤销入口](urov_y_backend.c#L4958)

### 真机复核（2026-11-09）

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `c00`。
App 在 `untrusted_app`、`CapEff=0`、`Seccomp=2`、SELinux Enforcing。使用原版
2.23.0 KPM（`d04e2b09…`）和重建的测试 APK（`d39f5ad7…`）。密钥仅用于装载和配置
测试会话及读取真值。`READ_DEFENSE_V223_BOUNDARY` 记录普通 App 可得到的新判定，旧判定
单独留作对照。
[真机矩阵](results/read-defense-v223-20261109-221033/summary.json)

| 活动伪造阶段 | 旧判定采信 | 新 AP 探针命中 | 新判定检出 | 新判定采信 |
| --- | ---: | ---: | ---: | ---: |
| BRK 调用窗口、全调用者（各） | 0/96 | 0/96 | 96/96 | 0/96 |
| UXN 调用窗口、全调用者（各） | 0/96 | 0/96 | 96/96 | 0/96 |
| AP 调用窗口 | 0/96 | 96/96 | 96/96 | 0/96 |
| AP 全调用者 | 96/96 | 96/96 | 96/96 | 0/96 |

六种配置各启动 3 次，每阶段 32 次，共 3,072 次判定。`identity` 与 `overlay` 共
1,152/1,152 检出接管。AP 探针在其中两个 AP 模式共命中 384/384，对应有效三联对照中
36,864/36,864 次目标 `STXR` 失败。干净阶段（含空载和卸载后）672/672 采信，单纯补丁和
撤销后保留补丁的 1,248/1,248 次均归为内容变化，`UNKNOWN=0`。干净阶段新探针平均 3.27 ms，
最长 6.71 ms，包含映射和 fd 身份复核。21 次启动中，业务线程累计执行 36,466,432 次
循环迭代，函数返回和管道 I/O 均无错误。该数据覆盖这台设备和测试页。
[AP 全调用者日志](results/read-defense-v223-20261109-221033/read-defense-v223-ap-all-3-16942.log)

18 次活动配置均在原会话仍生效时验证独立执行映射返回 `0x1234`，而原页执行补丁返回
`0x1235`。随后针对新 `PROT_EXEC`、`r--` 和匿名 RX 映射分别发起登记，三种形态各
18/18 返回 `EINVAL`。七种生产 CRC 模式均通过，`crc-ap-all` 仍有
`direct=window=file=f50bcaf6` 且 `execute=1235`。两轮矩阵清理后 KPM 列表为空，boot ID
一致，增量内核日志没有报告异常。
[防护与清理记录](results/read-defense-v223-20261109-221033/summary.json) ·
[生产 CRC 回归](results/crc-20261109-221404/summary.json)

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v223 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 6 --cycles 1
```

## 2.23.0 原生单步回放与调用/REV 模型

`urov-y` 2.23.0 在 2.22.0 的字节模型上新增 `BL/BLR/BR/RET` 和 SIMD
`REV16/REV32/REV64`。模型仍只走 64 条窗口；当窗口含 FP 算术、SIMD 立即数/置换、
SVE 数据处理、循环或长链时，handler 改为让 CPU 原生执行每条指令，并在消费预约的
`STXR` 前完成同一地址/宽度/值的 store。目标页的第二次读会先按原路径完成 load，
再继续回放；与监视字不重叠的普通 store、EL0 `MRS`、局部调用都可原生执行。重叠
监视字的 store、`CLREX`/其他独占、LSE 原子、`SVC`/异常、SVE 内存形式、非会话缺页、
信号/抢占和超过 4096 条指令仍失败关闭。

v223 探针在 AP-all overlay 阶段同时包含两次目标页 `LDRB`、无关地址 `STR`、
`MRS CNTVCT_EL0`、局部 `BL/RET` 和 `FADD D0,D0,D0`，
`READ_DEFENSE_V223_RESIDUAL` 逐阶段 `leaf_call=permute=fp_arith=0`。六种模式 ×3
PASS，AP-all overlay `accepted=32/32`、`evidence=0`、`unknown=0`；生产 CRC 7 模式 ×3
PASS（`crc-ap-all` `direct=window=file=f50bcaf6`、`execute=1235`）；Dobby 8×1
PASS（`ap=0/8`、`accepted_crc_with_ap=8/8`）；消除 3×1、多页 3×1 PASS；窗口模型
`cases=121 failures=0`。模块 SHA-256 `d04e2b09...`，APK `9bc60167...`。
[设计、残余与残余边界证明](ELIMINATION_2_23_DESIGN.md) ·
[v223 矩阵](results/read-defense-v223-20261109-215232/summary.json) ·
[CRC 回归](results/crc-20261109-215256/summary.json)

## 2.22.0 影子 GPR 预链与整数 SIMD 窗口

### 实现与旧探针的盲区

`urov-y` 从 `TCR_EL1` 取得页表几何，按内核符号和 BTF 或兼容布局绑定异常、内存读和
映射生命周期入口。ABI v8 的 `REGISTER` 经 `prctl` 的选项、magic、布局和 MAC 校验，
把单个会话绑定到当前进程的 `mm`。登记时保存目标页当时的 `snapshot`，把调用者提交的
`SRC_USER` 字节覆盖进 `image`；窗口内读 `image`，窗口外读 `snapshot`，空窗口列表覆盖
全调用者。夹具先改活页再登记，因此 `snapshot` 已含补丁，而 `image` 可与原文件相同。
[初始化](urov_y_backend.c#L6089) · [控制入口](urov_y_backend.c#L4664) ·
[建页与登记](urov_y_backend.c#L4251) · [调用窗口](urov_y_backend.c#L1710)

| 模式 | 接管位置 | App 可用的证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 读点所在的私有页，把指定 load 改成 `BRK`。异常处理器模拟原 load | 将已知读点的指令字与发布 ELF 对照，同时比较业务读者与独立读点 |
| `PAGE_UXN` | 设置读点页叶 PTE 的 UXN。取指异常时模拟已登记的 load 及有限的 BTI、NOP、RET | 比较两个读点。自有读点页可预置 `BTI C; RET` canary，配合同文件 RX 别名观察取指异常的独占副作用 |
| `PAGE_AP` | 清目标页叶 PTE 的 `AP[1]`。EL0 数据读经异常模拟，CPU 仍从活页取指 | 有调用窗口时可出现读者分歧；全调用者覆盖下只剩 LL/SC 配对探针 |

异常入口解码 load 并提交目标寄存器和 PC，覆盖范围可跨页。模块还在 GUP pin 或兼容
后置路径覆盖 `process_vm_readv`，在 `__access_remote_vm` 路径覆盖 `/proc/*/mem` 和
ptrace 读取，并替换 `vmsplice` 等 GUP 读者拿到的页。缺页和部分映射保护变更可重装
AP 陷阱，fork 子进程可继承覆盖。对活动的 BRK/UXN 会话，fork 会先撤销会话。
[异常入口](urov_y_backend.c#L3807) · [缺页重装](urov_y_backend.c#L4038) ·
[内核读路径](urov_y_backend.c#L4812) · [fork](urov_y_backend.c#L5218)

[2.22 设计](ELIMINATION_2_22_DESIGN.md) 补齐 2.21 的两处窗口盲区。后向窗口在私有
影子 GPR 文件上重放整段 pre-window：早前定义的源用影子值，整段都不写的源用故障现场
值，只在更晚指令里写的源视为不可重建并拒绝；从 `loaded` 与 `loaded ^ 1` 各重放一次，
两次的 `LDXR` 目标终值必须不同且与故障现场逐位一致。因此 `MOV X9,X0` 这类经旁路
寄存器的链也能证明 `LDXR` 的执行。前向窗口新增 Advanced SIMD 三同整数族：逻辑
`AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF`、`ADD/SUB`、`CMEQ/CMTST`、`CMGT/CMHI/CMGE/CMHS`、
`SMAX/SMIN/UMAX/UMIN`、`MUL/MLA/MLS`、`SSHL/USHL`，在 FPSIMD 镜像上逐 lane 重放，
`Q=0` 按架构清零目的寄存器高 64 位。整数 SIMD 不写 FPSR、不访问内存，不需要 FP
数据通路；快照与提交沿用 2.21 的懒加载路径。另外，`LDTR/LDTRB/LDTRH/LDTRSW` 在
EL0 与对应的 `LDUR` 形态等价，2.22 在共享解码器拒绝后按普通 unscaled load 重解码，
避免被 AP 陷阱拦下的读变成可观测的合成 `SIGSEGV`。
[前向窗口](urov_y_backend.c#L2532) · [读前校验](urov_y_backend.c#L2741) ·
[未特权别名](urov_y_backend.c#L3704) · [源位图](urov_y_window.h#L706) ·
[SIMD 族](urov_y_window.h#L966)

### 已验证的无信号 AP 探针

2.21 的 guard 用基线、读前写第二个 GPR、读后整数 SIMD 三条配对 LL/SC 序列验证
`PAGE_AP`。2.22 之后三条全部保住预约：`LDXR; MOV X9,X0; LDRB; STXR` 的影子链与
`LDXR; LDRB; EOR V0.16B,V0.16B,V0.16B; STXR` 的 SIMD 重放都由窗口模型完成，
`STXR` 由内核代写 `Ws=0`，原生 `STXR` 不再执行。
`simd` 序列现在还在 `LDXR` 前执行 `MOVI V0.16B,#0xff`，并在 `STXR` 后 `UMOV` 回读
lane0，与参考页上的原生结果对照；这条对照同时证明窗口完成了 `STXR` 和 FPSIMD 状态
写回，而不只是把状态位改成成功。
[配对对照](native/urov_observe.c#L327) ·
[合并判定](native/urov_observe.c#L905)

### 普通 App 接入

接入方式与 2.21 相同：业务线程保持原调用上下文，后台线程用同文件同偏移的只读非执行
别名做配对控制，采样自有 RX 页；`ud_observe_ap_v221()` 的三条序列全部阴性、
`ud_check_reader_views()` 无分歧、BRK/UXN 读点无证据时，才采信本次活页校验。
2.22 的 AP-all 阶段满足这三项，旧的 BRK/UXN 模式仍会留下各自的代码字/取指证据。
[读取对照](native/urov_detect.c#L187) · [测试 App 判定](apps/urov-detect/read_defense_fixture.inc#L287)

### 真机结果

Pixel 6、Android 16、ARM64、4 KiB、`6.1.186-android14-11`、KernelPatch `c00`。
App 为 `untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux Enforcing。KPM SHA-256
`ab90dab425c54b009784b7471258119ba151c99197bf8a653ec3e9b3eac4d064`，APK SHA-256
`3181b98c5a56ee05306f736aa6344111554ba54812878e7bd5c00cde0cfb8820`，窗口模型测试
SHA-256 `c7b65f694402707c99a4151c23c92074faff920eaea47c0d64bab1afc7bb2184`。
[矩阵汇总](results/read-defense-v222-20261109-001128/summary.json)

| 活动覆盖阶段 | 业务/独立读分歧 | AP 探针命中 | 综合检出 | 采信活页校验 |
| --- | ---: | ---: | ---: | ---: |
| BRK 调用窗口、BRK 全调用者 | 各 96/96 | 各 0/96 | 各 96/96 | 各 0/96 |
| UXN 调用窗口、UXN 全调用者 | 各 96/96 | 各 0/96 | 各 96/96 | 各 0/96 |
| AP 调用窗口 | 96/96 | 0/96 | 96/96 | 0/96 |
| AP 全调用者 | 0/96 | 0/96 | 0/96 | 96/96 |

2.21 的 identity（image 与文件等值）阶段仍被 AP 探针检出；2.22 的同一阶段没有分歧、
没有 AP 信号，按设计采信。全矩阵 21 次 App 启动、18 个覆盖配置 × 5 阶段 × 32 样本：
干净阶段 576/576 通过校验，identity 阶段 AP 模式 192/192 通过、BRK/UXN 仍留读点
证据，仅改码与撤销阶段 1,152/1,152 归类为内容变化；`unknown=0`。AP 全调用者覆盖
阶段的 `pre_gpr`、`simd`、`ap` 全为 0，`baseline_ok=96/96`，`simd_value=96/96`，
`accepted=96/96`；`LDTRB` 探针在 AP-all 覆盖页读到 image 字节（`byte=24 want=24`），
不再以合成信号暴露陷阱；每样本平均约 16.7–19.1 ms、最大约 20.0 ms（含三条配对
AP 探针与三路读值核对）。
生产 CRC 7 模式 3×1 PASS；`crc-ap-all` 的 EL0、`process_vm_readv`、pipe 与 fork
子进程读均等于文件摘要 `f50bcaf6`，执行仍是 Dobby 的 `1235`。Dobby 检测 8×1 PASS
（`ap=0/8`、`accepted_crc_old=8/8`、`accepted_crc_with_ap=8/8`）；消除矩阵 3×1
全部 `ELIM_CASE` 通过（`exclusive_match=0`、`ap_match=0`）；多页 3×1 PASS；窗口
模型差分测试 `cases=113 failures=0`（新增 40 条 SIMD/源位图用例，期望值由设备上的
原生指令产生）。会话结束后 `kpm list` 为空，前后 boot ID 一致，增量内核日志未见
BUG/WARNING。
[CRC](results/crc-20261109-000422/summary.json) ·
[Dobby](results/dobby-detect-20261109-000455/summary.json) ·
[消除](results/eliminate-20261109-000616/summary.json) ·
[多页](results/multipage-20261109-000848/summary.json)

`SITE_BRK`/`PAGE_UXN` 的代码字与 UXN 语义本身可被普通 App 观察，它们是诊断模式；
生产覆盖只使用 `PAGE_AP` 全调用者。残余与 2.21 相同，除 pre-load 影子链、整数 SIMD
三同族与未特权 `LDTR` 解码已消除；`BL/BLR/RET`、`SVE/SME`、FP 算术、SIMD
permute/立即数/内存形式、gap 内 LSE/成对独占、计数器/随机数 `MRS` 和超过 64 条的
形状仍 fail-closed，详见
[设计 §5](ELIMINATION_2_22_DESIGN.md#5-残余2220)。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v222 --repeats 32 --cycles 3
```

## 2.21.0 无密钥检测与读值防护

### 实现与旧探针的盲区

`urov-y` 从 `TCR_EL1` 得到页表几何，用内核符号和 BTF 或兼容布局绑定异常、内存读和
映射生命周期入口。ABI v8 的 `REGISTER` 经 `prctl` 的选项、magic、布局和 MAC 校验，
将单个会话绑定到当前进程的 `mm`。登记时保存各目标页的 `snapshot`，将调用者提交的
`SRC_USER` 字节覆盖到 `image`。命中调用窗口的读取得到 `image`，窗口外得到
`snapshot`，空窗口列表覆盖全调用者。窗口可以匹配 LR 或有界帧链。夹具先改活页再登记，
因此 `snapshot` 已含补丁，而 `image` 可与原文件相同。
[初始化](urov_y_backend.c#L6089) · [控制入口](urov_y_backend.c#L4664) ·
[建页与登记](urov_y_backend.c#L4251) · [调用窗口](urov_y_backend.c#L1710)

| 模式 | 接管位置 | App 可用的证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 读点所在的私有页，把指定 load 改成 `BRK`。异常处理器模拟原 load | 将已知读点的指令字与发布 ELF 对照，同时比较业务读者与独立读点 |
| `PAGE_UXN` | 设置读点页叶 PTE 的 UXN。取指异常时模拟已登记的 load 及有限的 BTI、NOP、RET | 比较两个读点。自有读点页可预置 `BTI C; RET` canary，配合同文件 RX 别名观察取指异常的独占副作用 |
| `PAGE_AP` | 清目标页叶 PTE 的 `AP[1]`。EL0 数据读经异常模拟，CPU 仍从活页取指 | 有调用窗口时可出现读者分歧。全调用者覆盖及等值覆盖由下文两条探针检测 |

异常入口解码 load 并提交目标寄存器和 PC，覆盖范围可跨页。模块还在 GUP pin 或兼容
后置路径覆盖 `process_vm_readv`，在 `__access_remote_vm` 路径覆盖 `/proc/*/mem`
和 ptrace 读取，并替换 `vmsplice` 等 GUP 读者拿到的页。缺页和部分映射保护变更可
重装 AP 陷阱，fork 子进程可继承覆盖。对活动的 BRK/UXN 会话，fork 会先撤销会话。
[异常入口](urov_y_backend.c#L3807) · [缺页重装](urov_y_backend.c#L4038) ·
[内核读路径](urov_y_backend.c#L4812) · [fork](urov_y_backend.c#L5218)

[2.21 设计](ELIMINATION_2_21_DESIGN.md) 在 `LDXR` 与故障 load 之间最多重放 12 条
指令，限制写入的寄存器并验证故障现场的值。故障 load 后最多模拟 64 条指令，覆盖整数
链、有限控制流、FPSIMD 位传送和指定系统寄存器。通过检查的窗口由内核代写
`STXR` 结果。原有读前原地 ALU 和读后 `FMOV` 探针因此都为阴性。用原 APK 重跑
时，全调用者 AP 覆盖的 48/48 个样本通过旧策略。
[前向窗口](urov_y_backend.c#L2532) · [读前校验](urov_y_backend.c#L2729) ·
[基线复跑](results/read-defense-v221-20261108-230605/summary.json)

### 已验证的无信号 AP 探针

在稳定的自有文件 RX 页上抽样一个字节，以同 fd、同偏移的独立只读非执行映射为对照。
两条序列各只执行一次目标 `LDRB`，`STXR` 只向线程私有暂存字写回原值。

```text
LDXR Xold,[scratch] → MOV X9,Xold → LDRB Wbyte,[target] → STXR Wstatus,Xold,[scratch]
LDXR Xold,[scratch] → LDRB Wbyte,[target] → EOR V0.16B,V0.16B,V0.16B → STXR Wstatus,Xold,[scratch]
```

`MOV` 写到与 `LDXR` 目标不同的寄存器，读前重放拒绝它。NEON `EOR` 超出读后模型
支持的位传送范围，窗口在代写前退出。两条路径都能完成 `LDRB`，但 AP 异常返回清除
独占监视器，随后的原生 `STXR` 失败。已建模的 `LDXR; LDRB; NOP; STXR` 是同一
目标字节的第三条对照。
[汇编](native/urov_observe.c#L309) · [合并判定](native/urov_observe.c#L899)

预热后，每条序列取三轮，每轮接纳 32 个“前对照成功、目标采样、后对照成功”的三元组。
映射或文件身份变化、字节不稳定、对照失败过多或结果混合均归入 `UNKNOWN`。两条新序列
的目标全部失败、且已建模序列的目标全部成功时才报 AP 命中。检测无密钥，在后台线程
运行，维持现有映射和信号处理。Arm 对夹有显式读的独占序列无进度保证，部署需按机型
确认对照稳定性。单次失败只作为观测。
[配对对照](native/urov_observe.c#L732) ·
[Arm 独占访问约束](https://community.arm.com/forums/f/architectures-and-processors-forum/5452/does-load-store-exclusive-violate-hypervisor-transparency/12878)

### 普通 App 接入

1. 在运行受检代码的进程中选取按设计保持稳定的自有文件 RX 页。按设备页大小定位，
   用发布 ELF 的 fd 和偏移核对映射身份，保留同文件、同偏移的 `PROT_READ` 对照。
   采样期间持有目标和对照映射及 fd，避开 `dlclose`、权限变更和并发改码。
2. 在后台线程按关键页抽样。通过 `ud_check_reader_views()` 比较实际业务读者、
   独立读点与 `pread` 的文件字节。保持业务读者原来的调用上下文，以覆盖按调用窗口
   生效的伪造。BRK 检查已知读取指令的字节，UXN 使用预置在该读点同页的 canary。
   `ud_observe_ap_v221()` 对每个受检页读取一个稳定字节，覆盖该页的 AP 权限异常。
   [读取对照](native/urov_detect.c#L187) · [读点检查](apps/urov-detect/read_defense_fixture.inc#L227) ·
   [AP 探针](native/urov_observe.c#L899)
3. 稳定的异常证据使本次活页校验失去采信资格。对照失败、缺少必要的探针或结果混合
   记为 `UNKNOWN`，稳定的内容差异另记为 `changed`。所需证据齐全且本次字节一致时，
   才采信该次校验。判定只约束完整性结果，业务继续。
   [测试 App 判定](apps/urov-detect/read_defense_fixture.inc#L287)

阴性结果只对应已采样的页、读点、调用上下文和时段。未激活或仅作用于其他读点的会话可能
漏检。原版 `PAGE_AP` 的调用窗口只决定返回哪份字节，目标页仍会发生权限异常。若改版
模块仅补齐两种新序列中的一条，AP 合并结果为 `UNKNOWN`。若两条都补齐且其他观测均
正常，则可能给出阴性。跨机型应先确认独占对照稳定性。
[AP 异常入口](urov_y_backend.c#L3932) · [合并判定](native/urov_observe.c#L899)

### 可选诊断与设备信任

- **`LDRB` / `LDTRB` 权限对照，源码推导。** 普通可读页上两种指令均可读取。
  2.21.0 的 `PAGE_AP` 陷阱会模拟 `LDRB`，而解码器拒绝 `LDTRB`，随后发出
  `SIGSEGV/SEGV_ACCERR`。这个观测独立于 LL/SC。实验应把自有载荷和检测放在同一
  隔离测试进程，先验证同文件对照的两种读取均成功，再确认目标的 `LDRB` 成功且
  `LDTRB` 在预期指令 PC 和目标 `si_addr` 处稳定出现权限异常。信号处理仅恢复这次
  已识别的探针异常，其余故障沿原处理流程。探针仍依赖内核交付信号。下方真机矩阵
  验证的是无信号方案。
  [解码拒绝](decode.c#L227) · [异常回退](urov_y_backend.c#L3764) ·
  [信号生成](urov_y_backend.c#L1763)
- **页来源辅证。** App 可在系统允许时读取自己的 `pagemap`，将已核对的私有文件 VMA
  中驻留页的来源标志与干净基线比较，辅助观察私有 COW。该接口只暴露部分页表信息，
  无法读取 `AP[1]` 或 `UXN`。
  合法改码也可能产生 COW，等值 AP 覆盖可保留原文件页来源。
  [Linux pagemap 文档](https://docs.kernel.org/admin-guide/mm/pagemap.html)
- **硬件密钥证明。** 对依赖设备信任的请求，App 可申请带服务端新鲜挑战的硬件证明。
  服务端验证证书链、撤销状态、硬件证明级别和挑战，并核对 `deviceLocked`、
  `verifiedBootState` 和预期启动密钥。
  这条证据验证启动链，运行时活页校验仍按上面的探针单独判定。
  [Android 密钥证明](https://developer.android.com/privacy-and-security/security-key-attestation) ·
  [启动状态字段](https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields)

### 阻止伪造影响校验

- **现有 ELF 代码页**。校验策略拒绝采信有覆盖证据或未知的活页 CRC。用可信 fd 的
  `pread` 或从开始即为 `PROT_READ` 的独立别名计算发布制品基准。该基准只证明制品内容。
- **可独立部署的自有 PIC 代码**。用同一可信制品 fd 建立独立 `PROT_EXEC` 执行映射及
  `PROT_READ` 读映射，保留现有业务映射。当前 `validate_target_vma()` 要求目标同时有
  `VM_READ | VM_EXEC` 且有 `vm_file`，所以分别拒绝两种映射，也拒绝私有匿名 RX。
  测试仅在自有无重定位载荷验证这三种形状。普通 App 可以隔离校验读和自有载荷，
  模块的全局停用需要管理权限。
  [目标校验](urov_y_backend.c#L1279) ·
  [独立映射夹具](apps/urov-detect/read_defense_fixture.inc#L571)

### 真机结果

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `0xc00`。
App 为 `untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux Enforcing。宿主使用
KernelPatch 权限装卸模块、采集内核日志，夹具单独使用会话密钥设置测试真值。
KPM SHA-256 为 `0bc084fdf7ef964ba96aff76ae819829ea78a094d1e290ed30ca616fcbfe2ffa`，
APK SHA-256 为 `3b1695cd8476e445a903a6ef6438b419207f43f0defe7df35ca6d19c2eb55217`。
[矩阵汇总](results/read-defense-v221-guarded-20261108-231429/summary.json)

| 活动覆盖阶段 | 业务/独立读分歧 | AP 探针命中 | 综合检出 | 采信活页校验 |
| --- | ---: | ---: | ---: | ---: |
| BRK 调用窗口、BRK 全调用者 | 各 96/96 | 各 0/96 | 各 96/96 | 各 0/96 |
| UXN 调用窗口、UXN 全调用者 | 各 96/96 | 各 0/96 | 各 96/96 | 各 0/96 |
| AP 调用窗口 | 96/96 | 96/96 | 96/96 | 0/96 |
| AP 全调用者 | 0/96 | 96/96 | 96/96 | 0/96 |

等值覆盖阶段另有 576/576 个样本检出。未覆盖对照为 0/1,920 误报，672/672 个干净
样本通过校验，1,248 个仅改码或撤销后样本归类为内容变化。3,072 个样本均有判定。
活动会话中的独立执行映射均返回 `0x1234`，18/18 次仍确认原会话活动。三种受保护
映射分别 18/18 次返回 `EINVAL`。AP 全调用者阶段，目标代码继续返回 `0x1235`。
并行业务操作 27,043,072 次、0 错误，UI 心跳最大间隔 20 ms。含旧探针的判定每阶段
平均每次约 15.0–17.5 ms，单样本最大约 57.4 ms。结果来自一台 4 KiB 真机。
[AP 全调用者日志](results/read-defense-v221-guarded-20261108-231429/read-defense-v221-guarded-ap-all-1-23716.log)

同一新 APK 的原有 v221 入口和生产 CRC 七模式回归均通过。生产夹具的 AP 全调用者
阶段仍以 `0x1235` 执行，EL0 和内核辅助样本却等于原文件 CRC `f50bcaf6`。各次
复跑前后 boot ID 一致，测试模块已卸载，增量内核日志未见异常。
[原有入口回归](results/read-defense-v221-20261108-231759/summary.json) ·
[CRC 回归](results/crc-20261108-231824/summary.json)

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v221-guarded --repeats 32 --cycles 3
```

## 2.21.0 预加载整数链与 FPSIMD 传送

2.21.0 清掉 2.20.0 测试面上仍稳定的两条 AP 读侧特征：一是在 `LDXR` 与故障 load
之间插入整数运算（`EOR/ADD/...`）时后向扫描看不到 `LDXR`；二是在 load 之后插入
`FMOV` 时窗口模型停止。现在后向窗口从 `LDXR` 重放最多 12 条整数指令，只接受
“只写 `LDXR` 目标寄存器、且结果实际依赖 `LDXR` 读值”的链；前向窗口从 24 条扩到
64 条，并补齐 `FMOV` 标量/半精度/128 位 lane、`MRS/MSR NZCV/FPCR/FPSR` 和只读
`TPIDR_EL0`/`TPIDRRO_EL0`/`CNTFRQ_EL0`/`CTR_EL0`/`DCZID_EL0`。FPSIMD 镜像只在窗口
出现 FP 指令时懒加载，提交时写回；H 形式只在 CPU 报告 FEAT_FP16 时接受。
ABI v8、`hooks=0xff`、请求布局、`ctl0` 文本和返回码不变。
[预加载链](urov_y_backend.c#L2729) · [前向窗口](urov_y_backend.c#L2532) ·
[FPSIMD 传送](urov_y_window.h#L721) · [设计](ELIMINATION_2_21_DESIGN.md)

### 真机结果

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`、KernelPatch `0xc00`。
App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。模块 SHA-256
`0bc084fdf7ef964ba96aff76ae819829ea78a094d1e290ed30ca616fcbfe2ffa`，测试 APK
SHA-256 `f6640b001d5602b2e89913703bd7ea2cbbc227bf7f1a2965884fd573417e12c5`，
窗口模型测试 SHA-256
`1b8331e04ee2be83594cb613779016246648cc9de3f253484c0fba1fe327d52f`。
[真机矩阵](results/read-defense-v221-20261108-225828/summary.json)

6 种配置各 1 轮、每阶段 32 个样本。活动覆盖阶段的 AP 策略探针：

| 配置 | `pre_alu` | `fp` | `ap` | `split` | `evidence` | 采信 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `SITE_BRK` 调用窗口 / 全调用者 | 0/32 | 0/32 | 0/32 | 32/32 | 32/32 | 0/32 |
| `PAGE_UXN` 调用窗口 / 全调用者 | 0/32 | 0/32 | 0/32 | 32/32 | 32/32 | 0/32 |
| `PAGE_AP` 调用窗口 | 0/32 | 0/32 | 0/32 | 32/32 | 32/32 | 0/32 |
| `PAGE_AP` 全调用者 | 0/32 | 0/32 | 0/32 | 0/32 | 0/32 | 32/32 |

AP 调用窗口的 `split` 是设计保留的 caller-window 语义：业务读者拿 image、窗口外
读者拿 snapshot，因此仍拒绝采信。AP 全调用者没有分歧、没有独占监视器信号，
策略层 32/32 采信。全部阶段 `unknown=0`；`READ_DEFENSE_KEYLESS2` 仍为
`load=store=branch=xload=0`、`value=128/128`、`clrex_bad=svc_bad=0`。会话结束后
`kpm list` 为空，前后 boot ID 一致。
[AP 全调用者日志](results/read-defense-v221-20261108-225828/read-defense-v221-ap-all-1-19593.log)

生产 CRC 7 模式 3×1 PASS；`crc-ap-all` 的 EL0、`process_vm_readv`、pipe 与 fork
子进程读均等于文件摘要 `f50bcaf6`，执行仍为 Dobby 的 `1235`。Dobby 检测 8×1 PASS
（`ap=0/8`、`accepted_crc_with_ap=8/8`、`spaced=0`、`views=0/8`）；消除矩阵 3×1
全部 `ELIM_CASE` 通过（`exclusive_match=0`、`ap_match=0`）；多页 3×1 PASS；窗口
模型差分测试 `cases=73 failures=0`（新增 17 个 FP/sysreg/dst 用例）。
[CRC](results/crc-20261108-225256/summary.json) ·
[Dobby](results/dobby-detect-20261108-225328/summary.json) ·
[消除](results/eliminate-20261108-225350/summary.json) ·
[多页](results/multipage-20261108-225504/summary.json)

残余与 2.20.0 相同，除 pre-load 整数链与 FPSIMD 传送已消除；`BL/BLR/RET`、
`SVE/SME`、非 `FMOV` SIMD/FP、gap 内 LSE/成对独占、计数器/随机数 `MRS` 和超过
64 条的形状仍 fail-closed。它们不出现在编译器生成的 LL/SC 序列里，且在不改变
执行语义、不新增 VMA/代码字/hook 的前提下无法完整模拟，详见
[设计 §5](ELIMINATION_2_21_DESIGN.md#5-残余2210)。

```powershell
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v221 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
```

## 2.20.0 普通 App 无密钥检测与读值防护

本轮复用 [2.20 设计](ELIMINATION_2_20_DESIGN.md) 所列的 KPM。SHA-256 为
`7b43e768a26b09b6c3fe230591281a31a1e7a894dd11555cdcbb089e4bcfd391`。
该制品的 `.kpm.info` 仍标为 `2.19.0`，版本按哈希及窗口模型的行为确认。
新增代码位于普通 App 的探针、夹具和复跑脚本。

### 从页登记到读值替换

KPM 从 `TCR_EL1` 取得页几何，按内核符号及 BTF/兼容性布局绑定异常、内存访问
和生命周期入口。控制面使用 ABI v8，请求通过 `prctl` 选项、magic、布局和
MAC 校验后才分发。登记绑定当前 `mm`，为目标页保存当时的活页 `snapshot`，
再将调用者提交的 `SRC_USER` 字节覆盖进 `image`。被接管的目标读命中调用
窗口时使用 `image`，窗口外使用 `snapshot`。空窗口列表允许全调用者。调用窗口可通过
LR 或有界帧链命中。测试先改活页再登记，所以 `snapshot` 可以已经含有补丁，
而 `image` 可以等于原文件。
[初始化](urov_y_backend.c#L5599) · [认证](urov_y_backend.c#L4574) ·
[登记](urov_y_backend.c#L4161) · [调用窗口](urov_y_backend.c#L1702)

| 模式 | 伪造位置 | 普通 App 的观测 |
| --- | --- | --- |
| `SITE_BRK` | 用私有 COW 页上的 `BRK` 代替指定读指令，handler 模拟原 load | 用独立读点核对业务读指令与文件，并比较业务读值和独立标量读值 |
| `PAGE_UXN` | 给读点所在页设置 UXN，模拟取指失败的读点及有限的控制流指令 | 比较两个读点。对已知读点页，可用预置的 `BTI C; RET` canary 和同文件 RX 别名做取指对照 |
| `PAGE_AP` | 清目标页叶 PTE 的 `AP[1]`，EL0 数据读陷入模拟，取指仍使用活页 | 有调用窗口时检查读值分歧。两种独占预约探针覆盖窗口及全调用者 |

`process_vm_readv` 的源页或返回缓冲区、`/proc/*/mem` 与 ptrace 所经的
`__access_remote_vm`、以及 `vmsplice` 所经的 GUP 都有相应覆盖路径。
`PAGE_AP` 可按映射身份识别 fork 的继承页，缺页及保护变更后也会重装陷阱。
本版的全调用者 AP 能让多个接口同时看到原文件字节。等长 `mremap`、锁页或
换成另一个已覆盖的读取接口，均不足以作为这版的通用防护。
[异常处理](urov_y_backend.c#L3722) · [内核读](urov_y_backend.c#L4698) ·
[GUP](urov_y_backend.c#L5001) · [映射生命周期](urov_y_backend.c#L5509)

### 2.20 窗口的两处边界

2.20 在故障 load 成功后，最多模拟 24 条后续指令。整数运算、条件、分支和常见
读写可在私有寄存器模型中运行。完成模型后，handler 先重放待写项，再执行
`STXR` 对应的写回并更新返回寄存器。旧的 CSEL、普通 load/store 和分支探针
在本轮复测中均为阴性。设计 §3.3 的提交说明需要区分模型阶段和写回阶段。
源码中若后续待写项或最终写回失败，先前已经完成的写入没有回滚。
[前置识别](urov_y_backend.c#L2705) · [窗口模型](urov_y_backend.c#L2532) ·
[提交](urov_y_backend.c#L2779)

- **读前整数运算。** `LDXR → EOR → LDRB → EOR → STXR`。两次异或还原私有
  临时字。handler 从故障指令回溯时只越过最多三条 `NOP`，遇到第一条
  `EOR` 就停止。 [汇编](native/urov_observe.c#L271)
- **读后 FP 寄存器传送。** `LDXR → LDRB → FMOV d0,Xn → FMOV Xn,d0 → STXR`。
  两次传送保留原位模式，故障后的窗口模型遇到 `FMOV` 就停止。两个序列在这台设备上
  遇到 AP 异常后都留下失败的原生 `STXR`。 [汇编](native/urov_observe.c#L290)

两种探针只用 `LDRB` 读取目标，`STXR` 只向线程私有字原样写回。
固定自有 RX 页和 fd，用同文件同偏移的新 `PROT_READ` 别名作对照。
预热后，每种序列收集三轮、每轮 32 个有效三元组。只有前后对照均成功的组才采信。
两种序列的目标全部失败才确认 AP 信号。部分失败、对照不稳定或前后文件/VMA
身份变化时返回 `UNKNOWN`。Arm 对夹有显式内存读的独占序列没有进度保证，
因此应在部署机型上验证对照，且不能把一次 `STXR` 失败当作发现。
[配对控制](native/urov_observe.c#L696) ·
[Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)

### 处置与接入

将本地读点分歧、读点指令差异、已知 canary 的取指异常及两种 AP 探针结合。
有稳定证据时拒绝采信当前活页校验。有必需观测不确定时保留 `UNKNOWN`。
只发现内容变化时单独分类。所有必需信号为阴性且两路数据匹配文件时，才采信
本次采样。判定在 worker 上运行，既不取模块状态也不依赖 `process_vm_readv`。
APK 中的 `process_vm_readv` 与载荷执行只用于回归和建立测试真值。
[本地三路核对](native/urov_detect.c#L187) ·
[判定入口](apps/urov-detect/read_defense_fixture.inc#L283)

用可信制品 fd 上的 `pread` 或从一开始就建立的只读非执行别名计算原始摘要。
这条路径不受当前 `urov-y` 的目标页覆盖，提供的是制品基准。活页完整性需要
单独核验。可独立映射、无需运行时重定位的 PIC 代码可由新建的 `PROT_EXEC`
映射执行，数据用独立 `PROT_READ` 映射读取。只读非执行、仅执行以及私有匿名
RX 三种形状都被本版的目标登记校验拒绝。此路径适用于独立设计的代码及数据，
业务线程可继续用原映射。普通 App 能控制自己的校验决策和映射形状，内核模块
全局停用需要管理权限。
[目标登记条件](urov_y_backend.c#L1271) ·
[独立映射对照](apps/urov-detect/read_defense_fixture.inc#L574) ·
[Android 应用沙箱](https://source.android.com/docs/security/app-sandbox)

### 真机结果

Pixel 6、Android 16、ARM64、4 KiB、`6.1.134-android14-11`。SELinux 为
Enforcing，测试 App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`。
root 只用于宿主机装卸和采集内核日志，模块密钥只用于夹具设置和验证会话。
测试 APK SHA-256 为
`203d1081adc4cb291e5fbad34ad1b4209c137cbe3393b9372c4b438cf1109678`。
[真机矩阵](results/read-defense-v220-20261108-203449/summary.json)

每种模式的窗口和全调用者配置各运行 3 次，每阶段 32 个样本。实际伪造阶段结果如下。
读点证据每次启动的该阶段检查一次。

| 配置 | 两路 EL0 读值分歧 | 读点证据 | 两种 AP 探针同时命中 | 旧校验采信 | 新校验采信 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `SITE_BRK` 窗口 / 全调用者（各） | 96/96 | 指令差异 3/3 | 0/96 | 0/96 | 0/96 |
| `PAGE_UXN` 窗口 / 全调用者（各） | 96/96 | 取指异常 3/3 | 0/96 | 0/96 | 0/96 |
| `PAGE_AP` 窗口 | 96/96 | 0/3 | 96/96 | 0/96 | 0/96 |
| `PAGE_AP` 全调用者 | 0/96 | 0/3 | 96/96 | 96/96 | 0/96 |

全调用者 AP 的 96 个样本中，业务读、独立标量读和内核拷贝都匹配原文件，
但执行值仍为补丁的 `0x1235`。新规则全部拒绝采信。实际伪造 576/576，
等值会话 576/576 均见到覆盖证据。等值会话说明读路径受介入，返回值可以仍然
正确。未登记阶段 1,920 个样本的覆盖误报为 0。672/672 个原始样本获采信，
1,248/1,248 个仅含 Dobby 改码的样本归类为内容变化。全矩阵 `UNKNOWN=0`。
[全调用者 AP 日志](results/read-defense-v220-20261108-203449/read-defense-v220-ap-all-1-29948.log)

活动会话期间，18/18 次独立 `PROT_EXEC` 映射执行原始值 `0x1234`，fd 及
只读别名字节均等于原文件。拆会话后，三种防护映射的注册挑战各 18/18 次得到
`EINVAL`。21 次 App 启动累计记录 21,107,200 次业务 worker 操作，错误 0，
UI 心跳最大间隔 20 ms。按阶段类别聚合，新探针与本地读点核对平均每样本
6.7–7.1 ms，单次最大 37.3 ms，另有每阶段一次的读点指令/取指核对。
KPM 已卸载，boot ID 一致，增量内核日志无 BUG/WARNING/Oops。
[真机矩阵](results/read-defense-v220-20261108-203449/summary.json) ·
[生产 CRC 回归](results/crc-20261108-203759/summary.json) ·
[旧 Dobby 规则复核](results/dobby-detect-20261108-203818/summary.json) ·
[多页回归](results/multipage-20261108-203827/summary.json)

本轮精度和开销针对该设备与该 KPM 制品。探针的结论只覆盖采样页、读点及观测
期间，加载但未启用的模块在本轮属于阴性对照。16 KiB、其他 CPU 和内核需分别
验证独占对照及开销后再启用。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v220 --repeats 32 --cycles 3
```

## 2.20.0 LL/SC 窗口的完整建模

`urov-y` 2.20.0 把 2.19.0 的“STXR 前向白名单”换成**整窗建模**：故障 load 提交
之后，handler 在私有寄存器副本上逐条执行 `LDXR..STXR` 之间的窗口指令（最多 24 条、
`fault_pc+4 .. +96` 字节），gap 里的普通 load 走与故障 load 相同的
`read_range(allow_fake)` 视图，gap 里的普通 store 先记录、提交时经内核 GUP/COW 写
路径完成并把同样字节发布进 image/shadow，最后停在真正消费预约的 `STXR` 上。窗口内
再出现的 `LDXR/LDAXR` 按架构重建预约并把监视地址移到新地址。方案与不引入新特征的
论证见 [ELIMINATION_2_20_DESIGN.md](ELIMINATION_2_20_DESIGN.md)。
[窗口执行](urov_y_backend.c#L2532) · [读](urov_y_backend.c#L2425) ·
[写记录](urov_y_backend.c#L2472) · [提交](urov_y_backend.c#L2779)

| 模式 | 实现 | 普通 App 的观察点 |
| --- | --- | --- |
| `SITE_BRK` | 私有 COW 页上的指定读指令换成 `BRK`，异常处理器模拟原 load | 用独立读指令核对已知读点的指令字，交叉检查业务/独立/内核三路读 |
| `PAGE_UXN` | 读点页叶 PTE 设 UXN，由取指异常处理器模拟读指令及受限 `RET`/`NOP`/`BTI` | 交叉检查三路读视图与 canary 取指 |
| `PAGE_AP` | 清目标页叶 PTE 的 `AP[1]`，EL0 数据读陷入模拟，取指走活页 | 六种窗口探针（下表）+ 三路读交叉检查 |

### 探针与处置

`--read-defense-v220` 在 `PAGE_AP` 上下发六种无密钥窗口探针，每种都把窗口算出的
值通过 `STXR` 写进线程私有字，再与原生（同一序列、未装模块）比较：

- `csel`：`LDXR; LDRB; CSEL x,x,x,EQ; STXR`，读 NZCV。2.19 的残余；
- `load`：gap 里一条 `LDR`，其值就是 `STXR` 写回的值；
- `store`：gap 里 `LDR`+`ORR`+`STR` 改私有字，观察该字是否真的被写；
- `branch`：`CBNZ` 按读到的字节决定是否执行 `ORR`；
- `xload`：gap 里第二条 `LDXR` 重建预约（2.19 也是 0，用于证明没把成功改成失败）；
- `clrex` / `svc`：gap 里 `CLREX` 或 `SVC #0`。架构上这两者清本地监视器，原生
  `STXR` 必须失败；探针要求模块装上后仍失败（`unexpected_stores == 0`），
  即“拒绝建模”没有变成新特征。

判定沿用 2.18/2.19 的配对控制：每个有效三元组由只读别名上的两次成功 `STXR` 夹住
一次目标读取，三段各 32 个三元组；目标全失败记读陷阱，全成功记阴性，混合记未知。
新增 `value`/`value_ok`：窗口算出的值与原生不一致时单独记失败，不给“预约保住了”
的假阳性。
[窗口探针](native/urov_observe.c) · [夹具](apps/urov-detect/read_defense_fixture.inc)

### 真机结果

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
模块 `urov-y.kpm` SHA-256 `7b43e768…`，测试 APK `0d4d8ad5…`。
[检测矩阵](results/read-defense-v220-20261108-201133/summary.json)

6 种配置各 1 轮、每阶段 8 个样本。下表是覆盖阶段（`overlay`）的统计，另外 3 个
阴性阶段（`clean`、`patch_only`、`deactivated`）与 `no-module`、`post-unload`
全部为 0：

| 活动覆盖配置 | load | store | branch | xload | csel | value_ok | clrex_bad | svc_bad |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SITE_BRK 调用窗口 / 全调用者 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 32/32 | 0 | 0 |
| PAGE_UXN 调用窗口 / 全调用者 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 32/32 | 0 | 0 |
| PAGE_AP 调用窗口 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 32/32 | 0 | 0 |
| PAGE_AP 全调用者 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 | 32/32 | 0 | 0 |

全部 6 配置 × 5 阶段 × 8 样本 = 240 个样本，`unknown=0`；`clrex_done=svc_done=8`
表示两种“原生必失败”的形状在每个阶段都被采样并保持失败。会话结束后 `kpm list`
为空，前后 boot ID 一致，增量内核日志无 BUG/WARNING/Oops。

单变量对照（同一 APK、同一页面，只换模块，`--repeats 4`，AP-all 覆盖阶段）：

| 模块 | load | store | branch | csel | value_ok |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2.19.0（`b173a91a…`） | 4/4 | 4/4 | 4/4 | 4/4 | 4/4 |
| 2.20.0（`7b43e768…`） | 0/4 | 0/4 | 0/4 | 0/4 | 16/16 |

2.19 上只有 `xload` 一种形状能完成 `STXR`，所以 `value_ok` 分母是 4；2.20 上四种
形状全部完成，分母 16，分子相同——窗口模型算出的寄存器与内存效果与原生一致。

### 窗口模型的差分测试

`out/urov_window_test`（源码 [tests/urov_window_test.c](tests/urov_window_test.c)，
与 backend 共用 [urov_y_window.h](urov_y_window.h)）对 56 条指令用**独立写出的架构
期望值**校验窗口模型：位域抽取/插入/符号扩展、逻辑立即数、`EXTR`、`MADD/MSUB`、
`UDIV/SDIV`、变量移位、`RBIT/REV/REV16/REV32/CLZ/CLS`、`ADD/SUB`（含 `SP` 形式）、
`MOVN/MOVZ/MOVK`、`CSEL/CSINC/CSINV/CSNEG`、`CCMP/CCMN`、`ADR/ADRP`、`NOP/BTI/
DMB/ISB`、窗口内分支的取/不取，以及 `MRS/CLREX/SVC` 必须被拒绝。运行
`adb shell /data/local/tmp/urov_window_test` 输出 `cases=56 failures=0`。该测试在
开发中发现并修掉了三处建模错误（`UBFX/LSR/ASR` 的字段掩码、`CSINV/CSNEG` 的
`op` 位、以及 `SBFIZ` 的符号位边界）。

### 残余（2.20.0）

计时、未解码 store 重放窗口、pkey/POE、root 可见性、子进程外部写、重放交叠与不缺页
uaccess 写与 2.18/2.19 相同。窗口模型的边界是 `MRS/MSR`、SIMD&FP、SVE/SME、
`BL/BLR/RET`、LSE 原子、成对独占和走出窗口区域的形状：它们在不装模块时通常成功，
因此仍是潜在特征，但都不出现在编译器生成的 LL/SC 序列里。见
[2.20.0 设计 §5](ELIMINATION_2_20_DESIGN.md#5-残余2200)。

## 2.19.0 无密钥检测与防护复测

`urov-y` 按地址空间建立会话。每个目标页保存登记时的 `snapshot` 和用
`SRC_USER` 字节覆盖后的 `image`。读点的返回地址或帧链命中调用窗口时使用
`image`，窗口外使用 `snapshot`。零个调用窗口表示全调用者。测试先做 Dobby
改码再登记，因此伪造读值可以匹配文件，指令取指仍执行补丁。
[目标页和会话](urov_y_backend.c#L4232) · [读值提交](urov_y_backend.c#L3647)

| 模式 | 实现 | 普通 App 的观察点 |
| --- | --- | --- |
| `SITE_BRK` | 私有 COW 页上的指定读指令被换成 `BRK`，异常处理器模拟原 load | 用独立读指令核对已知读点的指令字。对目标页交叉检查业务读取和独立标量读取 |
| `PAGE_UXN` | 给读点页的叶 PTE 设置 UXN，由取指异常处理器模拟读指令及受限的 `RET`、`NOP`、`BTI` | 交叉检查业务和独立读视图。可调用预置在同一读点页的无副作用 `BTI C; RET` canary，与未登记的 RX 别名成对比较独占预约 |
| `PAGE_AP` | 清目标页叶 PTE 的 AP[1]，让 EL0 数据读陷入模拟。普通取指使用活页 | 用未被 LL/SC 桥补偿的 `LDXR; LDRB; CSEL; STXR` 测目标页 |

`process_vm_readv` 的 GUP 源页可被替换，`__access_remote_vm` 能改写
`/proc/*/mem` 和 ptrace 的返回，`vmsplice` 的 GUP 源页也有覆盖。fork 可以继承
受陷阱影响的映射。全调用者 AP 下，多个接口与文件的 CRC 一致时仍可能执行
不同的指令。早期双 iovec 读回、`mlock` 和等长 `mremap` 的结论以旧版本为准。
[远端 pin](urov_y_backend.c#L4793) · [内核辅助读](urov_y_backend.c#L5010) ·
[AP 异常](urov_y_backend.c#L3796) · [2.19 设计](ELIMINATION_2_19_DESIGN.md)

### 探针与处置

- `CSEL Xold, Xold, Xold, EQ` 在条件成立与否时都保留原值，读取 NZCV 而不修改
  标志。2.19.0 补偿了常见整数数据处理 gap，遇到读标志的 `CSEL` 仍交给
  硬件执行 `STXR`。目标读发生 AP 异常时，返回 EL0 后的独占预约丢失。探针只用
  `LDRB` 读取目标，`STXR` 最多向线程私有临时字原样写回。
  [模块解码](urov_y_backend.c#L1921) · [CSEL 探针](native/urov_observe.c#L263) ·
  [Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)
- 低频在工作线程检查自有、生命周期固定的 RX 页。验证设备号、inode、文件偏移和
  VMA 前后一致。AP 对照用同文件同偏移的新 `PROT_READ` 别名。预热后取三轮
  各 32 组有效的「对照成功 → 目标 → 对照成功」样本。目标全失败才记读陷阱，
  全成功记本次未见异常。混合结果、别名对照异常或身份变更记 `UNKNOWN`。
  独占失败还可能来自调试、调度或硬件行为，故将阳性限定为当前页的异常证据。
  [对照和判定](native/urov_observe.c#L505)
- 将实际读取、独立读取和已验证的文件基准用于完整性判断。确认设备允许
  `process_vm_readv` 时可把它纳入交叉检查。稳定分歧、内容变化或读点/页陷阱
  会阻止采信该完整性结果。若必需信号缺失或不稳定，完整性结论降为
  `UNKNOWN`，业务继续。等值会话的陷阱阳性说明读路径被接管，样本字节仍可等于
  原值。作用域限于采样地址和时段。
  [夹具与判定](apps/urov-detect/read_defense_fixture.inc#L224)
- 使用已验证制品的文件描述符或只读非执行映射提供原始字节，供版本校验和摘要
  基准使用。专门设计的代码可使用新建 `PROT_EXEC` 映射并分离数据读取，或在
  系统允许时使用私有匿名 RX。三种映射形状都被本版目标登记校验拒绝。只读别名
  表示文件的原始字节，已被 COW 修改的执行页仍要单独检测。全局卸载或阻止
  内核加载需要设备管理权限。
  [目标校验](urov_y_backend.c#L1278) · [映射验证](apps/urov-detect/read_defense_fixture.inc#L380)
- 两页 `MAP_SHARED` RX 的只读 fd 别名在真机上仍可登记。内核对这种 fd
  清除 `VM_SHARED`，但 `maps` 仍能依据 `VM_MAYSHARE` 显示 `s`。
  [反例日志](results/read-defense-v219-20261108-192929/read-defense-v219-brk-1-11202.log) ·
  [Linux mmap](https://github.com/torvalds/linux/blob/v6.1/mm/mmap.c#L1277-L1279) ·
  [Linux maps](https://github.com/torvalds/linux/blob/v6.1/fs/proc/task_mmu.c#L245-L249)

### 真机结果

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`0xc00`。检测运行在 `untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux
Enforcing。主机 root 用于 KPM 装卸和日志核验，模块密钥只供夹具建立、校验和
拆除会话。探针入口只接收地址、文件和偏移等观察参数。
[检测矩阵](results/read-defense-v219-20261108-193150/summary.json)

每种配置运行 3 次，每阶段 32 个样本。下表统计真实补丁被覆盖的阶段。读点
指令或 canary 每阶段检查一次。

| 配置 | 读值分歧 | CSEL 陷阱 | 读点证据 | 新规则采信 |
| --- | ---: | ---: | --- | ---: |
| SITE_BRK 窗口 / 全调用者（各） | 96/96 | 0/96 | 指令字变化 3/3 | 0/96 |
| PAGE_UXN 窗口 / 全调用者（各） | 96/96 | 0/96 | canary 取指陷阱 3/3 | 0/96 |
| PAGE_AP 窗口 | 96/96 | 96/96 | — | 0/96 |
| PAGE_AP 全调用者 | 0/96 | 96/96 | — | 0/96 |

AP 全调用者下，旧 ADD 探针和三路字节比较仍采信 96/96，载荷执行值为
`0x1235`。六种配置的等值会话也各自命中对应的读点或页陷阱。未登记阶段的
1920 个样本中陷阱误报为 0，672/672 个原始样本获采信。仅 Dobby 改码及拆会话
后仍保留补丁的样本被分类为内容变化。全部 3072 个样本最终 `UNKNOWN=0`。

`PROT_READ` 别名、专用 `PROT_EXEC` 和私有匿名 RX 的登记尝试分别
18/18 返回 `EINVAL`，原字节或执行值正常。21 次 App 进程启动累计记录
4,868,608 次业务 worker 操作，错误为 0，UI 心跳最大间隔为 20 ms。
7 种 CRC 配置回归通过，两套矩阵均保持 boot ID 一致，最终模块列表为空，
增量内核日志没有 BUG、WARNING 或 Oops。性能和误报数据来自本机，其他
机型或页大小应独立跑对照。
[检测矩阵](results/read-defense-v219-20261108-193150/summary.json) ·
[CRC 矩阵](results/crc-20261108-193256/summary.json)

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v219 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1 --skip-install
```

## 2.19.0 LL/SC 寄存器 gap 补完

以下为原设计对 2.18.0 残余 §6.5 的补偿及旧探针基线。
`PAGE_AP` 的读异常清掉本地独占监视器后，`LDXR; LDRB; ADD; STXR` 仍能观察到
`STXR` 失败。2.19.0 保留 2.18.0 的 `LDXR` 执行证据、直接/间接分支门控和
fail-closed 路径，只把 STXR 前向窗口从 NOP/BTI 扩到寄存器-only 整数数据加工。
handler 在私有寄存器副本上重放 gap，读取 STXR 当前的 `Rn/Rt/Rs`，只有 `Rn`
仍等于监视地址且 `copy_to_user` 成功后才写回寄存器/NZCV、置 `Ws=0` 并跳过
STXR；白名单外形状仍走原生失败。没有新增 hook、线程、定时器、PTE/VMA/代码字；
ABI 仍为 v8、`hooks=0xff`，请求布局、`ctl0` 文本、计数器与返回码不变。方案与
不引入新特征的论证见 [ELIMINATION_2_19_DESIGN.md](ELIMINATION_2_19_DESIGN.md)。

### 普通 App 无密钥复核

`--read-defense-v219` 在 6 种配置下各启动一次，每次每阶段 16 个样本。
活动 AP-all 覆盖阶段的三路读均等于文件字节，ALU 探针
`trap=0`、`target_failed=0`、`accept=16/16`；AP 调用窗口阶段仍按 caller-window
语义给出 `split=16/16`、`trap=0`、`accept=0/16`。全部阶段 `unknown=0`，
阴性阶段未误报。会话结束后 `kpm list` 为空，前后 boot ID 一致，增量内核日志
无 BUG/WARNING/Oops。[正式矩阵](results/read-defense-v219-20261108-191009/summary.json)

| 活动覆盖配置 | 字节分歧 | 独占陷阱 | 采信结果 |
| --- | ---: | ---: | ---: |
| SITE_BRK 调用窗口 | 16/16 | 0/16 | 0/16 |
| SITE_BRK 全调用者 | 16/16 | 0/16 | 0/16 |
| PAGE_UXN 调用窗口 | 16/16 | 0/16 | 0/16 |
| PAGE_UXN 全调用者 | 16/16 | 0/16 | 0/16 |
| PAGE_AP 调用窗口 | 16/16 | 0/16 | 0/16 |
| PAGE_AP 全调用者 | 0/16 | 0/16 | 16/16 |

### 生产 CRC、Dobby 与旧路径

`--repeats 3 --cycles 1` 的 7 模式 CRC 矩阵全部 PASS；`crc-ap-all` 中
`execute=1235`（Dobby 载荷执行）、`file=direct=window=f50bcaf6`，即业务 EL0 读、
独立标量读、`crc32` 窗口都等于文件字节，而执行仍走补丁。`--dobby-detection
--repeats 8` 的 `accepted_crc_with_ap=8/8`、`ap=0/8`、`views=0/8`，说明
NOP/BTI 间隔、XZR、pair、1024-iovec、sibling、split 和 fork 路径未被本次
gap 扩宽破坏。消除 3×1 全部 `ELIM_CASE` PASS（`exclusive_match=0`、
`ap_match=0`、`ELIM_PROT_STORE shapes=16`），多页 3×1 的 `mp-multi`、
`mp-ld1`、`mp-cross`、`mp-srcpage`、`mp-audit`、`mp-prod` 全部 PASS。
构建 `urov-y.kpm b173a91a...`、`urovdetect.apk b7c82bde...`。
[CRC 矩阵](results/crc-20261108-191038/summary.json) ·
[Dobby 矩阵](results/dobby-detect-20261108-191106/summary.json) ·
[消除矩阵](results/eliminate-20261108-191126/summary.json) ·
[多页矩阵](results/multipage-20261108-191239/summary.json)

### 残余（2.19.0）

计时、未解码 store 重放窗口、pkey/POE、root 可见性、子进程外部写、重放交叠与
不缺页 uaccess 写与 2.18.0 相同。gap 含 load/store、分支、异常、system
register、`CLREX` 或读标志指令时仍不补完，走原生失败；这是有意的 fail-closed
边界，不是本轮新增的行为。见 [2.19.0 设计 §5](ELIMINATION_2_19_DESIGN.md#5-残余2190)。

## 2.18.0 读回源页替换与外部写合并

[普通 App 无密钥复核与注册防护](#普通-app-无密钥复核与注册防护)覆盖本版三种模式及其全调用者配置。

本节消掉 2.17.0 “残余（2.18.0）”里两条普通 App、无密钥、稳定的特征：
`process_vm_readv()` 双 iovec 读回（2.17 的后置钩子按用户内存里的目的地址写回，
`post` 会被稳定写中）和外部写者让注册页 `dead`（写 1 字节后整页覆盖退役）。
只改 `urov-y`、测试 App/夹具与文档；ABI 仍为 v8，`hooks=0xff`，请求布局、
`ctl0` 文本、计数器与返回码不变。方案与不引入新特征的论证见
[ELIMINATION_2_18_DESIGN.md](ELIMINATION_2_18_DESIGN.md)。

### 实现和取证依据

`REGISTER` 按调用者的 `mm` 建立会话，每页保留注册时的 `snapshot` 与叠加
`SRC_USER` 字节后的 `image`。注册若发生在 Dobby 改码之后，`snapshot` 已含补丁。
模块检查 LR 和帧链，调用窗口内返回 `image`，窗口外返回 `snapshot`。
`caller_count=0` 表示全调用者。SITE_BRK 通过私有 COW 把指定读取指令换成
BRK。PAGE_UXN 给读取点所在页设置 UXN，接管该页的取指异常。PAGE_AP 清除目标页
叶 PTE 的 AP[1]，让 EL0 数据读取进入模拟，取指仍使用活页。模块向 GPR 或
FPSIMD 写回模拟结果并推进 PC。测试中的 Dobby 补丁因此可以在业务 CRC 看到原文件
字节时继续执行。
[注册](urov_y_backend.c#L3965) · [调用窗口](urov_y_backend.c#L1674) ·
[BRK](urov_y_backend.c#L3481) · [权限异常](urov_y_backend.c#L3515)

`process_vm_readv` 现在只让内核复制覆盖页：入口钩子记录 caller-window 判定，
`pin_user_pages_remote()` 的后置钩子把落在注册页基址上的 pin 页替换成持有
image/snapshot 的私有内核页，并把 `GUP_PIN_COUNTING_BIAS` 在原活页与替换页之间
搬移，调用者的 `unpin_user_page()` 正好抵消。`copy_page_to_iter()` 随后把覆盖
字节写到**内核导入的**目的地址，用户 iovec 数组不再参与覆盖，双 iovec 自引用
只能改变内核写到哪里，不能改变写进去的字节。
[源页替换实现](urov_y_backend.c#L4512) · [pin 钩子](urov_y_backend.c#L4488)

外部写不再把页标 `dead`。uaccess 写缺页、fast-GUP `FOLL_WRITE` 与
`__get_user_pages()` 的 `FOLL_WRITE` 在把写权限交给写者时，先通过 nofault uaccess 把活页
快照到 `ext_pre`；uaccess 路径在 COW 后立即重装 AP[1]，GUP 路径在页数组返回后
在 `__get_user_pages` 后置钩子里重装。下一次任何读路径先做 `uy_ext_drain()`：
GUP 读回活页，与 `ext_pre` 逐字节比较，只把变化的字节发布进 image/snapshot。
写者仍写活页，写者自己的读仍看到写进去的字节；未被写到的偏移继续返回镜像。
[快照/合并](urov_y_backend.c#L747) · [GUP 重装](urov_y_backend.c#L4638)

模块 verbose 加载（Pixel 6，`6.1.134-android14-11`）：
`pin_remote=1 gup_slow=1 page_ref=1/52`，`mm_fault=handle_mm_fault/4`，
`hooks=0xff`、`abi=8`。

### 真机矩阵

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| 读回双 iovec 8×1 | PASS；四模式 `post=0/8` 全部阶段，AP caller-window 下 `split=8/8`、`guarded_accept=0/8`，AP-all 下 `split=0/8`、`guarded_accept=8/8` | [read-defense-v216-20261108-180103](results/read-defense-v216-20261108-180103/summary.json) |
| 旧读防御 8×1 | PASS；`READ_DEFENSE_PAIR ... match=0 target_ok=64` | [read-defense-20261108-180119](results/read-defense-20261108-180119/summary.json) |
| v217 App 1×6 + root 探针 | PASS；`V217_GUP live_matches=1 active=1`、`V217_GUP overlay_alive=1`，`GUP live_matches_file=1 active=1`，`STORE replay view=5a live=5a active=1 armed=1` | [v217-20261108-180042](results/v217-20261108-180042/summary.json) |
| 消除 3×1 | PASS；`ELIM_PROT_STORE shapes=16`，`ELIM_BRIDGE` 全 0 | [eliminate-20261108-180150](results/eliminate-20261108-180150/summary.json) |
| 多页 3×1 | PASS；5 条路径 | [multipage-20261108-180243](results/multipage-20261108-180243/summary.json) |
| CRC 5×1 | PASS；`CRC_PAGE overlay direct=f50bcaf6 window=0c7da8a0` | [crc-20261108-180132](results/crc-20261108-180132/summary.json) |
| Dobby 24×1 | PASS；`accepted_crc_with_ap=24/24`，`views=0/24` | [dobby-detect-20261108-180259](results/dobby-detect-20261108-180259/summary.json) |

### 残余（2.18.0）

1. **计时**：每次 EL0 数据读仍一次同步异常；未解码 store 多一次 Software
   Step 与整页 diff。按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读，其他 CPU 只在本地失效后
   仍保留陷阱项；跨 CPU TLB miss 的亚指令级竞态，见设计 §3.3。
3. **pkey/POE**：本机无 POE，App 的 seccomp 拒绝 syscall 288/234，只验证
   拒绝/透传路径不碰会话。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍能看到模块，需要改 KernelPatch
   核心；不在普通 App 的 CRC 输入集合内。
5. **独占丢失**：PAGE_AP 下读异常仍清本地独占监视器，只对相邻/`NOP` 间隔的
   可证明 LL/SC 形状补完；属于读取异常路径的架构后果。
6. **子进程外部写**：子进程 mm 的外部写保持 2.17 的原生可写处理；owner 的
   外部写已合并。
7. **外部写与未解码 store 重放交叠**：`p->replay` 置位时外部写不快照，保持
   2.17 行为。

### 普通 App 无密钥复核与注册防护

测试选取 App 自有的稳定文件 RX 页。以文件描述符、设备号、inode 和文件偏移
校验映射身份，保留同文件同偏移的 `PROT_READ` 对照页。独立标量读取用固定
`LDRB`，与实际业务读取使用不同指令地址。检测阶段在普通 App 的工作线程运行。
主机用 root 装卸模块，夹具用独立的模块密钥建立真值。读值和独占探针只使用
地址、读取函数、文件和偏移。
[App 夹具](apps/urov-detect/read_defense_fixture.inc) · [读值观察](native/urov_observe.c#L80)

1. **字节复核**。分别重复采集业务读取、独立标量读取和同进程 `process_vm_readv`
   的字节。每条路径内部必须稳定，两次观测的内核视图也必须相同。三路有稳定分歧
   时记录读视图异常。全调用者 SITE_BRK 和 PAGE_UXN 下，业务和内核读可同时
   返回原文件字节，独立标量读仍能在未登记的读取指令上看到补丁。三路一致但偏离
   经校验的文件参考时单列为内容变化。
2. **PAGE_AP 复核**。执行 `LDXR; LDRB; ADD; STXR`。独占操作仅访问线程私有
   栈上字，且成功时原样写回。中间的 `LDRB` 是对目标页的唯一访问。2.18 的
   LL/SC 桥接受 load 与 STXR 间的 NOP 或 BTI，遇到这里的 ADD 会交回原生
   STXR。三组各 32 个有效三元组以只读别名的两次成功夹住目标读。目标 96 次
   全失败才记读陷阱，全部成功才记阴性，混合样本、对照不稳或映射失配记未知。
   夹具在 `EAGAIN` 时重试一次。等值 PAGE_AP 会话也呈阳性，因此这一项识别
   被测页的数据访问陷阱。实际执行值与读取字节的差异由专用 Dobby 载荷取证。
   [独占序列](native/urov_observe.c#L248) · [对照和判定](native/urov_observe.c#L489)
3. **完整性决策**。三路稳定一致、匹配已校验的参考且独占探针阴性，才采信
   被测范围的结果。内容变化、陷阱、读视图分歧和未知分别记录。遇到不确定结果
   时保留普通业务，完整性结论降为未知。按实际使用的稳定代码页取样，在校验入口
   运行一次。调用 `process_vm_readv` 前应确认部署配置的 Android seccomp 允许该
   syscall。这里的计时只用于度量开销。

旧的双 iovec 复测中，`post` 全程保留填充值。主机验证本机的源页替换路径有效。
其他内核若缺少 pin hook、页引用字段或 `vmalloc_to_page`，仍可能走旧的目的
缓冲区兼容路径。proc mem、ptrace 和 fast GUP 读也有覆盖钩子。普通 App 应把这些
路径视作不同观测源，单一路径读出的 CRC 一致只说明该路径返回了预期字节。
[兼容回写](urov_y_backend.c#L4555) · [内核读](urov_y_backend.c#L4729) ·
[fast GUP](urov_y_backend.c#L4791) · [双 iovec 复测](results/read-defense-v216-20261108-182627/summary.json)

**防护**。在独立的新映射里部署适合单独装载的 PIC 代码。使用经过校验的 ELF
文件片段做 `PROT_EXEC` 映射，文件校验从另一个 `PROT_READ` 别名取字节。
该执行映射没有 `VM_READ`。若部署允许匿名可执行映射，也可从可信字节建私有匿名
RX 页，其 VMA 没有 `vm_file`。这两类映射都被 `validate_target_vma()` 拒绝。
这一防护保护所选映射作为读取目标时的注册入口。其他可注册目标的 BRK/UXN
读取点按各自的站点规则校验。已有 linker `.text` 上的活动会话与这些新映射
分开处理，校验层可先拒绝采信结果。已经注册的 PAGE_AP 页会在成功的保护切换
后重装，`mlock` 和等长 `mremap` 都能保留其会话。
[目标 VMA 校验](urov_y_backend.c#L1243) · [保护更新](urov_y_backend.c#L1446) ·
[站点校验](urov_y_backend.c#L1195)

#### 真机复核

Pixel 6、Android 16、4 KiB 页、内核 `6.1.134-android14-11`、KernelPatch
`0xc00`。测试 APK 为 `untrusted_app`、`CapEff=0`、`Seccomp=2`，
SELinux 为 Enforcing。当前源码重建的 KPM 与真机使用的 KPM 的 SHA-256 一致。
六种配置各独立启动三次，每次每阶段采 32 样本。
覆盖阶段实际执行均为 `0x1235`，业务读取均返回 `0x1234` 对应的原文件字节。
[正式矩阵](results/read-defense-v218-20261108-182541/summary.json)

| Dobby 改码后启用覆盖 | 字节分歧 | 独占陷阱 | 采信结果 |
| --- | ---: | ---: | ---: |
| SITE_BRK 窗口 | 96/96 | 0/96 | 0/96 |
| SITE_BRK 全调用者 | 96/96 | 0/96 | 0/96 |
| PAGE_UXN 窗口 | 96/96 | 0/96 | 0/96 |
| PAGE_UXN 全调用者 | 96/96 | 0/96 | 0/96 |
| PAGE_AP 窗口 | 96/96 | 96/96 | 0/96 |
| PAGE_AP 全调用者 | 0/96 | 96/96 | 0/96 |

672 个干净样本全部通过，另有 1,248 个仅改码或已撤销覆盖的样本全部归为
内容变化。上述 1,920 个阴性对照均未报读值分歧或陷阱。等值 PAGE_AP 的
192 个样本均报读陷阱。活动 PAGE_AP 阶段的 18,432 个有效三元组全部出现目标
STXR 失败。3,072 个样本共重试 5 次，最终未知 0 次。

新建的文件仅执行映射和匿名 RX 映射各 18/18 次注册尝试均返回 `EINVAL`。
两者执行结果均为 `0x1234`。21 次 App 启动合计完成 2,812,672 次并行业务夹具
迭代，错误为 0，UI 心跳最大间隔 22 ms。单次复核的阶段平均耗时 3.38–6.83 ms，
实测最大 53.18 ms，包含映射检查和重试。设备保持同一 boot ID，测试后 KPM
列表为空，内核增量日志未报 BUG、Oops 或挂起。结论的实测范围是该设备、该模块
二进制、测试夹具的读取点与采样页。

另复跑了 v217 普通 App 六项回归。直接 I/O 写目标页后，`live_matches=1` 且
`overlay_alive=1`。写到达活页，后续 `SET` 仍能发布读视图。
[普通 App GUP 回归](results/v217-20261108-182748/summary.json)

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v218 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_v217_device.py --serial $Serial --key $KpKey --repeats 16 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```
## 2.17.0 任意写形状、fork 快照与并发原子

本节消掉 2.16.0 “残余（2.16.0）”里除读取计时之外的全部条目：未解码
store（SIMD 单 lane、STTR、SVE/SME）、并发原子丢更新、fork 子进程的
`mremap`/`mprotect`、fork 快照时机、fast-GUP `FOLL_WRITE` 写者被截获，以及
被拒绝的 `remap_file_pages` 先拆会话。只改 `urov-y`、测试 App/夹具与构建
脚本；ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 文本和返回码不变。
方案与不引入新特征的论证见 [ELIMINATION_2_17_DESIGN.md](ELIMINATION_2_17_DESIGN.md)。

### 实现和取证依据

`PAGE_AP` 的读路径不变：注册页 `REGISTER` 时保存整页 `snapshot`，用请求字节
覆盖 `image` 的窗口，EL0 数据读按 LR/帧链选择 `image` 或 `snapshot`，写异常先
解码；无法解码的 store 改为**延迟原生重放**：恢复本 CPU 的 AP[1]（只做本地
TLBI）、打开 `SPSR_EL1.SS`/`MDSCR_EL1.SS`，让内核正常完成 COW、硬件在 EL0
执行原 store，再用 `do_debug_exception` 的 EC 0x32 把活页与重放前的快照逐字节
比较，只把变化的字节发布进 image/影子并重装 AP[1]。[重放实现](urov_y_backend.c#L2829)

| 特征 | 2.17.0 做法 | 真机证据 |
| --- | --- | --- |
| 未解码 store 让页 `dead` | 延迟原生重放；不需要新解码，SVE/SME 与将来形状同路径 | `V217_STORE view=5a image=5a pipe=0 mem=13 iov=0 active=1 armed=1`；root 探针 store 8/8 断言，`STORE replay view=5a live=5a active=1 armed=1` |
| 并发 LSE 原子丢更新 | 可睡眠写锁串行化 image 读、活页写和发布，也覆盖解码 store、LL/SC 提交和内核辅助写 | 4 线程×64 次 `LDADD`：`V217_ATOMIC ... value=... want=... failures=0`；root 探针 256/256 |
| 子进程 `mremap`/`mprotect` 失效 | 影子按 owner index 索引；`uy_page_by_identity()` 用 `vm_file`+文件页偏移把子进程移动后的地址解析回 owner 页 | `V217_FORK child=0 owner=bb child_byte=1f active=1`；root 探针子进程 `mremap` 后仍读 `aa`，写入 `77` 只进自己的影子 |
| fork 快照时机 | `copy_mm` after hook 在 fork 时立即把当时的 image/snapshot 复制进子进程影子 | owner 在 fork 后 `SET` 到 `bb`，子进程前后都读 `aa`，owner 读 `bb` |
| fast-GUP `FOLL_WRITE` 被截获/挂死 | 该标志视为真实写目的页：不替换、让写落到活页并让该页转原生；`handle_mm_fault` 区分插件内部写与外部写，外部写缺页不再重装 AP[1]（修掉 2.16 就存在的 GUP 重试死循环） | `V217_GUP live_matches=1 active=1`；root 探针 `O_DIRECT` 读 4096 字节进注册页，EL0 读回与源文件一致 |
| `remap_file_pages` 先拆会话 | shared VMA 的合法调用不再在 syscall 前释放会话；成功只退役覆盖页，失败（本机总为 `EINVAL`）完全透传 | App 的 seccomp 拒绝该 syscall：`V217_REMAP skipped seccomp` 且会话 ACTIVE；root 探针 `REMAP rc=-1 errno=22 active=1 overlay=dd` |

fork 子进程的读仍遵守 caller window：影子同时保存 image 与原生 snapshot，
窗口内读 image，窗口外读 snapshot；子进程的写同时更新两份，父进程的
image/snapshot 不受影响（`urov_y_test --fork-write`/`--mremap` 通过）。

生产 CRC 的旁路由 `v217-crc` 直接演示：对真实的 linker `.text` 页先由 Dobby
把执行结果从 `0x1234` 改成 `0x1235`，再注册发布文件页。EL0 逐字节读、
`memcpy`+`crc32`、`process_vm_readv`、`vmsplice`/pipe 和 fork 子进程读都得到
文件摘要 `96964c4f`，而执行仍是 `1235`；`/proc/self/mem` 在 `untrusted_app`
下被 SELinux 拒绝（`errno=13`，记为 skipped），root 探针的同一路径读到镜像
（`STORE ... mem=0`）。会话在全部读之后仍 ACTIVE，`failures=0`。

### 真机矩阵

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
模块密钥只用于夹具注册/`SET`/状态对照。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| v217 App 2×6 | PASS；store/atomic/fork/gup/remap/crc 各 2 轮，全部 `DETECT_RESULT PASS` | [v217-20261108-152015](results/v217-20261108-152015/summary.json) |
| v217 root 探针 | PASS；store 8、atomic 4、fork 6、gup 3、remap 4 断言，`remap rc=-1 errno=22 active=1` | 同上 |
| 加固读防御 8×1 | PASS；`READ_DEFENSE_V216 stage=overlay n=8 split=8 post=8 post_ok=8 unknown=0`，AP 对 `alu=1`、`guarded_accept=0` | [read-defense-v216-20261108-152107](results/read-defense-v216-20261108-152107/summary.json) |
| 旧读防御 8×1 | PASS；`READ_DEFENSE_PAIR stage=overlay n=64 match=0 target_ok=64`，显式 DEACTIVATE 后 `inactive_after=1` | [read-defense-20261108-152120](results/read-defense-20261108-152120/summary.json) |
| CRC 5×1 | PASS；`CRC_PROT name=linker_text ... state=1 generation=1`，`CRC_PAGE overlay direct=f50bcaf6 window=0c7da8a0` | [crc-20261108-152309](results/crc-20261108-152309/summary.json) |
| 消除 3×1 | PASS；`ELIM_PROT_STORE shapes=16`、`ELIM_PROT ... store_absorbed=1`、`ELIM_BRIDGE` 全 0、`site_call_ns=508`（AP） | [eliminate-20261108-152156](results/eliminate-20261108-152156/summary.json) |
| 多页 3×1 | PASS；24 页/96 KiB、`MP_PROD_DONE paths=5 child_overlay=1`、`MP_AUDIT ... mprotect_active=1` | [multipage-20261108-152133](results/multipage-20261108-152133/summary.json) |
| Dobby 24×1 | PASS；活动阶段 `DOBBY_DETECT_AP stage=overlay n=24 match=0 accepted_crc=24`，`DOBBY_DETECT_RESTORE ... still_active=1` | [dobby-detect-20261108-152327](results/dobby-detect-20261108-152327/summary.json) |
| `urov_y_test` | `--mode ap` PASS（39 断言）、`--fork-write` PASS（7 断言）、`--mremap` PASS（5 断言） | 设备输出 |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

```text
urov-y.kpm      cb8b6be4c83d71406bd076a4e9314b4f4c639df84711ca1b5f6726d4f7d981fd
urovdetect.apk  a50e03430248b8da2e3e3c231a28d4b45382e3128318337f27ca12cc0aa08a72
v217_probe      2828ea781e42b020c11b42dfdbcc9fc7e8cf2be74a4b2d22da6c7fdfd94382a4
```

### 机制要点

- **延迟原生重放**：未解码 store 由硬件在 EL0 执行，`pre`/`post` 私有页 diff
  后只发布变化字节；只在本 CPU `tlbi vae1`，其他 CPU 保留陷阱项；
  `__switch_to` 在迁移后补 `MDSCR_EL1.SS`，`uy_replay_cancel` 用 orphan 记录
  保证仍消费一次 step。
- **写串行化**：`uy_write_enter()` 覆盖原子 RMW 的 image 读、活页写、发布，
  以及解码 store、LL/SC 提交和内核辅助写；读路径不取锁。
- **fork**：`copy_mm` after hook 立即快照；影子池按注册页数分配（默认 4 个
  fork 世代，16 MiB 上限），按 owner index 索引并同时保存 image/snapshot。
- **身份解析**：`uy_page_by_identity()` 用 `vm_file`+`vm_pgoff` 把子进程移动
  后的地址解析回 owner 页；`uy_page_for_fault()` 用于读、写、重装陷阱与
  `handle_mm_fault` 重装。
- **GUP 写者**：`FOLL_WRITE` 不替换返回页；外部写缺页不重装 AP[1]（修掉
  2.16 的 GUP 重试死循环），该页按原生字节转 `dead`。
- **输出面**：没有新增 syscall hook、ABI 字段、文件、线程、定时器或返回码；
  `hooks=0xff`、`ctl0` 文本不变。

### 残余（2.17.0）

1. 每次 EL0 数据读仍一次同步异常；未解码 store 多一次 Software Step 与整页
   diff。计时属于 `PAGE_AP` 的架构代价，按题目允许保留。
2. 未解码 store 的重试期间该页在本 CPU 可读，其他 CPU 仍保留陷阱 TLB 项；
   若恰在本地失效后发生 TLB miss，理论上可看到一次活页字节。窗口是单条
   指令级，不是稳定的字节特征。
3. pkey/POE：本机无 POE，App 的 seccomp 也拒绝 syscall 288；只验证了拒绝/
   透传路径不碰会话，未验证正向 POE 权限变化。
4. 外部写者（`O_DIRECT` 读进注册页、`process_vm_writev`）按原生语义写活页后
   该页转 `dead`，不再覆盖；这与“App 自己写了代码页”一致，不是覆盖存在的
   指纹。
5. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；隐藏它需要改
   KernelPatch 核心，超出“只改 `urov-y`”的范围。
6. `execve`/进程退出仍结束会话；旧代码已不存在，不构成读值不一致。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_v217_device.py --serial $Serial --key $KpKey --repeats 64 --cycles 2
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```

## 2.16.0 普通 App 无密钥复核

### 实现和取证依据

`REGISTER` 校验 ABI v8 请求的 MAC 并绑定调用者 `mm`。目标须位于有 `vm_file` 的
RX VMA。模块从活页复制整页 `snapshot`，再用请求字节覆盖 `image` 的指定范围。
有调用窗口时按 LR 和帧链选视图，窗口内读 `image`，窗口外读 `snapshot`。全调用者
配置让受拦截的读统一取 `image`。两份缓冲区都独立于 CPU 执行的目标字节。
[注册与镜像](urov_y_backend.c#L3250)

| 模式 | 捕获方式 |
| --- | --- |
| `SITE_BRK` | 在读指令所在页做私有 COW，用 `BRK` 替换登记指令。异常处理器模拟原 load，写回寄存器并推进 PC。 |
| `PAGE_UXN` | 给读者代码页的 PTE 置 UXN，在取指异常里模拟登记 load 和受支持的控制流指令。 |
| `PAGE_AP` | 清目标页 PTE 的 `AP[1]`，用 EL0 数据权限异常模拟读取。取指仍执行目标页的活字节。 |

2.16.0 的 `get_user_pages_fast()` 后置钩子给 `vmsplice()` 返回镜像页副本，
`__access_remote_vm()` 和普通 `process_vm_readv()` 的覆盖仍在。新版同时补齐成对 LL/SC、
写入模拟和 fork 影子页，并在等长 `mremap` 后保留 AP 会话。原先的 pipe 读实页、紧邻
`LDXP/LDRB/STXP` 和等长 `mremap` 已失去在 PAGE_AP 下的判别或撤销能力。
[2.16.0 设计](ELIMINATION_2_16_DESIGN.md)

### 双 iovec 读取活页

对自身 PID 发起一次 `process_vm_readv()`，两个远端项依次指向一个保存 `post` 地址的
局部变量和待校验的 RX 区间。第一个本地项的目标是第二个本地项的 `iov_base` 字段，
第二个本地项最初指向 `live`。Linux 先导入 iovec，再执行复制。第一段把用户态描述符
改为指向 `post`，第二段仍按内核已经导入的描述符将活页字节写到 `live`。
`uy_vm_readv_after()` 从用户态重新读取描述符，于是把镜像或快照写到 `post`。
所有目的地址均为探针的私有可写缓冲区。
[Android 内核实现](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1-sp/mm/process_vm_access.c)
[UROV-Y 后置钩子](urov_y_backend.c#L3733)

对照用同文件、同偏移的只读非执行别名，检查完整复制长度、描述符和映射身份。
交替用两种填充值初始化 `post`，要求三轮结果稳定。`post_copy=MATCH` 表示额外写回，
即使镜像与活页相同也能观测。`reader_diff=MATCH` 表示业务读者与 `live` 的字节稳定分叉。
只用 `live` 与发布版本的可信摘要比较来判定代码完整性。Dobby 单独改码会使摘要不符，
此时双视图相等且无额外写回。短读、控制失败、元数据或样本变化均为 `UNKNOWN`。
[探针实现](native/urov_observe.c#L115)

PAGE_AP 可用第二条路径交叉确认。`LDXR; LDRB; ADD; STXR` 的 `LDRB` 只读目标，
独占存储只写线程私有 scratch。故障返回清本地独占监视器，`ADD` 让当前桥接拒绝跨越
该指令。3 轮各接纳 32 组成功的前后对照，只在目标全部丢失独占且字节稳定时报告命中。
这是 AP 数据陷阱的辅证。直接把 AP 页交给 `write(pipe, target, n)` 的初测在该设备超时，
该路径已从探针移除。[独占检查](native/urov_observe.c#L248)
[超时记录](results/read-defense-v216-20261108-140505/summary.json)

### 接入与防护边界

- 对常规 ELF `.text`，在后台抽样复核，完整性判定只采信可信摘要与活页字节。
  业务继续执行。普通 App 能绕过当前钩子对校验输入的改写，内核会话撤销由授权控制面执行。
- 对原本由 App 管理、可独立部署的位置无关代码，使用 `MAP_PRIVATE|MAP_ANONYMOUS`
  并在初始化后从 RW 切成 RX。`validate_target_vma()` 因缺少 `vm_file` 拒绝三种模式注册。
  现有 ELF 保持装载器映射。[目标页校验](urov_y_backend.c#L996)
- 只在已确认允许 `process_vm_readv` 的 Android 配置上启用主探针。调用者须持有映射和
  fd 的生命周期，避免采样期间卸载、改保护或改码。结论适用于当前模块和已采样字节，
  未加载、加载空闲和覆盖其他地址时均可能没有信号。

### 真机矩阵

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11`。探针运行于
`untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux Enforcing。KernelPatch 权限和
模块密钥用于装卸、设置测试会话和核对状态，检测函数无控制面参数。

| 阶段 | 业务读与活页分叉 | 后置写回 | 按活页拒绝伪造通过 |
| --- | ---: | ---: | ---: |
| 无活动覆盖，含原码、仅 Dobby 改码和撤销后 | 0 / 9,984 | 0 / 9,984 | 代码改动由活页摘要判定 |
| 会话活动，镜像与活页相同 | 0 / 3,072 | 3,072 / 3,072 | 原码正常通过 |
| 会话活动，Dobby 改码被镜像遮蔽 | 3,072 / 3,072 | 3,072 / 3,072 | 3,072 / 3,072 |

四种配置为 BRK、UXN、AP 调用窗口和 AP 全调用者，各 6 个进程、每阶段 128 次。
活页读回与夹具真值一致 16,128 / 16,128，未知结果为 0。两种 AP 配置在活动阶段的
2,304 组有效对照中，目标独占存储全部失败。匿名 RX 的 24 次注册均返回 `EINVAL`，
代码仍可读取和执行。所有活动测试在复核后仍报告父进程会话活动。

业务线程执行 11,794,944 次迭代，错误为 0。UI 心跳最大间隔 20 ms。每次复核 32 字节，
包含三轮对照和两次映射身份检查，各阶段的平均耗时为 3.08–4.12 ms。测试前后 boot ID
一致，增量内核日志无匹配故障，模块列表已恢复为空。旧读防御矩阵也通过回归。
[真机汇总](results/read-defense-v216-20261108-141353/summary.json)
[旧矩阵回归](results/read-defense-20261108-141542/summary.json)

```text
urov-y.kpm      9d715b110ecf6b505fb7a7a7fa326f510cc93ddfca162371b749c297ef2283c8
urovdetect.apk  805f9757fc7f0d47ab9de4ae0a3e5f6d820161c677d6fee95dbeb19e7bc69ea1
```

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 128 --cycles 6
```

## 2.16.0 GUP 读、成对独占、mremap 保活与写形状补全

### 读取路径

ABI 仍为 v8。`REGISTER` 在调用进程的 `mm` 上建立会话；`page_build_image()`
从当前内存保存整页 `snapshot`，再用请求给的字节覆盖 `image` 的指定窗口。
`PAGE_AP` 的 EL0 数据读仍由叶 PTE 的 `AP[1]=0` 触发
`do_mem_abort()`，handler 按调用窗口选镜像/快照并模拟 load。

2.16.0 在 2.15 的 EL0、`process_vm_readv`、`/proc/<pid>/mem`、`ptrace`
之外补齐：

| 路径 | 入口 | 2.16.0 做法 |
| --- | --- | --- |
| `vmsplice`/pipe | `get_user_pages_fast()` | after hook 把覆盖注册页的 GUP 项替换为镜像页副本；调用者按 GUP 约定释放 |
| 成对独占 | `LDXP/LDAXP; load; STXP/STLXP` | 有界前向/后向窗口 + 直接分支位图 + GPR 门控；handler 提交 `STXP` 自己的值和状态 0 |
| 等长/移动 `mremap` | `mremap` | after hook 更新页基址/VMA 范围并重排；不拆除会话；代码页位图按整段平移 |
| `munmap`/`MAP_FIXED` | `munmap`/`mmap(MAP_FIXED)` | 只退役重叠页（`gone`），其余页与会话保持 ACTIVE |
| 原子 RMW | `LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN`、`SWP`、`CAS/CASP` | 解码后在镜像/活页上完成同一操作；CAS 失败只写回旧值 |
| `STXR/STXP` 写注册页 | 独占 store | 按 `ERET` 清监视器的原生结果置状态 1，不退役页 |
| 跨页 store | 普通/SIMD/`DC ZVA` | 按页拆分写入并逐页发布 |
| fork 子进程写 | 子进程 `mprotect` + store | 固定池影子镜像；子进程读影子，owner 镜像不变 |

`PAGE_AP` 在缺页和 `mprotect` 后重装陷阱；fork 子进程的 `mprotect` 也会
重新清 `AP[1]`。普通 store 与原子写通过内核 COW/GUP 路径落到活页，并在
返回 EL0 前重装 `AP[1]=0`。

### 无密钥检测与保护

本节记录 2.15.0 旧探针在 2.16.0 上的回归。当前活页读取方法见[本轮无密钥复核](#2160-普通-app-无密钥复核)。

2.15.0 结果中的三条普通 App 路径在 2.16.0 上不再产生稳定分叉：

1. **读实页。** `vmsplice` 的 pipe 视图与 EL0 视图都等于镜像；原先
   `READ_DEFENSE stage=overlay match=8 guarded_accept=0` 改为
   `match=0 guarded_accept=8`。
2. **AP 成对独占。** `LDXP; LDRB; STXP` 的目标 `STXP` 成功，探针回到
   `NO_MATCH`（`READ_DEFENSE_PAIR ... target_ok=64`）。
3. **撤销会话。** 等长 `mremap(page,page,page,0)` 后会话仍 ACTIVE，
   `READ_DEFENSE_STATUS active_before=1 active_after_remap=1`；需要显式
   `DEACTIVATE` 才恢复真实页。

生产 CRC 仍应把“活页字节 + 可信文件摘要”作为最终依据；本版让 EL0/pipe/
内核辅助读在同一时点看到同一镜像，但读时间、SVE/SME store、root 可见性
等边界见 2.16.0 设计 §6。

### 真机数据

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch
`0xc00`。探针运行在 `untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux
Enforcing。模块密钥只用于夹具注册和状态对照。

```text
urov-y.kpm      9d715b110ecf6b505fb7a7a7fa326f510cc93ddfca162371b749c297ef2283c8
urovdetect.apk  6d7b8ae8d123aaf7501f23074c20bc2534a6dc621b240267232377aa87d73b17
```

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| 加固读防御 8×1 | PASS；BRK/UXN 保持原语义；AP/AP-all 的 `overlay=0/8`、`guarded_accept=8/8`、pipe 与 EL0 均为文件页；pair 全 `NO_MATCH`；`mremap` 后仍 ACTIVE | [read-defense-20261108-134410](results/read-defense-20261108-134410/summary.json) |
| CRC 5×1 | PASS；`crc-ap-*` 的 direct/window 均等于镜像 | [crc-20261108-134434](results/crc-20261108-134434/summary.json) |
| 消除 3×1 | PASS；`ELIM_PROT ... store_absorbed=1`、`ELIM_PROT_STORE shapes=16`（LDADD/SWP/CAS/CAS-fail/STADD/CASP）、`ELIM_BRIDGE` 全 0、`site_call_ns≈340` | [eliminate-20261108-134502](results/eliminate-20261108-134502/summary.json) |
| 多页 3×1 | PASS；24 页/96 KiB、五条读路径、fork 子进程 | [multipage-20261108-134615](results/multipage-20261108-134615/summary.json) |
| Dobby 24×1 | PASS；`accepted_crc=24/24`、`ap=0/24`、`views=0/24` | [dobby-detect-20261108-134638](results/dobby-detect-20261108-134638/summary.json) |
| `urov_y_test` | `--mode ap` PASS；`--fork-write` PASS；`--mremap` PASS | 设备输出 |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

### 机制要点

- **GUP fast**：只替换 owner 或带陷阱叶的 fork 子进程的页；跳过
  `FOLL_PIN`/`FOLL_LONGTERM`；镜像页由调用者的 GUP 引用持有，会话结束/
  模块卸载不影响已入 pipe 的页。
- **成对桥**：`LDXP` 的两半结果仍等于内存（或两半 `XZR` 时使用控制流证据），
  间隔只允许 `NOP/BTI`；提交 `STXP` 的原始值、状态 0、PC 跳过间隔。
- **映射保活**：等长 `mremap` 不前拆会话；移动 `mremap` 更新页基址/VMA；
  `munmap`/`MAP_FIXED` 只退役重叠页。代码位图整段平移，部分移动才
  fail-closed。
- **写形状**：普通 store、SIMD、`STP`、`ST1`、`DC ZVA`、LSE 原子、
  `CASP`、跨页写都由 handler 完成；`STXR/STXP` 写注册页按原生失败处理。
- **fork 影子**：子进程第一次写注册页时从固定池取影子页；父镜像不受影响，
  子进程读/pipe/内核辅助读都取影子。
- **输出面**：没有新增 syscall hook、ABI 字段、文件、线程、定时器或返回码；
  `hooks=0xff`、`ctl0` 文本格式不变。

### 残余（2.16.0）

1. 每次 EL0 数据读仍一次同步异常，GUP/原子/影子有额外计时；计时/PMU 是
   架构边界，按本轮要求保留。
2. SVE/SME store、非 `NOP/BTI` 间隔的独占序列仍 fail-closed；Pixel 6 无
   SVE/SME。
3. fork 子进程自己的 `mremap`/`munmap` 没有重建影子地址；owner 不受影响。
4. fork 影子在子进程第一次写时创建；owner 在 fork 后、子进程首次写前
   `SET` 会让子进程看到新镜像而不是 fork 快照。
5. 原子 RMW 的读-算-写不是硬件单指令原子；并发同页写可能丢更新。
6. fast-GUP 的 `FOLL_WRITE` 被当作源页；当前内核真正写注册页的 GUP 写者
   走 `access_remote_vm`。
7. `pkey_mprotect` 已分配 pkey/POE、shared VMA 的合法 `remap_file_pages`
   仍保守处理；`execve`/进程退出仍结束会话。
8. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；需要改
   KernelPatch 核心才能隐藏，超出只改 `urov-y` 的范围。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```

## 2.15.0 普通 App 读实页与撤销会话

### 读取路径

ABI v8 控制面校验请求 MAC。`REGISTER` 在调用进程的 `mm` 上建立会话。
`page_build_image()` 从当前内存保存整页 `snapshot`，再用请求给的字节覆盖 `image`
的指定窗口。对走仿真的读，命中 LR 或帧链中的调用范围时用 `image`，范围外用 `snapshot`。
调用范围为空时所有受拦截的读都用 `image`。未拦截的 load 由 CPU 执行。

| 模式 | 捕获点 | 伪造发生的位置 |
| --- | --- | --- |
| `SITE_BRK` | 指定读指令在私有 COW 页上被替换为 `BRK` | BRK handler 解码原 load，把镜像数据写回 GPR 或 FPSIMD，推进 PC |
| `PAGE_UXN` | 读者代码页的叶 PTE 置 UXN | 取指异常走同一 load 仿真，支持有限的 `RET`、`NOP`、`BTI` |
| `PAGE_AP` | 目标页叶 PTE 清 AP[1]，取指继续从活页执行 | EL0 数据权限异常仿真标量、SIMD 等已支持的 load。`process_vm_readv` 和 `__access_remote_vm` 的 after hook 另外改写内核辅助读的结果 |

`PAGE_AP` 在缺页和 `mprotect` 后重装陷阱。2.15.0 让受支持的 store 走内核 COW/GUP 写路径，
把同一批字节发布到镜像与快照，同时保留 AP 陷阱。单寄存器 `LDXR/STXR` 桥用直接分支位图、
寄存器值和间隔指令校验约束提交，覆盖 XZR scratch 非零的情形。普通 store、权限切换和
旧 XZR 探针因此不能作为撤销或可靠告警。详见 [后端源码](urov_y_backend.c) 和
[2.15.0 设计](ELIMINATION_2_15_DESIGN.md)。

### 无密钥检测与保护

1. **读实页并校验。** 对 App 持有且生命周期稳定的 RX 地址，用 `vmsplice` 把该地址的
   `iovec` 送入私有非阻塞 pipe，再用 `read` 取到普通缓冲区。内核通过 GUP 引用当前映射的
   页，路径绕开三个异常仿真入口和两条内核辅助读改写入口。同地址的活页字节可直接作为
   完整性校验的输入。需要确认伪造时，与业务读者交错取两份，确认各自稳定后逐字节比较。
   纯 Dobby 改码会使两条读取路径都看到改码，因而只报代码完整性不符。短读、错误、映射
   或样本变化归为未知。上线时按页分块，在后台对受控范围运行，检查目标机型允许该 syscall。
   [Android 内核 splice 实现](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1-sp/fs/splice.c)
   [Linux GUP 入口](https://raw.githubusercontent.com/torvalds/linux/v6.1/lib/iov_iter.c)
2. **AP 辅证。** 在 16 字节对齐的线程私有 scratch 上执行 `LDXP`，中间用 `LDRB` 读 RX，
   最后 `STXP` 把 scratch 原值写回。2.15.0 的桥不处理成对独占。预热并交替读取目标与
   RX 对照，本次使用 64 对样本。仅在对照成功至少 62 次、目标成功 0 次、采样字节相等时
   判为陷阱信号。调度、其他异常和 CPU 差异会影响独占状态，这条信号用于佐证。
3. **撤销现有会话。** 确认分叉后，仅对受控且页对齐的映射调用
   `mremap(page, page_size, page_size, 0)`。2.15.0 的范围门控在原 syscall 前撤销重叠会话。
   本机内核在等长、零标志条件下返回原地址，测试检查 VMA、活页字节及执行结果。
   撤销范围是整个会话。BRK 释放可能等待 RCU Tasks，适合后台维护点。原映射仍可再次注册。
   [Android 内核 mremap 实现](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1-sp/mm/mremap.c)
4. **防止特定目标注册。** 对 App 本来就管理的独立代码页，`MAP_PRIVATE|MAP_ANONYMOUS`
   的 RX VMA 没有 `vm_file`，三个模式的目标页校验都返回 `EINVAL`。测试仅用一段位置无关
   的自有函数，先 RW 填充再改 RX。常规 ELF `.text` 采用读实页校验，无需重映射。
   只读 fd 的 `MAP_SHARED` 在真机试跑中仍能注册。Linux 会清掉内部 `VM_SHARED`，而
   `/proc/self/maps` 仍可显示 `s`，因此不能用 `r-xs` 推断它会被此模块拒绝。
   [共享映射的内核标志](https://raw.githubusercontent.com/torvalds/linux/v6.1/mm/mmap.c#L1277)
   [共享映射试跑日志](results/read-defense-20261108-124959/read-defense-brk-1-16558.log)

### 真机数据

Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` / KernelPatch `0xc00`。
探针运行在 `untrusted_app`，`CapEff=0`、`Seccomp=2`，SELinux Enforcing。模块密钥只用于
夹具注册和状态对照。使用下方历史矩阵同一份 `urov-y.kpm`，SHA-256 为 `5fa88121…`。

| 阶段 | 两条路径的稳定分叉 | 原校验接受原始字节 | 实页校验接受原始字节 |
| --- | ---: | ---: | ---: |
| 原始代码 | 0 / 3,456 | 3,456 / 3,456 | 3,456 / 3,456 |
| 仅 Dobby 改码 | 0 / 3,456 | 0 / 3,456 | 0 / 3,456 |
| 活动伪造，四种配置各 6 个进程 | 3,072 / 3,072 | 3,072 / 3,072 | 0 / 3,072 |
| 等长 `mremap` 撤销后 | 0 / 3,072 | 0 / 3,072 | 0 / 3,072 |

- `vmsplice` 的 13,056 次对照和活动采样均取得与真实页一致的 32 字节，未知数为 0。
  各阶段单次管道取样均值为 3.2–27.3 μs，含创建和关闭私有 pipe。
- 两种 AP 配置各 6 个进程命中成对独占探针。目标 `STXP` 成功 0/768，对照 768/768。
  其余 90 组无命中。旧 Dobby `process_vm_readv`、单寄存器独占和 XZR 探针复跑仍漏掉
  96/96 次活动 AP 样本。[旧探针复跑](results/dobby-detect-20261108-125713/summary.json)
- 不重叠的 `mremap` 对照保持会话活动，24/24 次目标页撤销成功，24/24 次匿名 RX 注册被拒。
  BRK 撤销最长约 112 ms，UXN 和 AP 最长低于 0.3 ms。业务线程 703,744 次迭代零错误，UI
  心跳最大间隔 25 ms，VMA 与预期执行结果均通过。前后 boot ID 相同，增量日志未匹配内核故障，
  最终模块列表为空。

结果覆盖当前二进制和所测机型的采样范围。相等表示该次采样未发现分叉，加载但未布置伪造的
模块不会因此产生告警。`vmsplice` 取到的是当时的活页，业务校验仍需可信的期望摘要。

[测试实现](apps/urov-detect/read_defense_fixture.inc) ·
[正式矩阵及逐进程日志索引](results/read-defense-20261108-125531/summary.json)

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 128 --cycles 6
```

## 2.15.0 写入吸收与 XZR 桥接

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。App 在 `untrusted_app` 域，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
本轮改 `urov-y` 与测试 App，ABI 仍为 v8，请求布局、`ctl0` 字段、`hooks=0xff`
和返回码不变。

```text
urov-y.kpm      5fa88121848de7818eede63ce2e71e021b2af47a4a0592609e76e124f88cc6be
urovdetect.apk 5104264ba4db14c1bfd460a52e49235188eba74dbd0a2fbbb34a3d7676767f2c
```

### 本轮消除的特征点

| # | 2.14.0 仍成立的特征 | 2.15.0 做法 | 真机证据 |
| --- | --- | --- | --- |
| E5 | 第一次真实 store 让该页 `dead`：恢复 `AP[1]`，Linux 完成 COW，后续读真实字节 | 解码 store，按原地址/宽度/值调用内核 `FOLL_WRITE|FOLL_FORCE` 写路径完成同一批字节，把字节发布到 `image`/`snapshot`，保持 `AP[1]=0`；原 store 不重放 | `ELIM_PROT ... store_absorbed=1`；`ELIM_PROT_STORE shapes=11 smaps=1 dirty_kb=4 anon_kb=4`；写窗口后仍读镜像 |
| E6 | `LDXR XZR; LDRB; STXR XZR` 在非零 scratch 上 `STXR` 失败，`nonzero_match>0` | `XZR` 不再要求目标为零；用 `LDXR` 固定 PC + 全进程直接分支位图 + 故障时 GPR 目标门控证明执行，提交 `STXR` 自己的零值和 status | Dobby 活动阶段 `xzr=0/144`；消除矩阵 `nonzero_match=0`、`nonzero_clean=3` |

实现与不引入新特征的论证见
[ELIMINATION_2_15_DESIGN.md](ELIMINATION_2_15_DESIGN.md)。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 48×3 | PASS；3 个活动进程各 `ap=0/48`、`bytes_differ=0`、`accepted_crc_with_ap=48/48`；合计 `ap=0/144`、`accepted_crc_with_ap=144/144`、`views=0/144`、`xzr=0/144`、`cross_page=0/144` | [dobby-detect-20261108-122951](results/dobby-detect-20261108-122951/summary.json) |
| CRC 5×2 | PASS，16 次运行；`crc-ap-*` 的 `mprotect(R)`→`mprotect(RW)`→`mprotect(RX)` 三阶段普通 CRC 都等于镜像，`STATUS` 仍 ACTIVE | [crc-20261108-123036](results/crc-20261108-123036/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行；`ELIM_PROT` 的 11 种写形状全部吸收，`smaps` 仍为原生 COW 的 `Private_Dirty=4 KiB`；`ELIM_PROT_KWRITE skipped errno=13`（App 被 SELinux 拒绝写 `/proc/self/mem`）；`site_call_ns=305` | [eliminate-20261108-123118](results/eliminate-20261108-123118/summary.json) |
| 多页 5×1 | PASS，6 次运行；`mp-prod` 24 页/96 KiB、`paths=5`、`child_overlay=1` | [multipage-20261108-123233](results/multipage-20261108-123233/summary.json) |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

### 机制要点

- **写入吸收**：写异常在 `do_mem_abort()` 原生路径之前解码；支持的形状
  由内核 COW/GUP 写路径完成同一批字节，`image`/`snapshot` 用每页 `seq`
  发布，读者不会看到半条 store；base 写回和 `IC IALLUIS` 与原指令一致。
- **可写叶陷阱**：`page_set_ap_any()` 允许在 COW 后的 writable 叶上装/撤
  `AP[1]=0`；`uy_leaf_signature()` 接受 AP[2]=0/1，释放路径仍能恢复。
- **内核辅助写**：`__access_remote_vm` 的 `FOLL_WRITE` 路径把 owner 的
  内核缓冲区字节同步进镜像；fork 子进程的私有拷贝不更新父镜像。
- **XZR 桥**：`LDXR XZR` 的控制流证据替代寄存器存证；零/非零目标都得到
  原生 `status=0` 和 scratch=0。
- **输出面**：没有新增 syscall hook、ABI 字段、文件、线程、定时器或返回码；
  `hooks=0xff`、`ctl0` 文本格式不变。

### 残余（2.15.0）

1. `munmap`/`mremap`/`MAP_FIXED` 覆盖、owner `execve`、进程退出仍结束会话；
   `fork` 子进程把自己的拷贝改成可写后，该子进程走真实字节。
2. 原子 RMW（`LDADD`/`SWP`/`CAS`/`CASP`）、`STXR/STLXR` 写注册页、SVE/SME
   store、跨页 store 仍退回 2.14 的按页退役。
3. `LDXP/STXP`、非 `NOP/BTI` 间隔仍不桥接；每次读一次同步异常、每次写一次
   EL0 权限异常和计时/PMU 仍是架构边界。
4. `pkey_mprotect` 的已分配 pkey/POE 权限、shared VMA 的合法
   `remap_file_pages` 仍保守处理；本机 App 的 seccomp 对 syscall 288 直接
   `SIGSYS`。
5. root 仍可用 `kpm list`/`ctl0 status` 看到模块和会话。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 2
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
```

## 2.14.0 保护切换存活与写入移交

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。App 在 `untrusted_app` 域，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
本轮改 `urov-y` 与测试 App，ABI 仍为 v8，请求布局、`ctl0` 字段、`hooks=0xff`
和返回码不变。

```text
urov-y.kpm      51140d2147cf67f781f3883b5bac927d13e21279032f06c02562b5f80d49f175
urovdetect.apk  889cb318e2766fda38bdebc517a50b2805cb4a36e6940f9c9e7b5fd7aea319f8
```

### 本轮消除的特征点

| # | 2.13.0 仍成立的特征 | 2.14.0 做法 | 真机证据 |
| --- | --- | --- | --- |
| E3 | 对已登记页做任何成功的 `mprotect`（`PROT_READ`、`PROT_NONE`、`PROT_EXEC`、`PROT_READ\|PROT_WRITE`）都先 `release_session()`；App 随后读真实改码字节 | 会话在保护切换后继续存活；可读保护重新装 `AP[1]=0`，`PROT_NONE` 只挂起并在恢复可读时重装；private COW 页在 `mprotect(PROT_WRITE)` 后仍由镜像服务，第一次真实 store 才交给 Linux COW 并退役该页 | `CRC_PROT name=linker_text stage=all ... direct=f50bcaf6 window=0c7da8a0 state=1 generation=1`；`ELIM_PROT ... read_r=1 none_segv=1 exec_readable=1 rw_overlay=1 store_retired=1` |
| E4 | 未分配 pkey 的 `pkey_mprotect`、private VMA 的 `remap_file_pages`、`MAP_FIXED\|MAP_FIXED_NOREPLACE` 会让门控先拆会话，Linux 随后才返回 `EINVAL` | `mprotect`/`pkey_mprotect` 在 owner 的 `PAGE_AP` 会话期间不再因重叠拆除；`remap_file_pages` 先做参数/private VMA 校验；`mmap` 补 fixed 标志组合预校验；Linux 拒绝的调用直接透传 | `CRC_PROT_CTL ... stage=R/RW/RX rc=0 errno=0 state=1`（三次保护切换后会话仍 ACTIVE）；`DOBBY_DETECT_RESTORE ... still_active=1 active_after_keyless=1` |

实现与不引入新特征的论证见
[ELIMINATION_2_14_DESIGN.md](ELIMINATION_2_14_DESIGN.md)。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 48×3 | PASS；3 个活动进程各 `accepted_crc=48/48`、`live=96964c4f`（等于文件）、`ap=0/48`、`accepted_crc_with_ap=48/48`；合计 `ap=0/144`、`accepted_crc_with_ap=144/144`；`views=0/144`、`xzr=0/144`、`cross_page=0/144`；`DOBBY_DETECT_RESTORE` 3/3 `still_active=1 active_after_keyless=1 inactive_after_deactivate=1 deactivate_errno=0` | [dobby-detect-20261108-114638](results/dobby-detect-20261108-114638/summary.json) |
| CRC 5×2 | PASS，16 次运行；`crc-ap-text`/`crc-ap` 在 overlay 后追加 `mprotect(R)`→`mprotect(RW)`→`mprotect(RX)`，三个阶段普通 CRC 都等于镜像、`STATUS` 都 `state=1`，恢复 RX 后执行仍为原返回值；`CRC_PROT` 与 `CRC_PROT_VMA` 记录单页 VMA 的原生拆分 | [crc-20261108-114724](results/crc-20261108-114724/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、21 个 case、63 次观测；`w-active` 的 `ELIM_PROT` 验证 `mprotect(R)` 读镜像、非法 store 不杀覆盖、`PROT_NONE` 原生 `SIGSEGV`、`PROT_EXEC` 可读叶仍读镜像、`mprotect(RW)` 读镜像、真实 store 后该页退役且写入成功、`DEACTIVATE` 成功；`exclusive_match=0`、`reader_match=0`、`ap_match=0`、6048 个 accepted triplets；`site_call_ns=292` | [eliminate-20261108-114809](results/eliminate-20261108-114809/summary.json) |
| 多页 5×1 | PASS，6 次运行；`mp-prod` 24 页 / 96 KiB、`paths=5`、`child_overlay=1`、`kmem_errno=0` | [multipage-20261108-114927](results/multipage-20261108-114927/summary.json) |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

### 机制要点

- **保护状态机**：每页内部 `want`/`armed`/`dead`。`mprotect` 成功后按新 prot
  重装或挂起 `AP[1]=0`；只有 `PROT_NONE` 在 arm64 上是真正的 EL0 不可读叶，
  此时把 `want`/`armed` 清零、**不改 PTE**，让原生 `SIGSEGV` 保持。
- **写入移交**：`mprotect(PROT_WRITE)` 后 private 文件叶仍是只读 COW，读陷阱
  继续有效；第一次 `WNR=1` 的 store 故障把 `AP[1]` 恢复、置 `dead=1`，不
  `skip_origin`，由原 `do_mem_abort()` 完成 COW。非法 store（VMA 不可写）
  不碰陷阱，保持原生 `SIGSEGV`。
- **门控**：owner 的 `PAGE_AP` 会话期间 `mprotect`/`pkey_mprotect` 不再因
  重叠 `release_session()`；`remap_file_pages` 的 private VMA、`mmap` 的
  `MAP_FIXED|MAP_FIXED_NOREPLACE` 先校验后透传。
- **输出面**：没有新增 syscall hook、ABI 字段、文件、线程、定时器或返回码；
  `hooks` 仍为 `0xff`，`ctl0` 文本格式不变。真实 store 后该页 `armed` 计数
  降为 0，但会话仍 ACTIVE，`DEACTIVATE` 正常。

### 2.13.0 的对照

同一设备、同一测试 App 矩阵的 2.13.0 构建（KPM `3395b61b…`、APK
`6c1726f4…`）在保护切换上：

| 阶段 | 2.13.0 | 2.14.0 |
| --- | --- | --- |
| `mprotect(PROT_READ)` 后读 | 会话已拆除，读到真实改码字节 | 会话 ACTIVE，读到镜像 |
| `mprotect(PROT_READ\|PROT_WRITE)` 后读 | 会话已拆除，读到真实改码字节 | 会话 ACTIVE，仍读到镜像 |
| `PROT_NONE` 后读 | 会话已拆除；恢复 RX 后读真实字节 | 会话 ACTIVE；`PROT_NONE` 期间原生 `SIGSEGV`；恢复 RX 后读镜像 |
| 首次真实 store | 无（会话已结束） | 原 Linux COW 完成写入；该页 `dead`，后续读真实字节 |

### 残余（2.14.0）

1. **真实 store 会退役该页覆盖**：普通 store、`STP`、原子 RMW
   （`LDADD`/`SWP`/`CAS`）、`DC ZVA` 都让该页 `dead`；检测器写一个字节
   （包括写回原值）后即可读真实字节。这是“不解码 store”的边界。
2. `munmap`/`mremap`/`MAP_FIXED` 覆盖、owner `execve`、进程退出仍结束会话；
   `fork` 子进程把自己的拷贝改成可写仍不受 owner 门控保护。
3. `pkey_mprotect` 在支持 POE 且 pkey 已分配的内核上没有逐项建模 pkey
   权限；本机 arm64 6.1 无 POE，App 的 seccomp 对 syscall 288 直接
   `SIGSYS`，测试无法从 `untrusted_app` 覆盖。
4. `remap_file_pages` 只在 private VMA 上免拆除；shared VMA 的合法重映射仍
   保守结束会话。
5. `LDXR XZR` 非零目标、`LDXP/STXP`、非 `NOP/BTI` 间隔、计时/PMU 仍是
   2.13 的残余；`site_call_ns=288/292` 与 2.13 的 280/285 同量级。
6. 单页 `mprotect` 会把多页 `.text` 拆成 VMA，这是 Linux 原生行为；
   `CRC_PROT_VMA` 明确记录并重新取基线，不把它归因于模块。
7. root 仍可用 `kpm list`/`ctl0 status` 看到模块和会话。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 2
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
```

## 2.13.0 普通 App 的 AP 探针与无效映射门控消除

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。App 在 `untrusted_app` 域，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
本轮改 `urov-y` 与测试 App，ABI 仍为 v8，请求布局、`ctl0` 字段、`hooks=0xff`
和返回码不变。

```text
urov-y.kpm      3395b61bd8c707d281b9dc908fee27c56d6eb8f950a8a983b285447e58ae5b62
urovdetect.apk  6c1726f458b80812cb0fc0648e3cdc1f28547aaf6e3efabfaa6a1fc96fa48b83
```

### 本轮消除的特征点

| # | 2.12.0 仍成立的特征 | 2.13.0 做法 | 真机证据 |
| --- | --- | --- | --- |
| E1 | `LDXR; LDRB; NOP; STXR` 的目标 `STXR` 在 `ERET` 后失败，AP 探针 `MATCH` | AP 桥在故障 load 后做有界前向扫描（最多 8 条，只允许 `NOP/BTI`），命中 `STXR/STLXR` 后补做原 store、置状态 0、跳过间隔和 `STXR` | 3 个活动进程各 `ap=0/48`、`accepted_crc_with_ap=48/48`，合计 144/144（2.12.0 为 `ap=48/48`、`accepted_crc_with_ap=0`） |
| E2 | 非对齐 `mprotect(page+1,1,PROT_READ)` 先撤销会话再返回 `EINVAL`，App 可无密钥恢复 | 映射门控在拿控制锁/撤销会话前镜像 Linux 的页对齐、`TASK_SIZE`、`prot`、`mremap` flags 预校验；Linux 会拒绝的调用直接透传，不碰会话 | `DOBBY_DETECT_RESTORE ... still_active=1 active_after_keyless=1 inactive_after_deactivate=1 deactivate_errno=0`，3/3 活动进程；镜像保持 `file` 字节，VMA 不变 |

实现与不引入新特征的论证见
[ELIMINATION_2_13_DESIGN.md](ELIMINATION_2_13_DESIGN.md)。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 48×3 | PASS；3 个活动进程各 `accepted_crc=48/48`、`live=96964c4f`（等于文件）、`ap=0/48`、`accepted_crc_with_ap=48/48`；`views=0/144`、`iov1024/sibling/split` 全等、`xzr=0/144`、`cross_page=0/144`、`bridge/nop/ind` 全 0；`DOBBY_DETECT_RESTORE` 3/3 | [dobby-detect-20261108-110733](results/dobby-detect-20261108-110733/summary.json) |
| CRC 5×2 | PASS，16 次运行（BRK/UXN/AP/AP-all/text/libc/big 及 clean/idle）；门控预校验未改变合法映射行为 | [crc-20261108-110819](results/crc-20261108-110819/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、21 个 case、63 次观测；`exclusive_match=0`、`reader_match=0`、`ap_match=0`、6048 个 accepted triplets、0 个目标 store 失败；`site_call_ns=280`（2.12.0 为 285/286） | [eliminate-20261108-110905](results/eliminate-20261108-110905/summary.json) |
| 多页 5×1 | PASS，6 次运行；`mp-prod` 24 页 / 96 KiB、`paths=5`、`child_overlay=1`、`kmem_errno=0` | [multipage-20261108-111020](results/multipage-20261108-111020/summary.json) |

全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
panic/RCU stall/hung task，测试后 `kpm list` 为空。

### 2.12.0 的对照

同一设备、同一测试 App 矩阵的 2.12.0 构建（KPM
`13ca0c0c…`、APK `2b9427f9…`）在活动阶段为：

| 阶段 | AP 探针 `MATCH` | `accepted_crc_with_ap` | `DOBBY_DETECT_RESTORE` |
| --- | ---: | ---: | --- |
| 2.12.0 活动 | 48/48 | 0 | `inactive_after_keyless=1`（非对齐 `mprotect` 拆会话） |
| 2.13.0 活动 | **0/48** | **48/48** | `active_after_keyless=1`，随后认证 `DEACTIVATE` |

因此，2.12.0 文档中“用 AP 探针拒绝采信”和“用非对齐 `mprotect` 撤销会话”
这两条普通 App 阻断路径在 2.13.0 上都不再成立。

### 机制要点

- **前向 LL/SC 窗口**：`uy_llsc_prepare()` 从故障 load 的 `PC+4` 起最多扫描
  8 条指令；只允许 `NOP/BTI` 作为间隔，遇到 `CLREX`、`SVC`、另一次
  load/store 或会改寄存器的 ALU 指令立即放弃。仍要求 `LDXR/LDAXR` 在
  load 前 0–3 条 `NOP` 内、宽度/基址/数据寄存器一致、`LDXR` 结果仍等于
  `[Xn]`，并经过既有全进程直接分支位图和 GPR 门控。提交时写 `STXR` 自己
  的值、状态寄存器置 0、`PC` 设为 `STXR+4`。
- **门控预校验**：`uy_gate_before()` 在 `ctrl_try_lock()`/`release_session()`
  之前检查 `mprotect`/`pkey_mprotect`/`munmap`/`madvise`/`mremap`/
  `mmap(MAP_FIXED)` 的页对齐、范围、`prot` 和 `mremap` flags。非法调用直接
  透传，Linux 仍返回 `EINVAL`；合法调用保持 2.12.0 的保活/重装/结束策略。
- **输出面**：没有新增 syscall hook、ABI 字段、文件、线程、定时器或返回码；
  `hooks` 仍为 `0xff`，`ctl0` 文本格式不变。

### 残余（2.13.0）

1. `LDXR XZR; ...; STXR XZR` 且目标内存非零时仍不代写：`XZR` 无执行存证，
   代写零可能改变未执行 `LDXR` 的内存。消除矩阵保留 `nonzero` 正对照。
2. `LDXP/STXP` 成对独占、非 `NOP/BTI` 间隔、`CLREX`/`SVC` 间隔仍不桥；
   fail-closed，不是新增能力。
3. 每次读仍一次同步异常（约 280 ns 站点调用）；桥的 store 仍是内核 nofault
   普通写，不是硬件独占 store；计时仍可区分。
4. 可写 `mprotect`、`munmap`/`mremap`/`MAP_FIXED`、owner `execve`、进程退出
   仍结束会话；子进程把拷贝改成可写后该子进程失去覆盖。
5. PTE 重装窗口、孤儿陷阱修复依赖模块仍加载、`fork` 不重建会话状态、
   `REGISTER` 后新建匿名可执行页的位图残余、`caller_count>0` 窗口语义、
   root 可见性和 App 自己的 seccomp 控制面均不变。
6. `pkey_mprotect` 的 pkey 取值和 `remap_file_pages` 的架构特定参数没有逐项
   镜像 Linux 校验；本文只覆盖常见预校验路径。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 2
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
```

## 2.12.0 普通 App 无密钥检测与恢复

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。App 在 `untrusted_app` 域，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。
本轮只改测试 App 和运行器，KPM 未改（SHA-256 `13ca0c0c…`，`hooks=0xff`、ABI v8）。
新版 APK 的 SHA-256 为 `2b9427f9…`。ADB 使用 root 装卸 KPM 与检查设备状态；
夹具用随机模块密钥建立会话并核对状态，检测探针和非对齐 `mprotect` 都不使用密钥或控制请求。

### 机制与检测选择

[`REGISTER`](urov_y_backend.c#L2323) 经 [`prctl` 鉴权](urov_y_backend.c#L2692)，把唯一
活动会话绑定到调用者的 `mm`。登记时保留实际页快照，再将 `SRC_USER` 内容合入返回镜像；
带调用窗口时依据 `x30` 和最多 16 层 `x29` 链选择镜像或快照，无窗口时统一取镜像。
陷阱处理器模拟读取，写回 GPR / FPSIMD、回写地址和 PC。[读值选择](urov_y_backend.c#L1871)

| 模式 | 实现与普通 App 的检查 |
| --- | --- |
| `SITE_BRK` | 登记的 load 指令经 COW 改成 BRK，异常按 `mm`、PC 和立即数匹配。对照签名发布 ELF 中已知读点的指令字；软件断点也会产生 BRK，COW 只作佐证。 |
| `PAGE_UXN` | 设置读取点页的 UXN，模拟该页取指，VMA 和指令字可保持原样。只调用设计时放在读点同页的自有 `BTI C; RET` canary，用独立 RX 别名做独占预约对照。没有安全 canary 就标为未知。 |
| `PAGE_AP` | 清登记页 PTE 的 AP[1]，真实指令仍供取指，数据读触发 `do_mem_abort`。用 `LDXR; LDRB; NOP; STXR` 做配对探测；异常返回丢失本地独占预约，而该版桥要求 `STXR` 紧跟故障 load，不会补做这条 store。 |

`PAGE_AP` 的对照是同一文件、同一偏移的独立 `r--` 别名；该版要求目标 VMA 为 RX，不能
直接登记此别名。探针预热后分三轮，每轮取 32 组「对照成功 → 目标 → 对照成功」。只有目标
96 次全部失败才报 `MATCH`；结果混合、对照不稳或映射身份变化报 `UNKNOWN`。只读目标页，
独占写回限于线程私有 scratch。采样字节不需要与对照相等，因此可将正常 COW 字节差异和
读路径异常区分开。调试、缺页和 CPU 实现也能影响独占状态，阳性不是模块身份证明；
阴性仅表示此次所采页和时段未观察到该现象。
[探针接口](native/urov_observe.h#L81) · [桥的条件](urov_y_backend.c#L1770) ·
[Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)

2.12.0 已改写同/跨进程 `process_vm_readv` 以及 proc mem、ptrace 走的内核读缓冲区。
换 CRC 读函数、换 iovec 数、锁页、fork、同权限 `mprotect(RX)` 和 `madvise` 都不宜作为
本版 AP 的检测或恢复主方案。纯计时与 `maps/smaps` 的权限或脏页标记也不足以单独判定。

### 真机对照

测试 App 在专用 linker `.text` 页用 Dobby 将执行结果从 `0x1234` 改为 `0x1235`；
开启 `PAGE_AP + SRC_USER` 后仍执行改码，读到的却是发布文件字节。

| 阶段 | 样本数 | 执行结果 | 内存 CRC32 | 探针 MATCH | UNKNOWN | 采信 CRC 通过 |
| --- | ---: | --- | --- | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | `96964c4f` | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | `24a41313` | 0 | 1 | 0 |
| 改码并开启覆盖 | 480 | `0x1235` | `96964c4f` | **480** | 0 | **0** |
| 无密钥撤销覆盖 | 480 | `0x1235` | `24a41313` | 0 | 1 | 0 |

13 个进程全部通过，含未加载、已加载但空闲、10 轮活动会话和卸载后对照。活动期
46,080 组有效目标 `STXR` 全失败；1,728 个对照样本零命中、2 个未知。仅按旧读值判定会
采信活动期 480 次 CRC；加入 AP 探针后全部拒绝采信。活动期单次探针平均 3.24 ms、
最大 3.75 ms，含文件身份与映射检查；全矩阵最大 9.90 ms。并行业务执行
12,091,520 次迭代，0 错误，UI 心跳最大间隔 31 ms。
[Dobby 原始记录](results/dobby-detect-20261108-104239/summary.json)

同一 KPM 的三模式矩阵 14 次 App 运行通过：`SITE_BRK` 2/2 见到读点 BRK 并在注销后恢复
原指令；`PAGE_UXN` 取指 83/83 命中、263 次对照均阴性；`PAGE_AP` 的窗口内、窗口外、
更新后和等值覆盖合计 64/64 命中独占探针。其他 UID 对照阴性。两套矩阵前后 boot ID
一致，模块列表为空，内核增量日志无匹配的 BUG、Oops、WARNING 或挂起记录。
[三模式原始记录](results/eliminate-20261108-103820/summary.json)

### 如何阻断

- **默认仅拒绝采信。** 对 `MATCH` 或 `UNKNOWN` 不把这次 CRC 当作完整性证明。
  普通业务照常。用签名发布清单定位 App 自有且稳定的 RX 代码页，持有映射和 fd 生命周期，
  在后台低频复测。避免探测 JIT、热补丁或可卸载映射。必要时对敏感操作另做服务端验证。
- **撤销本版 AP 的当前会话。** 在夹具中对已登记页执行 `mprotect(page + 1, 1, PROT_READ)`。
  [模块的前置门控](urov_y_backend.c#L3046) 先按重叠范围撤销；[Linux 的对齐检查](https://github.com/torvalds/linux/blob/v6.1/mm/mprotect.c)
  随后拒绝修改 VMA。未激活时 13/13 不改变读值；活动期对非重叠别名 10/10 保持伪造，
  对登记页 10/10 撤销伪造并恢复改码字节；全部返回 `EINVAL`，目标映射身份、权限和执行
  结果保持。必须用前后读值与探针复核，`EINVAL` 本身没有检测价值。该动作会撤销整个
  会话，依赖这一版门控顺序，建议仅用于受控恢复，不放入常规业务检测。
  [恢复夹具](apps/urov-detect/dobby_crc_fixture.inc#L259)
- **限制再次注册。** 恢复后，在安装过滤器前仍可重新注册（10/10）。在明确采用该策略的
  进程启动时，可用 seccomp TSYNC 精确拒绝 ARM64、固定 magic、`REGISTER` 和 288 字节
  请求的组合。实测安装 10/10，调用线程和已有同线程组线程的重试各 10/10 返回 `EPERM`。
  过滤器仅阻断已受过滤的线程，既有会话需另行恢复；`NoNewPrivs` 和过滤器对进程生命周期
  持久，启用前应核对进程模型。它不构成对内核执行权的隔离。
  [过滤器夹具](apps/urov-detect/dobby_crc_fixture.inc#L157) ·
  [Linux seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)

结果仅限上述设备、模块和采样页。部署前需在其他 SoC、页大小和 App 生命周期上校准。
普通 App 无法阻止已能改页表和异常处理器的内核；设备侧应使用已知可信签名镜像及锁定的
Verified Boot，敏感请求可在服务端验硬件证明与新鲜挑战。启动证明不等于逐页运行时证明。
[Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot) ·
[Android 硬件密钥证明](https://developer.android.com/privacy-and-security/security-key-attestation)

```powershell
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 8 --cycles 2
```

## 2.12.0 生产读路径、锁页、映射门控与 fork 保活

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。检测在 `untrusted_app` 中执行（`CapEff=0`、`Seccomp=2`、SELinux
Enforcing）；root 只用于装卸 KPM 与核对设备状态。设计与实现见
[ELIMINATION_2_12_DESIGN.md](ELIMINATION_2_12_DESIGN.md)。

```text
urov-y.kpm      13ca0c0ccd6ca462b08a0df50235c20107315d92d206edeffffde613aaef73c5
urovdetect.apk  4494e72c94d5e157b43765d24448fa21ebbb25aeae1329a892bb963cf6792dae
```

### 本轮消除的特征点

| # | 2.11.0 仍成立的特征 | 2.12.0 做法 | 真机证据 |
| --- | --- | --- | --- |
| E1 | `/proc/self/mem`、`ptrace`、跨进程读看到真实字节 | 新增 `__access_remote_vm`（5/6 参）after hook，按 `mm` 覆盖内核读缓冲区；`process_vm_readv` 改按**目标** `mm` 判定；fork 子进程按“仍带陷阱的叶子 PTE”逐页覆盖 | `DOBBY_DETECT_KMEM` 18/18 `errno=0 match=1`；`DOBBY_DETECT_FORK_KMEM` 3/3 子进程自己的 `/proc/self/mem` 与镜像一致；`mp-prod` 的五条读路径 CRC 全等 |
| E2 | 先 `mlock` 自有 RX 页即让 `REGISTER` 返回 `EINVAL` | `UY_VM_IO` 改回真实 `0x4000`，显式接受 `VM_LOCKED=0x2000` | `CRC_LOCK_GUARD` 12/12 `register_errno=0 active=1`；`DOBBY_DETECT_LOCK` 3/3 `overlay=1` |
| E3 | 重叠的无效 `madvise` 恢复整个会话 | advice 先按 Linux 取值域校验；无效值直接透传；`PAGE_AP` 下有效 advice 也不拆会话（缺页回调重装） | `CRC_RESTORE` 10/10 `madvise_errno=22 survived=1`；`DOBBY_DETECT_RESTORE` 3/3 `still_active=1 image_kept=1` |
| E4 | 重叠 `mprotect(RX)` 结束会话 | `PAGE_AP` 下新权限仍含 `READ|EXEC` 且不含 `WRITE` 时不拆会话，after hook 重装陷阱 | `MP_AUDIT` `mprotect_active=1`（会话保持且仍读到镜像） |
| E5 | `fork()`/`vfork()` 结束会话 | `PAGE_AP` 的 clone 不拆会话；子进程用陷阱签名（present、`AP[2]=1`、`AP[1]=0`）识别并取镜像；未驻留页按 VMA 身份在缺页时重装；会话结束后孤儿陷阱修复为可读并重试 | `mp-audit` `child_overlay=1`；`mp-prod` 子进程 64 字节全等；`DOBBY_DETECT_FORK_KMEM` 3/3 |
| E6 | `vfork`+`execve` 带走父进程的会话 | `execve` 只在执行者属于 owner 线程组时拆会话；`posix_spawn` 之类的子进程 `exec` 不再影响父进程 | 见 `mp-prod`（子进程 fork 后读镜像、父会话保持）与 `urov_y_test` 的 mode 分支 |

另外把 `find_task_by_vpid` 从“可选回退”改为 `PAGE_AP` 注册的硬要求
（缺失时 `REGISTER` 返回 `EOPNOTSUPP`），消除兄弟 tid 路径在无该符号内核上的
静默缺口。`hooks` 增加 `0x80` 表示内核读 hook；ABI 仍为 v8，请求布局、
`ctl0` 文本、计数器与返回码不变。

### 实现要点

- **内核读 hook**：`__access_remote_vm` 的 after 回调只在 `ret > 0`、
  `!(gup_flags & FOLL_WRITE)`、`mm` 属于会话（或仍是 fork 副本）时改写调用者的
  内核缓冲区；模块自身的 `access_remote_vm` 调用用 `current` 标记绕过。
  `/proc/self/mem`、`/proc/<pid>/mem`、`ptrace(PTRACE_PEEKDATA)` 与
  `access_process_vm()` 由同一入口覆盖。
- **`process_vm_readv`**：判定从“调用者 `mm`”改为“目标 `mm`”。外部进程读
  owner、同线程组兄弟 tid、`CLONE_VM` 兄弟进程都改写；真正外部 `mm` 保留
  GUP 字节。
- **`mlock`**：`VM_LOCKED` 只固定页、不改叶子 PTE，注册与陷阱照常；锁页反而
  缩小了换出后重装陷阱的窗口。
- **`madvise`**：`MADV_NORMAL..MADV_COLLAPSE` 与 `HWPOISON/SOFT_OFFLINE` 之外
  的值交给 Linux 返回 `EINVAL`，不碰会话；`PAGE_AP` 下 `MADV_DONTNEED` 掉掉的
  PTE 由缺页回调重装。
- **`mprotect`**：同权限（常见 `mprotect(RX)` 硬化调用）Linux 通常直接返回，
  PTE 不变；确实改了权限时 after hook 对范围内仍满足 `validate_target_vma()`
  的页重清 `AP[1]` 并刷 TLB。改成可写或去掉 `READ/EXEC` 仍结束会话。
- **`fork`**：fork 的子进程继承同一批叶子 PTE 的拷贝（`AP[1]` 已清）。异常
  入口在 `current->mm` 不是会话 `mm` 时用“只有本模块能产生的 PTE 形状”识别，
  按 `caller_count` 语义返回镜像；会话结束后同样形状走“置回 `AP[1]` + 重试”，
  不会变成信号。`fork` 时未驻留的页在子进程缺页时按登记时的 VMA 身份
  （`vm_file` 指针、`vm_pgoff`、`vm_start`、`vm_end`）重装陷阱。
- **`execve`**：`vfork` 子进程与父进程共享 `mm`，exec 只替换子进程的地址空间；
  门控改为只在 `task->tgid == 会话 tgid` 时拆会话。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 24×3 | PASS；3 个活动进程各 `accepted_crc=24/24`（合计 72/72）、`live=96964c4f`（等于文件）；`views=0/72`、`iov1024_match=1`、`sibling_match=1`、`split_match=1`、`xzr=0/72`、`cross_page=0/72`；`DOBBY_DETECT_KMEM` 18/18 与 EL0 视图逐字节一致，`DOBBY_DETECT_FORK_KMEM` 3/3 | [dobby-detect-20261108-010644](results/dobby-detect-20261108-010644/summary.json) |
| CRC 5×2 | PASS，16 次运行（BRK/UXN/AP/AP-all/text/libc/big ×2）；`CRC_LOCK_GUARD` 12/12 成功覆盖，`CRC_RESTORE` 10/10 会话存活；`crc-ap-all` 的 `direct=window=file` | [crc-20261108-010719](results/crc-20261108-010719/summary.json) |
| 消除矩阵 6×2 | PASS，14 次运行；`w-active` 798 条断言，`exclusive_match=0`、`zero_match=0`、桥/NOP/间接/跨页 store 均 0；`ELIM_TIMING mode=ap site_call_ns=285/286`（2.11.0 相同量级） | [eliminate-20261108-010801](results/eliminate-20261108-010801/summary.json) |
| 多页 5×1 | PASS，6 次运行；新增 `mp-prod`：24 页 / 96 KiB 真实 `.text`、`caller_count=0`，标量、`memcpy`、`process_vm_readv`、`/proc/self/mem`、fork 子进程五条路径的 CRC 全部等于镜像（`paths=5 child_overlay=1`） | [multipage-20261108-010925](results/multipage-20261108-010925/summary.json) |

- 全部矩阵前后 boot ID 一致，增量内核日志未匹配 `BUG:`/`WARNING:`/`Oops`/
  panic/RCU stall/hung task，测试后 `kpm list` 为空。
- `site_call_ns=285/286`（2.11.0 为 285）说明新增 hook 没有进入 EL0 读取路径；
  读取成本仍是每次读一次同步异常。
- `DOBBY_DETECT_AP` 在活动阶段仍为 `match=24/24`、`accepted_crc_with_ap=0`：
  这是**架构性**的独占预约丢失（`ERET` 清本地监视器），2.11.0 就存在，
  本轮未改变；它只影响独占探针，不影响任何读值。

### 残余（2.12.0）

1. `PAGE_AP` 每次数据读仍一次同步异常（约 280 ns/次）；桥的 store 仍是内核
   nofault 普通写，不是硬件独占写。二者是 `ERET` 语义与“不解码 store”的架构
   边界。
2. `mprotect` 把页改成**可写**、`munmap`/`mremap`/`MAP_FIXED` 覆盖、owner 自己
   `execve`、进程退出仍结束会话：页本身可写或被替换，`PAGE_AP` 没有 store
   解码，无法在可写页上保持只读陷阱。
3. `fork` 子进程把自己的拷贝 `mprotect` 成可写后，该子进程失去覆盖（父进程
   不受影响）；孤儿陷阱的修复只在模块仍加载时可用。
4. PTE 重装窗口仍在：只存在于“页被回收后重新 fault-in”的
   `handle_mm_fault` 内部，after hook 在返回 EL0 前重装；只有另一个 CPU 上
   恰好同时读该页的线程能看到。
5. 每次 `fork` 继承的陷阱不重建会话状态；`REGISTER` 之后新建的匿名可执行页
   的间接分支仍按 2.11.0 的位图残余处理（`uy_llsc_skipped`）。
6. `caller_count>0` 的窗口语义不变；生产覆盖请用 `caller_count=0`。
7. root 仍可用 `kpm list`/`ctl0 status` 看到模块与会话；`seccomp` 仍可由 App
   自己拒绝 `prctl` 控制面（进程策略，不是模块特征）。
8. 孤儿陷阱修复只按“退役基址 + 陷阱 PTE 形状”识别。arm64 生产内核没有 XOM
   特性，可读 VMA 之外没有同形 PTE；只有把 XOM 实现成 `AP[1]=0, AP[2]=1` 且
   另一进程恰好在同一虚拟地址上有这种页时，该页会被误置回可读。

### 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 2
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 6 --cycles 2
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
```

## 2.11.0 普通 App 无密钥复核：检测数据陷阱与锁页防护

2026-11-08，Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00`。沿用下一节的 2.11.0 KPM，只改检测库、测试 App 和运行器。检测在
`untrusted_app` 中执行（`CapEff=0`、`Seccomp=2`、SELinux Enforcing），只接收
地址、参照映射、fd 和文件偏移。密钥只交给建立会话和核对状态的夹具；root 只用于
装卸 KPM 和核对设备状态。

```text
urov-y.kpm      8d0eb588010cc2bb8df5791c3f650e48cf6efcefe407689c40e7a73b4b3c9a20
urovdetect.apk  fdee78dd0c56ac58e36e5e87776986ba9df482f218bc8391c87423127f62f254
```

### 实现与检测依据

模块用派生 selector 和请求 MAC 验证 ABI v8 的 `REGISTER`，把唯一活动会话绑定到
发起者的 `mm`。登记时复制当时的真实页为快照，并把 `SRC_USER` 字节合入另一份镜像。
快照不一定等于磁盘文件；例如 Dobby 在登记前改码，快照就是改码页。异常处理器按
`x30` 或最多 16 层 `x29` 帧链选视图，窗口内取镜像，窗口外取快照，无窗口时统一取
镜像。它解码读取指令并提交结果寄存器、回写与 PC；缺页可重装 PTE 陷阱，重叠映射
操作先恢复陷阱。详见 [注册](urov_y_backend.c#L2094)、[异常处理](urov_y_backend.c#L1845)
和 [映射门控](urov_y_backend.c#L2695)。

| 模式 | 机制 | 普通 App 可采用的证据 |
| --- | --- | --- |
| `SITE_BRK` | 对已知读指令所在私有页做 COW，以 `BRK` 触发模拟。 | 在独立读取点复核已知读指令，要求发布 ELF 的预期指令稳定变成 A64 `BRK`。测试为 `f9400000 → d43730c0`，3/3 个活动进程命中，注销后指令恢复。 |
| `PAGE_UXN` | 对读者页置 UXN；接管该页的取指异常，支持有限的指令流。 | 对 App 预置的同页 `BTI C; RET` canary 做配对取指，验证独占状态是否丢失。活动窗口和等值覆盖共 72/72 命中；BRK、AP 同条件各 0/72。不可将任意地址当作 canary 调用。 |
| `PAGE_AP` | 清目标页叶 PTE 的 AP[1]；原机器码照常取指，EL0 数据读经异常处理。 | 对目标做配对独占探针。即使镜像、同进程内核读和文件一致，异常返回仍清掉预约。 |

如果能无副作用地调用真实业务读者，业务读值与独立读取的稳定差异也可交叉确认；
三种模式的窗口夹具各 3/3。所有读者都得到干净镜像时，文件比对不能证实活体代码完整性。
2.11.0 会重写同 `mm` 的 `process_vm_readv` 结果，包括 65/1024 项、拆分向量和兄弟 tid。
不同 `mm` 的读与 `/proc/self/mem` 不在该重写路径内；但本机普通 App 在无活动会话时
打开 `/proc/self/mem` 得到 `EACCES`，同 UID 的独立子进程读取父进程得到 `EPERM`。
这是权限结果，不能作为模块信号。没有更改 dumpable 或 SELinux，也没有 attach ptrace。
参见 [向量读钩子](urov_y_backend.c#L2534) 和
[Linux 跨进程读的权限检查](https://github.com/torvalds/linux/blob/v6.1/mm/process_vm_access.c)。

### PAGE_AP 探针

[探针](native/urov_observe.c#L502) 用 `LDXR; LDRB; NOP; STXR`。只有 `LDRB` 读目标
字节，独占加载和存回同一个值都在本线程的私有栈槽。`NOP` 放在目标读**之后**，
因此 [2.11.0 的桥](urov_y_backend.c#L1596) 在故障 PC + 4 找不到 `STXR`，不会代报
成功。[Arm 独占监视器说明 §3.2.4](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)
解释了 `ERET` 清本地监视器的行为。旧的相邻探针和读**之前**插 NOP 的探针可能被桥接；
既有非零 scratch 的 XZR 探针也可作交叉复核。

目标为 RX；参照必须是同一文件、同一偏移的 `r--` 别名。Y 要求目标为 RX，因此
参照不会被当前实现登记。前后核对映射和文件身份；两个字节各自稳定即可，合法
COW 改码导致的字节差异不会触发阳性。预热后做三组各 32 次“参照 → 目标 → 参照”，
两侧参照都成功才接受。目标 `STXR` 96/96 失败报 `MATCH`，96/96 成功报 `NO_MATCH`；
混合结果、参照不稳定、对照废弃超过 8 次、元数据变化均为 `UNKNOWN`。耗时不参与判决。

### 真机对照

| Dobby 场景 | 样本 | MATCH | NO_MATCH | UNKNOWN |
| --- | ---: | ---: | ---: | ---: |
| 未改码 | 624 | 0 | 621 | 3 |
| 仅 Dobby 改码 | 624 | 0 | 624 | 0 |
| 改码且 `PAGE_AP` 活动 | 480 | 480 | 0 | 0 |
| 解除 `PAGE_AP`，保留改码 | 480 | 0 | 479 | 1 |

10 个活动进程中，目标函数始终返回 `0x1235`，普通 CRC 和同 `mm` 内核读均返回干净
镜像。旧规则采信 480/480 次伪造 CRC；加探针后采信 0/480 次。独立模式矩阵的 AP
活动样本另有 144/144 命中，其中 36 次为等值覆盖，36 次在镜像字节窗口外；既有非零
XZR 探针结果一致。Dobby 并行业务调用 12,175,232 次，0 错误，UI 心跳最大间隔
25 ms；探针含映射核验，均值约 3.3 ms，单次最大 10.2 ms。

### 如何阻止与恢复

- **预防：**在可能注册之前，`mlock` 少量自有关键 RX 页并持续保持锁定。该构建
  的 `UY_VM_IO` 数值 `0x2000` 在 [Linux 6.1](https://github.com/torvalds/linux/blob/v6.1/include/linux/mm.h#L282)
  实际是 `VM_LOCKED`；[目标 VMA 校验](urov_y_backend.c#L651) 对三种模式都拒绝此位。
  本轮 16 次有效登记均返回 `EINVAL`，覆盖私有 Dobby 页、共享 RX 别名及链接器
  私有 `.text`；代码仍可取指，读值稳定。部署须检查 `mlock` 成功，受 `RLIMIT_MEMLOCK`
  约束；重映射、解锁或不同构建后需重新验证。它不会自动撤销已有会话。
- **恢复：**只在受控页面和维护时机使用。夹具给重叠页传入无效 `madvise` advice，
  模块在 Linux 返回 `EINVAL` 前先恢复陷阱；非重叠参照保持会话。Dobby 10/10 次恢复
  真实改码字节，映射和函数行为保持；CRC 夹具另验证三种模式。`EINVAL` 本身不能证明
  成功，且此操作会解除整个会话，不能拿它当日常只读探针。
- **可选：**专用进程可在登记前安装既有 seccomp TSYNC 规则，只拒绝 ABI v8 的
  `REGISTER` 封包。10 次均使当前线程和已存在的兄弟线程返回 `EPERM`。过滤器与
  `NoNewPrivs` 会留在进程中，采用前须确认进程策略允许；锁页预防无需这一步。

生产接入建议在 worker 低频抽查持有生命周期的少量自有 RX 页，保持映射、fd 和参照
稳定。`MATCH` / `UNKNOWN` 仅停止采信本次活体 CRC；正常业务继续，`UNKNOWN` 可复查。
`NO_MATCH` 仅表示采样路径未见异常。单机数据不外推到所有 ARM64/16 KiB 设备；预约
丢失也不能唯一归因到模块名，且无法发现空闲模块、其他 `mm` 或未采样页。

正式结果：[Dobby 48×10](results/dobby-detect-20261108-001444/summary.json)、
[三模式 12×3](results/eliminate-20261108-001615/summary.json)、
[CRC 与锁页 5×1](results/crc-20261108-001736/summary.json)。三组均通过，设备 boot ID
保持一致，增量内核日志未发现崩溃或挂起；结束时 KPM 列表为空。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-install --skip-x-control --repeats 12 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
```

## 2.11.0 全 iovec 窗口、同 mm pid 解析与 1024 项边界

2026-11-07 在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，KernelPatch
`0xc00`）复核。检测、业务读者、1024 项读取、四项拆分读取和兄弟线程读取都在
`untrusted_app` 中执行，`CapEff=0`、`Seccomp=2`、SELinux Enforcing。夹具使用
认证请求建立会话并核对真值，检测函数只接收地址、读者和映射身份所需的参数。

```text
urov-y.kpm      8d0eb588010cc2bb8df5791c3f650e48cf6efcefe407689c40e7a73b4b3c9a20
urovdetect.apk  a4db11783c8bc15d8274c4bdafad877079964f1d87c7664e4feb5db7260ce8fc
```

### 当前实现

2.10.0 的 `process_vm_readv` after hook 在任一侧 `iovcnt > 64` 时直接返回。
65 个本地 iovec 只给首项长度、其余长度为零时，内核仍只复制 1–64 字节；这条
GUP 路径保持改码后的真实页，而 EL0 读者得到镜像，Dobby 活动阶段因此
`MATCH=480/480`、`accepted_crc=0`。同一个 hook 还只接受调用者自己的 tid/tgid，
同一 `mm` 的兄弟线程 tid 仍能看到真实字节。

2.11.0 只改读取路径：

- **完整 iovec 窗口。** `UY_VM_IOV_MAX` 提到 Linux 的 `UIO_MAXIOV`（1024）。
  两个 1024 项数组放不进 KPM 栈，因此用 `uy_iov_load()` 逐项
  `copy_from_user`，以 local/remote 两个游标按 syscall 返回值推进；零长度项
  跳过，只访问承载字节的项。65 项技巧只读第一项，没有新增每样本成本。
  `iovcnt > 1024` 的调用在进入 hook 前已被 Linux 以 `EINVAL` 拒绝。
- **同 mm pid 解析。** pid 不是当前 tid/tgid 时，在 RCU 下用
  `find_task_by_vpid()` 解析任务，仅当 `task->mm` 等于会话 `mm` 才重写。覆盖
  同线程组兄弟 tid 和 `CLONE_VM` 兄弟进程；真正的外部 `mm` 保留 GUP 字节。
  符号缺失时回退到旧的 tid/tgid 门控。
- **不新增 ABI。** ABI v8、`ctl0`、`hooks=0x7f`、计数器语义不变；没有新增
  syscall hook、文件、线程、定时器或返回码。`find_task_by_vpid` 只在 pid
  非自身时查询。

### 夹具与期望

- `ud_observe_live()` 仍用 65 项本地 iovec；新增一次 1024 项读取
  （`DOBBY_DETECT_MANY`）、兄弟 tid 读取（`DOBBY_DETECT_SIBLING`）和四项不同
  边界的拆分读取（`DOBBY_DETECT_SPLIT`），三者都与实际 EL0 读者逐字节比较。
- `crc-ap-all` 的内核视图期望从“改码页”改为“镜像页”；重注册检查也要求
  `UD_NO_MATCH` 且用户/内核都是原始页。这是夹具对已消除特征的同步调整，不是
  模块新增的输出。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 48×10 | PASS；10 个活动进程各 `accepted_crc=48/48`，合计 480/480；`views=0/480`、`iov65` 全部等于文件、`iov1024_match=1`、`sibling_match=1`、`split_match=1`；`zero_match=0`、`cross_page=0`、bridge/NOP/间接 store 均 0 | [dobby-detect-20261107-234206](results/dobby-detect-20261107-234206/summary.json) |
| CRC 5×1 | PASS，9 次运行；`crc-ap-all` 的 `direct=window=file`，`crc-ap` 的 `direct=0c7da8a0`、`window=f50bcaf6`，全部 `bridge=0/5` | [crc-20261107-234320](results/crc-20261107-234320/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行；`w-active` 539 条断言，XZR `match=0`，桥/NOP/间接/跨页 store 均 0；`ELIM_TIMING mode=ap site_call_ns=285` | [eliminate-20261107-234340](results/eliminate-20261107-234340/summary.json) |
| 多页 3×1 | PASS，5 次运行（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcpage`/`mp-audit`） | [multipage-20261107-234434](results/multipage-20261107-234434/summary.json) |

测试前后 boot ID 一致，`kpm list` 为空，增量内核日志未匹配崩溃、挂起或 BUG。
所有矩阵结束后模块未常驻。

### 残余（2.11.0）

1. 仍只接管同 `mm` 的 `process_vm_readv`；`/proc/self/mem`、ptrace 和跨进程
   `process_vm_readv`/`process_vm_writev` 仍看到真实字节。生产 CRC 若走这些
   路径，需要各自的控制面。
2. `madvise` 撤销会话、`mlock` 拒绝注册、root 可见性、PTE 重装窗口、每次读取
   一次同步异常、以及桥的非硬件独占 store 仍在；这些是会话与体系结构的既有
   边界，本轮未改。
3. 兄弟 tid 路径依赖可选的 `find_task_by_vpid` 和 RCU 读取；符号缺失时回退到
   tid/tgid 门控，不阻止模块加载。
4. 1024 是 Linux `UIO_MAXIOV`；不存在低于它的计数阈值可用来区分 hook 前后。
5. `caller_count > 0` 的窗口内/外读者差异仍是有意保留的 API 语义；
   `process_vm_readv` 按 syscall 的帧链选择镜像或快照。

### 复跑

使用与本节 SHA-256 一致的 `out/urov-y.kpm` 和
`apps/urov-detect/out/urovdetect.apk`。

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-install --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 3 --cycles 1
```

## 2.10.0 普通 App 的 65 项向量读、会话撤销和锁页防护（历史）

2026-11-07 在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`）复核。KPM 与下一节是同一构建，本文档顶部 2.11.0 是后续
消除版本。检测、业务读者、`madvise` 与 `mlock` 均在 `untrusted_app` 中执行，
`CapEff=0`、`Seccomp=2`、SELinux Enforcing。

```text
urov-y.kpm      8e3ad63b39d938a78dd851b54abd79cad3892e4ecbd234d8f45f058afc943110
urovdetect.apk  9aec504b82a599f462dd3d9259476fcc8952f66acf6abdeeb7b61cd1d7da5867
```

### 当前实现（2.10.0）

`REGISTER` 校验由装载密钥派生的 `prctl` 选择器和请求 MAC，将单一活动会话绑定到
调用者的 `mm`。它为登记的 RX 页保存注册快照，再把调用者提供的字节合入镜像。
故障处理器按 `x30` 或最多 16 层 `x29` 帧链选择视图。窗口内读镜像，窗口外读
注册快照，`caller_count=0` 时全部读镜像。模拟器提交读值、地址回写和 PC。
缺页回调重装活动的页陷阱，重叠映射操作先恢复原指令或页权限。

| 模式 | 接管点 | 普通 App 可核对的证据 |
| --- | --- | --- |
| `SITE_BRK` | 读取指令 COW 后换成 `BRK` | 实际业务读者与内核视图的字节差异，已知读取点指令字与发布 ELF 的差异 |
| `PAGE_UXN` | 读取指令所在页置 UXN，由 EL0 取指异常进入模拟 | 实际业务读者与内核视图的字节差异，同页自有 canary 的配对取指 |
| `PAGE_AP` | 清目标页叶 PTE 的 AP[1]，数据读触发权限异常，取指仍来自实际代码 | 业务读者与 65 项向量读的字节差异，非零 XZR 独占序列可佐证等值覆盖 |

### 检测

**主信号是稳定的字节差异。** 2.10.0 的 `process_vm_readv` after hook 对本进程的
常规读取缓冲区重写镜像或快照，但任一侧向量数大于 64 时直接返回。65 个本地
`iovec` 中只给首项设置长度，其余置零，实际仍只读目标的 1–64 字节。Linux 的
向量上限是 1024，原调用通过 GUP 取得实际页。先用 65 项读一次，再走两次真实
业务读路径，最后用 65 项重读。两路各自稳定、RX 映射与后备文件身份稳定且字节
不同才报告 `MATCH`。短读、失败、文件偏移错配和不稳定样本报告 `UNKNOWN`。

**AP 等值覆盖用独占状态佐证。** 在非零的线程私有栈槽上执行
`LDXR XZR; LDRB; STXR Ws, XZR`。普通路径的 `STXR` 可成功并写零。AP 数据异常
返回后独占预约丢失，2.10.0 的桥只允许原值已经是零的 XZR 写回，所以目标组
失败并保留非零值。每次以同文件、同偏移的独立 RX 别名做前后对照。

### 处置与业务接入

- **阻止伪值进入判定。** 在 worker 上低频检查生命周期固定的自有 RX 页，每次取
  一页内最多 64 字节，按字节核对发布基准。`MATCH` 和 `UNKNOWN` 时不采信业务
  读者的完整性结果。
- **终止已确认的覆盖。** 在受控、页对齐的自有页调用
  `madvise(page, page_size, -1)`。Y 在 Linux 校验 advice 之前恢复整个重叠会话，
  Linux 随后返回 `EINVAL`。
- **阻止选定页重新注册。** 在受控 RX 页首次注册前调用 `mlock(page, page_size)`。
  锁成功后针对该页的 `REGISTER` 会返回 `EINVAL`。

### 真机结果（2.10.0）

Dobby 共 13 个进程，10 个活动进程每阶段 48 次。`1 iovec` 列与 EL0 读值一致。

| 阶段 | 样本 | 执行返回 | 1 iovec CRC32 | 65 iovec CRC32 | `MATCH` | 采信 CRC |
| --- | ---: | --- | --- | --- | ---: | ---: |
| 原始代码 | 624 | `0x1234` | `96964c4f` | `96964c4f` | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | `0e1aba24` | `0e1aba24` | 0 | 0 |
| 改码 + `PAGE_AP` 全读者覆盖 | 480 | `0x1235` | `96964c4f` | `0e1aba24` | **480** | **0** |
| 撤销覆盖后 | 480 | `0x1235` | `0e1aba24` | `0e1aba24` | 0 | 0 |

上表的 65 项差异就是 2.11.0 消除的现役特征；2.11.0 之后同阶段
`views=0/480`、`accepted_crc=48/48`。单页锁定拒绝 18/18 次有效注册，重叠的
无效 `madvise` 10/10 次恢复，非重叠对照 10/10 次保持活动。

## 2.10.0 同进程内核辅助读与 XZR 独占序列

2026-11-07，在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`）复核。探针在 `untrusted_app` 域运行，`CapEff=0`、
`Seccomp=2`、SELinux Enforcing。设备 root 只用于装卸 KPM 和检查内核日志。
App 夹具使用模块密钥建立会话和核对真值，检测函数只接收自有映射、fd、偏移和
读者。

```text
urov-y.kpm      8e3ad63b39d938a78dd851b54abd79cad3892e4ecbd234d8f45f058afc943110
urovdetect.apk  4f259a66cf7e5cc8f461662bef46257df2a55de6d8f4ccc9363e5c32e682c621
```

### 本轮消除的现役特征

2.9.0 的活动矩阵里普通 CRC 已经通过，但检测器仍能从两条路径给出确定性命中：

1. **同进程 `process_vm_readv` 的双读差异。** GUP 路径不经过 EL0 数据异常，
   内核视图仍是改码后的字节；两次 EL0 读得到镜像，两路稳定不同即 `MATCH`。
   2.9.0 的 Dobby 活动阶段是 480/480。
2. **`LDXR XZR; LDRB; STXR Ws, XZR` 的无预约状态。** `ERET` 清掉本地独占
   监视器后，目标 `STXR` 原生失败；2.9.0 的桥拒绝 `Rt=31`，于是目标组每次
   失败而两侧对照成功，构成 `MATCH`（480/480）。

2.10.0 的做法：

- **`process_vm_readv` after hook。** 沿用已有的 syscall 表控制面，只对调用者
  自身 `mm`、且 `pid` 等于调用者 pid/tgid 的读生效。用 syscall 返回值限定
  重写长度，按 iovec 顺序重走本地/远端流，只替换落在已登记页上的字节；窗口
  语义复用 `caller_allowed_deep()`：窗口内读者拿镜像，窗口外拿注册快照，
  `caller_count=0` 时所有读者拿镜像。不新增 ABI 字段、`ctl0` 位或计数器，
  `hooks=0x7f` 保持不变。
- **XZR 桥。** `LDXR XZR` 与 `STXR XZR` 同时出现、宽度/基址一致、目标字当前
  为零时，handler 与普通桥一样置 `Ws=0` 并跳过 `STXR`；写回 0 是 no-op，保持
  “桥不改变字节”的既有不变量。目标字非零时不桥，保留原生失败。
- **PAC/MTE 间接分支门控。** `BRAA/BLRAA/RETAA` 在寄存器里留下签名指针，
  MTE 还带 top-byte tag；门控同时比较原值和按 `VA_BITS` 掩码后的值，覆盖
  “签名目标仍在 GPR”的形状。
- **完整分支目标图。** 2.9.0 只在 `REGISTER` 扫一次、只看可读可执行 VMA。
  2.10.0 覆盖所有 `VM_EXEC` VMA；扫描时未驻留的页由 `handle_mm_fault` 的
  after hook 在页第一次变为 present 时补扫（在故障任务返回 EL0 之前）；
  `mmap`/`mprotect`/`mremap` 的 after hook 扫描新出现的可执行范围。任一可达
  代码页 “present 但读不到”（如 XOM）或范围无法加入时，map 标为 incomplete，
  读路径 fail-closed，不再用单页扫描兜底。扫描用 seqlock 与故障路径互斥，
  mark 走 O(1) 的源 VMA 快路径；本矩阵 `REGISTER` 为
  `DOBBY_ARM register_ns=69,681,193`（70 ms），2.9.0 同文档记录约 240 ms
  （两次测试进程的映射集可能不同，仅作同设备量级对照）。

[读值选择](urov_y_backend.c) · [分支目标图](urov_y_backend.c) ·
[映射门控](urov_y_backend.c) · [探针实现](native/urov_observe.c#L61)

### 夹具期望的同步调整

- Dobby 的 `overlay` 阶段把双读期望从 `UD_MATCH` 改为 `UD_NO_MATCH`：检测器
  现在与 clean 阶段同形，`accepted_crc` 成为覆盖仍然生效的正向对照。
- `w-active` 的 XZR 期望改为 `UD_NO_MATCH`（`zero_clean`）。
- `crc-ap-all` 的内核期望改为镜像字节；带调用窗口的 `crc-ap*` 仍由窗口外的
  读者拿快照，`window_match` 期望不变。

### 真机结果

Dobby 矩阵 8×1（同一 APK、同一夹具）：

| 阶段 | 样本 | 执行返回 | live CRC32 | 双读命中 | XZR 命中 | 桥/NOP/间接/跨页 | 采信 CRC |
| --- | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 8 | `0x1234` | `96964c4f`，等于文件 | 0 | 0 | 0/256 各 | 8 |
| 仅 Dobby 改码 | 8 | `0x1235` | `2ae99109`，与文件不同 | 0 | 0 | 0/256 各 | 0 |
| 改码 + `PAGE_AP` 全读者覆盖 | 8 | `0x1235` | `96964c4f`，等于文件 | **0** | **0** | **0/256 各** | **8** |
| 注销覆盖后 | 8 | `0x1235` | `2ae99109`，与文件不同 | 0 | 0 | 0/256 各 | 0 |

- 活动阶段 `kernel_crc=96964c4f`（与 EL0 视图、文件一致）、`live views=0/8`、
  `zero_match=0 zero_clean=8`、`bridge_successes=0`、`nop_successes=0`、
  `ind_successes=0`、`cross_page_successes=0`；`spaced_accepted=768`、
  `spaced_failed=0`，说明相邻/NOP 间隔桥仍在工作。`hits=4032`、`failures=0`。
  单次跨页探针平均 2.93 ms、最大 3.02 ms；双读平均 0.322 ms。
- 业务线程与 UI 心跳照常；worker `807 ms`、135 条断言、0 失败。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 8×1 | PASS；`accepted_crc=8/8`、双读/XZR/四种桥全部 0 | [dobby-detect-20261107-200157](results/dobby-detect-20261107-200157/summary.json) |
| CRC 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big）；`crc-ap-all` 的 `direct=window=file`，全部 `bridge=0/5` | [crc-20261107-200217](results/crc-20261107-200217/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行；`w-active` 497 条断言，XZR 全部 clean；`ELIM_TIMING mode=ap site_call_ns=281` | [eliminate-20261107-200235](results/eliminate-20261107-200235/summary.json) |
| 多页 3×1 | PASS，5 次运行（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcpage`/`mp-audit`） | [multipage-20261107-200347](results/multipage-20261107-200347/summary.json) |

CRC 回归中 `crc-ap` 仍是 `direct=0c7da8a0`、`window=f50bcaf6`（窗口外读者拿
快照的既有语义）；`crc-ap-all` 为 `direct=window=f50bcaf6`，与镜像一致；
`crc-ap-text`/`crc-ap-libc`/`crc-ap-big` 三项继续通过，`crc-ap-big` 的
16/32/64/160/512/1024/4096 字节业务读者矩阵不变。所有矩阵结束后 `kpm list`
为空，boot ID 不变，增量内核日志未匹配崩溃、挂起或 BUG。

### 审计特征点现状（2.10.0 PAGE_AP）

| 审计条目 | 2.10.0 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻、NOP 间隔与 XZR 目的三种形状都由桥完成；直接分支、PAC/MTE 间接分支仍被门控拒绝。 |
| 1b. 无预约 `STXR` 状态探针 | 直接/NOP/间接/跨页四种形状均 0/256；XZR 只对零目标 no-op 代写，非零目标保持原生失败。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；回归矩阵保持阴性。 |
| 3. 业务读者/独立读者差异 | `caller_count=0` 时所有读者（含 GUP）拿同一镜像；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 固定 `prctl` 指纹 | 未变：每次加载派生 option/MAC，未认证请求仍是原生 `EINVAL`。 |
| 5. 同进程 `process_vm_readv` 双读 | 已消除：GUP 视图与 EL0 视图一致。 |

### 残余（2.10.0）

1. 每次读取仍一次同步异常；锁页重装窗口、root 可见性、注册事务窗口仍在；
   桥的 store 仍是内核 nofault 普通写，不是硬件独占 store。
2. 分支目标图的完备性依赖“扫描时/首次 present 时可读”。XOM 或不透明可执行页
   会让 map 进入 incomplete 并关闭桥（fail-closed）；`REGISTER` 之后新建的
   **匿名可执行**映射若在原地写入并在不再次 `mprotect` 的情况下执行，写入后的
   分支不会被补扫；已扫描页内的自修改代码同理。W^X（写完再 `mprotect RX`）
   流程由 mprotect after hook 覆盖。
3. 只接管同 `mm`、同一进程的 `process_vm_readv`。`/proc/self/mem`、ptrace、
   跨进程 `process_vm_readv`/`process_vm_writev` 以及 iovec 数超过 64 的调用
   仍看到真实字节；本夹具不使用这些路径。
4. `REGISTER` 仍有一次全进程代码扫描；本矩阵 70 ms，是控制面成本，不在 CRC
   读取循环里。
5. XZR 桥只在目标字为零时生效；非零 `STXR XZR` 保持原生失败。
6. `caller_count > 0` 的窗口内外读者差异仍是有意保留的 API 语义；
   `process_vm_readv` 按 syscall 的帧链选择镜像或快照。

### 复跑

在仓库根目录执行，使用 SHA-256 与本节一致的 `out/urov-y.kpm` 和
`apps/urov-detect/out/urovdetect.apk`。

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 3 --cycles 1
```

## 2.9.0 普通 App 同进程读值复核

2026-11-07，在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`）复核。探针在 `untrusted_app` 域运行，`CapEff=0`、
`Seccomp=2`、SELinux Enforcing。设备 root 用于装卸 KPM 和检查内核日志。
App 夹具使用模块密钥建立会话和核对真值，检测函数只接收自有映射、fd、偏移和读者。

```text
urov-y.kpm      f7d55fd8e96c6f6ba3a5e3af5aab8b33f2c6cdca300f5df074d7eccff30cb96d
urovdetect.apk  8c171280f70cb5c518072b6c24a84ba9caa8191e67e1e8e5a69993694165f1f5
```

### 实现与检测依据

`REGISTER` 在当前 `mm` 内登记只读可执行页，保留注册时的现场字节，再将调用者通过
`SRC_USER` 提供的窗口合入覆盖镜像。模块只有一个活动会话。异常处理器根据 `x30` 或
最多 16 层 `x29` 帧链选用覆盖镜像或现场快照，`caller_count=0` 时全部匹配。它解码
触发异常的 load，将读值、地址写回和 PC 更新提交给用户态。多页 AP 按地址切段取值，
缺页安装 PTE 后会重装陷阱。
[注册](urov_y_backend.c#L1852) · [读值选择](urov_y_backend.c#L1463) ·
[异常与重装](urov_y_backend.c#L1611)

| 模式 | 触发点 | 可复核的证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 后把登记的读指令换成 BRK | 同进程双读检查实际业务读者，已知读指令字与发布 ELF 的差异可定位触发点 |
| `PAGE_UXN` | 在读指令所在页置 UXN，接管 EL0 取指异常 | 同进程双读检查实际业务读者，已知同页 canary 的配对取指可定位触发点 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，EL0 读触发权限异常，取指仍走原页 | 同进程双读检查目标字节，XZR 独占序列可补查同值覆盖 |

- `process_vm_readv(getpid(), ...)` 通过 GUP 固定本进程的实际页，从内核视图复制字节。
  当前 Y 接管 EL0 异常和控制、映射等入口，这条读取路径绕过其读值模拟。先读一次
  内核视图，再走两次真实读路径，最后重读内核视图。两路各自稳定、映射身份稳定且
  两路逐字节不同才报告 `MATCH`。I/O 错误、短读、错配文件偏移和不稳定样本归为
  `UNKNOWN`。两路一致且字节符合发布基准时才采信完整性结果。带调用窗口时要复用实际
  读路径，另起一个普通 load 可能只读到现场快照。
  [探针实现](native/urov_observe.c#L63) ·
  [Linux 内核读](https://raw.githubusercontent.com/torvalds/linux/v6.1/mm/process_vm_access.c) ·
  [同 mm 检查](https://raw.githubusercontent.com/torvalds/linux/v6.1/kernel/fork.c)
- `LDXR XZR; LDRB; STXR Ws, XZR` 在私有零值 scratch 上建立独占预约，目标代码页
  只做 `LDRB`。2.9.0 的桥拒绝 `Rt=31`，因此 AP 异常返回后原生 `STXR` 报失败。
  每次要求三个批次，每批 32 组同文件 RX 别名成功、目标失败、别名再成功的对照。
  混合结果归为 `UNKNOWN`。这一项受 CPU、调度与调试环境影响，作为陷阱的补充证据。
  [桥的寄存器校验](urov_y_backend.c#L1409) ·
  [Arm A64 独占监视器](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)

### 避免采信和撤销覆盖

- 检查在 worker 上低频运行，每次最多 64 字节且限一页，调用方保留 RX 映射和 fd 的
  生命周期。`MATCH` 和 `UNKNOWN` 的完整性结果不予采信，普通业务沿原路径运行。
  只在已验证允许 `process_vm_readv` 的 Android 配置启用该入口，其他配置可能因
  seccomp 收到 `SIGSYS`。结果范围限于采样地址、读者和时段。
  [探针接口](native/urov_observe.h#L32)
- 需要撤销已确认的活动会话时，在受控页上调用 `madvise(page, page_size, -1)`。
  Y 先按地址重叠恢复整个会话的陷阱，随后原生 Linux 拒绝无效 advice，返回 `EINVAL`。
  以撤销后的重新采样验证读值恢复。地址不重叠时同样返回 `EINVAL`，活动会话仍在。
  这是针对当前门控顺序的一次性处置，作用范围是整个会话。
  [映射门控](urov_y_backend.c#L2317) ·
  [Linux madvise 实现](https://raw.githubusercontent.com/torvalds/linux/v6.1/mm/madvise.c)
- 可在进程早期选择启用 seccomp TSYNC，拒绝 ARM64 上同时匹配 `prctl`、固定
  `UROVYLAB` magic、`REGISTER` 和 288 字节的请求，然后处理已有会话。过滤器和
  `NoNewPrivs` 在进程内不可撤销，后者约束 `execve` 提权。保护覆盖该线程组及继承
  过滤器的任务，依赖当前控制 ABI 和内核执行入口。
  [夹具过滤器](apps/urov-detect/dobby_crc_fixture.inc#L156) ·
  [Linux seccomp 文档](https://www.kernel.org/doc/html/v6.1/userspace-api/seccomp_filter.html)

### 真机结果

Dobby 矩阵包含 10 个活动进程，每阶段 48 次，外加未加载、加载空闲和卸载后对照。

| 阶段 | 样本 | 执行返回 | 普通 CRC 通过 | 双读命中 | XZR 命中 | 采信 CRC 通过 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | 624 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | 0 | 0 | 0 | 0 |
| 改码并启用 AP 全读者覆盖 | 480 | `0x1235` | 480 | 480 | 480 | 0 |
| 撤销覆盖后 | 480 | `0x1235` | 0 | 0 | 0 | 0 |

- AP 活动期间，普通读值的 CRC32 为文件值 `96964c4f`，内核视图为改码后的
  `aa953cdd`。双读与 XZR 全矩阵均为零未知，旧跨页探针在活动期仍为 0/480。
  双读活动期平均 0.330 ms、最大 0.660 ms，全部阶段最大 3.841 ms。UI 心跳最大间隔
  21 ms，业务线程累计 10,619,264 次迭代，零错误。
  [Dobby 原始数据](results/dobby-detect-20261107-191555/summary.json)
- 10/10 次重叠的无效 `madvise` 撤销会话并保留测试页的 `MADV_RANDOM`、VMA 范围
  与 RX 权限。10/10 次非重叠对照保持活动。TSYNC 安装 10/10 次成功，安装线程和
  安装前已存在的线程各 10/10 次重新注册收到 `EPERM`。
  [撤销与拦截记录](results/dobby-detect-20261107-191555/summary.json)
- CRC 矩阵 23 次运行通过。BRK、UXN、带调用窗口的 AP 各有 72/72 次业务读者命中，
  独立读者各 0/72。AP 全读者覆盖下两个用户读者各 72/72 次命中。960 组对照均为
  阴性，所有双读零未知。四类会话均经无效 advice 恢复，各 3/3 次。其余 `.text`、
  libc/zlib 与大块拷贝回归通过。
  [CRC 原始数据](results/crc-20261107-191717/summary.json)
- 模式与生命周期矩阵 17 次运行通过。AP 的活动页、覆盖窗口外、`SET` 后及等值覆盖
  四项 XZR 观测各命中 36/36。多页、向量和跨页矩阵 5 次运行通过。全部测试结束后
  模块列表为空，boot ID 一致，内核增量日志未匹配崩溃或挂起。
  [模式和生命周期](results/eliminate-20261107-191815/summary.json) ·
  [多页回归](results/multipage-20261107-191950/summary.json)

这些结果覆盖本机、该 KPM 构建和已知稳定的自有 RX 页。其他 Android 策略、SoC、
16 KiB 真机和生产流量需要各自校验。普通 App 的证据依赖当前内核读路径，拥有内核
执行权的一方可以改变读路径或过滤策略。

### 复跑

在仓库根目录执行，使用 SHA-256 与本节一致的 `out/urov-y.kpm`。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1 -Observer
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 24 --cycles 3
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 12 --cycles 3
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
```

## 2.9.0：REGISTER 期全进程分支目标位图

2026-11-07，Pixel 6（oriole），Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`。被测构建：

```text
urov-y.kpm      f7d55fd8e96c6f6ba3a5e3af5aab8b33f2c6cdca300f5df074d7eccff30cb96d
urovdetect.apk  2ad6df7061ad2e3a307b265cca407de37a6e7e6197f9e3476b0310d86df8132e
```

本轮消除 2.8.0 的现役特征：跨页直接分支探针。`REGISTER` 在清任何 `AP[1]`
之前，先枚举会话 `mm` 的所有可读可执行 VMA，把全部
`B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ` 的静态目标写入按 VMA 划分的位图；故障时只查
`[LDXR+4, load]`。`uy_llsc_prepare()` 的寄存器、宽度、自然对齐和
`Rt == [Xn]` 条件不变；`uy_llsc_commit()` 仍是同一地址、宽度和值的 nofault
普通写。

先试的硬件独占监视器方案在异常进入时失效：handler 内清 `PAN` 后发出的真实
`STXR` 在 2656 次尝试中全部失败（`dbg prepare=2656 pte=0 ok=0 fail=2656`），
因此改为注册期位图，避免读取路径出现首次扫描的 50–130 ms 尖峰。最终读取路径
的 `ELIM_TIMING mode=ap site_call_ns=283` 与 2.8.0 的 281 同量级。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS；活动阶段 `execute=0x1235`、`live=96964c4f`（等于文件）、`accepted_crc=24/24`、`cross_page_successes=0/768`、`bridge/nop/ind` 均 0；平均探针 3.03–3.27 ms，最大 7.68 ms | [dobby-detect-20261107-184405](results/dobby-detect-20261107-184405/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、1438 条断言；`ELIM_BRIDGE` 四项均 `verdict=0 trials=32 successes=0`；`ELIM_TIMING mode=ap site_call_ns=283` | [eliminate-20261107-184445](results/eliminate-20261107-184445/summary.json) |
| CRC 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-184601](results/crc-20261107-184601/summary.json) |
| 多页 3×1 | PASS，5 次运行（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcpage`/`mp-audit`） | [multipage-20261107-184622](results/multipage-20261107-184622/summary.json) |

测试进程的分支位图为 358 个可执行 VMA、6,000,742 字节；`REGISTER` 扫描约
240 ms。该成本只在显式注册路径，故障路径只做位测试。测试前后 boot ID 一致，
`kernel_issues=[]`，`kpm list` 为空。

### 审计特征点现状（2.9.0 PAGE_AP）

| 审计条目 | 2.9.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 顺序到达由桥完成；直接分支（含跨页、跨映射、任意距离）由注册期位图拒绝；间接分支目标仍在 GPR 时由 GPR 门控拒绝。 |
| 1b. 无预约 `STXR` 状态探针 | 直接/NOP/间接/跨页四种形状均 0/32；预置 `Rt==[Xn]` 也需 LDXR 真的执行，否则被分支/GPR 门控拦下。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；代码字与 smaps 仍等于基线。 |
| 3. 业务读者/独立读者差异 | `caller_count=0` 时所有读者拿同一伪视图；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 固定 `prctl` 指纹 | 每次加载派生 option/MAC；未认证请求仍是原生 `EINVAL`。 |

### 残余（2.9.0）

1. `REGISTER` 之后新建的可执行映射不在位图中；从这种映射跳入 `[LDXR+4, load]`
   的跨映射直接分支仍可绕过。
2. 不可读的可执行页（XOM）或 `REGISTER` 时未驻留的代码页无法 nofault 复制，
   其中的直接分支源不被扫描。
3. 间接分支的目标寄存器若在 load 前被覆盖，GPR 门控看不到（§16.5 残余）。
4. 注册路径新增一次全进程代码扫描：测试进程 358 个可执行 VMA、6.0 MB 位图、
   约 240 ms；读取路径不变。
5. 每次读取仍一次同步异常；PTE 重装窗口、root 可见性、注册事务窗口不变；桥的
   store 仍是内核 nofault 普通写，不是硬件独占 store；`caller_count > 0` 的窗口
   内外读者差异仍是有意保留的 API 语义。

### 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --dobby-detection --repeats 24 --cycles 5
python .\kpms\urov-lab\tools\run_elimination_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-x-control --repeats 3 --cycles 1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-install --repeats 5 --cycles 1
python .\kpms\urov-lab\tools\run_multipage_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-install --repeats 3 --cycles 1
```

以下为 2.8.0 及更早的复核记录。

## 2.8.0：移除 SRC_FILE，统一 SRC_USER 整页

2026-11-07，同一 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB /
KernelPatch `0xc00`。被测构建：

```text
urov-y.kpm      82f50d464bf1d701135124ea55932655bcdf52060c01e498dd7eed38ac7d2adf
urovdetect.apk  5ebc98018feae8eb745117c880767f3090bc4e85475eee20699f59d07b05e573
```

`urov-y` 2.8.0 不再支持 `SRC_FILE`：

- `UROV_Y_PAGE_SRC_FILE` 仅作为保留位保留，`REGISTER` 返回 `EINVAL`；
- `page_read_file()`、`kernel_read(vm_file, ...)` 的页读取路径移除；
- `QUERY` 不再报告 `UROV_Y_CAP_SRC_FILE`；
- 所有镜像由 `SRC_USER` 提供，一个页描述符一次最多传一页（4 KiB/16 KiB），
  由模块在 `REGISTER`/`SET_PAGE` 时复制，之后不再解引用调用者缓冲区。

测试夹具相应调整：

- Dobby 夹具在 `DobbyHook` 前把目标页的**完整干净页**从 ELF 读入
  `mmap` 用户缓冲区，用 `SRC_USER(off=0, len=page_size)` 注册；不再依赖
  `vm_file`/`vm_pgoff`。
- 多页夹具的 `mp-srcfile` 改为 `mp-srcpage`：用改过首尾字节的整页镜像注册，
  验证呼叫窗口内读到 `image`、窗口外和注销后读到真实页；`MP_AUDIT` 中
  `SRC_FILE` 描述符仍作为非法输入被 `EINVAL` 拒绝。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×1 | PASS；活动阶段 `execute=0x1235`、`live=96964c4f`（等于文件）、`accepted_crc=24/24`、直接/NOP/间接探针均 0/24 | [dobby-detect-20261107-174813](results/dobby-detect-20261107-174813/summary.json) |
| 多页/LD1/跨页/SRC_USER 整页 | PASS，5 次运行；`mp-srcpage` 窗口内等于镜像、窗口外和注销后等于真实页 | [multipage-20261107-174756](results/multipage-20261107-174756/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-174837](results/crc-20261107-174837/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、443 条断言；`ELIM_BRIDGE` 三项均 0/32；`ELIM_TIMING mode=ap site_call_ns=271` | [eliminate-20261107-174908](results/eliminate-20261107-174908/summary.json) |

因此，2.8.0 的读取覆盖不再依赖“从 VMA 后备文件借用页”的路径；干净页由调用者
一次性提供，模块只保存一份内核镜像。`SRC_USER` 的 `fake_len=0` 或
`fake_len=page_size` 都表示整页，`fake_off` 仍可指定页内窗口。

以下为 2.7.0 及更早的复核记录；其中 2.7.0 的 Dobby/多页矩阵使用 `SRC_FILE`，
仅作历史对照。

## 2.7.0 第八轮：NOP 间隔与间接分支门控

2026-11-07，Pixel 6（oriole），Android 16，内核 `6.1.134-android14-11`，4 KiB 页，
KernelPatch `0xc00`。检测仍在 `untrusted_app` 域运行（`CapEff=0`、`Seccomp=2`），
root 只用于装卸 KPM。被测构建：

```text
urov-y.kpm      ff818b3ee62995b7353b30346ce7dca4b9601390f6edf2ce3ec9817b0c930d18
urovdetect.apk  e21607a7cd45c6061458eb3e4094c2c43e58f1a430980da4215e4572dbb8954d
```

2.6.0 的直接分支门控只检查“目标等于故障 load PC”的
`B/BL/CBZ/CBNZ/TBZ/TBNZ`。新增的 NOP 分支探针把目标落在 load 前的 `NOP`
上：

```asm
clrex
b 1f
ldxr x9, [x1]        ; never executed
1: nop
ldrb w10, [x0]       ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]    ; Rt preset to [x1]
```

2.6.0 的 `uy_llsc_prepare()` 允许 `LDXR` 与 load 之间有 0–3 个 NOP，但
`uy_llsc_skipped()` 只扫描目标等于 load 的分支，因此该形状得到伪造的 `STXR`
成功（报告中的 480/480 命中）。2.7.0 新增：

1. **整页直接分支门控**：分块扫描故障 load 所在页的
   `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ`，目标落在 `[LDXR+4, load]` 即不代写；
   覆盖 NOP 间隔和 ±256 字节外的同页分支。
2. **间接分支寄存器门控**：故障时若 `x0..x30` 任一值落在同一区间，说明
   `ADR/ADRP + BR`、literal + `BR`、`RET` 等路径可能跳过 `LDXR`，不代写。
3. **`B.cond` 解码**：补上 2.6.0 漏掉的直接条件分支编码。

门控只读，不新增 hook、syscall、PTE/VMA/代码字节改动、`ctl0` 字段或 ABI 变化。

### Dobby 24×1

同一 Dobby 夹具：执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP + SRC_FILE`
让 32 字节代码读取回到文件字节。文件 CRC32 为 `96964c4f`，Dobby 改码后的
内存 CRC 为 `cda907a7`。

| 阶段 | 执行返回值 | 内存 CRC32 | 直接分支探针 | NOP 分支探针 | 间接分支探针 | 采信 CRC |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 0/24 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `cda907a7`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **0/24** | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `cda907a7`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |

活动阶段 `bridge=0/24`、`spaced=0/24`、`unknown=0`，并行业务线程照常运行。
[原始数据](results/dobby-detect-20261107-171627/summary.json)

### 消除矩阵与 CRC 回归

`run_elimination_device.py --skip-x-control --repeats 3 --cycles 1`：11 次运行、
443 条断言全部 PASS。`w-active` 的直接、NOP、间接三项 `ELIM_BRIDGE` 均为
`verdict=0 trials=32 successes=0`；`ELIM_RESIDUAL mode=ap` 仍是
`site_file_word == site_live_word`、`site_cow_private=0`、
`Private_Dirty/Anonymous=0`；`ELIM_TIMING mode=ap site_call_ns=288`。
[消除数据](results/eliminate-20261107-171731/summary.json)

`run_crc_device.py --repeats 5 --cycles 1`：9 次运行 PASS，覆盖 `crc-brk`、
`crc-uxn`、`crc-ap`、`crc-ap-all`、`crc-ap-text`、`crc-ap-libc`、`crc-ap-big`，
其中 `crc-ap` 的 `direct=0x0c7da8a0`、`window=file=0xf50bcaf6`，
`crc-ap-all` 的 `direct=window=file`。
[CRC 数据](results/crc-20261107-171907/summary.json)

`run_multipage_device.py --skip-install --repeats 3 --cycles 1`：5 次运行 PASS
（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcfile`/`mp-audit`）。
[多页数据](results/multipage-20261107-172858/summary.json)

### 审计特征点现状（2.7.0 PAGE_AP）

| 审计条目 | 2.7.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻/NOP 间隔顺序到达由桥完成；直接分支到 load 或 NOP、同页更远直接分支、目标仍在 GPR 的间接分支均不代写，`MATCH=0`。 |
| 1b. 无预约 `STXR` 状态探针 | 直接分支到 load 的变体不代写；NOP 变体本轮从 480/480 命中降为 0/24；间接 `ADR + BR` 变体也为 0/24。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；代码字与 smaps 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具 `caller_count=0`，所有读者拿同一伪视图，`reader_diff=0`；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | 每次加载派生 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

### 残余（2.7.0）

1. 间接分支的目标寄存器在 load 前被覆盖时，门控看不到区间地址。
2. 从另一页跳入本页的直接分支不在单页扫描范围。
3. 保守误伤扩大：本页任意分支目标落在 `[LDXR+4, load]`，或任一 GPR 恰好
   持有该区间地址时，桥不生效、原生 `STXR` 失败。
4. 每次读取仍一次同步异常；AP 业务调用 288 ns、UXN 约 404 ns。PTE 重装窗口、
   root 可见性、注册事务窗口仍在。
5. 桥的 store 仍是内核 nofault 普通写，不是硬件独占 store。
6. `caller_count > 0` 的窗口内外读者差异仍是有意保留的 API 语义。

### 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --dobby-detection --repeats 24 --cycles 1
python .\kpms\urov-lab\tools\run_elimination_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-x-control --repeats 3 --cycles 1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --repeats 5 --cycles 1
```

以下为 2.6.0 及更早的复核记录。

## 2.6.0 读取完整性复核

2026-11-07，Pixel 6（oriole），Android 16，内核 `6.1.134-android14-11`，4 KiB 页，
KernelPatch `0xc00`。测试 App 在 `untrusted_app` 域运行（`CapEff=0`、`Seccomp=2`），
root 只用于装卸 KPM。被测构建：

```text
urov-y.kpm      32c0eaca05b36e748196406c2cf5066be88f436bf8e487376af424c44b342b9b
urovdetect.apk  494d942930710447d14cd1087a314b8d4bd11d9c46f4d5695453be44c01be681
```

## 2.6.0 普通 App 无密钥复核与会话防护

沿用上面同一份 `urov-y.kpm`，重新构建测试 APK，SHA-256 为
`f5cd6a707025cdac786646230144d4c7aa1c1da4f3a3469afc111c328bb55d68`。矩阵仅装卸
`urov-y`。检测在 `untrusted_app` 中运行，`CapEff=0`、`Seccomp=2`。模块密钥由
夹具用于建立和核对会话，检测函数只接收目标地址、同文件 RX 别名、fd 和偏移。

### 模式与检测信号

Y 用认证后的 `REGISTER` 把单一活动会话绑定到调用者 `mm`。注册为每页保存现场快照，
`SRC_USER` 合成指定窗口，`SRC_FILE` 从 VMA 后备文件取整页。异常处理解码读取指令，
在 `x30` 或最多 16 层 `x29` 帧链命中业务窗口时取覆盖镜像，窗口外取注册快照。
`caller_count=0` 时所有读者共用覆盖镜像。处理器的 GPR、FPSIMD、地址回写和 PC 按模拟
结果提交。重叠的映射操作会先恢复陷阱，缺页回调会重装活动页的陷阱。
[注册](urov_y_backend.c#L1700) · [读值选择](urov_y_backend.c#L1284) · [异常分流](urov_y_backend.c#L1398)

| 模式 | 内核做法 | 普通 App 证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 后把登记的读取指令换成 `BRK` | 比较已知读取点的指令字和同一发布 ELF 偏移，配合真实业务读者和独立读者的结果差异。`smaps` 的 COW 统计可佐证。 |
| `PAGE_UXN` | 置读取点页的 UXN，接管 EL0 取指异常 | 在已知的读取点页调用自有 `BTI C; RET` canary，用同文件别名配对检查异常返回导致的独占预约丢失。 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，接管 EL0 数据读异常，原页继续供取指 | 验证未建立独占预约的 `STXR` 是否被异常处理器代报成功。`SRC_FILE` 可同时骗过内存 CRC 与文件比对。 |

`PAGE_AP` 新探针执行 `CLREX → B`，跳过 `LDXR` 落在紧邻 `LDRB` 之前的 `NOP`。
原生 `STXR` 返回 1，线程私有 scratch 保持初值。2.6.0 的扫描只查分支是否直接指向
故障 `LDRB`，而向前匹配允许 `NOP`。当 `Rt` 预置为 scratch 的值时，内核桥接逻辑把
同值写回 scratch，令 `Ws=0` 并跳过 `STXR`。探针将该状态与同文件、同偏移的独立 RX
别名比较。每次需要 32 个三元组，前后对照的 `STXR` 均失败，目标组全部报成功且
scratch 不变才输出 `MATCH`。混合结果、对照异常或文件与映射身份变化为 `UNKNOWN`。
目标页只读，测试在 worker 运行。该状态信号的阳性不依赖延迟阈值或普通预约失败率。
[分支门控和桥](urov_y_backend.c#L1170) · [探针](native/urov_observe.c#L99) ·
[Arm A-profile 架构参考手册](https://developer.arm.com/documentation/ddi0487/latest/)

### 会话处置

- **完整性判定。** `MATCH` 和 `UNKNOWN` 的 CRC 结果不采信，普通业务照常执行。
  实际接入时持有目标映射与 fd 的生命周期，在 worker 低频检查稳定的自有 RX 页。
  `NO_MATCH` 仅覆盖本次采样路径和时段。当前 `PAGE_AP` 信号依赖该构建的 LL/SC 桥可用，
  不同内核的桥接能力、16 KiB 真机和生产流量需另验。
- **撤销活动覆盖。** 对已是 `MADV_NORMAL` 的自有专用测试页调用同一 advice。Y 的
  `madvise` 门控在原系统调用前恢复陷阱。夹具随后读到 Dobby 改码后的真实 CRC，
  函数仍返回 `0x1235`。该操作可能结束整个 `mm` 的会话，部署时只在受控页使用。
  [映射门控](urov_y_backend.c#L2083) · [恢复夹具](apps/urov-detect/dobby_crc_fixture.inc#L187)
- **阻止重新注册。** 夹具在恢复前安装 seccomp TSYNC。规则只对 ARM64 上匹配固定
  `UROVYLAB` magic、`REGISTER` 命令与 288 字节参数长度的调用返回 `EPERM`。该规则
  不需要密钥，覆盖同一入口的三种模式。它在系统调用表进入 Y hook 前生效。过滤器和
  `NoNewPrivs` 在进程内不可撤销，且 `NoNewPrivs` 约束 `execve` 的权限变化。上线需要在可能
  注册之前安装、确认 TSYNC 成功，并限于接受此进程策略的场合。已有会话需要单独恢复。
  [过滤器](apps/urov-detect/dobby_crc_fixture.inc#L139) · [seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html) ·
  [ARM64 系统调用顺序](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/kernel/syscall.c)

这些结果针对当前 KPM 和 ABI。能修改内核的一方也能改变异常处理、过滤器或 App 的结果，
因此普通 App 的本地证据只适用于受测实现和范围。

### 真机结果

Pixel 6，Android 16，4 KiB，Dobby 模式 13 个进程，其中活动进程 10 个，每阶段 48 次。

| 阶段 | 样本 | 执行返回 | 传统 CRC 通过 | 新探针 `MATCH` | `UNKNOWN` | 采信 CRC 通过 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | 624 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | 0 | 0 | 0 | 0 |
| 改码后 `PAGE_AP + SRC_FILE` | 480 | `0x1235` | 480 | 480 | 0 | 0 |
| `MADV_NORMAL` 恢复后 | 480 | `0x1235` | 0 | 0 | 0 | 0 |

- 活动阶段 15,360 个目标三元组全部报告未预约的 `STXR` 成功，两侧对照均失败。旧的
  相邻、间隔、直接跳到 `LDRB` 的三种探针活动阶段均为 0/480 命中。新探针活动阶段
  单次平均 3.07 ms，最大 3.23 ms。全 Dobby 矩阵的新探针最大 11.32 ms，UI 心跳
  最大间隔 21 ms，并行业务线程累计 5,633,920 次操作，0 错误。
- `MADV_NORMAL` 使活动会话 10/10 次转为 `inactive`。TSYNC 10/10 次安装成功，
  安装线程及安装前已存在的线程各 10/10 次收到 `EPERM`，会话保持空闲。
  受测进程的 `NoNewPrivs` 从 0 变为 1。
- 三模式和生命周期矩阵 17 次 App 运行通过。BRK 指令字对照 3/3 命中，UXN 活动取指
  144/144 命中，AP 的 NOP 分支探针 33/33 命中。AP 覆盖了 8 个 CPU、业务调用窗口外、
  伪造字节窗口外和等值覆盖。其他 UID 与空闲、撤销的 AP 对照均无命中。
- CRC 矩阵 9 次与多页矩阵 5 次均通过，覆盖业务窗口、libc/zlib、多页、向量和跨页读取。
  整轮测试前后 boot ID 一致，各矩阵的增量内核日志均未匹配异常，测试后模块列表为空。

原始数据见 [Dobby 与防护](results/dobby-detect-20261107-164723/summary.json) ·
[三种模式](results/eliminate-20261107-164811/summary.json) ·
[CRC](results/crc-20261107-164942/summary.json) ·
[多页](results/multipage-20261107-165000/summary.json)。

在 `kpms\urov-lab` 目录复跑时使用报告开头哈希匹配的 `out\urov-y.kpm`。

```powershell
.\apps\urov-detect\build.ps1
.\apps\urov-detect\build.ps1 -Observer
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python .\tools\run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 12 --cycles 3
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
python .\tools\run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 3 --cycles 1
```

以下为 2.6.0 发布时原探针的回归记录。

## 2.6.0 本轮改动

2.5.0 的相邻 LL/SC 桥只用寄存器状态（`Rt == [Xn]`）判断 `LDXR` 是否执行；
调用者先读 `[Xn]`、把 `Rt` 预置成同一值、再用直接分支跳过 `LDXR`，仍会得到一次
伪造的 `STXR` 成功（`ud_observe_unreserved_status()` 的 MATCH）。2.6.0 增加两道
门控：

1. **直接分支门控**。提交桥之前扫描故障 PC 两侧各 256 字节的代码页，解码
   `B/BL/CBZ/CBNZ/TBZ/TBNZ`；只要有一条分支的目标落在故障 load 上，说明该路径
   可以绕过 `LDXR` 进入读取，handler 不代写，PC 停在 `STXR` 上让它原生失败。
   扫描只读、有界；代码页本身被注册为陷阱页时改用注册快照。
2. **NOP 间隔桥**。`LDXR` 与 load 之间允许 0–3 个 `NOP`，消除
   `LDXR; NOP; LDRB; STXR` 的形状残余；寄存器、宽度、`Rt == [Xn]` 与“待写值
   等于内存”的约束不变。

本轮还实测并否决了“在 EL1 重放 `STXR` 探测本地独占监视器”的方案：在
KernelPatch 线性映射别名上重放同一宽度、同一值、同一物理地址的 `STXR`，真实
`LDXR` 之后仍稳定返回 1，说明数据异常进入 handler 前本地监视器已经不可用。
执行存证只能来自控制流，不能来自监视器。设计与残余见
[ELIMINATION_DESIGN.md §15](ELIMINATION_DESIGN.md#15-第七轮直接分支门控与-nop-间隔桥)。

## 审计特征点现状

| 审计条目 | 2.6.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻/`NOP` 间隔且顺序到达的序列由桥完成，`STXR` 成功，`MATCH=0`；直接分支落到 load 的伪造序列不桥。 |
| 1b. 无预约 `STXR` 状态探针 | `CLREX/B;LDXR` + 预置 `Rt` 被直接分支门控拒绝，目标 `STXR` 原生失败，`MATCH=0`、`stores=0`。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限，不适用；代码字与 `smaps` 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具使用 `caller_count=0`（所有读者拿同一伪视图），`reader_diff=0`；带调用窗口的 `crc-ap` 仍按设计只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | `urov-y` 使用每次加载派生的 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

## 2.6.0 Dobby 矩阵

`run_crc_device.py --dobby-detection --repeats 24 --cycles 5`，5 轮活动运行。
同一 APK、同一夹具：Dobby 把执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP +
SRC_FILE` 把 32 字节代码读取改回文件字节。

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 间隔探针 MATCH | 无预约状态 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 0/24 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `16215a4e`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **0/24** | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `16215a4e`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |

5 轮合计 120 次活动探针；每轮 `DOBBY_DETECT_STATUS hits=6528 failures=0`，
`bridge_trials=768`、`bridge_successes=0`、`spaced_failed=0`，并行业务线程
`ops=187136 errors=0`。活动阶段三种探针平均约 9.1 ms，最大约 9.3 ms。2.5.0 的
同一矩阵是 `bridge_match=24/24`、`accepted_crc=0/24`。[原始数据](results/dobby-detect-20261107-162507/summary.json)

## 2.6.0 消除矩阵与回归

`run_elimination_device.py --repeats 3 --cycles 1`：12 次运行全部 PASS，包含
`urov-x` 阳性对照、三种 Y 模式、不同 UID 观察和活动期卸载。

- `w-active` 的 `active_page`、`active_outside_window`、`active_after_set`、
  `active_equal_value` 均为 `exclusive_match=0`、`exclusive_clean=3`；
  `ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。
- 11 项 `ELIM_BRIDGE`（含 8 个 CPU）全部 `expected=0 verdict=0 trials=32
  successes=0`。
- `ELIM_RESIDUAL mode=ap`：`site_file_word == site_live_word`，
  `site_cow_private=0`，`Private_Dirty/Anonymous` 与基线一致；
  `ELIM_TIMING mode=ap site_call_ns=283`。

| 矩阵 | 结果 | 结果目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS，120/120 采信 CRC，三种探针 MATCH 0 | [dobby-detect-20261107-162507](results/dobby-detect-20261107-162507/summary.json) |
| 消除矩阵 3×1 | PASS，12 次运行 | [eliminate-20261107-162803](results/eliminate-20261107-162803/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-162542](results/crc-20261107-162542/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-162615](results/multipage-20261107-162615/summary.json) |

所有矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。

## 残余（2.6.0）

1. **间接分支**：`BR/BLR`、`ADR/ADRP + BR`、从字面量池取目标等间接控制流仍可
   跳过 `LDXR` 并让桥代写；直接分支门控只覆盖 ±256 字节内的六种直接编码。
2. **窗口外分支**：直接分支在故障 PC 的 ±256 字节之外或另一页时不参与判定。
3. **保守误伤**：`LDXR` 之前的条件分支若落到 load（条件不成立时本来会顺序执行
   `LDXR`），被视为“可能跳过”，桥不生效、原生 `STXR` 失败。
4. **桥的语义**：store 仍是内核 nofault 普通写，不是硬件独占 store；多线程争用
   同一 scratch、`STLXR` 的 release 顺序和 store 原子性不完全等价原生。
5. **时间**：每次桥接候选额外扫描两个 256 字节窗口；仍每次读取一次同步异常，
   时间特征与 2.5.0 同量级。PTE 重装窗口、root 可见性、注册事务窗口仍在。
6. **带业务调用窗口的模式**：窗口内读者拿伪值、窗口外读者拿重放快照，仍是有意
   保留的 API 语义。

## 2.6.0 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 24 --cycles 5
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 3 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 3 --cycles 1
```

以下 2.5.0 的实测记录作为历史保留；其中的“本轮改动”“残余”描述已被上面的
2.6.0 结果取代。

## 2.5.0 本轮改动（历史）

`APP_READ_INTEGRITY_AUDIT.md` 第 1 条检测针对 `PAGE_AP`：

```asm
ldxr x9, [x1]      ; thread-private scratch
ldrb w10, [x0]     ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]  ; native failure because ERET cleared the monitor
```

2.5.0 在 AP 数据异常返回路径中恢复相邻 LL/SC 桥，但只对满足以下条件的序列
生效：

1. 故障 PC 前一条是 `LDXR/LDAXR`，后一条是 `STXR/STLXR`，两者宽度、基址
   `Rn`、数据寄存器 `Rt` 一致；
2. `Rn != XZR`、`Rt != XZR`，`Rn` 自然对齐，中间 load 不写 `Rt`/`Rn`；
3. `Rt` 仍等于 `[Rn]`（`LDXR` 执行存证，按宽度零扩展）；
4. 待写值等于 `[Rn]` 当前内存，`copy_to_user_nofault` 能写回。

满足后，在 load 模拟成功之后由 handler 写回同一值、`Ws=0`、跳过 `STXR`；
`STLXR` 追加 `dmb ishst`。旧探针跳过 `LDXR` 时保留与 `[Rn]` 不同的 sentinel，
因此第 3 条校验失败，`STXR` 保持原生失败。下方无密钥复核使用相同值触发桥。实现见
[urov_y_backend.c](urov_y_backend.c) 的 `uy_llsc_prepare()`/`uy_llsc_commit()`，
设计与残余见 [ELIMINATION_DESIGN.md §14](ELIMINATION_DESIGN.md#14-第六轮相邻-llsc-桥的执行存证恢复)。

### 2.5.0 审计特征点现状

| 审计条目 | 2.5.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻且执行存证成立的序列由桥完成，`STXR` 成功，`MATCH=0`；非紧邻/成对/`Xt=XZR` 是残余。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限，不适用；代码字与 `smaps` 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具使用 `caller_count=0`（所有读者拿同一伪视图），`reader_diff=0`；带调用窗口的 `crc-ap` 仍按设计只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | `urov-y` 使用每次加载派生的 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

### 2.5.0 Dobby 矩阵（审计原场景）

`run_crc_device.py --dobby-detection --repeats 24 --cycles 5`，5 轮活动运行。
同一 APK、同一夹具：Dobby 把执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP +
SRC_FILE` 把 32 字节代码读取改回文件字节。

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |

5 轮合计 120 次活动探针、11,520 个被接受的目标三元组：`target_failed=0`、
`control_failed=0`、`unknown=0`、`accepted_crc=120/120`。每轮
`DOBBY_DETECT_STATUS hits=3264 failures=0`；单次探针平均约 2.9 ms，最大约 3.0 ms。
2.4.1 的同一矩阵是 `match=120/120`、`accepted_crc=0/120`。

### 2.5.0 消除矩阵与计数器

`run_elimination_device.py --repeats 6 --cycles 1`：12 次运行全部 PASS，包含
`urov-x` 阳性对照、三种 Y 模式、不同 UID 观察和活动期卸载。

- `w-active` 的 `active_page`、`active_outside_window`、`active_after_set`、
  `active_equal_value` 均为 `exclusive_match=0`、`exclusive_clean=6`；
  `ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。
- 8 个 CPU 的 store 探针全部 0 写入。
- `ELIM_RESIDUAL mode=ap`：`site_file_word == site_live_word`，
  `site_cow_private=0`，`Private_Dirty/Anonymous` 与基线一致。
- `ELIM_FEATURE business_reader=1`：窗口内的业务调用仍拿到伪值
  `0x8877665544332211`，窗口外 `direct == file`。

另以 `w-active --repeats 200` 启动，在活动期轮询 `ctl0 status`：

```text
mode=data-ap state=active armed=1 hits=2009 replays=61547 failures=0 llsc=42952 ...
```

`llsc=42,952` 证明桥确实在异常路径完成了 store，而不是让原生 `STXR` 偶然成功。

### 2.5.0 回归

| 矩阵 | 结果 | 结果目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS，120/120 采信 CRC，MATCH 0 | [dobby-detect-20261107-140230](results/dobby-detect-20261107-140230/summary.json) |
| 消除矩阵 6×1 | PASS，12 次运行 | [eliminate-20261107-140259](results/eliminate-20261107-140259/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-140417](results/crc-20261107-140417/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-140448](results/multipage-20261107-140448/summary.json) |

所有矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。
`crc-ap`（业务窗口）仍保持 `direct=backing/window=file`，`crc-ap-all` 则是
`direct=window=file`；说明桥没有改变窗口语义。

### 2.5.0 残余

1. 桥只覆盖紧邻三条指令；`LDXR; NOP; load; STXR`、跨基本块、函数调用、成对
   `LDXP/STXP` 仍会看到目标 `STXR` 失败。
2. 调用者先读 `[Rn]`、把 `Rt` 预置为同一值、再分支跳过 `LDXR`，仍可让桥代写；
   由于待写值等于内存，该路径只改变 `Ws`，不改变内存。现有
   `ud_observe_unreserved_store` 探针不预置该值，保持 `match=0`、`stores=0`。
3. `Xt=XZR`、非自然对齐、不可写 `[Rn]` 不桥，按原生路径失败。
4. 仍是每次读取一次同步异常；时间特征与 2.4.1 同量级。PTE 重装窗口、root
   可见性、注册事务窗口仍在。
5. 带业务调用窗口的模式仍是有意保留的 API 语义：窗口内读者拿伪值，窗口外
   读者拿重放快照。Dobby 场景使用 `caller_count=0`，因此不存在读者差异。

### 2.5.0 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 24 --cycles 5
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 6 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 3 --cycles 1
```

## 2.5.0 普通 App 无密钥复核（历史）

> 2.6.0 复测：同一夹具的 `ud_observe_unreserved_status()` 在 24×5 活动矩阵中
> `bridge_match=0/24`、`bridge_successes=0`（3,840 个目标试验），
> `ud_observe_spaced_exclusive()` 为 `spaced_match=0/24`；2.5.0 记录的
> “无预约成功命中”和“间隔探针命中”不再出现。以下 2.5.0 数据保留作对照。

以下复核沿用报告开头所列的 2.5.0 KPM，使用重新构建的检测 APK
`5de21da422674de76b08fbffed6876442ff0f078fad77517683ba5ac34f78748`。
前文 `MATCH=0` 对应旧 APK 的相邻独占探针。新旧探针在同一夹具中并列运行。

### 检测依据

- **`PAGE_AP` 的主信号是无预约的 `STXR` 报成功。** 把线程私有栈槽的初值预置到
  `Rt`，用 `CLREX` 清预约，分支跳过紧挨目标 `LDRB` 的 `LDXR`。原生执行时
  `STXR` 报失败。目标页触发数据权限异常时，2.5.0 桥按故障 PC 前后各一条指令和
  `Rt == [Rn]` 判断并完成同值写回，令状态为 0。探针比较状态并核对栈槽仍为初值。
  每次先后读取同文件、同偏移的独立 RX 别名作为对照，32 个三元组均符合才判定命中。
  [桥实现](urov_y_backend.c#L1126) · [探针](native/urov_observe.c#L178) ·
  [Arm 指令手册](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
- **间隔独占探针用于交叉确认。** `LDXR → NOP → LDRB → STXR` 避开相邻匹配。
  `ERET` 清掉预约，目标组反复失败且前后对照成功才判定异常。每次要求三轮各 32 组
  有效对照。普通 load、抢占和调试均可能使预约丢失，混合结果与异常对照归为
  `UNKNOWN`，该信号只能说明读路径异常。2.4.1 或缺少可用桥接能力的构建也可以
  用独占失败检测。 [间隔探针](native/urov_observe.c#L309) ·
  [Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)
- **按陷阱类型选证据。** 基础版和 X 在目标页制造数据读异常，X 按登记的读指令
  PC 选择伪值。Y 的 `SITE_BRK` 对读取指令做 COW 后改成 BRK，可核对该指令字与
  发布 ELF。`PAGE_UXN` 在读者页禁取指，可在已知的同页自有 canary 上配对取指。
  对 PC 或调用窗口过滤的会话，可用真实业务读者和独立读者交叉比对。所有读者共用
  `SRC_FILE` 镜像时，两读者和文件一致也可能掩盖改码。
  [基础版](urov_backend.c#L404) · [X](urov_x_backend.c#L414) · [Y](urov_y_backend.c#L1349)

探针只接收目标地址、对照映射、文件描述符和偏移。两侧都核对映射权限、设备号、
inode 和文件偏移，并复核映射与文件身份。读目标页用普通 `LDRB`，写入限于
线程私有 scratch。测试夹具通过控制 ABI 注册并确认真值。部署宜将探针放在
worker，低频抽查生命周期固定的自有 RX 页，保留 `MATCH / NO_MATCH / UNKNOWN`。
阴性只覆盖所采样的页与时段。计时和 `smaps` 可用于诊断。旧设备上的内核辅助读
有权限拒绝及阻塞记录。 [辅助读复核](DETECTION_RESULTS.md#42-内核辅助读取不能笼统视为安全)

### Dobby 真机复测

Pixel 6，Android 16，4 KiB，`untrusted_app`、`CapEff=0`、`Seccomp=2`。
48 次 × 10 个活动进程，另测未装载、加载空闲和卸载后。测试在 Dobby 所改页的
`+64` 字节采样。文件 CRC32 为 `96964c4f`。

| 阶段 | 样本 | 执行返回值 | 内存 CRC32 | 相邻探针命中 | 间隔探针命中 | 无预约成功命中 | 采信 CRC |
| --- | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | `96964c4f` | 0 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | `7956f12b` | 0 | 0 | 0 | 0 |
| 改码并开启 `PAGE_AP + SRC_FILE` | 480 | `0x1235` | `96964c4f` | 0 | 480 | 480 | 0 |
| 触发恢复后 | 480 | `0x1235` | `7956f12b` | 0 | 0 | 0 | 0 |

无预约状态探针在 1,728 次对照中为 0 命中、0 未知。活动阶段共 15,360 组
无预约三元组，目标 `STXR` 均报告成功，两侧对照均失败。间隔探针活动阶段接受了
46,080 组，目标 `STXR` 均失败。有 4 次对照的合并结果为 `UNKNOWN`。
活动阶段三种探针合计平均 9.16 ms，最大 10.23 ms。全矩阵 worker 上的最大单次
耗时为 72.81 ms，UI 心跳最大间隔 24 ms。并行业务线程累计 4,251,520 次迭代、
0 错误。 [Dobby 原始数据](results/dobby-detect-20261107-143202/summary.json)

### 模式和回归

- 模式与生命周期矩阵 15 次 App 运行全部通过。无预约状态探针仅在 `PAGE_AP`
  活动页上命中，业务窗口外的重放和等值覆盖也能观测到该信号。每个 CPU 各做两轮，
  8 个 CPU 共 512 组无预约三元组全部命中。该矩阵单次无预约状态探针耗时中位数
  3.05 ms，最大 18.12 ms。 [模式和逐 CPU 数据](results/eliminate-20261107-143253/summary.json)
- 原 CRC 矩阵 9 项和多页、向量、跨页矩阵 5 项均通过。测试后模块列表为空，
  boot ID 与测试前相同，增量内核日志无命中的异常记录。
  [CRC 回归](results/crc-20261107-143607/summary.json) ·
  [多页回归](results/multipage-20261107-143416/summary.json)

### 处置和恢复

- **完整性证据。** 测试 App 将 `MATCH` 和 `UNKNOWN` 排除在可采信 CRC 之外，
  Dobby payload 及并行业务线程照常运行。生产侧可仅对高风险操作使用服务端验证的
  Play Integrity 请求绑定或硬件密钥证明，普通业务保留原流程。设备证明提供
  启动和设备可信度信号，页级结果仍由独立观测给出。
  [Play Integrity 请求绑定](https://developer.android.com/google/play/integrity/standard) ·
  [硬件证明校验](https://developer.android.com/privacy-and-security/security-key-attestation)
- **终止当前覆盖。** 夹具在自有、页对齐的 RX 测试页调用同权限
  `mprotect(PROT_READ | PROT_EXEC)`。Y 的重叠映射门控在系统调用之前恢复陷阱，
  10/10 次成功转为 `inactive`，CRC 再次读到 Dobby 改码，执行返回值仍为 `0x1235`。
  这是当前实现的一次会话恢复，仍允许重新注册。对任意业务页调用映射变更可能影响
  VMA、BTI 策略及并发，因此将主动恢复留在受控夹具。
  [映射门控](urov_y_backend.c#L2084)
- **内核信任。** 具有内核执行权的一方能控制页表、异常返回以及 App 的判定。
  可管理设备使用锁定引导加载程序和可信签名镜像约束启动链，服务端按硬件证明和
  操作风险授权。这里的设备证明未接入真机测试。检测率与开销仅涵盖当前设备和
  构建，其他 SoC、16 KiB 设备和生产流量需要各自的控制矩阵。
  [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot) ·
  [启动状态证明字段](https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields)

### 复跑本次矩阵

```powershell
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 48 --cycles 10
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 8 --cycles 2
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 3 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 5 --cycles 1
```
