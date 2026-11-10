# 普通 App 检测 UROV-Y 2.27.0 的读值覆盖

在当前 `urov-y` 2.27.0 上，普通 ARM64 App 可以检测**自己地址空间内已采样的活跃覆盖**。`PAGE_AP` 全调用者模式下，数据读返回发布文件的字节，取指仍执行改码后的内容。新探针利用模块代做的一次无预约存储来确认接管，检测输入只有 App 自有地址和参考文件，密钥与 `prctl` 只用于试验夹具的登记和真值校验。空载、其他 `mm` 和未采样位置仍属未验证。 [模块版本](urov_y.c#L19) · [探针接口](native/urov_observe.h#L363)

## 模块如何产生两个视图

模块装载时解析内核符号及页表几何，从运行内核或匹配的外部 BTF 得到 MM、VMA 等结构的偏移，并挂接异常与系统调用路径。`REGISTER` 经 ABI v8 控制入口检查派生 option、magic、请求布局和 MAC。模块持有调用者的 `mm`，当前全局会话存储每页活字节的初始快照和叠入请求字节后的镜像。文件后备、可读可执行、当前不可写是目标 VMA 的必要条件。私有 `.text` 可以登记，共享映射还需恰好一页且无 `VM_MAYWRITE`。读取时通过 `x30` 和最多 16 层 `x29` 帧链匹配调用窗口，窗口外回放快照。全调用者模式则对登记范围内所有受支持的读者提供镜像。 [内核解析](urov_y_backend.c#L6376) · [控制入口](urov_y_backend.c#L5062) · [注册](urov_y_backend.c#L4650) · [VMA 限制](urov_y_backend.c#L1312) · [调用窗口](urov_y_backend.c#L1720) · [多页读](urov_y_backend.c#L1137)

| 模式 | 接管位置 | App 可用证据 |
| --- | --- | --- |
| `SITE_BRK` | 对登记的读取指令做私有 COW，把该指令换成 `BRK`。命中会话、PC 和立即数时模拟原 load。 | 在构建时选定的读取点，发布 ELF 中为预期的 load，活指令却变成 `BRK`。调试断点也可能改变指令字，归因需结合部署环境。 |
| `PAGE_UXN` | 置读取点所在页的 UXN 位，在取指异常中模拟登记的 load 和支持的控制流。 | 在同页放置只含 `BTI C; RET` 的自有 canary。校验字节后比较两侧参考执行与目标执行的独占预约。缺少安全 canary 时跳过取指探测。 |
| `PAGE_AP` | 清被读目标页叶 PTE 的 `AP[1]`，EL0 数据读进入 `do_mem_abort`，从镜像或快照重建寄存器、回写地址与 PC。原指令仍可取指，VMA 保持 RX。 | 已知目标页使用下述无预约存储探针。窗口模式还可比较业务读点和独立标量读点的稳定字节。 |

[BRK 和取指异常处理](urov_y_backend.c#L4155) · [AP 数据异常处理](urov_y_backend.c#L4320) · [已知读点和 canary 的测试](apps/urov-detect/read_defense_fixture.inc#L256)

`process_vm_readv`、`__access_remote_vm` 以及 GUP/PIN 的相关钩子也可改写注册范围的内核代读视图，映射与缺页钩子能重新布防。`maps` 权限、内存与文件 CRC 相等、不同 load 指令和同一设备上另一条内核代读路径都只能提供各自的局部观察。重新映射同一文件能获得发布参考字节。原 RX 映射若已私有 COW，参考页与它是两个视图。 [代读钩子](urov_y_backend.c#L6550) · [缺页与生命周期钩子](urov_y_backend.c#L6593) · [现有读路径边界](ELIMINATION_2_27_DESIGN.md#4-是否能让普通-app-通过指定指令读到真值)

## PAGE_AP 的无预约存储探针

App 在线程私有栈上初始化并对齐一个哨兵字，预置另一个不同的待写值。真实控制流执行 `CLREX`，通过 `ADR; BR` 落在 `BTI J`，跳过文本里的 `LDXR`。随后用普通 `LDRB` 读目标字节，并对私有哨兵执行 `STXR`。原生执行中，没有加载建立预约，`STXR` 必须报告失败且哨兵保持初值。抢占和中断可以使有效预约消失，无法为这段序列补上预约。 [Arm 独占监视器](https://support.arm.com/documentation/110478/0100/Exclusives/Exclusive-monitors)

```asm
clrex
adr     x9, 1f
br      x9
.rept 64
nop
.endr
ldxr    xValue, [xScratch]
1: bti  j
ldrb    wByte, [xTarget]
stxr    wStatus, xValue, [xScratch]
```

在覆盖页读异常中，模块向后找到未执行的 `LDXR`。直接分支目标图看不到 `BR` 的边，入口检查从 `LDXR` 前向后最多读 64 条指令。64 个不可达 `NOP` 使 `BR` 成为第 65 条前驱，故障处理把死代码当作已执行，软件写入哨兵并返回 `STXR` 成功。短对照使用同一语义但紧邻 `BR` 和 `LDXR`，入口检查能拒绝代写。已核对最终 APK 的 ARM64 反汇编。 [入口检查和写回](urov_y_backend.c#L2732) · [App 指令序列](native/urov_observe.c#L1049)

一次判定要求短序列符合原生行为，并且长序列 32 组的目标均同时返回成功状态和新哨兵值。每组在目标前后执行同形状的 `r--` 同文件同偏移对照，两次对照均须返回失败、保留哨兵并读到文件字节。探针前后复核映射权限、设备号、inode、文件偏移及文件元数据。输入生命周期由调用方持有，映射失配或试验不一致输出 `UNKNOWN`。夹具对 `EAGAIN` 最多重试两次。探针只读目标，所有存储限于线程私有哨兵。 [采样实现](native/urov_observe.c#L1147) · [App 判据](apps/urov-detect/keyless225_fixture.inc#L55)

此处观测的是独占存储副作用，`LDRB` 返回值仍由该覆盖的镜像路径提供。入口回查边界和软件代写行为均与当前版本相关。代码分支图未完成、代写路径放弃、覆盖在抽样外或模块更改桥接策略时，探针可能没有证据。单一设备上的重复样本仅说明本矩阵中的表现。 [分支图门控](urov_y_backend.c#L2413) · [软件代写](urov_y_backend.c#L2882)

## 接入和阻断策略

1. 为自有关键 native 读点及目标页记录 ELF 构建标识、映射文件偏移和发布字节摘要。采样稳定的文件后备 RX 页，持有已打开的 fd 和对应库生命周期，避开重定位、合法热补丁、JIT 和并发卸载。SO 直接从 APK 映射时，偏移以实际后备文件为基准。对已知读点才做指令字和取指探测。业务读者和独立读者比较时保留原调用上下文，并确认两者本应读取同一字节。 [读者比较实现](native/urov_detect.c#L187)
2. 在后台按页低频取样，用带证据类别的结果记录 `TRAP`、`CHANGED`、`UNKNOWN` 或 `NO_EVIDENCE`。长短探针差分、读点 `BRK`、取指预约丢失和稳定的读视图分裂分别保留。仅文件与活页不同记 `CHANGED`，合法改码也可产生这个结果。对照失败和缺少可验证条件记 `UNKNOWN`。新测试模式将活内存 CRC 始终作为诊断数据，匹配值不进入完整性授权，普通业务路径继续执行。 [判定与日志](apps/urov-detect/keyless225_fixture.inc#L5)
3. 将**发布参考值**从 RX 活页读取中分离。对签名发布摘要，用保留的常规文件 fd `pread` 到普通数据缓冲区，或使用独立 `PROT_READ` 映射计算摘要。当前模块要求目标同时具备 `VM_READ`、`VM_EXEC`，因此 `r--` 参考映射以及独立 `--x` 执行别名均不能作为数据覆盖目标登记。执行别名只用于像测试叶函数这样位置无关、无需重定位和外部状态的受控代码。`SITE_BRK` 和 `PAGE_UXN` 的**读点**校验走另一条路径，任意 `--x` 读点仍要单独评估。 [数据目标校验](urov_y_backend.c#L1312) · [读点校验](urov_y_backend.c#L1264) · [别名拒绝登记试验](apps/urov-detect/keyless225_fixture.inc#L318)
4. 解除已有活 RX 覆盖需要可信管理侧撤销或卸载。普通 App 的隔离由同一内核实施，保护参考路径与拒绝采信 CRC 能阻断伪值进入应用决策。设备级防止 KPM 加载依赖受控内核和启动信任链。 [Android 应用沙箱](https://source.android.com/docs/security/app-sandbox) · [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot)

## 真机矩阵

2026-11-10，Pixel 6，Android 16，ARM64，4 KiB 页，内核 `6.1.134-android14-11`，KernelPatch `c00`。App 为 UID `10284` 的 `untrusted_app`，`CapEff=0`，`Seccomp=2`，SELinux Enforcing。ADB 管理模块，App 夹具用临时模块密钥建立和注销会话。KPM SHA-256 为 `ffe75cf7ac9c82e042c1b3488470ef773937de6a6c4d4941bc250fcf015324d4`。 [完整矩阵](results/keyless227-detect-20261110-231905/summary.json)

六种模式配置各运行 5 个新 App 进程，覆盖按调用窗口和全调用者两种范围。每阶段记录 32 次结果，`SITE_BRK` 指令和 `PAGE_UXN` 取指证据每阶段测一次，阶段内的读者及 `PAGE_AP` 探针重复采样。另起进程验证无模块、模块空载、卸载后。Dobby 仅在夹具中改写自有测试函数，使原入口从 `0x1234` 变为 `0x1235`。 [矩阵断言](tools/run_crc_device.py#L164)

| 阶段 | 接管判定 | 其他结果 |
| --- | ---: | --- |
| 原始代码 | 0 / 1,056 | 1,056 次无接管证据 |
| 仅 Dobby 改码 | 0 / 1,056 | 1,056 次 `CHANGED` |
| 活跃会话，镜像字节与原代码相同 | 960 / 960 | 接管证据与字节变化分别判断 |
| Dobby 改码，业务读取被覆盖 | 960 / 960 | 0 次采信活内存 CRC |
| 已注销，保留 Dobby 改码 | 0 / 960 | 960 次 `CHANGED` |

- `PAGE_AP` 两种范围合计 640/640 次长序列判定，观察到 20,480 次无预约哨兵写入。短序列 159,744 次目标试验，写入 0 次。最难的 `ap-all` 改码覆盖阶段 160/160 次命中。文件、独立读取和业务读取 CRC32 均为 `96964c4f`，读者差异为 0，活入口执行 `0x1235`。 [AP-all 原始日志](results/keyless227-detect-20261110-231905/keyless227-detect-ap-all-1-14048.log)
- 156 个阶段的 `r--` 参考值均与文件相符，`--x` 叶函数均返回 `0x1234`。撤销原会话后对两种映射各尝试登记 30 次，全部返回 `EINVAL`。60 个活动阶段的会话 ID、代际、模式和登记计数稳定，模块异常失败计数为 0。33 次错误偏移对照在采样前即为 `UNKNOWN`。 [完整矩阵](results/keyless227-detect-20261110-231905/summary.json)
- 33 次 App 运行期间，并行业务夹具完成 10,539,648 次运算、0 错误。含元数据检查、读者比较及短长探针的单次后台样本平均 9.72 ms，实测最大 33.71 ms。UI 心跳最大间隔 21 ms。测试前后 boot ID 一致，KPM 清单为空，新增内核日志无 BUG、WARNING、Oops 或 panic。 [完整矩阵](results/keyless227-detect-20261110-231905/summary.json) · [内核增量日志](results/keyless227-detect-20261110-231905/kernel-new.log)
- 同一 APK 回归通过旧探针矩阵及七种 CRC 模式。旧探针在 `ap-all` 仍为 0/8，新探针的命中来自此次验证的入口回查边界。设备覆盖目前为单台 Pixel 6，16 KiB、其他 SoC 和生产负载需另行验收。 [旧探针回归](results/keyless227-audit-20261110-232236/summary.json) · [CRC 回归](results/crc-20261110-232256/summary.json)

## 复现

在仓库根目录运行，`$Serial` 为测试设备序列号，`$KpKey` 为 KernelPatch 管理密钥。设备起始 KPM 清单需为空。脚本安装测试 APK、使用临时模块密钥运行对照与活动矩阵，结束时卸载本次模块并检查 boot ID 与内核增量日志。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v227-detect --repeats 32 --cycles 5
```

## 后续：2.28.0 的收口

[ELIMINATION_2_28_DESIGN.md](ELIMINATION_2_28_DESIGN.md) 记录了对本文
64 条填充探针的修复：[`uy_llsc_entry_skipped()`](urov_y_backend.c) 不再
在 64 条处停下，而是走到 LDXR 所在可执行 VMA 的起点或 16,384 条预算，
预算耗尽时拒绝。同设备、同夹具的
[`--keyless-v228-detect`](KEYLESS_2_28_AUDIT.md) 矩阵中，`ap-all` 的
`match`、`writes` 在全部 5 个阶段均为 0，生产 CRC 仍是
`file=direct=window=f50bcaf6`、`execute=1235`。

同文档 §5 给出了剩余第 6、8、12 项的构造性不可判定证明：同步故障、
跨 PE 写和跨函数/循环间接进入都不在异常现场，也没有非破坏性监视器
查询；在这些类上做到“与原生完全一致”需要硬件 trace 或 hypervisor 级
监视器虚拟化。2.28.0 因此把假成功收敛到这三类，把其余差异收敛到有界
假失败。
