# 普通 App 对 UROV-Y 2.26.0 的无密钥审计

即使 `PAGE_AP` 全调用者模式让两路活内存读取和安装文件的 CRC 完全相同，普通 ARM64 App 仍可
观察到模块的独占存储桥接。在本机，最强的证据是 **`CLREX` 后根本没有执行 `LDXR`，`STXR` 却
报告成功且写入了预置哨兵**。另一条短探针观察只在目标页上丢失的预约。两条都不用计时阈值、
模块密钥或 `prctl`，只对被测页做 `LDRB`，仅写当前线程的私有测试字。

## 源码与 2.26 设计复核

[`urov_y.c`](urov_y.c#L19) 声明版本 2.26.0。后端解析内核符号和匹配的 BTF 布局，设置异常、内核代读和
映射生命周期相关的 hook。ABI v8 的 `REGISTER` 由密钥派生的 option、magic 和 MAC 验证，绑定
调用者当前的 `mm`；目标须在文件后备、可读可执行、当前不可写的合格 VMA 中。它复制活页到
`snapshot`，在另一份 `image` 中叠入指定字节；`PAGE_AP` 可登记多页。
[控制入口](urov_y_backend.c#L4960) · [目标检查](urov_y_backend.c#L1294) ·
[快照与登记](urov_y_backend.c#L4550)

| 模式 | 实际接管点 | 普通 App 可观测信号 |
| --- | --- | --- |
| `SITE_BRK` | 把指定的读取指令换成 `BRK`，在异常处理里模拟原 load | 对比已知读点与文件中的指令字；检查是否为 A64 `BRK`；保留原上下文的读者与独立读者可不同 |
| `PAGE_UXN` | 给读点所在页设置 UXN，取指异常中模拟登记的 load 和有限的控制流指令 | 对已知读点页使用自有、核对过字节的 `BTI C; RET` canary，对比独占预约是否丢失；没有安全 canary 则不试跑未知代码 |
| `PAGE_AP` | 清**被读目标页**叶 PTE 的 `AP[1]`，保留原指令执行与 VMA 权限标志 | 数据 load 经 EL1 权限异常，执行与数据读可分离；普通 CRC 和 `/proc/self/maps` 可无差异，使用下述独占探针 |

[`read_range()`](urov_y_backend.c#L1119) 逐页组合读取；调用窗口可用 `x30` 或有限的 `x29` 帧链命中。
无窗口时适用所有调用者；窗口外的重放视图由登记参数决定。因此选择性覆盖可比较业务读者和独立
读者，全调用者模式二者可能一致。`process_vm_readv` 的 pin/拷贝、`/proc/*/mem`/ptrace 对应的
`access_remote_vm`、vmsplice 的 GUP 路径也有覆盖逻辑；fork 子映射及页权限恢复有专门处理。
把 CRC 换成 `memcpy`、向量 load 或换读 API，不能据此证明拿到了真实活页。
[AP 布防](urov_y_backend.c#L1426) · [调用范围](urov_y_backend.c#L1702) ·
[内核代读](urov_y_backend.c#L4988) · [缺页后恢复](urov_y_backend.c#L4334)

[2.26 设计](ELIMINATION_2_26_DESIGN.md) 中，异常时的 `pt_regs` 是回推起点；`uy_pre_step()` 对已
退休指令的 GPR/SP 写入求精确逆，无法回推就标为未知。`ADD #0` 可逆，旧探针失效。直接分支
目标图替代了根据 GPR 中的地址判断间接跳转的启发式；回溯上限增到 16,384 条，`MRS`、缓存维护
等编码分类也补全。这个修复并没有恢复硬件监视器。只有回溯、地址/宽度检查和前向模拟通过时，
后端才会代写 `STXR`、写回状态和 PC；前向模拟处理不了时还可尝试有界单步。
[预窗口模型](urov_y_prewin.h#L92) · [直接分支检查](urov_y_backend.c#L2395) ·
[计划/提交](urov_y_backend.c#L2703) · [AP 异常分支](urov_y_backend.c#L4212)

## 两条针对 PAGE_AP 的探针

下面是 APK 反汇编中关键指令的等价写法。`x0` 是本次采样地址，`x1` 是自然对齐的私有 scratch，
真实代码不接触业务锁、其他线程状态或目标页的写权限。

```asm
// 1. 实际保持基址，但掩码对任意输入不可逆
ldxr x8, [x1]
and  x1, x1, #0xfffffffffffffff8
ldrb w10, [x0]
stxr w11, x8, [x1]

// 2. x8 已预置哨兵；跳过 LDXR，硬件没有预约
clrex
adr  x9, 1f
br   x9
ldxr x8, [x1]
1: bti j
ldrb w10, [x0]
stxr w11, x8, [x1]
```

1. **对齐掩码。** `AND` 不改变这次预约地址，但不能对任意输入反推出低三位。2.26 的值证明放弃，
   `LDRB` 的异常返回清掉硬件预约，目标 `STXR` 因而失败。同线程的普通对照、以及在同一目标上
   把 `AND` 换成可逆 `ADD #0` 的对照都可以成功。ARM 允许普通独占存储失败，单次失败不作证据。
2. **无预约却写入。** `CLREX` 清预约，`BR` 直接跳到 `BTI J`，实际没有执行 `LDXR`。直接分支图
   没有这条边；回溯却在 `BTI J` 前看到死代码 `LDXR`，因此可能把哨兵当成一次合法的 `STXR`
   写入。硬件正常路径必须返回失败且保留初值；目标同时返回成功和改变 scratch 才算命中。
   这验证了设计 §5 的间接进入残余，也给出了 §4/§7 中“原生失败、模块成功”结论的反例。它不
   依赖调度耗时、同步故障信号处理器、跨线程写或特殊 CPU 扩展。

预约机制见 [Arm A64 同步原语文档 §3](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)。
实现见 [对齐掩码探针](native/urov_observe.c#L550)、[无预约存储探针](native/urov_observe.c#L1237)
及 [App 判据](apps/urov-detect/keyless225_fixture.inc#L17)。

采样前后用 `/proc/self/maps` 和 `fstat` 核对目标与 `r--` 别名的映射权限、文件设备号、inode、精确
偏移和文件元数据；调用方须持有两处映射和 fd 的生命周期。掩码探针先预热，两条探针都做
「对照 → 目标 → 对照」。
掩码探针要求 3 轮各 32 个有效三元组，目标全失败且两边对照成功；使用 `ADD` 对照确认同一目标的
桥接在可逆形状下正常。无预约探针要求 32 组目标都返回成功并写入哨兵，两边对照均失败且未写入。
混合结果、对照不可靠、映射或内容不稳定均不作阳性；可重试，仍不确定则返回 `UNKNOWN`。

`TRAP` 表示所采样读路径有接管证据。`CHANGED` 表示稳定的字节变化，单独不归因为该 KPM。
`NO_MATCH` 只覆盖本次的地址、路径和时间。分支图不完整时桥可直接放弃，其他 CPU 也可能令
对照不稳定；遇到这些情况应保留 `UNKNOWN`。空载模块、其他 `mm`、未登记或未采样的页不在覆盖
范围内。`BRK` 或取指异常还可能来自合法调试，生产决策应只报告观察到的现象。只在后台低频抽样
自有、稳定、可读的原生 `.text` 页，避免 JIT、重定位、热更新和正在卸载的库。

## 阻止假结果被采用

1. **已有 RX 映射：拦完整性结论。** 遇到 `TRAP`、`CHANGED` 或 `UNKNOWN`，即使 CRC 与文件相等，
   也不把这次活页检查当成可信通过。`UNKNOWN` 延后复核。普通业务照常运行；如需校验发布产物，
   用持有的正规 fd `pread` 到非执行数据缓冲区，与可信签名清单比对。文件通过只说明发布文件内容，
   不说明已经运行的那份 RX 页没有被修改。
2. **新建独立校验路径：避免成为本版的覆盖目标。** 文件数据使用 `PROT_READ` 非执行别名；如需调用
   自包含的固定例程，从同一可信文件用 `mmap(..., PROT_EXEC, MAP_PRIVATE, fd, offset)` 另建执行别名。
   执行例程不能依赖重定位、页内数据读取或外部符号。
   两者分别缺 `VM_EXEC`、`VM_READ`，不满足 `validate_target_vma()`。这是**目标页登记限制**；不能
   据此声称任意 `--xp` 页都不能作为 `SITE_BRK`/`PAGE_UXN` 的读指令站点。该方案不依赖硬件 XOM，
   见 [AOSP 的 XOM 支持说明](https://source.android.com/docs/security/test/execute-only-memory)。
3. **实际撤销现有覆盖需可信管理侧。** 普通 App 不能安全地强制解除已生效的内核会话并继续采信原
   活页。现有保护变更可能触发重布防，`mprotect`、fork、强制异常或丢弃原页还可能影响正常业务。
   受管设备上由管理侧撤销会话或卸载模块。对于可任意改写内核的对手，不能从普通 App 内部证明
   任意活页完整性；[Android 应用沙箱](https://source.android.com/docs/security/app-sandbox) 本身由内核实施。

## 真机结果（2026-11-10）

Pixel 6 / Android 16 / ARM64 / 4 KiB，内核 `6.1.134-android14-11`，KernelPatch `c00`，
SELinux Enforcing。APK 实际运行在 `untrusted_app`，`CapEff=0`、`Seccomp=2`。ADB 只管理模块并记录
设备真值；测试夹具使用临时模块密钥登记、查状态和清理。探针及其判据不接收密钥或会话状态，
不会调用控制通道。被测 KPM 未改动，SHA-256 与设计文档相同：
`a6c792563aaa388db2002e46b627b0206aed6fa42feaf1013d6a0fb7d7d38bcc`。

| 阶段 | 读接管命中 | 其它结果 |
| --- | ---: | --- |
| 干净（包括无模块、模块空载和卸载后） | 0 / 672 | 672 次采样未发现异常 |
| 仅 Dobby 改码（包括撤销覆盖后） | 0 / 1,248 | 1,248 次判为 `CHANGED` |
| 已登记，镜像与原字节相同 | 576 / 576 | 有读接管，字节值未改变 |
| Dobby 改码 + 读值覆盖 | 576 / 576 | 六种配置各 96 次，全部拒绝采信活内存 CRC |

`PAGE_AP` 的两种调用范围中，`AND` 和无预约探针分别命中 384/384；共观察到 36,864 次目标
预约丢失和 12,288 次无预约写入。最难的 `ap-all` 改码覆盖阶段，96 次的文件/直接读/业务读
CRC32 同为 `96964c4f`，两个读者没有分裂，原 RX 入口仍执行改码后的 `0x1235`；检测全部拦下，
独立数据别名仍与文件匹配，执行别名返回 `0x1234`。旧 `ADD #0` 和原六个 2.26 探针的回归
也通过：它们在同一 KPM 的 `ap-all` 阶段没有发现异常，不能替代新探针。

36 个活动阶段均保持活动、generation 和登记形状不变，模块报告 `failures=0`。撤销原会话后，
对 `r--` 和 `--x` 别名用不同镜像各尝试登记，36 次均返回 `EINVAL`，无活动会话竞争。21 次
错误偏移对照均为 `UNKNOWN`，未对目标采样。21 次 App 启动中并行业务完成 6,384,128 次运算、
零错误；单次完整采样路径最大 35.15 ms，UI 心跳最大间隔 19 ms。测试结束 KPM 清单为空，boot ID
未变，新增内核日志无 BUG、WARNING、Oops 或 panic。结果只代表本设备与这些夹具。

[正式矩阵](results/keyless226-audit-20261110-220249/summary.json) ·
[AP-all 原始日志](results/keyless226-audit-20261110-220249/keyless226-audit-ap-all-1-21421.log) ·
[旧探针回归](results/keyless226-20261110-220502/summary.json)

在仓库根目录复跑，使用已有的 2.26.0 KPM：

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v226-audit --repeats 32 --cycles 3
```

## 后续：2.27.0 的收口

[ELIMINATION_2_27_DESIGN.md](ELIMINATION_2_27_DESIGN.md) 记录了对本文两条探针的修复：
对齐掩码改由"exclusive 访问自然对齐"导出的精确逆处理，无预约写入改由 LDXR 入口的
间接分支目标证明拒绝。同设备、同夹具的 `--keyless-v227-audit` 矩阵中，ap-all 的
`mask`、`phantom` 在全部 5 个阶段均为 0，`trap=0/32`、`crc_eligible=32`，生产 CRC
仍为 `file=direct=business=f50bcaf6`、`execute=1235`。§5 中依赖硬件 trace 的残余
（区间中段间接进入的 >64 条填充/跨函数变体、信号处理器跳过、调用边界、跨线程写、
不可逆值保持写）仍在设计文档 §3 中逐项标注。

