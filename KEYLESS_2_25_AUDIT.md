# 普通 App 检测与隔离 UROV-Y 2.25.0 的读取伪造

普通 ARM64 App 可在不调用模块控制通道的情况下发现本进程目标页上的活动覆盖。
2.25.0 的 AP 全调用者模式即使让普通 CRC 和独立标量读都等于发布文件，
短序列里的独占存储结果仍会暴露读异常。App 可以拒绝采信这次活内存校验，
同时让普通业务继续；要保护新设计的路径，可以把文件校验和执行拆到不满足
本版模块登记条件的两种映射。

## 当前实现

- [模块入口](urov_y.c#L16) 向 KernelPatch 声明 2.25.0。后端根据页表参数、
  内核符号和匹配的 BTF 布置异常、GUP、映射变更等 hook。ABI v8 的控制入口
  验证密钥派生的选项字、固定 magic 和请求 MAC；不匹配时交回原生调用。
  [初始化](urov_y_backend.c#L6422) · [控制钩子](urov_y_backend.c#L5108)
- `REGISTER` 绑定当前调用者的 `mm`。目标要求完整一页落在有文件后备、可读且
  可执行、当前不可写的 VMA 内，普通链接器的私有 RX 映射满足此条件。
  后端先从活页取 `snapshot`，再把调用者给的 `SRC_USER` 字节叠加为 `image`。
  `PAGE_AP` 支持每页一个描述符的多页会话；`SET_PAGE` 能更新指定页的镜像。
  [VMA 检查](urov_y_backend.c#L1283) · [登记](urov_y_backend.c#L4709)
- 三种模式更改的是不同位置。目标页上的补丁可以继续运行，校验读到的值则由
  读位置、调用窗口或数据读异常决定。

| 模式 | 接管点 | 目标读语义 |
| --- | --- | --- |
| `SITE_BRK` | 已登记读指令被替换为 `BRK`，原指令保存在模块内 | 陷阱里模拟原 load；其它读指令原生读取 |
| `PAGE_UXN` | 读指令所在页的叶 PTE 设 UXN，VMA 和指令字不变 | 取指异常里模拟登记 load 和受限的 `RET/NOP/BTI`；页外读者可原生读取 |
| `PAGE_AP` | 目标页的叶 PTE 清 `AP[1]`（`PTE_USER`），保留 EL0 取指 | 目标页的数据读触发权限异常；处理器用软件解码 load，更新 GPR/FPSIMD、写回地址和 PC |

[布置 AP](urov_y_backend.c#L1415) · [布置读点](urov_y_backend.c#L1562) ·
[load 模拟](urov_y_backend.c#L4067) · [异常分流](urov_y_backend.c#L4201)

陷阱命中后用 `x30` 和有限的 `x29` 帧链匹配调用窗口，命中返回 `image`，
窗口外回放 `snapshot`，无窗口时适用所有调用者。跨页读取按登记页分别拼接。
同一版本也接管 `process_vm_readv`、`/proc/*/mem`/ptrace 的内核访问路径及部分
GUP 路径；fork 子映射和保护变更有重布防逻辑。因此，换用 `memcpy`、向量 load、
内核代读或 fork 并不提供独立的活页证据。正常 VMA 的 `/proc/self/maps` 输出也
不会显示这类叶 PTE 修改。
[调用范围](urov_y_backend.c#L1714) · [跨页视图](urov_y_backend.c#L1108) ·
[pin 替换](urov_y_backend.c#L5256) · [内核代读](urov_y_backend.c#L5473) ·
[映射变更](urov_y_backend.c#L5921)

## 2.25.0 留下的短探针

[2.25 设计](ELIMINATION_2_25_DESIGN.md) 已把成对、向量、多结构和独占 load 接入
预约处理。对于普通采样 load，`uy_llsc_prepare()` 向前寻找最近的独占 load，
用最多 4096 条指令的写集和分支检查证明基址仍指向原预约地址。证明成立才会尝试
软件完成 `STXR/STXP`，必要时进入原生单步；没有凭空恢复硬件独占监视器。

写集按**寄存器是否被写**判定，不会证明写后值等于写前值。以下是新探针在 APK
里的实际指令；`x1` 指向线程私有、自然对齐的 scratch，`x0` 轮流指向目标和对照：

```asm
ldxr x9, [x1]
add  x1, x1, #0
ldrb w10, [x0]
stxr w8, x9, [x1]
```

`ADD` 写了 `x1`，实际地址不变，也没有访问内存。原生路径没有同步异常时，
`STXR` 可以把原值写回 scratch；AP 路径的 `LDRB` 权限异常已经丢掉硬件预约，
而 `written & (1 << lrn)` 阻止软件代写，`STXR` 返回失败。即使采样字节与文件
完全相同，这个分支仍可观测。短窗口避免了超长代码、信号处理、跨线程写和计时
阈值。它依赖当前后端的证明条件及设备原生对照，不能推成所有 ARM64 平台上的
单次 `STXR` 保证。
[写集分类](urov_y_backend.c#L2701) · [基址写入门槛](urov_y_backend.c#L2848) ·
[探针](native/urov_observe.c#L530) ·
[Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)

同一条指令序列在同一线程上先预热。对照用同一已持有文件 fd、同偏移的独立
`r--` 别名，验证设备号、inode、文件偏移、映射权限及采样前后身份。只计两侧
对照都成功的「对照 / 目标 / 对照」。三轮各 32 组有效样本均为目标失败才报
`MATCH`；全部成功为 `NO_MATCH`。混合结果、对照不稳定或身份失配为 `UNKNOWN`。

部署时按以下顺序解释证据：

| 观测 | 解释 |
| --- | --- |
| 已知读点的指令与发布文件不同，且实际字是 A64 `BRK` | 与 `SITE_BRK` 一致；排除合法调试断点后才归因。普通指令差异单列为内容变化 |
| 已知读点页的自有 `BTI C; RET` canary 与干净可执行别名表现不同 | 与 `PAGE_UXN` 一致；必须预先核对 canary 字节，不能执行未知代码 |
| 保留调用上下文的业务读取和独立标量读取稳定地返回不同原始字节 | 发现选择性读视图。AP 全调用者模式可无差异 |
| 基址写入探针只在目标页丢失预约 | 与本版 `PAGE_AP` 的数据异常及桥接拒绝一致，字节相同也成立 |

每个判定只覆盖当前采样的地址、读点和时间。空载模块、未采样页、其他进程的
`mm`、不经过已知读点的覆盖都可能无信号。单个断点、调度失败、COW 或文件差异
不能唯一识别模块。生产中只采样自有、无重定位和热更新的稳定区间，持有 SO、映射
和 fd 生命周期；没有安全 canary 或对照不稳定时保留未知状态。后台低频复核即可，
不要全库高频扫描。检测器无需改目标页权限、写目标数据或装信号处理器；Dobby 改码
只用于布置对照夹具。

## 不干扰原业务的阻断

1. **阻断伪造结果被采信。** `TRAP`、`CHANGED` 和 `UNKNOWN` 都不让本次活内存 CRC
   进入可信判定，普通功能仍可继续。另用保留的常规文件 fd，通过 `pread` 到普通
   数据缓冲区校验发布产物；生产基准应来自签名清单，文件校验通过不证明现有活页
   未改。需要独立证明设备状态时，核验应放到 App 之外。
2. **阻止独立路径被本版登记。** 给文件字节使用独立 `PROT_READ` 非执行映射；如需
   执行专用例程，另建 `PROT_EXEC`、`MAP_PRIVATE` 的文件别名，只调用自包含、无需从
   执行页取数据或运行时重定位的代码。该 VMA 没有 `VM_READ`，数据别名没有
   `VM_EXEC`，两者都不符合 `validate_target_vma()`。检测和防护无需改变已有业务
   `.text` 的映射，也不依赖 Android 在硬件上实现 XOM。
   [AOSP 的 XOM 支持边界](https://source.android.com/docs/security/test/execute-only-memory)
3. **已有普通 RX 映射的覆盖无法由该方案安全撤销。** 2.25.0 可随保护变更和 fork
   保留或重建 AP 陷阱。普通 App 没有通用权限去掉活动 KPM 或修正原 PTE；受管设备
   应从可信管理侧撤销会话或卸载模块。App 的沙箱由内核实施，对任意改写内核的
   对手没有纯 App 的完整保证。[Android 应用沙箱](https://source.android.com/docs/security/app-sandbox)

## 真机复核（2026-11-10）

Pixel 6，Android 16，ARM64，4 KiB，内核 `6.1.134-android14-11`，KernelPatch
`c00`。App 以 `untrusted_app` 启动，`CapEff=0`、`Seccomp=2`、SELinux
Enforcing。被测 KPM 的 SHA-256 与 2.25 设计文档一致。密钥和 root 只用于布置、
确认和清理会话；观察函数不接收密钥或模式，不使用 `prctl`。

| 阶段 | 活动读路径异常 | 其它结果 |
| --- | ---: | --- |
| 干净，含未加载、空载及卸载后的对照 | 0 / 336 | 336 次读视图一致 |
| 仅 Dobby 修改，含覆盖撤销后 | 0 / 624 | 624 次记为代码变化 |
| 原样镜像的活动会话 | 288 / 288 | 识别读接管；原样镜像并没有改变读值 |
| Dobby 修改 + 原始文件镜像覆盖 | 288 / 288 | 六种模式各 48 次，均不采信活内存 CRC |

最难的 `ap-all` 覆盖中，48 次复核均无读者差异，文件、直接读及业务读的 CRC32
同为 `96964c4f`，原入口实际返回 `0x1235`。每次 96 组有效独占对照，合计
4608 组，目标 `STXR` 全失败，独立对照均成功。只读参考仍匹配文件，
独立执行别名返回 `0x1234`。原会话撤销后，18 次运行对两个别名各试一次
登记，36 次均为 `EINVAL`；无竞争会话。21 次故意传错文件偏移均为 `UNKNOWN`，
未开始采样。

21 次 App 启动均通过，业务线程共执行 1,645,440 次、错误为 0，UI 心跳最大间隔
20 ms。单次目标复核（读视图检查及 AP 探针，读点检查每阶段一次）实测最大
17.24 ms。测试结束 KPM 列表为空，boot ID 未变，增量内核日志无 BUG/WARNING/
Oops/panic。这些数字是该设备和夹具上的观测结果。

[最终矩阵](results/keyless225-20261110-210901/summary.json) ·
[AP-all 日志样例](results/keyless225-20261110-210901/keyless225-ap-all-1-10610.log) ·
[App 夹具](apps/urov-detect/keyless225_fixture.inc) · [矩阵脚本](tools/run_crc_device.py)

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --keyless-v225 --repeats 16 --cycles 3
```
