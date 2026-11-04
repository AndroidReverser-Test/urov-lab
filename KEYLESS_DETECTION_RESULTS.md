# UROV-X 无密钥检测复核与 App 实测

后续（2026-11-04）：针对本文第 3、4 节两项检测的读取点陷阱变体
`urov-y` 已完成真机验证，活动页上两项均 0 命中，业务调用窗口仍返回伪值；
新引入的读取点代码页差异已实测记录。见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) 与
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md)。本文保留为 `urov-x` 的检测记录。

日期：2026-11-04（Asia/Shanghai）。复核对象是 STEALTH_RESULTS.md 的同一个
`urov-x.kpm`，SHA256 为
`c2a5c3d3bb272f4bd2db6205f69cd277739f6e32e5c6cd67cecf2b3e7f393575`。
本轮没有修改、重编译或加强 KPM；只增加普通 App 检测代码、夹具和运行器。

**结论：除控制密钥之外，仍能检测自身 mm 内的活动受保护页。新增的独占监视器
观察不依赖时间阈值、伪值、授权读取点或控制通道。再结合已知纯读取函数的跨 PC
一致性校验，可以确认读取视图异常。它们均不能证明空闲模块不存在，也不能仅凭
一个硬件现象唯一归因于名为 urov-x 的模块。**

正式矩阵通过：9 次 App 运行、62 组观测用例、1,212 次完整 API 观测、5,569 项
夹具断言。342 次活动页观测全部命中；870 次正常页观测中，867 次未命中、3 次
UNKNOWN，**0 次误报**。这些是本机样本计数，不是全部 Android 设备的误报率保证。

## 1. 框架实际实现

代码主线为 `urov_x.c` → `urov_x_backend.c` → `decode.c` / `emulate.c`。
原 `urov_kpm.c` / `urov_backend.c` 仍组成另一个 `urov-lab.kpm` 对照模块。

| 环节 | 源码中的实际行为 | 对检测的影响 |
|---|---|---|
| 装载 | 4139 项核心自测；解析 fault、mm、pin、TLB 和 nofault copy 函数；安装 `do_mem_abort`、`prctl`、4 个映射操作及 clone/clone3 hook | root 能观察 hook 和模块清单；不属于普通 App 能力 |
| 控制 | ABI v3，192 字节；128 位装载密钥派生 selector、magic、MAC key，请求携带 64 位 SipHash MAC | 无效请求回落原生 prctl，不可通过旧 ABI 查询状态 |
| 注册 | 全模块一个会话，归属调用者 mm；一页文件后备 RX 映射，无 VM_MAYWRITE；固定页并快照原始 4096 字节 | 是自身进程的合作注册模型，非任意跨 App 内存覆盖 |
| 权限 | 清 VMA `vm_page_prot` 与叶子 PTE 的 `PTE_USER`，保留取指；不改 `vm_flags` | maps/smaps 仍显示普通 RX；**页内任何数据读取都需异常处理** |
| 模拟 | EL0 读 permission fault 且 mm/FAR 命中后，按 PC 选视图；授权 PC 取 fake 快照，其他 PC 取 original；解码、校验地址/综合征、合成字节，再提交 GPR/SP/PC | 未授权读取虽然返回原字节，仍必须经过异常返回；GPR 提交不能恢复独占监视器 |
| 更新 | seqlock 发布最多 32 字节 fake；单指令使用完整快照 | 检测不调用 SET，也不改变 generation/fake |
| 降级 | 未授权且无法模拟时结束会话，恢复页面后走原生 fault 重试 | SIMD、目标页独占/原子读取会破坏被测状态，不适合作为无干扰检测 |
| 生命周期 | 相交映射修改静默结束会话；复制 mm 的 clone 临时恢复页面；注销/卸载恢复 VMA/PTE/TLB，等 handler 后 unpin/mmput | 改映射和 fork 不适合作为业务检测手段 |

源码含本机 BTF 偏移、4 KiB 页和 A64 指令子集等约束。`urov_x_backend.c` 的
`ux_abort_before()` / `commit_model()` 是本轮新检测的直接依据：即便成功模拟后
`skip_origin=1`，返回 EL0 仍然是一次异常返回。

## 2. 已去除的检测点

已完整阅读 [STEALTH_RESULTS.md](STEALTH_RESULTS.md)，并复核对应实现。

| 原特征 | urov-x 的处理 | 本轮判断 |
|---|---|---|
| 固定 prctl option/magic、旧 kcmp | 密钥派生 + 请求 MAC；不安装 kcmp 通道 | 不用作无密钥检测 |
| QUERY 暴露其他 mm 的 EBUSY | 无认证无法分发；非 owner 不报告归属 | 不用作检测 |
| 普通标量读取与安装文件不等 | 只让注册 PC 读到 fake，其他 PC 读 original | 通用完整性扫描仍然会漏检 |
| smaps 的 rr/dc | 不改 vm_flags | 不可作为指纹；合法 madvise 也可设置这些位 |
| 映射修改返回 EBUSY | 静默恢复后放行原调用 | 不能用；会结束业务覆盖 |
| 不支持 load 产生 SIGSEGV | 未授权指令触发恢复和重试 | 不能用；会结束业务覆盖 |
| fork 子进程继承异常页 | clone 前后临时恢复/再保护 | 不能用；有多线程语义影响 |
| 每次读取的耗时 | 同步异常开销仍存在 | 只作诊断，不设耗时阳性阈值 |

所以旧报告关于“原检测核心不可判”的测试结果依旧成立，但不能进一步推出
“除耗时外再无无密钥观察面”。

## 3. 新检测 A：读取引起的独占监视器失效

Arm 的 A64 同步原语文档 Figure 3-1（第 18 页）将异常返回列为本地独占监视器
回到 Open 状态的原因，见
[Arm 官方文档](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)。
据此作出的实现推断是：在 scratch 上建立独占状态后，若目标 LDRB 每次都经
EL1 模拟和异常返回，随后对 scratch 的 STXR 应持续失败；实测验证了这个推断。

最终 APK 的 `exclusive_once` 反汇编为：

```asm
ldxr x9, [x1]       // x1 是本线程私有 scratch，绝不是目标页
ldrb w10, [x0]      // x0 才是目标地址，普通标量读取
stxr w8, x9, [x1]   // 只向 scratch 写回同一个值；w8=1 表示失败
```

三条指令之间没有函数调用、syscall、屏障、栈访问或隐藏重试。
**独占指令从不访问目标页**，不会触发本框架的“不支持原子指令”降级。

`native/urov_observe.c` 的 `ud_observe_exclusive()` 采用以下判据：

1. 调用方保留目标与正常参照映射；它们必须在不同虚拟页，映射同一普通文件的
   同一字节。核对 fd、dev/inode、准确偏移、长度及 RX 权限，并预热。
2. 使用同一个 `exclusive_once` 函数，执行“参照 → 目标 → 参照”。两侧参照的
   STXR 都成功，且三者字节相同，才接受该次目标结果。
3. 三组各 32 个有效三元组。目标 **96/96 全失败** 才返回 MATCH；**96/96 全成功**
   才返回 NO_MATCH。混合结果、对照不可靠、超过 8 个对照废弃、元数据变化均 UNKNOWN。
4. 结束后再次核对两个 VMA 和文件元数据。所有出口保留调用者 errno。

这不是“读慢了就判阳性”。原值等于伪值、采样没有落入 fake 窗口，均不妨碍观察：
模块保护的是整页 PTE，页内一个字节的读取就经过同一异常机制。

独占访问允许出现无竞争失败，插入普通 load 后的成功性也受实现影响，不能把
一次 STXR 失败当作异常证明。因此本实现保留对照和 UNKNOWN，不声称该序列在所有
CPU 上都有判别力。调试器、针对性硬件 watchpoint、虚拟化及其他异常模拟机制，
仍可能产生同类现象；MATCH 的准确含义是**该地址的读取稳定关联独占状态失效**。

## 4. 新检测 B：实际读取点与独立读取点不一致

`ud_observe_reader()` 接收调用方已知的、无副作用的 64 位纯加载函数，以及同一个
不可变 RX 地址和文件偏移。每轮执行文件 pread、独立 LDR、实际函数读取、独立
LDR、实际函数读取、文件 pread，共三轮；文件、独立值及函数结果须各自稳定。
独立值必须等于文件值，实际函数值稳定不等才报告 reader_diff。

本机活动样本：

```text
direct = file = 0xf2c66881f2aaacc1
reader        = 0x8877665544332211
```

检测器不知道密钥，也没有派生 selector。它只是执行原有的 `ux_site_ldr`，所以
自然经过模块注册的 PC。相同输入的纯加载在不可变内存上出现稳定的不同视图，
是内容语义异常；仅对文件作普通扫描则看不到这一点。

这个方法需要能安全调用实际读取函数，不是自动发现任意授权指令 PC 的技术。
内联在复杂业务中的站点若无法无副作用复现，就不能硬套此 API。伪值等于原值或
未采中覆盖字节时返回未命中；新检测 A 仍能发现对应页的活动保护。

## 5. 设备与正式结果

| 项目 | 实测值 |
|---|---|
| 设备 | Pixel 6 / oriole / `25091FDF60063J` |
| 系统 | Android 16 / SDK 36 / `BP31.250610.009` |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，arm64，4 KiB 页 |
| KernelPatch | `0xc00` |
| 检测 / 观察 UID | 10284 / 10287 |
| 两个 App 的实际权限 | `untrusted_app`、`CapEff=0000000000000000`、`Seccomp=2` |
| 正式结果 | [observe-20261104-225016/summary.json](results/observe-20261104-225016/summary.json) |

装载密钥由运行器临时随机生成，只交给建会话的夹具，不写入结果。
**检测 API 只接收地址、参照地址、fd/offset 或纯读取函数，不接收密钥或控制状态。**
单独编译检测对象的未定义符号仅有 `__errno`、`clock_gettime`、`fstat`、`memset`、
`pread`、`sysconf` 和只读元数据助手 `ud_mapping_at`；没有 syscall/prctl 控制依赖。
root 只负责装卸模块、获取状态真值和内核日志。

| 用例，三次活动周期合计 | 观测次数 | 监视器 MATCH | 跨 PC 内容差异 |
|---|---:|---:|---:|
| 活动页、伪值不同 | 90 | 90 | 90 |
| 活动页、采样在覆盖窗口外 | 90 | 90 | 0 |
| 活动页、伪值等于文件原值 | 90 | 90 | 0 |
| 活动页，分别固定 worker 到 CPU 0–7 | 72 | 72 | 72 |
| 正常页：无模块、空闲模块、注销/卸载后、另一正常别名、其他 UID、合法 rr/dc、refault 等 | 870 | 0 | 0 |

正常页的 870 次中，867 次明确未命中，3 次 UNKNOWN，UNKNOWN 未计作阴性成功或
模块阳性。三次出现在卸载后的正常映射，分别只出现一次目标 STXR 失败，符合瞬时
干扰的观察；本轮没有捕获中断追踪，不能进一步断言具体中断来源。

总计 116,288 个被接受的三元组；活动页的 32,832 个目标 STXR 全失败，正常页只有
上述 3 个目标失败，另有 3 个因参照失败而废弃的三元组。跨 PC 内容差异 162 次，
其他 1,050 次无差异。7 类不满足调用约束的负例也按预期拒绝或返回 UNKNOWN。

`observe-20261104-224448` 是探索性小样本；`-224849` 是早期严格夹具，误将一次
正常 UNKNOWN 视作失败后停止并卸载。随后修正的是夹具对 UNKNOWN 的解释，没有
降低检测器的阳性门槛，也没有将不确定结果改判阴性。上述正式数字只统计 `-225016`。

同一最终 APK 另通过原隐蔽性矩阵回归：原模块仍被旧检测核心识别，urov-x 仍对
旧核心隐藏；SIMD 降级、fork、跨 UID 与活动期卸载保持原有行为，见
[stealth-20261104-225350/summary.json](results/stealth-20261104-225350/summary.json)。

设备时间仍为 2025-10-01，未修改时钟；结果目录和报告日期使用宿主 UTC+8。

## 6. 对业务状态的验证与开销

- 三次活动周期中，检测后仍为 `active=1 sites=2 failures=0`，generation/fake
  与检测前相同。fixture 主动 SET 原值的阶段为 generation=2，检测也不改变它。
  `hits` 会因检测本身的正常标量读取增加，这是必要的观察开销。
- 并行业务累计 2,443,136 次运算，0 错误；目标页和原库函数继续执行原机器码，
  正常 pipe I/O 无错误。传给 pipe 的是普通业务缓冲区，绝不是受保护地址。
- errno、既有信号处理器、线程名、文件位置、VMA 属性保持；元数据 fd 未泄漏。
  检测核心不改 affinity；仅每 CPU 的测试夹具临时固定 worker 并恢复。
- UI 心跳一直运行，全部 9 次 App 的最大记录间隔为 21 ms。检测在 worker 线程上。
- 一次 `ud_observe_exclusive()` 包含四次 maps/文件身份检查，未固定 CPU 时，各组
  p50 约 3.6–3.8 ms；固定到小核时约 21–25 ms，最慢样本 29.190 ms。
  这些是该 API 的整体耗时，不是纯 load 耗时，也不包含另一个 reader API。
- 内核新日志没有 BUG/WARNING/Oops/panic/RCU stall/hung task；最终 KPM 列表为空，
  测试 App 均已 force-stop，持有会话期间卸载后原值恢复。

部署时只抽样自己持有生命周期的少量 RX 页，在后台低频执行。UNKNOWN 延后复查，
不能直接阻断业务；不要在 UI 或业务锁内循环全地址空间扫描。单次测试的无错误记录
不等于任意设备、任意并发映射变化下的零影响保证，调用方必须保持映射/fd/函数存活。

## 7. 其他路径为什么不选

| 路径 | 原因 |
|---|---|
| 耗时、系统调用固定额外成本 | 调度、DVFS、缺页、调试/监控等都有替代解释，不作模块阳性依据 |
| maps/smaps、单页 r-xs、rr/dc | 无法唯一标识模块，已用正常合法样本验证不误判 |
| pagemap 读出 PTE_USER | 该接口不导出原始 AP 权限位，普通 App 也不能取得 PFN，见 [Linux 官方接口定义](https://www.kernel.org/doc/html/v6.1/admin-guide/mm/pagemap.html) |
| PMU/硬件异常计数 | 受 perf 权限、SELinux/seccomp 和设备实现限制，不作为稳定依赖，见 [Linux perf 安全文档](https://www.kernel.org/doc/html/v6.1/admin-guide/perf-security.html)；本轮未尝试绕过权限 |
| `/proc/self/mem`、ptrace、process_vm_readv | 不满足本轮权限/稳定性前提，不将拒绝访问当作模块证据 |
| 把目标传给 write/writev 等内核 uaccess | 历史已发生持续重试，见 DETECTION_RESULTS.md；本轮不重复这个危险路径 |
| 在目标上执行 SIMD、LDXR、原子或未支持 load | 会结束会话，不能满足不改变业务覆盖的要求；与“在私有 scratch 上做独占”有实质区别 |
| mprotect/munmap/mremap/MAP_FIXED、fork | 可能结束覆盖或引入父线程原值窗口，不用作检测 |

**证据解释：** A 命中可报告活动页存在异常式读取的强信号；A+B 同时命中，可报告
与当前 UROV-X 模型一致的异常读取视图。没有可唯一识别模块名的无密钥指纹，不应
把任一结果直接表述为“设备一定安装 urov-x”。空闲模块、其他 mm 的活动会话、
未采样页均在检测覆盖范围外；跨 UID 实测验证了这个边界。

## 8. 产物与复现

- 检测核心：[urov_observe.c](native/urov_observe.c)、[调用约束](native/urov_observe.h)。
- App 夹具：[app.c](apps/urov-detect/app.c)，新增 `observe-clean` / `observe-active` 模式。
- APK：[urovdetect.apk](apps/urov-detect/out/urovdetect.apk)、[urovobserver.apk](apps/urov-detect/out/urovobserver.apk)。
- 运行器：[run_observe_device.py](tools/run_observe_device.py)。

```powershell
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_observe_device.py `
  --serial 25091FDF60063J --key <KP-SUPERKEY> --repeats 30 --cycles 3
```

运行器会随机产生 fixture 模块密钥，检查初始没有模块，安装两 APK，执行完整矩阵，
保存日志并清理。既有模块不为空时保留现场并退出。它不需要用户提供 UROV-X 密钥。
正式 APK SHA256：

```text
d0626a5beb75a5127b062a2962039ef53c93aa75816c801ab5c6c94dfa6f711f  urovdetect.apk
4bc0353f398a61e917302e54af181ca9f19765eb0a5d635e3b4f7f35ecfaee65  urovobserver.apk
```
