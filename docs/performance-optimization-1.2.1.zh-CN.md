# UROV-Z 1.2.1 多页读取优化实现与验证

实施及验证日期：2026-11-13 至 2026-11-14（客户端日期）。基线为 `7976445` / 1.2.0；此前的[性能分析](performance-analysis-1.2.0.zh-CN.md)保留原样。1.2.1 发布说明见 [RELEASE-1.2.1.md](RELEASE-1.2.1.md)。

## 实现与瓶颈

REGISTER 为 RX 文件页建立真实 snapshot 和替代 image，清 PTE_USER/AP[1]。取指继续执行真实代码；每条受管 EL0 load 通过权限异常、真实指令解码和寄存器/FPSIMD 提交返回 image。内核代读另外走 remote-vm 缓冲覆盖或 GUP/PIN 页替换。双 epoch 读者引用保护 SET、注销和外部读者的生命周期。

原版对普通 load 也进行最多 16,384 条历史指令的 LL/SC 分析。测试的 LD1 PC 前有 7,587 个指令字；每次取指还会在 owner 页索引未命中后做 VMA/文件身份遍历。注册页索引本身已经是二分查找，因此换哈希表没有解决根因。

## 本次改动

### 真实指令读取和块扫描

- `uz_fetch_insns` 区分 owner 和已确认的 child。owner 未注册 VA 直接 nofault 读取；不再按相同文件身份把别名误认为已注册 VA。child 使用文件身份和自己的 native snapshot，不能根据父 VA 读父 snapshot。
- `module/insn_scan.h` 使用一个 512 字节异常局部块，按原顺序逆向扫描。块不会越过 4 KiB/16 KiB 页边界。批量读取失败后只回退读取当前指令，不能因低地址不可读而跳过靠近 PC 的合法停止指令。
- 三个回溯阶段复用这一个小块；阶段之间重置。保留 16,384 条上限和原停止条件。不会在异常中申请内存。
- 当分支图稳定且已无效/不完整，提前执行原来 `uz_llsc_skipped` 的拒绝决定。该检查位于 sampled-exclusive 分支之后。本次 CRC 场景分支图完整，诊断显示此提前返回次数为 0，不能把收益归给它。

### 带完整内容验证的负分析缓存

没有把 `g_code.seq`、fake generation 或当前 opcode 当作真实代码版本。现有 hook 无法完整证明所有外部写入都被追踪，所以采用更保守的缓存：

1. 仅缓存第一轮得到“没有需要桥接的 exclusive load”的结论，以及实际检查过的全部指令字；遇到 exclusive 候选，继续按当前寄存器执行完整回推和分支检查，不缓存最终计划。
2. 每次命中先按当前地址空间重新读取整段指令，以 `memcmp` 核对每个字节；不是只比 PC/opcode，也不是可能碰撞的 hash。若上次因取指失败停止，还重新检查那个精确地址仍不可读。
3. 内容变化、原不可读地址变得可读或验证失败时退回完整块扫描。因而 mprotect 写入和没有 mprotect 的 `/proc/self/mem` 写入都能令旧结论失效。相同 VA 映射替换为不同字节也不能命中；同字节负结论与映射对象身份无关。
4. 每个会话在开放读者前可选分配 8 个槽，按 task/PC 分散并用非等待 CAS 租用。槽保存字节和数值地址，不保存可移动页描述符/VMA 指针；仅 owner 启用，child 保留慢路径。会话释放在读者排空后释放全部槽，不依赖固定为 1 的 ABI session 字段。
5. 总额外空间为 1,048,832 字节（约 1 MiB），独立于 CPU 数和注册页数；分配失败或槽忙继续慢路径，不拒绝注册。此空间不计入现有仅约束主影像池的 `max_kb`。

这是内容验证后的分析复用，仍然每次读取历史字节。它消除了逐字解码和大量 nofault 调用，不是零成本的版本缓存。并发修改正在执行的代码、VMA/PTE 生命周期和原有 native snapshot 写同步限制仍然存在；本次没有声称提供任意并发自修改代码的线性一致性。

### 一次异常内的固定工作

真实 opcode 和 GPR model 只构建一次，再供 LSE atomic / 普通 load 路径使用。保留 ESR read 可能实际为 RMW 的处理。单页读取在 LL/SC 分析之后只定位一次并复制，不再先 `range_covered` 后 `read_range`。跨页仍逐段检查，全部成功后才提交寄存器。

不把入口 FAR 描述符跨长扫描保存为最近页缓存：现有 mremap 会原地排序数组。本次没有扩大这种指针的生命周期，也没有解决原有并发映射的全部限制。读者协议、PIN 引用和 FPSIMD helper 均保留。

### 内核代读测试批次

`integration/host.c` 将 4 KiB 栈缓冲改为每线程独立的 64 KiB 缓冲，预分配、预触页均在计时外；处理短读、EINTR、0 返回及错误，proc 仍计入 open/close。四个压力线程使用独立堆缓冲，主套件单独使用静态缓冲。

204,608 字节范围需要的用户态 readv/pread 调用从 50 降为 4。内核仍可能分批 pin 或逐页处理。本次未修改 readv 的 PIN 生命周期和逐次独立页分配，也未改 fast-GUP 消费者的 GET 语义。

## 设备证据

设备：Pixel 6 / oriole，Android 16，Linux 6.1.134，4 KiB。始终使用受控重启替换 KPM，没有热卸载。日志与二进制备份位于被忽略的 `out/perf-optimization-20261113/`；没有保存设备 SuperKey。

### 同一旧 APK 隔离内核变化

优化前后使用同一个原版 `libuzhost.so`（SHA-256 `03b71648e3f6c6fc6462da4725403eb92707071dd162c5c06c08747da5265081`），保持 4 KiB 代读批次。读整个 204,608 字节 PT_LOAD，仅十页覆盖；每通道 2 次预热、9 次采样，以下为每轮中位数范围。

| 阶段 | 十页 direct + CRC | 四线程压力总耗时 | 结果 |
|---|---:|---:|---|
| 原版，两轮 | 683.019–683.435 ms | 9,519–9,526 ms | PASS |
| 仅块扫描/查找优化诊断版，两轮 | 68.891–68.903 ms | 999–1,092 ms | PASS |
| 加入完整字节验证缓存诊断版，两轮 | 5.735–6.207 ms | 130–160 ms | PASS |
| 最终关闭诊断版本，三轮 | 5.639–6.290 ms | 107–122 ms | PASS |

最终相同 APK 的覆盖态 direct 端到端耗时下降约 **108–121 倍**；以三轮中位数 6.152 ms 对比原版两轮中位数的中点 683.227 ms，约 **111 倍**。原生阶段自身约 1.9–4.7 ms，调频/调度漂移明显；该倍数仅描述本设备这组测试，不等于异常固有成本或所有程序的加速倍数。direct 与 readv/proc 使用不同 CRC 算法，不能横向作模块开销比较。

诊断版两轮套件（尚未运行其他回归时）共 58,880 次 load：仅块扫描版执行 446,722,560 个扫描字；加入缓存后为 10 次扫描、75,870 个字、58,870 次 cache hit，owner identity lookup/compare 均为 0。验证仍重读约 1.79 GB 历史字节，因此不宣称历史数据读取也被完全消除。最终测时版本 `diagnostics=0`，热路径不含这些计数原子操作。

原始日志：`baseline/manual-9962.txt`、`diagnostic-manual.txt`、`diagnostic-memo-manual.txt`、`final-old-apk-manual.txt`。

### 最终 64 KiB APK

保持相同 CRC 算法、十页覆盖和 204,608 字节范围。最终 APK 的 SHA-256 为 `641d7baf6fb0551bb95494523e3c9dff0a64a4dec5d541b310587a114a76aac8`，`libuzhost.so` 为 `e758f08b783b4a73ea60a16385f4a9e34b4fc89c585439496026d431c8b0cddc`。

上述 APK hash 标识本节性能采样使用的打包产物。11 月 14 日发布前重新打包的 CRC APK 为 `f7090cbd6b9dd1909d01efa1dd3e8bcc35451d4f0a61e2a4422c983956028c63`，native SO 与性能采样版本一致；发布版另行完成 manual/linker 各三轮验证。原有回归 APK 仅将版本元数据更新为 1.2.1，DEX/native SO 与已验证版本逐字节相同。Release 附件的最终校验以 `SHA256SUMS` 为准。

| 后端（三轮） | 覆盖态 direct | 覆盖态 readv | 覆盖态 proc | 压力总耗时 |
|---|---:|---:|---:|---:|
| manual，PID 7170 | 5.664–6.624 ms | 65.0–73.3 µs | 99.8–104.7 µs | 104–131 ms |
| linker，PID 7334 | 5.867–6.588 ms | 67.6–77.7 µs | 102.0–125.8 µs | 103–134 ms |

两种后端均 `RESULT PASS cycles=3`，每轮 96 次 CRC、20,480 次函数调用，mismatches/failures 均为 0。每个阶段还独立验证十页与整段 CRC。读批次减少与 readv/proc 时间下降一致，但未进行频率锁定或交替 APK 的统计实验，不据此承诺代读固定加速倍数。压力计时保留原来的 INSPECT 完成边界，新增缓冲分配/预触页和释放在计时之外。

原始日志：`final-new-apk-manual.txt`、`final-new-apk-linker.txt`。最后全局 `inactive pages=0 armed=0`，KCLF 请求已回收；模块继续驻留。

### 回归和边界

- 4,152 项核心自检。
- 4 KiB/16 KiB 模型的 256 轮逆序块遍历，共 4,194,304 个指令字；包括失败复制污染缓冲后的单字回退、非对齐/溢出和重置后代码变化。此项不代表 16 KiB 真机验证。
- 原有 73 项 App 回归通过，包含跨页/FPSIMD、readv/proc/vmsplice、fork、SET 竞争和注销。最终一轮 48 次更新、1,121,540 次并发读取，`torn_or_failed=0`，见 `final-app.txt`。
- `tests/perf_device.c`：1/2/4/8/10/32/64/128/256 页；固定只读一页与读全部页分离；8,192 条 NOP 的 LL/SC 长窗口、CLREX、间接跳入负例；前置 NOP→LDXR→NOP 修改、无 mprotect 的 proc-mem 写入；fork 子进程真实指令快照和父进程隔离；LSE LDADD。
- 新增子快照测试使用模块成功模拟 store 后已有的 I-cache flush，再执行 ISB。单独调用 EL0 `__clear_cache` 到受管 AP 页曾在 native-step 关闭配置下陷入重复 fault；测试用 alarm 终止，未发生设备重启。该缓存维护指令问题不在本次优化中修复，不能把子快照用例解释为任意自修改代码支持。

页数测试是纯读取+复制，无 CRC。通过 `taskset 40` 固定 CPU 6 的一轮，固定只读一页为 39.96–52.21 µs，全部页的 1/10/64/256 页分别为 52.08/427.69/2,505.78/10,017.42 µs。此 reader 前有 CLREX，仅短负分析；用于分离注册规模与读量，不应拿它的每页耗时代替长回溯 CRC reader 的成本。启动早期未固定亲和性的一轮波动较大，也保留在日志中。

## 构建与复现

```powershell
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk D:\androidSDK\ndk\26.1.10909125
.\integration\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
.\tests\build.ps1 -Ndk D:\androidSDK\ndk\26.1.10909125
```

普通构建关闭诊断。需要归因时加 `-Diagnostics` 构建单独 KPM，受控重启加载后运行 `kpm ctl0 urov-z perf`。字段是模块驻留期间累计计数，注销后仍可读取；`code_valid/code_complete` 是当前会话状态，inactive 时为 0。没有 reset 命令，区间计数使用前后差。`status/selftest` 和用户态 ABI 不变。

`out/tests/insn-scan-test` 可独立在设备执行；`out/tests/perf-device` 需要加载模块并使用公开的固定项目测试密钥。只在没有活动 owner 测试时执行。原有 App 和注入 App 的运行入口见 [INTEGRATION.md](INTEGRATION.md)。

最终 KPM SHA-256：`6f2661f6147a902f9cab7af16ad75c63762cc19ee898a9c6214ec8cfb0bc284c`。

## 后续空间

长期零验证缓存仍需要覆盖所有 native 写入的版本协议；只增加 mapping epoch 不足以做到。本轮未做正候选缓存、不可变 PIN 版本页、hits 分片、读者协议替换或 child 索引重构。PAGE_AP 仍然每条受管 load 触发一次异常，未改变架构能力范围。
