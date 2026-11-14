# UROV-Z 1.2.1

2026-11-14，Android ARM64 实验性预发布。

## 本次更新

- owner 未注册代码页直接 nofault 取指，消除重复 VMA/文件身份遍历；fork 子进程使用自己的真实指令快照。
- LL/SC 回溯改为 512 字节块读取，保留原有 16,384 条扫描上限、停止条件和单字失败回退。
- 增加有界负分析缓存，每次复用前重新核对全部历史指令字节及不可读边界；前置代码变化后退回完整分析，不缓存寄存器相关的最终桥接计划。
- 每次异常复用 opcode/GPR model，合并单页定位与读取；保留跨页、LSE 和 FPSIMD 语义。
- readv/proc 测试使用每线程独立、预分配并预触页的 64 KiB 缓冲，处理短读与 EINTR。
- 新增 `perf` 诊断命令和页数、长 LL/SC、代码修改、子快照、LSE 回归；普通发布构建关闭诊断计数。

实现分析与实测证据见 [优化报告](performance-optimization-1.2.1.zh-CN.md)，构建和复测步骤见 [README](../README.md) 与 [INTEGRATION.md](INTEGRATION.md)。

## 性能与验证

Pixel 6 / Android 16 / Linux 6.1.134 / 4 KiB，保持同一个旧版测试 APK，读取整个 204,608 字节可执行段、覆盖其中十页：direct + CRC 从约 683 ms 降至 5.6–6.3 ms，本组设备数据约提升 111 倍。不同设备、读取指令和调度状态下的收益会变化；这不是异常入口固有成本的测量。

- 核心自检 4,152 项、原有 App 回归 73 项通过。
- 块扫描验证包含 4K/16K 模型下 4,194,304 个指令字；不代表 16 KiB 真机验证。
- 1–256 页、8,192 条指令的 LL/SC 长窗口、CLREX、间接分支跳入负例、前置指令修改、无 mprotect 的 proc-mem 写入、父子真实指令快照隔离和 LSE LDADD 通过。
- 最终 CRC App 的 manual/linker 各三轮通过；每轮 96 次整段 CRC、20,480 次函数调用，mismatches/failures 均为 0。

## 下载与使用

附件包括 `urov-z.kpm`、`urov-injection-test.apk`（UROV CRC Lab）、`urov-z-test.apk`（原有回归）、`SHA256SUMS` 和 `BUILD-INFO.txt`。两套 APK 的版本元数据均为 1.2.1，SO 已打包进 APK。

设备 kpatch SuperKey 由用户在测试界面输入。公开固定模块测试密钥为 `59f5c4618474864a61d5469295548064`（MD5 of UTF-8 urov-lab，无换行）。附件不包含设备 SuperKey 或签名私钥。

当前宿主更新 KPM 使用受控重启，不热卸载。需要 RX 文件映射、受支持的指令和准确内核布局；16 KiB 内核与其他设备没有本次集成运行验证。关闭 native step 时对受管页执行 EL0 缓存维护指令、并发修改代码/VMA、原生写同步等已有边界仍见优化报告。分析缓存额外预算约 1 MiB，分配失败时继续使用原慢路径。
