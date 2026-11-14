# UROV-Z 1.2.0

2026-11-13，Android ARM64 实验性预发布。

## 本次更新

- 十个 Dobby 目标各占独立内存页；16 KiB 对齐，并按运行时页大小逐对核实。
- App 内直接复测 manual/linker，固定使用项目名 urov-lab 的 MD5 模块测试密钥。
- 界面显示基线、三通道实际 CRC、十页明细和阶段判定；十个函数每秒实测实际/期望返回值，保留覆盖期记录。
- 每轮 4 线程完成 96 次整段 CRC 和 20,480 次函数调用，并再次注入 probe。
- CRC 使用同范围、同通道前后中位数比较；每组计时仅一行日志。
- 移除两份 PowerShell 复测脚本与文件交换；运行结果只显示在界面和 logcat。
- KPM 保持现有覆盖/加载实现，仅更新版本元数据为 1.2.0；两套 APK 版本同步。

## 下载与复测

附件包括 `urov-z.kpm`、`urov-injection-test.apk`（UROV CRC Lab）、
`urov-z-test.apk`（原有回归）、`SHA256SUMS` 和 `BUILD-INFO.txt`。
SO 已打包进 APK，无需单独复制。简要操作见 [README](../README.md#复测流程无需-powershell-脚本)，实现细节见 [INTEGRATION.md](INTEGRATION.md)。

设备 kpatch SuperKey 由用户在界面输入。公开固定测试密钥为
`59f5c4618474864a61d5469295548064`（MD5 of UTF-8 urov-lab，无换行）。
设备 SuperKey、签名私钥均不包含在附件中。

## 验证范围

在 Pixel 6、Android 16、Linux 6.1.134、4 KiB 页上，当前测试逻辑的
manual/linker 各连续 3 轮通过。每后端 13 个阶段 CRC、130 个逐页结果均通过；
定时采样分别 64 / 63 组，合计 1,270 次重新调用，实际返回值均符合期望。
原有 App 回归 73 项通过，RELRO 边界断言 14 项通过，模块核心自检 4,152 项通过。

发布构建重新生成 KPM 与两套 APK，验证 APK 签名，并核对 APK 中 DEX/native SO、
KPM 可执行段与上述实测产物一致。版本和打包元数据不计入该一致性比较。
源码提交与最终 SHA-256 以附件为准。本次发布不热卸载重载设备 KPM。

16 KiB 仅做布局/边界设计，未在 16 KiB 内核运行验证。仍受支持指令、
RX 文件映射、协作线程、内核布局和 linker namespace 等条件限制。
