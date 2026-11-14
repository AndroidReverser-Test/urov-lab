# UROV-Z 1.2.5

2026-11-14（Asia/Shanghai），Android ARM64 实验性预发布。

本次将工作树中的 1.2.3–1.2.5 兼容性、生命周期和资源管理修订一并提交。当前实现的完整讲解见 [1.2.5 技术博客](implementation-1.2.5.zh-CN.md)，包含读取双视图、注册与更新、异常模拟、内核代读、页表与 GUP 适配、并发和 KCLF 集成流程图。项目自有设计、审计、历史发布与测试结果文档已集中到 [docs 索引](README.md)；组件 README 保留为入口。

## 代码变化

- 原生页表锁、连续 PTE 准入、GUP GET/PIN 和运行时 ABI 检查；新内核不直接套用旧私有函数签名。
- 稳定页描述符、双缓冲地址索引与 reader epoch，覆盖 fork、映射拆分/移动、缺页恢复和退役流程。
- 默认 `writes=rx`：观察到写权限或受监测的写入时退役，后续 SET 返回 ESTALE；辅助写入实验须显式选择 `writes=experimental`。
- 每页短锁取代已提交版本的序列重试及其快照回退，统一 SET 与读取的发布边界；RX 主缓冲由每目标 7 页减为 3 页。默认四份 fork 预留完整且未触发子池上限时，指定主/子缓冲由 15 页减为 11 页，减少 26.7%，不代表整机内存节省或速度提升。
- 新增 `buffer_kb` 额度与 `fork_copies` 预留配置，以及 `memory`、`health`、`compat` 诊断；默认预算 64 MiB，具体覆盖范围见 [审计](compatibility-audit-1.2.5.zh-CN.md)。
- KCLF 可通过加载参数 `loader=off` 关闭，或使用 `-OverlayOnly` 构建；默认仍包含 KCLF 1.5.7。
- 通用 `compat-check --inspect` 输出静态兼容性证据来源；用户态 ELF 使用 16K LOAD 对齐与兼顾 4K/16K 的 RELRO 布局。

用户态 wire ABI 保持 v1。API、模块和两款 APK 的版本关系、控制命令及构建步骤见 [项目 README](../README.md)。

## 附件与构建

| 附件 | 内容与验证范围 |
|---|---|
| `urov-z.kpm` | 普通完整构建，诊断计数关闭；本轮完成构建及重复构建一致性验证，未替换到设备加载 |
| `urov-z-diagnostics.kpm` | 完整诊断构建；与设备上已加载的 1.2.5 文件 SHA-256 一致，本轮 APK 与设备回归使用该构建 |
| `urov-z-test.apk` | UROV-Z Lab，基础读取/API 回归；versionName=1.2.5、versionCode=125 |
| `urov-injection-test.apk` | UROV CRC Lab，十页 CRC、Dobby、manual/linker 注入与压力回归；versionName=1.2.5、versionCode=125 |
| `SHA256SUMS` | 上述附件与验证信息文件的 SHA-256 校验清单 |
| `BUILD-INFO.txt` / `VALIDATION.txt` | 对应源码提交、工具链、构建配置及本轮验证摘要 |

两个 KPM 的内部模块名均为 `urov-z`，应选择一个加载，不能同时加载。设备实测版本可在下载后使用原文件名加载，模块管理命令仍为 `kpm ctl0 urov-z ...`。

构建环境：NDK 26.1.10909125 / Clang 17.0.2，SDK Build Tools 36.0.0 / android-36，JDK 21。KPM 使用 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`。普通构建另用 KernelPatch `406c85ce79a5e1c19b53be34c04baadc1ec68bc5` 的未修改头文件重建，得到相同 SHA-256；本次没有提交或部署外层 KernelPatch 的工作树改动。

普通 KPM SHA-256：`9f86d3c72eb0e0bbffe856f6e213452d55c33b586c9cee21b42046af449a646b`。

实测 Diagnostics KPM SHA-256：`4691049088e40ea0738a0add0f63da2864b7bcd45285c491e1aea4b1c9be73dc`。

APK 使用本地测试签名，SO 已打包。签名私钥、设备管理凭据和设备专用 BTF 不发布。公开模块测试密钥及加载步骤见 [README](../README.md#加载集成模块)。

## 本次发布前复测

设备为 Pixel 6 / Android 16 / Linux `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，4 KiB 页；设备已有完整 Diagnostics 模块，版本为 1.2.5。模块文件与本轮重建哈希一致，未热卸载、未重启。两款附件 APK 均由当前源码重建、签名验证、覆盖安装后执行。

| 项目 | 本轮结果 |
|---|---|
| 主机 ASAN/UBSAN | 生产辅助代码、预算/影像各 80,000 次并发操作、17,968 项 leaf 检查、18 组 GUP、4,096 组 ZVA、10,000 次索引发布、指令/窗口/ABI/CLI/KCLF/RELRO 测试通过 |
| 核心模型 | 4,152 项核心自检、4,194,304 个扫描指令字、192 个 HINT/屏障组合、46 项 KCLF、24 项 RELRO 检查通过 |
| 保存 BTF | 5.15.74、6.1.134、6.12、6.18、6.18/16K 静态回归通过；不代表这些平台均完成设备测试 |
| 构建 | 普通、Diagnostics、OverlayOnly KPM，API、两个 APK、10 个 Android 测试工具成功；19 个用户态 ELF 的 16K LOAD / 4K 与 16K RELRO 检查通过 |
| 基础 APK | `RESULT PASS checks=73 failures=0` |
| RX 生命周期 | 606 项父断言通过；部分迁移与 SET 下 1,138,802 次三通道检查，同页 SET 下 514,747 次三通道检查；子进程保护/缺页/迁移/替换与 RX 退役检查通过 |
| 默认资源会话 | 三页覆盖、执行值保持、完整释放通过 |
| CRC 集成 APK | manual、linker 各三轮，十页三通道 CRC、执行返回值、四线程压力、活动覆盖下 probe 与清理均通过；`assertions_failed=0` |
| 最终状态 | `writes=rx`、inactive，pages/armed/degraded/failures=0；`memory.used=0`；无 KCLF 请求及 manual 驻留镜像；本轮 crash buffer 无记录 |

现有模块已加载，本轮没有重新执行“无模块”基线；CRC App 对该阶段明确跳过。此前 1.2.5 审计中的预算负例、禁用 fork、experimental、无模块基线与其他设备记录保留为独立历史证据，详见 [1.2.5 审计](compatibility-audit-1.2.5.zh-CN.md)，不混作本轮新增测试。主机和设备并发测试不替代 TSan；原审计中 TSan 启动失败，不能计为通过。

本次日志位于本地忽略目录 `out/release-v1.2.5/` 和 `out/release-validation-tests/`，Release 提供可公开的验证摘要。设备日志自身时间与电脑日期不同；文档日期按 Asia/Shanghai 的 2026-11-14 记录，不以设备 logcat 时钟推断发布日期。

## 使用边界

- `compat` 仍明确输出 `refault_atomic=0` 与 `hot_unload=0`。缺页后原生 PTE 发布至重新设陷阱之间仍有窗口；inactive 和 used=0 不能证明安全热卸载。更新模块使用受控重启。
- 本机 `ptl=apply-existing`、`readv_refs=PIN`、`contpte=0`。需要拆分连续 PTE 组的页面会拒绝；不把模型通过当作连续 PTE 真机证据。
- 只覆盖满足契约的文件 RX 页及支持的读取指令/内核入口；不是任意指令、任意写者、任意 pin/DMA 或跨页事务的一致性保证。
- 16 KiB 实机、其他内核配置与 OverlayOnly/loader=off 独立加载没有本轮设备证据。新平台仍须通过运行时准入和相应设备回归。

更多原因、失败路径与复现实例见 [当前技术博客](implementation-1.2.5.zh-CN.md) 和 [设计契约](DESIGN.md)。
