# UROV-Z 1.1.0

2026-11-12，Android ARM64 实验性预发布。单个 `urov-z.kpm` 集成 PAGE_AP /
all-callers 代码页读取覆盖和 KCLF 1.5.7 加载器。

## 相比 1.0.0

- 内置 KCLF manual/linker 两种 SO 加载后端，控制命令统一为
  `kpm ctl0 urov-z kclf,<command>`，不需要另外加载 `kclf.kpm`。
- 加载器内部通过同步真实内存接口读取 ELF，注入 SO 保持普通 all-callers
  读取语义；修正 GNU_RELRO 页尾 padding 的专用范围检查。
- 默认关闭可选 native-step hook，保留普通 RX 读取覆盖及原 ABI v1 API。
- 恢复 `dev` 中原样的 Dobby 源码，增加独立注入 App、payload、probe、
  RELRO 测试和设备脚本，验证参数/返回值修改与代码段 CRC 覆盖。
- 增补实现分析、集成操作说明及验证记录。Git 仅跟踪源码、构建脚本、许可和
  文档；编译文件、构建缓存、密钥、BTF 和原始运行日志不进入源码提交。

## 下载附件

| 附件 | 用途 |
|---|---|
| `urov-z.kpm` | 集成模块，AArch64 ELF64 relocatable |
| `urov-z-test.apk` | 原有 73 项读取覆盖/API 回归 App |
| `urov-injection-test.apk` | KCLF、Dobby、代码段 CRC 联合测试 App |
| `libuzhost.so`、`libuzpayload.so`、`libuzprobe.so` | 联合测试的宿主、hook payload 和活动覆盖探针 |
| `liburovz.so` | 原回归 App 的 ARM64 native 库，亦包含于 APK |
| `liburov.a`、`liburov.so` | 独立用户态 API 静态库及动态库；头文件在 `api/include/` |
| `urov-query`、`urovz-query` | API 示例及 App 配套查询工具 |
| `compat-check`、`relro-test` | 兼容诊断与 RELRO 边界断言工具 |
| `BUILD-INFO.txt`、`SHA256SUMS` | 源码提交、构建环境、验证范围及全部交付文件校验值 |

APK 使用本地测试签名。签名私钥、设备 superkey 和模块 API 密钥均不在附件中。
API 及测试用户态程序以 Android API 26 / arm64-v8a 为构建目标；这不代表
任意 Android 26+ 内核都兼容 KPM。

## 本次发布验证

使用 NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36、JDK 21、
CMake 3.22.1 / Ninja 和工作区 KernelPatch 头文件，重新构建 KPM、API、原
回归 APK 及完整 integration native 目标。integration native 先执行 clean。
另从 KernelPatch 提交 `406c85ce79a5e1c19b53be34c04baadc1ec68bc5` 导出干净
头文件，在独立目录重建 KPM，得到完全相同的 SHA-256；发布 KPM 不依赖
外层工作树未提交的头文件修改。

- 所有构建及两套 APK 签名验证成功；KPM 保留一组 init/ctl0/exit 入口。
- 在连接的 ARM64 设备上运行现有核心自检模型：`CORE PASS checks=4152 result=0`。
- 运行本次构建的 `relro-test`：14 项断言通过，覆盖权限、越界、溢出与
  4K/16K 页尾算术；16K 算术通过不代表 16K 内核运行验证。
- KPM、libuzhost、libuzpayload、libuzprobe 的 SHA-256 与此前集成实测一致。
- 从设备取回此前实测安装包，确认其哈希与原验证记录一致。新 APK 的
  AndroidManifest、DEX、native SO 等全部非签名文件内容与原包相同；重打包
  后 APK 文件哈希变化，发布值以附件 `SHA256SUMS` 为准。

[此前实测记录](RESULTS-2026-11-12.md)包含 Pixel 6 / Android 16 /
Linux 6.1.134 / 4 KiB 环境下，manual/linker 各三轮、30 个 App 报告、7,680 次
函数调用及原有 73 项 App 回归。**本次发布没有重跑完整注入或覆盖生命周期，
也没有热卸载/重载设备 KPM。**

## 使用与边界

请先阅读 [README](../README.md)、[当前源码分析](implementation-1.1.0.zh-CN.md)
和 [集成说明](INTEGRATION.md)。在 GitHub Release 页面中，这些文档均可从
[v1.1.0 源码树](https://github.com/AndroidReverser-Test/urov-lab/tree/v1.1.0)访问。

REGISTER 限于满足条件的 RX 文件页，全局单一活动 owner mm。SO 注入依赖
协作线程边界、目标权限及后端支持的 ELF 特性。Dobby 的 literal 跳转不自动
兼容覆盖语义，测试使用近跳转并检查指令。宿主跳板回收与热卸载安全尚未验证；
替换 KPM 使用受控重启。未声明任意 App、任意指令、任意内核或 16 KiB 设备
的运行兼容性。
