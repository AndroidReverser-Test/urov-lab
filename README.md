# UROV-Z

## 中文

Android ARM64 用户态代码页读取覆盖实验模块，基于 UROV-Y 2.28.0，固定使用 **PAGE_AP / all-callers**。执行原始代码，数据读取由注册的影像替代；无需配置读取指令地址或调用者白名单。详细原理、ABI、兼容条件和限制见 [DESIGN.md](DESIGN.md)。

源码分为 `module/`、`app/` 和独立用户态库 `api/`；`out/` 中的 KPM、APK、测试日志、密钥与 BTF 不进入 Git。原实现可从 `dev` / `3679b4f` 查看。2026-11-11 的实现审查、修复证据和未解决问题见 [AUDIT.md](AUDIT.md)。当前 `main` 发布 UROV-Z 1.0.0；已编译 KPM、测试 APK 与校验值见 [Releases](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.0.0)，本次 Pixel 6 发布验证见 [RELEASE-1.0.0.md](RELEASE-1.0.0.md)。

用户态 C/C++ 接口见 [api/README.md](api/README.md)：查询、注册、更新、状态和注销均已封装；无需应用自己实现 syscall 参数和 MAC。构建静态库/动态库：`.\api\build.ps1 -Ndk <NDK目录>`。

### 编译

需要 Windows PowerShell、Android NDK、SDK、JDK（本次使用 NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36、JDK 21），以及提供 KPM 头文件的 KernelPatch 源码树。测试 APK 不需要 Gradle 或联网下载依赖。

```powershell
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk D:\androidSDK\ndk\26.1.10909125
.\app\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
```

输出：`out/urov-z.kpm`、`out/app/urov-z-test.apk`，以及可选的 `urovz-query` / `compat-check` 测试工具。APK 使用 `out/app/debug.keystore` 本地测试签名。

### 加载、测试、卸载

设备须已安装可加载 KPM 的 KernelPatch。`KP_KEY` 是设备的 kpatch superkey；`MODULE_KEY` 是另外生成的 16 字节模块密钥，二者不同。以下命令在电脑的 PowerShell 中运行，填写实际 superkey。

```powershell
$KP_KEY = '<device-superkey>'
$MODULE_KEY = python -c 'import secrets; print(secrets.token_hex(16))'
adb push out/urov-z.kpm /data/local/tmp/urov-z.kpm
adb shell "/data/local/tmp/kpatch $KP_KEY kpm load /data/local/tmp/urov-z.kpm 'key=$MODULE_KEY verbose'"
adb install -r out/app/urov-z-test.apk
.\app\test.ps1 -ModuleKey $MODULE_KEY
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z status
```

也可打开 **UROV-Z Lab**，填写模块密钥后点“运行完整测试”。App 在普通 `untrusted_app` 域运行；测试前后验证原始值，测试结束自动 `DEACTIVATE`，结果保存在 App 的 `files/report.txt`，同时输出 `UROVZ` logcat。`test.ps1` 会重启此测试 App，请等上一轮结束再运行。

确认测试 `RESULT PASS`，且模块状态为 `inactive pages=0 armed=0` 后卸载：

```powershell
adb shell /data/local/tmp/kpatch $KP_KEY kpm unload urov-z
.\app\test.ps1 -Baseline
```

**旧版 KernelPatch 必须先注销再卸载。** 存活的 fork 子进程会使注销返回 `EBUSY`；先让它退出或 exec。若测试 App 已异常退出，可在睡眠上下文中触发死会话回收，然后重新查询全局状态：

```powershell
adb push out/app/urovz-query /data/local/tmp/urovz-query
adb shell chmod 755 /data/local/tmp/urovz-query
adb shell /data/local/tmp/urovz-query $MODULE_KEY
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z status
```

`urovz-query` 的 `state` 仅针对调用者；**以 `ctl0 status` 判断全局是否可卸载**。该工具不能强行注销仍被其他进程使用的会话。

### 兼容性与参数

- 实机证据：小米 13 / fuxi，Android 13，Linux 5.15.74，4 KB；Pixel 6 / oriole，Android 16，Linux 6.1.134，4 KB。API 接入后两台设备的 App 均在 live / detached BTF 下通过 73 项，模块自检 4152 项；Pixel 6 的本次发布验证详见发布记录。6.12 / 6.18 / 16 KB 目前仅有 BTF 静态验证。
- 兼容目标为 Linux **5.4–6.x**、AArch64、4 KB / 16 KB 普通页。必须具备可识别的符号和准确 BTF；不支持的布局/页表会拒绝加载。5.0–5.3、32 位 App、64 KB、LPA2 未支持。
- 可选加载参数：`verbose`、`max_pages=N`（1–4096）、`max_kb=N`（64–65536，默认 8192，仅主影像池）、`btf=/absolute/path/kernel.uzbtf`。没有其他模式或 caller 参数。
- 目标必须是可读可执行、当前不可写的文件映射；普通私有 `.text` 最适合测试。使用未带标签的用户地址。App 明确禁用 native heap pointer tagging。
- 这是测试框架；并发改映射、写入/原子指令、原生单步重放、页表锁与观察范围存在限制，详见设计文档。运行成功不代表对任意程序透明。

无内置 BTF 时，用**同一内核构建**的 `vmlinux` 生成包并推送，再增加 `btf=` 参数；Build ID 不一致会拒绝加载。

```powershell
python module/package_btf.py --vmlinux path/to/vmlinux out/kernel.uzbtf
# 或：--notes kernel.notes --btf kernel.btf out/kernel.uzbtf
adb push out/kernel.uzbtf /data/local/tmp/kernel.uzbtf
```

## English

UROV-Z is an Android ARM64 code-page read-overlay experiment derived from UROV-Y 2.28.0. It uses **PAGE_AP / all-callers only**: original instructions execute while supported data reads receive a registered image. No reader-site addresses or caller allowlist are required. [DESIGN.md](DESIGN.md) describes the implementation, ABI, compatibility conditions and limitations.

This branch contains module, App and standalone userspace API sources. Generated KPM/APK files, logs, keys and BTF remain under ignored `out/`. The original implementation remains in `dev` / `3679b4f`. See [AUDIT.md](AUDIT.md) for the review and unresolved limitations, and [api/README.md](api/README.md) for the C/C++ API, static/shared libraries and CMake integration. Current `main` publishes UROV-Z 1.0.0: download the KPM, test APK and checksums from [Releases](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.0.0). [RELEASE-1.0.0.md](RELEASE-1.0.0.md) records the current Pixel 6 release validation.

### Build

Use Windows PowerShell, Android NDK/SDK, JDK and a KernelPatch source tree providing KPM headers. Verified tools: NDK 26.1.10909125, Build Tools 36.0.0, android-36 and JDK 21. No Gradle or dependency download is required. Run the two build commands in the Chinese section, adjusting paths. Outputs are `out/urov-z.kpm`, `out/app/urov-z-test.apk`, `urovz-query` and `compat-check`. A local debug signing key is generated under `out/app/`.

### Load and use

The device must already support KernelPatch modules. Set `KP_KEY` to its kpatch superkey and generate a separate random 32-hex-character `MODULE_KEY`. Follow the load/install/test commands above, or enter the module key in **UROV-Z Lab** and press **Run tests**. The App runs as an ordinary `untrusted_app`, automatically deactivates its session and writes `files/report.txt` and the `UROVZ` logcat tag. The PowerShell test script restarts this App; wait for any previous run to finish.

After `RESULT PASS`, verify global `ctl0 status` reports `inactive pages=0 armed=0`; then unload and run `app/test.ps1 -Baseline`. **Deactivate before unloading on legacy KernelPatch.** Deactivation returns `EBUSY` while a child snapshot is still live; let that child exit or exec first. If the owner crashed, the `urovz-query` commands above trigger dead-owner cleanup in a sleepable syscall. Its state is caller-local; always check global `ctl0 status` before unloading. It cannot forcibly deactivate a live foreign session.

### Compatibility

Xiaomi 13 / fuxi / Android 13 / Linux 5.15.74 / 4 KB and Pixel 6 / oriole / Android 16 / Linux 6.1.134 / 4 KB both passed 73 App checks through the API and 4152 core checks with live and detached BTF. The release record documents the current Pixel 6 runs. Linux 6.12, 6.18 and 16 KB configurations have BTF inspection results only, not runtime certification.

The target range is **Linux 5.4–6.x**, AArch64 and ordinary 4 KB / 16 KB pages, subject to validated symbols, BTF and translation geometry. Linux 5.0–5.3, AArch32, 64 KB and LPA2 are unsupported. Registration accepts readable executable, currently non-writable file mappings. Use untagged user addresses; this App disables native heap pointer tagging.

Optional load arguments are `verbose`, `max_pages=N` (1–4096), `max_kb=N` (64–65536; default 8192, main image pool only), and `btf=/absolute/path/kernel.uzbtf`. There is no mode or caller selector. For a kernel without built-in BTF, package its exact-build `vmlinux` with the command above; a mismatched GNU Build ID is rejected.

This is a test framework. Concurrent mapping changes, writes/atomics, native single-step replay, page-table locking and coverage have explicit limits in the design document. A passing run does not establish transparency for arbitrary programs.
