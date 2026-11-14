# UROV-Z

## 中文

Android ARM64 用户态代码页读取覆盖实验模块，基于 UROV-Y 2.28.0，固定使用 **PAGE_AP / all-callers**。取指执行物理代码页，数据读取由注册的影像替代；无需配置读取指令地址或调用者白名单。详细原理、ABI、兼容条件和限制见 [DESIGN.md](DESIGN.md)。

当前工作版本为 **1.2.1：多页读取性能优化**，单 KPM 集成 KCLF 1.5.7。取指使用块扫描和全字节验证的负分析缓存；内核代读测试使用预触页的 64 KiB 缓冲。实现、实测和边界见 [优化记录](docs/performance-optimization-1.2.1.zh-CN.md)。`module/kclf/` 是内置加载器，`integration/` 提供 Dobby 注入 SO、十页 CRC 测试 App 和应用内复测入口；`Dobby/` 保持原样。集成流程见 [INTEGRATION.md](INTEGRATION.md)，历史实测见 [集成验证记录](integration/RESULTS-2026-11-12.md)。

`app/` 保留原有 73 项回归，`api/` 保留独立用户态库；`tests/` 新增块扫描、长 LL/SC、代码修改和页数扩展测试。`out/` 中的 KPM、APK、签名材料与 BTF 不进入 Git。当前 APK、KPM 和校验文件见 [Release v1.2.1](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.2.1) 与 [版本说明](RELEASE-1.2.1.md)；历史版本见 [Release v1.2.0](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.2.0)。内核实现分析见 [1.1.0 源码分析](docs/implementation-1.1.0.zh-CN.md)，当前测试实现见 [INTEGRATION.md](INTEGRATION.md)。

用户态 C/C++ 接口见 [api/README.md](api/README.md)：查询、注册、更新、状态和注销均已封装；无需应用自己实现 syscall 参数和 MAC。构建静态库/动态库：`.\api\build.ps1 -Ndk <NDK目录>`。

### 编译

需要 Windows PowerShell、Android NDK、SDK、JDK（本次使用 NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36、JDK 21），以及提供 KPM 头文件的 KernelPatch 源码树。测试 APK 不需要 Gradle 或联网下载依赖。

```powershell
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk D:\androidSDK\ndk\26.1.10909125
.\app\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
.\integration\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
```

主要输出：

| 文件 | 用途 |
|---|---|
| `out/urov-z.kpm` | 包含读取覆盖和 KCLF 加载器的单一 KPM |
| `out/app/urov-z-test.apk` | 原有 73 项读取覆盖/API 回归 App |
| `out/integration/urov-injection-test.apk` | SO 注入、Dobby hook、CRC 联合测试 App |
| `out/integration/native/libuzpayload.so` | 使用 Dobby 修改测试函数参数和返回值的 SO |
| `out/integration/native/libuzprobe.so` | 活动覆盖期间再次注入的读取/执行探针 |

`app/build.ps1` 还生成 `out/app/urovz-query` 和 `compat-check`。两种 APK 分别使用各自 `out/app/`、`out/integration/` 下的本地测试签名。

### 加载集成模块

设备须已安装可加载 KPM 的 KernelPatch。以下命令在电脑的 **PowerShell** 中、从本仓库根目录执行；假定 ADB 已选中一台设备，多设备时给命令增加 `-s <serial>`。`KP_KEY` 是设备的 kpatch superkey，用于模块管理和注入；测试 `MODULE_KEY` 固定为项目名 `urov-lab`（UTF-8、无换行）的 MD5：`59f5c4618474864a61d5469295548064`。模块密钥与设备 SuperKey 不同；设备 SuperKey 不写入源码或文件。

仅加载 `urov-z.kpm`，不再单独加载 `kclf.kpm`。已有模块需要替换时按后文的受控重启流程处理，不直接热卸载重载。

```powershell
$KP_KEY = '<device-superkey>'
$MODULE_KEY = '59f5c4618474864a61d5469295548064' # MD5(urov-lab)
adb push out/urov-z.kpm /data/local/tmp/urov-z.kpm
adb shell "/data/local/tmp/kpatch $KP_KEY kpm load /data/local/tmp/urov-z.kpm 'key=$MODULE_KEY verbose'"
adb shell /data/local/tmp/kpatch $KP_KEY kpm list
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z status
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,probe
```

统一控制格式是 `kpm ctl0 urov-z <控制字符串>`。`status` 查询全局读取覆盖状态；`kclf,status` 查询注入请求。所有加载器命令都在控制字符串中带 `kclf,` 前缀，例如 `kclf,inject,...`，不是向名为 `kclf` 的另一个 KPM 发命令。

KPM 管理层也可使用以下查询，与后文的模块内部控制命令区分：

| 命令 | 用途 |
|---|---|
| `adb shell /data/local/tmp/kpatch $KP_KEY kpm num` | 已加载 KPM 的数量；应用首次自动加载要求为 0 |
| `adb shell /data/local/tmp/kpatch $KP_KEY kpm list` | 列出已加载模块名；集成模块名为 `urov-z` |
| `adb shell /data/local/tmp/kpatch $KP_KEY kpm info urov-z` | 查看版本、描述和加载参数；加载参数包含 `key=`，分享输出前须脱敏 |

### 将 SO 注入指定进程

注入实际指定的是目标进程中的 **TID（线程 ID）**；主线程的 TID 等于 PID。应选择已知不持有用户态锁、且 x16/IP0 不再使用的协作边界。本仓库测试 App 使用 `uz-inject` 线程；任意主线程或任意 syscall 边界不自动满足这些条件。

命令语法如下，方括号表示可选项，不要原样输入：

```text
kclf,inject,<tid>,<设备端SO绝对路径>[,manual|linker][,wake|resume][,force][,unload][,keepelf]
```

下面给出查找进程、查看线程和提交注入的完整命令。示例包名、PID、TID、SO 路径均需替换为实际值；`manual` 和 `linker` 两条注入命令是两种选择，不要为一次注入连续执行两条。

```powershell
$PACKAGE = 'com.example.target'
adb shell pidof $PACKAGE
$TARGET_PID = 12345  # 替换为上一步选定进程的 PID
adb shell "/data/local/tmp/kpatch $KP_KEY su -c 'ps -T -p $TARGET_PID -o TID,CMD'"
$TARGET_TID = 12367  # 替换为该进程中选定的协作线程 TID
$SO_PATH = '/data/app/~~.../com.example.target-.../lib/arm64/libpayload.so'

# 选择一：manual，自行映射、重定位 SO；省略后端选项时也是 manual
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,inject,$TARGET_TID,$SO_PATH,manual,wake"

# 选择二：linker，在目标用户态调用 bionic loader
# adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,inject,$TARGET_TID,$SO_PATH,linker,wake"

# 重复查询，等待请求和清理完成
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,status
```

**SO 路径与后端要求：**

- 路径是设备端的绝对路径，不是电脑上的 `E:\...`。SO 必须已存在，为支持的 64 位小端 AArch64 ELF 共享库（ET_DYN）。路径最多 255 字节，不能包含逗号、空格或其他空白分隔符；外层引号不能转义模块内部的这些分隔符。
- 文件由目标进程的凭据访问，必须满足目录访问、读取和 SELinux 条件。控制端 root 不会让普通 App 自动获得 `/data/local/tmp` 的访问权限。
- `manual` 使用匿名镜像，依赖须已加载且保持有效；不支持 ELF PT_TLS，也不提供完整 JNI/C++ loader 集成。它可使用目标能读取的路径，例如 App 自有文件目录，仍受设备映射策略限制。
- `linker` 还受目标 linker namespace 和文件可执行映射限制。测试将 SO 打包进 APK，安装到真实的 native library 目录，但不由 App 主动加载。优先使用 App 的 `ApplicationInfo.nativeLibraryDir`；`dumpsys package` 的 `legacyNativeLibraryDir` 可能只到 `/lib`，ARM64 库实际在其 `/arm64` 子目录，必须核对真实文件路径。

**如何判断成功：** `queued id=...` 只表示请求入队。继续查看 `kclf,status`，直到对应请求 `state=done`、`handle` 非零，且不再出现 `pending=` 或临时 `map=`；检查 `err=` 和清理结果。manual 显示 `via=manual`、`image=...`、`refs=...`，linker 显示实际 loader 入口，例如 `via=__loader_dlopen`。`resident=...` 是保留的 manual 镜像，不是待清理的临时 `map=`。还应通过 SO 自身的日志、构造函数标记或功能效果确认执行成功。`state=failed/cancelled` 不是成功；保存状态后再 `reap`，不要盲目重复注入。

| 请求状态/字段 | 应如何处理 |
|---|---|
| `armed` | 已排队、尚未开始准备；可能在等线程返回用户态，仍可尝试 cancel |
| `preparing` / `ready` / `running` | 分别处于准备映射、等待重定向、执行用户态程序阶段；继续轮询，不对同一请求重复 inject |
| `done`，但有 `pending=` 或临时 `map=` | 完成 token 已观察到，但回调或映射清理尚未完成；不能据此释放仍在使用的资源 |
| `failed` / `cancelled` | 记录 `stage=`、`err=` 和剩余映射，诊断后 reap；不能将失败当作自动回滚一切的证明 |
| `no requests` | 请求表为空；可能尚未注入，也可能结果已被 reap，不能单独证明加载成功或 SO 已卸载 |

`state` 是请求状态，`stage` 表示当前或最后处理阶段；两者不是一一对应的成功标志。比如已完成请求通常显示 `state=done stage=restore`。

### 注入选项

| 选项 | 含义与限制 |
|---|---|
| `manual` / `linker` | 二选一；默认 `manual`。不能重复指定或同时指定 |
| `resume` | 默认行为：等待线程自然返回用户态，不主动唤醒。它是 inject/release 的通知选项，不是恢复 quiesce 的命令 |
| `wake` | 使用支持的 task_work 通知唤醒可中断睡眠；与 `resume` 互斥。不保证任意阻塞线程立即运行，不支持时返回 `EOPNOTSUPP` |
| `force` | 只跳过安全点启发式，不消除锁、x16 恢复、namespace、权限或 ABI 限制；正常测试不需要使用 |
| `unload` | 本次加载后释放相应引用。新 manual 镜像在构造后执行析构并解除映射；linker 调用 dlclose，是否实际解除映射取决于引用计数等规则。省略时保持驻留 |
| `keepelf` | 仅 manual 可用，保留内存 ELF/program headers；不把匿名映射变为文件映射，不能与 `linker` 一起使用 |

有持续 hook、线程、定时器或回调的 SO 不应使用 `unload`，框架不会替 payload 停止这些使用者。重复注入同一路径不保证再次运行构造函数；重复 `inject,...,unload` 也不能代替释放先前保留的引用。涉及 Dobby 与读取覆盖时，先读 [API 中的 Dobby 限制](api/README.md#与-dobby-hook-联合使用的限制)，按“保存原页 → hook → REGISTER”以及“DEACTIVATE → 撤销 hook → 释放 SO”的顺序处理。

### 其他控制命令

下表的控制字符串均作为 `adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z` 的最后一个参数：

| 控制字符串 | 用途 |
|---|---|
| `status` | UROV 全局状态：active/inactive、页数、armed、hits、failures、能力等；不是注入状态 |
| `selftest` | 与 `status` 相同，显示初始化时已完成的 `core_checks` 等状态；不会重新运行 App 或内核自检 |
| `perf` | 1.2.1 取指/扫描/缓存诊断累计计数；普通构建为 `diagnostics=0`，加 `-Diagnostics` 才开启计数 |
| `kclf` / `kclf,help` | 显示加载器帮助；帮助中的子命令用于集成版时仍需带 `kclf,` 前缀 |
| `kclf,probe` | 运行时兼容性诊断：内核布局、BTF、pt_regs、页大小、唤醒支持、观察 hook、quiescing 状态等 |
| `kclf,sym` | 内核符号解析诊断，用于排查 ABI/符号缺失；输出可能包含内核地址 |
| `kclf,status` | 列出请求槽、请求 ID、目标线程、阶段、结果和清理状态；同时推动运行中请求的完成轮询 |
| `kclf,images[,cursor]` | 分页列出 manual 驻留镜像；有 `next=N` 时继续 `kclf,images,N`。不枚举 linker 驻留 SO |
| `kclf,release,<tid>,<image-id>[,wake\|resume][,force]` | 对指定目标 mm 中的 manual 镜像释放一个引用；最后一个引用释放时执行析构/解除映射。仍是异步请求，需查询 status |
| `kclf,cancel,<slot>` | 取消仍处于 armed、尚未开始准备的请求；使用 `#0` 等显示的槽号 0–3，不是请求 ID 或镜像 ID。已开始执行时返回 EBUSY |
| `kclf,reap` | 回收可清理的完成/失败/取消请求槽及死亡目标记录；不卸载仍在存活进程中使用的 SO，也不注销 UROV 覆盖 |
| `kclf,quiesce` | 停止接受新 inject，尝试取消尚未开始的加载并检查排空情况；release 仍允许。返回 idle 或 busy，busy 时需继续清理 |

TID、slot、image-id 和 cursor 都使用十进制，不带 `0x`。`status` 的 `#N` 是请求槽，`id=N` 是请求 ID，`images` 的 `image=N` 才是 manual 镜像 ID；不能把 `handle`、`base` 地址或请求 ID 当作 release 参数。

例如，在确认 payload 的线程/回调已停止、UROV 覆盖已注销且 Dobby hook 已撤销后，释放 manual 引用：

```powershell
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,images
# 若输出 next=2，则使用输出的游标继续读取
# adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,images,2
$IMAGE_ID = 7  # 替换为目标进程实际的 image= 编号
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,release,$TARGET_TID,$IMAGE_ID,wake"
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,status
# 等该 release 完成后回收请求槽，再检查引用数
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,reap
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,images
```

`TARGET_TID` 必须仍属于该镜像所在的目标地址空间；`refs` 大于一时一次 release 只减一。`nodelete=emutls/elf` 镜像在目标 mm 存活时不能 release，应先使目标进程退出再 reap。linker 驻留 SO 不支持此 release 命令，须由目标按其引用生命周期调用 dlclose，或随进程退出释放；`no manual images` 不表示 linker SO 已卸载。

取消尚未开始的请求，以及可选地停止接受后续注入：

```powershell
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,status
$SLOT = 0  # 替换为仍处于 armed 的 #槽号
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,cancel,$SLOT"
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,reap

# 仅在本轮不再注入时执行
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,quiesce
```

`quiesce` 没有对应的恢复命令；`resume` 选项不会重新开放加载器。即使返回 busy，停止接收新注入也已生效。恢复注入或更换 KPM 时，在当前宿主上使用受控重启后重新加载。`quiesce=idle` 只表示加载器自身可跟踪的工作已排空，不证明所有 linker SO 已卸载，也不证明 KP 跳板可安全热卸载。

### 常见错误与排查

先保留 `kclf,status` 中的 `stage=`、`err=`，再结合 `kclf,probe` 检查，不要看到失败就追加 `force` 或再次注入。

| 现象 | 检查方向 |
|---|---|
| `unknown, duplicate or conflicting option` / `EINVAL` | 检查 `kclf,` 前缀、参数数量、十进制 TID、绝对路径，以及互斥或重复选项；`linker,keepelf` 不合法 |
| `no such task` / `ESRCH` | 目标可能退出或重启；重新确认 PID、TID 及所属进程，不继续使用旧编号 |
| `task already has a request` / `no free request slot` / `EBUSY` | 查看最多四个请求槽的状态；等待在途工作结束并 reap 可回收槽，不强行清除运行中请求 |
| `manual: open library failed rc=-2` | ENOENT：确认真实设备路径和文件存在，尤其 `/lib` 与 `/lib/arm64` 的区别 |
| 打开/映射权限错误，或 linker 的 `dlerror` | 核对目标凭据、SELinux、namespace、依赖及 SO ABI；控制端 root 和 force 都不能代替这些条件 |
| `EOPNOTSUPP` | 结合具体 stage/err 与 probe 确认布局、wake、观察路径或 ELF 特性是否支持，不能仅凭 errno 推断唯一原因 |
| `cleanup incomplete` 或完成后持续出现临时 `map=` | 清理未完成；继续检查目标线程状态，保留现场，不能把 reap 当作强制 unmap |
| `module quiescing` / `ESHUTDOWN` | 本实例已停止接受 inject；resume 不是恢复命令，按受控重启/加载流程处理 |

对读取覆盖 API，密钥错误或模块缺失通常返回 `-EINVAL`；这与 KCLF 命令参数错误属于不同控制通道。相关失败的状态核对见 [API 文档](api/README.md)。

### 复测流程（无需 PowerShell 脚本）

1. 从 [Releases](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.2.1) 下载 `urov-z.kpm`、`urov-injection-test.apk` 和 `urov-z-test.apk`。在下载目录执行：

   ~~~text
   adb push urov-z.kpm /data/local/tmp/urov-z.kpm
   adb install -r urov-injection-test.apk
   adb install -r urov-z-test.apk
   ~~~

2. 设备首次加载前应无 KPM；若已有旧版或使用其他密钥的模块，先受控重启。打开 **UROV CRC Lab**，输入设备 kpatch SuperKey，选择 `manual`、默认 3 轮，点“运行 / 复测”。App 自动加载设备端 KPM；模块测试密钥固定为 `MD5(urov-lab) = 59f5c4618474864a61d5469295548064`，无需填写模块密钥。
3. 等待最终 **PASS** 后，切换 `linker`，再运行 3 轮。界面显示整段及十页三通道 CRC；10 个函数每秒实测并输出实际/期望返回值，切换及单次计时期间延后。覆盖生效时，应同时看到 **CRC 与基线一致、返回值为 hook 后值、10/10 页通过**；未覆盖的 hook 阶段应检出代码修改。计时仅简要显示三通道前/后中位数。
4. 最终 PASS 表示该轮检查通过，覆盖已注销、hook 已撤销。后续可直接点击“运行 / 复测”。需要原有 73 项回归时，等待 CRC 测试结束，再打开 **UROV-Z Lab** 点击“运行完整测试”。

每轮包含 10 个独立内存页上的 Dobby hook、4 线程的 96 次整段 CRC 和 20,480 次调用，以及活动覆盖期间再次注入探针。结果只显示在界面和 logcat，不写结果或密钥文件；日志可实时查看：

~~~text
adb logcat -v brief -s UROVZ-CRC:I UROVZ:I *:S
~~~

只有首次运行前 KPM 数量为零时才采集“模块未加载”耗时；已有模块时明确跳过该项，比较同一进程中的“已 hook 未覆盖 / 十页覆盖”。更新 KPM 使用受控重启，不热卸载。实现与计时口径见 [INTEGRATION.md](INTEGRATION.md)。

### 清理与更换模块

测试结束先在 owner 中 `DEACTIVATE`，撤销 Dobby hook，再停止测试进程并回收加载器状态：

```powershell
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,reap
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,status
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,images
```

**当前宿主不执行 KPM 热卸载/重新加载。** `inactive` 和 `no requests` 不能证明旧 hook 跳板已无在途调用；更新 KPM 使用受控重启。默认关闭可选 native step 只是缓解措施，未修复宿主的跳板回收。存活的 fork 子进程会使注销返回 `EBUSY`；先让它退出或 exec。若测试 App 已异常退出，可在睡眠上下文中触发死会话回收，然后重新查询全局状态：

```powershell
adb push out/app/urovz-query /data/local/tmp/urovz-query
adb shell chmod 755 /data/local/tmp/urovz-query
adb shell /data/local/tmp/urovz-query
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z status
```

`urovz-query` 的 `state` 仅针对调用者；以 `ctl0 status` 检查全局覆盖状态。该工具不能强行注销仍被其他进程使用的会话，状态 inactive 也不构成热卸载安全证明。

### 兼容性与参数

- 1.1.0 集成版在 Pixel 6 / Android 16 / Linux 6.1.134 / 4 KB 上通过 manual/linker 各 3 轮及原有 73 项回归。历史 1.0.0 在小米 13 / Linux 5.15.74 和 Pixel 6 有 live / detached BTF 证据；不能将这些历史结果视为集成版的跨设备验证。6.12 / 6.18 / 16 KB 仍无集成运行验证。
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

The current version is **1.2.1**, with KCLF 1.5.7 linked into `urov-z.kpm`. It adds block instruction reads, negative LL/SC analysis reuse with complete byte validation on every hit, and pre-touched 64 KiB readv/proc test buffers. See the [implementation and measurements](docs/performance-optimization-1.2.1.zh-CN.md). `Dobby/` remains unchanged; the independent API and original 73-check App are retained. Binaries and checksums are available in [Release 1.2.1](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.2.1); see the [release notes](RELEASE-1.2.1.md). Generated artifacts remain under ignored `out/`.

### Build

Use Windows PowerShell, Android NDK/SDK, JDK and a KernelPatch source tree providing KPM headers. Verified tools: NDK 26.1.10909125, Build Tools 36.0.0, android-36 and JDK 21. No Gradle or dependency download is required. Run the three build commands above, adjusting paths. They produce the integrated KPM, the original regression APK and tools, and `out/integration/urov-injection-test.apk` with `native/libuzpayload.so` and `native/libuzprobe.so`. Each App build generates its own local debug signing key.

### Load and use

The device must support KernelPatch modules. The test module key is always MD5 of the UTF-8 project name `urov-lab` without a newline: `59f5c4618474864a61d5469295548064`. The device superkey is separate. Open **UROV CRC Lab**, enter that device superkey, select manual/linker and 1–20 cycles, and tap **Run / Retest**. Results stay in the UI and logcat (`UROVZ-CRC`); no report, command, address or key files are written. **UROV-Z Lab** uses the same fixed module key for its original checks and logs to `UROVZ`.

After testing, deactivate the overlay, remove the Dobby hook, stop the test process and reap KCLF. Leave the KPM loaded: the current host does not prove safe retirement of in-flight hook trampolines. Use a controlled reboot to replace the KPM. Native step is disabled by default, but this does not repair host-level hot unloading. If the owner crashed, `urovz-query` triggers dead-owner cleanup in a sleepable syscall; its state is caller-local. Global inactivity is not proof of unload safety.

### Injecting a shared library

Load only `urov-z.kpm`. Every command targets `kpm ctl0 urov-z`; loader commands use the `kclf,` prefix. The module key authenticates the overlay API, while `KP_KEY` authorizes these administrator commands.

At the KPM management level, `kpm num` reports the module count, `kpm list` lists names, and `kpm info urov-z` reports metadata and load arguments. Redact the `key=` argument before sharing info output.

Select a cooperative thread in the intended process. A main thread's TID equals its PID, but neither an arbitrary main thread nor a syscall boundary is automatically safe: the target must not hold relevant user locks, and x16/IP0 must be dead at the return boundary. Replace the example TID and device-side path below. Use one injection backend per request:

```powershell
$TARGET_TID = 12367  # Replace with the selected target thread ID
$SO_PATH = '/data/app/~~.../com.example.target-.../lib/arm64/libpayload.so'
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,probe
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,inject,$TARGET_TID,$SO_PATH,manual,wake"
# Alternative backend; do not execute both for a single load:
# adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z "kclf,inject,$TARGET_TID,$SO_PATH,linker,wake"
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z kclf,status
```

The SO must already exist at an absolute device path, at most 255 bytes with no commas or whitespace, and be a supported ELF64 little-endian AArch64 shared object. Target credentials and SELinux apply; controller root does not make `/data/local/tmp` universally accessible to ordinary Apps. Linker additionally enforces its namespace and executable-file mapping rules. Use the actual `ApplicationInfo.nativeLibraryDir`; a dumpsys `legacyNativeLibraryDir` may refer to the parent `/lib` rather than `/lib/arm64`. Manual uses anonymous mappings and requires dependencies to be loaded and remain available; it does not provide ELF PT_TLS or complete JNI/C++ loader integration.

`queued` means accepted, not completed. Poll `kclf,status` until the corresponding request has `state=done`, a nonzero handle, no `pending=` or transient `map=`, and no unresolved error. Manual `resident=` describes the retained image, not a pending transient mapping. Independently verify a constructor marker or the intended payload behavior before reaping the request. Failed/cancelled requests are not successful loads.

Armed means queued; preparing/ready/running are intermediate states. Done can still have cleanup pending. `no requests` only describes an empty request table and proves neither load success nor payload removal. Preserve `stage=`, `err=` and remaining mappings before reap: open `rc=-2` indicates a missing path, slot/task EBUSY calls for waiting and eligible reaping, and `module quiescing` requires the documented restart procedure. For permission, namespace, ABI or unsupported-feature errors, use probe and the specific loader diagnostic; force does not bypass those requirements.

Injection options are `manual|linker` (default manual), `wake|resume` (default resume), `force`, `unload`, and `keepelf`. Resume waits for natural return to userspace; wake requests a supported interruptible task-work wakeup. Force only skips the safe-point heuristic. Keepelf preserves manual ELF headers and cannot be combined with linker. Unload releases this load's reference after initialization; it does not stop threads, callbacks or hooks, and must not be used for a persistent hook payload. Repeating inject with unload does not release an earlier retained reference.

### Control command reference

Pass each string as the last argument to `adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z`:

| Control string | Meaning |
|---|---|
| `status` / `selftest` | Global overlay status, including the already completed core checks; selftest is an alias, not a new test run |
| `perf` | Lifetime scan/cache counters; build with `-Diagnostics` to enable them (off in normal builds) |
| `kclf` / `kclf,help` | Loader help; prepend `kclf,` to its displayed subcommands when using the integrated module |
| `kclf,probe` | Runtime ABI, layout, page size, wake and completion-observation diagnostics |
| `kclf,sym` | Kernel-symbol diagnostics; output may contain kernel addresses |
| `kclf,status` | Request table, results and cleanup state; also schedules completion polling |
| `kclf,images[,cursor]` | Manual images only; follow `next=N` with `kclf,images,N` |
| `kclf,release,<tid>,<image-id>[,wake\|resume][,force]` | Asynchronously release one manual reference in the target mm; poll status for completion |
| `kclf,cancel,<slot>` | Cancel an armed request before preparation starts; slot is the displayed `#N`, 0–3 |
| `kclf,reap` | Reclaim eligible completed slots and dead-target records; does not unload live payloads or deactivate overlays |
| `kclf,quiesce` | Disable new injections, attempt queued-load cancellation and check drain state; release remains available |

All numeric command arguments are decimal. Request `#slot`, request `id=`, manual `image=`, and loader `handle` are distinct. Release uses the `image=` ID and a live TID from that image's address space, not its handle or request ID. Each release decrements one reference; the last releases the image. Images marked `nodelete=emutls/elf` require target-process exit followed by reap. Linker images are not listed by images and cannot be released through this manual command; their lifetime requires target-side dlclose with correct reference ownership, or process exit.

Quiesce has no resume command. The `resume` notification option does not re-enable injections, and quiesce disables new injections even when it returns busy. On the current host, use a controlled reboot and reload to reopen the loader. Neither idle nor `no manual images` proves that linker SOs are gone or that KP trampolines can be hot-unloaded safely.

Overlay REGISTER/SET/STATUS/DEACTIVATE are owner-process [API calls](api/README.md), not ctl0 commands. Injection does not automatically install a Dobby hook or register an overlay. Follow the [Dobby constraints](api/README.md#与-dobby-hook-联合使用的限制): save the original page before hook installation, register only after patching, and deactivate before removing hooks or releasing the payload.

Integration tests now run in a fresh private Android service process for every button press. Ten 16-KiB-aligned Dobby targets are checked for distinct runtime pages. Each cycle validates per-page and whole-code CRCs through three read paths, performs 96 concurrent CRC scans and 20,480 function calls using four threads, reinjects a probe while the overlay is active, then deactivates and removes every hook. The UI shows baseline and actual CRCs with stage verdicts, plus ten fresh function return values sampled every second (deferred during mutations, injection and timed reads). Timing uses two warmups and nine samples per channel, with a single concise before/after median line per comparison. A truly module-absent baseline is collected only before the first load; subsequent runs explicitly skip it and compare inactive/active overlays in the same process. Build scripts remain, but the PowerShell retest scripts and file-based result exchange have been removed. See [INTEGRATION.md](INTEGRATION.md).

### Compatibility

The 1.1.0 integration passed both injection backends (three cycles each), 73 App checks and 4152 core checks on Pixel 6 / Android 16 / Linux 6.1.134 / 4 KB. Earlier Xiaomi and detached-BTF results apply to the previous standalone version. Linux 6.12, 6.18 and 16 KB configurations have no integrated runtime validation.

The target range is **Linux 5.4–6.x**, AArch64 and ordinary 4 KB / 16 KB pages, subject to validated symbols, BTF and translation geometry. Linux 5.0–5.3, AArch32, 64 KB and LPA2 are unsupported. Registration accepts readable executable, currently non-writable file mappings. Use untagged user addresses; this App disables native heap pointer tagging.

Optional load arguments are `verbose`, `max_pages=N` (1–4096), `max_kb=N` (64–65536; default 8192, main image pool only), and `btf=/absolute/path/kernel.uzbtf`. There is no mode or caller selector. For a kernel without built-in BTF, package its exact-build `vmlinux` with the command above; a mismatched GNU Build ID is rejected.

This is a test framework. Concurrent mapping changes, writes/atomics, native single-step replay, page-table locking and coverage have explicit limits in the design document. A passing run does not establish transparency for arbitrary programs.
