# UROV / KCLF / Dobby 实现与应用内复测

当前测试流程（2026-11-13）：**10 个独立页面上的 Dobby hook、三通道 CRC、4 线程压力测试、模块/覆盖前后耗时对比**。测试直接在 **UROV CRC Lab** 中运行，结果通过内存、Binder 和 logcat 显示。构建仍使用 build.ps1；复测不需要 PowerShell 脚本，不生成报告、命令、上下文地址或密钥文件。历史单页结果见 integration/RESULTS-2026-11-12.md，不代表当前十页测试。

## 框架的实际实现

| 层次 | 源码 | 行为 |
|---|---|---|
| KPM 入口 | module/urov_z.c | 先初始化 UROV，再初始化内置 KCLF 1.5.7；status/selftest 查询覆盖状态，kclf, 前缀转发加载器控制 |
| 认证 API | api/src/urov.c、api/include/urov/auth.h | 16 字节模块密钥派生私有 prctl option 和 SipHash MAC；校验 ABI、结构大小、操作码、请求地址和 MAC |
| 会话注册 | module/backend.c | 全局一个活动 owner mm；验证完整、可读可执行、当前不可写的普通文件页；排序并拒绝重复描述符，保存原始/替代影像及映射身份 |
| 取指与数据读取 | ap_arm_pages、uz_abort_before | 清除叶子 PTE_USER/AP[1] 并刷新 TLB；取指执行真实代码，支持的 EL0 数据读取产生权限异常 |
| 指令模拟 | decode.c、emulate.c、uz_emulate_load | 解码 A64 load、按影像拼接数据，更新 GPR/FPSIMD、writeback 和 PC；不支持的指令不是成功 |
| 内核辅助读取 | uz_kread_after、GUP/PIN/process-vm 回调 | 替换相关读取缓冲区/页面，使 process_vm_readv、proc-mem 也取得注册影像 |
| 并发生命周期 | readers.h、release_session、copy_mm/映射回调 | 双 epoch 读者计数保护影像更新和回收；跟踪 fork、映射变化；注销恢复页权限并排空读者 |
| SO 加载 | module/kclf/ | 4 个请求槽，核对 task/mm；task_work 准备映射、重定向 EL0；manual 做 ELF 映射/重定位，linker 调用 bionic loader |

UROV 不修改函数指令。Dobby 修改真实入口，payload 在 hook **之前**保存十个原页，之后一次 REGISTER 十个描述符。CRC 数据读取取得原影像，函数执行仍进入 hook。UROV 在 REGISTER 时另存的真实快照已经包含 patch，用于真实页语义与指令读取。

host 在启动协作线程前，将测试上下文地址发布到进程内环境项 UROV_LAB_CONTEXT_V2；之后保持不变。payload/probe 经共享 libc 的 getenv 取得地址，并核对 magic 和 PID。该项不包含密钥，不写文件，也不新增 libuzhost.so 的 DT_NEEDED 依赖，因此 linker 的 default namespace 无需解析 App classloader namespace 中的宿主库。

KCLF 内部通过 kclf_urds → urov_z_read_current_real → uz_access_vm 取得真实字节，以免加载器解析到覆盖影像；这只用于同 KPM 的内部同步访问。新注入的 probe 仍遵守 all-callers，不享有读取豁免。manual 匿名 SO 自身不满足 RX 文件页注册条件，本测试覆盖的是 Android loader 加载的 libuzhost.so。

默认主影像预算 8 MiB，每个注册页占七页；4 KiB 设备对应 292 页上限。默认关闭可选 native step。可支持的指令、文件 VMA、BTF/内核布局、4K/16K 页配置仍是明确边界；十页测试不会证明任意程序的透明性。

## 十个 hook 如何保证分属不同页

integration/target.S 定义 uz_test_target_0 到 uz_test_target_9，每个入口使用 .balign 16384，末尾再次对齐，确保完整目标页位于可执行段。构建链接使用 max-page-size=16384。运行时用 sysconf(_SC_PAGESIZE) 检查 4K/16K，计算每个入口的实际页基址，逐对检查不重复，并检查完整页位于唯一 executable PT_LOAD 内。布局不符直接失败；日志输出十个地址和页基址。

每个目标有独立 replacement 和 original trampoline。第 i 个原函数为 a*7+b+17*i；输入 (3+i,4+2*i)，hook 调用 original(a+10,b*3)，再加 1000。每个检查阶段执行十个函数各 256 次，核对实参、原返回值和最终返回值，不能只靠一个函数或总 CRC 判定成功。

payload 强制 near trampoline，并逐个验证入口为 B imm26、目标页实际发生改变、跳转目的地位于所有覆盖页之外。覆盖页内的 LDR literal 远跳转会读到旧影像，不能用于此测试。部分安装失败按逆序撤销已安装 hook；撤销失败时保留记录和快照。REGISTER 错误后查询真实会话状态，避免把已提交但 copy-out 失败的注册误当作未生效。

## 测试流程与判定

1. 新建独立 :runner 进程，找到整段 RX 并保存整段和十页基线 CRC。
2. 使用设备 SuperKey 查询 KPM 数量。如果为零，先测 module_absent，再由 /data/local/tmp/kpatch 加载 /data/local/tmp/urov-z.kpm。若已有模块，明确输出 module_absent=SKIP，校验固定密钥和 inactive 状态。
3. 测 loaded_inactive；启动不持用户锁、SVC 返回后 x16 已死的 uz-inject 协作线程。
4. KCLF 注入 payload；根据本次请求 id 等待 DONE、非零 handle、没有 pending/map/err，再独立核对 constructor cookie。
5. 每轮执行 HOOK → CRC 检出十页修改 → OVERLAY → 三通道 CRC 恢复基线 → 压力测试 → 活动覆盖下再次注入 probe → DEACTIVATE → CRC 再次检出修改 → UNHOOK → 原函数和 CRC 恢复。
6. 每轮 probe 使用 unload 释放本次无后台工作的探针引用，核对构造次数递增、十个 hook 返回值和基线 CRC；驻留的 hook payload 不使用 unload。
7. 检查 inactive、无在途请求，结果发送给界面后退出测试进程。下次复测先 reap 死亡目标；每次均使用新进程，manual/linker 构造和 Dobby 分配不会串轮。

三通道是直接 EL0 数据读取、process_vm_readv、/proc/self/mem。每个阶段不仅比较整段 CRC，还分别核对十页在三通道上的 CRC。hooked_uncovered/deactivated 要求每一页都不同于原页；其他阶段要求每一页恢复原值。覆盖期间要求 registered=10、armed=10、hits>0、failures=0。

压力测试使用起跑同步的 4 个线程，每线程 8 轮，每轮十个函数各调用 64 次，再轮换顺序完成三通道整段 CRC。合计每周期 **20,480 次调用和 96 次 CRC**；所有线程 join 后才能注销或撤销 hook。日志单独显示 mismatch、armed、hits、failures。

## CRC 与定时返回值显示

界面独立展示整段 CRC 的基线、direct/readv/proc 三个实际值、完整性结论和阶段判定。hooked_uncovered/deactivated 阶段应当“检出代码修改”，该负对照符合预期时阶段判定仍为 PASS；覆盖启用或 hook 撤销后应当“与基线一致”。“展开 10 页 CRC 明细”显示每页的基线、三通道实际 CRC 和判定，成功页也输出 PAGE 日志。

测试运行期间，uz-returns 线程按约 1 秒周期重新调用全部十个函数入口；阶段切换后立即追加一组采样。RETURNS 行标明采样序号、时间、阶段和 hook/覆盖状态，接着十条 RETURN 行分别记录实际返回值、期望值、原始返回值、最近一次覆盖期实测值和 PASS/FAIL。任意一次实际值与期望不符，都计入最终失败。参数与原函数返回值仍由原有 256 次/函数及压力测试断言校验。

采样和安装/撤销 hook、注册/注销、KCLF 注入、单次 CRC 计时互斥：临界区内到期的采样延后，计时两端之间不执行采样调用或日志。压力测试期间继续采样。测试结束即停止定时线程；界面保留最后采样及覆盖期证据，不把清理后的原返回值误标为覆盖时返回值。

CRC、返回值和简短计时使用独立内存快照传到界面，最近日志使用 96 KiB 按完整行滚动的缓冲区。多轮运行超过日志缓冲区后，当前结果和最终 PASS/FAIL 仍可更新，logcat 持续接收输出。所有显示均不写文件。

## 耗时含义

使用 CLOCK_MONOTONIC 纳秒计时，统一转换为微秒。每个阶段每通道 2 次预热、9 次正式采样；每轮轮换通道顺序，每个样本核对 CRC。仅输出三通道的前/后中位数，每组比较一行 TIME；不再逐阶段输出均值、最小值、P95、差值和百分比。

计时范围是一次完整 executable PT_LOAD 的读取与 CRC。直接通道用明确的 LD1 四向量指令每次取 64 字节，再软件计算 IEEE CRC32，尾部按字节读取。1.2.1 起内核辅助通道使用每线程独立、预分配并预触页的 64 KiB 缓冲区加 zlib CRC32，逐次消费短读并重试 EINTR；proc 通道仍计入 open/close。204,608 字节范围的用户态 syscall 数由 50 次降至 4 次，内核内部仍可能逐页处理。主测试与四个压力线程不共享缓冲。比较只在**同一通道**前后进行；跨版本比较先使用相同 APK 隔离内核优化，再单独测试新缓冲尺寸。实测见 [1.2.1 优化记录](docs/performance-optimization-1.2.1.zh-CN.md)。

简短的 TIME compare= 日志提供（direct_us、readv_us、proc_us 的值均为“前/后”）：

- module_absent_to_loaded_inactive：真正未加载与已加载但未覆盖（仅本次起始无 KPM 时有效）。
- module_absent_to_overlay：真正未加载与十页覆盖生效（同上）。
- hooked_uncovered_to_overlay：相同 hook、相同进程、相同字节范围，仅覆盖关闭/开启。
- deactivated_to_overlay：覆盖测试后的关闭值，便于观察温度、调频、缓存和调度漂移。

hook、注册、注入、定时函数采样、日志和压力线程启动不在 CRC 计时区间。压力阶段的 elapsed_ms 是另一项并发总耗时。2 次预热和短样本不能消除所有 DVFS/调度影响，单次比值不能解释为精确固定开销。复测不为获得无模块基线而热卸载 KPM；需要新无模块样本时受控重启，再运行相同 APK。

## 构建与使用

固定模块测试密钥为 UTF-8 项目名 urov-lab（无换行）的 MD5：

    59f5c4618474864a61d5469295548064

唯一源码常量是 test_config.h，CRC payload、host、原有回归 App 和查询工具共享。设备 kpatch SuperKey 是另一层管理凭据，界面输入只保留在内存，不写入源码、配置或结果文件。测试中的错误密钥断言仍故意使用无效凭据。

在 urov-lab 根目录构建：

~~~powershell
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk D:\androidSDK\ndk\26.1.10909125
.\integration\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
.\app\build.ps1 -Sdk D:\androidSDK -Ndk D:\androidSDK\ndk\26.1.10909125
~~~

首次部署仅需：

~~~text
adb push out/urov-z.kpm /data/local/tmp/urov-z.kpm
adb install -r out/integration/urov-injection-test.apk
adb install -r out/app/urov-z-test.apk
~~~

打开 **UROV CRC Lab**，输入设备 kpatch SuperKey，选择 manual 或 linker、轮数 1–20（默认 3），点“运行 / 复测”。两种后端分别运行。状态、逐页检查、耗时和最终 PASS/FAIL 直接显示在界面；日志实时查看：

~~~text
adb logcat -v brief -s UROVZ-CRC:I *:S
~~~

也支持无需脚本的命令行启动；设备密钥替换占位符：

~~~text
adb shell am start -S -W -n com.example.urovzinject/.MainActivity --es superkey <device-superkey> --es backend manual --ei cycles 3 --ez autorun true
~~~

不要在上一轮仍运行时使用 -S。正常复测直接点击按钮。应用不从日志文件恢复结果；关闭界面进程后内存报告丢失。

原有 **UROV-Z Lab** 无需填写模块密钥，点击“运行完整测试”，或：

~~~text
adb shell am start -S -W -n com.example.urovz/.MainActivity --ez autorun true
adb logcat -v brief -s UROVZ:I *:S
~~~

integration/control.c 使用与 kpatch 相同的认证 supercall ABI 查询/控制 KPM，保持被测进程为普通应用 UID；只有首次加载模块时，临时子进程获取 root 并 exec 设备的 kpatch。活动覆盖期间不 fork 被测 owner，也不在注入期间让控制子进程继承测试页。

应用服务不导出，Binder 结果有大小上限，不保存密钥。注入超时/在途操作未知时不再操作 hook；进程退出后由认证 QUERY 和 reap 回收死亡会话。模块缺失、密钥不符、控制失败、CRC 错误、probe 失败或进程崩溃都不得判为通过。KPM 保持驻留；更新二进制仍采用受控重启，不热卸载。
