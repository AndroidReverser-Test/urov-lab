# UROV-LAB 普通 App 检测分析与实测

报告日期：2026-11-04（Asia/Shanghai）。分析对象为子仓库提交 `d560871` 的
`urov-lab`，本轮没有修改 KPM 后端、解码器或模拟器。

**结论：当前实现可以由普通 App 稳定识别。建议保留控制通道指纹、会话归属和
已知不可变代码的文件/标量读取差异；不把时间差或 smaps 标记当作定罪条件。**
前两项来自同一控制通道，不是两条独立证据。文件差异表示所采样代码的完整性异常，
单独出现时不应归因于 UROV。

正式验证为 **8 次运行、84 组用例、15,579 项断言，全部通过**。修改样本 723 个、
未修改样本 1,750 个，内容差异检测均符合预期。这个结果只描述下面的设备、模块版本、
样本和运行条件，不是面向全部 Android 设备的误报率或无故障保证。

## 1. 设备与交付文件

| 项目 | 本轮记录 |
|---|---|
| 设备 | Pixel 6 / oriole，序列号 `25091FDF60063J` |
| 系统 | Android 16 / SDK 36，`BP31.250610.009` |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` / arm64 / 4096 字节页 |
| KernelPatch | `0xc00` |
| 模块能力 | `caps=0xeb7`，`hooks=0xf`，核心自测 4139 项 |
| 检测 App | `com.example.urovdetect`，UID 10284 |
| 独立观察 App | `com.example.urovobserver`，UID 10287 |
| 两个 App 的权限 | `untrusted_app`、`CapEff=0`、`Seccomp=2`，无 root 授权 |
| 初始 / 最终模块列表 | 均为空 |

设备时钟实际为 `2025-10-01`，因此原始 logcat 行以 `10-01` 开头；没有调整设备时间。
结果目录的时间使用宿主 UTC+8，与本报告日期一致。

- 检测核心：[native/urov_detect.c](native/urov_detect.c)、[头文件及调用约束](native/urov_detect.h)。
- 测试 App：[apps/urov-detect](apps/urov-detect)，独立构建，无 Gradle 依赖。
- APK：[检测 App](apps/urov-detect/out/urovdetect.apk)、[独立观察 App](apps/urov-detect/out/urovobserver.apk)。
- 自动化：[tools/run_detection_device.py](tools/run_detection_device.py)。
- 正式原始结果：[summary.json](results/detection-20261104-213849/summary.json)。

SHA256：

```text
16b86f80c8799c1d00aab650e553955fe8955459c6d6f6f23037c16005e1c1cf  urov-lab.kpm
ba1182aadc800955cf7df3f0feb2c17b65a0adc6e2135c7050f8a75d869119d3  urovdetect.apk
08abb6f08c81c77d7aaf35952a4e4c14b117ef0fb5730558f21949bd8f96308a  urovobserver.apk
```

## 2. 实际实现

### 2.1 装载与控制

`urov_kpm.c` 导出 KPM 元数据、init/exit 和 `ctl0 status/selftest`。
`urov_backend_init()` 先执行 4139 项软件核心自测，通过 kallsyms 解析 fault、mm、
pin、TLB 和 nofault copy 等内核函数，然后安装 `do_mem_abort` before hook、
`kcmp`/`prctl` syscall hook，以及 5 个映射修改 syscall hook。
`hooks=0xf` 是四类 hook 的汇总位，不是仅有四个被 hook 的入口。

用户 ABI 为固定 128 字节、version 2 的 `urov_request`。普通 App 使用：

```c
syscall(__NR_prctl, 0x55524f56L, 0x55524f5653595343L,
        command, &request, 128L);
```

只有 option 和 magic 都匹配才截获。QUERY、REGISTER、SET、STATUS、DEACTIVATE
共用 `notify_dispatch()`。入口先复制并验证请求，再尝试获取控制忙标志；争用返回
`EBUSY`。`kcmp` 是旧/root 通道，本轮普通 App 检测器不调用它。

### 2.2 注册、原页与伪值

全模块只有一个 `g_sess`，归属于注册调用者的 `current->mm`。注册目标必须是一页
文件后备的只读可执行映射，不能有 `VM_WRITE`、`VM_MAYWRITE` 等标志。
普通 linker 的多页 `MAP_PRIVATE .text` 不满足这个模型；测试使用自身已安装
`.so` 的专用一页 `MAP_SHARED` RX 别名。这个实现是合作注册模型，不能直接为
另一个任意 App 的地址空间注册覆盖。

`do_register()` 依次持有 mm 引用、pin 用户页、获取 mmap 写锁，重新校验 VMA/PTE，
并复制整页原始内容。之后发布 base/offset/length、原页快照、最多 32 字节伪值及
generation，同步修改 `vm_page_prot` 和 PTE：清 `PTE_USER/AP[1]`，保留取指条件，
最后刷新该 mm 的 TLB。

所以它没有改写代码字节。取指继续执行原页；数据访问因权限异常进入软件模拟。
`/proc/self/maps` 仍可显示 `r-xs`，不能根据 maps 的 `r` 推断实际数据读取没有异常。

SET 使用序列锁发布四个 64 位字和新 generation。单条模拟指令使用同一份伪值快照。

### 2.3 fault 与解码/模拟

`urov_abort_before()` 只接管 A64 EL0 读数据异常、末级 permission fault，且 mm 和
FAR 必须命中当前会话。PC 在受保护页时，从保存的原页取 opcode，否则通过内核
nofault copy 取 opcode。

`decode.c` 白名单支持普通 GPR 的 1/2/4/8 字节 load、符号扩展、多种寻址和 GPR
pair load。`emulate.c` 校验有效地址、FAR、ESR、用户上下文及页内范围，再按字节从
原页/伪值窗口合成结果。全部验证成功才写回 GPR/SP/PC，PC 前进 4 字节，hits 增加。
覆盖窗口以外的字节也经模拟，但结果来自原页快照。

SIMD/FP、acquire/exclusive/atomic、未知编码、跨页和部分调试上下文不受支持，
会进入 fail-closed 的 SIGSEGV 路径。因此检测核心明确使用内联汇编 `LDRB`，
不会对目标地址调用 libc `memcpy`/`memcmp`，避免它们选用 SIMD。

### 2.4 会话、映射与卸载

SET/STATUS/DEACTIVATE 检查 mm 所有权。非 owner 的 QUERY 隐藏 session/generation，
但仍返回全局 caps，并以 `last_error=-EBUSY` 暴露“存在其他活会话”。

映射门控拦截与 owner 目标页相交的 mprotect、munmap、mremap、madvise 和
`mmap(MAP_FIXED)`，返回 `EBUSY`。普通 App 通过尝试修改业务页来检测不符合本任务
的无干扰要求，所以交付检测核心不使用这些探针。

注销/卸载先恢复页权限和 VMA 模板、刷新 TLB、停止活动并等待 handler，再 unpin/mmput。
owner 死亡后，下一次控制请求可按 `mm_users==1` 惰性回收。
因此 QUERY 不修改活会话的伪值或代次，但可能顺便回收已经死亡的 owner，不能把它
描述成内核中绝无副作用的查询。

task/mm/VMA 的多个偏移是按本设备 BTF 硬编码的，例如 task->mm 为 1440、
mm->pgd 为 56、mm_users 为 68；这也限制了后端跨内核的适用范围。

## 3. 可采用的检测点

| 检测点 | 通过条件 | 结果含义与边界 |
|---|---|---|
| option/magic/ABI 指纹 | 错 magic 原样返回原生 EINVAL；两次不同 request_id 的有效 QUERY 均成功，ABI、能力、状态编码及回显字段一致 | 高特异性地识别当前 UROV ABI；不把单个 errno 或成功码当作证据 |
| QUERY 会话归属 | 两次查询的状态、session、generation、offset、length、last_error 稳定 | ACTIVE/session=1 为自身 mm；INACTIVE/last_error=-EBUSY 为其他 mm；INACTIVE/last_error=0 为空闲 |
| 标量读取 / 安装文件差异 | 已知不可变 RX 代码和同一映射的文件字节，在三个完整回合里各自稳定但互不相等 | 确认样本读取完整性异常；单独出现不能区分 UROV、普通代码补丁或其他来源 |

文件比对实现先后检查 VMA 和文件身份、dev/inode、准确文件偏移、范围与文件长度。
每回合执行“文件 pread → 标量读取 → 文件 pread → 标量读取”，共三回合；最后再验证
VMA 及文件 size/mtime/ctime。任意差错、短读、身份不符、变化或不稳定都返回 UNKNOWN。
`pread` 不改变调用者的文件当前位置，适合与其他读取者共享保留的 fd；该语义见
[Linux pread 文档](https://man7.org/linux/man-pages/man2/pread.2.html)。

必须区分“模块存在”“自身有会话”和“所采样字节发生差异”。例如伪值恰好等于原值，
或采样未覆盖修改窗口时，文件检测应为未命中，而 QUERY 仍可识别自身会话。
本轮对这两个情形都做了负向验证。

## 4. smaps 的实际偏差与不采用的路径

### 4.1 当前模块设置的是 rr，不是 dc

源码 `UROV_VM_DONTCOPY=0x00010000`，但 Linux 6.1 的实际定义为：

```text
VM_RAND_READ = 0x00010000
VM_DONTCOPY  = 0x00020000
```

对应定义见 [Linux v6.1 include/linux/mm.h](https://raw.githubusercontent.com/torvalds/linux/v6.1/include/linux/mm.h)，
smaps 缩写见 [Linux 6.1 proc 文档](https://www.kernel.org/doc/html/v6.1/filesystems/proc.html)。
本机活动覆盖实测 `rr=1, dc=0`，注销后 `rr=0, dc=0`。
此外，源码的 `UROV_VM_IO=0x2000` 在上游 6.1 实际对应 VM_LOCKED；这是静态分析发现，
本轮未构造设备/IO VMA 进行验证。

已有 fork 验收仅验证子进程读不到可接受值；收到 SIGSEGV 或其他失败也会通过，
不能据此证明 VMA 根本没有继承。因此旧文档的“设置 dc / fork 不继承”描述需要修正。
本轮保留原始 KPM，以保证检测的是原实现。

`MADV_RANDOM` 合法产生相同的 rr；`MADV_DONTFORK` 合法产生 dc。
本轮两种正常映射均未被判成内容伪造。所以 rr/dc 和单页 r-xs 别名只输出诊断信息，
均不作为独立阳性条件。

### 4.2 内核辅助读取不能笼统视为安全

- **write(pipe) / copy_from_user：排除。** 早期实验把受保护地址直接传给非阻塞 pipe
  的 write。后台线程持续重试，直到手动卸载模块才恢复；单次检查耗时约 87.5 秒，
  当时 hits=0。证据保存在 [被拒绝的 pipe 实验](results/detection-rejected-pipe-pilot.log)。
  非阻塞 pipe 只约束管道容量等待，不能约束用户地址的缺页处理。源码只处理 EL0
  异常；Linux arm64 uaccess 可使用 LDTR 家族，见
  [copy_from_user.S](https://raw.githubusercontent.com/torvalds/linux/v6.1/arch/arm64/lib/copy_from_user.S)。
  这些现象与 EL1 uaccess 权限异常持续重试相符；本轮未取得完整内核故障跟踪，
  不把具体故障调用栈当成已证实结论。最终代码没有此路径或回退。
- **/proc/self/mem：排除。** 普通 App 实测 open 返回 EACCES(13)。权限不足不是模块
  阳性，最终检测核心不访问它。
- **process_vm_readv / ptrace：不采用。** 没有作为正式 App 检测路径执行；设备策略、
  seccomp 和权限差异不适合本任务的稳定性要求，也不把其可用性当作检测信号。
- **SIMD、原子/独占 load、故意触发 SIGSEGV、fork、映射修改：不采用。** 可能进入
  fail-closed、改变进程状态或与 ART/业务生命周期冲突。
- **读取耗时阈值：不采用。** 异常成本确实可观，但调度、DVFS、后台限额及冷页也会
  产生延迟，不能作为高准确率结论。

### 4.3 已跳过的反例

测试夹具尝试构造普通 MAP_PRIVATE 代码补丁作为反例。在这台设备上，改写后恢复 RX
被 SELinux execmod 拒绝，errno=13，因此该反例记录为 SKIP，不计入通过用例及样本数。
没有通过关闭 SELinux、修改 seccomp 或给检测 App 提权来让它通过。
文件差异本身的归因限制仍然适用，不能因为此反例未执行就把文件差异单独当作 UROV。

## 5. 正式测试结果

检测和观察均在无 root 的 App 内执行。root 仅用于模块装卸、状态真值和设备日志。
App 内控制夹具只对自己的专用页做 REGISTER/SET/DEACTIVATE，和检测核心分开。

| 情形 | 指纹 / scope | 文件差异 | 结果 |
|---|---|---|---|
| 未装模块 | 未命中 / UNKNOWN | 未命中 | PASS |
| 已装但空闲 | 命中 / IDLE | 未命中 | PASS |
| 8/16/24/32 字节窗口，fake A/B | 命中 / SELF | 命中，首差异为样本内 offset=4 | 每种状态 30 次，3 轮，PASS |
| 活动页但样本在窗口之外 | 命中 / SELF | 未命中 | PASS |
| 活动会话但 fake 等于原字节 | 命中 / SELF | 未命中 | PASS |
| 每次注销后 | 命中 / IDLE | 未命中 | PASS |
| 合法 DONTFORK / RANDOM | 按真值返回 | 未命中，dc/rr 不参与判断 | PASS |
| 其他 UID 持有活会话 | 命中 / OTHER | 观察者自身代码未命中 | PASS |
| owner 运行时卸载 | 指纹消失 / UNKNOWN | 恢复未命中 | PASS |
| 无 fd、错误文件偏移、跨页、PROT_NONE | 不以错误推断模块 | UNKNOWN | PASS |

本轮统计：

- 指纹命中样本 2,283 个，未命中 190 个，均与模块装卸真值一致。
- SELF 归属样本 1,443 个；跨 UID 的 OTHER 归属样本 90 个。
- 文件差异阳性 723 个，阴性 1,750 个，均符合对应内容真值。它们是同设备重复样本，
  不是独立设备统计；阴性中包含“存在自身会话但样本没有变化”的情形。
- 每轮 fake A 检查的 hits 增加 11,520，generation 保持 1，failures 为 0，符合
  30 × 3 回合 × 2 次 × 64 字节的显式 LDRB 读取数。读取会增加 hits，检测不改变伪值。
- 跨 UID 观察前后，owner 的完整状态字符串相同：ACTIVE、generation=1、hits=1152、
  failures=0。观察者未修改 owner 会话，也没有读取其地址空间。
- 并行业务线程持续执行正常 lib 和受保护别名中的原始函数，并做普通管道 I/O。
  累计业务循环 **6,932,224 次，错误 0**。
- 八次运行的 UI 心跳最大间隔 **28 ms**；测试不在 UI 线程执行。
- 检测前后 errno、SIGSEGV/SIGBUS/SIGSYS/SIGPIPE handler、线程名、所采样 VMA 属性
  保持预期。检测打开的 /proc fd 无累积泄漏。ART/渲染线程会自行开关其他 fd，
  总 fd 数波动单独记录，不据此误报检测器泄漏。
- 正式实验窗口新增内核日志没有检出 BUG/WARNING/Oops/panic/RCU stall/hung task；
  最终 `kpm list` 为空。

App 日志和内核增量均在
[results/detection-20261104-213849](results/detection-20261104-213849)；
原始 [机器结果](results/detection-20261104-213849/summary.json)
含各用例、断言数、耗时、UID、artifact hash 和装卸状态。

## 6. 业务接入条件与耗时

正式测量中，前台各用例的控制检测中位数为 **1–5 µs**，文件检查中位数为
**2.725–3.143 ms**。可选 smaps 诊断中位数为 **7.965–8.826 ms**，不需要放入业务
常规检测。owner 被观察者遮挡后，后台的文件检查中位数为 **35.451 ms**、P95 为
**42.236 ms**，smaps 中位数达 **92.708 ms**；这也是不采用耗时定罪、不在主线程运行
或高频全内存扫描的原因。

推荐先在低频后台任务中调用 `ud_probe_control()`，记录模块指纹和 scope。
需要确认自身已知代码时，再调用 `ud_check_views()`。结果用于告警或诊断，不接入
退出、阻塞业务或强制异常流程。两个函数保留 errno，不安装信号处理器，不调整
调试、SELinux、seccomp、线程优先级或业务映射。

文件比较前，业务必须持有目标映射和 fd 的生命周期，使用相应锁或确定不 dlclose 的
常驻模块。仅采样自己已知无 relocation/热补丁/JIT 变化的不可变 RX 指令，长度最多
256 字节且不跨页。文件偏移来自目标 VMA 的映射偏移加地址差，不能把虚拟地址直接
当成 ELF 文件偏移，也不能把运行时读取的代码当成唯一可信基线。
读取 `/proc/self/maps` 自身不能消除并发 unmap 的竞态；内核文档也明确说明
[maps/smaps 读取存在竞态](https://www.kernel.org/doc/html/v6.1/filesystems/proc.html)。

本轮检查的是当前 ABI 和本机后端。其他版本、被隐藏的控制通道、不同页大小/内核、
不可用的元数据、被修改的安装文件或对采样范围之外的覆盖，需要单独验证；
UNKNOWN 和未命中都不表示设备被证明安全。只有控制通道检查可以在完全不读取
受保护代码的情况下识别会话；普通标量读取在此版本的正常 EL0 上下文中已通过测试，
无法对任意内核、恶意内核或任意调试上下文保证不故障。

## 7. 复现

在仓库根目录执行，密钥通过参数传入，结果文件不记录密钥：

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_detection_device.py `
    --serial 25091FDF60063J --key <KEY> --repeats 30 --cycles 3
```

脚本遇到已经加载的同名模块会保留现场并停止；只卸载本次加载的模块，只 force-stop
两个专用测试包，不清空全局 logcat。APK 默认按钮执行被动检查，显式 clean/idle/
active/hold/observer 模式用于上述自动化夹具。
native 编译开启 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`，已通过 Clang 静态分析；
产物反汇编确认目标复制循环使用 `LDRB`。Python 脚本通过语法检查。
