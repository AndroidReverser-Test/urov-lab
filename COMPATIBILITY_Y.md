# UROV-Y 2.6.0：实现、兼容性与代码审计

## 实现

`urov-lab`、`urov-x` 和 `urov-y` 共用 [AArch64 load 解码](decode.c)与
[软件模拟核心](emulate.c)。基础版让目标页的 EL0 数据读产生权限异常；X 变体增加
进程和读取点约束；Y 变体支持以下三种陷阱。三种模式都在异常中改写受支持的 load 的
目标寄存器与 PC，目标代码本身仍执行原字节。BRK 模式会改动另一处的读取指令。
2.5.0 只改变 `PAGE_AP` 的相邻 LL/SC 处理；2.6.0 在同一路径上增加 NOP 间隔与直接
分支门控；2.4.0 的内核接口、BTF 兼容矩阵和静态检查继续适用。

| 模式 | 陷阱与模拟边界 |
| --- | --- |
| `SITE_BRK` | 用内核 COW 路径把登记的私有只读读取指令换成 BRK。按 `mm`、PC 和 BRK 立即数匹配，只模拟登记的标量 load。恢复原指令后，该页仍可能保留 COW。 |
| `PAGE_UXN` | 在读取点页设置 UXN，按 EL0 叶级取指权限异常接管。读取点支持标量 load；同一页只放受支持的 `RET X30`、NOP 和 BTI hint，拒绝带 BTI Guarded Page 位的 PTE。 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，处理 EL0 数据读权限异常；取指仍由硬件执行。支持多页、跨页、FPSIMD、LD1/2/3/4，拒绝任意写、缓存维护及其他来源的异常。2.5.0 对紧邻且执行存证成立的 `LDXR/LDAXR; load; STXR/STLXR` 完成原 store；2.6.0 允许中间 0–3 个 NOP，并在代写前扫描 ±256 字节的直接分支，目标落到 load 时不代写。 |

[控制 ABI](urov_y_abi.h) 使用带 MAC 的 `prctl` 请求。`REGISTER` 绑定调用者 `mm`，
核对目标 RX 映射与页数组，复制原始快照并为每页构建覆盖镜像。故障先匹配会话与陷阱，
再根据 `x30` 和最多 16 层有效 `x29` 帧链选镜像；返回地址带 PAC 时，仅去签名后比较。
无窗口时匹配所有该 `mm` 的调用。未命中窗口时从注册快照重放；跨页 load 的未登记部分用
nofault 读真实地址。未知指令或不可安全读取的地址会走信号或内核原异常路径。

`SET` / `SET_PAGE` 先校验代际号并写入备用缓冲，原子交换镜像指针，然后等旧读者退出才
复用旧缓冲。单条 load 对同一页只取一份镜像；跨页不承诺多个页更新为同一事务。控制注销、
覆盖范围内的映射变更、进程换 `mm` 或 fork/vfork 前先停覆盖与重装，再恢复陷阱，最后关闭
读侧、等待引用清空并释放快照。仅 `CLONE_VM` 的普通线程保留会话。具体见
[内核后端](urov_y_backend.c)和[读者状态机](urov_y_readers.h)。

## 兼容决策

| 差异 | 2.4.0 的选择 |
| --- | --- |
| MM/VMA 和页表 | 用 BTF 解析 task、mm、VMA 和寄存器帧；优先成对的 `mmap_write_lock/unlock`，或按 BTF 的 `mmap_lock` / `mmap_sem` 偏移调用 rwsem。TCR 提供 TTBR0 范围及 4/16 KiB 页长，要求宿主遍历几何匹配。 |
| 缺页和异常入口 | 接受三、四参数 `handle_mm_fault` 及 BTF 验证的五参数厂商入口；公有入口缺少原型时保留八个参数寄存器。BRK 支持 `brk_handler` 和 `do_el0_brk64`；数据异常支持 32/64 位 ESR 形参，仅在 BTF 确认全宽时检查 ISS2。缺页回调提前取 `mm` 和地址，返回后不访问可能失效的 VMA，跳过未完成的 fault。 |
| 远程内存与分配 | 优先公有五参数 `access_remote_vm`，私有 `__access_remote_vm` 按 BTF 匹配的五/六参数原型调用。用户读取可用 `copy_from_user_nofault` 或旧 `probe_user_read`；无 nofault 写时仅 App 控制回包可使用普通可写 GUP。`FOLL_FORCE` 优先取 BTF，缺少枚举时用 6.3 作为回退分界。分配器支持原名及 `_noprof`，与各自释放接口配对。 |
| FPSIMD | 优先 `fpsimd_save_and_flush_current_state`，旧内核回退到 `fpsimd_signal_preserve_current_state`，用对齐的局部副本交给 `fpsimd_update_current_state`。保存状态布局和 helper 不匹配时不给向量能力；拒绝操作有 SVE/SME 状态的任务。 |
| 能力发现 | ABI v8 请求仍为 288 字节；`QUERY` 报告 `page_stride`（页位移 12/14）、`page_count`（有效上限）和 `session_flags`（支持模式及功能）。BRK 与页陷阱独立探测，均不可用则拒绝加载；缺文件布局/接口时不报告 `SRC_FILE`。 |

接口核对依据：[Linux 5.4 缺页 ABI](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/memory.c)、
[5.4 nofault 读取](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/maccess.c)、
[5.10 远程 VM](https://raw.githubusercontent.com/torvalds/linux/v5.10/mm/memory.c)、
[6.3 GUP 标志](https://raw.githubusercontent.com/torvalds/linux/v6.3/include/linux/mm_types.h)、
[6.6 VMA 锁](https://raw.githubusercontent.com/torvalds/linux/v6.6/mm/mmap.c)、
[6.12 分配接口](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/vmalloc.h)、
[6.18 BRK 入口](https://raw.githubusercontent.com/torvalds/linux/v6.18/arch/arm64/kernel/debug-monitors.c)、
[6.18 FPSIMD](https://raw.githubusercontent.com/torvalds/linux/v6.18/arch/arm64/kernel/fpsimd.c)、
[ARM64 返回地址 PAC](https://raw.githubusercontent.com/torvalds/linux/v6.18/arch/arm64/include/asm/compiler.h)。

适配目标为 [Android 5.4 起的 5.x/6.x](https://source.android.com/docs/core/architecture/kernel/android-common)，
仅 ARM64 小端 EL0，要求宿主 KernelPatch 提供兼容的 hook 与页表遍历。4 KiB 与满足几何
检查的 16 KiB 页可以加载；64 KiB、LPA2、超 48 位物理地址、TTBR0/TTBR1 不同遍历深度均
拒绝。每页占原始快照和双镜像三份空间：默认 `max_kb=8192` 时为 682 个 4 KiB 页或 170 个
16 KiB 页，`max_pages` 可再限页数。版本号不能替代厂商内核实际符号、布局和功能验证。

## 审计结论

| 旧实现问题 | 2.4.0 处理 |
| --- | --- |
| 先做 `page_size - len` 的无符号运算，超长描述符可能让长度检查下溢。 | 按先长度、再偏移的顺序检查；核对地址区间、描述符步长、保留位、重复页和数据源。失败的 SET 不发布镜像或增加代际。 |
| 会话拆除与异常回调并行时，原来的有界等待可能先释放页数组或镜像。 | 页表陷阱生效前准备重放数据；读侧进入、换代和关闭用同一原子状态。撤销先停重装，恢复陷阱后再收回读引用。恢复失败会保留会话供重试，`ctl0 status` 显示 `degraded=1`。 |
| LL/SC 桥用寄存器值推断硬件独占状态，可能把本来应失败的 `STXR` 变成写入。 | 2.5.0 恢复相邻桥，但只对 `LDXR` 结果仍在 `Rt`、待写值等于 `[Xn]` 且 `Xt!=XZR` 的序列代写；分支跳过 `LDXR` 的序列保持原生失败和零写入。非紧邻、成对独占不桥。 |
| AP 目标本身含读取指令时，从 PC 作数据读可能也触发权限故障；厂商库保存的 PAC 返回地址使窗口误判。 | 目标页上的指令从原始快照取码；PAC 只在比较时剥离，不改用户寄存器或栈。 |
| KernelPatch 0.12.0 在 RCU 读侧调用 KPM exit。BRK 撤销中的 Tasks RCU 等待可能自锁。 | KPM exit 跳过 Tasks RCU 等待。旧宿主由 owner App 在自己的 `prctl` 控制路径先执行 `DEACTIVATE`，确认状态空闲后再卸载。 |

模块适用于受控的 App 自测。页表写入使用 KernelPatch 页表遍历、RCU、CAS 和 TLB 刷新，
仍缺少 Linux 原生 PTE 锁与映射更新协议的保证。内核回收、远程变更及已有在途的映射操作
仍可能与重装竞争。在途 hook 的安全回收与 exit 失败时能否保留模块也取决于宿主版本。
常规流程是先 `DEACTIVATE` 再卸载。活动卸载测试选项要求加载器明确报告 `sleepable-v2`。
[Linux PTE 锁文档](https://cdn.kernel.org/doc/html/latest/mm/split_page_table_lock.html)、
[KernelPatch 0.12.0 加载器](https://raw.githubusercontent.com/bmax121/KernelPatch/0.12.0/kernel/patch/module/module.c)。

大页/连续 PTE、SVE/SME、MTE 标签地址、独占/acquire、PKEY/GCS 等特殊访问未承诺；
文件后备与目标代码在会话中应保持稳定。调用窗口由 App 提供，不是安全隔离边界。
`ctl0 status` 只走无缺页回包，旧内核缺 helper 时用 App 的 `QUERY` / `STATUS`。

### 没有内置 BTF 时

用**与运行内核同一构建**的 AArch64 `vmlinux` 制作布局包。如果该 ELF 没有
`.BTF`，可用 `pahole --btf_encode_detached kernel.btf vmlinux` 从其 DWARF
生成原始 BTF，再在打包时加 `--btf kernel.btf`。也可用 `--notes` 和 `--btf`
打包同一设备取得的二进制 `/sys/kernel/notes` 和原始 BTF。

```sh
python kpms/urov-lab/tools/package_y_btf.py --vmlinux vmlinux kernel.uybtf
adb push kernel.uybtf /data/local/tmp/kernel.uybtf
adb push kpms/urov-lab/out/urov-y.kpm /data/local/tmp/urov-y.kpm
adb shell "/data/local/tmp/kpatch <KP_KEY> kpm load /data/local/tmp/urov-y.kpm 'key=<32_HEX> btf=/data/local/tmp/kernel.uybtf verbose'"
```

模块在安装 hook 前检查包头和运行内核的 GNU Build ID。需要运行内核公开 note 边界
符号，并使用可信的同构建 BTF；缺少可信布局时拒绝加载。

## 2.4.0 验收（2026-11-07）

| 环境 | 结果 |
| --- | --- |
| 小米 13，Android 13，5.15.74，4 KiB，KernelPatch `0xc00` | [CRC 9 项](results/crc-20261107-092216/summary.json)和[生命周期 11 项](results/eliminate-20261107-092015/summary.json)均通过。覆盖 BRK、UXN、AP、厂商 `libz`、4 KiB SIMD、独立 UID 对照和三种模式注销后卸载。内置 BTF 识别厂商 `do_handle_mm_fault/5`。 |
| 同一设备，ABI v8 多页 | [内置 BTF 5 项](results/multipage-20261107-092234/summary.json)及[外置 BTF 5 项](results/multipage-20261107-092246/summary.json)通过。覆盖 24 页、`SET_PAGE`、LD1/2/3/4、跨页和 `SRC_FILE`。每轮拒绝 5 个非法描述符，并发 48 次更新中分别完成 38,531 / 37,078 次读，撕裂数为零。会话在重叠 `mprotect` 和 fork 时恢复。[错误 Build ID](results/multipage-20261107-092246/negative-build-id.json)在安装 hook 前被拒绝。 |
| 同一设备，原生验收 | 无模块基线与三种模式通过。三种模式各通过 35 项断言，包含失败读信号、手动注销、父子进程恢复和映射门控。[原生程序结果](results/eliminate-20261107-092015/native-followup.json)。 |
| 主机 | 解码 224,473 项和软件模拟 288,099 项通过。BTF 合成检查覆盖三/四/五参数缺页入口、旧六参数远程 VM、截断和不匹配；TCR 检查覆盖 4 KiB、16 KiB、不同遍历深度和 LPA2。 |
| AOSP ARM64 6.12.18，4 KiB | 从 `ab13257114` 的 `kernel-6.12-gz-allsyms` 按同构建 `System.map-allsyms` 提取 BTF。通过 MM/VMA/FPSIMD 布局和四参数缺页入口检查，确认 `brk_handler`、旧 FPSIMD 保存接口、rwsem 和 `vmalloc_noprof`。[AOSP 构建](https://android.googlesource.com/kernel/prebuilts/6.12/arm64/+/ba5af8825f23428021efb670c0ad025d6b1e0966)。 |
| AOSP ARM64 6.18.16，4 KiB 和 16 KiB | 从 `ab15097451` 的 4 KiB allsyms 和 16 KiB 正常镜像分别提取 BTF。两份真实布局和原型均通过，确认 `do_el0_brk64`、`fpsimd_save_and_flush_current_state`、四参数缺页、rwsem 和 `vmalloc_noprof`。[AOSP 构建](https://android.googlesource.com/kernel/prebuilts/6.18/arm64/+/6b2d4fe8c0c7ffe9e72f64dbc9811d6a8d4d2907)。 |

App 在普通 `untrusted_app` 域运行。最终矩阵的内核日志未发现 Oops、BUG、RCU stall 或
调用栈告警，测试结束后模块列表为空，生命周期矩阵前后 boot ID 一致。先前一次 BRK
活动卸载期间设备重启，未留下可读的崩溃栈。该中断和最终复测分开记录。
[活动卸载中断记录](results/eliminate-20261107-005508/summary.json)。

本版真机验收覆盖 5.15.74 / 4 KiB。6.12 和 6.18 是真实镜像的静态验证，6.x 与 16 KiB
仍需本版真机运行。Pixel 6 的 6.1.134 运行记录来自 2.3.0，覆盖内置、外置及强制回退路径。
[6.1 CRC](results/crc-20261106-232939/summary.json)、[6.1 生命周期](results/eliminate-20261106-233422/summary.json)、
[6.1 多页](results/multipage-20261106-233231/summary.json)、[6.1 回退路径](results/multipage-20261106-233719/summary.json)。

从仓库根目录复跑，测试 APK 最低 API 为 30（Android 11）：

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> --verbose
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> --skip-x-control --repeats 5 --cycles 1
```

多页脚本可加 `--btf kernel.uybtf` 验证外置路径。主机运行
`bash kpms/urov-lab/tools/test_host.sh`。可传入小米 13 / Pixel 6 的原始 BTF 作固定样本检查，
也可用 `--gki gki-6.12-arm64.btf gki-6.18-arm64.btf gki-6.18-16k-arm64.btf` 检查
上述三个 GKI 样本。原始 BTF 从解压后的 ARM64 `Image` 按 `__start_BTF - _text` 到
`__stop_BTF - _text` 的字节区间提取，使用同一个构建的符号表。
