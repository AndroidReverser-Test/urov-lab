# UROV-Y 2.4.0：实现、兼容性与代码审计

## 实现

`urov-lab`、`urov-x` 和 `urov-y` 共用 [AArch64 load 解码](decode.c)与
[软件模拟核心](emulate.c)。基础版让目标页的 EL0 数据读产生权限异常；X 变体增加
进程和读取点约束；Y 变体支持以下三种陷阱。三种模式都在异常中改写受支持的 load 的
目标寄存器与 PC，目标代码本身仍执行原字节。BRK 模式会改动另一处的读取指令。

| 模式 | 陷阱与模拟边界 |
| --- | --- |
| `SITE_BRK` | 用内核 COW 路径把登记的私有只读读取指令换成 BRK。按 `mm`、PC 和 BRK 立即数匹配，只模拟登记的标量 load。恢复原指令后，该页仍可能保留 COW。 |
| `PAGE_UXN` | 在读取点页设置 UXN，按 EL0 叶级取指权限异常接管。读取点支持标量 load；同一页只放受支持的 `RET X30`、NOP 和 BTI hint，拒绝带 BTI Guarded Page 位的 PTE。 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，处理 EL0 数据读权限异常；取指仍由硬件执行。支持多页、跨页、FPSIMD、LD1/2/3/4，拒绝写、缓存维护及其他来源的异常。 |

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
| LL/SC 桥用寄存器值推断硬件独占状态，可能把本来应失败的 `STXR` 变成写入。 | 移除代写。AP 同步异常允许使真实独占序列的 `STXR` 原生失败；跳过 `LDXR` 的序列必须保持零写入。`llsc=0` 保留为旧输出字段。 |
| AP 目标本身含读取指令时，从 PC 作数据读可能也触发权限故障；厂商库保存的 PAC 返回地址使窗口误判。 | 目标页上的指令从原始快照取码；PAC 只在比较时剥离，不改用户寄存器或栈。 |

结论：修复了上述越界、并发释放和错误写入问题，模块仍适合受控的 App 自测。它通过
KernelPatch 修改页表和异常入口；RCU、CAS 与 TLB 刷新不能替代 Linux 的
[原生 PTE 锁和映射更新协议](https://cdn.kernel.org/doc/html/latest/mm/split_page_table_lock.html)。
内核回收、远程变更及已有在途的映射操作仍可能与重装竞争。宿主 hook 撤销是否等待所有
在途 trampoline、卸载是否尊重 exit 失败码，也取决于 KernelPatch 版本。
建议常规使用先 `DEACTIVATE` 再卸载；老 loader 不支持安全失败回滚时不要带活动会话卸载。
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

## 2026-11-06 验收

| 环境 | 结果 |
| --- | --- |
| Pixel 6，Android 16，6.1.134，4 KiB，KP `0xc00`，内置 BTF | [CRC 9 次](results/crc-20261106-232939/summary.json)和[生命周期 11 次](results/eliminate-20261106-233422/summary.json)均通过。三种模式命中覆盖，退出会话或活动期卸载后恢复原读值；独立 UID 对照通过。 |
| 同一设备，显式外置 BTF | [多页 4 次](results/multipage-20261106-233231/summary.json)通过，覆盖 24 页、`SET_PAGE`、LD1/2/3/4、跨页和 `SRC_FILE`。篡改 Build ID 的包在安装 hook 前返回 `-EINVAL`。 |
| 同一设备，测试构建强制走回退路径 | [多页 4 次](results/multipage-20261106-233719/summary.json)通过。日志确认使用 rwsem、五参数私有 VM 接口和普通 GUP 控制回包。这是回退路径测试，内核仍为 6.1。 |
| 主机 | 软件解码、模拟和兼容测试通过。解析实际的小米 13 5.15.74 / Pixel 6 6.1.134 BTF，分别识别五、四参数缺页入口；合成数据覆盖三参数、旧六参数远程 VM、签名不匹配和截断包。 |

上述 App 在普通 `untrusted_app` 域运行。真机测试的内核日志增量未发现 Oops、
BUG、挂起或调用栈告警，测试结束后模块列表为空。当前只连接了 6.1 真机；
5.15 的本版证据是 BTF 验证，[其 App 真机记录](results/eliminate-20261105-233109/summary.json)
属于先前版本。5.4、5.10 和其他 6.x 小版本也未做本版真机验收。

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
`bash kpms/urov-lab/tools/test_host.sh`；可选传入保存的 5.15.74、6.1.134 原始
BTF（该测试按这两份实际样本的布局断言）。
