# UROV-Y 2.3.0：实现、内核适配与设备验收

## 实现

`urov-lab`、`urov-x` 和 `urov-y` 共用 [AArch64 load 解码](decode.c)和
[软件模拟](emulate.c)。基础版直接让目标页的用户数据读产生异常；X 变体引入按
读取点和进程限制的控制；Y 变体允许 App 选择三种异常触发方式。改变的是被模拟
load 写入寄存器的字节，目标代码的原始取指结果仍来自原映射。

1. [控制 ABI](urov_y_abi.h) 通过 `prctl` 传输请求。模块验证命令、大小和 MAC，
   绑定调用者的 `mm`，校验目标 RX 映射，快照原字节并构建覆盖镜像。
   `SET` / `SET_PAGE` 用代次和序列锁发布新镜像。
2. `SITE_BRK` 在读取指令的私有 COW 页写一条 BRK；`PAGE_UXN` 设置读取点页的
   UXN，使该页取指进入模拟器；`PAGE_AP` 清目标页叶子 PTE 的 AP[1]，
   使用户数据读进入模拟器，目标页取指仍原生执行。AP 支持多页、跨页及 SIMD/FP。
3. 异常入口核对会话和调用窗口，将原字节或覆盖字节交给解码和模拟逻辑，更新
   GPR 或 FPSIMD 状态以及 PC。未知指令等不支持的访问按模式拒绝或退出覆盖；
   非会话异常交还给内核原处理函数。
4. 模块限制会影响活动映射的系统调用，在 fork 窗口暂撤陷阱，并在注销、会话回收
   或卸载时恢复读取点和页权限。实现见 [urov_y_backend.c](urov_y_backend.c)。

## 兼容决策

| 差异 | 2.3.0 的选择 |
| --- | --- |
| 内核结构与 mmap 锁 | BTF 解析 task/mm/VMA/寄存器帧。优先成对的 `mmap_write_lock/unlock`；否则使用 BTF 的 `mmap_lock` 或旧 `mmap_sem` 偏移和 `down_write/up_write`。VMA 查找和 `vm_file` 使用均持有映射锁。 |
| 缺页和异常入口 | 接受三参数、四参数 `handle_mm_fault` 和 BTF 验证过的五参数厂商入口；公有入口缺少原型时保留全部八个参数寄存器。BRK 支持旧 `brk_handler` 和较新 `do_el0_brk64`。缺页入口在调用前保存 mm，完成后不再解引用 VMA；重试、释放锁或失败时跳过重装。PTE 更新用比较交换保留并发变化。 |
| 远程 VM 与拷贝 | 优先公有五参数 `access_remote_vm`；内部 `__access_remote_vm` 只按匹配原型调用，旧六参数路径向 task 槽传 NULL。用户读支持旧 `probe_user_read` 和新 nofault 接口。缺少 nofault 写时仅控制回包用普通可写 GUP；AP 的 LL/SC 桥不模拟 store。 |
| GUP 与分配 | 优先采用 BTF 中的 `FOLL_FORCE`；缺少枚举时用 Linux 6.3 为分界。分配支持原名和 `_noprof` 变体，与 `kvfree` / `vfree` 配对。 |
| 可选能力 | BRK 与两个页陷阱模式分别检查入口；两类都不可用时拒绝加载。页模式缺少 FPSIMD helper 或寄存器布局时只提供受支持的标量读；缺少文件页元数据时不报告 `SRC_FILE`。 |

接口核对依据：[Linux 5.4 缺页 ABI](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/memory.c)、
[5.4 nofault 读取](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/maccess.c)、
[5.10 远程 VM](https://raw.githubusercontent.com/torvalds/linux/v5.10/mm/memory.c)、
[6.3 GUP 标志](https://raw.githubusercontent.com/torvalds/linux/v6.3/include/linux/mm_types.h)、
[6.6 VMA 锁](https://raw.githubusercontent.com/torvalds/linux/v6.6/mm/mmap.c)、
[6.12 分配接口](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/vmalloc.h)、
[6.18 BRK 入口](https://raw.githubusercontent.com/torvalds/linux/v6.18/arch/arm64/kernel/debug-monitors.c)。

适配范围是 5.4 起的 Android 5.x/6.x、ARM64 小端和 4 KiB 基础页，要求 KernelPatch
能提供所需的 hook 与页表接口。大页、连续 PTE、LPA2 和与宿主页表遍历深度不匹配的
用户页表仍不支持。版本号不能替代对厂商内核实际符号和布局的验证。

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
