# UROV-LAB

UROV-LAB 是一个适用于 Android arm64 的独立 KPM：把一个封存只读页注册给模块后，该页上的普通 A64 整数 load 会读到伪造值，而取指仍执行原始机器码。模块自带解码器、寄存器模拟器、EL0 数据异常后端和控制系统调用；**不需要修改或重新编译外部宿主内核**。

当前实现在 Pixel 6（oriole，Android 6.1.134，KP 0.12.0 / `0xc00`，4 KiB 页）上通过了活动覆盖验收：1/2/4/8 字节 load、LDP、跨覆盖区读取、8 个 CPU 的并发更新、映射门控、fail-closed、fork 不继承、注销恢复以及带在途读线程的模块卸载。证据见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)。

## 工作方式

```text
用户态测试程序                               urov-lab.kpm（单个 KPM）
  syscall(272, magic, cmd, &req, sizeof)  ->  __NR_kcmp 函数指针 hook
                                                REGISTER / SET / STATUS / DEACTIVATE
  注册页 RX (sealed memfd)                ->  pin_user_page + mm_users
                                                PTE.AP[1] 清零（raw XOM）
                                                取指仍从原页执行（UXN=0）
  普通 LDR/LDP 读取                        ->  do_mem_abort inline hook
                                                解码 + 用原页快照和 fake64 模拟
                                                写回 GPR/PC，跳过原异常路径
  注销 / 卸载                              ->  恢复 PTE/VMA/TLB，解 pin，撤销 hook
```

- 活动范围是调用者自己的 `mm`、一个 4 KiB 页、一个 8 字节覆盖区间。
- 更新只发布一个 8 字节对齐的 `fake64`，不修改代码页，不需要每次读取切换 PTE。
- 读权限异常由模块自己接管：`do_mem_abort` 在原生 fault 分发之前处理 EL0 读 permission fault；不属于本会话的异常原样放行。
- 写、SIMD/FP、原子/独占、认证 load、未知编码等不在白名单内的访问会 fail-closed（SIGSEGV），绝不返回原字节冒充成功。
- `mprotect`/`munmap`/`mremap`/`madvise`/`mmap(MAP_FIXED)` 会拒绝与活动页相交的请求；`fork` 不继承目标页（`VM_DONTCOPY`）。
- 模块卸载时先恢复页面再撤销 hook；四个持续 fault 的读线程在卸载后继续按原值运行，已实测。

## 构建

在 KernelPatch 仓库根目录运行（默认 NDK 路径可按需传入）：

```powershell
.\kpms\urov-lab\build.ps1
```

产物在 `kpms/urov-lab/out/`：

| 文件 | 用途 |
|---|---|
| `urov-lab.kpm` | 独立活动覆盖模块（本实现） |
| `urov_overlay_test` | 活动覆盖验收程序（需 root 运行） |
| `urov_hold_test` / `urov_hold2_test` | 卸载生命周期测试（无读者 / 有读者） |
| `urov-lab-check.kpm` | 历史只读预检产物，保留用于对照 |
| `urov_emulate_test`、`urov_native_test`、`urov_copy_probe`、`urov_vector_fault_probe`、`urov_kpm_check_test` | 软件核心、原生差分与平台基线测试 |

## 设备运行

模块名固定为 `urov-lab`。先把产物推到 `/data/local/tmp/`，用 kpatch 加载；控制请求由测试程序通过被 hook 的 `__NR_kcmp` 发出，不需要 kpatch 的 `ctl0`。

```sh
adb push kpms/urov-lab/out/urov-lab.kpm /data/local/tmp/
adb push kpms/urov-lab/out/urov_overlay_test /data/local/tmp/
adb shell 'chmod 755 /data/local/tmp/urov_overlay_test'
adb shell '/data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/urov-lab.kpm active'
adb shell "/data/local/tmp/kpatch <KEY> su -c '/data/local/tmp/urov_overlay_test --iterations 100'"
adb shell '/data/local/tmp/kpatch <KEY> kpm unload urov-lab'
```

Windows 下可用自动化脚本完成构建、推送、加载、测试、卸载和循环：

```powershell
.\kpms\urov-lab\tools\run_overlay_device.ps1 -Key <KEY> -Serial <SERIAL> -Iterations 100 -Cycles 10
```

测试程序需要 root（sealed memfd 的只读重开在普通 shell 下被 SELinux 拒绝）。若上一次测试异常退出留下活动会话，先运行 `urov_overlay_test --cleanup` 再卸载。模块卸载后可用 `kpatch kpm ctl0 urov-lab status` 查看运行状态：

```text
mode=standalone-resident caps=0xb7 state=inactive hooks=0x7 core_checks=4114 ...
```

## 控制系统调用 ABI

`urov_abi.h` 定义 128 字节的 `struct urov_request`（无指针、无隐式 padding）：

```c
long r = syscall(272, (long)0x55524f5653595343ULL, (long)cmd, &req, (long)sizeof(req));
```

| cmd | `op` | 输入 | 输出 |
|---|---|---|---|
| `QUERY` (1) | 1 | — | caps、state、session、generation、hits、failures |
| `REGISTER` (2) | 2 | `address`（页对齐）、`offset`（0..4088）、`value`（fake64）、`flags`（0 或 `UROV_F_RAW_XOM`） | `session=1`、`generation=1`、`state=ACTIVE` |
| `SET` (3) | 3 | `session`、`expected_generation`、`value` | 新 `generation`；代次不匹配返回 `-EAGAIN` |
| `STATUS` (4) | 4 | `session` | 当前代次、值、命中/失败计数 |
| `DEACTIVATE` (5) | 5 | `session` | 幂等；恢复后 `state=INACTIVE` |

控制请求只在 magic 匹配时被截获；普通 `kcmp` 调用不受影响。只有调用者自己的 `mm` 可以注册；注册事务校验 VMA（一页、RX、MAP_SHARED、文件映射、offset 0）、PTE（present、user、read-only、UXN=0、非 contig/special）并 pin 住页面。

## 结果与限制

- 真机结果、命令输出、产物散列与内核日志检查见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)。
- 软件核心自测与历史设备记录见 [IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md)、[CURRENT_RESULTS.md](CURRENT_RESULTS.md)。
- 设计背景与未采用的 CORE-1 常驻内核方案见 [DESIGN.md](DESIGN.md)、[BACKEND_CONTRACT.md](BACKEND_CONTRACT.md)。

限制：

1. 这是合作测试模型：一次一个会话、一页、一个 8 字节覆盖；不承诺任意进程、任意映射或任意指令。
2. 设备没有 EPAN。清除 `PTE.AP[1]` 后 EL0 读会异常，但内核仍能通过普通 uaccess 读取该页，因此不能把 raw XOM 当作生产级隔离。
3. fork 不继承目标页；拒绝继承（`VM_DONTCOPY`）是明确约定，不是透明继承。
4. 模块与 kpatch 的加载/卸载必须串行；卸载前应先注销会话或让测试程序正常退出。本设备实测了带持续读线程和 owner 被 kill 后的卸载；若宿主仍是“exit 在 RCU 读侧调用”的极老 loader，应先在模块外注销会话再卸载。
5. 仅支持 64 位 EL0、小端、4 KiB 基础页、白名单内的通用寄存器 load（含 LDP）；SIMD/FP、跨页、acquire/exclusive、MTE/标签地址明确拒绝。
6. 页面内容来自注册时的快照；同一页面若被测试程序之外的路径改写，不承诺覆盖结果。

## 目录

| 路径 | 说明 |
|---|---|
| `urov_backend.c` / `.h` | 合并进 KPM 的常驻异常/控制后端（本实现核心） |
| `urov_kpm.c` | KPM 入口、`ctl0` 状态输出、元数据 |
| `decode.c` / `emulate.c` / `core_selftest.c` | A64 解码、模拟、4114 项无分配自测 |
| `urov_abi.h` | 用户态/内核共享的 128 字节请求 ABI 与 syscall 约定 |
| `tests/urov_overlay_test.c` | 活动覆盖验收程序 |
| `tests/urov_hold_test.c` / `urov_hold2_test.c` | 卸载生命周期测试 |
| `tools/run_overlay_device.ps1` | 设备自动化脚本 |
| `results/` | 构建、设备与覆盖运行记录 |
