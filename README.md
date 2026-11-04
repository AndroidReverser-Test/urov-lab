# UROV-LAB

2026-11-04 后续无密钥复核：新增独占监视器观察和实际读取点一致性校验，可发现
`urov-x` 自身 mm 内的活动受保护页；不依赖耗时阈值，不结束会话。342 次活动页
观测全部命中，870 次正常页观测无误报（3 次 UNKNOWN）。实现、边界和原始结果见
[KEYLESS_DETECTION_RESULTS.md](KEYLESS_DETECTION_RESULTS.md)。本轮未修改 KPM。

2026-11-04 普通 App 检测复核已完成，见 [DETECTION_RESULTS.md](DETECTION_RESULTS.md)。
新增独立检测器与双 UID 测试 App，未修改 KPM。复核发现当前 `0x10000` 实际产生
smaps `rr`，并非文中原先描述的 `dc`；对 raw-XOM 地址执行 pipe write 还可能持续
重试。以下旧描述中涉及 fork 标记及内核辅助读取可用性的部分，以该复核结果为准。

UROV-LAB 是一个适用于 Android arm64 的独立 KPM：把一个一页只读可执行映射注册给模块后，该页上的普通 A64 整数 load 会读到伪造值，而取指仍执行原始机器码。模块自带解码器、寄存器模拟器、EL0 数据异常后端和控制系统调用；**不需要修改或重新编译外部宿主内核**。

自 2026-11-04 起支持普通 app：控制通道除 root 用的 `__NR_kcmp` 外新增 `__NR_prctl`（在 `untrusted_app` 的 seccomp allowlist 内）；注册对象扩展为 app 自己的一页只读可执行文件映射（推荐自身已安装 native library 的 `MAP_SHARED` RX 别名，或 app 私有目录的一页 payload 文件）。会话按 mm 归属，非 owner 不能更新/注销，owner 进程死亡后按 `mm_users == 1` 惰性回收。方案、检测面、限制和真机日志见 [APP_OVERLAY.md](APP_OVERLAY.md)。

当前实现在 Pixel 6（oriole，Android 6.1.134，KP 0.12.0 / `0xc00`，4 KiB 页）上通过了活动覆盖验收：1/2/4/8 字节 load、LDP、8/16/24/32 字节覆盖区间、跨覆盖区读取、8 个 CPU 的并发更新、映射门控、fail-closed、fork 不继承、注销恢复以及带在途读线程的模块卸载。证据见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)。

## 工作方式

```text
用户态程序                                   urov-lab.kpm（单个 KPM）
  root/旧程序: syscall(272, magic, ...)   ->  __NR_kcmp hook
  app: syscall(__NR_prctl, option, magic,
               cmd, &req, sizeof(req))    ->  __NR_prctl hook
                                                REGISTER / SET / STATUS / DEACTIVATE
  注册页 RX（app：一页 MAP_SHARED 文件映射）->  pin_user_page + mm_users
                                                VMA page_prot 清 PTE_USER
                                                PTE.AP[1] 清零（raw XOM）
                                                取指仍从原页执行（UXN=0）
  普通 LDR/LDP 读取                        ->  do_mem_abort inline hook
                                                解码 + 原页快照 + 32 字节 fake 快照
                                                写回 GPR/PC，跳过原异常路径
  注销 / 卸载                              ->  恢复 PTE/VMA/TLB，解 pin，撤销 hook
```

- 活动范围是调用者自己的 `mm`、一个 4 KiB 页、一个 8/16/24/32 字节覆盖区间。
- 注册页必须是恰好一页、只读、可执行、文件后备、无 `VM_MAYWRITE` 的映射；root 验收使用 sealed memfd 的 `MAP_SHARED` RX 映射，普通 app 使用自身 lib 的一页 `MAP_SHARED` RX 别名或私有 payload 文件。`MAP_PRIVATE` 因可被 COW、pin 页身份不稳定而被拒绝。
- 更新通过 seqlock 发布一份完整的 32 字节 `fake` 向量（实际使用前 `length` 字节），不修改代码页，不需要每次读取切换 PTE；一条指令的 LDP 两个结果来自同一份快照。
- 读权限异常由模块自己接管：`do_mem_abort` 在原生 fault 分发之前处理 EL0 读 permission fault；不属于本会话的异常原样放行。
- 写、SIMD/FP、原子/独占、认证 load、未知编码等不在白名单内的访问会 fail-closed（SIGSEGV），绝不返回原字节冒充成功。
- `mprotect`/`munmap`/`mremap`/`madvise`/`mmap(MAP_FIXED)` 会拒绝与活动页相交的请求；`fork` 不继承目标页（`VM_DONTCOPY`，只作用于注册的那一页别名）。
- 模块卸载时先恢复页面再撤销 hook；四个持续 fault 的读线程在卸载后继续按原值运行，已实测。
- 会话按 `mm` 归属：非 owner 的 SET/STATUS/DEACTIVATE 返回 `ENOENT`，REGISTER 在已有活跃会话时返回 `EBUSY`；owner 进程死亡后下一次控制请求惰性回收。全模块同一时间仍只有一个活跃会话。

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
| `urov_foreign_test` | 非 owner 控制/死 owner 回收探针（root 运行） |
| `urov-lab-check.kpm` | 历史只读预检产物，保留用于对照 |
| `urov_emulate_test`、`urov_native_test`、`urov_copy_probe`、`urov_vector_fault_probe`、`urov_kpm_check_test` | 软件核心、原生差分与平台基线测试 |

普通 app 测试程序在 `apps/urov-app/out/urovapp.apk`，由
`apps/urov-app/build-app.ps1` 构建（`-Hold` 生成生命周期变体
`urovapp-hold.apk`）。

## 设备运行

模块名固定为 `urov-lab`。先把产物推到 `/data/local/tmp/`，用 kpatch 加载；root
验收程序通过被 hook 的 `__NR_kcmp` 发控制请求，普通 app 通过 `__NR_prctl`，都
不需要 kpatch 的 `ctl0`。

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

普通 app 的构建、安装、多轮验收和状态检查：

```powershell
.\kpms\urov-lab\apps\urov-app\build-app.ps1 -Source app.c
.\kpms\urov-lab\tools\run_app_device.ps1 -Key <KEY> -Iterations 3
```

root 测试程序需要 root（sealed memfd 的只读重开在普通 shell 下被 SELinux 拒绝）。
若上一次测试异常退出留下活动会话，先运行 `urov_overlay_test --cleanup` 再卸载。
模块卸载后可用 `kpatch kpm ctl0 urov-lab status` 查看运行状态：

```text
mode=standalone-resident caps=0xeb7 state=inactive hooks=0xf core_checks=4139 ...
```

## 控制系统调用 ABI

`urov_abi.h` 定义 128 字节的 `struct urov_request`（无指针、无隐式 padding），当前 `UROV_ABI_VERSION == 2`：

```c
/* root/旧程序： */
long r = syscall(272, (long)UROV_NOTIFY_MAGIC, (long)cmd, &req, (long)sizeof(req));

/* 普通 app（seccomp 允许 prctl）： */
long r = syscall(__NR_prctl, (long)UROV_PRCTL_OPTION,
                 (long)UROV_PRCTL_MAGIC, (long)cmd, &req, (long)sizeof(req));
```

| cmd | `op` | 输入 | 输出 |
|---|---|---|---|
| `QUERY` (1) | 1 | — | caps、state、session、generation、length、hits、failures |
| `REGISTER` (2) | 2 | `address`（页对齐）、`offset`、`length`（0=8 / 8 / 16 / 24 / 32）、`value` + `value_hi[0..2]`（最多 32 字节 fake）、`flags`（0 或 `UROV_F_RAW_XOM`） | `session=1`、`generation=1`、`length`、`state=ACTIVE` |
| `SET` (3) | 3 | `session`、`expected_generation`、`length`（必须等于会话长度，或 0 表示 8）、`value` + `value_hi[0..2]` | 新 `generation`；代次不匹配返回 `-EAGAIN`，长度不匹配返回 `-EINVAL` |
| `STATUS` (4) | 4 | `session` | 当前代次、长度、fake 字节、命中/失败计数 |
| `DEACTIVATE` (5) | 5 | `session` | 幂等；恢复后 `state=INACTIVE` |

fake 字节按小端排列：`value` 是字节 0..7，`value_hi[0]` 是 8..15，`value_hi[1]` 是 16..23，`value_hi[2]` 是 24..31；窗口外的 `value_hi` 必须为零，否则请求按非法编码拒绝。`caps` 中的 `UROV_CAP_FAKE16`/`UROV_CAP_FAKE32` 表示支持 16/32 字节窗口，`UROV_CAP_PRCTL` 表示 app 控制通道已安装。

控制请求只在 magic 匹配时被截获；普通 `kcmp`/`prctl` 调用不受影响。只有调用者自己的 `mm` 可以注册；注册事务校验 VMA（恰好一页、只读可执行文件映射、无 `VM_MAYWRITE`，实际为 `MAP_SHARED`）、PTE（present、user、read-only、UXN=0、非 contig/special）并 pin 住页面。`MAP_PRIVATE` 文件映射因携带 `VM_MAYWRITE`（可被 COW）被拒绝。

## 结果与限制

- 真机结果、命令输出、产物散列与内核日志检查见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)、[RESULTS_APP.md](RESULTS_APP.md)。
- 软件核心自测与历史设备记录见 [IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md)、[CURRENT_RESULTS.md](CURRENT_RESULTS.md)。
- 设计背景与未采用的 CORE-1 常驻内核方案见 [DESIGN.md](DESIGN.md)、[BACKEND_CONTRACT.md](BACKEND_CONTRACT.md)。
- 普通 app 方案、检测面与真机复现见 [APP_OVERLAY.md](APP_OVERLAY.md)；旧限制实测见 [APP_DOMAIN_LIMITS.md](APP_DOMAIN_LIMITS.md)。

限制：

1. 这是合作测试模型：全模块同一时间一个会话、一页、一个最多 32 字节的覆盖区间；多个 app 需串行（非 owner 会得到 `EBUSY`/`ENOENT`，死 owner 会自动回收）。不承诺任意进程、任意映射或任意指令。单条 A64 整数 load 最多 8 字节，LDP 最多 16 字节；32 字节窗口需要多条指令读取。
2. 设备没有 EPAN。清除 `PTE.AP[1]` 后 EL0 读会异常，但内核仍能通过普通 uaccess 读取该页，因此不能把 raw XOM 当作生产级隔离。
3. fork 不继承目标页；拒绝继承（`VM_DONTCOPY`）是明确约定，不是透明继承。普通 app 模式只对注册的一页别名设置该标志，不会让子进程失去正常 lib 映射。
4. 模块与 kpatch 的加载/卸载必须串行；卸载前应先注销会话或让测试程序正常退出。实测了带持续读线程、普通 app 会话活跃、owner 被 kill 后的卸载/回收；若宿主仍是“exit 在 RCU 读侧调用”的极老 loader，应先在模块外注销会话再卸载。
5. 仅支持 64 位 EL0、小端、4 KiB 基础页、白名单内的通用寄存器 load（含 LDP）；SIMD/FP、跨页、acquire/exclusive、MTE/标签地址明确拒绝。
6. 页面内容来自注册时的快照；同一页面若被测试程序之外的路径改写，不承诺覆盖结果。注册页必须保持只读且无 `VM_MAYWRITE`；普通 app 推荐使用已安装 native library 的一页 `MAP_SHARED` RX 别名。
7. 更新路径使用 seqlock；fault 路径遇到写者临界区会短暂重试。若极端情况下重试耗尽，按 fail-closed 处理，不会返回撕裂数据或原字节。
8. 普通 app 已可直接使用：控制走 `__NR_prctl`，页来源为自身一页只读可执行 `MAP_SHARED` 文件映射（lib 别名或私有 payload 页），会话按 mm 归属并支持死 owner 回收。仍有限制：全局单会话、单页/32 字节窗口、仅 GPR load、模块装卸需 root；详见 [APP_OVERLAY.md](APP_OVERLAY.md)。

## 目录

| 路径 | 说明 |
|---|---|
| `urov_backend.c` / `.h` | 合并进 KPM 的常驻异常/控制后端（本实现核心） |
| `urov_kpm.c` | KPM 入口、`ctl0` 状态输出、元数据 |
| `decode.c` / `emulate.c` / `core_selftest.c` | A64 解码、模拟、4139 项无分配自测 |
| `urov_abi.h` | 用户态/内核共享的 128 字节请求 ABI、kcmp/prctl 通道约定 |
| `tests/urov_overlay_test.c` | 活动覆盖验收程序（8/16/24/32 字节窗口） |
| `tests/urov_hold_test.c` / `urov_hold2_test.c` | 卸载生命周期测试 |
| `tests/urov_foreign_test.c` | 非 owner 控制/死 owner 回收探针 |
| `apps/urov-app/` | 普通 app 验收程序、能力探针与 APK 构建脚本 |
| `tools/run_overlay_device.ps1` | root 设备自动化脚本 |
| `tools/run_app_device.ps1` | 普通 app 设备自动化脚本 |
| `APP_OVERLAY.md` / `RESULTS_APP.md` | 普通 app 方案、检测面、限制与真机证据 |
| `urov_x_backend.c` / `.h` / `urov_x.c` / `urov_x_abi.h` | covert 变体 `urov-x`：密钥化控制通道、读取点绑定、透明生命周期 |
| `tools/run_stealth_device.py` | `urov-x` 设备矩阵（无密钥/活动/观察者/卸载/SIMD/fork） |
| `STEALTH_DESIGN.md` / `STEALTH_RESULTS.md` | 检测特征点消除设计与真机对照结果 |
| `results/` | 构建、设备与覆盖运行记录 |
