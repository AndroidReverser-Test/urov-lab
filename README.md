# UROV-LAB

2026-11-06 ABI v8 多页/宽 load（本轮）：`urov-y` 的 `PAGE_AP` 模式从"一页一会话"
扩到**一次会话任意页数组**（`struct uy_page_desc[page_count]`，默认配额 4096 页 /
8 MiB 镜像，`kvmalloc` 动态分配），并新增 **LD1/LD2/LD3/LD4**（含 post-index
立即数/寄存器两种形式）与**跨页 load**：一条 64 字节的 `ld1 {v0-v3.16b}` 或 32
字节的 `ldp q` 可以在两个已注册页之间拼接，未注册段走 nofault uaccess 读真实
内存。每页有独立整页镜像、窗口、seqlock 与 `SET_PAGE` 更新；`SRC_FILE` 从
`vm_file` 读原始页，`SRC_USER` 拷贝调用者镜像。真机
[multipage-20261106-224709](results/multipage-20261106-224709/summary.json)：
24 页同时 ARMED 的 96 KiB `memcpy` 整段等于伪页、`SET_PAGE` 换第 7 页后重读一致、
注销后 24 页全部恢复；LD1 1/2/3/4 寄存器、LD1 8B、post-index 立即数/寄存器、
LD2/LD3/LD4 去交织全部等于架构解释；跨页 `ldp q`/`ld1` 与"两页镜像拼接"逐字节
一致，起始于未注册页的跨界读前半段为真实内存；`SRC_FILE` 路径也已上机。同轮
`crc-*` 回归矩阵全 PASS（含 `crc-ap-big` 的 SIMD 大长度传输）。**16 KiB 基础页
本轮明确不实现**：`QUERY` 报 `page_shift=12`、caps 不含 `UROV_Y_CAP_16K`，
`supported_pagetables()` 仍拒绝非 4 KiB 内核。

2026-11-06 大长度传输（ABI v7）：`urov-y` 的 `PAGE_AP` 模式现在能服务 SIMD&FP
load，并把覆盖镜像从 32 字节扩到整页 4 KiB。bionic 的 `memcpy` 从 16 字节起、
`memcmp` 从 160 字节起、`strlen` 越过前 32 字节后都会走 `LDR q`/`LDP q`，此前这些
路径 fail-closed（SIGSEGV）；本轮扩展 `decode.c` 到 B/H/S/D/Q 的 load（无缩放/
前中后索引/寄存器偏移/literal/LDP），故障处理调用内核自己的
`fpsimd_signal_preserve_current_state()` + `fpsimd_update_current_state()` 改写并
重新绑定当前任务的 FPSIMD 状态，`REGISTER`/`SET` 可以用 `fake_addr` 发布整页镜像。
真机 `crc-ap-big`：`memcpy`/`memcmp`/`strlen`/`crc32` 在 16/32/64/160/512/1024/4096
字节上全部读到伪页（`window_crc=71515206`、`strlen=4095`），业务窗口外的同长度
`memcpy` 仍读原页，32 字节内部窗口按字节合并（`CRC_MIXED offset=64`），`SET` 换值后
重新读到新镜像；16 次运行全 PASS、`kernel_issues=[]`、卸载后无模块残留。设计见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §13，数据见
[CRC_INJECTION_RESULTS.md](CRC_INJECTION_RESULTS.md) 与
[本轮矩阵](results/crc-20261106-212757/summary.json)。

2026-11-05 第四轮消除：`PAGE_AP_KEYLESS_RESULTS.md` 的 `CLREX/B;LDXR` 探针证明旧
LL/SC 桥只看相邻指令编码——分支跳过 `LDXR` 也会被代写哨兵。本轮把桥改成"执行
存证"：仅当 `LDXR` 目的寄存器仍等于 `[Xn]`（`LDXR` 确实执行且数据未被改写）时
才代写；否则只推进 PC，让 `STXR` 原生失败。同一 APK 的单变量 A/B：旧 KPM
42/42 次异常写入、新 KPM 0/42；正式矩阵 174 次 AP store 观测 / 5,568 个目标试验
0 写入、441 次独占观测全阴性，业务伪值保留。设计见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §11，数据见
[PAGE_AP_KEYLESS_RESULTS_R2.md](PAGE_AP_KEYLESS_RESULTS_R2.md) 与
[本轮矩阵](results/eliminate-20261105-224534/summary.json)。

2026-11-05 第三轮消除：`PAGE_UXN` 那次复核本身证明了当前检测集的最后一个确定性
特征——读取点页不在 EL0 原生取指。`urov-y` 新增 `PAGE_AP` 模式（ABI v6，`mode=3`）：只清**目标页**
叶子 PTE 的 `AP[1]`，读取点页和取指路径完全不动；EL0 数据读触发 permission abort，
由 `do_mem_abort` 按同一调用窗口/快照规则模拟。为消掉旧数据陷阱的独占监视器信号，
handler 对紧邻的 `LDXR/LDAXR; load; STXR/STLXR` 完成 store 并推进 PC，`ctl0 status`
的 `llsc` 记录次数。真机正式矩阵 14 次运行、225 次观测：独占 MATCH 0、reader MATCH 0；
AP 两轮各 48 次 execution 观测（含 8 CPU canary）`match=0`，代码页与 smaps 不变，
业务伪值保留；单独 30 次 `w-active` 轮询到 `llsc=11,960`（最终产物）。设计见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §10，数据见
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md) §10 与
[本次矩阵](results/eliminate-20261105-213741/summary.json)。残余（仅相邻 LL/SC 形状、
时间、SIMD/原子 fail-closed、PTE 重装窗口）在该节明列。

2026-11-05 无密钥取指复核覆盖了 `urov-y` 的 `PAGE_UXN` 模式。
[`ud_observe_execution`](native/urov_observe.h) 在已知读取点所在页执行 `BTI C` 和 `RET`，
用同一文件的另一份 RX 映射作对照。活动页 255/255 命中，669 次对照中 668 次阴性、1 次
不确定。适用范围是当前进程持有的已知探针页。真机矩阵和复跑方式见
[取指复核数据](results/eliminate-20261105-210733/summary.json)与
[设备运行器](tools/run_elimination_device.py)。

2026-11-05 第二轮消除：`urov-y` 新增 `PAGE_UXN` 读取点陷阱模式（ABI v5，`mode=2`）。
目标页仍不改任何权限；读取点页也不改一个字节、不改 VMA、不产生 COW，只清叶子 PTE
的 EL0 执行许可（UXN），由 `do_mem_abort` 接管 EL0 instruction abort 并模拟读取点。
第一轮"活动期间代码页被改写为 BRK / 私有 COW 页"的特征因此消失：活动期间
`site_live_word == site_file_word`，代码页 `Private_Dirty=0`、`Anonymous=0`，
注销/卸载后无残留。153 次观测中独占监视器与跨 PC 内容差异仍为 0 命中，业务窗口
仍返回伪值；同夹具的 BRK 模式（`y-active`）继续作为该特征的阳性对照。设计见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §9，设备矩阵见
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md)。

2026-11-04 第一轮消除：新增 `urov-y` 变体（`urov_y.c` / `urov_y_backend.c`），
把覆盖从"数据页权限异常"移到"读取点指令陷阱"：目标页保持普通可读 RX，读取点
在会话期间改写为 BRK，只有注册的业务调用窗口（`x30` 落在注册区间）才拿伪值，
其余调用按原字节透明模拟。真机上 KEYLESS 的两项检测（独占监视器失效、跨 PC
内容差异）在活动页上均为 0 命中（129 次观测、12,384 个三元组），业务窗口仍读到
伪值；新引入的读取点代码页差异已实测记录。设计见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md)，设备矩阵见
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md)。

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

## UROV-Y 的 5.x 和 6.x 兼容路径

`urov-y` 使用 ABI v8 的 `prctl` 通道（288 字节请求，比 v7 多 `page_count`/
`page_stride`/`pages_addr`/`session_flags`/`reserved2`，多页页描述符数组），
校验请求 MAC 后在调用者的 `mm` 中注册一个文件后备的 RX 页和读取点。模块快照目标页，
异常处理中按读取点 PC 和调用者 `x30` 选择覆盖字节或原字节，模拟 A64 load 后更新
寄存器（`PAGE_AP` 的 SIMD&FP load 更新 FPSIMD 状态）和 PC。`length` 可达 4096（整页），
超过 32 字节时用 `fake_addr` 指向调用者缓冲区，`SET` 用代际号和 seqlock 重新发布
整份镜像。注销或卸载会恢复读取点或页权限。[控制与模拟实现](urov_y_backend.c)

| 模式 | 触发入口 | 修改范围 |
| --- | --- | --- |
| `SITE_BRK` | EL0 BRK | 在读取点的私有 COW 页替换一条 load 指令 |
| `PAGE_UXN` | EL0 取指异常 | 设置读取点页的 UXN，模拟该页的读取点及支持的控制指令 |
| `PAGE_AP` | EL0 数据读权限异常 | 清目标页的 AP[1]，继续从原页原生取指 |

`PAGE_AP` 的目标不再限一页共享别名：普通 app 可以注册 linker 加载的 `.text`
中的一页（私有、多页 VMA、带 `VM_MAYWRITE`）。注册时先 fault-in 目标页，再在
`mmap_write_lock` 下复核 VMA/PTE；共享 VMA 仍保留一页、无 `VM_MAYWRITE` 的
约束。2026-11-05 的 `crc-ap-text` 真机数据（90,112 字节 VMA 的普通
`MAP_PRIVATE` `.text`，覆盖中 `Private_Dirty/Anonymous=0`）见
[CRC_INJECTION_RESULTS.md](CRC_INJECTION_RESULTS.md)。

业务调用窗口除当前 `x30` 外，还会沿 `x29` 帧链最多回溯 16 层，因此
`memcpy`/`memcmp`/`strlen` 以及 zlib `crc32` 这类内部有嵌套调用的 libc 读者
也能在业务窗口内命中；无帧指针时退回只检查当前 LR。`crc-ap-libc` 验证了
12 字节 `memcpy`、32 字节 `memcmp`、31 字节 `strlen` 和 zlib CRC 的标量路径；
`crc-ap-big`（ABI v7）进一步覆盖 bionic 的 SIMD 路径：16/32/64/160/512/1024/4096
字节的 `memcpy`、4 KiB `memcmp`、4095 字节 `strlen` 和整页 `crc32`。SIMD&FP load
通过内核 `fpsimd_signal_preserve_current_state()` /
`fpsimd_update_current_state()` 提交到当前任务，覆盖窗口可达整页 4 KiB。
ABI v8 进一步覆盖多结构 load（`LD1`/`LD2`/`LD3`/`LD4`，含 post-index 两种形式）
和跨页 load；残余仅 SVE/SME、acquire/exclusive、MTE/标签地址与 16 KiB 基础页；
没有这两个内核 helper 或 BTF 布局时 `PAGE_AP` 的向量 load 仍 fail-closed，
`ctl0 status` 的 `fpsimd=` 字段报告是否可用。

2.3.0 在加载时适配 Android ARM64 的 5.4 及之后的 5.x/6.x 内核接口。
默认从运行内核读取 BTF；没有内置 BTF 时可用 `btf=/path` 提供同一内核构建的
外置 BTF 包，模块会核对 GNU Build ID。异常、远程内存和映射锁接口根据实际符号与
BTF 选择。ABI 仍为 v8；`QUERY` 和 `ctl0 status` 只报告可用的能力。

2.3.0 在 Pixel 6（6.1.134，4 KiB）通过 CRC、多页、跨页、向量读取与活动卸载的 App
测试；保存的小米 13 5.15.74 BTF 通过本版主机验证。完整实现分析、兼容边界和复跑命令见
[UROV-Y 兼容性与验收](COMPATIBILITY_Y.md)。[历史 5.15.74 App 实测](results/eliminate-20261105-233109/summary.json)
使用的是较早版本。

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
mode=standalone-resident caps=0xeb7 state=inactive hooks=0xf core_checks=4152 ...
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

1. 这是合作测试模型：全模块同一时间一个会话；`urov-x`/`urov-lab` 为一页、`urov-y`
   的 `PAGE_AP` 可注册任意页数组（默认 4096 页 / 8 MiB 镜像配额）。多个 app 需串行
   （非 owner 会得到 `EBUSY`/`ENOENT`，死 owner 会自动回收）。不承诺任意进程、任意
   映射或任意指令。单条 A64 整数 load 最多 8 字节，LDP 最多 16 字节，`PAGE_AP` 的
   `LDP Q` 最多 32 字节、`LD1` 四寄存器最多 64 字节。
2. 设备没有 EPAN。清除 `PTE.AP[1]` 后 EL0 读会异常，但内核仍能通过普通 uaccess 读取该页，因此不能把 raw XOM 当作生产级隔离。
3. fork 不继承目标页；拒绝继承（`VM_DONTCOPY`）是明确约定，不是透明继承。普通 app 模式只对注册的一页别名设置该标志，不会让子进程失去正常 lib 映射。
4. 模块与 kpatch 的加载/卸载必须串行；卸载前应先注销会话或让测试程序正常退出。实测了带持续读线程、普通 app 会话活跃、owner 被 kill 后的卸载/回收；若宿主仍是“exit 在 RCU 读侧调用”的极老 loader，应先在模块外注销会话再卸载。
5. 仅支持 64 位 EL0、小端、4 KiB 基础页。`urov-x`/`urov-lab` 只模拟白名单内的通用寄存器 load（含 LDP）；`urov-y` 的 `PAGE_AP` 另外模拟 B/H/S/D/Q 的 SIMD&FP load（无缩放/前中后索引/寄存器偏移/literal/LDP，含写回）、`LD1`/`LD2`/`LD3`/`LD4`（无偏移与 post-index 立即数/寄存器）以及跨页 load。SVE/SME、acquire/exclusive、MTE/标签地址仍明确拒绝。16 KiB 基础页本轮未实现：`QUERY` 返回 `page_shift=12` 且不设 `UROV_Y_CAP_16K`。没有 `fpsimd_signal_preserve_current_state()`/`fpsimd_update_current_state()` 或 `thread.uw.fpsimd_state` BTF 布局时，向量 load 退回 fail-closed。
6. 页面内容来自注册时的快照；同一页面若被测试程序之外的路径改写，不承诺覆盖结果。注册页必须保持只读且无 `VM_MAYWRITE`；普通 app 推荐使用已安装 native library 的一页 `MAP_SHARED` RX 别名。
7. 更新路径使用 seqlock；fault 路径遇到写者临界区会短暂重试。若极端情况下重试耗尽，按 fail-closed 处理，不会返回撕裂数据或原字节。整页镜像的发布在 seqlock 内做 4 KiB 拷贝，读侧只拷当前 load 触到的 ≤32 字节。
8. 普通 app 已可直接使用：控制走 `__NR_prctl`，页来源可为自身只读可执行 `MAP_SHARED` 文件映射（lib 别名或私有 payload 页）或私有 `.text` 页；ABI v8 的多页数组只承诺 `PAGE_AP`。会话按 mm 归属并支持死 owner 回收。仍有限制：全局单会话、16 KiB 未实现、`PAGE_AP` 之外仅 GPR load、模块装卸需 root；详见 [APP_OVERLAY.md](APP_OVERLAY.md)。

## 目录

| 路径 | 说明 |
|---|---|
| `urov_backend.c` / `.h` | 合并进 KPM 的常驻异常/控制后端（本实现核心） |
| `urov_kpm.c` | KPM 入口、`ctl0` 状态输出、元数据 |
| `decode.c` / `emulate.c` / `core_selftest.c` | A64 解码（GPR 与 `PAGE_AP` 用的 SIMD&FP load）、模拟、4152 项无分配自测 |
| `urov_abi.h` | 用户态/内核共享的 128 字节请求 ABI、kcmp/prctl 通道约定 |
| `tests/urov_overlay_test.c` | 活动覆盖验收程序（8/16/24/32 字节窗口） |
| `tests/urov_hold_test.c` / `urov_hold2_test.c` | 卸载生命周期测试 |
| `tests/urov_foreign_test.c` | 非 owner 控制/死 owner 回收探针 |
| `apps/urov-app/` | 普通 app 验收程序、能力探针与 APK 构建脚本 |
| `tools/run_overlay_device.ps1` | root 设备自动化脚本 |
| `tools/run_app_device.ps1` | 普通 app 设备自动化脚本 |
| `APP_OVERLAY.md` / `RESULTS_APP.md` | 普通 app 方案、检测面、限制与真机证据 |
| `urov_x_backend.c` / `.h` / `urov_x.c` / `urov_x_abi.h` | covert 变体 `urov-x`：密钥化控制通道、读取点绑定、透明生命周期 |
| `urov_y_backend.c` / `.h` / `urov_y.c` / `urov_y_abi.h` | 读取点陷阱变体 `urov-y`：`mode=1` BRK 读取点、`mode=2` EL0 execute-never 页陷阱、`mode=3` 目标页 AP[1] 数据陷阱 + 相邻 LL/SC 桥（仅在 `LDXR` 结果仍存于 `Rt` 时代写）；业务调用窗口；ABI v8 的多页数组、LD1/LD2/LD3/LD4、跨页 load 与整页 SIMD&FP 提交 |
| `PAGE_AP_KEYLESS_RESULTS.md` / `PAGE_AP_KEYLESS_RESULTS_R2.md` | 普通 App 无密钥复核：AP 数据陷阱的可检测特征（R1）与本轮 LL/SC 桥执行存证消除（R2） |
| `tests/urov_y_test.c` | `urov-y` root 验收程序（三种模式；功能/fork/门控/活动期卸载/代码页探针） |
| `apps/urov-detect/uy_fixture.inc` | `urov-y` App 夹具（`y-*` BRK、`z-*` UXN 页陷阱、`w-*` AP 数据陷阱） |
| `apps/urov-detect/mp_fixture.inc` | ABI v8 App 夹具（`mp-multi` 24 页、`mp-ld1` 多结构 load、`mp-cross` 跨页、`mp-srcfile`） |
| `apps/urov-detect/crc_fixture.inc` | CRC 夹具：`crc-ap-text`/`crc-ap-libc`（标量 libc）与 `crc-ap-big`（整页覆盖 + SIMD 大长度传输、内部窗口、`SET`） |
| `tools/run_elimination_device.py` | `urov-y` 设备矩阵（含 `urov-x` 阳性对照与三种模式对照） |
| `tools/run_crc_device.py` | 同进程改码/CRC 矩阵（`crc-brk`/`crc-uxn`/`crc-ap`/`crc-ap-text`/`crc-ap-libc`/`crc-ap-big`） |
| `ELIMINATION_DESIGN.md` / `ELIMINATION_RESULTS.md` | 读取点陷阱方案（§9 UXN、§10 AP+LL/SC 桥、§11 桥的执行存证、§13 SIMD&FP 大长度传输）、代码页/取指特征消除与真机对照结果 |
| `MULTIPAGE_DESIGN.md` | 设计稿：任意多页同时覆盖、LD1/LD2、跨页 load、16 KiB 页（16 KiB 未实现） |
| `MULTIPAGE_RESULTS.md` | ABI v8 多页/LD1/LD2/LD3/LD4/跨页/SRC_FILE 的实现说明与真机证据 |
| `tools/run_multipage_device.py` | ABI v8 设备矩阵（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcfile`） |
| `tools/run_stealth_device.py` | `urov-x` 设备矩阵（无密钥/活动/观察者/卸载/SIMD/fork） |
| `STEALTH_DESIGN.md` / `STEALTH_RESULTS.md` | 检测特征点消除设计与真机对照结果 |
| `results/` | 构建、设备与覆盖运行记录 |
