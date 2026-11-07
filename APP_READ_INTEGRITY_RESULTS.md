# UROV-Y 读取完整性复核结果

本文按最新复核在前排列。

## 2.10.0 同进程内核辅助读与 XZR 独占序列

2026-11-07，在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`）复核。探针在 `untrusted_app` 域运行，`CapEff=0`、
`Seccomp=2`、SELinux Enforcing。设备 root 只用于装卸 KPM 和检查内核日志。
App 夹具使用模块密钥建立会话和核对真值，检测函数只接收自有映射、fd、偏移和
读者。

```text
urov-y.kpm      8e3ad63b39d938a78dd851b54abd79cad3892e4ecbd234d8f45f058afc943110
urovdetect.apk  4f259a66cf7e5cc8f461662bef46257df2a55de6d8f4ccc9363e5c32e682c621
```

### 本轮消除的现役特征

2.9.0 的活动矩阵里普通 CRC 已经通过，但检测器仍能从两条路径给出确定性命中：

1. **同进程 `process_vm_readv` 的双读差异。** GUP 路径不经过 EL0 数据异常，
   内核视图仍是改码后的字节；两次 EL0 读得到镜像，两路稳定不同即 `MATCH`。
   2.9.0 的 Dobby 活动阶段是 480/480。
2. **`LDXR XZR; LDRB; STXR Ws, XZR` 的无预约状态。** `ERET` 清掉本地独占
   监视器后，目标 `STXR` 原生失败；2.9.0 的桥拒绝 `Rt=31`，于是目标组每次
   失败而两侧对照成功，构成 `MATCH`（480/480）。

2.10.0 的做法：

- **`process_vm_readv` after hook。** 沿用已有的 syscall 表控制面，只对调用者
  自身 `mm`、且 `pid` 等于调用者 pid/tgid 的读生效。用 syscall 返回值限定
  重写长度，按 iovec 顺序重走本地/远端流，只替换落在已登记页上的字节；窗口
  语义复用 `caller_allowed_deep()`：窗口内读者拿镜像，窗口外拿注册快照，
  `caller_count=0` 时所有读者拿镜像。不新增 ABI 字段、`ctl0` 位或计数器，
  `hooks=0x7f` 保持不变。
- **XZR 桥。** `LDXR XZR` 与 `STXR XZR` 同时出现、宽度/基址一致、目标字当前
  为零时，handler 与普通桥一样置 `Ws=0` 并跳过 `STXR`；写回 0 是 no-op，保持
  “桥不改变字节”的既有不变量。目标字非零时不桥，保留原生失败。
- **PAC/MTE 间接分支门控。** `BRAA/BLRAA/RETAA` 在寄存器里留下签名指针，
  MTE 还带 top-byte tag；门控同时比较原值和按 `VA_BITS` 掩码后的值，覆盖
  “签名目标仍在 GPR”的形状。
- **完整分支目标图。** 2.9.0 只在 `REGISTER` 扫一次、只看可读可执行 VMA。
  2.10.0 覆盖所有 `VM_EXEC` VMA；扫描时未驻留的页由 `handle_mm_fault` 的
  after hook 在页第一次变为 present 时补扫（在故障任务返回 EL0 之前）；
  `mmap`/`mprotect`/`mremap` 的 after hook 扫描新出现的可执行范围。任一可达
  代码页 “present 但读不到”（如 XOM）或范围无法加入时，map 标为 incomplete，
  读路径 fail-closed，不再用单页扫描兜底。扫描用 seqlock 与故障路径互斥，
  mark 走 O(1) 的源 VMA 快路径；本矩阵 `REGISTER` 为
  `DOBBY_ARM register_ns=69,681,193`（70 ms），2.9.0 同文档记录约 240 ms
  （两次测试进程的映射集可能不同，仅作同设备量级对照）。

[读值选择](urov_y_backend.c) · [分支目标图](urov_y_backend.c) ·
[映射门控](urov_y_backend.c) · [探针实现](native/urov_observe.c#L61)

### 夹具期望的同步调整

- Dobby 的 `overlay` 阶段把双读期望从 `UD_MATCH` 改为 `UD_NO_MATCH`：检测器
  现在与 clean 阶段同形，`accepted_crc` 成为覆盖仍然生效的正向对照。
- `w-active` 的 XZR 期望改为 `UD_NO_MATCH`（`zero_clean`）。
- `crc-ap-all` 的内核期望改为镜像字节；带调用窗口的 `crc-ap*` 仍由窗口外的
  读者拿快照，`window_match` 期望不变。

### 真机结果

Dobby 矩阵 8×1（同一 APK、同一夹具）：

| 阶段 | 样本 | 执行返回 | live CRC32 | 双读命中 | XZR 命中 | 桥/NOP/间接/跨页 | 采信 CRC |
| --- | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 8 | `0x1234` | `96964c4f`，等于文件 | 0 | 0 | 0/256 各 | 8 |
| 仅 Dobby 改码 | 8 | `0x1235` | `2ae99109`，与文件不同 | 0 | 0 | 0/256 各 | 0 |
| 改码 + `PAGE_AP` 全读者覆盖 | 8 | `0x1235` | `96964c4f`，等于文件 | **0** | **0** | **0/256 各** | **8** |
| 注销覆盖后 | 8 | `0x1235` | `2ae99109`，与文件不同 | 0 | 0 | 0/256 各 | 0 |

- 活动阶段 `kernel_crc=96964c4f`（与 EL0 视图、文件一致）、`live views=0/8`、
  `zero_match=0 zero_clean=8`、`bridge_successes=0`、`nop_successes=0`、
  `ind_successes=0`、`cross_page_successes=0`；`spaced_accepted=768`、
  `spaced_failed=0`，说明相邻/NOP 间隔桥仍在工作。`hits=4032`、`failures=0`。
  单次跨页探针平均 2.93 ms、最大 3.02 ms；双读平均 0.322 ms。
- 业务线程与 UI 心跳照常；worker `807 ms`、135 条断言、0 失败。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 8×1 | PASS；`accepted_crc=8/8`、双读/XZR/四种桥全部 0 | [dobby-detect-20261107-200157](results/dobby-detect-20261107-200157/summary.json) |
| CRC 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big）；`crc-ap-all` 的 `direct=window=file`，全部 `bridge=0/5` | [crc-20261107-200217](results/crc-20261107-200217/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行；`w-active` 497 条断言，XZR 全部 clean；`ELIM_TIMING mode=ap site_call_ns=281` | [eliminate-20261107-200235](results/eliminate-20261107-200235/summary.json) |
| 多页 3×1 | PASS，5 次运行（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcpage`/`mp-audit`） | [multipage-20261107-200347](results/multipage-20261107-200347/summary.json) |

CRC 回归中 `crc-ap` 仍是 `direct=0c7da8a0`、`window=f50bcaf6`（窗口外读者拿
快照的既有语义）；`crc-ap-all` 为 `direct=window=f50bcaf6`，与镜像一致；
`crc-ap-text`/`crc-ap-libc`/`crc-ap-big` 三项继续通过，`crc-ap-big` 的
16/32/64/160/512/1024/4096 字节业务读者矩阵不变。所有矩阵结束后 `kpm list`
为空，boot ID 不变，增量内核日志未匹配崩溃、挂起或 BUG。

### 审计特征点现状（2.10.0 PAGE_AP）

| 审计条目 | 2.10.0 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻、NOP 间隔与 XZR 目的三种形状都由桥完成；直接分支、PAC/MTE 间接分支仍被门控拒绝。 |
| 1b. 无预约 `STXR` 状态探针 | 直接/NOP/间接/跨页四种形状均 0/256；XZR 只对零目标 no-op 代写，非零目标保持原生失败。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；回归矩阵保持阴性。 |
| 3. 业务读者/独立读者差异 | `caller_count=0` 时所有读者（含 GUP）拿同一镜像；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 固定 `prctl` 指纹 | 未变：每次加载派生 option/MAC，未认证请求仍是原生 `EINVAL`。 |
| 5. 同进程 `process_vm_readv` 双读 | 已消除：GUP 视图与 EL0 视图一致。 |

### 残余（2.10.0）

1. 每次读取仍一次同步异常；锁页重装窗口、root 可见性、注册事务窗口仍在；
   桥的 store 仍是内核 nofault 普通写，不是硬件独占 store。
2. 分支目标图的完备性依赖“扫描时/首次 present 时可读”。XOM 或不透明可执行页
   会让 map 进入 incomplete 并关闭桥（fail-closed）；`REGISTER` 之后新建的
   **匿名可执行**映射若在原地写入并在不再次 `mprotect` 的情况下执行，写入后的
   分支不会被补扫；已扫描页内的自修改代码同理。W^X（写完再 `mprotect RX`）
   流程由 mprotect after hook 覆盖。
3. 只接管同 `mm`、同一进程的 `process_vm_readv`。`/proc/self/mem`、ptrace、
   跨进程 `process_vm_readv`/`process_vm_writev` 以及 iovec 数超过 64 的调用
   仍看到真实字节；本夹具不使用这些路径。
4. `REGISTER` 仍有一次全进程代码扫描；本矩阵 70 ms，是控制面成本，不在 CRC
   读取循环里。
5. XZR 桥只在目标字为零时生效；非零 `STXR XZR` 保持原生失败。
6. `caller_count > 0` 的窗口内外读者差异仍是有意保留的 API 语义；
   `process_vm_readv` 按 syscall 的帧链选择镜像或快照。

### 复跑

在仓库根目录执行，使用 SHA-256 与本节一致的 `out/urov-y.kpm` 和
`apps/urov-detect/out/urovdetect.apk`。

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 3 --cycles 1
```

## 2.9.0 普通 App 同进程读值复核

2026-11-07，在 Pixel 6（Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`）复核。探针在 `untrusted_app` 域运行，`CapEff=0`、
`Seccomp=2`、SELinux Enforcing。设备 root 用于装卸 KPM 和检查内核日志。
App 夹具使用模块密钥建立会话和核对真值，检测函数只接收自有映射、fd、偏移和读者。

```text
urov-y.kpm      f7d55fd8e96c6f6ba3a5e3af5aab8b33f2c6cdca300f5df074d7eccff30cb96d
urovdetect.apk  8c171280f70cb5c518072b6c24a84ba9caa8191e67e1e8e5a69993694165f1f5
```

### 实现与检测依据

`REGISTER` 在当前 `mm` 内登记只读可执行页，保留注册时的现场字节，再将调用者通过
`SRC_USER` 提供的窗口合入覆盖镜像。模块只有一个活动会话。异常处理器根据 `x30` 或
最多 16 层 `x29` 帧链选用覆盖镜像或现场快照，`caller_count=0` 时全部匹配。它解码
触发异常的 load，将读值、地址写回和 PC 更新提交给用户态。多页 AP 按地址切段取值，
缺页安装 PTE 后会重装陷阱。
[注册](urov_y_backend.c#L1852) · [读值选择](urov_y_backend.c#L1463) ·
[异常与重装](urov_y_backend.c#L1611)

| 模式 | 触发点 | 可复核的证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 后把登记的读指令换成 BRK | 同进程双读检查实际业务读者，已知读指令字与发布 ELF 的差异可定位触发点 |
| `PAGE_UXN` | 在读指令所在页置 UXN，接管 EL0 取指异常 | 同进程双读检查实际业务读者，已知同页 canary 的配对取指可定位触发点 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，EL0 读触发权限异常，取指仍走原页 | 同进程双读检查目标字节，XZR 独占序列可补查同值覆盖 |

- `process_vm_readv(getpid(), ...)` 通过 GUP 固定本进程的实际页，从内核视图复制字节。
  当前 Y 接管 EL0 异常和控制、映射等入口，这条读取路径绕过其读值模拟。先读一次
  内核视图，再走两次真实读路径，最后重读内核视图。两路各自稳定、映射身份稳定且
  两路逐字节不同才报告 `MATCH`。I/O 错误、短读、错配文件偏移和不稳定样本归为
  `UNKNOWN`。两路一致且字节符合发布基准时才采信完整性结果。带调用窗口时要复用实际
  读路径，另起一个普通 load 可能只读到现场快照。
  [探针实现](native/urov_observe.c#L63) ·
  [Linux 内核读](https://raw.githubusercontent.com/torvalds/linux/v6.1/mm/process_vm_access.c) ·
  [同 mm 检查](https://raw.githubusercontent.com/torvalds/linux/v6.1/kernel/fork.c)
- `LDXR XZR; LDRB; STXR Ws, XZR` 在私有零值 scratch 上建立独占预约，目标代码页
  只做 `LDRB`。2.9.0 的桥拒绝 `Rt=31`，因此 AP 异常返回后原生 `STXR` 报失败。
  每次要求三个批次，每批 32 组同文件 RX 别名成功、目标失败、别名再成功的对照。
  混合结果归为 `UNKNOWN`。这一项受 CPU、调度与调试环境影响，作为陷阱的补充证据。
  [桥的寄存器校验](urov_y_backend.c#L1409) ·
  [Arm A64 独占监视器](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)

### 避免采信和撤销覆盖

- 检查在 worker 上低频运行，每次最多 64 字节且限一页，调用方保留 RX 映射和 fd 的
  生命周期。`MATCH` 和 `UNKNOWN` 的完整性结果不予采信，普通业务沿原路径运行。
  只在已验证允许 `process_vm_readv` 的 Android 配置启用该入口，其他配置可能因
  seccomp 收到 `SIGSYS`。结果范围限于采样地址、读者和时段。
  [探针接口](native/urov_observe.h#L32)
- 需要撤销已确认的活动会话时，在受控页上调用 `madvise(page, page_size, -1)`。
  Y 先按地址重叠恢复整个会话的陷阱，随后原生 Linux 拒绝无效 advice，返回 `EINVAL`。
  以撤销后的重新采样验证读值恢复。地址不重叠时同样返回 `EINVAL`，活动会话仍在。
  这是针对当前门控顺序的一次性处置，作用范围是整个会话。
  [映射门控](urov_y_backend.c#L2317) ·
  [Linux madvise 实现](https://raw.githubusercontent.com/torvalds/linux/v6.1/mm/madvise.c)
- 可在进程早期选择启用 seccomp TSYNC，拒绝 ARM64 上同时匹配 `prctl`、固定
  `UROVYLAB` magic、`REGISTER` 和 288 字节的请求，然后处理已有会话。过滤器和
  `NoNewPrivs` 在进程内不可撤销，后者约束 `execve` 提权。保护覆盖该线程组及继承
  过滤器的任务，依赖当前控制 ABI 和内核执行入口。
  [夹具过滤器](apps/urov-detect/dobby_crc_fixture.inc#L156) ·
  [Linux seccomp 文档](https://www.kernel.org/doc/html/v6.1/userspace-api/seccomp_filter.html)

### 真机结果

Dobby 矩阵包含 10 个活动进程，每阶段 48 次，外加未加载、加载空闲和卸载后对照。

| 阶段 | 样本 | 执行返回 | 普通 CRC 通过 | 双读命中 | XZR 命中 | 采信 CRC 通过 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | 624 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | 0 | 0 | 0 | 0 |
| 改码并启用 AP 全读者覆盖 | 480 | `0x1235` | 480 | 480 | 480 | 0 |
| 撤销覆盖后 | 480 | `0x1235` | 0 | 0 | 0 | 0 |

- AP 活动期间，普通读值的 CRC32 为文件值 `96964c4f`，内核视图为改码后的
  `aa953cdd`。双读与 XZR 全矩阵均为零未知，旧跨页探针在活动期仍为 0/480。
  双读活动期平均 0.330 ms、最大 0.660 ms，全部阶段最大 3.841 ms。UI 心跳最大间隔
  21 ms，业务线程累计 10,619,264 次迭代，零错误。
  [Dobby 原始数据](results/dobby-detect-20261107-191555/summary.json)
- 10/10 次重叠的无效 `madvise` 撤销会话并保留测试页的 `MADV_RANDOM`、VMA 范围
  与 RX 权限。10/10 次非重叠对照保持活动。TSYNC 安装 10/10 次成功，安装线程和
  安装前已存在的线程各 10/10 次重新注册收到 `EPERM`。
  [撤销与拦截记录](results/dobby-detect-20261107-191555/summary.json)
- CRC 矩阵 23 次运行通过。BRK、UXN、带调用窗口的 AP 各有 72/72 次业务读者命中，
  独立读者各 0/72。AP 全读者覆盖下两个用户读者各 72/72 次命中。960 组对照均为
  阴性，所有双读零未知。四类会话均经无效 advice 恢复，各 3/3 次。其余 `.text`、
  libc/zlib 与大块拷贝回归通过。
  [CRC 原始数据](results/crc-20261107-191717/summary.json)
- 模式与生命周期矩阵 17 次运行通过。AP 的活动页、覆盖窗口外、`SET` 后及等值覆盖
  四项 XZR 观测各命中 36/36。多页、向量和跨页矩阵 5 次运行通过。全部测试结束后
  模块列表为空，boot ID 一致，内核增量日志未匹配崩溃或挂起。
  [模式和生命周期](results/eliminate-20261107-191815/summary.json) ·
  [多页回归](results/multipage-20261107-191950/summary.json)

这些结果覆盖本机、该 KPM 构建和已知稳定的自有 RX 页。其他 Android 策略、SoC、
16 KiB 真机和生产流量需要各自校验。普通 App 的证据依赖当前内核读路径，拥有内核
执行权的一方可以改变读路径或过滤策略。

### 复跑

在仓库根目录执行，使用 SHA-256 与本节一致的 `out/urov-y.kpm`。

```powershell
./kpms/urov-lab/apps/urov-detect/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1 -Observer
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 24 --cycles 3
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 12 --cycles 3
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
```

## 2.9.0：REGISTER 期全进程分支目标位图

2026-11-07，Pixel 6（oriole），Android 16，`6.1.134-android14-11`，4 KiB，
KernelPatch `0xc00`。被测构建：

```text
urov-y.kpm      f7d55fd8e96c6f6ba3a5e3af5aab8b33f2c6cdca300f5df074d7eccff30cb96d
urovdetect.apk  2ad6df7061ad2e3a307b265cca407de37a6e7e6197f9e3476b0310d86df8132e
```

本轮消除 2.8.0 的现役特征：跨页直接分支探针。`REGISTER` 在清任何 `AP[1]`
之前，先枚举会话 `mm` 的所有可读可执行 VMA，把全部
`B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ` 的静态目标写入按 VMA 划分的位图；故障时只查
`[LDXR+4, load]`。`uy_llsc_prepare()` 的寄存器、宽度、自然对齐和
`Rt == [Xn]` 条件不变；`uy_llsc_commit()` 仍是同一地址、宽度和值的 nofault
普通写。

先试的硬件独占监视器方案在异常进入时失效：handler 内清 `PAN` 后发出的真实
`STXR` 在 2656 次尝试中全部失败（`dbg prepare=2656 pte=0 ok=0 fail=2656`），
因此改为注册期位图，避免读取路径出现首次扫描的 50–130 ms 尖峰。最终读取路径
的 `ELIM_TIMING mode=ap site_call_ns=283` 与 2.8.0 的 281 同量级。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS；活动阶段 `execute=0x1235`、`live=96964c4f`（等于文件）、`accepted_crc=24/24`、`cross_page_successes=0/768`、`bridge/nop/ind` 均 0；平均探针 3.03–3.27 ms，最大 7.68 ms | [dobby-detect-20261107-184405](results/dobby-detect-20261107-184405/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、1438 条断言；`ELIM_BRIDGE` 四项均 `verdict=0 trials=32 successes=0`；`ELIM_TIMING mode=ap site_call_ns=283` | [eliminate-20261107-184445](results/eliminate-20261107-184445/summary.json) |
| CRC 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-184601](results/crc-20261107-184601/summary.json) |
| 多页 3×1 | PASS，5 次运行（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcpage`/`mp-audit`） | [multipage-20261107-184622](results/multipage-20261107-184622/summary.json) |

测试进程的分支位图为 358 个可执行 VMA、6,000,742 字节；`REGISTER` 扫描约
240 ms。该成本只在显式注册路径，故障路径只做位测试。测试前后 boot ID 一致，
`kernel_issues=[]`，`kpm list` 为空。

### 审计特征点现状（2.9.0 PAGE_AP）

| 审计条目 | 2.9.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 顺序到达由桥完成；直接分支（含跨页、跨映射、任意距离）由注册期位图拒绝；间接分支目标仍在 GPR 时由 GPR 门控拒绝。 |
| 1b. 无预约 `STXR` 状态探针 | 直接/NOP/间接/跨页四种形状均 0/32；预置 `Rt==[Xn]` 也需 LDXR 真的执行，否则被分支/GPR 门控拦下。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；代码字与 smaps 仍等于基线。 |
| 3. 业务读者/独立读者差异 | `caller_count=0` 时所有读者拿同一伪视图；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 固定 `prctl` 指纹 | 每次加载派生 option/MAC；未认证请求仍是原生 `EINVAL`。 |

### 残余（2.9.0）

1. `REGISTER` 之后新建的可执行映射不在位图中；从这种映射跳入 `[LDXR+4, load]`
   的跨映射直接分支仍可绕过。
2. 不可读的可执行页（XOM）或 `REGISTER` 时未驻留的代码页无法 nofault 复制，
   其中的直接分支源不被扫描。
3. 间接分支的目标寄存器若在 load 前被覆盖，GPR 门控看不到（§16.5 残余）。
4. 注册路径新增一次全进程代码扫描：测试进程 358 个可执行 VMA、6.0 MB 位图、
   约 240 ms；读取路径不变。
5. 每次读取仍一次同步异常；PTE 重装窗口、root 可见性、注册事务窗口不变；桥的
   store 仍是内核 nofault 普通写，不是硬件独占 store；`caller_count > 0` 的窗口
   内外读者差异仍是有意保留的 API 语义。

### 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --dobby-detection --repeats 24 --cycles 5
python .\kpms\urov-lab\tools\run_elimination_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-x-control --repeats 3 --cycles 1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-install --repeats 5 --cycles 1
python .\kpms\urov-lab\tools\run_multipage_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-install --repeats 3 --cycles 1
```

以下为 2.8.0 及更早的复核记录。

## 2.8.0：移除 SRC_FILE，统一 SRC_USER 整页

2026-11-07，同一 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB /
KernelPatch `0xc00`。被测构建：

```text
urov-y.kpm      82f50d464bf1d701135124ea55932655bcdf52060c01e498dd7eed38ac7d2adf
urovdetect.apk  5ebc98018feae8eb745117c880767f3090bc4e85475eee20699f59d07b05e573
```

`urov-y` 2.8.0 不再支持 `SRC_FILE`：

- `UROV_Y_PAGE_SRC_FILE` 仅作为保留位保留，`REGISTER` 返回 `EINVAL`；
- `page_read_file()`、`kernel_read(vm_file, ...)` 的页读取路径移除；
- `QUERY` 不再报告 `UROV_Y_CAP_SRC_FILE`；
- 所有镜像由 `SRC_USER` 提供，一个页描述符一次最多传一页（4 KiB/16 KiB），
  由模块在 `REGISTER`/`SET_PAGE` 时复制，之后不再解引用调用者缓冲区。

测试夹具相应调整：

- Dobby 夹具在 `DobbyHook` 前把目标页的**完整干净页**从 ELF 读入
  `mmap` 用户缓冲区，用 `SRC_USER(off=0, len=page_size)` 注册；不再依赖
  `vm_file`/`vm_pgoff`。
- 多页夹具的 `mp-srcfile` 改为 `mp-srcpage`：用改过首尾字节的整页镜像注册，
  验证呼叫窗口内读到 `image`、窗口外和注销后读到真实页；`MP_AUDIT` 中
  `SRC_FILE` 描述符仍作为非法输入被 `EINVAL` 拒绝。

### 真机结果

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×1 | PASS；活动阶段 `execute=0x1235`、`live=96964c4f`（等于文件）、`accepted_crc=24/24`、直接/NOP/间接探针均 0/24 | [dobby-detect-20261107-174813](results/dobby-detect-20261107-174813/summary.json) |
| 多页/LD1/跨页/SRC_USER 整页 | PASS，5 次运行；`mp-srcpage` 窗口内等于镜像、窗口外和注销后等于真实页 | [multipage-20261107-174756](results/multipage-20261107-174756/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-174837](results/crc-20261107-174837/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、443 条断言；`ELIM_BRIDGE` 三项均 0/32；`ELIM_TIMING mode=ap site_call_ns=271` | [eliminate-20261107-174908](results/eliminate-20261107-174908/summary.json) |

因此，2.8.0 的读取覆盖不再依赖“从 VMA 后备文件借用页”的路径；干净页由调用者
一次性提供，模块只保存一份内核镜像。`SRC_USER` 的 `fake_len=0` 或
`fake_len=page_size` 都表示整页，`fake_off` 仍可指定页内窗口。

以下为 2.7.0 及更早的复核记录；其中 2.7.0 的 Dobby/多页矩阵使用 `SRC_FILE`，
仅作历史对照。

## 2.7.0 第八轮：NOP 间隔与间接分支门控

2026-11-07，Pixel 6（oriole），Android 16，内核 `6.1.134-android14-11`，4 KiB 页，
KernelPatch `0xc00`。检测仍在 `untrusted_app` 域运行（`CapEff=0`、`Seccomp=2`），
root 只用于装卸 KPM。被测构建：

```text
urov-y.kpm      ff818b3ee62995b7353b30346ce7dca4b9601390f6edf2ce3ec9817b0c930d18
urovdetect.apk  e21607a7cd45c6061458eb3e4094c2c43e58f1a430980da4215e4572dbb8954d
```

2.6.0 的直接分支门控只检查“目标等于故障 load PC”的
`B/BL/CBZ/CBNZ/TBZ/TBNZ`。新增的 NOP 分支探针把目标落在 load 前的 `NOP`
上：

```asm
clrex
b 1f
ldxr x9, [x1]        ; never executed
1: nop
ldrb w10, [x0]       ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]    ; Rt preset to [x1]
```

2.6.0 的 `uy_llsc_prepare()` 允许 `LDXR` 与 load 之间有 0–3 个 NOP，但
`uy_llsc_skipped()` 只扫描目标等于 load 的分支，因此该形状得到伪造的 `STXR`
成功（报告中的 480/480 命中）。2.7.0 新增：

1. **整页直接分支门控**：分块扫描故障 load 所在页的
   `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ`，目标落在 `[LDXR+4, load]` 即不代写；
   覆盖 NOP 间隔和 ±256 字节外的同页分支。
2. **间接分支寄存器门控**：故障时若 `x0..x30` 任一值落在同一区间，说明
   `ADR/ADRP + BR`、literal + `BR`、`RET` 等路径可能跳过 `LDXR`，不代写。
3. **`B.cond` 解码**：补上 2.6.0 漏掉的直接条件分支编码。

门控只读，不新增 hook、syscall、PTE/VMA/代码字节改动、`ctl0` 字段或 ABI 变化。

### Dobby 24×1

同一 Dobby 夹具：执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP + SRC_FILE`
让 32 字节代码读取回到文件字节。文件 CRC32 为 `96964c4f`，Dobby 改码后的
内存 CRC 为 `cda907a7`。

| 阶段 | 执行返回值 | 内存 CRC32 | 直接分支探针 | NOP 分支探针 | 间接分支探针 | 采信 CRC |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 0/24 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `cda907a7`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **0/24** | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `cda907a7`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |

活动阶段 `bridge=0/24`、`spaced=0/24`、`unknown=0`，并行业务线程照常运行。
[原始数据](results/dobby-detect-20261107-171627/summary.json)

### 消除矩阵与 CRC 回归

`run_elimination_device.py --skip-x-control --repeats 3 --cycles 1`：11 次运行、
443 条断言全部 PASS。`w-active` 的直接、NOP、间接三项 `ELIM_BRIDGE` 均为
`verdict=0 trials=32 successes=0`；`ELIM_RESIDUAL mode=ap` 仍是
`site_file_word == site_live_word`、`site_cow_private=0`、
`Private_Dirty/Anonymous=0`；`ELIM_TIMING mode=ap site_call_ns=288`。
[消除数据](results/eliminate-20261107-171731/summary.json)

`run_crc_device.py --repeats 5 --cycles 1`：9 次运行 PASS，覆盖 `crc-brk`、
`crc-uxn`、`crc-ap`、`crc-ap-all`、`crc-ap-text`、`crc-ap-libc`、`crc-ap-big`，
其中 `crc-ap` 的 `direct=0x0c7da8a0`、`window=file=0xf50bcaf6`，
`crc-ap-all` 的 `direct=window=file`。
[CRC 数据](results/crc-20261107-171907/summary.json)

`run_multipage_device.py --skip-install --repeats 3 --cycles 1`：5 次运行 PASS
（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcfile`/`mp-audit`）。
[多页数据](results/multipage-20261107-172858/summary.json)

### 审计特征点现状（2.7.0 PAGE_AP）

| 审计条目 | 2.7.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻/NOP 间隔顺序到达由桥完成；直接分支到 load 或 NOP、同页更远直接分支、目标仍在 GPR 的间接分支均不代写，`MATCH=0`。 |
| 1b. 无预约 `STXR` 状态探针 | 直接分支到 load 的变体不代写；NOP 变体本轮从 480/480 命中降为 0/24；间接 `ADR + BR` 变体也为 0/24。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限；代码字与 smaps 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具 `caller_count=0`，所有读者拿同一伪视图，`reader_diff=0`；带窗口的 `crc-ap` 仍只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | 每次加载派生 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

### 残余（2.7.0）

1. 间接分支的目标寄存器在 load 前被覆盖时，门控看不到区间地址。
2. 从另一页跳入本页的直接分支不在单页扫描范围。
3. 保守误伤扩大：本页任意分支目标落在 `[LDXR+4, load]`，或任一 GPR 恰好
   持有该区间地址时，桥不生效、原生 `STXR` 失败。
4. 每次读取仍一次同步异常；AP 业务调用 288 ns、UXN 约 404 ns。PTE 重装窗口、
   root 可见性、注册事务窗口仍在。
5. 桥的 store 仍是内核 nofault 普通写，不是硬件独占 store。
6. `caller_count > 0` 的窗口内外读者差异仍是有意保留的 API 语义。

### 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --dobby-detection --repeats 24 --cycles 1
python .\kpms\urov-lab\tools\run_elimination_device.py --serial <SERIAL> --key <KP-KEY> `
  --skip-x-control --repeats 3 --cycles 1
python .\kpms\urov-lab\tools\run_crc_device.py --serial <SERIAL> --key <KP-KEY> `
  --repeats 5 --cycles 1
```

以下为 2.6.0 及更早的复核记录。

## 2.6.0 读取完整性复核

2026-11-07，Pixel 6（oriole），Android 16，内核 `6.1.134-android14-11`，4 KiB 页，
KernelPatch `0xc00`。测试 App 在 `untrusted_app` 域运行（`CapEff=0`、`Seccomp=2`），
root 只用于装卸 KPM。被测构建：

```text
urov-y.kpm      32c0eaca05b36e748196406c2cf5066be88f436bf8e487376af424c44b342b9b
urovdetect.apk  494d942930710447d14cd1087a314b8d4bd11d9c46f4d5695453be44c01be681
```

## 2.6.0 普通 App 无密钥复核与会话防护

沿用上面同一份 `urov-y.kpm`，重新构建测试 APK，SHA-256 为
`f5cd6a707025cdac786646230144d4c7aa1c1da4f3a3469afc111c328bb55d68`。矩阵仅装卸
`urov-y`。检测在 `untrusted_app` 中运行，`CapEff=0`、`Seccomp=2`。模块密钥由
夹具用于建立和核对会话，检测函数只接收目标地址、同文件 RX 别名、fd 和偏移。

### 模式与检测信号

Y 用认证后的 `REGISTER` 把单一活动会话绑定到调用者 `mm`。注册为每页保存现场快照，
`SRC_USER` 合成指定窗口，`SRC_FILE` 从 VMA 后备文件取整页。异常处理解码读取指令，
在 `x30` 或最多 16 层 `x29` 帧链命中业务窗口时取覆盖镜像，窗口外取注册快照。
`caller_count=0` 时所有读者共用覆盖镜像。处理器的 GPR、FPSIMD、地址回写和 PC 按模拟
结果提交。重叠的映射操作会先恢复陷阱，缺页回调会重装活动页的陷阱。
[注册](urov_y_backend.c#L1700) · [读值选择](urov_y_backend.c#L1284) · [异常分流](urov_y_backend.c#L1398)

| 模式 | 内核做法 | 普通 App 证据 |
| --- | --- | --- |
| `SITE_BRK` | COW 后把登记的读取指令换成 `BRK` | 比较已知读取点的指令字和同一发布 ELF 偏移，配合真实业务读者和独立读者的结果差异。`smaps` 的 COW 统计可佐证。 |
| `PAGE_UXN` | 置读取点页的 UXN，接管 EL0 取指异常 | 在已知的读取点页调用自有 `BTI C; RET` canary，用同文件别名配对检查异常返回导致的独占预约丢失。 |
| `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]，接管 EL0 数据读异常，原页继续供取指 | 验证未建立独占预约的 `STXR` 是否被异常处理器代报成功。`SRC_FILE` 可同时骗过内存 CRC 与文件比对。 |

`PAGE_AP` 新探针执行 `CLREX → B`，跳过 `LDXR` 落在紧邻 `LDRB` 之前的 `NOP`。
原生 `STXR` 返回 1，线程私有 scratch 保持初值。2.6.0 的扫描只查分支是否直接指向
故障 `LDRB`，而向前匹配允许 `NOP`。当 `Rt` 预置为 scratch 的值时，内核桥接逻辑把
同值写回 scratch，令 `Ws=0` 并跳过 `STXR`。探针将该状态与同文件、同偏移的独立 RX
别名比较。每次需要 32 个三元组，前后对照的 `STXR` 均失败，目标组全部报成功且
scratch 不变才输出 `MATCH`。混合结果、对照异常或文件与映射身份变化为 `UNKNOWN`。
目标页只读，测试在 worker 运行。该状态信号的阳性不依赖延迟阈值或普通预约失败率。
[分支门控和桥](urov_y_backend.c#L1170) · [探针](native/urov_observe.c#L99) ·
[Arm A-profile 架构参考手册](https://developer.arm.com/documentation/ddi0487/latest/)

### 会话处置

- **完整性判定。** `MATCH` 和 `UNKNOWN` 的 CRC 结果不采信，普通业务照常执行。
  实际接入时持有目标映射与 fd 的生命周期，在 worker 低频检查稳定的自有 RX 页。
  `NO_MATCH` 仅覆盖本次采样路径和时段。当前 `PAGE_AP` 信号依赖该构建的 LL/SC 桥可用，
  不同内核的桥接能力、16 KiB 真机和生产流量需另验。
- **撤销活动覆盖。** 对已是 `MADV_NORMAL` 的自有专用测试页调用同一 advice。Y 的
  `madvise` 门控在原系统调用前恢复陷阱。夹具随后读到 Dobby 改码后的真实 CRC，
  函数仍返回 `0x1235`。该操作可能结束整个 `mm` 的会话，部署时只在受控页使用。
  [映射门控](urov_y_backend.c#L2083) · [恢复夹具](apps/urov-detect/dobby_crc_fixture.inc#L187)
- **阻止重新注册。** 夹具在恢复前安装 seccomp TSYNC。规则只对 ARM64 上匹配固定
  `UROVYLAB` magic、`REGISTER` 命令与 288 字节参数长度的调用返回 `EPERM`。该规则
  不需要密钥，覆盖同一入口的三种模式。它在系统调用表进入 Y hook 前生效。过滤器和
  `NoNewPrivs` 在进程内不可撤销，且 `NoNewPrivs` 约束 `execve` 的权限变化。上线需要在可能
  注册之前安装、确认 TSYNC 成功，并限于接受此进程策略的场合。已有会话需要单独恢复。
  [过滤器](apps/urov-detect/dobby_crc_fixture.inc#L139) · [seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html) ·
  [ARM64 系统调用顺序](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/kernel/syscall.c)

这些结果针对当前 KPM 和 ABI。能修改内核的一方也能改变异常处理、过滤器或 App 的结果，
因此普通 App 的本地证据只适用于受测实现和范围。

### 真机结果

Pixel 6，Android 16，4 KiB，Dobby 模式 13 个进程，其中活动进程 10 个，每阶段 48 次。

| 阶段 | 样本 | 执行返回 | 传统 CRC 通过 | 新探针 `MATCH` | `UNKNOWN` | 采信 CRC 通过 |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | 624 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | 0 | 0 | 0 | 0 |
| 改码后 `PAGE_AP + SRC_FILE` | 480 | `0x1235` | 480 | 480 | 0 | 0 |
| `MADV_NORMAL` 恢复后 | 480 | `0x1235` | 0 | 0 | 0 | 0 |

- 活动阶段 15,360 个目标三元组全部报告未预约的 `STXR` 成功，两侧对照均失败。旧的
  相邻、间隔、直接跳到 `LDRB` 的三种探针活动阶段均为 0/480 命中。新探针活动阶段
  单次平均 3.07 ms，最大 3.23 ms。全 Dobby 矩阵的新探针最大 11.32 ms，UI 心跳
  最大间隔 21 ms，并行业务线程累计 5,633,920 次操作，0 错误。
- `MADV_NORMAL` 使活动会话 10/10 次转为 `inactive`。TSYNC 10/10 次安装成功，
  安装线程及安装前已存在的线程各 10/10 次收到 `EPERM`，会话保持空闲。
  受测进程的 `NoNewPrivs` 从 0 变为 1。
- 三模式和生命周期矩阵 17 次 App 运行通过。BRK 指令字对照 3/3 命中，UXN 活动取指
  144/144 命中，AP 的 NOP 分支探针 33/33 命中。AP 覆盖了 8 个 CPU、业务调用窗口外、
  伪造字节窗口外和等值覆盖。其他 UID 与空闲、撤销的 AP 对照均无命中。
- CRC 矩阵 9 次与多页矩阵 5 次均通过，覆盖业务窗口、libc/zlib、多页、向量和跨页读取。
  整轮测试前后 boot ID 一致，各矩阵的增量内核日志均未匹配异常，测试后模块列表为空。

原始数据见 [Dobby 与防护](results/dobby-detect-20261107-164723/summary.json) ·
[三种模式](results/eliminate-20261107-164811/summary.json) ·
[CRC](results/crc-20261107-164942/summary.json) ·
[多页](results/multipage-20261107-165000/summary.json)。

在 `kpms\urov-lab` 目录复跑时使用报告开头哈希匹配的 `out\urov-y.kpm`。

```powershell
.\apps\urov-detect\build.ps1
.\apps\urov-detect\build.ps1 -Observer
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 48 --cycles 10
python .\tools\run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 12 --cycles 3
python .\tools\run_crc_device.py --serial $Serial --key $KpKey --skip-install --repeats 5 --cycles 1
python .\tools\run_multipage_device.py --serial $Serial --key $KpKey --skip-install --repeats 3 --cycles 1
```

以下为 2.6.0 发布时原探针的回归记录。

## 2.6.0 本轮改动

2.5.0 的相邻 LL/SC 桥只用寄存器状态（`Rt == [Xn]`）判断 `LDXR` 是否执行；
调用者先读 `[Xn]`、把 `Rt` 预置成同一值、再用直接分支跳过 `LDXR`，仍会得到一次
伪造的 `STXR` 成功（`ud_observe_unreserved_status()` 的 MATCH）。2.6.0 增加两道
门控：

1. **直接分支门控**。提交桥之前扫描故障 PC 两侧各 256 字节的代码页，解码
   `B/BL/CBZ/CBNZ/TBZ/TBNZ`；只要有一条分支的目标落在故障 load 上，说明该路径
   可以绕过 `LDXR` 进入读取，handler 不代写，PC 停在 `STXR` 上让它原生失败。
   扫描只读、有界；代码页本身被注册为陷阱页时改用注册快照。
2. **NOP 间隔桥**。`LDXR` 与 load 之间允许 0–3 个 `NOP`，消除
   `LDXR; NOP; LDRB; STXR` 的形状残余；寄存器、宽度、`Rt == [Xn]` 与“待写值
   等于内存”的约束不变。

本轮还实测并否决了“在 EL1 重放 `STXR` 探测本地独占监视器”的方案：在
KernelPatch 线性映射别名上重放同一宽度、同一值、同一物理地址的 `STXR`，真实
`LDXR` 之后仍稳定返回 1，说明数据异常进入 handler 前本地监视器已经不可用。
执行存证只能来自控制流，不能来自监视器。设计与残余见
[ELIMINATION_DESIGN.md §15](ELIMINATION_DESIGN.md#15-第七轮直接分支门控与-nop-间隔桥)。

## 审计特征点现状

| 审计条目 | 2.6.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻/`NOP` 间隔且顺序到达的序列由桥完成，`STXR` 成功，`MATCH=0`；直接分支落到 load 的伪造序列不桥。 |
| 1b. 无预约 `STXR` 状态探针 | `CLREX/B;LDXR` + 预置 `Rt` 被直接分支门控拒绝，目标 `STXR` 原生失败，`MATCH=0`、`stores=0`。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限，不适用；代码字与 `smaps` 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具使用 `caller_count=0`（所有读者拿同一伪视图），`reader_diff=0`；带调用窗口的 `crc-ap` 仍按设计只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | `urov-y` 使用每次加载派生的 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

## 2.6.0 Dobby 矩阵

`run_crc_device.py --dobby-detection --repeats 24 --cycles 5`，5 轮活动运行。
同一 APK、同一夹具：Dobby 把执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP +
SRC_FILE` 把 32 字节代码读取改回文件字节。

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 间隔探针 MATCH | 无预约状态 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 0/24 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `16215a4e`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **0/24** | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `16215a4e`，与文件不同 | 0/24 | 0/24 | 0/24 | 0/24 |

5 轮合计 120 次活动探针；每轮 `DOBBY_DETECT_STATUS hits=6528 failures=0`，
`bridge_trials=768`、`bridge_successes=0`、`spaced_failed=0`，并行业务线程
`ops=187136 errors=0`。活动阶段三种探针平均约 9.1 ms，最大约 9.3 ms。2.5.0 的
同一矩阵是 `bridge_match=24/24`、`accepted_crc=0/24`。[原始数据](results/dobby-detect-20261107-162507/summary.json)

## 2.6.0 消除矩阵与回归

`run_elimination_device.py --repeats 3 --cycles 1`：12 次运行全部 PASS，包含
`urov-x` 阳性对照、三种 Y 模式、不同 UID 观察和活动期卸载。

- `w-active` 的 `active_page`、`active_outside_window`、`active_after_set`、
  `active_equal_value` 均为 `exclusive_match=0`、`exclusive_clean=3`；
  `ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。
- 11 项 `ELIM_BRIDGE`（含 8 个 CPU）全部 `expected=0 verdict=0 trials=32
  successes=0`。
- `ELIM_RESIDUAL mode=ap`：`site_file_word == site_live_word`，
  `site_cow_private=0`，`Private_Dirty/Anonymous` 与基线一致；
  `ELIM_TIMING mode=ap site_call_ns=283`。

| 矩阵 | 结果 | 结果目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS，120/120 采信 CRC，三种探针 MATCH 0 | [dobby-detect-20261107-162507](results/dobby-detect-20261107-162507/summary.json) |
| 消除矩阵 3×1 | PASS，12 次运行 | [eliminate-20261107-162803](results/eliminate-20261107-162803/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-162542](results/crc-20261107-162542/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-162615](results/multipage-20261107-162615/summary.json) |

所有矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。

## 残余（2.6.0）

1. **间接分支**：`BR/BLR`、`ADR/ADRP + BR`、从字面量池取目标等间接控制流仍可
   跳过 `LDXR` 并让桥代写；直接分支门控只覆盖 ±256 字节内的六种直接编码。
2. **窗口外分支**：直接分支在故障 PC 的 ±256 字节之外或另一页时不参与判定。
3. **保守误伤**：`LDXR` 之前的条件分支若落到 load（条件不成立时本来会顺序执行
   `LDXR`），被视为“可能跳过”，桥不生效、原生 `STXR` 失败。
4. **桥的语义**：store 仍是内核 nofault 普通写，不是硬件独占 store；多线程争用
   同一 scratch、`STLXR` 的 release 顺序和 store 原子性不完全等价原生。
5. **时间**：每次桥接候选额外扫描两个 256 字节窗口；仍每次读取一次同步异常，
   时间特征与 2.5.0 同量级。PTE 重装窗口、root 可见性、注册事务窗口仍在。
6. **带业务调用窗口的模式**：窗口内读者拿伪值、窗口外读者拿重放快照，仍是有意
   保留的 API 语义。

## 2.6.0 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 24 --cycles 5
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 3 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 3 --cycles 1
```

以下 2.5.0 的实测记录作为历史保留；其中的“本轮改动”“残余”描述已被上面的
2.6.0 结果取代。

## 2.5.0 本轮改动（历史）

`APP_READ_INTEGRITY_AUDIT.md` 第 1 条检测针对 `PAGE_AP`：

```asm
ldxr x9, [x1]      ; thread-private scratch
ldrb w10, [x0]     ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]  ; native failure because ERET cleared the monitor
```

2.5.0 在 AP 数据异常返回路径中恢复相邻 LL/SC 桥，但只对满足以下条件的序列
生效：

1. 故障 PC 前一条是 `LDXR/LDAXR`，后一条是 `STXR/STLXR`，两者宽度、基址
   `Rn`、数据寄存器 `Rt` 一致；
2. `Rn != XZR`、`Rt != XZR`，`Rn` 自然对齐，中间 load 不写 `Rt`/`Rn`；
3. `Rt` 仍等于 `[Rn]`（`LDXR` 执行存证，按宽度零扩展）；
4. 待写值等于 `[Rn]` 当前内存，`copy_to_user_nofault` 能写回。

满足后，在 load 模拟成功之后由 handler 写回同一值、`Ws=0`、跳过 `STXR`；
`STLXR` 追加 `dmb ishst`。旧探针跳过 `LDXR` 时保留与 `[Rn]` 不同的 sentinel，
因此第 3 条校验失败，`STXR` 保持原生失败。下方无密钥复核使用相同值触发桥。实现见
[urov_y_backend.c](urov_y_backend.c) 的 `uy_llsc_prepare()`/`uy_llsc_commit()`，
设计与残余见 [ELIMINATION_DESIGN.md §14](ELIMINATION_DESIGN.md#14-第六轮相邻-llsc-桥的执行存证恢复)。

### 2.5.0 审计特征点现状

| 审计条目 | 2.5.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻且执行存证成立的序列由桥完成，`STXR` 成功，`MATCH=0`；非紧邻/成对/`Xt=XZR` 是残余。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限，不适用；代码字与 `smaps` 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具使用 `caller_count=0`（所有读者拿同一伪视图），`reader_diff=0`；带调用窗口的 `crc-ap` 仍按设计只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | `urov-y` 使用每次加载派生的 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

### 2.5.0 Dobby 矩阵（审计原场景）

`run_crc_device.py --dobby-detection --repeats 24 --cycles 5`，5 轮活动运行。
同一 APK、同一夹具：Dobby 把执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP +
SRC_FILE` 把 32 字节代码读取改回文件字节。

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |

5 轮合计 120 次活动探针、11,520 个被接受的目标三元组：`target_failed=0`、
`control_failed=0`、`unknown=0`、`accepted_crc=120/120`。每轮
`DOBBY_DETECT_STATUS hits=3264 failures=0`；单次探针平均约 2.9 ms，最大约 3.0 ms。
2.4.1 的同一矩阵是 `match=120/120`、`accepted_crc=0/120`。

### 2.5.0 消除矩阵与计数器

`run_elimination_device.py --repeats 6 --cycles 1`：12 次运行全部 PASS，包含
`urov-x` 阳性对照、三种 Y 模式、不同 UID 观察和活动期卸载。

- `w-active` 的 `active_page`、`active_outside_window`、`active_after_set`、
  `active_equal_value` 均为 `exclusive_match=0`、`exclusive_clean=6`；
  `ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。
- 8 个 CPU 的 store 探针全部 0 写入。
- `ELIM_RESIDUAL mode=ap`：`site_file_word == site_live_word`，
  `site_cow_private=0`，`Private_Dirty/Anonymous` 与基线一致。
- `ELIM_FEATURE business_reader=1`：窗口内的业务调用仍拿到伪值
  `0x8877665544332211`，窗口外 `direct == file`。

另以 `w-active --repeats 200` 启动，在活动期轮询 `ctl0 status`：

```text
mode=data-ap state=active armed=1 hits=2009 replays=61547 failures=0 llsc=42952 ...
```

`llsc=42,952` 证明桥确实在异常路径完成了 store，而不是让原生 `STXR` 偶然成功。

### 2.5.0 回归

| 矩阵 | 结果 | 结果目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS，120/120 采信 CRC，MATCH 0 | [dobby-detect-20261107-140230](results/dobby-detect-20261107-140230/summary.json) |
| 消除矩阵 6×1 | PASS，12 次运行 | [eliminate-20261107-140259](results/eliminate-20261107-140259/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-140417](results/crc-20261107-140417/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-140448](results/multipage-20261107-140448/summary.json) |

所有矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。
`crc-ap`（业务窗口）仍保持 `direct=backing/window=file`，`crc-ap-all` 则是
`direct=window=file`；说明桥没有改变窗口语义。

### 2.5.0 残余

1. 桥只覆盖紧邻三条指令；`LDXR; NOP; load; STXR`、跨基本块、函数调用、成对
   `LDXP/STXP` 仍会看到目标 `STXR` 失败。
2. 调用者先读 `[Rn]`、把 `Rt` 预置为同一值、再分支跳过 `LDXR`，仍可让桥代写；
   由于待写值等于内存，该路径只改变 `Ws`，不改变内存。现有
   `ud_observe_unreserved_store` 探针不预置该值，保持 `match=0`、`stores=0`。
3. `Xt=XZR`、非自然对齐、不可写 `[Rn]` 不桥，按原生路径失败。
4. 仍是每次读取一次同步异常；时间特征与 2.4.1 同量级。PTE 重装窗口、root
   可见性、注册事务窗口仍在。
5. 带业务调用窗口的模式仍是有意保留的 API 语义：窗口内读者拿伪值，窗口外
   读者拿重放快照。Dobby 场景使用 `caller_count=0`，因此不存在读者差异。

### 2.5.0 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 24 --cycles 5
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 6 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 3 --cycles 1
```

## 2.5.0 普通 App 无密钥复核（历史）

> 2.6.0 复测：同一夹具的 `ud_observe_unreserved_status()` 在 24×5 活动矩阵中
> `bridge_match=0/24`、`bridge_successes=0`（3,840 个目标试验），
> `ud_observe_spaced_exclusive()` 为 `spaced_match=0/24`；2.5.0 记录的
> “无预约成功命中”和“间隔探针命中”不再出现。以下 2.5.0 数据保留作对照。

以下复核沿用报告开头所列的 2.5.0 KPM，使用重新构建的检测 APK
`5de21da422674de76b08fbffed6876442ff0f078fad77517683ba5ac34f78748`。
前文 `MATCH=0` 对应旧 APK 的相邻独占探针。新旧探针在同一夹具中并列运行。

### 检测依据

- **`PAGE_AP` 的主信号是无预约的 `STXR` 报成功。** 把线程私有栈槽的初值预置到
  `Rt`，用 `CLREX` 清预约，分支跳过紧挨目标 `LDRB` 的 `LDXR`。原生执行时
  `STXR` 报失败。目标页触发数据权限异常时，2.5.0 桥按故障 PC 前后各一条指令和
  `Rt == [Rn]` 判断并完成同值写回，令状态为 0。探针比较状态并核对栈槽仍为初值。
  每次先后读取同文件、同偏移的独立 RX 别名作为对照，32 个三元组均符合才判定命中。
  [桥实现](urov_y_backend.c#L1126) · [探针](native/urov_observe.c#L178) ·
  [Arm 指令手册](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab)
- **间隔独占探针用于交叉确认。** `LDXR → NOP → LDRB → STXR` 避开相邻匹配。
  `ERET` 清掉预约，目标组反复失败且前后对照成功才判定异常。每次要求三轮各 32 组
  有效对照。普通 load、抢占和调试均可能使预约丢失，混合结果与异常对照归为
  `UNKNOWN`，该信号只能说明读路径异常。2.4.1 或缺少可用桥接能力的构建也可以
  用独占失败检测。 [间隔探针](native/urov_observe.c#L309) ·
  [Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions)
- **按陷阱类型选证据。** 基础版和 X 在目标页制造数据读异常，X 按登记的读指令
  PC 选择伪值。Y 的 `SITE_BRK` 对读取指令做 COW 后改成 BRK，可核对该指令字与
  发布 ELF。`PAGE_UXN` 在读者页禁取指，可在已知的同页自有 canary 上配对取指。
  对 PC 或调用窗口过滤的会话，可用真实业务读者和独立读者交叉比对。所有读者共用
  `SRC_FILE` 镜像时，两读者和文件一致也可能掩盖改码。
  [基础版](urov_backend.c#L404) · [X](urov_x_backend.c#L414) · [Y](urov_y_backend.c#L1349)

探针只接收目标地址、对照映射、文件描述符和偏移。两侧都核对映射权限、设备号、
inode 和文件偏移，并复核映射与文件身份。读目标页用普通 `LDRB`，写入限于
线程私有 scratch。测试夹具通过控制 ABI 注册并确认真值。部署宜将探针放在
worker，低频抽查生命周期固定的自有 RX 页，保留 `MATCH / NO_MATCH / UNKNOWN`。
阴性只覆盖所采样的页与时段。计时和 `smaps` 可用于诊断。旧设备上的内核辅助读
有权限拒绝及阻塞记录。 [辅助读复核](DETECTION_RESULTS.md#42-内核辅助读取不能笼统视为安全)

### Dobby 真机复测

Pixel 6，Android 16，4 KiB，`untrusted_app`、`CapEff=0`、`Seccomp=2`。
48 次 × 10 个活动进程，另测未装载、加载空闲和卸载后。测试在 Dobby 所改页的
`+64` 字节采样。文件 CRC32 为 `96964c4f`。

| 阶段 | 样本 | 执行返回值 | 内存 CRC32 | 相邻探针命中 | 间隔探针命中 | 无预约成功命中 | 采信 CRC |
| --- | ---: | --- | --- | ---: | ---: | ---: | ---: |
| 原始代码 | 624 | `0x1234` | `96964c4f` | 0 | 0 | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | `7956f12b` | 0 | 0 | 0 | 0 |
| 改码并开启 `PAGE_AP + SRC_FILE` | 480 | `0x1235` | `96964c4f` | 0 | 480 | 480 | 0 |
| 触发恢复后 | 480 | `0x1235` | `7956f12b` | 0 | 0 | 0 | 0 |

无预约状态探针在 1,728 次对照中为 0 命中、0 未知。活动阶段共 15,360 组
无预约三元组，目标 `STXR` 均报告成功，两侧对照均失败。间隔探针活动阶段接受了
46,080 组，目标 `STXR` 均失败。有 4 次对照的合并结果为 `UNKNOWN`。
活动阶段三种探针合计平均 9.16 ms，最大 10.23 ms。全矩阵 worker 上的最大单次
耗时为 72.81 ms，UI 心跳最大间隔 24 ms。并行业务线程累计 4,251,520 次迭代、
0 错误。 [Dobby 原始数据](results/dobby-detect-20261107-143202/summary.json)

### 模式和回归

- 模式与生命周期矩阵 15 次 App 运行全部通过。无预约状态探针仅在 `PAGE_AP`
  活动页上命中，业务窗口外的重放和等值覆盖也能观测到该信号。每个 CPU 各做两轮，
  8 个 CPU 共 512 组无预约三元组全部命中。该矩阵单次无预约状态探针耗时中位数
  3.05 ms，最大 18.12 ms。 [模式和逐 CPU 数据](results/eliminate-20261107-143253/summary.json)
- 原 CRC 矩阵 9 项和多页、向量、跨页矩阵 5 项均通过。测试后模块列表为空，
  boot ID 与测试前相同，增量内核日志无命中的异常记录。
  [CRC 回归](results/crc-20261107-143607/summary.json) ·
  [多页回归](results/multipage-20261107-143416/summary.json)

### 处置和恢复

- **完整性证据。** 测试 App 将 `MATCH` 和 `UNKNOWN` 排除在可采信 CRC 之外，
  Dobby payload 及并行业务线程照常运行。生产侧可仅对高风险操作使用服务端验证的
  Play Integrity 请求绑定或硬件密钥证明，普通业务保留原流程。设备证明提供
  启动和设备可信度信号，页级结果仍由独立观测给出。
  [Play Integrity 请求绑定](https://developer.android.com/google/play/integrity/standard) ·
  [硬件证明校验](https://developer.android.com/privacy-and-security/security-key-attestation)
- **终止当前覆盖。** 夹具在自有、页对齐的 RX 测试页调用同权限
  `mprotect(PROT_READ | PROT_EXEC)`。Y 的重叠映射门控在系统调用之前恢复陷阱，
  10/10 次成功转为 `inactive`，CRC 再次读到 Dobby 改码，执行返回值仍为 `0x1235`。
  这是当前实现的一次会话恢复，仍允许重新注册。对任意业务页调用映射变更可能影响
  VMA、BTI 策略及并发，因此将主动恢复留在受控夹具。
  [映射门控](urov_y_backend.c#L2084)
- **内核信任。** 具有内核执行权的一方能控制页表、异常返回以及 App 的判定。
  可管理设备使用锁定引导加载程序和可信签名镜像约束启动链，服务端按硬件证明和
  操作风险授权。这里的设备证明未接入真机测试。检测率与开销仅涵盖当前设备和
  构建，其他 SoC、16 KiB 设备和生产流量需要各自的控制矩阵。
  [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot) ·
  [启动状态证明字段](https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields)

### 复跑本次矩阵

```powershell
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 48 --cycles 10
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 8 --cycles 2
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 3 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --skip-install --repeats 5 --cycles 1
```
