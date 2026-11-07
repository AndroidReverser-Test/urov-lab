# Android ARM64 代码读取完整性复核

2026-11-07，Pixel 6，Android 16，内核 `6.1.134-android14-11`，4 KiB 页，KernelPatch `0xc00`。检测在 `untrusted_app` 域运行，`CapEff=0`，`Seccomp=2`。ADB 端使用 root 装卸模块和收集内核真值。活动测试夹具用单独的模块密钥注册自己的页，检测函数只接收地址、同文件参考映射和偏移。

## 当前源码怎样伪造读取

| 产物 | 陷阱与选择规则 |
| --- | --- |
| `urov-lab` 2.0.0 | 固定 `prctl` 和旧 `kcmp` 控制入口。注册调用者 `mm` 内一页共享文件 RX 别名，清除数据访问所需的 `PTE_USER`，由 `do_mem_abort` 接管 EL0 叶级读权限异常。按页内窗口合成最多 32 字节，模拟标量 A64 load 和 LDP，原页继续供取指。 |
| `urov-x` 1.0.0 | 仍让目标页数据读进异常。控制选择器、magic 和请求 MAC 由每次加载的密钥派生。只有登记的读取 PC 得到伪值，其余受支持的读取回放原字节。未登记的读取遇到解码边界时可以触发撤销并回到内核原路径。 |
| `urov-y` 2.4.1 `SITE_BRK` | 对私有读取点做 COW，把登记的 load 换成 BRK。命中 `mm`、PC 和立即数后模拟原 load。恢复指令后 COW 可能仍可见。 |
| `urov-y` 2.4.1 `PAGE_UXN` | 置读取点页 PTE 的 UXN，接管该页的 EL0 取指权限异常。解释登记的 load 和受支持的 RET、NOP、BTI。读取点的字节和 VMA 可保持原样。 |
| `urov-y` 2.5.0 `PAGE_AP` | 清目标页叶子 PTE 的 AP[1]。数据读取进 `do_mem_abort`，取指仍执行该页的真实字节。支持普通私有 `.text`、多页、跨页、FPSIMD 与 LD1/2/3/4。2.5.0 对紧邻 `LDXR/LDAXR; load; STXR/STLXR`、`Rt==[Xn]` 且待写值等于内存的序列完成原 store，`ERET` 后不再出现确定性的目标 `STXR` 失败。 |
| `urov-y` 2.6.0 `PAGE_AP` | 在 2.5.0 之上允许 `LDXR` 与 load 之间 0–3 个 `NOP`，并在提交桥前扫描故障 PC 两侧各 256 字节，解码直接分支；只要有 `B/BL/CBZ/CBNZ/TBZ/TBNZ` 落到 load 上，就不代写，让原生 `STXR` 报告失败。这样“预置 `Rt==[Xn]` 后分支跳过 `LDXR`”的探针不再得到伪造成功。 |
| `urov-y` 2.9.0 `PAGE_AP` | 在 2.8.0 基础上把“是否顺序到达 load”从单页扫描改为 `REGISTER` 期全进程直接分支目标位图：清 `AP[1]` 之前枚举会话 `mm` 的所有可读可执行 VMA，按 4 字节指令记录 `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ` 的静态目标；故障时只查 `[LDXR+4, load]`。2.8.0 的跨页探针不再命中，读取路径耗时不变。 |
| `urov-y` 2.10.0 `PAGE_AP` | 在 2.9.0 基础上补齐两条仍可命中的读路径：同 `mm` 的 `process_vm_readv` 由 syscall after hook 按同一镜像/快照规则重写调用者缓冲区；`LDXR XZR; load; STXR XZR` 在目标字为零时由桥完成 no-op store。分支目标图覆盖 `VM_EXEC`-only VMA，未驻留代码页在首次 fault-in 时补扫，`mmap`/`mprotect`/`mremap` 新增可执行范围在返回 EL0 前补扫，任何无法读取的可达页使 map incomplete 并关闭桥；间接分支门控同时比较 PAC/MTE 掩码后的值。 |

[基础版后端](urov_backend.c) · [X 后端](urov_x_backend.c) · [Y 后端](urov_y_backend.c) · [指令解码](decode.c) · [软件模拟](emulate.c)

基础版保留 `mm` 和 pin 页引用，同时修改 `vm_page_prot` 与叶子 PTE，使用 seqlock 取得一致的伪值快照。相交的映射变更会返回 `EBUSY`。它写入的 `0x10000` 在本机对应 `smaps` 的 `rr`，合法的 `MADV_RANDOM` 对照也会出现该标记。X 只调整页保护，重叠映射操作会撤销覆盖后按原生路径执行。 [基础版注册和映射门控](urov_backend.c#L491) · [X 映射门控](urov_x_backend.c#L883)

Y 的 ABI v8 通过 `prctl` 校验密钥派生的选择器、固定的 `UROVYLAB` magic 和请求 MAC。注册按调用者 `mm` 绑定会话，先保存目标页快照。`SRC_USER` 取调用者提供的整页镜像（2.8.0 起移除 `SRC_FILE`）。故障发生时先检查陷阱来源，再用 `x30` 和最多 16 层 `x29` 帧链判断调用窗口，比较时剥离返回地址的 PAC。窗口内返回镜像，窗口外回放快照，无窗口时覆盖该会话的所有调用。模拟结束写回 GPR 或 FPSIMD、地址回写和 PC。跨页未登记部分走 nofault 读取。`SET` 和 `SET_PAGE` 校验代际后发布新镜像。注销先恢复陷阱，再等待读侧退出并回收会话。

当前 `PAGE_AP` 的 2.5.0 版本恢复了历史版本的相邻 LL/SC 桥，但加了执行存证：仅当
故障 PC 前一条 `LDXR/LDAXR` 的目的寄存器仍等于 `[Xn]`、后一条 `STXR/STLXR` 使用同一
基址与数据寄存器、宽度一致，且待写值等于当前内存时才代写。分支或 `CLREX` 跳过
`LDXR` 的序列仍由原生 `STXR` 失败且不写内存；非紧邻、`Xt=XZR`、成对独占不桥。
[Y ABI](urov_y_abi.h) · [兼容与 LL/SC 审计](COMPATIBILITY_Y.md)

2.6.0 进一步把 `LDXR` 与 load 之间允许插入 0–3 个 `NOP`，并在代写前扫描故障 load
所在页前后各 256 字节的直接分支（`B/BL/CBZ/CBNZ/TBZ/TBNZ`）：目标等于 load PC 时
视为“可绕过 `LDXR`”，不代写。寄存器存证仍保留，但它不再是唯一条件。该门控只覆盖
直接编码；间接分支与窗口外分支仍是残余，见 [设计 §15](ELIMINATION_DESIGN.md#15-第七轮直接分支门控与-nop-间隔桥)。

## 普通 App 可采用的检测

1. 对已知、稳定的自有 RX 页做配对读探针。`LDXR` 读线程私有 scratch，普通 `LDRB` 读目标字节，`STXR` 尝试把原值写回 scratch。每组用同一文件同一偏移的 RX 别名在目标前后作对照。连续三轮各 32 组有效试验、两侧对照均成功且目标 `STXR` 全失败，才输出 `MATCH`。对照异常过多、结果混合或文件与映射身份变化时输出 `UNKNOWN`。该信号适合 `urov-x`；2.5.0 的 `PAGE_AP` 对紧邻且执行存证成立的序列代写，目标 `STXR` 成功，因此不再命中。非紧邻形状、`Xt=XZR`、成对独占，以及预置 `Rt` 等于 `[Xn]` 后跳过 `LDXR` 的主动探针仍是残余（见“2.5.0 桥接后复测”）。AArch64 的异常返回会清本地独占监视器，额外 load、调试及调度也可能影响独占结果，因此需要配对控制。 [检测实现](native/urov_observe.c#L186) · [Arm 独占访问约束](https://support.arm.com/documentation/ddi0487/mb/-Part-B-The-AArch64-Application-Level-Architecture/-Chapter-B2-The-AArch64-Application-Level-Memory-Model/-B2-12-Synchronization-and-semaphores/-B2-12-5-Load-Exclusive-and-Store-Exclusive-instruction-usage-restrictions) · [Arm 异常返回说明](https://community.arm.com/forums/f/architectures-and-processors-forum/5452/does-load-store-exclusive-violate-hypervisor-transparency/12878)
2. 对 `SITE_BRK`，把已知读取点的指令字和发布 ELF 对照，COW 和 `smaps` 仅作佐证。对 `PAGE_UXN`，在已知读取点页上用预先校验的自有 `BTI C; RET` canary 做配对取指探针。若 App 没有同页可安全调用的 canary，这条证据不可用。 [取指探针契约](native/urov_observe.h#L65)
3. 对按 PC 或调用窗口选择伪值的模式，让真实业务读者和独立标量读者读取同一地址，并以 `pread` 取得已核对身份的 ELF 字节。必须保留触发时的调用上下文，否则可能读到窗口外的重放值。仅有文件差异时，证据是代码视图发生变化，合法插桩或热补丁也能造成差异。反过来，文件与内存 CRC 相同仍可能是 `PAGE_AP + SRC_FILE` 的结果。 [读者差异实现](native/urov_observe.c#L277) · [Dobby 验证夹具](apps/urov-detect/dobby_crc_fixture.inc#L134)
4. 基础版可额外使用固定 `prctl` 的 QUERY 指纹，核对错误 magic 的原生回退和两次正确回包。X/Y 的未认证请求可表现成原生 `EINVAL`，因此这个指纹仅用于已知基础版。空闲会话、其他进程的 `mm`、未采样页和未触发的调用窗口都可能给出阴性。 [基础版指纹实现](native/urov_detect.c#L31)

部署时以构建产物的 ELF 文件身份和偏移定位关键页，选无重定位、无热更新的稳定字节，在后台低频抽样。持有映射和 fd 的生命周期，避开并发 `dlclose`、映射修改和代码写入。探针只读取目标，`STXR` 只写私有 scratch。将 `MATCH` 用作证据复核或遥测，将 `UNKNOWN` 用作待复核状态，两者均可保留普通业务。文件摘要可用签名清单中的 SHA-256，运行时读取路径的信任仍需独立证据。当前版本能覆盖实际 bionic/zlib 标量与向量路径，换读函数、计时阈值和 `maps` 权限位均不足以单独判定。旧 raw-XOM 设备上，管道写入等内核辅助读有挂起记录，不适合接进业务。 [基础版辅助读复核](DETECTION_RESULTS.md#42-内核辅助读取不能笼统视为安全)

## 阻断的边界

- **拒绝采信伪造的完整性结果。** 本次 App 演示把传统 CRC 通过和读路径异常分开计数。若探针为 `MATCH` 或 `UNKNOWN`，该次 CRC 通过不计为有效完整性证据，测试函数仍按原业务路径执行。生产中可让高风险操作由服务端核验绑定请求的 Play Integrity 或硬件 Key Attestation，普通业务继续，设备证据缺失按未知分级。该信任覆盖设备和启动状态，内存页的读值仍需应用侧证据。 [Play Integrity 请求绑定](https://developer.android.com/google/play/integrity/standard) · [硬件密钥证明校验](https://developer.android.com/privacy-and-security/security-key-attestation)
- **结束当前实验会话。** 持有模块密钥的 owner 可发 `DEACTIVATE`，测试后由 root 卸载。多页回归也证实当前 Y 会在重叠 `mprotect`、fork 等生命周期事件中恢复映射。这类操作有应用语义和并发影响，还允许再次注册，适合测试恢复而非业务防护。 [映射门控源码](urov_y_backend.c#L2317) · [多页回归](results/multipage-20261107-132907/summary.json)
- **阻止该类内核改写。** 普通 App 位于 EL0，已取得内核执行权的一方能控制页表、系统调用和探针本身。设备侧应由可信启动链约束可加载的内核，在可管理设备上使用锁定引导程序与可信签名系统镜像。服务端校验硬件证明、启动状态和新鲜挑战，可以独立于 App 的本地检测结果决定是否授权敏感请求。 [Android Verified Boot](https://source.android.com/docs/security/features/verifiedboot) · [硬件证明的启动字段](https://source.android.com/docs/security/features/keystore/attestation#rootoftrust-fields)

## 本轮设备数据

同一 Dobby 夹具在实际 linker `.text` 中把测试函数执行结果由 `0x1234` 改为 `0x1235`。独占探针采样同页 `+64` 处的稳定字节。每轮有覆盖前、仅改码、覆盖中和注销后的观测。没有模块、模块已加载但空闲和卸载后也分别起进程复测。

| 阶段 | 执行返回值 | 传统内存 CRC32 | 独占探针 MATCH | UNKNOWN | 采信 CRC 通过 |
| --- | --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/192 | 0 | 192/192 |
| 仅 Dobby 改码 | `0x1235` | `37b57a40`，与文件不同 | 0/192 | 0 | 0/192 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **120/120** | 0 | **0/120** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `37b57a40`，与文件不同 | 0/120 | 0 | 0/120 |

8 次 App 运行均通过。活动阶段五个进程合计 11,520 个有效目标三元组全失去 reservation，配对对照无失败。各阶段单次探针平均耗时约 2.85–5.98 ms，最大实测约 19.32 ms，UI 心跳最大间隔 20 ms。耗时包含元数据检查，测试运行在 worker 上。Dobby 改码是夹具注入步骤，检测本身只读取目标页。 [Dobby 完整数据](results/dobby-detect-20261107-132634/summary.json)

- X 的活动值差异和独占探针都命中，另在 8 个 CPU 的已知夹具上各完成 3 次命中。Y 的 `SITE_BRK` 三轮均出现读取指令字差异。`PAGE_UXN` 取指信号 147/147，507 次对照 506 阴性、1 次未知。`PAGE_AP` 独占信号 144/144（2.5.0 已消除，见下一节），513 次对照 512 阴性、1 次未知。对照包含其他模式、空闲和已撤销页。9 个活动 App 进程合计 2,227,968 次并行业务测试操作，0 错误。另一个 UID 的观察进程没有命中 owner 的页。 [模式与生命周期矩阵](results/eliminate-20261107-132021/summary.json)
- CRC 回归 9 项和 ABI v8 多页回归 5 项通过。覆盖 24 页/96 KiB、多页更新、SIMD 及跨页读取。并发更新测试完成 307,149 次读取，0 撕裂或业务值错误。 [CRC 回归](results/crc-20261107-132848/summary.json) · [多页回归](results/multipage-20261107-132907/summary.json)
- 基础版的固定指纹区分未装、空闲和活跃会话。三轮活动测试覆盖 8/16/24/32 字节窗口，480 次变化值读样本均命中文件差异，480 次窗口外或等值覆盖均阴性。首次运行的 App 用例全部通过，但旧日志正则将 `binder_debug:` 误归为 BUG。修正单词边界后复跑的 6 项均通过，使用 App 先注销再卸载的流程。 [首次运行](results/detection-20261107-133040/summary.json) · [复跑数据](results/detection-20261107-133250/summary.json)

结果限于本次设备、当前 KPM、抽样页和受控夹具。跨 SoC、16 KiB 真机和生产流量的误报率与性能仍需验证。远程证明是生产防护方案，本轮真机验证覆盖本地探针、完整性判定和实验会话恢复。设备测试前后 boot ID 相同，测试模块已卸载，复跑的内核增量日志无 BUG、Oops 或挂起记录。

## 2.5.0 桥接后复测（2026-11-07）

同一 Pixel 6、`6.1.134-android14-11`、4 KiB 页、KernelPatch `0xc00`。测试 APK 仍在
`untrusted_app` 域运行，`CapEff=0`、`Seccomp=2`；只把模块换成 2.5.0，并把
`dobby_detection_stage("overlay", ...)` 的 `expect_trap` 从 `true` 改为 `false`
（该特征已被消除，旧断言不再适用）。`run_crc_device.py --dobby-detection
--repeats 24 --cycles 5`：

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |

5 轮合计 120 次活动探针、11,520 个被接受的目标三元组，`target_failed=0`、
`control_failed=0`、`unknown=0`、`accepted_crc=120/120`；每轮 `DOBBY_DETECT_STATUS`
`failures=0`、`hits=3264`，平均单次探针约 2.9 ms，最大约 3.0 ms。2.4.1 的同一矩阵
是 `match=120/120`、`accepted_crc=0/120`。

`w-active`（带业务调用窗口的 AP 夹具）6 次重复：`active_page`、
`active_outside_window`、`active_after_set`、`active_equal_value` 均为
`exclusive_match=0`、`exclusive_clean=6`；跳过 `LDXR` 的
`ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。8 个 CPU 的 store 探针
也为 0 写入。另以 `w-active --repeats 200` 启动并在活动期轮询 `ctl0 status`：
`state=active` 时 `llsc=42,952`，证明桥确实在异常路径中完成 store，而不是让
原生 `STXR` 偶然成功。

残余（与设计 §14 一致）：

- 桥只匹配故障 PC 前后各一条指令。`LDXR; NOP; load; STXR`、跨基本块、函数调用
  或成对 `LDXP/STXP` 仍会看到目标 `STXR` 失败。
- 调用者在跳过 `LDXR` 前显式预置 `Rt==[Xn]`，仍可让桥代写；由于待写值等于内存，
  该路径只改变 `STXR` 的状态，不改变内存。检测 App 的 `CLREX/B;LDXR` 探针不预置
  该值，保持 `NO_MATCH`。
- `Xt=XZR` 没有可验证寄存器，按 fail-closed 不桥。
- 每次读取仍一次同步异常，时间特征与 2.4.1 同量级；PTE 重装窗口、root 可见性、
  注册事务窗口仍在。
- `PAGE_AP` 只处理相邻执行存证成立的序列；任意写、缓存维护和其他来源的异常仍
  原样放行或 fail-closed。

完整复测报告与四组矩阵入口见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md)。

## 2.6.0 分支门控复测（2026-11-07）

同一 Pixel 6、同一 APK 夹具。`run_crc_device.py --dobby-detection --repeats 24
--cycles 5`：5 轮活动阶段 `bridge_match=0/24`、`spaced_match=0/24`、
`unknown=0`、`accepted_crc=24/24`；每轮 `bridge_trials=768`、
`bridge_successes=0`。2.5.0 的同一矩阵是 `bridge_match=24/24`、
`accepted_crc=0/24`。`run_elimination_device.py --repeats 3 --cycles 1` 12 次
运行 PASS，11 项 `ELIM_BRIDGE expected=0 verdict=0 successes=0`，`w-active`
仍是 `exclusive_match=0`、`exclusive_clean=3`、store 探针 0 写入。CRC 5×1 与
多页 3×1 回归 PASS，`kernel_issues=[]`、测试后模块为空。

残余（与设计 §15 一致）：

- 间接分支（`BR/BLR`、`ADR/ADRP + BR`、字面量池取目标）和 ±256 字节窗口外/另一页
  的直接分支不参与判定，仍可绕过 `LDXR`。
- `LDXR` 之前的条件分支若落到 load，会被保守地视为“可能跳过”，桥不生效、原生
  `STXR` 失败。
- 桥的 store 仍是内核 nofault 普通写，不是硬件独占 store；时间、PTE 重装窗口、
  root 可见性和注册事务窗口同 2.5.0。
- `Xt=XZR`、成对 `LDXP/STXP`、非自然对齐仍不桥。

完整数据见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.6.0 矩阵。

## 2.7.0 NOP/间接分支门控复测（2026-11-07）

同一 Pixel 6、同一 APK 夹具，构建
`urov-y.kpm ff818b3e...`、`urovdetect.apk e21607a7...`。2.7.0 把
`uy_llsc_skipped()` 从“目标等于 load 的 ±256 字节直接分支”扩展为**整页**
`[LDXR+4, load]` 直接分支扫描，补上 `B.cond`，并在故障时检查
`x0..x30` 是否仍持有该区间地址，以拦住 `ADR/ADRP + BR`、literal + `BR`、
`RET` 等间接形状。

- Dobby 24×1 活动阶段：`nop=0/24`（2.6.0 报告为 480/480 命中）、
  `ind=0/24`、`bridge=0/24`、`spaced=0/24`、`accepted_crc=24/24`。执行仍为
  `0x1235`，内存 CRC 等于文件 `96964c4f`。
- 消除矩阵 3×1：11 次运行、443 条断言 PASS；`ELIM_BRIDGE` 的直接、NOP、
  间接三项均 `verdict=0 trials=32 successes=0`；`ELIM_TIMING mode=ap
  site_call_ns=288`。
- CRC 5×1：9 次运行 PASS；`crc-ap` 的 `direct=0x0c7da8a0`、
  `window=file=0xf50bcaf6`，`crc-ap-all` 的 `direct=window=file`。
- 多页/LD1/跨页/SRC_FILE 3×1：5 次运行 PASS。

残余（与设计 §16 一致）：间接分支的目标寄存器在 load 前被覆盖；跨页直接
分支；保守误伤扩大（本页任意分支目标或 GPR 值落在区间内即不桥）；每次读取
仍一次同步异常（AP 288 ns / UXN 404 ns）；PTE 重装窗口、root 可见性、注册
事务窗口、桥的非硬件独占语义、`caller_count > 0` 的窗口语义不变。

完整数据见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.7.0 矩阵。

## 2.8.0 镜像来源变更（2026-11-07）

`urov-y` 2.8.0 移除了 `SRC_FILE`：`REGISTER` 遇到 `UROV_Y_PAGE_SRC_FILE`
返回 `EINVAL`，`QUERY` 不再报告 `UROV_Y_CAP_SRC_FILE`，后端不再调用
`kernel_read(vm_file, ...)` 或依赖 `vm_pgoff`。所有页镜像改为 `SRC_USER`，
每个描述符一次最多一页，由调用者在 `REGISTER`/`SET_PAGE` 时提供。

夹具变化：

- Dobby 在 `DobbyHook` 前把目标页的完整干净页读入用户缓冲区，以
  `SRC_USER(off=0, len=page_size)` 注册；业务读者仍读到文件页，执行仍走
  Dobby 改码后的页。
- 多页夹具的 `mp-srcfile` 改名为 `mp-srcpage`：用首尾改过的整页镜像注册，
  窗口内读到镜像，窗口外和注销后读到真实页；`MP_AUDIT` 仍把 `SRC_FILE`
  描述符当作非法输入（`EINVAL`）。

真机结果：Dobby 24×1 `accepted_crc=24/24`、直接/NOP/间接探针 0/24；多页
5 项、CRC 9 次、消除矩阵 11 次运行 PASS；`ELIM_TIMING mode=ap` 271 ns。
构建 `urov-y.kpm 82f50d46...`、`urovdetect.apk 5ebc9801...`。完整数据见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.8.0 节。

## 当前 2.8.0 的跨页分支复核

复核以 `5ba3a1c` 的 `urov-y` 2.8.0 和 ABI v8 为准。`REGISTER` 绑定当前 `mm`，
复制每个目标页的原始快照和调用者提供的 `SRC_USER` 镜像。`PAGE_AP` 清目标页叶子
PTE 的 `AP[1]`，保持硬件取指。低异常级的读权限异常由 `do_mem_abort` 接管，按
`x30` 和最多 16 层 `x29` 帧链匹配业务窗口，再把镜像或原始快照的读值写回寄存器。
`SITE_BRK` 与 `PAGE_UXN` 则在读取点触发，分别改写私有指令字和改变取指权限。
[注册事务](urov_y_backend.c#L1852) · [异常处理](urov_y_backend.c#L1611)

[设计 §16.5](ELIMINATION_DESIGN.md#165-残余特征与限制诚实清单) 的跨页分支残余在
2.8.0 仍可复现。新探针执行 `CLREX`，从另一代码页用直接 `B` 跳过 `LDXR`，进入
`LDRB; STXR`。原生 `STXR` 缺少预约，返回 1。AP 桥只扫描故障指令所在页内的分支，
直接 `B` 也没有在通用寄存器里留下跳转目标。探针提前把待写寄存器置为私有 scratch
的当前值，满足桥的寄存器校验，handler 写回同一值并把 `STXR` 状态置 0。
成品 ELF 中的 `B` 位于 `0xc8054`，`LDRB` 位于 `0xcc004`，对齐布局跨越 4 KiB
和 16 KiB 页边界。 [LL/SC 桥](urov_y_backend.c#L1374) ·
[无密钥探针](native/urov_observe.c#L253) ·
[Arm A64 独占监视器](https://documentation-service.arm.com/static/68c223238a337a2bc6645c0a)

每次观测做 32 组同文件、同偏移的 RX 别名与目标页对照。两侧对照每次都返回 1、
目标每次都返回 0、scratch 值和映射身份保持稳定时输出 `MATCH`。结果混合或对照
异常时输出 `UNKNOWN`。检测只读目标页，写入限于线程私有 scratch，在 worker 上
执行。`MATCH` 表示该页的读取路径出现模拟证据。`NO_MATCH` 的范围限于本次采样的
地址与时段。此探针依赖当前 AP 桥及其 nofault 写能力，16 KiB 只有布局验证。
[探针契约](native/urov_observe.h#L96)

BRK 以已知读取点的原始 load 与活跃 BRK 指令字差异为主，私有脏页为辅。
UXN 以已校验且可调用的同页 `BTI C; RET` canary 为目标，和独立 RX 别名对照
取指时的独占预约状态。能安全复现真实调用窗口时，可对三种模式补充业务读值与
文件字节的差异证据。 [模式夹具](apps/urov-detect/uy_fixture.inc)

### 真机结果

Pixel 6，Android 16，内核 `6.1.134-android14-11`，4 KiB，KernelPatch `0xc00`。
探针运行在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、SELinux `Enforcing`。
KPM SHA-256 以 `82f50d46` 开头，测试 APK 以 `3bd329ec` 开头。

| Dobby 阶段 | 样本 | 执行返回 | 内存 CRC32 | 跨页探针 `MATCH` | 采信 CRC |
| --- | ---: | --- | --- | ---: | ---: |
| 原始代码 | 624 | `0x1234` | `96964c4f` | 0 | 624 |
| 仅 Dobby 改码 | 624 | `0x1235` | `8001aa03` | 0 | 0 |
| 改码并开启 `PAGE_AP + SRC_USER` | 480 | `0x1235` | `96964c4f` | 480 | 0 |
| 恢复页权限 | 480 | `0x1235` | `8001aa03` | 0 | 0 |

活动阶段 15,360 个目标 `STXR` 全部被代报成功，1,728 次观测对照零命中，跨页探针
全矩阵零未知。活动阶段单次跨页观测平均 3.21 ms，全矩阵最大 7.90 ms。并行业务
完成 8,578,176 次迭代，零错误，测试 UI 心跳最大间隔 20 ms。
[Dobby 矩阵](results/dobby-detect-20261107-180809/summary.json)

模式与生命周期矩阵 14 次 App 运行通过。BRK 两轮均观测到指令字变化与 COW，UXN
的活动 canary 83/83 命中。AP 的覆盖字节范围内外、等值覆盖和 8 个 CPU 上均命中跨页探针。
其他 UID 的对照为阴性，卸载前的 owner 注销后读值恢复。
[三模式矩阵](results/eliminate-20261107-180922/summary.json)

CRC 回归 9 项和多页、向量、跨页回归 5 项全部通过。测试前后 boot ID 一致，测试模块
已卸载，四组矩阵的内核增量日志未发现 Oops、BUG、WARNING 或挂起。
[CRC 矩阵](results/crc-20261107-181043/summary.json) ·
[多页矩阵](results/multipage-20261107-181101/summary.json)

### 恢复和阻止重新注册

- **保留普通业务。** Dobby 夹具只在完整性判定中剔除 `MATCH` 或 `UNKNOWN` 下的
  CRC 通过记录，执行路径照常运行。生产中在后台检查稳定自有 RX 页，并持有映射
  及文件生命周期。
- **撤销当前会话。** 对已采用默认 advice 的自有测试页调用 `madvise(MADV_NORMAL)`，
  Y 的重叠门控会恢复会话涉及的页权限并结束会话，再放行原生 syscall。10/10 次由
  active 变为 inactive，随后 CRC 恢复到仅改码阶段的值。此动作允许未来重新注册，
  并可能与并发控制请求竞争。 [映射门控](urov_y_backend.c#L2317)
- **阻止同进程重新注册。** 已有 opt-in seccomp TSYNC 规则只对 ARM64、固定 magic、
  `REGISTER` 和 288 字节请求的组合返回 `EPERM`。10/10 次安装成功，调用线程与
  既存线程各 10/10 次重试被拦截。`NoNewPrivs` 和过滤器的进程内持久性适合明确采用
  此策略的进程。已有会话需另行撤销，具备内核执行权的代码仍可改变过滤器或探针结果。
  [恢复与过滤器夹具](apps/urov-detect/dobby_crc_fixture.inc#L156) ·
  [Linux seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## 2.9.0 跨页直接分支消除（2026-11-07）

2.9.0 消除的是 2.8.0 复核里仍能稳定命中的跨页直接分支探针。`REGISTER` 在给
任何目标页清 `AP[1]` **之前**，先在 `mmap` 读锁下枚举会话 `mm` 的全部可读可执行
VMA，把每个 `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ` 的静态目标写入按 VMA 划分的位图
（每 4 字节指令一位，约为可执行虚拟地址跨度的 1/32）。故障时
`uy_llsc_skipped()` 只查 `[LDXR+4, load]` 的 1–4 个槽位；任一位命中就不代写，
交回原生 `STXR` 报失败。分支源可以在任意页、任意距离、甚至另一个映射，只要它
在 `REGISTER` 时已经存在。扫描只读，不改 hook、syscall、PTE、代码字节或
`ctl0` 字段；故障路径只做位测试，读取延迟不变。

同一轮先试过更直接的执行存证：在 handler 里清 `PAN`，对 STXR 目标发真实
`STXR`，用硬件独占监视器判断 `LDXR` 是否真的执行。Pixel 6 上 2656 次尝试全部
失败，说明异常进入已经让本地监视器回到 Open Access，该方案不可用；寄存器存证、
直接分支位图和 GPR 门控因此保留。

真机结果（Pixel 6，`6.1.134-android14-11`，4 KiB，KernelPatch `0xc00`；
`urov-y.kpm f7d55fd8...`、`urovdetect.apk 2ad6df70...`）：

| 矩阵 | 结果 |
| --- | --- |
| Dobby 检测 24×5 | PASS；活动阶段 `execute=0x1235`、`live=96964c4f`（等于文件）、`accepted_crc=24/24`、`cross_page_successes=0/768`、`bridge/nop/ind` 均 0；平均探针 3.03–3.27 ms，最大 7.68 ms |
| 消除矩阵 3×1 | PASS，11 次运行、1438 条断言；`ELIM_BRIDGE` 直接/NOP/间接/跨页均 `verdict=0 trials=32 successes=0`；`ELIM_TIMING mode=ap site_call_ns=283` |
| CRC 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） |
| 多页 3×1 | PASS，5 次运行 |

测试进程上分支位图为 358 个可执行 VMA、6,000,742 字节，`REGISTER` 扫描约
240 ms；这段成本只在显式注册路径，读取路径的 `site_call_ns` 与 2.8.0 相同
（281→283 ns）。完整数据见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md)。

残余（新增/仍存）：

1. **`REGISTER` 之后新建的可执行映射不在位图中**。位图只在注册时构建一次，
   不随 VMA 变化更新；从这种映射跳入 span 的跨映射直接分支仍可绕过。
2. **不可读或注册时未驻留的可执行页**：XOM 页不能用 nofault 读取复制，被换出的
   代码页在 `REGISTER` 时也不会触发缺页；其中的直接分支源不被扫描。目标 `PC`
   若落在位图外，`uy_code_hit()` 返回 0。
3. **间接分支的目标寄存器在 load 前被覆盖**：GPR 门控看不到区间地址
   （同 §16.5 残余）。
4. **注册路径成本**：一次全进程代码扫描，测试进程约 240 ms、6.0 MB 内核位图；
   读取路径不变。
5. PTE 重装窗口、root 可见性、注册事务窗口不变；每次读取仍一次同步异常；
   桥的 store 仍是内核 nofault 普通写，不是硬件独占 store；`caller_count > 0`
   的窗口语义不变。

## 2.10.0 内核辅助读与 XZR 序列复核（2026-11-07）

同一 Pixel 6、`6.1.134-android14-11`、4 KiB、KernelPatch `0xc00`。构建
`urov-y.kpm 8e3ad63b...`、`urovdetect.apk 4f259a66...`。2.9.0 的活动矩阵里
仍有两条确定性检测：同进程 `process_vm_readv` 的 GUP 视图与 EL0 视图不同
（480/480），以及 `LDXR XZR; LDRB; STXR XZR` 的目标 `STXR` 在 `ERET` 后失败
（480/480）。

2.10.0 的读取路径：

- **`process_vm_readv` after hook。** syscall 表条目在 `mm` 是会话 owner、`pid`
  是调用者自身时，按返回长度重走 local/remote iovec 流，只改写落在已登记页上的
  字节；镜像/快照选择复用 `caller_allowed_deep()`。只新增一个 after 回调，不新增
  ABI、`ctl0` 位、计数器或 `hooks` 位。
- **XZR 桥。** `LDXR XZR` + `STXR XZR`、同宽度/基址、目标字为零时置 `Ws=0`
  并跳过 `STXR`；写回 0 是 no-op。目标字非零时保持原生失败。
- **完整分支目标图。** 覆盖 `VM_EXEC`，未驻留页在 `handle_mm_fault` 首次
  present 时补扫（返回 EL0 之前），`mmap`/`mprotect`/`mremap` 新增范围在
  after hook 补扫；读不到的可达页或无法加入的范围使 map incomplete，桥
  fail-closed。扫描用 seqlock 与故障路径互斥，mark 用源 VMA 快路径；
  本矩阵 `REGISTER` 为 70 ms（2.9.0 记录约 240 ms）。
- **PAC/MTE 间接分支门控。** 掩码后比较 GPR，覆盖签名指针仍在寄存器的
  `BRAA/BLRAA/RETAA` 形状。

真机结果：

- Dobby 8×1：活动阶段 `accepted_crc=8/8`、双读 `0/8`、XZR `0/8`、
  bridge/NOP/indirect/cross `0/256` 各、`spaced_accepted=768` 且
  `spaced_failed=0`、`hits=4032`、`failures=0`。
- CRC 5×1：9 次运行 PASS；`crc-ap-all` 的 `direct=window=file`，`crc-ap` 的
  `direct=0c7da8a0`、`window=f50bcaf6`，全部 `bridge=0/5`。
- 消除矩阵 3×1：11 次运行 PASS；`w-active` 497 条断言，XZR 全 clean，
  `ELIM_TIMING mode=ap site_call_ns=281`。
- 多页 3×1：5 次运行 PASS。测试后模块列表为空、boot ID 不变。

残余（2.10.0）：

1. 每次 EL0 读取仍一次同步异常；PTE 重装窗口、root 可见性、注册事务窗口、
   非硬件独占 store 仍在。
2. 分支图依赖“扫描时/首次 present 时可读”。XOM 或不透明可执行页使桥
   fail-closed；`REGISTER` 之后原地写入且不再 `mprotect` 的匿名可执行映射，
   以及已扫描页内的自修改代码不会被补扫。W^X 流程由 mprotect after hook 覆盖。
3. 只接管同 `mm`、同进程的 `process_vm_readv`；`/proc/self/mem`、ptrace、
   跨进程读写和 iovec 数超过 64 的调用仍看到真实字节。
4. `REGISTER` 的一次全进程扫描仍是控制面成本（本矩阵 70 ms），不在读取循环。
5. XZR 桥只对零目标 no-op；`caller_count > 0` 的窗口语义不变。

完整数据和复跑命令见
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.10.0 节。

## 复跑

在仓库根目录运行。`<KP_KEY>` 为设备的 KernelPatch 密钥，模块密钥由脚本另行生成。

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> --dobby-detection --repeats 48 --cycles 10
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> --skip-x-control --repeats 8 --cycles 2
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> --skip-install --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> --skip-install --repeats 3 --cycles 1
```

