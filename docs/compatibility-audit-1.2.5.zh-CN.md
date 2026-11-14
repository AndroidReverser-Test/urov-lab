# UROV-Z 1.2.5：并发、内存和兼容诊断优化

日期：2026-11-14（Asia/Shanghai）。基线是工作树中的 1.2.4，包括已有未提交修改；原审计保留在 [1.2.4](compatibility-audit-1.2.4.zh-CN.md)。本轮修改独立 `urov-lab`，保留外层 KernelPatch、KCLF vendor 源码和 Dobby 的既有改动。用户态 ABI v1 不变。

## 实现与优化结果

框架继续以经认证的 prctl 绑定一个 owner mm：注册文件 RX 页，保存原始 snapshot 与替代 image，清除原物理页 PTE_USER，使取指仍执行原代码、受支持的数据 load 进入模拟路径；proc/ptrace 原生读成功后替换返回缓冲，remote/fast GUP 对允许的 GET/PIN 调用提供带正确引用的新影像页。稳定描述符、不可变地址索引和 reader epoch 保护对象寿命，fork 子影像独立保存。默认 RX 在观察到写权限或受监测写入时退役；辅助写入仍须显式 experimental。

| 优化 | 源码与结果 | 边界 |
| --- | --- | --- |
| 全局影像锁改为每页锁 | `short_lock.h`、`backend.c`：每个 owner/child 描述符独立 acquire/release 短锁，忙等使用 relaxed load；复制、store、SET 和 GUP 读取锁定实际源描述符 | IRQ 排除保持；用户访问、分配、epoch 等待在锁外。同页仍串行，跨页或多指令不保证统一 generation |
| RX 缓冲缩减 | 每页主缓冲从 7 页减为 image/spare/snapshot 3 页；experimental 保留 7 页；inactive 切换同步更新布局，缺少辅助缓冲时拒绝相关路径 | 主缓冲减少 57.1%；默认四份 fork 预留不变时，主缓冲加子影像由 15 降为 11 页/目标，减少 26.7%。这是指定缓冲的字节计算，不是整机内存或速度提升 |
| 明确覆盖缓冲预算 | `buffer_budget.h` 在调用可睡眠分配器前保留额度，失败/释放归还；覆盖主/子 arena、描述符、双索引、指令 memo、分支图和 detached BTF | 默认 64 MiB，按运行时页大小向上取整。排除 KCLF、宿主跳板、allocator 元数据/额外 slab 容量及交给 native 调用者的 GUP 页；不是全系统物理内存硬上限 |
| 可调 fork 预留 | `fork_copies=0..4`，默认 4；0 不分配子池并取消快照能力位；active owner 的非 CLONE_VM fork 返回 EOPNOTSUPP，线程仍可使用 | 另受 4096 槽和 16 MiB 上限约束；槽在一个会话内不循环复用，容量不足返回 ENOSPC |
| 缺页恢复身份复核 | `mapping_identity.h`、`pt_access.h`：owner 和 child 共用检查；核对 fault 前捕获的文件页身份，再在同一次 mmap 保护下读取当前 VMA、复核身份和访问 leaf PTE；修复孤立 trap 恢复中的嵌套 trylock | 支持同一文件页的 split/move；拒绝替换、边界不完整和偏移溢出。没有 pgoff 时使用原 VMA 边界。没有消除原生 PTE 发布到 after-hook 的窗口 |
| 运行诊断 | `health` 公开 mmap 忙、重试、rearm 分类、写入退役、readv 槽耗尽与 GUP 分配失败；`memory` 公开额度、使用、峰值和拒绝次数；诊断构建增加每页锁等待与持有时间 | health/perf 为模块寿命累计值；并发采集各计数不是原子整体快照。普通构建不启用每次 load 的性能计数 |
| 兼容证据来源 | `compat` 显示 BTF 来源、入口/参数数、public ABI 检查计数与 FOLL 来源；`compat-check --inspect` 接受任意 raw BTF，不再要求 Pixel/Xiaomi 固定偏移 | 保留原 fixture 回归入口。检查成功只表示报告完成，始终输出 `runtime=unverified`；名字存在不证明运行地址、geometry 或 hook 成功 |
| KCLF 可选 | 完整构建支持 `loader=off`，跳过加载器 preflight/init/control；`-OverlayOnly` 完全不链接六个 KCLF 实现单元 | 默认仍含 KCLF 1.5.7。关闭加载器不自动解除其他内核约束；本轮实机使用完整诊断构建 |

`max_kb` 保留旧的页数准入公式 `min(max_pages, max_kb*1024/(7*page_size))`，避免 RX 内存节省隐式扩大工作量：默认仍为 4K/292 页或 16K/73 页。新的 `buffer_kb` 是另一层明确限定范围的额度。若旧 quota 连一页都放不下，在发布 hook 前返回 EINVAL。

## 管理与构建

加载参数新增 `buffer_kb=64..262144`（KiB，默认 65536）、`fork_copies=0..4`、`loader=on|off`。前两项以及 `writes=rx|experimental` 可以通过 ctl0 在全局 inactive 时修改；活动会话返回 EBUSY，不能改变现有描述符布局。loader 是加载期选择。

```powershell
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk <NDK>
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk <NDK> -Diagnostics -OutDir out/diagnostics
.\build.ps1 -KernelPatchRoot E:\KernelPatch -Ndk <NDK> -OverlayOnly -OutDir out/overlay-only
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z memory
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z health
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z compat
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z perf
```

`memory.used/peak/limit` 单位为字节，`denied` 是预算或记录槽拒绝次数，不含 native allocator 自己的失败。降低额度不会清除历史 peak。`perf` 的 `*_ticks` 使用 CNTVCT，除以 `clock_hz` 得秒；观测最大值不是最坏执行时间保证，也没有与旧版做同温控/调频基准。

`compat.public_checks_*` 统计存在符号的 public 接口检查次数，包含可选候选与重复检查，不是不同函数数或已安装 hook 数。FOLL 来源掩码：GET=0x01、PIN=0x02、LONGTERM=0x04、FAST_ONLY=0x08、FORCE=0x10；分别落在 `foll_btf`、`foll_version` 或 `foll_unavailable`。不改变原适配策略，缺少 BTF 的稳定 public 回退与需要严格 BTF 的 private 入口继续区分。

```bash
out/compat-1.2.5/compat-check --inspect kernel.btf --symbols symbols.txt --kernel 6.1.134
```

symbols 支持每行一个名字或 `/proc/kallsyms` 原文；未提供则输出 unknown。未提供内核版本时不生成依赖版本的 FOLL 回退值。inspect 退出 0 表示布局可解析并生成报告，2 表示输入错误，3 表示布局不支持；均不替代 KPM preflight 和设备回归。

## 当前 6.1 设备结论

Pixel 6 / oriole、Android 16、AArch64、内核 `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，4 KiB 页。此前静态证据的 BTF SHA-256 为 `ef6ffa2e5d2f10ad1438a89a77d42747e80c7b78367c1d191140c5e623ff4970`，Build ID 为 `9daa9338ce7dbe41569bda1f6bb43f77191160ff`。

本轮最终候选在此设备完成实际加载和运行回归：`ptl=apply-existing`、`handle_mm_fault/4`、`__get_user_pages_remote/7` + PIN、`internal_get_user_pages_fast`、FPSIMD helper 可用。运行时 public 检查为 strict=25、fallback=0、rejected=0；FOLL 来源为 version=0x1f，GET/PIN/LONGTERM/FAST_ONLY/FORCE 分别为 `0x4/0x40000/0x10000/0x80000/0x10`。

结论是该 **6.1.134 具体构建、普通支持的文件 RX 页和已测读取/生命周期路径兼容**。缺少经验证的 contpte unfold helper，`contpte=0`，需要拆分连续组的目标仍拒绝。不能外推为所有 Android 6.x 内核或全部指令/页形态兼容。

## 验证与产物

NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36。KPM 保持 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`。默认、Diagnostics、OverlayOnly 均构建成功；API、两个 APK、原生工具成功；19 个用户态 ELF 的 4K/16K LOAD/RELRO 检查通过。

| 验证 | 本轮结果 |
| --- | --- |
| 新生产辅助代码 | 主机 ASAN/UBSAN 与设备：8 万次并发预算 reservation、8 万次影像发布、独立锁推进、预算溢出/取整/失败归还/槽耗尽、4K/16K 映射身份正负例通过 |
| 原有模型 | native leaf 17,968 项、GUP 18 组、索引 10,000 次发布、核心 4152、块扫描、HINT/FMOV、KCLF 46 与 RELRO 24 项通过 |
| BTF | 5.15.74、6.1.134、6.12、6.18、6.18/16K 保存 BTF；新通用 inspector 的错误输入、符号精确匹配，以及设备 live BTF 检查通过 |
| 普通 App | 无模块 baseline 5/5；加载最终候选后 73/73、failures=0 |
| RX 生命周期 | 606 项父断言及子检查；部分迁移+SET 的四线程三通道检查 883,855 次；同页 SET 检查 566,190 次；均正常退出 0 |
| 资源控制 | 64 KiB 额度拒绝注册，保留 native 值、回收 used=0；fork_copies=0 拒绝 fork 且线程读取正常；active 下三项配置拒绝；模式切换分配布局 3→7→3，通过 |
| experimental | 1/2/4/8/10/32/64/128/256 页、LLSC-8192、CLREX、间接路径、代码/内核写入、子影像、LSE、64 字节 DC ZVA，正常退出 0 |
| KCLF 集成 | manual/linker 各 3 轮：十页三通道 CRC、四线程扫描/调用、活动覆盖下 probe、清理和最终请求回收，assertions_failed=0；runner 完成后退出 |
| TSan | WSL 内启动即报 `ThreadSanitizer: unexpected memory mapping`、退出 66，未运行测试，不计为通过；ASAN/UBSAN 和设备并发测试不能替代 race detector |

首次启动 App 时误用了完整测试而非 baseline 参数，模块尚未加载，认证 QUERY 如预期失败；该日志保留为 `preload-full-app-missing-module.txt`。随后显式 baseline 得 5/5，再加载一次候选并执行以上回归，未隐去失败尝试。

| KPM | SHA-256 | 字节 |
| --- | --- | ---: |
| 默认构建 `out/urov-z.kpm` | `9f86d3c72eb0e0bbffe856f6e213452d55c33b586c9cee21b42046af449a646b` | 443976 |
| **设备实测 Diagnostics** `out/optimization-1.2.5/diagnostics/urov-z.kpm` | `4691049088e40ea0738a0add0f63da2864b7bcd45285c491e1aea4b1c9be73dc` | 455768 |
| OverlayOnly `out/optimization-1.2.5/overlay-only/urov-z.kpm` | `e735dc97335335bd61bb5c7b4633899d41e8e9211c2449cc0a45b6763900aa21` | 279296 |

默认与 OverlayOnly 为构建验证，未在本轮热替换到设备；`loader=off` 未单独实机加载。最终诊断 KPM 文件与设备散列一致，KPM info 为 1.2.5。设备 boot ID 前后一致，未主动重启或热卸载。

最终状态：一份 KPM 驻留，`writes=rx`、inactive、pages=armed=degraded=failures=0；覆盖缓冲 used=0、limit=64 MiB、peak=17,293,312、denied=1（限额负例）；KCLF 无请求、无 manual image。累计 rearm 8/8 成功、rearm 错误=0；mmap 忙/原指令重试分别 36,901/36,898，写入退役 2 次来自 RX 专项。它们不等同于数据读失败，也不是零争用声明。当前采集的 crash 日志为空；模块加载后的 dmesg 未匹配 Oops、BUG、panic、WARNING、CFI failure。系统启动早期的 wpa_supplicant 兼容 warning 不属于本轮模块运行。

完整构建日志、主机与设备输出、最终状态和产物清单保存在忽略目录 `out/optimization-1.2.5/`；`baseline/` 和 `baseline-sha256.json` 保留本轮开始时的源码，便于区分原有未提交修改。设备管理密钥没有写入源码或报告。

## 尚未消除的设计边界

1. 原生 fault 安装 PTE 到 after-hook rearm 的并发可见窗口仍存在。当前复核避免对错误映射重新设 trap，并提供失败诊断；没有宣称 PTE 发布与覆盖原子化，`compat` 明确给出 `refault_atomic=0`。
2. 共享文件别名、任意外部写者、长期 pin/DMA、LL/SC 历史 reservation，以及跨页/多指令事务仍受原契约限制。SVE/SME、任意 tagged ABI、AArch32、64K、LPA2 未新增支持。
3. 宿主 hook 跳板的在途回收没有被模块内锁或 epoch 修复。`hot_unload=0`，保持驻留，受控重启后更新。此处没有修改或部署外层 KernelPatch loader；inactive、used=0 和 KCLF 空闲均不是热卸载安全证明。
4. 5.4/5.10、其他新 6.x、16K 与 RT/debug/non-PREEMPT_RCU 仍需要匹配设备的准入和压力测试。本轮不以 BTF/模型通过替代这些设备证据。
