# UROV-Z 1.2.2 实现审计与兼容性修订

日期：2026-11-14（Asia/Shanghai）。基线：独立 `urov-lab` 仓库 `21772ec`。
本次只修改该独立仓库；外层 KernelPatch 的已有修改不属于此次交付。

## 结论与适用范围

该框架的主要方案成立于受控的 ARM64 RX 文件代码页测试：执行使用实际代码，受支持的数据读取由注册影像提供。它已有较完整的指令解码、进程生命周期跟踪、认证接口和 BTF 适配，但仍不是任意程序、任意内核配置下透明的通用内存虚拟化层。

本次针对 5.x/6.x 的符号、函数参数、页引用及 BTF 传递修复兼容缺口，同时修复指令模拟器和构建工具中的确定性问题。版本范围仍是 **5.4 ≤ Linux < 7.0，AArch64，普通 4 KB/16 KB 页**；这是准入范围，不是全范围实机认证。缺少必要符号、匹配 BTF 或不支持页表格式时仍拒绝加载。

## 实现拆解

| 组成 | 实现与数据流 |
| --- | --- |
| 入口 `module/urov_z.c` | 单 KPM 内编排读取覆盖后端与 KCLF，提供全局 status/perf 和 `kclf,` 管理入口 |
| 注册与控制 | 用户态 API 通过 prctl 传递固定 ABI，SipHash 校验请求；会话绑定 owner mm，先复制并验证全部页描述及影像，再发布会话 |
| PAGE_AP | 注册可读、可执行、不可写的普通文件映射；清除 leaf PTE 的 AP[1]/PTE_USER，刷新 TLB。取指继续使用实际页，数据访问产生权限异常 |
| 异常读取 | `do_mem_abort` hook 验证 ESR/FAR/EL0 状态，解码访存指令，从影像窗口或原始快照取值，再提交寄存器、writeback 和 PC；SIMD 依赖经验证的 FPSIMD 布局与 helper |
| 内核代读 | 远程 VM helper 在原权限检查完成后处理返回缓冲；process_vm_readv/GUP 使用独立影像页，并维持 GET/PIN 引用约定。覆盖能力由实际安装的 hook 与 helper 决定 |
| 读者生命周期 | 单原子字维护关闭位、epoch 与两组读者计数；SET 使用备用影像交换，等待旧 epoch 清空后复用。该机制保护影像寿命，不自动保护描述符重排或所有写入 |
| 映射与 fork | 跟踪 mprotect/refault/unmap/remap；fork 建立独立子快照并保留 mm 引用；仍存活的快照子进程阻止注销 |
| 指令分析缓存 | 分块读取指令；负 LL/SC 分析缓存每次命中仍验证完整字节，避免使用已修改代码的旧结论 |
| KCLF | 通过 task_work 在协作线程边界执行 manual ELF 映射/重定位或 bionic linker 调用；追踪请求、临时映射、manual 镜像引用和清理 |

必须区分三类密钥/权限：设备 kpatch superkey 用于管理，固定项目测试密钥用于 overlay 请求认证，目标进程的凭据/SELinux/linker namespace 决定 SO 文件与映射访问。root 管理能力不会取消后两者的内核约束。设备 superkey 没有写入本次源码或测试报告。

## 本次修复

| 优先级 | 原问题 | 修改 |
| --- | --- | --- |
| P1 | `__get_user_pages` 固定为七参数；旧版带 task 前缀，新版去掉 vmas，可能读取错误参数或遗漏 hook | 从完整 BTF 原型识别六/七/八参数，统一提取 mm/start/count/flags/pages；内部入口缺原型或类型不符时禁用 |
| P1 | 5.4 的 process_vm_readv 使用 GET 页引用，原框架只适配 PIN | 缺少 PIN 的符号与 BTF 证据时启用经完整 BTF 验证的 get_user_pages_remote；新页初始引用直接移交，原页及失败数组使用 put_page，PIN 路径仍使用 grab/unpin |
| P1 | 外层接受精确 Build ID 的 detached BTF，KCLF 却重新只找 live BTF | 将已验证 BTF 提取为 KCLF 的独立标量 profile；不保留 BTF 内存指针，释放包后不存在悬空类型引用；probe 显示 `source=shared` |
| P1 | KCLF 必需符号/布局验证发生在 overlay hooks 安装后，失败会进入依赖宿主的回滚 | 在任何 overlay hook 安装前执行幂等 preflight；后续加载器观察 hooks 可降级 polling |
| P1 | LL/SC 的泛化 HINT 掩码也匹配 PAC/AUT/XPACLRI，模型会静默略过签名寄存器更新；屏障同样被当作无操作 | 只接受明确 NOP 与既有 BTI landing pad；其余 HINT、DMB/DSB/ISB/SB 拒绝在后窗口模拟，保持原寄存器不变；目的/源寄存器分类同步修正 |
| P2 | FMOV S/H 清零高 12/14 字节时对 64 位值移位 ≥64，触发 C 未定义行为 | 限制移位范围，超出八字节直接填零；修复前 UBSAN 可复现，修复后模型测试通过 |
| P2 | 旧版页分配入口为 `__alloc_pages_nodemask`，新版可能是 `_noprof`，原选择和校验名字不一致 | 按候选实际符号校验并选择相应分配器，增加初始化诊断 |
| P2 | 新内核移除 `try_grab_page`，导致 READV 能力下降 | 校验 `try_grab_folio` 的完整签名及 `folio.page` 的零偏移完整布局，只对新分配的 order-0 页使用；保持初始 ref、PIN ref、unpin 平衡 |
| P2 | mmap_read wrapper 常被内联，扫描会退化为 mmap 写锁 | 在布局及函数签名可用时使用 `down_read/up_read`，两半统一使用 rwsem ABI；保留原有保守回退 |
| P2 | task_work_add 仅验证 notify 类型 | 同时验证返回值、task_struct 指针和 callback_head 指针；不兼容原型在装 hook 前拒绝 |
| P2 | 部分测试/诊断 ELF 是 NDK 26 默认 4 KB 对齐 | API、App、集成库及所有测试程序设置 max/common page size=16384，包括原先遗漏的 query、compat-check、insn-scan 和 relro-test |
| P1 | 16 KB common-page-size 的 SO 在 4 KB 设备上被 manual 加载器错误拒绝：RELRO padding 可超过运行页尾 | 按 LOAD 声明且 bias 满足的链接对齐验证 padding，并拒绝实际保护页与其他 LOAD 相交；ELF 数据表仍使用严格字节范围检查。24 项回归和三个真实 SO 的 4K/16K 布局检查通过 |
| P2 | perf-device 无条件执行 LSE，在老 ARMv8.0 CPU 上可能 SIGILL | 查询 HWCAP_ATOMICS，仅跳过 LSE 专项，其余读取回归继续执行 |
| P2 | 干净 Windows PowerShell 进程缺少 ZipArchiveMode 类型，APK 打包失败 | 两个 APK 构建脚本显式加载 System.IO.Compression 与 FileSystem 程序集 |

HINT 修改会减少可以完整模拟的 LL/SC 窗口；它修正的是错误接受，不表示解决了任意独占序列的透明性。4 KB/16 KB ELF 对齐也不等价于在 16 KB 内核上验证了模块。

## 仍需优先解决的整体问题

1. **P1：原生 PTL/VMA 并发。** 现有 walker/CAS、mmap lock、RCU/关中断不足以替代 Linux split PTE lock。在 reclaim、迁移、上级页表拆除及较新 per-VMA lock 场景下，仍需验证表页寿命、加锁并再次核对挂接关系。不能用更多版本分支来宣称该问题已解决。
2. **P1：描述符发布。** 并发 mremap 后的原地 base 更新/排序可能与无控制锁的异常读者冲突。建议发布不可变页索引表，再经过读者 grace period 回收；现有 epoch 仅保护影像释放。
3. **P1：父子映射状态耦合。** 子快照仍有依赖父描述符 armed/want/dead 状态的路径。父映射保护或移除与子读取并发时，应把子映射身份和 arming 状态独立保存。
4. **P1：写入与原子语义。** 原地影像写入、SET、外部内核写入与 LL/SC 重建没有统一线性化协议。DC ZVA 辅助路径还假定 64 字节块。建议先把严格 RX 读取契约与辅助写入实验分开，再处理跨线程原子内存模型；暂不将这些路径表述为任意写入兼容。
5. **P1：宿主 hook 回收。** preflight 降低初始化失败时已发布回调的概率，但没有修复宿主跳板在途调用的回收。更新模块仍使用受控重启；inactive、无请求或 quiesce idle 均不是热卸载安全证明。
6. **P2：配置边界。** 5.0–5.3、AArch32、64 KB、LPA2、SVE/SME load、带标签 ABI 地址不在已支持范围；CONFIG_NUMA 下底层页分配的 preferred_nid 约定及厂商回移的 TIF 位号仍需专项适配。常规 Android 配置上的结果不可外推到这些组合。
7. **P2：维护性。** backend 仍同时承担控制、异常、映射、GUP、fork 和重放。建议后续按这些职责拆分，并保持实际 ABI 选择函数的独立合成测试；避免先做大规模格式重排掩盖语义差异。

## 验证口径

本次唯一实机：Pixel 6 / Android 16 / Linux 6.1.134 / 4 KB。离线真实 BTF 覆盖 5.15.74、该设备 6.1.134、GKI 6.12、GKI 6.18、GKI 6.18 16 KB。5.4/5.10 的新增路径来自上游源码与合成原型测试，暂无对应实机证据。

构建使用 NDK 26.1.10909125、SDK Build Tools 36.0.0、android-36。KPM 保持 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`。测试新增完整 HINT 空间及屏障选项拒绝测试、KCLF profile 的有效/无效 BTF 测试、GUP 参数宽度/顺序/缺失原型和 folio 布局测试。

设备实测记录和产物校验保存在忽略目录 `out/audit-20261114/`。后文记录最终结果；未在本次设备运行的内核版本不计作实机通过。

## 最终验证结果

最终 KPM SHA-256：`B5BBC10ACFCCF170C78E6C70CA4F2AF7305B60691F10A4762CEEE1A7C18D317E`。

| 项目 | 结果 |
| --- | --- |
| KPM / API / 两个 APK 严格构建 | 通过；Windows PowerShell 干净进程可完成 APK 打包 |
| 13 个原生工具与 SO 的 LOAD / RELRO 对齐 | 均满足 16 KB 对齐检查 |
| 模块未加载基线 | 5/5 |
| 最终模块 + exact-build detached BTF，普通 untrusted_app 回归 | 73/73，failures=0 |
| 最终模块 manual 注入 | 3 轮，每轮十页三通道 CRC、执行返回值、并发扫描、活动覆盖时探针注入、清理全部 PASS |
| 最终模块 linker 注入 | 同上，3 轮 PASS，assertions_failed=0 |
| 读取专项 | 1/2/4/8/10/32/64/128/256 页，LLSC-8192、CLREX、间接跳转、代码改写、proc 写入、子快照及 LSE 全部 PASS |
| 指令扫描 | 核心 4152 项、256 次分块扫描、4,194,304 个指令字、失败回退与缓存重置 PASS |
| HINT/屏障/FMOV | 192 项 HINT/屏障测试和 2 项 FMOV 高位清零通过；主机 UBSAN 通过 |
| KCLF BTF profile | 46 项通过；主机 ASAN/UBSAN 通过 |
| RELRO | 24 项通过，三个真实 SO 的 4K/16K 布局检查通过；主机 ASAN/UBSAN 通过 |
| 真实 BTF + 合成 ABI | 5.15.74、6.1.134、GKI 6.12、6.18、6.18/16K 均通过，含 GUP/folio 正反例 |
| 错误 Build ID | 加载返回 -EINVAL，KPM 数量保持 0，随后匹配包正常加载 |
| 最终设备状态 | 1.2.2 已加载，`inactive pages=0 armed=0 degraded=0 failures=0`；无请求、无 manual 镜像 |

测试过程没有掩盖失败：第一版候选经 live BTF 加载，73 项、读取专项和 linker 三轮通过，manual 暴露上述 RELRO padding 问题。修复 RELRO 和 FMOV 后，重启加载最终构建，使用 detached BTF 跑完上表的最终模块回归。最终构建没有再次走 live 加载；两种来源均经同一 profile/preflight，不能将第一版候选的 live 结果冒称最终二进制的 live 实测。

内核日志保存为 `live-dmesg.txt` 和 `final-dmesg.txt`。采集范围内未发现内核 Oops、BUG、panic 或 module 栈的 WARN；启动日志有 eBPF、linker 配置等系统警告，NFC 驱动也输出错误，不能描述为整个日志无警告。两次重启均为用户授权的测试操作，没有执行 KPM 热卸载。

本次未以受控 CPU、温度、调度和同代样本进行前后性能比较，因此不宣称具体提速百分比。读锁回退减少了不必要的写锁使用；实际收益需要在 wrapper 被内联的目标设备上测量。

主要证据：`final-app.txt`、`final-manual.txt`、`final-linker.txt`、`final-perf.txt`、`final-probe.txt`、`final-status.txt`、`compat-final.txt`、`relro-final.txt`、`elf-alignment.txt`。这些位于 `out/audit-20261114/`，未纳入 Git。

## 上游依据

- [Linux 5.4 页分配实现](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/page_alloc.c)、[5.4 GUP](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/gup.c)、[5.4 process_vm_access](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/process_vm_access.c)。
- [Linux 6.12 GUP 与 folio 引用](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/gup.c)。
- [Linux 5.8 task_work](https://raw.githubusercontent.com/torvalds/linux/v5.8/include/linux/task_work.h)。
- [Linux 6.1 ARM64 HINT 编码](https://raw.githubusercontent.com/torvalds/linux/v6.1/arch/arm64/include/asm/insn.h)。
- [Linux split page table lock](https://docs.kernel.org/mm/split_page_table_lock.html)。
- [Android 16 KB 构建与验证要求](https://developer.android.com/guide/practices/page-sizes)。
