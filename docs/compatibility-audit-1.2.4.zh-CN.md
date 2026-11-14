# UROV-Z 1.2.4：5.x/6.x 兼容性修订

日期：2026-11-14（Asia/Shanghai）。修改基线是本地尚未提交的 1.2.3 工作树；它的实现与既有证据保留在 [1.2.3 审计](compatibility-audit-1.2.3.zh-CN.md)。本轮只修改独立 `urov-lab` 仓库，没有把外层 KernelPatch 的已有修改当成本轮交付。

## 结果与范围

兼容目标仍为 **Linux 5.4 ≤ version < 7.0、AArch64、4 KB / 16 KB 页**，实际准入同时取决于准确 BTF、函数 ABI 和页表几何。本轮在 **小米 13（fuxi / 2211133C）、Android 13、Linux 5.15.74、4 KB** 完成最终二进制的加载、普通 App、生命周期、辅助写入和两种 KCLF 集成测试。

最终 KPM SHA-256：`CE0E85C5A9777B2A2B67FB5EB86664DFFE400C96897C0868B01D94E9B99C142A`。最终源码重新构建得到相同散列，并与设备端 `/data/local/tmp/urov-z.kpm` 相同。KPM 和两个 APK 的版本更新为 1.2.4，用户态 UAPI ABI v1 保持不变。

5.15.74、6.1.134、GKI 6.12、6.18、6.18/16K 的真实 BTF 检查通过。**6.x 和 16 KB 本轮没有实机运行**；Pixel 6 / 6.1 的实机记录属于 1.2.3。5.4/5.10 仍是源码依据与合成 ABI 覆盖，不能由 BTF 或模型通过推导为所有厂商内核兼容。

## 框架实现与兼容性入口

1. `urov_z.c` 提供 KPM 初始化、认证管理控制和退出入口。`backend.c` 先解析参数、校验内核几何与 BTF，再进行 KCLF preflight，成功后发布 hook。live 与精确 Build ID 匹配的 detached BTF 共用布局/原型解析，避免依赖 KernelPatch 私有的 BTF 导出。
2. 用户态库通过带 MAC 的 prctl 请求绑定 owner mm。REGISTER 校验可读、可执行、当前不可写的文件映射，建立真实快照和替代影像。描述符采用固定槽位，`page_index.h` 发布不可变地址索引，mremap 更新地址而不移动正在被读者使用的影像描述符。
3. PAGE_AP 清除 leaf PTE_USER/AP[1]，保留物理页和取指权限。受支持的 EL0 数据 load 在 `do_mem_abort` before-hook 中解码，从影像复制数据后提交寄存器；原代码仍从原物理页执行。FPSIMD 等能力按已验证 helper 和布局开放。
4. `/proc/<pid>/mem`、ptrace 等代读在原生权限检查和复制成功后覆盖内核缓冲。process_vm_readv 和 fast-GUP 路径用新分配的 order-0 影像页替换已成功获得的页面，按 GET/PIN 分别交还引用；不重读用户 iovec 后改写目的地址。
5. fork 子槽独立保存影像、快照、base、文件页身份和 want/armed/dead/gone。影像复制和 SET 发布共享短锁。默认 `writes=rx` 在观察到写权限或受监测写入时退役目标页，SET 返回 ESTALE；`writes=experimental` 显式开放原有辅助写入实验。KCLF 使用共享 BTF profile，在协作线程 task_work 边界完成 manual/linker 加载。

## 本轮代码修改

| 兼容性问题 | 修改 | 实际边界 |
| --- | --- | --- |
| 完整 native callback 被限制在旧内核，新内核由模块拼接 PTL/RCU 解锁 | 5.x/6.x 均优先选择经 BTF 完整校验的 `apply_to_existing_page_range`；由 Linux 配对锁、PMD 重验、RCU 和 lockdep | 缺失时保留受限制的 map-lock fallback；旧 allocating callback 仅在 <5.8 且无 lockless-table-removal 证据时可选 |
| 6.x 自动折叠连续 PTE 会导致普通代码页注册被拒绝 | 提取生产 `pt_leaf.h`；需要修改 AP 时在 PTL 内调用经校验的 `__contpte_try_unfold`，由内核完成整个连续组的 BBM、TLBI 和 AF/dirty 合并，再重新读取目标 PTE | 不手动清 CONT；没有可验证 helper 则返回 EOPNOTSUPP。只读 residency/AP 检查不触发拆分；block/special/devmap/PROT_NONE 仍拒绝 |
| 连续 PTE helper 的最后一个参数为值类型 pte_t | BTF 分别验证 descriptor 的指针和值：单个 64 位成员、名字、偏移、typedef/const 和参数层数 | 不把 pte_t*、错误结构或错误宽度强制转换成值参数 |
| 内部/公开 GUP 入口与引用模式的选择耦合 | `uz_remote_gup_select` 分开选择入口和 GET/PIN，检查 kallsyms、BTF pin/unpin 函数及 FOLL_PIN 枚举证据；损坏的 PIN ABI 不回退为 GET | 老 GET 共享入口仅在公开 GET 原型同时可证明时开放；PIN 共享入口仍过滤非 PIN 调用 |
| 旧 5.x 的 try_grab_page 可能被内联 | 增加经完整 `page* → page*` ABI 校验的 `try_grab_compound_head(page, 1, FOLL_PIN)` fallback | 仅用于模块新分配的 order-0 影像页，NULL 表示失败，不混用 int/folio 返回约定 |
| fast-GUP 只验证最后参数是任意 pointer | 内部与公开 fast-GUP 原型改为校验 page**，保留 64 位/32 位 page count 的差异 | 错误指针层数、folio** 和返回宽度负例拒绝 |
| 仅检查 LOAD 对齐遗漏 Android 13 RELRO 加载失败 | 所有本仓库用户态链接入口统一采用 max-page-size=16384、common-page-size=4096；新增独立 ELF 检查工具 | 保留 16 KB LOAD 对齐；每个产物另验 4 KB/16 KB 下 RELRO 完整映射及与可变数据隔离。换工具链/布局应重验 |

`status` 增加 `contpte=0|1`、`readv_refs=none|GET|PIN`，PTL 字段区分 `apply-existing`、`apply-checked`、`map-lock-rcu`。这些是管理员诊断字段，没有修改用户态请求结构或能力位定义。`contpte=1` 只说明 native unfold helper 的 ABI 和符号可用。

### 页表锁的具体保证

`pt_access.h` 仍通过 mmap write-owner 识别或 read trylock 保护上级页表。忙时异常保留 PC/寄存器重试，其他 rearm 路径报告降级。不会退回无锁 leaf 写入。callback 与直接 map-lock 共用 `pt_leaf.h`，CAS 继续额外保留硬件 AF/DBM 更新，目标 VA 的 TLBI 在释放 native PTL 前完成。

完整 callback 能让内核自行处理其 PTL/RCU/lockdep 实现，消除了这一条路径对“spinlock 起始成员必须是 raw lock”和“必须手工配对 RCU 解锁”的依赖。它**不是整个模块的 RT、非 PREEMPT_RCU 或 debug 内核兼容证明**：例如集成 KCLF 的任务查询仍需要可用的 RCU accessor pair，其余运行环境限制也仍存在。

连续组拆分后会重新加载 PTE，不能拿拆分前的值继续 CAS，否则可能丢失内核合并的 AF/dirty。分组大小、物理地址递增和拆分期间的 TLB 行为全部由内核 helper 决定；模块不硬编码 16/128 项去修改真实页表。模型测试才分别用 4K/16K 分组替身验证目标与邻居行为。

### Android 13 的实际加载故障与修复

最初的无模块 App 基线和多个纯测试尚未进入 main/JNI 就报 `can't enable GNU RELRO protection ... Out of memory`。例如旧 `pt-leaf-test` 的 RELRO 从 `0xa260` 延伸到 `0xc000`，对应 RW LOAD 的实际末尾仅为 `0xa4e0`；4 KB 向上取整只映射到 `0xb000`。旧 linker 尝试保护包含未映射页的区间，mprotect 失败。

在本仓库 NDK 26.1.10909125 的实际布局中，改为 common-page-size=4096 后 RELRO 尾部不再扩展到空洞，max-page-size=16384 继续保持 LOAD 对齐。最终 17 个 ELF 均通过 `tests/check_elf.py`：对 4 KB 和 16 KB 分别检查 LOAD 页范围、RELRO 覆盖以及可执行/可变字节隔离；保存的旧产物被准确拒绝。Android 13 上工具启动和普通 App 基线随后通过。

这项参数选择针对已验证的旧工具链和旧 linker 组合。[Android 通用 16 KB 指南](https://developer.android.com/guide/practices/page-sizes)对 r27 及以下推荐两项都设为 16384；本轮的实机故障说明仅套参数和检查 LOAD p_align 不足以验证此仓库的产物。当前替代配置通过双页大小布局检查，但没有替代 16 KB 真机测试，也不宣称任意使用该静态库的消费者都自动满足隔离要求。

## 最终验证

工具链：NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36、JDK。KPM 编译保持 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`；主机测试使用 WSL Ubuntu 24.04 的 ASAN/UBSAN。

| 验证 | 结果 |
| --- | --- |
| KPM、独立 API、两个 APK、全部原生测试工具构建 | 通过；最终 KPM 重建散列不变，与设备相同 |
| 新 leaf 生产代码模型 | 主机 ASAN/UBSAN 和设备均通过 17,968 项；4K/16K 连续组所有位置、AF/dirty、目标/邻居、拒绝路径与 arm/disarm |
| GUP 与 BTF | 18 组共享/公开 GET/PIN 选择；12 组新 contpte ABI 正反例；fast-GUP/compound ABI；旧原型、分配器、folio 等全部通过 |
| 真实 BTF | 5.15.74 live 与已有保存文件 SHA-256 相同；连同 6.1.134、6.12、6.18、6.18/16K 共五配置通过。新 GKI 同时证明 apply callback、unfold helper 和新 folio ABI |
| ELF 布局 | 17 个工具/SO：AArch64 ELF64 little-endian、16 KB LOAD 对齐、4 KB/16 KB RELRO 完整映射并隔离；旧失败产物负例拒绝 |
| 无模块 App 基线 | 普通 untrusted_app，5/5 |
| 最终加载模块后的 App | 普通 untrusted_app，73/73、failures=0 |
| RX 生命周期 | 606 项父断言及子进程断言通过；100 次部分迁移 + SET 的四线程三通道检查 986,895 次；100 次同页 SET 检查 580,005 次 |
| 默认 RX 退役 | mprotect、COW store、proc 写入恢复 native；SET 返回 ESTALE；其他页继续覆盖 |
| 实验模式专项 | 1/2/4/8/10/32/64/128/256 页、LLSC-8192、CLREX、间接跳转、代码改写、proc 写入、子影像、LSE 通过；DC ZVA 实际 64 字节块、非对齐操作数与相邻字节通过 |
| manual 集成 | 三轮，每轮十页三通道 CRC、四线程 96 次 CRC/20,480 次调用、活动覆盖下 probe、清理均通过；assertions_failed=0 |
| linker 集成 | 三轮，同上；assertions_failed=0 |
| 其他模型回归 | 四线程索引 10,000 次发布；核心 4152、256 次块扫描/4,194,304 指令字、192 HINT/屏障、2 FMOV、46 KCLF profile、24 RELRO 全通过 |
| 最终设备状态 | 1.2.4 驻留，writes=rx，ptl=apply-existing，readv_refs=PIN，contpte=0，inactive pages=0 armed=0 degraded=0 failures=0；no requests、no manual images |

5.15 设备没有 `__contpte_try_unfold`，所以 `contpte=0` 是预期结果；本轮不能将普通页运行结果写成连续组 native 拆分实机通过。最终 dmesg 采集中未匹配到 Oops、BUG、Kernel panic、WARNING 或 CFI failure 标记。没有温控/调频下的同条件前后性能基准，不报告固定性能提升。

本轮未热卸载或主动重启设备。加载前模块数为 0；最终只加载一份上述 KPM。最初的 RELRO 启动失败发生在模块加载之前，未计入最终通过结果。集成 APK 首次安装被系统拒绝，后续正常安装成功，再完成两种后端回归。detached BTF 包和 Build ID 有合成回归，本轮最终模块使用 live BTF，没有再加载 detached 来源。

复现见 [tests/README.md](../tests/README.md)、`tests/host_compat.sh`、`tests/check_elf.py` 和 [INTEGRATION.md](INTEGRATION.md)。原始结果保存在忽略目录 `out/compat-1.2.4/`，包括 `host-final.txt`、`gki.txt`、`device-models.txt`、`baseline-app.txt`、`final-app.txt`、`final-lifecycle.txt`、`final-experimental.txt`、`final-manual.txt`、`final-linker.txt`、`elf-final.txt`、`build-final.txt`、`final-status.txt`、`final-probe.txt`、`final-dmesg.txt` 和产物散列清单。设备管理凭据没有写入源码或报告。

## 仍需验证或不能覆盖的边界

1. 5.4/5.10、新 6.x native callback 和连续 PTE 拆分仍需对应设备压力测试；16 KB 当前只有模型、真实 BTF 和 ELF 布局证据。部分 RT/debug/non-PREEMPT_RCU 组合仍会被其他 preflight 条件拒绝。
2. 原生 fault 安装 PTE 到 after-hook rearm 仍有并发可见窗口；mmap trylock 忙时也可能降级。本轮没有把这个窗口描述为已消除。
3. 任意外部写者、共享文件别名、已有长期 pin 和 DMA 不都经过受监测路径。默认 RX 退役只处理已观察到的变化；实验写入不构成通用线性化内存事务。
4. LL/SC 历史 reservation、跨 CPU 冲突、间接入口和跨页/多指令的统一 generation 保证仍有限。SVE/SME、任意 tagged ABI 地址、AArch32、64 KB、LPA2、Linux 5.0–5.3 未新增支持。
5. 宿主 hook 跳板的在途回收未在本仓库修复，保持模块驻留，更新继续采用受控重启。inactive/no requests/no manual images 均不是热卸载安全证明。

## 上游依据

- [Linux 5.4 memory.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/memory.c)、[6.12 memory.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/memory.c)、[6.18 memory.c](https://raw.githubusercontent.com/torvalds/linux/v6.18/mm/memory.c)：apply callback 的 PTL 与 map/unmap 配对。
- [Linux 6.12 pgtable-generic.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/pgtable-generic.c)：native map-lock 的 PMD 重验和 RCU 生命周期。
- [Linux 6.12 ARM64 contpte.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/mm/contpte.c)、[6.18 contpte.c](https://raw.githubusercontent.com/torvalds/linux/v6.18/arch/arm64/mm/contpte.c)、[ARM64 pgtable.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/include/asm/pgtable.h)：连续组转换、AF/dirty 合并、BBM/TLBI 和 PTL 调用要求。
- [Linux 5.4 process_vm_access.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/process_vm_access.c)、[5.4 gup.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/gup.c)、[5.15 gup.c](https://raw.githubusercontent.com/torvalds/linux/v5.15/mm/gup.c)、[6.12 gup.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/gup.c)：GET/PIN、compound helper 和 folio 返回约定。
- [Android 13 linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/android13-mainline-permission-release/linker/linker_phdr.cpp)：RELRO 范围按运行时页大小取整后执行 mprotect。
