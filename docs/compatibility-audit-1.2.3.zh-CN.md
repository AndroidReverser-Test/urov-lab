# UROV-Z 1.2.3 兼容性与并发修订

日期：2026-11-14（Asia/Shanghai）。基线：独立 `urov-lab` 仓库 `66ae73d`。
本轮修改仅在该仓库内，外层 KernelPatch 的已有改动没有纳入交付。

## 结果与适用范围

本轮落实 [1.2.2 审计](compatibility-audit-1.2.2.zh-CN.md) 中的原生页表锁、描述符发布、父子状态隔离、影像复制同步和平台 ABI 修订，并把默认 RX 读取契约与辅助写入实验分开。它仍是受控代码页读取测试框架，不是任意进程的透明内存虚拟化层。

准入目标保持 **5.4 ≤ Linux < 7.0、AArch64、普通 4 KB/16 KB 页**。实际加载还需要匹配 BTF、可识别的函数原型及页表路径。只有 **Pixel 6 / Android 16 / Linux 6.1.134 / 4 KB** 完成本轮实机验证。5.15.74、GKI 6.12、6.18、6.18/16K 是保存的真实 BTF 检查；5.4/5.10 是源码与合成 ABI 覆盖，均不能冒称本轮实机通过。

## 实现与数据流

注册通过带 MAC 的 prctl API 绑定 owner mm，验证 RX 文件页并复制真实快照和替代影像。PAGE_AP 清除 leaf PTE_USER/AP[1]，保持物理页及执行权限。取指运行原代码；受支持的 EL0 数据 load 进入 `do_mem_abort` hook，从影像取数并提交寄存器。内核代读在原权限检查之后覆盖已成功返回的字节或替换 GET/PIN 页。KCLF 与读取后端共享已验证 BTF，使用协作 task_work 边界完成 manual/linker 加载。

本轮将容易随内核变化的部分提取到 `compat.h`、`runtime_compat.h`、`pt_access.h`，索引发布提取到 `page_index.h`。`backend.c` 继续负责控制、异常和生命周期编排；没有通过整体重排文件掩盖语义修改。

| 原问题 | 1.2.3 修改 | 证据和限制 |
| --- | --- | --- |
| 无锁 walker/CAS 不能代替 Linux PTL | 所有 leaf 读写进入 native PTL helper；CAS 仅额外保留硬件 AF/DBM 更新，TLBI 在解锁之前完成 | 6.1 使用 `apply_to_existing_page_range` 实测；新 map-lock 路径为真实 BTF/源码验证 |
| mremap 原地移动、排序描述符 | 描述符固定槽位；备用地址索引排序后原子发布，旧 epoch 排空后重用 | 四线程 10000 次发布，ASAN/UBSAN、TSAN 和设备通过；另有实际部分迁移测试 |
| 子读取依赖父 armed/want/dead 与地址 | 每个子槽保存独立影像、快照、base、文件页身份及生命周期状态；子映射 syscall 纳入控制事务 | 父 PROT_NONE、SET、unmap 后子读取/执行不变；子自己保护、refault、迁移、替换通过 |
| 就地写入、SET、sequence fallback 可能撕裂 | 短 IRQ 屏蔽锁统一影像复制、写入发布和 SET 交换；SET 在锁内合并最新窗口外快照 | 同页 SET 与四线程直接/readv/proc 检查通过；不等于任意 native writer 的原子保证 |
| 写入机制与 RX 读取保证混在一起 | 默认 `writes=rx`；观察到写权限或受监测写入后退役页，恢复 native，SET 返回 ESTALE；辅助写入显式开启 | RX 生命周期测试、实验模式原有写入/LSE 专项分别运行 |
| 底层 allocator 的 nid=-1 不成立于所有 NUMA 配置 | 优先验证 policy allocator；否则使用 `first_online_pgdat()->node_id`，拒绝负节点/不可用 accessor | 合成在线节点变化、缺失、失败测试；实机使用 `__alloc_pages` |
| 新旧 folio helper 返回约定不同 | 分别校验 page*→folio* 与 folio*→int 两种 `try_grab_folio` ABI；不混用 NULL/零成功语义 | 合成正反例和真实 BTF；GET/PIN 引用约定保持 |
| GUP 仅检查任意 pointer | page**、VMA**、int* 分层解析 typedef/const 并检查 pointee | 6/7/8 参数、错误层数/类型/顺序/宽度测试 |
| access_remote_vm 的 int 返回误按 long 解释 | 取 W0 的有符号 int32，并以原请求 int 长度为界 | 负 errno、非零 X0 高位、短读、超长返回测试 |
| DC ZVA 固定 64 字节 | 读取 DCZID_EL0 的 BS/DZP，按块大小对齐 Xt，检查 SCTLR.DZE | 4096 组模型组合；设备 64 字节块、块内非对齐操作数和相邻字节通过 |
| 厂商回移 TIF_UPROBE 编号 | 同时保守检查 bit 4/5，不只按版本号选择 | 可能额外拒绝某些安全点；不扩大任意线程注入保证 |

### 原生 PTL 与 VMA

`pt_access.h` 的 guard 在模块自身持有 mmap write lock 时识别当前 owner；其他上下文使用 mmap read trylock。fault/GUP 可能已经持有 native 读锁，不能再次阻塞获取读锁并排在写者之后。trylock 忙时异常返回保留 PC/寄存器重试；rearm 路径报告降级，不能静默继续无锁访问。

新内核优先调用 `__pte_offset_map_lock`，由 Linux 映射 PTE、取得 split PTL、重验 PMD 挂接关系。BTF 校验 pte_t/pmd_t 的单个 64 位成员、spinlock_t** 层数、raw_spinlock pointee，以及非 RT 的零偏移 rlock。ARM64 无 HIGHPTE 映射，解锁后配对 `__rcu_read_unlock`。缺失 PREEMPT_RCU helper、RT mutex 型 spinlock、存在 `rcu_lock_map` 而不能配平 lockdep 的配置会拒绝该路径，不能宣称支持所有 RT/debug 内核。

旧内核用 `apply_to_existing_page_range` 的原生 callback。5.4 无此函数时，在 mmap 保护下确认 PMD 为现存普通页表后，才允许 `apply_to_page_range`。旧路径限定 <6.5，且不能存在新 map-lock/`pte_free_defer` 的回移证据。缺少必要 ABI 在任何 overlay hook 发布前拒绝加载；不会回退至无锁 leaf CAS。

上级遍历使用实际 TCR 几何，只到 PMD。为兼容未导出 `linear_voffset` 的宿主，加载前从当前用户 mm 的线性映射 PGD 做一次 AT/PAR 翻译，保存/恢复 IRQ 状态及 PAR_EL1，并用 `memstart_addr` 校验推导的 PAGE_OFFSET；不依赖 KernelPatch 私有导出或硬编码 KASLR 偏移。5.x/6.x arm64 PGD 来自 page/slab allocator 的依据见文末源码。非标准厂商分配方式不能仅凭这个检查认定支持。

VMA 查询返回复制的 start/end/flags/file/pgoff，不在可能释放锁的 helper 之后保留 VMA 指针。子页与部分迁移页使用注册时固定的文件页偏移比对，避免拿新 base 与旧 VMA 起点重新计算。跨页数据读取也检查各段权限。PAGE_AP 仍只接管受支持的普通 leaf；contiguous、special/devmap、huge 等不被当作普通页处理。

### 生命周期与写入契约

索引只存 `{base, slot}`，影像缓冲永远属于稳定槽位。mremap 更新不再复制正在被读者使用的整个描述符，也不会在持有自身 reader 引用时等待旧 epoch。移动后原 LL/SC 分支图标为 incomplete，保守拒绝依赖该图的证明。

子快照不再借用父映射状态。涉及受管页的 `MREMAP_DONTUNMAP` 或 old_size=0 映射复制需要额外的独立槽位管理，本轮明确返回 EOPNOTSUPP。普通迁移、缩减、munmap、MAP_FIXED 只更新对应 mm 的槽位。存活子快照仍使 DEACTIVATE 返回 EBUSY。

默认 `writes=rx` 的页在 mprotect 增加写权限或受监测的内核写路径触达后退役：dead=1、want=0，尽力恢复 AP[1]，全局 degraded=1。后续直接/GUP/proc 读取使用 native 值；SET 不复活该页而返回 ESTALE，须注销重新注册。恢复了 AP[1] 但仍只读的 COW PTE 交给 Linux 处理，不能吞掉原生写 fault。若页表锁暂时不可得，保留 tombstone，后续异常重试恢复。

加载参数与认证 KPM ctl0 支持 `writes=rx|experimental`；仅 inactive 可切换，活动会话返回 EBUSY，UAPI 结构不变。实验模式保留原标量/向量 store、LSE 和辅助重放。大于 64 字节的 ZVA 虽能正确解码，当前 store 缓冲不能模拟，走 native handoff；启用实验模式也不是所有 DC ZVA/SVE/SME 都能保持覆盖。

## 最终验证

最终 KPM SHA-256：`174C929A89C19DC4ED636FE9AD9AB6395F2FA60D7F88586CD1D304FE7CB548F7`。

使用 NDK 26.1.10909125、SDK Build Tools 36.0.0 / android-36。KPM 保持 `-Wall -Wextra -Werror -Wformat=2 -Wshadow`。主机测试在 WSL Ubuntu 24.04 使用 ASAN/UBSAN，索引压力另外使用 TSAN。

| 验证 | 结果 |
| --- | --- |
| KPM、API、两个 APK、原生工具构建 | 通过 |
| 原生 ELF 对齐与产物一致性 | 16 个工具/SO 均为 AArch64 ELF64 little-endian，全部 PT_LOAD 至少 16 KB 对齐且 offset/vaddr 同余；本地与设备 KPM SHA-256 一致；20 项产物散列已归档 |
| 模块未加载 App 基线 | 5/5 |
| 最终 live-BTF 模块，普通 untrusted_app | 73/73，failures=0 |
| RX 生命周期 | 606 项父断言通过，子进程保护/迁移等断言通过并正常退出 |
| 部分 mremap + SET | 100 次迁移/更新；四线程稳定页三通道检查 1,644,996 次，未错配 |
| 同页 SET 发布 | 100 次更新；四线程三通道检查 672,465 次，未撕裂 |
| RX 写入退役 | mprotect、COW store、proc 写入恢复 native；其他页继续覆盖；SET 返回 ESTALE |
| manual / linker | 各三轮，每轮十页三通道 CRC、函数执行、四线程压力、活动覆盖下 probe、清理全部通过；assertions_failed=0 |
| 实验模式读取/写入专项 | 1/2/4/8/10/32/64/128/256 页、LLSC-8192、CLREX、间接跳转、代码改写、proc 写入、子快照、LSE 通过 |
| DC ZVA | 主机/设备模型 4096 组合；最终模块设备实际 64 字节块、块内非对齐地址和未触碰邻居通过 |
| 独立索引压力 | 四线程、10000 次发布；主机 ASAN/UBSAN 与 TSAN 无报告，设备通过 |
| BTF/ABI | 五份真实 BTF；新增 12 组 PTL pointee/回调/锁负例和 NUMA、folio、GUP 正反例通过 |
| 指令/加载器纯测试 | 核心 4152、256 次块扫描/4,194,304 个指令字、192 HINT/屏障、2 FMOV、46 KCLF profile、24 RELRO 通过 |
| 最终设备状态 | 1.2.3 驻留，writes=rx，inactive pages=0 armed=0 degraded=0 failures=0；KCLF no requests |

最终版本使用 live BTF 加载。detached BTF 的包格式/Build ID 检查与共享 profile 有主机回归，上一轮 1.2.2 有设备结果；本轮没有再以 detached 来源加载最终二进制，不混计两者。

本轮按用户授权受控重启一次，没有热卸载。首个加载尝试因宿主未导出 `linear_voffset` 在重定位阶段失败，KPM 数量保持 0；修复该依赖后加载候选。新生命周期测试随后暴露 RX COW 重试循环，终止该测试并回收死亡会话后修正，重启加载上述最终构建，606 项全通过。测试初版还错误把线程启动的控制锁 EBUSY 当成失败，后按 API 约定只对未提交的 EBUSY 重试。这些候选结果未计为最终通过。

最终采集的 dmesg 中没有发现内核 Oops、BUG、panic 或 module 栈 WARN；启动阶段仍有 eBPF、linker 配置等系统警告，不能称整个日志无警告。没有做温度/调频控制下的同条件前后基准，不宣称固定性能提升。

复现入口见 [tests/README.md](../tests/README.md)、`tests/host_compat.sh` 和 [集成说明](INTEGRATION.md)。原始日志、构建记录及产物散列在忽略目录 `out/compat-1.2.3/`；主要为 `host-final.txt`、`index-tsan.txt`、`final-lifecycle.txt`、`final-app.txt`、`final-manual.txt`、`final-linker.txt`、`final-perf-zva.txt`、`final-dmesg.txt`、`final-status.txt`、`elf-alignment.txt` 和 `artifacts.json`。设备管理凭据未写入源码或本报告。

## 仍未解决或未验证的边界

1. 原生 fault 安装 PTE 至 after-hook 重新 arm 之间仍有并发可见窗口；trylock 忙时也可能降级。PTL 改进不是任意 reclaim、迁移、厂商回移和 per-VMA 配置的全组合证明。
2. 任意外部写者、已有长期 pin、共享文件别名和 DMA 不都经过已装 hook。RX 退役只针对已观察到的变化，不提供全系统写入追踪。实验模式外部写后合并也不是通用线性化事务。
3. LL/SC 的历史 reservation、跨 CPU 冲突、间接入口仍不能从有限指令窗口完全恢复。多页、多指令读取不保证统一 generation；同页单次复制的同步不应扩大成整次 CRC 的事务保证。
4. 宿主在途 hook 跳板回收未在本仓库修复。inactive/no requests 不是热卸载安全证明，更新继续受控重启。
5. 5.0–5.3、AArch32、64 KB 页、LPA2、SVE/SME load、任意 tagged ABI 地址、部分 RT/lockdep 配置未支持。5.4/5.10 与 6.12/6.18 原生 PTL 分支仍需要相应内核设备压力测试。

## 上游依据

- [Linux split page table lock](https://docs.kernel.org/mm/split_page_table_lock.html)：split PTL 与 native map/unmap helper 的职责。
- [Linux 6.12 pgtable-generic.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/pgtable-generic.c)：PMD 挂接重校验、PTE 映射和 RCU 生命周期。
- [Linux 5.4 memory.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/memory.c)：`apply_to_page_range` 的 callback 在 native PTL 内执行。
- [Linux 5.4 ARM64 pgd.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/arch/arm64/mm/pgd.c)、[6.1 pgd.c](https://raw.githubusercontent.com/torvalds/linux/v6.1/arch/arm64/mm/pgd.c)、[6.1 memory.h](https://raw.githubusercontent.com/torvalds/linux/v6.1/arch/arm64/include/asm/memory.h)：PGD page/slab 分配和线性映射变换。
- [Linux 5.4 mempolicy.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/mempolicy.c)、[6.12 mempolicy.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/mm/mempolicy.c)、[5.4 mmzone.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/mm/mmzone.c)：policy allocator、preferred node 与在线 pgdat。
- [Linux 6.1 clear_page.S](https://raw.githubusercontent.com/torvalds/linux/v6.1/arch/arm64/lib/clear_page.S)：按 DCZID_EL0 取得 ZVA 块大小。
