# UROV-LAB：ARM64 读取异常覆盖完整设计

日期：2026-11-02。状态：设计、解码/模拟核心、预检KPM及部分真机测试已完成，活动覆盖后端尚未实现；不是已通过完整真机覆盖验收的 KPM。最新证据见 `IMPLEMENTATION_RESULTS.md`，下一阶段详细实施契约见 `BACKEND_CONTRACT.md`。

本文承接仓库根目录 `ARM64_USER_READ_OVERLAY_DESIGN.md` 与 `../urov-probe/` 的设备验证。原文的通用目标不变；这里明确当前设备能做的受限实验、不能省略的可靠性条件，以及实验到完整后端的实现边界。测试细则见 `TEST_PLAN.md`。

## 1. 决策与可交付边界

采用“原页取指 + 数据读取权限异常 + 软件模拟普通 load”的路线。禁止硬件断点/观察点、单步、每次读取临时开放 PTE、改写读取点、全局关闭 PAN/CFI、修改全局 protection_map。

当前 Pixel 6 没有 EPAN，正常 `PROT_EXEC` 仍可数据读取。底层权限分离在架构上可表达，但强制 raw-XOM 会使相关映射失去原有 PAN 读取隔离。上游正因此撤回了这类无 EPAN 的用户 XOM；不可把本实验称为保留内核隔离的生产方案。[上游撤回说明](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jbarnes/linux/+/24cecc37746393432d994c0dbc251fb9ac7c5d72)

明确区分两个交付档位：

| 档位 | 范围 | 可靠性上限 | 当前状态 |
|---|---|---|---|
| LAB-1 | 精确内核、合作测试进程、一页 sealed memfd、一个 8 字节覆盖 | 可验证的受限实验；接受局部 PAN 退化，不保证任意应用生命周期 | 解码/模拟已有，后端未实现，装卸门槛真机失败 |
| CORE-1 | 匹配内核中的常驻后端 + 薄 KPM 管理 | 可建立异常入口、MM 生命周期及代码释放的完整协议；生产目标要求 EPAN/等价隔离 | 设计方案，需内核/KP 核心集成 |

**本机现有 KP 上“独立、任意装卸的 KPM + 任意用户代码 + 通用稳定”不是目前已证明可实现的交付组合。** LAB-1 的入口和卸载条件不成立时，必须停在能力检查，不通过关闭保护或忽略失败继续启用。

## 2. 已验证事实与未验证事项

设计初稿时只做只读核对；本次已运行预检KPM并卸载，最终列表为空、内核版本和boot_id未变。未修改页表或异常入口。

| 项目 | 证据 |
|---|---|
| 设备 | Pixel 6 / oriole，Android 16，4 KiB 页 |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` |
| KP | 先前探测为 `0xc00`；不能等同于当前源码 checkout |
| 硬件/权限 | 先前逐核测试 CPU 0–7：PAN 字段 2，EPAN 位 0；PROT_EXEC 下数据读全部可读 |
| BTF | 5,636,966 字节、130,615 类型；SHA-256 `ef6ffa2e5d2f10ad1438a89a77d42747e80c7b78367c1d191140c5e623ff4970` |
| decoder 复验 | `PASS checks=211127 vectors=50 random=100000 independent_assembler=verified`；ASAN/UBSAN 和 NDK freestanding 编译通过 |
| 新增证据 | 模拟核心288090检查通过；8核26类原生指令41600次差分通过；预检内核核心4114检查通过；slot与KCFI类型匹配 |
| 失败门槛 | 真实KP在exit返回EBUSY后仍移除模块；缺少候选Tasks-Rude同步符号；root首次触页复制基线异常 |
| 尚无证据 | fault_info 实际可写性、完整入口反汇编/回收协议、PTE事务、真实异常覆盖、活动更新/恢复/卸载的真机结果 |

50 条独立汇编器向量只核对编码；随机 opcode 测试主要验证不变量，不是随机寄存器状态下的原生指令差分。BTF 证明数据布局/声明，不证明函数体、锁协议、可写性和模块回收安全。

## 3. LAB-1 固定语义

1. 只允许注册发起调用者自己的 `current->mm`，不接受 PID/任意 mm 地址；同 mm 的线程共享覆盖。
2. 一次全系统仅一个实验实例、一页 4096 字节，页面起址必须对齐。只接受低位、无 tag 的用户地址；首版拒绝 TBI 指针、MTE、AArch32、大端和未审计的用户调试/单步状态。
3. 后备文件必须为验证过的 shmem memfd，大小恰好一页，offset 为 0；映射必须为独立的、恰好一页的 `MAP_SHARED`、RX、Normal Cacheable 基础页。拒绝匿名页、MAP_PRIVATE、可写页、THP/hugetlb、DAX、PFN/device/special、contiguous PTE、userfaultfd 等未支持形态。
4. 创建过程：RW 填充并逐字节校验 → 同步指令缓存 → 撤销可写映射 → 加 seals → 只读重开文件 → 建立 RX → 预触页。当前设备这条完整路径需已有授权root上下文；不放宽全局策略。要求 `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`；`F_SEAL_FUTURE_WRITE` 不能代替 `F_SEAL_WRITE`。内核重新检查，不能相信用户自报。root首次触页复制异常须先隔离，不能仅以标量填充规避后宣布平台可靠。
5. 覆盖区间 `[page+offset, page+offset+8)`，`0 <= offset <= 4088`。覆盖值按数值 uint64_t 解释：`8877665544332211` 对应内存字节 `11 22 33 44 55 66 77 88`。
6. 一条被支持的 load 的全部访问字节必须落在该页内；pair 最多 16 字节。跨页一律明确失败；跨页能力不能用一次 nofault 读取拼凑冒充。
7. 同页未覆盖字节来自同一不可变原页；取指仍执行原始字节。其他别名、内核辅助读取、ptrace/proc/process_vm_readv 不承诺返回覆盖值。
8. 活动期间合作程序不得改变目标 VMA、创建新的写入者、执行 JIT 修改读取点、fork/exec 或附加调试器。预先创建工作线程，先停读者再注销。违反合作契约不在 LAB-1 的无泄漏承诺内，不能声称所有违规都能在事后检测到。
9. 明确设置本页 `VM_DONTCOPY`，正常 fork 子进程不获得该映射；这不是透明 fork 继承。不得把可由用户撤销的标志当作强制安全隔离。

sealed、pin、mlock 均不能单独证明 VA/PTE 永远不变。seal 限制内容变更，pin 保留页引用，mm 引用保留地址空间生命周期；三者各有职责。

## 4. 必须先通过的实现门槛

### 4.1 运行时 ABI 清单

正式构建需要精确设备构建的源代码/反汇编、配置、工具链与 ABI manifest。仅 `uname` 相同仍不足。下列偏移已由本机 BTF 验证，**只适用于这份 BTF**：

| 类型（大小） | 字段与字节偏移 |
|---|---|
| mm_struct（960） | pgd=56，mm_users=68，mm_count=72，mmap_lock=96 |
| task_struct（4800） | mm=1440，pid=1584，tgid=1588 |
| vm_area_struct（200） | start=0，end=8，mm=16，page_prot=24，flags=32，ops=120，pgoff=128，file=136 |
| file（264） | inode=32，f_op=40，mode=68，mapping=232 |
| inode（704） | sb=40，mapping=48，size=80 |
| super_block（1536） | magic=96 |
| shmem_inode_info（840） | seals=4，vfs_inode=128 |
| pt_regs（336） | regs=0，sp=248，pc=256，pstate=264 |

`tools/inspect_btf.js` 可复验。函数原型、pte_t/pgprot_t 的真实类型、VA/PA宽度、页表级数、ASID/KPTI、页属性、BTI/PAC/KCFI、current 获取方式均要单独核实。BTF 类型名称相似或 C 结构大小相同不等于 KCFI 类型相同。

### 4.2 KP 基础设施：真正阻断项

当前仓库源代码存在以下事实；其中“exit错误不能阻止卸载”还已由无外部资源的预检模块在设备KP上直接验证：

- `kernel/patch/module/module.c`：init 失败后调用 exit 并释放；unload 也不因 exit 返回错误而保留模块。
- 同文件：控制回调处于 RCU 读侧；ctl0 在该区段内分配、替换共享 `ctl_args`，并发调用可互相释放参数。仅让模块回调不睡眠不能修复 loader 自己的问题。
- `kernel/linux/include/linux/rcupdate.h`：`synchronize_rcu()` 包装指向错误的同步函数；不能据其函数名证明宽限期。
- `kernel/base/hook.c`：动态 trampoline 删除缺少在途执行排空。

正式启用 LAB-1 前，需要在**实际运行的** KP 中证明：

1. 模块管理状态为 LIVE / STOPPING / RETAINED / DEAD；并发 load/ctl/unload 有真实互斥和调用引用。模块名称在回收完成前不得重用。
2. 控制参数是每次调用私有副本；分配/释放在可睡眠且不持 RCU 读锁的上下文。获取模块引用后退出查找锁，执行回调，最后释放引用。
3. STOPPING 阻止新的修改命令并排空已有管理调用；exit 在无 RCU 读锁、无全局自死锁的上下文调用。
4. init 回滚或 exit 未完成时，模块代码/数据/参数/资源保留为 RETAINED，允许查询和重试清理，不得调用 `kp_free_exec`。init 失败的残留实例也必须可发现。
5. 只有模块确认无入口、无回调、无资源后，loader 才做真实读者排空并释放。等待超时只能报告/保留，不能转成强制释放。

不修改 preset ABI 或 `MAP_SYMBOL_NUM`。这些是模块运行时生命周期改进，不应改变持久化 preset 布局。本轮只设计，不部署 KP 核心更新。

### 4.3 异常入口的两个实现

**根据新增实测，下一阶段选定 CORE-1 的常驻分发器**，见第11节及 `BACKEND_CONTRACT.md`。以下LAB-1动态入口保留为条件研究，不是当前部署路线。若重新研究替换 `fault_info[15].fn`，须满足所有条件：

- 精确确认结构大小/字段、槽 15 为 L3 permission、原函数为预期原生处理器、真实机器码确实间接读取该槽。源码中的 `static const` 不是动态注册 API，kallsyms 的 `d` 也不是可写证明。
- 先证明实验期间没有其他入口写入者，再在不改页属性的条件下用有异常修复的 nofault 同值写测试可写性；失败即拒绝。若存在竞争，同值写也可能把别人刚安装的指针覆盖成旧值，因此不能只依赖后续接管时的 CAS 补救；无法建立排他条件就不做此测试。该检查本身属于后续实验写操作，本轮未做。
- CFI 采用目标内核实际模式及精确函数原型，由编译器生成类型信息并比对本机原函数。不能伪造 hash、关闭 CFI 或依赖已有绕过来通过测试；同时核对 BTI/PAC/SCS。
- 原生回退须是可验证的真尾跳转：模块栈/SCS 已退出、返回地址直接属于原生调用者。C 源码写 `return original(...)` 不是反汇编证据。
- CAS 只在预期原指针仍在时接管/归还；不覆盖其他模块。完整状态先 release 发布，入口独立 acquire 读取；不能把原生普通指针加载误认为 acquire。
- 所有可能执行模块代码的分支（含错误路径和外部 helper）均须没有 voluntary quiescent state。退出等待真实 Tasks-RCU；由于入口还可能由 EL1/idle 路径访问，另需证明这些路径的排空机制，例如经核实的 Tasks-Rude。普通 RCU 仅保护真实参与其读侧协议的对象，不能代替以上证明。

任一条件不能成立，就放弃该动态入口，不自动退回 KP inline hook。Tasks-RCU 的适用边界见[内核 RCU 文档](https://docs.kernel.org/RCU/Design/Requirements/Requirements.html#tasks-rcu)。

## 5. 对象、所有权与线性化

LAB-1 不需要多页 XArray 或每次更新分配对象：

- `session`：mm 引用、page 引用、页起址、文件身份、原属性与修改位掩码、原生入口、只读 4096 字节快照、清理阶段位图。
- 永不并发修改的配置：页边界、8 字节覆盖偏移、原页快照、注册时身份。
- 唯一动态数据：自然 8 字节对齐的 `fake64`，原子 store-release / load-acquire；每条指令只取一次，pair 的两半共用这一份。
- 原子状态：PREPARING / ARMED / ACTIVE / DRAINING / RETAINED / DEAD。ARMED 已拥有完整可模拟上下文；直到恢复完成并排空旧异常之前都不能销毁上下文。
- 统计独立于正确性。功能测试可用 relaxed 原子计数；高并发性能版本再用经验证的 per-CPU 计数，不能因未经验证的 per-CPU ABI 换来错误。status 多字段为近似快照。

线性化点：启用在权限变更和跨 CPU TLB 同步完成后向测试程序开放读取；更新在 fake64 原子发布；注销在恢复权限/TLB、排空旧异常并返回后完成。注销重叠的读允许完成旧视图，注销完成后的新读必须为原值。

不声明“禁用过程中同时读到原值就是泄漏”：禁用边界按上述协议定义。ACTIVE 期间若 MM 重建出可读 PTE，根本不会进入 handler，异常内检查无法补救。

## 6. 注册事务与 MM 协议

注册只能在调用者进程、允许睡眠的控制上下文执行，不能放进当前 ctl0 的 RCU 读侧。

1. 验证第 4 节所有门槛、参数、配额和互斥所有权。构造全部缓冲区及恢复记录，尚不改变目标。
2. `get_task_mm(current)` 取得 mm_users 引用。只保存 mm，不持有无引用的任务指针。
3. 在映射仍 RX 时使用已核实的 `pin_user_pages_unlocked(start, 1, &page, 0)`，必须恰好返回 1，失败不发布。不能在持 mmap 写锁时调用这个会自行加锁的接口；不能传 FOLL_GET、FOLL_WRITE、FOLL_FORCE、手工 FOLL_PIN 或 FOLL_LONGTERM。
4. 取得 mmap 写锁，重新验证 current mm、VMA、seals、文件/offset、映射属性及 pin 对应页。两次检查之间可能发生变化，不能沿用前一次 VMA 指针。锁顺序为管理互斥 → mmap_lock → 短期 PTE 锁，不在 PTE 锁内睡眠。
5. 对原页取得稳定内核访问方式并复制快照；缓存只在 seal 和页身份已证明时可信。禁止任意转换用户 VA 为内核指针；不在启用 XOM 后以普通 uaccess 读取目标页。
6. 发布完整 ARMED 上下文，然后接入异常分发。此时任何新权限异常都已有处理记录。
7. 在 mmap 写锁下保存/修改 VMA 自己拥有的属性位：清 VM_READ、设置 VM_DONTCOPY，vm_page_prot 清除用户数据可访问位。保留其他合法属性，不改全局 protection_map，不递归调用自行加 mmap 锁的 mprotect 路径。
8. 使用核实后的非分配页表遍历；候选是 `apply_to_existing_page_range`。进入前排除 huge/block 等不支持层级，不能依赖可能 BUG 的 walker 去探测。回调在真实 PTE 锁下再次检查 present、页身份、只读、Normal、非 special/contiguous，必须恰好处理一个 leaf。
9. 通过精确内核的页表更新 helper 改权限，保持 PFN、缓存属性、AF/dirty、只读和 PXN；不擅自清已有执行保护。原页必须已允许 EL0 执行，仅撤销其 EL0 数据权限。
10. 使用目标内核正确的 TLB/ASID/KPTI 协议和屏障，完成远端可见性；不可用未经验证的几条内联 TLBI 替代。此路径只在注册/恢复，非读取热路径。
11. 复核属性与阶段位图，发布 ACTIVE，释放锁，再让用户工作线程通过 barrier 开始读取。

`pin_user_pages_unlocked` 在核对的 Android 6.1 实现中拒绝 FOLL_LONGTERM；不能直接照搬新内核 API。[GUP 实现](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/gup.c)

PTE pin 不阻止所有临时替换/重建。迁移恢复会从 `vma->vm_page_prot` 生成 PTE，所以仅改 PTE 不足。必须同步 VMA 模板，并审计目标分支的 fault/migration/reclaim/NUMA 路径；mmap 锁不替代 PTE 锁。[迁移实现](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/migrate.c)

临时 translation/access-flag fault 交原生路径；原生重建保持预期 XOM 后，再重试进入读取权限异常。是否确实如此必须对精确设备实现验证，不能仅从一份通用 6.1 源码推断。

每一步失败按已完成阶段逆向清理；出现恢复不确定性就 RETAINED，不返回“可安全释放”。不会写回一份过期的整 PTE，不会用保存的 PFN 覆盖 migration/swap/新映射。

## 7. 读取异常处理

### 7.1 路由与严格过滤

先 acquire 获取上下文状态，再按 mm 和地址匹配。正常无关异常走原生路径，不改变它们的寄存器、错误码或信号。

只允许：EL0、A64、小端、有效 FAR、预期 L3 stage-1 data-read permission fault。拒绝将 write、instruction abort、FnV、S1PTW、CM、external-abort、MTE、alignment、未定义 syndrome 等解释成普通读取。

对属于目标页但不支持的读取，保持全部 pt_regs 不变，记录原因并终止测试进程；LAB-1 采用 SIGKILL，避免应用信号处理器无限重试。信号 helper 的非睡眠性质也必须审核；CORE-1 让常驻分发器在离开模块读侧后负责发信号。store 不模拟成功，保留原生只读错误。

### 7.2 获取指令与解码

- `PC` 对齐、在合法 EL0 范围、`PC+4` 无溢出；必须验证读取点是可信且未并发修改的可执行映射。
- PC 在受保护 sealed 页：从不可变原页快照取 4 字节，不使用覆盖值取指。
- PC 在普通读取点：只用已审核的 nofault 取指及映射/内容稳定性条件，失败即终止；不能调用会 fault-in 的普通 uaccess。首批真机用例全部把读取 stub 放进 sealed 页，先消除外部取指变量。
- 不把 ESR.ISV 当通用指令描述；始终用 `uro_decode()` 白名单解码，有有效 syndrome 时再交叉核对。
- FAR 必须位于完整访问区间内，pair 可在第二个元素故障，不能要求 FAR 永远等于首地址。
- 首版拒绝带 tag 地址，不用随意清高位来绕过地址/权限检查；完整区间及基址写回都要检查。decoder 保留 tag 不代表后端支持 tag。

### 7.3 支持与拒绝矩阵

| 支持 | 约束 |
|---|---|
| LDRB/H/W/X，LDRSB/SH/SW，LDUR 系列 | 正确符号扩展、W写入清高位 |
| scaled/unscaled、pre/post、register offset、literal | SP/XZR 区分；UXTW/LSL/SXTW/SXTX；writeback 事务提交 |
| LDP/LDNP/LDPSW | 8/16字节页内；拒绝目的重叠/不可预测写回 |
| 同页部分覆盖、非对齐普通访问 | 全字节范围合法；不扩展到对齐异常模拟 |

拒绝 SIMD/FP、SVE/SME、exclusive、atomic、acquire、LDTR、认证 load、MTE、PRFM 及未知编码。PRFM 可能不产生异常，本机制不承诺观察或改变预取行为。16 字节支持表示 GPR pair，不是 NEON Q。

### 7.4 合并与零部分提交

1. 保存 decoder 输出，不直接修改真实 pt_regs。
2. 从不可变原页复制至最多 16 字节临时缓冲。
3. **一次** acquire 读取 fake64；按小端字节覆盖读取区间与 8 字节配置区间的交集。
4. 构造两个临时目的值，先符号扩展再按 W/X 宽度处理；rt=31 丢弃结果但不跳过访问验证。
5. 检查所有访问、两个目的值、writeback 和下一 PC 全部合法。
6. 提交 GPR、必要 SP/基址写回，最后 PC+=4。PSTATE 不变。

成功路径不分配、不睡眠、不打印、不做 TLB flush、不临时修改权限。只执行有界页内工作；不使用可能无限重试的 seqlock。归属不符走原生；归属明确但不能模拟则失败，不返回原字节来“保证兼容”。

## 8. 更新、注销、回滚与卸载

建议控制协议版本 `abi=1`，仅状态与固定值更新使用 ctl0；参数长度严格限制，输出缓冲预触且 nofault 拷出，输出不足返回错误。

```text
init:   <pagebase_hex> <offset_decimal> <16hex_fake>
ctl0:   status
ctl0:   set <16hex_fake>
```

status 至少包含 abi、profile、state、active、last_error、restore_pending、近似 hits/errors 和已通过的能力位；不输出物理地址、内核地址、原字节或密钥。set 只允许注册 mm 的合作调用者；状态/清理允许持已有 KP 管理授权的监督进程。命令不得与卸载并行，即使未来 loader 修复也保留明确串行测试协议。

拟定错误契约如下；返回错误和资源是否仍被持有必须分别表达：

| 情况 | 返回及状态 |
|---|---|
| 参数/区间/格式错误 | `-EINVAL`，尚未发布或已完整回滚 |
| ABI、入口、页型或架构条件不满足 | `-EOPNOTSUPP`，不得启用权限覆盖 |
| 另一实例/状态不允许修改 | `-EBUSY`，不修改已有实例 |
| 可重试的临时映射状态 | `-EAGAIN`，仅在已完整回滚时供调用者重试注册 |
| 用户输入/输出缓冲不可访问 | `-EFAULT`；status失败不改变实例；set不得因回复失败而重复假定未生效 |
| 清理/回滚不能证明完成 | `-EIO` + RETAINED + restore_pending，loader保留全部仍需资源 |

set 命令只发布数值，不依赖附带回复才能生效；重试设置同一数值是幂等的。已退出 DEAD 的实例不得用旧句柄或旧 mm 指针重新激活。

正常退出：

1. 用户停止 updater 和所有读者，join 完成；内核设置 DRAINING，禁止新配置修改，但保留旧 fault 处理能力。
2. mmap 写锁下重新定位 VMA，验证文件/offset/mm/页身份及自己拥有的修改位。
3. 按目标内核协议处理临时非 present/migration 状态，必要时释放锁后有界重试；不能在 PTE 锁内等待。若无法确认所有受影响映射均已恢复/不存在，转 RETAINED。
4. 只恢复本模块改变的 VMA/PTE 权限位，保留运行期间内核更新的其他位。若映射已变成新对象，不恢复到新对象上；无法排除原 XOM 被移动的情况不能盲目认定安全。
5. 完成 TLB 同步。权限仍可能 XOM 时绝不先删除 handler。
6. 归还异常入口；若 CAS 失败或存在未知链式引用，保留模块并报告，不能覆盖竞争者或释放代码。
7. 按入口协议等待真实读者排空：动态入口的 Tasks-RCU/额外上下文证明，或常驻桥接的原生 RCU 协议；并排空管理回调。所有等待均在无 mmap/PTE 锁、无 RCU 读锁的上下文。
8. 释放 page pin、mm 引用、快照/状态；置 DEAD；此时 loader 才可释放模块。

unpin 与 pin 类型必须匹配，不能拿 `__put_task_struct` 代替引用递减。mmput 在上述锁外执行，因为可能触发旧 mm 的最终拆除。

owner 异常退出/exec：额外 mm_users 引用使旧地址空间仍存在，外部监督程序按记录进行清理。它可能保留整个旧进程地址空间，不能宣传为仅占一页。实验设短时限和配额，超时告警/停止负载后清理；不在模块里加未经证明的自卸载定时器。

回滚和 exit 共用幂等清理逻辑，逐阶段记录资源所有权；重复调用不能二次 unpin/mmput。RETAINED 是故障隔离状态，不是成功，也不是后台已自动修复。

## 9. 测试二进制设计

完整覆盖测试文件仍计划为 `tests/urov_lab_test.c`（尚未实现）。已有 `emulate_test.c`、`native_test.c`、`kpm_check_test.c`、`copy_probe.c` 分别验证软件核心、原生差分、预检模块和平台基线，不能互相冒充。完整测试须在自己的mm中直接发起注册；不能用另一个kpatch进程替它注册地址。

- `--module PATH`、`--iterations N`、负向 case 选择；凭据从交互/继承描述符读取优先，若兼容 CLI 参数绝不回显/写日志，测试文件不保存密钥。
- memfd 原数据填充固定模式，原函数 `BTI c; MOV W0,#42; RET; NOP`，把覆盖区放到执行代码字节上；**执行必须始终返回42，同时读取得到不同预设值**，不是只验证无关数据。
- 预建线程和两个完整 fake64 值；更新时读者只接受完整 old/new，pair 的所有覆盖字节使用同一版本。先单CPU再逐核/迁核，再多核。
- 检查宽度、符号扩展、非覆盖、双向部分覆盖、写回、XZR、literal、pair、原页取指；逐条与原生 RX 执行和独立软件模型对比。
- 负向 case 独立进程运行，先输出 READY；监督者检查实际退出信号，然后清理留存 session。不能只依据 adb/CLI 的255推断内核 errno。
- 普通错误路径先清理后 munmap；清理失败不继续进行破坏性映射操作，报告需监督者处理。
- 每组记录 boot_id 前后、模块列表、内核新增告警、恢复后的原值/执行结果。不能把设备重启后状态正常算成卸载成功。

## 10. 性能与验收口径

稳态一条受保护 load 至少一次 EL0→EL1→EL0 异常；整个页的数据读取受影响，不只是 8 字节覆盖区。避免 PTE 切换只消除额外成本，不保证高频扫描低开销。

分别测 RX 基线、覆盖读、同页不覆盖读、纯执行、set、注册/注销；记录 ns/op、分位数、吞吐、CPU/频率/热状态、线程数和错误数。先小循环确保恢复，再扩大压力；不预设或编造性能数字。纯执行应无额外 UROV fault，但缓存/调度干扰仍可能影响耗时。

进阶优化顺序：稳定正确性 → 减少每次异常外部 helper → 可选 per-CPU 统计 → 经测量再考虑解码缓存。若缓存 opcode，键必须含不可变代码身份与 PC，不能仅按 PC 缓存可变进程代码。不得用跳过异常/放宽权限优化到泄漏原值。

发布条件：所有门槛通过、全部白名单原生差分通过、未知指令零提交、更新无混合版本、装卸/死亡/失败注入完全恢复、无 UAF/RCU stall/内核告警。压力通过只提升证据，不消除 LAB-1 的合作假设和 PAN 风险。详见 `TEST_PLAN.md` 的 S0–S7。

## 11. CORE-1：要获得通用可靠性必须补上的常驻后端

推荐把真正异常处理和 MM 状态放在匹配内核的常驻代码；KPM 只做经过版本校验的管理客户端。这不是已安装功能，也不能仅复制当前 KPM 实现而省略内核集成。

### 11.1 常驻分发解决代码生命周期

在原生 EL0 data-abort 路径、通用 VMA 权限检查前增加明确路由。优先整个 decoder/emulator 均常驻，不保存 KPM 函数地址。

若允许可卸载扩展 callback，则由**常驻**分发器在加载函数指针之前进入真实 RCU 读侧，执行非睡眠 callback 后退出。callback 返回 HANDLED / NOT_MINE / FATAL，常驻代码在退出读侧后再调用可睡眠的原生 fault 或发信号。注销撤销指针再等待对应宽限期；因此没有“进入模块前尚未记引用”的空隙，也不要求模块回退原生函数的尾调用技巧。

控制 UAPI 建议有 size、abi_version、flags、reserved-zero、opaque session_id；提供 inspect/register/update/deactivate/status。KPM 卸载失败时，残留状态由常驻后端继续拥有，不依赖即将释放的 KPM text。管理并发本身仍要使用已修复的 KP loader，或改用原生可睡眠 ioctl 接口。

### 11.2 原生 MM 生命周期

使用真实内核类型/helper，注册记录绑定 mm；mprotect/mremap/破坏性 madvise 要么在改变映射前拒绝，要么事务撤销；munmap/MAP_FIXED 在删除前撤销；远程强制写和可写别名与注册互斥；文件失效/迁移/NUMA/reclaim 用原生协议维持权限和页身份。

fork 初期明确不继承；若后续支持继承，须在子进程可运行前完成 mm 状态/配置克隆，失败使 fork 失败。exec/exit 由 mm 销毁路径回收，不永久额外持有 mm_users。引用、失效、映射锁和 fault 慢路径必须形成同一协议，不能靠多个独立 hook 补丁拼接。

### 11.3 多页、跨页与 SIMD 的后续扩展

多页/多区间使用每 mm 的不可变配置根，一次发布整个版本；单条 load 只持一份根快照，不能每页各取一个版本。跨页慢路径先拿对象引用，再退出 RCU 后做允许睡眠的页操作，最后一次性提交；回到提交点前重新确认会话/映射有效。

SIMD 需要原生 FPSIMD/SVE 状态保存与返回恢复 helper，不直接写不存在于 pt_regs 的向量寄存器。acquire/exclusive/atomic/认证指令另建架构语义和顺序证明，不能复用普通 LDR 接口假装支持。

生产安全档要求系统范围 EPAN 与真实 XOM 验证，或另行设计并完整验证等价的用户/内核页表隔离。现有无 EPAN 的 raw-XOM 即使不崩溃，也仍不满足该安全档。

## 12. 实施顺序与本轮停止点

1. 已完成：能力报告、BTF inspector、普通GPR解码/模拟核心、host复验、预检KPM、8核原生差分、loader拒绝卸载实测、详细常驻后端契约及测试计划。
2. 下一门槛：解决root首次触页复制基线异常，实施并验证loader安全保留/并发/同步及原生常驻后端；当前不启用权限覆盖。
3. 门槛通过后完成：常驻 `backend_abi`、`mapping`、`fault`、原生MM生命周期，薄KPM管理层、完整 `tests/urov_lab_test.c` 和反汇编检查。已有 `emulate.c` 仍须在真实入口下重新验证。
4. 严格按 S2–S7 递增测试，先一次启用/读取/执行/恢复，再扩大范围；每一阶段保留真实证据。

本轮新增的是 `urov-lab-check.kpm`，不声称已有活动 `urov-lab.kpm` 或完整Android覆盖测试通过。没有刷写、重启、安装硬件断点、改变PAN/CFI、安装fault hook或启用raw-XOM。部署修复后的KP/常驻后端涉及新的启动环境操作，必须另行确认，不能把编写/设计工作当作刷写授权。

## 13. 核对资料

以下 Android 6.1 分支源码用于核对机制；它们不是本机厂商构建机器码等价证明，正式实现须锁定实际提交：

- [异常分发与原生权限检查](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/mm/fault.c)
- [非分配 PTE walker](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/memory.c)
- [页 pin 接口与限制](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/gup.c)
- [迁移与 PTE 重建](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/migrate.c)
- [memfd seals](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/mm/memfd.c)
- [ARM64 TLB helper](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/arch/arm64/include/asm/tlbflush.h)
- [Tasks-RCU 适用边界](https://docs.kernel.org/RCU/Design/Requirements/Requirements.html#tasks-rcu)
- [Arm 官方 A64 ISA 文档](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
