# UROV 实验后端：审计记录与分阶段测试计划

> 历史计划与记录（2026-11-02）。2026-11-03 当前代码交付见 [DELIVERY.md](DELIVERY.md)，最新结果见 [CURRENT_RESULTS.md](CURRENT_RESULTS.md)。S3–S7 仍未完成。

日期：2026-11-02（Asia/Shanghai）。适用范围：当前设备绑定的、单个自有测试进程、单个 4 KiB sealed memfd RX 页、单个可原子更新的 8 字节覆盖区间。

更新：本文件第1–2节保留最初设计阶段的历史记录。后续已实现软件模拟核心、预检KPM和原生差分测试；最新真实结果见 `IMPLEMENTATION_RESULTS.md`。S2的loader保留门槛已实际失败，S3–S7真实异常覆盖仍未执行。根据实测选定的常驻后端契约见 `BACKEND_CONTRACT.md`。

## 1. 最初设计阶段的实施状态与结论边界（历史）

本轮只重新执行了 host A64 GPR 解码器测试和 freestanding 编译检查；没有加载新模块、修改设备页表、安装 fault 分发入口或执行 Android overlay 测试。

截至本文编写时，`urov-lab` 只有 `decode.c`、`decode.h`、`tests/decode_test.c` 和只读 BTF 检查工具等基础材料，**不存在可运行的 Android overlay KPM 后端，也不存在已经完成的端到端覆盖验收结果**。`urov-probe` 是另一套诊断程序，不提供读取覆盖功能。

下文 S2–S7 是后续实现完成后的测试计划，不是已经运行的记录。任何阶段的成功都不能替代下一阶段验收；host 解码测试尤其不能替代真实指令执行、异常入口、页表更新和卸载安全验证。

## 2. 最初设计阶段的实际审计与复验（历史）

### 2.1 命令、产物与结果

在 `E:\KernelPatch` 下通过 PowerShell 实际执行以下命令；WSL 发行版是 `Ubuntu-24.04`。构建目录已存在。

```powershell
wsl -d Ubuntu-24.04 bash -lc 'cd /mnt/e/KernelPatch && gcc -std=c11 -Wall -Wextra -Werror -O2 -fsanitize=address,undefined -fno-omit-frame-pointer kpms/urov-lab/decode.c kpms/urov-lab/tests/decode_test.c -o build/urov-lab-20261102/decode-test-audit && aarch64-linux-gnu-gcc -x assembler-with-cpp -DURO_ASM_CORPUS -c kpms/urov-lab/tests/decode_test.c -o build/urov-lab-20261102/decode-corpus-audit.o && aarch64-linux-gnu-objcopy -O binary -j .text build/urov-lab-20261102/decode-corpus-audit.o build/urov-lab-20261102/decode-corpus-audit.bin && build/urov-lab-20261102/decode-test-audit build/urov-lab-20261102/decode-corpus-audit.bin'
```

退出码 0，测试实际输出：

```text
PASS checks=211127 vectors=50 random=100000 independent_assembler=verified
```

WSL 还输出了与本机 `.wslconfig` 选项有关的启动警告；测试本身没有报告 ASAN/UBSAN 错误。

另实际执行：

```powershell
& 'D:\androidSDK\ndk\27.0.12077973\toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe' --target=aarch64-none-elf -std=c11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdinc -fno-builtin -fno-pic -fno-pie -fno-stack-protector -mgeneral-regs-only -mno-outline-atomics -ffixed-x18 -I kernel/include -c kpms/urov-lab/decode.c -o build/urov-lab-20261102/decode-audit.o
& 'D:\androidSDK\ndk\27.0.12077973\toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe' -s build/urov-lab-20261102/decode-audit.o
```

严格编译通过。符号表没有未解析函数/libcall；`uro_decode` 为 1112 字节，局部 `register_offset` 为 184 字节。这个检查**不含 KPM callback 的 KCFI 验证**，也不证明最终链接后的异常代码没有额外调用。

新增审计产物都位于 `build/urov-lab-20261102/`：

| 产物 | 字节数 | 用途 |
|---|---:|---|
| `decode-test-audit` | 85200 | Linux host sanitizer 测试程序 |
| `decode-corpus-audit.o` | 880 | GNU AArch64 汇编器生成的 50 条指令 |
| `decode-corpus-audit.bin` | 200 | 用于逐字比较的指令编码 |
| `decode-audit.o` | 2224 | NDK freestanding 目标文件 |

### 2.2 已审查的支持矩阵

| 类别 | 当前 decoder 处理 |
|---|---|
| 单 GPR 无符号 B/H/W/X load | 支持 |
| 有符号 B/H→W/X、W→X load | 支持 |
| scaled imm12、unscaled imm9、pre/post-index | 支持；拒绝有歧义的 writeback overlap |
| register offset | UXTW、LSL、SXTW、SXTX；rm=31 表示零 |
| PC-relative literal | W、X、LDRSW |
| pair | LDP、LDNP、LDPSW；拒绝重复目的、writeback overlap 和保留编码 |
| SP/XZR | rn=31 使用 SP 并检查原始 SP 对齐；目的31表示丢弃 |
| store、PRFM、LDTR | 拒绝 |
| SIMD/FP、acquire、exclusive、PAC/SVE/SME 等非白名单 | 拒绝，不作普通 GPR load 模拟 |

解码器使用临时描述符，仅在最终成功路径写 `*out`。地址计算避免 C 有符号溢出，检查最后一个访问字节和 writeback 是否溢出。64 位地址回绕一律拒绝，是保守支持范围，不是所有架构地址运算的完整模拟。

保留 top-byte tag 不代表已验证 TBI/MTE；`pstate` 也没有在 decoder 内解释。fault 调用者仍必须完成 EL0/A64/端序、有效 FAR、完整访问区间、TCR/VA/TBI/MTE、PC、页身份和权限检查。

### 2.3 测试不能证明的内容

- 50 条指令通过独立汇编器核对，只证明这些向量的指令编码；不是所有接受编码的架构语义证明。
- 100000 次随机测试使用随机 opcode、固定寄存器，主要检查描述符不变量和失败不修改输出；**不是真机架构语义差分测试**。
- 尚未测试实际内存读取、覆盖字节合并、符号扩展后的寄存器提交、PC/writeback、异常失败策略、并发更新和 MM 生命周期。
- 未检查最终 KPM 的 KCFI entry hash、fallback 真实尾调用、SCS、非睡眠性质及全部代码可达调用；这些必须在实现后重新审计。

## 3. 全阶段约束与停止条件

禁止使用硬件断点/观察点、读取点改写、逐次 PTE 开放读取、单步回填；禁止全局 PAN/CFI 弱化。不得自行刷写 boot/vendor_boot、切换内核或重启。设备管理命令串行执行，测试程序只操作自己创建的不可变页。

原始 XOM 实验页在无 EPAN 硬件上失去原有 PAN 读取隔离；这个风险不能通过成功测试消除。批准单页实验不等于批准对任意应用、其他映射或全局安全机制的修改。

出现下列任一情况停止升级测试阶段：

- ABI/CFI、入口可写性或原始回调身份未知；
- 恢复 PTE/VMA/TLB 或撤销入口失败，或 cleanup 无法证明已排空调用；
- 设备重启、内核 Oops/WARN、RCU stall、hung task、锁错误或无法解释的 SIGSEGV/SIGKILL；
- 模块管理者无法保证串行操作，或测试进程在活动期间违反映射合作约束；
- KPM 报告成功但状态/计数/原值恢复不符，或没有清晰可复现记录。

不得因清理失败强制释放模块代码/状态；不得把“无法卸载但设备暂时可用”记作通过。若恢复需要新的高影响操作，应报告设备现场状态并取得明确授权。

## 4. S0：纯 host / ABI 审计

当前 host decoder 复验通过；其余条目仍待实现和验收。

1. 保留本节命令、编译器版本、源文件和产物 SHA-256。
2. 扩展独立语义 oracle：随机寄存器、所有寻址模式、带符号边界、SP、XZR、立即数极限、地址末字节溢出及 writeback 溢出。
3. 对字节合并和寄存器提交建立纯函数测试：全覆盖/部分覆盖/零覆盖；一条 pair 只获取一次 fake64；符号扩展、W 高32位清零、XZR 丢弃、失败零提交。
4. 校验目标完整 kernel release/build、4 KiB 页、A64 小端、实际 BTF 类型/偏移/函数签名；不以版本字符串相似替代 ABI 匹配。
5. 对最终 KPM 反汇编，检查一般寄存器限制、所有未解析符号/重定位、意外 libc/outline atomic 调用、KCFI 元数据、SCS 和尾调用。
6. 建立可审计的状态机及回滚资源账本；每次成功获取资源、发布状态、修改权限都必须有对应撤销步骤。

通过标准：所有 host 测试成功且没有 sanitizer/编译警告；ABI 和静态审计不存在未解释项。未完成 ABI/入口审计不得设置 raw XOM PTE。

## 5. S1：原生 RX 与 PROT_EXEC 能力基线

历史记录见 `../urov-probe/DEVICE_RESULTS.md`，不是本轮复测：当前 Pixel 6 的 8 个 CPU 上，RX 读取/执行及 PROT_NONE 负对照通过；`mprotect(PROT_EXEC)` 数据读取仍成功，CPU PAN 字段为2、SCTLR EPAN为0。因此普通 PROT_EXEC 不能为本机提供该异常来源。

后续需要能力复测时，先记录 boot_id、内核构建、KP版本、页大小、CPU集合和初始模块列表，再用诊断程序逐核测试：

- RX：B/H/W/X/pair 读取正确，代码返回42；
- PROT_NONE：发生预期 ACCERR，核对 FAR 与故障 PC；
- PROT_EXEC：区分取指成功和数据读取是否被禁止；
- 恢复 RX：数据和执行重新通过；
- 结束后诊断模块卸载，模块列表与 boot_id 核对。

当前设备此阶段的预期分类为 `NO_XOM`；这不是 overlay 功能通过，也不阻止已单独接受风险的 raw-XOM 研究继续进入静态/门槛验证。未获 raw-XOM 实验授权时必须停止，不得自动降低安全条件。

## 6. S2：安全门槛、事务回滚与失败注入

**下列全部条件满足前，不得运行 S3 或将测试页变为 raw XOM。**

本表的入口可写性/真尾调用条件针对 `DESIGN.md` 的 LAB-1 动态 fault-table 候选。CORE-1 若使用源码内置的常驻分发器，不做表写测试、不依赖尾调用；应改验常驻入口在加载回调指针前建立真实读侧保护、退出读侧后才调用原生可睡眠路径，以及注销后的正确排空。两种入口不能互相借用未经证明的安全结论。

| 门槛 | 必须提供的证据 |
|---|---|
| loader 可保留未清理模块 | exit/rollback 失败时模块代码、状态、页引用不被释放；当前“exit返回错误仍释放”的行为不能用于验收 |
| 真实 grace period | 解析并核对真实同步实现，说明适用读侧协议和所有可达调用；不能采用本仓库不等价/可能为空的包装函数作为证明 |
| 入口可写性 | 对确切表/entry 的非破坏验证成功；禁止解锁全局 rodata；权限不满足则拒绝 |
| 入口身份及 CFI | 原回调、函数原型、真实编译器生成的 KCFI 元数据兼容；不伪造 hash、不依赖全局 CFI bypass |
| 尾调用与模块生命周期 | 无关 fault 必须真正尾转发且已退栈/退SCS；反汇编证明无返回到模块路径；排空覆盖“取得指针尚未进入”的窗口 |
| 页表/VMA恢复 | 只恢复本模块拥有的权限变更；在锁下检查当前身份，不能覆盖已替换PFN；TLB及屏障协议明确 |
| 映射稳定 | sealed memfd、大小与封印、RX共享专属VMA、pin与mm引用、VMA页权限同步及受限生命周期都已验证 |

故障注入必须先在无设备页表修改的 host/mock 或 inspect-only 模式验证；即使转入设备测试，也必须保持可恢复性：

- 参数解析失败、非法范围/跨页/溢出、不对齐页、零/过大长度；
- 非memfd、缺少每一种seal、大小改变、可写映射、错误VMA范围、特殊/huge页；
- 符号缺失、ABI/CFI不符、入口只读、原回调不符、CAS冲突；
- pin失败/部分完成、状态分配失败、PTE回调次数不符、PTE身份变化；
- 分别在权限发布前后模拟失败，检查恢复顺序和资源账本；
- 模拟恢复失败、入口撤销失败、无法排空：确认loader保留模块，状态清楚报告失败而不是成功卸载。

通过标准：接管前的拒绝返回明确错误且不改变原映射与入口；接管后的可恢复失败完整还原并释放已取得资源；无法恢复的失败转RETAINED、保留其安全所需资源和代码，并如实报告尚未恢复的状态，不能保证原状态已还原。仅“模块exit返回-EBUSY”不构成保留证明。

## 7. S3：最小单次覆盖、原始执行与恢复

预创建一个 dedicated memfd 4 KiB页，写入确定模式、offset64处 `BTI c; MOV W0,#42; RET; NOP`；完成指令缓存同步、撤销写映射后设置 WRITE/GROW/SHRINK/SEAL 全部封印，再建立单页共享RX映射。覆盖区应与该函数的真实代码字节重叠，证明同一批字节的数据读取与指令执行视图分离，而非只测试无关数据。线程在启用之前已创建且处于确定屏障；首轮只让一个线程进行访问。

拟议模块参数为 `<pagebase_hex> <overlay_offset_decimal> <16hex_fake>`。fake按数值uint64解释：`8877665544332211` 在小端机器上的覆盖字节为 `11 22 33 44 55 66 77 88`。真实 load 必须用显式 A64 汇编，避免编译器隐式生成 SIMD。

顺序：

1. 原生读记录真实值、函数返回42。
2. 由测试进程自己的调用上下文注册，成功后检查 active 状态。
3. 单个 `LDR X` 得到预设值；同页非覆盖单读得到原值。
4. 执行页内函数仍返回42，不增加数据读模拟计数。
5. 测试线程停止访问后撤销；核对入口、权限和生命周期恢复完成。
6. 同地址读取真实值且函数仍返回42；此后才允许munmap/close。
7. 检查模块列表、boot_id和内核日志新增错误。

通过标准：以上全部成立；单次覆盖不是仅由打印字符串或ctl成功码证明。第一轮不并行、不做压力、不自动重试未知异常。

## 8. S4：完整 GPR 差分与边界

使用可信、独立的期望值构造器；每个case先在普通RX映射上原生执行记录完整结果，再在相同字节/寄存器输入的覆盖页上执行，对比仅应改变的目的值。不得用同一decoder充当唯一oracle。

- B/H/W/X和有符号变体，符号位为0/1、W目的高32位原为非零。
- imm12、imm9正负边界、pre/post-index、四种register extend及shift、literal。
- LDP/LDPSW的offset、pre-index、post-index及LDNP的offset形式；独立验证两目的和适用的writeback，LDNP没有pre/post-index。
- XZR/WZR目的、SP寻址、未覆盖同页读取。
- 覆盖区内每个起点、跨覆盖区左右边界的部分重叠、pair仅第一/第二/两元素命中。
- 读取指令PC位于受保护页：使用缓存真实指令取指；专门覆盖页内literal读，证明执行指令字节不是fake字节。
- 不对齐页内读取仅在目标配置与架构允许且设计明确支持时验收；跨页访问明确负向拒绝。
- store、SIMD、acquire、exclusive、LDTR、未知编码和不受支持上下文均使用独立子场景；核对设计规定的确定性失败，不允许开放真实读取重试。

失败路径必须不提前更新目的寄存器、基址或PC。对不能从被杀进程直接观察的状态，使用纯提交函数单测和专门诊断构建检查，不把进程退出码当作零提交证明。

通过标准：白名单全部一致；负向行为与文档一致；无无限重复fault、真实值回落、半条pair提交或意外原生信号。

## 9. S5：多CPU读、更新与无撕裂

测试线程在注册前创建；所有线程共享同一mm。一个控制线程串行执行fake64更新，不能同时启动多个ctl调用者；主线程在停止并join更新者以后才能status/unload。

1. 先两CPU，再覆盖全部允许CPU；分别测试绑核和允许迁移。
2. fake在两种字节模式相差明显的64位数之间切换，每次fault只接受完整旧值或完整新值。
3. 部分覆盖和pair以一次fault取一个配置快照为判据，不能接受跨版本拼接。
4. 读取和执行同时进行；页内非覆盖值与函数42保持正确。
5. 逐步增加迭代次数，记录每CPU完成数、命中、拒绝和错误；采用测试程序外部超时，不依赖fault路径打印日志。

通过标准：零非法拼接、零真实值泄漏、零计数无法解释、零挂起；控制接口并发仍保持已声明的单写者约束。统计读取允许按文档为近似快照，不能以统计快照不一致误报fake撕裂。

## 10. S6：死亡、卸载与回滚

每类场景使用新测试进程和单独注册，先验收正常路径再加入异常路径：

- 正常停止全部读者、停止控制线程、卸载、原读/原执行恢复。
- 活动owner收到SIGKILL后，外部串行管理者清理；模块持有mm引用时仍能正确找到旧mm并恢复/释放资源。
- 不支持指令导致设计规定的致命失败后，外部清理路径同样成立。
- 重复注册/卸载小批次循环，逐步增加，检查引用、页pin、模块状态和错误日志。
- 入口竞争/身份不符、VMA/PTE身份不符、恢复故障等失败注入：不得错误覆盖别人状态，不得释放仍可达模块代码。
- 注册/回滚/卸载之间的受控并发只在loader协议已经解决且实现明确支持时测试；否则作为拒绝场景。

禁止把“不允许fork/exec/mprotect/munmap”仅写进说明后声称已支持这些生命周期。未实现安全处置前，这些属于不支持条件；故意违反合作契约的实验只能在已另行批准、具备故障恢复条件的环境开展，不作为当前设备默认压力项目。

通过标准：每次成功清理都证明权限/TLB、入口、调用排空及资源释放完成；每次清理失败都保留安全所需模块和资源，报告明确状态。没有“非零exit但模块仍被释放”的例外。

## 11. S7：性能与长期压力

只有S0–S6全部满足后才进入。异常处理必有成本；“没有逐次TLB切换”不能替代性能证据。

测量项目：原生RX load、覆盖load、同页非覆盖load、函数取指执行、更新、注册、撤销；分别测B/H/W/X/pair和各并发度。记录ns/op、吞吐、分布（可获得时p50/p95/p99）、异常次数、测试CPU及频率/温度/调频状态。

使用预热、重复批次和扣除/单独报告计时框架开销；先短批次，再约定时长的压力；期间保持CPU迁移与更新场景。不使用高频printk，不以单次均值或最小值代表稳定性能，也不预设必须达到的“低开销”结论。

正式生产可靠性还需要匹配调试内核上的KASAN/KFENCE/lockdep/RCU等检查和更完整MM生命周期覆盖。当前设备没有这些条件时，应明确缺项；不得自行刷机补齐。

## 12. 记录格式、保密与清场

每轮记录：时间、源/产物SHA-256、完整内核标识、KP版本、boot_id前后、CPU集合、阶段/case、输入（不含凭据）、预期、实际、退出码/信号、耗时、错误计数、清理状态及未解决限制。

测试密钥只作为运行时输入，不写入源代码、参数示例、日志、报告或产物；避免打印完整命令行。任何设备测试都应结束于已证明卸载并恢复或清楚声明的保留现场，不能在清理失败时误报“设备干净”。

最初设计阶段的清场结论为：未对设备执行变更、新增host审计产物列于第2节。后续预检KPM已真实加载并卸载；最新设备状态和产物校验以 `IMPLEMENTATION_RESULTS.md` 为准。
