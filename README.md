# UROV-LAB

`urov-y` 2.22.0 清掉 2.21.0 `--read-defense-v221-guarded` 仍能稳定复现的两条 AP 读侧
特征：`LDXR` 与故障 load 之间写第二个 GPR 的 `MOV X9,X0` 链，以及 load 之后的整数
SIMD `EOR V0.16B`。后向窗口从 `LDXR` 起在私有影子 GPR 文件上重放最多 12 条整数
指令，允许值经旁路寄存器传递；两次不同输入的 `LDXR` 终值必须不同且与故障现场逐位
一致。前向窗口在 2.21 的 64 条指令、`FMOV`、`MRS/MSR` 之外新增 Advanced SIMD 三同
整数族（`AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF`、`ADD/SUB`、`CMEQ/CMTST`、`CMGT/CMHI/
CMGE/CMHS`、`SMAX/SMIN/UMAX/UMIN`、`MUL/MLA/MLS`、`SSHL/USHL`），在 FPSIMD 镜像上
逐 lane 重放，`Q=0` 按架构清零高 64 位，提交时写回；AP 陷阱路径上的未特权 `LDTR` 形态按等价 `LDUR` 解码，不再变成可观测的合成 `SIGSEGV`。没有新增 hook、线程、定时器、
PTE/VMA/代码字，ABI 仍为 v8、`hooks=0xff`。普通 App 的 `--read-defense-v222` 在
AP-all 覆盖阶段给出 `pre_gpr=simd=ap=0`、`baseline_ok=32/32`、`simd_value=32/32`、
`evidence=0`、`accepted=32/32`；AP 调用窗口仍是 `split=32`（设计保留的
caller-window 语义）。CRC 的 `.text` 在 EL0/`process_vm_readv`/pipe/fork 上仍等于
文件摘要，执行仍是 Dobby 的 `1235`。v222 6 模式 ×32、CRC 7 模式 ×3、Dobby 8×1
（`ap=0/8`、`accepted_crc_old=8/8`、`accepted_crc_with_ap=8/8`）、消除 3×1、多页
3×1 均 PASS；`out/urov_window_test` 的 113 条独立期望值差分校验通过（新 SIMD 用例
的期望值由设备原生指令产生）。设计与残余见
[ELIMINATION_2_22_DESIGN.md](ELIMINATION_2_22_DESIGN.md)。构建
`urov-y.kpm ab90dab4...`、`urovdetect.apk 3181b98c...`。

`urov-y` 2.21.0 清掉 2.20.0 测试面仍稳定的两条 AP 读侧特征：`LDXR` 与故障 load
之间的整数链（`LDXR; EOR; LDRB; EOR; STXR`）和 load 之后的 `FMOV` 传送
（`LDXR; LDRB; FMOV d0,x0; FMOV x0,d0; STXR`）。后向窗口从 `LDXR` 重放最多 12 条
“只写目标寄存器、且结果实际依赖 `LDXR` 读值”的整数指令；前向窗口从 24 条扩到
64 条（256 字节），并补齐 `FMOV D/S/H`、`FMOV Vd.D[1]`、`MRS/MSR NZCV/FPCR/FPSR`
和只读 `TPIDR_EL0`/`TPIDRRO_EL0`/`CNTFRQ_EL0`/`CTR_EL0`/`DCZID_EL0`。FPSIMD 镜像
只在窗口出现 FP 指令时懒加载，提交时写回；H 形式只在 CPU 报告 FEAT_FP16 时接受。
没有新增 hook、线程、定时器、PTE/VMA/代码字，ABI 仍为 v8、`hooks=0xff`。普通 App
的 `--read-defense-v221` 在 AP-all 覆盖阶段给出 `pre_alu=fp=ap=0`、`evidence=0`、
`accepted=32/32`；AP 调用窗口仍是 `split=32`（设计保留的 caller-window 语义）。
CRC 的 `.text` 在 EL0/`process_vm_readv`/pipe/fork 上仍等于文件摘要，执行仍是
Dobby 的 `1235`。v221 6 模式 ×32、CRC 3×1、Dobby 8×1（`accepted_crc_with_ap=8/8`、
`ap=0/8`）、消除 3×1、多页 3×1 均 PASS；`out/urov_window_test` 的 73 条独立期望值
差分校验通过。设计与残余见 [ELIMINATION_2_21_DESIGN.md](ELIMINATION_2_21_DESIGN.md)。
构建 `urov-y.kpm 0bc084fd...`。

`urov-y` 2.20.0 把 2.19.0 的“LL/SC 前向白名单”换成**整窗建模**：故障 load 提交
之后，handler 在私有寄存器副本上逐条执行 `LDXR..STXR` 之间的全部窗口指令（最多
24 条、96 字节区域），读 gap 里的普通 load（与故障 load 同一 image/snapshot 视图），
把 gap 里的 store 记成待提交项并在提交时经内核 GUP/COW 写路径完成，最后在真正消费
预约的 `STXR` 处停下。覆盖 `NOP/BTI/HINT#0/DMB/DSB/ISB`、整数加减/逻辑/位域/搬移/
1·2·3 源数据加工、`CSEL` 族、`CCMP/CCMN`、`ADR/ADRP`、窗口内 `B/B.cond/CBZ/CBNZ/
TBZ/TBNZ`、GPR `LDR/LDP/STR/STP` 和 `LDXR/LDAXR`。`CLREX`、异常、成对/不同宽度的
独占、与监视地址重叠的 store 一律交给硬件——实测这些形状原生本来就失败
（`clrex_bad=0`、`svc_bad=0`），所以拒绝它们是复现架构而不是掩盖特征。没有新增
hook、线程、定时器、PTE/VMA/代码字，ABI 仍为 v8、`hooks=0xff`、请求布局、`ctl0`
字段与返回码不变。普通 App 的无密钥探针（`--read-defense-v220`）在 AP-all 覆盖阶段
从 2.19 的 `load=4 store=4 branch=4 csel=4` 变为全部 0，且窗口算出的值与原生一致
（`value=32/32`）；CRC 的 `.text` 在 EL0/crc32/pipe/process_vm_readv/fork 上仍等于
文件摘要，执行仍是 Dobby 的 `1235`。v220 6 模式 ×8、CRC 3×1、Dobby 8×1
（`accepted_crc_with_ap=8/8`、`ap=0/8`）、消除 3×1、多页 3×1 均 PASS；
`out/urov_window_test` 用 56 条独立期望值差分校验窗口模型。设计与残余见
[ELIMINATION_2_20_DESIGN.md](ELIMINATION_2_20_DESIGN.md)。构建
`urov-y.kpm 7b43e768...`。

`urov-y` 2.19.0 消掉 2.18.0 残余里唯一稳定的普通 App、无密钥读侧特征：
`PAGE_AP` 的读异常清掉本地独占监视器后，`LDXR; LDRB; ADD; STXR` 仍能观察到
`STXR` 失败。2.19.0 保留 2.18.0 的 `LDXR` 执行证据、直接/间接分支门控和
fail-closed 路径，只把 STXR 前向窗口从 NOP/BTI 扩到寄存器-only 整数数据加工
（`ADD/SUB` imm/reg、`AND/ORR/EOR/ANDS` 及反码形式、`MOVN/MOVZ/MOVK`）。handler
在私有寄存器副本上按序重放 gap，读取 STXR 当前的 `Rn/Rt/Rs`，只有 `Rn` 仍等于
监视地址且 store 成功后才写回寄存器/NZCV、置 `Ws=0` 并跳过 STXR；其余形状仍走
原生失败。没有新增 hook、线程、定时器、PTE/VMA/代码字，ABI 仍为 v8、
`hooks=0xff`、请求布局、`ctl0` 字段与返回码不变。普通 App 的 ALU 探针从
`trap=n/accept=0` 变为 `trap=0/accept=n`（AP-all；本轮 16×1）；CRC 的 `.text`
在 EL0/crc32/pipe/process_vm_readv/fork 上仍等于文件摘要，执行仍是 Dobby 的
`1235`。v219 6 模式 ×16、CRC 3×1、Dobby 8×1（`accepted_crc_with_ap=8/8`、
`ap=0/8`）均 PASS。设计与残余见
[ELIMINATION_2_19_DESIGN.md](ELIMINATION_2_19_DESIGN.md)。构建
`urov-y.kpm b173a91a...`、`urovdetect.apk b7c82bde...`。

`urov-y` 2.18.0 消掉 2.17.0 “残余”里两条普通 App、无密钥、稳定特征：
`process_vm_readv()` 不再按用户内存里的 iovec 目的地址回写，而是在
`pin_user_pages_remote()` 后置钩子里把注册页的 pin 页替换成持有 image/snapshot
的私有内核页（`GUP_PIN_COUNTING_BIAS` 在原活页与替换页之间搬移），由内核自己
把覆盖字节复制到它导入的目的地址，双 iovec 自引用技巧失效；
外部写（`read()`/`O_DIRECT`/`process_vm_writev` 写注册页）不再把页标 `dead`，
而是先快照活页、重装 AP[1]，下一次读路径用 GUP 读回活页并逐字节 diff，只把
变化的字节发布进 image/snapshot，未被写到的偏移继续返回镜像。ABI 仍为 v8，
`hooks=0xff`，请求布局、`ctl0` 字段和返回码不变。读回双 iovec 8×1、旧读防御
8×1、v217 App 1×6 + root 探针、消除 3×1（`ELIM_PROT_STORE shapes=16`）、
多页 3×1、CRC 5×1、Dobby 24×1（`accepted_crc_with_ap=24/24`、`views=0/24`）
均 PASS。设计与残余见 [ELIMINATION_2_18_DESIGN.md](ELIMINATION_2_18_DESIGN.md)。
构建 `urov-y.kpm 2827ea13...`、`urovdetect.apk 3bb50f80...`。
`urov-y` 2.17.0 消掉 2.16.0 “残余”里除读取计时外的全部条目：解码器之外的
store（SIMD 单 lane、STTR、SVE/SME 与将来形状）改由硬件在 EL0 执行，插件
恢复本 CPU 的 AP[1]、开 Software Step，在内核完成 COW 后用 `pre`/`post`
整页 diff 把变化字节发布进镜像并重装陷阱；并发 LSE 原子由可睡眠写锁串行化；
fork 快照改在 `copy_mm` 时创建，子进程自己的 `mremap`/`mprotect` 用
`vm_file`+页偏移解析；fast-GUP `FOLL_WRITE` 不再被替换页截获（同时修掉 2.16
就存在的 GUP 重试死循环）；被拒绝的 shared `remap_file_pages` 不再先拆会话。
ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 字段和返回码不变。
App 2×6（store/atomic/fork/gup/remap/crc）与 root 探针 5 模式全部 PASS，
生产 CRC 的 `.text` 页在 EL0/`crc32`/pipe/`process_vm_readv`/fork 子进程读上
一致等于文件摘要，执行仍是 Dobby 的 `1235`；加固读防御 8×1、旧读防御 8×1、
CRC 5×1、Dobby 24×1、消除 3×1（`ELIM_PROT_STORE shapes=16`）、多页 3×1 均
PASS；`site_call_ns=508`。设计与残余见
[ELIMINATION_2_17_DESIGN.md](ELIMINATION_2_17_DESIGN.md)。构建
`urov-y.kpm cb8b6be4...`、`urovdetect.apk a50e0343...`。

`urov-y` 2.16.0 消除 2.15.0 仍成立的三条无密钥读侧路径和两类写侧残余：
`vmsplice()` 的 `get_user_pages_fast()` 读改由 GUP after hook 返回镜像页；
`LDXP; LDRB; STXP` 成对独占由与单寄存器桥相同的控制流证据完成；等长
`mremap` 不再先拆会话，移动 `mremap` 会更新页基址/VMA，`munmap`/`MAP_FIXED`
只退役重叠页。写侧新增 LSE 原子 RMW（`LDADD` 族、`SWP`、`CAS/CASP`）、
`STXR/STXP` 写注册页的原生失败处理、跨页 store，以及 fork 子进程的私有
影子镜像；代码页重复扫描改读 snapshot，避开 PAN 下 `AP[1]=0` 的 uaccess
失败。ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 字段和返回码不变。
2.16.0 的矩阵：加固读防御 8×1、CRC 5×1、消除 3×1
（`ELIM_PROT_STORE shapes=16`）、多页 3×1、Dobby 24×1 均 PASS；
`site_call_ns≈340`。设计与残余见
[ELIMINATION_2_16_DESIGN.md](ELIMINATION_2_16_DESIGN.md)。构建
`urov-y.kpm 9d715b11...`、`urovdetect.apk 6d7b8ae8...`。

`urov-y` 2.15.0 消除 2.14.0 的两个稳定写侧特征：对已登记页的普通 store
不再把该页退役，而是解码出原指令、由内核 COW/GUP 写路径完成同样的字节，
再把镜像与快照同步并重新装回 `AP[1]=0` 陷阱；`LDXR XZR; LDRB; STXR XZR`
在非零 scratch 上也按控制流证据完成，`nonzero` 探针回到 `NO_MATCH`。
`ELIM_PROT` 的 11 种写形状（GPR/SIMD/STP/ST1/DC ZVA、pre/post-index）全部
吸收，`smaps` 仍是原生 COW 的 `Private_Dirty=4 KiB`。ABI 仍为 v8，
`hooks=0xff`、请求布局、`ctl0` 字段和返回码不变。

2.14.0 把 2.13.0 仍成立的两类保护切换恢复路径消掉：对已登记页做
`mprotect(PROT_READ/PROT_NONE/PROT_EXEC/PROT_READ|PROT_WRITE)` 不再结束
会话，私有文件页在 `mprotect(PROT_WRITE)` 后仍由 `AP[1]=0` 读陷阱服务，
第一次真实 store 才把该页交给 Linux COW 并退役这一页的覆盖；未分配 pkey
的 `pkey_mprotect`、private VMA 的 `remap_file_pages` 等 Linux 会拒绝的调用
不再先拆会话。ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 字段和返回码不变。

2.13.0 消除 2.12.0 仍成立的两个普通 App 无密钥特征：AP 独占探针的
`LDXR; LDRB; NOP; STXR` 不再因 `ERET` 清监视器而失败（有界前向 LL/SC 窗口），
非对齐 `mprotect` 等 Linux 本来会拒绝的映射调用不再先撤销会话（门控参数预校验）。
ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0` 字段和返回码不变。

2.12.0 把读覆盖扩到**内核辅助读**：新增 `__access_remote_vm` after
hook，`/proc/<pid>/mem`、`ptrace` 与 `access_process_vm()` 与 EL0 读者看到同一
镜像；`process_vm_readv` 改按**目标** `mm` 判定。`VM_LOCKED` 不再被拒绝
（`mlock` 不是门槛），无效 `madvise` 透传给 Linux，同权限 `mprotect(RX)` 与
`fork()`/`vfork()` 不再结束 `PAGE_AP` 会话：fork 子进程继承的陷阱 PTE 用 PTE
形状识别并按镜像返回，会话结束后孤儿陷阱修复为可读并重试；`execve` 只在执行者
属于 owner 线程组时拆会话。**同 `mm` 的 `process_vm_readv`** 仍按镜像/快照规则
重写调用者缓冲区，**`LDXR XZR; load; STXR XZR`** 在目标字为零时由 LL/SC 桥完成
no-op store。ABI v8 请求布局、`ctl0` 字段和计数器不变，`hooks` 因内核读 hook
变为 `0xff`。
2.8.0 将 `prctl` 的 magic 固定为 `UROVYLAB`，保留 ABI v8 请求布局和 MAC 校验。
2.4.0 的参数校验、并发镜像发布和陷阱撤销适配继续用于 Android ARM64 的 5.4 起的 5.x 和 6.x 内核，
支持 4 KiB 及符合条件的 16 KiB 页表。实测、支持边界和复跑命令见
[UROV-Y 兼容性与审计](COMPATIBILITY_Y.md)。下方日期条目保留各历史版本的行为和证据。

2026-11-08 第十六轮消除：`urov-y` 2.17.0 消掉 2.16.0 残余里除计时外的全部
条目。未解码 store（SIMD 单 lane、STTR、SVE/SME）由硬件在 EL0 执行，插件
只做整页 diff 发布；并发 LSE 原子由写锁串行化；fork 快照在 `copy_mm` 创建，
子进程 `mremap`/`mprotect` 按文件身份解析；fast-GUP `FOLL_WRITE` 写者不再被
截获，并修掉 GUP 重试死循环；shared `remap_file_pages` 不再先拆会话。
App 2×6 与 root 探针 5 模式全部 PASS；生产 CRC 的 `.text` 页在 EL0、`crc32`、
pipe、`process_vm_readv` 与 fork 子进程读上一致等于文件摘要 `96964c4f`，执行
仍是 `1235`。加固读防御 8×1、旧读防御 8×1、CRC 5×1、Dobby 24×1、消除 3×1
（`ELIM_PROT_STORE shapes=16`）、多页 3×1 均 PASS。构建
`urov-y.kpm cb8b6be4...`、`urovdetect.apk a50e0343...`。方案与残余见
[2.17.0 设计](ELIMINATION_2_17_DESIGN.md) 与
[结果 2.17.0](APP_READ_INTEGRITY_RESULTS.md#2170-任意写形状fork-快照与并发原子)。

2026-11-08 第十五轮消除：`urov-y` 2.15.0 让普通 store 不再退役覆盖：解码
11 种 GPR/SIMD/STP/ST1/DC ZVA 写形状，由内核 COW/GUP 写路径完成同一批字节，
同步镜像/快照后保持 `AP[1]=0`；`LDXR XZR` 的非零目标按直接分支位图 + GPR
门控完成，`nonzero` 探针归零。Dobby 48×3 活动阶段 `ap=0/144`、
`accepted_crc_with_ap=144/144`；CRC 5×2（16 次）、消除 3×1（11 次，
`ELIM_PROT ... store_absorbed=1`、`shapes=11`）、多页 5×1 均 PASS。构建
`urov-y.kpm 5fa88121...`、`urovdetect.apk 5104264b...`。方案与残余见
[2.15.0 设计](ELIMINATION_2_15_DESIGN.md)、
[结果 2.15.0](APP_READ_INTEGRITY_RESULTS.md#2150-写入吸收与-xzr-桥接) 与
[审计 2.15.0](APP_READ_INTEGRITY_AUDIT.md#2150-写入吸收与-xzr-桥接)。

2026-11-08 第十四轮消除：`urov-y` 2.14.0 让保护切换不再结束会话：`mprotect(R)`、
`PROT_NONE`、`PROT_EXEC`、`mprotect(RW)` 后普通读取仍等于镜像；private COW 页
上的第一次真实 store 由原 Linux fault 路径完成 COW，只退役这一页。`pkey_mprotect`
未分配 pkey、private `remap_file_pages`、`MAP_FIXED|MAP_FIXED_NOREPLACE` 等
Linux 会拒绝的调用不再先拆会话。Dobby 48×3 活动阶段 `ap=0/144`、
`accepted_crc_with_ap=144/144`；CRC 5×2（16 次，`CRC_PROT state=1`）、消除
3×1（11 次，`ELIM_PROT ... store_retired=1`）、多页 5×1 均 PASS。构建
`urov-y.kpm 51140d21...`、`urovdetect.apk 889cb318...`。方案与残余见
[2.14.0 设计](ELIMINATION_2_14_DESIGN.md)、
[结果 2.14.0](APP_READ_INTEGRITY_RESULTS.md#2140-保护切换存活与写入移交) 与
[审计 2.14.0](APP_READ_INTEGRITY_AUDIT.md#2140-保护切换存活与写入移交)。

2026-11-08 第十三轮消除：`urov-y` 2.13.0 让 AP 探针在活动阶段回到
`NO_MATCH`，并让普通 App 不能用非对齐 `mprotect` 撤销会话。Dobby 48×3 活动
阶段 `ap=0/144`、`accepted_crc_with_ap=144/144`、`views=0/144`；CRC 5×2（16
次）、消除 3×1（11 次）、多页 5×1（含 `mp-prod` 24 页/96 KiB 五路径）均 PASS。
构建 `urov-y.kpm 3395b61b...`、`urovdetect.apk 6c1726f4...`。方案与残余见
[2.13.0 设计](ELIMINATION_2_13_DESIGN.md)、
[结果 2.13.0](APP_READ_INTEGRITY_RESULTS.md#2130-普通-app-的-ap-探针与无效映射门控消除) 与
[审计 2.13.0](APP_READ_INTEGRITY_AUDIT.md#2130-ap-探针与无效映射门控消除)。

2026-11-08 第十二轮消除：`urov-y` 2.12.0 补齐内核辅助读，并让锁页、无效
`madvise`、同权限 `mprotect(RX)`、`fork`/`vfork` 与 `vfork`+`exec` 不再带走
或暴露会话。Dobby 24×3 活动阶段 `accepted_crc=24/24`（合计 72）、`views=0/72`、
`iov1024/sibling/split` 全等，`/proc/self/mem` 18/18 与 EL0 视图一致，fork 子
进程的 `/proc/self/mem` 3/3 一致；CRC 5×2（16 次）、消除 6×2（14 次）、多页
5×1（含新增 24 页五路径 `mp-prod`）均 PASS。构建 `urov-y.kpm 13ca0c0c...`、
`urovdetect.apk 4494e72c...`。方案与残余见
[2.12.0 设计](ELIMINATION_2_12_DESIGN.md)、
[结果 2.12.0](APP_READ_INTEGRITY_RESULTS.md) 与
[审计 2.12.0](APP_READ_INTEGRITY_AUDIT.md)。

2026-11-07 第十一轮消除：`urov-y` 2.11.0 把同 `mm` 的
`process_vm_readv` 覆盖从 64 项扩到 Linux 允许的全部 1024 项 iovec，用逐项
游标避免 32 KiB 栈数组；pid 不是自身 tid/tgid 时在 RCU 下用
`find_task_by_vpid` 比较 `task->mm`，覆盖同线程组兄弟 tid 和 `CLONE_VM`
兄弟进程。ABI v8、`ctl0`、`hooks=0x7f` 和计数器不变。Dobby 48×10 活动阶段
`views=0/480`、`accepted_crc=48/48`（合计 480）、`iov1024_match=1`、
`sibling_match=1`、`split_match=1`；CRC 5×1、消除 3×1、多页 3×1 均 PASS。
构建 `urov-y.kpm 8d0eb588...`、`urovdetect.apk a4db1178...`。残余见
[结果 2.11.0](APP_READ_INTEGRITY_RESULTS.md) 与
[设计 §19](ELIMINATION_DESIGN.md#19-第十一轮完整-iovec-窗口与同-mm-pid-解析)。

2026-11-07 第十轮消除：`urov-y` 2.10.0 让 Dobby 活动矩阵的
`process_vm_readv` 双读与 XZR 独占序列同时归零，`accepted_crc=8/8`。构建
`urov-y.kpm 8e3ad63b...`、`urovdetect.apk 4f259a66...`；Dobby 8×1、CRC 5×1、
消除 3×1、多页 3×1 均 PASS，`REGISTER` 约 70 ms、AP 读取 281 ns。残余
（XOM/自修改代码、`/proc/self/mem`/ptrace、每次读取一次异常等）见
[结果 2.10.0](APP_READ_INTEGRITY_RESULTS.md) 与 [设计 §18](ELIMINATION_DESIGN.md#18-第十轮同进程内核辅助读与-xzr-独占序列)。

2026-11-07 镜像来源变更：`urov-y` 2.8.0 **移除 `SRC_FILE`**，所有页镜像统一走
`SRC_USER`，每个描述符一次最多一页（4 KiB/16 KiB）。`SRC_FILE` 常量保留为
保留位，`REGISTER` 返回 `EINVAL`；`QUERY` 不再报告 `CAP_SRC_FILE`，也不再需要
`kernel_read`/`vm_pgoff` 的文件布局。Dobby 夹具改为把干净整页读入用户缓冲区，
用 `SRC_USER(off=0, len=page_size)` 注册；多页夹具的 `mp-srcfile` 改为
`mp-srcpage`，并用改过的整页镜像验证窗口内读到 `image`、窗口外和注销后读到
真实页。真机 Dobby 24×1 `accepted_crc=24/24`、NOP/间接探针 0/24；多页 5 项、
CRC 9 次、消除矩阵 11 次运行均 PASS。构建：
`urov-y.kpm 82f50d46...`、`urovdetect.apk 5ebc9801...`。

2026-11-07 第八轮消除：`urov-y` 2.7.0 把 `PAGE_AP` 的 LL/SC 门控从“目标等于
故障 load 的直接分支”扩展到**整页直接分支**，覆盖落在 NOP 间隔上的分支和
±256 字节外的同页分支；同时解码 `B.cond`（此前漏掉的直接条件分支），并在
故障时检查 `x0..x30` 是否仍持有 `[LDXR+4, load]` 区间地址，拦住
`ADR/ADRP + BR`、literal + `BR`、`RET` 等间接形状。门控仍只读，不新增
hook、PTE/VMA/代码字节改动或 `ctl0` 字段。检测 App 的 Dobby 24×1 活动阶段
`nop=0/24`、`ind=0/24`、`bridge=0/24`、`spaced=0/24`、`accepted_crc=24/24`
（2.6.0 的 NOP 探针为 480/480 命中）；消除矩阵 11 次运行、443 条断言，
`ELIM_BRIDGE` 三项均 `verdict=0 successes=0`；CRC 5×1 与多页 5 项全 PASS。残余（间接
目标寄存器被覆盖、跨页分支、保守误伤、时间）见
[设计 §16](ELIMINATION_DESIGN.md#16-第八轮nop-间隔分支与间接分支门控)。

2026-11-07 第七轮消除：`urov-y` 2.6.0 给 `PAGE_AP` 的 LL/SC 桥加**直接分支门控**，
并把 `LDXR` 与 load 之间 0–3 个 `NOP` 纳入桥。提交桥前扫描故障 load 所在页前后各
256 字节，解码 `B/BL/CBZ/CBNZ/TBZ/TBNZ`；目标落在 load 上说明该路径可以绕过
`LDXR`，handler 不代写，PC 停在 `STXR` 上让原生指令报告失败。这样
`CLREX/B;LDXR` + 预置 `Rt==[Xn]` 的无预约探针不再得到伪造成功。另实测否决了
“在 EL1 重放 `STXR` 探测本地监视器”：数据异常进入 handler 前监视器已不可用。
检测 App 的 Dobby 矩阵 5 轮 × 24 次：活动阶段 `bridge=0/24`、`spaced=0/24`、
`unknown=0`、`accepted_crc=24/24`（2.5.0 为 `bridge=24/24`、
`accepted_crc=0/24`）；`w-active` 的 11 项 `ELIM_BRIDGE` 全部 `verdict=0`。
残余（间接分支、窗口外分支、保守误伤）见
[设计 §15](ELIMINATION_DESIGN.md#15-第七轮直接分支门控与-nop-间隔桥)。

2026-11-07 第六轮消除：`urov-y` 2.5.0 在 `PAGE_AP` 的 EL0 数据异常返回路径中恢复
**相邻 LL/SC 桥**。仅当故障 PC 前一条是 `LDXR/LDAXR`、后一条是 `STXR/STLXR`，
三条指令的基址/数据寄存器与宽度一致，`LDXR` 目的寄存器仍等于 `[Xn]`（执行存证），
且 `STXR` 待写值等于当前内存时，handler 才在模拟 load 成功后完成这次 store、把
`Ws` 置 0 并跳过 `STXR`。这样真实独占序列不会因为 `ERET` 清本地监视器而失败；
分支跳过 `LDXR` 的 `CLREX/B;LDXR` 探针仍按原生失败且零写入。检测 App 的 Dobby
矩阵 5 轮 × 24 次：活动阶段 `match=0/120`、`accepted_crc=120/120`（2.4.1 为
`match=120/120`、`accepted_crc=0/120`）；`w-active` 的 AP 独占探针
`exclusive_match=0`、跳过 `LDXR` 的 store 探针 0 写入；活动期 `ctl0 status`
`llsc=42,952`。桥只覆盖紧邻三条指令、`Xt!=XZR`、非成对独占；残余见
[设计 §14](ELIMINATION_DESIGN.md#14-第六轮相邻-llsc-桥的执行存证恢复)。

2026-11-06 ABI v8 多页/宽 load：`urov-y` 的 `PAGE_AP` 模式从"一页一会话"
扩到**一次会话任意页数组**（`struct uy_page_desc[page_count]`，默认配额 4096 页 /
8 MiB 镜像，`kvmalloc` 动态分配），并新增 **LD1/LD2/LD3/LD4**（含 post-index
立即数/寄存器两种形式）与**跨页 load**：一条 64 字节的 `ld1 {v0-v3.16b}` 或 32
字节的 `ldp q` 可以在两个已注册页之间拼接，未注册段走 nofault uaccess 读真实
内存。每页有独立整页镜像、窗口、seqlock 与 `SET_PAGE` 更新；`SRC_FILE` 从
`vm_file` 读原始页（2.8.0 已移除），`SRC_USER` 拷贝调用者镜像。真机
[multipage-20261106-224709](results/multipage-20261106-224709/summary.json)：
24 页同时 ARMED 的 96 KiB `memcpy` 整段等于伪页、`SET_PAGE` 换第 7 页后重读一致、
注销后 24 页全部恢复；LD1 1/2/3/4 寄存器、LD1 8B、post-index 立即数/寄存器、
LD2/LD3/LD4 去交织全部等于架构解释；跨页 `ldp q`/`ld1` 与"两页镜像拼接"逐字节
一致，起始于未注册页的跨界读前半段为真实内存；当时的 `SRC_FILE` 路径也已上机
（2.8.0 已移除）。同轮
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
校验请求 MAC 后在调用者的 `mm` 中注册文件后备的 RX 页和可选读取点。模块快照目标页，
异常处理按陷阱位置和调用窗口选择覆盖字节或原字节，模拟 A64 load 后更新目标寄存器和 PC。
`length` 可达运行内核的基础页大小，超过 32 字节时用 `fake_addr` 指向调用者缓冲区。
`SET` / `SET_PAGE` 校验代际号，构建新镜像后原子发布。注销或卸载时恢复读取点或页权限，
再关闭读侧并等待在途回调释放会话引用。[控制与模拟实现](urov_y_backend.c)

2.5.0 的控制调用为 `syscall(__NR_prctl, option, UROV_Y_PRCTL_MAGIC, op, &req, sizeof(req))`。
`UROV_Y_PRCTL_MAGIC` 的值为 `0x42414c59564f5255`，是 `UROVYLAB` 的 8 字节小端编码。
`option` 和请求 MAC 密钥仍由加载参数 `key=` 派生。客户端需与 KPM 一起更新。
[控制 ABI](urov_y_abi.h)

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

业务调用窗口先检查当前 `x30`，再按 `x29` 帧链最多回溯 16 层。比较时会移除
返回地址的 PAC。嵌套调用缺少可走的帧链时只按能取得的返回地址匹配，未匹配则重放原值。
`crc-ap-libc` 验证短长度的 bionic 读取和 zlib CRC；`crc-ap-big` 覆盖最多 4 KiB 的
`memcpy`、`memcmp`、`strlen` 和 CRC。`PAGE_AP` 还支持 LD1/2/3/4 和跨页读，
通过内核 FPSIMD helper 保存与提交向量状态。没有匹配的 helper 或布局时，向量读不模拟；
`ctl0 status` 的 `fpsimd=` 字段报告可用性。`PAGE_AP` 不模拟任意写入；只有紧邻且
`LDXR` 执行存证成立的 `STXR/STLXR` 由 handler 完成原 store，其余独占形状仍可能
因异常返回失去 reservation。

2.4.0 在加载时适配 Android ARM64 的 5.4 及之后的 5.x/6.x 内核接口。
默认从运行内核读取 BTF；没有内置 BTF 时可用 `btf=/path` 提供同一内核构建的
外置 BTF 包，模块会核对 GNU Build ID。异常、远程内存和映射锁接口根据实际符号与
BTF 选择。`QUERY` 报告基础页大小、页数配额和可用模式。2.4.0 已在小米 13 的 5.15.74
内核通过 App 验收，并通过 AOSP 6.12.18 / 6.18.16 实际镜像的 BTF 静态检查。
旧版 KernelPatch 使用 App 先注销、宿主再卸载的流程。[UROV-Y 兼容性与审计](COMPATIBILITY_Y.md)。

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
| `urov_window_test` | LL/SC 窗口模型差分测试（56 条指令，无 root/KPM） |

普通 app 测试程序在 `apps/urov-app/out/urovapp.apk`，由
`apps/urov-app/build-app.ps1` 构建（`-Hold` 生成生命周期变体
`urovapp-hold.apk`）。

## Dobby 按钮验收

在 KernelPatch 仓库根目录运行 `.\kpms\urov-lab\apps\urov-detect\build.ps1 -Install`。
脚本使用 Android SDK 的 CMake 和 Ninja，从 `Dobby/` 静态构建并链接到 `liburovdetect.so`。
仓库内的 Dobby 基于上游提交 `5dfc8546954ce3b3198132ab13fddb89ee92cdd7`，包含 Android 构建兼容修复。
APK 在 `apps/urov-detect/out/urovdetect.apk`。[App 构建脚本](apps/urov-detect/build.ps1)

`KP_KEY` 用于设备上的 kpatch，`MODULE_KEY` 是为本次 KPM 加载选取的 128 位密钥，以 32 个十六进制字符表示。
从 shell 启动 App 时，把相同的 `MODULE_KEY` 传给启动参数 `key`。

```sh
adb push kpms/urov-lab/out/urov-y.kpm /data/local/tmp/urov-y.kpm
adb shell "/data/local/tmp/kpatch $KP_KEY kpm load /data/local/tmp/urov-y.kpm 'key=$MODULE_KEY'"
adb shell am force-stop com.example.urovdetect
adb shell "am start -n com.example.urovdetect/.MainActivity --es key $MODULE_KEY"
```

点击 **Check code CRC32**。首次点击从 ELF 文件取得参考 CRC32，并用 `DobbyHook` 改写 App 自有的
`.text` 测试函数。替换函数经 Dobby trampoline 调用原函数，再将返回值从 `0x1234` 改为 `0x1235`。
每次点击用 `PAGE_AP` 和整页 `SRC_USER` 注册目标页：夹具先把后备文件的干净页读入用户缓冲区，
模块在 `REGISTER` 时复制这一页，逐字节读取该函数的 32 字节机器码并计算一次内存
CRC32。覆盖命中且模拟失败数为零、CRC 与文件相符、函数返回 `0x1235`、会话注销成功时显示 PASS。
[Dobby 测试实现](apps/urov-detect/dobby_crc_fixture.inc)

卸载对照可以在同一进程内做。先等按钮结果出现，再运行 `adb shell "/data/local/tmp/kpatch $KP_KEY kpm unload urov-y"`，
然后再次点击。此次 CRC 应读到 Dobby 改写的字节并与文件参考值不同，函数仍返回 `0x1235`。

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

1. 模块同一时间只有一个会话，绑定 App 的 `mm`。`urov-x` / `urov-lab` 为单页；
   `urov-y` 的 `PAGE_AP` 支持页数组。每页需要原始快照和两份镜像，默认 8 MiB 可容纳
   682 个 4 KiB 页或 170 个 16 KiB 页，实际配额以 `QUERY` 为准。
2. `urov-y` 在 fork/vfork 建立新地址空间前结束覆盖；只共享 `mm` 的线程保留会话。
   `urov-lab` / `urov-x` 的映射继承细节参见各自历史记录。
3. 仅模拟白名单中的 AArch64 小端 EL0 load。`PAGE_AP` 的单条结构化向量 load 最多读
   64 字节；SVE/SME、acquire/exclusive、MTE 标签地址、大页和 64 KiB 页不在支持范围内。
4. 目标需为 App 自身文件后备 RX 映射。单页 `MAP_SHARED` 别名不得带 `VM_MAYWRITE`；
   `urov-y` 支持符合条件的私有 `.text`。原字节来自注册快照，外部修改映射或后备文件会破坏前提。
5. KPM 需要 root 装卸；正常测试应先注销会话再卸载。页表修改、宿主 hook 释放和失败恢复有
   内核版本及 KernelPatch 约束，详见 [审计和使用边界](COMPATIBILITY_Y.md)。

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
| `APP_READ_INTEGRITY_AUDIT.md` / `APP_READ_INTEGRITY_RESULTS.md` | 读取完整性检测面、特征清单与 2.7.0 整页/间接分支门控复测（Dobby、消除矩阵、CRC、多页） |
| `urov_x_backend.c` / `.h` / `urov_x.c` / `urov_x_abi.h` | covert 变体 `urov-x`：密钥化控制通道、读取点绑定、透明生命周期 |
| `urov_y_backend.c` / `.h` / `urov_y.c` / `urov_y_abi.h` | `urov-y`：BRK 读取点、UXN 页陷阱、AP[1] 数据读陷阱；调用窗口、ABI v8 多页和向量读 |
| `urov_y_window.h` | LL/SC 窗口模型（纯函数）：整数数据加工、`CSEL` 族、`CCMP/CCMN`、窗口内分支；由 backend 与窗口测试共用 |
| `tests/urov_window_test.c` | 窗口模型的差分测试：56 条指令的编码与原生期望值 |
| `urov_y_compat.h` / `urov_y_readers.h` | 内核 ABI、页表几何、BTF 校验和会话读侧引用 |
| `PAGE_AP_KEYLESS_RESULTS.md` / `PAGE_AP_KEYLESS_RESULTS_R2.md` | 历史普通 App 复核：AP 数据陷阱和旧 LL/SC 桥（2.4.0 已移除） |
| `tests/urov_y_test.c` | `urov-y` root 验收程序（三种模式；功能/fork/门控/活动期卸载/代码页探针） |
| `tests/urov_window_test.c` | 窗口模型差分测试（真机或任意 arm64 环境运行，无 root、无 KPM） |
| `apps/urov-detect/uy_fixture.inc` | `urov-y` App 夹具（`y-*` BRK、`z-*` UXN 页陷阱、`w-*` AP 数据陷阱） |
| `apps/urov-detect/mp_fixture.inc` | ABI v8 App 夹具：24 页、SIMD、跨页、文件源及 `mp-audit` 并发/生命周期回归 |
| `apps/urov-detect/crc_fixture.inc` | CRC 夹具：`crc-ap-text`/`crc-ap-libc`（标量 libc）与 `crc-ap-big`（整页覆盖 + SIMD 大长度传输、内部窗口、`SET`） |
| `tools/run_elimination_device.py` | `urov-y` 设备矩阵（含 `urov-x` 阳性对照与三种模式对照） |
| `tools/run_crc_device.py` | 同进程改码/CRC 矩阵（`crc-brk`/`crc-uxn`/`crc-ap`/`crc-ap-text`/`crc-ap-libc`/`crc-ap-big`） |
| `ELIMINATION_DESIGN.md` / `ELIMINATION_RESULTS.md` | 读取点陷阱方案（§9 UXN、§10 AP+LL/SC 桥、§11 桥的执行存证、§13 SIMD&FP 大长度传输、§14 2.5.0 相邻 LL/SC 桥恢复）、代码页/取指特征消除与真机对照结果 |
| `MULTIPAGE_DESIGN.md` | 历史设计稿：多页覆盖、LD1/LD2、跨页 load、16 KiB 页 |
| `MULTIPAGE_RESULTS.md` | ABI v8 多页/LD1/LD2/LD3/LD4/跨页/SRC_FILE 的实现说明与真机证据 |
| `tools/run_multipage_device.py` | ABI v8 设备矩阵（`mp-multi`/`mp-ld1`/`mp-cross`/`mp-srcfile`/`mp-audit`） |
| `tools/run_stealth_device.py` | `urov-x` 设备矩阵（无密钥/活动/观察者/卸载/SIMD/fork） |
| `STEALTH_DESIGN.md` / `STEALTH_RESULTS.md` | 检测特征点消除设计与真机对照结果 |
| `results/` | 构建、设备与覆盖运行记录 |

(End of file - total 336 lines)
