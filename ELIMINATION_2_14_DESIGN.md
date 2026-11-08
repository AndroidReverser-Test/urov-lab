# UROV-Y 2.14.0：保护切换存活与写入移交方案

本文是 `urov-y` 2.14.0 的设计说明。目标：把
[ELIMINATION_2_13_DESIGN.md](ELIMINATION_2_13_DESIGN.md) §5 仍列出的
**保护切换恢复路径**消掉，同时不引入新的可观测特征；只改 `urov-y` 与测试
App，`urov-lab`、`urov-x` 不动。ABI 仍为 v8。

## 1. 输入：2.13.0 仍成立的两类恢复路径

2.13.0 已消除 AP 独占探针（`LDXR; LDRB; NOP; STXR`）和无效 `mprotect`
撤销会话。复核代码与真机后，普通 App（`untrusted_app`、`CapEff=0`、
`Seccomp=2`）仍有两类**不需要密钥、稳定可重复**的恢复路径：

| # | 2.13.0 行为 | App 侧用法 | 2.13.0 证据 |
| --- | --- | --- | --- |
| E3 | 对已登记页做**任何成功的保护切换**都会结束会话：`mprotect(PROT_READ)`、`PROT_NONE`、`PROT_EXEC`、`PROT_READ\|PROT_WRITE` 都在 syscall 前 `release_session()` | 对目标页调用其中任一 `mprotect`；VMA 没有变化或只是权限变化，随后普通读取得到真实改码字节 | `DOBBY_DETECT_RESTORE`、`CRC_RESTORE` 的 2.13 策略；`ELIM_PROT` 在 2.13 构建上会在首个 `mprotect(R)` 后 `state=inactive` |
| E4 | 门控在 Linux 参数校验/映射类型校验之前撤销会话：未分配 pkey 的 `pkey_mprotect`、private VMA 上的 `remap_file_pages` 都返回 `EINVAL`，但会话已被拆掉 | `pkey_mprotect(page, len, PROT_READ\|PROT_WRITE, 0)`（本机 arm64 6.1 无 POE）或 `remap_file_pages(private_page, ...)`；返回 `EINVAL` 后读取真实字节 | 2.13 的 `uy_gate_before()` 只在 `mprotect`/`pkey_mprotect` 的 `prot` 保持 RX 时早退；其余重叠调用先 `release_session()` |

E3 是**策略选择**而不是架构边界：私有文件页在 `mprotect(PROT_WRITE)` 后仍是
只读 COW 叶（PTE `AP[2]=1`、`AP[1]=1`），因此仍可承载 `AP[1]=0` 的读陷阱；
`PROT_READ`/`PROT_EXEC` 在 arm64 上仍产生 EL0 可读叶（本机 `--xp` 实测可读，
见 §6）。真正不可读的只有 `PROT_NONE`。E4 是门控顺序问题，和 2.13 的 E2
同类。

## 2. 威胁模型

生产代码段 CRC 的输入仍只有两类：

1. **读者看到的字节**：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`。
2. **读者能观察到的副作用**：映射属性、页表统计、异常、独占监视器、耗时、
   崩溃、系统调用返回值。

2.14.0 只处理“普通 App 不需要密钥就能稳定重复”的 E3/E4。它不声称消除
每次读一次的同步异常、真实写入后的覆盖失效、`munmap`/`execve` 等生命周期
操作，也不处理 `LDXP/STXP`、非 `NOP/BTI` 间隔等 LL/SC 形状残余。

## 3. 方案

### 3.1 保护状态机：`want` / `armed` / `dead`

每个登记页新增两个内部状态位（不进入 ABI）：

- `want`：当前 VMA 允许 EL0 读，陷阱应存在；
- `dead`：真实 store 已改过该页，镜像已过期，本会话不再装陷阱；
- `armed`：当前叶 PTE 确实装了 `AP[1]=0`（沿用 2.13 的 0/1/2 语义）。

`mprotect`/`pkey_mprotect` 成功后，`uy_gate_after()` 在 `g_sess.mm` 上按页
更新：

- **可读保护**（`PROT_READ`、`PROT_WRITE`、`PROT_EXEC` 任一，
  arm64 上只有 `PROT_NONE` 不可读）：`want=1`，若未 `dead` 则重新装
  `AP[1]=0`；PTE 已经是该状态时只把 `armed=1`，不重复写；
- **不可读保护**（`PROT_NONE`）：`want=0`、`armed=0`，**不改 PTE**。内核
  已经装入自己的 `PTE_PROT_NONE`，读必须继续原生 `SIGSEGV`；后续可读
  保护会重新装陷阱；
- **PTE 无法承载只读陷阱**（可写共享叶、DBM、CAS 竞争失败）：`dead=1`、
  `armed=0`，该页退回真实视图，**会话本身不结束**。这和 2.13 对整个会话
  的处置相比，只影响确实无法覆盖的那一页。

`ap_rearm_range()` 被 `ap_protection_update()` 取代。PTE 重装仍沿用
`page_update_bits()` 的 RCU + CAS + 广播 TLBI；`page_set_ap()` 放宽了
“禁止 UXN”这一条，因为去掉 `PROT_EXEC` 后页仍有 UXN，但数据陷阱与执行
权限无关。

### 3.2 写入移交：只结束“这一页”，不结束会话

`mprotect(PROT_WRITE)` 后，私有文件页的叶 PTE 仍是只读 COW，所以读陷阱
可以继续存在。第一次真实 store 会以 `WNR=1` 的 permission abort 进入
`uy_abort_before()`：

1. 若该页 `armed && !dead`，且当前 VMA 有 `VM_WRITE`：把叶 PTE 的
   `AP[1]` 恢复（`PTE_USER=1`，保持 `RDONLY`），置 `dead=1`、`armed=0`，
   广播 TLBI；
2. **不设置 `skip_origin`**，让原 `do_mem_abort()` 继续处理这次写故障，
   由 Linux 做正常的 COW/共享写；
3. 写入成功后该页的镜像不再有效，后续读走真实字节；其他登记页不受影响。

若 VMA 本身不可写（`PROT_READ`/`PROT_NONE`/`PROT_EXEC`），第 1 步不做：
未授权的 store 必须保持原生 `SIGSEGV`，检测器不能靠“故意写一下再捕获
信号”来拆掉覆盖。

### 3.3 门控参数与映射类型预校验

- `mprotect`/`pkey_mprotect`：只要 owner 的 `PAGE_AP` 会话仍 live，
  `uy_gate_before()` 不再因重叠而 `release_session()`。成功时由 after hook
  更新状态；Linux 拒绝的调用（未分配 pkey、非法 prot 等）原样返回，会话
  不动。
- `remap_file_pages`：`uy_gate_args_invalid()` 先校验对齐、长度、prot；
  `uy_gate_before()` 对 private VMA（Linux 必然 `EINVAL`）直接透传，不再
  撤销会话；shared VMA 仍保留保守拆除。
- `mmap(MAP_FIXED)`：补上 `MAP_FIXED|MAP_FIXED_NOREPLACE` 同时置位的
  预校验（Linux 在改 VMA 前返回 `EINVAL`），避免这条路径先拆会话。
- 现有 `mprotect` 页对齐/`TASK_SIZE`/prot 掩码、`munmap`/`madvise`/
  `mremap`/`MAP_FIXED` 预校验保持不变。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 模块不改 VMA；`mprotect` 本身改 VMA 是 App 的 syscall。测试中的单页 `mprotect` 会把多页 `.text` 拆成 VMA，这是原生行为，`CRC_PROT_VMA` 明确记录并重新取基线 |
| 新的代码字差异 | 仍只改叶 PTE 的 `AP[1]`；`PROT_NONE`/不可读页不回写 PTE，代码字节始终不变 |
| 新的崩溃 | 非法 store 在只读 VMA 上仍 `SIGSEGV`；`PROT_NONE` 仍 `SIGSEGV`；合法 store 仍成功（多一次模块的 PTE 修正，随后由 Linux COW） |
| 新的错误码/返回码 | `mprotect`/`pkey_mprotect`/`remap_file_pages`/`mmap` 的返回值全部来自 Linux；模块不新增返回码 |
| 新的 hook/ABI/字段 | 没有新 hook；`hooks=0xff`、ABI v8、请求布局、`ctl0` 文本格式和计数器不变 |
| 新的线程/定时器/文件 | 没有新增 |
| 新的映射身份 | 不 split/merge VMA、不额外 mmap、不改 `vm_file` |
| 新的写语义 | 真实 store 由原 fault 路径完成 COW；模块只把此前由模块自己清掉的 `AP[1]` 恢复，store 的值、宽度、地址都不变 |
| 新的计时台阶 | 读路径不变（`site_call_ns=288/292`，与 2.13 的 280/285 同量级）；保护切换多一次 PTE walk + TLBI；首次真实 store 本来就有 COW fault，模块只在同一 fault 内多做一次 PTE 修正 |
| 会话“永不结束” | 真实 store 后该页 `dead`，读真实字节；`munmap`/`mremap`/`MAP_FIXED`/owner `execve`/退出仍结束会话；`PROT_NONE` 期间读仍 `SIGSEGV` |

## 5. 残余（2.14.0 仍不做的事）

1. **真实 store 会退役该页的覆盖**：普通 store、`STP`、原子 RMW
   （`LDADD`/`SWP`/`CAS`）、`DC ZVA` 都会让该页 `dead`；检测器只要写一个
   字节（包括写回原值）就能随后读到真实改码字节。这是“不解码 store”的
   边界，2.13 用结束整个会话规避，2.14 只退役一页。
2. `munmap`/`mremap`/`MAP_FIXED` 覆盖、owner `execve`、进程退出仍结束会话；
   `fork` 子进程把自己的拷贝改成可写仍不受 owner 门控保护。
3. `pkey_mprotect` 在支持 POE 且 pkey 已分配的内核上没有逐项建模 pkey
   权限；本机 arm64 6.1 无 POE，且 App 的 seccomp 直接 SIGSYS 该 syscall
   （测试无法从 `untrusted_app` 覆盖）。
4. `remap_file_pages` 只在 private VMA 上免拆除；shared VMA 的合法重映射仍
   保守结束会话；其架构特定参数只做了常见预校验。
5. `LDXR XZR` 非零目标、`LDXP/STXP`、非 `NOP/BTI` 间隔、计时/PMU 仍是
   2.13 的残余；本轮没有改变 LL/SC 桥的形状。
6. 多页 `.text` 上一次 `mprotect` 只覆盖一页时，VMA 拆分是 Linux 原生
   行为；对包含“正在执行的读者代码”的整个 VMA 去掉 EXEC 在原生环境也会
   崩溃，测试不做这种非法组合。
7. root 仍可用 `kpm list`/`ctl0 status` 看到模块和会话；真实 store 后
   `armed` 计数会降为 0，`ctl0` 文本格式不变。

## 6. arm64 保护语义的实测依据

在 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB 上，
`mprotect()` 后实际 EL0 读权限：

| prot | `/proc/self/maps` | EL0 读 |
| --- | --- | --- |
| `PROT_NONE` | `---p` | 故障 |
| `PROT_WRITE` | `-w-p` | 成功 |
| `PROT_EXEC` | `--xp` | **成功**（arm64 无真正的 execute-only 叶） |
| `PROT_WRITE\|PROT_EXEC` | `-wxp` | 成功 |
| `PROT_READ` | `r--p` | 成功 |

因此 2.14 以“除了 `PROT_NONE` 之外都可读”为状态机输入；`PROT_EXEC` 的
`--xp` 只是 VMA 标记，模块必须继续用镜像服务读，而不是把它当作
execute-only 叶。

## 7. 验证计划与结果

在 Pixel 6 / Android 16 / `6.1.134-android14-11` / 4 KiB / KernelPatch
`0xc00` 上复跑四个矩阵，并新增两组断言：

| 矩阵 | 新增断言 | 结果 |
| --- | --- | --- |
| `dobby-detect` 48×3 | overlay 阶段 AP 探针仍 `NO_MATCH`；`accepted_crc_with_ap=48/48`；`DOBBY_DETECT_RESTORE ... still_active=1 active_after_keyless=1` | PASS；3 个活动进程各 `ap=0/48`、`accepted_crc_with_ap=48/48`，合计 144/144；`views=0/144` |
| `crc` 5×2 | `crc-ap-text`/`crc-ap` 在 overlay 后追加 `mprotect(R)`、`mprotect(RW)`、`mprotect(RX)`；每次普通 CRC 和业务读者都等于镜像，`STATUS` 仍 ACTIVE，`CRC_PROT state=1`，恢复 RX 后执行仍为原返回值 | PASS，16 次运行；`CRC_PROT` 每次 `state=1 generation=1` |
| `eliminate` 3×1 | `w-active` 追加 `ELIM_PROT`：`mprotect(R)` 读镜像、非法 store 不杀覆盖、`PROT_NONE` 原生 SIGSEGV、`PROT_EXEC` 可读叶仍读镜像、`mprotect(RW)` 读镜像、真实 store 后该页退役且写入成功、`DEACTIVATE` 成功 | PASS，11 次运行、21 个 case、63 次观测；`ELIM_PROT ... read_r=1 none_segv=1 exec_readable=1 rw_overlay=1 store_retired=1`；`site_call_ns=288/292` |
| `multipage` 5×1 | 不改断言；确认 24 页/96 KiB 五条读路径与 fork 子进程 | PASS，6 次运行；`mp-prod` 24 页 / 96 KiB、`paths=5`、`child_overlay=1` |

构建与真机数据见
[APP_READ_INTEGRITY_RESULTS.md 的 2.14.0 节](APP_READ_INTEGRITY_RESULTS.md#2140-保护切换存活与写入移交)。
