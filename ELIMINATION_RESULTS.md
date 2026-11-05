# UROV-Y 设备实测：两项无密钥检测归零，代码页特征也已消除

日期：2026-11-05（Asia/Shanghai）。对象为 `urov-y.kpm`（ABI v5，两种读取点陷阱模式）
与未修改的检测核心 `native/urov_observe.c`、`native/urov_detect.c`。设计与限制见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md)。

**结论：正式矩阵通过。10 次 App 运行、27 组观测用例、153 次完整 API 观测、14,688
个被接受三元组。活动目标页上独占监视器 MATCH **0**、跨 PC 内容差异 MATCH **0**；
同一设备、同一 App、同一夹具对 `urov-x` 的阳性对照仍为 6/6（8 个 CPU 共 24/24）。**

**第一轮（BRK 模式）引入的"读取点代码页被改写"特征在第二轮（`PAGE_UXN` 页陷阱）
中已消除：活动期间读取点 4 字节与库文件相同（`f9400000 == f9400000`），代码页
`Private_Dirty=0`、`Anonymous=0`，注销/卸载后无任何残留 COW 页。同一探针在 BRK
模式下仍稳定报告 `differs=1`、`+4 KiB` 私有页，作为阳性对照。注册业务调用窗口
仍读到伪值 `0x8877665544332211`。应用持有活动会话时卸载模块，两种模式都能在运行中
的 App 里恢复，App 未收信号。**

> 2026-11-05 第三轮：上一轮 §9 留下的"读取点页不在 EL0 原生取指"已被
> `ud_observe_execution()` 实测为 255/255 可复现。新增 `PAGE_AP` 模式（ABI v6，
> `mode=3`）：只清目标页 `AP[1]`，站点页取指保持原生；数据 permission abort
> 由相邻 `LDXR/load/STXR` 桥接消除独占监视器信号。正式矩阵
> [results/eliminate-20261105-213741](results/eliminate-20261105-213741)：
> 14 次 App 运行、225 次观测，独占 MATCH **0**、reader MATCH **0**，
> AP 两次运行各 48 次 execution 观测、24 个 per-CPU canary 全部 `match=0`，
> 业务伪值保留。详细数据与残余见 §10。

## 1. 设备与产物

| 项目 | 实测值 |
|---|---|
| 设备 | Pixel 6 / oriole / `25091FDF60063J` |
| 系统 | Android 16 / SDK 36 / `BP31.250610.009`（`oriole_beta`） |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，arm64，4 KiB 页 |
| KernelPatch | `0xc00` |
| App | `com.example.urovdetect`，uid 10284，`untrusted_app`、`CapEff=0`、`Seccomp=2` |
| 结果目录 | [results/eliminate-20261105-002613/summary.json](results/eliminate-20261105-002613/summary.json) |

产物 SHA256（本轮）：

```text
7d9d77ecbbfcb262e861eba5ea143ae332b997328fd1b37af6c5b3f8ee965e9f  urov-y.kpm
c2a5c3d3bb272f4bd2db6205f69cd277739f6e32e5c6cd67cecf2b3e7f393575  urov-x.kpm（对照，未改动）
01f9573c5acbf2d08c3bfa3d1bc99a47fe2a8e688e677832229b4dd464603d5a  urovdetect.apk
```

模块密钥与 urov-x 对照密钥由运行器每次随机生成，不写入结果。`ctl0 status` 显示
`hooks=0x7f`（`brk_handler` + prctl + 6 个门控 + clone + clone3 + `do_mem_abort` +
`handle_mm_fault`），`core_checks=4139`，`imm` 每次装载不同（本轮 `97d2`）。

## 2. 两种模式的正面对比

| 探针 | BRK 模式（`y-active`） | 页陷阱模式（`z-active`） |
|---|---|---|
| `site_file_word` | `f9400000` | `f9400000` |
| `site_live_word` | `d421e8e0`（BRK） | **`f9400000`** |
| `differs` | 1 | **0** |
| `site_cow_private` | 1 | **0** |
| `Private_Dirty` / `Anonymous`（相对基线） | +4 / +4 KiB | **0 / 0 KiB** |
| 注销后代码页 | 仍为私有 COW 页（`+4 KiB`） | **回到干净文件页** |
| 独占监视器 / reader 检测 | NO_MATCH | NO_MATCH |
| 业务窗口伪值 | 命中 | 命中 |
| 单次业务调用 | ~219–232 ns | ~227–241 ns |

也就是说：本轮新增的机制在不引入新的 App 可见差异的前提下，把第一轮唯一已知的
代码页特征也去掉了。时间开销与第一轮同量级（一次同步异常），不是新增特征。

## 3. 正式矩阵

运行器：`tools/run_elimination_device.py --serial … --key Test6666 --repeats 6
--cycles 2`。每一步都校验 App 的 `untrusted_app`、`CapEff=0`、`Seccomp=2`。

| # | 用例 | 结果 | 关键数据 |
|---|---|---|---|
| 01 | 未装载模块，`y-clean` | PASS | 独占/reader 全 NO_MATCH；无密钥通道 `EINVAL` |
| 02 | `urov-x` 阳性对照，`observe-active` | PASS | `active_changed` 独占 6/6、reader 6/6；8 个 CPU 各 3/3（共 24/24） |
| 03 | 装载 `urov-y`、无会话，`y-clean` | PASS | 模块在场但空闲；独占/reader 全 NO_MATCH |
| 04-1/2 | `y-active`（BRK）两轮 | PASS | 7 用例 / 266 断言；代码页特征阳性对照成立 |
| 05-1/2 | `z-active`（PAGE_UXN）两轮 | PASS | 7 用例 / 267 断言；代码页探针全 0 |
| 06 | `y-hold` 活动期卸载 | PASS | 卸载后模块列表为空；App 记录 `ELIM_HOLD_RESTORED opcode=f9400000`，进程存活 |
| 07 | `z-hold` 活动期卸载 | PASS | 同上，且 `private_dirty_kb=0 anonymous_kb=0`（等于基线） |
| 08 | 卸载后 `y-clean` | PASS | 独占/reader 全 NO_MATCH |

每个 `*-active` 运行的逐用例（两轮一致，n=6）：

| 用例 | 独占 MATCH / clean / UNKNOWN | reader MATCH / clean | 说明 |
|---|---|---|---|
| `baseline` | 0 / 6 / 0 | 0 / 6 | 注册前 |
| `active_page` | **0 / 6 / 0** | **0 / 6** | 活动目标页：两项检测都不命中 |
| `active_outside_window` | 0 / 6 / 0 | 0 / 0 | 伪值窗口外（直读值为 0） |
| `active_after_set` | 0 / 6 / 0 | 0 / 6 | SET 之后 |
| `active_equal_value` | 0 / 6 / 0 | 0 / 6 | 伪值等于原值 |
| `deactivated` | 0 / 6 / 0 | 0 / 6 | 注销之后 |

合计（summary.json）：`observations=153`、`exclusive_matches=0`、
`exclusive_clean=153`、`exclusive_unknown=0`、`reader_matches=0`、
`reader_clean=153`、`accepted_triplets=14,688`、`failed_target_stores=0`、
`control_failed_stores=0`。作为对比，同一设备上 `urov-x` 的活动页是 6/6 MATCH、
8 CPU 24/24 MATCH、目标 STXR 全部失败。

## 4. 功能保留

同一页面、同一读取点、同一不可变地址：

```text
ELIM_FEATURE business_reader=1 direct=0xf2c66881f2aaacc1 reader=0x8877665544332211 file=0xf2c66881f2aaacc1
```

- 注册窗口内的 `uy_business_ldr()` 返回伪值 `0x8877665544332211`；
  `uy_business_ldrb()` 返回伪字节 `0x11`。
- 直接调用 `uy_site_ldr()`、`copy_scalar` 与 `ud_check_views` 都返回文件字节
  `0xf2c66881f2aaacc1`；`ud_observe_reader(at, fd, off, uy_site_ldr)` 为
  `NO_MATCH`。
- SET 到新值、SET 回原值、注销后恢复都在两轮矩阵中验证；业务 worker 在活动页
  之外持续执行（`ELIM_BUSINESS ops=… errors=0 execution=original`）。
- App 侧断言覆盖：errno 不变、4 种信号处理器不变、线程名不变、文件位置不变、
  元数据 fd 不泄漏、目标 VMA（start/end/offset/r-x/shared/dc/rr/mw）前后一致。

## 5. 活动会话中卸载：两种模式都可在运行中恢复

`y-hold` / `z-hold` 注册并持续执行读取点；运行器在 App 仍活动时直接
`kpatch kpm unload urov-y`：

```text
# BRK 模式
ctl0 status: mode=site-trap state=active sites=2 armed=2 hits=1 failures=0
App: ELIM_HOLD_RESTORED pid=… opcode=f9400000 direct=f2c66881f2aaacc1 private_dirty_kb=4
# 页陷阱模式
ctl0 status: mode=page-trap state=active sites=2 armed=2 hits=2 failures=0
App: ELIM_HOLD_RESTORED pid=… opcode=f9400000 direct=f2c66881f2aaacc1 private_dirty_kb=0 anonymous_kb=0 base_dirty_kb=0
```

两种模式都不需要"先注销才能卸载"，也没有把 BRK 留在进程里、没有把 UXN 留在 PTE 里。
BRK 模式卸载后代码页仍是私有 COW 页（第一轮特征），页陷阱模式卸载后代码页与基线
完全相同。

## 6. root 验收程序

`tests/urov_y_test --key … --mode page|brk`（33 项断言，均含代码页探针）：

```text
# page
TRAP mode=page site_word=f9400000 dirty_kb=0 base_dirty_kb=0 anon_kb=0 base_anon_kb=0
TRAP_CALL mode=page active_ns=379
TRAP_CALL mode=page restored_ns=2
PASS cases=1 assertions=33 failures=0
# brk
TRAP mode=brk site_word=d4333a40 dirty_kb=4 base_dirty_kb=0 anon_kb=4 base_anon_kb=0
TRAP_CALL mode=brk active_ns=585
TRAP_CALL mode=brk restored_ns=6
PASS cases=1 assertions=33 failures=0
```

覆盖：多字节/字节读取点、窗口外地址、未映射地址的 SIGSEGV 语义、fork 窗口
（子进程读原值、父进程保留覆盖）、mprotect 门控、注销后指令与页面状态恢复、
`--hold` 活动期卸载。读取点页必须自包含这一部署前提在两种夹具中都由汇编段
`.p2align 12` 保证（实测 `liburovdetect.so` 读取点页 `0x13000-0x14000` 内只有两个
stub + NOP 填充，业务包装在 `0x9060`）。

## 7. 残余特征与限制（诚实清单）

1. **时间**：每次业务调用一次同步异常，页陷阱 ~227–241 ns、BRK ~219–232 ns
   （未注册时 2–6 ns）。两种模式同一量级；不做零开销承诺。
2. **读取点页不在 EL0 原生取指**：普通 App 不能直接看 PTE 权限，但可用
   `perf_event_open` 统计 EL0 指令数（Android 上普通 App 被 SELinux 限制），或用
   统计式计时发现该页首次执行多一次异常。本矩阵不含这两项。
3. **PTE 重新装回时的窗口**：页被回收后内核先装一个可执行 PTE，after-hook 再改回
   UXN；这微秒级窗口内另一 CPU 上正好执行读取点的线程可能原生执行一次。普通 App
   要触发需要先让页被回收（`madvise` 已被门控，只剩内存压力或 `/proc/self/mem`
   类 GUP），再与业务线程抢窗口。本矩阵未观测到，但它是非确定性缺口。
4. **业务路径复现即功能本身**：把已注册的业务包装函数当 reader 传给
   `ud_observe_reader` 仍得到 MATCH。
5. **合作模型约束**：单会话、单页、≤4 读取点、≤4 调用窗口、≤32 字节窗口；读取点
   必须是可执行映射；读取点页必须自包含；调用窗口基于 `x30`。
6. **映射门控与第一轮相同**：与目标页/读取点页相交的 `mprotect/munmap/mremap/
   mmap(MAP_FIXED)/madvise` 结束会话，`execve` 结束会话。
7. **root 可观察性**：`do_mem_abort`、`handle_mm_fault`、`brk_handler` 的 inline
   hook 与 6 个 syscall 表项、模块清单、`ctl0 status` 仍对 root 可见。
8. **本轮修复的第一轮缺陷**：`s->page = pc & ~(UROV_Y_PAGE - 1)` 中
   `UROV_Y_PAGE` 是 32 位常数，会把高 32 位地址掩掉；第一轮因此没有真正恢复读取点
   页的 PTE 写保护，映射门控也没有匹配读取点页。本轮改为 `page_base()` 并复测。

## 8. 内核状态与清理

- 正式矩阵前后各取一次 `dmesg`；新增日志无 `BUG:`、`WARNING:`、`Oops:`、panic、
  RCU stall、hung task 或 `Call trace`，也没有模块自身的 `failures`（两次活动
  运行均为 `failures=0`、`degraded=0`）。
- 结束状态：模块列表为空，App 已 force-stop，读取点页干净。
- 开发过程中出现过两类失败并已修正：(a) `pgtable_entry()` 对读取点页返回
  `-EFAULT`，根因是上面的 32 位掩码缺陷；(b) root 程序把"代码页 `Private_Dirty`"
  与 0 比较，而刚 `adb push` 的测试文件 page cache 仍是脏的，基线本身可能非 0；
  改为"活动值 == 注册前基线"后稳定。两者都不是模块在设备上的行为缺陷。

## 9. 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial 25091FDF60063J --key <KP-SUPERKEY> --repeats 6 --cycles 2
```

手工步骤（页陷阱模式）：

```text
adb push out\urov-y.kpm /data/local/tmp/urov-y.kpm
adb push out\urov_y_test /data/local/tmp/urov_y_test
kpatch <KEY> kpm load /data/local/tmp/urov-y.kpm "key=<32-hex-secret>"
kpatch <KEY> su -c '/data/local/tmp/urov_y_test --key <secret> --mode page'
adb shell am start -n com.example.urovdetect/.MainActivity --es mode z-active --es key <secret>
kpatch <KEY> kpm unload urov-y
```

`y-clean` 不带密钥运行（模块在场/不在场都可）；`y-hold`/`z-hold` 用于活动期卸载；
`y-active` 是 BRK 模式的代码页特征阳性对照，`z-active` 是被测的页陷阱模式；
`observe-active`/`x-*` 仍用于 `urov-x` 对照。

## 10. 第三轮：PAGE_AP 与相邻 LL/SC 桥

### 10.1 触发点与设备

2026-11-05 的取指复核在 `PAGE_UXN` 活动页上用 `ud_observe_execution()` 执行
`BTI C; RET` canary，255/255 命中；同一 canary 在 669 次普通页对照中 668 次阴性、
1 次 UNKNOWN。这个信号由 `ERET` 清本地独占监视器产生，与伪值和调用窗口无关。
本轮因此需要一种"取指原生、数据仍可伪造"的模式。

设备与上一轮相同：Pixel 6 / `25091FDF60063J`、Android 16 / SDK 36、
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`、4 KiB 页、KernelPatch `c00`。
检测 App 仍是 `com.example.urovdetect`（uid 10284），`untrusted_app`、
`CapEff=0`、`Seccomp=2`。

正式结果目录：[results/eliminate-20261105-213741](results/eliminate-20261105-213741)。
产物 SHA256：

```text
fbe8dc8409351696f0f17ecaf2da77818a8df2cfdcb4e8fd6d0b81d02d38a87b  urov-y.kpm
53dcd774e2a9550df0d76a22287b58cea1dc857dfd5be22da438ae7d46b9420c  urov_y_test
04d55b42371b95337a0cd9a31376cbdd1691a44e0208ba042d2c4016a44334f8  urovdetect.apk
1d4ada4d0e61bbf37d96129adfef5f1a5e1367012be560121dd47c394b600942  urovobserver.apk
```

### 10.2 正式矩阵

运行器：`tools/run_elimination_device.py --serial … --key Test6666 --repeats 6
--cycles 2`。14 次 App 运行、39 组用例、225 次完整 API 观测、21,536 个被接受三元组。

| # | 用例 | 结果 | 关键数据 |
|---|---|---|---|
| 01 | 无模块，`y-clean` | PASS | 独占/reader 0；无密钥通道 `EINVAL` |
| 02 | `urov-x` 阳性对照，`observe-active` | PASS | `active_changed` 独占与 reader 均阳性；8 CPU 均阳性 |
| 03 | 装载 `urov-y`、无会话 | PASS | 空闲模块不产生观测 |
| 04-1/2 | `y-active`（BRK）两轮 | PASS | 代码页 `differs=1`、私有页，作为第一轮特征对照 |
| 05-1/2 | `z-active`（UXN）两轮 | PASS | 代码页干净；active/equal/per-CPU 取指 canary 全部命中（本轮要消除的特征；上一轮取指复核为 255/255） |
| 06-1/2 | `w-active`（PAGE_AP）两轮 | PASS | 独占 0、reader 0；execution **48/48 `match=0`**，含 24 个 per-CPU canary |
| 07 | `y-hold` 活动期卸载 | PASS | 模块列表空；App 存活并恢复 |
| 08 | `z-hold` + 其他 UID 观察 | PASS | 观察者看不到 owner 的取指异常；卸载恢复 |
| 09 | `w-hold` 活动期卸载 | PASS | `ELIM_HOLD_RESTORED opcode=f9400000`，目标页恢复，App 存活 |
| 10 | 卸载后 `y-clean` | PASS | 独占/reader 0 |

总计：`exclusive_matches=0`、`exclusive_clean=224`、`exclusive_unknown=1`、
`failed_target_stores=1`、`reader_matches=0`、`reader_clean=225`、
`feature_business_reads=6`。唯一一次 `UNKNOWN` 出现在无模块的
`10-final-clean / idle_unregistered`（目标 STXR 瞬时失败 1 次），不是 MATCH；
`04-active-2` 另有 1 次对照失败，均按 UNKNOWN 处理，不计阳性。

### 10.3 AP 模式逐项数据

`w-active` 每轮：

- 6 个 `ELIM_CASE`（baseline/active_page/outside/after_set/equal_value/deactivated），
  每个 `exclusive_match=0`、`reader_match=0`；活动页 `accepted=576`、
  `failed=0`、`control_failed=0`。
- `ELIM_EXEC`：baseline、active_changed、8 个 `active_cpu_*`、equal_value、
  deactivated，每轮 12 项 / 48 次观测，`expected=0`、`match=0`；两轮共 24 项 /
  96 次观测、9,216 个三元组。
- `ELIM_FEATURE business_reader=1 direct=0xf2c66881f2aaacc1
  reader=0x8877665544332211 file=0xf2c66881f2aaacc1`。
- `ELIM_RESIDUAL mode=ap site_file_word=f9400000 site_live_word=f9400000
  differs=0 site_cow_private=0 private_dirty_kb=0 anonymous_kb=0`
  （与基线相同）。
- `ELIM_TIMING mode=ap site_call_ns=273..281`。
- `ELIM_EXEC_STATE` 中 `failures=0`、`hits=2`、`replays=1457`（每轮）。

### 10.4 LL/SC 桥的直接证据

`w-active repeats=30` 的单独运行中，在 App 活动期间轮询
`kpatch ctl0 urov-y status`，观察到 `llsc` 从 0 增长到 **11,960**；同一次运行的
`active_page exclusive_match=0`、`ELIM_EXEC active_changed match=0`、
`DETECT_RESULT PASS cases=19 assertions=1314 failures=0`。原始轮询序列见
[llsc-poll.txt](results/eliminate-20261105-213741/llsc-poll.txt)。
如果桥没有生效，`LDRB` 的同步异常会让随后 `STXR` 失败，检测器应得到
`exclusive_match>0`；同一检测核心在 `urov-x` 阳性对照上正是如此。

### 10.5 root 验收与生命周期

`tests/urov_y_test --mode ap`（33 项断言）通过：

```text
TRAP mode=ap site_word=f9400000 dirty_kb=0 base_dirty_kb=0 anon_kb=0 base_anon_kb=0
TRAP_CALL mode=ap active_ns=756
TRAP_CALL mode=ap restored_ns=5
PASS cases=1 assertions=33 failures=0
```

覆盖：多字节/字节读取点、窗口外地址、未映射地址的 SIGSEGV 语义、fork 窗口、
`mprotect` 门控、注销恢复、活动期卸载。`w-hold` 在 App 仍执行读取点时卸载模块，
App 记录 `ELIM_HOLD_RESTORED opcode=f9400000 direct=f2c66881f2aaacc1
private_dirty_kb=0 anonymous_kb=0`，进程未收信号；模块列表为空。

### 10.6 残余

见 [ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §10.7。最关键的三条：

1. 每次读取仍有一次同步数据异常（~273–281 ns）。
2. 桥只覆盖紧邻的 `LDXR/load/STXR`；换一种 LL/SC 排布仍可看到监视器失效。
3. AP[1] 是页级数据权限，SIMD/原子/独占 load 仍 fail-closed；PTE 重新装回有
   微秒级窗口。该模式消除的是**当前检测集的取指 canary**，不是"任意检测面"。
