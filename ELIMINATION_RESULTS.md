# UROV-Y 设备实测：两项无密钥检测归零，功能保留

日期：2026-11-04（Asia/Shanghai）。对象为新增的 `urov-y.kpm` 与未修改的检测核心
`native/urov_observe.c`、`native/urov_detect.c`。设计与限制见
[ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md)。

**结论：正式矩阵通过。7 次 App 运行、15 组观测用例、129 次完整 API 观测、
12,384 个被接受三元组。活动目标页上独占监视器 MATCH **0**、跨 PC 内容差异
MATCH **0**；同一设备、同一 App、同一夹具对 `urov-x` 的阳性对照仍为
10/10（8 个 CPU 共 24/24）。注册业务调用窗口仍读到伪值
`0x8877665544332211`，直接读取与文件一致。应用持有活动会话时卸载模块，
运行中的 App 观察到读取点恢复为原指令且未收信号。新引入的代码页特征已实测
记录：活动期间 `f9400000 → d4235b40`，注销后恢复相等。**

## 1. 设备与产物

| 项目 | 实测值 |
|---|---|
| 设备 | Pixel 6 / oriole / `25091FDF60063J` |
| 系统 | Android 16 / SDK 36 / `BP31.250610.009`（`oriole_beta`） |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，arm64，4 KiB 页 |
| KernelPatch | `0xc00` |
| App | `com.example.urovdetect`，uid 10284，`untrusted_app`、`CapEff=0`、`Seccomp=2` |
| 结果目录 | [results/eliminate-20261104-234841/summary.json](results/eliminate-20261104-234841/summary.json) |

产物 SHA256（本轮）：

```text
0da468166586d311b8b49587d9739944a712ffc9996ac2da0225bb62d61f59e5  urov-y.kpm
c2a5c3d3bb272f4bd2db6205f69cd277739f6e32e5c6cd67cecf2b3e7f393575  urov-x.kpm（对照，未改动）
eafb05913953d8cc90431b95abdcbaf5bf9509ec0ef3492b86814dd8ef0b4779  urovdetect.apk
```

模块密钥与 urov-x 对照密钥由运行器每次随机生成，不写入结果。`ctl0 status` 显示
`hooks=0x1f`（brk_handler + prctl + 6 个门控 + clone + clone3），
`core_checks=4139`，`imm` 每次装载不同（本轮 `1ada`）。

## 2. 正式矩阵

运行器：`tools/run_elimination_device.py --serial … --key Test6666 --repeats 10
--cycles 2`。每一步都校验 App 的 `untrusted_app`、`CapEff=0`、`Seccomp=2`。

| # | 用例 | 结果 | 关键数据 |
|---|---|---|---|
| 01 | 未装载模块，`y-clean` | PASS | `idle_unregistered` 独占/reader 全 NO_MATCH；无密钥通道 `EINVAL` |
| 02 | `urov-x` 阳性对照，`observe-active` | PASS | `active_changed` 独占 10/10、reader 10/10；8 个 CPU 各 3/3（共 24/24） |
| 03 | 装载 `urov-y`、无会话，`y-clean` | PASS | 模块在场但空闲；独占/reader 全 NO_MATCH |
| 04-1 | `y-active` 第 1 轮 | PASS | 7 用例 / 385 断言；见下表 |
| 04-2 | `y-active` 第 2 轮 | PASS | 同上 |
| 05 | 活动会话中卸载模块 | PASS | 卸载后模块列表为空；App 记录 `ELIM_HOLD_RESTORED opcode=f9400000`，进程存活 |
| 06 | 卸载后 `y-clean` | PASS | 独占/reader 全 NO_MATCH |

`y-active` 逐用例（两轮相同，n=10）：

| 用例 | 独占 MATCH / clean / UNKNOWN | reader MATCH / clean | 说明 |
|---|---|---|---|
| `baseline` | 0 / 10 / 0 | 0 / 10 | 注册前 |
| `active_page` | **0 / 10 / 0** | **0 / 10** | 活动目标页：两项检测都不命中 |
| `active_outside_window` | 0 / 10 / 0 | 0 / 0 | 伪值窗口外（直读值为 0） |
| `active_after_set` | 0 / 10 / 0 | 0 / 10 | SET 之后 |
| `active_equal_value` | 0 / 10 / 0 | 0 / 10 | 伪值等于原值 |
| `deactivated` | 0 / 10 / 0 | 0 / 10 | 注销之后 |

合计（summary.json）：`observations=129`、`exclusive_matches=0`、
`exclusive_clean=129`、`exclusive_unknown=0`、`reader_matches=0`、
`reader_clean=129`、`accepted_triplets=12,384`、`failed_target_stores=0`、
`control_failed_stores=1`。也就是说，本方案的活动页在所有采样里都表现为普通
可读 RX 页；检测器的 12,384 次目标 STXR 全部成功，只有 1 个对照三元组因正常的
瞬时干扰被丢弃。作为对比，同一设备上 `urov-x` 的活动页是 10/10 MATCH、
8 CPU 24/24 MATCH、目标 STXR 全部失败。

## 3. 功能保留

同一页面、同一读取点、同一不可变地址：

```text
ELIM_FEATURE business_reader=1 direct=0xf2c66881f2aaacc1 reader=0x8877665544332211 file=0xf2c66881f2aaacc1
```

- 注册窗口内的 `uy_business_ldr()` 返回伪值 `0x8877665544332211`；
  `uy_business_ldrb()` 返回伪字节 `0x11`。
- 直接调用 `uy_site_ldr()`、`copy_scalar` 与 `ud_check_views` 都返回文件字节
  `0xf2c66881f2aaacc1`；`ud_observe_reader(at, fd, off, uy_site_ldr)` 为
  `NO_MATCH`。
- SET 到新值、SET 回原值、注销后恢复都在两轮矩阵中验证；业务 worker 累计
  执行 119,424 次（单轮记录见 `ELIM_BUSINESS ops=… errors=0 execution=original`）。
- App 侧断言覆盖：errno 不变、4 种信号处理器不变、线程名不变、文件位置不变、
  元数据 fd 不泄漏、目标 VMA（smaps 的 start/end/offset/r-x/shared/dc/rr/mw）
  前后一致。目标页从未被改写权限。

## 4. 活动会话中卸载：跨进程恢复

`y-hold` 注册并持续执行读取点；运行器在 App 仍活动时直接
`kpatch kpm unload urov-y`：

```text
ctl0 status: state=active sites=2 armed=2 hits=2 failures=0
unload: 模块列表随后为空
App: ELIM_HOLD_RESTORED pid=… opcode=f9400000 direct=f2c66881f2aaacc1
     DETECT_RESULT PASS mode=y-hold
```

卸载路径用 `__access_remote_vm()` 写回原指令（内核按会话 mm 的页表做临时映射），
`copy_to_user_page()` 负责把 D-cache 清到 PoC，随后 `IC IALLUIS` 广播失效
指令缓存；因此不需要"先注销才能卸载"，也没有把 BRK 留在进程里。App 在下一次
调用读取点时读到原值并继续运行，没有 SIGTRAP。

root 验收程序 `tests/urov_y_test` 另覆盖：多字节/字节读取点、窗口外地址、
未映射地址的 SIGSEGV 语义、fork 窗口（子进程读原值、父进程保留覆盖）、
mprotect 门控、注销后指令恢复，共 29 项断言全部通过。

## 5. 新特征：读取点代码页

这是本方案最主要的代价，已实测而不是隐藏。活动期间 App 自己比较读取点 4 字节
与库文件：

```text
ELIM_RESIDUAL site_file_word=f9400000 site_live_word=d4235b40 differs=1 site_cow_private=1
ELIM_RESIDUAL restored_site_file_word=f9400000 live_word=f9400000 equal=1
```

即：`ldr x0,[x0]` 被替换为本装载的 `BRK`，代码页成为私有 COW 页（+4 KiB
`Private_Dirty`），注销后字节恢复一致。任何"读自己的代码页并与安装文件比较"
的自检都能发现活动会话。本轮交付的检测 App 不做这种代码完整性检查，所以矩阵
的 0 命中**不代表**该特征不存在；把它加入检测矩阵是下一步的首要工作。

其他残余：

1. **业务路径复现**：把注册的业务包装函数当 reader 传给 `ud_observe_reader`
   会得到 MATCH；能执行真实业务读取路径的同进程代码本来就能看到伪值。
2. **时间**：读取点调用仍有一次同步 debug 异常；本方案不做零开销承诺。
3. **约束**：单页/单会话/≤4 读取点/≤4 调用窗口/≤32 字节窗口；读取点必须是私有
   可 COW 的可执行映射；调用窗口基于读取点执行时的 `x30`。
4. **root 可观察性**：`brk_handler` 的 inline hook 与 6 个 syscall 表项仍对 root
   可见；本方案只针对普通 App 的无密钥检测。

## 6. 内核状态与清理

- 正式矩阵前后各取一次 `dmesg`；新增日志无 `BUG:`、`WARNING:`、`Oops:`、
  panic、RCU stall、hung task 或 `Call trace`。
- 结束状态：模块列表为空，App 已 force-stop，读取点恢复原指令。
- 本轮共执行 3 次完整自动化矩阵（前两次失败是运行器自身的断言/大小写过滤缺陷，
  与模块无关，已修正并删除对应结果目录）、多轮 root 验收程序，以及活动期卸载、
  fork 窗口和重复装载/卸载。最终保留的正式结果为
  `results/eliminate-20261104-234841`。早期一版"活动会话中卸载"实现曾在卸载
  路径触发内核 Oops（详见第 7 节），修复后复测通过。

## 7. 一次失败的记录（保留）

第一版实现把"卸载时的读取点恢复"限制在会话 mm 的上下文，并要求卸载前注销；
在设备上对活动会话执行 `kpm unload` 时，内核在 debug 异常路径发生了 Translation
fault（`comm:kpatch`，调用链含 `do_debug_exception → el1_abort`）。该版本没有
写回原指令就撤销了 hook。修复方式是让恢复路径完全不依赖当前 mm：写回走
`__access_remote_vm(mm, …)`，缓存维护走 `copy_to_user_page` + `IC IALLUIS`；
同时删除了卸载否决。修复后的活动期卸载在 root 程序与普通 App 上都通过
（本文第 4 节）。这条记录保留，因为它说明"卸载路径"本身也是攻击面。

## 8. 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial 25091FDF60063J --key <KP-SUPERKEY> --repeats 10 --cycles 2
```

手工步骤：

```text
adb push out\urov-y.kpm /data/local/tmp/urov-y.kpm
kpatch <KEY> kpm load /data/local/tmp/urov-y.kpm "key=<32-hex-secret>"
adb shell am start -n com.example.urovdetect/.MainActivity --es mode y-active --es key <secret>
kpatch <KEY> kpm unload urov-y
```

`y-clean` 不带密钥运行（模块在场/不在场都可），`y-hold` 用于活动期卸载，
`observe-active`/`x-*` 仍用于 `urov-x` 对照。
