# 独立活动覆盖真机结果（8/16/24/32 字节窗口）

记录时间：2026-11-03 23:37–23:45（Asia/Shanghai）。测试期间未刷写、未重启、未升级 KernelPatch，未修改宿主内核源码。

本次构建把单个用户态代码页的伪造窗口从固定的 8 字节扩展到 8/16/24/32 字节；ABI 升级为 v2（`length` + `value_hi[3]`），fault 路径通过 seqlock 获取一份完整的 32 字节快照。100 次更新、8 CPU 并发读、5 次加载/卸载循环和带在途读者的卸载均通过。

## 环境

| 项 | 值 |
|---|---|
| 设备 | Pixel 6 / oriole（`google/oriole_beta/oriole:16/BP31.250610.009/13905196:user/release-keys`） |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` |
| KernelPatch | `0xc00`（kpatch CLI，superkey 由命令行传入） |
| boot_id | `62c2bf2e-135c-40d0-8435-d98445e10042` |
| 页大小 / CPU | 4 KiB / 8 |
| 运行用户 | root（`kpatch su -c`，sealed memfd 只读重开需要） |

## 产物

`out/SHA256SUMS` 中本次构建的关键产物：

```text
c55987c4667c02590f63f241a8a18012f8f4c4e790cf25fc290f77c1c085ebdd  urov-lab.kpm
128a8bc7583ec24c4d75b9ef531df017cb8709cd1d129ae66d11b7c1bc2baa58  urov_overlay_test
ea5939d187d56c6ae947d2f045ff330beba0fa49a3cd5e80eb493bbcb677f4b8  urov_hold_test
5f2a4bffdbb665a61eb6d78a2910b8d9c53fdada49dfb8f06e37721548c35b52  urov_hold2_test
```

模块加载后 `kpatch kpm ctl0 urov-lab status`：

```text
mode=standalone-resident caps=0x6b7 state=inactive hooks=0x7 core_checks=4139 gen=0 hits=0 failures=0 notify_nr=272 notify_magic=0x55524f5653595343
```

`caps=0x6b7` = `READY|RESIDENT|RAW_XOM|PAIR|GPR|MM_GATES|FAKE16|FAKE32`；`hooks=0x7` 表示 abort、notify syscall 与全部门控 hook 均已安装。

## 1. 宽窗口 100 次更新 + 8 CPU 并发读（`results/overlay-run-100-wide.txt`）

```text
backend_caps=0x6b7 state=0
page=0x7827b51000 baseline_ok
registered width=8 session=1 generation=1
concurrent_readers=8 updates=100 loops=75921
status width=8 generation=102 hits=160700 failures=0
width=8 restored=verified
registered width=16 session=1 generation=1
concurrent_readers=8 updates=100 loops=79458
status width=16 generation=102 hits=171379 failures=0
width=16 restored=verified
registered width=24 session=1 generation=1
concurrent_readers=8 updates=100 loops=104799
status width=24 generation=102 hits=225666 failures=0
width=24 restored=verified
registered width=32 session=1 generation=1
mapping_gates=verified
fork_inherit=blocked
unsupported_access=fail_closed
concurrent_readers=8 updates=100 loops=111417
status width=32 generation=102 hits=242698 failures=1
width=32 restored=verified
PASS scope=standalone_active_overlay widths=8,16,24,32 ordinary_loads=1,2,4,8,ldp execution=42 update=verified gates=verified fork=blocked fail_closed=verified concurrency=verified restore=verified
```

- `widths=8,16,24,32`：依次注册四种长度的覆盖区间，每种都完成注册、读值、更新、并发更新、状态和注销恢复。
- `ordinary_loads=1,2,4,8,ldp`：在窗口前后和窗口内部按 1/2/4/8 字节读取并与字节级 oracle 对比；LDP 覆盖 16 字节，且窗口尾部/首部与原页字节的拼接位置也被检查。
- `concurrent_readers=8 updates=100`：8 个 CPU 上的读者持续执行 `LDR`、`LDP` 和原页函数；控制线程每轮发布一份新的完整 fake 快照。读者只接受两个完整版本之一，未观察到撕裂。
- `status width=32 hits=242698 failures=1`：32 字节窗口单会话完成 24 万余次覆盖命中；`failures=1` 来自测试主动执行的 SIMD `ldr q0` fail-closed 用例，其余三种窗口为 0。
- `execution=42`：同一页的原始函数 `BTI c; MOV W0,#42; RET; NOP` 始终返回 42；取指不受覆盖影响。
- `gates=verified`：活动期间 `mprotect`/`madvise`/`munmap`/`mremap`/`mmap(MAP_FIXED)` 与目标页相交均返回 `EBUSY`；无关映射的 `mprotect` 正常通过。
- `fork=blocked`、`fail_closed=verified`、`restore=verified`：fork 不继承目标页；SIMD 访问按约定发 SIGSEGV；注销后读回原值且窗口可再次注册。

## 2. 5 次加载/测试/卸载循环（`results/overlay-cycles-5-wide.txt`）

每次循环都重新加载模块、跑完整的 8/16/24/32 字节验收，再卸载模块：

```text
cycle 1 PASS
cycle 2 PASS
cycle 3 PASS
cycle 4 PASS
cycle 5 PASS
ALL_CYCLES_PASS
```

每次卸载后 `kpatch kpm list` 均为空，未出现模块残留；重新加载后的 `core_checks` 仍为 4139。

## 3. 在途读者存在时卸载（`results/overlay-unload-readers-wide.txt`）

4 个线程分别绑核，在活动的 32 字节会话下持续执行普通 `LDR` 和原页执行；主线程在另一个 kpatch 进程中卸载模块：

```text
before_unload: READY readers=4
unload: (rc=0)
after_unload: READY readers=4 AFTER loops=110419641 errors=0 exec=42 value=d65f03c052800540
module_list_after: []
```

- 卸载后 4 个读者共完成约 1.10 亿次循环，`errors=0`，执行结果仍为 42。
- 读到的值恢复为原页偏移 4 的 8 字节：`0xd65f03c052800540`（即 `MOV W0,#42` + `RET`）。
- 说明模块 `exit` 先恢复 PTE/VMA/TLB 并排空在途 handler，再撤销 hook；卸载返回 0 且模块列表为空。该用例覆盖了 32 字节 fake 快照与在途读者同时存在时的卸载。

## 4. 软件核心与并发快照自测

本机 WSL（gcc 13.3，ASAN+UBSAN）和 Pixel 6 上的同一测试程序均运行：

```text
PASS emulator_checks=288099 core_checks=4139 value_cases=144000 threaded_pair_cases=100000 scope=software_core_only
```

- `core_checks=4139`：`uro_core_selftest()` 的断言数，模块 load 时要求完全一致。
- `value_cases=144000`：随机 8/16/32 字节窗口、所有白名单 load 类型与随机地址的组合。
- `threaded_pair_cases=100000`：读写线程并发发布 32 字节快照，验证 LDP 两个结果来自同一版本。

同一构建的真机原生差分测试（`results/native-differential-wide.txt`）：

```text
PASS cpus=8 native_cases=26 comparisons=20800 scope=native_vs_software_model overlay=NOT_ENABLED
```

26 类白名单 load 在 8 个 CPU 上与原生 RX 页执行结果逐项对比，全部一致。

## 5. 内核日志

测试后 `dmesg` 未出现 `BUG:`、`WARNING:`、`Oops`、`panic`、RCU stall 或 KASAN 记录。可预期的 `urov:` 日志只有测试主动触发的 SIMD fail-closed 用例：

```text
urov: emulation failure far=... esr=9200000f opcode=3dc00120 result=-3
```

`result=-3` 为 `URO_UNSUPPORTED`；每次完整验收只出现一次。

## 已覆盖与未覆盖

已覆盖：

- EL0 普通 GPR load 白名单：LDRB/LDRH/LDR/LDRSW 等由 `decode.c` 定义的编码，含 scaled/unscaled、pre/post、寄存器偏移、符号扩展、写回、XZR、LDP。
- 8/16/24/32 字节覆盖窗口；窗口前部、内部、尾部的部分重叠；窗口外同页读取返回原值。
- 同一份 32 字节 fake 快照在一次指令内一致；LDP 两个结果共用一份快照；`SET` 长度校验、期望代次校验与 `-EAGAIN`。
- 注册页校验、页 pin、`mm_users` 保留、注销/卸载恢复。
- 目标页取指、fork 不继承、映射门控、fail-closed。

未覆盖 / 明确不支持：

- SIMD/FP、SVE/SME、原子/独占/acquire、认证 load、MTE 标签、跨页访问、非 4 KiB 页、AArch32。
- 任意第三方进程的任意映射；一次只有一个会话、一页、一个最多 32 字节的覆盖窗口。
- 单条 A64 整数 load 的架构上限是 8 字节，LDP 是 16 字节；32 字节窗口需要多条指令分别读取。
- 设备无 EPAN，raw XOM 页对内核 uaccess 仍可读，不能视为生产级隔离。
- 普通 app 进程不可直接使用：`untrusted_app` seccomp 拒绝 `__NR_kcmp`（SIGSYS），SELinux 拒绝 `/proc/self/fd` 只读重开（EACCES）；实测见 [APP_DOMAIN_LIMITS.md](APP_DOMAIN_LIMITS.md)。
- 未做长时间压力、迁移/回收故障注入、性能基准；未测试模块加载期间与 `mmap` 等未门控路径的并发。

## 历史 8 字节基线

上一版固定 8 字节窗口的 100 次更新/8 CPU 并发结果、10 次加载/卸载循环和产物散列保留在 `results/overlay-run-100.txt`、`results/overlay-cycles-10.txt` 与旧记录中；本次改动没有删除这些历史证据。
