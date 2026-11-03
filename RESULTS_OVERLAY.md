# 独立活动覆盖真机结果

记录时间：2026-11-03 23:05–23:13（Asia/Shanghai）。测试期间未刷写、未重启、未升级 KernelPatch，未修改宿主内核源码。

## 环境

| 项 | 值 |
|---|---|
| 设备 | Pixel 6 / oriole |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` |
| KernelPatch | `0xc00`（kpatch CLI，superkey 由命令行传入） |
| boot_id | `62c2bf2e-135c-40d0-8435-d98445e10042` |
| 页大小 / CPU | 4 KiB / 8 |
| 运行用户 | root（`kpatch su -c`，sealed memfd 只读重开需要） |

## 产物

`out/SHA256SUMS` 中本次构建的关键产物：

```text
1a24f1f61131b2800b6fb501357c08af579d0ed2e5bda44d8c15413dd0108b65  urov-lab.kpm
d3b50be48138b6102417c0d611099b5494bee529daeadf2ba6bd6ece162e45fe  urov_overlay_test
cc63f6aaee599cdf48888bf0cfe9fbeef22489859760d46c59547c0c05b14c63  urov_hold_test
5c6b96edb4002be7cd2ce45bd6dfe382c4ae4f72d839f04c960b84ee6af95c30  urov_hold2_test
```

模块加载后 `kpatch kpm ctl0 urov-lab status`：

```text
mode=standalone-resident caps=0xb7 state=inactive hooks=0x7 core_checks=4114 gen=0 hits=0 failures=0 notify_nr=272 notify_magic=0x55524f5653595343
```

`caps=0xb7` 表示 `READY|RESIDENT|RAW_XOM|PAIR|GPR|MM_GATES`；`hooks=0x7` 表示 abort、notify syscall 与全部门控 hook 均已安装。

## 1. 100 次更新 + 8 CPU 并发读（`results/overlay-run-100.txt`）

```text
backend_caps=0xb7 state=0
page=0x7532c1f000 baseline_ok
registered session=1 generation=1
mapping_gates=verified
fork_inherit=blocked
unsupported_access=fail_closed
concurrent_readers=8 updates=100 loops=171298
status generation=101 hits=182628 failures=1
deactivated restored=verified
PASS scope=standalone_active_overlay ordinary_loads=1,2,4,8,ldp execution=42 update=verified gates=verified concurrency=verified restore=verified
```

- `ordinary_loads=1,2,4,8`：覆盖区间内按 1/2/4/8 字节读取均返回快照与 `fake64` 合并后的值；区间外返回原页字节。
- `ldp`：LDP 两个目标寄存器使用同一份 `fake64` 快照。
- `execution=42`：同一页的原始函数 `BTI c; MOV W0,#42; RET; NOP` 始终返回 42；取指不受覆盖影响。
- `failures=1`：测试显式执行一次 SIMD load（`ldr q0,[xN]`），模块按约定 fail-closed 发 SIGSEGV；因此最终计数为 1，属预期。
- `gates=verified`：活动期间 `mprotect`/`madvise`/`munmap`/`mremap`/`mmap(MAP_FIXED)` 与目标页相交均返回 `EBUSY`；无关映射的 `mprotect` 正常通过。
- `fork_inherit=blocked`：fork 出的子进程不继承目标页。
- `restore=verified`：注销后按 1/2/4/8/LDP 读回原值，执行仍为 42。

## 2. 10 次加载/测试/卸载循环（`results/overlay-cycles-10.txt`）

```text
cycle 1 PASS
...
cycle 10 PASS
ALL_CYCLES_PASS
```

每次循环后 `kpatch kpm list` 为空，未出现模块残留。

## 3. 在途读者存在时卸载（`results/overlay-unload-readers.txt`）

4 个线程分别绑核持续执行普通 `LDR` 和原页执行；主线程注册会话后在另一个 kpatch 进程中卸载模块：

```text
before_unload: READY readers=4
unload: (rc=0)
after_unload: READY readers=4 AFTER loops=88790412 errors=0 exec=42 value=d65f03c052800540
module_list_after: []
```

- 卸载后 4 个读者共完成约 8879 万次循环，`errors=0`，执行结果仍为 42。
- 读到的值恢复为原页偏移 4 的 8 字节：`0xd65f03c052800540`（即 `MOV W0,#42` + `RET`）。
- 说明模块 `exit` 先恢复 PTE/VMA/TLB 并排空在途 handler，再撤销 hook；卸载返回 0 且模块列表为空。

附加（`results/overlay-orphan-unload.txt`）：会话所有者进程被 `kill -9` 终止后，`ctl0` 仍报告 `state=active`（模块持有 `mm_users`），随后 `kpm unload` 返回 0 并完成恢复；卸载后的 `dmesg` 无异常。

## 4. 内核日志

测试后 `dmesg` 未出现 `BUG:`、`WARNING:`、`Oops`、`Call trace`、`panic`、RCU stall 或 KASAN 记录。可预期的 `urov:` 日志只有：

```text
urov: emulation failure far=... esr=9200000f opcode=3dc00120 result=-3
```

对应测试主动触发的 SIMD fail-closed 用例（`result=-3` 为 `URO_UNSUPPORTED`）。

## 已覆盖与未覆盖

已覆盖：

- EL0 普通 GPR load 白名单：LDRB/LDRH/LDR/LDRSW 等由 `decode.c` 定义的编码，含 scaled/unscaled、pre/post、寄存器偏移、符号扩展、写回、XZR、LDP。
- 同一 `fake64` 在一次指令内一致；`SET` 期望代次校验与 `-EAGAIN`。
- 注册页校验、页 pin、`mm_users` 保留、注销/卸载恢复。
- 目标页取指、fork 不继承、映射门控、fail-closed。

未覆盖 / 明确不支持：

- SIMD/FP、SVE/SME、原子/独占/acquire、认证 load、MTE 标签、跨页访问、非 4 KiB 页、AArch32。
- 任意第三方进程的任意映射；一次只有一个会话、一页、8 字节覆盖。
- 设备无 EPAN，raw XOM 页对内核 uaccess 仍可读，不能视为生产级隔离。
- 未做长时间压力、迁移/回收故障注入、性能基准；未测试模块加载期间与 `mmap` 等未门控路径的并发。
