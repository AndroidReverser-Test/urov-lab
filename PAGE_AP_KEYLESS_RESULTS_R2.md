# 普通 App 无密钥复核（第二轮）：PAGE_AP 相邻 LL/SC 桥的执行存证

2026-11-05，Pixel 6，Android 16，arm64，内核 `6.1.134-android14-11`，KernelPatch
`0xc00`。本轮以 [PAGE_AP_KEYLESS_RESULTS.md](PAGE_AP_KEYLESS_RESULTS.md) 记录的
LL/SC 桥语义特征为起点：旧产物 `urov-y.kpm` SHA-256
`fbe8dc8409351696f0f17ecaf2da77818a8df2cfdcb4e8fd6d0b81d02d38a87b`（本轮保留为
`urov-y-baseline.kpm`），新产物 `55361f3bdf092620cfa0a01c303bd42f544916a0d8aa031737923cf46324594c`。
设计见 [ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §11，机器结果见
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md) §11 和
[summary.json](results/eliminate-20261105-224534/summary.json)。

## 源码复核

`urov-y` ABI v6 保留密钥化控制和单 `mm`、单目标页会话。`PAGE_AP`（`mode=3`）不改
代码字节、不产生 COW、不改变 EL0 取指：注册时在 `mmap_write_lock` 下只清目标页
叶子 PTE 的 `AP[1]`（`PTE_USER`），`do_mem_abort` hook 按 `mm`、`EC=0x24`、`WnR=0`、
permission FSC、`FAR` 落在目标页筛选；`uy_emulate_load()` 解码受支持的 GPR load，
调用者 `x30` 在注册窗口内时合成伪值，窗口外从注册快照透明模拟，然后提交
GPR/SP/PC。`handle_mm_fault` after-hook 在目标页重新装回后再次清 `AP[1]`；
注销/卸载恢复权限；相交映射、`clone`、`execve` 的门控与第三轮相同。

AP 模式独有的代价是每次读取一次同步数据异常，异常返回必经 `ERET`，`ERET` 把本地
独占监视器恢复为 Open Access。旧实现为了让紧邻的

```asm
ldxr  x9, [x1]        ; PC-4
ldrb  w11, [x0]       ; PC，目标页的 permission abort
stxr  w10, x9, [x1]   ; PC+4
```

看起来和原生一样，在 handler 里用 `copy_to_user_nofault` 代写 `STXR` 的存储、
把 `Ws` 置 0、把 PC 推进到 `PC+8`。匹配条件只有三条相邻指令的编码和寄存器编号。

## 检测 App 的具体方法

检测核心在 `native/urov_observe.c`，不接收模块密钥、不装信号处理器、不改变映射；
它只拿到两个本进程 RX 地址、后备文件 fd 和偏移，在后台线程执行。四个独立探针：

| 探针 | 关键序列 | 针对的特征 |
|---|---|---|
| `ud_observe_exclusive` | `LDXR scratch; LDRB target; STXR scratch`，3 epoch × 32 组 | `ERET` 清本地独占监视器（`urov-x`/无桥的 AP） |
| `ud_observe_reader` | `pread` vs 直接 `LDR` vs 经注册站点函数的调用 | 同一地址按 PC 返回不同字节 |
| `ud_observe_execution` | 校验过的 `BTI C; RET` canary + `LDXR/STXR`，3 × 32 组 | EL0 取指进入 EL1（`PAGE_UXN`） |
| `ud_observe_unreserved_store` | `CLREX; B 1f; LDXR x9,[x1]; 1: LDRB w11,[x0]; STXR w10,x9,[x1]`，32 组 | 桥在没有执行 `LDXR` 时仍代写 |

此外 App 还比较活动站点字与安装文件字、读取 `smaps` 的 `Private_Dirty/Anonymous`
（抓 `SITE_BRK` 的 COW 页），并用两个正常别名和 8 个 CPU 做对照。判定是
"全部目标样本一致"：`MATCH` 需要 32/32 组都出现异常成功并写入哨兵；任一混合、
元数据变化或对照失败都归 `UNKNOWN`，不当作阳性。

`unreserved_store_once()` 的实际反汇编（NDK `-O2`，常量构造合并）关键部分是：

```asm
mov  x9, #0xc3175ed9246ab08f   ; 哨兵
str  x8, [x1]                  ; scratch = 0x5a5a5a5aa5a5a5a5
clrex
b    1f
ldxr x9, [x1]                  ; 被分支跳过
1: ldrb w11, [x0]              ; 目标页，AP[1] permission abort
stxr w10, x9, [x1]
```

`clrex` 后没有架构上执行的 `LDXR`，原生 `STXR` 必须返回 1 且不写内存；旧桥只看到
"`PC-4` 是 `LDXR`、`PC+4` 是 `STXR`"，于是代写哨兵并返回 0。这就是本轮要消除的
确定性特征。

## 消除方案：只代写"有执行证据"的 STXR

`LDXR` 留给 handler 的唯一架构痕迹是目的寄存器 `Xt`：执行后它必然等于 `[Xn]`。
新检查在 armed 之前做一次 nofault 读：

1. 取 `Xt = regs[R(LDXR)]`、`[Xn]`；
2. 要求 `LDXR`/`STXR` 宽度一致；`Xt=31`（`XZR`）没有可验证寄存器，不桥；
3. 仅当 `Xt == [Xn]` 时置 `valid`；否则桥完全不生效，只把 PC 推进到 `STXR`，让
   `STXR` 原生执行并按 `ERET` 后的 Open Access 失败。

| 序列 | `Xt` | `[Xn]` | 原生 STXR | 新 handler |
|---|---|---|---|---|
| 正常 LL/SC | `LDXR` 装回的值 | 同一值 | 成功 | 代写、`Ws=0`、`PC+=8`（不变） |
| 分支跳过 `LDXR` | 调用者预置的哨兵 | 初值 | 失败 | 不桥；`STXR` 原生失败（`Ws=1`、不写） |
| 两指令之间另一 PE 写 `[Xn]` | 旧值 | 新值 | 应失败 | 不桥；原生失败 |
| 预置 `Xt == [Xn]` 再跳过 | 同一值 | 同一值 | 失败 | **残余：仍代写**（§11.5.1） |

实现只改 `uy_llsc_prepare()`：形状匹配后多一次
`copy_from_user_nofault(&loaded, [Xn], width)` 和一次寄存器比较；不新增 hook、
PTE 位、指令改写、调试寄存器、syscall 或状态字段。`ctl0 status` 的 `llsc` 仍只统计
真正代写的次数。检测 App 的期望也相应翻转为"任何模式都必须 `NO_MATCH`"。

## 真机结果

检测与业务都在 `untrusted_app` 中运行，实测 `CapEff=0`、`Seccomp=2`、SELinux
`Enforcing`、uid 10284。模块装卸、密钥和 `ctl0` 只由 ADB 侧 root 完成。

### 单变量 A/B

同一个新 APK（`ccb327d9…`）、同一夹具、同样 `w-active repeats=6`，只换 KPM：

| KPM | 活动 store 观测 | 写入 | App |
|---|---:|---:|---|
| 旧桥 `fbe8dc84…` | **42/42 MATCH** | 1,344 | FAIL（新探针要求原生失败） |
| 新桥 `55361f3b…` | **0/42，42 clean** | **0** | PASS，551 项断言 |

两次运行的 `active_page` 独占探针都是 `exclusive_match=0`：真正执行过 `LDXR` 的
序列仍由桥代写，否则该探针会立刻变成阳性；业务伪值
`0x8877665544332211` 也都保留。原始日志见
[baseline.log](results/ab-llsc-baseline-vs-verified/baseline.log) 与
[verified.log](results/ab-llsc-baseline-vs-verified/verified.log)。

### 正式矩阵

运行器 `tools/run_elimination_device.py --repeats 12 --cycles 2`：
15 次 App 运行、39 组用例、441 次完整 API 观测、42,336 个被接受三元组，
`RESULT PASS`。

| 项目 | 数量 |
|---|---:|
| 全部独占观测（AP/BRK/UXN/无模块） | 441 clean，0 MATCH，0 UNKNOWN |
| AP 运行内 store 观测（w-active/w-hold，含 baseline/deactivated） | 174 次，0 MATCH，174 clean |
| AP store 目标试验 | 5,568 次，0 次写入 |
| 对照 store 观测（y-*/z-*） | 324 次，0 MATCH，0 写入 |
| 独占探针的目标 STXR 失败 | 0 |
| 业务伪值读取 | 6/6 |
| 内核 Oops/BUG/WARNING | 0 |

`w-active` 每轮 6 个 `ELIM_CASE`（baseline/active_page/outside/after_set/
equal_value/deactivated）全部 `exclusive_match=0 reader_match=0`、`accepted=1152`；
12 个 `ELIM_STORE` 项（含 8 个 `active_cpu_*`）全部 `expected=0 match=0 clean>0
stores=0`，`active_cpu_*` 每项 3 次观测、96 个目标试验。`ELIM_FEATURE` 仍为
`business_reader=1 reader=0x8877665544332211`，`ELIM_TIMING mode=ap
site_call_ns=280/275`。

### 生命周期与 root 验收

`09-hold-ap` 在活动会话中卸载：

```text
mode=data-ap state=active sites=2 armed=2 hits=2 replays=96 failures=0 llsc=0
ELIM_HOLD_RESTORED pid=23387 opcode=f9400000 direct=f2c66881f2aaacc1
private_dirty_kb=0 anonymous_kb=0 base_dirty_kb=0 base_anonymous_kb=0
```

`llsc=0` 是本轮的新预期：hold 夹具在活动会话里只跑那个"分支跳过 `LDXR`"的探针，
桥一次都不应代写；旧矩阵在这里会看到 `llsc` 随探针增长。卸载后 `kpm list` 为空，
App 存活并观察到原始读取值；另一 UID 的观察者用例在 owner 会话活跃时仍看不到伪值。
root 验收 `urov_y_test --mode ap --key …`：

```text
TRAP mode=ap site_word=f9400000 dirty_kb=20 base_dirty_kb=20 anon_kb=0 base_anon_kb=0
TRAP_CALL mode=ap active_ns=525
TRAP_CALL mode=ap restored_ns=2
PASS cases=1 assertions=33 failures=0
```

## 业务影响和结论边界

- 检查只在紧邻 LL/SC 形状的异常上多一次 nofault 读，读的是 `LDXR` 刚读过的同一
  cache line；不改变伪值、调用窗口、命中/重放计数、页表或代码页。
- 新桥对"`LDXR` 确实执行且 `[Xn]` 未被改写"的序列仍返回成功；对"分支跳过
  `LDXR`"和"两指令之间被另一 PE 改写"的序列按原生语义失败。这消除了检测 App
  能稳定复现的那个特征，而不是把失败改写成成功。
- 残余（详见设计 §11.5）：调用者若预置 `Xt == [Xn]` 再跳过 `LDXR`，仍可让桥代写；
  非紧邻的 LL/SC 排布、`Xt=31`、`STLXR` 顺序/争用、每次读取一次同步异常
  （~275–280 ns）、`AP[1]` 的 fail-closed 边界、PTE 重装窗口和 root 可见性都未
  改变。该结果只覆盖当前检测集和本机，不声称"任意检测面"为零。
- 检测探针只采样已知的不可变 RX 页；文件读用 `pread`，不写目标页，唯一写入是
  线程私有栈变量。`SITE_BRK` 的代码字/COW、`PAGE_UXN` 的取指 canary 在矩阵中仍
  作为阳性对照通过。

## 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 12 --cycles 2
```

单变量 A/B：保留旧产物为 `out/urov-y-baseline.kpm`，运行
[ab_llsc.py](results/ab-llsc-baseline-vs-verified/ab_llsc.py)。
