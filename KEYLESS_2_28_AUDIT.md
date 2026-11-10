# 普通 App 对 UROV-Y 2.28.0 的无密钥审计

2.27.0 的 [`KEYLESS_2_27_DETECTION.md`](KEYLESS_2_27_DETECTION.md) 用
`CLREX; ADR; BR; 64×NOP; LDXR; BTI J; LDRB; STXR` 证明入口回查的 64 条
上限本身可被观测。2.28.0 把入口回查扩展到 LDXR 所在 VMA 的起点或
16,384 条指令预算，并在预算耗尽时拒绝。本文用同一个测试 App、同一个
`KEYLESS_ENTRY_227` 探针集复测，确认 `ap-all` 的长窗口和短窗口都不再
命中，同时确认生产 CRC 路径不变。

本文只覆盖 2.28.0 可判定的读侧；剩余差异的构造性证明和不可判定性见
[ELIMINATION_2_28_DESIGN.md](ELIMINATION_2_28_DESIGN.md) §5。

## 结论

在 Pixel 6 / Android 16 / ARM64 / 4 KiB 上，普通 `untrusted_app`
（UID 10284、`CapEff=0`、`Seccomp=2`、SELinux Enforcing）对 2.28.0 的
`PAGE_AP` 全调用者会话做了 5 轮 ×32 次采样：

- `ap-all` 的全部 5 个阶段 `trap=0/32`、`split=0`、`ap=0`；
- `KEYLESS227_ENTRY` 的每个阶段每轮 1,024 次长窗口试验全部
  `match=0`、`writes=0`（5 轮 ×5 阶段合计 25,600 次长窗口、25,600 次
  短窗口）；短窗口对照同样 `short_match=0`、`short_writes=0`；
- overlay 阶段 `file=direct=business=96964c4f`，活入口执行 `1235`；
- 2.27.0 的同一探针在同一设备上每轮是 `match=32`、`writes=1024`。

2.28.0 没有消除 `SITE_BRK` 的代码字特征、`PAGE_UXN` 的取指预约特征，
也没有消除非 all-callers 模式的 caller-window 分裂；这些是各模式的设计
语义，不是本轮要收口的 AP 读侧假成功。`ap`（非 all-callers）仍显示
`split=32`，与 2.27.0 相同。

## 设备与产物

| 项目 | 值 |
| --- | --- |
| 设备 | Pixel 6（oriole），Android 16，ARM64，4 KiB 页 |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` |
| KernelPatch | `c00` |
| SELinux | Enforcing |
| App | `untrusted_app`，UID 10284，`CapEff=0`，`Seccomp=2` |
| `urov-y.kpm` SHA-256 | `5e35571381dfdbade560d2a390bdd1cfb20200658e9454e4acc894a51e6185b0` |
| `urovdetect.apk` SHA-256 | `82360af1e0dc0b3f1982b73bffa19b9f89bdbd0e79b5f306ca6a8632de9a688e` |

## 完整矩阵

命令：

```powershell
python ./kpms/urov-lab/tools/run_crc_device.py `
    --serial $Serial --key $KpKey `
    --keyless-v228-detect --repeats 32 --cycles 5
```

`--keyless-v228-detect` 复用 2.27.0 的 App 模式前缀和
`KEYLESS_ENTRY_227` 探针集，只把期望值从“长窗口命中”改成“全部静默”；
App 不需要重新编译探针。完整结果：
[results/keyless228-detect-20261111-001129/summary.json](results/keyless228-detect-20261111-001129/summary.json)。

### `ap-all` 逐阶段（5 轮 ×32 次，合计 n=160）

| 阶段 | trap | entry match | entry writes | short match | split | file | direct | business | execute |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | ---: |
| clean | 0/160 | 0/5,120 | 0 | 0/5,120 | 0 | 96964c4f | 96964c4f | 96964c4f | 1234 |
| identity | 0/160 | 0/5,120 | 0 | 0/5,120 | 0 | 96964c4f | 96964c4f | 96964c4f | 1234 |
| patch_only | 0/160 | 0/5,120 | 0 | 0/5,120 | 0 | 96964c4f | 65806702 | 65806702 | 1235 |
| overlay | 0/160 | 0/5,120 | 0 | 0/5,120 | 0 | 96964c4f | 96964c4f | 96964c4f | 1235 |
| deactivated | 0/160 | 0/5,120 | 0 | 0/5,120 | 0 | 96964c4f | 65806702 | 65806702 | 1235 |

说明：

- `identity` 阶段登记了会话但镜像字节与原代码相同；2.28.0 没有读接管
  证据，符合“值不变但路径被接管”的旧基准。
- `patch_only` 是仅 Dobby 改码、无会话；`direct/business` 读到改码后的
  活字节 `65806702`，属于预期的 `CHANGED`，不是模块命中。
- `overlay` 阶段是会话活跃且 Dobby 改码：`file/direct/business` 三者都
  是 `96964c4f`，`execute=1235`，即“读发布字节、执行改码字节”。
- `deactivated` 注销后仍保留 Dobby 改码，读数回到 `65806702`，说明会话
  撤销后没有残留读覆盖。
- `crc_eligible` 在 `KEYLESS_ENTRY_227` 模式下固定为 0（App 只把活页
  CRC 作为诊断数据）；判定依据是 `trap`、`entry match/writes` 和
  `file/direct/business` 的相等关系。

### 其他模式

| 模式 | overlay 结果 | 解释 |
| --- | --- | --- |
| `brk` / `brk-all` | `trap=32/32`、`site_brk=1` | 读点指令被换成 `BRK`，设计定义的代码字特征 |
| `uxn` / `uxn-all` | `trap=32/32`、`site_fetch=1` | 读点页 UXN，取指异常，设计定义的取指特征 |
| `ap`（非 all-callers） | `trap=32/32`、`split=32` | 业务读与独立读者被调用窗口分开，作用域语义 |
| `ap-all` | `trap=0/32`、`split=0` | 全调用者模式，本文要收口的读侧 |

`brk`/`uxn`/`ap`（非 all）在 2.28.0 中仍是 2.27.0 的行为；它们不在
“AP 全调用者读侧假成功”的范围内，也没有因为入口回查的改动而回归。

## 2.28.0 关闭的探针

2.27.0 的探针在 `LDXR` 前放了 64 条 NOP，正好耗尽 64 条入口回查预算：

```asm
clrex
adr     x9, 1f
br      x9
.rept 64
nop
.endr
ldxr    x8, [x1]
1: bti  j
ldrb    w10, [x0]
stxr    w11, x8, [x1]
```

2.28.0 的回查不再在 64 条处停下：它继续走过 NOP，看到 `BR`，把
`(ldxr_pc, fault_pc]` 内的目标判为“可能跳过 LDXR”，计划放弃。硬件随后
原生执行 `STXR`，没有预约，返回失败；App 看到 `status=1`、哨兵保持
初值，与无模块一致。矩阵中 `short_match=0`、`match=0`、`writes=0`。

同函数内更长的填充，只要跳过分支落在 16,384 条预算内，同样会被走到；
分支在预算外时 2.28.0 选择拒绝而不是接受，因此最多产生假失败，不会在
无预约地址上制造成功。

## 仍然存在的读侧特征

2.28.0 **没有**消除以下三类假成功；它们是
[ELIMINATION_2_28_DESIGN.md](ELIMINATION_2_28_DESIGN.md) §5 的不可判定
核心：

1. **LDXR 与采样读之间的同步故障。** App 在 `LDXR` 后故意触发一次
   `SIGSEGV`，在信号处理器里跳过故障指令，再执行采样读。异常返回已经
   清掉预约；回推只看到指令字，看不到这次异常。模块仍可能代写
   `STXR` 成功。
2. **跨线程/跨 PE 写监视地址。** 另一个线程在 `LDXR` 与 `STXR` 之间
   写私有 scratch。硬件全局监视器让原生 `STXR` 失败；模块的软件模型
   看不到这次写，可能报成功。即使单步跟踪本线程，也无法原子地观察
   另一个 PE 的 store。
3. **跨函数/循环间接进入。** 分支可以放在回查路径之外：例如在
   `STXR` 之后用 `ADR; BR` 回到采样读，下一轮跳过 `LDXR`；或从另一个
   函数 `BR` 进采样读。线性回查和直接分支目标图都看不到这条边。

这三类都不需要读真值，也不需要计时阈值；它们只观察 `STXR` 状态和
哨兵。要把它们也消掉，需要硬件 branch record/ETM 或 hypervisor 级
监视器虚拟化，EL1 KPM 没有这些能力。详见设计文档 §5.3、§5.4。

## 真值读取的复核

同一设备上 `--read-defense-v225`（6 模式 ×4）与生产 CRC（7 模式 ×8）
用来复核“换指令读真值”不成立：

- `read-defense-v225-ap-all`：`accept=4/4`、`evidence=0/4`、
  `value=16/16`，所有采样访问形状（标量、`LDP`、`LD1..4`、跨页、
  `LDXR`、LSE、成对独占）都没有返回活页真值；
- 生产 `crc-ap-all`：`file=direct=window=f50bcaf6`，活页
  `backing=0c7da8a0`，执行 `1235`；
- `keyless-v226` 的六个前窗形状 `chain=adr=mrs=zva=cvac=long=0`；
- `process_vm_readv`/pipe/GUP/`/proc/self/mem` 的内核代读与 EL0 读
  一致，均为 image/快照字节。

因此“普通 App 用某条指定 EL0 指令读到真值”没有实现路径；审计探针读到
的是监视器状态，不是目标页字节。别名、内核代拷、DMA/GPU 和计时四条
非指令通道的边界见设计文档 §6.2。

## 复现

```powershell
./kpms/urov-lab/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py `
    --serial $Serial --key $KpKey `
    --keyless-v228-detect --repeats 32 --cycles 5
python ./kpms/urov-lab/tools/run_crc_device.py `
    --serial $Serial --key $KpKey `
    --keyless-v226 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py `
    --serial $Serial --key $KpKey `
    --read-defense-v225 --repeats 4 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py `
    --serial $Serial --key $KpKey --repeats 8 --cycles 1
```

完整矩阵结束时满足：KPM 清单为空、boot ID 未变、新增内核日志无
BUG/WARNING/Oops/panic；`summary.json` 中 `passed=true`。
