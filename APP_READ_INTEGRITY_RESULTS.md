# UROV-Y 2.5.0 读取完整性复核结果

2026-11-07，Pixel 6（oriole），Android 16，内核 `6.1.134-android14-11`，4 KiB 页，
KernelPatch `0xc00`。测试 App 在 `untrusted_app` 域运行（`CapEff=0`、`Seccomp=2`），
root 只用于装卸 KPM。被测构建：

```text
urov-y.kpm      8290c5c5602132ddbd9afe9ad1fd6171020c3d5d76ae9c963cfe775779d93088
urovdetect.apk  6cec15beab4e23d74a1c4c0408e5aab51b09f1e2348d726a63bb5d06a396f3a8
```

## 本轮改动

`APP_READ_INTEGRITY_AUDIT.md` 第 1 条检测针对 `PAGE_AP`：

```asm
ldxr x9, [x1]      ; thread-private scratch
ldrb w10, [x0]     ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]  ; native failure because ERET cleared the monitor
```

2.5.0 在 AP 数据异常返回路径中恢复相邻 LL/SC 桥，但只对满足以下条件的序列
生效：

1. 故障 PC 前一条是 `LDXR/LDAXR`，后一条是 `STXR/STLXR`，两者宽度、基址
   `Rn`、数据寄存器 `Rt` 一致；
2. `Rn != XZR`、`Rt != XZR`，`Rn` 自然对齐，中间 load 不写 `Rt`/`Rn`；
3. `Rt` 仍等于 `[Rn]`（`LDXR` 执行存证，按宽度零扩展）；
4. 待写值等于 `[Rn]` 当前内存，`copy_to_user_nofault` 能写回。

满足后，在 load 模拟成功之后由 handler 写回同一值、`Ws=0`、跳过 `STXR`；
`STLXR` 追加 `dmb ishst`。分支或 `CLREX` 跳过 `LDXR` 的序列不满足第 3 条，
保持原生失败且零写入。实现见
[urov_y_backend.c](urov_y_backend.c) 的 `uy_llsc_prepare()`/`uy_llsc_commit()`，
设计与残余见 [ELIMINATION_DESIGN.md §14](ELIMINATION_DESIGN.md#14-第六轮相邻-llsc-桥的执行存证恢复)。

## 审计特征点现状

| 审计条目 | 2.5.0 `PAGE_AP` 状态 |
| --- | --- |
| 1. `LDXR/LDRB/STXR` 独占探针 | 紧邻且执行存证成立的序列由桥完成，`STXR` 成功，`MATCH=0`；非紧邻/成对/`Xt=XZR` 是残余。 |
| 2. BRK 代码字 / UXN 取指 canary | AP 不改代码页、不改取指权限，不适用；代码字与 `smaps` 仍等于基线。 |
| 3. 业务读者/独立读者差异 | Dobby 夹具使用 `caller_count=0`（所有读者拿同一伪视图），`reader_diff=0`；带调用窗口的 `crc-ap` 仍按设计只让窗口内读者拿伪值。 |
| 4. 基础版固定 `prctl` 指纹 | `urov-y` 使用每次加载派生的 option/MAC，固定 magic 之外无可用指纹；未认证请求仍是原生 `EINVAL`。 |

## Dobby 矩阵（审计原场景）

`run_crc_device.py --dobby-detection --repeats 24 --cycles 5`，5 轮活动运行。
同一 APK、同一夹具：Dobby 把执行返回值由 `0x1234` 改为 `0x1235`，`PAGE_AP +
SRC_FILE` 把 32 字节代码读取改回文件字节。

| 阶段 | 执行返回值 | 内存 CRC32 | 独占探针 MATCH | 采信 CRC 通过 |
| --- | --- | --- | --- | --- |
| 原始代码 | `0x1234` | `96964c4f`，等于文件 | 0/24 | 24/24 |
| 仅 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |
| 改码后 `PAGE_AP + SRC_FILE` | `0x1235` | `96964c4f`，等于文件 | **0/24** | **24/24** |
| 注销覆盖，保留 Dobby 改码 | `0x1235` | `4e9e8cbc`，与文件不同 | 0/24 | 0/24 |

5 轮合计 120 次活动探针、11,520 个被接受的目标三元组：`target_failed=0`、
`control_failed=0`、`unknown=0`、`accepted_crc=120/120`。每轮
`DOBBY_DETECT_STATUS hits=3264 failures=0`；单次探针平均约 2.9 ms，最大约 3.0 ms。
2.4.1 的同一矩阵是 `match=120/120`、`accepted_crc=0/120`。

## 消除矩阵与计数器

`run_elimination_device.py --repeats 6 --cycles 1`：12 次运行全部 PASS，包含
`urov-x` 阳性对照、三种 Y 模式、不同 UID 观察和活动期卸载。

- `w-active` 的 `active_page`、`active_outside_window`、`active_after_set`、
  `active_equal_value` 均为 `exclusive_match=0`、`exclusive_clean=6`；
  `ud_observe_unreserved_store` 全部 `match=0`、`stores=0`。
- 8 个 CPU 的 store 探针全部 0 写入。
- `ELIM_RESIDUAL mode=ap`：`site_file_word == site_live_word`，
  `site_cow_private=0`，`Private_Dirty/Anonymous` 与基线一致。
- `ELIM_FEATURE business_reader=1`：窗口内的业务调用仍拿到伪值
  `0x8877665544332211`，窗口外 `direct == file`。

另以 `w-active --repeats 200` 启动，在活动期轮询 `ctl0 status`：

```text
mode=data-ap state=active armed=1 hits=2009 replays=61547 failures=0 llsc=42952 ...
```

`llsc=42,952` 证明桥确实在异常路径完成了 store，而不是让原生 `STXR` 偶然成功。

## 回归

| 矩阵 | 结果 | 结果目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS，120/120 采信 CRC，MATCH 0 | [dobby-detect-20261107-140230](results/dobby-detect-20261107-140230/summary.json) |
| 消除矩阵 6×1 | PASS，12 次运行 | [eliminate-20261107-140259](results/eliminate-20261107-140259/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-140417](results/crc-20261107-140417/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-140448](results/multipage-20261107-140448/summary.json) |

所有矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。
`crc-ap`（业务窗口）仍保持 `direct=backing/window=file`，`crc-ap-all` 则是
`direct=window=file`；说明桥没有改变窗口语义。

## 残余

1. 桥只覆盖紧邻三条指令；`LDXR; NOP; load; STXR`、跨基本块、函数调用、成对
   `LDXP/STXP` 仍会看到目标 `STXR` 失败。
2. 调用者先读 `[Rn]`、把 `Rt` 预置为同一值、再分支跳过 `LDXR`，仍可让桥代写；
   由于待写值等于内存，该路径只改变 `Ws`，不改变内存。现有
   `ud_observe_unreserved_store` 探针不预置该值，保持 `match=0`、`stores=0`。
3. `Xt=XZR`、非自然对齐、不可写 `[Rn]` 不桥，按原生路径失败。
4. 仍是每次读取一次同步异常；时间特征与 2.4.1 同量级。PTE 重装窗口、root
   可见性、注册事务窗口仍在。
5. 带业务调用窗口的模式仍是有意保留的 API 语义：窗口内读者拿伪值，窗口外
   读者拿重放快照。Dobby 场景使用 `caller_count=0`，因此不存在读者差异。

## 复跑

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --dobby-detection --repeats 24 --cycles 5
python kpms/urov-lab/tools/run_elimination_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 6 --cycles 1
python kpms/urov-lab/tools/run_crc_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 5 --cycles 1
python kpms/urov-lab/tools/run_multipage_device.py --serial <SERIAL> --key <KP_KEY> `
  --repeats 3 --cycles 1
```
