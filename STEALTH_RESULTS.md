# UROV-X 设备验证结果

后续复核发现了不依赖密钥和耗时阈值的活动页观察方法，见
[KEYLESS_DETECTION_RESULTS.md](KEYLESS_DETECTION_RESULTS.md)。本文保留原检测核心
的历史结果；“原核心不可判”不能推广为所有普通 App 检测均不可判。

日期：2026-11-04（Asia/Shanghai）。设计与实现见
[STEALTH_DESIGN.md](STEALTH_DESIGN.md)；被消除的特征点定义见
[DETECTION_RESULTS.md](DETECTION_RESULTS.md)。

## 1. 环境与交付物

| 项目 | 值 |
|---|---|
| 设备 | Pixel 6 / oriole，序列号 `25091FDF60063J` |
| 系统 | Android 16 / SDK 36，`BP31.250610.009` |
| 内核 | `6.1.134-android14-11-g66e758f7d0c0-ab13748739` / arm64 / 4 KiB 页 |
| KernelPatch | `0xc00` |
| 检测 App | `com.example.urovdetect`，UID 10284，`untrusted_app`、`CapEff=0`、`Seccomp=2` |
| 观察 App | `com.example.urovobserver`，UID 10287，权限同上 |
| 初始/最终模块列表 | 均为空 |

```text
c2a5c3d3bb272f4bd2db6205f69cd277739f6e32e5c6cd67cecf2b3e7f393575  urov-x.kpm
16b86f80c8799c1d00aab650e553955fe8955459c6d6f6f23037c16005e1c1cf  urov-lab.kpm
9d3a5cc64f57a37e5ed0f324b502cc0688e8b8571aa612faf3052bcd42160f9b  urovdetect.apk
e884915ed92f88f2b02381101ffff68c5aaa58aed9592880011705a3a3ce856e  urovobserver.apk
```

正式运行（同一最终构建，连续两次）：

| 运行 | 结果 | 检查项 | App 运行数 | 原始结果 |
|---|---|---|---|---|
| `stealth-20261104-222126` | PASS | 22/22 | 11 | [summary.json](results/stealth-20261104-222126/summary.json) |
| `stealth-20261104-222219` | PASS | 22/22 | 11 | [summary.json](results/stealth-20261104-222219/summary.json) |

两次运行都是完整矩阵（3 个活动周期 + 无密钥 + 原模块对照 + SIMD + fork +
owner/observer + 运行中卸载 + 卸载后复检）。`results/` 下其余 `stealth-*` 目录是
开发过程中的旧构建或脚本修订记录，均非模块缺陷：

- `-221223` / `-221302`：运行器断言解析缺陷（字符串匹配写错、Python
  `int("01", 0)` 失败）；
- `-221406` / `-221522`：早期 `urov-x.kpm`（`678e1ad2...`）构建，结果相同；
- `-221809` / `-221901`：最终 KPM + 旧 APK 构建，结果相同；
- `-222032`：运行器把 owner 自己的 `hits` 递增误当成 observer 干扰（本轮起
  owner 在 hold 期间持续读取站点，`hits` 本应递增）。

## 2. 同一设备上的前后对照

### 2.1 原 `urov-lab` 仍被原检测核心识别

`02-original-detected`：加载 `urov-lab.kpm active` 后运行未修改的 `active` 矩阵，
23 个用例全部 PASS，检测核心给出的结论是"命中"：

```text
NATIVE_RESULT PASS cases=23 assertions=4336 failures=0 module=1 scope=0 integrity_diff=0
CASE active_8_A result=PASS n=30 ctl=1 scope=1 caps=0xeb7 file=1 dc=0 rr=1 diff_at=4 ...
```

| 证据 | 值 |
|---|---|
| 控制通道指纹（`module=`） | **1（命中）** |
| 看到 SELF 归属的用例 | 23/23 |
| 看到"读取/文件差异"的用例 | 8（如 `file=1, diff_at=4`） |
| smaps | `dc=0, rr=1`（FP-4 现场） |

### 2.2 `urov-x` 在同一检测核心下不可判

`04-stealth-active-*`（每个正式运行 3 个周期，典型读数）：

```text
UX_PROOF control=0 scope=-1 file_diff=0 rounds=3 smaps_dc=0 smaps_rr=0
         site=0x8877665544332211 file_word=0xf2aaacc1d28ef101 watch=0x01
         hits_delta=2 read_us_base=0 read_us_active=83
```

| 特征点 | 检测核心原始判据 | `urov-x` 实测 | 结论 |
|---|---|---|---|
| FP-1 通道指纹 | 有效 QUERY 成功且 ABI 一致；错误 magic 原生 `EINVAL` | `control=0`（`UD_NO_MATCH`），`scope=-1`；legacy/错 MAC 调用均为原生 `EINVAL` | 不可判 |
| FP-2 会话归属 | `INACTIVE + last_error=-EBUSY` 表示他人会话 | 未认证调用根本不进入分发；观察者只看到 owner 自身读取造成的 `hits` 增长，其余状态逐字相同 | 不可判 |
| FP-3 读取/文件差异 | 标量读取与文件三轮稳定且不等 | `file_diff=0`、`rounds=3`；`watch=0x01` 与 `file_word` 低字节一致；站点读到 `0x8877665544332211` | 不可判 |
| FP-4 smaps | `rr=1` | `smaps_dc=0 smaps_rr=0` | 已消除 |
| FP-5 门控 EBUSY | 相交 mprotect 返回 `EBUSY` | `mprotect(PROT_READ\|PROT_EXEC)` 返回 0 且会话静默结束 | 已消除 |
| FP-7 不支持指令 | 受保护页上的 SIMD 读取 `SIGSEGV` | `LDR Q0` 读到真实字节，会话静默结束，无信号 | 已消除 |
| fork 继承 | 子进程读取失败 | 子进程读到文件字节并正常退出（`x-fork` PASS） | 已消除 |
| FP-6 耗时 | 异常成本 | 64 字节标量读取：原生 0 µs，活动期 59–118 µs（两轮共 6 个周期） | **仍可测** |

功能侧同时成立：授权站点（`ux_site_ldr`/`ux_site_ldrb`）读到伪值，`SET` 后
立即变成新伪值；未授权站点（`ux_watch_ldrb`、普通 `LDRB` 循环）读到文件字节；
同页取指仍执行原始机器码（`fn(x) == x ^ 0x1122334455667788`）；并发业务线程
0 错误；`hits` 只随被模拟的 load 递增（两次授权读取恰好 +2）。

## 3. 无密钥 / 跨 UID / 生命周期

| 场景 | 结果 |
|---|---|
| `urov-x` 已加载，App 不带密钥（`03-stealth-loaded-unkeyed`） | PASS：`control=0`，派生出的错误 selector 返回原生 `EINVAL`，legacy `prctl` 通道 `EINVAL`，无 `UX_PROOF` |
| owner 持有活动会话（`x-hold`） | `state=active sites=2 hits=… failures=0`，`HOLD_READY`；hold 期间每 100 ms 经授权站点读一次页面 |
| 另一 UID（10287）观察（`07-observer-other-uid`） | PASS：看不到任何会话/状态差异 |
| observer 前后 owner 状态 | `state/sites/failures/hooks` 逐字相同；`hits` 仅由 owner 自身读取增长（3 → 21） |
| owner 持续读取期间卸载模块（`07-owner-unload-restored`） | PASS：`HOLD_UNLOADED restored=1`，页面恢复原值，无信号 |
| 卸载后复检（`08-post-unload-clean`） | PASS：回到与空设备一致的结论 |
| `x-simd`（`05`） | PASS：未授权向量读取正常返回真实字节，随后会话静默结束、页面恢复 |
| `x-fork`（`06`） | PASS：子进程读取一致并退出码 0，父进程会话与站点覆盖保持 |

模块状态（`ctl0 status`）：

```text
mode=site-bound state=inactive sites=0 hits=0 failures=0 hooks=0x1f core_checks=4139
```

`hooks=0x1f` = `do_mem_abort | prctl | 4 个映射 | clone | clone3`；`core_checks=4139`
是复用的软件自测门槛。

## 4. 内核侧检查

- 两次正式运行的 `kernel-new.log` 中没有 `BUG/WARNING/Oops/panic/RCU stall/hung task`。
- 唯一 `avc: denied { execmod }` 来自原 `urov-lab` 对照组的
  `ordinary_private_patch` 负向夹具（DETECTION_RESULTS 4.3 已记录的 SELinux
  execmod 拒绝），与本模块无关。
- 运行结束 `kpm list` 为空；App 被 force-stop；`urov-x` 的 init 默认不打印日志
  （未使用 `verbose`），对照组的 `urov:` 行只来自原模块。

## 5. 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_stealth_device.py `
    --serial 25091FDF60063J --key <SUPERKEY> --module-key <32-hex-secret>
```

脚本只用 root 装卸模块和读取内核状态；两个 App 始终是无 root、无 capability、
`Seccomp=2` 的 `untrusted_app`。密钥不写入结果文件（日志中的 `<KEY>` /
`<MODULE-KEY>` 由脚本替换）。
