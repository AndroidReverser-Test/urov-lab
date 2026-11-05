# 同进程 SO 改码与 UROV-Y CRC32 复核

2026-11-05，在 Pixel 6（Android 16、arm64、内核 `6.1.134-android14-11`、SELinux `Enforcing`）上测试。检测 App 通过 `dlopen` 加载随 APK 打包的 `liburov_crc_patch.so` 模拟同进程注入。测试 SO 负责变更专用页和发送认证的 `prctl` 请求。CRC 与无密钥探针在 App 的 `untrusted_app` 工作线程运行。设备端 root 用于装卸 KPM 和核对状态。[测试夹具](apps/urov-detect/crc_fixture.inc) · [测试 SO](apps/urov-detect/crc_patch_fixture.c)

> 2026-11-05 后续：下文“原地修改普通 ELF 代码页”记录的是当时 `urov-y` 的负向结果。
> 该限制现已解除：后端接受普通 app `.text` 中的一页（私有、多页 VMA、带
> `VM_MAYWRITE`），新增的 `crc-ap-text` / `crc-ap-libc` 场景在真机上验证通过。
> 注册条件的变化、测试方法与数据见下文“普通 app 正常代码段（私有多页 `.text`）”。


## 原地修改普通 ELF 代码页

三个 `crc-ap` 进程都先成功发送认证 `QUERY`。随后把 linker 加载的原始 `.text`（本次 VMA 为 81,920 字节）和同一代码的独立 4,096 字节 `MAP_PRIVATE` RX 别名分别提交注册，均返回 `EINVAL`。单页别名的 `VmFlags` 仍有 `mw`。当时后端要求整个 VMA 恰好一页、文件后备、当前为 RX，并拒绝 `VM_MAYWRITE`，所以仅将普通私有代码页拆成一页仍无法注册。[VMA 校验](urov_y_backend.c) · [Android 6.1 mmap 权限处理](https://android.googlesource.com/kernel/common/%2B/refs/tags/android14-6.1-2023-12_r14/mm/mmap.c)

测试 SO 在私有别名上把 `mov w0, #0x1234` 改成 `mov w0, #0x1235`。写入成功，直接 CRC 变为 `0c7da8a0`。在本设备上，写后恢复 RX 返回 `EACCES`，内核审计为 `execmod`，夹具跳过该别名的执行。再次注册改后的私有页仍返回 `EINVAL`。因此当时的 KPM 无法给这种普通私有代码页建立覆盖会话，即使注入代码持有有效密钥。[私有页 App 日志](results/crc-20261105-222216/crc-ap-1-18739.log) · [设备审计增量](results/crc-20261105-222216/kernel-new.log)

## 框架接受注册时的改码模拟

测试 SO 用 APK 内预置的修改版文件页替换 App 专用 RX 别名。两版只差一条 4 字节指令，替换前后函数虚拟地址相同。替换后可执行映射为单页文件后备 RX，符合当时的注册条件。这个正例验证读取伪装对实际执行已改变的页是否有效，模拟方式是同址重映射。原 ELF 文件偏移与映射偏移此时不同，原 `ud_check_views()` 按旧偏移核验得到 `UNKNOWN/ESTALE`。[同址替换日志](results/crc-20261105-222216/crc-ap-all-1-18817.log)

CRC32 校验覆盖 `BTI C`、`MOV`、`RET` 共 12 字节，原文件 CRC32 为 `f50bcaf6`，修改版为 `0c7da8a0`。两条内存读路径都先逐字节执行 `LDRB`，再对普通栈缓冲计算 CRC32。控制请求把原始前 8 字节作为伪值，覆盖包含修改指令的范围。每个场景分别校验原文件、实际执行、独立标量读、直接调用同一读点及经注册包装函数读取。[App 检测实现](apps/urov-detect/crc_fixture.inc)

| 场景 | 函数返回 | 独立读取 CRC32 | 注册路径 CRC32 | 无密钥观测 |
| --- | ---: | --- | --- | --- |
| 原页 | `0x1234` | `f50bcaf6` | `f50bcaf6` | AP 探针 0/210 |
| 仅修改 | `0x1235` | `0c7da8a0` | `0c7da8a0` | AP 探针 0/210 |
| `SITE_BRK`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | 读取点指令字差异 3/3 轮 |
| `PAGE_UXN`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | 读取点页取指 canary 45/45 |
| `PAGE_AP`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | AP 探针 45/45 |
| `PAGE_AP`，`caller_count=0` | `0x1235` | `f50bcaf6` | `f50bcaf6` | AP 探针 45/45 |
| 注销覆盖 | `0x1235` | `0c7da8a0` | `0c7da8a0` | AP 探针 0/180 |

在 `caller_count=0` 的 AP 用例中，覆盖范围内的独立 `LDRB` 也得到原字节，单独比较 CRC 与原文件会漏掉实际修改。把上一轮独占代写探针放在同页的 `RET` 首字节（偏移 `+8`，覆盖窗口外）仍然命中。若改采样 `MOV` 的变更字节（偏移 `+4`），目标返回的原字节与真实后备文件的修改字节不同，探针按对照不一致返回 `UNKNOWN/EAGAIN`。这两项均在三轮复现。[AP 全调用者样本](results/crc-20261105-222216/crc-ap-all-1-18817.log) · [有调用窗口的 AP 样本](results/crc-20261105-222216/crc-ap-1-18739.log)

共 14 次 App 运行。四个活动模式各测 3 轮，每轮各阶段重复 15 次。AP 探针在已知稳定字节上阳性 90/90，其他场景阳性 0/690。各活动会话 `failures=0`。注销后在同一进程复测，读路径恢复看见修改字节。原有三模式装卸检测矩阵也在新版 APK 上通过回归。最终 KPM 列表为空，实验增量无内核 BUG、Oops 或挂起。[CRC 机器结果](results/crc-20261105-222216/summary.json) · [原有矩阵回归结果](results/eliminate-20261105-222459/summary.json)

结论的范围是当前 KPM、App 自有且已知的代码映射与检测路径。CRC 表示选定路径返回的字节，AP 探针表示采样页触发了代写语义。其他能篡改同进程检测逻辑的注入方式和未采样页仍需单独验证。

## 普通 app 正常代码段（私有多页 `.text`）

### 注册条件

`urov-y` 的目标只被读取，三种模式都不写目标页的字节或 VMA：BRK 改写读取点页，
UXN 改读取点页 PTE，AP 只清目标页叶子 PTE 的 `AP[1]`。因此目标不再要求“整个 VMA
恰好一页、无 `VM_MAYWRITE`”的专用映射，新规则为：

```text
目标页完全落在 VMA 内                                      start <= address && end - address >= 4096
VMA 可读、可执行、当前不可写                                VM_READ | VM_EXEC，无 VM_WRITE
无 PFNMAP / HUGETLB / VM_IO / MIXEDMAP
文件后备                                                    vm_file != NULL
共享 VMA（VM_SHARED）仍只接受恰好一页、无 VM_MAYWRITE 的专用别名
私有 VMA 允许 VM_MAYWRITE、允许多页                          linker 的普通 .text 形状
```

私有页没有第二个写者；会话期间与目标页或读取点页相交的
`mprotect/munmap/mremap/mmap(MAP_FIXED)/madvise` 仍会先结束会话，`execve`
直接结束会话，所以注册后页不会被应用的常规映射操作换成另一个页。注册事务先
用 `access_remote_vm()` 把目标页 fault-in 并取快照，再在 `mmap_write_lock` 下
复核 VMA/PTE；若在持锁窗口内 PTE 被回收则重新 fault-in 重试。AP 模式在
`handle_mm_fault` after-hook 中重新清 `AP[1]`，因此文件页被回收后重新装入仍
保持数据陷阱。

### `crc-ap-text` 场景

测试把 **linker 加载的真实 `.text` 页**（不是 MAP_SHARED 别名）注册为 AP 目标：
`&crc_original` 位于 `liburovdetect.so` 的可执行 PT_LOAD 内，本次 VMA 为
90,112 字节、文件偏移 0x6000、`r-xp`、`shared=0`、`maywrite=1`、`dc=0`，页的
`Private_Dirty=0`、`Anonymous=0`。伪值取同库相邻页 `crc_patched` 的前 8 字节
（`BTI C; MOV w0,#0x1235`），真实页仍是 `BTI C; MOV w0,#0x1234; RET`。

| 观测 | clean | AP 覆盖中 | 注销后 |
| --- | ---: | ---: | ---: |
| `crc_original` 执行返回 | `0x1234` | `0x1234` | `0x1234` |
| 业务窗口 `uy_business_ldrb` 读 12 字节 CRC32 | `f50bcaf6` | `0c7da8a0` | `f50bcaf6` |
| 裸站点 `uy_site_ldrb` 读 CRC32（窗口外） | `f50bcaf6` | `f50bcaf6` | `f50bcaf6` |
| 直接 `LDRB` 拷贝 CRC32 | `f50bcaf6` | `f50bcaf6` | `f50bcaf6` |

每次运行 15 轮，覆盖期间 `hits=180`（15×12 字节，全部来自业务窗口）、
`replays=360`（裸站点与直接读各 180 次）、`failures=0`；`generation=1`。
覆盖中重新读取 `/proc/self/smaps`：VMA 起止、文件偏移、`rwx`、`shared`、
`maywrite` 与覆盖前一致，`Private_Dirty`/`Anonymous` 仍为 0，说明只改了叶子
`AP[1]`，没有 COW、没有改代码页、没有新增映射。

### libc 读者与嵌套调用

新增 `crc-ap-libc`：仍注册真实 linker `.text` 页，伪值窗口扩展到 32 字节
（字节 0–11 为修改版 payload，12–30 为 `0x41`，31 为 0），调用者窗口只覆盖
`crc_libc_business()`。覆盖中由该函数通过 libc 读取目标页：

| 读取方式 | 结果 |
| --- | --- |
| `memcpy(copy, target, 12)`（bionic 标量路径） | `copy` 得到伪字节 |
| `memcmp(target, fake, 32)`（bionic 标量路径） | 0 |
| `memcmp(target, original, 32)` | 非 0 |
| `strlen(target)`（前 32 字节标量） | 31（fake 在 +31 的终止符） |
| zlib `crc32(0, target, 12)`（直接读页） | `0c7da8a0` |
| zlib `crc32(0, copy, 12)`（读 `memcpy` 后的缓冲） | `0c7da8a0` |

`memcpy`/`memcmp`/`strlen` 在 bionic 中是叶子函数，load 处的 `x30` 就是
`crc_libc_business` 内的返回地址，直接命中调用者窗口。zlib `crc32` 会先调用
内部 helper，load 处的 `x30` 落在 libz 内；后端新增 `caller_allowed_deep()`，
在直接 LR 不命中时用 `x29` 帧链最多回溯 16 层，用 nofault 读
`[x29]`/`[x29+8]`，找到保存的、落在业务窗口内的返回地址。没有帧指针的代码
自然退回原来的“只看当前 LR”行为。

`crc-ap-libc` 每次运行 15 轮，`hits=360`、`replays=504`、`failures=0`；
窗口外直接读/裸站点读仍为 `f50bcaf6`，执行仍返回 `0x1234`，注销后恢复。
该场景证明的是**标量 libc 路径**：bionic 的 `memcpy` 在 16 字节起、`memcmp`
在 160 字节起、`strlen` 在越过前 32 字节后会使用 SIMD `LDR q`/`LDP q`；
这些大范围路径仍按 fail-closed 处理（SIGSEGV），不在本次解决范围。内核辅助
读取（`/proc/self/mem`、ptrace、`process_vm_readv`）也仍看到真实字节。

### 真机结果

2026-11-05 在 Pixel 6 上运行
`run_crc_device.py --repeats 15 --cycles 3`：3 个 cycle ×
（`crc-brk`、`crc-uxn`、`crc-ap`、`crc-ap-all`、`crc-ap-text`、`crc-ap-libc`）
加 `crc-clean` 两轮共 20 次运行全部 PASS。`crc-ap-text` 三次运行均为
`execute=1234 / window=0c7da8a0 / direct=f50bcaf6 / failures=0`；
`crc-ap-libc` 三次均为 `hits=360 / replays=504 / failures=0`，
memcpy12/memcmp32/strlen31/zlib CRC 全部通过。
原有三种模式、`crc-ap` 的私有单页别名正例以及写入后 `VM_WRITE` 仍返回
`EINVAL` 的负例同时通过。最终 `kpm list` 为空，内核增量无 BUG、Oops、WARN
或挂起（[机器汇总](results/crc-20261106-002515/summary.json)）。另外在 root
夹具 `urov_y_test --mode ap` 上回归 33 项断言（含 fork、映射门控、注销恢复）
全部通过。

残余：目标页若是之前已被 COW 的私有页，页不再来自文件，但内容在会话期间仍
受映射门控保护；通过 `/proc/self/mem`、ptrace、`process_vm_readv` 的内核辅助
读仍看到原字节；AP 模式的同步异常时间特征仍在（与 §10.7 相同）。

## 复现

在仓库根目录运行。脚本为每次矩阵生成临时模块密钥，复用设备上 `/data/local/tmp/kpatch`，生成 App 日志、机器汇总及内核增量。

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 15 --cycles 3
```
