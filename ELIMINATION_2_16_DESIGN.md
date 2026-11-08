# UROV-Y 2.16.0：GUP 读、成对独占、mremap 保活与写形状补全

本文是 `urov-y` 2.16.0 的设计说明。目标是把
[APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 2.15.0 节
“普通 App 读实页与撤销会话”列出的、不需要密钥即可稳定复现的读侧/写侧特征
消掉，同时不引入新的 App 可观察特征。只改 `urov-y` 与测试 App/测试夹具，
`urov-lab`、`urov-x` 不动；ABI 仍为 v8，`hooks=0xff`、请求布局、`ctl0`
字段和返回码不变。

## 1. 输入：2.15.0 仍成立的特征

2.15.0 已让 EL0 读、`process_vm_readv`、`/proc/<pid>/mem`、`ptrace` 和普通
store 看到同一镜像。复核后，普通 App 仍可无密钥复现：

| # | 2.15.0 行为 | App 侧用法 | 2.15.0 证据 |
| --- | --- | --- | --- |
| F1 | `vmsplice()` 走 `get_user_pages_fast()`，直接引用活页，不经过 EL0 异常或 `__access_remote_vm` | 把目标页 `iovec` 送入 pipe，再读 pipe；得到 Dobby 改码后的真实字节 | `READ_DEFENSE ... match=8/8`、`guarded_accept=0` |
| F2 | `LDXP; LDRB; STXP` 的成对独占没有桥接；`ERET` 清本地监视器，目标 `STXP` 必然失败 | 预置线程私有 scratch，执行成对探针；目标/对照 `status` 不同 | `READ_DEFENSE_PAIR ... match=1`、`target_ok=0` |
| F3 | 等长 `mremap(page,page,page,0)` 在 Linux 返回原地址前先 `release_session()` | 对已登记页做 no-op `mremap`，随后普通读；得到真实改码字节 | `READ_DEFENSE_REMAP stage=overlap`、`inactive_after=1` |
| F4 | 第一次真实 store 后的写形状只覆盖 2.15 的 11 种：原子 RMW（`LDADD`/`SWP`/`CAS`/`CASP` 等）、`STXR`/`STXP` 写注册页、跨页 store 仍让该页 `dead` | 对注册页做原子 RMW 或 `str` 跨页写，再读；得到真实字节 | 2.15 设计 §5 第 2 条 |
| F5 | fork 子进程 `mprotect(RW)` 后写自己的 COW 拷贝；子进程读真实页 | fork、子进程 `mprotect(RW)`、写一个字节、读整页 | 2.15 设计 §5 第 1 条 |
| F6 | 代码页被 `mremap` 后重新扫描时，`copy_from_user_nofault()` 在 PAN 下按 EL0 权限执行，读到 `AP[1]=0` 叶会失败；分支位图被标成不完整 | `mremap` 代码页后执行 AP 独占探针 | 2.16 开发中复现：`mremap code ... complete=0`，随后 pair `target_ok=0` |

F1/F2/F3 是 2.15.0 结果文档“无密钥检测与保护”直接列出的三条恢复/检测
路径；F4/F5 是 2.15 设计 §5 的残余；F6 是修 F3 时新暴露的实现细节，不是
新增外部特征。

## 2. 威胁模型

生产 CRC 的输入仍只有两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe。
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、
   崩溃、系统调用返回值。

2.16.0 不声称消除每次读一次同步异常的耗时，也不消除 root 通过
`kpm list`/`ctl0 status` 看到模块的能力；这两项不在普通 App 的 CRC 输入
集合内。其余普通 App 可无密钥复现的稳定字节差异/恢复路径，本轮逐项处理。

## 3. 方案

### 3.1 GUP fast 读：vmsplice 与 pipe

`get_user_pages_fast()` 是 `iov_iter_get_pages2()` 的入口，`vmsplice()`
把用户页 pin 进 pipe 后由 `pipe_read()` 直接拷贝。它既不触发 EL0 数据
异常，也不经过 `__access_remote_vm()`，因此 2.15 的三个读入口都看不到。

2.16.0 在 `get_user_pages_fast()` 上加 after hook：

1. 只处理 `current->mm` 属于会话（owner）或带有本模块陷阱叶的 fork 子进程；
2. 跳过 `FOLL_PIN`/`FOLL_LONGTERM`（这些调用要求精确的用户页）；
3. 对返回数组里覆盖注册页的项，分配一个 order-0 页，用
   `copy_highpage()` 从页镜像复制整页，`put_page()` 原来的 GUP 引用，
   把数组项替换为镜像页；
4. 调用者按 GUP 约定在释放时 `put_page()` 镜像页；镜像页归 pipe 所有，
   模块卸载/会话结束后仍安全。

`vmsplice()` 的 `FOLL_WRITE` 是 `iov_iter` 为源页强制 COW 设置的，不是
写目的页；真正的 GUP 写者（`ptrace`/`/proc/<pid>/mem`）走
`access_remote_vm()`，不经过这个 fast 入口。GUP 没有调用者 PC/LR，无法
逐次判断 caller window；因此 `caller_count>0` 时返回 `snapshot`（窗口外语义），
只有生产用的 `caller_count=0` 才返回 `image`，不扩大伪造窗口。测试覆盖
32 字节 pipe 读取，两次采样逐字节等于文件页。

### 3.2 成对独占：LDXP/LDAXP; load; STXP/STLXP

在 `uy_llsc_prepare()` 的单寄存器桥之后增加成对桥：

1. 从故障 load 的 `PC-4` 起 0–3 条 `NOP` 内找 `LDXP/LDAXP`；
2. 从 `PC+4` 起最多 8 条内找 `STXP/STLXP`，间隔只允许 `NOP`/`BTI`；
3. 校验 `size`、基址、两半数据寄存器、状态寄存器一致，基址按 2×size
   对齐，故障 load 不覆盖这些寄存器；
4. 用 `copy_from_user_nofault()` 读回 16 字节，要求 `LDXP` 的两半结果仍等于
   内存（执行存证）；两半都是 `XZR` 时改用直接分支位图 + GPR 间接目标门控；
5. 提交时写回 `STXP` 自己的两个值、状态寄存器置 0、PC 设为 `STXP+4`。
   提交值若落在注册页，同步镜像/快照或 fork 影子镜像并重装 `AP[1]=0`。

这与 `LDXR` 单桥使用同一组控制流证据，避免把“分支跳过 `LDXP`”误判为成功。

### 3.3 mremap/munmap/MAP_FIXED：按页保活而不是整会话拆除

2.15 的映射门控把任何重叠映射调用都当成会话结束。2.16.0 改成：

- **等长 `mremap`（flags=0）**：Linux 会返回原地址；after hook 只更新
  VMA 范围，不拆除会话。目标页的 PTE 陷阱原样保留。
- **移动 `mremap`**：PTE 随页表移动；after hook 用返回地址更新每个
  `uy_page.base`、`vma_start/end`，重新排序页数组；被缩小掉的页标 `gone`。
- **`munmap`/`MAP_FIXED`**：成功后只把落在范围内的页标 `gone`、清
  `want/armed`，整个会话与其余页继续 ACTIVE；`page_find()` 跳过 `gone`。
- **代码页移动**：`uy_code_mremap()` 按整段移动分支位图区域的
  `start/end`，不释放旧 arena；只有部分区域移动或目标地址已有代码区域时
  才把位图标为不完整，桥 fail-closed。

`MAP_FIXED` 覆盖后新映射的字节来自 Linux 的新 VMA（通常是文件原始页），
不再属于旧镜像；把该页退役是语义正确的，不是可利用的真实字节泄漏。

### 3.4 LSE 原子 RMW、STXR 与跨页写

`decode.c` 新增 `uro_decode_atomic()`，支持：

```text
LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN（含 ST* 无返回形式）
SWP/SWPA/SWPL/SWPAL
CAS/CASA/CASL/CASAL、CASP/CASPA/CASPL/CASPAL
```

写异常先尝试原子解码，再尝试普通 store；读异常也先尝试原子解码（本机
CPU 把 `LDADD`/`CAS` 报成读异常）。处理步骤：

1. 校验地址、总宽度、自然对齐、目标 VMA 可写；
2. 从镜像读出旧值，按操作计算新值；CAS/CASP 比较失败时只把旧值写回
   `Rs/Rs+1` 并推进 PC，不写内存；
3. 通过内核 `FOLL_WRITE|FOLL_FORCE` GUP 路径写活页，发布到镜像/快照；
4. 把旧值按 W/X 宽度零扩展写回目标寄存器，推进 PC；
5. 立即重装 `AP[1]=0`，防止 GUP/COW 把叶改成可写可读叶。

普通 store 的跨页路径去掉“单页”限制：按页拆分写入并用每页 `seq`
发布；`DC ZVA`、`STP`、SIMD `ST1` 等原有形状继续支持。

如果写的是 `STXR/STLXR/STXP/STLXP` 本身（没有经过前面的桥），
`ERET` 已清本地监视器，原生结果必然是失败；handler 直接置状态 1、推进 PC、
不改页，因此探测不会让该页 `dead`。若 `STXP` 是桥的一部分，由 3.2 提交。

### 3.5 fork 子进程的私有镜像

fork 子进程的 COW 页不再是只读旁路：

1. `mprotect()` 的 after hook 对非 owner 的 mm 也检查文件身份，并把
   `AP[1]=0` 重新装回（`PROT_NONE` 保持原生不可读）；
2. 子进程第一次写注册页时，从固定池分配一页影子镜像，先复制当前 owner
   镜像，再按同一批字节更新影子；活页仍走 GUP COW；
3. 子进程读、`vmsplice`、`process_vm_readv`、内核辅助读都从影子镜像取字节；
4. owner 的镜像/快照完全不受子进程写影响；
5. 池满或没有影子时 fail-closed 到“只更新活页、读回 owner 镜像”，
   不会把子进程字节写进父镜像。

`ap_shadow_rearm()` 改用文件偏移而不是整段 VMA 相等来判断 fork 副本，
因此子进程 `mprotect` 拆分 VMA 后仍能在缺页回调里重装陷阱。

### 3.6 PAN 下的代码扫描

`copy_from_user_nofault()` 在 arm64 PAN 下执行 unprivileged load，会遵守
`AP[1]=0`。2.15 的 `uy_code_build()` 在装陷阱前扫描，所以没问题；
2.16 在 `mremap` 后重新扫描已装陷阱的代码页会失败并把位图标成不完整。
`uy_code_scan_page_buf()` 现在对已登记页直接读 `snapshot`，未登记页才走
`copy_from_user_nofault()`。这样代码页移动/重复扫描不会关掉成对桥。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 不新增/移动 VMA；`mremap`/`munmap`/`MAP_FIXED` 是 Linux 自己的行为，模块只更新内部页表状态；GUP 替换发生在 pipe 内部页，不进入进程映射 |
| 新的代码字/页表权限 | 仍只改叶 PTE 的 `AP[1]`；store/原子写的是 App 自己的值，镜像与活页同步；`MAP_FIXED` 后旧页退役，不伪造新映射 |
| 新的崩溃 | 不支持的形状仍退回 2.14 的按页退役；非法写仍原生 `SIGSEGV`；`PROT_NONE` 仍原生 `SIGSEGV` |
| 新的返回码/ABI | `mprotect`/`mmap`/`mremap`/`munmap` 返回值仍来自 Linux；ABI v8、请求布局、`ctl0` 文本、计数器、`hooks=0xff` 不变 |
| 新的 hook 可见性 | 只增加 `get_user_pages_fast` 一个 after hook；`hooks` 字段已满 8 位，文本不新增位；没有新 syscall hook |
| 新的线程/定时器/文件 | 没有 |
| 新的写语义 | 地址、宽度、值、写回、COW 都由原指令/内核决定；原子操作按 ARM 语义计算；影子镜像只服务子进程 |
| 新的计时台阶 | 读路径仍一次同步异常；GUP/原子只在对应系统调用/写异常上多一次复制/解码，与原路径同量级 |
| 独占探针被误报成功 | 仍要求控制流证据（直接分支位图 + GPR 间接目标）和寄存器执行存证；不满足就 fail-closed |

## 5. 真机验证

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB /
`6.1.134-android14-11` / KernelPatch `0xc00`。App 在 `untrusted_app`，
`CapEff=0`、`Seccomp=2`、SELinux Enforcing。

```text
urov-y.kpm      9d715b110ecf6b505fb7a7a7fa326f510cc93ddfca162371b749c297ef2283c8
urovdetect.apk  6d7b8ae8d123aaf7501f23074c20bc2534a6dc621b240267232377aa87d73b17
```

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| 加固读防御 8×1 | PASS；BRK/UXN/AP/AP-all 四种；AP 的 pipe 视图与 EL0 视图相等（`guarded_accept=8/8`）、`match=0`、pair `NO_MATCH`、等长 `mremap` 后 `active_after_remap=1` | [read-defense-20261108-134410](results/read-defense-20261108-134410/summary.json) |
| CRC 5×1 | PASS；`crc-ap-*` 的 direct/window 均等于镜像 | [crc-20261108-134434](results/crc-20261108-134434/summary.json) |
| 消除 3×1 | PASS；`ELIM_PROT ... store_absorbed=1`、`ELIM_PROT_STORE shapes=16`（含 LDADD/SWP/CAS/CAS-fail/STADD/CASP）、`ELIM_BRIDGE` 全 0、`site_call_ns≈340` | [eliminate-20261108-134502](results/eliminate-20261108-134502/summary.json) |
| 多页 3×1 | PASS；24 页/96 KiB、五条读路径、fork 子进程 | [multipage-20261108-134615](results/multipage-20261108-134615/summary.json) |
| Dobby 24×1 | PASS；`accepted_crc=24/24`、`ap=0/24`、`views=0/24` | [dobby-detect-20261108-134638](results/dobby-detect-20261108-134638/summary.json) |
| `urov_y_test` | `--mode ap` PASS（39 断言）；`--fork-write` PASS（7 断言，子进程写 0x5a 后读回 0x5a，父镜像不变）；`--mremap` PASS（5 断言，移动后仍读镜像） | 设备输出 |

## 6. 残余（2.16.0）

以下不属于本轮能消除的普通 App 稳定特征，或受测试机硬件限制：

1. **计时**：每次 EL0 数据读仍一次同步异常；GUP、原子、影子路径的额外
   开销可被高精度计时/PMU 观察。这是 `PAGE_AP` 的架构代价，按题目允许保留。
2. **SVE/SME store**：解码器未覆盖 SVE/SME 谓词 store；在支持 SVE/SME 的
   机器上仍按页退役。Pixel 6 的 CPU 无 SVE/SME，本机不可复现。
3. **非 NOP/BTI 间隔的独占序列**：`LDXR; load; ALU; STXR`、`LDXP; ...;
   STXP` 仍 fail-closed；只桥接间隔为 `NOP`/`BTI` 的序列。
4. **子进程的 mremap/munmap**：owner 的 `mremap`/`munmap` 已按页处理；
   fork 子进程自己的 `mremap`/`munmap` 没有重建影子地址，仍可能让该子进程
   的覆盖失效（父进程不受影响）。
5. **fork 快照时机**：子进程影子在第一次写时从 owner 当时的镜像创建；
   若 owner 在 fork 后、子进程第一次写前 `SET`，子进程看到的是新镜像而不是
   fork 时快照。生产 CRC 不 `SET`，但这是可构造的时间窗。
6. **原子并发**：原子 RMW 的读-算-写不是硬件单指令原子；与同一页的并发
   原子/普通写竞争时可能丢更新。单线程 CRC 不受影响。
7. **GUP 写者**：fast GUP 的 `FOLL_WRITE` 被当作源页处理；当前内核路径里
   真正写注册页的 GUP 写者走 `access_remote_vm`，但若未来出现 fast-GUP
   写者，替换页会截获其写。
8. **root 可见性**：`kpm list`/`ctl0 status` 仍能看到模块与会话；这只对
   root 开放，不在普通 App 的 CRC 输入集合内。隐藏它需要改 KernelPatch
   核心，超出“只改 `urov-y`”的范围。
9. **pkey/POE 与 shared `remap_file_pages`**：未分配 pkey 的调用已透传；
   已分配 pkey/POE 权限和 shared VMA 的合法重映射仍保守处理。
10. **execve/进程退出**：替换/销毁地址空间仍结束会话；旧代码已不存在，
    不构成读值不一致。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```
