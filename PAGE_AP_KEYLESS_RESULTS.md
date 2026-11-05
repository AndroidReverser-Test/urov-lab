# 普通 App 无密钥复核 UROV-Y PAGE_AP

2026-11-05，Pixel 6，Android 16，arm64，内核 `6.1.134-android14-11`，KernelPatch `0xc00`。本轮以 `c452720` 的 KPM 后端为基线，重建的 `urov-y.kpm` SHA-256 为 `fbe8dc8409351696f0f17ecaf2da77818a8df2cfdcb4e8fd6d0b81d02d38a87b`，与消除实验使用的产物一致。日志目录使用主机 UTC+8 时间，logcat 使用设备时钟。[既有消除结果](ELIMINATION_RESULTS.md) · [本轮机器结果](results/eliminate-20261105-215844/summary.json)

## 源码复核

早期 `urov-lab` 通过固定的 `kcmp` 和 `prctl` 协议管理会话，在单页只读可执行映射上移除 EL0 数据访问权限。`do_mem_abort` hook 解码受支持的 A64 load，把从快照和伪值合成的结果写回用户寄存器。普通 App 可按已知文件偏移比较实际返回字节。`urov-x` 改用派生的 `prctl` selector、magic 和 SipHash MAC，并在故障处理里按读取点 PC 区分伪值与透明模拟。无效控制请求落回原生 `prctl`，但直接读目标页仍会进入 EL1。[旧版实现](STANDALONE.md) · [UROV-X 无密钥复核](KEYLESS_DETECTION_RESULTS.md)

`urov-y` ABI v6 保留密钥化控制和单 `mm`、单目标页会话。注册先检查文件后备的只读 RX 页、叶子 PTE 与受支持的读取点，保存原始目标页，并发布最多 32 字节的伪值窗口。模拟器检查 `x30` 是否处于调用者窗口，随后合成字节并提交 GPR/SP/PC。`PAGE_AP` 的 abort 路径按 `mm`、异常类型和故障地址筛选，伪值由 `x30` 和目标页偏移决定，桥接逻辑无需进入业务调用窗口。相交的映射操作会结束会话，clone 和注销路径负责恢复对应的指令或 PTE 权限。`PAGE_AP` 需要显式注册 `mode=3`，`mode=0` 会选用 `SITE_BRK`。[控制与异常后端](urov_y_backend.c) · [消除设计第 9–10 节](ELIMINATION_DESIGN.md)

| 模式 | 活动时的实现 | 普通 App 可验证的现象 |
| --- | --- | --- |
| `SITE_BRK` | 在读取点所在的私有 COW 页把 4 字节指令改成 `BRK`，目标数据页原生可读 | 读取点字与同偏移安装文件字不同。私有脏页只作旁证，注销写回原指令后仍可能留下 COW 页 |
| `PAGE_UXN` | 置读取点页叶子 PTE 的 UXN 位，EL1 模拟取指，文件字节和 VMA 保持一致 | 在该页执行经校验的 `BTI C; RET` canary 会使独占写稳定失败，正常同偏移别名保持成功。需要 App 拥有并保留这种可调用入口 |
| `PAGE_AP` | 只清目标页的 `PTE_USER`，取指原生执行，目标页标量读取进入 EL1 | 旧的紧邻 `LDXR/LDRB/STXR` 探针由桥代写而回报成功。先清除独占状态并跳过 `LDXR`，仍能诱发该桥的代写 |

三种模式都可让普通独立读点和文件返回相同的字节。对已知无副作用的真实业务读取路径，同地址返回稳定的不同值仍能确认该路径的完整性异常。`PAGE_AP` 的取指 canary、站点字比对和原紧邻探针均按消除设计表现为阴性。[活动 AP App 日志](results/eliminate-20261105-215844/06-ap-1-17323.log)

## 新探针

`uy_llsc_prepare()` 按故障 PC 的前后各一个指令字匹配 `LDXR` 和 `STXR`，比较两条指令的基址、数据寄存器。`uy_llsc_commit()` 取寄存器里的待写值，经 `copy_to_user_nofault` 写入该地址，把状态寄存器置为 0，然后跳过 `STXR`。匹配条件只看相邻指令的编码，因此分支跳过的 `LDXR` 也能触发代写。[桥接源码](urov_y_backend.c)

测试 App 的实际反汇编中，`x0` 指向采样字节，`x1` 指向检测线程私有的 8 字节栈变量，`x9` 预先装入与栈变量初值不同的哨兵值。

```asm
clrex
b    1f
ldxr x9, [x1]
1: ldrb w11, [x0]
stxr w10, x9, [x1]
```

`CLREX` 清除本地独占状态。分支直接到 `LDRB`，没有架构上执行的 `LDXR`，因此原生 `STXR` 应回报 1，栈变量保持初值。当前 `PAGE_AP` 在被采样页上的 `LDRB` 进入 EL1 后会回报 0，并把哨兵实际写入栈变量。调度和中断能使真正的独占尝试失败，这里要求观察到的是无独占状态时实际发生的写入。[Arm A64 CLREX 说明](https://documentation-service.arm.com/static/6245e8f0f7d10f7540e0c054#page=96) · [Armv8-A 架构手册 §B2.10](https://www.bitsavers.org/components/arm/ARM_Architecture_Reference_Manual_ARMv8_Rev_A.k_201609.pdf)

`ud_observe_unreserved_store()` 每次执行 32 组「正常别名 → 目标地址 → 正常别名」。两处地址必须映射同一文件的同一偏移，且是调用者持有的、稳定的只读 RX 映射。每组检查三个 `LDRB` 的返回字节与文件一致，并验证两个正常别名的 `STXR` 均失败且初值保留。32 个目标样本全部回报成功并写入哨兵才是 `MATCH`，全部原生失败为 `NO_MATCH`。混合结果、异常对照、文件或映射身份变化返回 `UNKNOWN`。耗时仅用于记录开销。[检测实现](native/urov_observe.c) · [调用约束](native/urov_observe.h)

## 真机结果

检测与业务均在 `untrusted_app` 中运行，实测 `CapEff=0`、`Seccomp=2`、SELinux `Enforcing`。ADB 侧用 root 装卸模块并核对真值，App 的注册夹具持有临时模块密钥。检测函数只接收两个本进程地址、文件描述符和文件偏移。另一 UID 的观察 App 未接收模块密钥。

| 场景 | 探针阳性 / 次数 |
| --- | ---: |
| 活动 `PAGE_AP`，伪值窗口内 | 90 / 90 |
| 活动 `PAGE_AP`，同页窗口外 | 90 / 90 |
| 活动 `PAGE_AP`，伪值等于文件原值 | 90 / 90 |
| 活动 `PAGE_AP`，分别绑定 CPU 0–7 | 72 / 72 |
| 活动 `PAGE_AP`，持有会话待卸载 | 3 / 3 |
| 无模块、已加载但无会话、最终清理 | 0 / 90 |
| 三模式的注册前、注销后 | 0 / 540 |
| 活动 `urov-x`、`SITE_BRK`、`PAGE_UXN` | 0 / 576 |
| 不同 UID 分别观察活动 `PAGE_UXN` 和 `PAGE_AP` | 0 / 60 |
| 三模式从存活 App 卸载后，在同一进程复测 | 0 / 9 |

345 次活动 AP 检查共观察到 11,040 次哨兵写入。1,275 次对照共完成 40,800 个三元组，无意外写入。新探针本轮没有 `UNKNOWN`。AP 持有用例 App 观察到 96 次写入，`ctl0 status` 同时显示 `llsc=96`。另一 UID 在 AP 会话活跃时检查自身映射 30 次均为阴性，owner 的 `llsc` 保持 96。卸载后同一 owner 恢复原读取结果，探针 3 次均为阴性。[原始汇总](results/eliminate-20261105-215844/summary.json) · [同进程装卸日志](results/eliminate-20261105-215844/09-hold-ap-after-unload-17886.log) · [不同 UID 日志](results/eliminate-20261105-215844/09-other-uid-ap-17987.log)

同时复现了三轮 BRK 的指令字差异和 COW，以及 UXN 的取指 canary 阳性 255/255。取指对照有 2 次 `UNKNOWN`，旧数据独占探针有 3 次 `UNKNOWN`，均为已有探针的独占失败波动。`urov-x` 的旧数据读取探针提供阳性对照。

## 业务影响和结论边界

- 探针在后台线程工作，目标页只执行受支持的 `LDRB`，唯一写入地址是线程私有栈变量。文件读使用 `pread`，App 验证了文件位置、`errno` 和元数据 fd。检测不装信号处理器，不改变映射或模块会话。AP 的透明模拟与代写会增加 `replays` 和 `llsc` 诊断计数，业务 `hits`、伪值、代际及失败计数在探针前后保持一致。
- 三种 `urov-y` 模式的并行业务线程共完成 5,211,008 次原函数执行对照，错误 0，常规管道 I/O 通过。AP 三轮合计 1,962,112 次。非绑核前台 AP 样本每次 32 组检查的组内均值为 3.89–4.06 ms，UI 心跳最大间隔为 30 ms。新增内核日志未检出 Oops、BUG、WARNING 或挂起，结束时 KPM 清单为空。[业务及内核汇总](results/eliminate-20261105-215844/summary.json) · [内核日志增量](results/eliminate-20261105-215844/kernel-new.log)
- 该结果验证当前构建在本进程已知采样页上的异常写入语义。空闲模块、其他 `mm` 和未采样页的存在性仍无法由该信号判定。阳性也可能由产生相同语义的其他模拟器造成。设备矩阵仅覆盖一台 Pixel 6，重复样本用于同机对照。
- 调用者必须保证映射、文件和 fd 的生命周期。对不支持的访问指令或模块正在切换权限的场景，后端可能触发原生故障。检测因此只采样已知的不可变 RX 页，不遍历未知地址。文档提到的非紧邻 LL/SC 可以暴露监视器丢失，但独占失败会受硬件与调度影响。本轮以实际发生的代写作为判据，避免用延迟、故意触发信号、改变映射或跨 UID 读取作为判定条件。

## 复现

在仓库根目录构建两个 APK 和 KPM。脚本使用临时模块密钥建立测试会话，超级密钥只供 ADB 侧的 `kpatch` 使用，结果文件会脱敏。

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 30 --cycles 3
```
