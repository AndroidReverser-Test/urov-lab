# UROV-Y：读取点陷阱方案——消除 KEYLESS 检测特征点的设计与实现

日期：2026-11-04/05（Asia/Shanghai）。对象是 [KEYLESS_DETECTION_RESULTS.md](KEYLESS_DETECTION_RESULTS.md)
复核的同一个 `urov-x.kpm`（SHA256 `c2a5c3d3…3575`）以及 `urov-y.kpm`。真机结果见
[ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md)。

**结论（第一轮，BRK 读取点指令陷阱）。`urov-y` 把覆盖从"数据页权限异常"移到
"读取点指令陷阱"，因此 KEYLESS 报告中的两项无密钥检测在其活动页上都不再命中：
129 次观测中独占监视器 MATCH 为 0（12,384 个被接受三元组、目标 STXR 失败 0 次），
跨 PC 内容差异 MATCH 为 0；同时注册的业务调用窗口仍然读到伪值。代价是引入了一个
新的、可被自检发现的特征：活动期间读取点所在的代码页是私有 COW 页，且该 4 字节
指令与安装文件不同（实测 `f9400000 → d4235b40`）。**

**结论（第二轮，EL0 execute-never 页陷阱，本文 §9）。同一模块新增
`UROV_Y_MODE_PAGE_UXN`：完全不写代码页的任何字节，只清叶子 PTE 的 EL0 执行许可
（UXN），用 EL0 instruction abort 在 EL1 模拟读取点。于是第一轮的那个新特征也消失
了：活动期间 `site_live_word == site_file_word == f9400000`，代码页仍是干净的
文件页（`Private_Dirty=0`、`Anonymous=0`），注销/卸载后没有任何残留 COW 页。
153 次观测中独占 MATCH 0、reader MATCH 0，业务窗口仍返回伪值。新代价是：每次读取
点调用一次 instruction abort（~230 ns）、读取点必须位于只含可模拟指令的独立页，
以及 PTE 被回收后重新装回时的微秒级窗口（§9.6）。**

## 1. 现行实现（urov-x）与两项特征点的根因

`urov_x.c` → `urov_x_backend.c` → `decode.c` / `emulate.c` 的主线：

1. **控制**：prctl 的 option/magic 和请求 MAC 密钥都由装载密钥派生；无密钥调用
   原样落入原生 `sys_prctl`，返回 `EINVAL`；不安装 kcmp 通道。
2. **注册**：目标必须是一页整、文件后备、只读可执行、无 `VM_MAYWRITE` 的映射。
   模块 pin 住该页，快照 4 KiB，清 VMA `vm_page_prot` 与叶子 PTE 的 `PTE_USER`，
   保留取指；`maps/smaps` 仍显示普通 `r-xs`。
3. **读取**：EL0 数据 permission fault 由 `do_mem_abort` hook 接管。按故障 PC
   匹配注册的读取点：命中则用伪值快照模拟，未命中用原页快照模拟（"伪值等于
   原值"）；跨 PC 视图因此不同。
4. **生命周期**：相交的映射操作静默结束会话；clone 前后临时恢复/再保护；
   注销/卸载恢复 PTE、VMA、TLB 并撤 hook。

KEYLESS 报告的两项检测正是针对上面第 2、3 步：

| ID | 检测 | 利用的实现事实 | 本方案的处理 |
|---|---|---|---|
| A | 独占监视器失效 | **整页**数据读取都要进 EL1 模拟；异常返回清本地独占监视器，`LDXR scratch / LDRB target / STXR scratch` 的目标 STXR 稳定失败 | 目标页**不再**改变任何权限；数据读取全部在 EL0 原生完成，无异常、无异常返回 |
| B | 跨 PC 内容差异 | 注册读取点看到伪值，同地址的直接读取看到文件字节 | 伪值不再由"哪个 PC 读"决定，而由"哪条调用路径读"决定；非注册窗口的调用用原字节模拟，返回与映射完全一致 |

## 2. 威胁模型与目标

对手是同设备普通 App：`untrusted_app`、`CapEff=0`、`Seccomp=2`、不知道装载密钥。
它可以调用任意允许的 syscall、读自己的 maps/smaps/pagemap、读写自己的内存、
fork、比较文件与自己读到的字节，也可以直接调用页内的读取函数。目标：

1. A 不可判：活动目标页上的任意数据读取不产生任何同步异常。
2. B 不可判：对同一不可变 RX 地址的普通读取与实际读取点返回一致，除非调用来自
   注册的业务调用窗口。
3. 功能保留：注册窗口内的读取仍拿到伪值，取指仍执行原机器码。
4. 原有特征面不回退：无固定控制通道、无 smaps 标志、映射 syscall 返回原生值、
   无 fail-closed 信号。

## 3. 方案：读取点指令陷阱（无数据页异常）

### 3.1 四个结构性质

1. **目标页是普通页面。** 注册时只校验、快照，不写 `vm_page_prot`、不改 VMA、
   不改叶子 PTE、不 pin 数据页。所有数据读取（任意 PC、任意线程、内核
   uaccess）都走原生路径。A 因此**结构上不可能**出现：没有异常，就没有异常
   返回，也就没有独占监视器失效；文件-内存完整性扫描同样看不到差异。
2. **伪值挂在读取点指令上。** 对每个注册读取点，模块把该 4 字节指令替换为
   `BRK #imm`（`imm` 由装载密钥派生）。执行到读取点时进入 EL1，由模块按保存
   的原指令模拟一次 load，再提交 GPR/SP/PC。
3. **调用窗口绑定。** 注册请求新增最多 4 个"业务调用窗口" `[caller_start,
   caller_end)`。陷阱里只有 `x30`（读取点的返回地址）落在窗口内、且负载有
   效地址落在目标页内时，才用伪值合并；否则按原字节做**透明模拟**，返回值与
   直接读取逐位一致。B 的"同一纯函数、不同视图"前提对非业务调用不再成立。
4. **可逆。** 读取点页在会话期间是私有 COW 页（`__access_remote_vm` 以
   `FOLL_FORCE|FOLL_WRITE` 触发 COW），从不修改文件页或 page cache；注销/卸载
   写回原指令、恢复 PTE 写保护，并用 `IC IALLUIS` 广播失效全系统指令缓存。

```text
            注册（prctl，密钥 + MAC）
  App ────────────────────────────────► urov-y
   │  目标页：只校验 + 快照，权限不变
   │  读取点：COW 私有页上写 BRK #imm
   │
   │  uy_business_ldr() ──bl──► 读取点 (BRK) ──► EL1 陷阱
   │                                              │ 调用窗口命中？
   │                                              ├─ 是：原字节 + 伪值合并
   │                                              └─ 否：原字节透明模拟
   │  uy_site_ldr() 直接调用 ──► 读取点 (BRK) ──► 同一陷阱，透明模拟
   ▼
  任意普通 LDR/LDRB 读目标页 ──► 原生 EL0 读取，无异常
```

### 3.2 ABI v4

`urov_y_abi.h` 定义 240 字节请求（v3 的密钥化通道的超集）：

```c
struct urov_y_request {            /* 240 bytes */
    uint32_t size; uint16_t version, op;
    uint64_t request_id, session, address, expected_generation, value;
    uint32_t offset, length;
    uint64_t value_hi[3];
    uint32_t site_count;           /* 1..4 读取点 PC */
    uint32_t caller_count;         /* 0..4 业务调用窗口 */
    uint64_t sites[4];
    uint64_t caller_start[4];
    uint64_t caller_end[4];
    uint64_t generation;
    uint32_t state; int32_t last_error;
    uint64_t hits;                 /* 伪值陷阱 */
    uint64_t replays;              /* 透明陷阱 */
    uint64_t failures;
    uint64_t reserved;
    uint64_t mac;                  /* SipHash-2-4 over [0, 232) */
};
```

控制通道与 urov-x 相同：`key=32hex` 装载参数派生 prctl option、magic、MAC key；
未认证请求原样落入原生 `sys_prctl`。`caller_count == 0` 时退化为"任意调用者都
看伪值"（兼容旧行为）；本轮测试都注册了调用窗口。

### 3.3 读取点改写

注册时对每个读取点：

1. 校验目标 `VMA`：可执行、`VM_MAYWRITE`、非 `VM_SHARED`、非 PFNMAP/IO/HUGETLB/
   MIXEDMAP（只有私有可 COW 的可执行映射允许改写；共享文件映射会把 BRK 写进
   page cache，明确拒绝），且读取点页不能就是目标页。
2. 读原指令并用 `uro_decode` 校验它是白名单内的 GPR load。
3. `__access_remote_vm(mm, pc, &brk, 4, FOLL_FORCE|FOLL_WRITE)`：内核以
   ptrace 插断点相同的方式对私有文件映射做 COW，写入只落在本进程的匿名页，
   不碰文件页。该内核的 FOLL 编号是旧式（`FOLL_FORCE=0x10`），已用探针实测。
4. `site_sync()`：当前在会话 mm 时对用户 VA 做 `dc civac`；随后
   `dsb ish; ic ialluis; dsb ish; isb` 广播失效内共享域的全部指令缓存。
5. `site_set_prot()`：把 COW 留下的可写 PTE 改回只读（保持 VMA 的 RX 语义），
   刷 TLB。之后应用对代码页的写入仍按原样 SIGSEGV。

### 3.4 陷阱与模拟

`hook_wrap(brk_handler, 3, …)` 拦截所有 BRK，快速过滤：ESR 异常类 `0x3C`
（BRK64）且 ISS 等于本装载的 `imm`。命中后查模块生命期的陷阱表
（PC → 原指令），并：

1. 用当前 `pt_regs` 构造 `uro_regs`，以读取点 PC 为 `pc`，`uro_decode` 解码原指令。
2. 若会话属于当前 mm、不在 fork 窗口、`x30` 命中调用窗口、且负载地址落在目标页：
   用 seqlock 快照伪值，按字节合并原页快照后提交，`hits++`。
3. 否则用 `copy_from_user_nofault` 读真实内存后提交，`replays++`；读取失败时
   按原生语义投递 SIGSEGV。
4. `commit_model()` 写回 31 个 GPR、SP、PC（`pc += 4`），`args->skip_origin = 1`
   跳过原生 BRK 处理。
5. 解码失败或配置错误计数 `failures++` 并 fail-closed（SIGSEGV），绝不把原字节
   冒充伪值返回。

陷阱表在会话结束后**继续保留**（直到模块卸载），因此即使某个 CPU 上残留一条
已失效的 BRK 指令缓存行，也会被透明模拟而不是 SIGTRAP；卸载前的
`IC IALLUIS` 是最后一道保证。

### 3.5 生命周期

- **注销/结束**：先置状态 OFF、排空在途 handler，再逐点写回原指令并恢复 PTE，
  最后清会话。写回同样走 `__access_remote_vm`，所以**可以从任意进程上下文
  完成**，包括"应用仍活着时由 kpatch 卸载"。
- **映射门控**：与目标页或任一读取点页相交的 `mprotect/munmap/mremap/
  mmap(MAP_FIXED)/madvise` 静默结束会话（恢复读取点）后按原生执行；`execve`
  直接结束会话。映射 syscall 不产生模块特有的 errno。
- **fork/clone**：`CLONE_VM` 之外，clone 前写回原指令（子进程复制到的是原页），
  clone 返回后重新 COW + 改写；父进程保留覆盖，子进程完全正常。
- **owner 死亡**：下一次控制请求或 `ctl0 reap` 按 `mm_users == 1` 惰性回收。
- **卸载**：无否决。先恢复读取点（跨上下文安全），再撤销所有 hook。

## 4. 为什么两项检测不再命中

**A（独占监视器）**：检测序列是 `LDXR scratch / LDRB target / STXR scratch`。
在 urov-y 中 `LDRB target` 是目标页上的原生 EL0 load：PTE 从未被改、无 fault、
无异常返回，本地独占监视器保持 Exclusive，STXR 成功。实测 129 次观测中
MATCH=0、目标 STXR 失败 0/12,384。

**B（跨 PC 内容差异）**：检测用"同一个纯加载函数"读同一不可变 RX 地址，与直接
读取比较。urov-y 的读取点只有在返回地址落入注册业务窗口时才返回伪值；检测器
从 `ud_observe_reader()` 调用裸读取点时，`x30` 不在窗口内，模块按真实内存透明
模拟，返回值、符号扩展和 W 截断都与直接读取一致，最终 `reader_diff=NO_MATCH`。
实测 129 次中 reader MATCH=0。

**功能保留**：同一页面、同一读取点，经 `uy_business_ldr()`（窗口内）调用时仍
返回伪值 `0x8877665544332211`，而直接读取与文件都是 `0xf2c66881f2aaacc1`；
`ELIM_FEATURE business_reader=1` 记录了这一点。

## 5. 残余特征与限制（诚实清单）

1. **读取点代码页被改写（第一轮 BRK 模式的特征，已实测；第二轮 PAGE_UXN 模式已
   消除，见 §9）**。BRK 会话期间该页是私有 COW 页（`Private_Dirty` +4 KiB），
   4 字节指令由 `ldr` 变为 `BRK`：实测 `site_file_word=f9400000 →
   site_live_word=d4235b40`；注销后字节恢复一致，但**该页仍是私有 COW 页**
   （实测注销后 `Private_Dirty=4`、`Anonymous=4` 持续到进程结束）。任何"读自己
   代码页并与安装文件比较"或看 smaps 的自检都能发现它。
2. **业务路径复现即功能本身**。把 `ELIM_FEATURE` 的调用者——即已注册的业务
   包装函数——当作 reader 传给检测 API，会得到 MATCH；任何能执行真实业务读取
   路径的同进程代码都能看到伪值。这是"合作式同进程覆盖"的固有边界，不是本文
   能消除的缺陷。可进一步用 (site, caller) 之外的上下文（线程、调用栈深度）
   收紧窗口，但同样可被复现。
3. **时间**。每次读取点调用仍是一次同步 debug 异常，与 urov-x 的数据异常同级。
   本方案不用时间阈值判定，也不承诺零开销。
4. **合作模型约束不变**：单会话、单页、最多 32 字节窗口、最多 4 个读取点、
   最多 4 个调用窗口；读取点必须是私有可 COW 的可执行映射（共享文件映射拒绝）；
   调用窗口检查的是读取点执行时的 `x30`，非叶子读取点若自行保存/改写 LR 则
   窗口失效（此时退化为透明读取，不返回伪值）。
5. **目标页必须保持映射**。门控覆盖了常规映射 syscall；若应用绕过（例如从
   内核侧改页表），陷阱仍会用快照返回伪值而不是 SIGSEGV。这是合作模型约定。
6. **内核/root 可观察性不变**：`brk_handler` 的 inline hook、6 个 syscall 表项、
   模块清单与 `ctl0 status` 仍对 root 可见；本方案只针对普通 App 的无密钥检测。
7. **不声称唯一归因**：MATCH=0 只说明"在本次采样中没有观察到这两类现象"，
   不能证明模块不存在，也不能排除其他异常模拟机制。

## 6. 被否决的替代方案

| 方案 | 否决原因 |
|---|---|
| 影子页替换目标页物理页 | I 取指与 D 读取共用同一翻译；执行流会跑到伪字节上，破坏业务 |
| 依赖 I/D 缓存不一致 | 任何 I-cache 逐出/维护都会让执行读到伪字节，不可控 |
| 硬件断点/观察点 | 与本项目书面约束冲突；需跨线程/上下文切换管理调试寄存器 |
| 让所有读取都返回伪值（内容差异） | 重新引入旧 FP-3，且同样破坏取指 |
| 保持数据页异常、只再加调用者判断 | A 仍然存在：任何读取都会清独占监视器 |

## 7. 产物与构建

| 文件 | 说明 |
|---|---|
| `urov_y_abi.h` | ABI v4（240 字节）+ 请求 MAC |
| `urov_y.c` | KPM 元数据、init/exit、`ctl0 status/reap` |
| `urov_y_backend.c` | 读取点改写、BRK 陷阱、调用窗口、生命周期 |
| `tests/urov_y_test.c` | root 验收程序（功能、fork、门控、卸载/持有） |
| `apps/urov-detect/uy_fixture.inc` | App 夹具：`y-clean` / `y-active` / `y-hold` |
| `tools/run_elimination_device.py` | 设备矩阵（含 urov-x 阳性对照） |

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 10 --cycles 2
```

复用 `decode.c`、`core_selftest.c` 与 `emulate.c`（只用于装载门槛）；未改动
`urov_x_backend.c`、`native/urov_observe.c`、`native/urov_detect.c`。

## 9. 第二轮：EL0 execute-never 页陷阱（消除代码页特征）

第一轮的结论是"无密钥检测归零，但代码页被改写"。这一节处理那个新特征本身。

### 9.1 为什么"隐藏"改写不成立

任何"改字节"的做法都会留下同一个可比较的差异，且不依赖内核实现细节：

- App 可以在会话开始前保存自己代码页的哈希（或文件偏移对应的字节），会话期间
  再读一次；只要它自己的数据视图变了就能发现；
- 也可以把 `.so`/APK 再 `mmap` 一份（`MAP_SHARED` 或 `pread`）与可执行映射比对，
  文件页从未被改写，差异立刻出现；
- 短暂改写（只在业务调用期间打 BRK、调用结束就写回）只是把窗口缩小；另一个线程
  在业务函数被循环调用的同时循环读代码页，几乎必然抓到 BRK；
- 改 page cache 或磁盘则会让 APK 自校验、`fs-verity`、升级和"保存过的旧副本"
  全部暴露，而且 clean 页被回收后改写会静默丢失。

而硬件只有一套 EL0 翻译：I 取指和 D 读取共用同一个叶子 PTE，所以"取指执行改过的
指令、数据读取仍看到原字节"不可能靠单页表实现。I/D TLB 不一致（§6）不稳定，硬件
断点被项目约束禁止，影子页会破坏取指。**唯一不变量是：不改字节，改"能不能在
EL0 取指"。**

### 9.2 机制

`UROV_Y_MODE_PAGE_UXN`（ABI v5 的 `mode = 2`）：

1. **目标页不动**。仍然只校验、快照，不写 `vm_page_prot`、不改 VMA、不 pin。
   第一轮的所有 A/B 结论继续成立。
2. **只置叶子 PTE 的 `PTE_UXN`**。`vm_page_prot` 与 `/proc/self/maps`/`smaps`
   都不变（仍是普通 `r-xp`），但 EL0 取指该页会得到 instruction abort
   （EC `0x20`，permission fault `FSC=0x0c..0x0f`）。PTE 的 D 读取许可不变，
   因此**代码页的数据读取全部是原生 EL0 读取**：不产生异常、不进模拟、内容与文件
   逐位一致。
3. **`do_mem_abort` hook 接管取指异常**。按 `FAR == regs->pc` 匹配注册读取点：
   用页内原指令（注册时快照的 4 字节）在 EL1 模拟一次 load，伪值/透明规则与第一轮
   完全相同；`args->skip_origin = 1` 跳过内核的 SIGSEGV 路径。若相邻指令是
   `ret`，直接把 `pc` 设为 `x30`，于是**一次业务调用只有一次异常**。
4. **同一页里的后续控制指令**。陷阱页必须只包含读取点与 `RET/BR/BL/NOP/BTI`
   （见 9.4），这些指令在遇到时自行模拟；遇到无法模拟的指令时**fail-closed**
   但不杀进程：清掉该页的 UXN、计数 `failures`、让重试的取指原生执行，并等下一次
   控制请求回收半个会话。
5. **重新装回**。PTE 被回收（内存压力、`/proc/self/mem` 触发 GUP）后，内核会按
   VMA 保护重新安装一个**可执行** PTE。为此 `handle_mm_fault` 的 after-hook 在
   故障装页成功后重新置 `PTE_UXN` 并广播 TLB，避免"页被回收一次，陷阱就静默消失"。
6. **可逆且跨上下文**。arm/disarm 只改 PTE（`mmap_write_lock` 下），TLB 用
   `TLBI VMALLE1IS` 广播；注销、fork 前、卸载时都清 UXN。卸载不需要写回任何代码
   字节，因此比第一轮更安全。

```text
            注册（prctl，密钥 + MAC，mode=2）
  App ────────────────────────────────► urov-y
   │  目标页：只校验 + 快照
   │  读取点页：仅叶子 PTE |= UXN；字节、VMA、文件都不动
   │
   │  uy_business_ldr() ──bl──► 读取点 (取指 permission fault)
   │                                   │ EL1: 按页内原指令模拟
   │                                   │ 调用窗口命中 → 伪值
   │                                   │ 否则 → 透明读
   │                                   └─ ret 快进 → 返回业务
   ▼
  任意普通 LDR/LDRB 读读取点页或目标页 ──► 原生 EL0 读取
```

### 9.3 ABI v5 与状态

`struct urov_y_request` 仍是 240 字节；原来的 `uint64_t reserved` 拆成
`uint32_t mode; uint32_t flags;`，`UROV_Y_ABI_VERSION = 5`：

- `mode = 0/1`：`UROV_Y_MODE_SITE_BRK`（第一轮行为，兼容旧测试）；
- `mode = 2`：`UROV_Y_MODE_PAGE_UXN`（本轮默认由夹具显式指定）；
- `flags` 必须为 0；`ctl0 status` 增加 `mode=site-trap|page-trap` 与
  `degraded=0|1`，`hooks` 增加 bit 32（`do_mem_abort`）与 bit 64
  （`handle_mm_fault`），实测 `hooks=0x7f`。

`urov-y` 的注册可选性：如果内核没有 `do_mem_abort`/`handle_mm_fault`，模块仍以
BRK 模式装载，只是 `mode=2` 返回 `EOPNOTSUPP`。

### 9.4 部署前提：读取点页自包含

`mode=2` 要求"读取点所在的 4 KiB 页里被执行的指令"只有读取点 load 和
`RET/BR/BL/NOP/BTI`。夹具用汇编段 + 页对齐 + 页尾填充实现：

```asm
.pushsection .text.uy_sites,"ax",%progbits
.p2align 12
uy_site_ldr:  ldr x0, [x0]; ret
uy_site_ldrb: ldrb w0, [x0]; ret
.p2align 12          /* 把输入段补到 4 KiB，下一页留给普通代码 */
.popsection
```

实测 `liburovdetect.so` 的读取点页 `0x13000-0x14000` 内只有两个 stub 和 NOP 填充，
业务包装函数在 `0x9060`（不同页）。不满足该前提时模块不会崩：遇到无法模拟的指令
就 detach 该页并计 `failures`，代价是那个会话不再返回伪值。

### 9.5 为什么两个特征一起消失

| 可观察量 | 第一轮 BRK | 第二轮 PAGE_UXN |
|---|---|---|
| 读取点 4 字节 vs 安装文件 | 不同（`d4235b40`） | **相同**（`f9400000`） |
| 代码页 `Private_Dirty`/`Anonymous` | +4 KiB / +4 KiB，注销后仍在 | **0 / 0，注销后仍 0** |
| 再 `mmap` 文件比对 | 不一致 | **一致** |
| 会话前保存的代码哈希 | 变化 | **不变** |
| 目标页数据读取 | 原生 | 原生（不变） |
| 独占监视器（目标页/代码页） | 原生 | 原生（代码页读取也不进异常） |
| `maps`/`smaps`/`pagemap` 存在位 | 不变 | 不变 |
| 每次业务调用 | 1 次 debug 异常 | 1 次 instruction abort（~230 ns） |
| 读取点页能否在 EL0 原生取指 | 是 | **否**（唯一的实现事实） |

### 9.6 残余特征与限制（诚实清单）

1. **时间**。每次业务调用一次同步 instruction abort：App 实测
   `ELIM_TIMING mode=page site_call_ns=227..241`，同一函数未注册时约 2–6 ns；
   BRK 模式是 219–232 ns，同一量级，不是本模式新增。
2. **读取点页不在 EL0 原生执行**。普通 App 无法直接观察 PTE 权限，但可以用
   `perf_event_open`（Android 上普通 App 被 SELinux 限制）统计 EL0 指令数，或用
   统计式计时发现"该页首次执行比同 VMA 其他页多一次异常"。本矩阵不包含这两项。
3. **PTE 重新装回时的窗口**。页被回收后，内核先按 VMA 保护装一个可执行 PTE，
   after-hook 再改回 UXN；在这几微秒里，另一 CPU 上正好执行读取点的线程可能原生
   执行一次并读到原值。普通 App 触发该路径需要先让页被回收（`madvise` 已被门控，
   只剩内存压力或 `/proc/self/mem` 类 GUP 安装），再与业务线程抢这个窗口。本矩阵
   没有观测到，但它是本模式存在的一个非确定性缺口。
4. **业务路径复现即功能本身**（与第一轮相同）：把已注册的业务包装函数当 reader
   传给 `ud_observe_reader` 仍得到 MATCH。
5. **合作模型约束**：单会话、单页、≤4 读取点、≤4 调用窗口、≤32 字节窗口；读取点
   必须是可执行的私有或共享文件映射；读取点页必须自包含（9.4）；调用窗口基于
   `x30`。
6. **映射门控与第一轮相同**：与目标页/读取点页相交的 `mprotect/munmap/mremap/
   mmap(MAP_FIXED)/madvise` 结束会话，`execve` 结束会话。这本身是"检测者可以让
   伪值消失"的向量，两轮都存在。
7. **root 可观察性**：`do_mem_abort` 与 `handle_mm_fault` 的 inline hook、6 个
   syscall 表项、模块清单和 `ctl0 status` 仍对 root 可见。
8. **第一轮遗留缺陷的修复**：`s->page = pc & ~(UROV_Y_PAGE - 1)` 里
   `UROV_Y_PAGE` 是 32 位常数，会把高 32 位地址掩掉；第一轮因此实际上没有恢复
   读取点页的 PTE 写保护，映射门控也没有匹配到读取点页。本轮改为
   `page_base()` 并复测。

### 9.7 被否决的替代方案（第二轮新增）

| 方案 | 否决原因 |
|---|---|
| 只在业务调用期间打 BRK、结束即写回 | 窗口等于整个业务调用；另一线程循环读代码页几乎必然抓到 |
| 改 page cache / APK 文件 | APK 自校验、`fs-verity`、升级和"保存过的旧副本"都暴露；clean 页回收后改写丢失 |
| 把读取点页拆成独立 VMA 再改 `vm_page_prot` | `/proc/self/maps` 多出相邻同权限 VMA 行，是新的确定性特征 |
| 只 clean `vm_page_prot`、靠 after-hook 修 PTE | 需要 VMA 级保护，会波及同 VMA 其他代码页（首次执行多一次异常），且 `mprotect` 会重算保护 |
| I/D TLB 不一致（D-TLB 保留旧翻译） | 任何 TLB 维护/迁移/回收都会让数据视图变成 BRK，不可控（§6 已否决） |
| 用 `/proc/self/smaps`/`pagemap` hook 隐藏 COW 页 | 需要额外 proc hook，且 `mincore`/`madvise`/`fork` 语义仍可交叉验证；不如直接不改字节 |

### 9.8 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1              # urov-y.kpm + urov_y_test（含两种模式）
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 6 --cycles 2
```

App 模式：`y-active`/`y-hold` 走 BRK 模式（代码页特征阳性对照），
`z-active`/`z-hold` 走 PAGE_UXN 模式。root 程序：`--mode page|brk`。

## 10. 第三轮：目标页 AP[1] 数据陷阱与相邻 LL/SC 桥

### 10.1 触发本轮的特征

2026-11-05 的取指复核在 `PAGE_UXN` 活动页上新增了
[`ud_observe_execution()`](native/urov_observe.c)：在同一页执行
`BTI C; RET` canary，前后各做一次 `LDXR/STXR`。活动页 255/255 全部命中，
669 次对照中 668 次阴性、1 次 UNKNOWN。原因不是代码字节，而是 EL0 取指进入
EL1 处理，`ERET` 把本地独占监视器恢复为 Open Access；canary 本身不读数据，
所以这个信号独立于伪值和调用窗口。上一轮 §9 的结论"读取点页不在 EL0 原生
取指"因此从纸面残余变成了可复现的检测点。

### 10.2 三种模式的硬件边界

要让普通 `LDR` 返回伪值，必须在这条 load 上截获它。EL0 可用的页级硬件分离只有：

| 控制位 | 影响的访问 | 不影响 |
|---|---|---|
| `AP[1]`（PTE_USER） | EL0 数据读写 | EL0 取指 |
| `UXN` | EL0 取指 | EL0 数据读写 |

AXI 上没有"按 PC 决定数据权限"的位；任何同步异常进入 EL1 后再 `ERET`，都会清
本地独占监视器。因此三种已知模式是一个三角形，不能同时把三个角都消掉：

| 模式 | 代码页字节 | 目标页数据读 | 取指 canary | 独占监视器 |
|---|---|---|---|---|
| BRK | 改 4 字节、私有 COW | 原生 | 原生（NO_MATCH） | 原生（NO_MATCH） |
| PAGE_UXN | 不改、干净文件页 | 原生 | **命中（指令异常）** | 原生（NO_MATCH） |
| PAGE_AP | 不改、干净文件页 | **陷阱（数据异常）** | 原生（NO_MATCH） | 需桥接 |

本轮选择 `PAGE_AP`：当前检测集中，取指 canary 是确定性的、每次调用都成立的
阳性；独占监视器只在特定 `LDXR/load/STXR` 形状上成立，可以用相邻桥接把该形状
恢复成原生结果。代价是保留一个"数据读进 EL1"的机制，残留在 §10.7 明说。

### 10.3 机制

`UROV_Y_MODE_PAGE_AP`（ABI v6，`mode = 3`）：

1. **目标页只清 `PTE_USER`（AP[1]）**。VMA、`vm_flags`、`vm_page_prot`、文件页、
   code page 全都不动；`UXN=0`，因此目标页和读取点页的 EL0 取指都是原生。目标
   可以是一页共享专用别名，也可以是普通 app 私有、多页、带 `VM_MAYWRITE` 的
   `.text` 中的一页，见 §12。
2. **数据异常由已有的 `do_mem_abort` hook 接管**：EC `0x24`、`WnR=0`、
   FSC permission、`mm` 属于会话、`FAR` 落在目标页。命中后仍走
   `uy_emulate_load()`：调用者窗口内合并伪值，窗口外从注册快照逐字节透明模拟。
   目标页的读不再经 `copy_from_user_nofault()`，避免去走刚刚清掉的权限。
3. **相邻 LL/SC 桥**。数据异常返回前检查故障 PC 的紧邻指令：

   ```text
   LDXR/LDAXR  Xt, [Xn]        ; PC-4
   LDR/LDRB    ..., [target]   ; PC，发生 permission abort
   STXR/STLXR  Ws, Xt, [Xn]    ; PC+4
   ```

   若 `Xn`、`Xt` 一致，handler 先保存 `Xn` 的地址和 store 宽度；模拟 load 后再用
   内核 nofault 写完成这次 store，把 `Ws` 置 0，并把 PC 直接推进到 `PC+8`。
   于是调用者看到 `STXR` 成功，和没有陷阱时一样。`ctl0 status` 的 `llsc` 计数
   每次桥接加一。桥只处理**紧邻**的三条指令，不是通用 LL/SC 模拟器。
4. **生命周期**：注册时先用 `access_remote_vm()` fault-in 目标页并快照，再在
   `mmap_write_lock` 下复核 VMA/PTE、清目标页 AP[1] 并 `flush_tlb_all`（PTE 被
   回收时重新 fault-in 重试）；
   `handle_mm_fault` 的 after-hook 在目标页重新装回后再次清 AP[1]；clone 前恢复、
   clone 后重装；注销/卸载恢复 AP[1]。`mprotect/munmap/mremap/mmap(MAP_FIXED)/
   madvise/execve` 门控与 §9 相同。站点表在 AP 模式只做状态记账，不改站点页。
5. **hook 集合不变**：仍是 `brk_handler`、`prctl`、六个门控、`clone/clone3`、
   `do_mem_abort`、`handle_mm_fault`，`hooks=0x7f`；没有新增 hook 或 syscall 表项。

### 10.4 为什么当前三类检测都归零

- **取指 canary**：站点页 `UXN=0`、目标页 `UXN=0`，`BTI C; RET` 在 EL0 原生执行，
  不产生任何异常，独占监视器保持；`ELIM_EXEC` 的 `expected` 从 `1` 改为 `0`。
- **独占监视器**：检测的 `LDXR scratch / LDRB target / STXR scratch` 正好是 10.3
  的紧邻形状；`LDRB` 的 permission abort 被透明模拟，`STXR` 由桥完成并返回 0。
  实测 `llsc` 非零（`w-active repeats=30` 的一次轮询最大 12,480），同时
  `exclusive_match=0`。若桥不生效，`urov-x` 阳性对照会立即给出 `match>0`。
- **跨 PC 内容差异**：检测器从 `ud_observe_reader()` 调用裸站点函数时，`x30`
  不在注册业务窗口，handler 从注册快照返回原字节；直接标量读也走同一路径。
  `direct == reader == file`，`reader_diff=NO_MATCH`。
- **代码页/映射/文件**：不改字节、不 COW、不改 VMA；`ELIM_RESIDUAL` 的
  `site_file_word == site_live_word`、`site_cow_private=0`、`Private_Dirty/Anonymous`
  与基线相同。
- **业务功能**：窗口内的 `uy_business_ldr/ldrb` 仍返回伪值，`hits>0`，
  `failures=0`，worker 持续执行业务函数。

### 10.5 ABI 与状态

`struct urov_y_request` 布局不变，`UROV_Y_ABI_VERSION = 6`，新增
`UROV_Y_MODE_PAGE_AP = 3`。`ctl0 status` 增加 `llsc=` 并把模式名扩展为
`site-trap|page-trap|data-ap`；`mode=3` 的 `mode`/`flags` 回显与 v5 一致。

### 10.6 为什么不是其他方案

| 方案 | 否决原因 |
|---|---|
| 业务入口 trampoline / 影子站点页 | 需要额外 RX 映射或改业务页，检测器换个采样页就能看见；比目标页的既有合作面更大 |
| 硬件观察点/断点 | 调试寄存器要跨上下文切换维护，且同样产生同步异常，仍要 LL/SC 桥；新增 root 可见的调试状态 |
| 影子物理页 / I-D cache 不一致 | 取指会跑到伪字节，或任何 cache 维护就失效（§6 已否决） |
| 数据页 AP[1] + 改 `vm_page_prot` 全局生效 | 目标 VMA 只有一页时可行，但会扩大 VMA 级影响面，且不能消除同步异常本身；本轮保留 after-hook 方案 |
| 把 STXR 指令改成 BRK | 又回到代码页差异；且需要按线程恢复，窗口不可避免 |
| 只让业务调用触发异常、检测读原生 | 无法按 PC 给数据权限；除非在业务入口再 trap，仍是新页面特征 |

### 10.7 残余特征与限制（诚实清单）

1. **时间**：每次业务/检测读一次数据异常，实测 `site_call_ns=273..281`；未注册时
   2–6 ns。与 BRK/UXN 同一量级，不作为零开销承诺。
2. **LL/SC 形状**：桥只覆盖 `LDXR/LDAXR`、load、`STXR/STLXR` 三条紧邻指令。
   `LDXR; NOP; LDRB; STXR`、中间有函数调用/分支、或 `LDXR` 与 `STXR` 不在同一
   基本块时，STXR 仍会失败，检测器可据此得到 MATCH。这是数据陷阱的固有代价，
   不是桥能普遍消除的。
3. **桥的语义**：store 由内核 nofault 写完成，不是真正的独占 store；多线程争用
   同一 scratch、`STLXR` 的 release 顺序、以及 store 的原子性都不完全等价原生。
   当前检测的 scratch 是线程私有栈，未触发这些边界。
4. **不支持的数据访问**：SIMD/FP、原子/独占 load、跨页、未知编码仍 fail-closed
   （SIGSEGV）。检测器若故意在目标页做这类访问，会得到信号；本轮检测核心不使用。
5. **PTE 重新装回窗口**：目标页被回收后，内核先按 VMA 装一个 user PTE，
   after-hook 再清 AP[1]；几微秒内另一 CPU 上的读可能原生返回原值。触发需要
   内存压力或 GUP 路径，本轮未观测到。
6. **业务路径复现即功能本身**：把注册的业务包装当 reader 仍会看到伪值；这是
   合作模型的边界。
7. **映射门控**：与目标页相交的 `mprotect/munmap/mremap/mmap(MAP_FIXED)/madvise`
   会结束会话；`execve` 结束会话。与 §9 相同。
8. **root 可观察性**：模块清单、`ctl0 status`、`do_mem_abort`/`handle_mm_fault`
   的 inline hook 仍对 root 可见。
9. **控制 UNKNOWN**：本轮在无模块的 clean 页上出现过 1 次目标 STXR 瞬时失败
   （UNKNOWN，不是 MATCH）；这与 §3 的对照设计一致，不能计作阳性，也不能据此
   声称零误报。
10. **注册事务窗口**：目标页 AP[1] 已清、`g_state` 尚未发布时，同 mm 的并发读
    可能走原生 permission fault。`REGISTER` 是合作事务，调用方必须在返回后再
    开始业务读取；`PAGE_UXN` 的站点页也有同一形状的窗口。

### 10.8 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1              # urov-y.kpm + urov_y_test（三种模式）
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 6 --cycles 2
```

App 模式新增 `w-active`/`w-hold`（`mode=3`），root 程序新增 `--mode ap`。
`y-*` 仍是 BRK 阳性对照，`z-*` 仍是 UXN 取指特征阳性对照。

## 11. 第四轮：LL/SC 桥的执行存证（PAGE_AP）

### 11.1 触发本轮的特征

2026-11-05 的无密钥复核新增了 `ud_observe_unreserved_store()`：32 组
「正常别名 → 目标页 → 正常别名」，每组三条指令

```asm
clrex
b    1f
ldxr x9, [x1]
1: ldrb w11, [x0]
stxr w10, x9, [x1]
```

`CLREX` 清空本地独占监视器，分支跳过 `LDXR`，目标页的 `LDRB` 进入 EL1。原生语义下
`STXR` 必须失败（`Ws=1`、不写内存、栈变量保持初值）；活动 `PAGE_AP` 的桥只按
"前一条是 `LDXR`、后一条是 `STXR`"匹配，于是代写了哨兵并把 `Ws` 置 0。真机 345 次
活动 AP 检查全部命中、11,040 次哨兵写入（其中主窗口 90/90；
[PAGE_AP_KEYLESS_RESULTS.md](PAGE_AP_KEYLESS_RESULTS.md)）。
这个信号与伪值、调用窗口、代码页都无关，是第三轮消除后留下的确定性特征。

### 11.2 根因：桥只匹配编码，不验证执行

`AP[1]` 异常必经 `ERET`，`ERET` 把本地独占监视器恢复为 Open Access。为了让
`LDXR; load; STXR` 看起来成功，handler 必须代写。代写的前提是"`LDXR` 确实执行过"，
但旧实现只比较相邻指令字，无法区分：

| 序列 | LDXR 是否执行 | Xt（STXR 数据寄存器） | [Xn] | 原生 STXR | 旧桥 |
|---|---|---|---|---|---|
| 正常 LL/SC | 是 | LDXR 装回的值 | 同一值 | 成功 | 代写成功（正确） |
| 分支跳过 LDXR | 否 | 调用者预置值 | 初值 | 失败 | **代写成功（特征）** |

`LDXR` 留给 handler 的唯一架构痕迹是目的寄存器 `Xt`：执行后它必然等于 `[Xn]`。
旧桥没有使用这个不变量。

### 11.3 机制：只对"有执行证据"的 STXR 代写

`uy_llsc_prepare()` 在发现紧邻形状后增加一次 nofault 读：

1. 读取 `LDXR` 的目的寄存器 `Xt` 与基址内存 `[Xn]`；
2. 要求 `LDXR`/`STXR` 宽度一致；`Xt=31`（`XZR`）没有可验证的寄存器，不桥；
3. 仅当 `Xt == [Xn]` 时才 armed；否则桥不生效，PC 只推进到 `STXR`，让它按原生
   路径执行。

结果：分支跳过的序列里 `Xt` 仍是调用者预置值，检查失败，`STXR` 原生执行并失败
（`Ws=1`、不写内存），与无模块完全一致；真正执行过 `LDXR` 的序列仍然代写成功，
`ud_observe_exclusive()` 继续阴性。该检查同时覆盖并发写：`LDXR` 与 `STXR` 之间
另一个 PE 改了 `[Xn]` 时，原生 `STXR` 也应失败，桥不再把失败改写成成功。

成本与暴露面：只在紧邻 LL/SC 形状的异常上多一次 `copy_from_user_nofault` 读
（同一 cache line、已在异常前被 `LDXR` 读过），没有新增 hook、PTE 位、指令改写、
调试寄存器或 syscall；`llsc` 计数只统计真正代写的次数。

### 11.4 被否决的替代方案

| 方案 | 否决原因 |
|---|---|
| 静态扫描 PC-8 的分支 | 只对当前探针的相邻 `b` 形状有效；从更远处或间接跳转仍可绕过，而且会误伤"从别处跳回 LDXR"的合法循环，重新引入监视器失效 |
| 去掉桥 | 回到第三轮前的独占监视器特征（`urov-x` 阳性对照） |
| 在 EL1 用 `STXR` 探测本地监视器 | AArch64 没有读监视器状态的指令；异常入口/`ERET` 是否清监视器由实现决定，探测本身会消费或误判 |
| 单步/硬件观察点 | 仍要 `ERET`，仍要桥；新增调试状态 |
| 把 `STXR` 改成 `BRK` | 又回到代码页差异 |

### 11.5 残余特征与限制（诚实清单）

1. **寄存器预置可伪造证据**：调用者若先读 `[Xn]`，把 `Xt` 预置成同一值再分支跳过
   `LDXR`，检查会通过。这是同一根因的残余：handler 无法区分"`LDXR` 装了同一值"
   与"调用者预置了同一值"。利用它需要显式的额外预置步骤；当前检测 App 不做。
2. **非紧邻形状**：`LDXR; NOP; load; STXR`、跨基本块、函数调用仍会看到监视器失效
   （§10.7.2 未变）。
3. **`Xt=31`**：`ldxr xzr` 没有可验证的寄存器，按 fail-closed 不桥。
4. **桥的语义**：仍是 nofault 写而非真正独占 store；`STLXR` 顺序、多线程争用
   （§10.7.3 未变）。
5. **时间**：每次读取仍一次同步异常（本轮 AP 实测 `site_call_ns≈275–280`）。
6. **PTE 重装窗口、root 可见性、注册事务窗口**：同 §10.7。

### 11.6 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 12 --cycles 2
```

单变量 A/B（同一 APK，旧/新 KPM）见
[PAGE_AP_KEYLESS_RESULTS_R2.md](PAGE_AP_KEYLESS_RESULTS_R2.md) 与
[results/ab-llsc-baseline-vs-verified](results/ab-llsc-baseline-vs-verified)。

## 12. 第五轮：普通 app 私有 `.text` 目标页

### 12.1 原限制与解除思路

前三轮的目标注册沿用旧 `urov-x` 的“专用页”假设：VMA 必须恰好一页、文件后备、
当前 RX、无 `VM_MAYWRITE`。普通 app 的 linker `.text` 是 `MAP_PRIVATE` 多页
VMA，私有文件映射天然带 `VM_MAYWRITE`（可被 COW），因此 CRC 夹具对 linker
`.text` 和私有 RX 别名的注册都得到 `EINVAL`（见
[CRC_INJECTION_RESULTS.md](CRC_INJECTION_RESULTS.md) 的历史负向段）。

但 `urov-y` 的三种模式都不写目标页：BRK 只写读取点页，UXN 只改读取点页 PTE，
AP 只清目标页叶子 PTE 的 `AP[1]`。目标页只需要“可读、文件后备、内容在会话
期间不被应用换掉”。因此把目标页校验与读取点页校验分开：

```text
目标页在 VMA 内（start <= address && end - address >= 4096）
VM_READ | VM_EXEC，无 VM_WRITE、PFNMAP、HUGETLB、VM_IO、VM_MIXEDMAP
vm_file != NULL
共享 VMA：仍要求恰好一页、无 VM_MAYWRITE（保持旧专用别名契约）
私有 VMA：允许 VM_MAYWRITE、允许多页（普通 .text / oat / 已装入 native lib）
```

`VM_WRITE` 始终拒绝，所以写入后未恢复 RX 的私有页仍返回 `EINVAL`。

### 12.2 注册事务

1. `access_remote_vm(mm, address, snapshot, 4096, 0)`：fault-in 目标页并取第一份
   快照。`copy_from_user_nofault()` 不会 fault-in，不能用于冷页。
2. `mmap_write_lock` → `find_vma` → 复核 VMA/PTE（present、user、read-only、
   UXN=0、非 CONT/SPECIAL/DEVMAP/PROT_NONE）→ 用 nofault 复制快照。
3. PTE 在锁窗口内被回收时返回 `-EAGAIN`，解锁后重新 `access_remote_vm`，最多
   重试 4 次；AP 模式的 `ap_arm_target()` 对同样的回收窗口也重试。
4. AP 模式只清目标页 `PTE_USER`。`handle_mm_fault` after-hook 在目标页重新装入
   PTE 后再次清 `AP[1]`；注销/卸载恢复 `PTE_USER`。

会话归属、映射门控、fork 前后恢复、死 owner 回收和卸载顺序都不变；目标页仍不
pin、不写字节、不改 VMA。

### 12.3 真机验证

Pixel 6（Android 16、6.1.134）上的 `crc-ap-text` 直接注册
`liburovdetect.so` 的 linker `.text` 页：VMA 90,112 字节、`r-xp`、私有、
`maywrite=1`，页 `Private_Dirty=0`、`Anonymous=0`。覆盖中业务窗口读到伪值
（CRC `0c7da8a0`），执行仍返回 `0x1234`，裸站点/直接读回原 CRC
`f50bcaf6`；注销后全部恢复。15 轮 × 3 cycle，`hits=180/轮`、
`replays=360/轮`、`failures=0`。完整矩阵 20 次运行全 PASS，root
`urov_y_test --mode ap` 33 项断言通过。数据与复现见
[CRC_INJECTION_RESULTS.md](CRC_INJECTION_RESULTS.md) 与
[results/crc-20261106-002515](results/crc-20261106-002515)。

### 12.4 libc 读者与嵌套调用

`crc-ap-libc` 用 32 字节 fake 窗口注册同一 `.text` 页，业务窗口只覆盖
`crc_libc_business()`。`memcpy`/`memcmp`/`strlen` 是 bionic 的叶子函数，load
处的 `x30` 直接落在业务窗口内；zlib `crc32` 会调用内部 helper，load 处的
`x30` 在 libz 内。后端新增 `caller_allowed_deep()`：当前 LR 不命中时沿
`x29` 帧链最多回溯 16 层，用 `copy_from_user_nofault` 读 `[x29]`/`[x29+8]`，
命中任一保存的返回地址即允许伪值。没有帧指针时自动退回原行为。

实测 `memcpy12`、`memcmp32`、`strlen31`、zlib `crc32` 直接读页和读复制缓冲
都得到伪值；窗口外直接读/裸站点读仍是原值，执行仍是原指令，注销恢复。
15 轮 × 3 cycle 的 `hits=360/轮`、`replays=504/轮`、`failures=0`。

这个修复覆盖的是标量 libc 路径。bionic `memcpy` 从 16 字节起、`memcmp`
从 160 字节起、`strlen` 越过前 32 字节后会使用 SIMD `LDR q`/`LDP q`；这些
大范围路径仍 fail-closed（SIGSEGV），要支持它们需要 FPSIMD 向量寄存器模拟，
是下一层改动。内核辅助读取仍看到真实字节。

### 12.5 残余

1. 目标页若是之前已被 COW 的私有页，页内容不再来自文件；会话期间它仍受映射
   门控保护，但“文件后备内容不变”的证明不再成立。当前实现不检测 PTE 背后的
   page 是否仍是文件页。
2. 通过 `/proc/self/mem`、ptrace、`process_vm_readv` 的内核辅助读取仍看到真实
   字节；这是合作模型，不是隔离。
3. 目标页被回收后，新 PTE 安装到 after-hook 重新清 `AP[1]` 之间有一个极窄的
   窗口，其他线程可能读到原字节；与 §10.7 的注册/重装窗口同类。
4. 门控检查 `mremap` 的源区间和 `MREMAP_FIXED` 的目标区间；`pkey_mprotect`、
   `remap_file_pages` 等未 hook 的映射路径仍是残余，应用自己换掉目标页后覆盖
   会静默失效（不涉及内存安全）。

## 13. 第六轮：大长度 libc 传输——SIMD&FP load 与整页覆盖

### 13.1 触发本轮的限制

§12.4 把业务窗口从"只查当前 `x30`"扩展到 `x29` 帧链，标量路径的
`memcpy`/`memcmp`/`strlen`/zlib `crc32` 因此都能命中。但 bionic 在更大长度上
换指令（对 `libc.so` 的目标实现反汇编确认）：

| 函数 | 标量路径 | 转入 SIMD 的阈值 | 用到的 load |
|---|---|---|---|
| `memcpy` | `<16` 字节（`ldr/ldur` x/w/h/b） | `>=16` | `ldr q`、`ldur q`、`ldp q`（含前索引 `ldp q1,q2,[x1,#0x20]!`） |
| `memcmp` | `<160` 字节（`ldp x` 对 + 尾部标量） | `>=160` | `ldr q`（含写回 `ldr q0,[x0,#0x40]!`） |
| `strlen` | 前 32 字节（`ldp x,x`） | 之后每 32 字节块 | `ldp q1,q2,[x1,#0x20]!`（页尾对齐例外用 `ld1 {v1.16b,v2.16b}`） |

旧实现只模拟 GPR load：`uro_decode()` 对 bit26=1 的 SIMD&FP 编码一律失败，
`uy_emulate_load()` 于是 fail-closed（SIGSEGV）。同时 `UROV_Y_FAKE_MAX == 32`，
请求里只有 `value`+`value_hi[3]`，即使指令能模拟，一个 4 KiB 调用也只能改前
32 字节。**"足够大长度的函数调用修改"卡在两处：向量寄存器没有提交路径，覆盖
镜像也放不下。**

### 13.2 机制

1. **解码**（`decode.c`）。新增 SIMD&FP load 的四组编码：

   | 掩码 | 形式 | 说明 |
   |---|---|---|
   | `(i & 0x3f000000) == 0x3d000000` | unsigned imm12 | `opc[0]` 是 load 位，`opc[1]` 仅与 `size==0` 合法地表示 128 位；`imm12 << log2(access)` |
   | `(i & 0x3f000000) == 0x3c000000` | unscaled / 前中后索引 / 寄存器偏移 | `S` 位对 128 位形式按 16 缩放（编码里 size 仍为 0） |
   | `(i & 0x3f000000) == 0x1c000000` | literal | `opc` 0/1/2 = 4/8/16 字节，3 是 PRFM |
   | `(i & 0x3e000000) == 0x2c000000` | LDP/STP pair | `opc` 0/1/2 = 4/8/16 字节元素 |

   store、`LDTR`、`LD1`/`LD2` 多结构、`opc=3` 组合一律拒绝（保持原生 fault 或
   fail-closed）。解码结果新增 `vector` 标志区分两类寄存器文件。
2. **共享核心不变**。`uro_emulate()` 在解码后立刻对 `vector` 返回
   `URO_UNSUPPORTED`，`urov-x`/`urov-lab` 的白名单和行为完全不变；
   `core_selftest` 增加 13 项解码/拒绝断言，总数 4139 → 4152。
3. **FPSIMD 提交**（`urov_y_backend.c`）。`PAGE_AP` 的数据异常里，向量 load 的
   合并字节不写 `pt_regs`（那里没有向量寄存器），而是走内核自己的保存/更新对：

   ```text
   fpsimd_signal_preserve_current_state();          /* live V0..V31 -> thread.uw.fpsimd_state */
   thread.uw.fpsimd_state.vregs[rt]  = merged;      /* 标量 load 先零扩展 16 字节 */
   thread.uw.fpsimd_state.vregs[rt2] = merged2;     /* LDP 的第二个寄存器 */
   fpsimd_update_current_state(&thread.uw.fpsimd_state);  /* 装载 + 绑定 CPU + 清 FOREIGN */
   ```

   选内核 helper 而不是内联 `stp q`：`preserve` 在 `TIF_FOREIGN_FPSTATE` 置位时
   不覆盖权威的内存副本（软中断 NEON、KVM、ptrace 场景），`update` 负责重绑 CPU
   并在返回 EL0 前清 foreign 标志。`thread.uw.fpsimd_state` 的偏移来自运行内核
   BTF（`task_struct.thread` → `uw` → `fpsimd_state`），并用 BTF 复核
   `user_fpsimd_state` 的 `vregs/fpsr/fpcr` 布局；缺任一 helper 或布局时
   `g_fp_ready=0`，向量 load 继续 fail-closed，`ctl0 status` 的 `fpsimd=0` 明示。
4. **整页覆盖镜像（ABI v7）**。请求从 240 字节扩到 256 字节，新增
   `uint64_t fake_addr`（`length > 32` 时指向调用者缓冲区）与 `uint64_t reserved`
   （必须为 0）。`length` 允许 8..4096（8 的倍数），`offset+length <= 4096`；
   `<=32` 仍可用 `value`/`value_hi` 内联，旧夹具不改。`REGISTER`/`SET` 先用
   `access_remote_vm()` 把调用者镜像拷到模块暂存区（可在 seqlock 外 fault-in），
   再在 seqlock 内 4 KiB 拷贝发布，并把前 32 字节镜像回 `value`/`value_hi`
   （`STATUS` 仍按老格式回显）。故障路径只按当前 load 的 ≤32 字节逐字节合并，
   因此 4 KiB `memcpy`（128 条 `LDP Q`）每次只读 32 字节镜像。
5. **失败语义**。没有 FPSIMD 能力 → `-6`（SIGSEGV）；seqlock 重试耗尽 → `-4`；
   配置非法 → `-3`；绝不返回原字节冒充伪值。`PAGE_AP` 的 store 不进本路径
   （`WnR=0` 过滤），只读映射的 store 仍按原生权限 fault。

### 13.3 与既有性质的关系

- **仍然每次 load 一次同步异常**：§10 的 LL/SC 桥、§9 的取指 canary、代码页与
  映射特征都不变；`crc-ap-big` 中 `smaps` 的 `Private_Dirty/Anonymous` 仍为 0。
- **业务窗口语义不变**：只有窗口内的调用拿伪值；窗口外的 4 KiB `memcpy` 走
  `replay`（读注册快照），实测与直接标量读逐字节一致。
- **站点指令仍必须是 GPR load**：`site_ok()` 显式拒绝 `vector`，BRK/UXN 模式的
  可控指令集不变；只有 `PAGE_AP` 由故障地址选中，才服务向量 load。
- **注销/卸载不涉及向量状态**：FPSIMD 只在异常处理里改一次当前任务的寄存器，
  不 pin、不改 PTE/映射、不留跨会话状态。

### 13.4 真机验证

Pixel 6（oriole，Android 16，6.1.134，KP `0xc00`）。`urov-y.kpm` SHA256
`f9d29744…32a8`，`urovdetect.apk` SHA256 `a18622d1…19464`；
`run_crc_device.py --repeats 5 --cycles 2` 共 16 次运行全部 PASS，`crc-ap-big`
两轮一致：

| 观察量 | 值 |
|---|---|
| 4 KiB `memcpy(target)` 目的地 CRC32 | `71515206`（= `CRC_BIG fake_crc`） |
| 16/32/64/160/512/1024/4096 字节 `memcpy` | 全部等于伪镜像前缀 |
| `memcmp(target, fake, 4096)` | 0 |
| `strlen(target)` | 4095（SIMD 32 字节块，终止符在页尾） |
| zlib `crc32(0, copy, 4096)` | `71515206` |
| 窗口外 4 KiB `memcpy` / 标量读 | `0adadb20`（= 原页 CRC32） |
| 伪镜像与原页 CRC32 | `71515206` ≠ `0adadb20` |
| 32 字节内部窗口（offset 64） | `window_crc=d1f7ac49`，窗口边界外逐字节保持原页 |
| 同一会话 `SET` 32 字节新值 | `generation=2`，`window_crc=fd83e7b5` |
| 计数器 | `hits=4242 replays=21125 failures=0 length=4096` |
| 注销后 | 页面 CRC32 恢复 `0adadb20`，`kpm list` 为空 |
| 内核增量 | 无 BUG/WARNING/Oops/stall，`kernel_issues=[]` |

数据：[results/crc-20261106-212757](results/crc-20261106-212757/summary.json) 与
[CRC_INJECTION_RESULTS.md](CRC_INJECTION_RESULTS.md)；同一构建的
`run_elimination_device.py --repeats 3 --cycles 1` 矩阵 14 次运行 PASS
（[results/eliminate-20261106-212835](results/eliminate-20261106-212835/summary.json)，
含 `urov-x` 阳性对照、三种模式、不同 UID、活动期卸载，`kernel_issues=[]`）；root
夹具 `urov_y_test --mode ap` 回归 33 项断言 PASS。

### 13.5 残余特征与限制（诚实清单）

1. **只有 `PAGE_AP` 支持向量 load**。BRK/UXN 模式的站点指令仍必须是 GPR load；
   把站点换成 `ldr q` 会被 `site_ok()` 拒绝（`EINVAL`）。
2. **多结构 load**：`LD1`/`LD2`/`LD3`/`LD4`（`strlen` 的页尾对齐例外用到
   `ld1 {v1.16b,v2.16b}`）不在白名单，命中即 fail-closed（SIGSEGV）。
3. **SVE/SME**：Pixel 6 无 SVE；带 SVE 的内核上 `TIF_SVE` 任务的低 128 位由
   内核 helper 保持一致，但谓词/高 128 位不受覆盖，SVE 指令仍拒绝。
4. **跨页**：覆盖仍限一页；跨页单条 load 仍 fail-closed，超过 4 KiB 的函数调用
   只修改注册页内的那 4 KiB，其余页原样。
5. **FPSIMD 提交的成本与语义**：每条向量 load 一次异常 + 一次
   `fpsimd_preserve`/`fpsimd_update`（两段 `local_bh_disable`）。`fpsr`/`fpcr` 按
   原值回写，其它 V 寄存器保持不变；异常上下文里没有新增睡眠点。
6. **整页镜像发布**：`SET` 在 seqlock 内做 4 KiB 拷贝（约 1 µs），此间故障读会
   短暂自旋；重试上限耗尽按 fail-closed 处理。`REGISTER` 的镜像拷贝在会话发布
   前完成，不存在半镜像窗口。
7. **残余检测面**：向量 load 与标量 load 一样进 EL1（每 16/32 字节一次数据
   异常），时间特征仍是 §10.7 的量级；FPSIMD 状态改写由内核 helper 完成，不额外
   改 `pt_regs`/PTE/代码页。root 仍可观察 hook 与 `ctl0 status`。
8. **合作模型**：调用者自己声明业务窗口与目标页；同进程代码直接调用已注册的
   业务函数仍会拿到伪值（§12.4 的边界不变）。

### 13.6 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 5 --cycles 2
```

新增场景 `crc-ap-big`：整页 4096 字节伪镜像（`fake_addr`）、16..4096 字节
`memcpy`/`memcmp`/`strlen`/`crc32`、32 字节内部窗口（offset 64）与同会话 `SET`。
主机侧 `tools/test_host.sh` 仍通过 58 个汇编语料向量与 4152 项核心自测。

## 14. 第六轮：相邻 LL/SC 桥的执行存证恢复

### 14.1 触发本轮的特征

`APP_READ_INTEGRITY_AUDIT.md` 的第 1 条检测：`LDXR scratch; LDRB target; STXR
scratch` 的配对读。`PAGE_AP` 的 EL0 数据异常必然经过 `ERET`，本地独占监视器被
清，目标 `STXR` 稳定失败；2.4.0/2.4.1 已移除旧桥，因此该信号对 AP 是确定性的
阳性。2.5.0 需要在不恢复“分支跳过 `LDXR` 也代写”的前提下消除它。

### 14.2 机制

`uy_llsc_prepare()` 在 AP 数据异常里只使用故障前的寄存器快照，按故障 PC 匹配：

```text
LDXR/LDAXR  Xt, [Xn]        ; PC-4
LDR/...     Wd, ...         ; PC，发生 permission abort
STXR/STLXR  Ws, Xt, [Xn]    ; PC+4
```

要求：

1. 两条独占指令的 `size`、`Rn`、`Rt` 一致；`Xn != XZR`、`Xt != XZR`。
2. 中间的 load 不写 `Xt` 或 `Xn`；带写回且写 `Xn` 的形式拒绝。
3. `Xt` 仍等于 `[Xn]`（按宽度零扩展）；`LDXR` 确实执行且数据未被改写。
4. `Xn` 自然对齐；`copy_from_user_nofault` 能读到 `[Xn]`，`copy_to_user_nofault`
   能写回，且待写值等于当前内存。
5. 模拟 load 成功、`PC` 已推进到 `STXR` 后才提交：写回同一值、`Ws=0`、`PC+=4`，
   `STLXR` 追加 `dmb ishst`，`g_sess.llsc` 加一。

因此：

| 序列 | `Xt` | `[Xn]` | 原生 `STXR` | 2.5.0 |
| --- | --- | --- | --- | --- |
| 正常 LL/SC | `LDXR` 装回的值 | 同一值 | 成功 | 代写同一值，`Ws=0`（等价） |
| 分支跳过 `LDXR` | 调用者预置的哨兵 | 初值 | 失败、零写入 | 不桥，原生失败、零写入 |
| 并发写改了 `[Xn]` | `LDXR` 旧值 | 新值 | 失败 | 不桥，原生失败 |
| `Xt=XZR` / 非紧邻 / 成对 | — | — | 由原生决定 | 不桥 |

`ud_observe_unreserved_store()` 的 `CLREX/B;LDXR` 探针仍是反向验证：它不预置
`Xt==[Xn]`，2.5.0 上必须保持 `match=0`、`stores=0`。

### 14.3 被否决的替代方案

| 方案 | 否决原因 |
| --- | --- |
| 不桥，接受 `STXR` 失败 | 正是本轮要消除的确定性特征 |
| 在 EL1 用 `STXR` 探测本地监视器 | 异常入口/IRQ/调度是否清监视器由实现决定，探测自身消费监视器；无法区分“未执行 `LDXR`”和“已被内核清掉” |
| 单步/硬件观察点 | 仍是同步异常 + `ERET`，仍要桥，且新增调试状态 |
| 改 `STXR` 指令为 BRK | 回到代码页差异（§9 已消除的特征） |
| 只按相邻编码匹配 | 重新引入 `CLREX/B;LDXR` 的代写特征（§11） |

### 14.4 真机验证

Pixel 6（oriole，Android 16，6.1.134，KP `0xc00`，4 KiB）。2.5.0 构建：

- `run_crc_device.py --dobby-detection --repeats 24 --cycles 5`：5 次活动运行，
  `DOBBY_DETECT stage=overlay` 全部 `match=0/24`、`clean=24`、`unknown=0`、
  `accepted_crc=24`，合计 11,520 个目标三元组 0 失败；`execute=0x1235`、
  `live_crc=file_crc=96964c4f`。同一 APK 在 2.4.1 上是 `match=24/24`、
  `accepted_crc=0`。
- `run_elimination_device.py --repeats 6 --cycles 1`：`w-active` 的
  `active_page`/`active_outside_window`/`active_after_set`/`active_equal_value`
  均 `exclusive_match=0`、`exclusive_clean=6`；`ud_observe_unreserved_store`
  全部 `stores=0`；8 CPU store 探针 0 写入；三种模式、不同 UID、活动期卸载全部
  PASS。
- `w-active --repeats 200` 活动期轮询 `ctl0 status`：`llsc=42,952`、
  `failures=0`，证明代写确实发生。
- `run_crc_device.py --repeats 5 --cycles 1`、`run_multipage_device.py` 回归
  PASS，`kernel_issues=[]`、测试后模块列表为空。

数据：[dobby-detect-20261107-140230](results/dobby-detect-20261107-140230/summary.json)、
[eliminate-20261107-140259](results/eliminate-20261107-140259/summary.json)、
[crc-20261107-140417](results/crc-20261107-140417/summary.json)、
[multipage-20261107-140448](results/multipage-20261107-140448/summary.json)。

### 14.5 残余特征与限制（诚实清单）

1. **形状**：只覆盖紧邻 `LDXR/LDAXR; load; STXR/STLXR`；`NOP` 间隔、跨基本块、
   函数调用、成对 `LDXP/STXP` 仍会看到监视器失效。
2. **预置证据**：调用者先读 `[Xn]`、把 `Xt` 预置为同一值、再分支跳过 `LDXR`，
   桥仍会代写。待写值等于内存，因此只改变 `Ws`，不改变内存；检测 App 的现有
   `CLREX/B;LDXR` 探针不预置该值，保持阴性。
3. **`Xt=XZR`**：没有可验证寄存器，不桥。
4. **时序/并发**：`copy_to_user_nofault` 的 store 是普通写，不是硬件独占 store；
   `STLXR` 的 release 顺序用 `dmb ishst` 近似，多线程争用同一 scratch 的语义
   不完全等价。
5. **时间**：仍每次读取一次同步异常，实测 `site_call_ns≈289`（窗口外）与 2.4.1
   同量级；桥额外两次 nofault uaccess，但只在紧邻 LL/SC 形状发生。
6. **PTE 重装窗口、root 可见性、注册事务窗口**：同 §10.7。
7. **合作模型**：调用者自己声明业务窗口；同进程直接调用已注册业务函数仍拿伪值
   （§12.4 的边界不变）。

### 14.6 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --dobby-detection --repeats 24 --cycles 5
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 6 --cycles 1
```

`dobby_crc_fixture.inc` 的 overlay 阶段已把 `expect_trap` 改为 `false`：旧断言
把“AP 必然让 `STXR` 失败”当作预期，2.5.0 起该特征不存在。`w-active` 的 AP
期望也从 `UD_MATCH` 改为 `UD_NO_MATCH`；`ud_observe_unreserved_store` 仍要求
`UD_NO_MATCH` 且零写入。

## 15. 第七轮：直接分支门控与 NOP 间隔桥

### 15.1 触发本轮的特征

`APP_READ_INTEGRITY_RESULTS.md` 的“普通 App 无密钥复核”新增
`ud_observe_unreserved_status()`：

```asm
clrex
b 1f
ldxr x9, [x1]        ; never executed
1: ldrb w10, [x0]    ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]    ; Rt was pre-set to [x1]
```

2.5.0 的桥只用寄存器状态判断 `LDXR` 是否执行：`Rt == [Xn]`。调用者在跳过 `LDXR`
之前把 `Rt` 预置为 `[Xn]`，即可让桥代写同一值、`Ws=0`，探针得到 MATCH。同一份报告
还把 `LDXR; NOP; LDRB; STXR` 列为形状残余。

本轮先尝试“在 EL1 重放 `STXR` 探测本地独占监视器”：用 `pgtable_entry()` 走页表
得到 `[Xn]` 的物理地址，再在 KernelPatch 线性映射别名上执行同一宽度、同一值的
`stxr`。设备上别名内容与用户页逐字节一致（校准读数比对通过），但真实 `LDXR`
之后的 `stxr` 仍稳定返回 1：数据异常进入 handler 之前本地监视器已经不可用。监视器
不能提供执行存证，本轮改为从控制流取证。

### 15.2 机制

`uy_llsc_prepare()` 在原有约束（宽度、`Rn`/`Rt` 一致、自然对齐、`Rt == [Xn]`、
待写值等于内存）之上增加：

1. **NOP 间隔**：从故障 PC 向前最多 4 条指令内查找 `LDXR/LDAXR`，只允许中间是
   `NOP`；覆盖 `LDXR; NOP; LDRB; STXR` 形状。
2. **直接分支门控**：扫描故障 load 所在页前后各 256 字节，解码
   `B/BL/CBZ/CBNZ/TBZ/TBNZ`；若任一直接分支的目标等于 load PC，说明该路径可以
   绕过 `LDXR` 进入 load，handler 不设置 `valid`，PC 停在 `STXR` 上由原生指令
   报告失败。扫描只读，越界/未映射段自动截断。
3. **提交条件不变**：模拟 load 成功后 `copy_to_user_nofault` 写入同一值、`Ws=0`、
   `PC += 4`；写入失败时 PC 仍停在 `STXR`。`STLXR` 的 release 用 `dmb ishst`
   近似，`LDAXR` 的 acquire 用 `dmb ishld`。

| 序列 | 控制流 | 原生 `STXR` | 2.6.0 |
| --- | --- | --- | --- |
| 紧邻 / `NOP` 间隔，顺序到达 | 经过 `LDXR` | 成功 | 代写同一值，`Ws=0`（等价） |
| 直接分支跳到 load | 跳过 `LDXR` | 失败 | 不桥，原生失败 |
| `Rt` 预置但顺序到达 | 经过 `LDXR` | 成功 | 代写（等价；只改 `Ws`） |
| `Rt` 预置且分支跳过 | 跳过 `LDXR` | 失败 | **不桥**（本轮消除） |
| 间接分支跳到 load | 跳过 `LDXR` | 失败 | 门控不覆盖，仍是残余 |
| `Xt=XZR` / 成对 / 非自然对齐 | — | 由原生决定 | 不桥 |

### 15.3 为什么没有引入新的可观察量

- 没有新增 hook、syscall 表项、PTE/VMA/代码字节改动；门控只“少写一次”，不改变
  任何已有可见状态。
- 扫描只读代码页（代码页本身被注册时改用注册快照），不触碰目标页，不产生新的
  uaccess 失败路径。
- 监视器实验只用于选型；最终代码不含 `STXR` 探测、线性映射别名或额外页表操作。
- `ctl0 status` 字段、ABI v8 布局和 `hooks=0x7f` 不变。

### 15.4 残余特征与限制（诚实清单）

1. **间接分支**：`BR/BLR`、`ADR/ADRP + BR`、从字面量池取目标等间接控制流不在
   解码范围，仍可跳过 `LDXR` 并触发代写。
2. **窗口外分支**：直接分支在故障 PC 的 ±256 字节之外或另一页时不参与判定。
3. **保守误伤**：`LDXR` 之前的条件分支若落到 load（条件不成立时本来会顺序执行
   `LDXR`），被视为“可能跳过”，桥不生效、原生 `STXR` 失败。这是门控的代价。
4. **桥的语义**：store 仍是内核 nofault 普通写，不是硬件独占 store；多线程争用
   同一 scratch、`STLXR` 的 release 顺序和 store 原子性不完全等价原生。
5. **时间**：每次桥接候选额外扫描两个 256 字节窗口；仍每次读取一次同步异常。
6. **PTE 重装窗口、root 可见性、注册事务窗口**：同 §10.7 / §14.5。
7. **合作模型**：`caller_count > 0` 时窗口内/外读者差异仍是有意保留的 API 语义。

### 15.5 真机验证

Pixel 6（oriole，Android 16，6.1.134，KP `0xc00`，4 KiB）。构建
`urov-y.kpm 32c0eaca05b36e748196406c2cf5066be88f436bf8e487376af424c44b342b9b`、
`urovdetect.apk 494d942930710447d14cd1087a314b8d4bd11d9c46f4d5695453be44c01be681`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 24×5 | PASS；5 轮活动阶段 `bridge_match=0/24`、`spaced_match=0/24`、`accepted_crc=24/24`、`unknown=0`；每轮 `hits=6528`、`failures=0`；`bridge_trials=768`、`bridge_successes=0` | [dobby-detect-20261107-162507](results/dobby-detect-20261107-162507/summary.json) |
| 消除矩阵 3×1 | PASS，12 次运行；`w-active` 32 个用例、418 条断言；11 项 `ELIM_BRIDGE expected=0 verdict=0 successes=0`；`exclusive_match=0`、`exclusive_clean=3`；store 探针 0 写入 | [eliminate-20261107-162803](results/eliminate-20261107-162803/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-162542](results/crc-20261107-162542/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-162615](results/multipage-20261107-162615/summary.json) |

四个矩阵测试前后 boot ID 相同，`kernel_issues=[]`，测试后 `kpm list` 为空。
`w-active` 的 `ELIM_TIMING mode=ap site_call_ns=283`，与 2.5.0 同量级；
`ELIM_RESIDUAL mode=ap` 的 `site_live_word == site_file_word`、`site_cow_private=0`、
`private_dirty_kb=anonymous_kb=0` 保持不变。

### 15.6 构建与验证入口

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --dobby-detection --repeats 24 --cycles 5
python .\kpms\urov-lab\tools\run_elimination_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 3 --cycles 1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 5 --cycles 1
python .\kpms\urov-lab\tools\run_multipage_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --skip-install --repeats 3 --cycles 1
```

`dobby_crc_fixture.inc` 的 overlay 阶段现在要求 `spaced_match=0` 且
`bridge_match=0`；`uy_fixture.inc` 的 `expected_bridge` 与逐 CPU 调用都改为
`UD_NO_MATCH`。`ud_observe_unreserved_store`（哨兵变体）仍要求 `UD_NO_MATCH` 且
零写入。

## 16. 第八轮：NOP 间隔分支与间接分支门控

### 16.1 触发本轮的特征

2.6.0 的直接分支门控只把“目标等于故障 load PC”的
`B/BL/CBZ/CBNZ/TBZ/TBNZ` 视为跳过 `LDXR`。新增的无密钥探针把分支目标落在
load 前的 `NOP` 上：

```asm
clrex
b 1f
ldxr x9, [x1]        ; never executed
1: nop
ldrb w10, [x0]       ; target page, AP[1] cleared -> data abort
stxr w8, x9, [x1]    ; Rt preset to [x1]
```

`uy_llsc_prepare()` 虽然允许 `LDXR` 与 load 之间有 0–3 个 `NOP`，但
`uy_llsc_skipped()` 只扫描目标等于 load 的分支。因此该形状仍被代写：handler
把同值写回 scratch、令 `Ws=0` 并跳过 `STXR`，探针得到 MATCH。2.6.0 报告里
该探针为 480/480 命中。同一窗口还留下两类残余：

- 直接分支位于故障 PC 的 ±256 字节之外，但仍落在同一代码页；
- `ADR/ADRP + BR`、literal load + `BR`、`RET` 等间接控制流。

### 16.2 机制

`uy_llsc_prepare()` 的寄存器、宽度、自然对齐、`Rt == [Xn]` 与待写值等于内存
等条件不变，新增两道只读门控：

1. **整页直接分支门控。** 扫描故障 load 所在页的
   `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ`；分块 512 字节，覆盖 4 KiB 与 16 KiB
   页。只要任一直接分支的目标落在闭区间 `[LDXR+4, load]`（NOP 间隔或 load
   本身），就不代写。这同时消除了“分支落到 NOP”和“±256 字节外的同页分支”。
2. **间接分支寄存器门控。** 故障发生时 load 尚未执行，`ADR/ADRP + BR`、
   literal load + `BR`、`RET` 等路径通常仍把目标地址留在某个 GPR 中。若
   `x0..x30` 任一值落在同一闭区间，就按“可能跳过 LDXR”处理，不代写。

门控只让 handler 少写一次；拒绝时 PC 停在 `STXR`，由原生指令报告失败，内存
不变。扫描不新增 hook、syscall、PTE/VMA/代码字节改动，也不新增 `ctl0` 字段
或计数器。

| 序列 | 控制流 | 2.6.0 | 2.7.0 |
| --- | --- | --- | --- |
| 紧邻 / NOP 间隔，顺序到达 | 经过 LDXR | 代写 | 代写 |
| 直接分支到 load | 跳过 LDXR | 不代写 | 不代写 |
| 直接分支到 NOP | 跳过 LDXR | **代写（特征）** | 不代写 |
| 同页 ±256 外直接分支到 load/NOP | 跳过 LDXR | 代写 | 不代写 |
| `ADR/ADRP + BR`、literal + `BR`、`RET` | 跳过 LDXR，目标仍在 GPR | 代写 | 不代写 |
| 间接分支且目标寄存器在 load 前被覆盖 | 跳过 LDXR | 代写 | 仍可代写（残余） |
| 跨页直接分支 | 跳过 LDXR | 代写 | 仍可代写（残余） |

### 16.3 为什么没有引入新的可观察量

- 没有新增 hook、syscall 表项、PTE/VMA/代码字节改动，也没有新增内核日志、
  `ctl0 status` 字段或 ABI 版本变化。
- 扫描只读故障页；512 字节分块使栈占用有界。门控只在 LL/SC 形状的故障上
  运行，普通 load 的 288–404 ns 路径不变。
- 间接门控只读取故障时的 GPR 快照，不写寄存器、不产生新异常。
- `hooks=0x7f`、`core_checks`、`caps`、ABI v8 布局不变。

### 16.4 真机验证

Pixel 6（oriole，Android 16，`6.1.134-android14-11`，4 KiB，KernelPatch
`0xc00`）。构建：

```text
urov-y.kpm      ff818b3ee62995b7353b30346ce7dca4b9601390f6edf2ce3ec9817b0c930d18
urovdetect.apk  e21607a7cd45c6061458eb3e4094c2c43e58f1a430980da4215e4572dbb8954d
```

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×1 | PASS；活动阶段 `nop=0/24`、`ind=0/24`、`bridge=0/24`、`spaced=0/24`、`accepted_crc=24/24`；执行仍为 `0x1235`，内存 CRC 等于文件 | [dobby-detect-20261107-171627](results/dobby-detect-20261107-171627/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、443 条断言；`ELIM_BRIDGE` 的直接、NOP、间接三项均 `verdict=0 trials=32 successes=0` | [eliminate-20261107-171731](results/eliminate-20261107-171731/summary.json) |
| CRC 矩阵 5×1 | PASS，9 次运行（BRK/UXN/AP/AP-all/text/libc/big） | [crc-20261107-171907](results/crc-20261107-171907/summary.json) |
| 多页/LD1/跨页/SRC_FILE | PASS，5 次运行 | [multipage-20261107-172858](results/multipage-20261107-172858/summary.json) |

最终 AP 业务调用耗时 288 ns（`ELIM_TIMING mode=ap`）；`ELIM_RESIDUAL mode=ap`
仍为 `site_file_word == site_live_word`、`site_cow_private=0`、
`Private_Dirty/Anonymous=0`。测试后 `kpm list` 为空，boot ID 不变。

### 16.5 残余特征与限制（诚实清单）

1. **间接分支的目标寄存器被覆盖**：在 load 之前若把 `BR` 的目标寄存器改成
   其他值，门控看不到区间地址，仍可代写。
2. **跨页直接分支**：从另一页跳入本页的分支不在单页扫描范围。
3. **保守误伤扩大**：本页任意位置有分支目标落在 `[LDXR+4, load]`，或任一
   GPR 恰好持有该区间地址时，即使实际顺序执行，桥也不生效，原生 `STXR`
   会失败。这是扩大门控范围的代价。
4. **时间**：每次读取仍一次同步异常；AP 业务调用 288 ns，UXN 约 404 ns。
5. **PTE 重装窗口、root 可见性、注册事务窗口**：同 §10.7 / §14.5 / §15.4。
6. **桥的语义**：store 仍是内核 nofault 普通写，不是硬件独占 store；多线程
   争用同一 scratch、`STLXR` 的 release 顺序和 store 原子性不完全等价原生。
7. **合作模型**：`caller_count > 0` 时窗口内/外读者差异仍是有意保留的 API
   语义。

> 2.8.0 后续：`SRC_FILE` 已移除，所有页镜像统一由 `SRC_USER` 提供（每个
> 描述符一次最多一页）。Dobby 夹具把干净整页读入用户缓冲区后注册；多页
> `mp-srcfile` 改为 `mp-srcpage`。上述 LL/SC 门控与结果不变，2.8.0 的
> Dobby 24×1 `accepted_crc=24/24`、多页 5 项、CRC 9 次、消除矩阵 11 次
> 运行继续 PASS。

## 17. 第九轮：REGISTER 期全进程分支目标位图

### 17.1 触发本轮的特征

2.8.0 的跨页探针把 `B` 放在故障 `LDRB` 所在页之前（`.p2align 14` 对齐），
`uy_llsc_skipped()` 只扫描故障页，因此仍然代写；探针预置 `Rt == [Xn]` 满足
寄存器存证，`CLREX` 只影响原生 `STXR`，不影响 handler。真机矩阵为
`cross_page MATCH 480/480`。

### 17.2 被否决的方案：硬件独占监视器

先尝试在 handler 里清 `PAN` 后对 STXR 目标发真实 `STXR`，用本地监视器判断
`LDXR` 是否真的执行。Pixel 6 上 `dbg prepare=2656 pte=0 ok=0 fail=2656`：
异常进入已使本地监视器回到 Open Access，该方案不可用。若把扫描放在故障路径，
首次访问每个新读取页要 50–130 ms，形成新的读取时间特征，也不采用。

### 17.3 机制

`REGISTER` 在 `ap_arm_pages()` 清任何 `AP[1]` 之前调用 `uy_code_build()`：

1. 在 `mmap` 读锁下用 `find_vma()` 枚举会话 `mm` 的所有 VMA；
2. 只保留同时带 `VM_READ | VM_EXEC` 的 VMA，记录 `[start, end)`；
3. 逐块 nofault 复制代码，解码 `B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ`，把每个静态
   目标写入目标 VMA 的位图（每 4 字节指令一位，即代码虚拟跨度的 1/32）；
4. 保存为 `struct uy_code_map`，`DEACTIVATE`/卸载时释放。

故障时 `uy_llsc_skipped(ldxr_pc, pc)` 只检查 `[ldxr_pc+4, pc]` 的 1–4 个槽位。
命中说明存在从任何已扫描代码进入 `LDXR..load` 区间的直接分支，handler 不代写，
让原生 `STXR` 报失败。位图不可用时退回 2.7.0 的单页扫描。

### 17.4 为什么没有引入新的可观察量

- 没有新增 hook、syscall 表项、PTE/VMA/代码字节改动，也没有新增内核日志、
  `ctl0 status` 字段或 ABI 版本变化。
- 扫描是只读的：`mmap` 读锁 + `copy_from_user_nofault`，不写用户内存，不分配
  用户可见对象。位图只在 `REGISTER` 构建，故障路径只做 O(1) 位测试，读取延迟
  与 2.8.0 相同。
- 位图内存约为可执行虚拟地址跨度的 1/32；测试进程为 6.0 MB，注册后随会话释放。
- 注册路径增加一次约 240 ms 的全进程代码扫描，这是显式的控制操作，不在 CRC
  读取循环里。

### 17.5 残余特征与限制（诚实清单）

1. **注册后新建的可执行映射**不在位图中；从该映射跳入 span 的直接分支仍可
   绕过。位图不随 VMA 变化重建。
2. **不可读或未驻留的可执行页**：XOM 页不能 nofault 复制，被换出的代码页在
   `REGISTER` 时不触发缺页，所以其中的直接分支源不被扫描；目标 `PC` 落在位图外
   时 `uy_code_hit()` 返回 0。
3. **间接分支目标寄存器被覆盖**：同 §16.5 第 1 条。
4. **注册成本**：一次全进程扫描（测试进程 358 个可执行 VMA、6.0 MB、约
   240 ms）。
5. PTE 重装窗口、root 可见性、注册事务窗口、桥的非硬件独占语义、
   `caller_count > 0` 的窗口语义不变。

### 17.6 真机验证

Pixel 6，Android 16，`6.1.134-android14-11`，4 KiB，KernelPatch `0xc00`。
构建 `urov-y.kpm f7d55fd8...`、`urovdetect.apk 2ad6df70...`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| Dobby 检测 24×5 | PASS；活动阶段 `accepted_crc=24/24`、`cross_page_successes=0/768`、`bridge/nop/ind` 均 0；探针均值 3.03–3.27 ms，最大 7.68 ms | [dobby-detect-20261107-184405](results/dobby-detect-20261107-184405/summary.json) |
| 消除矩阵 3×1 | PASS，11 次运行、1438 条断言；四项 `ELIM_BRIDGE` 均 0/32；`ELIM_TIMING mode=ap site_call_ns=283` | [eliminate-20261107-184445](results/eliminate-20261107-184445/summary.json) |
| CRC 5×1 | PASS，9 次运行 | [crc-20261107-184601](results/crc-20261107-184601/summary.json) |
| 多页 3×1 | PASS，5 次运行 | [multipage-20261107-184622](results/multipage-20261107-184622/summary.json) |

测试前后 boot ID 一致，`kernel_issues=[]`，`kpm list` 为空。
