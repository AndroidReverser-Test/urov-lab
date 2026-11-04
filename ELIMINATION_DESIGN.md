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