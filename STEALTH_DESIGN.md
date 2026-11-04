# UROV-X：UROV-LAB 检测特征点的消除设计与实现

日期：2026-11-04（Asia/Shanghai）。对象为 `kpms/urov-lab` 当前实现（提交
`74d6d83`，检测结论见 [DETECTION_RESULTS.md](DETECTION_RESULTS.md)）。本轮新增
`urov-x` 变体，原 `urov-lab` 保持不变，用于同一设备上的前后对照。

**结论：DETECTION_RESULTS.md 采纳的三类特征点（控制通道指纹、会话归属、标量读取
与安装文件的差异）在 `urov-x` 上全部不可判；同时"指定读取点返回值被替换"的功能
仍然成立。** smaps `rr/dc` 诊断、映射门控 `EBUSY` 探针、未支持指令 `SIGSEGV` 探针
和 fork 继承问题也一并消除。仍保留的只有同步异常带来的耗时差异，以及"必须预先
注册一页只读可执行文件映射和读取点"这一合作模型约束。

## 1. 现有框架的实现分析

### 1.1 组成

| 文件 | 职责 |
|---|---|
| `urov_abi.h` | 固定 128 字节、版本 2 的 `urov_request`；`kcmp`/`prctl` 双通道常量；能力位 |
| `urov_kpm.c` | KPM 元数据、init/exit、`ctl0 status/selftest` |
| `urov_backend.c` | 常驻后端：`do_mem_abort` hook、控制通道、映射门控、会话状态机 |
| `decode.c` | A64 GPR load 白名单解码（单寄存器、pair、literal、多种寻址） |
| `emulate.c` | 校验 ESR/FAR/上下文，按字节合并原页与伪值，零部分提交地写回寄存器与 PC |
| `core_selftest.c` | 4139 项纯软件自测，装载门槛 |
| `urov_check.c` / `fault_signature.c` | 只读预检 KPM（不注册、不写 PTE、不 hook 读取路径） |
| `native/urov_detect.c` | 普通 App 可用检测核心：控制探针、maps/smaps、文件比对 |
| `apps/urov-detect` | 无 Gradle 的检测/观察 App，以及合作式注册夹具 |

### 1.2 控制通道

`urov_backend_init()` 先跑 4139 项自测，再通过 `kallsyms_lookup_name` 解析
`do_mem_abort`、`get_task_mm`、`mmput`、`find_vma`、`mmap_write_lock/unlock`、
`flush_tlb_mm`、`pin_user_pages_unlocked`、`unpin_user_page`、`force_sig_fault` 和
`copy_{from,to}_user_nofault`，然后安装四类 hook（`hooks=0xf`）：

1. `do_mem_abort` before hook（`hook_wrap`，3 参数）；
2. `__NR_kcmp`（272）旧/root 通道；
3. `__NR_prctl` 普通 App 通道：`prctl(0x55524f56, 0x55524f5653595343, cmd, req, 128)`；
4. `mprotect/munmap/mremap/madvise/mmap` 五个映射门控。

两个控制通道共用 `notify_dispatch()`：校验 128 字节请求的 `size/version/flags/
length` 与规范化零填充，再抢一个控制忙标志（争用返回 `EBUSY`），随后
`reap_dead_session()` 惰性回收死 owner，再分发 QUERY/REGISTER/SET/STATUS/
DEACTIVATE。QUERY 只报告调用者自身 mm 的会话，非 owner 看到
`INACTIVE + last_error=-EBUSY`，这就是"存在其他活会话"的归属提示。

### 1.3 注册与页面保护

注册目标必须是一页整、文件后备、当前只读可执行、且不含 `VM_WRITE/VM_MAYWRITE/
VM_PFNMAP/VM_HUGETLB/VM_IO/VM_MIXEDMAP` 的映射。流程是：`get_task_mm` 持有 mm →
校验 `task->mm` 与 BTF 偏移一致 → `pin_user_pages_unlocked` 触页并固定 → 取
`mmap_write_lock` → 重新校验 VMA/PTE → 用 `copy_from_user_nofault` 复制整页原始
内容 → 写 `vm_page_prot` 和 PTE（清 `PTE_USER`/AP[1]、保留取指、置 `PTE_AF`）→
刷新该 mm 的 TLB。`/proc/self/maps` 仍显示 `r-xs`。

当前实现还写了一个 VMA 标志：源码 `UROV_VM_DONTCOPY=0x00010000`，在 Linux 6.1
实际是 `VM_RAND_READ`。于是 smaps 出现 `rr=1, dc=0`（见 DETECTION_RESULTS 4.1），
这是本轮要一并消除的残留。

### 1.4 读取异常与模拟

`urov_abort_before()` 只接管：ESR 异常类 `0x24`（EL0 数据异常）、`WnR=0`（读）、
DFSC=15（末级 permission fault）、`current->mm` 与 FAR 命中会话。PC 在受保护页内
时从 pinned 原页取 opcode，否则用内核 nofail copy 取。随后把 `pt_regs` 复制进
`uro_regs`，用 seqlock 取一份完整伪值快照，交给 `uro_emulate()`：解码 → 校验有效
地址/FAR/ESR 综合征/上下文 → 按字节合并原页与伪值 → 一次性提交目的寄存器、
base writeback 和 `pc += 4`，最后 `hits++`。

白名单之外（SIMD/FP、acquire/exclusive、未知编码、跨页等）一律 fail-closed：
`failures++` 并 `force_sig_fault(SIGSEGV)`，绝不返回原值后继续。

### 1.5 会话与生命周期

全模块只有一个 `g_sess`，归属注册者的 mm；SET/STATUS/DEACTIVATE 校验 mm 所有权。
注销/卸载先恢复 VMA 模板与 PTE、刷新 TLB、停活并等待 in-flight handler，再
unpin/mmput。owner 死亡后由下一次控制请求按 `mm_users==1` 惰性回收。活动范围内
的 `mprotect/munmap/mremap/madvise/mmap(MAP_FIXED)` 一律返回 `EBUSY`。

### 1.6 适用边界

只支持 64 位 EL0、4 KiB 页、`decode.c` 白名单内的 GPR load（含 LDP）；单页、单
会话、最多 32 字节伪值窗口；多个 mm/VMA/PTE 偏移按本机 BTF 硬编码。

## 2. DETECTION_RESULTS.md 的特征点

| ID | 特征点 | 检测方式 | 交付检测核心是否采用 |
|---|---|---|---|
| FP-1 | 控制通道指纹 | 错误 magic 原样返回原生 `EINVAL`；两次有效 QUERY 的 ABI/caps/状态编码/回显一致 | 采用（高特异性） |
| FP-2 | 会话归属 | 两次查询的 state/session/generation/offset/length/last_error 稳定；`INACTIVE + last_error=-EBUSY` 表示别的 mm 持有会话 | 采用 |
| FP-3 | 标量读取与安装文件差异 | 已知不可变 RX 代码的标量读取与同一映射的文件字节，三轮稳定且互不相等 | 采用（内容差异单独不足以归因） |
| FP-4 | smaps `rr=1`/`dc=0` | `VM_DONTCOPY` 常量写错成 `VM_RAND_READ` | 仅诊断 |
| FP-5 | 映射门控 `EBUSY` | 对活动页做 mprotect/munmap/mremap/madvise 返回 `EBUSY`，与原生行为不同 | 仅记录，交付核心未用 |
| FP-6 | 读取耗时 | 受保护页的每次标量读取都要经过一次同步异常 | 不采用（噪声大） |
| FP-7 | 未支持指令 `SIGSEGV` | SIMD/原子等读取在受保护页上触发 fail-closed 信号 | 不采用（会改变进程状态） |
| FP-8 | 旧 `kcmp` 通道 | root/旧通道常量 | 普通 App seccomp 不可达 |

## 3. 威胁模型与设计目标

对手是同设备的普通 App：`untrusted_app`、`CapEff=0`、`Seccomp=2`、没有 root、
不知道模块加载时注入的密钥，也拿不到内核内存。对手可以：调用任意允许的 syscall、
读取自己的 maps/smaps/pagemap、读写自己的内存、fork、比较文件与自己读到的字节。

目标是同时满足：

1. FP-1/FP-2/FP-8：控制面不可被无密钥者发现；任何未认证调用与"没有模块"逐位一致。
2. FP-3：任何**未被显式授权**的读取点读到的字节，必须与安装文件（或正常映射）一致。
3. 功能保留：被显式授权的读取点仍然返回伪值，取指始终执行原字节。
4. FP-4/FP-5/FP-7：不留下 smaps 标志、不改变映射 syscall 的返回值、不把合法读取变成信号。

## 4. 消除方案

### 4.1 K1 密钥化隐蔽控制通道（消除 FP-1、FP-2、FP-8）

- 加载参数携带 128 位密钥：`kpm load urov-x.kpm "key=<32 hex>"`。模块用
  SipHash-2-4 从密钥派生三样东西：`prctl` 的 option 字（低 32 位）、magic 字、
  请求 MAC 的 128 位密钥。**源码里没有任何固定通道常量**，每次装载的通道都不同。
- 每个请求携带 64 位 MAC（覆盖结构体前 184 字节）。option、magic、MAC 三者任一
  不匹配时，hook 直接返回、不设置 `skip_origin`，内核继续执行原生 `sys_prctl`，
  未知 option 返回 `EINVAL`——与没有模块时完全一致；也不会读会话、不会改状态。
- 不安装 `kcmp` 通道；QUERY/STATUS 只报告调用者自身 mm，非 owner 得到
  `INACTIVE`，`last_error` 恒为 0，删除了 `-EBUSY` 归属提示。
- 未认证调用不产生任何可区分的时间/返回值差异（SipHash 只在校验通过后才会发生
  在已认证路径上；未认证路径只是两次 32/64 位比较）。

### 4.2 K2 读取点绑定（消除 FP-3，同时保留功能）

注册请求新增 `site_count` 和 `sites[8]`：**允许观察伪值的读取指令 PC**。故障
处理按 `regs->pc` 精确匹配：

- 命中：用 seqlock 取伪值快照，照常模拟，返回值被替换（功能保留）。
- 未命中：仍走同一套模拟，但 `view.fake` 指向 pinned 原页的对应偏移，即"伪值
  等于原值"。结果与正常可读映射逐位一致，`hits` 递增但没有任何差异。

因此通用完整性扫描（`LDRB` 循环、`memcmp` 前的标量复制）无论读多少字节、读哪
一段，都只会得到安装文件的字节；只有被授权的读取点会看到伪值。注册时用
`uro_decode` 校验每个 site 确实是白名单内的 GPR load，避免把无法模拟的指令
（SIMD 等）登记成授权点。

### 4.3 K3 映射生命周期透明化（消除 FP-4、FP-5）

- **不再修改 `vm_flags`**：删掉写错的 `VM_DONTCOPY`，只改 `vm_page_prot` 和叶子
  PTE，两者在注销/静默结束时都恢复。smaps 的 `VmFlags` 回到 `rd ex ...`，
  不再出现 `rr`；`dc` 也不会被设置。
- **不再返回 `EBUSY`**：与受保护页相交的 `mprotect/munmap/mremap/mmap(MAP_FIXED)`
  先静默结束会话（恢复页面权限），再让原 syscall 正常执行。对调用者而言返回值和
  普通映射完全相同；活动页不再有"只有模块在场才有的 errno"。
- `madvise` 不拦截：`vm_page_prot` 已经清掉 AP[1]，`MADV_DONTNEED` 之后的 PTE
  重建仍保持只执行语义，覆盖继续有效。

### 4.4 K4 未授权读取的 fail-safe（消除 FP-7 类信号探针）

未授权读取点若命中解码白名单之外的指令（例如 `LDR Q0`），不再 `SIGSEGV`：
先 `cleanup`（恢复页面、结束会话、释放 pin/mm 引用），再让内核原生 fault 路径
重试该指令。重试时 PTE 已可读，指令正常完成。对调用者来说就是"这次读取成功，
返回真实字节"，与没有模块时一致；代价是覆盖被静默关闭。授权站点仍然 fail-closed
（那是配置错误，必须显式失败）。

### 4.5 K5 fork 窗口

fork 会复制 VMA 和 PTE，子进程会继承一个"数据读取会 fault、但没有自己的会话"的
页面。`urov-x` 在 `clone`/`clone3`（`CLONE_VM` 除外）的 before/after 回调里，用
引用计数临时恢复父进程页面：子进程复制到的 PTE/VMA 是正常可读的，syscall 返回后
再恢复保护。父进程的覆盖保留，子进程完全正常。

### 4.6 K6 标识与日志

默认不打印任何 `pr_info`；`verbose` 才输出。`ctl0 status` 只给 root 看，不含密钥、
通道字和伪值。模块名、版本等只出现在 KPM 列表（root/superkey 可达）。

### 4.7 特征点与对策对照

| 特征点 | `urov-lab` | `urov-x` 对策 | 结果 |
|---|---|---|---|
| FP-1 通道指纹 | 固定 option/magic + ABI 回显 | K1 密钥派生 + MAC；未认证走原生 | 无指纹 |
| FP-2 会话归属 | `-EBUSY` 提示他人会话 | K1 非 owner 恒为 INACTIVE/last_error=0 | 无归属 |
| FP-3 读取/文件差异 | 页内任意读都被覆盖 | K2 仅授权 PC 见伪值 | 无差异 |
| FP-4 smaps rr | 误写 `VM_RAND_READ` | K3 不改 `vm_flags` | `rr=0, dc=0` |
| FP-5 门控 EBUSY | 相交映射操作 `EBUSY` | K3 静默结束 + 原生执行 | 原生返回值 |
| FP-6 读取耗时 | 每次读一次异常 | 未消除（见 §6） | 仍可测 |
| FP-7 不支持指令信号 | fail-closed SIGSEGV | K4 恢复页面并重试 | 无信号 |
| FP-8 旧 kcmp 通道 | 安装 | K1 不安装 | 不存在 |
| fork 继承 | 子进程可能异常 | K5 clone 窗口 | 子进程正常 |

## 5. 实现

### 5.1 文件

| 文件 | 说明 |
|---|---|
| `urov_x_abi.h` | ABI v3（192 字节）+ SipHash-2-4 + 密钥派生 + 请求 MAC；模块与 App 共用 |
| `urov_x.c` | KPM 元数据、init/exit、`ctl0 status/selftest` |
| `urov_x_backend.c` | 密钥化通道、读取点绑定、静默生命周期、fail-safe、fork 窗口 |
| `apps/urov-detect/app.c` | 新增 `x-clean/x-active/x-hold/x-simd/x-fork/x-observer` 夹具模式 |
| `tools/run_stealth_device.py` | 设备矩阵与原始结果采集 |

复用 `decode.c`、`emulate.c`、`core_selftest.c`；`emulate.c` 未改动，K2 通过
"`fake` 指向原页"实现零差异读取，避免改动共享核心和 4139 项自测。

### 5.2 ABI v3

```c
struct urov_x_request {          /* 192 bytes */
    uint32_t size; uint16_t version, op;
    uint64_t request_id, session, address, expected_generation, value;
    uint32_t offset, length; uint64_t value_hi[3];
    uint32_t site_count, reserved; uint64_t sites[8];
    uint64_t generation, hits, failures; uint32_t state; int32_t last_error;
    uint64_t mac;                /* SipHash over bytes [0, 184) */
};
```

密钥派生：

```text
option = low32( SipHash(k, "UROVX/1" + 0x01) )
magic  =       SipHash(k, "UROVX/1" + 0x02)
mac_k  = (     SipHash(k, "UROVX/1" + 0x03), SipHash(k, "UROVX/1" + 0x04) )
```

### 5.3 状态与 hook

- 状态只有 `UX_OFF / UX_LIVE`；`g_handlers` 计数、`g_ctrl_busy` 控制锁、
  `g_suspend_depth` fork 窗口深度。
- hooks（`ctl0 status` 的 `hooks` 掩码）：`0x1 abort | 0x2 prctl | 0x4 gates |
  0x8 clone | 0x10 clone3`；本机实测 `hooks=0x1f`。
- 故障快路径：`state==LIVE` → ESR/FAR/mm 过滤 → 计数 → 再校验 → `site_match(pc)`
  → 取 opcode → `uro_emulate`（授权点用伪值快照，否则用原页）→ 提交或
  fail-safe/信号。
- 控制路径与映射路径都可能调用 `release_session()`（幂等、需持控制锁）：恢复
  `vm_page_prot` 与 PTE → 刷 TLB → 置 `UX_OFF` → 等待 handler → unpin/mmput →
  清零会话。

## 6. 残余特征与限制（诚实清单）

1. **耗时**。受保护页的每次数据读取仍是一次同步异常。实测 64 字节标量读取
   0 µs（原生）对 50–123 µs（活动期）。DETECTION_RESULTS 明确不把耗时作为定罪
   条件，但统计型检测器仍可能利用。要消除它需要改写读取点指令或 shadow-page，
   都会引入新的可检测面（代码页差异/映射差异）。
2. **页形态**。仍要求"一页整、文件后备、只读可执行、非 MAYWRITE"的专用映射；
   普通多页 `MAP_PRIVATE .text` 不满足。这是合作注册模型的约束，不是隐藏能力。
3. **授权点必须是可解码的 GPR load**。SIMD/原子读取点不能作为站点；未授权读取
   会走 K4 正常降级，但无法被覆盖。
4. **密钥分发**。测试 App 通过 `am start --es key` 注入密钥；真实客户端需要把
   密钥做成不可轻易提取的形式（设备绑定、混淆或由上游控制器下发）。拿到密钥的
   同进程对手可以调用通道并观察到会话，这是设计使然。
5. **内核层可观察性**。`urov-x` 用 per-syscall 函数指针 hook（改动
   `sys_call_table` 项）以绕过 su uid gate；root/内核级检测器可以观察到这些表项
   与 `do_mem_abort` 的 inline hook。本方案只针对普通 App。
6. **单会话/单页/32 字节窗口/仅当前 mm**：与 `urov-lab` 相同。
7. **fork 窗口的语义缝隙**：clone 期间父进程页面短暂恢复为原生可读，其他线程
   在授权站点上的读取会看到真值。窗口是 sub-ms 级，且非授权读取本来就返回真值。
8. **MAC 不防重放**：同一进程内的对手若截获合法请求可重放；攻击者需要先拿到
   密钥或进程内代码执行，超出本威胁模型。

## 7. 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1 -Observer
python .\kpms\urov-lab\tools\run_stealth_device.py `
    --serial <SERIAL> --key <KP-SUPERKEY> --module-key <32-hex-secret>
```

手工步骤：

```text
adb push out\urov-x.kpm /data/local/tmp/urov-x.kpm
kpatch <SUPERKEY> kpm load /data/local/tmp/urov-x.kpm "key=<32-hex-secret>"
adb shell am start -n com.example.urovdetect/.MainActivity \
    --es mode x-active --es key <32-hex-secret>
kpatch <SUPERKEY> kpm ctl0 urov-x status
kpatch <SUPERKEY> kpm unload urov-x
```

`x-clean` 不带密钥运行，用于证明"模块在场但无密钥的 App 与没有模块不可区分"；
`x-hold` 保持活动会话等待卸载；`x-observer` 由另一个 UID 的 APK 运行；`x-simd`
与 `x-fork` 分别验证 fail-safe 与 fork 窗口。设备实测见
[STEALTH_RESULTS.md](STEALTH_RESULTS.md)。
