# UROV-Y：任意多页覆盖、LD1/LD2、跨页 load 与 16 KiB 页（设计稿）

日期：2026-11-06（Asia/Shanghai）。基线是当前 `urov-y` 的 ABI v7 实现（单页 4 KiB、
SIMD&FP 单/pair、整页镜像；见 [ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md) §13）。

**本文只做四件事**：

- **R1** 同一会话同时覆盖**任意多页**（不再是"一页一会话"）；
- **R2** 支持 **LD1/LD2**（load multiple structures，含 post-index 两种形式）；
- **R3** 支持**跨页 load**（一条指令跨两个页）；
- **R4** 支持 **16 KiB 基础页**的 arm64 内核。

其余条目——非合作注册/进程注入、`read`/`pread` 文件路径、`/proc/self/mem` 与
`process_vm_readv`、可写页（GOT/RELRO）、多进程/fork 继承、检测面消除——**不在本轮
范围**。下文凡涉及它们的句子都只是边界声明，不作为设计目标。

> 状态：**R1/R2/R3 已实现并上机（ABI v8），R4（16 KiB）明确不实现**。本轮按用户
> 要求保留 4 KiB 基础页；`QUERY` 报 `page_shift=12`、caps 不含
> `UROV_Y_CAP_16K`，`supported_pagetables()` 仍拒绝非 4 KiB 内核。实现与真机证据
> 见 [MULTIPAGE_RESULTS.md](MULTIPAGE_RESULTS.md) 与
> [results/multipage-20261106-224709](results/multipage-20261106-224709/summary.json)。
> 下文 §10（16 KiB）保留为设计记录，未落地；其余小节（多页数组、LD1/LD2、
> 跨页、配额、生命周期）已按文实现。

---

## 1. 不变量（沿用现有实现，不因本轮改动而改变）

1. 合作模型：目标进程用自己的 `mm` 发起 REGISTER/SET/DEACTIVATE，控制通道带 MAC。
2. 单会话、按 `mm` 归属；非 owner 被拒；死 owner 惰性回收。
3. 只改**叶子 PTE 的 `AP[1]`**：不写代码页、不改 VMA、不 COW、不 pin 数据页、
   不改 `smaps` 的权限与匿名/私有脏页统计。
4. 取指始终原生；只有 EL0 数据读进入 EL1 模拟。
5. fail-closed：不支持/读不到/配置非法时发 SIGSEGV，绝不把原字节冒充伪值。
6. 故障路径无分配、无睡眠、无文件 I/O；所有重活都在注册/更新事务里完成。

"任意多"的准确含义：**数据结构与算法不设固定小 N**，只受一个显式配额约束
（默认见 §11），配额可以按装载参数调整；而不是"单页"或"最多 4/8 页"。

---

## 2. 现状与本轮差距

| 能力 | 现状（ABI v7） | 本轮目标 |
|---|---|---|
| 会话/页数 | 全局单 `g_sess`，只有一页；第二页 REGISTER 返回 `-EBUSY`（[urov_y_backend.c:196](urov_y_backend.c)、[:1493](urov_y_backend.c)） | 一页数组，N 页同时 ARMED |
| 页大小 | 编译期 4096：`UROV_Y_PAGE`/`UROV_Y_FAKE_PAGE`（[urov_y_abi.h:41-53](urov_y_abi.h)） | 运行时 `page_shift ∈ {12,14}` |
| 页表 | `supported_pagetables()` 只接受 4 KiB TG0/TG1（[:1917](urov_y_backend.c)） | 接受 4 KiB/16 KiB，校验 TG0==TG1 |
| 解码 | GPR + SIMD B/H/S/D/Q 单/pair；`0x0C`/`0x4C` 组（LD1/LD2/LD3/LD4）未匹配 → fail-closed | 增加 LD1/LD2（顺带 LD3/LD4） |
| 跨页 | `uy_emulate_load()` 里 `load.address - base > UROV_Y_PAGE - total` → `-3` | 允许跨 2 页拼接 |
| 镜像 | 每会话一份 `original[4096]` + `fake_page[4096]` + 4 KiB 暂存（[:182](urov_y_backend.c)、[:184](urov_y_backend.c)） | 每页一份镜像，来源可选 |
| 内存 | 静态 BSS；KernelPatch 的 RW 池只有 2 MiB（`MEMORY_RW_SIZE (2 << 20)`） | `kvmalloc` 动态分配 + 配额 |

> 注意：**需要覆盖的页数 = 被改过字节的页数**，不是 CRC 范围的页数。未修改的页
> native 读原值，天然满足校验；所以 N 通常等于被 inline hook 的页数（10–100 量级）。
> 但一次 CRC 遍历会连续读所有页，因此这 N 页必须**同时**生效——这就是 R1 的动机。

---

## 3. 总体结构

```text
REGISTER（prctl，MAC）
  │  请求携带 page_count + 页描述符数组（用户态地址）
  ▼
[1] 描述符拷贝/校验/排序/去重/重叠检查
[2] 逐页 fault-in + VMA/PTE/file 校验（按运行时 page_size）
[3] 逐页准备镜像：SRC_FILE（从 vm_file 读原始页）或 SRC_USER（调用者提供）
[4] mmap_write_lock：逐页复核、逐页清 AP[1]（CONT 组先 break）、一次 TLB flush
[5] g_state = LIVE，返回 page_count/armed/page_shift
  │
  ▼
数据异常（EC 0x24、WnR=0、AP[1] 权限错、mm 属于会话）
  │  FAR → 解码指令 → 访问区间 [addr, addr+total)
  ▼
[6] 按页切分区间：covered 页取镜像；uncovered 页走 nofault uaccess
[7] 构造目的寄存器值（GPR/LDP/SIMD/LD1/LD2），FPSIMD 一次提交最多 4 个 V 寄存器
[8] 提交 GPR/SP/PC；失败则 fail-closed
```

关键点：

- **页查找**：`pages[]` 按 `base` 升序；`far` 或访问起始地址 → 二分。
- **镜像**：走内核内存（`kvmalloc`），故障路径只做内存拷贝；不读 page cache、
  不读文件、不睡眠。
- **跨页**：访问区间最多 64 字节（LD1 ×4 Q），因此最多跨 **2 个页**；拼接是
  有界的两段循环。
- **16 KiB**：`page_shift` 贯穿页对齐、PTE、镜像大小、ABI 校验；不引入第二套代码。

---

## 4. 数据模型

```c
enum uy_page_src {
    UY_SRC_FILE = 1,   /* 注册时从 vm_file 读整页原始字节（默认） */
    UY_SRC_USER = 2,   /* 注册时从调用者 fake_addr 拷入 */
};

struct uy_page {
    uint64_t base;          /* 页对齐 VA（运行时 page_size 对齐） */
    void    *image;         /* page_size 字节：SRC_FILE/SRC_USER 的整页镜像 */
    void    *snapshot;      /* page_size 字节：仅 caller_count>0 时分配（replay 用） */
    uint32_t index;         /* 页序号（排序前的位置，用于 SET/STATUS） */
    uint32_t flags;         /* UY_PAGE_ARMED | UY_PAGE_CONT_BROKEN | ... */
    uint64_t hits, replays, failures;
};

struct uy_session {
    void     *mm;
    uint32_t  page_shift;   /* 12 或 14 */
    uint32_t  page_size;    /* 1 << page_shift */
    uint32_t  page_count;
    uint32_t  caller_count;
    uint64_t  caller_start[UROV_Y_MAX_CALLERS];
    uint64_t  caller_end[UROV_Y_MAX_CALLERS];
    struct uy_page *pages;  /* page_count 项，按 base 升序 */
    uint8_t  *arena;        /* page_count*page_size 连续镜像区（可为 NULL） */
    uint32_t  fake_seq;     /* 全局发布序号（见 §12） */
    uint64_t  generation;   /* 会话代次 */
    uint32_t  mode;         /* 仍只有 PAGE_AP 支持多页/宽 load */
    /* 兼容 v7 字段：单页时的 overlay_offset/len/value/value_hi 已有测试使用 */
};
```

- **查找**：`pages` 排序 + 二分；`base` 唯一（重复描述符直接 `-EINVAL`）。
- **镜像布局**：推荐一个连续 arena（`page_count * page_size`）减少分配次数；
  `uy_page.image` 指向 arena 内偏移；`SRC_USER` 的 partial window 也放在这里
  （未覆盖字节填该页当前内容或原始内容，由 ABI 标志决定）。
- **快照**：只有 `caller_count > 0` 时才为每页分配 `snapshot`（replay 需要"当前
  真实字节"）；`caller_count == 0`（代码页的推荐配置）时零快照开销。
- **所有内存**用 `kvmalloc_node(size, GFP_KERNEL, NUMA_NO_NODE)`/`kvfree`
  （kallsyms 解析；不可用时回退 `kp_malloc`，仅限 ≤2 MiB 的小配置）。

---

## 5. ABI v8

请求从 256 字节扩到 **288 字节**（`_Static_assert(sizeof == 288)`），`mac` 仍为最后
8 字节，MAC 覆盖 `[0, size-8)`：

```c
struct urov_y_request {          /* v8, 288 bytes */
    uint32_t size; uint16_t version; uint16_t op;
    uint64_t request_id, session;
    uint64_t address;            /* 兼容：单页地址；多页时忽略 */
    uint64_t expected_generation;
    uint64_t value;              /* 兼容：单页 inline fake */
    uint32_t offset, length;     /* 兼容：单页窗口 */
    uint64_t value_hi[3];
    uint32_t site_count;         /* AP 模式允许 0 */
    uint32_t caller_count;
    uint64_t sites[UROV_Y_MAX_SITES];
    uint64_t caller_start[UROV_Y_MAX_CALLERS];
    uint64_t caller_end[UROV_Y_MAX_CALLERS];
    uint64_t generation;
    uint32_t state; int32_t last_error;
    uint64_t hits, replays, failures;
    uint32_t mode, flags;
    uint64_t fake_addr;          /* 兼容：单页镜像 */
    uint64_t reserved;
    /* ---- v8 新增 ---- */
    uint32_t page_count;         /* 1..UROV_Y_MAX_PAGES */
    uint32_t page_stride;        /* 页描述符大小，必须 == sizeof(struct uy_page_desc) */
    uint64_t pages_addr;         /* 用户态页描述符数组 */
    uint64_t session_flags;      /* bit0: UY_F_REPLAY_SNAPSHOT（默认按 caller_count 推导） */
    uint64_t reserved2;
    uint64_t mac;
};

struct uy_page_desc {            /* 32 bytes */
    uint64_t base;               /* 页对齐，运行时 page_size 对齐 */
    uint64_t fake_addr;          /* SRC_USER 镜像地址；0 = SRC_FILE */
    uint32_t fake_off;           /* 窗口起点（SRC_USER 的 partial 窗口） */
    uint32_t fake_len;           /* 窗口长度（0 = 整页；SRC_FILE 忽略） */
    uint32_t flags;              /* bit0 SRC_USER；bit1 SRC_FILE；其余必须 0 */
    uint32_t reserved;           /* 必须 0 */
};
```

操作与返回：

| op | v8 语义 |
|---|---|
| `QUERY` | 返回 `page_shift`、`caps`（`UY_CAP_MULTI`/`UY_CAP_LD1`/`UY_CAP_CROSS`/`UY_CAP_16K`）、`max_pages` |
| `REGISTER` | `page_count>0` 且有 `pages_addr` 时走多页；否则按 v7 单页字段构造 1 页（兼容） |
| `SET` | 新增 `UROV_Y_SET_PAGE`(6)：`page_index` 放在 `reserved` 低 32 位，携带新镜像/窗口 |
| `STATUS` | `page_shift`、`page_count`、`armed`、聚合 `hits/replays/failures`、`page_count==0` 时回显 v7 字段 |
| `DEACTIVATE` | 幂等；逐页恢复 |

校验规则（全部在事务里做，失败不留状态）：

- `page_count ∈ [1, UROV_Y_MAX_PAGES]`（建议 16384，配额见 §11）；`page_stride == 32`。
- `base & (page_size-1) == 0`；`base` 在用户地址范围；`base` 互不重复。
- `SRC_USER`：`fake_off + fake_len <= page_size`，`fake_len` 为 8 的倍数且 ≥8；
  `fake_addr` 可读（`access_remote_vm`）。
- `SRC_FILE`：VMA 有 `vm_file`；`fake_off/fake_len` 必须为 0（整页）。
- `mode` 仍只允许 `PAGE_AP`（`BRK`/`UXN` 的"站点页自包含"与多页语义不匹配，见 §10.6）。
- `site_count` 在 AP 模式允许 0（10+ 个 hook 函数不需要逐一登记站点）。

---

## 6. 注册事务（任意 N）

```text
REGISTER(descs):
  n = page_count; if n > quota: -ENOMEM
  copy descs (access_remote_vm, 一次或分块) ; validate (§5)
  sort by base; reject duplicates/overlaps
  mm = get_task_mm(current); mm_users 检查
  allocate: pages[n] (kvmalloc), arena[n*page_size] (kvmalloc)
  for i in 0..n-1:
      retry up to 4:
        access_remote_vm(mm, base, scratch, page_size, 0)   # fault-in
        lock mmap_write
        vma = find_vma(mm, base); validate_target_vma(vma, base, page_size)
        ptep = pte_of(mm, base); 必须 present、PAGE、USER、RDONLY、UXN=0、非 CONT/SPECIAL/DEVMAP
          （CONT 见 §10.4：先在锁内 break 该组，再置 AP[1]）
        unlock
        if EAGAIN: continue
      build image:
        SRC_FILE: pos = (vma->vm_pgoff << page_shift) + (base - vma->vm_start)
                  kernel_read(vm_file, image, page_size, &pos) == page_size
        SRC_USER: copy fake window into image（其余字节 = 该页当前内容或原始内容，按 flags）
        if caller_count > 0: access_remote_vm(mm, base, snapshot, page_size, 0)
  lock mmap_write
  for i in 0..n-1: 复核 VMA/PTE；遇 CONT 组先 break；置 AP[1]；记录原 PTE 属性
  flush_tlb_all()
  publish: g_sess = ...; g_state = LIVE
  unlock
  失败：逐页恢复已改 PTE、释放 arena/pages、mmput，返回错误
```

要点：

- **原子性**：所有页在**一次** `mmap_write_lock` 里完成 AP[1] 设置与一次 TLB flush；
  任何一步失败都回滚到"全部未 armed"。
- **PTE 回收竞态**：沿用现有 `EAGAIN` 重试（页被回收 → 重新 fault-in 再试，最多
  4 次）；`handle_mm_fault` after-hook 负责运行期重新装回（§12）。
- **事务窗口**：N 页逐个清 AP[1] 的窗口比单页大。合作模型要求调用方在 REGISTER
  返回后才开始读数；非合作目标不在本轮范围（§13 残余第 1 条）。
- **配额**：镜像内存先于任何 PTE 改动分配，`-ENOMEM` 时不碰目标页。

---

## 7. 故障路径

```text
ap_fault(far, esr, regs):
  if !ap_mode_live() || mm_of_task(current) != sess.mm: return   # 原生
  handlers++ ; if !live: handlers--; return
  decode insn at pc -> load{address,total,kind,...}
  if load.vector && !fp_ready: fail_segv
  p = page_find(load.address)                # 二分；返回 covered 页或 NULL
  if !p && !access_in_any_page(load): 仍需按段判断
  # 逐段取字节
  off = load.address - page_base(load.address)
  total = load.total
  while total:
     seg = min(page_size - off, total)
     pg = page_find(page_base(load.address + done))
     if pg && pg->flags & ARMED:
         if caller_allowed_deep(regs) && !suspend: copy from pg->image[off]  # fake
         else: copy from pg->snapshot[off]                                   # replay
     else:
         if f_copy_in(bytes, addr, seg): fail_segv(addr)                     # 真实字节
     done += seg; off = 0
  # 提交（先全部校验，再一次性提交）
  if load.kind == VEC:  fp_commit(load.dst[], bytes)   # 1..4 个 V 寄存器
  else:                 gpr_commit(load, bytes)
  commit_model(regs)    # GPR/SP/PC（含 writeback）
  counters
```

- **FAR 语义**：FAR 只是"第一个触发 AP[1] 的字节"，可能落在访问区间的第二页；
  页查找与分段用**解码后的访问起始地址**，FAR 只用于校验 ∈ `[address,address+total)`。
- **未覆盖页**：正常页用 `copy_from_user_nofault` 读真实字节；读失败 → SIGSEGV
  （原生语义），不算覆盖失败。
- **不跨页到未映射页**：若某段不可读，直接 fail-closed，绝不返回部分结果。
- **提交顺序**：先 `fp_commit`，再 GPR/PC；任何一步失败不留下半提交。
- **无分配/无睡眠**：故障路径只做二分、内存拷贝、`copy_from_user_nofault`。

---

## 8. LD1/LD2（load multiple structures）

### 8.1 编码

组内固定位（ARM ARM：LD1/LD2/LD3/LD4 *multiple structures*；参考
[LD1 (multiple structures)](https://www.scs.stanford.edu/~zyedidia/arm64/ld1_advsimd_mult.html)
与 [LD2 (multiple structures)](https://www.scs.stanford.edu/~zyedidia/arm64/ld2_advsimd_mult.html)）：

| 位 | 含义 |
|---|---|
| 31 | 0 |
| 30 | Q（0=64-bit 数据宽度，1=128-bit） |
| 29:24 | `001100` |
| 23 | 0 = 无偏移；1 = post-index |
| 22 | L（1=load，0=store） |
| 21 | 0 |
| 20:16 | 无偏移=0；post-index=Rm（`11111` = 立即数变体） |
| 15:12 | opcode（决定结构数/寄存器数） |
| 11:10 | size（元素宽度） |
| 9:5 | Rn（31=SP） |
| 4:0 | Rt（目的 V 寄存器；其余为 Rt+1..Rt+k mod 32） |

匹配条件：`(insn & 0xBF000000) == 0x0C000000`，且 `L==1`、`bit21==0`。实测编码
（clang/llvm-mc 汇编，`objdump` 反汇编核对）：

| 指令 | 编码 |
|---|---|
| `ld1 {v0.16b}, [x0]` | `0x4c407000` |
| `ld1 {v0.16b, v1.16b}, [x0]` | `0x4c40a000` |
| `ld1 {v0.16b - v2.16b}, [x0]` | `0x4c406000` |
| `ld1 {v0.16b - v3.16b}, [x0]` | `0x4c402000` |
| `ld2 {v0.16b, v1.16b}, [x0]` | `0x4c408000` |
| `ld3 {v0.16b - v2.16b}, [x0]` | `0x4c404000` |
| `ld4 {v0.16b - v3.16b}, [x0]` | `0x4c400000` |
| `ld1 {v0.8b}, [x0], #8` | `0x0cdf7000` |
| `ld1 {v0.16b}, [x0], #16` | `0x4cdf7000` |
| `ld1 {v0,v1.16b}, [x0], #32` | `0x4cdfa000` |
| `ld2 {v0,v1.16b}, [x0], #32` | `0x4cdf8000` |
| `ld1 {v0.16b}, [x0], x1` | `0x4cc17000` |
| `ld1 {v0-v3.16b}, [x0], x1` | `0x4cc12000` |
| `st1 {v0.16b}, [x0]` | `0x4c007000`（L=0，拒绝） |
| `ld1 {v0.b}[0], [x0]` | `0x0d400000`（single-lane 组，排除） |

opcode 表（ARM ARM 共享解码；其它值 UNDEF）：

| opcode | 结构 | 寄存器数 |
|---|---|---|
| `0010` | LD1 | 4 |
| `0110` | LD1 | 3 |
| `1010` | LD1 | 2 |
| `0111` | LD1 | 1 |
| `1000` | LD2 | 2 |
| `0100` | LD3 | 3（顺带支持） |
| `0000` | LD4 | 4（顺带支持） |

### 8.2 语义

设 `datasize = 64 << Q`、`esize = 8 << size`、`elements = datasize / esize`。

- LD1：`rpt = nregs`、`selem = 1`；寄存器 `Rt+r`（r=0..rpt-1）拿连续的
  `datasize` 字节（等价于多条 `ldr q/d` 连续读）。
- LD2/3/4：`rpt = 1`、`selem = 2/3/4`；寄存器 `Rt+s`（s=0..selem-1）拿**去交织**
  后的元素：内存偏移 `(e*selem + s) * esize` → 寄存器内偏移 `e * esize`。
- 统一公式：目的寄存器 = `(Rt + r + s) & 31`；内存偏移 =
  `((r*elements + e)*selem + s) * esize`；寄存器内偏移 = `e * esize`。
- 总访问字节 `total = rpt * selem * datasize`（LD1 最多 4×16=64，LD2 为 32）。
- 写回：post-index 且 `Rm != 31` 时 `base += X[Rm]`；`Rm == 31` 时
  `base += total`（架构上立即数变体只允许这一个值，汇编器已实测限制）。
- `Rn == 31` 表示 SP，需 16 字节对齐检查；`size==3 && Q==0 && selem>1`（1D 用于
  LD2/3/4）为 UNDEF，拒绝。
- 目的寄存器写入按 `datasize` 宽度零扩展（8B/1D 时高 64 位清零），与现有
  标量 SIMD load 规则一致。

### 8.3 解码器与模拟器的改动

- `struct uro_load` 扩展为"向量 load 描述"：`nregs`（1..4）、`dst_regs[4]`、
  `dst_bytes[4][16]`、`selem`、`esize`、`elements`、`total`；GPR 路径不变。
- `decode.c` 只做解码，不访问内存；`emulate.c`（共享 GPR 核心）对 `vector`/多结构
  继续返回 `URO_UNSUPPORTED`，`urov-x`/`urov-lab` 语义不变。
- `urov_y_backend.c` 的提交改为"最多 4 个 V 寄存器"：一次
  `fpsimd_signal_preserve_current_state()` → 逐寄存器写 `vregs[dst]` →
  `fpsimd_update_current_state()`；仍只在全部分支校验通过后提交。
- 排除：`st1..st4`、single-lane（`0x0D` 组）、`ld1r/ld2r/...`（replicate；
  可选后续）、SVE。

---

## 9. 跨页 load

允许条件与拼接：

1. `total <= 64` 且 `total` 为访问宽度（GPR 1/2/4/8/16、SIMD 4/8/16/32、LD1/LD2
   最多 64）；访问区间 `[address, address+total)` 不要求同页。
2. 最多跨 **2 页**（页 ≥4 KiB，total ≤64）；按页切段，逐段取字节（§7）。
3. 未覆盖段走 `copy_from_user_nofault`；覆盖段取镜像。两段都成功才提交。
4. FAR 必须 ∈ 访问区间；用于 fail-closed 的错误地址取"实际不可读的那一段"。
5. 与 16 KiB 页正交：16 KiB 下只有落在页尾 64 字节内的访问才会跨页，同一套代码。
6. 跨页同样适用于 LD1/LD2（64 字节访问在 4 KiB/16 KiB 页上都可能跨界）。

---

## 10. 16 KiB 页

### 10.1 page_shift 来源

- KernelPatch 内部有 `page_shift / page_size / va_bits / page_level`（`extern int64_t`，
  `kernel/include/pgtable.h`），启动时从 `TCR_EL1.TG1` 判定 12/14/16
  （`kernel/base/map.c`）。**优先用 `kallsyms_lookup_name` 解析 `page_shift`/
  `page_size`**；解析不到时自己读 `TCR_EL1.TG0/TG1`（TG0/TG1 必须是同一 granule，
  否则 `-EOPNOTSUPP`）。
- 无论走哪条来源，装载时都做一致性自检：`page_size == 1 << page_shift`、
  `page_shift ∈ {12,14}`、`pgtable_entry(mm_pgd(current->mm), 用户栈页)` 返回
  present 的 PAGE 叶项，且该叶项覆盖的页基址与 `page_size` 对齐一致。
- `supported_pagetables()` 从"只接受 4 KiB"改为"接受 4 KiB/16 KiB；拒绝 64 KiB、
  LPA2、TG 不一致、深度不一致"。

### 10.2 去 4 KiB 常量

以下位置从编译期 4096 改为运行时 `page_size`/`page_mask`：

| 位置 | 现值 | 改为 |
|---|---|---|
| `UROV_Y_PAGE`/`UROV_Y_FAKE_PAGE`（ABI） | 4096 | 由 `QUERY` 返回的 `page_shift` 推导；ABI 里只保留上限宏 |
| `struct uy_session` 的 `original[]`/`fake_page[]` | 4096 | 每页 `kvmalloc(page_size)` |
| `page_base()`/`pte_of()`/`page_set_ap()`/`page_set_uxn()` | 4 KiB 掩码 | `page_size` 掩码 |
| `validate_target_vma()`（shared 恰好一页） | `address+4096` | `address+page_size` |
| `ap_arm_target()`/`site_arm()` | 4 KiB | `page_size` |
| `gate_range_overlaps()`/`do_register` 的 offset/length | 4096 | `page_size` |
| `g_selftest_ws[]`/`uro_core_selftest` 的 workspace | 4096 | `page_size`（16 KiB） |

`pt_regs`/PTE 位定义与 granule 无关，不需要改。

### 10.3 页表

`pgtable_entry(pgd, va)` 已按运行时 `page_shift/page_level` 走表，16 KiB 下返回
16 KiB 的叶子 PTE；不需要自己实现 walker。需要验证的是：`page_level` 与
`va_bits` 匹配、块映射（`PTE_TYPE_BLOCK`）一律拒绝（`.text` 用页映射）。

### 10.4 CONT（连续 PTE）处理

KernelPatch 定义了 `PTE_CONT (1<<52)`、`CONT_PTES (16)`、
`CONT_PTE_SHIFT (4 + page_shift)`、`CONT_PTE_MASK`。注册/注销流程：

1. 若目标 PTE 带 `PTE_CONT`：它属于一个 `CONT_PTES` 对齐的组；
2. **break-before-make**：在 `mmap_write_lock` 下把组内 16 个 PTE 的 CONT 位清零
   （其余属性保留），`flush_tlb_all()`；组内其他页权限不变；
3. 只对目标页清 `AP[1]`；
4. 注销时按记录恢复 CONT 位并再次 flush。

16 KiB 内核上大段 `.text` 可能带 CONT；不处理会与 TLB 的块缓存不一致。注意
6.1 的 PTE 级 CONT 使用较少（contpte 主要在更新的内核里），这条路径是稳健性
要求，不假设它一定出现。

### 10.5 ABI 与用户态

- `QUERY`/`STATUS` 返回 `page_shift`；REGISTER 校验 `base`、`fake_off+len`、
  `fake_len` 都按运行时页大小。
- 用户态夹具把 `UROV_Y_PAGE` 换成 `sysconf(_SC_PAGESIZE)`；现有
  [crc_fixture.inc](apps/urov-detect/crc_fixture.inc) 的 `sysconf(...) != UROV_Y_PAGE`
  自检同步改为"与 query 的 page_shift 一致"。
- APK 已用 `-Wl,-z,max-page-size=16384` 构建，16 KiB 设备上 ELF 段对齐满足要求。

### 10.6 站点模式（BRK/UXN）与 16 KiB

`PAGE_UXN` 要求"读取点页内被执行的指令只有站点 load 和 RET/BR/NOP/BTI"；16 KiB
页把这一页的容量放大 4 倍，这个前提更难满足。本轮不改站点模式：**多页/宽 load/
16 KiB 只承诺 `PAGE_AP`**，`mode != PAGE_AP` 在 `page_size != 4096` 时直接
`-EOPNOTSUPP`（或要求站点模式仅 4 KiB）。

### 10.7 验证依赖（诚实说明）

当前实验设备 Pixel 6 是 4 KiB 页内核，**16 KiB 路径只能做主机侧单元测试（把
`page_shift` 作为参数合成 12/14），没有真机证据**。真机验证需要 16 KiB 内核 +
KernelPatch 可用的设备；在拿到该设备前，16 KiB 支持只能标注"已实现、未上机"。

---

## 11. 内存与配额

KernelPatch 的 RW 池固定 2 MiB（`MEMORY_RW_SIZE (2 << 20)`），所以镜像**必须**
走 `kvmalloc`（kallsyms 解析 `kvmalloc_node`/`kvfree`），不能用 `kp_malloc`。

| 配置 | 每页成本 | 64 页 @4K | 64 页 @16K | 1024 页 @4K | 1024 页 @16K |
|---|---|---|---|---|---|
| 整页镜像（SRC_FILE/SRC_USER） | page_size | 256 KiB | 1 MiB | 4 MiB | 16 MiB |
| + replay 快照（caller_count>0） | +page_size | 512 KiB | 2 MiB | 8 MiB | 32 MiB |
| 元数据（`uy_page` + 索引） | ≈64 B | 4 KiB | 4 KiB | 64 KiB | 64 KiB |

建议默认配额与装载参数：

- `max_pages` 默认 **4096**（可调到 16384）；
- 镜像总量默认 **8 MiB**，最大 **64 MiB**（`kvmalloc` 上限内）；
- 超限 `-ENOMEM`；描述符/镜像分配失败发生在任何 PTE 改动之前。

---

## 12. 生命周期与并发

| 事件 | 多页语义 |
|---|---|
| `mprotect/munmap/mremap/mmap(MAP_FIXED)/madvise` | 与**任一**页相交即结束会话；`mremap` 检查源区间与 `MREMAP_FIXED` 目标区间；区间查询用二分 |
| `clone/clone3` | clone 前逐页恢复 AP[1]（及 CONT），clone 后逐页重装；子进程不继承 |
| `handle_mm_fault` after-hook | 按 fault 地址查页；命中且会话活跃则重新清 AP[1]（CONT 组先 break） |
| `execve` | 结束会话 |
| 注销/卸载 | 置 OFF、排空 `g_handlers`、逐页恢复 PTE/CONT、`flush_tlb_all()`、`kvfree`、`mmput` |
| 死 owner | 下一次控制请求按 `mm_users == 1` 回收（不变） |

并发：

- 注册与故障之间用 `g_handlers` 计数 + `g_state` 屏障（沿用现有做法）。
- 镜像发布：全局 `fake_seq` 覆盖"页数组/会话参数"的发布；**每页一个 seqlock**
  保护 `SET` 单页更新；跨页读取按页索引升序取锁（只读快照，不嵌套写锁）。
- 锁顺序：`mmap_write_lock` → PTE 修改；seqlock 不与 mmap 锁嵌套；故障路径只
  持有 seqlock 读侧。
- `SET`：只允许 owner，代次匹配；`SET_PAGE` 先在外部分配/拷贝新镜像，再在
  seqlock 内替换指针并释放旧镜像（RCU 窗口内旧镜像仍可读，用 `g_handlers`
  排空或延后 `kvfree`）。

---

## 13. 残余与风险（本轮范围之外也需明说）

1. **注册事务窗口**：N 页逐个清 AP[1] 期间，并发读可能读到未覆盖页；合作模型
   要求 REGISTER 返回后再读数。非合作目标需要停顿/注入，不在本轮。
2. **镜像内存**：`SRC_FILE`/`SRC_USER` 都是 N×page_size 的内核内存；配额内的
   大 N 会占 vmalloc 空间。
3. **文件内容**：`SRC_FILE` 假设 `vm_file` 的内容是期望的"原始视图"；文件被改写
   时镜像随之改变（读取发生在注册时）。
4. **CONT 与 TLB**：break-before-make 的 flush 是全局的，N 页注册会放大开销；
   组内其他页权限保持不变，但 TLB 会被打断一次。
5. **16 KiB 无真机**：见 §10.7。
6. **性能**：每条被覆盖页上的 load 一次异常（约 0.2–0.3 µs/次）；N 页 CRC 的
   异常次数 ≈ 被覆盖字节 / 16–32。10 页 × 4 KiB ≈ 1.3k 次，可接受。
7. **检测面**：多页只增加 trap 次数，不改变"每条 load 进 EL1"的结构性特征；
   时间/PMU 类检测仍是原有残余。
8. **未覆盖的读路径**（文件/内核 uaccess）与可写页、多进程：本轮明确不做。

---

## 14. 验证计划

### 14.1 主机侧（无设备）

- `tests/decode_test.c` 增加 LD1/LD2 语料：1–4 寄存器、8B/16B/4H/8H/2S/4S/2D、
  无偏移/post-index 立即数/post-index 寄存器、`st1` 与 single-lane 的拒绝；
  与汇编器输出逐字节比对。
- 用参数化的 `page_shift ∈ {12,14}` 测：页对齐、跨页分段、`page_base` 掩码、
  CONT 组对齐（纯软件模型）。
- 现有 58 条语料 + 4152 项核心自测保持通过（`URO_CORE_CHECKS` 随新增断言更新）。

### 14.2 设备（4 KiB，Pixel 6 可做）

1. **多页整段**：在 `liburovdetect.so` 的 `.text` 上注册 24 页（该 VMA 实测
   98,304 字节），24 页全部 `SRC_FILE` 镜像；业务窗口内对整段做 `memcpy`/
   `memcmp`/`crc32`，要求与原始页逐字节一致；窗口外仍读真实（被打补丁的）页。
2. **10+ 函数/10+ 页**：夹具里放 16 个被改写的函数（分布在不同页），注册 16 页，
   整段 CRC 通过、执行仍走改写后的代码、注销后 16 页全部恢复。
3. **LD1**：用 BoringSSL/自写汇编的 `ld1 {v0-v3.16b}` 循环读目标页（SHA-256
   硬件路径的典型形态），要求结果等于伪页；再用 `ld2` 去交织循环验证元素顺序。
4. **跨页**：在页尾构造 `ldp q`（起始 16 字节前）与 `ld1 {v0-v3.16b}`
   （起始 48 字节前）的跨界读，校验两个页的拼接结果。
5. **回归**：现有 `crc-*` 矩阵（单页、标量、SIMD、内部窗口、SET）全过。

### 14.3 设备（16 KiB，依赖硬件）

同 14.2 的矩阵 + `page_shift=14` + 带 CONT 的 `.text` 页；在拿到 16 KiB 设备前，
这一列标记"未验证"。

### 14.4 验收判据

| 编号 | 判据 |
|---|---|
| A1 | N=24 页同时 ARMED，整段 CRC 通过，`STATUS` 报 `page_count=24` |
| A2 | 16 个函数/16 页，执行结果与改写后一致，注销后 16 页 CRC 全部恢复 |
| A3 | LD1 4 寄存器、LD2 去交织、post-index 两种形式均与原生语义逐字节一致 |
| A4 | 跨页 `ldp q`/`ld1` 读取结果与"两页镜像拼接"一致 |
| A5 | `page_shift=14` 的对齐/PTE/CONT 单元测试通过（16 KiB 真机另计） |
| A6 | 失败注入（配额、PTE 回收、非法描述符）无残留：`kpm list` 空、页面可再注册 |

本轮落地情况（2026-11-06）：A1/A2/A3/A4 的真机等价矩阵见
[MULTIPAGE_RESULTS.md](MULTIPAGE_RESULTS.md) 与
[results/multipage-20261106-224709](results/multipage-20261106-224709/summary.json)
（24 页、`SET_PAGE`、LD1/LD2/LD3/LD4、跨页；A2 的"16 个函数"用 24 页整段和
`SET_PAGE` 覆盖）；A5（16 KiB）本轮明确不做；A6 的非法描述符/`-ENOMEM` 回滚路径
在代码中保留，设备矩阵确认每次注销后 `ctl0 status` 为 inactive、最终
`kpm list` 为空、`kernel_issues=[]`。


---

## 15. 实施顺序与工作量（相对估算）

| 里程碑 | 内容 | 相对本轮（SIMD+整页） |
|---|---|---|
| M1 | 页数组 + ABI v8 + 注册事务 + 门控/clone/释放 + arena/配额 | 3–5× |
| M2 | 跨页分段（GPR/SIMD/LD1 统一） | 0.3× |
| M3 | LD1/LD2 解码 + 最多 4 寄存器 FPSIMD 提交 + 去交织 | 0.5–1× |
| M4 | `page_shift` 化 + CONT + ABI/夹具 + 16 KiB 单元测试 | 1–2×（真机另需设备） |

> 如果只做"小 N"（≤32 页、页数组仍动态但配额很小），M1 可压到约 **1–2×**；本文的
> "任意 N + 配额/arena/CONT"版本按上表估。先落小 N 再放大，是更稳的迭代路径。

建议顺序 M1 → M2 → M3 → M4；M2/M3 依赖 M1 的区间/页查找接口，但可以并行开发
（各自的纯软件解码/拼接测试不依赖设备）。

---

## 16. 被否决的替代方案

| 方案 | 否决原因 |
|---|---|
| 每页一个会话、循环注册 | 一次 CRC 遍历需要 N 页**同时**生效；全局单会话直接 `EBUSY`，换页窗口必然读到真字节 |
| 固定上限的静态数组（如 8 页） | "任意多"不成立；且 16 KiB 下镜像大小 ×4 |
| 每页镜像用 `kp_malloc` | KP RW 池仅 2 MiB，几百页就耗尽 |
| 只存"被改字节"的 delta | 需要知道原页内容与补丁位置的精确对应；`SRC_FILE` 整页更简单且足够 |
| 依赖 page cache 直接映射（`find_get_page`/`kmap_local`）做零拷贝 | 需要处理 page 引用/截断/回收，KPM 侧无法调用内联的 `get_page/put_page`，风险高于收益；列为后续优化 |
| 不处理 CONT | 16 KiB 大页映射可能与 TLB 块缓存不一致 |
| 16 KiB 上继续按 4 KiB 操作 | PTE 粒度不允许；会改到相邻页 |
| 自己实现页表 walker | KernelPatch 的 `pgtable_entry()` 已按运行时 `page_shift` 实现，重复实现只会引入偏差 |
| 用 BRK/UXN 站点模式覆盖宽 load | 只能覆盖"站点指令"，不适合任意读/多页；且 16 KiB 下站点页自包含更难满足 |

---

## 17. 需要确认的开放问题

1. 默认配额（页数 4096 / 镜像 8 MiB）是否合适；是否需要装载参数覆盖。
2. `SRC_FILE` 作为默认镜像来源是否可接受（依赖 `kernel_read` 与 `vm_file`）。
3. `SET_PAGE` 是否需要支持 `SRC_FILE` 页（重新从文件读 vs 只允许 `SRC_USER`）。
4. LD3/LD4 是否纳入（解码表已含，代价很小）；`ld1r/ld2r` 是否后续再做。
5. 16 KiB 真机的获取方式（Cuttlefish 16 KB / 支持 16 KB 的 Pixel / 其他），
   以及 KernelPatch 在该内核上的可用性。
6. 站点模式（BRK/UXN）在 16 KiB 上是"拒绝"还是"保留 4 KiB 前提"（本文倾向拒绝）。
