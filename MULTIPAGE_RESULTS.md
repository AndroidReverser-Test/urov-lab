# UROV-Y ABI v8：多页、LD1/LD2/LD3/LD4 与跨页 load（实现与真机结果）

> 2.8.0 更新：`SRC_FILE` 已移除，原 `mp-srcfile` 夹具改为 `mp-srcpage`，
> 用 `SRC_USER(off=0, len=page_size)` 传入整页镜像；`REGISTER` 遇到
> `SRC_FILE` 返回 `EINVAL`，`QUERY` 不再报告 `CAP_SRC_FILE`。下文 2026-11-06
> 的 `SRC_FILE` 实现与结果保留为历史对照。

日期：2026-11-06（Asia/Shanghai）。基线是 ABI v7（单页 4 KiB、SIMD&FP 单/pair、
整页镜像）；设计稿见 [MULTIPAGE_DESIGN.md](MULTIPAGE_DESIGN.md)。本轮按用户要求：
**R1 多页、R2 LD1/LD2（顺带 LD3/LD4）、R3 跨页全部实现；R4 16 KiB 不实现**。

## 1. 实现摘要

### 1.1 ABI v8

`struct urov_y_request` 从 256 字节扩到 **288 字节**（`_Static_assert`，MAC 仍为最后
8 字节、覆盖 `[0, size-8)`）：

```c
uint32_t page_count;      /* 1..max_pages；0 = v7 单页兼容 */
uint32_t page_stride;     /* 必须 32 */
uint64_t pages_addr;      /* struct uy_page_desc[] */
uint64_t session_flags;   /* bit0 强制 replay 快照 */
uint64_t reserved2;
uint64_t mac;
```

`struct uy_page_desc`（32 字节）：`base`、`fake_addr`、`fake_off`、`fake_len`、
`flags`（`SRC_USER`/`SRC_FILE`）、`reserved`。新 op `UROV_Y_SET_PAGE = 6`，页号在
`reserved` 低 32 位。`QUERY` 返回 `page_count = max_pages`、
`page_stride = page_shift`、`session_flags = caps`；`STATUS` 返回活动页数，`reserved`
低 32 位为仍 ARMED 的页数。caps：`MULTI|LD1|LD2|LD3|LD4|CROSS|SRC_FILE`，**不含
`CAP_16K`**。

v7 请求（`page_count == 0`）继续走原来的 `address/offset/length/value/fake_addr`
字段和 SITE_BRK/PAGE_UXN/PAGE_AP 三种模式；页数组只接受 `PAGE_AP`。

### 1.2 会话与内存

- `struct uy_page`：`base`、`image`（整页已合并视图）、`snapshot`（replay 用）、
  `file/file_off`（SRC_FILE）、`fake_off/fake_len`、`seq`、`index`、`armed`、
  `changed`、`retired`。
- `struct uy_session`：`pages[]`（按 base 升序）、连续 `arena`（N×4 KiB 镜像）、
  可选 `snapshots`（N×4 KiB）、调用者窗口与站点数组。
- 分配走 `kvmalloc_node(size, GFP_KERNEL, NUMA_NO_NODE)` + `kvfree`；解析不到时
  回退 `vmalloc`/`vfree`。默认配额 4096 页、8 MiB（镜像+快照），装载参数
  `max_pages=N`/`max_kb=N` 可调。所有分配在任何 PTE 改动之前完成，失败原子回滚。
- **快照策略**：v7 单页、站点模式、`caller_count > 0` 或设置
  `UROV_Y_F_REPLAY_SNAPSHOT` 时每页一份；多页 AP 且无 replay 需求时零快照。

### 1.3 注册事务

1. 拷贝/校验描述符数组（分块 `access_remote_vm`），`base` 4 KiB 对齐、唯一、无重叠；
2. `sort_descs()` 排序；`index` 保留描述符原序号供 `SET_PAGE` 使用；
3. 逐页 fault-in、VMA/PTE 校验、构建镜像：
   - `SRC_FILE`：`kernel_read(vm_file, image, 4096, &pos)`，
     `pos = (vm_pgoff << 12) + (base - vm_start)`；
   - `SRC_USER`：整页或 partial 窗口（`fake_len == 0` 表示整页）；
4. 一次 `mmap_write_lock` 内逐页复核 PTE（present/page/user/read-only/UXN=0/
   非 CONT/SPECIAL/DEVMAP）并清 `AP[1]`，一次 `flush_tlb_all()`；失败逐页恢复；
5. 发布 `g_state = LIVE`，返回 `page_count`。

### 1.4 故障路径

- `do_mem_abort` 只接管 `EC=0x24`、`WnR=0`、permission fault、当前 mm 且
  `page_find(page_base(FAR))` 命中的异常；不命中原样放行。
- 解码后的访问区间 `[address, address+total)` 按页切段：注册页从 `image`（fake）
  或 `snapshot`（replay）拷贝，未注册段用 `copy_from_user_nofault` 读真实字节；
  两段都成功才提交。最多跨 2 个 4 KiB 页（total ≤ 64）。
- `FAR` 必须落在访问区间内；否则 fail-closed。
- 提交顺序：FPSIMD（最多 4 个 V 寄存器）→ GPR/SP/PC；任何一步拒绝都不留半提交。
- 无分配、无睡眠；失败只发 SIGSEGV。

### 1.5 LD1/LD2/LD3/LD4

`decode.c` 新增 multiple-structure 组：`(insn & 0xbf000000) == 0x0c000000`，
`L=1`、bit21=0。opcode 表：`0010/0110/1010/0111` = LD1 4/3/2/1 寄存器，
`1000` = LD2，`0100` = LD3，`0000` = LD4；`size` 选 8/16/32/64 位元素，Q 选
64/128 位数据宽度；支持无偏移、post-index 立即数（Rm=31）和 post-index 寄存器。
`struct uro_load` 新增 `total/multi/nregs/selem/esize/elements/dst[4]`。

提交公式（与 ARM ARM 一致）：

```
dst[r*selem+s] = (Rt + r + s) & 31
mem_off = ((r*elements + e)*selem + s) * esize
reg_off = e * esize
```

一次 `fpsimd_signal_preserve_current_state()` 后写最多 4 个 V 寄存器，再一次
`fpsimd_update_current_state()`；64 位数据宽度时高 64 位清零。

### 1.6 16 KiB

**未实现**。`UROV_Y_PAGE`/`UROV_Y_PAGE_SHIFT` 仍为 4096/12，
`supported_pagetables()` 只接受 4 KiB TG0/TG1，`QUERY` 不设 `CAP_16K`，
`page_shift` 恒为 12。设计稿 §10 仅作为后续工作记录。

## 2. 主机侧验证

在 WSL 中运行：

```bash
cd /mnt/e/KernelPatch/kpms/urov-lab
UROV_TEST_OUT=/tmp/urov-host bash tools/test_host.sh
```

结果（2026-11-06）：

```text
PASS checks=224473 vectors=58 multi=17 random=100000 independent_assembler=verified
PASS emulator_checks=288099 core_checks=4152 value_cases=144000 threaded_pair_cases=100000
```

- `vectors=58`：原有 GPR/SIMD 语料全部保持；
- `multi=17`：LD1/LD2/LD3/LD4、8B/16B/4H/2S/2D、post-index 立即数/寄存器，
  以及 `st1`、single-lane、1D LD2、无偏移 Rm≠0、地址回绕的拒绝；
- 与 `aarch64-linux-gnu-gcc` 汇编输出逐字节比对（`independent_assembler=verified`）。

## 3. 真机矩阵

设备：Pixel 6（oriole，Android 16 / 内核 6.1.134，4 KiB 页），
KernelPatch superkey `Test6666`。

```bash
python kpms/urov-lab/tools/run_multipage_device.py \
    --serial 25091FDF60063J --key Test6666 --skip-install \
    --repeats 5 --cycles 2
```

结果：[results/multipage-20261106-224709/summary.json](results/multipage-20261106-224709/summary.json)
（`passed=true`、8 次运行全 PASS、`final_modules=[]`、`kernel_issues=[]`）。

| 模式 | 覆盖内容 | 结果 |
|---|---|---|
| `mp-multi` | 24 页同时 ARMED；96 KiB `memcpy` 整段等于 24 页伪镜像；业务窗口外读原页；`SET_PAGE` 换第 7 页后重读一致；注销后 24 页恢复 | PASS ×2 |
| `mp-ld1` | `ld1` 4/2/1 寄存器、`ld1 8B`、post-index 立即数/寄存器、`ld2`/`ld3`/`ld4` 去交织；每组先做原生 oracle | PASS ×2 |
| `mp-cross` | `ldp q`（32B）与 `ld1`（64B）跨页；`ld1` 页尾 8B；起始于未注册页的 32B 读（前半真实、后半伪值）；注销恢复 | PASS ×2 |
| `mp-srcfile` | `SRC_FILE` 从 `vm_file` 读整页；业务窗口内读等于文件页，窗口外读保持原页 | PASS ×2 |

关键日志（`mp-multi-1`）：

```text
MP_QUERY caps=0x7f max_pages=4096 page_shift=12 abi=8
MP_MULTI pages=24 span=98304 register=1 generation=1
MP_STATUS name=multi pages=24 armed=24 hits=0 replays=0 failures=0
MP_SET_PAGE page=7 generation=2 diff=98304
MP_MULTI_DONE pages=24 restored=1
```

`mp-ld1-1`：`MP_LD_DONE readers=ld1x4/ld1x2/ld1x1/ld1_8b/post_imm/post_reg/ld2/ld3/ld4 n=5`；
`mp-cross-1`：`MP_CROSS_DONE reads=ldp_page1_page2/ld1_page1_page2/ld1_tail/uncovered_page0 n=5`；
`mp-srcfile-1`：`MP_SRC_FILE register=1 page=1`、`MP_SRC_FILE_DONE page=1 reads=5`。

同轮回归：`tools/run_crc_device.py --repeats 3 --cycles 1` 全 PASS
（[results/crc-20261106-224729](results/crc-20261106-224729/summary.json)），
覆盖 `crc-brk`/`crc-uxn`/`crc-ap`/`crc-ap-all`/`crc-ap-text`/`crc-ap-libc`/
`crc-ap-big`，证明 v7 单页三种模式、整页 SIMD 传输与 `SET` 未被 v8 改动破坏。

产物 SHA-256：

```text
bea1c4c26e635c7b229fe3af3720049da808bff8858a975a0d7ae60699c6809d  out/urov-y.kpm
dee2dfb1268ac55ce5578c56ee65a4a44bb467f24f22b3c6bc42f8a7e10ee867  apps/urov-detect/out/urovdetect.apk
```

## 4. 已知边界

1. **16 KiB 未实现**：4 KiB 常量 `UROV_Y_PAGE`、`page_shift=12`、
   `supported_pagetables()` 的 4 KiB 限制都保留；不要在 16 KiB 设备上启用。
2. **SRC_FILE 的 file 指针是借用的**：依赖合作模型（注册后到注销前目标 VMA
   不被并发 unmap/mprotect）；现有 mapping gates 会结束会话，但不持有 `file` 引用。
3. **partial `SET_PAGE` 需要快照**：`caller_count==0` 且页面是整页 SRC_USER 时，
   没有原始页快照，partial 窗口无法重建，返回 `-EOPNOTSUPP`；整页更新仍可用。
4. **配额**：默认 4096 页/8 MiB（镜像+快照），大 N 会占用 vmalloc 空间；
   `-ENOMEM` 发生在任何 PTE 改动之前。
5. **未覆盖段**：跨页读若邻页不可读，按原生语义 SIGSEGV，不返回部分结果。
6. **CONT 组**：`page_pte_leaf()` 仍拒绝 `PTE_CONT`；当前 4 KiB Pixel 6 的 `.text`
   未触发。16 KiB 设计中的 break-before-make 未实现。
7. **性能**：每条覆盖页上的 load 一次异常（约 0.2–0.3 µs）；24 页 96 KiB
   `memcpy` 的异常次数约数千，测试中可接受。

## 5. 复现

```powershell
# 构建
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1

# 设备矩阵（会自行加载/卸载模块）
python kpms\urov-lab\tools\run_multipage_device.py `
    --serial <SERIAL> --key Test6666 --repeats 5 --cycles 2
```

手动单模式：

```sh
adb push kpms/urov-lab/out/urov-y.kpm /data/local/tmp/
adb shell /data/local/tmp/kpatch Test6666 kpm load /data/local/tmp/urov-y.kpm key=<32hex>
adb shell am start -W -n com.example.urovdetect/.MainActivity \
    --es mode mp-multi --ei repeats 5 --es key <32hex>
adb shell /data/local/tmp/kpatch Test6666 kpm ctl0 urov-y status
adb shell /data/local/tmp/kpatch Test6666 kpm unload urov-y
```
