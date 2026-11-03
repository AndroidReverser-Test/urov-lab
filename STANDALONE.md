# 独立内核后端：实现与验收

更新于 2026-11-03。早期版本把异常/MM 后端放在匹配内核中，KPM 只做管理客户端；本版本把后端直接链接进 `urov-lab.kpm`，由模块自己安装内核入口，不再修改宿主内核。

## 实现结构

| 组件 | 位置 | 作用 |
|---|---|---|
| EL0 异常入口 | `urov_backend.c`，`hook_wrap(do_mem_abort, 3, ...)` | 在原生 fault 分发前识别本会话的 EL0 读 permission fault，解码并模拟 GPR load，成功后写回寄存器/PC 并跳过原路径 |
| 控制通道 | `urov_backend.c`，`fp_hook_syscalln(__NR_kcmp)` | magic + 128 字节请求；普通 kcmp 原样放行 |
| 映射事务 | `urov_backend.c` | `get_task_mm`、`pin_user_pages_unlocked`、VMA/PTE 校验、清 `PTE.AP[1]`、`flush_tlb_mm`、恢复 |
| 映射门控 | `urov_backend.c` | mprotect/munmap/mremap/madvise/mmap(MAP_FIXED) 与活动页相交时返回 `-EBUSY` |
| 解码/模拟 | `decode.c`、`emulate.c` | 纯软件、无分配；支持 8/16/24/32 字节覆盖窗口；`core_selftest.c` 提供 4139 项加载自测 |
| KPM 入口 | `urov_kpm.c` | 元数据、init/exit、`ctl0` 只读状态输出 |

## 语义

- 注册对象：调用者自己的 `mm`，一个 4 KiB、页对齐、sealed memfd 的 `MAP_SHARED` RX 页，文件 offset 0；一次一个会话、一个 8/16/24/32 字节覆盖窗口。
- 启用：保存 VMA/PTE 属性，设置 `VM_DONTCOPY`，清除 `vm_page_prot` 与 PTE 的 `AP[1]`（PTE_USER），`flush_tlb_mm`。取指使用同一 PTE，`UXN=0`，因此仍执行原页。
- 命中：只处理 EC=0x24、WnR=0、FSC=0x0f 且 `far` 在页内的 EL0 读异常；从快照取指令，`uro_emulate` 校验上下文、区间、syndrome 后一次性提交 GPR/SP/PC；窗口字节按 `length` 与伪数据合并。
- 更新：`SET` 在控制锁内校验 `session`、`expected_generation` 和 `length`，用 seqlock 发布一份完整的 32 字节 fake 向量；一次指令只取一份快照，LDP 两半一致。
- 失败：地址属于会话但指令/上下文不被支持时，`force_sig_fault(SIGSEGV, SEGV_ACCERR)`，并跳过原路径，绝不返回原字节。
- 注销/卸载：先恢复 PTE、VMA 权限模板和 `VM_DONTCOPY`，`flush_tlb_mm`，再清 active、排空在途 handler、解 pin、`mmput`；最后撤销 hook。

## 所有权与并发

- 会话对象是模块内静态对象，不依赖宿主回调；故障路径无分配、无睡眠、无锁，只读原页快照和 seqlock fake 快照（极端重试耗尽时 fail-closed）。
- 控制路径用单个 CAS 标志串行化；`g_handlers` 计数配合 `yield` 排空，避免在注册/释放会话时仍有 handler 读取旧字段。
- `get_task_mm` 取得的 `mm_users` 保证会话期间地址空间存活；`pin_user_pages_unlocked` 保证目标页驻留。注销时两者都在锁外释放。
- 模块卸载先恢复页面再撤销 hook；本版本实测了 4 个持续 fault 读者的卸载场景。

## 验收证据

- [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)：Pixel 6 / 6.1.134 / KP 0.12.0 上的 8/16/24/32 字节窗口、每个窗口 100 次更新、8 CPU 并发、5 次装卸循环、带读者卸载、fail-closed、fork 不继承和 dmesg 检查。
- [CURRENT_RESULTS.md](CURRENT_RESULTS.md)：当前状态、产物散列和限制。
- [IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md)：早期软件核心、原生差分和预检记录（历史）。

## 历史设计

`DESIGN.md` 与 `BACKEND_CONTRACT.md` 记录的 CORE-1 方案要求匹配内核常驻代码和 loader v2；本实现选择在 KPM 内安装 hook，从而避免修改宿主内核，但继承了其中的语义边界：一次一页/一覆盖、拒绝 SIMD 与跨页、raw XOM 的安全限制（本设备无 EPAN）。
