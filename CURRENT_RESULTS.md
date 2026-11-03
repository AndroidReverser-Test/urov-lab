# UROV-LAB 当前进度

更新于 2026-11-03（Asia/Shanghai）。

**独立 KPM 已在 Pixel 6 上完成活动覆盖验收。** `urov-lab.kpm` 自带解码/模拟核心、EL0 数据异常后端和控制 syscall hook，不再依赖任何外部宿主补丁或内置内核后端。普通 `load` 读取注册页时获得伪造值，同一页的取指仍执行原始机器码；更新、注销和卸载均已验证。

> 2026-11-04 更新：普通 app 支持已落地并验收（`__NR_prctl` 控制通道、app 自身一页只读可执行 `MAP_SHARED` 文件映射、mm 所有权与死 owner 回收）。见 [APP_OVERLAY.md](APP_OVERLAY.md) 与 [RESULTS_APP.md](RESULTS_APP.md)。下文 2026-11-03 的 root/KPM 结果仍有效。

## 本次交付

| 项目 | 状态与证据 |
|---|---|
| 常驻异常后端合并进 KPM | `urov_backend.c` 在模块 init 中 hook `do_mem_abort`；清除目标页 `PTE.AP[1]` 后捕获 EL0 读 permission fault，解码并模拟 GPR load，写回 `pt_regs`。 |
| 控制系统调用 | hook `__NR_kcmp`（272）；magic `0x55524f5653595343`；128 字节 `urov_request`（ABI v2）支持 QUERY/REGISTER/SET/STATUS/DEACTIVATE，`length` 选择 8/16/24/32 字节窗口。普通 kcmp 调用不受影响。 |
| 宽窗口覆盖 | `length` + `value_hi[3]` 携带最多 32 字节 fake；fault 路径用 seqlock 获取一份完整快照，LDP 两半一致。 |
| 映射事务 | `pin_user_pages_unlocked` 预触页并 pin，`get_task_mm` 保留 `mm_users`，VMA/PTE 校验，`VM_DONTCOPY`，PTE/VMA/TLB 恢复。 |
| 映射门控 | 活动范围内 `mprotect`/`munmap`/`mremap`/`madvise`/`mmap(MAP_FIXED)` 返回 `EBUSY`。 |
| 失败语义 | 白名单外指令（SIMD 等）fail-closed，强制 SIGSEGV；不返回原字节。 |
| 卸载恢复 | 32 字节活动会话下带 4 个持续 fault 读者卸载：1.10 亿次循环、0 错误、原始值恢复、模块列表为空。 |
| 真机覆盖 | 8 CPU 并发、每个窗口 100 次更新；8/16/24/32 字节窗口分别 160700/171379/225666/242698 次命中；1/2/4/8 字节与 LDP 均通过。 |

完整命令输出、产物散列和日志检查见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)；构建运行方式见 [README.md](README.md)。

## 产物散列

```text
c55987c4667c02590f63f241a8a18012f8f4c4e790cf25fc290f77c1c085ebdd  urov-lab.kpm
128a8bc7583ec24c4d75b9ef531df017cb8709cd1d129ae66d11b7c1bc2baa58  urov_overlay_test
```

## 当前限制

1. 合作测试模型：一个会话、一页、一个最多 32 字节的覆盖窗口；只注册调用者自己的 `mm`。单条 A64 整数 load 最多 8 字节，LDP 最多 16 字节。
2. 设备无 EPAN；raw XOM 只用于 EL0 权限实验，不等价于生产级 XOM 隔离。
3. 仅支持 64 位 EL0、4 KiB 页和 `decode.c` 白名单内的 GPR load（含 LDP）；SIMD/FP、跨页、原子/独占、MTE 明确拒绝。
4. 未做长时间压力、migration/reclaim 故障注入和性能测试。

## 历史记录

2026-11-02 至 2026-11-03 早期的预检、软件核心、原生差分、内置内核后端草稿和 loader v2 讨论保留在以下文档中：

- [IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md)（软件核心与预检）
- [DELIVERY.md](DELIVERY.md)（历史桥接交付）
- [STANDALONE.md](STANDALONE.md)（独立后端设计与验收历史）
- [DESIGN.md](DESIGN.md)、[BACKEND_CONTRACT.md](BACKEND_CONTRACT.md)（CORE-1 设计与契约）
- [TEST_PLAN.md](TEST_PLAN.md)（测试计划）
