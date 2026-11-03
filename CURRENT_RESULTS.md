# UROV-LAB 当前进度

更新于 2026-11-03（Asia/Shanghai）。

**独立 KPM 已在 Pixel 6 上完成活动覆盖验收。** `urov-lab.kpm` 自带解码/模拟核心、EL0 数据异常后端和控制 syscall hook，不再依赖任何外部宿主补丁或内置内核后端。普通 `load` 读取注册页时获得伪造值，同一页的取指仍执行原始机器码；更新、注销和卸载均已验证。

## 本次交付

| 项目 | 状态与证据 |
|---|---|
| 常驻异常后端合并进 KPM | `urov_backend.c` 在模块 init 中 hook `do_mem_abort`；清除目标页 `PTE.AP[1]` 后捕获 EL0 读 permission fault，解码并模拟 GPR load，写回 `pt_regs`。 |
| 控制系统调用 | hook `__NR_kcmp`（272）；magic `0x55524f5653595343`；128 字节 `urov_request` 支持 QUERY/REGISTER/SET/STATUS/DEACTIVATE。普通 kcmp 调用不受影响。 |
| 映射事务 | `pin_user_pages_unlocked` 预触页并 pin，`get_task_mm` 保留 `mm_users`，VMA/PTE 校验，`VM_DONTCOPY`，PTE/VMA/TLB 恢复。 |
| 映射门控 | 活动范围内 `mprotect`/`munmap`/`mremap`/`madvise`/`mmap(MAP_FIXED)` 返回 `EBUSY`。 |
| 失败语义 | 白名单外指令（SIMD 等）fail-closed，强制 SIGSEGV；不返回原字节。 |
| 卸载恢复 | 带 4 个持续 fault 读者卸载：8879 万次循环、0 错误、原始值恢复、模块列表为空。 |
| 真机覆盖 | 8 CPU 并发、100 次更新、182628 次模拟命中；1/2/4/8 字节与 LDP 均通过。 |

完整命令输出、产物散列和日志检查见 [RESULTS_OVERLAY.md](RESULTS_OVERLAY.md)；构建运行方式见 [README.md](README.md)。

## 产物散列

```text
1a24f1f61131b2800b6fb501357c08af579d0ed2e5bda44d8c15413dd0108b65  urov-lab.kpm
d3b50be48138b6102417c0d611099b5494bee529daeadf2ba6bd6ece162e45fe  urov_overlay_test
```

## 当前限制

1. 合作测试模型：一个会话、一页、8 字节覆盖；只注册调用者自己的 `mm`。
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
