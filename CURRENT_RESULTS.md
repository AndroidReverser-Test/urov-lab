# UROV-LAB 当前进度

更新于 2026-11-08（Asia/Shanghai）。

> 2026-11-08 补充：`urov-y` 2.14.0 消除 2.13.0 仍成立的两条 **App 可及** 恢复
> 路径：成功的 `mprotect(PROT_READ/PROT_NONE/PROT_EXEC/PROT_READ|PROT_WRITE)`
> 不再结束会话（private COW 页仍由 `AP[1]=0` 读陷阱服务；`PROT_NONE` 仍原生
> `SIGSEGV`），第一次真实 store 才由原 Linux fault 路径完成 COW 并退役该页；
> 未分配 pkey 的 `pkey_mprotect`、private VMA 的 `remap_file_pages` 和
> `MAP_FIXED|MAP_FIXED_NOREPLACE` 等 Linux 会拒绝的调用不再先拆会话。
> Dobby 48×3 活动阶段 `ap=0/144`、`accepted_crc_with_ap=144/144`；
> CRC 5×2（16 次）、消除 3×1（11 次，`ELIM_PROT ... store_retired=1`）、
> 多页 5×1 均 PASS；`site_call_ns=288/292`。构建 `urov-y.kpm 51140d21...`、
> `urovdetect.apk 889cb318...`。见
> [ELIMINATION_2_14_DESIGN.md](ELIMINATION_2_14_DESIGN.md)、
> [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.14.0 节
> 与 [APP_READ_INTEGRITY_AUDIT.md](APP_READ_INTEGRITY_AUDIT.md) 的 2.14.0 节。

> 2026-11-08 补充：`urov-y` 2.12.0 消除 2.11.0 仍成立的五条 **App 可及** 特征：
> `/proc/<pid>/mem`/ptrace/跨进程 `process_vm_readv` 的内核辅助读（新增
> `__access_remote_vm` after hook，并按目标 `mm` 判定 `process_vm_readv`）、
> `mlock` 拒绝注册（`VM_LOCKED` 现在接受）、无效 `madvise` 撤销会话（改为透传
> Linux 的 `EINVAL`）、重叠 `mprotect(RX)` 结束会话（改为保活并重装），以及
> `fork`/`vfork`/`vfork`+`exec` 结束会话（改为子进程继承陷阱并按镜像返回，
> 会话结束后孤儿陷阱修复为重试）。Dobby 24×3 活动阶段 `views=0/72`、
> `accepted_crc=72/72`、`/proc/self/mem` 18/18 与 EL0 视图一致；CRC 5×2、
> 消除 6×2、多页 5×1（含新增 24 页五路径 `mp-prod`）均 PASS，
> `site_call_ns=285/286`。构建 `urov-y.kpm 13ca0c0c...`、
> `urovdetect.apk 4494e72c...`。见
> [ELIMINATION_2_12_DESIGN.md](ELIMINATION_2_12_DESIGN.md) 与
> [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.12.0 节。

> 2026-11-07 补充：`urov-y` 2.10.0 用同进程 `process_vm_readv` after hook 补齐
> GUP 读路径，但任一侧 iovec 数超过 64 时直接返回。2.11.0 把计数上限对齐
> `UIO_MAXIOV=1024`，用逐项游标覆盖全部合法 iovec；pid 不是自身 tid/tgid 时
> 在 RCU 下用 `find_task_by_vpid` 比较 `task->mm`，覆盖同 mm 兄弟 tid。
> Dobby 48×10 活动阶段 `views=0/480`、`accepted_crc=48/48`（合计 480）、
> `iov1024_match=1`、`sibling_match=1`、`split_match=1`。见
> [ELIMINATION_DESIGN.md §19](ELIMINATION_DESIGN.md#19-第十一轮完整-iovec-窗口与同-mm-pid-解析)
> 与 [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.11.0 节。

> 2026-11-07：`urov-y` 2.8.0 移除 `SRC_FILE`，所有页镜像统一由 `SRC_USER`
> 提供（每页一次最多一页）；Dobby/多页/CRC/消除矩阵已复跑。2.7.0 的整页直接
> 分支/NOP/间接分支门控见 [ELIMINATION_DESIGN.md §16](ELIMINATION_DESIGN.md#16-第八轮nop-间隔分支与间接分支门控)，
> 最新真机数据见 [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md)。
>
> 2026-11-07 补充：`urov-y` 2.9.0 在 `REGISTER` 期构建全进程直接分支目标位图，
> 消除 2.8.0 仍命中的跨页 LL/SC 探针；Dobby 24×5 活动阶段
> `cross_page_successes=0/768`、`accepted_crc=24/24`，读取路径耗时不变。见
> [ELIMINATION_DESIGN.md §17](ELIMINATION_DESIGN.md#17-第九轮register-期全进程分支目标位图)
> 与 [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的 2.9.0 节。

**独立 KPM 已在 Pixel 6 上完成活动覆盖验收。** `urov-lab.kpm` 自带解码/模拟核心、EL0 数据异常后端和控制 syscall hook，不再依赖任何外部宿主补丁或内置内核后端。普通 `load` 读取注册页时获得伪造值，同一页的取指仍执行原始机器码；更新、注销和卸载均已验证。

> 2026-11-04 更新：普通 app 支持已落地并验收（`__NR_prctl` 控制通道、app 自身一页只读可执行 `MAP_SHARED` 文件映射、mm 所有权与死 owner 回收）。见 [APP_OVERLAY.md](APP_OVERLAY.md) 与 [RESULTS_APP.md](RESULTS_APP.md)。下文 2026-11-03 的 root/KPM 结果仍有效。
>
> 2026-11-04 补充：针对 [DETECTION_RESULTS.md](DETECTION_RESULTS.md) 的特征点新增 stealth
> 变体 `urov-x`（密钥化隐蔽控制通道、读取点绑定、透明映射生命周期、fork 窗口、
> 未支持指令 fail-safe）。设计与设备矩阵见 [STEALTH_DESIGN.md](STEALTH_DESIGN.md)、
> [STEALTH_RESULTS.md](STEALTH_RESULTS.md)。原 `urov-lab.kpm` 未改动。
>
> 2026-11-05 补充：读取点陷阱变体 `urov-y` 已两轮验收。第一轮把覆盖移到读取点
> 指令（BRK），KEYLESS 的两项检测归零，但代码页被改写；第二轮新增 `PAGE_UXN`
> 模式（ABI v5，`mode=2`）：不改一个代码字节，只清 EL0 执行许可，用 instruction
> abort 在 EL1 模拟读取点，代码页特征也消失（`differs=0`、`Private_Dirty=0`）。
> 见 [ELIMINATION_DESIGN.md](ELIMINATION_DESIGN.md)（§9）与
> [ELIMINATION_RESULTS.md](ELIMINATION_RESULTS.md)。原 `urov-x`、`urov-lab.kpm`
> 未改动。
>
> 2026-11-05 第三轮：`ud_observe_execution()` 证明 UXN 模式的读取点页可被取指
> canary 识别（255/255）。新增 `PAGE_AP`（ABI v6，`mode=3`）：只清目标页 AP[1]，
> 读取点页取指原生；数据 permission abort 由紧邻 LL/SC 桥消除监视器信号。正式
> 矩阵 14 次运行、225 次观测，独占/reader MATCH 0，AP 的 48 次 execution 观测
> 全部 `match=0`；30 次 `w-active` 轮询到 `llsc=11,960`。见 §10 与
> [结果](results/eliminate-20261105-213741/summary.json)。

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
