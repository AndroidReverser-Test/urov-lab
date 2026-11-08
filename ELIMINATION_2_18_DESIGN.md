# UROV-Y 2.18.0：读回目的页替换与外部写合并

本文是 `urov-y` 2.18.0 的设计说明。目标是消掉
[ELIMINATION_2_17_DESIGN.md](ELIMINATION_2_17_DESIGN.md) §6/§8 里除“读取计时”
之外仍存在的、普通 App 无密钥即可复现的特征点，同时不引入新的 App 可观察特征。
只改 `urov-y`、测试 App/夹具与文档；`urov-lab`、`urov-x` 不动；ABI 仍为 v8，
`hooks=0xff`、请求布局、`ctl0` 文本、计数器与返回码不变。

## 1. 输入：2.17.0 仍成立的特征

| # | 2.17.0 行为 | 普通 App 的用法 | 2.17.0 证据 |
| --- | --- | --- | --- |
| H1 | `process_vm_readv()` 的后置钩子重新读取用户态 iovec，并按“当前”目的地址写回镜像；第一个 iovec 的目的地可以改掉第二个 iovec | 两段 iovec：第一段把 `redirect` 写进 `local[1].iov_base`，第二段仍由内核导入到 `live`；后置钩子把镜像写进 `post` | 2.17 设计 §8.1；`READ_DEFENSE_V216 ... post=128/128` |
| H2 | 内核辅助写（`read()`/`O_DIRECT`/`process_vm_writev` 写进注册页）让该页 `dead`；此后该页读真实字节 | 先写 1 字节（或整页），再读未被写到的偏移，得到被 Dobby 改过的活页字节 | 2.17 设计 §3.4/§6.5；`v217-gup` 只验证“写到达活页” |
| H3 | 未解码 store 的延迟原生重放期间，该页在本 CPU 上可读；其他 CPU 若恰好 TLB miss 并重走页表，理论上能看到一次活页字节 | 需要精确卡在重放窗口内制造 TLB miss | 2.17 设计 §6.2，已被 2.17 自己定性为“不是稳定的字节特征” |
| H4 | pkey/POE 只验证了拒绝/透传路径，未验证真实 POE 正向权限 | 需要 POE 硬件；本机无 POE，App 的 seccomp 也拒绝 syscall 288/234 | 2.17 设计 §3.6、§6.3 |
| H5 | root 通过 `kpm list`/`ctl0 status` 能看到模块与会话 | 需要 root；不在普通 App 的 CRC 输入集合内 | 2.17 设计 §6.4 |
| H6 | `execve`/进程退出结束会话 | 新地址空间里的代码是真实的，读值与执行一致 | 2.17 设计 §6.6 |
| H7 | PAGE_AP 下 `LDXR; LDRB; ADD; STXR` 仍可观察到“读关联的独占丢失” | 在 LDXR 与 STXR 之间放一条寄存器 ALU 指令，读一次注册页，统计 STXR 失败 | 2.17 设计 §8.2；`read-defense-v216-ap-* alu=1` |

本轮处理 H1、H2；H3–H7 的处置见 §4。H1 是本轮唯一“普通 App、无密钥、稳定、
可脚本化”的读值伪造证据，H2 是唯一能让覆盖在一条普通 `read()`/`O_DIRECT` 之后
整页退役的稳定路径，因此两者都必须真正消除，不能只换检测方式。

## 2. 威胁模型（不变）

生产 CRC 的输入仍是两类：

1. 读者能拿到的字节：EL0 标量/向量 load、`memcpy`/`memcmp`/`crc32`、
   `process_vm_readv`、`/proc/*/mem`、`ptrace`、`vmsplice`/pipe、fork 子进程的读；
2. 读者能观察的副作用：映射属性、页表统计、异常、独占监视器、耗时、崩溃、
   系统调用返回值。

计时不在消除范围。root 可见性不在普通 App 的输入集合内。

## 3. 方案

### 3.1 H1：把“写回目的地址”改成“替换内核将要复制的源页”

2.17.0 的 `uy_vm_readv_after()` 在 Linux 完成复制后，再次读取用户态 iovec 数组，
按读到的目的地址把 image/snapshot 写回。问题不在“后置写回”本身，而在**目的地址
来自用户内存**：内核在复制前导入 iovec，复制期间用户可以改这段内存，于是
“内核写 A、插件写 B”可以被稳定构造出来，B 里的活页字节就是伪造证据。

2.18.0 不再让用户内存参与覆盖：

1. `process_vm_readv` 入口钩子只记录本次调用的 caller-window 判定
   （`allow = caller_count==0 || caller_allowed_deep(regs)`），按 task 存进一个
   64 项槽位，不读任何用户内存；
2. `pin_user_pages_remote()` 的后置钩子拿到内核已经 pin 住的远端页数组、远端
   起始地址和页数；对每一个恰好落在注册页基址上的 pin 页，把数组项换成持有
   覆盖视图的内核页（owner 的 `image`/`snapshot`，子进程的影子页同理）；
3. 换页时把 `GUP_PIN_COUNTING_BIAS`（1024）从原活页搬到替换页，调用者随后的
   `unpin_user_page()` 两边正好抵消，活页的 pin 计数与覆盖页的引用计数都不泄漏；
4. 随后 `copy_page_to_iter()` 用替换页作为源，把 image/snapshot 复制到**内核
   自己导入的那个目的地址**。用户 iovec 数组无论怎么改，都只能改变内核写到哪里，
   不能改变写进去的字节；双 iovec 自引用技巧因此失效：`post` 保持填充值。

已解码页以外的映射（`page_find()` 未命中）与 `FOLL_WRITE` 的 pin（写目的页）
不替换。`pin_user_pages_remote`、`struct page._refcount` 或 `vmalloc_to_page`
任一不可用时，保留 2.17.0 的目的地址回写作为兼容路径，并在 verbose 日志里
标明；本机三者都可用，走新路径。

### 3.2 H2：外部写不再让页退役，改为“先快照、后合并”

2.17.0 在外部写者拿到写权限时把页标 `dead`：写确实落到活页，但覆盖对该页永久
失效，这是“写 1 字节再读其余偏移”就能稳定命中的指纹。2.18.0 保留写者的原生
语义，同时保留覆盖：

1. **快照**：在确认外部写者已拿到可写翻译的三个点——uaccess 写缺页
   （`handle_mm_fault` 的 `FAULT_FLAG_WRITE` 且 `pt_regs != NULL`）、fast-GUP
   `FOLL_WRITE`、slow-GUP `__get_user_pages` 的 `FOLL_WRITE`——用用户态 nofault
   读把活页复制到私有 `ext_pre`，置 `ext` 标志。此时叶子刚被 COW 改成
   EL1 可写、AP[1] 已由内核置 1，所以该读不会因陷阱失败，也不需要从缺页/GUP
   回调里再取 mmap 锁；
2. **重新装陷阱**：uaccess 写缺页在 COW 已把叶子改成 EL1 可写、AP[1] 被内核
   置 1 之后立即清回 AP[1]（EL1 重试写不受 AP[1] 影响，不会重试死循环）；
   GUP 写缺页不在缺页钩子里重装，而是等 `__get_user_pages` 返回页数组后由
   `uy_gup_slow_after()` 重装；fast-GUP 由 `uy_gup_after()` 在返回页数组后
   重装。写者始终通过 pin 住的 `struct page *` 写，不经过 PTE，所以重装安全；
3. **合并**：下一次任何读路径（EL0 数据异常仿真、`process_vm_readv` 源页替换、
   `__access_remote_vm` 读、`vmsplice` 页替换、`SET`/`SET_PAGE`、卸载）在
   `read_range()`/`uy_*_overlay()` 里先调用 `uy_ext_drain()`：GUP 读回活页，
   与 `ext_pre` 逐字节比较，只把变化的字节发布进 image/snapshot，然后清 `ext`。
   写者仍写的是活页，app 自己的读仍得到它写进去的字节；未被写到的偏移继续返回
   镜像，覆盖没有退役；
4. 并发：`ext_busy` 保证同一页只有一个 drain 在比较；`ext_pre`/`ext_buf` 与
   重放用的 `pre`/`post` 分开（每描述符 7 个私有页），所以外部写与未解码 store
   重放互不覆盖缓冲区；子进程仍按 2.17 的“保持原生可写”处理，不进入 owner 的
   `ext` 状态。

### 3.3 H3–H7 的处置

- **H3 重放窗口**：不新增机制。窗口从“恢复 AP[1] + 本地 TLBI”到 Software Step
  处理结束，仍是一次跨 CPU TLB miss 的亚指令级竞态；要把它变成零窗口只能在
  重放期间停其他 CPU（`stop_machine`）或给故障 task 复制页表，两者都会引入
  系统级停顿/新页表，是比原特征更大的新特征。按 2.17.0 的定性保留，并明确它
  属于“读/写异常路径”的架构代价，与计时同级。
- **H4 pkey/POE**：不改。陷阱仍只清 AP[1]，PTE 的 permission index 由内核
  `pkey_mprotect` 写入、CAS 不碰；AP[1]=0 对 EL0 数据访问强于 pkey/POE，
  `pkey_mprotect` 只透传并重装陷阱。本机无 POE，App 的 seccomp 拒绝
  syscall 288/234，因此只验证拒绝/透传路径不碰会话。
- **H5 root 可见性**：不改。`kpm list`/`ctl0 status` 需要 root，不在普通 App
  的 CRC 输入集合内；隐藏它要改 KernelPatch 核心，超出“只改 `urov-y`”。
- **H6 execve/退出**：不改。地址空间被替换，新代码是真实的，读值与执行一致，
  不构成读值不一致特征。
- **H7 独占丢失**：不改判定，保留 2.17 的相邻/`NOP` 桥接。它是“每次读一次同步
  异常”的直接结果：异常返回清本地独占监视器，插件只能在该异常里补完可证明的
  LL/SC 结果；要把任意中间指令都补完，需要在 EL0 单步执行中间指令再拦截 STXR，
  那会为每条指令增加一次 Software Step 异常——属于新的可观察特征。真实业务
  不会把注册页的读放进 LL/SC 临界区，夹具把它记为“辅助证据”。本轮把它归入
  “读取异常（计时）”这一类，而不是读值伪造。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 不新增/移动 VMA；替换页与 `ext_pre`/`ext_buf` 都是插件私有内核页 |
| 新的代码字/页表权限 | 仍只改叶 PTE 的 AP[1]；外部写后重装的仍是同一个 AP[1]=0 陷阱，AP[2] 保持 COW 结果 |
| 新的崩溃 | 外部写仍由内核完成；drain 用 `access_remote_vm`，失败只保留 `ext` 稍后重试；未改变 SIGSEGV 路径 |
| 新的返回码/ABI | `process_vm_readv` 的返回值仍来自 Linux（源页替换不改变长度/错误）；ABI v8、请求布局、`ctl0` 文本、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；新增的 `pin_user_pages_remote`、`__get_user_pages` 都是函数钩子，不新增 syscall 入口 |
| 新的写语义 | 写者仍写活页（O_DIRECT/`read()`/`process_vm_writev` 的字节真的到达映射）；镜像只多一次“把已发生的写合并进来” |
| 新的读视图 | EL0 读仍返回 image/snapshot；`process_vm_readv` 对同一 caller 返回与 EL0 相同的视图（window 外 snapshot，all-caller 下 image），只是不再多写一个用户态目的地址 |
| 新的计时台阶 | 外部写后第一次读多一次 4 KiB 比较（写侧事件，不是每次读）；H1 的源页替换把一次 4 KiB 内核复制留在同一次 syscall 内，没有额外异常 |

## 5. 真机验证（本轮）

设备：Pixel 6 / Android 16 / ARM64 / 4 KiB / `6.1.134-android14-11` /
KernelPatch `0xc00`。App 在 `untrusted_app`，`CapEff=0`、`Seccomp=2`、
SELinux Enforcing。模块 verbose 加载确认
`pin_remote=1 gup_slow=1 page_ref=1/52`（`struct page._refcount.counter`
偏移 52），`mm_fault=handle_mm_fault/4`。

| 矩阵 | 结果 | 目录 |
| --- | --- | --- |
| 读回双 iovec 8×1（v216 四模式） | PASS；`post=0/8` 全部阶段，`split` 与 `guarded_accept` 按 caller-window 语义 | [read-defense-v216-20261108-180103](results/read-defense-v216-20261108-180103/summary.json) |
| 旧读防御 8×1 | PASS | [read-defense-20261108-180119](results/read-defense-20261108-180119/summary.json) |
| v217 App 1×6 + root 探针 | PASS；`V217_GUP live_matches=1 active=1`、`V217_GUP overlay_alive=1`，gup 探针 `live_matches_file=1 active=1` | [v217-20261108-180042](results/v217-20261108-180042/summary.json) |
| 消除 3×1 | PASS | [eliminate-20261108-180150](results/eliminate-20261108-180150/summary.json) |
| 多页 3×1 | PASS | [multipage-20261108-180243](results/multipage-20261108-180243/summary.json) |
| CRC 5×1 | PASS | [crc-20261108-180132](results/crc-20261108-180132/summary.json) |

详细数字见 [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的
2.18.0 节。

## 6. 残余（2.18.0）

1. **计时**：每次 EL0 数据读仍一次同步异常；未解码 store 多一次 Software Step
   与整页 diff。按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍
   保留陷阱项；跨 CPU TLB miss 的亚指令级竞态。见 §3.3 H3。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改核心。
5. **独占丢失（H7）**：PAGE_AP 下读异常仍会清本地独占监视器；只对相邻/
   `NOP` 间隔的可证明 LL/SC 形状补完。属于读取异常路径的架构后果。
6. **子进程的外部写**：子进程 mm 的外部写仍保持 2.17 的“原生可写、不合并”
   处理；owner 的外部写已合并。子进程覆盖本身由 `copy_mm` 快照与文件身份
   解析维持，不构成 owner 的读值特征。
7. **外部写与未解码 store 重放的交叠**：`p->replay` 置位时外部写不快照（保持
   2.17 行为）；两者同时发生需要同一页上并发“外部写 + 未解码 store”，是
   罕见交叠，不影响单一路径的特征。
8. **不缺页的 uaccess 外部写**：如果叶子此前已被吸收的 store 改成 EL1 可写
   （AP[2]=0），随后一次纯 uaccess 写（例如缓冲 `read()` 直接 `copy_to_user`
   到注册页）不会触发缺页，因而不会被快照/合并；该次写回对读视图不可见。
   GUP 路径（O_DIRECT、`process_vm_writev`、`vmsplice` 写目的页）不看缺页，
   仍会快照。这一条只会让“写回不可见”，读视图仍是镜像，不会泄漏活页字节，
   因此不构成 CRC 完整性检测。

## 7. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_v217_device.py --serial $Serial --key $KpKey --repeats 16 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```
