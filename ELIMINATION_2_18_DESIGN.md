# UROV-Y 2.18.0 读回源页替换与外部写合并

本文记录 `urov-y` 2.18.0 针对双 iovec 写回和外部写导致页退役的变更。
普通 App 当前可复现的读值分歧与独占探针见
[§7 普通 App 无密钥检测与防护](#7-普通-app-无密钥检测与防护)。
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

2.18.0 针对 H1 和 H2 修改读写路径。H3–H7 的处置见 §3.3。

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
- **H7 独占丢失**。2.18 保留相邻或 `NOP`、`BTI` 间隔的 LL/SC 桥接。
  夹具在读取与 `STXR` 之间插入寄存器 `ADD`，使 `STXR` 原生执行，
  并按 §7 的配对判定观察目标读关联的独占丢失。该信号识别读陷阱，
  等值覆盖也可命中。耗时只用于记录开销。

## 4. 不引入新特征的论证

| 潜在新特征 | 为什么不出现 |
| --- | --- |
| 新的 VMA/`smaps` 差异 | 不新增/移动 VMA；替换页与 `ext_pre`/`ext_buf` 都是插件私有内核页 |
| 新的代码字/页表权限 | 仍只改叶 PTE 的 AP[1]；外部写后重装的仍是同一个 AP[1]=0 陷阱，AP[2] 保持 COW 结果 |
| 新的崩溃 | 外部写仍由内核完成；drain 用 `access_remote_vm`，失败只保留 `ext` 稍后重试；未改变 SIGSEGV 路径 |
| 新的返回码/ABI | `process_vm_readv` 的返回值仍来自 Linux（源页替换不改变长度/错误）；ABI v8、请求布局、`ctl0` 文本、计数器、`hooks=0xff` 不变 |
| 新的线程/定时器/文件 | 没有；新增的 `pin_user_pages_remote`、`__get_user_pages` 都是函数钩子，不新增 syscall 入口 |
| 新的写语义 | 写者仍写活页（O_DIRECT/`read()`/`process_vm_writev` 的字节真的到达映射）；镜像只多一次“把已发生的写合并进来” |
| 新的读视图 | 被拦截的 EL0 读和 `process_vm_readv` 均按各自入口的调用窗口选择 image 或 snapshot。BRK 和 UXN 下，未受陷阱影响的 EL0 读仍可见活页 |
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
| 普通 App 三路读与独占探针，六种配置各 32×3 | PASS，576/576 个活动覆盖样本均被拒绝采信 | [read-defense-v218-20261108-182541](results/read-defense-v218-20261108-182541/summary.json) |

详细数字见 [APP_READ_INTEGRITY_RESULTS.md](APP_READ_INTEGRITY_RESULTS.md) 的
2.18.0 节。

## 6. 残余（2.18.0）

1. **计时**：已装陷阱的 PAGE_AP 页每次 EL0 数据读仍有一次同步异常；未解码 store 多一次 Software Step
   与整页 diff。按题目允许保留。
2. **重放窗口**：未解码 store 重试期间本 CPU 可读、其他 CPU 只在本地失效后仍
   保留陷阱项；跨 CPU TLB miss 的亚指令级竞态。见 §3.3 H3。
3. **pkey/POE**：本机无 POE，只验证拒绝/透传。
4. **root 可见性**：`kpm list`/`ctl0 status` 仍可见，需要改核心。
5. **独占丢失（H7）**：PAGE_AP 下读异常仍会清本地独占监视器；只对相邻/
   `NOP`、`BTI` 间隔的可证明 LL/SC 形状补完。普通 App 的实测判定见 §7。
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

## 7. 普通 App 无密钥检测与防护

### 7.1 采样与判定

`--read-defense-v218` 在工作线程上复核 App 自有的稳定文件 RX 页。夹具每次
比较页内 32 字节，以文件描述符、设备号、inode 和文件偏移验证映射身份，并保留
同文件同偏移的非执行 `PROT_READ` 别名。检测输入仅包含地址、读取函数、参考
文件和偏移。主机负责模块装卸与内核日志，测试夹具使用独立的模块密钥建立覆盖真值。
[App 实现](apps/urov-detect/read_defense_fixture.inc#L225)

1. **三路字节对照**。分别用业务读取 `crc_copy_window` 和不同指令地址的
   `copy_scalar` 调用 `ud_observe_live()`，各自与同进程 `process_vm_readv`
   的结果逐字节比较。每次调用检查映射前后身份与重复读取的稳定性。两次调用的
   内核读结果也必须一致，任意两路稳定分歧记为 `split`。在全调用者 SITE_BRK
   和 PAGE_UXN 下，业务读与内核读均可返回原文件字节，独立 `LDRB` 仍可看到
   活页补丁。调用 `process_vm_readv` 适用于已验证允许该系统调用的部署配置。
   [字节观测实现](native/urov_observe.c#L80)
2. **PAGE_AP 独占探针**。`ud_observe_ap_alu()` 执行
   `LDXR → LDRB → ADD → STXR`。独占操作只访问线程私有栈字，成功时原样写回。
   `LDRB` 是对被测页的唯一访问。每个有效三元组由只读别名上的两次成功夹住
   一次目标读取。三组各 32 个有效三元组中，目标全部失败记为 `trap`，全部成功
   记为阴性。混合结果、对照不稳或映射失配记为 `unknown`，夹具对探针的
   `EAGAIN` 重试一次。PAGE_AP 全调用者配置能使三路字节一致，因此仍需独占探针。
   等值 PAGE_AP 也可触发该信号，执行与读取的差异由测试专用 Dobby 载荷取证。
   [独占序列](native/urov_observe.c#L248) · [配对实现](native/urov_observe.c#L489)
3. **完整性结果**。三路稳定一致、匹配可信文件参考且独占探针阴性时计为
   `accept`。三路一致但偏离参考时计为 `changed`。读失败、短读或视图不稳时
   保留未知结论。校验结果只作用于被测范围的完整性决策，普通业务继续执行。

H1 的双 iovec 在本机复跑时 `post` 始终保留填充值。带目的地址回写的兼容路径
见 §3.1。proc mem、ptrace 与 fast GUP 路径均有覆盖钩子，因此单个内核读的
结果只代表该读路径的视图。
[双 iovec 复跑](results/read-defense-v216-20261108-182627/summary.json) ·
[内核读钩子](urov_y_backend.c#L4729) · [fast GUP 钩子](urov_y_backend.c#L4791)

### 7.2 注册防护

可单独装载的可信 PIC 代码可放在新建的文件 `PROT_EXEC` 映射中，另用
`PROT_READ` 别名校验文件。部署允许匿名执行映射时，也可由可信字节建立私有
匿名 RX 页。两类 VMA 分别缺少 `VM_READ` 和 `vm_file`，因此
`validate_target_vma()` 拒绝将它们注册为读取目标。该限制作用于新建的目标
映射，BRK 和 UXN 的读取点按各自的站点规则校验。已有普通 `.text` 上的活动
PAGE_AP 会话应在完整性决策处处理，无损撤销需要模块控制权限或 root。
[目标页校验](urov_y_backend.c#L1243) · [匿名 RX 夹具](apps/urov-detect/read_defense_fixture.inc#L328) ·
[文件执行映射夹具](apps/urov-detect/read_defense_fixture.inc#L358)

### 7.3 真机结果

设备与权限同 §5。六种配置分别启动三次，每次每阶段采样 32 次。活动覆盖时，
业务读返回原文件字节，Dobby 载荷实际执行返回 `0x1235`，原文件对应 `0x1234`。
[正式矩阵](results/read-defense-v218-20261108-182541/summary.json)

| 活动覆盖配置 | 字节分歧 | 独占陷阱 | 采信结果 |
| --- | ---: | ---: | ---: |
| SITE_BRK 调用窗口 | 96/96 | 0/96 | 0/96 |
| SITE_BRK 全调用者 | 96/96 | 0/96 | 0/96 |
| PAGE_UXN 调用窗口 | 96/96 | 0/96 | 0/96 |
| PAGE_UXN 全调用者 | 96/96 | 0/96 | 0/96 |
| PAGE_AP 调用窗口 | 96/96 | 96/96 | 0/96 |
| PAGE_AP 全调用者 | 0/96 | 96/96 | 0/96 |

1,920 个阴性对照均未误报读值分歧或陷阱。其中 672 个干净样本全部通过，
1,248 个仅改码或已撤销覆盖的样本均归为内容变化。192 个等值 PAGE_AP 样本
均报陷阱。全部 3,072 个样本共重试 5 次，最终未知 0 次。

文件执行映射和匿名 RX 映射各 18/18 次注册尝试均返回 `EINVAL`，测试函数
执行结果均为 `0x1234`。并行业务夹具完成 2,812,672 次迭代，错误为 0。
UI 心跳最大间隔 22 ms，单次工作线程复核最大耗时 53.18 ms。测试结束后 KPM
列表为空，设备 boot ID 一致。结果适用于本机、测试二进制与采样页。

## 8. 复跑

```powershell
./kpms/urov-lab/build.ps1
./kpms/urov-lab/apps/urov-detect/build.ps1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v218 --repeats 32 --cycles 3
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense-v216 --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --read-defense --repeats 8 --cycles 1
python ./kpms/urov-lab/tools/run_v217_device.py --serial $Serial --key $KpKey --repeats 16 --cycles 1
python ./kpms/urov-lab/tools/run_elimination_device.py --serial $Serial --key $KpKey --skip-x-control --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_multipage_device.py --serial $Serial --key $KpKey --repeats 3 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --repeats 5 --cycles 1
python ./kpms/urov-lab/tools/run_crc_device.py --serial $Serial --key $KpKey --dobby-detection --repeats 24 --cycles 1
```
