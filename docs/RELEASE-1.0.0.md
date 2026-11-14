# UROV-Z 1.0.0 发布与实现分析

日期：2026-11-11（Asia/Shanghai）。本次交付将 `codex/urov-z` 的实现、已有工作树修复及独立用户态 API 提交为新的 `main`。模块版本为 `1.0.0`，协议为 ABI v1；旧 UROV-Y 实现仍可从 `dev` / `3679b4f` 查看。

## 实现结论

这是受控 Android ARM64 RX 文件代码页的读取覆盖实验框架。它保留执行代码，通过 PAGE_AP 权限异常为受支持的数据读取提供另一份影像。`all-callers` 表示不要求配置读取指令 PC 或调用者白名单，实际覆盖范围仍受地址空间、目标页、指令解码器及已安装 hook 限制。

| 层次 | 主要实现 | 行为 |
|---|---|---|
| 模块入口 | `module/urov_z.c` | 加载、全局 status、自检结果和卸载入口 |
| 控制协议 | `api/include/urov/abi.h`、`auth.h`；`backend.c` 的 `uz_prctl_before` / `dispatch` | 184 字节请求、派生 prctl option、SipHash MAC；QUERY、REGISTER、SET、STATUS、DEACTIVATE、SET_PAGE |
| 注册与页表 | `do_register`、`ap_arm_pages`、`page_update_bits_locked` | 验证 RX 文件 VMA，复制 native snapshot 与替代影像，清除 leaf PTE 的 PTE_USER/AP[1] 并刷新 TLB |
| 普通数据读取 | `uz_abort_before`、`uz_emulate_load`；`decode.c`、`emulate.c` | 检查 EL0 data permission fault、FAR 和 mm，解码访存，从影像读取并提交 GPR/FPSIMD、writeback 和 PC；目标页内的读取指令从原始快照解码 |
| 内核辅助读取 | `uz_kread_after`、`uz_vm_readv_before/after`、`uz_pin_after`、`uz_gup_after` | proc mem 的已授权结果缓冲区覆盖；readv 的 pin 页替换；vmsplice 的普通 GUP 页替换。各路径保留 Linux 原权限检查和引用类型 |
| 更新与生命周期 | `page_swap_image`、`readers.h`、mapping gates、`uz_copy_mm_after`、`release_session` | spare 影像发布、两组 epoch 读者计数、fork 快照、映射后 rearm；注销恢复 AP、等待读者并释放存储 |
| 内核适配 | `compat.h`、`btf.h`、`resolve_symbols` | 根据真实 BTF 校验布局、函数签名和 FOLL 常量；外置 BTF 必须匹配内核 Build ID |
| 用户态与测试 | `api/`、`app/` | NDK C/C++ 接口和普通 untrusted_app 回归；测试代码位于可控的文件 `.text` fixture |

会话全局最多一个，控制权绑定 owner mm。多页输入按地址排序并保留原描述符序号；SET_PAGE 使用原序号和 expected_generation。每页主池保留七页存储，默认 8 MiB 主池预算在 4 KB 设备允许最多 292 个目标页；fork 及指令扫描池另有预算。

已有工作树修复涵盖 BTF 验证的内部 GUP 入口、fast-GUP 的 32 位有符号返回值、影像页分配失败处理、单字节 mprotect、非驻留页 refault 后 armed 发布、冲突 FOLL 定义拒绝及测试报告防陈旧处理。本次从该源码重新构建并验证，未对核心算法作额外变更。

## 当前设备发布验证

设备为 Pixel 6 / oriole，Android 16 / API 36，Linux `6.1.134-android14-11-g66e758f7d0c0-ab13748739`，AArch64 / 4096 字节页，KernelPatch `c00`。测试 App UID 10286，SELinux 域为 `u:r:untrusted_app:s0:c30,c257,c512,c768`。root 仅用于模块管理和内核日志采集。

| 检查 | 结果 |
|---|---|
| KPM 构建 | NDK 26.1.10909125，严格警告作为错误，AArch64 ELF REL |
| APK 构建 | SDK Build Tools 36.0.0 / android-36，NDK，Java；APK 签名验证通过 |
| 用户态 API 构建 | 静态库、动态库和查询示例编译通过；示例在已加载模块时查询成功 |
| 加载前 / 卸载后 App 基线 | 各 5/5，原代码执行和原始数据读取正常 |
| live BTF | App 73/73；核心自检 4152；caps=0xfc3f |
| detached BTF | 使用当前设备提取的 BTF 与 notes 打包，App 73/73；核心自检 4152；caps=0xfc3f |
| 全局最终状态 | 两轮均 inactive、pages=0、armed=0、degraded=0；最终卸载，KPM list 为空 |
| 设备与日志 | 前后 boot ID 相同；所采集测试窗口的 703 行 dmesg 中未匹配 WARN/WARNING、Oops、panic、BUG、Call trace 或 kernel fault 标记 |
| 兼容性检查器 | 合成 ABI、FOLL、错误包和页表几何通过；真实 5.15/6.1 与已保存 GKI 6.12/6.18/6.18 16 KB BTF 检查通过 |

| 并发更新轮次 | 成功 SET_PAGE | direct 读取 | readv 读取 | 合计 | 撕裂/失败样本 |
|---|---:|---:|---:|---:|---:|
| live BTF | 48 | 417,633 | 415,556 | 833,189 | 0 |
| detached BTF | 48 | 431,990 | 431,862 | 863,852 | 0 |

73 项包含 native 执行、页内与独立读取者、多页与跨页、标量/pair/FPSIMD/LD2/LD4、libc/CRC、proc mem/readv/vmsplice、失败 GUP/readv、generation 冲突、并发 SET、mprotect/refault、fork 快照隔离、存活子阻止注销、API 错误约定和 inline 请求。caps 中 STEP 可用不代表本次覆盖了所有 native single-step/replay 路径。

本地原始证据位于忽略目录 `out/release-urov-z-1.0.0/`：`app-live.txt`、`app-detached.txt`、`baseline-before.txt`、`baseline-after.txt`、`status-live.txt`、`status-detached.txt`、`compat-*.txt`、`dmesg-test-window.log` 与 `build-*.log`。Release 另附不含密钥的 `validation.txt`。此前小米 13 / 5.15 的独立运行记录与修复证据保留在 [AUDIT.md](AUDIT.md)。6.12/6.18/16 KB 仍只有结构验证。

## 发布文件

从当前源码重新编译，Release tag 为 `v1.0.0`：

| 文件 | 字节数 | SHA-256 |
|---|---:|---|
| `urov-z.kpm` | 233760 | `5a35a8b74f49b55d1e6168c087aee173dd6a519d1557f2ea4c4a62c5f53ae9b7` |
| `urov-z-test.apk` | 29146 | `39edd5a0301529bc0ec019778a95ceb921f1d687e164bc8f942081c8d9061ddd` |

下载入口：[UROV-Z 1.0.0 Release](https://github.com/AndroidReverser-Test/urov-lab/releases/tag/v1.0.0)。附带 `SHA256SUMS` 与 `validation.txt`。APK 是本地 debug 测试签名，签名私钥、模块密钥、设备 superkey、设备专用 BTF 不发布。加载与测试命令见 [README.md](../README.md)。

## 尚存限制

这次通过只证明上述受控测试场景。代码审查仍确认以下问题，未随发布修复：

1. `page_update_bits_locked` 没有普遍获取 Linux 原生 split PTE lock；CAS、mmap 锁和 RCU 不能单独证明与 reclaim、迁移及页表回收并发安全。
2. `uz_mremap_update` / `uz_page_sort` 原地更新直接读者引用的描述符，epoch 目前只保证存储寿命；复杂映射修改应先静止相关读者。
3. 子快照仍依赖父描述符的部分 armed/want/gone 状态，父映射变化后的任意子进程行为未获保证。
4. 写入、LL/SC、原子和 native replay 的并发语义不完整；临时恢复 AP 期间可能暴露原值，有限重试的影像读取也不构成通用内存模型。
5. 旧 KernelPatch loader 的卸载上下文和 exit 错误处理不能由模块元数据升级。必须由 owner 成功 DEACTIVATE、确认全局 inactive/pages=0/armed=0，再卸载。

完整机制、ABI 和边界见 [DESIGN.md](DESIGN.md)，逐项审查依据见 [AUDIT.md](AUDIT.md)。
