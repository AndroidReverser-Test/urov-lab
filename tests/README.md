# 读取路径优化回归

在 urov-lab 根目录运行：

```powershell
.\tests\build.ps1 -Ndk D:\androidSDK\ndk\26.1.10909125
adb push out/tests/insn-scan-test /data/local/tmp/urov-insn-scan-test
adb push out/tests/perf-device /data/local/tmp/urov-perf-device
adb push out/tests/window-hint-test /data/local/tmp/urov-window-hint-test
adb push out/tests/kclf-profile-test /data/local/tmp/urov-kclf-profile-test
adb shell chmod 755 /data/local/tmp/urov-insn-scan-test /data/local/tmp/urov-perf-device
adb shell chmod 755 /data/local/tmp/urov-window-hint-test /data/local/tmp/urov-kclf-profile-test
adb shell /data/local/tmp/urov-insn-scan-test
adb shell /data/local/tmp/urov-window-hint-test
adb shell /data/local/tmp/urov-kclf-profile-test
# 先在 inactive 状态开启写入专项；KP_KEY 使用设备管理凭据
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z writes=experimental
adb shell taskset 40 /data/local/tmp/urov-perf-device
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z writes=rx
```

`insn-scan-test` 不需要模块：运行 4152 项核心自检和块扫描的 4K/16K 边界、回退、重置测试。

`window-hint-test` 不需要模块：验证 128 个 HINT 编码与 64 个屏障选项不会错误接受 PAC/AUT、等待或有序操作，并检查 FMOV S/H 的高位清零。`kclf-profile-test` 运行 46 项布局/task_work ABI 正反例；不依赖 live BTF 或 root。三个纯测试也可在主机 C 编译器下运行，建议对模型测试开启 undefined-behavior sanitizer。

`perf-device` 需要已加载固定项目测试密钥的 urov-z、无其他活动会话，并显式使用 `writes=experimental`。LSE 子用例通过 `HWCAP_ATOMICS` 检测，不支持的 CPU 输出 `SKIP LSE`；`taskset 40` 表示 CPU 6，应按设备调整。覆盖页数、长 LL/SC、CLREX、间接分支、代码写入、子快照、LSE 和 DC ZVA。后者按 DCZID_EL0 判断大小，验证块内非对齐地址及两侧不受影响的影像；禁用或超出测试支持的 8–64 字节范围会明确跳过。所有 Android 工具均使用 16 KiB ELF segment alignment。

页数计时不含 CRC，固定只读一页与读取全部页分别测量。这里只验证读路径，不是任意应用兼容性测试。子快照用例依赖模块 store 模拟器已有的 I-cache flush，未验证关闭 native step 时对受管页执行 EL0 缓存维护指令。更多证据和限制见 [优化记录](../docs/performance-optimization-1.2.1.zh-CN.md)。

`app/` 的原有 73 项回归和 `integration/` 的 manual/linker 各三轮应另外执行，见 [集成说明](../docs/INTEGRATION.md)。

## 1.2.3 兼容性与生命周期

```powershell
adb push out/tests/runtime-compat-test /data/local/tmp/urov-runtime-compat-test
adb push out/tests/page-index-test /data/local/tmp/urov-page-index-test
adb push out/tests/lifecycle-device /data/local/tmp/urov-lifecycle-device
adb shell chmod 755 /data/local/tmp/urov-runtime-compat-test /data/local/tmp/urov-page-index-test /data/local/tmp/urov-lifecycle-device
adb shell /data/local/tmp/urov-runtime-compat-test
adb shell /data/local/tmp/urov-page-index-test
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z writes=rx
adb shell /data/local/tmp/urov-lifecycle-device
```

- `runtime-compat-test`：在线 NUMA node、policy allocator 优先、失败返回、W0 负返回值和边界、4096 组 DC ZVA 几何/权限组合。无需模块。
- `page-index-test`：四个 pthread reader 与 10000 次双缓冲索引发布，持有旧索引跨调度后再核对 generation/slot，验证 epoch 回收。无需模块。
- `lifecycle-device`：606 项父进程断言，子进程另有保护/重缺页/迁移/替换断言。使用 memfd 文件 RX 映射，检查父 PROT_NONE/SET/unmap 后子三通道值和执行独立；拒绝 DONTUNMAP；100 次部分 mremap + SET 配合四线程读取稳定页；100 次同页 SET 配合四线程三通道一致性读取；RX mprotect、COW 写入和 proc 写入退役，以及 ESTALE。要求默认 `writes=rx`，不应在其他活动会话中运行。仅重试保证未提交的 EBUSY。

主机 Linux/WSL 可使用同一实现运行 ASAN/UBSAN（从仓库根目录）：

```bash
bash tests/host_compat.sh
# 可选本机已保存的真实 BTF；二者必须分别对应下列平台
bash tests/host_compat.sh out/fuxi-5.15.74.btf out/audit-20261114/oriole.btf
out/compat-1.2.5/compat-check --gki out/gki-6.12-arm64.btf out/gki-6.18-arm64.btf out/gki-6.18-16k-arm64.btf
cc -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=thread -pthread tests/page_index_test.c -o out/compat-1.2.5/page-index-tsan
out/compat-1.2.5/page-index-tsan
```

BTF 文件不随源码分发。无文件时仍可运行合成 ABI、allocator、ZVA、index、指令与 RELRO 测试。当前证据与已知限制见 [1.2.5 审计](../docs/compatibility-audit-1.2.5.zh-CN.md)。测试失败并退出后可用 `urovz-query` 回收死亡会话；保持模块驻留，更新二进制采用受控重启。

## 1.2.4 页表与 ELF 兼容性

`pt-leaf-test` 直接编译生产 `pt_leaf.h`，用 native unfold/TLBI 替身验证 4K/16K 连续组的每个位置、相邻 PTE 不被单页权限修改、AF/dirty 合并后重新读取、缺少 helper/错误页形态拒绝以及 arm/disarm。共 17968 项检查；这是模型，不是连续 PTE 内核实机验证。`runtime-compat-test` 增加 18 组共享/公开 GUP 入口与 GET/PIN 选择正反例。`compat-check` 增加连续 PTE 值参数、fast-GUP page**、旧 compound grab 的 ABI 检查；三份新 GKI BTF 同时检查完整 apply callback 和 unfold helper。

```powershell
adb push out/tests/pt-leaf-test /data/local/tmp/pt-leaf-test
adb shell chmod 755 /data/local/tmp/pt-leaf-test
adb shell /data/local/tmp/pt-leaf-test
python tests/check_elf.py 'out/tests/*' 'out/integration/native/lib*.so' out/integration/native/relro-test out/app/lib/arm64-v8a/liburovz.so out/app/urovz-query out/app/compat-check 'out/api/*.so' out/api/urov-query
```

`check_elf.py` 只需 Python 标准库，检查 ELF64/AArch64、16K LOAD 对齐、4K 和 16K 下 RELRO 区域完整映射、与可变/可执行数据隔离。会拒绝旧 `common-page-size=16384` 在本仓库 NDK r26 产物中产生的 RELRO 尾部空洞；不能用单纯的 LOAD 对齐检查代替它。检查的是链接后的工具/SO，不接受 relocatable KPM 或静态库。

## 1.2.5 并发、预算与通用报告

`optimization-test` 直接编译生产的 `short_lock.h`、`buffer_budget.h`、`mapping_identity.h`。测试不同页锁独立推进、四线程 80000 次完整影像发布、八线程 80000 次额度 reservation，覆盖取整/溢出/失败释放/槽耗尽，以及 4K/16K split/move/replacement/边界/偏移溢出。主机脚本使用 ASAN/UBSAN，并运行 `inspect_cli_test.py` 检查输入错误与静态报告不会冒充运行通过。

```bash
bash tests/host_compat.sh
out/compat-1.2.5/compat-check --inspect kernel.btf --symbols symbols.txt --kernel 6.1.134
```

`--inspect` 使用 raw BTF（不是 uzbtf package）。可省略符号表或版本，相应证据输出 unknown/unavailable；原位置参数及 `--gki` 仍为有固定预期的 regression fixture。主机输出目录可用 `UROV_TEST_OUT` 覆盖。

`resource-device` 需要 KPM 和无活动会话，默认注册三个页并验证读取、执行、释放。以下负例修改全局 inactive 配置，测试结束须恢复默认；不要在其他应用的活动会话中运行：

```powershell
adb push out/tests/resource-device /data/local/tmp/urov-resource-device
adb shell chmod 755 /data/local/tmp/urov-resource-device
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z buffer_kb=64
adb shell /data/local/tmp/urov-resource-device --budget
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z memory
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z buffer_kb=65536
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z fork_copies=0
adb shell /data/local/tmp/urov-resource-device --nofork
adb shell /data/local/tmp/kpatch $KP_KEY kpm ctl0 urov-z fork_copies=4
```

`--budget` 期望 ENOMEM、inactive、原生值保持；管理员查询还应得到 used=0。`--nofork` 验证线程可读而独立 fork 被拒绝。`--hold` 保持三页会话五秒，供另一个 shell 读取 memory 并确认 active 配置修改失败。experimental 专项同时验证 3→7→3 缓冲布局切换。`memory.denied` 与 `health.retired_writes` 包含预期负例，不要求始终为零。

本轮 TSan 在 WSL 初始化时因 unexpected memory mapping 退出 66，未执行测试；不要把该结果写为 race detector 通过。默认/Diagnostics/OverlayOnly 的构建和具体实机覆盖范围见审计；仅诊断完整构建在本轮设备实际加载，模块保持驻留。
