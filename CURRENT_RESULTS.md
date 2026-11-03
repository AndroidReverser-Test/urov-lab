# 当前实现与验证结果

日期：2026-11-03，Asia/Shanghai。此文描述当前交付；2026-11-02 的历史记录保留在原文档中。

**结论：候选实现源码和二进制已交付；当前设备未启用活动覆盖，端到端可靠性验收未完成。**

## 1. 构建与主机检查

| 检查 | 实际结果 | 证明范围 |
|---|---|---|
| NDK 26.1 / Clang 17 严格构建 | 活动/预检 KPM、六个 Android 程序构建成功 | ELF/编译/链接，不是覆盖功能通过 |
| KP 核心交叉构建 | `kernel/kpimg` 与 `kpimg.elf` 链接成功 | 修改后的 KP 核心可构建，未部署 |
| 内置后端四个对象 | `urov`、`decode`、`emulate`、`core_selftest` 编译成功 | 真实匹配头文件/API 检查，保留 KCFI、SCS、general regs only |
| 集成锚点 | fault、MM、userfaultfd 的替换锚点匹配逐文件取得的 commit `66e758f7d0c0` 源码 | 不是完整 checkout 的全量编译/链接 |
| ASAN/UBSAN decoder | 211127 检查、50 向量、100000 随机 opcode 通过 | 独立汇编语料核对通过 |
| ASAN/UBSAN emulator | 288090 检查、4114 内置检查通过 | 144000 取值场景、100000 线程 pair 场景 |
| ASAN/UBSAN loader | 49 检查通过 | 包含真实 loader 源码及可控的并发 barrier |

最终输出见 [results/2026-11-03-host.txt](results/2026-11-03-host.txt)。loader 测试直接包含真实 `kernel/patch/module/module.c`，替代分配、文件与锁等主机环境接口，检查 retained、init 回滚、ctl/unload 竞争、同名加载、legacy RCU 上下文及错误文件长度关闭。

内置后端编译输入使用 `build/urov-native-final-argv.json` 和 `build/urov-device.config`。其源码/头文件副本由精确 commit 的文件和归档组成；generated headers 来自配置重建。集成脚本锚点验证时因副本无 Git 元数据，临时替代了 revision 查询结果；**这不构成真实 Git checkout、完整 Kbuild、最终内核链接或启动证明。**

KP 链接仍有现有 RWX segment 提示及一个无关的 unused-variable 警告。TSAN 两次尝试均因 `unexpected memory mapping` 无法启动，不计为通过。尚未运行内核 sanitizer 或 lockdep。

## 2. 最终二进制真机基线

原始记录：[results/2026-11-03-device.json](results/2026-11-03-device.json)。脚本上传四个最终产物并逐个核对 SHA256。设备 Pixel 6 / oriole，KP `0xc00`，内核：

```text
6.1.134-android14-11-g66e758f7d0c0-ab13748739
```

| 本轮用例 | 结果 |
|---|---|
| shell memfd libc/scalar copy | PASS |
| root memfd libc copy，未预触页 | FAIL，`first_diff=16` |
| root memfd 预触页 copy / scalar copy | PASS |
| shell SIMD 八个组合 | PASS |
| root SIMD anonymous / 已预触页 memfd | PASS |
| root SIMD 未预触页 memfd，跨页和不跨页 | FAIL，两个用例；`memory_diff=0 registers_diff=0` |
| root `urov_lab_test --text-only` | PASS，读取自身 ELF 字节，封存原页执行返回 42；`overlay=NOT_ENABLED` |

SIMD 探针的 diff 表示首个不同字节的位置，64 表示全部 64 字节一致，0 表示从首字节已不同。它同时检查故障返回后寄存器写回的保存缓冲与目标内存，观察到基线损坏；根因尚未定位，不能直接归责某个 KP/内核函数。

本轮测试脚本退出码 `3`：

```text
outcome=BLOCKED_BASELINE overlay_test=NOT_RUN
```

前后模块列表均为 `[]`，boot_id 均为：

```text
62c2bf2e-135c-40d0-8435-d98445e10042
```

早前记录属于另一个 boot_id，不能合并声称全过程处于同一次启动。本轮没有重启、刷写、升级 KP 或加载活动覆盖模块。

## 3. 先前已测、此次未重复的项目

- 软件核心 Android 测试及 8 核 41600 次原生指令差分曾通过；见 [IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md)。它们没有安装真实读取覆盖。
- 旧 KP 的 exit 返回 EBUSY 后仍删除模块已经实测。当前源码修复仅通过主机真实 loader 测试，还未在新启动环境真机验收。
- 此前活动 KPM 加载返回 `module_load=-2 overlay_test=NOT_RUN requires=KP_lifecycle_v2_and_native_UROV`、退出 2。该旧 KP 缺少强导入的新符号；本轮因基线失败没有再次尝试。

## 4. 尚未执行

完整内核构建/链接及启动、新 KP 的真机生命周期测试、S3–S7 活动覆盖、MM 生命周期并发与失败注入、长时稳定性和性能测试。当前限制及构建说明见 [DELIVERY.md](DELIVERY.md)。用户选择先交付代码与当前结果，本轮停止在此边界。
