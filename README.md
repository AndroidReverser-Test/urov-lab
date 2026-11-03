# UROV-LAB

Android ARM64 自有测试进程的代码页读取覆盖实验。目标语义：**普通整数 load 读取覆盖值，CPU 取指仍执行原始代码。**

2026-11-03 状态：已提供内核常驻后端候选源码、KP loader v2 改动、管理 KPM 和自验证二进制。KPM/测试程序及 KP 核心构建通过；常驻后端完成四个对象的头文件/API 编译检查。**当前设备没有启用活动覆盖，尚未完成完整内核链接、启动和端到端验收，不能视为已验证稳定的通用内存修改模块。**

## 当前交付

| 文件 | 用途 |
|---|---|
| [DELIVERY.md](DELIVERY.md) | 当前架构、构建、操作协议、适用范围和限制 |
| [CURRENT_RESULTS.md](CURRENT_RESULTS.md) | 本轮实际验证、失败基线、未执行项目 |
| [native/urov.c](native/urov.c) | 随匹配内核内置的异常与映射后端 |
| [urov_kpm.c](urov_kpm.c)、[urov_abi.h](urov_abi.h) | 薄 KPM、固定 128 字节管理协议 |
| [tests/urov_lab_test.c](tests/urov_lab_test.c) | 读取自身 ELF 字节，在封存测试页上检查普通读取与原始执行 |
| [tools/device_test.py](tools/device_test.py) | 上传并校验散列，检查基线；通过后才允许请求活动测试 |
| [tools/prepare_native.py](tools/prepare_native.py) | 针对内核 commit 前缀 `66e758f7d0c0` 的源码集成脚本 |
| [tools/test_host.sh](tools/test_host.sh) | 解码、模拟及真实 loader 源码的 ASAN/UBSAN 测试 |
| [build.ps1](build.ps1) | 构建管理 KPM、预检 KPM、六个 Android 二进制 |
| [results/2026-11-03-device.json](results/2026-11-03-device.json) | 本轮可复核的真机记录，不包含管理凭据 |

KP 核心修改位于父仓库的 `kernel/patch/module/module.c`、`kernel/patch/include/module.h`、`kernel/include/kpmodule.h`、`kernel/patch/common/supercall.c`、`kernel/patch/common/urov_bridge.c` 和 `kernel/linux/include/linux/rcupdate.h`。单独复制此目录的 `.kpm` 无法为旧 KP/内核增加后端。

## 构建与基线复核

在 KernelPatch 根目录运行：

```powershell
./kpms/urov-lab/build.ps1 -Ndk D:\androidSDK\ndk\26.1.10909125
wsl -d Ubuntu-24.04 bash kpms/urov-lab/tools/test_host.sh
python kpms/urov-lab/tools/device_test.py --serial 25091FDF60063J
```

设备脚本交互读取凭据，或从 `--key-fd FD` 读取；不把凭据写入源码或报告。现有 kpatch CLI 会在设备进程参数中短暂接收凭据。默认只跑基线；退出 `3 / BLOCKED_BASELINE` 表示平台基线未通过，覆盖测试未执行。

产物位于 `out/`：`urov-lab.kpm`、`urov_lab_test`、`urov_copy_probe`、`urov_vector_fault_probe` 等。最终二进制可运行 `urov_lab_test --text-only`；此模式明确输出 `overlay=NOT_ENABLED`。

交付包：`out/urov-lab-delivery-20261103.zip`，包含源码、KP 核心补丁、八个产物与本轮报告；内部 `SHA256SUMS` 可校验内容。该包不是启动镜像。

## 当前结果

- root 自身代码读取、封存页原始执行返回 42：通过。
- shell 复制和 SIMD 基线：通过。
- root 首次触页 memfd libc 复制失败，SIMD 探针有两个失败用例；根因尚未定位。
- 当前 KP `0xc00` 缺少新导出；此前活动 KPM 加载被拒绝。本轮基线脚本没有尝试加载。
- 本轮前后模块列表均为空，boot_id 相同；用户选择先交付代码，本轮未准备启动镜像。

当前受限于单 session、调用者自身 mm、一页 4 KiB sealed memfd RX、一个 8 字节覆盖区间和白名单 GPR load。没有通用 SIMD、acquire/exclusive、跨页读取或任意进程/ELF VMA 支持。

## 历史材料

[DESIGN.md](DESIGN.md)、[BACKEND_CONTRACT.md](BACKEND_CONTRACT.md)、[IMPLEMENTATION_RESULTS.md](IMPLEMENTATION_RESULTS.md) 和 [TEST_PLAN.md](TEST_PLAN.md) 保留 2026-11-02 的设计与测试证据；其中“后端尚未实现”描述的是当时状态。请以本页和当前交付/结果文档判断实现进度。
