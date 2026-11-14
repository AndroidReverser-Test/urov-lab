# 读取路径优化回归

在 urov-lab 根目录运行：

```powershell
.\tests\build.ps1 -Ndk D:\androidSDK\ndk\26.1.10909125
adb push out/tests/insn-scan-test /data/local/tmp/urov-insn-scan-test
adb push out/tests/perf-device /data/local/tmp/urov-perf-device
adb shell chmod 755 /data/local/tmp/urov-insn-scan-test /data/local/tmp/urov-perf-device
adb shell /data/local/tmp/urov-insn-scan-test
adb shell taskset 40 /data/local/tmp/urov-perf-device
```

`insn-scan-test` 不需要模块：运行 4152 项核心自检和块扫描的 4K/16K 边界、回退、重置测试。

`perf-device` 需要已经加载使用固定项目测试密钥的 urov-z，且没有其他活动会话。用例要求 AArch64 LSE（本次设备 Pixel 6 支持）；`taskset 40` 表示 CPU 6，应按设备实际 CPU 配置调整。覆盖页数、长 LL/SC、CLREX、间接分支、代码写入、子快照和 LSE。对首次执行可能发生的缺页先预热；影像使用无标签 mmap 地址。

页数计时不含 CRC，固定只读一页与读取全部页分别测量。这里只验证读路径，不是任意应用兼容性测试。子快照用例依赖模块 store 模拟器已有的 I-cache flush，未验证关闭 native step 时对受管页执行 EL0 缓存维护指令。更多证据和限制见 [优化记录](../docs/performance-optimization-1.2.1.zh-CN.md)。

`app/` 的原有 73 项回归和 `integration/` 的 manual/linker 各三轮应另外执行，见 [集成说明](../INTEGRATION.md)。
