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
adb shell taskset 40 /data/local/tmp/urov-perf-device
```

`insn-scan-test` 不需要模块：运行 4152 项核心自检和块扫描的 4K/16K 边界、回退、重置测试。

`window-hint-test` 不需要模块：验证 128 个 HINT 编码与 64 个屏障选项不会错误接受 PAC/AUT、等待或有序操作，并检查 FMOV S/H 的高位清零。`kclf-profile-test` 运行 46 项布局/task_work ABI 正反例；不依赖 live BTF 或 root。三个纯测试也可在主机 C 编译器下运行，建议对模型测试开启 undefined-behavior sanitizer。

`perf-device` 需要已经加载使用固定项目测试密钥的 urov-z，且没有其他活动会话。LSE 子用例通过 `HWCAP_ATOMICS` 检测，不支持的 CPU 会明确输出 `SKIP LSE`，其余用例继续执行；`taskset 40` 表示 CPU 6，应按设备实际 CPU 配置调整。覆盖页数、长 LL/SC、CLREX、间接分支、代码写入、子快照和 LSE。对首次执行可能发生的缺页先预热；影像使用无标签 mmap 地址。两种测试可执行文件均使用 16 KiB ELF segment alignment。

页数计时不含 CRC，固定只读一页与读取全部页分别测量。这里只验证读路径，不是任意应用兼容性测试。子快照用例依赖模块 store 模拟器已有的 I-cache flush，未验证关闭 native step 时对受管页执行 EL0 缓存维护指令。更多证据和限制见 [优化记录](../docs/performance-optimization-1.2.1.zh-CN.md)。

`app/` 的原有 73 项回归和 `integration/` 的 manual/linker 各三轮应另外执行，见 [集成说明](../INTEGRATION.md)。
