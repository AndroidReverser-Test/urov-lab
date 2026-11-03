# 普通 app / 非 root 进程可用性实测（2026-11-03）

> **2026-11-04 更新**：本文第 1–4 项限制已有实现与真机验收：
> `__NR_prctl` 控制通道替代 `kcmp`；注册对象改为 app 自己的一页只读可执行
> `MAP_SHARED` 文件映射（推荐自身 native library 的别名），不再需要 sealed
> memfd 或 `/proc/self/fd`；会话按 mm 归属并提供死 owner 惰性回收。第 5 项
> （模块装卸需要 root）保持不变。详见 [APP_OVERLAY.md](APP_OVERLAY.md)。
> 下文 2026-11-03 的实测记录保留作为问题背景。

设备：Pixel 6 / Android 16（`BP31.250610.009`），模块 `urov-lab.kpm` 已由 root 加载。

## 1. 普通 app（untrusted_app，uid 10284）

临时最小 NativeActivity APK（无 Java 代码，native onCreate 直接运行探针）安装在设备上，
SELinux 域和 seccomp 状态如下：

```text
I urovapp : onCreate
I urovapp : uid=10284 pid=11324
I urovapp : context=u:r:untrusted_app:s0:c28,c257,c512,c768
I urovapp : open /proc/self/fd failed errno=13
I urovapp : PAGE FAIL
I urovapp : RESULT FAIL
```

`errno=13` 为 `EACCES`：`untrusted_app` 域不允许对 sealed memfd 执行
`open("/proc/self/fd/N", O_RDONLY)`，因此无法建立测试要求的只读 RX 映射。

把控制 syscall 放到映射之前再做一次，进程在第一次 `kcmp` 调用时被 seccomp 杀死：

```text
I urovapp : onCreate
I urovapp : uid=10284 pid=11157
F libc    : Fatal signal 31 (SIGSYS), code 1 (SYS_SECCOMP), syscall 272 in tid 11157 (example.urovapp)
F DEBUG   : Cause: seccomp prevented call to disallowed arm64 system call 272
```

即普通 app 的 seccomp 策略直接拒绝 `__NR_kcmp`（272），用户态根本发不出 QUERY/REGISTER。

## 2. 非 root shell（uid 2000，无 seccomp）

```text
uid=2000(shell) ... context=u:r:shell:s0
backend_caps=0x6b7 state=0
open /proc/self/fd: Permission denied
```

shell 没有 seccomp，控制通道可以到达模块（成功拿到 caps），但同样被 SELinux 拒绝
`/proc/self/fd` 的只读重开，注册仍无法进行。

## 3. root（kpatch su）基线

现有验收程序在 root 下通过：

```text
PASS scope=standalone_active_overlay widths=8,16,24,32 ... concurrency=verified restore=verified
```

## 结论

**当前版本不能直接用于普通 app 进程。** 故障处理后端本身没有 uid 限制，只认
`current->mm`；问题出在控制通道和页准备方式：

1. **seccomp 拒绝控制 syscall。** 控制通道使用 `__NR_kcmp`（272，
   [urov_abi.h](urov_abi.h:38)）。普通 app 的 seccomp 策略把它列为 disallowed，
   第一次 QUERY 就会收到 `SIGSYS`，连注册请求都发不出去。
2. **SELinux 拒绝 sealed memfd 的只读重开。** 验收程序需要
   `open("/proc/self/fd/N", O_RDONLY)`（[urov_overlay_test.c](tests/urov_overlay_test.c:352)）
   才能得到只读 fd 并建立 `MAP_SHARED|PROT_READ|PROT_EXEC` 映射；
   `untrusted_app` 域实测返回 `EACCES`。
3. **`validate_vma()` 只接受专用页形状。** 它要求恰好一页、`MAP_SHARED`、文件映射、
   `pgoff=0`、无 `VM_WRITE|VM_MAYWRITE`（[urov_backend.c](urov_backend.c:253)）。
   普通 app 的 `.text` 是 `MAP_PRIVATE`、通常多页，不能直接注册；当前只支持测试程序
   自己构造的单页 sealed memfd。
4. **单会话、单 mm。** 模块只有一个全局 `g_sess`（[urov_backend.c](urov_backend.c:109)），
   且 `do_register()` 只注册调用者自己的 mm（[urov_backend.c](urov_backend.c:453)）。
   一个 app 不能替另一个 app 注册，多个 app 也不能并发使用。
5. **模块装卸需要 root。** 普通 app 只能作为使用方，无法自行加载/卸载 KPM。

## 要支持普通 app，需要改什么

1. **换控制通道**：使用 app seccomp 允许、且 SELinux 可授权的入口，例如
   `ioctl` 专用字符设备 `/dev/urov`、binder 服务或 `syscall(__NR_...)` 白名单内的
   稳定 syscall；不能依赖 `kcmp`。
2. **换页来源/放宽 VMA 条件**：让 app 使用一个 SELinux 允许的只读 RX 文件页，
   例如单独打包的一页 native library；或把 `validate_vma()` 扩展到
   `MAP_PRIVATE` 只读文件映射和多页范围，并为每页建立快照/生命周期状态。
   同时必须继续拒绝可写映射、COW 和远程写，避免 pin 住的原始页失效。
3. **多会话与所有权**：把单全局会话改为每 `mm`/每区间状态，定义配额和句柄；
   若要由管理 app 控制目标 app，需要 pidfd + `ptrace_may_access` + SELinux 检查，
   当前没有实现。
4. **SELinux/seccomp 策略**：为控制设备、memfd/exec 映射增加明确的 allow 规则；
   对第三方 app 来说，修改系统 seccomp 策略通常不现实，因此专用设备 + SELinux
   策略是更可行的方向。
5. **生命周期**：app 更新、fork/exec、JIT、`mprotect`/`munmap` 等仍需沿用现有的
   门控和恢复协议；跨进程场景还要额外处理目标进程退出和句柄失效。

在这些改动完成前，普通 app 只能依赖 root 测试进程（`kpatch su -c`）来使用当前模块。

## 2026-11-04 落地情况

- 控制通道：已改为 `__NR_prctl(option=0x55524f56, magic, cmd, req, size)`，
  `untrusted_app` Seccomp mode 2 实测可发；`__NR_kcmp` 仅保留给 root/旧程序。
- 页来源：已支持 app 自己的“恰好一页、只读、可执行、文件后备、无
  `VM_MAYWRITE`”的 `MAP_SHARED` 映射；推荐把自身已安装 native library 的一页
  以 `MAP_SHARED` RX 别名映射后注册。sealed memfd 与 `/proc/self/fd` 不再是
  必需。`MAP_PRIVATE` 因携带 `VM_MAYWRITE`（可被 mprotect/FOLL_FORCE COW）被
  明确拒绝。
- 所有权/生命周期：单会话仍为全局，但按 mm 归属；非 owner 不能 SET/
  DEACTIVATE；owner 进程死亡后由下一次控制请求按 `mm_users == 1` 惰性回收。
  跨 app 并发仍需后续多会话改造。
- fork：只对注册的一页别名设置 `VM_DONTCOPY`，app 正常 lib 映射不受影响。
- 模块装卸仍需 root。
- 真机验收、日志与复现命令见 [APP_OVERLAY.md](APP_OVERLAY.md)。

