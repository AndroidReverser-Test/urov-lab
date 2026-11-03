# UROV-LAB 普通 app 真机验收结果（2026-11-04）

设备：Pixel 6 / oriole，Android 16（SDK 36），内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`，4 KiB 基础页。
KPM 由 root 通过 `/data/local/tmp/kpatch <KEY> kpm load` 加载；测试 app 以
`untrusted_app`（uid 10286，Seccomp mode 2）运行。

## 产物

| 文件 | SHA-256 | 大小 |
|---|---|---|
| `out/urov-lab.kpm` | `16b86f80c8799c1d00aab650e553955fe8955459c6d6f6f23037c16005e1c1cf` | 38992 |
| `apps/urov-app/out/liburovapp.so` | `4128f9e8563c4243a186f02206458b7005d87ee9acde965db133ef5dffe94f65` | 23520 |
| `apps/urov-app/out/urovapp.apk` | `d512adab832ddd97461af0ee62fd6020eb9a919f8a5153178d36e627c6447c01` | 33187 |
| `out/urov_overlay_test` | `128a8bc7583ec24c4d75b9ef531df017cb8709cd1d129ae66d11b7c1bc2baa58` | 35232 |
| `out/urov_foreign_test` | `3a2feab61ff6a04c5018336fab6ad9eabbf49de60618c2487cc8b568bf831508` | 7816 |

APK 每次构建会因签名/zip 时间戳不同而散列变化；上面的散列是本次测试使用的
构建，`liburovapp.so` 的散列才是代码内容的稳定标识。

## 验收矩阵

| 项目 | 结果 | 证据 |
|---|---|---|
| app 内 QUERY（`__NR_prctl`） | PASS，`caps=0xeb7` | [app-final-acceptance.log](results/app-final-acceptance.log) |
| 自身 lib 一页 `MAP_SHARED` RX 别名注册 | PASS，`r-xs`、4096 字节 | 同上 |
| 1/2/4/8 字节 load、部分重叠、LDP | PASS | 同上 |
| 取指仍执行原字节 | PASS（`exec=0x1122334455667788`） | 同上 |
| SET / stale generation | PASS（`EAGAIN`） | 同上 |
| 4 读线程 + 128 次更新 | PASS，`errors=0`、`loops=11145` | 同上 |
| `mprotect` gate / 注销恢复 | PASS（活跃 `EBUSY`，注销后 0） | 同上 |
| SIMD `ldr q0` fail-closed | PASS（SIGSEGV，不返回原值） | 同上 |
| 私有 payload 页（`MAP_SHARED`） | PASS | 同上 |
| `MAP_PRIVATE` 负向 | PASS（`EINVAL`，`VM_MAYWRITE` 被拒绝） | 同上 |
| 普通 `prctl` 透传 | PASS（`PR_SET_NAME`/`PR_GET_NAME`） | 同上 |
| 非 owner SET/DEACTIVATE | PASS（`ENOENT`） | [app-final-foreign-reap.txt](results/app-final-foreign-reap.txt) |
| 非 owner QUERY 不暴露会话 | PASS（`state=0`、`last_error=-16`） | 同上 |
| owner 被 kill 后惰性回收 | PASS（模块 `inactive`，无需重载） | 同上 |
| 卸载时 app 会话活跃 | PASS（读从 fake 回到原值，执行不变） | [app-final-unload-active.txt](results/app-final-unload-active.txt) |
| root sealed-memfd 回归 | PASS（8/16/24/32、LDP、fork、fail-closed、并发） | [app-final-root-regression.txt](results/app-final-root-regression.txt) |
| 内核日志 | 无 BUG/WARNING/Oops/RCU stall | [app-final-dmesg.txt](results/app-final-dmesg.txt) |
| 多轮 app 自动化 | 3/3 PASS，结束后 `state=inactive hits=0 failures=0` | [app-device-20261104-003058.log](results/app-device-20261104-003058.log)、[002653](results/app-device-20261104-002653.log) |

## 关键日志摘录

### app 上下文与能力

```text
I urovapp : context=u:r:untrusted_app:s0:c30,c257,c512,c768
I urovapp : prctl passthrough name=urovapp
I urovapp : QUERY rc=0 errno=0 caps=0xeb7 state=0
```

`caps=0xeb7` = `GPR|PAIR|MM_GATES|RAW_XOM|READY|FAKE16|FAKE32|PRCTL`。

### 自身 lib 代码页

```text
lib_alias: page=0x7569724000 in_page=0x7f0 file_off=0x37f0
lib_alias vma=7569724000-7569725000 perms=r-xs size=4096 path=/data/app/.../liburovapp.so
lib_alias baseline execution
lib_alias registered offset=2036 length=16 generation=1
lib_alias execution after register (fetch original)
lib_alias execution after SET
lib_alias bench ns_per_1k normal=357 overlay=227749 overhead=637x
lib_alias stale SET rejected
lib_alias STATUS rc=0 hits=65923 failures=0
lib_alias mprotect gate errno=16
lib_alias unsupported SIMD access fails closed
concurrent readers=4 loops=1242 errors=0 generation=130
lib_alias DEACTIVATE rc=0 state=0
lib_alias execution after restore
lib_alias mprotect after restore errno=0
```

### 私有 payload 页与负向用例

```text
data_shared: page=0x7569724000 flags=0x1
data_shared vma=7569724000-7569725000 perms=r-xs size=4096 path=/data/data/.../files/urov_overlay.bin (deleted)
data_shared registered offset=8 length=16 generation=1
data_shared bench ns_per_1k normal=357 overlay=227710 overhead=637x
data_shared STATUS rc=0 hits=65923 failures=0
data_shared unsupported SIMD access fails closed
data_shared DEACTIVATE rc=0 state=0
data_private_reject: page=0x7569724000 flags=0x2
data_private_reject vma=... perms=r-xp size=4096 ...
data_private_reject: rejected errno=22 as designed
RESULT PASS
```

`flags=0x1` 是 `MAP_SHARED`，`flags=0x2` 是 `MAP_PRIVATE`；后者 VMA
`vm_flags=0x75` 含 `VM_MAYWRITE (0x20)`，模块按设计返回 `EINVAL`。

### 所有权与回收

```text
--- foreign while app owns session ---
query rc=0 errno=0 caps=0xeb7 state=0 session=0 gen=0 last_error=-16
set rc=-1 errno=2
deactivate rc=-1 errno=2
mode=standalone-resident caps=0xeb7 state=active hooks=0xf ...
--- kill owner, then query ---
query rc=0 errno=0 caps=0xeb7 state=0 session=0 gen=0 last_error=0
mode=standalone-resident caps=0xeb7 state=inactive hooks=0xf gen=0 hits=0 failures=0 ...
```

`last_error=-16` = `-EBUSY`，表示有活跃会话但不属于当前进程；`errno=2` =
`ENOENT`。

### 模块卸载与恢复

```text
--- before unload ---
HOLD t=3 read=0x8877665544332211 exec=0x1122334455667788
--- after unload ---
HOLD t=4 read=0xf2aaacc1d28ef101 exec=0x1122334455667788
HOLD t=5 read=0xf2aaacc1d28ef101 exec=0x1122334455667788
```

`0x8877665544332211` 是注册的 fake；`0xf2aaacc1d28ef101` 是原代码字节。
卸载前 `session_stop()` 恢复 VMA/PTE/TLB 并解 pin，因此 app 继续执行/读取不会
SIGSEGV。

### 内核日志

`dmesg` 中只有预期的：

```text
urov: resident backend ready, notify nr=272
urov: emulation failure ... opcode=3dc00260 result=-3   # SIMD fail-closed 负向用例
urov: vma shape rejected flags=75                       # MAP_PRIVATE 负向用例
```

没有 `BUG:`、`WARNING:`、`Oops`、`Call trace`、RCU stall 或 watchdog 记录。
payload 文件路径会出现预期的 SELinux `avc: granted { execute }`（root/dmesg
可见），这是 Android 对 app 自有可执行文件的正常审计。

## 性能

app 内对同一地址做 65536 次 `LDR X`，取多次运行范围：

| 路径 | 普通 cache 命中 | overlay 读 | 倍率 |
|---|---|---|---|
| lib 别名 | 0.36–0.72 ns/次 | 0.23–0.42 µs/次 | 约 475–1175× |
| payload 页 | 0.36–0.72 ns/次 | 0.23–0.47 µs/次 | 约 475–1175× |

覆盖读的成本是 EL0 同步异常 + 解码/模拟的固有成本；热路径没有内存分配、全局锁、
TLB flush 或 PTE 切换。控制路径只在 REGISTER/SET/STATUS/DEACTIVATE 执行。

## 复现

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-app\build-app.ps1 -Source app.c
.\kpms\urov-lab\tools\run_app_device.ps1 -Key <KEY> -Iterations 3
```

手工加载/测试：

```sh
adb push kpms/urov-lab/out/urov-lab.kpm /data/local/tmp/
adb shell '/data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/urov-lab.kpm active'
adb shell '/data/local/tmp/kpatch <KEY> kpm ctl0 urov-lab status'
adb install -r -g kpms/urov-lab/apps/urov-app/out/urovapp.apk
adb shell am start -n com.example.urovapp/android.app.NativeActivity
adb logcat -s urovapp:*
adb shell '/data/local/tmp/kpatch <KEY> kpm unload urov-lab'
```

完整方案与限制见 [APP_OVERLAY.md](APP_OVERLAY.md)。
