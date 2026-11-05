# 同进程 SO 改码与 UROV-Y CRC32 复核

2026-11-05，在 Pixel 6（Android 16、arm64、内核 `6.1.134-android14-11`、SELinux `Enforcing`）上测试。检测 App 通过 `dlopen` 加载随 APK 打包的 `liburov_crc_patch.so` 模拟同进程注入。测试 SO 负责变更专用页和发送认证的 `prctl` 请求。CRC 与无密钥探针在 App 的 `untrusted_app` 工作线程运行。设备端 root 用于装卸 KPM 和核对状态。[测试夹具](apps/urov-detect/crc_fixture.inc) · [测试 SO](apps/urov-detect/crc_patch_fixture.c)

## 原地修改普通 ELF 代码页

三个 `crc-ap` 进程都先成功发送认证 `QUERY`。随后把 linker 加载的原始 `.text`（本次 VMA 为 81,920 字节）和同一代码的独立 4,096 字节 `MAP_PRIVATE` RX 别名分别提交注册，均返回 `EINVAL`。单页别名的 `VmFlags` 仍有 `mw`。后端要求整个 VMA 恰好一页、文件后备、当前为 RX，并拒绝 `VM_MAYWRITE`，所以仅将普通私有代码页拆成一页仍无法注册。[VMA 校验](urov_y_backend.c) · [Android 6.1 mmap 权限处理](https://android.googlesource.com/kernel/common/%2B/refs/tags/android14-6.1-2023-12_r14/mm/mmap.c)

测试 SO 在私有别名上把 `mov w0, #0x1234` 改成 `mov w0, #0x1235`。写入成功，直接 CRC 变为 `0c7da8a0`。在本设备上，写后恢复 RX 返回 `EACCES`，内核审计为 `execmod`，夹具跳过该别名的执行。再次注册改后的私有页仍返回 `EINVAL`。因此当前 KPM 无法给这种普通私有代码页建立覆盖会话，即使注入代码持有有效密钥。[私有页 App 日志](results/crc-20261105-222216/crc-ap-1-18739.log) · [设备审计增量](results/crc-20261105-222216/kernel-new.log)

## 框架接受注册时的改码模拟

测试 SO 用 APK 内预置的修改版文件页替换 App 专用 RX 别名。两版只差一条 4 字节指令，替换前后函数虚拟地址相同。替换后可执行映射为单页文件后备 RX，符合当前注册条件。这个正例验证读取伪装对实际执行已改变的页是否有效，模拟方式是同址重映射。原 ELF 文件偏移与映射偏移此时不同，原 `ud_check_views()` 按旧偏移核验得到 `UNKNOWN/ESTALE`。[同址替换日志](results/crc-20261105-222216/crc-ap-all-1-18817.log)

CRC32 校验覆盖 `BTI C`、`MOV`、`RET` 共 12 字节，原文件 CRC32 为 `f50bcaf6`，修改版为 `0c7da8a0`。两条内存读路径都先逐字节执行 `LDRB`，再对普通栈缓冲计算 CRC32。控制请求把原始前 8 字节作为伪值，覆盖包含修改指令的范围。每个场景分别校验原文件、实际执行、独立标量读、直接调用同一读点及经注册包装函数读取。[App 检测实现](apps/urov-detect/crc_fixture.inc)

| 场景 | 函数返回 | 独立读取 CRC32 | 注册路径 CRC32 | 无密钥观测 |
| --- | ---: | --- | --- | --- |
| 原页 | `0x1234` | `f50bcaf6` | `f50bcaf6` | AP 探针 0/210 |
| 仅修改 | `0x1235` | `0c7da8a0` | `0c7da8a0` | AP 探针 0/210 |
| `SITE_BRK`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | 读取点指令字差异 3/3 轮 |
| `PAGE_UXN`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | 读取点页取指 canary 45/45 |
| `PAGE_AP`，限定调用窗口 | `0x1235` | `0c7da8a0` | `f50bcaf6` | AP 探针 45/45 |
| `PAGE_AP`，`caller_count=0` | `0x1235` | `f50bcaf6` | `f50bcaf6` | AP 探针 45/45 |
| 注销覆盖 | `0x1235` | `0c7da8a0` | `0c7da8a0` | AP 探针 0/180 |

在 `caller_count=0` 的 AP 用例中，覆盖范围内的独立 `LDRB` 也得到原字节，单独比较 CRC 与原文件会漏掉实际修改。把上一轮独占代写探针放在同页的 `RET` 首字节（偏移 `+8`，覆盖窗口外）仍然命中。若改采样 `MOV` 的变更字节（偏移 `+4`），目标返回的原字节与真实后备文件的修改字节不同，探针按对照不一致返回 `UNKNOWN/EAGAIN`。这两项均在三轮复现。[AP 全调用者样本](results/crc-20261105-222216/crc-ap-all-1-18817.log) · [有调用窗口的 AP 样本](results/crc-20261105-222216/crc-ap-1-18739.log)

共 14 次 App 运行。四个活动模式各测 3 轮，每轮各阶段重复 15 次。AP 探针在已知稳定字节上阳性 90/90，其他场景阳性 0/690。各活动会话 `failures=0`。注销后在同一进程复测，读路径恢复看见修改字节。原有三模式装卸检测矩阵也在新版 APK 上通过回归。最终 KPM 列表为空，实验增量无内核 BUG、Oops 或挂起。[CRC 机器结果](results/crc-20261105-222216/summary.json) · [原有矩阵回归结果](results/eliminate-20261105-222459/summary.json)

结论的范围是当前 KPM、App 自有且已知的代码映射与检测路径。CRC 表示选定路径返回的字节，AP 探针表示采样页触发了代写语义。其他能篡改同进程检测逻辑的注入方式和未采样页仍需单独验证。

## 复现

在仓库根目录运行。脚本为每次矩阵生成临时模块密钥，复用设备上 `/data/local/tmp/kpatch`，生成 App 日志、机器汇总及内核增量。

```powershell
.\kpms\urov-lab\build.ps1
.\kpms\urov-lab\apps\urov-detect\build.ps1
python .\kpms\urov-lab\tools\run_crc_device.py `
  --serial <SERIAL> --key <KP-SUPERKEY> --repeats 15 --cycles 3
```
