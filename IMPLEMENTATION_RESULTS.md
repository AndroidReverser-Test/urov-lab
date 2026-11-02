# 实现与设备验证记录

日期：2026-11-02，Asia/Shanghai。设备/内核与设计一致。**这里只验收模拟核心和预检KPM，不是完整读取异常覆盖验收。**

## 已实现

- `emulate.c/.h`：严格上下文/区间/FAR检查、白名单解码、最多16字节的交集合并、符号扩展/W零扩展、writeback/PC零部分提交。只访问调用者提供的不可变快照，不操作真实PTE/pt_regs。
- `core_selftest.c`：无分配的4114项核心自测，可在KPM初始化时运行。
- `urov_check.c`：可加载的 **urov-lab-check.kpm**，只读探测、核心自测、确定拒绝register，以及无外部资源的卸载拒绝语义测试。
- `tests/emulate_test.c`、`native_test.c`、`kpm_check_test.c`、`copy_probe.c` 和 `build.ps1`。
- `fault_signature.c` 仅用于对比编译器真实生成的KCFI类型，未注册或调用此函数。类型匹配不证明完整callback协议。

没有 `urov-lab.kpm` 活动后端，没有raw-XOM页、fault hook、页pin或异步回调。新产物用独立的check名称，避免把预检误当成覆盖模块。

## 实际通过的测试

| 测试 | 结果 | 边界 |
|---|---|---|
| 原decoder sanitizer/汇编向量复验 | 211127检查，50向量，100000随机opcode | 非完整架构语义证明 |
| 新core host ASAN/UBSAN | 288090检查、4114内置检查 | 144000取值场景、100000并发pair快照场景 |
| Android同一core用例 | 同上，PASS | 在用户态调用核心，不是EL1 fault |
| 原生A64差分 | CPU0–7，26类，41600次比较PASS | 原生原页/影子页结果与核心比较，无异常覆盖 |
| 原页执行 | 8个CPU均返回42，原字节校验通过 | 使用sealed RX原页，不执行改值后的影子页 |
| KPM核心自测 | 每次加载4114检查PASS | 真实EL1执行纯核心，不安装handler |
| KPM装卸/负向接口 | 最终10轮串行循环PASS（此前另3轮） | init非法参数、未知命令、小输出、NULL及PROT_NONE输出、register拒绝 |
| slot/KCFI检查 | kernel_match=1，slot_match=1，kcfi_type_match=1 | 不证明入口可写或装卸安全 |

输出摘录：

```text
PASS emulator_checks=288090 core_checks=4114 value_cases=144000 threaded_pair_cases=100000 scope=software_core_only
PASS cpus=8 native_cases=26 comparisons=41600 scope=native_vs_software_model overlay=NOT_ENABLED
```

原生用例覆盖普通无符号/有符号GPR、scaled/unscaled/pre/post、register扩展、pair与XZR；当前原生差分不包含SP/literal所有形态。软件测试覆盖部分SP/literal情况，但不能冒充全部原生验收。未进行真实异常吞吐或覆盖模块并发卸载压力。

## 实测失败的安全门槛

预检状态：

```text
abi=1 mode=preflight active=0 backend=none core=pass checks=4114 kernel=0x60186 kp=0xc00 kernel_match=1 slot_match=1 kcfi_type_match=1 symbols=0xdff cpu_pan=2 cpu_epan=0 entry_writable=unverified loader_contract=unverified reason=activation_backend_not_available
loader_exit_veto=NOT_RETAINED result=-EBUSY module_after=absent activation_gate=FAIL
```

`veto-test`模式不持有任何外部资源，只让exit返回EBUSY。实测unload报错后模块已不在列表；因此这不是仅从checkout源码推断的风险。**当前设备KP的安全保留门槛实际失败，禁止启用活动覆盖模块。**

`symbols=0xdff` 按源码required数组顺序表示第9位缺失，即 `synchronize_rcu_tasks_rude` 未解析。另读kallsyms仅找到普通Tasks和Tasks-Trace同步函数。不能用Trace或callback barrier的名字直接替换不同读侧协议。

据此更新后的选定架构见 `BACKEND_CONTRACT.md`：常驻后端处理异常/MM生命周期，薄KPM负责管理；不是只修改退出函数返回值。

## 其他发现及修正

1. 主机首次sanitizer运行发现**测试生成器**在页尾构造覆盖区后未再次clamp导致越界；已修复生成器，最终ASAN/UBSAN重新通过。未把失败计入PASS。
2. 初次freestanding自测结构复制产生额外memcpy导入；改为显式寄存器字段复制，最终KPM无该导入。最终emulate函数只有对decoder的调用，没有TLBI、日志、分配或SIMD调用。
3. Android API31没有声明本测试使用的explicit_bzero，改为volatile逐字节清除凭据。密钥仅经运行时FD输入，未保存到源/文件/报告。
4. sealed memfd从原RDWR描述符直接重建R/RX得到EPERM；增加只读重开后，普通shell为EACCES、受授权root运行成功。未删除seal、关闭SELinux或修改mount。
5. 测试准备阶段在root路径出现首次触页的libc复制不一致，独立无hook用例得到：

```text
shell:
libc_copy prefault=0 result=PASS first_diff=4096
libc_copy prefault=1 result=PASS first_diff=4096
copy_probe failures=0 overlay=NOT_ENABLED

kpatch root:
libc_copy prefault=0 result=FAIL first_diff=16
scalar_copy prefault=0 result=PASS
libc_copy prefault=1 result=PASS first_diff=4096
scalar_copy prefault=1 result=PASS
copy_probe failures=1 overlay=NOT_ENABLED
```

该异常根因未定位，不宣称是某个特定FPSIMD/KP缺陷。native_test以显式标量初始化并即时验证数据后得到前述差分PASS；这只排除了测试输入不可信，不等于修复平台异常。完整验收仍受此基线问题阻断。

## 复验方式

本地构建：

```powershell
.\kpms\urov-lab\build.ps1
wsl -d Ubuntu-24.04 bash -lc 'cd /mnt/e/KernelPatch && gcc -std=c11 -O2 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -pthread kpms/urov-lab/decode.c kpms/urov-lab/emulate.c kpms/urov-lab/core_selftest.c kpms/urov-lab/tests/emulate_test.c -o build/urov-lab-20261102/emulate-test && build/urov-lab-20261102/emulate-test'
```

Android产物位于 `/data/local/tmp/urov-lab-check-20261102/`：

- `urov_emulate_test`：不需root，运行软件测试。
- `urov_native_test 100`：当前设备须从已有授权root上下文运行，比较原生指令与模型；`--data-only`会跳过原页执行，不能算执行验证。
- `urov_kpm_check_test --module /data/local/tmp/urov-lab-check-20261102/urov-lab-check.kpm --key-fd FD --cycles 10`：密钥经FD输入；输出PASS仅代表预检用例预期行为，必须同时看activation_gate。
- `urov_copy_probe`：普通shell和root分别运行，保留失败结果；程序不调整系统设置。

所有模块管理操作串行；测试拒绝接管已经存在的同名模块。ADB重新push二进制后需重新设置执行位。

## 产物校验与最终设备状态

本地 `out/` 与设备SHA-256逐一相同：

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| urov-lab-check.kpm | 13528 | `37ecbbd1b7d194f9f6770277fa012e023c1b532434c4488645d03c5b6585f767` |
| urov_emulate_test | 23384 | `06d18d98eb0ecedf9eeed905fe6ed4ee11c91d99b9939eb61fd7bfe5d32cb47a` |
| urov_native_test | 25032 | `c424c66979f385ba42150554cea349a83ee1d8048be9721bd1279db6a93004ff` |
| urov_kpm_check_test | 16792 | `db781663d74917df95cf8c9d2cea3a711cde38c31e924f3cb716344ec68a54a6` |
| urov_copy_probe | 12992 | `975aa1f6008a7d43bc75846c1b553a15b9ee82d3654afa3f9de43386583fc3d3` |

- 最终KPM列表为空，与本次开始一致。
- 前后boot_id均为 `f5801c21-1426-4e9a-bff2-9d6ddeb1de29`，没有重启。
- 测试查看到预检装卸/负向返回日志；未做完整内核日志审计，因此不声称已经排除所有平台告警。
- 没有刷写/升级KP、fault入口写入、PTE修改、硬件断点、全局PAN/CFI/SELinux更改或持久加载设置。
- 产物保留供复验，无密钥文件。原有用户文件和共享核心源码未修改。

## 未完成的用户目标

真正的读取异常覆盖KPM、权限事务、pin/mm生命周期、恢复失败保留、真实异常并发/性能以及S3–S7完整测试尚未完成。继续需要实施并部署设计中的loader/常驻后端及解决基线异常；不得把这里的预检PASS当作全部需求完成。
