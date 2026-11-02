# UROV-LAB

ARM64 用户代码页读取异常覆盖的受限实验设计。禁止硬件断点；不在每次读取时切换页表。

**当前有可加载的预检 KPM，但没有活动覆盖 KPM，也没有通过 Android 读取异常覆盖功能测试。** 不要将模拟核心/原生差分的 PASS 或相邻 `urov-probe` 的能力探测误认为覆盖后端已工作。

- [完整设计](DESIGN.md)：实验契约、ABI、异常入口、映射事务、并发更新、恢复/卸载、常驻可靠后端。
- [测试计划与真实复验结果](TEST_PLAN.md)：S0–S7 门槛和验收。
- [本次实现与真机结果](IMPLEMENTATION_RESULTS.md)：软件核心、8核原生差分、预检装卸，以及实际失败的loader安全门槛。
- [常驻后端与生命周期契约](BACKEND_CONTRACT.md)：根据实测选定的下一阶段架构和接口。
- `decode.c` / `decode.h`：普通 A64 GPR load 解码器；不访问目标内存、不修改真实 pt_regs。
- `tests/decode_test.c`：host 不变量测试和独立汇编编码核对。
- `tools/inspect_btf.js`：只读核对本机 BTF 布局/原型。
- `emulate.c/.h`：纯软件的字节合并与零部分提交核心；不操作真实映射。
- `urov_check.c` / `out/urov-lab-check.kpm`：预检与内核核心自测，无fault hook；`register`明确拒绝。
- `build.ps1`：构建预检KPM和四个Android测试二进制。

2026-11-02 复验：`PASS checks=211127 vectors=50 random=100000 independent_assembler=verified`，ASAN/UBSAN、NDK freestanding 编译通过。不是原生 ARM64 全语义差分。

新增核心host/Android用例通过288090检查，原生差分在8核完成41600次比较。预检KPM最终10轮装卸通过，但**实际运行的KP在exit返回EBUSY后仍移除模块**，装卸安全门槛失败；另有root首次触页复制基线异常待定位。

当前设备无 EPAN，raw-XOM 实验会损失相关映射的 PAN 读取隔离。当前禁止启用活动覆盖；下一阶段选用常驻后端与原生 MM 生命周期集成，详见设计第11节及新增实施契约。
