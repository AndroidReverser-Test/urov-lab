# UROV-Z 文档索引

当前代码版本为 **1.2.5**。先阅读当前实现与验证，再按需要追溯历史。版本号表示文档对应的实现阶段；旧审计中的缺陷、旧版本的计时与设备结果，不自动代表当前版本。所有构建、ADB 命令及行文中的代码路径默认以仓库根目录为基准。

## 当前版本

| 文档 | 适合解决的问题 |
|---|---|
| [项目 README](../README.md) | 构建、加载、测试、控制命令与下载入口 |
| [1.2.5 技术博客](implementation-1.2.5.zh-CN.md) | 从双视图概念到异常模拟、内核代读、并发与生命周期的完整源码分析 |
| [持续维护的设计契约](DESIGN.md) | 顶部记录 1.2.5 的原生 PTL、并发、子映射、资源与写入契约；后文保留 1.0.0 设计和历史验证，须结合顶部更新阅读 |
| [1.2.5 审计](compatibility-audit-1.2.5.zh-CN.md) | 本版资源、并发和兼容诊断的修改依据、已有测试与限制 |
| [1.2.5 发布说明](RELEASE-1.2.5.md) | 本次发布产物、验证范围与使用条件 |
| [集成测试说明](INTEGRATION.md) | 两种加载后端、Dobby、十页 CRC、四线程压力及耗时口径 |
| [用户态 API](../api/README.md) | C/C++ 接口、返回值、注册/更新/注销及 Dobby 配合顺序 |
| [测试入口](../tests/README.md) | 主机模型、兼容检查与设备专项的构建和复现 |
| [内置 KCLF 说明](../module/kclf/README.md) | 加载器来源、集成方式和边界 |

源码入口：[模块控制](../module/urov_z.c)、[读取覆盖后端](../module/backend.c)、[指令解码](../module/decode.c)、[指令模拟](../module/emulate.c)、[公开 ABI](../api/include/urov/abi.h)、[用户态封装](../api/src/urov.c)、[测试 App](../app/)、[CRC 集成 App](../integration/)。

## 实现演进与历史证据

| 阶段 | 文档 | 阅读范围 |
|---|---|---|
| 1.2.4 | [兼容性修订](compatibility-audit-1.2.4.zh-CN.md) | 原生页表锁、连续 PTE、GUP 适配及该阶段的证据 |
| 1.2.3 | [兼容性与并发修订](compatibility-audit-1.2.3.zh-CN.md) | 写入契约、索引、子映射和生命周期修订 |
| 1.2.2 | [实现审计与兼容性修订](compatibility-audit-1.2.2.zh-CN.md) | 5.x/6.x 适配的中间基线 |
| 1.2.1 | [多页读取优化](performance-optimization-1.2.1.zh-CN.md) · [发布说明](RELEASE-1.2.1.md) | 缓存、缓冲区与同口径性能比较 |
| 1.2.0 | [性能分析](performance-analysis-1.2.0.zh-CN.md) · [发布说明](RELEASE-1.2.0.md) | 十页测试的初始瓶颈与优化方案 |
| 1.1.0 | [内核实现分析](implementation-1.1.0.zh-CN.md) · [发布说明](RELEASE-1.1.0.md) · [2026-11-12 集成结果](RESULTS-2026-11-12.md) | 首次内置 KCLF 与单页 Dobby 联合测试 |
| 1.0.0 | [发布前审查](AUDIT.md) · [发布说明](RELEASE-1.0.0.md) | 初始 Z 实现、ABI、GUP 修复与当时的限制；历史设计正文保留在持续维护的 DESIGN 文档中 |
| 1.0.0 对比文章 | [读取覆盖解析与其他内核 Hook 方案比较](urov-z-kernel-read-overlay.zh-CN.md) | 固定历史提交的机制比较；外部项目与缺陷结论均按当时版本理解 |

历史日志中的 `out/` 路径属于本地忽略目录，源码下载包不保证包含它们。发布附件以对应 [GitHub Releases](https://github.com/AndroidReverser-Test/urov-lab/releases) 的说明和校验清单为准。BTF/模型检查、真机执行与性能测量是不同层次的证据，阅读时请保留每份记录的设备、内核、页大小、配置和测试范围。

项目自有设计、审计、发布和测试结果文档集中于本目录；根目录及组件 `README.md` 保留作为使用入口。根 `LICENSE` 与 `Dobby/` 的第三方文档、许可证维持原结构。
