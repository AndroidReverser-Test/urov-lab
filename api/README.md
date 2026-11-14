# UROV-Z 用户态 C API

这个目录可独立复制到 Android NDK 项目中使用，无需 KernelPatch 内核头文件。它封装 UROV-Z ABI v1 的 `prctl` syscall、密钥派生、MAC、请求初始化和结果转换，支持 little-endian AArch64、Android API 26 及以上。头文件也可由 C++11 及以上代码包含。

应用无需 root 调用 API，但设备管理员必须先加载 `urov-z.kpm`。传给 API 的是模块加载参数 `key=` 对应的 **32 位十六进制模块密钥**，不是 kpatch superkey。API 不负责获取 root、加载模块或卸载模块。

## 目录与构建

- `include/urov/urov.h`：面向应用的 API、客户端上下文、查询和状态结构。
- `include/urov/abi.h`、`auth.h`：模块与应用共用的协议和认证实现，避免两份定义发生漂移。
- `src/urov.c`：唯一需要链接的实现文件。
- `examples/query.c`：可编译、可运行的查询示例。
- `build.ps1`：生成静态库、动态库和示例；`CMakeLists.txt`：NDK CMake 接入。
- `LICENSE`：GPL v2 文本；这些源文件声明 GPL-2.0-or-later。

在仓库根目录执行：

```powershell
.\api\build.ps1 -Ndk D:\androidSDK\ndk\26.1.10909125
```

输出 `out/api/liburov.a`、`liburov.so`、`urov-query`。链接同时设置 `max-page-size=16384` 和 `common-page-size=16384`，覆盖 ELF LOAD 与 GNU_RELRO 页对齐；CMake 接入也会把这两个选项传给链接 `urov` 的目标。这只代表二进制布局支持，不代表模块在所有 16 KB 内核上通过运行验证；要求依据见 [Android 官方 16 KB 指南](https://developer.android.com/guide/practices/page-sizes)。

应用 CMake 接入：

```cmake
add_subdirectory(path/to/urov-lab/api urov-api)
target_link_libraries(your_native_library PRIVATE urov)
```

也可以直接把 `api/src/urov.c` 编译到自己的 native library，并把 `api/include` 添加到 include 路径。源码必须按 C 编译；C++ 调用方使用头文件提供的 `extern "C"` 接口。

独立示例：

```powershell
adb push out/api/urov-query /data/local/tmp/urov-query
adb shell chmod 755 /data/local/tmp/urov-query
adb shell /data/local/tmp/urov-query $MODULE_KEY
```

## 接口

所有返回 `int` 的函数成功返回 `0`，失败返回 **负 errno**；用 `strerror(-ret)` 打印错误，不依赖调用之后的全局 `errno`。除请求初始化和 destroy 外，失败不修改输出对象；`urov_client_init` 初始化失败也保留旧上下文，所以不要在换密钥失败后继续假定新密钥已生效。

| 函数 | 行为 |
|---|---|
| `urov_client_init` / `urov_client_init_bytes` | 从 32 个 hex 字符 / 16 字节密钥初始化上下文 |
| `urov_client_destroy` | 清零派生密钥；不会注销内核会话 |
| `urov_query` | 查询能力、页大小、最大页数及调用者状态；也会尝试回收死亡 owner |
| `urov_register_pages` | 注册页描述符数组；数据来自 `image`，`length=0` 表示完整运行时页 |
| `urov_register_inline` | 注册单页中的 8/16/24/32 字节覆盖窗口 |
| `urov_set_page` | 更新原始输入数组中 `index` 对应的页，必须给出当前 generation |
| `urov_set_inline` | 更新单页会话的原覆盖窗口；长度必须与注册时一致 |
| `urov_get_status` | 查询调用者会话，包括 generation、页数、armed 页数和计数器 |
| `urov_deactivate` | 注销当前地址空间的会话；已经 inactive 时幂等成功 |
| `urov_request_init` / `urov_call` | 低层 ABI 接口，供协议测试或自定义封装使用 |

`struct urov_client` 初始化后可只读共享给多个线程。每次调用使用独立请求，没有全局可变客户端状态，也不会自动重试。不要在仍有调用执行时 destroy 或重新初始化同一上下文。并发控制操作可能返回 `-EBUSY`；应用自行决定等待多久。`-EAGAIN` 表示 generation 冲突等情况，应查询状态后决定如何更新。

所有 typed mutation 接口都要求非 NULL 的 `out`，在发起 syscall 之前检查它。它们不持有输入影像；模块在调用期间复制影像，因此成功返回后可复用或释放输入缓冲区。调用期间，描述符、影像和输出内存必须保持有效且内容稳定。

## 使用示例

下面的函数由拥有目标映射的进程调用。`text_page` 必须指向已存在、页对齐、可读可执行且不可写的普通文件映射。覆盖窗口以外仍读取原始快照；取指执行保持原始代码。

```c
#include <urov/urov.h>
#include <errno.h>
#include <stdint.h>

int exercise_overlay(const char *module_key, const void *text_page)
{
    struct urov_client client = {0};
    struct urov_info info;
    struct urov_status status;
    uint64_t fake = UINT64_C(0x1122334455667788);
    int ret = urov_client_init(&client, module_key);
    if (ret) return ret;

    ret = urov_query(&client, &info);
    if (ret) goto out;
    if (!(info.capabilities & UROV_Z_CAP_PAGE_AP)) {
        ret = -EOPNOTSUPP;
        goto out;
    }
    ret = urov_register_inline(&client, text_page, 256, &fake, sizeof(fake), &status);
    if (ret) goto out;

    /* 此时从 text_page + 256 的受支持数据读取应得到 fake。
     * 将实际读取放在另一个函数或使用 volatile，避免编译器常量折叠。 */
    fake = UINT64_C(0xaabbccddeeff0011);
    ret = urov_set_inline(&client, status.generation, &fake, sizeof(fake), &status);
    {
        int cleanup = urov_deactivate(&client);
        if (cleanup) ret = cleanup; /* 不能忽略注销失败 */
    }
out:
    urov_client_destroy(&client);
    return ret;
}
```

这是最小流程示例；生产调用方还必须处理 `-EFAULT` 的状态不确定性：内核可能已完成注册/更新，但最终 copy-out 失败。此时调用 `urov_get_status` 核对状态，不能直接重复提交。上例的输入和输出必须始终有效，不适用于并发解除映射的情况。

多页描述符示例：

```c
struct urov_page pages[2] = {
    { text_page0, image0, 0, 0 },  /* 完整运行时页 */
    { text_page1, image1, 128, 16 }
};
struct urov_status result;
int ret = urov_register_pages(&client, pages, 2, &result);
/* 成功后 urov_set_page 的 index 仍对应输入顺序，即使 base 没有排序。 */
```

## 与 Dobby hook 联合使用的限制

UROV 只替换受支持的数据读取结果，不负责安装 Dobby hook，也不会让 hook 代码自动获得读取豁免。取指仍执行物理页中的代码：先安装 Dobby hook、再注册原始读取影像后，执行的是已修改代码，CRC 等数据读取才得到修改前的字节。

1. **不能依赖覆盖页中的已修改 literal。** Dobby 的远跳转可能使用 `LDR literal; BR; address`，其中 LDR 是数据读取，同样受 `all-callers` 覆盖。若读取影像保存的是 hook 前字节，跳转地址会被替换成原始指令数据，可能导致崩溃；本次实测曾因此发生 App SIGBUS。替换函数、原函数及 trampoline 对覆盖页的其他数据读取也没有例外。
2. **近跳转必须验证，不能只打开开关。** 本仓库测试在 `DobbyHook` 前调用 `dobby_set_near_trampoline(true)`，并在 REGISTER 前检查实际入口为 AArch64 `B imm26`；不能生成该布局时撤销 hook 并报错。还应检查转发 trampoline 及其 literal 所在位置，避免它们落入提供旧字节的覆盖范围。近跳转开关本身不证明任意目标函数、重定位指令或内存布局都兼容。
3. **先保存原页，再 patch，最后注册。** 顺序为：等待注入完成 → 保存 hook 前字节 → `DobbyHook` 并确认跳转布局、参数/返回值 → 确认目标页恢复为 RX 且不可写 → `urov_register_pages` 提交 hook 前影像。UROV 在 REGISTER 时取得的真实快照已经包含 patch，与调用方保存的原始读取影像不同。页大小使用 `info.page_shift`；必须覆盖实际改写的全部字节及涉及的页，不能假定 hook 永远只修改固定长度或单页。
4. **覆盖活动期间不要直接重新 patch 或销毁 hook。** `DobbyHook` / `DobbyDestroy` 会读取或修改代码并切换页权限，可能与影像、映射跟踪及并发执行冲突。调用方须同步相关线程，避免在 patch/恢复期间执行目标函数；API 不提供通用的线程暂停或原子安装保证。正常结束顺序为：成功 `urov_deactivate` → `DobbyDestroy` → 确认无线程、回调或函数指针继续使用 payload 后再释放 SO。注销失败时不得继续释放；若 mutation 返回 `-EFAULT`，先查询实际会话状态再决定如何恢复。
5. **目标映射仍须符合 REGISTER 条件。** Dobby 修改后的目标必须是满足条件的普通 RX 文件映射。KCLF manual 注入的 SO 和通常由匿名内存分配的 Dobby trampoline 不能因此直接注册；manual 注入的 payload 可以控制宿主已有文件代码页。需要覆盖注入 SO 自身时应使用 linker 后端，并重新检查映射条件。

当前验证目标是本仓库带有 NOP 入口的 ARM64 测试函数：manual/linker 各 3 轮，参数和返回值修改、直接读取、`process_vm_readv`、`/proc/self/mem` CRC 均通过。该结果不证明任意函数的 literal、独占/原子序列、并发改映射或任意 Dobby 版本都可透明运行。

随仓库恢复的 Dobby 版本中，可选 SymbolResolver 插件与 `RuntimeModule` 定义不一致，测试构建关闭了 `Plugin.SymbolResolver`，由测试 App 提供目标函数地址；不要据此假设 `DobbySymbolResolver` 已构建或验证。实现示例见 [payload.c](../integration/payload.c)，完整说明见 [集成设计](../INTEGRATION.md) 和 [实测记录](../integration/RESULTS-2026-11-12.md)。

## 使用边界

会话是进程地址空间所有，当前实现全局最多一个会话；client 对象本身没有独立内核句柄。fork 子进程可以继承快照，但不能用复制的 client 控制父进程会话。`QUERY/STATUS` 仅反映调用者的视图，全局状态使用 root 的 `kpm ctl0 urov-z status` 查询。存活的子快照使注销返回 `-EBUSY`。全局 inactive 不证明 hook 跳板已排空；当前 1.1.0 集成测试不热卸载 KPM，详见 [集成生命周期](../INTEGRATION.md)。

输入目标/影像地址必须未带标签；MTE、带标签的外部 ABI 指针、AArch32、SVE/SME load 不在验证范围。API 对自己分配的描述符地址去除 Android heap top-byte tag，不承诺支持任意 MTE 内存。不要把库中的 4096 常量当作设备页大小，读取 `info.page_shift`。

typed API 每次创建全新请求，避免把响应里的 capability 等字段带回 REGISTER。低层 `urov_call` 会设置 size/version/MAC，但保留其他字段以支持协议测试；调用前必须用 `urov_request_init`，填入本次操作需要的输入字段。`request_id` 只是回显关联值，不是防重放 nonce。

模块缺失和密钥错误通常都返回 `-EINVAL`。能力标志表示模块可安装的路径，厂商内核优化仍需要实际测试；不会自动将不支持的读取伪装成成功。测试 App 的 73 项回归已接入此 API，见 [审查报告](../AUDIT.md)；页表锁、映射并发与写入/原子操作的限制仍然适用。
