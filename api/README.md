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

输出 `out/api/liburov.a`、`liburov.so`、`urov-query`。共享库使用 16 KB ELF segment alignment；这只代表二进制布局支持，不代表模块在所有 16 KB 内核上通过运行验证。

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

## 使用边界

会话是进程地址空间所有，当前实现全局最多一个会话；client 对象本身没有独立内核句柄。fork 子进程可以继承快照，但不能用复制的 client 控制父进程会话。`QUERY/STATUS` 仅反映调用者的视图，判断是否可以卸载必须使用 root 的 `kpm ctl0 urov-z status`。存活的子快照使注销返回 `-EBUSY`。

输入目标/影像地址必须未带标签；MTE、带标签的外部 ABI 指针、AArch32、SVE/SME load 不在验证范围。API 对自己分配的描述符地址去除 Android heap top-byte tag，不承诺支持任意 MTE 内存。不要把库中的 4096 常量当作设备页大小，读取 `info.page_shift`。

typed API 每次创建全新请求，避免把响应里的 capability 等字段带回 REGISTER。低层 `urov_call` 会设置 size/version/MAC，但保留其他字段以支持协议测试；调用前必须用 `urov_request_init`，填入本次操作需要的输入字段。`request_id` 只是回显关联值，不是防重放 nonce。

模块缺失和密钥错误通常都返回 `-EINVAL`。能力标志表示模块可安装的路径，厂商内核优化仍需要实际测试；不会自动将不支持的读取伪装成成功。测试 App 的 73 项回归已接入此 API，见 [审查报告](../AUDIT.md)；页表锁、映射并发与写入/原子操作的限制仍然适用。
