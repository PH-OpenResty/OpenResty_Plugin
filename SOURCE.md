# 源码来源与许可

最初独立整理的 Config 与 Edge 提取自 [PH-OpenResty/OpenResty_Lua](https://github.com/PH-OpenResty/OpenResty_Lua) 提交 [62fb61947f4c6d10eca468b7b66979009957de55](https://github.com/PH-OpenResty/OpenResty_Lua/commit/62fb61947f4c6d10eca468b7b66979009957de55)。本次再将该来源的 native-sync 提取为本仓库独立目录，并补全统一构建、测试、文档与 CI；当前运行模块共五个。

最初导入时的 `.c`、`.h` 和模块 `config` 文件原样保留。2026-11-14 新增 native-api，并扩展 Config 的 HTTPS/IPv6/命名池/origin_host 字段与 Edge 的自动 profile 接入；当前工作区已经包含这些后续实现改动，不再与导入时的源码摘要逐字节相同。

[SOURCE-SHA256SUMS](SOURCE-SHA256SUMS) 现记录本次交付实现文件的摘要，用于校验当前源码。最初来源仍可通过上述历史提交复核，不能把新的清单当作原提交未变的证明。

在仓库根目录可核对：

```sh
sha256sum -c SOURCE-SHA256SUMS
```

项目沿用目标仓库已有的 [Apache License 2.0](LICENSE)。没有将 Lua 运行库、Nginx、OpenResty 或 OpenSSL 源码打包进仓库。构建时使用的 Nginx/OpenResty、OpenSSL、PCRE2、zlib、libcurl 和测试用 Python 包各自适用其上游许可证。

`native-sync` 从同一来源提交 `62fb61947f4c6d10eca468b7b66979009957de55` 的 `native-sync/` 提取。[角色模块、公共核心、头文件和 config](https://github.com/PH-OpenResty/OpenResty_Lua/tree/62fb61947f4c6d10eca468b7b66979009957de55/native-sync)在最初导入时逐字节保留；0.2.0 增加本仓库原创的缓存任务实现及 libcurl 接入，角色模块、头文件和 config 已相应修改；本仓库调整文档、通用路径、统一构建包装器与动态/静态测试接入。旧 Lua 仓库 PR #1 是来源记录，本仓库中的本地目录和手册是安装入口。

`native-purge` 是本仓库新增的原生实现，未从第三方清理模块复制代码。其缓存机制调研基于固定归档的 Nginx 文件缓存源码和公开文档，见 [调研报告](docs/CACHE-MECHANISM.zh-CN.md)。当前 SOURCE-SHA256SUMS 覆盖五个运行模块的 config、C 源码和头文件；它是当前实现的校验清单，不把后续修改冒充为最初导入内容。Ban 的设计契约另列在 native-ban，尚不属于运行模块。

构建脚本固定 OpenResty 测试归档为 1.31.8.1，归档 SHA-256 为 `b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4`。归档用于可复现的测试环境，不表示预编译插件能跨任意 Nginx/OpenResty ABI 使用。

2026-11-15 增加 Config/Edge 的站点/前缀缓存头解析和原生请求/响应处理，SOURCE-SHA256SUMS 已按当前 24 个实现文件重新生成。Ban v2 集群快照头文件和策略仍是设计材料，未混入运行模块清单。
