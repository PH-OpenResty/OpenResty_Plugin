# 源码来源与许可

Config 与 Edge 插件提取自 [PH-OpenResty/OpenResty_Lua](https://github.com/PH-OpenResty/OpenResty_Lua) 的提交 [62fb61947f4c6d10eca468b7b66979009957de55](https://github.com/PH-OpenResty/OpenResty_Lua/commit/62fb61947f4c6d10eca468b7b66979009957de55)。本仓库补全了两个插件的使用文档，并把构建、测试依赖和 CI 整理为独立入口。

导入时的 `.c`、`.h` 和模块 `config` 文件原样保留；其 SHA-256 清单见 [SOURCE-SHA256SUMS](SOURCE-SHA256SUMS)。文档、示例和构建工具可以针对独立仓库更新，清单只用于核对本次导入的实现来源；未来修改实现时需要同步更新来源记录。

在仓库根目录可核对：

```sh
sha256sum -c SOURCE-SHA256SUMS
```

项目沿用目标仓库已有的 [Apache License 2.0](LICENSE)。没有将 Lua 运行库、Nginx、OpenResty 或 OpenSSL 源码打包进仓库。构建时使用的 Nginx/OpenResty、OpenSSL、PCRE2、zlib 和测试用 Python 包各自适用其上游许可证。

`native-purge` 是本仓库新增的原生实现，未从第三方清理模块复制代码。其缓存机制调研基于固定归档的 Nginx 文件缓存源码和公开文档，见 [调研报告](docs/CACHE-MECHANISM.zh-CN.md)。原有 SOURCE-SHA256SUMS 继续只约束导入的 Config/Edge 实现。

构建脚本固定 OpenResty 测试归档为 1.31.8.1，归档 SHA-256 为 `b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4`。归档用于可复现的测试环境，不表示预编译插件能跨任意 Nginx/OpenResty ABI 使用。
