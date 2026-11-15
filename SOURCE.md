# 源码来源与许可

Config 与 Edge 插件提取自 [PH-OpenResty/OpenResty_Lua](https://github.com/PH-OpenResty/OpenResty_Lua) 的提交 [62fb61947f4c6d10eca468b7b66979009957de55](https://github.com/PH-OpenResty/OpenResty_Lua/commit/62fb61947f4c6d10eca468b7b66979009957de55)。本仓库补全了两个插件的使用文档，并把构建、测试依赖和 CI 整理为独立入口。

最初导入时的 `.c`、`.h` 和模块 `config` 文件原样保留。2026-11-14 新增 native-api，并扩展 Config 的 HTTPS/IPv6/命名池/origin_host 字段与 Edge 的自动 profile 接入；当前工作区已经包含这些后续实现改动，不再与导入时的源码摘要逐字节相同。

[SOURCE-SHA256SUMS](SOURCE-SHA256SUMS) 现记录本次交付实现文件的摘要，用于校验当前源码。最初来源仍可通过上述历史提交复核，不能把新的清单当作原提交未变的证明。

在仓库根目录可核对：

```sh
sha256sum -c SOURCE-SHA256SUMS
```

项目沿用目标仓库已有的 [Apache License 2.0](LICENSE)。没有将 Lua 运行库、Nginx、OpenResty 或 OpenSSL 源码打包进仓库。构建时使用的 Nginx/OpenResty、OpenSSL、PCRE2、zlib 和测试用 Python 包各自适用其上游许可证。

构建脚本固定 OpenResty 测试归档为 1.31.8.1，归档 SHA-256 为 `b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4`。归档用于可复现的测试环境，不表示预编译插件能跨任意 Nginx/OpenResty ABI 使用。
