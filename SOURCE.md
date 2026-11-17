# 源码来源与许可

最初独立整理的 Config 与 Edge 提取自 [PH-OpenResty/OpenResty_Lua](https://github.com/PH-OpenResty/OpenResty_Lua) 提交 [62fb61947f4c6d10eca468b7b66979009957de55](https://github.com/PH-OpenResty/OpenResty_Lua/commit/62fb61947f4c6d10eca468b7b66979009957de55)。本次再将该来源的 native-sync 提取为本仓库独立目录，并补全统一构建、测试、文档与 CI；当前运行模块共八个。

最初导入时的 `.c`、`.h` 和模块 `config` 文件原样保留。2026-11-14 新增 native-api，并扩展 Config 的 HTTPS/IPv6/命名池/origin_host 字段与 Edge 的自动 profile 接入；当前工作区已经包含这些后续实现改动，不再与导入时的源码摘要逐字节相同。

[SOURCE-SHA256SUMS](SOURCE-SHA256SUMS) 现记录本次交付实现文件的摘要，用于校验当前源码。最初来源仍可通过上述历史提交复核，不能把新的清单当作原提交未变的证明。

API 协议别名与媒体处理的后续实现包含本仓库的原生端点分类、原始代理回归和独立 Python 媒体工具。媒体工具及固定 Pillow 依赖也纳入实现摘要；Pillow 不链接进 Nginx，按其上游许可单独安装。

在仓库根目录可核对：

```sh
sha256sum -c SOURCE-SHA256SUMS
```

项目沿用目标仓库已有的 [Apache License 2.0](LICENSE)。没有将 Lua 运行库、Nginx、OpenResty 或 OpenSSL 源码打包进仓库。构建时使用的 Nginx/OpenResty、OpenSSL、PCRE2、zlib、libcurl 和测试用 Python 包各自适用其上游许可证。

`native-sync` 从同一来源提交 `62fb61947f4c6d10eca468b7b66979009957de55` 的 `native-sync/` 提取。[角色模块、公共核心、头文件和 config](https://github.com/PH-OpenResty/OpenResty_Lua/tree/62fb61947f4c6d10eca468b7b66979009957de55/native-sync)在最初导入时逐字节保留；0.2.0 增加本仓库原创的缓存任务实现及 libcurl 接入，角色模块、头文件和 config 已相应修改；本仓库调整文档、通用路径、统一构建包装器与动态/静态测试接入。旧 Lua 仓库 PR #1 是来源记录，本仓库中的本地目录和手册是安装入口。

`native-purge` 是本仓库新增的原生实现，未从第三方清理模块复制代码。其缓存机制调研基于固定归档的 Nginx 文件缓存源码和公开文档，见 [调研报告](docs/CACHE-MECHANISM.zh-CN.md)。当前 SOURCE-SHA256SUMS 覆盖八个运行模块及独立 Ban Agent/BPF的 config、C 源码和头文件；它是当前实现的校验清单，不把后续修改冒充为最初导入内容。Ban 的运行代码位于 native-ban/src、agent、bpf；旧设计契约在 design 中单独保留。

构建脚本固定 OpenResty 测试归档为 1.31.8.1，归档 SHA-256 为 `b569c63b420f80a4ac8466f2deffe73ed93ab760026532e039c3658409a997f4`。归档用于可复现的测试环境，不表示预编译插件能跨任意 Nginx/OpenResty ABI 使用。

2026-11-15 增加 Config/Edge 的站点/前缀缓存头解析和原生请求/响应处理，SOURCE-SHA256SUMS 已按当时 24 个实现文件生成。Ban v2 集群快照头文件和策略仍是设计材料，未混入运行模块清单。

Sync 0.3.0 的原生配置封装、RSA-OAEP/AES-GCM/Ed25519 处理、发布/应用/回退和 Tier 0.1.1 均为本仓库新增实现。Sync 通过私有符号编译同一份 Config 数据解析器和恢复代码，防止独立加载时引入第二套较弱语法；不复制第三方分层缓存模块源码。Tier 对旧 Lua tier/flush 行为的迁移、304 续期及缓存格式升级说明见 [手册](native-tier/README.zh-CN.md)。

Ban 0.1.0 的 IPC/共享视图、Agent、内核解析/Map 和 Sync 桥为本仓库实现，0.2.0 使用系统 libbpf/json-c/OpenSSL/libcurl 和本仓库原生 Ban Store，不依赖 SQLite。Agent 为 C++17，Nginx 和 BPF 为 C。源码摘要包含实际运行文件，设计 ABI 不混算为已验收执行实现。

`compat/lua/lib/security_guard.lua` 是原生快照到保留 Lua 安全引擎的桥接代码；转换器与暂存工具仅用于退出旧写入路径。测试 fixtures 保留既有 Lua WAF/限流和规则接口，以验证没有因迁移删除或绕过安全执行。它们不构成新原生 WAF/Ban 实现，真实部署目录和策略仍不进入仓库。

`native-ban-store/` 是本仓库新增的 Ban 专用 C++17 存储组件，包含内存索引、变更事务、校验追加日志、原子快照和容量限制；未复制 Redis 或其他数据库源码。仅 Agent 使用该组件，Nginx Worker 保持只读共享视图。

`docs/security-seeds/` 是版本化种子；Bot 的目录/地址已接入策略编译器，弱密码仍待认证消费者。Bot 前缀按各提供者官方来源保留精确值、来源 URL 和快照摘要；分类与范围不得合并为通用可信表。弱密码摘要集合派生自 SecLists 固定提交 `fd15eaaa5ee6b1be059796a2e3058f3fa244243a` 的公开常见值数据，单独保留 [MIT 许可](docs/security-seeds/SECLISTS-LICENSE.txt)、[来源与摘要 manifest](docs/security-seeds/weak-passwords.manifest.json)及[使用边界](docs/security-seeds/README.zh-CN.md)，不以仓库的 Apache 许可替代上游署名和许可。它不包含用户口令，不是认证密码存储，也不代表 Bot/Auth Guard 已实现。

`native-bot/` 与共享的 `native-security/src/scdn_security.h` 为本仓库实现。运行代码包含只读 UA 自动机、IPv4/IPv6 前缀树、可信代理解析、一次主请求决策与共享动作计数；规则/来源编译工具使用 Python 标准库，不在 Worker 查询网络或文件。Bot 模块、头文件和编译工具纳入实现摘要。
