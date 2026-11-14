# OpenResty Plugin

纯 C 的 Nginx/OpenResty HTTP 插件：直接读取站点数据热更新路由、证书和缓存策略，并提供精确、批量、前缀和整站的持久化缓存失效。运行时不依赖 Lua，不生成站点 Lua、字节码或 `nginx.conf`。

| 插件 | 职责 | 文档 |
| --- | --- | --- |
| `ngx_http_scdn_config_module.so` | 后台检测文件内容、校验并预加载候选版本、等待各 Worker 就绪、切换不可变配置版本 | [Config 完整手册](native-config/README.zh-CN.md) |
| `ngx_http_scdn_edge_module.so` | Host 与最长前缀路由、启停、静态目录、SNI 证书选择、缓存层/可选热度、Prometheus 指标 | [Edge 完整手册](native-edge/README.zh-CN.md) |
| `ngx_http_scdn_purge_module.so` | 持久化版本隔离、精确/批量/前缀/整站失效、并发写回防护与后台检查点 | [Purge 完整手册](native-purge/README.zh-CN.md) |

Edge 依赖 Config 的 C 接口，必须使用同一源码版本编译，并先加载 Config。代理、静态文件与缓存文件管理继续使用 Nginx 自带模块。WAF、请求限速、连接限速、远程 Master→Node 同步不在本仓库实现范围内。

Purge 可独立加载，不依赖前两个插件，也不修改 Nginx 核心或私有缓存索引。它保证新请求不命中已失效版本，**不表示立即删除磁盘文件**；旧空间仍由 Nginx 管理。接入时必须把实际 cache key 改为 `$scdn_purge_key`。

## 文档导航

- [安装、编译和最小运行](docs/INSTALL.zh-CN.md)：依赖、独立构建、现有安装接入、权限与 ABI。
- [配置监听与完整站点语法](native-config/README.zh-CN.md)：全部指令、字段、限制、提交与失败行为。
- [业务路由、TLS、缓存和指标](native-edge/README.zh-CN.md)：全部指令、变量、请求路径与兼容边界。
- [日常操作与故障处理](docs/OPERATIONS.zh-CN.md)：原子发布、证书轮换、状态查询、回退和常见错误。
- [从旧 Lua 流程迁移](docs/MIGRATION.zh-CN.md)：字段映射、替换步骤、热更新边界。
- [验证记录](docs/VALIDATION.zh-CN.md)：实测项目、CI、内存检查及未验证范围。
- [缓存机制调研](docs/CACHE-MECHANISM.zh-CN.md)、[精确清理接入](native-purge/README.zh-CN.md)和[缓存清理基准](native-purge/bench/README.zh-CN.md)。
- [源码来源](SOURCE.md)、[公开发布规则](PUBLISHING.md)、[许可证](LICENSE)。

## 独立构建与验证

已验证 Linux x86_64、Nginx 1.31.8 与 OpenResty 1.31.8.1。构建需要 HTTP SSL 和线程池；测试使用 Python `cryptography`。在全新测试前缀中执行：

```sh
git clone https://github.com/PH-OpenResty/OpenResty_Plugin.git
cd OpenResty_Plugin
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tests/requirements.txt
sh tools/build-runtime.sh /tmp/scdn-plugin-nginx nginx
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-nginx-results.json
python native-purge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-purge-results.json
```

系统构建依赖与 OpenResty 构建方式见 [安装文档](docs/INSTALL.zh-CN.md)。脚本固定下载归档并验证 SHA-256，编译三个插件，拒绝覆盖已有安装。

## 配置如何生效

```mermaid
flowchart LR
    A[完整站点数据文件和证书] --> B[各 Worker 的后台读取线程]
    B --> C[解析 / 校验 / 证书预加载]
    C --> D[相同内容稳定且全部 Worker 就绪]
    D --> E[切换共享活动摘要]
    E --> F[新请求采用新版本]
    E --> G[旧请求继续持有旧版本]
```

默认每 250ms 检查内容、稳定至少 500ms 后允许提交。实际延迟取决于扫描、I/O、证书与最慢 Worker，不保证固定时限。半写、缺失、重复 Host、错误字段或证书不匹配会保留当前版本；默认保护空站点集合。完整例子见 [nginx.conf](native-edge/examples/nginx.conf) 和 [sites.conf](native-config/examples/sites.conf)。

可热更新的是站点数据。监听端口、模块加载、线程池、共享区大小、cache zone 定义等 Nginx 启动指令仍需单独重载。状态中的 `ready` 表示本 Worker 已装入活动配置，不证明源站或业务健康。

## 仓库边界

本仓库独立提供 Config、Edge 和 Purge 的源码、模板、测试与构建工具，不需要克隆原 Lua 仓库，也不需要安装原生 Sync 身份模块。外部发布者负责交付站点数据；Config/Edge 只读源配置，Purge 另行维护私有的失效日志。当前没有配置编辑 HTTP API、自动证书签发、程序自动升级、跨机分发或持久站点历史回滚服务。

仓库示例只使用保留域名、本机地址和通用路径。运行配置、站点数据、证书、私钥、token、日志及构建二进制应保存在受限的部署目录或忽略目录中。
