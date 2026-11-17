# OpenResty Plugin

七个纯 C 的 Nginx/OpenResty HTTP 插件：Sync 提供 Master/Node 身份、站点/证书加密发布与热应用、缓存刷新与预热任务；Config/Edge 读取站点数据热更新路由、证书和缓存策略；API 自动识别动态 API、AI 与流式请求；Purge 提供持久化失效、源站校验及过时复用。Nginx/BPF 为 C，Ban Agent 与专用 Ban Store 为 C++17。这些原生模块不依赖 Lua，不生成站点 Lua、字节码或 `nginx.conf`。

| 插件 | 职责 | 文档 |
| --- | --- | --- |
| `ngx_http_scdn_sync_module.so` | Master/Node 角色、mTLS 身份、加密站点/证书发布、Node 热应用/回退和缓存任务 | [Sync 完整手册](native-sync/README.zh-CN.md) |
| `ngx_http_scdn_config_module.so` | 后台检测文件内容、校验并预加载候选版本、等待各 Worker 就绪、切换不可变配置版本 | [Config 完整手册](native-config/README.zh-CN.md) |
| `ngx_http_scdn_api_module.so` | 请求/响应自动识别、API/AI 代理策略、缓存绕过、流式响应与 TLS 连接复用身份检查 | [API 完整手册](native-api/README.zh-CN.md) |
| `ngx_http_scdn_edge_module.so` | Host 与最长前缀路由、启停、静态目录、SNI 证书选择、缓存层/可选热度、规则回源头/响应诊断、Prometheus 指标 | [Edge 完整手册](native-edge/README.zh-CN.md) |
| `ngx_http_scdn_ban_module.so` | 可信 WAF/CC 事件、固定期限 L7/L3、独立 Agent/eBPF、所有节点完整封禁快照 | [Ban 运行手册](native-ban/RUNTIME.zh-CN.md) |
| `libscdn-ban-store.a` | Ban Agent 专用 IP 状态存储，内存索引、可选持久化、批量事务与恢复 | [Ban Store 手册](native-ban-store/README.zh-CN.md) |
| `ngx_http_scdn_tier_module.so` | 原生热度选层、L1 → L2 → 源站、晋升/冷层保留、对象大小准入与原始到期 | [Tier 完整手册](native-tier/README.zh-CN.md) |
| `ngx_http_scdn_purge_module.so` | 持久化精确/批量/通配符/正则/后缀/目录/整站/节点失效、源站条件校验、有界过时复用 | [Purge 完整手册](native-purge/README.zh-CN.md) |

Edge 依赖 Config 的 C 接口；一起构建 API 时也调用其判定接口。业务模块必须使用同一源码版本编译，全量动态加载顺序建议 Config → Ban → Tier → API → Edge → Purge → Sync；Sync、Tier 与 Purge 可独立加载。代理、静态文件与缓存文件管理继续使用 Nginx 自带模块。WAF、业务限速仍由外部能力承担。

API 已补齐图片编辑/变体分类、按方法/路径/可选站点的协议别名，以及 Responses/Chat/Gemini/Messages 工具链原始传输回归。显式 [媒体工具](native-api/tools/media_artifact.py)可从已有 JSON/SSE/二进制结果完整解码并保存图片，使用独立 Pillow 依赖；它不在 Worker 解码、不调用模型，也不把文件保存冒充客户端已展示。Bot/注册防护的[规划与种子](docs/BOT-UA-AUTH-GUARD-RESEARCH-DESIGN.zh-CN.md)仍按各自能力状态推进。

**Sync 0.3.0 已补齐原生站点配置与证书发布/应用。** Master 自动检查完整源快照并按 Node 加密签名，Node 验证、持久准备、热应用并等待全 Worker 确认，失败回退，结果可重报；详见 [发布手册](docs/SYNC-PUBLICATION.zh-CN.md)。这是独立的 native.snapshot.v2 协议，不与旧 Lua JWE/JWS API 混用；迁移需明确交接唯一配置写入权。

Purge 可独立加载，不依赖其他插件，也不修改 Nginx 核心或私有缓存索引。它保证新请求不命中已失效版本，**不表示立即删除磁盘文件**；旧空间仍由 Nginx 管理。接入时必须把实际 cache key 改为 `$scdn_purge_key`。

自定义客户端 IP 头统一为 `X-Clinet-IP`，Purge 控制头为 `X-Purge-Mode` / `X-Purge-Scope`；调用方需同步升级。头名与信任边界见 [HTTP 头约定](docs/HTTP-HEADERS.zh-CN.md)。

## 文档导航

- [安全与性能独立复审](docs/AUDIT-REVIEW-2026-11-16.zh-CN.md)：CNB issue #2/#3–#10 的逐项证据、修复、验证与升级约束。

- [当前文档与能力核对](docs/DOCUMENTATION-INDEX.zh-CN.md)：所有模块入口、当前功能与历史证据边界。

- [站点配置与证书加密发布/应用](docs/SYNC-PUBLICATION.zh-CN.md)：真实 Master/Node 发布、热更新、回退、身份与序号边界。
- [原生 L1/L2 分层缓存](native-tier/README.zh-CN.md)：接替 Lua 选层及维护落盘流程。

Tier 0.1.1 完善分层 ETag/Last-Modified 校验与 304 续期、路由大小限制、内部头隔离及无歧义缓存键。升级时模块和两份代理模板同时更新，并使用新链路隔离旧缓存元数据；详见 Tier 手册的升级说明。

- [缓存刷新/预热任务](docs/CACHE-TASKS.zh-CN.md)：Master 持久队列、Node 原生 mTLS 拉取、刷新/预热执行、租约与结果。
- [Sync 角色与身份接口](native-sync/README.zh-CN.md)、[安装/共存迁移](docs/SYNC-MIGRATION.zh-CN.md)、[原生化路线与缺口](docs/SYNC-ROADMAP.zh-CN.md)。
- [安装、编译和最小运行](docs/INSTALL.zh-CN.md)：依赖、独立构建、现有安装接入、权限与 ABI。
- [配置监听与完整站点语法](native-config/README.zh-CN.md)：全部指令、字段、限制、提交与失败行为。
- [业务路由、TLS、缓存和指标](native-edge/README.zh-CN.md)：全部指令、变量、请求路径与兼容边界。
- [缓存响应头与规则回源头](docs/CACHE-HEADERS.zh-CN.md)：命中状态、缓存层/策略/版本、站点/前缀配置与热更新。
- [自动 API/AI 识别与代理优化](native-api/README.zh-CN.md)：判定规则、流式配置、HTTPS 回源和连接复用检查。
- [日常操作与故障处理](docs/OPERATIONS.zh-CN.md)：原子发布、证书轮换、状态查询、回退和常见错误。
- [从旧 Lua 流程迁移](docs/MIGRATION.zh-CN.md)：字段映射、替换步骤、热更新边界。
- [验证记录](docs/VALIDATION.zh-CN.md)：实测项目、CI、内存检查及未验证范围。
- [缓存机制调研](docs/CACHE-MECHANISM.zh-CN.md)、[精确清理接入](native-purge/README.zh-CN.md)和[缓存清理基准](native-purge/bench/README.zh-CN.md)。
- [源站校验、过时复用与匹配清理调研](docs/CACHE-REVALIDATION-RESEARCH.zh-CN.md)：ETag/Last-Modified、两个 stale 窗口、规则预算与节点范围。
- [IP 封禁与 eBPF 运行模块](native-ban/README.zh-CN.md)：原生 Nginx、单写 Agent、XDP/TCX、任意设备上报及全节点完整同步、两类日志和恢复。
- [源码来源](SOURCE.md)、[公开发布规则](PUBLISHING.md)、[许可证](LICENSE)。

## 独立构建与验证

已验证 Linux x86_64、Nginx 1.31.8 与 OpenResty 1.31.8.1。构建需要 HTTP SSL 和线程池；测试使用 Python `cryptography`。在全新测试前缀中执行：

```sh
git clone https://github.com/PH-OpenResty/OpenResty_Plugin.git
cd OpenResty_Plugin
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tests/requirements.txt
sh native-sync/tests/check-core.sh
sh tools/build-runtime.sh /tmp/scdn-plugin-nginx nginx
python native-sync/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-sync-results.json
python native-sync/tests/distribution.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-distribution-results.json
python native-tier/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-tier-results.json
python native-tier/tests/boundaries.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-tier-boundary-results.json
python native-sync/tests/cache_tasks.py --prefix /tmp/scdn-plugin-nginx --tier \
  --report /tmp/scdn-tier-task-results.json
python native-tier/tests/coexist.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-six-module-results.json
python native-sync/tests/cache_tasks.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-cache-task-results.json
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-nginx-results.json
python native-api/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-api-results.json
python native-purge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-purge-results.json
python native-purge/tests/patterns.py --prefix /tmp/scdn-plugin-nginx
python native-purge/tests/revalidate.py --prefix /tmp/scdn-plugin-nginx
python native-api/tests/integration.py --prefix /tmp/scdn-plugin-nginx --purge --sync \
  --report /tmp/scdn-five-modules-results.json
```

系统构建依赖与 OpenResty 构建方式见 [安装文档](docs/INSTALL.zh-CN.md)。脚本固定下载归档并验证 SHA-256，构建七个插件，拒绝覆盖已有安装。

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

本仓库独立提供 Sync、Config、Ban、API、Edge、Tier、Purge 源码、模板、测试与构建工具。Config 的普通 watcher 保持只读；启用 scdn_config_managed 后与 Sync 的持久事务及启动回退配合。Sync 0.3.0 已负责原生 v2 站点/证书分发，Tier 负责原生层级缓存；Ban 已提供独立 Agent、XDP/TCX 和全节点 L3 同步；部署权限与明确支持范围见运行手册。自动证书签发和程序自动升级不属于本次实现。

仓库示例只使用保留域名、本机地址和通用路径。运行配置、站点数据、证书、私钥、token、日志及构建二进制应保存在受限的部署目录或忽略目录中。

当前修复把配置与应用记录纳入同一恢复事务，补充真实 I/O 故障和进程中断回归；原生模块与剩余 Lua 按功能交接，保留 WAF/限流执行，见 [Lua 交接](docs/LUA-HANDOFF.zh-CN.md)。

Ban 0.2.0 已去除 SQLite，新增直接集成到 Agent 的 [Ban Store](native-ban-store/README.zh-CN.md)。七个 HTTP 模块之外的该存储组件不增加 Nginx 加载顺序或外部存储服务。Node 可选 memory，权威 Master 保留持久化；执行容量与存储容量独立。
