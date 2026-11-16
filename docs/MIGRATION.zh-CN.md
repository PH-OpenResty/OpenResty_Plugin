# 从旧 Lua 配置管理迁移

目标是把业务请求和本机配置检测迁入纯 C 插件，直接读取受限的完整站点数据文件；新增 API 模块负责动态 API、AI 与流式请求判定。独立部署不依赖 Lua 生成配置；已有 SCDN 的受信冷发布适配器可以继续交付快照。

## 1. 能力对应

| 旧组件/行为 | 新入口 | 注意事项 |
| --- | --- | --- |
| `lib.registry`、`sites/*.lua/*.ljbc` | Config 完整快照和 Host 查询 | 数据文件不是可执行 Lua，不扫描旧 `.ljbc` |
| `lib.route` | Edge + 原生 proxy/static location | prefix 是最长字节前缀，保留 URI/查询串 |
| `lib.sni` | Config 预加载 + Edge 证书回调 | 路径变更和同路径内容替换均需验证，所有 Host 要有 DNS SAN |
| `lib.metrics` | Edge 本机指标 | 指标名与标签需更新仪表盘，不能假定兼容旧面板 |
| `tier.lua` | cache auto + tier | 有界固定窗口，按站点/Host/URI 隔离，不是严格滑动窗口 |
| sitectl、panel/admin、旧集群 Agent | 外部发布者原子交付完整数据文件 | 不提供等价文件写入 API 或自动生成工具 |
| Sync Master/Node 角色、身份登记 | native-sync | 仅角色/鉴权/能力发现；完整旧同步仍保留 |
| 缓存复制/reload 辅助脚本 | Nginx 管理各 cache zone | 不复制 L1/L2 文件，不实施多层 miss 回退 |
| Lua WAF、限速和连接字段 | 不由这些原生模块迁移 | 需要时独立配置 Nginx 或外部能力，不能以字段保留冒充功能已实现 |

## 2. 字段转换

| 旧站点字段 | 新站点数据 |
| --- | --- |
| `name` / `site_id` | `site ID { ... }`，用稳定合法 ID |
| `server_names = {...}` | 多个 `host name;`，转为小写 ASCII 精确 Host |
| `enabled = true/false` | `enabled on/off;` |
| `upstream = '127.0.0.1:8080'` | `upstream http://127.0.0.1:8080;` |
| `root = '/srv/sites/demo'` | `root /srv/sites/demo;` |
| `cache.layer` | `cache l1/l2/off;`，auto 另需 tier |
| `ssl.cert/key` | `certificate ...; certificate_key ...;` 成对填写 |
| `locations[].prefix/upstream/cache` | `prefix /api/ { upstream ...; cache ...; }` |
| `origin_host` / `locations[].origin_host` | 站点或 prefix 的 `origin_host auto/NAME;` |
| 空字符串字段 | 省略对应可选字段，不写空引号占位 |
| `waf`、`rate_limit`、`port_forward`、`live` | 不复制；新语法会拒绝未知字段 |

每个站点仍需至少一个 Host，以及 root/upstream 至少一个。HTTPS/IPv6 URL 可保留；HTTPS 还需配置正确的 Host、SNI、CA 验证。命名池需预先声明，泛域名及任意 Nginx 参数不能通过机械替换字段获得支持。

## 3. 推荐迁移步骤

1. 记录现有 Nginx 构建、模块、业务配置、站点集合、证书和可验证的回退点。
2. 在独立目录与端口使用统一六模块构建，先验证需要启用的业务模块；Sync 单独验证角色/mTLS，Purge 单独验证持久失效。
3. 从可信配置来源导出完整站点文件，逐个核对 Host、回源、root、缓存和证书；不要执行不可信 Lua 来转换数据。
4. 使用真实 Worker 账户核对全部文件和父目录可读，缓存/运行目录可写，消除旧证书 symlink 路径依赖。
5. 在隔离实例观察状态、业务 HTTP/TLS、缓存与指标；对照启停、删除、证书轮换及回退行为。
6. 计划切换时为每个托管范围指定唯一的权威发布者，停止旧文件生成、编译及写入流程，再接入原生配置消费。
7. 保留原版本和已知有效输入以便恢复，按业务灰度策略扩大接入范围。

不能让旧 Lua Agent、面板和外部发布者同时写同一站点数据源。旧 `.admin_token`、registry reload API 与新只读 status/metrics 不属于相同接口，不应继续由旧 CLI 触发。

## 4. 与 Sync 的关系

Sync 0.3.0 已提供站点/证书的原生加密发布、Node 拉取、受管热应用和回退。它使用独立 native.snapshot.v2，不直接兼容旧 Lua JWE/JWS/HTTP nonce 协议；按 [Sync 迁移](SYNC-MIGRATION.zh-CN.md)在独立目录验收后交接唯一配置写入权。

Config 的 generation/revision 用于本机内存版本选择，不能代替 Sync 的单调序号、防重放或节点授权。业务 health 与本机 ready 也需分别观察。

## 5. 验收范围

站点文件支持的字段可在 Worker 不重建的情况下切换；Nginx 启动参数和模块程序仍需 reload/重启。旧缓存对象按原策略淘汰，新版本 cache key 可能隔离旧数据。现有 TLS 连接不会强制断开，完全重启必须有磁盘有效输入。

完成迁移应以实际站点和目标运行时验收为准，不把测试环境的 47 项检查推导为生产容量、所有协议或全部业务配置已覆盖。

## 缓存任务及 HTTP 头升级

Sync 0.3.0 保留的持久化缓存任务投递、状态、删除、Node 后台执行及故障恢复见 [缓存任务手册](CACHE-TASKS.zh-CN.md)。刷新成功再提交预热，不能假定队列顺序。原生配置发布按独立协议交接，不能与旧流程同时写入受管目录。代理头采用 `X-Clinet-IP`，Purge 控制调用方同步切换为 `X-Purge-Mode` / `X-Purge-Scope`，见 [HTTP 头约定](HTTP-HEADERS.zh-CN.md)。

## 缓存头升级

站点/前缀缓存策略可增加 cache_headers、cache_request_header，继承和优先级见 [手册](CACHE-HEADERS.zh-CN.md)。删除旧 X-Cache 等重复 add_header，缓存 key 保留配置 revision；错误候选仍保留旧活动版本。Ban 的节点本地设计已改为 [全节点完整有效表合同](../native-ban/design/CLUSTER-SYNC.zh-CN.md)，跨机运行实现仍待对应 Agent/执行器完成。

旧 tier.lua 和 flush_l1_to_l2.lua 的原生替代是 [Tier](../native-tier/README.zh-CN.md)：L1 miss 读取 L2、L2 miss 回源、热对象晋升、冷层副本保留；不再需要维护时扫描拷贝活动缓存文件。

## 原生模块与 Lua 的功能交接

只让已由模块接管的 Lua 实现退出运行路径；保留 WAF/限流及未被替代的其他 Lua。新的类型化策略、security_guard 桥接器、一次性转换和暂存清理工具见 [Lua 交接](LUA-HANDOFF.zh-CN.md)。必须同时退出旧 registry/native_export 的启动写入与 Lua SNI 回调，不能只停 timer。
