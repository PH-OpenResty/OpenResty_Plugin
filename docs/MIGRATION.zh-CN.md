# 从旧 Lua 配置管理迁移

目标是把业务请求和本机配置检测迁入两个纯 C 插件，直接读取受限的完整站点数据文件；不再依赖 Lua 生成配置、源码写入、LuaJIT 字节码编译或 reload 管理接口。

## 1. 能力对应

| 旧组件/行为 | 新入口 | 注意事项 |
| --- | --- | --- |
| `lib.registry`、`sites/*.lua/*.ljbc` | Config 完整快照和 Host 查询 | 数据文件不是可执行 Lua，不扫描旧 `.ljbc` |
| `lib.route` | Edge + 原生 proxy/static location | prefix 是最长字节前缀，保留 URI/查询串 |
| `lib.sni` | Config 预加载 + Edge 证书回调 | 路径变更和同路径内容替换均需验证，所有 Host 要有 DNS SAN |
| `lib.metrics` | Edge 本机指标 | 指标名与标签需更新仪表盘，不能假定兼容旧面板 |
| `tier.lua` | cache auto + tier | 有界固定窗口，按站点/Host/URI 隔离，不是严格滑动窗口 |
| sitectl、panel/admin、旧集群 Agent | 外部发布者原子交付完整数据文件 | 不提供等价文件写入 API 或自动生成工具 |
| 缓存复制/reload 辅助脚本 | Nginx 管理各 cache zone | 不复制 L1/L2 文件，不实施多层 miss 回退 |
| Lua WAF、限速和连接字段 | 不在这两个插件内迁移 | 需要时独立配置 Nginx 或外部能力，不能以字段保留冒充功能已实现 |

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
| 空字符串字段 | 省略对应可选字段，不写空引号占位 |
| `waf`、`rate_limit`、`port_forward`、`live` | 不复制；新语法会拒绝未知字段 |

每个站点仍需至少一个 Host，以及 root/upstream 至少一个。HTTPS/IPv6 回源、泛域名、多源站池和任意 Nginx 参数不能通过机械替换字段获得支持。

## 3. 推荐迁移步骤

1. 记录现有 Nginx 构建、模块、业务配置、站点集合、证书和可验证的回退点。
2. 在独立目录与端口构建两个插件；先验证 Config/Edge 的测试和完整示例。
3. 从可信配置来源导出完整站点文件，逐个核对 Host、回源、root、缓存和证书；不要执行不可信 Lua 来转换数据。
4. 使用真实 Worker 账户核对全部文件和父目录可读，缓存/运行目录可写，消除旧证书 symlink 路径依赖。
5. 在隔离实例观察状态、业务 HTTP/TLS、缓存与指标；对照启停、删除、证书轮换及回退行为。
6. 计划切换时为每个托管范围指定唯一的权威发布者，停止旧文件生成、编译及写入流程，再接入原生配置消费。
7. 保留原版本和已知有效输入以便恢复，按业务灰度策略扩大接入范围。

不能让旧 Lua Agent、面板和外部发布者同时写同一站点数据源。旧 `.admin_token`、registry reload API 与新只读 status/metrics 不属于相同接口，不应继续由旧 CLI 触发。

## 4. 与 Sync 的关系

本仓库没有包含 Master/Node 身份模块、Node 拉取、JWE/JWS、HTTP 请求签名、journal、ACK 报告或发布编排。外部 Sync 可以在完成自身认证/验证之后交付站点文件，但端到端协议安全、持久化、远程失败报告和回退由该系统负责。

Config 的 generation/revision 用于本机内存版本选择，不能代替 Sync 的单调序号、防重放或节点授权。业务 health 与本机 ready 也需分别观察。

## 5. 验收范围

站点文件支持的字段可在 Worker 不重建的情况下切换；Nginx 启动参数和模块程序仍需 reload/重启。旧缓存对象按原策略淘汰，新版本 cache key 可能隔离旧数据。现有 TLS 连接不会强制断开，完全重启必须有磁盘有效输入。

完成迁移应以实际站点和目标运行时验收为准，不把测试环境的 47 项检查推导为生产容量、所有协议或全部业务配置已覆盖。
