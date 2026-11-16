# Edge：原生业务路由、TLS、缓存选择和指标

`ngx_http_scdn_edge_module.so` 读取 [Config](../native-config/README.zh-CN.md) 的不可变活动快照，实现站点路由、最长前缀、启停、SNI、缓存层选择、可选热度和 Prometheus 指标。业务请求不依赖 Lua，模块不实现 WAF、请求限速或连接限速。

先阅读 [安装手册](../docs/INSTALL.zh-CN.md)。本仓库的 [完整 Nginx 模板](examples/nginx.conf)和[站点文件模板](../native-config/examples/sites.conf)可一起接入；公开站点模板默认停用。

## 1. 依赖与指令

业务链由 Config、API、Edge 构成，动态加载顺序为 Config → API → Edge，三者使用同一源码与目标 ABI 构建。统一构建还提供 Sync、Tier、Purge，共六个模块。运行时需要 HTTP SSL，Config 还需要线程池支持。Edge 用到 Nginx 代理/静态文件/缓存功能时，这些原生模块也必须存在。API 默认关闭，启用方式见 [API 手册](../native-api/README.zh-CN.md)。

[Sync](../native-sync/README.zh-CN.md) 的角色/身份接口不改变 Edge 站点版本，0.3.0 的配置发布通过受管 active.conf 和 Config 热更新生效。五模块共存、独立控制 token 与流式代理的验证入口是 `native-api/tests/integration.py --purge --sync`，静态构建增加 `--static`。

| 指令 | 上下文 | 默认/参数 | 作用 |
| --- | --- | --- | --- |
| `scdn_edge on\|off` | server | off | 对该 server 的请求启用活动站点路由 |
| `scdn_edge_tls on\|off` | server | off | 使用原生动态证书回调，要求同 server 的 Edge 为 on |
| `scdn_edge_proxy_location @name` | server | `@scdn_edge_proxy` | 动态回源的命名 location，必须以 @ 开头并实际存在 |
| `scdn_edge_zone NAME SIZE` | http | 启用业务时必填；示例 2m | 指标和热度共享区，上限 64MiB，最小值由结构体大小及页大小决定 |
| `scdn_edge_metrics` | location | 默认无端点 | 只读本机 Prometheus 输出，不能混用其他 content handler |

启用 Edge 的 server 同时需要有效 Config watcher 和共享区，否则配置检查失败。共享区不存放配置对象；更大的 zone 也不会突破固定指标标签和热度表数量上限。

## 2. 请求处理与变量

Nginx 先按自己的监听地址/server_name/location 选择静态配置，Edge 在启用的 server 中根据规范化 Host 查活动站点。建议使用模板中的受管理默认 server；其他未启用 Edge 的 server 仍按 Nginx 自身配置执行，不会自动受本模块接管。

未知 Host 或停用站点返回 403；Worker 尚未装入共享活动摘要时返回 503。有效站点选择最长 URI 前缀，否则使用站点默认值；有 upstream 时内部跳转到命名代理 location，无 upstream 时使用 Nginx 静态 root。一次请求固定一个快照，内部跳转不会重新取得不同版本。

| 变量 | 值与用途 |
| --- | --- |
| `$scdn_edge_site` | 当前站点 ID，用作日志、指标、缓存隔离标签 |
| `$scdn_edge_upstream` | 当前选中的 HTTP/HTTPS URL 或命名池，用于 proxy_pass |
| `$scdn_edge_origin_host` | 当前 origin_host 策略选择的回源 Host |
| `$scdn_edge_origin_sni` | 明确指定的 origin_host 或从源站推导的无端口 SNI |
| `$scdn_edge_grpc_upstream` | 将回源 scheme 转换为 grpc/grpcs，供原生 grpc_pass 使用 |
| `$scdn_edge_root` | 当前站点的绝对静态目录，用于 root |
| `$scdn_edge_cache` | 当前最终选择的 l1/l2/off；auto 根据热度求值 |
| `$scdn_edge_revision` | 请求持有的快照摘要，供缓存键和排障使用 |

在未启用 Edge 或没有匹配站点时，变量可能为 not found/空值。不要把这些变量放进先于 Edge 执行、或会结束正常访问阶段的 `return` 等静态配置中，期待它们自动代替完整路由接入。

## 3. 反代、静态文件和缓存

核心接入如下：

```nginx
server {
    listen 80 default_server;
    server_name _;
    scdn_edge on;
    location / {
        root $scdn_edge_root;
        disable_symlinks on;
    }
    location @scdn_edge_proxy {
        proxy_pass $scdn_edge_upstream;
        proxy_cache $scdn_edge_cache;
        proxy_cache_key "$scdn_edge_revision|$host|$request_uri";
        proxy_cache_valid 200 1m;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_connect_timeout 3s;
        proxy_read_timeout 30s;
    }
}
```

`l1`、`l2` 必须在 http 级别预先用 `proxy_cache_path ... keys_zone=...` 定义。off 禁用缓存，auto 由站点 tier 选择 l1/l2。zone 不存在、目录不可写或原生代理参数错误仍由 Nginx 报错，本模块不替它们修复配置。

缓存键应包含版本和 Host，防止回源或策略变更后返回旧源站内容。当前 revision 对完整源文件及有效 TLS 材料计算，因此注释、空白或证书变动也可能使整个快照换摘要；版本化缓存键会相应降低旧缓存复用。按实际需求制定容量与保留策略。

Edge 自身仍负责路由和策略选层；新增 [Tier](../native-tier/README.zh-CN.md) 实现 L1 miss 后读取 L2、热对象晋升与冷层保留，接替旧 Lua 选层/flush 流程。写入、锁、过期与清理由 Nginx 管理。支持 HTTP/HTTPS、括号 IPv6、命名 upstream 及 origin_host 字段；TLS 验证与连接池定义由原生代理配置实施。命名池成员不通过站点文件热更新。

变量 proxy_pass 的域名解析需要配置 resolver。上游连接池和 DNS 行为仍按 Nginx 变量代理语义执行，不能假定它和静态命名 upstream 的 keepalive 行为完全相同。默认保留原 URI 和查询串，匹配 prefix 不剥离路径。

## 4. TLS 证书选择

TLS server 需要本机 bootstrap 证书建立 SSL_CTX，然后由原生回调在新握手时选择 Config 已准备的站点证书：

```nginx
listen 443 ssl default_server;
ssl_certificate /etc/scdn/bootstrap.crt;
ssl_certificate_key /etc/scdn/bootstrap.key;
ssl_session_cache off;
ssl_session_tickets off;
scdn_edge on;
scdn_edge_tls on;
```

站点数据中的 certificate/key 由 Config 后台加载并验证。证书/私钥内容更新会构建新版本；新握手采用新材料，已有连接不因文件变化而关闭。回调检查 SNI、站点启用状态与证书期限，未匹配或没有有效站点 TLS 材料时拒绝握手，不把 bootstrap 当成未知站点的默认业务证书。

该回调独占管理的 SSL_CTX 证书选择；变量证书配置会被拒绝，Lua 等其他证书回调也不能在同一上下文混用。仅更新 bootstrap 文件属于 Nginx 启动配置，不应把它当作动态站点证书发布。

示例关闭 session cache/tickets，现有测试验证的是新完整握手和已有 TLS 连接。会话恢复、HTTP/2 连接合并、HTTP/3、多证书算法选择等没有被描述为完整验收。逐请求 Host 检查仍然执行；停用站点不等于立即关闭所有既有连接或执行证书撤销协议。

## 5. 热度策略

站点设置 `cache auto; tier 3 5000;` 表示固定窗口 5000ms 内同一站点、Host、规范化 URI 到达第 3 次计数时选择 l1，否则 l2。查询串不进入热度键；不同 Host 的别名也分别计数。

共享热度表固定 4096 槽，以内容摘要映射到固定槽；冲突、窗口结束会重置。它是有界的缓存选择提示，不保证完整统计或严格滑动窗口，不用于安全限流、计费和配额。配置版本切换不自动清空全部热度，改变参数后的行为会受保留计数影响。客户端访问量不因此被拒绝。

## 6. Prometheus 指标

配置本机 endpoint：

```nginx
server {
    listen unix:/run/scdn-edge/control.sock;
    location = /status { scdn_config_status; }
    location = /metrics { scdn_edge_metrics; }
}
```

真实传输必须来自 Unix Socket 或 loopback。GET/HEAD 可用，非空查询或请求体返回 400，其他方法返回 405，非本机连接返回 403。无内置 bearer token；通过受限 Socket 父目录或额外 Nginx 访问层控制读取。指标不输出配置正文、源站或证书材料。

| 指标 | 标签 | 含义 |
| --- | --- | --- |
| `scdn_edge_requests_total` | site | 每站点主请求数量 |
| `scdn_edge_bytes_total` | site | 按当前 Nginx 请求结束时发送计数累加的字节量 |
| `scdn_edge_responses_total` | site, class | 0xx～5xx 状态分类 |
| `scdn_edge_cache_requests_total` | site, status | none/MISS/BYPASS/EXPIRED/STALE/UPDATING/REVALIDATED/HIT |

内部跳转不应重复计数；子请求不独立增加主请求计数。没有匹配到站点的请求不创建 `_unknown` 标签。更新后新请求和仍在运行的旧请求可累加到同一站点 ID 的计数器，指标不按 revision 拆标签。

最多保留 1024 个历史站点 ID，删除站点不会立即清除其计数；达到上限时新 ID 不再增加指标，但业务仍可运行。没有 reset API 或在线回收。普通手工 Nginx reload 可复用相同结构的共享计数，进程重启/新 zone 会重置；程序版本改变共享结构时需重新规划 zone，不能假定跨任意实现兼容。

计数使用原子操作，抓取不是所有计数的事务快照。HTTP/2/HTTP/3 的字节与请求边界需要另外验证；当前指标不作为精确计费保证。

## 7. 变更、恢复和迁移

日常只修改完整站点文件，不修改生成的 `.lua`、`.ljbc` 或 server/location 片段。使用 [操作流程](../docs/OPERATIONS.zh-CN.md)观察 ready、revision、错误码和真实业务请求。配置就绪不代表源站可达；业务健康需外部按站点需求检测。

旧 Lua 的注册表、SNI、指标、热度由这两个模块接管，旧配置写入/编译管理链路不随本仓库发布。字段迁移及 WAF/限速的处理见 [迁移手册](../docs/MIGRATION.zh-CN.md)。

## 8. 测试与支持边界

在仓库根目录：

```sh
sh tools/build-runtime.sh /tmp/scdn-plugin-nginx nginx
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-results.json
```

运行时也可为 openresty。测试创建临时证书、源站、Unix Socket 和两个真实 Worker，退出后清理。详细验证内容、ASan/UBSan 设置和未验证项见 [验证记录](../docs/VALIDATION.zh-CN.md)。远程站点/证书发布与回退由 [Sync 0.3.0](../docs/SYNC-PUBLICATION.zh-CN.md) 承担，Edge 继续读取 Config 的活动快照。

## HTTP 头与缓存任务联动

自定义客户端 IP 头统一采用 `X-Clinet-IP`，代理端从可信的 `$remote_addr` 覆盖；Purge 使用 `X-Purge-Mode` / `X-Purge-Scope`。完整命名与信任边界见 [HTTP 头约定](../docs/HTTP-HEADERS.zh-CN.md)。Sync 0.3.0 保留的缓存刷新/预热任务及配置同步的边界见 [缓存任务手册](../docs/CACHE-TASKS.zh-CN.md)。

## 原生缓存头

Edge 按当前请求持有的配置版本生成 `X-Cache`、`X-Cache-Layer`、`X-Cache-Policy` 和 `X-Cache-Revision`，站点/prefix 的 `cache_headers off;` 可关闭。删除已有同名 add_header，避免重复。规则的静态回源头在 proxy_pass 前替换客户端全部同名值；站点/前缀继承、私有绕过、Nginx 固定 proxy_set_header 的优先级及 HTTP/gRPC 边界见 [缓存头手册](../docs/CACHE-HEADERS.zh-CN.md)。

Edge 现在以 HTTP_FILTER 类型注册，确保静态和动态构建均在 Nginx 基础 header filter 之后接入原生缓存诊断；动态加载仍保持 Config → API → Edge，三个模块需同源码版本一起编译。

## 原生策略与保留 Lua 的衔接

`$scdn_edge_security` 从当前请求持有的原生快照提供安全策略，`$scdn_edge_security_checked` 由已配置的安全处理器成功检查后置 1。策略开启但未经过处理器时，内容阶段返回 503。新桥接器不查询旧 Lua registry；详见 [Lua 交接](../docs/LUA-HANDOFF.zh-CN.md)。

`scdn_edge_tls_fallback on` 可显式保留未知/无 SNI 的 bootstrap 证书行为，默认 off。它要求 `scdn_edge_tls on`；HTTP Host 仍由 Edge 检查，已配置站点的过期或不可用证书不会降级。迁移后移除 Lua SSL 回调。
