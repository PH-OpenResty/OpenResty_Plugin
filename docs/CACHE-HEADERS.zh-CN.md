# 缓存响应头与规则回源请求头

Config/Edge 增加站点和前缀规则的 HTTP 头配置。规则随站点快照热更新；新请求采用新版本，已在途请求保留原版本。诊断响应头使用无产品前缀的名称，回源请求头是静态元数据，不接纳客户端自报身份。

## 响应头

`cache_headers on|off;` 可以放在 site 或 prefix。站点默认 on，前缀继承站点；可以在子规则关闭。Edge 原生输出：

| 响应头 | 含义 |
| --- | --- |
| `X-Cache` | 实际 MISS/HIT/BYPASS/EXPIRED/STALE/UPDATING/REVALIDATED；没有使用缓存时为 OFF |
| `X-Cache-Layer` | 实际选择的 l1/l2；未使用缓存或绕过时为 off |
| `X-Cache-Policy` | 当前规则配置的 l1/l2/auto/off，与本次命中状态分开 |
| `X-Cache-Revision` | 本次请求持有的站点配置内容摘要；不暴露站点正文、源站地址或缓存键 |

这些是观测信息，不控制浏览器 TTL，不自动改写源站 `Cache-Control`、`ETag`、`Last-Modified`、`Vary` 或 Nginx 缓存有效期。API/AI、认证、Cookie 和流式策略继续绕过缓存，不因配置了请求头而变为可缓存。cache_headers off 只关闭 Edge 生成的诊断；源站自己返回的同名头需要通过 proxy_hide_header 另行处理。

Edge 输出时替换源站同名诊断头。原有 Nginx `add_header X-Cache ...` 等配置需删除，避免后续 headers_filter 再添加第二份；普通 `X-Clinet-IP` 的回源设置保留。只加载 Purge 时仍需 Nginx 的 `add_header X-Cache $upstream_cache_status always;`；Purge 不依赖 Edge。

## 回源请求头

在 site 内使用 `cache_request_header NAME VALUE;`，最多 8 个，名称 3～64 字节，值最多 1024 字节。为保持热更新不碰 HTTP 协议和身份控制，仅允许由 ASCII 字母、数字和连字符组成的 `X-` 自定义字段；不支持标准 Host/Authorization/Cookie/Connection/Content-Length，也拒绝客户端 IP、转发链、API key、X-Accel 控制和已废弃产品前缀。值按原始文本发送，`$name` 不执行变量替换，不允许 CR/LF/控制字符。

站点列表默认被前缀继承；前缀出现自己的 cache_request_header 后替换整份列表。前缀可用 `cache_request_headers off;` 禁用继承列表。名称不区分大小写，同层重复名称拒绝。可设置缓存标签或源站的非敏感元数据，例如：

```nginx
sites {
    site demo {
        host www.example.com;
        upstream http://127.0.0.1:8080;
        cache l1;
        cache_headers on;
        cache_request_header X-Cache-Tag "public-assets";
        cache_request_header X-Cache-Policy "static-default";

        prefix /images/ {
            upstream http://127.0.0.1:8080;
            cache l2;
            cache_request_header X-Cache-Tag "images";
        }
        prefix /private/ {
            upstream http://127.0.0.1:8080;
            cache off;
            cache_headers off;
            cache_request_headers off;
        }
    }
}
```

列表适用于该站点/路由的 HTTP 代理请求，即使某次因私有/API 策略绕过缓存，仍可向源站传递所配置的静态元数据。它不实现客户端请求头匹配规则。源站内容会随这些字段改变时，必须使用示例中含 `$scdn_edge_revision` 的缓存 key，使一次配置变更得到新缓存命名空间；部署自行移除 revision 后，不能依靠新增头防止旧对象被错误复用。

模块在路由转入 proxy_pass 前过滤全部客户端同名字段，再添加唯一配置值，避免重复值绕过；其余客户端字段与实际身份保持原流程。Nginx 固定 `proxy_set_header` 的同名字段优先，不能把同一字段同时交给两种配置管理；`proxy_pass_request_headers off` 会阻止该列表传给源站。此功能覆盖 Edge 选择的 HTTP proxy 路径，不宣称已覆盖 grpc_pass、自定义 Lua 代理或不经过 Edge 的独立入口。

配置文件可能包含私有运行元数据，真实值不提交 Git；本功能也不用于密钥分发。值会出现在回源请求，需按站点权限管理。改变允许列表、字段或响应开关不重建 Worker；错误候选被拒绝并保留旧活动快照。

## 验证

`python native-edge/tests/cache_headers.py --prefix /isolated/runtime`；静态编入时加 `--static`。真实进程检查覆盖 MISS/HIT、伪造源站诊断覆盖、客户端重复字段、站点/前缀继承、关闭、API/私有绕过、非法配置和不重建 Worker 的更新。它不证明任意第三方模块的过滤顺序或所有自定义缓存 key 配置均正确。
