# API：自动识别与代理优化

`ngx_http_scdn_api_module` 是纯 C 的 Nginx/OpenResty 模块。它自动识别普通动态 API、AI API、SSE/NDJSON、gRPC 和 WebSocket，再选择对应代理配置。它在请求进入源站前判定，在收到上游响应头后补判；请求路径不执行 Lua，不调用外部识别服务，不记录 Prompt 或密钥。

本模块实现自动识别、缓存绕过、响应流转发、超时配置接入、客户端取消处理及 HTTPS 连接复用身份检查。网络选路、厂商密钥托管、模型协议转换、回答缓存和推理算力不在本版本范围内。

## 接入方式

与同一源码版本的 Config、Edge 一起构建。动态加载顺序为 Config → API → Edge；静态编入时无需 `load_module`。统一构建还包含独立的 Purge 和 [Sync](../native-sync/README.zh-CN.md)，共五个模块，支持纯 Nginx 和完整 OpenResty。Sync 角色与其本机鉴权不参与 API/AI 分类。

```nginx
load_module modules/ngx_http_scdn_config_module.so;
load_module modules/ngx_http_scdn_api_module.so;
load_module modules/ngx_http_scdn_edge_module.so;
```

新 Edge 在内部跳转之前调用 API 的原生识别接口，因此即使模块阶段注册顺序不同，也会先完成必要判定再选择代理 location。请求上下文保存在请求池中，命名 location 的内部跳转不会丢失判定结果或重复读取正文。

将 [proxy-common.conf](examples/proxy-common.conf) 安装为 `/etc/scdn/proxy-common.conf`，在每个 Edge 管理的业务 server 中包含 [profiles.conf](examples/profiles.conf)。这个模板替代原来的 `@scdn_edge_proxy` 定义，不能再同时保留同名 location。按实际操作系统调整 CA 证书路径。

```nginx
http {
    # 保留现有 Config、Edge、cache zone 和 DNS resolver 配置。
    scdn_api_zone api_counters 64k;
    server {
        listen 80;
        scdn_edge on;
        include /etc/scdn/profiles.conf;
        location / { root $scdn_edge_root; }
    }
    server {
        listen unix:/run/scdn-edge/control.sock;
        location = /api-metrics { scdn_api_metrics; }
    }
}
```

如果保留现有自定义代理配置，需要同时接入 `proxy_cache_bypass $scdn_api_skip_cache;`、`proxy_no_cache $scdn_api_skip_cache;`，并在缓存键加入 `$scdn_api_cache_namespace`。命名 profile 负责首包前的超时、取消与重试策略；响应过滤器负责收到上游响应后的补判和流式处理。只启用 C 模块而不接入配置，不能保证首包前就使用 AI 的长等待时间，也不能撤回旧缓存文件已经返回的内容。

已经启用 [Purge](../native-purge/README.zh-CN.md) 的缓存 location 应保留 `$scdn_purge_key`，把 API 命名空间加入它的原始 key，继续以请求 URI 作为规则匹配资源。例如在已有 Purge zone/journal 配置下：

```nginx
scdn_purge_key $scdn_edge_site "$scdn_api_cache_namespace|$scdn_edge_revision|$host|$request_uri" $request_uri;
proxy_cache_key $scdn_purge_key;
proxy_cache_bypass $scdn_api_skip_cache;
proxy_no_cache $scdn_api_skip_cache;
```

可用 `native-api/tests/integration.py --purge` 验证 API、流式与 Purge/回源再验证同时启用；原 Purge 的三套测试继续单独运行。静态构建时两类测试均使用 `--static`。

再增加 `--sync` 可验证五模块同实例启用：独立 Sync token、Node 角色/能力接口与业务代理、缓存、Purge 同时工作；它不把本机 watcher 的成功误报为远程同步 applied。CI 的组合命令为 `--purge --sync`，Sync 的角色/节点 mTLS 另有独立测试。

不使用 Edge 时，可以在入口 location 设置 `scdn_api_dispatch on;`，由 API 模块跳转到配置的命名 profile；各 profile 自行使用固定或其他受信变量指定源站。Edge 管理的入口不需要该指令。

## 自动判定规则

| 信号 | 判定 | 行为 |
| --- | --- | --- |
| 非 GET/HEAD、JSON 请求类型/Accept、XHR、`/api/`、`/v1/`、GraphQL | `api` | 动态 API profile，绕过共享缓存 |
| 常见模型端点，或 `anthropic-version` 请求头 | `ai` | AI profile，绕过缓存、关闭响应聚合与 gzip、较长等待时间 |
| 小型完整 JSON 对象，顶层同时有 `model` 与 `messages`/`input`/`prompt` | `ai` | 在转发前识别自定义路径的常见 AI 请求结构 |
| `Accept: text/event-stream` | `stream` | 进入流式 profile，不据此单独认定为 AI |
| 上游 `text/event-stream`、`application/x-ndjson`、`application/json-seq` | 流式补判 | 禁止缓存，关闭上游响应缓冲并及时 flush；已有 AI 标签保留 |
| 上游 JSON 响应、请求阶段没有 API 信号 | `api` 补判 | 禁止本次响应进入共享缓存 |
| `Content-Type: application/grpc` 或 `application/grpc+...` | `grpc` | 交给原生 `grpc_pass` profile，保留二进制消息和 trailers |
| WebSocket Upgrade | `websocket` | HTTP/1.1 Upgrade profile，保留双向数据通道 |
| 缺少以上信号 | `web` | 保留普通站点代理和公共资源缓存能力 |

模型端点包括常见 Chat Completions、Responses、Messages、Embeddings、图片/音频接口、Ollama `/api/chat` 和 `/api/generate`，以及 Gemini `:generateContent` / `:streamGenerateContent`。匹配规范化 URI 的大小写敏感端点后缀，不在任意正文字符串里搜索这些词。

这是可解释的协议与结构识别，不是业务语义证明。自定义二进制协议、压缩请求体、大型或分块 JSON、非标准字段、完全不透明的接口，可能只能判为普通 API；收到 SSE 也不能证明使用了 AI。识别结果只用于代理策略，不作为授权、计费或安全白名单。

## 正文检查边界

默认仅预读有已知 Content-Length、未压缩、声明为 JSON 且不超过 16 KiB 的请求体。上限可调至 64 KiB，设置为 0 可停用。已识别的 AI/gRPC/WebSocket 不需要为了分类再次读取正文。

预读使用 Nginx 异步 request-body API；解析只访问内存中的 buffer，不自行读取临时文件。若请求体已经落到临时文件、超过限制、使用 chunked 或 Content-Encoding，则跳过正文识别，继续按其他信号处理。模块不改写请求 buffer 的读指针，转发的正文和方法保持原样。

JSON 扫描验证完整结构、UTF-8、转义、数值与嵌套边界，仅保留顶层字段信号。最大嵌套深度为 32，不把字符串内容或嵌套 metadata 内的同名字段当作顶层信号。超出判定能力的正文不会因识别失败被模块拒绝；应用仍按自己的协议校验它。

## 配置与变量

| 指令 | 作用域 | 默认 | 含义 |
| --- | --- | --- | --- |
| `scdn_api on\|off` | http/server/location | off | 启用本模块 |
| `scdn_api_inspect_body SIZE` | http/server/location | 16k | 正文检查上限，0～64k |
| `scdn_api_stream_timeout TIME` | http/server/location | 600s | 响应补判为流式后使用的回源读空闲超时，1s～1h |
| `scdn_api_dynamic_location @name` | http/server/location | 空 | 普通 API profile |
| `scdn_api_ai_location @name` | http/server/location | 空 | AI profile |
| `scdn_api_stream_location @name` | http/server/location | 空 | 普通流式 profile |
| `scdn_api_grpc_location @name` | http/server/location | 空 | gRPC profile |
| `scdn_api_websocket_location @name` | http/server/location | 空 | WebSocket profile |
| `scdn_api_dispatch on\|off` | location | off | 不使用 Edge 时的独立命名跳转 |
| `scdn_api_zone NAME SIZE` | http | 无 | 可选共享指标区，最少 8 个内存页、最大 1 MiB |
| `scdn_api_metrics` | location | 无 | 本机只读 Prometheus 端点，需共享区 |

profile 未配置时使用 Edge 原有的代理 location。不要把不存在的 location 名作为配置值；Nginx 在跳转时会拒绝不存在的目标。启用 `dispatch` 的入口应把代理策略放在相应命名 location 中。

| 变量 | 内容 |
| --- | --- |
| `$scdn_api_kind` | `web/api/ai/stream/grpc/websocket` |
| `$scdn_api_reason` | `default/request_api/accept_sse/ai_endpoint/json_schema/grpc_content_type/websocket_upgrade/response_stream/response_json` |
| `$scdn_api_skip_cache` | 非公共 web 请求或携带身份/禁止缓存信号时为 1，否则 0 |
| `$scdn_api_stream` | 已有明确流式信号时为 1，否则 0；AI 非流式调用也可为 0 |
| `$scdn_api_connection` | WebSocket 时为 `upgrade`，其他请求为空 |
| `$scdn_api_cache_namespace` | `api-policy-v1`，用于隔离启用新规则之前的旧缓存 |

`Authorization`、`Proxy-Authorization`、`Cookie`、`X-API-Key`、`Api-Key`、`Cache-Control: no-cache/no-store`、`Pragma: no-cache` 或携带请求正文，都会禁止共享缓存命中与写入。上游自己的 `Set-Cookie`、`Vary` 和 Cache-Control 仍由 Nginx 原生规则处理，不应在其他配置中强制忽略这些头。

## 流式、超时与取消

模板中普通 web 回源读空闲超时为 30s，API 为 60s，AI/流式/WebSocket 为 600s。它们是读取空闲超时，不是整个模型任务最长执行时间。SSE 心跳与有效 Token 也不等价。

已识别的 AI/流式请求使用 `proxy_buffering off`、`proxy_request_buffering off`、`proxy_ignore_client_abort off` 和 `proxy_next_upstream off`。因此不会为了缓存继续消费客户端已经取消的模型回答，也不会因模块自动重试重复发起生成任务。源站是否停止实际推理，仍取决于应用如何处理连接取消。

补判流式的响应会在发送响应头后、Nginx 选择缓冲/非缓冲转发路径之前，切换当前请求的 upstream 状态。需要改动超时等字段时复制一份请求级 upstream 配置，不修改 location 共享配置。输出数据块会显式标记 flush；不注入心跳、不改写 Token、不增加完整响应聚合。

模板向上游发送空 Accept-Encoding，使路径未知的 SSE 也能直接流式转发；普通内容仍可由边缘 gzip。这个选择会减少上游压缩收益，应根据回源带宽评估。额外 Brotli/Zstd/应用压缩仍需要在相应 profile 中确认关闭或支持正确的流式刷新，不能仅凭本模块的 gzip 处理推定兼容所有过滤器。

## HTTPS 源站与连接池

Config 现在支持 HTTP、HTTPS、默认端口、带括号 IPv6 地址和预先声明的命名 upstream。可在站点或 prefix 设置 `origin_host auto;` 自动采用源站 authority，或填写明确 Host。省略时保留旧 CDN 的客户端 Host 行为；默认 SNI 从源站解析，明确 `origin_host` 同时用于 SNI。

```nginx
upstream model-pool {
    server api.example.com:443;
    keepalive 64;
    keepalive_requests 1000;
    keepalive_timeout 60s;
}
```

对应站点快照：

```nginx
sites {
    site model {
        host ai.example.com;
        upstream https://model-pool;
        origin_host api.example.com;
        cache off;
    }
}
```

命名池由 Nginx 启动配置预先声明，复用由原生 upstream keepalive 管理。直接变量 URL 不自动获得这样的连接池。新增池或修改池成员仍按 Nginx 自身配置流程操作，不能把站点快照的热更新视为池定义热更新。

本模块为启用了 API 的命名池请求增加复用检查：HTTP/TLS 模式、实际 SNI、当前 SSL_CTX 与证书验证结果需要匹配。发现旧连接身份不符合本次请求时，丢弃该缓存连接并重新建连，重新执行当前证书验证。动态客户端证书不复用旧连接。

原生 peer 的 TLS session 缓存没有动态 SNI/客户端证书分区键，因此这些身份使用变量时不取用或保存旧 TLS session；已有且身份匹配的连接仍可复用。固定身份的 TLS session reuse 继续使用 Nginx 的实现。CA、客户端证书与上游池应按受信业务边界配置。

`proxy_ssl_verify on`、CA 文件和正确 SNI 是模板的一部分。Nginx/OpenResty 的客户端 HTTP/2/HTTP/3、TLS 参数与已有压缩模块仍由原生配置管理；本模块不自动探测并切换源站协议版本。默认 HTTP 代理使用 1.1，gRPC 使用原生 HTTP/2 上游。

## 观测与验证

可在原访问日志添加 kind、reason、stream 和 upstream timing；不要加入请求体或鉴权值。共享指标只有固定类型标签：`scdn_api_requests_total{kind="..."}` 与 `scdn_api_stream_requests_total`，不以模型名、URI、用户或 Prompt 建立标签。

指标端点只接受实际来自 Unix Socket 或 loopback 的 GET/HEAD，拒绝查询串、请求正文和其他方法。未配置共享区时返回 503；不要把它当成外部公开接口。

```sh
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-edge-results.json
python native-api/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-api-results.json
```

真实进程测试覆盖 API/AI 结构识别、混淆输入、正文完整性、异步读取、缓存绕过、SSE 首段延迟、HTTP/2 多路复用、gRPC 二进制与 trailers、WebSocket 双向数据、连接取消、TCP 复用、HTTPS/SNI 验证与热更新。测试不调用真实模型厂商，不证明所有外部模型协议或高负载容量；精确结果见 [验证记录](../docs/VALIDATION.zh-CN.md)。

## HTTP 头与缓存任务联动

自定义客户端 IP 头统一采用 `X-Clinet-IP`，代理端从可信的 `$remote_addr` 覆盖；Purge 使用 `X-Purge-Mode` / `X-Purge-Scope`。完整命名与信任边界见 [HTTP 头约定](../docs/HTTP-HEADERS.zh-CN.md)。Sync 0.2.0 的缓存刷新/预热任务及原生配置同步的边界见 [缓存任务手册](../docs/CACHE-TASKS.zh-CN.md)。

Config/Edge 已支持 [缓存响应头与规则回源头](../docs/CACHE-HEADERS.zh-CN.md)。与 Edge 共用时由原生响应过滤器输出 X-Cache，删除重复 add_header；仅 Purge 独立使用时仍按原模板设置 X-Cache。API/私有/流式绕过优先，配置头不提供缓存权限。
