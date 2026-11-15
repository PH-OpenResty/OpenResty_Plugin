# 源站校验、过时缓存复用与多种清理方式调研

调研日期：2026-11-14。依据 HTTP 标准、Nginx 官方文档及 OpenResty 1.31.8.1 所带 Nginx 1.31.8 的实际源码。本文先确定协议语义和边界，后续实现和测试按这些结论验收。

## 源站是否变化，应使用哪些请求头

| 源站响应头 | 后续校验请求头 | 判断能力 |
| --- | --- | --- |
| `ETag: "revision"` | `If-None-Match: "revision"` | 资源表示的版本标识，优先使用；源站负责正确生成 |
| `Last-Modified: ... GMT` | `If-Modified-Since: ... GMT` | 修改时间校验，通常只有秒精度，同一秒多次变化可能无法区分 |
| `Cache-Control` / `Expires` / `X-Accel-Expires` | 不直接用于内容比较 | 控制缓存新鲜期，不能证明内容相同 |
| `Vary` | 保留原请求相应维度 | 不同语言、压缩等表示必须分别校验，不能混用校验头 |
| `Content-Length` / `Date` | 不作为版本校验器 | 等长文件仍可能完全不同；响应日期不是修改时间 |

RFC 9110 §13.1.2/§13.1.3 要求源站优先处理 If-None-Match；不能把两个条件当作同时必须满足的内容相等证明。GET 条件满足时返回 `304 Not Modified`，不重传正文；不满足时正常返回 `200` 与完整新正文。HEAD 可能缺少或错误实现部分头，且不能取得新正文，不适合作为必须先执行的额外一跳。

因此采用原生条件 GET：同时保存源站提供的 ETag/Last-Modified，Nginx 已实现相应请求头生成。没有可靠校验器时重新完整 GET；不靠 Content-Length 猜测变化，也不先删除有效缓存。标准允许弱 ETag 用于缓存再校验，但它不保证压缩表示逐字节相等。如果源站错误地沿用旧 ETag/修改时间并返回 304，边缘节点无法仅凭这些头发现变化；需要修正源站版本生成，或关闭该位置的原生条件头而每次完整获取。

按用户选择，采用有访问才触发的校验间隔，不维护空闲资源轮询清单。间隔到达不代表主动发送请求：下一次符合规则的访问才触发校验。强制缓存一天和每 30 秒检查不是同时保留两套原生新鲜期：模块将内部新鲜期限制到检查间隔，复用原生过期/后台更新机制；浏览器 TTL 属于另一层，不能据此声称浏览器立即更新。

## 过时缓存何时可以复用

RFC 5861 定义两种独立的宽限期：

- `stale-while-revalidate`：过期后，在指定秒数内可先返回旧正文，并在后台校验；304 续期，200 完整写入并原子替换。宽限期结束后需要同步校验。
- `stale-if-error`：连接/超时或 500/502/503/504 等回源错误时，在指定秒数内可返回最后的可用正文；不能把错误页面写成成功的新版本，也不能因一次失败重置旧正文的年龄。

两种年龄都从内部缓存新鲜期结束算起，不能每次命中就延长。手动清理属于显式撤销：已清理的旧 epoch 绝不作为错误兜底重新暴露。401/403/404/410 及源站改为不可缓存属于撤回或内容状态变化，不等同于临时网络错误，不以失败复用掩盖；需要使该逻辑资源旧版本失效。

Nginx 的 `proxy_cache_use_stale updating/error/...` 是条件开关，不自带时间上限；不能单纯打开全部条件然后宣称有有限宽限期。实际 `ngx_http_file_cache_read` 会计算 `stale_updating`/`stale_error`，但 `ngx_http_upstream_test_next` 对部分 HTTP 错误只读取配置条件位。因此实现需要限制缓存头的 updating/error 秒数，并在当前请求的宽限期内设置对应条件，避免配置位绕过上限。缓存 `inactive` 仍可更早回收文件；复用不能恢复已回收正文。

正常 HIT 不比较正文、不读 journal、不探测源站。校验失败需要有界的跨 Worker 重试抑制，防止持续请求把故障源站压满。抑制表可以有界淘汰，因为丢失重试时间最多增加一次校验，不得影响持久失效版本。后台校验期间允许旧正文；超出宽限期的新请求要等待校验或收到真实错误，不能继续无期限返回旧值。

## 清理匹配方式

全部匹配对象是显式配置的逻辑 RESOURCE，而非凭空推断的文件系统路径。既可以使用 `$request_uri`，也可以使用稳定完整 URL；控制端必须与业务端一致。

| 模式 | 匹配约定 | 示例 |
| --- | --- | --- |
| exact / batch | 完整资源字节相等，包括查询串 | `/a.js?v=1` |
| prefix | 对完整资源按字节前缀匹配 | `/assets/` |
| wildcard | 完整资源 glob，`*` 任意字节序列、`?` 单字节，支持反斜杠转义 | `/assets/*.js*` |
| regex | 区分大小写的 PCRE2；默认搜索，使用 `^...$` 明确锚定 | `^/assets/.*\.(css\|js)(\?.*)?$` |
| suffix | 忽略查询串后，对资源路径做后缀匹配 | `.css` 可覆盖 `/a.css?v=2` |
| directory | 忽略查询串，目录本身及其下级；明确路径分隔边界 | `/assets` 不覆盖 `/assets-other/x` |
| scope / site | 失效一个站点命名空间的所有资源及变体 | 稳定站点 ID |
| all / node | 失效本实例接入模块的所有 scope、缓存区域 | 本节点所有站点 |

不做百分号解码、大小写折叠和查询参数重排，避免错误扩大清理范围。正则需要长度、编译大小和运行 match/depth/heap 预算；超预算必须拒绝或失败关闭，不能把匹配错误误当成未命中而暴露旧缓存。模式规则有容量上限，可由整站/全局失效覆盖回收。匹配规则与版本持久化，不靠扫描目录；新请求在生成 key 时选取所有匹配失效版本中的最新值。正常本地 key 缓存命中免做正则匹配；高基数流量或频繁规则变动仍会增加慢路径成本。

“整机”在一个 Nginx master 管理本节点全部缓存区时即 all/node。一个进程不能直接承诺控制另一个 master、其他用户目录或未接入版本键的缓存；多实例节点应由控制端枚举并逐实例下发，不应通过任意目录递归删除模拟整机能力。

## 更新与磁盘回收

自动更新优先让 Nginx 完整接收新响应，然后以自己的临时文件/rename/共享索引流程替换同一版本键，现有读者可读完旧文件。显式清理或源站撤回通过持久版本键失效；这类旧文件仍由 cache manager 依据 inactive/max_size 回收。避免先删旧文件、重复回源再填充和手工修改私有 cache node。后台请求在途时发生手动清理，旧 writer 继续使用它捕获的旧 epoch，不能复活已清理版本。

## 一手资料

- [RFC 9110：Last-Modified](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2)、[ETag](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3)、[If-None-Match](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.2)、[If-Modified-Since](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3)。
- [RFC 9111 §4.3：缓存校验](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3)、[§4.2.4：返回过时内容](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4)。
- [RFC 5861：stale-while-revalidate / stale-if-error](https://www.rfc-editor.org/rfc/rfc5861.html)。
- [Nginx proxy_cache_revalidate](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_revalidate)、[background_update](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_background_update)、[use_stale](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_use_stale)。
- [OpenResty 1.31.8.1 归档](https://openresty.org/download/openresty-1.31.8.1.tar.gz)：实际核对 `bundle/nginx-1.31.8/src/http/ngx_http_upstream.c` 中 cache/background_update/test_next/send_response、`ngx_http_file_cache.c` 中 read/update/update_header，以及 `modules/ngx_http_proxy_module.c` 的条件头模板。

验收应覆盖 ETag/仅 Last-Modified/无校验器、304 连续续期、200 更新、Vary、HEAD、并发单次更新、失败重试、宽限期结束、404/不可缓存、显式清理与在途更新，以及新增匹配模式的边界、容量、重启与检查点恢复。原有基准只描述原有失效功能，不自动代表新增校验/正则路径的性能。
