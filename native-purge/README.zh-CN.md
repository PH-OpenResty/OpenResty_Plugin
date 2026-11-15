# 原生缓存清理、源站再校验与有界过时复用

`ngx_http_scdn_purge_module.so` 是独立的纯 C 模块，用持久化版本键实现缓存内容失效。它不依赖 Lua、Config/Edge 模块或 Nginx 核心补丁；只有接入 `$scdn_purge_key` 的缓存位置受保护。

已实现：完整资源字节匹配、最多 256 项批量、前缀、通配符、PCRE2 正则、后缀、目录、整站 scope/site、可选全局 all/node、Vary 隔离、旧 writer 版本隔离、后台日志持久化/检查点，以及按访问触发的源站条件 GET 和有时间上限的过时缓存复用。缓存机制见 [原设计依据](../docs/CACHE-MECHANISM.zh-CN.md)，本次扩展依据见 [源站校验与 stale 调研](../docs/CACHE-REVALIDATION-RESEARCH.zh-CN.md)。

**成功表示新请求不能命中旧版本，不表示磁盘文件已经删除。** API 明确返回 `physical_deleted=false`；旧文件仍由 Nginx 的 inactive/max_size 管理回收。这里不通过目录删除获取空间，也不修改 Nginx 内部 size/count/deleting 字段。

## 1. 构建与接入

统一构建脚本现在同时编译三个插件，也可以只使用本模块目录构建动态模块。需要 Linux 64 位、PCRE2 开发库、HTTP SSL/OpenSSL 和线程池支持，并与目标 Nginx/OpenResty ABI 匹配。新增正则不支持使用旧 PCRE1 构建。

```sh
sh tools/build-runtime.sh /tmp/scdn-purge nginx
python native-purge/tests/integration.py --prefix /tmp/scdn-purge
```

完整模板见 [nginx.conf](examples/nginx.conf)。模块加载后，必须在每个需要清理的缓存位置配置：

```nginx
scdn_purge_key "$scheme|$host" "$scheme|$proxy_host|$request_uri" "$request_uri";
proxy_cache_key $scdn_purge_key;
```

第一个参数是 namespace/scope，第二个是原始完整缓存键，第三个是可选的逻辑清理资源；省略第三个时按原始完整键清理。示例用资源 `$request_uri`，所以 API 可以直接对 `/assets/a.css?x=1` 精确清理或对 `/assets/` 做前缀清理。

必须保留原缓存键的所有隔离维度，例如方法、租户、回源、请求体摘要、配置版本等；模块不会推测原业务的缓存语义。不要对未接入该变量的位置声称清理已生效。原始缓存键和独立资源都进入实际键的隔离编码，避免不同逻辑资源意外共用一个缓存对象。

## 2. 指令

| 指令 | 上下文 | 默认/限制 |
| --- | --- | --- |
| `scdn_purge_zone NAME SIZE` | http | 启用时必填，1m～64m，建议 16m |
| `scdn_purge_journal /absolute/file` | http | 必填，一个实例一份，不得被外部写入 |
| `scdn_purge_token_file /absolute/file` | http | 开放 API/status 时必填，普通私有文件，43～128 个 base64url 字符 |
| `scdn_purge_cache_entries N` | http | 每 Worker 默认 1024，64～16384 的二次幂 |
| `scdn_purge_checkpoint SIZE` | http | 默认 64m，64k～64m；超过阈值在下一次提交前压缩日志 |
| `scdn_purge_allow_all on/off` | http | 默认 off，单独控制全局 all |
| `scdn_purge_key SCOPE ORIGINAL_KEY [RESOURCE]` | http/server/location | 定义版本化键；禁止自引用 `$scdn_purge_key` |
| `scdn_purge_revalidate off\|TIME` | http/server/location | 默认 off；检查间隔 1s～24h，仅支持 proxy_cache |
| `scdn_purge_stale updating=TIME error=TIME` | http/server/location | 再校验位置默认 updating=30s、error=0；各自 0～24h，0 禁用对应宽限 |
| `scdn_purge_api` | location | POST 清理端点，不与其他 content handler 混用 |
| `scdn_purge_status` | location | GET/HEAD 只读状态 |

主配置需显式声明 `thread_pool scdn_cache_purge threads=2 max_queue=64;`。请求体缓冲区建议 1m；需要使用接近 4096 字节的原始键/资源时，配置足够大的原生 proxy header buffer，示例使用 16k。

普通请求的 scope 长度 1～256 字节，不能有首尾空格；原始键与资源各 1～4096 字节，均不接受控制字符。内置 Worker 本地缓存是四路有界缓存，保存完整字节并比较；单个条目的内存受实际键长度影响。未命中或提交版本变动时才查询共享状态。

任何提交都会推进全实例序号，使其他 scope 的本地解析缓存也在下次使用时重查；它不会因此失效其他 scope 的 HTTP 缓存内容。高频清理、高基数键和大量前缀会增加慢路径访问，不能按单热键测试推导全部负载的开销。

## 3. 首次创建私有状态

先确定实际 Worker 账户，并让它能读写 journal、稳定 `.lock` 和检查点目录。master 还会持有 `.owner` 文件锁，拒绝另一个 master 使用同一份日志。示例目录：

```sh
sudo install -d -o scdn -g scdn -m 0700 /var/lib/scdn-purge
sudo install -d -o root -g scdn -m 0750 /etc/scdn-purge
sudo install -d -o scdn -g scdn -m 0750 /run/scdn-purge /var/cache/scdn/content
```

只在首次安装、文件不存在时初始化；下面的 noclobber 防止覆盖已有日志：

```sh
sudo -u scdn sh -eu -c 'umask 077; set -C
: > /var/lib/scdn-purge/epochs.log
: > /var/lib/scdn-purge/epochs.log.lock
: > /var/lib/scdn-purge/epochs.log.owner'
```

token 用密码学随机源生成，放在仓库之外，仅所有者有权限，例如 0600/0400；不接受组或其他用户权限。模块不打印 token，也不接受查询串凭据。示例 curl 配置文件应填写实际 token 并设为 0600，避免把 token 放进命令行参数。

`nginx -t` 会验证或初始化日志，并可能修复不完整的末尾记录；它不是完全无状态的磁盘只读动作。Nginx 手工 reload 必须保留 zone 名称/大小和日志身份，变更这些项目要完全停止旧实例后再启动。不要删除 owner/lock 文件来绕过活跃实例。

## 4. 清理协议

端点同时要求真实 Unix/loopback 连接和 `Authorization: Bearer ...`。这个 token 是整实例的可信管理权限，不是按租户授权系统。请求使用 `Content-Type: text/plain`，固定 Content-Length，不接受 chunked、非空查询参数或子请求。

模式通过 `X-SCDN-Purge-Mode` 指定；scope 通过 `X-SCDN-Purge-Scope` 指定。精确/前缀 body 每行一个目标，最后一行 LF 可有可无；不接受空行、CRLF 或原始控制字符。最多 256 行、每项 4096 字节、总 body 最多 1MiB。UTF-8/百分号编码按实际字节比较，不做 URL 解码或查询参数重排。

| mode | scope | body | 作用 |
| --- | --- | --- | --- |
| exact | 必填 | 完整资源列表 | 只失效这些资源，包括对应 Vary 变体 |
| prefix | 必填 | 资源前缀列表 | 在该 scope 中按字节前缀失效，不遍历缓存对象 |
| wildcard | 必填 | glob 列表 | 整个资源匹配，`*` 任意字节序列、`?` 单字节、反斜杠转义 |
| regex | 必填 | PCRE2 表达式列表 | 默认区分大小写、搜索语义；可用 `^`/`$` 锚定完整资源 |
| suffix | 必填 | 后缀列表 | 忽略查询串后匹配路径尾部，例如 `.css` |
| directory | 必填 | 目录列表 | 忽略查询串，目录本身与其子目录，按 `/` 区分边界 |
| scope / site | 必填 | 必须为空 | 整站/整个命名空间失效 |
| all / node | 可省略 | 必须为空 | 本实例所有 scope 和已接入 cache zone，需 allow_all on |

前缀 `/assets/` 不匹配 `/assets-other`；`/assets` 则按字节语义同时匹配。完整 URL 是否属于资源取决于配置的 RESOURCE 表达式，不要把 API 目标和浏览器 URL 自动等同。

directory `/assets` 或 `/assets/` 匹配 `/assets`、`/assets?x=1`、`/assets/a.css`，不匹配 `/assets-other/a.css`；不解码 `%2F`，不合并重复 `/`。suffix `.css` 匹配 `/a.css?v=2`，不匹配 `/a.CSS` 或 `/x?name=a.css`。wildcard/regex 对完整资源匹配，查询串也参与；例如 glob `/assets/*.js*`、正则 `^/assets/[^/]+\.(css|js)(\?.*)?$`。两者最长 1024 字节；directory/suffix 目标不接受查询串或 fragment。

prefix/wildcard/regex/suffix/directory 共用每 scope 128 个不同模式规则的预算，不是每种各 128。正则编译产物最多 128KiB；执行限制为 100000 次匹配步骤、128 深度、1MiB 匹配堆；glob 也有步骤预算。编译错误整批返回 400，容量不足整批返回 507。运行预算耗尽时，请求绕过缓存读取并在回源前失败为 5xx，不把执行失败当作“没有匹配”。整站清理可回收问题规则。

规则在本地 key 缓存未命中时匹配；表达式编译使用每 Worker 64 项有界缓存。匹配在共享锁外进行，不扫描缓存文件。高基数流量、复杂正则和频繁失效仍会增加请求成本。node 是整机单实例的所有缓存区；多 master、其他进程及未接入版本键的缓存需要控制端分别处理。

## 5. 调用示例

假设使用模板的 scope `$scheme|$host`、资源 `$request_uri`，并将本机 token 配置保存在 `/etc/scdn-purge/control.curl.conf`：

```sh
# 精确键或批量，所有目标共用一次持久提交。
umask 077
printf '/assets/a.css?x=1\n/assets/b.js\n' > /tmp/purge-keys.txt
curl --config /etc/scdn-purge/control.curl.conf \
  --unix-socket /run/scdn-purge/control.sock http://localhost/purge \
  -H 'Content-Type: text/plain' -H 'X-SCDN-Purge-Mode: exact' \
  -H 'X-SCDN-Purge-Scope: http|www.example.com' --data-binary @/tmp/purge-keys.txt

# 前缀清理。
printf '/assets/\n' > /tmp/purge-prefixes.txt
curl --config /etc/scdn-purge/control.curl.conf \
  --unix-socket /run/scdn-purge/control.sock http://localhost/purge \
  -H 'Content-Type: text/plain' -H 'X-SCDN-Purge-Mode: prefix' \
  -H 'X-SCDN-Purge-Scope: http|www.example.com' --data-binary @/tmp/purge-prefixes.txt

# 整站，body 为空。
curl --config /etc/scdn-purge/control.curl.conf \
  --unix-socket /run/scdn-purge/control.sock http://localhost/purge \
  -H 'Content-Type: text/plain' -H 'X-SCDN-Purge-Mode: scope' \
  -H 'X-SCDN-Purge-Scope: http|www.example.com' --data-binary ''
```

成功响应为 `ok=true`、sequence、operations、`durable=true`、`physical_deleted=false`。operations 是输入操作数量，不是删除文件数量。队列不可用或 I/O 错误返回 503，元数据/前缀容量不足返回 507；错误响应不会包含原始资源和 token。

503、连接断开或超时属于未确认结果：记录可能已经可恢复，不能假定操作一定未发生。恢复会先同步可见尾部，再发布版本；重试相同失效是安全的，但可能推进额外版本。输入错误或容量预检失败不会部分提交当前批次。

## 6. 持久化与资源边界

共享区存放精确资源、scope 和模式的版本；不静默淘汰有效失效元数据，否则可能重新暴露旧缓存。每 scope 最多 128 个不同模式。整站 scope 推进该 scope 版本后，以短锁批次回收被其覆盖的精确/模式元数据，并保留 scope 版本；显式全局 all 可回收全部旧索引。失败批次会撤销预留，不能只提交前半个批次。

每个成功批次先 append 日志并 fsync，之后发布共享序号。一次最多 256 项，fsync 成本按批次摊销。检查点只保留有效的最新版本，用临时文件、fsync、rename 和目录同步替换；稳定 `.lock` 文件负责跨 Worker/线程串行化写入。

日志的完整记录有 CRC 校验；启动核对整个日志，在线恢复核对尚未读入的新增记录。不完整末尾可截断，已扫描完整记录损坏时拒绝继续，不静默清空；每次提交不会重扫全部历史，禁止外部就地改写日志。重启重放版本，手工 reload 复用同一共享状态。在线恢复较旧日志会被拒绝；完全停止后的恢复仍需一致备份策略，不能把旧日志配上任意新缓存数据就声称无回滚风险。

I/O 持久化会等待磁盘，管理队列与文件锁可能产生延迟。它不阻塞业务线程的文件操作，但仍与业务共享 CPU/存储资源。队列和 metadata 需要监控；没有无限容量或任意磁盘故障下的可用性保证。

日志保存原始资源标识，可能含业务查询参数，必须按私有业务元数据保护。token 更新需 reload；旧 Worker 在退出前仍可能使用旧配置。一个 master/共享区对应一份日志，不提供跨主机或多实例全局清理。

共享索引变更带有临界区故障标记。Worker 若在其中异常退出，数据请求和新的清理会失败关闭，状态报告 `state_recovery_required=true`；此时应保留日志、完全停止旧实例，再启动重放恢复，不能只通过 reload 清掉标记。普通磁盘提交等待不会设置该标记，也不会因此封锁数据请求。

## 7. 与 Edge 集成

在 Edge 的命名代理 location 中保留原配置版本隔离，同时按稳定 URL 清理：

```nginx
scdn_purge_key "$scdn_edge_site" "$scdn_edge_revision|$scheme|$host|$request_uri" "$scheme://$host$request_uri";
proxy_cache_key $scdn_purge_key;
proxy_cache $scdn_edge_cache;
```

此例 scope 是稳定站点 ID，例如 demo；精确/前缀目标是完整 URL，例如 `https://www.example.com/assets/a.css` 或 `https://www.example.com/assets/`。这样精确 URL 不会误清理其他别名，而 scope 整站操作可以同时覆盖该站点所有别名、scheme、缓存层和配置版本；回到旧配置也不会因此命中清理前的版本。

l1/l2 使用相同 scope/resource 时同时失效；需要单独隔离某层时，在 scope 中显式加入层名，并由管理端使用同一规则。独立模板使用 scheme/Host 作为 scope，它不会自动发现 DNS 别名或控制面站点归属；管理端和业务端必须采用同一命名规则。

首次启用版本化键会形成新缓存空间，原键下的文件不会自动迁移。修改 scope/resource 映射属于缓存语义变更，需计划相应的 scope/all 失效；不要让部分请求绕过 `$scdn_purge_key`。

## 8. 状态、测试与性能

GET/HEAD status 返回 sequence、metadata_nodes、journal_bytes、批次数、检查点数和回答该请求 Worker 的 LRU hits/misses。LRU 指标是每 Worker 的局部计数，不能把一次响应当作全实例汇总。状态接口也需本机传输和 token。

当前主要验证 HTTP/1.1 的 proxy_cache，以及本模块启用的原生 background_update。FastCGI/SCGI/uWSGI、slice/range、其他子请求组合、HTTP/2/3 和磁盘真实掉电需要另外验收；不能把本机键解析边界扩展为所有协议及子请求的全局快照保证。

真实进程用例见 [integration.py](tests/integration.py)和[验证记录](tests/VALIDATION.zh-CN.md)，对照压测方法与原始结果见 [bench](bench/README.zh-CN.md)。目标是低开销、无目录扫描和精确并发语义；不宣称在所有负载下绝对最低开销，也不把回环压测结果当作生产公网容量。

## 9. 源站自动再校验与过时缓存复用

先阅读 [HTTP/Nginx 调研](../docs/CACHE-REVALIDATION-RESEARCH.zh-CN.md)。只在需要自动更新的公开页面/静态资源规则中启用，例如：

```nginx
location /assets/ {
    scdn_purge_key "$scheme|$host" "$scheme|$proxy_host|$request_uri" "$request_uri";
    proxy_cache_key $scdn_purge_key;
    proxy_cache content;
    proxy_cache_valid 200 1d;
    scdn_purge_revalidate 30s;
    scdn_purge_stale updating=30s error=5m;
    proxy_pass http://127.0.0.1:8080;
    add_header X-Cache $upstream_cache_status always;
}
```

检查间隔是内部新鲜期上限。即使源站给出很长的 Cache-Control、Expires 或 X-Accel-Expires，也会在最多该间隔的新鲜期后进入再校验；源站要求更短新鲜期时保留更短值。源站无缓存头时仍按原 proxy_cache_valid 判断可缓存性。模块不自动覆盖 private/no-store、Set-Cookie、Vary、proxy_cache_bypass 或 proxy_no_cache 的保护；强制缓存公开资源如需忽略源站 TTL，应由管理员显式配置原生 proxy_ignore_headers，不能把它用于个性化响应。

资源有访问且过期时，模块启用原生条件 GET、更新锁和后台更新：有 ETag/Last-Modified 时发送 If-None-Match/If-Modified-Since；304 仅续期元数据，不重新下载正文；200 完整接收后由 Nginx 原子替换。无校验器时完整 GET。源站错误沿用校验头的情况无法仅靠这些头发现；也不会根据 Content-Length 判断内容相同。首次启用或改变 interval/stale 窗口会产生独立缓存键空间，防止旧的长 TTL 对象绕过新策略。

两个 stale 窗口都从该内部新鲜期结束开始计算，单位为秒；原生缓存时间为整秒，触发可能有约 1 秒边界偏差。updating 窗口内先返回旧正文并后台更新，超过后同步校验。error 窗口内允许连接/超时/无效响应头以及 500/502/503/504 回源错误复用最后的缓存；超过后返回真实错误。失败不会续期旧对象，5xx/429 即使带 public/max-age 也不写成新缓存。模块按时间限制管理本位置的原生 stale 条件位，不能再用 proxy_cache_use_stale 的无期限开关扩大这两个窗口。

此处 stale 是管理员为该位置显式设置的复用策略，沿用 Nginx 的缓存实现，不代表完整实现 RFC 9111 的全部缓存约束。对于必须严格服从源站 must-revalidate/proxy-revalidate 的资源，把两个窗口都设为 0；浏览器缓存控制仍需单独配置。

403/404/410 等撤回、源站变为不可缓存或携带 Set-Cookie 时，后台通过同一私有 journal 提交该资源的精确失效。提交期间已有旧请求仍可能完成；成功后新请求不能命中其旧 epoch。队列/持久化失败记录通用错误和计数，下次符合条件时重试，不报告虚假的成功。手动 exact/pattern/site/node 清理后，旧 epoch 一律不参与 stale 兜底；在途旧更新也不能写入清理后的新版本。

启用再校验会额外申请 512KiB 共享区（名称是原 zone 名加 `:revalidate`），用 4096 个槽记录跨 Worker 的后台尝试间隔。正常 HIT 不访问该表，也不发源站请求；失败后的后台检查不早于上次尝试的 interval。槽位冲突可淘汰冷条目，最多增加校验，不改变失效版本。超出后台复用窗口的同步请求优先获取真实结果，不受此重试抑制；原生锁超时、超长回源和高基数冲突仍可能增加并行回源，不能承诺任意故障下严格只有一次源站请求。

空闲资源不轮询；inactive/max_size 可先回收旧文件，所以 stale 不是持久保留承诺。不要把浏览器缓存或其他未接入模块的 CDN 当作已更新。关闭再校验会恢复原始版本键，关闭前应显式做相关 scope/all 失效，避免重新命中启用前的长 TTL 对象。新增正则/通配符等日志记录需要本版本恢复，降级前保留一致的缓存和 journal 备份。

status 新增 `worker_revalidate`：probes、not_modified、fetched、failures、suppressed、cooldown_evictions、invalidated、invalidate_failed，均为回答请求的 Worker 局部计数。fetched 表示完成的 200 缓存更新；failures 包括无法缓存、撤回和回源错误等未完成缓存更新的尝试，不是单纯网络错误计数。测试见 [revalidate.py](tests/revalidate.py) 与 [patterns.py](tests/patterns.py)。新功能不依赖 Lua、不增加 WAF 或业务限速，也不提供跨节点传播。
