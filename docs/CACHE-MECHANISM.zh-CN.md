# OpenResty 文件缓存机制与精确清理设计

调研对象：固定 OpenResty 1.31.8.1 归档中的 Nginx 1.31.8。以下机制来自当前源码与真实进程测试；性能结论另见 [清理模块基准](../native-purge/bench/README.zh-CN.md)，不把源码推导当作生产容量数据。

## 1. 缓存不是一个普通文件目录

| 层次 | 机制 | 清理时的影响 |
| --- | --- | --- |
| 业务缓存键 | `proxy_cache_key` 生成字节串 | URL 不一定等于完整键，Host、scheme、版本、方法或租户可能参与 |
| 磁盘寻址 | Nginx 对完整键计算 MD5，用 `levels` 生成文件路径 | 文件名哈希不是原始 URL，不能凭路径前缀猜测域名或业务目录 |
| 文件内容 | 版本化缓存头、CRC32、原始 KEY、Vary 元数据与响应 | 单纯删除主键文件不能证明所有 Vary 派生键已失效 |
| 共享索引 | rbtree + inactive queue，引用数、exists/updating/size 等 | 直接操作磁盘可能与共享状态、引用或更新写入竞争 |
| 回源写入 | 临时文件、rename 提交，再更新共享节点与空间计数 | 清理前启动的旧回源可以在清理后完成并写回 |
| 生命周期 | cache loader、manager、inactive/max_size/min_free | 内容失效和磁盘空间回收是不同过程 |

`open_file_cache` 是文件描述符/属性缓存，也不同于 HTTP 响应缓存。请求可能已经持有打开的旧文件，清理不能把已发送或正在发送的响应“收回”。

本版本的 cache loader 在启动后约 60 秒开始工作；在 cold 标记尚未清除时，文件缓存 HIT 的读取路径还可能多进入一次核心共享锁。只把少量对象预热成 HIT，并不等于运行时已进入加载完成的稳态；基准脚本会等待 loader 退出后再测量。

## 2. 关键源码链路

在固定归档的 `bundle/nginx-1.31.8/src/http/` 下：

- `ngx_http_file_cache.c:228`：create_key 对各 key 片段计算 CRC32/MD5，保存 main key。
- `ngx_http_file_cache.c:265` 与 `:889`：open/exists 在共享索引中维护引用和存在状态，冷启动时可重新检查磁盘文件。
- `ngx_http_file_cache.c:547`：read 校验文件头、CRC32、原始 KEY，并处理 Vary。
- `ngx_http_file_cache.c:1277`：Vary 不匹配时 reopen 到派生哈希；一个逻辑资源可以有多个实际缓存文件。
- `ngx_http_file_cache.c:1426`：update 先 rename 临时文件，再更新共享节点及空间计数。
- `ngx_http_file_cache.c:1683`：free 处理请求引用与更新状态，不能任意释放被其他请求引用的节点。
- `ngx_http_file_cache.c:1979`：manager 删除时管理 deleting/count/size，并释放引用为零的节点。
- `ngx_http_cache.h:39`、`:147`：节点及共享缓存结构。当前开源文件路径没有可直接调用的完整“任意 URL/前缀清理”公共 API。

归档版本与校验值见 [源码来源](../SOURCE.md)。字段和行号只针对本次固定版本，不能直接推导到其他 ABI。

## 3. 比较过的实现方式

| 方式 | 优点 | 需要承担的问题 |
| --- | --- | --- |
| 扫目录删除匹配文件 | 可回收部分文件空间 | O(磁盘对象数)、解析文件 KEY、Vary、并发写回、共享空间计数与 I/O 抖动 |
| 精确定位哈希并操作共享节点 | 单键定位快 | 与 Nginx 私有结构绑定；仍需协调在途 writer、冷加载、变体和安全回收 |
| 修改核心加入 writer fence | 可以设计严格的物理删除协议 | 维护核心补丁、ABI、每节点生命周期和每请求检查，需跨版本维护 |
| 版本化缓存键 | 失效时不扫缓存目录，天然隔离晚写与 Vary | 请求路径有版本解析成本；需要持久化版本，旧文件不立即释放 |

也阅读了 [FRiCKLE/ngx_cache_purge](https://github.com/FRiCKLE/ngx_cache_purge) 的公开实现：它通过 file_cache_open 获取节点，调整节点后删除文件，特意保留可能被其他请求引用的内存节点。本模块没有复制其实现；本次选择避免修改核心和直接操作 Nginx 私有节点。

## 4. 本模块采用的语义

`native-purge` 按 namespace/scope 与资源标识保存最新清理 epoch。实际传给 Nginx 的完整键包含持久化 namespace identity、scope、epoch 和原始缓存键；独立资源标识需要时也编码入键，以免隔离维度发生歧义。

清理线程先写入并同步日志，再在短共享锁内发布整个批次。新请求解析键时读取提交后的 epoch，所以不能访问旧 epoch 的文件。先前已取得旧键的请求可以完成，但晚写仍落在旧 epoch；新的请求不会将其当作当前缓存。Vary 在该新基础键上继续派生，因此各响应变体一并隔离。

完整键和资源均作字节匹配，不猜测 URL 规范化，不把 `/asset`、`/asset?x=1`、`/asset%2Fa` 当作相同目标。索引使用 CRC32 选桶，但完整长度及字节仍会比较，CRC32 碰撞不授予命中或授权。

## 5. 开销设计

普通热请求先读共享提交序号，再查询 Worker 私有的有界四路缓存。命中时不进入清理状态共享锁、不读日志、不遍历清理规则。未命中或清理版本变化后，在共享锁中查 scope、精确键及该 scope 的有界前缀列表，再缓存结果。

精确/批量失效只更新目标元数据；前缀和整站失效不遍历磁盘对象。每个 scope 最多 128 条前缀规则。全局 all 会分离旧元数据索引，并以每次最多 64 个节点的短锁批次回收，避免把整个元数据释放过程放进一个长锁区。

日志 I/O、fsync、恢复与检查点在专用线程池中执行；它们仍消耗主机 CPU/磁盘，不能宣称与业务完全无资源竞争。批量最多 256 个目标共用一次提交，降低每键持久化成本。默认检查点阈值 64MiB，可配置为 64KiB～64MiB。

相比“删除文件”，这里将成本转移为少量键解析、元数据和后台持久化。它不可能在所有工作集、文件系统、清理频率和平台上都达到数学意义的最低开销；需要按目标负载测量。

## 6. 一致性与磁盘回收边界

成功响应表示该批次的失效版本已持久化并发布，之后开始解析缓存键的新请求采用新版本。它不承诺取消已在运行的请求，也不表示已经删除磁盘文件。响应明确给出 `physical_deleted=false`。

旧文件和空间计数仍由 Nginx cache manager 管理，按 inactive/max_size 等策略回收。高频清理会产生新旧对象并存，需合理设置容量、inactive 和监控，不能拿“失效成功”代替空间已经释放的证据。

日志是当前版本的恢复依据；删除或回滚它可能造成全局冷缓存或不一致。模块拒绝损坏的完整记录、在线日志回滚与另一个 Nginx master 共享同一日志，不提供跨主机分布式一致性。

## 7. 官方参考

- [proxy_cache_key](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_key)
- [proxy_cache_path](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_path)
- [proxy_cache_lock](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_lock)
- [proxy_cache_background_update](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_background_update)
- [open_file_cache](https://nginx.org/en/docs/http/ngx_http_core_module.html#open_file_cache)

这些文档描述 Nginx 功能；当前模块的能力、配置和实测以本仓库源码、[使用手册](../native-purge/README.zh-CN.md)和测试为准。
