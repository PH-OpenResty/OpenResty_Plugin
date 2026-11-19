# 原生日志与网络指标同步 0.1.0

`ngx_http_scdn_log_sync_module` 在后台直接连接 Elasticsearch Bulk API 和 ClickHouse HTTP JSONEachRow。可以只选一种后端，也可同时投递到多个后端。HTTP 请求处理线程不执行日志磁盘读取、压缩解压、数据库请求或系统状态采样；多 Worker 通过文件锁选出一个发送者，其他 Worker 待命，平滑重载后接管相同持久游标。

## 交付与运行方式

| 组件 | 职责 |
| --- | --- |
| `ngx_http_scdn_log_sync_module.so` | 可独立加载的 Nginx/OpenResty HTTP 模块；后台发送、采样与私有状态入口 |
| `libscdn-log-sync.a` | C++17 文件读取、持久批次、直连后端与指标采样核心 |
| `scdn-log-sync` | 相同核心的配置检查、单轮补采、采样预览和独立运行工具 |
| `scdn-log-netmon` / `packet.bpf.o` | 可选高权限、只读网络观测；按指定网卡和监听端口统计实际 TCP 标志及 UDP 数据报 |
| `schema/` / `grafana/` | ES 映射、CH 类型化视图、81 个既有面板及其指标清单 |

模块不依赖 Lua、SSH、Redis、SQLite、Logstash 或外部日志队列。发送状态由当前节点保存；ES/CH 是最终接收方。网络辅助程序不连接 ES/CH，不在 TC/XDP 挂载程序，不修改 Ban 规则或现有内核 Map；它只给自己的捕获套接字安装 eBPF 过滤器，并可读取指定 Ban 状态和内核计数。

## 全量与增量

`sources[].start` 支持：

- `full`：首次启动从保留文件开头读取；随后按确认游标持续增量。
- `tail`：首次初始化跳过当时已有普通文件的字节，以及当时已经存在的压缩归档；只追随后续追加。启动时已有半行会丢弃到下一个换行。启动后新建或轮转的新文件从零读取。

每个源有独立 ID、路径和格式，可混合配置。完整行优先按 JSON 对象解析，保留未知字段和嵌套值；非 JSON、无效 UTF-8 和过长行仍按原始字节投递，不静默丢弃。事件同时保留 `raw_base64`、文件身份、generation、字节范围、换行和片段标记。超过 `line_bytes` 的行拆成带 `fragment=1` 的片段，可按 generation/offset/terminated 还原；片段不冒充完整 JSON。

支持普通文件、重命名轮转、迟到追加、copytruncate 的游标锚点检测和 `.gz` 历史归档。压缩文件使用连续读取窗口，读完后释放解压状态；已封存且文件元数据未变的归档不反复解压。压缩替换已读普通文件时可继承匹配的游标。用户源日志不会被本插件删除。

恢复以实际保留的源文件为边界：已经删除且从未读取的内容无法重建；尚未完成的归档不得被日志轮转提前删除。普通文件缩短或锚点改变时启动新 generation；在同一 inode 上写入与旧锚点完全相同内容的特殊重写不提供无限期追踪证明。压缩归档按封存文件使用，不支持把持续追加当作实时 gzip 日志。

## 确认与恢复语义

1. 从文件准备一个有界批次，写入带 SHA-256 的 `pending.json`，同步文件并原子替换。
2. 将同一批事件直接写到所有指定后端。各后端的确认单独持久化。
3. 所有后端均成功后提交 `state.json` 的文件游标，再清理待发送批次。

ES 必须满足 HTTP 成功、Bulk item 数量/ID 匹配、每项状态成功且 `errors=false`。HTTP 200 中的 429/映射错误不能确认。CH 使用同步 INSERT、`wait_end_of_query=1`；响应异常或断开不会提交游标。重试不把后端错误原文或凭据写入正常日志。

传输语义为至少一次：网络可能在服务端提交后丢失确认。ES 使用稳定 `_id` 覆盖同一事件。CH 给批次发送 deduplication token，并用 `ReplacingMergeTree` 和 `FINAL` 视图实现查询去重；不要仅凭普通 MergeTree 的 token 声称物理插入恰好一次。批次包含已确认后端的记录，单个后端恢复时不会重新发送到已持久确认的其他后端。

有效 Nginx request ID 用于访问事件身份，Ban 使用完整审计身份；其余内容使用持久 generation、偏移和原始字节摘要。手工删除游标目录会改变普通日志的 generation；计划重建时应同时考虑接收端已有数据。状态目录、日志源和 sink 绑定改变时拒绝沿用不匹配状态，避免把旧待发送批次交给新目的地；修改这些字段前先排空并准备新的受控状态目录。凭据文件内容可在相同路径轮换。

## 指标与 Grafana 参数覆盖

用户引用的 Grafana 安装目录包含安装配置和备份。实际 CDN 数据定义来自现有 observability 的 81 个内容面板、79 条数据查询和访问/封禁/节点/采集健康表结构；[指标目录](schema/metrics-catalog.json)逐项保存字段与查询，三个移植仪表盘在 [grafana](grafana/)。数据源 UID 为 `scdn-native-clickhouse`，数据库为 `scdn`，避免覆盖既有仪表盘资源。

覆盖的输入包括请求数/速率、正文流量、缓存命中及流量、状态码、耗时/P95/P99、HTTP 协议、站点、IP、国家、ASN、运营商、URI、封禁审计/当前执行视图、L3 DROP、CPU/负载/内存/磁盘/网卡、原生 API 分类计数、Sync/业务健康及采集进度。排名、比率和分位数由数据库按范围计算，保持原始统计口径。地理/ASN 字段来自 JSON 日志已有内容，插件不凭空生成城市或地理库数据。缺少 `site_id` 的旧访问日志可按配置中的站点/Host 目录补映射。

未满足访问/封禁基础字段的 JSON 仍完整保存，但不生成虚假的访问或封禁统计；无效记录计数随确认游标推进。另有 [18 个网络面板](grafana/scdn-native-network.json)，观察 Nginx/主机 TCP、UDP socket、TCP ACK/SYN/SYN-ACK、UDP 包及速率、重传和监听队列丢弃。采样配置可在正常重载时更新；关闭新采样后仍会发送已有持久指标段，日志游标不因采样配置变化而重置。

`kind=access/ban` 在保留原始 JSON 的同时增加类型化 `normalized_json`。归一 URI 删除查询参数和绝对 URL 的用户信息；原始完整日志仍保留在受控接收端，配置源之前应确认其实际内容。CH 兼容视图与 ES `normalized`/`metrics` 映射支持分析；ES 原始任意字段使用有界 `flattened`，系统指标另有数字字段，支持真实数值聚合。

### 实时连接和报文口径

| 字段 | 来源和含义 |
| --- | --- |
| `connections.nginx_tcp_sockets` | 指定 Nginx master 及子进程持有的去重 TCP socket inode |
| `nginx_tcp_established/listen/syn_sent/syn_recv` | 上述被进程持有的 socket 状态；尚未分配 socket inode 的半开请求不算作进程已持有连接 |
| `nginx_udp_sockets/nginx_udp_connected_sockets` | UDP 套接字数与内核 connected UDP 套接字数；UDP 自身没有握手连接 |
| `nginx_quic_sessions` | 默认 NULL；QUIC 会话由用户态维护，不能把一个 UDP 监听 socket 当作一个 QUIC 连接。自有 Nginx 状态中的扩展指标完整保存在 `status/nginx_stats` |
| `host_tcp_sockets/host_udp_sockets` | 当前采集网络命名空间的整机 socket 视图，与进程归属指标分开 |
| `network_protocols.*` | Linux SNMP、TcpExt、IPv6 的实际命名计数：InSegs/OutSegs、重传、UDP 数据报、ListenDrops、Syncookies 等 |
| `packets.ingress/egress.tcp_ack/tcp_syn/tcp_syn_ack/tcp_syn_only` | 指定网卡和监听端口的实际 TCP 标志包计数。ACK 与 SYN 按位计数，SYN-ACK 同时属于 ACK、SYN，不能直接相加 |
| `tcp_packets/tcp_bytes/tcp_fin/tcp_rst/udp_packets/udp_bytes` | 同一端口观测范围的报文与捕获长度；包含协议头，与访问日志正文流量分开 |
| `packet_pps` | 同一采集会话连续有效样本的包速率；采集器重启或首次样本留空 |

UDP 没有 TCP ACK/SYN 标志，使用 UDP 数据报及错误计数。监听端口计数不是进程身份认证，同端口共享服务也在范围内；选择避免重复经过桥接/物理层的网卡，采集器不把多个观测点的同一个包自动推断为唯一线上报文。支持 IPv4/IPv6、两层 VLAN 和有界 IPv6 扩展头；无法取得端口的非首片段和不支持的加密/扩展不冒充可归属 TCP/UDP。

CPU、网卡带宽和 L3 增量在首次采样、计数器重置、系统 boot 改变或采集不可用时为 NULL。没有权限读取其他 Worker fd、Ban socket、内核 Map，或包快照超过 5 秒时，也报告不可用而非健康的零。根权限辅助程序可补采这些只读数据；Nginx Worker 不需要因发送日志而取得 BPF/原始套接字权限。

接收端补充 `received_at`，并计算类型化 `source_clock_skew_ms`：接收时间减源样本时间，包含排队/传输耗时和两端时钟差，不把它当作独立 NTP 偏差估计。本地原始采样基线与接收端派生字段分开保存。

### 本地缓冲和背压

指标在独立线程按配置间隔采样到状态目录内的受限 JSONL，再走相同确认管道；数据库不可用不会阻止继续采样到 `spool_bytes` 上限。到达容量、记录或文件上限后停止新增采样并增加 `sample_failures`，保留现有未确认数据。已经确认的封存指标段才允许清理。历史日志仍留在原目录，不另外复制整个历史；发送不及新增速度时由源日志保留策略承担积压。

同步间隔是目标调度间隔，不是跨网络实时性保证。采样配置中每个状态端点有 1 秒请求上限；CPU/磁盘压力与多个状态读取会影响实际周期。指标包含采集时间、后端健康和延迟，供查询区分旧数据与真实零值。

## 编译与安装

依赖 C++17、json-c、libcurl、OpenSSL、zlib、libbpf、pthread；报文程序另需 clang 的 BPF 目标和 Linux 头文件。

```sh
sh tools/build-runtime.sh /tmp/scdn-with-log-sync nginx dynamic
sh native-log-sync/tools/build-core.sh /tmp/scdn-log-sync-core
sh native-log-sync/tools/build-netmon.sh /tmp/scdn-log-sync-core
```

完整构建现在包含十个 HTTP 模块。可只把本目录作为 `--add-dynamic-module` 或 `--add-module` 接到匹配 Nginx 源码；`config` 会在当前构建目录生成私有静态核心。发送模块可以独立加载，不需要配置其他九模块。

按实际 Nginx Worker 用户创建模式 0700 的 `/var/lib/scdn-log-sync`，使它可以只读访问日志、配置和所需状态。凭据文件必须由使用者拥有并设为 0600；`authorization_file` 存完整 Authorization 值，CH 可用独立用户名/密码文件。TLS 验证始终启用，私有 CA 使用 `ca_file`；明文 HTTP 必须显式 `allow_http=true`，仅建议用于受控本机测试。配置 URL 不接受用户信息、查询或 fragment；不自动跟随重定向。

配置见 [log-sync.json](examples/log-sync.json)、[nginx.conf](examples/nginx.conf) 和 [netmon.json](examples/netmon.json)。保留需要的 sink 即可选择 ES 或 CH；全部配置的 sink 都属于确认条件。示例采用较大记录预算，以容纳完整活动封禁快照；普通小日志可调低 `line_bytes/batch_bytes`。最多 4 MiB 单次片段、32 MiB 批次、4096 条记录/批、64 个来源（含内部指标）和 8 个后端，实际值有额外一致性校验。

```sh
/tmp/scdn-log-sync-core/scdn-log-sync --check /etc/scdn-log-sync/log-sync.json
/tmp/scdn-log-sync-core/scdn-log-sync --once /etc/scdn-log-sync/log-sync.json
/tmp/scdn-log-sync-core/scdn-log-sync --sample /etc/scdn-log-sync/log-sync.json
```

`--once` 执行有界单轮；全量补采可重复运行或使用 `--run`。`--sample` 的输出含实际指标/IP/站点，应仅保存在受限本地位置。命令行只传配置文件路径。

管理员需先应用 [ClickHouse DDL](schema/clickhouse.sql)，或先以名称 `scdn-log-sync` 安装 [ES ingest pipeline](schema/elasticsearch-pipeline.json)，再安装 [ES index template](schema/elasticsearch-template.json)。ES 的 `@timestamp` 使用原始访问/封禁/指标时间，解析失败安全回落至采集时间；`timestamp` 保留入队时间，补采历史不会冒充新发生的访问。Worker 使用最小写权限，模块不自动执行 DDL。CH 的 `scdn.node_inventory` 由管理员登记节点资产；本插件不从 Host 猜测资产数。导入移植仪表盘前配置数据源 UID；生产已有库应使用独立表名/数据库，避免与旧采集器同时累计相同数据。

报文采集用 [systemd 模板](examples/scdn-log-netmon.service)，按机器调整接口、端口、用户组及实际路径。`nginx_pid_file`、`ban_socket`、`ban_counter_map` 是可选只读补采范围。确认服务能力后再安装；本仓库不自动改动生产内核挂载或防火墙。

## 状态与验证

`scdn_log_sync_status;` 放在受限 Unix/loopback 控制位置，并关闭该位置访问日志以免自采循环。输出为本 Worker 的线程/周期/发送统计，待命 Worker 的 `owned_by_other_worker` 不是后端失败。节点全局确认游标、采集健康和指标进度通过持久状态及 `collection_health` 查看。

状态目录内的 state/pending、指标段和本地锁都属于私有运行数据；损坏时保留现场并恢复匹配备份，不自动清空后继续。生产切换前按项目约定备份程序、配置、状态与日志保留点；本次开发不包含生产激活。

验证程序包括 `tests/core.py`、`telemetry.py`、`runtime.py`、`netmon.py` 和 `backends.py`：覆盖全量/增量、半行、轮转/压缩、重放、丢失确认、部分 Bulk 失败、TLS、游标完整性、指标缺失、实际两 Worker/平滑重载、真实内核包验证，以及真实 ES/CH 和全部既有 79 条数据查询。具体已执行结果见本轮验证记录；测试报告不上传实际日志、凭据、私钥或节点数据。
