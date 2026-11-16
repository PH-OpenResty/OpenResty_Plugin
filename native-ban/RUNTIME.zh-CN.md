# Ban 0.1.0 运行手册

本版实现 Nginx HTTP 封禁检查/事件上报、单写 Agent、实际 eBPF 丢包和 Master/Node 全量 L3 同步。部署前核对真实客户端直连条件、受保护接口/VIP/端口、现有 XDP/TC 链和独立回退路径；仓库测试只在临时 netns/veth/bpffs 中运行，没有改动生产设备。

## 构建

统一 Nginx/OpenResty 构建包含七个模块。Ban `.so` 本身不依赖 libbpf；Agent 链接 libbpf 与独立 Ban Store，运行和构建均不依赖 SQLite，Worker 不持有 BPF Map FD 或加载权限。

```sh
# Debian/Ubuntu Agent build dependencies, in addition to normal Nginx deps:
sudo apt-get install -y build-essential clang libbpf-dev libelf-dev \
  libjson-c-dev libcurl4-openssl-dev libssl-dev iproute2
sh native-ban/tools/build-agent.sh /tmp/scdn-ban-build
sh tools/build-runtime.sh /tmp/scdn-ban-nginx nginx
```

Alpine 对应为 build-base、clang、libbpf-dev、elfutils-dev、json-c-dev、curl-dev、openssl-dev、iproute2。要求 Linux 64 位小端、原子 64 位读写、CLOCK_BOOTTIME、BPF 和 libbpf 1.x 的 TCX API；TCX 需要 Linux 6.6+，实际验证使用隔离 WSL2 和 Actions Linux。构建产生 scdn-ban-agent 和 ban.bpf.o；二进制不提交 Git。

一起编译时动态加载顺序为 Config → Ban → Tier → API → Edge → Purge → Sync。API/Edge 调用 Ban 的预检查，因此同一构建启用 Ban 时必须先加载 Ban；未配置 scdn_ban on 时普通业务流程不启用封禁。静态编入不使用 load_module。

## 运行配置与权限

实际入口为 [policy.json.example](examples/policy.json.example)，严格拒绝未知字段、重复 JSON key、非法类型、无效 IP/CIDR、超限值及不安全路径。旧 design/policy.schema.json 和 TOML 属于历史设计，不是此 JSON 格式的验证器；运行解析由 Agent 的 --check 执行。

```sh
scdn-ban-agent --config /etc/scdn-ban/policy.json --check
scdn-ban-agent --config /etc/scdn-ban/policy.json
```

配置文件和密钥为私有普通文件，不跟随父目录/叶路径 symlink。预先创建以下目录，按实际账户替换数值 UID/GID：

- runtime_dir：tmpfs 上的 Agent 所有目录，例如 /run/scdn-ban，0750，组允许指定 Worker 遍历；视图文件由 Agent 拥有、0600。
- state_dir：Agent 所有的 0700，持久模式保存 ban-store.aof、单实例锁和完整同步状态；memory 不写状态日志。不可使用旧备份覆盖在线状态。
- event_log、ip_log 的父目录：受控路径，两文件必须不同 inode，Agent 写入，默认 0600；JSONL 日志不是权威数据库。
- datapath.pin_root：预挂载 bpffs 下的独立 0700 子目录。只用于本实例的 Maps/links，不能与其他程序共用。
- event_socket：0660，校验真实 SO_PEERCRED、Worker UID、instance UUID、net/time namespace 和 boot；admin_socket 仅 root；Sync socket 仅配置的 sync_uid。

示例 Agent 使用 root，Nginx Worker 必须非 root 且不同 UID；生产可按实际 libbpf/网卡要求收紧为独立特权服务账户并验收能力集。本版禁止非零 BOOTTIME namespace 偏移；跨机同步要求内核报告时间已同步，CLOCK_UNCERTAIN 时保留本机已有期限而不虚报新的远程应用。

`instances` 是受信 Nginx 实例 UUID；`trusted_rules` 明确允许 source=waf/cc 与 reason 组合。相同 Worker UID 的进程属于受信事件边界，不能与不可信业务程序共用账户。客户端 HTTP 头、源站 403/429、API/AI 标签不会触发封禁。真正源 IP 通过 getpeername 取得，不信任 X-Clinet-IP、X-Forwarded-For 或 real_ip 改写后的值。

## Nginx 与 WAF/CC 接入

```nginx
# main:
load_module modules/ngx_http_scdn_ban_module.so;
# http:
scdn_ban_agent /run/scdn-ban/events.sock 0 00000000-0000-0000-0000-000000000100;
# protected server/location:
scdn_ban on;
scdn_ban_scope $scdn_edge_site;  # or an explicit stable site ID without Edge
```

scope 使用最多 95 字节的稳定 ASCII 站点 ID，不使用任意客户端值。独立 server 可设置 scdn_ban_scope demo。Agent 刚启动且尚未应用初始集群表时，受保护入口返回 503；已经同步过的节点断线后继续使用原视图和期限。

已有 C 检测器可调用 ngx_http_scdn_ban_report(request, BAN_WAF/BAN_CC, reason)。已有 Lua WAF 的适配只需在真实命中后设置受控变量，不搬迁其规则引擎：

```lua
ngx.var.scdn_ban_reason = "942100"
ngx.var.scdn_ban_event = "waf"
return ngx.exit(403)
```

确认 CC 时设置已登记 cc reason 和事件 cc。不要从 `$http_*` 或响应状态直接映射这些变量。`scdn_ban_deny waf RULE;` / `scdn_ban_deny cc RULE;` 提供受信策略分支的 content handler；它拒绝当前请求并提交事件，不能与 proxy_pass 等内容处理器混用。

Nginx 前置检查返回有效 L7/L3 影子的 403，视图尚未就绪或读取不稳定为 503。普通请求只访问 mmap 的只读内存，不逐请求访问文件、跨机网络或 BPF Map。事件队列每 Worker 最多 1024 条，非阻塞投递，逐条等待持久回执后释放；连接恢复重放相同 producer/sequence，Agent 不重复执行。队列满不会阻塞业务 Worker，当前检测器仍负责拒绝攻击请求。

## 决策、期限和内核行为

policy 中 l7_seconds/l3_seconds 为固定期限，范围 1 秒～30 天；window_ms 为升级窗口，threshold 为 2～1024 次。WAF 首次是站点 L7；同 IP 的 WAF_DENY 和已存在 WAF L7 的 L7_HIT 在窗口内达到阈值后升级 L3。CC_CONFIRMED 直接申请 L3。只有真实有效 L7 ban_id 的拒绝命中才计入；fallback、L3 影子和错误返回不反过来成为攻击证据。

每个主请求使用随机 request ID，内部跳转/重传不重复计数；迟到事件有 event_age_ms 和策略代际限制。期限从本机 Agent 接受原始决策开始，重试或同步只消耗剩余时间。同 IP 的多设备事件合并为同一有效轮次，不能把期限向后延。IPv4-mapped IPv6 统一为 IPv4。

datapath.mode 显式选 xdp_native 或 tcx_ingress。XDP 使用 bpf_link，拒绝覆盖已有未知 XDP 程序；TCX 使用 BPF_F_BEFORE 插入现有 ingress 链前端，未命中返回 NEXT，不替换其他程序。已有 XDP REDIRECT 绕过 TCX 的负载均衡部署，必须先把过滤接入 XDP 上游，不能声称单独 TCX 覆盖该旁路。

内核使用普通 HASH 保存有效封禁，禁止 LRU 驱逐。匹配配置的目的 VIP 后查询源 IP 和 BOOTTIME，再按 TCP/UDP 端口丢弃。普通未封源不读时钟。已封源的分片/受限 IPv6 扩展包无法确认端口时按受保护 VIP 丢弃；正常 ARP/IPv6 邻居发现和未保护端口不被整体拉黑。只做 ingress，不承诺撤回已发送响应或阻止所有出站流量。

Agent Map 更新后读取核对，才发布 L3 影子；失败不报告内核应用成功。HTTP 可获得有界 L7 兜底，使用原决策时间和 L7 期限，local_waf=0，不进入升级统计；纯 TCP/UDP 没有应用兜底。Agent 停止时 pinned link/Map 继续运行，到期由内核自行停止 DROP，无需等待 GC。

## 全节点同步

所有设备配置相同 cluster_id、authority_epoch、members 和 allowlist；node_id 必须唯一，Master 设备本身也在 members 中。Master Agent 配 signing_key（Ed25519 私钥），所有节点配固定 verify_key；Node 配实际 mTLS CA、客户端证书/私钥和 HTTPS Master 根地址。签名密钥、mTLS 身份、本机管理身份分开。

Master 的原生 Sync 增加：

```nginx
# main:
thread_pool scdn_sync_ban threads=2 max_queue=32;
# http, alongside existing master role/peer/mTLS configuration:
scdn_sync_ban_agent /run/scdn-ban/sync.sock;
```

Sync 根据真实 TLS 验证和登记指纹取得 Node ID，再经限定 Worker UID 的 Unix RPC 交给 authority Agent。Node 自报头不能改变这个身份。接口如下：

| 接口 | 权限与含义 |
| --- | --- |
| POST /_scdn_sync/v1/ban/proposals | 登记 mTLS Node；上报原始 L3 决策，按持久 source sequence/event ID 去重 |
| GET /_scdn_sync/v1/ban/snapshot | 登记 mTLS Node；返回同一签名完整有效 IP 集合、members、撤销水位及 revision |
| POST /_scdn_sync/v1/ban/results | 登记 mTLS Node；回报匹配 revision/摘要的真实应用结果 |
| GET /__scdn_sync/v1/ban/status | 本机 Bearer control；authority 逐节点收敛状态 |
| POST /__scdn_sync/v1/ban/unban | 本机 Bearer control；正文 ip、ban_id，人工全局解封 |

完整快照使用 Ed25519 签署的 JSON 原始字节及 SHA-256，传输经 mTLS。persistent 将状态保存在私有 Ban Store AOF 中；本版不提供存储层加密，需部署磁盘加密时由系统落实。固定 authority_epoch 由管理员配置，不能由新载荷自动替换；最高已验证 revision/摘要持久化，拒绝倒退或同版本冲突。签名完整空表有效，下载/验签失败不是空表。

首次加入与重连都获取最新完整表。Master 对未变化 revision 复用已签名对象，Node 每 poll_ms 获取完整对象并校验；v0.1.0 尚未加入条件 GET/压缩优化，因此大表/多节点的网络成本需单独测量。不会把缓存任务的有限三次领取当作封禁投递：未确认本机意图保留 outbox，离线恢复后按原期限上报。

Node 将全局副本与尚未确认的本机 L3 意图合并；同 revision 仍会处理新收到的本机 ACK。接收副本、内核 DROP 和重放不会生成新的本地事件。新增/更新先于旧副本删除，不先清空 Map；整表应用不是内核原子切换，只有所有 Map/视图/日志处理完成后 ACK。Master 的 ALL_APPLIED 针对当前 members 和 revision，缺一个节点便为 PARTIAL；成员 ACK 超过 max(10 秒, 3×poll_ms) 未刷新也回到 PARTIAL，不以旧 ACK 永久宣称在线。

本机 L7 可在本机解除；L3 只能向 authority 申请全局解除，必须带当前 ban_id。解除保存时间水位，迟到原始决策和旧快照不能复活该轮次。新攻击在解除后仍可产生新决策，长期豁免需另行调整集群策略。跨机使用绝对 UTC 到期，转本机 BOOTTIME 时扣除 clock_uncertainty_ms；同一轮次重放保留更早的本机截止，不复制其他机器的 BOOTTIME。

## 持久化、两类日志和恢复

Ban Store 以内存索引和可选追加日志保存 PREPARE/决定、去重收据、事件窗口、outbox、全量快照与反重放水位。persistent 在事务 fdatasync 成功后才发送回执；Node 的 memory 模式仅表示本进程接受，重启从 Master 重新获取完整表。内核/共享视图是执行结果。APPLIED 仍与状态写入同一事务，日志可补投；两份文件任一失败时 logs_durable=0，不报告全节点完成。日志以字符串保存 64 位时间/序号，不记录 Cookie、认证值、请求正文或攻击载荷。

event_log 保存决策/应用/解除/过期/策略变更；ip_log 保存对应 IP 历史字段，seq 关联原始事件。扫描末条完整记录与存储高水位核对，半写尾可截断恢复，已完整记录冲突拒绝继续。以 256 项分页顺序补投直至追平；积压未追平不能当作已持久。文件超过 16MiB 后由 Agent rename/reopen，并以末序号命名归档，归档不自动删除；禁止 copytruncate 或外部回滚文件。

同 boot 重启重用同一 view inode 和 pinned Maps/links，核对实例配置摘要、程序 tag、接口、Map 布局及执行水位。持久状态落后于内核/视图水位时拒绝启动，避免旧备份使已执行决策倒退。持久 AOF、状态与审计日志需一致备份；不要在写入期间只复制文件前半部分。整机重启 tmpfs/bpffs 重建后按受信时间恢复剩余期限，禁止重置完整 TTL。

SIGHUP 只热更新 policy 的 TTL/窗口/阈值/事件时效，保留现有封禁期限并切换策略代际；不重建 Nginx Worker。身份、members、allowlist、服务/接口、Map ABI 或路径变化会返回 reload_requires_maintenance，必须走停服务、受控撤销/重建和验收流程。本版没有多 Master 自动选主，禁止两个权威写者；固定 epoch、state 锁和 runtime 锁用于防止意外共享状态/视图/Socket。

初版容量明确有界：4096 活动记录、8192 共享槽/最多 64 次探测、4096 内核封禁、1024 服务元组、128 VIP、128 事件连接、16 并发 RPC、1024 规则队列/Worker、16384 producer 和未确认 outbox 上限、200000 审计/来源回执上限、4MiB 快照/RPC。达到上限明确背压，不能驱逐有效封禁；执行表不提供在线扩容；存储层有独立配额、AOF checkpoint 与已投影审计回收，来源回执和生产者仍保留显式容量边界。

## 状态与管理

```sh
python native-ban/tools/banctl.py --socket /run/scdn-ban/admin.sock status
python native-ban/tools/banctl.py --socket /run/scdn-ban/admin.sock list
python native-ban/tools/banctl.py --socket /run/scdn-ban/admin.sock unban \
  --ip 198.51.100.23 --ban-id CURRENT_BAN_ID
```

kernel_ready 表示所有配置接口已附着；pending_enforcement 表示尚未确认执行的记录；logs_durable 为两份投影的真实状态。sync_error/policy_error 区分传输/执行错误与热配置失败。cluster_revision 是本节点已完整应用版本，authority 另提供 desired_revision、pending_nodes、cluster_state。没有为每个 IP 创建无界 Prometheus 标签。

停止 Agent 默认保留 pinned BPF，保护到原到期。需要维护撤销时，在确认目标/备份后使用相同配置运行 `scdn-ban-agent --config ... --detach`，只撤销本配置已核对的 links；保留 Map/历史文件以便审计。它不是跨版本自动迁移工具，也不删除其他程序的 pin。

## 验证范围

`tests/runtime.py` 要求 root/CAP_BPF/CAP_NET_ADMIN，主动创建随机名称的临时 netns/veth/bridge 和独立 bpffs，测试后停止所创建进程并清理这些对象。权限不足直接失败，不用 mock 或 skip 冒充真实 eBPF 验收。用 --mode tcx_ingress/xdp_native 分别验证；--static 验证静态编入的 Nginx 模块。

覆盖真实 HTTP/UDP 丢包、IPv4/IPv6、固定过期、L7 升级、任意设备全量发布、成员 ACK、解封、Master 断线、Agent kill/重启、只读 FD、过时/重复事件、CIDR 豁免、策略热更新、日志失败/补投，以及内核 BPF_PROG_TEST_RUN 的 VLAN/分片/边界语料。既有七模块回归同时执行。生产 NIC offload/多缓冲区、HTTP/3 L7、所有跨地域时钟/断电组合、全容量压力和 p99 收敛延迟需要目标环境验收，不能由隔离用例推导吞吐承诺。

保留的 compat/lib/security_guard 在真实 WAF 命中且 `$scdn_ban_enabled=1` 时自动上报该引擎返回的 rule ID；Agent trusted_rules 必须登记相同 ID。普通限流 429 不会自动变成 CC，CC 检测器仍须显式确认。主分支的 Sync 收据恢复/Lua 交接逻辑已合并保留。

`tests/lua_waf.py` 在 OpenResty 中执行保留的真实 SQL 注入规则和 security_guard，验证原生 scope/rule 上报、L7 和三节点内核 L3；该 4 项联动套件只在实际含 Lua 的 OpenResty 运行，不在纯 Nginx 冒报。

## 水位、时钟与日志恢复补充

签名 UTC 解封水位转换为本 boot 的事件截止时间，重复水位不滑动，旧排队事件不能复活封禁；更换 boot 清除旧单调水位，仍拒绝旧 boot 身份。恢复期限受原时长、UTC 期限和最后持久化剩余单调时间约束，时钟回拨不会增加额外小时。

日志投影一次启动处理有界的可恢复积压。仅变更回执/证据且没有待执行或日志错误时省略全量 reconcile，周期任务继续重试失败工作。tests/recovery.py --agent-build /absolute/build 验证真实 Engine/Ban Store/BPF 的四组恢复，--sanitize 启用辅助 ASan/UBSan。完整结论见[独立复审](../docs/AUDIT-REVIEW-2026-11-16.zh-CN.md)。

## Ban Store 配置与升级

Agent 0.2.0 内置 [Ban Store 0.1.0](../native-ban-store/README.zh-CN.md)。根对象可配置 storage.mode（persistent/memory）、max_entries、max_memory_mb 和 checkpoint_mb。默认 1,048,576 个内部条目、512MiB 计账预算和 64MiB 追加日志门限；它们不扩大本节列出的内核/视图 4,096 活动记录上限。

Nginx 只读 mmap 请求路径不访问存储。Agent 一轮 poll 中最多合并 128 个来源事件，持久提交后批量执行/投影并确认；回执和证据单独变化也不会复制整个 IP 集合。status.storage 明确报告模式、磁盘持久性、计账大小、日志、事务、同步和 checkpoint 情况。

memory 仅支持 Node：重启丢失本机状态，等待当前 Master 完整表，既有 Worker 使用新握手重编号待确认事件并保留旧观察代际；全局 IP 以原期限恢复。审计日志独立保留，不能把它们作为 memory 状态恢复来源。Agent 和 Ban 模块必须一起更新。

旧 state.sqlite 及伴随文件会触发明确的离线迁移错误，程序不读取或删除它们。本次没有自动转换器；已有权威状态应先备份并完成可信迁移，新 Node 可使用新私有目录重新同步，禁止通过清空权威水位绕过保护。
