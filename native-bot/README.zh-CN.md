# Bot 0.1.0：UA 与 CIDR 管理

`ngx_http_scdn_bot_module` 是原生 C HTTP 模块，支持纯 Nginx、OpenResty、动态与静态构建。请求路径使用启动时编译的 UA 自动机和 IPv4/IPv6 前缀树，不查 DNS、不下载地址表、不读策略文件，不依赖 Lua、SQLite 或 Redis。

## 安装和接入

统一构建包含八个 HTTP 模块。完整动态加载顺序为 Config → Bot → Ban → Auth Guard → Tier → API → Edge → Purge → Sync。同一次构建中的 API/Edge 会显式调用 Bot，在正文识别前执行廉价检查；这些动态模块需一起更新并先加载 Bot。Bot 本身可独立加载；使用站点 ID 作用域时需加载并启用 Edge。

Bot 共享的地址解析头文件位于 `native-security/src/`，需要与 `native-bot/` 一起保留，不产生额外动态模块。

先将仓库中的可审查种子编译为实际策略：

```sh
python native-bot/tools/build_catalog.py --out /etc/scdn/bots.conf
```

在已有 Nginx 配置中加入：

```nginx
load_module modules/ngx_http_scdn_bot_module.so;
http {
    include /etc/scdn/bots.conf;
    scdn_bot_zone bot_counts 64k;

    # 只填写实际的前置代理，不默认信任访客提供的地址头。
    # scdn_bot_trusted_proxy 192.0.2.0/24;

    server {
        listen 8080;
        scdn_bot on;
        scdn_bot_mode observe;
        location / { root /srv/www; }
    }
    server {
        listen unix:/run/scdn/bot-admin.sock;
        scdn_bot off;
        location = /status { scdn_bot_status; }
    }
}
```

该片段展示独立 Bot，实际业务可使用 Config/Edge 的现有代理链。控制 Socket 的目录与权限由管理员配置，不应将控制状态 location 放进由 Edge 完全接管的业务路由。先用 `nginx -t` 校验，再按既有管理流程 reload；编译工具不自行重启或接管服务。

## 拒绝与分类

每条 entry 的 UA 与 IP 条件采用 **OR**。一个 UA 命中，或一个 IP/CIDR 命中，都可以触发该条拒绝规则；换成浏览器 UA 不能绕过地址拒绝。拒绝优先于观察/普通分类。搜索来源分类不会跳过认证、WAF、站点停用、协议或容量规则。

内置目录来自[种子数据](../docs/security-seeds/README.zh-CN.md)。当前有 29 个可匹配条目，另列 4 个无法独立识别的搜索服务。实际默认策略含 44 个 UA 模式、1,590 条按规则关联的前缀；完整来源库存仍有 17 份、3,154 条记录，两份 Google 用户触发来源未被宽泛 UA 自动绑定。已知 IP 的来源分别查询对应表，没有 IP 的保留 UA 路径。源表共享不等于已独立证明具体 Bot 用途。

Censys 的官方 `CensysInspect` 与 16 个 IPv4、4 个 IPv6 前缀默认拒绝。FOFA 的 `FofaBot` 为默认拒绝的候选 UA，尚无完整权威 IP 清单；不将候选当作完整识别能力。公开端口/TLS 发现、未知浏览器伪装扫描和源站直达还需要原有网络/管理入口边界与其他行为控制。

搜索请求来源状态区分 `ip_match`、`seed_ip_match`、`ip_mismatch`、`stale`、`ua_only`、`candidate_ua`、`unknown`。种子数据不是本次新抓取的结果；只有经过更新工具实际获取的数据标为 published。任何来源状态都不授予身份或认证豁免。

## 自定义规则

最小 JSON 规则文件可以同时含 UA 与 IP，例如：

```json
[
  {
    "id": "deny-custom",
    "site_id": "site-example",
    "action": "deny",
    "ua": [{"type": "product_token", "value": "ExampleBlockedBot"}],
    "ip_cidrs": ["203.0.113.0/24", "2001:db8:100::/48"]
  }
]
```

```sh
python native-bot/tools/build_catalog.py --rules /etc/scdn/custom-bots.json --out /etc/scdn/bots.conf
```

`--site SITE_ID` 将整个目录限制到一个 Config/Edge 站点；每条规则的 `site_id` 可单独指定。站点 ID 来自已登记的配置，访客头不能创建它。空规则、重复 ID、非规范 CIDR、控制字符及预算超限拒绝编译。规则包含引号、分号、反斜线、美元符号时仍按字面数据解析，不生成额外指令。

## 更新和发布

```sh
python native-bot/tools/build_catalog.py --refresh --out /etc/scdn/bots.conf
```

`--refresh` 仅访问代码中固定的 17 个官方来源，使用 HTTPS、正常 CA/SNI 验证、公共 DNS 地址检查和固定连接地址。重定向只接受同一官方主机的 HTTPS；每份数据最多 8 MiB，完整解析/规范化后才发布。地址数或覆盖地址空间显著变化需明确的 `--accept-large-change`；异常宽泛的自动来源前缀仍拒绝。只读查询不需要任何厂商账号、Key 或 Cookie。

任一来源失败时不替换原 include。写入采用临时文件、文件同步、原子替换和目录同步；如果替换后目录同步失败，工具明确报告已经替换且持久性未确认，不谎称旧文件仍在。工具不自动 reload，失败输出不应触发激活。更新任务可由现有管理系统在后台调用；本模块没有在 Worker 自动轮询或加入 Sync 的新资源类型。

## 指令与变量

| 指令 | 作用域 | 默认/含义 |
| --- | --- | --- |
| `scdn_bot on/off` | http/server/location | off；显式关闭决策可跨同一请求的 profile 跳转保留 |
| `scdn_bot_mode enforce/observe` | http/server/location | enforce；observe 将拒绝记录为 would_deny 并继续原业务 |
| `scdn_bot_ua_limit SIZE` | http/server/location | 2 KiB，可设 128～8192 字节；超出不静默截断 |
| `scdn_bot_trusted_proxy CIDR` | http | 默认无；最多 1024 条 |
| `scdn_bot_entry ID CATEGORY ACTION [SITE_ID]` | http | 声明规则；ACTION 为 continue/observe/deny，最多 256 条 |
| `scdn_bot_ua ID TYPE VALUE` | http | TYPE 为 token/phrase/exact/prefix/contains；ASCII 不区分大小写 |
| `scdn_bot_ip ID CIDR` | http | 地址条件；最多 16,384 条前缀 |
| `scdn_bot_feed ID MODE CHECKED_AT MAX_AGE` | http | MODE 为 manual/seed/published/candidate；更新工具生成 |
| `scdn_bot_zone NAME SIZE` | http | 可选跨 Worker 计数，8 页～1 MiB |
| `scdn_bot_status` | location | 只读 GET/HEAD JSON，no-store；放在受控管理入口 |

UA 总模式最多 512 个、每个最多 256 字节、自动机最多 32,768 个节点；一次请求最多处理 4096 个候选匹配。拒绝无限制正则，超出 UA/匹配预算返回 431，重复 UA 或不明确的可信转发链返回 400；观察模式记录 would_deny。拒绝响应 no-store。共享计数的 actions 顺序为 continue、observe、deny、invalid、would_deny，按主请求只计一次。

可使用 `$scdn_bot_id`、`$scdn_bot_category`、`$scdn_bot_source`、`$scdn_bot_action`、`$scdn_bot_match`、`$scdn_bot_client_ip`、`$scdn_bot_identity`。它们用于受控日志/诊断，不应组成新的账号授权或高基数 Prometheus 标签。没有执行决策的请求不凭变量查询补做一次晚到的安全检查。

## 客户端地址与访问阶段

TCP 首先从真实 Socket 获取对端。仅当该对端命中管理员的可信代理 CIDR，才从右向左解析单份 X-Forwarded-For，最多 16 跳、2048 字节，并停在首个不受信地址。IPv4 映射 IPv6 统一成 IPv4。X-Clinet-IP、X-Real-IP 和任意访客头默认不提供身份权限。对未连接的传输，存在 stock realip 模块时通过其公开原始对端变量恢复地址，不复制 Nginx 私有 realip 结构。

Edge/API 的代理跳转已移到 ACCESS 之后；PREACCESS 只固定站点、执行廉价检查和必要的有界准备。这样原始 location 的 deny、HTTP Basic Auth、Lua WAF/限流可以执行。使用站点 WAF/限流的部署应将保留的 `security_guard` 放在 server 或原始入口，不能只放在命名代理位置；现有桥通过原生 checked 标记避免跳转后重复计数。新增源码需要 API/Edge 一起更新。

Bot 不自动调用旧 WAF/CC 的 Ban 上报，不产生全节点 L3 封禁。IP 拒绝来自版本化策略；运行状态明确报告 automatic_ip_ban=false、sync_resources=false。Auth Guard 与其行为/IP 决策是独立后续能力。

## 验证

`native-bot/tests/integration.py` 覆盖真实代理、独立 Bot、UA/IP OR、IPv4/IPv6、可信/伪造代理链、HTTP/2 多流隔离、特殊字符、观察/关闭、共享计数和正文前拒绝。`native-bot/tests/catalog.py` 覆盖数据完整性、异常来源与写入故障。原始访问控制的独立回归位于 `native-api/tests/access_phases.py`；所有程序使用隔离前缀和本机服务，不修改生产或调用真实模型。
