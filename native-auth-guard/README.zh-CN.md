# Auth Guard 0.1.0

原生登录/注册准入模块，面向固定路由版本的 Sub2API 和 NewAPI。Worker 使用有界共享内存；没有 SQLite、Redis、外部查询或同步磁盘访问。账号声明和会话令牌仅以独立 realm 密钥的 HMAC 作为计数键；密码只在本次请求内用于公开弱值集合查询，既不记录，也不写入 Ban Store。

这套实现由原生模块、[Go 应用协作库](adapters/go/guard.go)、[版本核验的应用补丁工具](adapters/prepare_upstream.py)和[策略快照工具](tools/snapshot_policy.py)共同组成。只加载 Nginx 模块不能证明实际数据库写入前已经检查：后端必须安装协作补丁。当前不会自动修改、重编译或部署用户的上游应用。

## 1. 请求与结果

1. Bot/Ban 与可信地址检查之后，在 API 正文识别之前预留 realm/IP 容量；原始 location 的 ACCESS 规则仍然执行。
2. 有界读取至多 16 KiB 的认证 JSON，拒绝不明确编码、重复凭据键和超预算输入。新密码按完整原值 SHA-256 查询 [10,001 条公开弱值](../docs/security-seeds/weak-passwords.manifest.json)。登录可继续使用既有弱口令；加密登录交给应用解密。
3. 按应用实际使用的字段预留声明身份/IP 组合与身份并发。NewAPI 登录使用 username，附加 email 不能切换计数键；MFA 使用 opaque temp/flow token，附加 email 不能切换因子预算。这些声明不是已认证用户身份。
4. 向固定上游发送有 MAC 的私有上下文，绑定 node、realm、随机 attempt、策略版本、15 秒期限、方法、原始 URI、完整正文和可信客户端地址。客户端传入的 `X-SCDN-Auth-*` 会被移除并重建。
5. 后端在验证**这个邮箱的实际所有权**后调用 `RequireCreate`，检查当前应用设置、支持域、弱密码，再回调发起请求的 Node 的私有预创建接口。Node 重查策略新鲜度、attempt 期限、IP 短封、并发预留和人工解封 fence；允许后应用才执行账号插入。
6. 后端用明确的结果类型反馈；Node 验签并剥离私有响应头。HTTP 200、401、429、依赖 5xx 或自然语言错误文本都不是口令失败证据。`primary_ok_requires_verification` 不记为已完成登录；口令失败与第二因子失败分别计数。

所有认证响应附加 `Cache-Control: no-store`，无自动重试。读取正文前拒绝时会关闭该连接的 keepalive，防止未读凭据被当成下一条请求行并进入 Nginx 错误日志。仍应关闭认证路径包含 query/body 的外部审计日志；不要记录私有上下文、Cookie、Authorization 或响应令牌。

## 2. 内存状态、限额与封禁边界

共享 slab/rbtree 在本机 Worker 间协作，不依赖单 Worker 的私有计数。状态不足或分配失败返回 503，不能淘汰正在使用的身份桶来放行请求。桶最多存活两小时的空闲期，覆盖可配置的一小时最大短封/冷却；过期和异常 Worker 残留采用每轮最多 64 条的清扫。

| 项目 | 默认/硬上限 |
| --- | --- |
| realm 数量 / ID 长度 | 最多 32 / 64 字节 |
| 正文 / 顶层字段数 | 16 KiB / 128 |
| zone 大小 | 1–256 MiB，由管理员配置 |
| `max_entries` | 默认 65,536，范围 1,024–1,000,000，仍受 zone 实际容量限制 |
| `max_inflight` | 默认 512，范围 4–4,096 |
| realm / IP / 组合 / 声明账号同时在途 | 128 / 4 / 2 / 8 |
| 每 IP 准入 | 默认每分钟 60、burst 20；GCRA，不等待排队 |
| 口令/因子组合失败 | 默认 300 秒内 5 次，冷却 60 秒 |
| 异常注册 | 默认 300 秒内至少 20 次政策/邮箱码拒绝、5 个不同声明身份、拒绝占比至少 90% |
| 异常注册 IP 短封 | 默认 600 秒，固定到期；被拦截的重试不续期 |
| attempt 最长期限 | 15 秒；超时取消上游，清扫崩溃 Worker 预留 |

realm 总量还受 IP 速率的 32 倍、burst 的 16 倍约束。账号维度记录不同来源及失败行为，但不会仅凭匿名失败锁死整个账号；组合冷却只影响该 realm、该 IP 和声明身份。人工解封使用**独立管理密钥**，推进 fence，旧在途反馈不能重新封禁该 IP。

**IP 短封目前只保护本节点的该 realm 认证路由；普通网站/API 请求不受此状态影响。** 它不接入 Ban Agent、Ban Store、内核 L3、跨 Node 同步或持久化。重启会丢失；reload 在同一 zone、相同 realm/key 列表时保留。状态接口明确 `durable_ip_bans=false`、`global_quota=false`。不能冒充旧 WAF/CC 来源发送到自动 L3 升级路径。

`scdn_auth_mode observe` 观察边缘弱值/域名/速率/冷却/短封命中，但硬容量、输入完整性、签名、期限和后端的真实邮箱所有权/创建政策仍然执行。它不是允许异常账号创建的开关。

## 3. 应用适配

[锁定文件](adapters/upstream-lock.json)固定 Sub2API `15871f904056f548dd874a1d069ffc6cdf777b78` 和 NewAPI `669d774976369e986f03b6e24fff1042f6f94832` 的相关源文件摘要。先在干净的隔离上游 checkout 生成补丁；工具只输出 diff，拒绝已修改的源文件，不修改 checkout。两者生成代码均复用这里的标准库 Go 协作库，无需额外 Go 第三方依赖；Gin 使用应用原有版本。

```sh
python native-auth-guard/adapters/prepare_upstream.py \
  --application sub2api --source /srv/build/sub2api \
  --output /srv/build/sub2api-auth.patch
git -C /srv/build/sub2api apply --check /srv/build/sub2api-auth.patch
# 审核 diff 后，在该隔离 checkout 应用并执行应用自身的构建/测试：
git -C /srv/build/sub2api apply /srv/build/sub2api-auth.patch
# NewAPI 改为 --application newapi，源目录与输出也分别指定。
```

Sub2API 补丁从 `SettingService.GetPublicSettings` 读取实时开关及邮箱后缀，只在 `emailService.VerifyCode` 实际成功后标记邮箱已验证，在 `createUserAndClaimInvitation` 前回查。共享 user repository 对带认证上下文的写入再次核对已放行邮箱，覆盖未安装所有权 hook 的 OAuth 自动创建；可信管理/CLI 创建保持自身权限边界。

Sub2API 的新 OAuth 创建在首版补丁中会被 repository fence 拒绝，直至为该提供者的实际邮箱证明接入 `RequireCreate`；已有 OAuth 账号登录正常经过原应用验证，不被要求重新注册或改写合成邮箱。不要把“提供者返回了一个 email 字符串”当成真实所有权证明。

NewAPI 补丁在 `cleanUser.Insert` 前调用协作库；关闭邮件验证时严格注册失败。统一 OAuth 路径要求实现 `VerifiedEmailProvider`、成功获取并匹配实际邮箱，再在事务前检查；未提供已验证邮箱的提供者、新 WeChat 自动账号创建被拒绝。已有账号登录继续原流程。退役 Telegram legacy 路径不重新启用。

两者将明确的 credential 错误、MFA 中间态、完成登录/注册及已知因子错误接入结果反馈；数据库故障不转换为失败口令。Passkey 等未提供精确 typed outcome 的失败只受输入/IP/并发准入限制，不能宣称已完成全部应用错误类型映射。

生成补丁需在**实际部署的定制版**重新复审。当前测试验证固定源码摘要、Go 语法和 `git apply --check`，以及真实 Go SDK 与 C 模块的互操作；不替代整个 Sub2API/NewAPI 应用构建和部署验收。

应用通过 `SCDN_AUTH_GUARD_CONFIG` 指向私有配置，例如：

```json
{
  "realm": "sub2api-main",
  "key_file": "/etc/scdn/auth/sub2api.key",
  "password_file": "/etc/scdn/auth/weak-passwords.sha256",
  "nodes": {"node-a": "https://node-a.internal.example/auth-control"}
}
```

node→control endpoint 必须显式固定；也支持 `unix:///run/scdn/auth-control.sock`，HTTP 仅允许数字 loopback。HTTPS 使用正常证书验证，不跟随重定向；应用必须使用边缘签名给出的可信客户端地址，不能让任意客户端头覆盖风控或验证器 IP。现有 CAPTCHA、CSRF、MFA、邀请码、配额和事务不被替换。

## 4. 最小策略读取与 Nginx 接入

安装补丁后专用 exporter 为 Sub2API `/api/v1/internal/scdn-auth/policy`、NewAPI `/api/internal/scdn-auth/policy`。请求 MAC 绑定时间、随机值和 realm；响应 MAC 再绑定同一请求及完整响应。只返回注册/邮件验证开关、规范化支持域、别名政策和版本。**不访问 NewAPI `/api/option/` RootAuth，不下发应用 Root 凭据。**

Sub2API 的非白名单域名 quota 例外不被继承；NewAPI 关闭域限制时导出空 allowlist。空表、关闭邮件验证或超过 `max_age` 均关闭严格注册，不变成无限制注册。`*.enterprise.example` 与调查的 Sub2API 一致，同时匹配 base 和子域；不匹配追加攻击域。当前策略只接受显式 ASCII DNS 名称，国际域名请在受控配置阶段转为 A-label；不在 Worker 猜测 Unicode/IDNA。

将模板中的绝对路径、realm、Node 和 exporter URL 改为自身值，先生成最小快照，再 `nginx -t`、reload。工具失败保留上一份输出，不自动 reload；必须由运维定期执行并监控失败/到期。原子替换后目录 fsync 失败会明确报告“已替换但耐久未确认”，不能当作完全未发布。

```sh
umask 077
openssl rand -out /etc/scdn/auth/sub2api.key 32
openssl rand -out /etc/scdn/auth/admin.key 32
# 各 realm 与 admin 使用不同密钥，文件仅所属运行身份可读。
python native-auth-guard/tools/snapshot_policy.py \
  --config /etc/scdn/auth/sources.json --output /etc/scdn/auth/policy.json
```

[sources 模板](examples/sources.json)和 [Nginx 示例](examples/nginx.conf)使用占位路径，不包含真实密钥。Linux 密钥必须为不跟随符号链接的私有普通文件；Windows 运维需自行配置等效 ACL。更换 realm 列表、顺序或密钥时不得静默复用旧共享状态：当前 zone 兼容标签会拒绝不一致 reload，应采用新 zone 并明确交接；计数不是可迁移的账号数据。

| 指令 | 上下文 | 作用 |
| --- | --- | --- |
| `scdn_auth_policy FILE` | http | 只在加载配置时读取策略、realm 私有密钥、公开弱值集合、可信代理 |
| `scdn_auth_zone NAME SIZE` | http | 一个 slab zone，1–256 MiB |
| `scdn_auth_guard REALM\|off` | http/server/location | 选 realm；关闭/启用决策随主请求跨 profile 保留 |
| `scdn_auth_mode enforce\|observe` | http/server/location | 默认 enforce，观察边界见上文 |
| `scdn_auth_control` | 私有 location | HMAC 认证预创建/管理解封；请求最多 4 KiB |
| `scdn_auth_status` | 私有 location | 聚合状态，不输出账号、口令、令牌、密钥或 IP 列表 |

变量为 `$scdn_auth_realm`、`$scdn_auth_client_ip`、`$scdn_auth_result`。可信地址与 Bot 共用 `native-security` 静态帮助代码，但各自使用显式代理范围；实际 peer 优先，可信代理才从右向左解析有界 XFF，IPv4-mapped IPv6 归一化。不要将所有公网地址配置为可信代理。

全量动态加载顺序：Config → Bot → Ban → Auth Guard → Tier → API → Edge → Purge → Sync。Auth Guard 可独立加载；若同次构建的 API/Edge 调用其 C 接口，必须先加载。私有控制/status 不应暴露于业务公网 server。

## 5. 验证

```sh
(cd native-auth-guard/adapters/go && go test -race ./...)
(cd native-auth-guard/tests/backend && go build -o /tmp/scdn-auth-backend .)
python native-auth-guard/tests/tools.py --report /tmp/auth-tools.json
python native-auth-guard/tests/integration.py --prefix /tmp/scdn-plugin \
  --backend /tmp/scdn-auth-backend --report /tmp/auth-runtime.json
# 静态构建的集成测试另加 --static。
```

集成测试只使用内存计数的账号创建 fixture、一次性私有密钥和本机 Go SDK 服务；验证创建 gate、策略 MAC、原始正文、错误结果、弱口令、邮箱域、固定短封、MFA、并发、超时及 Worker 崩溃清扫。无真实账号、邮件发送、模型调用或生产改动。完整记录见 [Auth 验证](../docs/validation-auth-guard-20261117.json)。
