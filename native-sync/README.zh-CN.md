# 原生 Sync 模块：站点/证书同步与缓存任务

版本：0.3.0。当前交付为可编译、加载的 `ngx_http_scdn_sync_module.so`，不依赖 Lua。实现实例级角色、配置约束、本机控制鉴权、Master 的 mTLS 节点登记与能力发现。

本目录是 `OpenResty_Plugin` 的原生 Sync 入口。实现来源及校验摘要见 [SOURCE](../SOURCE.md)，安装、角色示例、测试和迁移说明均在本仓库内；旧 Lua 同步是否保留由迁移阶段决定，不能与原生发布者同时写入同一受管配置。

**0.3.0 已实现站点配置/证书的原生发布与应用。** 启用 config_state 后由 Master 自动发布按节点加密签名的完整快照，Node 拉取校验、版本化证书、配置热应用、结果重报及失败恢复。功能和精确边界见 [完整发布手册](../docs/SYNC-PUBLICATION.zh-CN.md)。未启用发布的实例仍返回 not_started；不再把启用实例的状态固定为未开始。旧 Lua 协议需独立迁移，不直接兼容。

## 缓存刷新与预热

0.2.0 提供 Master 持久队列、Node 原生后台 mTLS 拉取、Purge 刷新、验证 HIT 的本机预热及结果回报。该功能默认关闭，独立于 0.3.0 新增的站点/证书发布通道；启用后能力位 `cache_tasks/cache_refresh/cache_preheat=true`，未启用时为 false。完整指令、接口、恢复语义与示例见 [缓存任务手册](../docs/CACHE-TASKS.zh-CN.md)。自定义 HTTP 头见 [统一约定](../docs/HTTP-HEADERS.zh-CN.md)。

## Master 与 Node

一个 Nginx 实例选择一个角色。Master 与 Node 分别运行各自配置；默认 `off`，不注册业务 handler。角色不能在 location 中更换。

这里的 Master/Node 是业务同步角色，与 Nginx 自己管理 Worker 的 master 进程不同。角色和登记信息属于启动配置，修改后需按 Nginx 的配置 reload 流程生效；Config 站点数据热更新不修改这些身份。

| 配置/接口 | Master | Node |
| --- | --- | --- |
| `scdn_sync_id` | Master 实例 ID，必填 | Node ID，必填 |
| `scdn_sync_scope` | 拒绝；scope 属于各节点登记 | 必填 |
| `scdn_sync_peer` | 登记 Node ID、scope 与客户端叶证书 DER 的 SHA-256 | 拒绝 |
| `scdn_sync_api control` | 本机状态、能力与节点登记查询 | 本机状态与能力查询 |
| `scdn_sync_api exchange` | 仅允许启用 mTLS 的 Master | 配置检查失败 |

## 配置指令

以下实例指令放在 `http` 中：

```nginx
scdn_sync_role master;  # off / master / node
scdn_sync_id master-a;
scdn_sync_control_token_file /etc/scdn-sync-native/master/control.token;
# Master only:
# scdn_sync_peer node-a edge <64 lowercase hexadecimal characters>;
```

Node 使用 `scdn_sync_role node`，配置自己的 ID 与 `scdn_sync_scope edge`。ID 保持旧协议约束：首字符为 ASCII 字母或数字，其余可含 `_`、`-`，最长 96 字节。Master 最多登记 1024 个节点，重复 ID 或证书指纹会被拒绝。

在选定 location 中配置 `scdn_sync_api control` 或 `scdn_sync_api exchange`；不能与另一个 content handler 组合。完整示例见 [Master](examples/master.nginx.conf) 与 [Node](examples/node.nginx.conf)。示例不包含实际凭据；Master 节点登记默认为空，所有远程节点访问均被拒绝。

示例使用独立的 `/etc/scdn-sync-native`、`/run/scdn-sync-native-master` 和 `/run/scdn-sync-native-node` 路径。Master 8443 是示意端口；不要让这些原生角色 location 替换旧 Lua Sync 正在使用的 desired/objects/reports 或本机事务入口。

token 文件要求绝对路径、普通文件、无组/其他用户权限，不接受叶路径符号链接；内容为 43～128 个 base64url 字符，可附一行 LF/CRLF。部署时使用受限父目录和正确文件所有者，并由密码学安全随机源生成。配置检查和 reload 时读取，运行中替换文件需 reload 才生效。日志不记录 token 内容，控制 location 建议关闭访问日志。

## 已实现的 API

| 方法与路径 | 入口 | 权限与结果 |
| --- | --- | --- |
| `GET/HEAD /__scdn_sync/v1/status` | control | 实例角色、ID、scope、节点数量、当前未启动状态 |
| `GET/HEAD /__scdn_sync/v1/capabilities` | control | 原生版本、目标协议、已实现与未实现能力 |
| `GET/HEAD /__scdn_sync/v1/peers` | Master control | 已登记节点与 scope，不返回指纹或凭据 |
| `GET/HEAD /_scdn_sync/v1/capabilities` | Master exchange | 根据真实 mTLS 身份返回该 Node 的绑定与 Master 能力 |

control 同时要求真实传输连接来自 Unix Socket 或 loopback，并验证 `Authorization: Bearer ...`。检查不依赖客户端提供的转发头。exchange 要求配置 `ssl_verify_client on`，运行中还核对实际 TLS 客户端证书验证结果及登记的 SHA-256；token 或自报 Node ID 不授予 exchange 权限。

角色查询拒绝查询参数、编码后的 API 路径、GET body 与修改方法；缓存任务按独立的 POST/GET/DELETE 合同开放。响应为 JSON、`Cache-Control: no-store`。未实现的 desired、objects、reports、heartbeat、stage、commit 等操作不会返回成功；后续迁移按能力位逐项开放。此处的 bearer 控制接口是原生组件新接口，不能宣称与旧 Lua 控制 token 请求头已经兼容。

本机调用可把凭据保存在 0600 的 curl 配置文件，使用 `curl --config /etc/scdn-sync-native/master/control.curl.conf --unix-socket /run/scdn-sync-native-master/control.sock http://localhost/__scdn_sync/v1/status`。配置文件内容为私有的 `header = "Authorization: Bearer <private-token>"`，不把实际 token 写入脚本、Git 或命令行。Node 相应替换目录与 Socket 路径。

只读变量 `$scdn_sync_role`、`$scdn_sync_id`、`$scdn_sync_scope` 可用于 Nginx 配置。Master 的 scope 变量为空；Node 的 scope 为自身托管范围。

## 构建与验证

模块源码通过 Nginx `auto/module` 接入，支持动态或静态构建；需匹配目标 Nginx/OpenResty 的版本、ABI 和构建条件。统一构建包含 Sync、Config、API、Edge、Tier、Purge 六个模块。Sync 可独立加载；另外三个业务模块仍按 Config → API → Edge 加载，Purge 也独立使用。

```sh
# Native helpers, with warnings treated as errors.
sh native-sync/tests/check-core.sh

# Full OpenResty build, into a new isolated prefix.
sh tools/build-runtime.sh /tmp/scdn-native-openresty openresty
python native-sync/tests/integration.py --prefix /tmp/scdn-native-openresty

# Also prove the module works without Lua, using the bundle's nginx core.
sh tools/build-runtime.sh /tmp/scdn-native-nginx nginx
python native-sync/tests/integration.py --prefix /tmp/scdn-native-nginx
python native-sync/tests/cache_tasks.py --prefix /tmp/scdn-native-nginx

# Static OpenResty includes all six modules; remove load_module directives.
sh tools/build-runtime.sh /tmp/scdn-native-static openresty static
python native-sync/tests/integration.py --prefix /tmp/scdn-native-static --static

# Activate Sync roles beside Config/API/Edge/Purge and exercise real proxy I/O.
python native-api/tests/integration.py --prefix /tmp/scdn-native-openresty \
  --purge --sync --report /tmp/scdn-five-modules.json
```

构建脚本固定 OpenResty 1.31.8.1 并校验归档 SHA-256；拒绝覆盖已有安装。系统需要 C 编译器、make、Perl、PCRE2/OpenSSL/zlib 开发包、libcurl 开发包（7.85+）和 curl。进程测试需要 Python `cryptography`，复用仓库现有测试依赖。

`native-sync/tests/build-runtime.sh` 保留为统一构建入口的兼容包装器，支持相同的 runtime/linkage 参数。测试 `--module` 可指定另一个动态产物，不能与 `--static` 同用。Sanitizer 使用仓库公共 [tests/asan.supp](../tests/asan.supp)，只排除 Nginx 生成注册表的既有 ODR 报告。

测试仅使用临时 CA、token、loopback 端口与 Unix Socket，结束后停止所创建进程并删除材料。可用 `--report /outside/repository/results.json` 保存不含凭据的检查摘要。

本地验证结果与适用边界见 [验证记录](tests/VALIDATION.zh-CN.md)。

## 发布配置及后续边界

完整的 config_state/source/peer_key/signing/trust/mTLS/managed 配置、实例目录、API、事务恢复和验证见 [站点/证书发布手册](../docs/SYNC-PUBLICATION.zh-CN.md)。对象使用固定 AES-GCM/RSA-OAEP/Ed25519 原生二进制封装；旧 Lua JWE/JWS 互通、HTTP nonce 请求签名、自动密钥轮换与跨地域容量验证未被宣称完成。

Config/Edge 已支持 [缓存响应头与规则回源头](../docs/CACHE-HEADERS.zh-CN.md)，这些字段会随完整站点快照发布。原生 [Tier](../native-tier/README.zh-CN.md) 提供 L1/L2 读取链并与 Purge 版本失效、缓存任务预热配合。Ban 跨机封禁仍按独立设计推进。
