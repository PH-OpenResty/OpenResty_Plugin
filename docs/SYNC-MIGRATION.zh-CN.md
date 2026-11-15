# 原生 Sync 安装、共存与迁移

本仓库包含 `native-sync` 0.1.0 的角色/身份基础，与 Config、API、Edge、Purge 统一构建。它提供实际可加载的原生模块及只读鉴权接口；完整 Master→Node 加密同步仍由原 Lua Sync 部署承担。

## 1. 能力对应

| 能力 | 当前原生入口 | 接入决定 |
| --- | --- | --- |
| Master/Node 实例角色、ID、scope | Sync | 独立 Nginx 实例显式选择；默认 off |
| 本机控制认证、Master mTLS 节点登记 | Sync | 使用独立凭据、Socket 和监听端口 |
| 文件内容变更与本机站点热更新 | Config + Edge/API | 与 Sync 角色接口分开，不代表远程同步 |
| 按节点加密发布、对象下载、签名/防重放 | 原 Lua Sync | 继续保留既有服务，原生能力位仍为 false |
| Node 拉取、stage/commit/rollback/finalize、报告队列 | 原 Lua Sync | 不把原生只读 location 接到旧生产路由 |
| Sync journal、发布历史与业务探测 | 原 Lua Sync / 外部控制面 | 不复用 Purge journal 或 Config generation 冒充 |

## 2. 独立构建与测试

```sh
sh native-sync/tests/check-core.sh
sh tools/build-runtime.sh /tmp/scdn-sync-native nginx
python native-sync/tests/integration.py --prefix /tmp/scdn-sync-native \
  --report /tmp/scdn-sync-native-results.json

sh tools/build-runtime.sh /tmp/scdn-sync-static openresty static
python native-sync/tests/integration.py --prefix /tmp/scdn-sync-static --static
python native-api/tests/integration.py --prefix /tmp/scdn-sync-static --static \
  --purge --sync --report /tmp/scdn-five-modules-results.json
```

产物必须匹配目标运行时的架构、ABI、SSL 和编译选项。动态 Sync 可单独加载，不要求加载 Config/API/Edge/Purge。一起加载时保留业务模块的 Config → API → Edge 顺序，Sync 与 Purge 无相互加载依赖。静态构建不写重复的 load_module。

## 3. 首次配置

按真实服务账户创建受限目录，保留现有服务的备份和回退点。示例路径使用 `/etc/scdn-sync-native/master`、`/etc/scdn-sync-native/node`，以及独立的 `/run/scdn-sync-native-master`、`/run/scdn-sync-native-node`。

每个实例用不同随机控制 token。首次生成可使用受限账户运行 `umask 077` 与 `openssl rand -hex 32`，输出重定向到对应 `control.token`；启用 noclobber 防止覆盖已有凭据，文件权限 0600/0400。master 与 worker 要按实际启动身份读取/使用配置；不要把真实 token 放进 Git、示例或命令行参数。

Master 为 exchange 准备受信服务端证书、私钥和 Node CA，配置 `ssl_verify_client on`，再以 Node 客户端叶证书 DER 的 SHA-256 登记节点。未登记证书、客户端自报 Node ID 或控制 token 不能授权 exchange。指纹提取可用 `openssl x509 -in node.crt -outform DER | openssl dgst -sha256`，登记时仅填写 64 个小写十六进制字符。

Node 当前配置自己的角色/ID/scope 和本机 token，没有已实现的 Master URL、自动轮询或发布应用事务。完整模板见 [Master](../native-sync/examples/master.nginx.conf) 与 [Node](../native-sync/examples/node.nginx.conf)。

## 4. 查询与判读

把实际 `Authorization: Bearer ...` 保存到 0600 的 curl 配置文件，通过 `curl --config /etc/scdn-sync-native/master/control.curl.conf --unix-socket /run/scdn-sync-native-master/control.sock http://localhost/__scdn_sync/v1/status` 查询。Node 使用自己的目录与 Socket。

- control 接口同时检查真实 Unix/loopback 连接和独立 Bearer token。
- exchange 只允许 Master，并核对实际 TLS 验证结果及登记指纹。
- 只读方法为 GET/HEAD；修改方法为 405，带正文/查询串或编码路径为 400，认证错误为 401/403。
- 当前 status 的 `sync_state=not_started`、`applied_revision=null`、`business_health=unknown` 是真实能力边界，不通过 watcher 的 revision 填充这些字段。
- capabilities 的 `encrypted_distribution/node_pull/apply_transactions/business_health` 仍为 false。查询成功只证明当前角色/身份接口正常。

## 5. 旧 Lua Sync 的共存规则

1. 先在新端口、Socket、token 路径中验证原生角色接口，避免与旧服务共享控制路由。
2. 保留旧 desired/objects/reports/heartbeat 和本机 stage/commit 等全部实际工作入口；原生模块当前不会实现这些操作。
3. 为站点数据保留唯一权威发布者。原生 Sync 的导入不新增配置写入、站点 Lua 编译或 `.conf` 生成器。
4. 不把本机 Bearer token 与旧 Lua 本机控制头当作兼容协议，也不复用 Node 身份密钥作为本机管理凭据。
5. 后续每个原生能力按 [路线图](SYNC-ROADMAP.zh-CN.md)完成互通、故障恢复及目标环境验收后，再逐项切换。

更改 Sync role/ID/peer/token 属于 Nginx 启动配置，按 `-t`、reload/重启及回退流程操作。Config 文件监听的无 Worker 重建能力仅覆盖其站点数据，并不会热改 Sync 身份。Node 原有业务配置不因原生能力处于 not_started 而被清空或替换。
