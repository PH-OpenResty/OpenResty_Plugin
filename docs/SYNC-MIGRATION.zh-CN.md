# 原生 Sync 安装、共存与迁移

Sync 0.3.0 已提供原生站点配置/证书发布与应用，并继续支持缓存任务。它和 Config、Tier、API、Edge、Purge 统一构建。完整指令、目录与协议见 [发布手册](SYNC-PUBLICATION.zh-CN.md)，缓存维护见 [缓存任务](CACHE-TASKS.zh-CN.md)。

## 能力与交接

| 能力 | 原生入口 | 迁移要求 |
| --- | --- | --- |
| Master/Node、mTLS、scope、本机 token | Sync | 独立身份和 Socket；不从转发头授权 |
| 站点完整集合与证书链/私钥 | Sync native.snapshot.v2 | Master source、每 Node RSA 公钥、Master Ed25519 签名密钥 |
| Node 版本化落地与应用 | Sync + Config managed + Edge | 受管目录、有效 bootstrap、全 Worker 确认、previous/pending 回退 |
| API/流式策略 | API/Edge | 继续使用现有 profile 和可信源站 TLS 配置 |
| 缓存维护 | Purge/Sync cache tasks | 独立 token/journal，刷新成功后再按需要预热 |
| L1/L2 读取链 | Tier | 两个 Nginx cache zone、本机受限 Socket、原生选层与冷层保留 |
| 旧 Lua 加密/HTTP 协议 | 不与 native v2 直接互通 | 独立部署验收后交接写入权，不能替换路由便假定兼容 |

## 运行前准备

按真实 Worker 账户创建 0700 状态目录；Node 的 active.conf 必须是有效 bootstrap，已有部署使用已知有效的上一快照。分别准备私有控制 token、mTLS 客户端身份、Node RSA 解密密钥，以及 Master 签名信任公钥。实际域名、源站、证书和私钥不进入 Git。

在独立前缀中编译，动态加载顺序建议 Config → Tier → API → Edge → Purge → Sync；静态编入不使用 load_module。保留目标运行时版本、ABI、编译参数和库，不能复制不匹配的 .so。

```sh
sh tools/build-runtime.sh /tmp/scdn-native nginx
python native-sync/tests/integration.py --prefix /tmp/scdn-native
python native-sync/tests/distribution.py --prefix /tmp/scdn-native
python native-sync/tests/cache_tasks.py --prefix /tmp/scdn-native
python native-tier/tests/integration.py --prefix /tmp/scdn-native
python native-tier/tests/boundaries.py --prefix /tmp/scdn-native
python native-sync/tests/cache_tasks.py --prefix /tmp/scdn-native --tier
python native-tier/tests/coexist.py --prefix /tmp/scdn-native --report /tmp/scdn-six.json
```

## 切换顺序

1. 保留原二进制、配置、站点/证书及一致状态的备份和回退入口。
2. 用新端口/Socket/目录部署原生 Master 和 Node；先验证身份，再验证完整配置发布、源站请求、TLS、停用/删除与失败恢复。
3. 核对 Node 的 config_state 与 scdn_config_managed 指向同一目录，status_socket 提供 Config /status；普通 scdn_config_watch 不同时使用。
4. 确认所有目标 Node 的目标序号与实际 applied 后，明确交接唯一配置写入权，再停止旧 Lua publisher/apply 对该配置源的写入。缓存任务可以独立启用。
5. Tier 使用新 cache zone/path 或已验收的预热流程；接入完整读取链后停用旧 tier Lua 和维护 flush 脚本。旧 L1 独有对象不会自动成为新 L2 副本。0.1.1 的模块与 front/backend 模板一起升级，切换时隔离旧 Socket 协议及缓存元数据。

Node applied 与业务健康分开。未配置 probe 时 health=unknown，配置了 probe 也只证明相应 URL/状态。Master 离线不会删除已应用的路由/证书；恢复按持久序号续发。不要单独回滚 highest.state、desired 或证书目录。

Sync 身份、线程池、监听/模块更新仍需要 Nginx 启动配置流程；站点、证书和缓存规则数据应用无需重建 Worker。真实线上切换未由本仓库测试自动执行。

## 原生模块与 Lua 的功能交接

只让已由模块接管的 Lua 实现退出运行路径；保留 WAF/限流及未被替代的其他 Lua。新的类型化策略、security_guard 桥接器、一次性转换和暂存清理工具见 [Lua 交接](LUA-HANDOFF.zh-CN.md)。必须同时退出旧 registry/native_export 的启动写入与 Lua SNI 回调，不能只停 timer。
