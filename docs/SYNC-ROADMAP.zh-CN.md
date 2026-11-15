# Sync 原生能力与后续路线

当前版本 native-sync 0.3.0。角色/身份基础最初来自 OpenResty_Lua 62fb619；0.2.0 增加缓存任务；0.3.0 已补齐原生站点配置/证书的发布、分发、应用和回退。配置协议为 scdn.sync.native.v2 / native.snapshot.v2，完整合同见 [发布手册](SYNC-PUBLICATION.zh-CN.md)。

## 已实现

| 能力 | 当前实现与验收入口 |
| --- | --- |
| 角色/身份与本机控制 | off/master/node、ID/scope、私有 Bearer、真实本机连接、mTLS 登记；integration.py |
| 配置/证书发布 | 完整源文件和证书校验、稳定窗口、按 Node RSA-OAEP/AES-GCM 密文、Ed25519 签名、持久 desired；distribution.py |
| Node 拉取与反回滚 | Node/scope/摘要/期限核验、持久最高序号、未变化条件读取、独立 Node 状态；distribution.py |
| 应用/回退 | 版本化证书、Config 受管 active.conf、全 Worker 准备/活动确认、可选探测、previous/pending 启动恢复；distribution.py |
| 结果与维护 | applied 收据、ACK 丢失重报、拒绝版本不重复切换、已识别旧版本 GC；distribution.py |
| 缓存刷新/预热 | 持久任务、mTLS 领取、本机 Purge 与验证 HIT 的预热、租约/结果；cache_tasks.py |

每项 capabilities 按实际启用的功能和角色返回，不用 Config watcher 的 ready 冒充远程 applied。关闭 config_state 时角色查询仍为 not_started；启用后实际状态和结果来自发布/应用流程。

## 仍需单独完成

- 旧 Lua JWE/JWS 与 HTTP 请求签名/nonce 协议的双向兼容：当前采用独立固定二进制封装，不能宣称无缝互通。
- 自动密钥轮换、多权威 Master 的 fencing/容灾切换、跨地域大规模性能与完整磁盘/掉电故障矩阵。
- 管理员指定探测以外的全站业务健康、静态内容文件发布、证书自动签发和程序自动升级。
- [Ban 全节点 L3 同步](../native-ban/design/CLUSTER-SYNC.zh-CN.md)：任意设备上报、完整有效集合、逐节点内核确认，目前仍是设计。站点配置已能同步不代表 Ban Agent/BPF 已实现。

## 配置与缓存生命周期

Config/Edge 保持唯一活动站点版本，Sync 通过受管事务交付，不另造一份在 Worker 中独立切换的路由表。普通 Config watcher 与受管写入模式互斥，源文件只允许一个权威写者。Purge 维护自己的失效 journal；[Tier](../native-tier/README.zh-CN.md) 建立 L1/L2 读取链；两者不充当配置发布序号或事务日志。

新能力须以真实进程、失败恢复和对应角色的证据验收。历史 Lua 或仅 Schema/ABI 检查不计入原生运行验收。
