# 当前文档与能力核对

当前运行模块为十个：Sync 0.3.0、Config、Bot 0.1.0、Ban、Auth Guard 0.1.0、API、Edge、Tier 0.1.1、Purge 0.3.0、Log Sync 0.1.0。下面各入口描述当前实现；历史验证 JSON、带版本/日期的基线和研究报告保留其当时的结果，不将历史数字改成新版本证据。

| 范围 | 当前入口 | 核对结论 |
| --- | --- | --- |
| 总览/构建 | [README](../README.md)、[安装](INSTALL.zh-CN.md) | 十模块、目标 ABI/依赖、动态/静态、独立与组合运行 |
| 日志与网络指标 | [Log Sync](../native-log-sync/README.zh-CN.md)、[指标清单](../native-log-sync/schema/metrics-catalog.json) | ES/CH 直连、完整/增量、WAL/游标、81 个既有面板和 TCP/UDP 只读采集 |
| Sync | [模块手册](../native-sync/README.zh-CN.md)、[配置/证书发布](SYNC-PUBLICATION.zh-CN.md) | 已实现原生 v2 发布/拉取/热应用/回退，按启用状态报告 |
| Sync 迁移/路线 | [迁移](SYNC-MIGRATION.zh-CN.md)、[路线](SYNC-ROADMAP.zh-CN.md) | 不与旧 Lua JWE/JWS 直接互通，写入权交接和剩余能力明确 |
| 缓存任务 | [任务手册](CACHE-TASKS.zh-CN.md) | 独立刷新/预热，与配置发布分开，支持 Tier 业务入口 |
| Config/Edge | [Config](../native-config/README.zh-CN.md)、[Edge](../native-edge/README.zh-CN.md) | 普通只读 watcher、Sync managed 恢复、路由/TLS/请求版本 |
| Bot | [手册](../native-bot/README.zh-CN.md) | 原生 UA/CIDR、Censys/FOFA 规则、可信代理、观察与拒绝；来源更新为独立工具，尚无安全资源 Sync |
| Auth Guard | [手册](../native-auth-guard/README.zh-CN.md) | 原生共享准入、公开弱值、最小邮箱策略、应用创建前回查、明确认证反馈；需真实应用 hook，仅本机认证短封 |
| API | [API](../native-api/README.zh-CN.md)、[协议与媒体](API-PROTOCOL-MEDIA-DESIGN.zh-CN.md) | 图片编辑/变体、按站点协议别名、四协议 raw/工具链和显式本地图片解码；附件发出与实际展示独立报告 |
| Bot/注册防护研究 | [总设计](BOT-UA-AUTH-GUARD-RESEARCH-DESIGN.zh-CN.md)、[种子数据](security-seeds/README.zh-CN.md) | 目录和弱库已由对应模块消费；设计中的跨节点认证状态、持久短封与更多应用适配仍按各自能力推进 |
| 分层缓存 | [Tier](../native-tier/README.zh-CN.md) | 0.1.1；Lua 选层/flush 对应、晋升/降温、304 续期、两层限额/隔离、预热恢复和升级 |
| 缓存清理 | [Purge](../native-purge/README.zh-CN.md)、[机制](CACHE-MECHANISM.zh-CN.md)、[再验证研究](CACHE-REVALIDATION-RESEARCH.zh-CN.md) | 两层共同失效、原生回收、穿透 L2 的条件校验与边界 |
| HTTP 头 | [约定](HTTP-HEADERS.zh-CN.md)、[缓存头](CACHE-HEADERS.zh-CN.md) | X-Clinet-IP、缓存诊断/回源头、私有 X-Tier 和 X-Config 控制元数据 |
| 原生/Lua 交接 | [迁移工具与安全桥接](LUA-HANDOFF.zh-CN.md) | 仅退役模块已接管的脚本，保留 WAF/限流，统一请求策略与证书来源 |
| 运维和 Lua 迁移 | [运维](OPERATIONS.zh-CN.md)、[迁移](MIGRATION.zh-CN.md) | 单写者、备份/回退、停止旧 tier/flush 的前提、受管事务 |
| Ban/eBPF | [Ban](../native-ban/README.zh-CN.md)、[集群合同](../native-ban/design/CLUSTER-SYNC.zh-CN.md) | 已提供 Agent、XDP/TCX 和完整集群快照；当前实现以 Ban 运行手册为准 |
| 验证/来源/隐私 | [验证](VALIDATION.zh-CN.md)、[来源](../SOURCE.md)、[发布规则](../PUBLISHING.md) | 当前测试与历史证据分开，源码清单、文档和实际索引检查 |

公开配置仅使用保留域名/本机地址和通用目录。更新过的例子包括 Sync 发布片段、Tier front/backend/完整配置、Config 站点模板和 API/Edge 代理模板。真实源站、私钥、token、运行对象、状态和日志不进入仓库。

Ban 0.1.0 的当前配置、事件/权限、全量同步、日志持久化与运行验收见 [运行手册](../native-ban/RUNTIME.zh-CN.md)，历史设计字段不直接用于启动。

[2026-11-16 独立安全与性能复审](AUDIT-REVIEW-2026-11-16.zh-CN.md)逐项记录 CNB issue #2/#3–#10 的确认、修复与不同意结论。

[Ban Store](../native-ban-store/README.zh-CN.md) 是 Ban 0.2.0 的当前状态存储：Agent 直接集成，无 SQLite，支持持久化和内存 Node。历史验证与审查记录中的 SQLite 指当时实现。
