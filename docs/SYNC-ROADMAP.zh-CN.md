# Sync 原生化路线与完成标准

当前版本：native-sync 0.2.0。本页记录仍需迁移的合同，与本仓库已经提供的角色/身份模块分开判读。实现来源为 [OpenResty_Lua 62fb619](https://github.com/PH-OpenResty/OpenResty_Lua/tree/62fb61947f4c6d10eca468b7b66979009957de55/native-sync)；历史协议/缺口依据见[原生设计](https://github.com/PH-OpenResty/OpenResty_Lua/blob/62fb61947f4c6d10eca468b7b66979009957de55/doc/NATIVE-SYNC-PLUGIN-DESIGN.zh-CN.md)和[完整性审查](https://github.com/PH-OpenResty/OpenResty_Lua/blob/62fb61947f4c6d10eca468b7b66979009957de55/doc/SYNC-GAP-REVIEW.zh-CN.md)。

## 已实现

- 实例级 off/master/node、ID/scope 约束、重复节点和证书指纹拒绝。
- 本机真实传输检查、私有 token 文件、Bearer 恒时比较。
- Master 的 mTLS 客户端证书验证与叶 DER 指纹登记。
- 只读 status/capabilities/peers、原生变量、路径/方法/正文边界。
- 纯 C 核心、独立动态加载和统一静态编入入口。

- 缓存任务持久队列、mTLS Node 拉取、Purge 刷新、本机预热及结果恢复，见 [任务合同](CACHE-TASKS.zh-CN.md)。这些能力与下表配置快照协议分开。

## 后续阶段

| 阶段 | 迁移内容 | 完成条件 |
| --- | --- | --- |
| S1 协议/密码学 | 严格 JSON/序号、JWE/JWS、HTTP 请求签名与防重放 | Lua→C、C→Lua 双向互通；篡改、重复键、过期与跨 Node 拒绝 |
| S2 Master 发布/分发 | 完整快照、文件稳定窗口、每节点密文、desired 原子提交、授权对象读取 | 半写/磁盘失败不推进 desired；慢 Node 不阻塞其他 Node |
| S3 Node 拉取/恢复 | 有界并发、退避、下载验证、持久 journal/outbox | Master 离线仍保留当前业务；重启和 ACK 丢失不会重复切换 |
| S4 本机应用事务 | stage/prepare、全 Worker 就绪、commit/rollback/finalize | 与当前 Config/Edge/API 共用一套活动配置生命周期，旧请求/证书引用安全 |
| S5 状态/运维 | 前置失败报告、业务探测、批次结果、历史保留/恢复 | 配置 applied 与业务健康分离；永久 4xx 不阻塞后续报告 |

## 安全和数据边界

配置及证书材料继续按 Node 独立加密，不能以 Base64、字节码或签名代替保密。mTLS、请求签名、摘要、时效、nonce 与 scope 授权共同校验；Node 不能下载其他节点对象。发布、分发、报告持久化和 Node 拉取保留进程/队列隔离，不能把 C 的阻塞文件调用放进业务 Worker 后声称非阻塞。

兼容旧协议时固定 JWE 为 RSA-OAEP-256 与 A256GCM，外层使用 Ed25519/EdDSA JWS，先验可信发布签名再解密。Node POST 的请求签名、防重放与 mTLS 身份保持绑定；不根据未受信 alg/kid 自动降级或引入临时信任密钥。它们是后续 S1 合同，当前原生能力位仍为 false。

序号单调推进；主动回退也产生新的投递序号。完整快照明确删除/停用语义；空集合保留保护。Master 在不可变文件全部持久后推进 desired；Node 先验证、准备，再切换；每阶段故障必须可恢复并保持上一有效业务版本。

公开错误和日志只保存受控 ID、阶段、摘要及错误码，不输出私钥、token、明文站点正文或完整密文。各角色使用独立身份与目录权限。静态内容通过已验证路径引用，不把任意 HTML/图片/缓存文件纳入配置发布协议。

## 必须补齐的完整性合同

1. **配置应用与业务健康分开。** 专用版本探针不能证明真实回源/静态文件正常，需明确业务路径与预期。
2. **下载/解密/证书校验前置失败可见。** 无法验证的清单不自报伪造 release_id，节点级错误也应可查询。
3. **持久队列区分临时/永久错误。** 永久 4xx 不无限堵住队头；幂等收据绑定相同请求和真实结果。
4. **文件提交边界明确。** 原子 rename 不等于多文件事务；需要检查点、目录同步、恢复及故障注入。
5. **长期保留与恢复可操作。** 检查点、历史 GC、磁盘满、可信时间、回滚状态和密钥轮换均有验收。
6. **本机配置版本唯一。** Config generation/revision 不充当远程序号，Purge journal 不充当 Sync journal。

这些阶段尚不能通过给现有功能加字段或状态名认定完成。新能力实现并通过真实进程验收后，才逐项把 capabilities 从 false 改为 true。当前迁移方式见 [Sync 迁移说明](SYNC-MIGRATION.zh-CN.md)。

## Ban 全节点有效 IP 快照

新增必须实施的 [Ban 集群合同](../native-ban/design/CLUSTER-SYNC.zh-CN.md)：任意登记设备上报原始 L3 决策，所有登记节点接收完整有效快照并逐节点确认实际内核应用。此通道独立于缓存任务和配置快照，当前尚未实现；缓存任务成功不能证明封禁已跨机生效。
