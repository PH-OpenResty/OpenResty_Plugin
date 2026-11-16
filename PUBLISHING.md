# 公开发布规则

只提交源码、测试、通用模板和文档。真实站点、客户/租户数据、非公开节点清单、源站地址、凭据、证书材料、运行状态、日志、备份与编译二进制不进入 Git。

`native-config/examples/sites.conf` 是公开示例；实际输入文件应放在部署目录。测试在临时目录中生成 CA、证书和私钥，退出时清理。不要把生成的材料或测试运行目录复制进仓库。

`native-sync` 只提交原生源码、合成角色模板和测试。真实 Master/Node 清单、客户端指纹、控制 token、PKI、证书私钥、发布对象及同步状态不进入 Git。Sync 测试现场生成临时 mTLS 身份和不同的 Sync/Purge token；CI 只上传检查名称/数量与非敏感运行时摘要，不上传运行目录。

提交前检查实际 Git 索引：

```sh
git diff --cached --check
python tools/check-publication.py --staged
gitleaks dir --redact .
gitleaks git --redact --log-opts=--all .
```

默认发布脚本检查已跟踪工作树文件，`--staged` 检查索引中的实际内容。检查只输出文件、行号和规则，不打印匹配的值。`.gitignore` 不会删除已经跟踪的数据，也无法阻止强制添加；新增文件仍需人工确认域名、地址、路径与业务内容。

新提交使用 GitHub noreply 邮箱可避免新增个人邮箱。已有历史作者元数据由原仓库保留，源码扫描不会重写历史。已公开的凭据需要按实际情况撤销，删除文件不能使凭据重新安全。

Sync 缓存任务的队列、Node 收据、目标 URL/缓存键列表和运行锁均属于私有运行数据，不进入 Git。公开示例只保留合成目标；CI 仅上传检查名及数量，不上传任务目录、mTLS 材料或请求正文。

Ban 集群的真实 IP 集合、来源设备、签名私钥、快照和 outbox/收据属于私有运行材料；公开日志例子只用保留 IP 和合成 UUID。缓存规则头只展示非敏感合成值，不上传真实源站业务头或凭据。

原生配置发布的 source、desired.bundle、releases、active/previous.conf、highest/applied/rejected/reported 状态及 Node RSA/签名私钥均属于私有运行材料。测试仅生成临时身份/合成站点，报告不保存明文快照。Tier 实例令牌只存在共享内存和受限 Unix 请求，不进入文档、报告或正常访问日志。

Ban 的实际 policy.json、Ban Store AOF/checkpoint、共享视图、pin/链接、客户端证书和签名密钥、事件/IP 日志均是私有运行材料，不提交仓库。公开运行示例使用保留 IP、合成身份和通用路径。CI 只上传检查名称/结果，不上传状态目录或签名快照。

Ban Store 的 ban-store.aof、锁、临时 checkpoint、离线状态副本和测试性能运行目录均为私有材料，不提交。memory 模式的审计日志仍按相同隐私规则处理。CI 仅上传断言、非敏感计数和合成 IP 基准的性能摘要。
