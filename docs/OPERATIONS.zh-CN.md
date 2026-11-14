# 发布、观察、恢复与排障

以下流程针对已按 [安装手册](INSTALL.zh-CN.md)接入的 Config/Edge 实例。插件没有写配置 API，发布者直接维护 `/etc/scdn/sites.conf` 及其引用的材料。站点数据更新不需要 `nginx -s reload`，启动指令或模块程序更新仍按原 Nginx 服务流程处理。

## 1. 发布完整站点快照

1. 从当前已知有效版本制作完整候选文件，包含所有应继续存在的站点。
2. 在受限目录预先准备好需要的静态目录、证书、私钥及权限。
3. 将候选文件写入正式文件同一目录，保留管理员认可的已知有效旧版本。
4. 用同文件系统内的原子 rename 替换正式路径，观察 status 与业务请求。

例如，候选文件已经由受信任发布者准备好时：

```sh
sudo install -o root -g scdn -m 0640 ./candidate-sites.conf /etc/scdn/sites.conf.next
sudo mv -T -- /etc/scdn/sites.conf.next /etc/scdn/sites.conf
sudo curl --unix-socket /run/scdn-edge/control.sock http://localhost/status
curl -H 'Host: www.example.com' http://127.0.0.1:8081/
```

示例 `mv -T` 是 GNU/Linux 写法；临时文件必须与正式文件位于同一文件系统，否则不能依赖 rename 的原子性。发布脚本可以在 rename 前对文件做 `fsync`、之后同步父目录，以满足自己的掉电持久性要求；Config 读取文件，不替发布者实现落盘提交。

一份文件就是一个完整集合。删除一个 `site` 即移除其全部 Host；修改 Host 列表会移除未再出现的别名。配置文件中的空白与注释也进入版本摘要，保存这些变化可能产生新 generation。

## 2. 新增、修改、停用和删除

| 操作 | 数据文件动作 | 生效后表现 |
| --- | --- | --- |
| 新增 | 增加唯一 site 与 Host | 新请求可以命中站点 |
| 修改回源/前缀 | 修改对应 upstream/prefix | 新请求使用新路由，旧请求继续原版本 |
| 暂停站点 | `enabled off;` | HTTP 请求返回 403，新完整 TLS 握手拒绝 |
| 恢复站点 | `enabled on;` 并提供有效资源 | 后台校验成功后重新服务 |
| 删除站点 | 从完整文件移除该 site | 后续 Host 查找失败，返回 403 |
| 删除全部 | 启动配置显式允许空集合，再发布 `sites { }` | 完整集合变空 |

`scdn_config_allow_empty` 属于启动配置，切换该选项本身要按 Nginx reload 流程处理。默认 off 能阻止误清空全部站点，但不会阻止从 100 个站点误改成 1 个；发布者仍需查看差异或设置删除阈值。

## 3. 证书轮换

优先使用版本化、不可变的真实文件路径，例如 `/etc/scdn/certificates/demo-v2.crt` 与 `.key`。完整写好并验证配对和权限后，在一次站点文件替换中引用新的一对路径。

同路径更新也可识别，但证书和 key 是两个文件，无法用一次 rename 同时替换。中间不匹配时插件保留旧内存版本；完整匹配、稳定并等待所有 Worker 就绪后才提交。不要把两次文件替换之间的间隔当作受保护的跨文件事务。

证书链与私钥可读只是前提，叶证书还需未过期、匹配私钥并覆盖全部 Host 的 DNS SAN。部分证书链或不完整 PEM 会被拒绝。ACME 的 symlink 路径需要由外部交付流程转换为受限真实文件，再让站点配置引用；插件不跟随 symlink，也不签发或自动续期证书。

轮换后核对新的完整 TLS 握手：

```sh
openssl s_client -connect 127.0.0.1:443 -servername www.example.com </dev/null
```

该命令展示握手材料，仍需根据服务实际信任链检查验证结果。已有 TLS 连接不会因轮换自动关闭，session cache/tickets 政策也不会由插件自动撤销。示例关闭会话缓存与票据，其他策略需单独验收。

## 4. 读取状态

```sh
sudo curl --unix-socket /run/scdn-edge/control.sock http://localhost/status
sudo curl --unix-socket /run/scdn-edge/control.sock http://localhost/metrics
```

status 示例，revision 在实际响应中始终为 64 字符：

```json
{
  "generation": 2,
  "revision": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sites": 2,
  "worker_pid": 1234,
  "ready": true,
  "last_error": "",
  "writes_source": false,
  "restarts_workers": false
}
```

generation/revision 表示共享活动版本；ready、sites、last_error 还反映回答该请求的 Worker。重建中的 Worker 可以返回 `ready=false`、sites=0，而不是说明整个站点集合真的为空。一次请求不代表查询到所有 Worker；需要跨 Worker 观察时记录响应 PID 并多次采样。

ready=true 只表示该 Worker 可用的配置版本匹配共享活动摘要。即使源站已经停止，配置仍可能正常应用，业务请求返回 502；业务健康检测应使用真实业务路径和明确预期。指标也不提供完整源站健康或发布审计服务。

## 5. 错误处理

| 现象/错误 | 先检查什么 |
| --- | --- |
| 启动时 `configuration_unavailable` | 绝对路径、普通文件、目录权限、大小、外层 `sites {}` 是否完整 |
| 运行中 `invalid_site_configuration` | 未知/重复字段、重复 ID/Host/prefix、格式和字段范围 |
| `certificate_validation_failed` | 完整 PEM、链截断、key 配对、有效期、所有 Host 的 SAN |
| `static_root_unavailable` | root 是真实存在的目录，Worker 能遍历全部父目录，无 symlink |
| `empty_configuration` | 是否误发布空集合、是否确实需要 allow_empty |
| `reader_task_unavailable` | 是否声明专用线程池，队列是否被占用，线程任务是否异常 |
| status 403 | 请求是否来自真实本机/Unix 传输，是否另有 Nginx 访问规则 |
| 业务 403 | Host 未登记或站点停用；也可能由用户自行配置的其他访问模块返回 |
| 业务 503 | Worker 尚未装入活动摘要；检查就绪、源文件与后台任务 |
| 业务 502/504 | 源站、DNS resolver、端口、网络与原生 proxy 超时；不代表 watcher 解析失败 |
| 缓存始终 MISS | 所选 cache zone、目录权限、响应缓存头、cache key 与 revision 是否不断变化 |
| 无指标的新站点 | 是否启用 Edge、ID 是否匹配、指标区是否达到 1024 个历史 ID |
| `undefined symbol: scdn_config_*` | 是否先加载 Config、两个模块是否来自同一构建版本 |

运行时错误只拒绝候选版本，旧内存快照继续服务。修复后后台任务会再次尝试，成功后 last_error 清空。不要通过反复重启解决无效文件：完整重启需要再次从磁盘加载，可能将尚能服务的旧内存版本丢失。

## 6. 候选版本迟迟不提交

逐项核对：

1. 所有 Worker 是否在线，是否有暂停、崩溃重建或事件循环阻塞。
2. 每个 Worker 是否用相同权限读取到同一组文件，而不是 NFS/挂载差异或频繁并发覆盖。
3. 数据是否不断变化，始终未满足 settle；证书文件是否处于配对更换过程中。
4. 专用线程是否卡在文件系统或昂贵解析，扫描容量是否超过合理规模。
5. 扫描调度和稳定窗口是否过大；Worker 就绪检查还使用当前实现的 5 秒新鲜度约束。

默认先使用 250ms/500ms，按实际 I/O 和规模测量后调整。扩大 interval 或增加 Worker 数并不必然提升性能。模块没有无条件提交或忽略某 Worker 的运维开关；应修复阻塞原因。

## 7. 主动回退与进程恢复

主动回退是由发布者把已知有效的完整文件和所需证书重新放回正式路径，后台会为其构建版本。没有“回退到指定 generation”的 HTTP API，也没有自动保存的历史源文件。

回退文件、证书和密钥必须一起保留；只恢复指向已删除证书路径的旧文件会失败。版本摘要按内容计算，回到相同内容时可以出现旧 revision；generation 只在本次 Nginx 配置周期内递增，不是跨重启的发布序号或防回滚机制。

Worker 异常退出后，Nginx 拉起新 Worker；新进程继承启动快照，再扫描当前磁盘内容并加入活动版本。其未匹配活动摘要期间拒绝业务请求。所有进程完全停止后，内存快照消失；恢复需要磁盘上完整有效的源文件、证书、启动配置和模块程序。

## 8. Nginx 配置与程序升级

下列改变不属于站点热更新：监听地址/端口、协议选项、模块 `.so`、线程池、Worker 数、共享区大小、cache zone 及固定 header/proxy 指令。使用目标二进制 `-t` 验证后，按现有服务的 graceful reload/重启及回退流程执行。

Config 的共享活动代际在手工 reload 后属于新配置周期；Edge 指标区可在兼容结构下复用。升级到不同数据结构时规划新共享区名称。没有把 `.so` 文件替换当作在线更新程序的保证。

本仓库不自带 systemd 管理器、磁盘历史 GC、源站探测调度器或跨主机同步服务。保留必要监控和备份，实际静态内容与缓存容量仍按 Nginx/存储层管理。
