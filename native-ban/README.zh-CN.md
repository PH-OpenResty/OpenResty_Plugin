# Ban：原生 IP 封禁、eBPF 与全节点同步

版本 0.1.0。已提供纯 C 的 `ngx_http_scdn_ban_module`、C++17 单写 Agent、XDP native/TCX ingress 内核程序和原生 Sync 桥接。运行路径不依赖 Lua 或 Python；Python 只用于测试和可选管理客户端。完整安装、配置、状态和验证见 [运行手册](RUNTIME.zh-CN.md)。

客户端直连节点。可信 CC 事件直接申请 L3；WAF 首次建立 `(site, IP)` L7 封禁，窗口内 WAF/L7_HIT 达到阈值后升级 L3。期限按配置固定，命中、重试、重启和跨节点复制都不重新起算。L3 只保护配置列出的 Web/LB VIP、协议和端口；不无条件封掉整机所有服务。

任意登记设备（包括 Master 所在设备）的 L3 原始决策进入持久 outbox，由 Master 汇总成签名完整有效 IP 快照。所有登记 Node 接收同一完整集合，来源设备也接收；断线恢复后重新核验最新全量。只有各节点真实内核应用和日志持久化都确认，Master 才显示 ALL_APPLIED。离线、Map 或日志失败显示未收敛，不把下载成功当成内核生效。

| 组件 | 代码与职责 |
| --- | --- |
| Nginx Ban | src/ngx_http_scdn_ban_module.c；真实连接 IP、只读视图查询、受信 WAF/CC 上报、L7 拒绝 |
| 共享协议/视图 | src/ban_common.h、ban_common.c；有界 IPC、SipHash 索引、原子双 bank、完整键比较 |
| Agent | agent/；配置/事件去重、固定期限、SQLite WAL、内核 Map、两份日志、全量同步 |
| eBPF | bpf/ban.bpf.c；IPv4/IPv6、VLAN、分片、业务入口、BOOTTIME 过期、真实 DROP |
| Sync 桥 | native-sync/src/scdn_sync_ban.c；实际 mTLS 身份绑定、受限 Unix Agent RPC、全量/结果 API |
| 运行配置/运维 | examples/policy.json.example、http.conf、sync-master.conf、systemd 示例、tools/banctl.py |
| 真实验收 | tests/runtime.py、producer.c、packet-test.c；隔离 netns/veth、实际 Nginx/Agent/内核和多节点 |

原 v1/v2 设计文档、TOML 和四个草案 ABI 保留在 design/ 供追溯。实际 0.1.0 使用严格 JSON 配置、SQLite WAL 和 src/ 中的新运行 ABI；旧 TOML/草案结构不能直接作为运行配置或线协议使用。实现取舍与仍需部署验收的范围均写入运行手册。

模块执行封禁，不实现 WAF 引擎、CC 检测器、业务限速或账户鉴权。API/Edge 会在 API 正文准备和业务转发前显式检查 Ban；TCP/UDP 负载均衡流量由内核入口规则保护，应用侧兜底仅覆盖 HTTP。
