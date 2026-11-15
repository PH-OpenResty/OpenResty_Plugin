# 自定义 HTTP 请求头约定

插件的自定义 HTTP 头统一去掉产品名前缀。本文只定义 HTTP 头；模块文件名、`scdn_*` Nginx 指令、变量、协议及控制路径保留现有命名。

| 请求头 | 用途 | 生成或信任边界 |
| --- | --- | --- |
| `X-Clinet-IP` | 代理向源站传递客户端 IP | 按本次指定拼法保留 `Clinet`；由代理覆盖为 `$remote_addr` |
| `X-Purge-Mode` | Purge/Sync 任务匹配方式 | 已鉴权的本机控制或 mTLS 任务通道 |
| `X-Purge-Scope` | 缓存命名空间 | 已鉴权请求且 Node scope 白名单校验 |
| `X-Task-ID`、`X-Task-Type` | 缓存任务 ID、refresh/preheat | 管理端创建；Master 持久化，Node 验证 |
| `X-Task-Digest`、`X-Task-Lease` | 任务摘要、当前尝试号 | Master 生成，Node 核对，结果回报匹配租约 |
| `X-Task-State`、`X-Task-Completed`、`X-Task-Error` | 任务执行结果 | 已登记的 mTLS Node 回报自己的结果 |
| `X-Node-ID`、`X-Node-Scope` | 目标节点及登记范围 | 远程权限始终绑定实际客户端证书，不接受自报身份授权 |

HTTP 头名不区分大小写，HTTP/2 在线路上使用小写。`X-Clinet-IP` 是项目约定，非 HTTP 标准；它与 `X-Client-IP`、`X-Real-IP`、`Forwarded` 是不同名称。示例保留已有标准/常用代理头，同时增加并覆盖该头：

```nginx
proxy_set_header X-Clinet-IP $remote_addr;
```

默认 `$remote_addr` 是连接对端。经过管理员明确配置的 `real_ip` 可信代理链后，它可以是验证后的客户端地址。不要直接用 `$http_x_clinet_ip` 或不受信的转发头作为 WAF、封禁或 mTLS 身份；直连节点不根据客户端自行提交的 IP 头改写身份。本机 Sync/Purge 控制检查实际 Socket 对端，不依赖此头。Ban 仍处于设计阶段，L3 使用实际包源地址。

Purge 调用方、测试和示例必须同时改用 `X-Purge-Mode`、`X-Purge-Scope`。旧产品前缀头不作为别名接受，缺少新模式头返回 400；升级时同步切换管理端及节点，避免旧调用失效。凭据继续放在独立的 `Authorization: Bearer ...` 中。
