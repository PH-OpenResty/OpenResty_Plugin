# Config：原生站点配置监听与内存热更新

`ngx_http_scdn_config_module.so` 把一个完整站点数据文件及其引用的证书转换为不可变内存版本。后台按内容扫描，所有 Worker 准备好同一版本后切换活动摘要；不发送 HUP、不重建 Worker，也不生成 Lua、字节码或 `nginx.conf`。

安装入口见 [构建与安装](../docs/INSTALL.zh-CN.md)，实际发布和恢复见 [操作手册](../docs/OPERATIONS.zh-CN.md)。本模块不依赖 Lua，Edge 消费本模块的 C 接口；加载顺序必须先 Config、后 Edge。

## 1. Nginx 指令参考

| 指令 | 上下文 | 默认或要求 | 作用与范围 |
| --- | --- | --- | --- |
| `scdn_config_watch /absolute/sites.conf` | http | 默认不启用；只允许一份 | 受监控完整数据文件，需绝对路径 |
| `scdn_config_zone NAME SIZE` | http | 启用 watch 时必填；只允许一份 | 共享摘要/Worker 状态；64KiB～4MiB，示例 128k |
| `scdn_config_interval TIME` | http | 250ms | 扫描调度间隔，50ms～60s |
| `scdn_config_settle TIME` | http | 500ms | 候选内容稳定窗口，不小于 interval，最大 120s |
| `scdn_config_allow_empty on\|off` | http | off | 是否允许用完整空集合删除最后一个站点 |
| `scdn_config_status` | location | 默认无端点 | 只读本机状态，不能与其他 content handler 混用 |

`TIME` 使用 Nginx 时间格式，例如 `250ms`、`1s`。zone 是静态启动参数，增加它不会提高站点数据解析上限。未配置 watch 时不启动扫描；只配 zone、不配 watch 的组合无效。

需要在线程池启用的运行时中，显式声明专用池：

```nginx
load_module modules/ngx_http_scdn_config_module.so;
thread_pool scdn_config_reader threads=1 max_queue=2;
http {
    scdn_config_zone configurations 128k;
    scdn_config_watch /etc/scdn/sites.conf;
    scdn_config_interval 250ms;
    scdn_config_settle 500ms;
    scdn_config_allow_empty off;
    server {
        listen unix:/run/scdn-edge/control.sock;
        location = /status { scdn_config_status; }
    }
}
```

上例是指令位置说明；完整可运行配置还需 `events` 和业务 server，见 [nginx.conf](../native-edge/examples/nginx.conf)。线程池是每 Worker 的专用后台执行位置，一个 Worker 最多有一个本模块扫描任务在途。

## 2. 数据文件不是 nginx.conf

源文件使用受限数据语法：

```nginx
sites {
    site demo {
        host www.example.com;
        host alias.example.com;
        enabled on;
        upstream http://127.0.0.1:8080;
        cache auto;
        tier 3 5000;
        certificate /etc/scdn/certificates/demo.crt;
        certificate_key /etc/scdn/certificates/demo.key;
        prefix /api/ {
            upstream http://127.0.0.1:9000;
            cache off;
        }
    }
    site assets {
        host assets.example.com;
        root /srv/sites/assets;
        cache off;
    }
}
```

只允许一个外层 `sites { ... }`，不能在后面附加其他块或指令。`#` 引入行注释；字段以分号结束，块以花括号结束。可用单引号或双引号包住值；仅支持对引号和反斜线的简单转义，不接受任意 Nginx 表达式。

解析器不执行 `include`、Lua、shell 或变量展开。它不是 JSON，也不是可以直接交给 Nginx 原生解析器的 server/location 配置。一次文件替换代表完整站点集合，未出现的旧站点会被移除。

## 3. 站点字段

| 字段 | 是否必填/默认 | 校验和语义 |
| --- | --- | --- |
| `site ID { ... }` | 必填 | 全局唯一，1～96 字节；首字符 ASCII 字母/数字，其余可含 `_`、`-` |
| `host NAME;` | 至少一个 | 小写 ASCII 精确 Host；可多次指定别名，全局不得重复 |
| `enabled on\|off;` | 默认 on | off 拒绝新 HTTP 请求和新 TLS 握手；保留其配置定义 |
| `upstream http://host:port;` | 与 root 至少有一个 | HTTP 回源，显式端口 1～65535；只支持这一结构 |
| `root /absolute/directory;` | 与 upstream 至少有一个 | 启用站点时目录需存在，路径不得含符号链接 |
| `cache l1\|l2\|off\|auto;` | 默认 off | 选择 Nginx 已声明的 cache zone；auto 需 tier |
| `tier HITS WINDOW_MS;` | auto 时必填 | HITS 为 1～1000000，窗口为 100～86400000 毫秒 |
| `certificate /absolute/chain.crt;` | 可选，与 key 成对 | PEM 证书链，启用站点时读取并预加载 |
| `certificate_key /absolute/private.key;` | 可选，与 certificate 成对 | 无交互口令的 PEM 私钥，必须匹配叶证书 |
| `prefix /path/ { ... }` | 可选，可多个 | 最长字节前缀选择回源和缓存 |

除 host 与 prefix 外，重复同一字段会拒绝候选版本。upstream 与 root 可以同时出现，此时 upstream 优先；prefix 只能覆盖回源与缓存，不能用它切到静态 root。停用站点仍需结构正确、Host 和路由定义有效，但不要求旧静态目录和证书文件继续可读。

Host 最长 253 字节、每个 DNS 标签最多 63 字节，不接受 Unicode 原文、泛域名 `*`、端口或 scheme。需要国际化域名时由发布者先转换为小写 ASCII 表示。回源域名也使用受限小写格式，不能附 URI、查询、userinfo 或变量；域名解析依赖业务 Nginx 中的 resolver，IP 回源无需 DNS resolver。HTTPS、IPv6 和命名 upstream 池尚未进入该数据模型。

root/证书/私钥要求绝对路径，不接受 `$`、反斜线和控制字符。路径每个分量按文件系统约束校验，拒绝 `.`、`..`、空分量及符号链接。根目录 `/` 不是可用的站点 root。

## 4. prefix 的语义

```nginx
prefix /api/ {
    upstream http://127.0.0.1:9000;
    cache off;
}
prefix /api/private/ {
    upstream http://127.0.0.1:9100;
}
```

每个 prefix 必须有 upstream；cache 可省略，省略时继承站点 cache。prefix 以 `/` 开头且长度至少为 2 字节，不能是单独的 `/`；站点本身提供默认路由。同站点不允许重复 prefix。

对 Nginx 规范化后的 URI 做最长前缀匹配，不按路径段自动补边界：`/api` 也会匹配 `/apix`，要表达目录请写 `/api/`。回源保留请求 URI 和查询串，不自动剥离匹配前缀。

## 5. 后台校验与提交

启动配置解析时先读取并验证源文件；失败会使 `nginx -t` 或启动失败。运行时由各 Worker 的后台任务读取整个文件和引用材料，计算内容摘要、校验字段、目录、证书配对、时间及 DNS SAN，并预加载对象。

相同内容连续稳定到 settle 后，Worker 声明自己的准备状态；共享状态要求所有目标 Worker 在线、新鲜且准备好同一摘要，才能推进活动摘要和 generation。某个 Worker 暂停或读取失败时等待它恢复，其他 Worker 继续使用旧活动版本。

请求取得活动快照引用，内部跳转仍保留；切换后旧请求继续使用原版本，最后一个相关引用释放后回收。普通 C/OpenSSL 指针不跨进程共享。新生 Worker 未装入当前活动摘要时返回 503，后台重建完成后加入服务。

后台任务会读取内容，不能把它视为仅检查 mtime 的低成本通知。证书内容未变时复用已解析对象，但仍需核对材料和有效性。轮询可识别 atomic rename、同路径替换和删除后重建；不提供 inotify 专用模式或固定时延 SLA。

## 6. 文件和证书发布要求

源文件必须是绝对路径下的普通文件，读取会检查文件在读取前后是否变化。受限目录、文件所有者、权限与访问策略由部署者配置。启动 master 和实际 Worker 都要能读取，因为运行时扫描使用 Worker 权限。

建议写好完整临时文件，再在同目录原子 rename 为正式文件。不要依靠稳定窗口代替一次多文件发布的提交边界。证书更新优先使用新的不可变文件路径，证书与 key 准备完成后再原子替换站点文件；同路径更换也会检测，但暂时不匹配时只能保留旧版本等待。

叶证书必须与私钥匹配、未过期并覆盖站点全部 DNS Host，链最多 10 张证书。解析会拒绝截断的证书块。当前没有实现完整公开 CA 路径验证、OCSP、自动签发或续期。bootstrap TLS 配置、会话恢复政策见 [Edge TLS](../native-edge/README.zh-CN.md#4-tls-证书选择)。

## 7. 大小与数量边界

| 项目 | 当前上限 |
| --- | --- |
| 完整站点文件 | 4MiB |
| 站点数 | 256 |
| 每站点 Host / prefix | 各 32 |
| 配置及证书/私钥累计读取量 | 8MiB；按引用计算，不能假定重复引用只计一次 |
| 单证书链 / 单私钥文件 | 256KiB / 64KiB |
| 证书链长度 | 10 张 |
| Nginx Worker 数 | 1～128 |

超限拒绝整个候选版本，不提交部分站点。完整文件和每个引用对象也会在各 Worker 中占用内存；这些边界不等于已完成上限规模压测。手工 reload 为 Config 建立新共享区，generation 从启动状态重新开始。

## 8. 状态接口

`scdn_config_status;` 只允许真实 Unix/loopback 连接的 GET/HEAD。非空查询串或请求体返回 400，不支持的方法返回 405，非本机传输返回 403。它是只读接口，没有内置 token，也不是公网管理 API；使用受限 Unix Socket 父目录隔离访问。

成功响应字段：

| 字段 | 含义 |
| --- | --- |
| generation | 共享活动代际，本次 Nginx 配置周期内的计数 |
| revision | 活动配置和已读取 TLS 材料的 64 字符摘要 |
| sites | 本 Worker 可用快照的站点数量；未就绪时可能为 0 |
| worker_pid | 回答本次请求的 Worker |
| ready | 本 Worker 已装入共享活动版本 |
| last_error | 本 Worker 最近扫描错误，修复后清空 |
| writes_source | 固定为 false |
| restarts_workers | 固定为 false |

状态响应设 `Cache-Control: no-store`。ready 不是源站健康、证书公信任或整个服务的可用性证明。没有启用有效 watcher 时端点可返回 503；单次状态请求也不代表已观察到全部 Worker 的状态。

## 9. 错误码与恢复

| 错误 | 常见触发 | 处理 |
| --- | --- | --- |
| `configuration_unavailable` | 文件不可读、路径/类型/大小错误、读取期间变动，或入口无法解析 | 检查实际 Worker 权限、真实路径及完整外层块 |
| `invalid_site_configuration` | 未知/重复字段、重复 Host/ID/prefix、语法或字段约束错误 | 修复完整文件，再原子发布 |
| `static_root_unavailable` | 启用站点的 root 不存在或路径不安全 | 创建真实目录并授予 Worker 遍历/读取权限 |
| `certificate_validation_failed` | PEM/链截断、配对、有效期或 SAN 不匹配 | 交付完整证书与匹配私钥 |
| `empty_configuration` | 空集合且 allow_empty 为 off | 恢复文件；只有明确删除全部站点时才允许空集合 |
| `reader_task_unavailable` | 专用池任务提交失败 | 检查线程池声明、队列与运行时日志 |

运行中候选失败保留当前内存版本，不自动保存历史文件。全进程重启后仍需要磁盘上有有效完整输入；旧内存不能替代备份。恢复与主动回退按 [操作手册](../docs/OPERATIONS.zh-CN.md)执行。

## 10. 热更新范围

可更新：Host/别名、启停、回源、最长前缀、静态 root、缓存选择、tier 参数和站点 TLS 材料。需要 Nginx reload/重启的项目：监听端口、模块程序、线程池、Worker 数、共享区大小、cache zone 定义、固定 proxy/header/协议指令等启动配置。

插件本身没有远程同步、Master/Node 角色、HTTP 编辑器、WAF、限速、程序升级和持久化发布历史。外部发布者可以交付该文件，但应保证只有一套权威配置来源。
