# 模块接管与保留 Lua 安全引擎

迁移原则：已有原生模块负责的功能只走原生模块；WAF、限流及其他尚未被模块替代的 Lua 继续保留。这里没有将 WAF 或限流伪称为原生实现，也不要求删除 LuaJIT 运行库。

## 唯一站点快照

Config/Sync 的受管快照同时携带站点身份和有类型约束的安全策略。Edge 为当前请求保留不可变版本，通过 `$scdn_edge_security` 提供 JSON；`compat/lua/lib/security_guard.lua` 按同一请求的 site/revision 读取，调用原有 `lib.waf`、`lib.ratelimit`。它不读取 Lua 站点文件、不重建注册表、不发布配置或选择证书。

站点数据新增以下字段，仅在 site 层使用，默认 WAF/限流关闭：

```nginx
site app {
    host app.example.test;
    upstream https://origin.example.test;
    cache l2;
    waf on;
    waf_threshold 5;
    waf_group sqli;
    waf_group xss;
    rate_limit 50 100;
}
```

`waf` 为 on/off；threshold 为 1～1000000，默认 5；最多 16 个不重复的 waf_group，名称是长度不超过 96 的安全标识符，不支持路径或 Lua 表达式。WAF 开启时必须至少有一个组。`rate_limit off` 关闭限流；数字形式是每秒请求数（1～1000000）和 burst（0～1000000）。未知字段、重复开关、越界值和路径型组名拒绝整份候选。策略是数据，随签名/加密快照一同发布；规则程序本身仍安装在节点本地。

`$scdn_edge_security` 包含 `name`、`waf.enabled/threshold/groups`、`rate_limit.enabled/req_per_sec/burst`，不包含证书私钥、源站地址或任意可执行源码。适配器使用容量 512 的 Worker LRU；源版本变化后不复用旧策略。模块会在内容阶段检查 `$scdn_edge_security_checked`：策略开启却没有安全处理器确认时返回 503，避免忘记安装适配器后直接放行。客户端请求头不能设置该 Nginx 内部变量。适配器只在 WAF 和限流检查通过后置为 1，命名 location 跳转不会造成重复扣减；同一站点和快照的内部子请求可以继承主请求已完成的确认，其他站点不能继承。

WAF 分组文件缺失时返回 503，不沿用旧引擎的忽略行为。WAF 命中继续 403，限流继续 429；现有引擎的其他规则、计数算法、存储和错误行为不在此迁移中改写。

## 哪些文件退出运行路径

| 原有功能 | 接管者 | 处理 |
|---|---|---|
| Lua 站点路由、registry/native_export、旧 sitectl 发布 | Config/Edge/Sync | 停止旧写入入口；迁移源数据后退出这些脚本及对应字节码 |
| cluster agent/control、旧 timer | Sync 原生发布与拉取 | 交接唯一写入权后停用旧 service/timer/控制 location |
| `lib.sni` | Edge TLS | 删除 Lua 证书回调，启用 `scdn_edge_tls on` |
| `tier`、`flush_l1_to_l2`、旧 tier 配置 | Tier / Nginx cache | 建立完整 L1→L2 读取链后退出旧计数和停机复制路径 |
| 逐请求 Lua metrics | Edge 原生计数器 | 退出旧计数；可保留仅转换指标格式的 native_metrics 适配器 |
| WAF、限流、WAF 规则 | 现有 Lua 引擎 | 保留代码；security_guard 替换为读取原生策略的桥接器 |
| 未知业务 Lua / 外部辅助功能 | 原有实现 | 保留；若仍依赖退役模块，暂存检查会报错，需明确适配 |

不再执行 `init_by_lua require("lib.registry").reload()`、旧 `/cluster/*` 发布/拉取/报告、旧 admin reload 和 Lua SNI 回调。只停止 timer 而保留启动时 registry reload，仍然存在双写冲突。退出旧 CLI 不代表 TCP/RTMP 等独立 Nginx 配置应删除：它们需保留在原有 include 中，站点转换器对这些不支持字段拒绝转换，避免静默丢失。

## 一次性转换与暂存工具

先备份已有站点源、证书和服务配置。`compat/lua/export_sites.lua` 只接受管理员信任的旧 `.lua/.ljbc` 文件；loadfile 具有执行能力，不能用于上传文件或不可信输入。将结果保存到私有候选，交由原生 Config 完整校验后再作为 Master source：

```sh
umask 077
luajit /source/compat/lua/export_sites.lua /private/legacy-sites/*.lua \
  > /private/native-sites.candidate.conf
```

转换保留 Host、源站 Host、前缀、启停、证书引用、缓存层和 WAF/限流参数。它不复制证书私钥，不修改输入或活动配置；不支持的字段直接失败，输出只有完整成功的快照。后续操作应直接编辑原生 Master source，不再运行旧 CLI 写 Lua 站点表。

`tools/stage-lua-handoff.py` 创建**新的** Lua 树：按精确清单去掉模块已接管的脚本、对应字节码和旧同步状态，替换 security_guard，保留其他文件原字节。它拒绝符号链接及重叠目录，发现保留文件仍引用退役模块时失败。原树和 systemd/活动 Nginx 配置始终由部署步骤管理：

```sh
python tools/stage-lua-handoff.py \
  --source /private/legacy-lua --destination /private/native-lua-stage \
  --luajit /opt/openresty/luajit/bin/luajit \
  --report /private/lua-handoff.json
```

暂存里的维护 hook 要求显式 `NGINX_BIN`，构建脚本要求显式 `LUAJIT_BIN`；它们不复制缓存文件、不重新生成旧站点数据。报告列出保留和退役文件。此工具不是自动部署器，不会自行停止旧服务、替换缓存目录或发布真实站点。

## TLS 与激活

保留 bootstrap 证书，启用 `scdn_edge_tls on`，删除 `ssl_certificate_by_lua*`。默认未知 SNI 仍拒绝握手；需要维持原先默认证书行为时可显式配置 `scdn_edge_tls_fallback on`。这只允许未知、禁用或无站点证书的 SNI 使用 bootstrap 证书，HTTP Host 仍由原生 Edge 检查；有效站点证书失败不会降级。该设置不能绕过浏览器证书名称校验。

参考 [http 安全片段](../compat/examples/security-http.conf) 与 [server 安全片段](../compat/examples/security-server.conf)。将它们与既有原生 API/Tier/Purge 和 Sync managed 配置组合，在新端口验证。确认 native source、TLS、WAF、限流、停用/删除和回退均正常后，交接唯一写者，再停用旧 timer/publisher 与脚本入口。日志和缓存路径可沿用部署已有路径；旧 L1 独有对象的迁移仍遵循 Tier 手册。

## 验证

`native-sync/tests/lua_handoff.py` 在真实 Master/双 Node 上测试：转换及暂存不改旧树、保留原 WAF/限流文件、无 registry 的新增 Host、新站点 WAF、动态安全策略、429、删除 Host、无 Lua SNI 的证书热更新、缺失适配器/规则 fail closed，以及非法策略保持旧配置。只适用于带 Lua 的 OpenResty，支持动态与静态构建；Nginx 纯 C 构建仍可传输策略，安全执行必须由已安装处理器确认。

测试 fixtures 保留已有精简 Lua WAF/限流接口及规则，用于证明执行路径；不将其计为新的原生安全模块。暂存工具、示例与测试不含真实服务器、token、密钥或站点配置。
