# 验证记录与复现

统一构建和 CI 包含 Sync、Config、Ban、API、Edge、Tier、Purge 七个插件。Sync 角色/身份见 [Sync 验证](../native-sync/tests/VALIDATION.zh-CN.md)，Purge 见 [清理模块验证](../native-purge/tests/VALIDATION.zh-CN.md)和[基准报告](../native-purge/bench/README.zh-CN.md)。本页保留历史基线，并单独记录当前整合结果。

## Ban 0.1.0 当前运行验收

新增 native-ban 的 Nginx 模块、C++ Agent、XDP/TCX 内核对象和原生 Sync 桥，统一构建现为七模块。`native-ban/tests/runtime.py` 使用真正的 root netns/veth/bpffs、三个 Agent/节点和已登记 mTLS，权限不足直接失败；不以 Schema/ABI 或模拟 Map 替代内核 DROP。

当前 Ban 运行套件为 64 项，涵盖 L7/CC、固定期限、IPv4/IPv6/UDP、任意来源设备的完整表、内核 ACK、全局解封、签名篡改/旧快照拒绝、离线 outbox、Agent kill/原 inode 恢复、内核独立过期、事件重放、只读 FD、CIDR 豁免、策略热更新、日志故障补投、VLAN/IPv4 分片及报文边界。XDP native 和 TCX ingress 分别执行；Nginx 动态 CI 同时为 Nginx/模块和 Agent 启用 ASan/UBSan。

既有 646 项回归、主分支新增的 47 项 Sync 恢复和 OpenResty 的 27 项 Lua 交接继续执行；每种构建新增 64 项 TCX，Nginx 动态另执行 64 项 XDP，两种 OpenResty 另执行 4 项真实 Lua WAF → Ban → 全节点 eBPF 联动。实际完成状态以最新提交 Actions 和报告为准。本地/CI 结果不代表生产 NIC offload、全容量压力、所有时钟/断电组合或已在真实节点部署。

历史设计检查仍用于草案追溯，0.1.0 实际配置、SQLite WAL 和运行 ABI 以 [运行手册](../native-ban/RUNTIME.zh-CN.md)为准。

## 应用记录恢复与原生/Lua 交接修复

本轮独立 OpenResty 静态构建通过原有 646 项，以及新增 47 项应用记录/恢复检查和 27 项 Lua 交接检查，共 720 项。新测试真实注入 write/fsync/rename/unlink 错误，在提交窗口终止进程，并核对活动配置、旧应用记录、回退点、重启恢复及文件属主。Lua 测试保留原引擎文件，验证新 Host、WAF 403、限流 429、原生 TLS 热更新、内部子请求、缺失处理器拒绝和受限暂存清理。

结构化本地记录见 [validation-sync-recovery-lua-20261115.json](validation-sync-recovery-lua-20261115.json)。CI 新增 recovery.py（三种构建）和 lua_handoff.py（两种 OpenResty 构建）；完整上游结果以 PR 对应提交为准。纯 Nginx 不执行 Lua，引擎交接检查不在那里冒报通过。没有部署生产节点，也没有声称完整断电/磁盘故障矩阵或性能验收。

## PR #9 合并审查补充

审查补齐 Tier 独立运行时的 Api-Key、Proxy-Authorization 和 Pragma: no-cache 绕过，并修复重复凭据/缓存控制头不能被识别的问题。新增 9 项实际回源/隔离检查，覆盖已存在的匿名缓存、不同调用者凭据和重复字段；Tier 套件增为 48 项，当前每种构建矩阵为 646 项，三种合计 1,938 项。旧 637 项结果仍按初次交付基线保留，最新提交的全部 Actions 成功才允许合并。

## Sync 0.3.0 与 Tier 0.1.0 初次交付矩阵

初次交付运行时包含六模块。新增站点/证书原生发布套件 40 项，Tier 独立层级缓存 39 项，六模块真实代理共存 51 项；连同既有启动 6、角色 50、缓存任务 99、Config/Edge 47、缓存头 32、API 44、五模块组合 50、Purge 70、模式 64、源站/stale 45，每种构建共 637 项进程检查。Nginx 动态、OpenResty 动态和 OpenResty 静态各通过 637 项，共 1,911 项；本地结构化结果见 [validation-native-sync-tier-20261115.json](validation-native-sync-tier-20261115.json)。

配置发布证据包括两个 Node 的路由与证书实效、源变更、删除/停用、签名/加密/过期/旧序号/跨节点拒绝、损坏水位、业务探测回退、ACK 重报、Master 断线和启动恢复；Tier 验证 L2 命中晋升、固定层级下绝对期限保持、大小预算、Vary/查询串、两层共同失效、穿透 L2 的源站校验，以及 L1 丢失后从 L2 恢复。六模块组合含真实 API/AI/SSE/WebSocket/gRPC 流程。

这些是隔离功能与故障路径检查，未宣称生产吞吐、完整掉电矩阵、任意第三方过滤器或所有目标 ABI。32 个当前实现/config 文件的摘要、全量文档链接/围栏、脚本语法与公开索引检查同时执行。最终结果以当前提交的 CI 和本页链接报告为准；历史基线如下保留原数值。

## 缓存规则头及 Ban v2 集群合同（历史设计阶段）

新增 `native-edge/tests/cache_headers.py` 的 32 项真实进程检查，覆盖静态回源元数据、客户端重复头清除、源站伪造诊断覆盖、MISS/HIT/BYPASS/OFF、site/prefix 继承、非法头和字段预算、在途快照版本及不重建 Worker 的热更新。它和原有 475 项组成每种构建 507 项完整矩阵；实际构建结果另见对应提交 CI。

`native-ban/tests/check-design.py` 校验 v2 必需集群字段、禁止局部/增量替代全量、Schema/TOML、容量约束、四个 C11 ABI 头及合成事件/IP 日志关联。Ban 的 18 项集群运行验收仍为待实现，不能将设计校验或缓存头进程测试计为多机封禁/eBPF DROP 已验收。

缓存头语义见 [手册](CACHE-HEADERS.zh-CN.md)，Ban 完整快照、固定期限、离线/撤销/逐节点内核确认合同见 [设计](../native-ban/design/CLUSTER-SYNC.zh-CN.md)。

## Sync 0.2.0 缓存任务与 HTTP 头更新（历史）

本地日期：2026-11-15，隔离 WSL2/Alpine x86_64。Nginx 动态、OpenResty 动态、OpenResty 静态各通过 475 项进程检查：

| 套件 | 每种构建通过数 |
| --- | ---: |
| Worker 启动 | 6 |
| Sync 角色、鉴权及 mTLS | 50 |
| Master/Node 缓存任务及公开配置片段 | 99 |
| Config/Edge | 47 |
| API 及客户端 IP 头覆盖 | 44 |
| 五模块组合 | 50 |
| Purge | 70 |
| 匹配失效 | 64 |
| 源站校验与 stale | 45 |

结构化结果见 [validation-cache-tasks-20261115.json](validation-cache-tasks-20261115.json)。缓存任务覆盖真实落盘、Master/Node 重启、ACK 丢失、租约耗尽、登记 scope 变化、并发幂等、128 项队列容量、各清理模式、HTTP/HTTPS 预热、HIT 验证和 Worker PID 保持；API/任务代理验证 `X-Clinet-IP` 被连接地址覆盖。任务始终以至少一次执行表述，不把重启测试当作任意掉电或 exactly-once 的证明。

纯 C 核心严格 C99 和 UBSan trap 通过；24 个当前实现文件摘要、相对 Markdown 链接/围栏、脚本语法、实际索引公开检查及 Gitleaks 工作树/历史扫描通过。该次本地没有宣称 ASan；Actions 的 Nginx 任务保留 ASan/UBSan，结果见对应历史提交。

这些是功能验证，不证明生产吞吐、跨地域网络故障、完整磁盘故障矩阵或配置快照同步已原生化。配置快照仍按 [Sync 路线图](SYNC-ROADMAP.zh-CN.md)迁移，缓存任务合同见 [任务手册](CACHE-TASKS.zh-CN.md)。

## Sync 0.1.0 迁入后的五模块验证（历史）

该次迁入的 Sync 来源实现不改动，独立测试补齐静态编入和当前启动就绪/错误诊断。API 组合套件增加 `--purge --sync`：实际启用五个模块，使用不同 Sync/Purge token，检查 Node 身份、不冒报远程 applied、准确能力位及原有代理、缓存和流式行为。结构化结果见 [validation-sync-import-20261114.json](validation-sync-import-20261114.json)。

该次三种构建为 Nginx 动态、OpenResty 动态和 OpenResty 静态。每种执行启动 6 项、Sync 50 项、Config/Edge 47 项、API 43 项、五模块组合 49 项、Purge 70 项、模式 64 项、再验证 45 项，共 374 项；纯 C 核心另行执行。它们验证角色/身份和共存，不证明 JWE/JWS、Node 拉取或事务已经原生化。CI 报告按套件分别上传，不包含运行目录和密钥。

## API 合入时的四模块验证（历史）

基于 `64c9d3c`（包含 Purge 与回源再验证）重新构建纯 Nginx 动态模块和完整 OpenResty 静态模块，两种运行时均通过：Config/Edge 47 项、API 43 项、API＋Purge 共用 44 项、Purge 70 项、模式匹配 64 项、回源再验证 45 项、交付模板 43 项。共用测试开启 API 分类、原生失效 key 和源站再验证，并检查缓存命中后的持久化清理及原有流式/协议行为。

结果与每份报告的摘要见 [validation-api-main-integration-20261114.json](validation-api-main-integration-20261114.json)。Purge 三套测试新增 `--static` 入口，检查内容保持；CI 继续执行所有套件，并保留 Nginx ASan/UBSan 与动态/静态 OpenResty 矩阵。以上为本地隔离结果，远端 CI 结果以 PR 检查记录为准。

日期：2026-11-14。这份记录区分导入前已有结果和新仓库的独立验证；远程 CI 结果以当前提交的 Actions 记录为准。

## API 扩展验证（历史基线）

API 引入阶段新增协议识别，并扩展 Config/Edge 的 HTTPS、IPv6、命名池、origin_host 与自动 profile 接入。该阶段摘要覆盖 12 个实现/config 文件；后续清单已继续扩展至当前六模块，历史记录不作为原始源码未修改的证明。

结构化结果见 [validation-api-20261114.json](validation-api-20261114.json)。本轮没有替换线上 Node 二进制或配置，没有调用真实模型厂商。

| 构建或场景 | Config/Edge | 自动 API/代理 | 说明 |
| --- | --- | --- | --- |
| 纯 Nginx 核心，三个动态模块 | 47 项通过 | 43 项通过 | 业务不需要 Lua |
| 完整 OpenResty，三个动态模块 | 47 项通过 | 43 项通过 | 与完整运行时集成 |
| 完整 OpenResty，三个静态模块 | 47 项通过 | 43 项通过 | 对齐 Node 的静态编入方式 |
| 实际 profiles/common 模板 | — | 43 项通过 | 使用交付模板执行真实代理测试 |
| UBSan trap 构建 | 47 项通过 | 43 项通过 | 原生模块的 alignment 等检查保持 |
| 旧 SCDN Node 结构的隔离接入 | — | 6 项通过 | 预检、HTTP/HTTPS、访问处理、缓存映射和冷导出器 |

这些是同一核心测试在不同构建上的验证次数，不能把重复运行累计成不同能力。Node 接入使用本地夹具，不能描述为目标服务器现场验收。

API 测试覆盖路径/头部/有界 JSON 判定、响应 JSON/SSE 补判、混淆和无效 UTF-8、正文完整性、异步读取、缓存绕过、SSE 首段、HTTP/2 多路复用、gRPC DATA/trailers、WebSocket、取消传播、TCP 复用、HTTPS/SNI 及热更新。

本地环境为隔离 WSL2/Alpine x86_64、GCC 14.2.0。UBSan 使用 `-fsanitize=undefined -fsanitize-undefined-trap-on-error`。首次 HTTP/2 检查在上游 `ngx_http_v2_send_settings` 的 write_sid 触发，调试栈对应固定源码 `ngx_http_v2.c:2837`；Nginx 在支持的架构上用 `NGX_HAVE_NONALIGNED` 选择这种读写。

[sanitizer-cc.sh](../tools/sanitizer-cc.sh) 仅对上游 `src/http/v2/*.c`、`ngx_http_grpc_module.c`、`ngx_http_proxy_v2_module.c` 关闭 alignment 插桩，其余 UBSan 及全部原生插件的 alignment 检查保持。采用该测试编译设置后两套测试均通过，没有修改 Nginx 核心源码或线上参数。

该阶段本地 Alpine 缺少 ASan 运行库，未执行本地 ASan。CI 保留 Nginx 的 ASan/UBSan、普通完整 OpenResty 和静态 OpenResty，远端结果按相应提交的 Actions 判读；下方本地基线不替代当前 CI。

```sh
python native-api/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-api-results.json
```

静态构建使用构建脚本第三参数 `static`，两套测试均加 `--static`；测试交付模板增加 `--templates`。本轮缺少 SSH 登录，未执行目标 Node 现场构建或安装。

## 已有实现基线

初始实现来自原仓库提交 62fb619。当时的无 Lua Nginx 和完整 OpenResty 各通过 47 项 Config/Edge 检查，初次整理未修改实现；后续 API 扩展已修改 Config/Edge 并新增模块，当前摘要见 [SOURCE-SHA256SUMS](../SOURCE-SHA256SUMS)。

原仓库的 Sync 角色与 Lua 协议结果不混入历史 Config/Edge 47 项。现在原生 Sync 有本仓库自己的 50 项套件；旧 Lua 端到端同步结果仍不作为原生传输完成的证据。

## 初始独立仓库验证（API 扩展前）

在全新的测试前缀中，使用本仓库自己的 `tools/build-runtime.sh`，只编译 Config/Edge：

| 项目 | 本地结果 |
| --- | --- |
| Nginx 1.31.8 的独立构建与真实进程检查 | 47 项通过 |
| 完整 OpenResty 1.31.8.1 的独立构建与真实进程检查 | 47 项通过 |
| 实际发布的 nginx.conf/sites.conf 模板，在隔离路径和账户适配后启动 | 语法、默认路由、前缀路由、热更新、Worker PID 保持共 5 项通过 |
| 8 个实现文件与来源摘要、文档链接/代码围栏、Python/构建脚本语法 | 通过 |

本地环境为隔离 WSL2/Alpine x86_64、GCC 14.2.0、OpenSSL 3.5.9。模板测试没有在用户系统创建生产账户、安装服务或覆盖原 Nginx。CI 另在 Ubuntu 上运行，结果以当前提交记录为准。

## 当前测试覆盖

`native-edge/tests/integration.py` 创建临时源文件、证书、两个 loopback 源站、Unix Socket 和两个真实 Worker，检查后停止进程并删除临时材料。47 项检查覆盖：

- 启动语法、未知/重复字段、重复 Host/ID、错误上游、空集合和截断输入语料。
- Host/别名、静态目录、最长 prefix、URI 与查询串保留。
- SNI、未知 SNI、停用站点、部分证书链、配对失败和同路径证书轮换。
- 回源变更后新请求换版本，旧请求和已有 TLS 连接继续完成；Worker PID 保持不变。
- 新增/删除站点、错误候选保留、暂停 Worker 时等待、Worker 重建后加入活动版本。
- 缓存选择、可选热度、指标、源文件与字节码不被写入，以及没有内置 WAF/限速。

## 独立复现

```sh
python -m pip install -r tests/requirements.txt
sha256sum -c SOURCE-SHA256SUMS
sh tools/build-runtime.sh /tmp/scdn-plugin-nginx nginx
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-nginx-results.json
```

把 runtime 换成 openresty，并使用新前缀，可以验证完整 OpenResty。测试报告只保存检查名称和通过数量，不包含证书、私钥、token 或站点正文。

## Sanitizer 设置

CI 的 nginx 构建为运行时和六个动态模块启用 `-fsanitize=address,undefined -fno-omit-frame-pointer`，UBSan 遇错中止；OpenResty 做普通严格编译及动态/静态真实进程检查。上游协议解析的窄 alignment 设置仍按 sanitizer-cc.sh 说明，原生模块不取消该检查。完整测试关闭 leak detection，因为测试中 Nginx fork/退出生命周期与进程级分配不用于此项泄漏验收。

[tests/asan.supp](../tests/asan.supp)仅排除 Nginx 按 dlsym 设计同时从可执行文件与动态模块导出的 `ngx_modules`、`ngx_module_names`、`ngx_module_order` 注册表 ODR 报告，不排除模块缓冲区、释放后访问或其他全局数据诊断。

既有本地 UBSan trap 调试发现上游 Nginx 缓存对缺失 ETag 使用 `memcpy(NULL, 0)` 的检查触发点。测试源站对正常 200 响应提供 ETag；新增缓存任务负例的 302/503 和私有响应明确声明 no-store。Nginx 会主动清空非 200/206 缓存响应的内部 ETag，因此只补响应 ETag 不能避免这些负例进入该路径。失败预热断言及 sanitizer 诊断检查继续保留，插件没有修改该核心路径；不能把当前语料通过描述为 Nginx 全部缓存路径都已通过 UBSan。

## Worker 启动时差回归

2026-11-14 的主分支 [Actions 43658761073](https://github.com/PH-OpenResty/OpenResty_Plugin/actions/runs/43658761073) 在 `two real workers started` 断言失败：首个 Worker 可以先回答状态请求，另一个还未完成初始化，测试过早记录了 PID 集合。Nginx 在 `ngx_worker_process_init` 返回后才设置 `worker process` 标题；单个 HTTP 响应不能替代全部 Worker 就绪。

Config/Edge 和 Purge 测试夹具现在都等待实际的两个 Worker（最多 10 秒），再记录完整 PID 基线。源站校验测试直接沿用该基线，后续 PID 保持断言仍严格比较原集合。进程枚举处理子进程退出时的 `/proc` 读取竞争；启动检查还检查本次启动新增的错误/标准输出，不把崩溃后的重建视为正常启动。按日志偏移读取，避免原有故障注入的历史记录干扰下一次有意重启。

[worker_startup.py](../tests/worker_startup.py) 增加 6 项真实进程检查：测试专用 fork 夹具暂停第二个子进程，证明首个 HTTP 响应早于全部 Worker 就绪；验证有限等待、释放后返回完整集合、崩溃重建仍失败，以及 master 退出时立即失败。夹具只在临时目录编译并通过 LD_PRELOAD 注入，不链接进生产模块。两种运行时均执行这组检查；Nginx CI 仍启用 ASan/UBSan，未增加诊断抑制或失败重试。

该次启动修复的基线每种运行时共 232 项：6 项启动回归、47 项 Config/Edge、70 项原有 Purge、64 项模式、45 项源站/stale。迁入时的五模块完整矩阵为上面的 374 项。失败诊断与报告仍保留，报告不包含 token、证书或 journal。

## 文档与发布验证

独立发布前检查六模块摘要、相对文档链接、示例所需文件、脚本语法、实际待提交文件和凭据扫描。源码仅包含通用模板，实际运行配置和二进制不进入 Git。Actions 执行当前完整矩阵及公开内容检查，历史 47 项仍属于其中 Config/Edge 的独立套件。

## 未验证范围

当前不证明生产吞吐/容量上限、长时间压力与磁盘故障、ARM64、所有非 root/systemd 组合、HTTP/2/HTTP/3 全部行为、会话恢复/撤销政策或任意目标构建的 ABI。ready 不是业务健康结果，原生配置快照及缓存任务均已有独立通道；完整高可用控制面、旧 Lua 协议互通及全部故障矩阵未宣称完成。

Tier 的缓存期限回归显式固定 L1 选择，在丢失 L1 后由仍有效的 L2 晋升，再在原始绝对到期后核对源站新版本；避免用热度降层掩盖 TTL 重起。远端 UBSan 发现有效空变量返回 NULL 时触发 Nginx 的零长度复制，现返回有效空字符串；保持诊断失败断言并单独用带 UBSan 的 Nginx 重跑 Tier。
