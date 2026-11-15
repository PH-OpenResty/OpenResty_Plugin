# 验证记录与复现

本页记录 Config/API/Edge；Purge 的一致性、恢复与性能结果见 [清理模块验证](../native-purge/tests/VALIDATION.zh-CN.md)和[基准报告](../native-purge/bench/README.zh-CN.md)。统一构建和 CI 包含四个插件，下面的三模块结果为合入最新主分支前的记录，整合后的验证单独记录。

## 合入当前 main 后的四模块验证

基于 `64c9d3c`（包含 Purge 与回源再验证）重新构建纯 Nginx 动态模块和完整 OpenResty 静态模块，两种运行时均通过：Config/Edge 47 项、API 43 项、API＋Purge 共用 44 项、Purge 70 项、模式匹配 64 项、回源再验证 45 项、交付模板 43 项。共用测试开启 API 分类、原生失效 key 和源站再验证，并检查缓存命中后的持久化清理及原有流式/协议行为。

结果与每份报告的摘要见 [validation-api-main-integration-20261114.json](validation-api-main-integration-20261114.json)。Purge 三套测试新增 `--static` 入口，检查内容保持；CI 继续执行所有套件，并保留 Nginx ASan/UBSan 与动态/静态 OpenResty 矩阵。以上为本地隔离结果，远端 CI 结果以 PR 检查记录为准。

日期：2026-11-14。这份记录区分导入前已有结果和新仓库的独立验证；远程 CI 结果以当前提交的 Actions 记录为准。

## API 扩展的当前验证

当前实现新增 API 模块，并扩展 Config/Edge 的 HTTPS、IPv6、命名池、origin_host 与自动 profile 接入。当前摘要覆盖 12 个实现/config 文件；下方初始导入记录为历史，不能据此认为源码仍未修改。

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

本地 Alpine 缺少 ASan 运行库，本轮未执行本地 ASan。CI 已配置 Nginx 的 ASan/UBSan、普通完整 OpenResty 和静态 OpenResty；当前工作区没有推送，不能声称本次远程 CI 已通过。

```sh
python native-api/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-api-results.json
```

静态构建使用构建脚本第三参数 `static`，两套测试均加 `--static`；测试交付模板增加 `--templates`。本轮缺少 SSH 登录，未执行目标 Node 现场构建或安装。

## 已有实现基线

初始实现来自原仓库提交 62fb619。当时的无 Lua Nginx 和完整 OpenResty 各通过 47 项 Config/Edge 检查，初次整理未修改实现；后续 API 扩展已修改 Config/Edge 并新增模块，当前摘要见 [SOURCE-SHA256SUMS](../SOURCE-SHA256SUMS)。

原仓库同时验证的 Sync 角色和 Lua 协议测试不属于这两个插件的新仓库测试数量，不作为本仓库具备远程同步的证据。

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

CI 的 nginx 构建为整个运行时和两个动态模块启用 `-fsanitize=address,undefined -fno-omit-frame-pointer`，UBSan 遇错中止；OpenResty 额外做普通严格编译及真实进程检查。完整测试关闭 leak detection，因为测试中 Nginx fork/退出生命周期与进程级分配不用于此项泄漏验收。

[tests/asan.supp](../tests/asan.supp)仅排除 Nginx 按 dlsym 设计同时从可执行文件与动态模块导出的 `ngx_modules`、`ngx_module_names`、`ngx_module_order` 注册表 ODR 报告，不排除模块缓冲区、释放后访问或其他全局数据诊断。

既有本地 UBSan trap 调试发现上游 Nginx 缓存对缺失 ETag 使用 `memcpy(NULL, 0)` 的检查触发点。测试源站提供正常 ETag，插件没有修改该核心路径；不能把当前语料通过描述为 Nginx 全部缓存路径都已通过 UBSan。

## Worker 启动时差回归

2026-11-14 的主分支 [Actions 43658761073](https://github.com/PH-OpenResty/OpenResty_Plugin/actions/runs/43658761073) 在 `two real workers started` 断言失败：首个 Worker 可以先回答状态请求，另一个还未完成初始化，测试过早记录了 PID 集合。Nginx 在 `ngx_worker_process_init` 返回后才设置 `worker process` 标题；单个 HTTP 响应不能替代全部 Worker 就绪。

Config/Edge 和 Purge 测试夹具现在都等待实际的两个 Worker（最多 10 秒），再记录完整 PID 基线。源站校验测试直接沿用该基线，后续 PID 保持断言仍严格比较原集合。进程枚举处理子进程退出时的 `/proc` 读取竞争；启动检查还检查本次启动新增的错误/标准输出，不把崩溃后的重建视为正常启动。按日志偏移读取，避免原有故障注入的历史记录干扰下一次有意重启。

[worker_startup.py](../tests/worker_startup.py) 增加 6 项真实进程检查：测试专用 fork 夹具暂停第二个子进程，证明首个 HTTP 响应早于全部 Worker 就绪；验证有限等待、释放后返回完整集合、崩溃重建仍失败，以及 master 退出时立即失败。夹具只在临时目录编译并通过 LD_PRELOAD 注入，不链接进生产模块。两种运行时均执行这组检查；Nginx CI 仍启用 ASan/UBSan，未增加诊断抑制或失败重试。

当前每种运行时共 232 项：6 项启动回归、47 项 Config/Edge、70 项原有 Purge、64 项模式清理、45 项源站校验/过时复用。失败时同时输出有长度限制的 error.log 和 stdout.log，已产生的检查报告也会上传；报告不包含 token、证书或 journal。

## 文档与发布验证

独立发布前检查模块摘要、相对文档链接、示例所需文件、脚本语法、实际待提交文件和凭据扫描。源码仅包含通用模板，实际运行配置和二进制不进入 Git。新仓库 Actions 分别执行源码摘要核对、两种运行时的 47 项测试及公开内容检查。

## 未验证范围

当前不证明生产吞吐/容量上限、长时间压力与磁盘故障、ARM64、所有非 root/systemd 组合、HTTP/2/HTTP/3 全部行为、会话恢复/撤销政策或任意目标构建的 ABI。ready 不是业务健康结果，插件也没有实现远程 Master→Node 协议或完整高可用控制面。
