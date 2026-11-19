# Sub2API 全渠道请求路径与原生 API 插件覆盖

核对日期：2026-11-18。本次更新让已确认的模型、计数和媒体入口在读取正文前进入 AI profile，并将目录、用量和初始化接口明确归为动态 API。正文大小、分块上传和是否携带 SDK 特征头不再决定这些已登记路径能否识别。

## 核对范围与来源

渠道清单来自 [Sub2API 平台注册表](https://github.com/Wei-Shaw/sub2api/blob/2af3f1e15c98c893a89255a037f551046883b8c0/backend/internal/domain/platforms.go)，固定提交 `2af3f1e15c98c893a89255a037f551046883b8c0`。同时核对该提交的 `provider_profile.go`、`domain_constants.go`、`openai_endpoint_url.go`、`gateway.go` 和前端自动生成渠道目录，共 13 个具体渠道；`composite` 是组合调度方式，复用这些入口。

可审阅的[渠道请求样本](api-provider-catalog-20261118.json)保留每个接入模式和协议的具体默认 URL，包含 40 个默认请求与 8 个官方变体。[网关路由样本](api-gateway-routes-20261118.json)从该提交的 `gateway.go` 提取 125 条方法/路径组合，覆盖根路径、Codex、AGY、Gemini 与 Seedance 任务入口。动态资源用示例 ID 替换；模型 action 通配路由还分别验证 generate、stream 和 count。

官方补充来源：

- [智谱国内 API](https://docs.bigmodel.cn/cn/api/introduction)与 [Z.AI 国际 Chat Completions](https://docs.z.ai/api-reference/llm/chat-completion)：`/api/paas/v4/chat/completions`；Sub2API Coding 预设为 `/api/coding/paas/v4/chat/completions`。
- [MiniMax OpenAI Chat](https://platform.minimax.io/docs/api-reference/text-chat-openai)和 [Anthropic 兼容接口](https://platform.minimax.io/docs/api-reference/text-anthropic-api)：国际 `api.minimax.io` 与 Sub2API 国内 `api.minimaxi.com` 域名不同，但标准路径协议相同。
- [OpenCode 模型端点](https://opencode.ai/docs/console/models/)与 [Go](https://opencode.ai/docs/console/go/)：当前文档已提供 `/inference/...`。其公开[推理文档源码](https://github.com/anomalyco/opencode/blob/88ca792e024aa2085fa6e15288be37037c4871d2/services/site/src/docs/content/console/api/inference.mdx)明确 Gemini 实际 action 仍为 `:generateContent` 或 `:streamGenerateContent`，无需把无 action 的任意模型路径当作生成。Sub2API 当前默认仍使用 `/zen`、`/zen/go`。
- [Sub2API AGY 路由](https://github.com/Wei-Shaw/sub2api/blob/2af3f1e15c98c893a89255a037f551046883b8c0/backend/internal/server/routes/gateway.go#L490)和 [AGY 上游 URL 构造](https://github.com/Wei-Shaw/sub2api/blob/2af3f1e15c98c893a89255a037f551046883b8c0/backend/internal/pkg/antigravity/client.go#L33)。

## 逐渠道结论

| 渠道 | 核对的主要路径 | 本次处理 |
| --- | --- | --- |
| Anthropic | `/v1/messages`、`/v1/messages/count_tokens` | 补齐计数的路径识别，保留工具、thinking/signature 和原始事件 |
| OpenAI / Codex | `/v1/responses`、根 `/responses`、compact/input_tokens、`/backend-api/codex/...`、Chat、图片、live | 补齐根别名、资源、异步媒体和实时入口 |
| Gemini | `/v1beta/models/{id}:generateContent/streamGenerateContent/countTokens`、目录和 cachedContents | 补齐 countTokens；目录和显式上下文缓存管理归动态 API |
| Antigravity | `/v1internal:...`、`/antigravity/v1/messages`、AGY Gemini 路由 | 保留已覆盖生成；补齐计数与三个辅助方法的分类 |
| Grok / xAI | Responses/Chat、图片、视频任务/内容、tts/stt、自定义声音、realtime、搜索 | 补齐网关已暴露的媒体、实时和搜索入口 |
| Kimi | `/v1/...`、`/coding/v1/...`、`/anthropic/v1/messages` | 按量/Coding 的三协议预设逐项覆盖 |
| Zhipu GLM / Z.AI | `/api/paas/v4/chat/completions`、Coding 变体、`/api/anthropic/v1/messages` | 修复 v4/Coding Chat 漏判；国内与国际同路径适用 |
| DeepSeek | `/v1/chat/completions`、无 `/v1` 的 `/responses`、`/anthropic/v1/messages` | 修复 Responses 根路径；上游 profile 明确覆盖该路径 |
| MiniMax | `/v1/chat/completions`、`/v1/responses`、`/anthropic/v1/messages` | 按量/Coding、国内/国际逐项回归；计数入口不再依赖请求头 |
| OpenCode Go / Zen / Inference | `/zen[/go]/v1/...`、`/inference/openai/v1/...`、Anthropic、Google action、SystemOne | 保留三协议部署前缀，补齐 SystemOne 和辅助目录识别 |
| TypeSafe / Jev | `/v1/systemone` | 新增 `systemone` 协议标签与 AI profile，保留原始文本/JSON |
| Command Code | `/provider/v1/chat/completions`、`/provider/v1/responses`、`/provider/v1/messages` | 按模型分流的三种实际协议预设逐项回归 |
| Cline | `/api/v1/chat/completions` | 使用 Chat 分类，验证其实际预设 |

渠道名和模型名不参与身份判断。GLM、MiniMax、Kimi 等即使经 OpenCode 聚合，边缘也只按它收到的请求协议选择代理配置。CDN 在 Sub2API 前面时通常看见公共网关 URL；Sub2API 发往渠道的后台 URL 只有在也经过该代理时才需要在该位置识别。

## 新增的内置入口

### 生成、计数、媒体：AI profile

- Responses 根路径和 `compact/input_tokens`；Codex 直连路径；版本化 Responses 的检索、删除、input_items 和取消。
- Messages 的 `count_tokens` 与 Gemini/AGY 的 `:countTokens`。
- GLM v4/Coding Chat 与 TypeSafe/SystemOne。
- 图片 generations/edits 的异步提交、任务读取、批次列表、详情、结果、下载、取消和删除。
- 视频 generations/edits/extensions 的提交、状态与原始内容；Seedance `/contents/generations/tasks` 在根、v1、v3 和 api/v3 的提交、状态与删除。
- xAI tts/stt、自定义声音的创建、列表、详情、音频读取和修改/删除。
- live/Realtime、Codex 实时入口、Alpha/Web/X 搜索。

新增协议值为 `systemone/videos/realtime`，可用于 `$scdn_api_protocol` 及显式 `scdn_api_endpoint` 配置。它们选择已有 AI profile；WebSocket Upgrade 和 gRPC 仍选择专用 profile，同时保留已取得的协议元数据。

### 目录、用量、初始化：动态 API profile

模型列表/详情、用量、`/v1/sub2api/billing`、Gemini cachedContents 的 CRUD，以及 AGY `fetchAvailableModels/loadCodeAssist/onboardUser` 在请求阶段即禁止共享缓存，并记录 `api_endpoint` 原因。它们不因为缺少 JSON Accept 或身份头而被当作公共网页；也不因协议标签而被记作模型生成。

## 匹配与兼容边界

内置规则明确方法，区分 POST 生成、GET/HEAD 读取、PATCH 修改和 DELETE 删除。匹配对象是 Nginx 已规范化的 URI，不包含查询参数；大小写敏感。命名空间明确的路径保留部署前缀兼容，无版本根别名按绝对根路径匹配。动态 ID 仅消费一段非空路径，额外子路径不会被单个 ID 规则吞掉。匹配不调用正则，不创建请求级路由状态。

Sub2API 还显式转发 POST Responses 子路径；因此根 `/responses/`、版本化 `/v1/responses/` 和 Codex Responses 的 POST 子路径沿用上游的有界约定：最多 8 段、每段最多 128 字节，只接受字母、数字、下划线、连字符和点，拒绝仅由点组成的段。该识别只是代理配置选择，不替代应用的路径验证。其他媒体 ID 规则仍只消费一段。

显式 `scdn_api_endpoint` 继续优先于内置规则，保留方法、站点、继承及最长路径约束。未登记的私有部署路径仍可显式配置。未知方法、未知 Gemini action、未知媒体子资源和近似路径不会仅因字符串相似而取得 AI 标签；应用最终决定路径是否有效。

API 元数据不是鉴权结果，不触发放行、计费或厂商能力声明。Sub2API 的协议转换、按模型调度、账号限制、OAuth、工具执行、任务状态及媒体下载策略继续由应用处理。插件原样代理请求和结果，不替上游实现未支持的厂商接口；本次覆盖的是固定 Sub2API 注册表、相关原生协议及网关路由，不代表每家厂商所有独立产品接口。

默认 AI profile 关闭共享缓存、请求/响应缓冲和 gzip，使用较长空闲超时，关闭回源重试并传播客户端取消。普通动态 API profile 仍关闭共享缓存；辅助接口不强制套用长生成配置。大型媒体不受 16/64 KiB 分类检查预算限制。

## 验证方法

`native-api/tests/providers.py` 使用本地确定性 origin 和保存的上游请求样本，在 `scdn_api_inspect_body 0` 时验证所有渠道与网关路由。样本包括超过检查预算的原始正文、分块上传、未知工具字段/签名、分段 SSE、目录无 Accept 头、明确方法/资源段反例、显式站点覆盖、定长和分块的提前回源，以及真正的 WebSocket 握手。厂商域名仅为 URL 来源，不在测试中连接。

已有四协议工具链、大图片、媒体提取、API/Edge/Purge/Sync 共存和访问阶段回归继续运行。三种构建均纳入 CI；本地和远端实际通过数量见对应验证记录，不能用测试样本代替生产或真实厂商验收。

本地三种构建共通过 2,508 项检查，每种 836 项，其中新渠道套件为 615 项。详细 suite 数量、报告摘要、二进制摘要和验证边界见[本地验证记录](validation-api-providers-20261118.json)。
