# 原生 API 工具链与图片原始/处理结果：上游调研和设计

日期：2026-11-17，America/Los_Angeles。状态：端点修复、按方法/路径/站点的协议目录、raw 传输回归和显式本地媒体工具已实现；服务器媒体服务、客户端附件发出及真实展示仍需相应集成。研究基线为 OpenResty_Plugin `d4d5609`、Sub2API `15871f9`、NewAPI `669d774`；完整提交见[总设计](BOT-UA-AUTH-GUARD-RESEARCH-DESIGN.zh-CN.md)，当前接口见[API 手册](../native-api/README.zh-CN.md)。

## 1. 交付目标和当前事实

`native-api` 应覆盖 OpenAI Responses、OpenAI Chat Completions、Gemini、Anthropic Messages 的普通/流式调用、工具请求及结果、图片输入和返回，以及已登记的异步资源入口。工具执行由调用方或上游应用完成；CDN 对调用、结果、状态和不透明字段提供完整传输，不自行执行模型提出的工具。

本项目已有线上图片端点补丁与 CLI 兼容报告。该报告确认官方 Codex CLI 0.167.0 在本地协议 fixture 收到原生图片事件后没有产出图片附件或文件；这不是对所有客户端或 Desktop 渲染器的结论。本次读取该报告、补丁和测试源码，没有重新访问生产节点，也没有重新调用收费模型。

修复前基线的端点表缺少 `/v1/images/edits`、`/v1/images/variations`。本次已在源码补齐，并纳入真实代理回归；音频翻译也已补齐。变体接口进入正确代理策略，不意味着每一种上游都实现了变体业务。

图片交付分别记录以下事实：

| 事实 | 所需证据 |
| --- | --- |
| 原始协议传输完成 | 接收端重组后的正文完整，事件 ID/顺序/终态与源端一致 |
| 图片数据有效 | 严格解码，PNG/JPEG/WebP 图像解码器完整读取成功 |
| 真实文件保存成功 | 原子保存、实际 MIME/尺寸/字节数/摘要可核验 |
| 附件已返回 | 调用方通过其支持的附件 API 或绝对本地路径预览输出 |
| 客户端已展示 | 针对所测客户端与版本的实际展示证据 |

`HTTP 200`、`b64_json`、`image_generation_call.result`、模型文字“已生成”和结束事件，都不能代替后面几项。代理服务器上的文件路径不能冒充用户电脑上的绝对路径。

## 2. 协议覆盖合同

| 协议 | 入口范围 | 工具链必须保留 | 媒体及流式重点 |
| --- | --- | --- | --- |
| OpenAI Responses | `/v1/responses`，以及内置的 `/responses`、compact/input_tokens、Codex 路由和已核对资源子路径；自定义路径可登记 | 工具定义、`function_call`、`call_id`、`function_call_output`、并行调用、状态/错误/usage、不透明 reasoning/工具字段 | output item、文本/工具参数增量、图片 partial/final、`image_generation_call.result`、响应终态 |
| OpenAI Chat | `/v1/chat/completions` 及已登记别名 | `tool_calls`、`tool_call_id`、arguments 增量、tool 消息、`finish_reason`、usage | JSON、SSE、多 choice、未知扩展字段、图片 URL/data URL 等提供者扩展 |
| Google Gemini | 已登记版本的 `/models/...:generateContent`、`:streamGenerateContent` | `functionCall`/`functionResponse`、ID、`thoughtSignature`、不透明 parts 和安全/结束元数据 | `inlineData`/`fileData`、文本与图片混合、`alt=sse`、多 candidate；新 Interactions 路由按能力另行登记 |
| Anthropic Messages | `/v1/messages`、已登记别名及 `count_tokens` 等辅助入口 | `tool_use`/`tool_result`、`tool_use_id`、thinking/signature、服务端工具结果、stop reason | `content_block_*`、`input_json_delta.partial_json`、message 终态、工具结果中的图片块 |
| Images/任务资源 | generations、edits、variations，以及上游声明支持的 async/task/batch/download | 请求字段和文件、任务 ID、状态、错误、原始返回字段 | multipart、JSON/Base64、URL、二进制、ZIP/JSONL 下载，分类型配置 |

Anthropic Messages 此处指其内容与工具协议，不据此声称它具有原生 Images 生成接口。提供者扩展产生的媒体也不能被强制解释为标准 OpenAI 字段。

Sub2API 基线同时登记 `/v1/responses` 与根 `/responses`、`/chat/completions`、图片 edits/generations、async/tasks/batches；仅识别 `/v1/*` 不足以覆盖真实部署。NewAPI 的协议适配、任务插件和结果转换已经在上游实现；CDN 不再叠加一轮隐式跨协议转换。

路径目录使用方法、规范化路径、参数化资源段、版本与可选部署前缀。不能把任意网页 `/messages` 或全部 `/v1/*` 自动认定为模型调用。2026-11-18 的[渠道覆盖核对](API-PROVIDER-COVERAGE-2026-11-18.zh-CN.md)已将 compact、计数、异步媒体、检索/取消等已确认路径纳入内置表；自定义路径继续由站点/受信上游显式登记，不用无限制后缀通配符猜测。

## 3. 默认 `raw` 模式

1. 应用层正文按字节完整传输，保留未知 JSON 字段、事件、工具类型、签名和错误。HTTP/1 chunk 与 HTTP/2 framing 可以变化，不将传输分块边界作为正文一致性的条件。
2. 不把工具参数碎片当成独立完整 JSON，不重新排序并行调用；UTF-8、JSON 转义和 SSE 事件可跨任意网络分块。未知事件继续转发，不能因为本地观测器不认识就丢弃。
3. 推理/生成入口统一采用无共享缓存、无请求缓冲、无响应缓冲、无压缩的 AI profile，保留长首包等待、取消传播、背压和禁止透明重试。异步状态查询及文件下载另有 profile，但私有状态同样不进入共享 CDN 缓存。
4. gzip、Brotli、Zstd 分别根据实际构建能力配置和测试。只设置 gzip 的运行字段不能宣称其他压缩过滤器也已停用；配置模板不能向未编译的 Nginx 填入未知模块指令。
5. 请求分类的 16/64 KiB 检查预算不是上传或图片响应大小上限。上传/响应/媒体解码限额分别定义，既不为识别而预读整个图片，也不为流式观测累积整个响应。
6. 取消只释放一次资源；已经开始传输响应或上游可能产生副作用后不重放请求。不把上游的 error/SSE error 改写成成功结束。

协议观测器可输出有界元数据和 capability，不能将 prompt、工具实参、图片 Base64、签名、Cookie、API Key 写入日志或高基数指标。观测解析预算用尽时停用观测并报告状态，原始合法响应继续转发；显式安全/大小策略独立执行。

## 4. 显式的媒体处理与 `raw + artifacts`

### 4.1 原始结果和处理结果的关系

普通兼容 API 始终返回上游协议。调用方可显式选择“保留 raw，同时生成 artifacts”，通过受保护的独立结果清单取得处理结果。不能在原 Responses/Chat/SSE 中混入本地文件路径、HTML、私有包装对象或“已生成”文字来代替协议。

媒体处理器运行在受限后台任务或调用方工具中，避免在 Nginx Worker 同步读取大文件、完整解码图片或同步下载外部 URL。客户端侧落盘工具能给出当前工作区的真实绝对路径；服务器侧处理器只提供已鉴权的资源标识/下载地址，不能提供可在用户本机预览的假路径。

### 4.2 输入适配

- Images：`data[].b64_json`、`data[].url`，支持多张和部分失败。
- Responses：完成 item 中的 `image_generation_call.result`；partial image 按 item ID/序号区分预览与最终结果，不能把进度事件或第一张 partial 当成最终成功。
- Chat：只处理当前受信提供者声明支持的 image/data URL/媒体扩展字段；未知扩展保留 raw，不能凭任意字符串猜测图片。
- Gemini：支持 `inlineData`/`inline_data` 的 MIME 与 Base64，以及登记的文件资源；文本、图片、工具内容可以交错。
- Anthropic：处理实际出现的图片内容块/工具结果块；不推测任意文本都是图片生成结果。
- 二进制：登记入口直接返回 `image/*`、文件或下载包时使用对应类型和完整性规则；不能统一按 JSON 解析。

Sub2API 已有按账户启用的 `images_url_to_b64_json` 非流式回填：只对缺失/空 b64 且有 URL 的项下载并回填，保留原 URL；其下载路径检查出站地址、大小及图片头部。该能力不等于完整图像解码或客户端附件展示，边缘也不应自动重复下载。NewAPI 已有任务 artifact 的受控存储和访问限制，可在明确的兼容合同下复用。

### 4.3 处理结果合同

处理清单至少包含 `artifact_id`、tenant/owner、原请求关联、protocol/item ID/index、状态、实际 MIME、字节数、实际宽高、SHA-256、创建/到期时间和受控读取方式。raw 的保存另行显式授权并设置期限，不默认长期保留含提示词与工具数据的完整响应。

解码使用严格 Base64/data URL 语法，分别限制编码字节、解码字节、像素、帧数、CPU/任务期限和并发；真实解码器完整读取后才提交文件。文件名由受信服务生成，先写临时文件再原子完成。原图保持原始字节；缩略图/转码产物具有独立 ID 和摘要。格式错误、截断、过大和下载失败分别报告，不返回假图片或空白成功。

只为明确登记、允许下载的提供者资源取外部 URL；每跳重定向和最终连接地址都验证，拒绝回环/私网/链路本地/metadata 目的地及 DNS rebinding。下载不携带用户对模型服务的 Authorization/Cookie 到第三方；请求来源、跨租户读取、文件权限、生命周期和清理均需测试。

### 4.4 Codex/客户端展示适配

沿用项目图片交付约定：实际保存 PNG/JPEG/WebP、用解码器完整校验，再返回图片附件和带绝对本地路径的 Markdown 预览。原生图片事件不被当前客户端消费时，使用明确的文件/附件适配工具；不要求 CDN 修改官方客户端内部渲染器。

客户端验收独立覆盖 Codex CLI 0.167.0 的已知限制及实际使用的 Desktop/SDK 版本。需要真实模型测试时沿用明确授权的凭据来源和 imagegen 执行方式；协议 fixture 不触发收费模型调用，也不伪造客户端身份绕过上游授权。

## 5. 验收与 PR 顺序

| PR | 交付 | 必须证明 |
| --- | --- | --- |
| API-1 | edits/variations 源码修复和已有传输回归正式纳入 | multipart 首段先到源站、多 MiB Base64 和二进制完整、无缓存/缓冲/压缩、普通 API 不回归 |
| API-2 | 按站点绑定的协议/端点目录及 raw 合同 | 四协议非流式、SSE、并行工具、工具结果再提交、签名/未知字段/未知事件、根别名、资源路径；字节/事件序列一致 |
| API-3 | 显式媒体提取/解码/落盘和原始+处理结果清单 | 多图、partial/final、所有来源类型、实际尺寸/MIME、完整读取、URL 安全、权限/配额/期限/失败状态 |
| API-4 | 客户端附件适配与端到端验收 | raw 收到、文件保存、解码成功、附件返回、实际展示分别有证据；报告所测客户端和版本 |

每次源码变更完成 Nginx 动态、OpenResty 动态和静态矩阵。原七模块共存、HTTP/2、多请求取消、Worker reload、慢上传/慢读、磁盘满、解码故障与内存峰值必须覆盖。性能比较以同硬件未启用观测、raw 观测、媒体处理三种状态测量，不预先承诺吞吐或延迟。

## 6. 本次核对的上游资料

- OpenAI Docs：[Responses](https://developers.openai.com/api/reference/resources/responses/methods/create)、[Chat](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create)、[图片生成](https://developers.openai.com/api/docs/guides/image-generation)。
- Google：[函数调用](https://ai.google.dev/gemini-api/docs/function-calling)、[图片](https://ai.google.dev/gemini-api/docs/image-generation)、[官方 v1beta 内容协议](https://github.com/googleapis/googleapis/blob/master/google/ai/generativelanguage/v1beta/content.proto)。本次文档入口已跳转到 AI Studio 的新文档；新 Interactions 示例不能代替既有 generateContent 合同。
- Anthropic：[定义工具](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools)、[Messages 流式事件](https://platform.claude.com/docs/en/build-with-claude/streaming)。
- Sub2API：[入口](https://github.com/Wei-Shaw/sub2api/blob/15871f904056f548dd874a1d069ffc6cdf777b78/backend/internal/server/routes/gateway.go)、[图片 URL/b64 回填](https://github.com/Wei-Shaw/sub2api/blob/15871f904056f548dd874a1d069ffc6cdf777b78/backend/internal/service/openai_images_b64_backfill.go)、[Responses 图片转换](https://github.com/Wei-Shaw/sub2api/blob/15871f904056f548dd874a1d069ffc6cdf777b78/backend/internal/service/openai_images_responses.go)。
- NewAPI：[relay 路由](https://github.com/QuantumNous/new-api/blob/669d774976369e986f03b6e24fff1042f6f94832/router/relay-router.go)、[任务产物存储](https://github.com/QuantumNous/new-api/blob/669d774976369e986f03b6e24fff1042f6f94832/setting/system_setting/task_artifact_store.go)。

本文件同时保留完整设计和当前实现边界。当前原生目录与媒体工具的离线/隔离验证见[记录](validation-api-protocol-media-20261117.json)；本次没有修改生产节点、调用真实厂商模型或宣称 CLI 工具已替客户端发出图片附件。
