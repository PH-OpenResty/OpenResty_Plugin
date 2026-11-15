# IP 封禁与 eBPF 联动：详细设计 v1

状态：**设计草案**，尚无可加载的 Ban 模块、Agent 或 BPF 执行程序。此目录提供实现契约，不加入当前四个模块的构建或加载流程。

已确认：客户端直连节点；业务范围是 Web 与负载均衡入口；确认 CC 直接申请 L3；WAF 确认拦截先 L7，频繁时升级 L3；时长固定配置；保留指定文件中的封禁事件与 IP 历史。

设计确定为 C 的 HTTP 模块、本机单写 Agent、XDP/TCX 入站执行程序。Nginx stream 的纯 TCP/UDP 入口由薄适配执行应用侧兜底。WAF/CC 判定器通过受信事件接入；业务状态码或 API/AI 类型标签不直接产生封禁。

| 设计材料 | 内容 |
| --- | --- |
| [研究背景](design/RESEARCH.zh-CN.md) | XDP/TC、计数、日志与源站直连的依据；具体 v1 取舍以详细设计为准 |
| [详细设计](design/DESIGN.zh-CN.md) | 状态、固定期限、共享视图、进程协议、内核执行、日志事务与恢复 |
| [策略 Schema](design/policy.schema.json) | 严格字段、数值和类型边界，基于 JSON Schema 2020-12 |
| [策略示例](examples/ban-policy.toml.example) | 独立 TOML 文件草案，只使用保留地址和示意参数 |
| [IPC ABI](design/scdn_ban_wire.h) | 64 字节帧头、272 字节安全事件、确认及视图交换 |
| [Map ABI](design/scdn_ban_map.h) | IPv4/IPv6 键、32 字节封禁值、服务元组和计数 |
| [只读视图 ABI](design/scdn_ban_view.h) | Agent 单写、所有 Worker 共用的固定布局与原子双缓冲记录 |
| [验收矩阵](design/ACCEPTANCE.zh-CN.md) | 后续必须实现的功能、协议、恢复与性能用例 |
| [事件日志示例](examples/ban-events.jsonl.example)与[IP 台账示例](examples/ban-ips.jsonl.example) | 合成记录，展示封禁、升级、固定到期及 64 位字符串字段 |

普通请求只读本机内存视图；控制事件才通过非阻塞 Unix Socket 交给 Agent。Agent 先持久化意图再发布正式封禁；XDP 自行判断 BOOTTIME 到期，流量命中不延长 TTL。L7 的站点级封禁与 L3 的节点业务入口作用域分开记录。

原生 Sync 当前在 [OpenResty_Lua PR #1](https://github.com/PH-OpenResty/OpenResty_Lua/pull/1)，仍是角色/身份基础。Ban v1 在节点本地工作，不以尚未完成原生化的加密发布/拉取能力为前提；动态封禁与日志也不默认跨节点同步。

## 设计校验

在隔离 WSL2/Linux 上完成：三个头文件的 C11 严格编译与静态布局断言、Schema 结构、TOML/字段语义、日志投影关联和固定期限示例校验。示例只读视图精确计算为 73,400,576 字节。UID 隔离原型验证 Worker 无法写入/重开可写映射，替代 Agent 可重新打开同一 tmpfs inode 并让旧读者看到更新；memfd 的 FUTURE_WRITE 限制也单独核对过。它们不构成运行模块或真实内核丢包验收。

协议布局可直接复现：

```sh
cc -std=c11 -Wall -Wextra -Werror -I native-ban/design -x c -fsyntax-only - <<'C'
#include "scdn_ban_wire.h"
#include "scdn_ban_map.h"
#include "scdn_ban_view.h"
int main(void) { return 0; }
C
```

策略是 TOML 解码后的 JSON Schema 2020-12。可在独立 Python 环境安装 `jsonschema==4.25.1`，用 `Draft202012Validator.check_schema` 和带 `FormatChecker` 的 validator 校验示例；CIDR、文件别名、内存及 UID 等跨字段/运行环境约束仍按详细设计单独检查。
