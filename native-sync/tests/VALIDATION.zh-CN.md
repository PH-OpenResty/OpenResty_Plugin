# 原生 Sync 验证记录

## 0.2.0 缓存任务验证入口

新增 `cache_tasks.py` 在真实 Master/Node、临时 mTLS、原生 Purge、HTTP/HTTPS 缓存及临时源站之间验证任务全链路：落盘/重启、ACK 丢失后的收据重报、队列容量、节点/缓存 scope、租约耗尽、匹配清理、预热 HIT、无凭据默认表示、拒绝重定向/私有响应、并发创建和 Worker PID 保持。当前结果见 [总验证记录](../../docs/VALIDATION.zh-CN.md)。

此前 0.1.0 的迁入结果保留如下；0.2.0 已修改角色模块、头文件和 config，新增任务源码，不再与来源提交逐字节相同。

## 0.1.0 历史迁入验证

日期：2026-11-14。本仓库统一构建包含 Sync、Config、API、Edge、Purge 五个模块，Sync 的 config/核心 C/模块 C/头文件与来源提交 62fb619 保持一致。测试入口、动态/静态支持、启动就绪与诊断接入当前仓库。

| 本仓库场景 | 检查 |
| --- | --- |
| 独立 Sync，Nginx 动态 / OpenResty 动态 / OpenResty 静态 | 各 50 项 Master/Node、scope、本机 token、mTLS 与能力边界 |
| 所有五模块同实例启用 | `native-api/tests/integration.py --purge --sync`，含 49 项角色/独立凭据、代理、缓存与流式检查 |
| 原有 Config/Edge、API、Purge、模式和再验证 | 保留各自套件，不把角色测试混算成加密同步能力 |
| 纯 C 核心及当前摘要 | `check-core.sh` 与 `SOURCE-SHA256SUMS` |

结构化迁入结果见 [validation-sync-import-20261114.json](../../docs/validation-sync-import-20261114.json)；最终远端构建结果以当前提交的 CI 为准。CI 的 Nginx 动态运行时保持 ASan/UBSan，普通和静态 OpenResty 分别验证，所有证书与 token 都在临时目录产生。

`--static` 跳过 load_module，`--module` 仅用于单独动态产物；两个参数不能同时使用。启动时等待 Master 和 Node 各两个实际 Worker，并检查本次启动日志。测试失败打印有长度限制且移除控制 token 的诊断；报告只包含检查名称与数量。

## 迁入前历史基线

本地验证日期：2026-11-13。环境：隔离 WSL2/Alpine x86_64、GCC 14.2.0、OpenSSL 3.5.9、来自固定 OpenResty 1.31.8.1 归档的源码。两种运行时分别使用独立测试前缀，未覆盖现有安装。

| 项目 | 结果 |
| --- | --- |
| 纯 C 边界检查，`-Wall -Wextra -Werror -pedantic` | 通过 |
| 纯 C 检查，UBSan trap 模式 | 通过 |
| 独立 nginx 1.31.8 + 动态模块 | 编译、加载与 50 项角色/身份/接口检查通过 |
| 完整 OpenResty 1.31.8.1 + 动态模块 | 编译、加载与 50 项角色/身份/接口检查通过 |

真实进程检查使用独立 Master 与 Node，各两个 Worker；证书和 token 在临时目录生成，结束时停止进程并清理。检查覆盖默认关闭、错误角色、重复身份、scope 边界、token 文件权限/符号链接、content handler 冲突、只读控制接口、mTLS 登记与冒用拒绝、路径/方法/body 限制，以及能力未实现时不返回假成功。

本地 Alpine 工具链未提供 ASan 运行库，因此本地未宣称 ASan 通过。GitHub Actions 在 Ubuntu 上配置 AddressSanitizer 与 UndefinedBehaviorSanitizer 的核心检查，以及 nginx/OpenResty 两种构建；远程结果以对应提交的 Actions 记录为准。

历史迁入记录不证明配置快照加密分发、Node 拉取、应用事务或业务健康检查已经迁移，也不证明生产容量、ARM64、HTTP/3 或所有目标 OpenResty 构建的 ABI 兼容。部署产物需按目标构建重新生成。
