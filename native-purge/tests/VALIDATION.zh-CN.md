# 原生缓存失效模块验证

日期：2026-11-14。模块作用是精确的内容失效；磁盘回收仍由 Nginx cache manager 负责。实测使用临时日志、token、cache zone、本地源站、两个真实 Worker 和 Unix 控制 Socket，没有修改生产服务。

## 功能与恢复

真实进程检查覆盖：

- 精确键、查询串、百分号编码、最大键长、独立资源/配置版本，以及构造的 CRC32 索引碰撞。
- 同基础键在 l1/l2、不同 scope 的隔离；同资源所有 Vary 变体失效。
- 批量同一次提交、前缀边界、整站及显式全局模式；前缀和元数据容量限制。
- 在途旧回源返回旧响应，但不能污染清理后的新请求；多轮并发 post-ack 请求检查。
- 日志重放、graceful reload、半写尾部、检查点、完整记录损坏、在线旧日志恢复拒绝，以及日志不可用时不确认清理。
- 注入持续 fsync 失败，验证失败不确认、可见但未持久的完整尾部不提前发布，存储恢复后继续提交。
- 定点 SIGKILL 正在共享索引临界区复制键的 Worker，验证数据请求和后续清理失败关闭，整实例重启后从日志重建。
- 单 master 所有权、本机与 token 边界、请求大小/类型/方法、客户端断开时任务生命周期。
- 失败批次预留撤销、整站/全局覆盖元数据回收，旧文件保持由原生 cache manager 管理。

当前包含 70 项 Purge 检查；本地 Nginx 严格编译与 UBSan trap 已通过，完整 OpenResty 也完成真实进程验证。CI 在两种运行时执行 Purge 与原 47 项 Config/Edge 回归；Nginx 分支对完整运行时和模块启用 ASan/UBSan，最终结果以对应提交的 Actions 记录为准。

## 复现

```sh
sh tools/build-runtime.sh /tmp/scdn-purge-validation nginx
python native-purge/tests/integration.py --prefix /tmp/scdn-purge-validation \
  --report /tmp/scdn-purge-validation-results.json
```

也可选择 openresty 并使用新前缀。测试需要 C 编译器，会在临时目录构建仅用于 fsync 故障注入的 LD_PRELOAD 辅助库；性能脚本显式关闭此辅助库。所有报告只包含检查名称和数量；私有日志、token 和缓存对象不上传为 artifact。ASan 对 Nginx 自动生成的三个模块注册表采用仓库既有的 ODR 排除规则，其余内存检查仍有效。

## 性能验证

见 [基准方法与结果](../bench/README.zh-CN.md)。测量使用优化构建、普通缓存基线、实际缓存 HIT 和每批 fsync，不以关闭持久化或改变缓存命中率获取表面优势。管理批量指标统计提交的失效规则，不表示删除同样数量的磁盘文件。

## 0.2.0 扩展验收

先核对 [源站校验与 stale 调研](../../docs/CACHE-REVALIDATION-RESEARCH.zh-CN.md)，再扩展实现。两个 Worker 的 Nginx 1.31.8 和完整 OpenResty 1.31.8.1 均运行新增真实进程测试；最终提交还由 CI 重建并执行，Nginx CI 包含完整 ASan/UBSan。

- [patterns.py](patterns.py)：64 项，覆盖 glob/转义、PCRE2 锚定与查询串、后缀、目录边界与重复斜杠、站点隔离、批次语法拒绝、共享模式容量、失败关闭、检查点、重启及跨 cache zone 的 node 清理。
- [revalidate.py](revalidate.py)：45 项，覆盖 ETag/Last-Modified/完整 GET、相同 Last-Modified 下的等长正文变化、304 连续续期及缺失新鲜度头、长 Cache-Control/X-Accel-Expires 上限、HEAD/Vary、后台并发合并、失败重试、有限 stale、显式清理隔离、301/403/404/410/private/Set-Cookie、部分正文、分段响应头、无重启更新、状态指标和配置校验。
- 源站返回不可缓存的 304 时，临时移走测试 journal，确认失效提交失败也不会把旧长 TTL 再次续期，恢复 journal 后可重新提交失效。
- 原有 70 项 Purge 和 47 项 Config/Edge 回归继续保留；导入的八个 Config/Edge 实现文件 SHA-256 不变。

```sh
python native-purge/tests/patterns.py --prefix /tmp/scdn-purge-validation
python native-purge/tests/revalidate.py --prefix /tmp/scdn-purge-validation
```

新增功能共 109 项，加原有回归后每种运行时共 226 项。报告只包含检查名称，不发布测试源站、token、journal 或实际缓存文件。有限后台宽限期结束后的同步并发、锁超时、高基数抑制表冲突不被描述为严格单次回源保证；需要在目标流量下另外压测。

## 未覆盖的范围

真实掉电/存储损坏的全部模式、不同文件系统的 fsync 保证、超大工作集、长时间压力、ARM64、所有非 root/systemd 组合、TLS/HTTP2/HTTP3、slice/range/其他子请求组合、其他缓存后端和跨节点清理均需按目标环境另行验证。本模块启用的 proxy_cache background_update 已覆盖；不能扩展为任意第三方后台请求组合保证。CRC 用于检测记录损坏，不是防止有权改写私有文件的攻击者。
