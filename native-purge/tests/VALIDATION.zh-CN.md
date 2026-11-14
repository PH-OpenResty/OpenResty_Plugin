# 原生缓存失效模块验证

日期：2026-11-14。模块作用是精确的内容失效；磁盘回收仍由 Nginx cache manager 负责。实测使用临时日志、token、cache zone、本地源站、两个真实 Worker 和 Unix 控制 Socket，没有修改生产服务。

## 功能与恢复

真实进程检查覆盖：

- 精确键、查询串、百分号编码、最大键长、独立资源/配置版本，以及构造的 CRC32 索引碰撞。
- 同基础键在 l1/l2、不同 scope 的隔离；同资源所有 Vary 变体失效。
- 批量同一次提交、前缀边界、整站及显式全局模式；前缀和元数据容量限制。
- 在途旧回源返回旧响应，但不能污染清理后的新请求；多轮并发 post-ack 请求检查。
- 日志重放、graceful reload、半写尾部、检查点、完整记录损坏、在线旧日志恢复拒绝，以及日志不可用时不确认清理。
- 单 master 所有权、本机与 token 边界、请求大小/类型/方法、客户端断开时任务生命周期。
- 失败批次预留撤销、整站/全局覆盖元数据回收，旧文件保持由原生 cache manager 管理。

本地 Nginx 严格编译与 UBSan trap 已通过，完整 OpenResty 也完成真实进程验证。此前发布代码的 CI 在 Nginx、OpenResty 两种运行时各通过 63 项 Purge 检查与 47 项 Config/Edge 回归；当前新增日志不可用场景，共 64 项。Nginx 分支对完整运行时和模块启用 ASan/UBSan，最终提交结果以 Actions 记录为准。

## 复现

```sh
sh tools/build-runtime.sh /tmp/scdn-purge-validation nginx
python native-purge/tests/integration.py --prefix /tmp/scdn-purge-validation \
  --report /tmp/scdn-purge-validation-results.json
```

也可选择 openresty 并使用新前缀。所有报告只包含检查名称和数量；私有日志、token 和缓存对象不上传为 artifact。ASan 对 Nginx 自动生成的三个模块注册表采用仓库既有的 ODR 排除规则，其余内存检查仍有效。

## 性能验证

见 [基准方法与结果](../bench/README.zh-CN.md)。测量使用优化构建、普通缓存基线、实际缓存 HIT 和每批 fsync，不以关闭持久化或改变缓存命中率获取表面优势。管理批量指标统计提交的失效规则，不表示删除同样数量的磁盘文件。

## 未覆盖的范围

真实掉电/存储损坏的全部模式、不同文件系统的 fsync 保证、超大工作集、长时间压力、ARM64、所有非 root/systemd 组合、TLS/HTTP2/HTTP3、slice/range/background_update、其他缓存后端和跨节点清理均需按目标环境另行验证。CRC 用于检测记录损坏，不是防止有权改写私有文件的攻击者。
