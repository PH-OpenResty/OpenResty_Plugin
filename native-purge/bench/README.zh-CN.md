# 缓存清理模块的性能对照

性能测试必须使用未启用 sanitizer 的优化构建。测试在同一运行时比较普通原生缓存 HIT、版本键 HIT，以及后台持续提交无关站点清理时的版本键 HIT；这不是不同主机或不同缓存命中率的对比。

```sh
SCDN_NATIVE_CFLAGS='-O2 -Werror' sh tools/build-runtime.sh /tmp/scdn-purge-bench openresty
# Install wrk using the test system's package manager before running.
python native-purge/bench/run.py --prefix /tmp/scdn-purge-bench \
  --body-bytes 128 --connections 128 --threads 2 --seconds 5 --runs 3 \
  --output /tmp/scdn-purge-small.json
python native-purge/bench/run.py --prefix /tmp/scdn-purge-bench \
  --body-bytes 16384 --connections 128 --threads 2 --seconds 5 --runs 3 \
  --output /tmp/scdn-purge-large.json
```

脚本拒绝运行在包含 `-fsanitize` 的运行时上。两个路径都使用原生 proxy_cache，预热相同长度的响应；区别是是否解析版本键。脚本还等待 Nginx 约 60 秒后启动的 cache loader 完成，避免 cold 标记额外锁混入稳态。每轮交替普通/版本键测试顺序，记录全部原始 QPS、p99 和 Nginx Worker CPU 时间，再对三轮取中位数。

第三种场景以目标每秒 20 次提交无关 scope 的精确失效，实际提交数量及失败数量也保存在结果中。清理不会使被测资源失效，所以它测量元数据与持久化竞争，而不是借缓存 MISS 改变结果。另测 16 个管理客户端同时提交 48 个请求，批量分别为 1、32、256，并报告请求/键吞吐和延迟；每次成功都包含 fsync。

服务端 CPU 使用 `/proc` 中 Worker 线程组的 CPU tick 差除以实际完成请求数，受 tick 精度影响。请求客户端与服务端在同一台 WSL/Linux 主机共享 CPU，回环网络、文件系统、调度和其他负载都可能造成数个百分点的变化。吞吐超过基线也不能据此认定模块“负开销”或更快。

当前场景是 HTTP/1.1 keepalive、两个 Worker、128 个并发连接、一个热键；不证明 TLS、HTTP/2/3、高基数键、最坏前缀数量、磁盘故障、百万连接或公网生产容量。实际缓存工作集超出本地解析缓存、频繁清理和大量前缀时，需要另外测量慢路径。

## 本次 OpenResty 测量

2026-11-14，隔离 WSL2/Alpine x86_64、GCC 14.2.0、OpenSSL 3.5.9、OpenResty 1.31.8.1，优化构建 `-O2 -Werror`，未启用 sanitizer。两个 Worker、wrk 两个客户端线程、128 个连接，每场景 5 秒、3 轮；两次运行都等待 cache loader 退出约 60.08 秒后开始。以下均为各轮中位数：

| 响应长度 | 场景 | QPS | p99 | Worker CPU/请求 |
| --- | --- | ---: | ---: | ---: |
| 131B | 普通缓存 HIT | 22,620 | 9.64ms | 87.48μs |
| 131B | 版本键 HIT | 22,173 | 10.91ms | 89.35μs |
| 131B | 版本键 HIT + 持续清理其他 scope | 21,970 | 10.40ms | 90.78μs |
| 16,387B | 普通缓存 HIT | 22,170 | 10.46ms | 88.83μs |
| 16,387B | 版本键 HIT | 21,197 | 10.48ms | 92.28μs |
| 16,387B | 版本键 HIT + 持续清理其他 scope | 19,174 | 13.86ms | 103.17μs |

版本键吞吐分别约为基线的 98.02% 和 95.61%，CPU 中位数增加约 2.14% 和 3.88%。持续清理场景在这台共享 CPU/存储的测试机上吞吐分别下降约 2.9% 和 13.5%，因此不能宣称后台清理对业务完全无影响。数据存在轮次波动，结果只代表当前工作集和环境。

两个大小的后台清理场景分别完成 303 和 305 次提交，失败数均为 0；这是三轮累计，目标每秒 20 次。管理吞吐测量为 16 个客户端、48 个请求、逐批持久 fsync：

| 每批键数 | 131B 测试后的规则提交吞吐 | 16KiB 测试后的规则提交吞吐 |
| --- | ---: | ---: |
| 1 | 199 键规则/s | 188 键规则/s |
| 32 | 6,263 键规则/s | 6,233 键规则/s |
| 256 | 43,942 键规则/s | 46,856 键规则/s |

这些管理键没有逐个预填缓存，测量的是持久化失效规则提交，不是删除文件数，也不是保证同样数量的对象曾经存在。持久性和文件系统决定吞吐上限；批量将 fsync 和连接成本摊到更多目标。

完整原始数据：[131B](results-openresty-131.json)、[16KiB](results-openresty-16k.json)。所有轮次均保留，不能只挑最佳值。不要将当前对照或源码中的低开销设计等同于所有负载下的绝对最低开销。
