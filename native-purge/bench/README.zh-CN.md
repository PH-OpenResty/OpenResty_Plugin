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

## 0.1.0 原有失效路径测量

2026-11-14，隔离 WSL2/Alpine x86_64、GCC 14.2.0、OpenSSL 3.5.9、OpenResty 1.31.8.1，优化构建 `-O2 -Werror`，未启用 sanitizer 和故障辅助库。最终构建包含共享临界区故障保护。两个 Worker、wrk 两个客户端线程、128 个连接，每场景 5 秒、3 轮；两次运行都等待 cache loader 退出约 60 秒后开始。以下均为各轮中位数：

| 响应长度 | 场景 | QPS | p99 | Worker CPU/请求 |
| --- | --- | ---: | ---: | ---: |
| 131B | 普通缓存 HIT | 22,112 | 9.89ms | 89.74μs |
| 131B | 版本键 HIT | 20,686 | 13.22ms | 95.94μs |
| 131B | 版本键 HIT + 持续清理其他 scope | 20,100 | 11.94ms | 98.89μs |
| 16,387B | 普通缓存 HIT | 21,609 | 11.05ms | 91.40μs |
| 16,387B | 版本键 HIT | 20,510 | 10.16ms | 96.42μs |
| 16,387B | 版本键 HIT + 持续清理其他 scope | 18,841 | 13.41ms | 105.58μs |

版本键吞吐分别约为基线的 93.55% 和 94.91%，CPU 中位数增加约 6.92% 和 5.50%。持续清理场景在这台共享 CPU/存储的测试机上吞吐分别下降约 9.1% 和 12.8%，因此不能宣称后台清理对业务完全无影响。轮次波动明显，不能把全部差异都归因于模块；结果只代表当前工作集和环境，不构成“最低开销”的证明。

两个大小的后台清理场景分别完成 303 和 305 次提交，失败数均为 0；这是三轮累计，目标每秒 20 次。管理吞吐测量为 16 个客户端、48 个请求、逐批持久 fsync：

| 每批键数 | 131B 测试后的规则提交吞吐 | 16KiB 测试后的规则提交吞吐 |
| --- | ---: | ---: |
| 1 | 198 键规则/s | 182 键规则/s |
| 32 | 6,292 键规则/s | 6,089 键规则/s |
| 256 | 46,353 键规则/s | 45,382 键规则/s |

这些管理键没有逐个预填缓存，测量的是持久化失效规则提交，不是删除文件数，也不是保证同样数量的对象曾经存在。持久性和文件系统决定吞吐上限；批量将 fsync 和连接成本摊到更多目标。

完整原始数据：[131B](results-openresty-131.json)、[16KiB](results-openresty-16k.json)。所有轮次均保留，不能只挑最佳值。不要将当前对照或源码中的低开销设计等同于所有负载下的绝对最低开销。

## 0.2.0 源站条件校验对照

新增 [origin.py](origin.py)，在同一个完整 OpenResty 1.31.8.1 运行时比较原生 HIT、仅版本键 HIT，以及版本键加每 2 秒条件校验的 HIT。响应正文均为 131B，两个 Worker、128 个连接、wrk 两个线程，每场景 5 秒、3 轮，未启用 sanitizer/故障注入。先等待 cache loader 退出，每轮每项开始前还等待资源处于 fresh 状态，避免把闲置超过后台窗口后的首波同步校验混入稳态。

```sh
python native-purge/bench/origin.py --prefix /tmp/scdn-purge-bench \
  --body-bytes 128 --connections 128 --seconds 5 --runs 3 \
  --output /tmp/scdn-origin-benchmark.json
```

2026-11-14，隔离 WSL2/Alpine x86_64 环境，测量实现提交 `8eaceac`，三轮中位数（后续修正了空 ETag/撤回响应边界，此表不作为后续提交的重新测量）：

| 场景 | QPS | p99 | Worker CPU/请求 |
| --- | ---: | ---: | ---: |
| 原生缓存 HIT | 20,152 | 15.01ms | 98.11μs |
| 版本键 HIT | 19,071 | 14.10ms | 103.77μs |
| 版本键 + 周期条件 GET | 19,419 | 11.98ms | 100.82μs |

每个再校验场景都实际产生携带 ETag 的条件 GET 和 304，不是只配置开关后测一个永远不校验的 HIT。再校验场景相对原生 HIT 的吞吐约为 96.4%；其相对仅版本键的表面提升属于本机波动，不能据此声称自动校验是负开销。单轮原生 QPS 约 1.67 万～2.11 万，调度噪声明显；该数据不能精确分离再校验的增量开销，更不能证明所有工作集的最低开销。

保留全部轮次及条件请求数量：[原始 JSON](results-origin-openresty.json)。本次未测复杂 regex/高基数匹配、跨实例和宽限期结束后的闲置并发突发；这些情形不能从单热键稳态结果推导。后者可能有多个同步回源，需要按目标业务选择可接受的后台窗口和原生回源并发配置。
