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

脚本拒绝运行在包含 `-fsanitize` 的运行时上。两个路径都使用原生 proxy_cache，预热相同长度的响应；区别是是否解析版本键。每轮交替普通/版本键测试顺序，记录全部原始 QPS、p99 和 Nginx Worker CPU 时间，再对三轮取中位数。

第三种场景以目标每秒 20 次提交无关 scope 的精确失效，实际提交数量及失败数量也保存在结果中。清理不会使被测资源失效，所以它测量元数据与持久化竞争，而不是借缓存 MISS 改变结果。另测 16 个管理客户端同时提交 48 个请求，批量分别为 1、32、256，并报告请求/键吞吐和延迟；每次成功都包含 fsync。

服务端 CPU 使用 `/proc` 中 Worker 线程组的 CPU tick 差除以实际完成请求数，受 tick 精度影响。请求客户端与服务端在同一台 WSL/Linux 主机共享 CPU，回环网络、文件系统、调度和其他负载都可能造成数个百分点的变化。吞吐超过基线也不能据此认定模块“负开销”或更快。

当前场景是 HTTP/1.1 keepalive、两个 Worker、128 个并发连接、一个热键；不证明 TLS、HTTP/2/3、高基数键、最坏前缀数量、磁盘故障、百万连接或公网生产容量。实际缓存工作集超出本地解析缓存、频繁清理和大量前缀时，需要另外测量慢路径。

测量结果和适用范围在发布验证时补充。不要将源码中的低开销设计直接等同于所有负载下的绝对最低开销。
