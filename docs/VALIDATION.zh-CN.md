# 验证记录与复现

日期：2026-11-14。这份记录区分导入前已有结果和新仓库的独立验证；远程 CI 结果以当前提交的 Actions 记录为准。

## 已有实现基线

导入的实现来自原仓库提交 62fb619。该版本已验证：无 Lua 的 Nginx 1.31.8 和完整 OpenResty 1.31.8.1，各 47 项真实 Config/Edge 检查通过。原生源文件摘要保存在 [SOURCE-SHA256SUMS](../SOURCE-SHA256SUMS)；本次独立整理没有修改 `.c`、`.h` 或模块 `config` 实现。

原仓库同时验证的 Sync 角色和 Lua 协议测试不属于这两个插件的新仓库测试数量，不作为本仓库具备远程同步的证据。

## 本次独立仓库验证

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

## 文档与发布验证

独立发布前检查模块摘要、相对文档链接、示例所需文件、脚本语法、实际待提交文件和凭据扫描。源码仅包含通用模板，实际运行配置和二进制不进入 Git。新仓库 Actions 分别执行源码摘要核对、两种运行时的 47 项测试及公开内容检查。

## 未验证范围

当前不证明生产吞吐/容量上限、长时间压力与磁盘故障、ARM64、所有非 root/systemd 组合、HTTP/2/HTTP/3 全部行为、会话恢复/撤销政策或任意目标构建的 ABI。ready 不是业务健康结果，插件也没有实现远程 Master→Node 协议或完整高可用控制面。
