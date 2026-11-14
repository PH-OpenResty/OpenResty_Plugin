# 安装、构建和首次运行

统一构建现在生成 Config、Edge、Purge 三个插件；Edge 通过 Config 的 C 接口读取活动版本，二者需同版本编译并按顺序加载。Purge 独立使用，私有日志和 token 的初始化见 [专门手册](../native-purge/README.zh-CN.md)。插件运行时不需要 Lua、Python、独立 Agent 或生成配置的脚本。Python 仅用于测试。

## 1. 构建要求

已验证 Linux x86_64、GCC、OpenSSL 3、Nginx 1.31.8 和 OpenResty 1.31.8.1。源代码使用 Linux 文件描述符、`openat`、`O_NOFOLLOW`、`/proc` 测试辅助和 Nginx 线程池；没有把 Windows、ARM64 或其他系统描述为已验收。

Debian/Ubuntu 构建依赖：

```sh
sudo apt-get update
sudo apt-get install -y build-essential perl libpcre2-dev libssl-dev zlib1g-dev curl \
  python3 python3-venv
```

Alpine 的对应构建包为 `build-base perl pcre2-dev openssl-dev zlib-dev curl`，测试还需 Python 和 `cryptography`。本地不具备 ASan 库时可运行普通构建；远程 CI 在 Ubuntu 上进行 ASan/UBSan 验证，不能据此声称本地也完成同样的检查。

## 2. 用固定测试运行时独立构建

在源码根目录执行：

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r tests/requirements.txt

sh tools/build-runtime.sh /tmp/scdn-plugin-nginx nginx
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-nginx \
  --report /tmp/scdn-plugin-nginx-results.json

sh tools/build-runtime.sh /tmp/scdn-plugin-openresty openresty
python native-edge/tests/integration.py --prefix /tmp/scdn-plugin-openresty \
  --report /tmp/scdn-plugin-openresty-results.json
```

构建脚本从 OpenResty 官方地址下载固定归档并校验 SHA-256。`nginx` 模式仅解包其中的 Nginx 核心，不编入 Lua；`openresty` 模式构建完整 OpenResty。两种模式都启用 `--with-compat --with-http_ssl_module --with-http_v2_module --with-pcre-jit --with-threads`，并将这两个插件作为动态模块构建。

| 模式 | Nginx 可执行文件 | 两个 `.so` 的目录 |
| --- | --- | --- |
| nginx | `/tmp/scdn-plugin-nginx/sbin/nginx` | `/tmp/scdn-plugin-nginx/modules/` |
| openresty | `/tmp/scdn-plugin-openresty/nginx/sbin/nginx` | `/tmp/scdn-plugin-openresty/nginx/modules/` |

前缀必须是绝对路径，脚本拒绝覆盖已有 Nginx 可执行文件。需要重建时选用新前缀。临时构建源码会清理，选定安装前缀会保留。上述 `/tmp` 前缀用于验证，不应直接当作长期部署位置。

构建环境变量：

| 变量 | 默认 | 用途 |
| --- | --- | --- |
| `SCDN_NATIVE_BUILD_JOBS` | `2` | make 并行任务数 |
| `SCDN_NATIVE_CFLAGS` | `-Werror` | 附加编译选项 |
| `SCDN_NATIVE_LDFLAGS` | 空 | 附加链接选项 |

内存检查的准确选项和 Nginx 注册表排除见 [验证记录](VALIDATION.zh-CN.md)。不要将启用了 sanitizer 的测试构建作为性能基线。

## 3. 接入已有 Nginx/OpenResty

先保存现有二进制、模块、配置、站点源文件及证书，并确认可恢复的版本。通过目标二进制的 `-V` 核对 Nginx/OpenResty 版本、补丁、构建选项、TLS 库和架构。

使用目标的匹配源码和原构建参数构建两个动态模块，增加 `--with-threads` 和 HTTP SSL 支持，并分别指定本仓库的 `native-config`、`native-edge` 目录。原有模块、路径和编译参数需保留。`--with-compat` 不等于跨任意版本或构建的通用 ABI；如果目标二进制没有需要的功能，需按其原安装流程升级运行时，不能只复制 `.so`。

确认兼容后将两个 `.so` 安装到目标模块目录，在主配置最前面依次加入：

```nginx
load_module modules/ngx_http_scdn_config_module.so;
load_module modules/ngx_http_scdn_edge_module.so;
```

相对 `modules/` 路径按 Nginx 的运行前缀解析；系统发行包的模块目录可能不同，可以改用绝对路径。出现 `module is not binary compatible`、`module version ... instead of ...` 时重新按目标构建，不应忽略检查。配置/模块程序更新仍遵循 Nginx 的重载或重启流程；只有站点数据在加载后支持无 Worker 重建更新。

## 4. 创建数据目录与服务账户

[完整示例](../native-edge/examples/nginx.conf)使用 `scdn` Worker 账户。以下是 Debian/Ubuntu 新部署的示例；已有服务应使用其实际账户并调整 `user` 指令：

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin scdn
sudo install -d -o root -g scdn -m 0750 /etc/scdn /etc/scdn/certificates
sudo install -d -o scdn -g scdn -m 0750 \
  /run/scdn-edge /var/cache/scdn/l1 /var/cache/scdn/l2
sudo install -o root -g scdn -m 0640 \
  native-config/examples/sites.conf /etc/scdn/sites.conf
sudo install -o root -g root -m 0644 \
  native-edge/examples/nginx.conf /etc/scdn/nginx.conf
```

如果账户已存在，不重复创建。使用非 root 启动 Nginx 时，按启动者权限配置目录、端口和配置中的 `user` 行。`/run` 可能随重启清空，需由现有 service、tmpfiles 或等效机制重建目录。

启动进程和 Worker 都需要能遍历源文件及证书的所有父目录；Worker 在后台线程里读取文件，不能只让 root master 可读。私钥可以是 root 所有、scdn 组可读的 0640 文件，并放在受限父目录中。源文件、证书、静态 root 的读取不接受路径中的符号链接；选择真实目录，不能直接指向 ACME 的 symlink 布局。

## 5. 首次运行 HTTP 示例

公开站点模板默认停用。将源文件中的 demo 改为 `enabled on`，回源指向自己的测试服务；示例 `http://127.0.0.1:8080` 需要该端口已有源站。也可将站点改为静态模式，填写实际存在的 `root` 并移除 `upstream`。

示例 Nginx 监听 80；隔离测试时可改为 `listen 127.0.0.1:8081 default_server`，确认端口未占用。使用选定的目标二进制进行检查和启动，例如测试前缀：

```sh
sudo /tmp/scdn-plugin-nginx/sbin/nginx -t \
  -p /tmp/scdn-plugin-nginx/ -c /etc/scdn/nginx.conf
sudo /tmp/scdn-plugin-nginx/sbin/nginx \
  -p /tmp/scdn-plugin-nginx/ -c /etc/scdn/nginx.conf

# If using the isolated HTTP port above:
curl -H 'Host: www.example.com' http://127.0.0.1:8081/
sudo curl --unix-socket /run/scdn-edge/control.sock http://localhost/status
sudo curl --unix-socket /run/scdn-edge/control.sock http://localhost/metrics
```

停止该测试实例时必须使用相同前缀和配置路径：

```sh
sudo /tmp/scdn-plugin-nginx/sbin/nginx \
  -p /tmp/scdn-plugin-nginx/ -c /etc/scdn/nginx.conf -s quit
```

## 6. 启用 TLS

为 Nginx 提供有效的本机 bootstrap 证书/私钥后，启用示例中的 `listen ... ssl` 和 `scdn_edge_tls on`。在站点数据中填写 `certificate`、`certificate_key`；证书需匹配该站点全部 Host 的 DNS SAN。

bootstrap 用于让 Nginx 建立 TLS 上下文，实际新握手由模块选择已准备的站点证书。没有 SNI、未知 SNI、停用站点或无有效 TLS 材料时拒绝握手。该回调与 Lua 证书回调、变量证书选择不能混用；保持示例关闭 session cache/tickets，直到自行验收恢复和撤销策略。

证书签发、续期与 CA 信任部署由外部系统完成。如何发布配对文件、观察切换及回退见 [操作手册](OPERATIONS.zh-CN.md)。
