# 公开发布规则

只提交源码、测试、通用模板和文档。真实站点、客户/租户数据、非公开节点清单、源站地址、凭据、证书材料、运行状态、日志、备份与编译二进制不进入 Git。

`native-config/examples/sites.conf` 是公开示例；实际输入文件应放在部署目录。测试在临时目录中生成 CA、证书和私钥，退出时清理。不要把生成的材料或测试运行目录复制进仓库。

提交前检查实际 Git 索引：

```sh
git diff --cached --check
python tools/check-publication.py --staged
gitleaks dir --redact .
gitleaks git --redact --log-opts=--all .
```

默认发布脚本检查已跟踪工作树文件，`--staged` 检查索引中的实际内容。检查只输出文件、行号和规则，不打印匹配的值。`.gitignore` 不会删除已经跟踪的数据，也无法阻止强制添加；新增文件仍需人工确认域名、地址、路径与业务内容。

新提交使用 GitHub noreply 邮箱可避免新增个人邮箱。已有历史作者元数据由原仓库保留，源码扫描不会重写历史。已公开的凭据需要按实际情况撤销，删除文件不能使凭据重新安全。
