# 验证记录入口

独立插件仓库的验证步骤、47 项检查范围、CI、ASan/UBSan 设置与未验证边界统一维护在 [docs/VALIDATION.zh-CN.md](../../docs/VALIDATION.zh-CN.md)。

源码导入前的验证来自原仓库提交 62fb619；47 项保留为 Config/Edge 的独立检查。当前仓库还包含 API、Purge 和原生 Sync，Sync 的 50 项角色/身份检查单独记录在 [native-sync 验证](../../native-sync/tests/VALIDATION.zh-CN.md)，不把不同组件或旧 Lua 协议测试混算为 Config/Edge 功能。

## 缓存 HTTP 头

新增 32 项 `cache_headers.py` 真实进程检查，验证规则回源头与原生响应诊断、站点/前缀继承、私有绕过、重复字段替换、非法输入、热更新和在途版本。与原 47 项路由/TLS 测试分别执行；三种构建和 CI 的最终状态见 [总验证记录](../../docs/VALIDATION.zh-CN.md)。
