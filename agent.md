# 后续 Agent 开发指南

本文件是面向后续代码 Agent 的项目约定。开始工作前同时阅读 [project.md](project.md)、[progress.md](progress.md)、[README.md](README.md) 和当前任务对应的 `docs/` 文档。

## 开始任务前

1. 查看 `git status --short`、当前分支、`VERSION` 和最近提交；识别已有修改及未跟踪文件。
2. 先定位当前实现和测试，再修改最小的所有者模块。Server API、前端类型/调用、Client 行为和部署脚本若共享一个契约，要一起核对。
3. 把用户提供的日志、主机报告和 GitHub 状态当作证据；不要将过期采样、缺失字段或历史记录当成当前事实。

## 修改与兼容性

- Server 逻辑放在 `server/`，节点采集和动作放在 `client/`，UI 放在 `frontend/src/`，安装/更新放在 `scripts/`。避免把业务逻辑塞进大入口文件。
- API 变更需检查 `frontend/src/api/` 的请求和类型，以及旧版 Client 的兼容性。Server-first 托管升级和签名/版本门禁不可绕过。
- 对安全检测、隔离、限速和自动处置采用证据优先、失败保留未知的实现。校验精确节点/容器身份、证据时效、规则归属和执行后的读回；不因通知成功或任务已排队就显示处置完成。
- 不把 CPU、连接数、外部攻击或网络保护信号单独当作客户违规证据。遵循对应安全设计文档中的范围、保留和恢复边界。
- `VERSION` 是 Server/Client 的统一版本源。对 `client/`、`server/` 或 `scripts/` 的运行时/部署改动，按 `.github/workflows/build-and-push-ghcr.yml` 更新版本；仅文档变更不需版本递增。
- 前端源码构建输出到 `server/static/`。不要手工改带哈希的 bundle；源码变更后按 CI 流程构建并检查 `server/static/index.html` 引用是否一致。
- SQLite schema 变更需要可重复、向前兼容的迁移；不要在正常启动路径执行昂贵或破坏性压缩。

## 推荐验证

按改动范围选择现有检查；只有任务要求或需要验证实现时才执行。GitHub 工作流是完整 CI 的准绳：

```bash
cd frontend
npm ci --ignore-scripts
npm run build
cd ..
python -m compileall -q client server scripts tests
python -m unittest discover -s tests -v
```

浏览器回归由 `tests/run_ui_regressions.py` 执行，需要工作流安装的隔离 Playwright/Chromium 环境。CI 还覆盖 Python 3.11/3.12 兼容性、Linux 网络隔离探测和 amd64/arm64 Server 镜像导入检查。构建或模拟检查不能替代目标 Linux 节点的生产验证。

## Git 与生产环境

- 只暂存当前任务要求的文件；保留他人已存在的 staged、unstaged 和 untracked 内容。不要用 `git reset --hard`、`git clean` 或宽泛暂存来“整理”工作区。
- 不要覆盖 `server/static/`、SQLite 业务数据、外部 `.env` 或 TLS 文件；备份/恢复遵循运维手册。
- SSH/生产操作前按用户提供的主机映射确认目标和身份，校验 host key；不猜测别名、不绕过认证。执行前先查看状态和影响范围，执行后读回验证。
- 不部署生产、不强推或直接改写远端历史，除非用户明确要求。报告时区分代码检查、CI 通过和生产已验证。
