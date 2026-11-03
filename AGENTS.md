# Agent instructions

开始任务前阅读 [agent.md](agent.md)、[project.md](project.md) 和 [progress.md](progress.md)，并核对当前 `git status` 与 `VERSION`。

保留已有工作区修改，只处理用户授权范围内的文件。遵循对应 `docs/` 的安全边界；过期或缺失证据保持未知。对运行时代码变更按 CI 要求更新 `VERSION` 并选择相关验证；不要把 CI 结果描述成生产验证。代码完成及验证通过后，自动提交并直接推送到 fork 的 GitHub `main` 分支（`origin main`），不要提交 PR。SSH、生产变更或发布前确认用户授权和目标。
