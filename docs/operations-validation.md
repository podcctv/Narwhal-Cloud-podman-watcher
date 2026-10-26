# v1.7.84 验收记录

日期：2026-10-26。源分支基线：fork `main` `93790f4`。此记录随本次实现更新，发布与生产结果在提交后补记。

## 本次改动

- GitHub Actions 新增 Python 依赖漏洞审计，以及只访问合成 loopback 预览站的 Playwright 回归任务；全部 12 个 `.cjs` 回归脚本纳入编排。浏览器截图作为 7 天构建产物保存。
- Dashboard 页面改为按需加载；登录页面不加载 Dashboard，未选中的告警、统计、设置、经营、运维和防火墙页面不下载。容器详情和 ECharts 分包。
- SQLite 每小时记录主库/WAL/可复用页大小，最多保留 45 天；运维中心显示趋势。告警仅在 24 小时增长同时超过绝对值和百分比阈值时显示，不推送客户、不自动清理。
- 首次 CI 依赖审计发现 FastAPI/Starlette 与 cryptography 的已知漏洞；已将 FastAPI 升级到 0.162.0、cryptography 升级到 50.0.2 下限，等待新 CI 再次审计。
- 从 `client/agent.py` 抽离 Incus OpenMetrics 解析器，同时保留旧模块函数名以兼容既有调用；运维页拆出数据库增长趋势卡片。

## 本机已验证

- TypeScript `tsc --noEmit` 通过。
- Vite 生产构建通过，输出独立页面包；主 Dashboard 页面约 160 KiB，压缩约 44 KiB；ECharts 独立为约 1.1 MiB 包。Vite 仍提示单个 ECharts 包超过 500 KiB，但该包只在需要图表的页面加载。
- `tests.test_database_telemetry`：3 项通过，覆盖每小时去重、45 天清理和双阈值判定。
- 对改动的 Python 源文件执行 `py_compile` 通过。

## CI 与生产状态

- GitHub Actions（Python 全量测试、依赖审计、Playwright 浏览器回归、镜像构建）：待本次推送后确认。
- 生产 Server 版本与容器健康：待本次发布后通过 SSH/运行状态核验；不以静态资源 HTTP 状态代替运行版本确认。
- 不在此次变更中修改任何主机防火墙或容器处置策略。
