# v1.7.85 验收记录

日期：2026-10-26。源分支基线：fork `main` `93790f4`。本记录对应实现提交 `5cfb0c6a7c771da9bc6ab60706b21db6792c2fbb`（版本 `1.7.85`）。

## 本次改动

- GitHub Actions 新增 Python 依赖漏洞审计，以及只访问合成 loopback 预览站的 Playwright 回归任务；全部 12 个 `.cjs` 回归脚本纳入编排。浏览器截图作为 7 天构建产物保存。
- Dashboard 页面改为按需加载；登录页面不加载 Dashboard，未选中的告警、统计、设置、经营、运维和防火墙页面不下载。容器详情和 ECharts 分包。
- SQLite 每小时记录主库/WAL/可复用页大小，最多保留 45 天；运维中心显示趋势。告警仅在 24 小时增长同时超过绝对值和百分比阈值时显示，不推送客户、不自动清理。
- 首次 CI 依赖审计发现 FastAPI/Starlette 与 cryptography 的已知漏洞；升级 FastAPI 到 0.162.0、cryptography 到 50.0.2 下限后，依赖审计通过。FastAPI 0.162.0 要求 Python 3.10 及以上；服务镜像使用 Python 3.12。
- 浏览器回归确认历史“连接数保护”记录不应出现客户通知入口；服务器镜像须包含数据库趋势采样模块。
- 从 `client/agent.py` 抽离 Incus OpenMetrics 解析器，同时保留旧模块函数名以兼容既有调用；运维页拆出数据库增长趋势卡片。

## 本机已验证

- TypeScript `tsc --noEmit` 通过。
- Vite 生产构建通过，输出独立页面包；主 Dashboard 页面约 160 KiB，压缩约 44 KiB；ECharts 独立为约 1.1 MiB 包。Vite 仍提示单个 ECharts 包超过 500 KiB，但该包只在需要图表的页面加载。
- `tests.test_database_telemetry`：3 项通过，覆盖每小时去重、45 天清理和双阈值判定。
- 对改动的 Python 源文件执行 `py_compile` 通过。

## CI 与生产状态

- GitHub Actions：Run `#263`（commit `5cfb0c6`）全部通过，包括 Python 全量测试、依赖审计、12 个隔离 Playwright 浏览器回归、Linux 网络准入测试及 server 镜像构建/冒烟检查；GHCR 镜像发布成功。
- 生产核验：自动更新服务完成目标 SHA `5cfb0c6a7c771da9bc6ab60706b21db6792c2fbb`；`narwhal-monitor-server` 使用 `1.7.85`，镜像 revision 与该 SHA 一致，镜像 ID 为 `c8fc2a1556590161a9369d34c223d252fe4275bda7366b095ea54d46044011cf`。容器运行中，`/app/database_telemetry.py` 存在；本机回环后端返回 `303 See Other` 登录跳转，证明应用可响应。
- 本地环境没有项目 Python 依赖，故未在本机运行完整 Python 服务测试；以通过的 Linux CI 全量测试和容器冒烟检查为准。本机已完成的构建及定向测试见上文。
- 不在此次变更中修改任何主机防火墙或容器处置策略。
