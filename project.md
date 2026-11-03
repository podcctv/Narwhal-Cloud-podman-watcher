# 项目概览

更新基线：本次从 fork 最新 `origin/main`（`43ee526` / v1.7.202）继续维护 Runman Rust v2 兼容；发布目标为 `1.7.203`（2026-11-03）。提交历史与主要功能索引见 [README.md](README.md)。

## 项目目标

Narwhal Cloud Container Watcher 由 Server、Client Agent 和 Web 界面组成，用于监测 Podman、Incus、Docker 与 Runman Rust v2 实例及主机状态，并提供告警、调查、受控保护和运维工作流。Incus 实例状态巡检、生命周期操作卡死告警与 stop 前二次核验见 [Incus 运行时健康手册](docs/incus-runtime-health.md)。Runman 支持代次绑定的受限 guest exec、通用只读进程/监听/协议扫描、shell 卡片与 MOTD、主机 RFW、TCP 限额、自动滥用检测与 veth 隔离、手动/自动单容器限速，以及磁盘 I/O 和网络指标。SSH 认证前 Banner、专用 VMess/Trojan/测速规则、CPU 进程归因、UDP socket 归因、Podman 式镜像写层大小、动态 CPU/内存/I/O 配额和一般破坏性服务处置仍未适配。部署状态、采样新鲜度、策略回执和实际生效状态需要分开判断。

## 组件与入口

| 组件 | 主要入口 | 职责 |
|---|---|---|
| Server | `server/app.py`、`server/` | FastAPI API、身份与权限、SQLite 状态、告警/运维/策略/升级协调；由 `server/Dockerfile` 打包运行。 |
| Client Agent | `client/agent.py`、`client/` | 安装在节点主机上的 Python Agent，采集运行时、资源、安全和网络证据，接收并执行受限动作。安装与升级脚本位于 `scripts/`。 |
| Web UI | `frontend/src/` | React、TypeScript、Vite 前端。`frontend/vite.config.ts` 将构建产物写入 `server/static/`，Server 镜像使用这些静态文件。 |
| 发布与检查 | `.github/workflows/`、`tests/` | 构建 GHCR 多架构镜像、前端构建、Python 单元/兼容性测试和浏览器回归。CI 定义以工作流文件为准。 |

Server 与 Client 共用根目录的 `VERSION`。托管升级依赖固定的 Git 提交、版本匹配、Agent 健康报告和分批发布门禁；升级流程入口见 `server/fleet_updates.py`、`server/upgrade_health.py` 与 `docs/operations-runbook.md`。

## 开发时的系统边界

- 缺失、过期或身份不匹配的数据是“未知/待核实”，不能改写成健康、零值或容器当前状态。
- 安全发现、保护动作、客户通知和处置回执是不同状态。通知成功不证明处置成功，保护信号也不能单独归因为客户滥用。
- 网络隔离和防火墙操作必须限定到已核实的节点、运行时与规则归属；应用策略后还要核验读回结果。共享网络或无法证明隔离边界的情况应保留待人工处理状态。
- 数据库恢复演练不得覆盖线上数据库；真实恢复按 `docs/operations-runbook.md` 的停服、备份和读回步骤执行。

## 进一步阅读

- 开发要求：[agent.md](agent.md) 与自动加载入口 [AGENTS.md](AGENTS.md)
- 当前状态：[progress.md](progress.md)
- 运维：[docs/operations-runbook.md](docs/operations-runbook.md)、[docs/operations-plan.md](docs/operations-plan.md)、[docs/operations-validation.md](docs/operations-validation.md)
- 安全边界：[docs/abuse-network-quarantine.md](docs/abuse-network-quarantine.md)、[docs/host-security-audit.md](docs/host-security-audit.md)、[docs/vmess-protection.md](docs/vmess-protection.md)、[docs/user-investigation.md](docs/user-investigation.md)
- Runman 兼容性：[docs/runman-rust-v2-compatibility.md](docs/runman-rust-v2-compatibility.md)
- Incus 运行时健康：[docs/incus-runtime-health.md](docs/incus-runtime-health.md)
