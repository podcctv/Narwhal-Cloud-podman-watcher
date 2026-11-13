# 项目概览

更新基线：基于 fork `origin/main` v1.8.27，新增 Runman 连续 CPU/内存过载自动重启（Watcher v1.8.29，Agent 最低版本 v1.8.28）。提交历史与版本演进规范见 [README.md](README.md)。

## 项目目标

Narwhal Cloud Container Watcher 由 Server、Client Agent 和 Web 界面组成，用于监测 Podman、Incus、Docker 与 Runman Rust v2 实例及主机状态，并提供告警、调查、受控保护和运维工作流。Incus 实例状态巡检、生命周期操作卡死告警与 stop 前二次核验见 [Incus 运行时健康手册](docs/incus-runtime-health.md)。网络可达性与质量支持全国省份 TCP Ping 与参考开源 reach-check 的全球 18 区域及中国电信/联通/移动三网可达性检测，展示 DNS/TCP/TLS/首包分段时延、GFW 针对性阻断研判与排查指引，并集成于 TCPPING 页面与宿主机卡片。Runman 支持代次绑定的受限 guest exec、只读进程/监听/协议扫描与深度快照、连接来源时间线/历史回放、shell 卡片/MOTD/按用户定向登录提醒/条件式 SSH 认证前 Banner、主机 RFW、TCP 限额、自动滥用检测与 veth 隔离、手动/自动限速、CPU offender 采样、UDP socket/进程引用指标、cgroup v2 CPU/内存/I/O guards、明确选择或全局默认策略下的 VMess/Trojan/测速保护、人工复核后的 SOCKS 指定进程停止，以及带连续新鲜证据和 UUID 代次条件的过载自动停止。Runman 上报 overlay `upperdir/up` 普通文件逻辑字节和已分配块，并通过进程启动 tick/文件指纹支持 allowlist 面板与 XMRig 清理、systemd/OpenRC/SysVinit 精确服务停止。upperdir 指标不承诺与 Podman `SizeRw` 逐字节等价，清理也不执行任意递归删除。部署状态、采样新鲜度、策略回执和实际生效状态需要分开判断。

Watcher 还把 Runman 接入 Admission：先验证当前实例代次、init PID、guest 地址和 host veth，再执行准入规则；GFW 公网端点发现要求明确 DNAT/直连与实时监听证据。受限磁盘清理保持默认关闭并只处理 allowlist 归档，PasarGuard 只清理精确识别的服务目标。Runman CPU 或内存达到 90% 并持续一小时后可触发代次核验自动重启；动作只重启精确 systemd unit 并尝试恢复原 `io.max`。Runman 持久弱 SOCKS 自动停止策略仍关闭，人工复核的单次 PID 停止可用。

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
