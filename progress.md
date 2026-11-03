# 当前进展与待办

更新时间：2026-11-03（Asia/Shanghai）

## Runman Rust v2 兼容开发

- 基于 fork `main` 全面补齐 Runman (Rust) 容器监控与部署脚本自适应。
- 支持实时带宽速率计算（`_derive_net_bps`）与流量计数器（`traffic_counters`）、容器网络 IP（`network_addresses`）透出、独立磁盘与 `/data` 容量上报、安全 MOTD 登录提示、买家映射（`buyer_mapping`）与用户备注接口（`/api/v1/containers/user-note`）以及前端抽屉无缝呈现。
- 同步更新 Agent 部署与更新脚本（`scripts/install-client.sh`），自动检测 `docker` / `incus` / `podman` / `runman`，并保持 `DOCKER_MONITOR_MODE=notice` 默认不干预。
- 本轮版本目标为 `1.7.199`。

## 代码基线

- 当前工作区基于 fork `main` 继续维护 Runman Rust v2 适配与全链路监控闭环。
- 本次根目录 `VERSION` 更新目标为 `1.7.199`。
- 本次工作涵盖 Runman 容器网络 IP、带宽速率与流量计数器补全、独立磁盘与 procfs 文件系统容量映射、安全 MOTD 写入、买家映射与用户备注放行、前端详情抽屉网络展示、Agent 安装脚本多运行时自动检测及全量回归单测。

## 最近完成的工作

- v1.7.199：全面补齐 Runman Rust 容器监控、流量速率、MOTD 登录提示与 Agent 部署脚本自适应：
  1. 补全 Runman 容器 IP 与网络速率：`_runman_inventory_containers()` 与 `collect_runman_report()` 提取解析 `network_addresses`；接入 `_derive_net_bps` 实时计算 `net_rx_bps` 与 `net_tx_bps`，上报规范化 `traffic_counters`；映射 `disk_gb` 与 procfs 文件系统至 `container_disk` 容量。
  2. 买家映射与用户备注放行：`server/buyer_mapping.py` 与 `server/app.py`（`/api/v1/containers/user-note`）全面放行 `runman` 运行时，前端 `ContainerDrawer` 放行备注卡片并直接展示容器 IP。
  3. 安全 MOTD 登录提示写入：使用当前 init PID 和启动 tick 代次校验，通过宿主机 procfs 原子更新普通 `/etc/motd`。
  4. `CONTAINER_RUNTIMES` 与 `runtime_inventory` 完整兼容识别 `runman`，消除未知运行时警告并在节点运行状态中准确声明。
  5. 同步更新 `scripts/install-client.sh`：自动检测 `docker` / `incus` / `podman` / `runman (rust 容器)`，任意存在时不强制安装 podman；保持 Docker 为 `notice` 默认仅提醒不接管。
  6. 单元测试全量通过，前端构建生成最新生产静态资源。
- v1.7.198：在 Runman 清单与 bridge 只读探测前检查 Unix socket 平台能力；不支持 `AF_UNIX` 时返回不可用，保持 Windows 测试/工具环境可运行。Runman 连接限制、防火墙和 Linux 行为不变。
- v1.7.196：修复 Incus CPU 限额命令执行、内存阶梯升档死锁与协议待核验误报：
  1. 修复 `client/cpu_guard.py` 中 `_runtime_args` 重复前置 `runtime` 二进制导致 `subprocess.run` 拼接成 `incus incus ...` 并报错 `Error: unknown command "incus" for "incus"` 的缺陷，使 Incus 容器 CPU 配额读取、生效与自动阶梯防护闭环。
  2. 修复 `client/memory_guard.py` 中进入第 2 阶（80%）后因实际内存受限（~81%）永远低于全局 `start_usage`（85%）导致升档计数器在每轮都被清零重置的死锁，增加按阶梯门槛自适应判断。
  3. 修复前端 `ContainerStateBadges` 与 `ContainerCardCompact` 在未检出协议且无端点阻断时因单轮扫描不完整误显 `[VMess 阻断待核验]` / `[Trojan 阻断待核验]`，并在 `ContainerDrawer` 中明确区分 `阻断待核验` 与 `未检测到 (扫描待核验)`。
  4. 补齐 Alpine/Minimal 容器内无标准 `ps -eo` 或 `ss` 时的宿主机 procfs 回退采集，准确关联监听端点并消除假性 `process_snapshot_unavailable`。
- v1.7.195：增强 Trojan/VMess 阻断有效召回率与面板端点级诊断原因透出：
  1. 前端 `ContainerDrawer` 的 `ProtocolGuardCard` 为每个待核验端点显式标注具体阻断障碍原因（如 `共用监听端口 (防误杀)`、`实时监听未匹配`、`配置在进程启动后更新` 等），结合现有“按需触发一次性深度采样”功能，在面板上提供完整的可观测诊断视图。
  2. 修复 `client/agent.py` 中容器 procfs 不可读时的宿主机时钟代次回退闭环，当容器内 `/proc/{pid}/stat` 缺失但宿主机已核验进程稳定性时，采纳宿主机代次时钟，消除假性 `process_start_generation_unavailable`。
  3. `client/socks_detector.py` 增加对 sing-box 命令行配置目录参数（`-C`、`--config-directory`）识别，遍历内部配置并避免被当成非法文件导致整轮扫描放弃；并在 sing-box 省略 `network` 时默认将 Trojan/VMess 映射至 TCP 传输层。
  4. 对齐 Trojan 待核验告警的原因解析链路，精准透出进程与端口级瓶颈。
- v1.7.194：CPU 保护告警标题为“持续高 CPU，保护需要检查”时，告警摘要及 `cpu_guard` 详情中透出底层实际错误原因（`last_error`），消除排查黑盒；修复 CI 单测偶发受 Runner 宿主机 `/proc/123/net/tcp` 干扰与升级测试整秒跳变问题。
- v1.7.193：升级 `.agents/skills/narwhal-ui-design` v2.0 技能并结合 `modern-web-guidance`，统一全局设计 Token（`.ui-surface-card`、`.ui-btn-*`、`.ui-input`、`.ui-select`、`.ui-table-wrap`），重构顶栏、命令面板、登录页、总览、容器详情抽屉、告警历史、用户排查、统计分析、经营账本、运维中心、母机防火墙与系统设置视图，实现桌面端与手机端（`320px–1920px`）自适应及表格键盘无障碍滚动。
- v1.7.192：在线容器列表和 KPI 排除过期快照；保留的快照单独用于离线/过期核查，不能当作当前容器操作目标。
- v1.7.191：分别展示主机心跳与容器采样时间，避免把容器采样过期误说成主机离线。
- v1.7.188–v1.7.189：修正隔离目标替换复核、隔离状态标签、过期告警保护和 Fleet 升级结果显示。
- v1.7.187：总览、表格和详情补充容器保护/违规状态展示。

## 已确认的问题与注意事项

- GitHub `main` 曾领先于交接来源工作区多个提交；来源工作区基于 `6cb8c80`/v1.7.168，并有未提交的 UI 修改和未跟踪技能/临时目录。为避免覆盖，本次提交从最新 `origin/main` 的隔离 worktree 制作。这些本机修改未包含在 GitHub 提交中。若继续处理原工作区，先查看 `git status` 和逐文件差异，与当前 `main` 对比后再移植；不要清理、重置或假定它们已合入。
- 交接前 README 仍标 v1.7.186，而 `VERSION` 已到 v1.7.192，且缺少 v1.7.187–v1.7.192 的近期摘要。此文档更新同步 README 版本、近期说明和完整版本索引。
- 仓库记录不足以确认当前生产部署版本；开始生产排查前先取得目标主机的新鲜上报或授权的主机核验。
- 本次查看范围未发现最新 `main` 的 CI 失败；此前中间提交出现过失败工作流，后续 `3d961d1` 与 `ec054cf` 均通过。处理新改动时仍以其自身 CI 和必要的目标验证为准。

## 下一步

1. 如继续原工作区的 UI 改动，逐项与 `main` 的容器状态、隔离和过期采样改动对照，保留有效差异并补齐对应回归。
2. 任何发布/部署前，核对 Server 与 Client 的 `VERSION`、Agent 健康采样、升级回执和目标节点状态；按 [运维运行手册](docs/operations-runbook.md) 执行。
