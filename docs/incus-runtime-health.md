# Incus 运行时健康与卡住实例处理

## 目标与边界

Client Agent 对 Incus 容器实例和后台操作做有界、只读巡检，帮助发现 `ERROR` 实例、长期不完成的停止/启动/重启/删除操作，以及 Incus 管理接口超时或变慢。巡检不执行实例修复动作，不会强杀容器、删除 operation、停止或重启 `incus.service`。

Agent 只把需要人工检查的日志路径放入告警，不读取或上传 `console.log`、`lxc.log`、`forkexec.log` 的内容。故障的具体原因仍需结合 LXC 日志、systemd 配置和宿主机状态确认。

## Agent 巡检

每次主机报告周期内，Agent 在本地执行两次限时 CLI 查询：

- `incus list` 的容器过滤清单，按 `INCUS_PROJECT` 选择项目；默认扫描全部项目。
- `incus operation list`，同样遵循项目范围；默认扫描全部项目。

默认单条命令超时为 8 秒，超时配置可由 `INCUS_HEALTH_COMMAND_TIMEOUT_SECONDS` 调整，范围为 3–15 秒。运行超过 300 秒的生命周期操作会产生严重告警；创建时间缺失或不可解析时会产生待核实告警，仍会阻止重复停止，可由 `INCUS_STUCK_OPERATION_SECONDS` 调整，范围为 60–3600 秒。查询超过 3000 毫秒会产生 API 变慢提示，可由 `INCUS_SLOW_API_MILLISECONDS` 调整，范围为 500–10000 毫秒。

只要节点启用了 Incus（`CONTAINER_RUNTIMES=auto` 或显式包含 `incus`），即使 `SECURITY_MONITOR_ENABLED=false`，也会收集该运行时健康状态。其他未启用 Incus 的节点不会产生 Incus API 缺失告警。

## 自动停止保护

Incus 的连接过载自动停止必须同时满足以下条件：

1. Agent 上报本轮实例和后台操作清单都完整。
2. 目标实例精确匹配，状态仍为 `RUNNING`。
3. 目标实例不处于 `ERROR`，也没有正在执行的启动、停止、重启或删除操作。
4. 不存在目标不明的运行中生命周期操作。
5. Client 收到 stop 动作后，再次读取该项目的精确实例状态和 operation 清单，且再次确认目标为 `RUNNING`、没有待处理操作。

状态或操作清单不完整时，Server 不会为 Incus 排队新的自动停止。Client 的二次检查也会在身份不精确、状态异常、Incus 查询超时或发现现有生命周期操作时取消 stop。Podman 的连接过载策略不受此 Incus 专属门禁影响。

## 卡住实例排查步骤

1. 先保存告警中的实例 UUID 和操作 ID，避免再次对同一实例提交停止请求。
2. 只读查看 `/var/log/incus/<实例 UUID>/lxc.log`、`forkexec.log` 和 `console.log`，重点关注失败时间附近的 LXC 启动/清理钩子、PID、挂载、cgroup 与设备卸载错误。日志可能包含容器内部敏感信息，分享前需先检查并脱敏。
3. 检查 `incus operation list --all-projects`、`systemctl cat incus.service`、`systemctl cat incus.socket` 和 `systemctl show incus.service -p MainPID -p KillMode -p ExecStop -p TimeoutStopUSec -p Restart -p FragmentPath`。
4. 确认宿主机是否有相关进程处于 D 状态、内核日志中的 I/O/OOM 错误，以及 systemd 在停止守护进程时的 KillMode/ExecStop 行为。
5. 若需要重启 Incus 守护进程，先确认服务单元行为、其余实例状态、日志留存和维护窗口；该恢复步骤由管理员根据现场控制执行。Agent 不会自动替管理员做此决定。

不要用 `incus admin shutdown` 作为仅重启守护进程的替代步骤，也不要把删除 operation 当作解锁手段。任何恢复动作前都要明确它会不会影响其他实例。

## 运维中心状态

Agent `operations.health` 中会出现 `incus_runtime` 项，呈现扫描完整性、实例数、ERROR 实例数、生命周期操作数、卡住操作数和 API 延迟。告警在完整扫描再次确认问题消失后才会恢复；部分扫描、API 不可用或旧 Agent 未上报该能力时，Server 保留已存在的 Incus 告警。
