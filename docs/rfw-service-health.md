# RFW 宿主机服务健康检查

Python 与 Rust Client Agent 在每次主机报告中只读检查 `rfw.service`。检查依赖本机 systemd，使用有界的 `systemctl show` 查询，不读取服务日志或配置，不执行启动、停止、重启或规则变更。

## 状态判定

| 状态 | 判定 | 界面行为 |
| --- | --- | --- |
| `healthy` | systemd 报告服务处于 active | 显示“运行中” |
| `stopped` | 服务处于 inactive、failed 或 deactivating | 显示主机告警卡片 |
| `restart_loop` | systemd 子状态为 auto-restart；或 5 分钟采样到至少 3 次重启；或重启计数至少 3 且本次运行不足 3 分钟 | 显示“疑似重启循环”告警卡片 |
| `not_installed` | systemd 未发现 `rfw.service` | 显示“未安装”，不告警 |
| `not_applicable` | Agent 在子容器中，无法证明其观察的是宿主机 systemd | 显示“Agent 容器”，不推断宿主机服务状态 |
| `unavailable` / `unknown` | systemd 无法访问、状态字段缺失或状态正在转换 | 显示待评估，不推断健康或故障 |

短时间重启统计只在 Agent 运行周期内比较 systemd 的 `NRestarts` 增量，并按主机启动 ID 分段。Agent 重启后以新样本建立计数基线；systemd 明确处于 `auto-restart` 时无需等待计数基线。

## 告警处理

告警卡片提供只读排查入口：

```sh
systemctl status rfw.service --no-pager
journalctl -u rfw.service --since "-10 min" --no-pager
```

应先核对失败日志、启动次数和最近变更，再按实际原因处理。Watcher 不会自动重启 RFW。超过 Server 允许的主机报告有效期后，历史异常不再作为实时告警展示。

检查与通用安全扫描开关独立，但仅在新版本 Agent 上报后生效。Server 会将状态作为主机遥测字段返回，不会送入 Telegram、Webhook 或其他外部通知通道。
