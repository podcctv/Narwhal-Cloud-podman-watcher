# 当前进展与待办

更新时间：2026-11-13（Asia/Shanghai）

## Runman 连续资源过载自动重启（Watcher v1.8.29，Agent 最低版本 v1.8.28）

- 在 v1.8.27 模块化客户端结构上新增资源过载保护：CPU 或内存达到 90%、持续满 3600 秒、至少 5 次有效样本且最大间隔 900 秒后才触发。
- Server 绑定节点 node ID、Runman UUID 与实例代次；Agent 重读 inventory 和当前指标、串行锁定重启、复核精确 systemd unit 与 MainPID，并恢复读回原 `ct/io.max`。
- 动作记录为 `ops_resource_guard` 非滥用保护信号；服务端镜像显式包含策略模块，Agent 报告响应字段保持原样。
- 本地 Python 语法、前端 TypeScript 检查和 Vite 生产构建通过；GitHub Actions 的 Python 3.11/3.12 兼容检查、完整测试集、amd64/arm64 镜像烟测均通过。未部署生产节点。

## 运维中心「节点升级」交互重设计：版本下拉选择与一键全选（v1.8.27）

- **后端 (`server/operations_api.py`)**：`/api/v1/ops/upgrades` 返回 `server_revision` 与 `available_releases`（自动关联当前主控 `VERSION` + `NARWHAL_REVISION` 及历史发布记录）；`POST /api/v1/ops/upgrades` 在未显式传入 `revision` 且目标等于当前主控版本时自动填充 `NARWHAL_REVISION`。
- **前端 (`frontend/src/components/operations/OperationsView.tsx`)**：移除反直觉的「已发布的 main 提交 SHA」与版本号手工输入框，改为目标版本下拉菜单自动绑定对应 `main` SHA，并在节点列表上方新增「全选待升级」「全选全部」「清空选择」与实时已选计数。

## 修复 `runtime_drivers.py` Linux Runman `security_banner` 导入与代次字典同步（v1.8.26）

- 补充 `client/runtime_drivers.py` 中缺失的 `security_banner` 导入，修复 Linux `/proc` 校验路径下的 `NameError`。
- 将 `_runman_inventory_containers()` 中的 `_runman_instance_generations` 重置与更新改为原地 `.clear()` / `.update()`，确保与 `agent._runman_instance_generations` 共享同一字典引用。

## 客户端核心采集模块拆分与覆盖升级/回滚跨架构基建加固（v1.8.25）

- **需求背景**：
  1. 为后续 Rust 渐进式替换（Strangler Fig 路线）铺平道路，需先将 14,595 行单文件 `client/agent.py` 按职责拆分为内聚模块，同时保持现有 `agent.*` 导入、单测 mock 与命令行入口 100% 兼容。
  2. 原 `scripts/managed-client-update.sh` 存在硬编码 `*.py` 清单与回滚盲区（不备份/不恢复新拆分模块、原生二进制、`narwhal-monitor-client.service` 及更新器自身），且 `install-client.sh` / `update_archive.py` 缺少统一的 `uname -m` 架构归一化校验。
- **全链路落地与实现**：
  1. **阶段 1：Python 客户端核心热点模块化拆分 (`client/agent.py`, `client/proc_scanner.py`, `client/geoip_enricher.py`, `client/socket_collector.py`, `client/runtime_drivers.py`)**：
     - 将 `client/agent.py` 从 14,595 行精简至 9,282 行，拆出 `proc_scanner.py`（667 行，`/proc` 进程树与快照缓存）、`geoip_enricher.py`（550 行，MMDB 查询与 TTL 缓存）、`socket_collector.py`（2,527 行，连接安全、conntrack 与四维滥用评估）及 `runtime_drivers.py`（2,231 行，Podman/Incus/Docker/Runman 运行时发现与 cgroup/容器指标采集）。
     - `client/agent.py` 保留完整向后兼容重导出与 `client.*`/本地双路径导入回退，并向各拆分模块注册 `globals()` 引用，确保既有 `mock.patch.object(agent, ...)` 与 `spec_from_file_location` 加载用例 100% 兼容。
  2. **阶段 2：升级/回滚动态化与跨架构分发基建加固 (`scripts/managed-client-update.sh`, `scripts/install-client.sh`, `scripts/update_archive.py`, `tests/test_managed_update_scripts.py`)**：
     - `managed-client-update.sh` 将 `py_compile`、快照备份与 `restore()` 改为动态遍历 `client/*.py` 与可选 `client/bin/` 二进制，并记录 `installed-files.manifest` / `staged-files.manifest` 以在回滚时清理本次新增文件；同步快照与还原 `/etc/systemd/system/narwhal-monitor-client.service`（回滚后执行 `systemctl daemon-reload`）、`managed-client-update.sh` 与 `update_archive.py`。
     - `install-client.sh` 与 `update_archive.py` 新增 `normalize_arch`（`x86_64|amd64 -> amd64`，`aarch64|arm64 -> arm64`，未知架构明确报错退出），并在 `install-client.sh update` 中动态同步全部 `client/*.py`、可选 `client/bin/*` 与更新器脚本。
     - 新增 `tests/test_managed_update_scripts.py` 并更新 `tests/test_managed_upgrade.py`、`tests/test_socks_detector.py` 断言以覆盖动态发现、清单清理、`systemd` 单元回滚与架构归一化测试。

## Agent 单核 CPU 尖峰消除与 Incus/Runman 多容器争抢及 `/ct` 子 cgroup CPU 保护优化（v1.8.24）

- **需求背景**：
  1. 单核（1 vCPU）主机上 `narwhal-monitor-client` 存在周期性 ~56.8% CPU 尖峰，导致主机卡顿。
  2. 多容器（`incus` / `runman`）并发运行时各自占用落在 `/ct` 子 cgroup 且均配置为 `CPUQuotaPerSecUSec=1s`（单容器上限 100%），单容器未达 85% 持续 300s 阈值但合计打满单核主机引发卡死。
- **全链路落地与修复实现**：
  1. **Agent 采集性能与调度优化 (`client/agent.py`, `tests/test_agent_perf.py`)**：
     - 引入 `_collection_tick_scope()` 与 `_scan_host_proc_tree()`（`O(descendants)` BFS 与轻量 `_extract_proc_ppid`，每 256 个 PID 让出调度），单轮采集中 `/proc` 仅扫描一次并按 `init_pid` 缓存快照，复用至 `collect_top_cpu_process`、`collect_suspicious_processes` 与 `collect_panel_pairing_indicators`。
     - 跳过 `runman` 已有 `container_fs_available` 时的冗余 `df`、重复 `_sample_cgroup_cpu_metrics` 与重复 `_enrich_socket_ips_geoip`；新增 `_apply_low_priority_scheduling()`（`AGENT_NICE=10`）与容器循环 `AGENT_COLLECT_YIELD_SECONDS=0.02`。
     - 修复 `incus` 在 `_incus_stats` 报告 `cpu_percent > 0` 时跳过 cgroup `cpu.stat`/`cpu.max` 采样的问题，修复 `runman` `pid_start_ticks` 传递，支持 `/ct/cpu.max` 为 `max` 时回退读取父单元 `.service/cpu.max` 并受主机容量上限约束。
  2. **Incus/Runman 多容器争抢保护与快速限额 (`client/cpu_guard.py`, `tests/test_resource_protection.py`)**：
     - 新增 `_runman_effective_cpus_from_cgroup`，在 `/ct/cpu.max` 为 `max` 时回退读取父 unit `cpu.max`；支持 Incus 百分比配额（如 `50%`）解析。
     - 新增多容器主机争抢检测与按比例公平限额（`_target_limit`、`CPU_AUTO_LIMIT_MAX_SIMULTANEOUS`），将默认失控/争抢确认窗口缩短至 `180s`（`interval` 下限 `30.0s`），保留读回验证（`readback_confirmed`）、`reason_is_user_abuse: False` 与压力回落后自动恢复。

## 四维连接证据紧凑折叠卡片重构与单核节点 Runman 持续高 CPU 采样及自动限额修复（v1.8.23）

- **需求背景**：
  1. 用户反馈 `Socket / 代理连接四维判断依据` 告警卡片高度过高（默认展开 6 张纵向 IP 卡片与 4 张场景评估大卡片导致总高超 800px，且左侧连接状态拆解框存在大面积空白黑洞，来源网络去重标签重复渲染多次）。
  2. 用户反馈单核节点（如 `JINX` 1 vCPU）上 `runman` Rust 容器 CPU 异常占满 100% 持续 40 分钟未被监测到且未触发自动限制（需人工重启容器恢复）。
- **全链路落地与修复实现**：
  1. **四维判断依据卡片紧凑横条化与按需折叠重构 (`SocketAbuseEvidence.tsx`, `SecurityAlertSection.tsx`, `AlertHistoryView.tsx`, `ContainerDrawer.tsx`)**：
     - **四层紧凑架构（默认高度缩减 $>75\%$）**：顶栏单行汇总结论与代理对称度徽章；4 维核心指标采用 `grid-cols-1 sm:grid-cols-2 lg:grid-cols-4` 等高水平紧凑卡片（含 `tabular-nums` 核心数字、`h-1.5` 状态占比条与单行副指标），彻底消除左右高度失衡与空白黑洞；业务场景评估压缩为单行水平胶囊条（带颜色状态点、概率标签与首要倾向依据）。
     - **原生 `<details>` 按需披露与双列 IP 网格**：将入站/出站公网 IP 样本、脱敏代理进程启动命令及完整排查说明收纳进原生 `<details>` 折叠面板（`展开 IP 与诊断明细` / `收起明细`，兼顾键盘无障碍与 `Ctrl+F` 页内检索）；展开后 IP 列表采用 `md:grid-cols-2` 紧凑双列网格，并对 `source_networks` 按网络分类标签聚合去重（附 ASN 明细）。
     - **冗余提示整合**：当告警已携带四维判断依据且无独立深度快照时，将多段式保护说明折叠为单行提示条，并避免抽屉内重复渲染同一四维卡片。
  2. **Runman 容器 cgroup v2 / 宿主 `/proc` 增量 CPU 采样与单核节点自动 `cpu.max` 限额闭环 (`client/agent.py`, `client/cpu_guard.py`, `server/control_reconciliation.py`)**：
     - **Runman 多源增量 CPU 采样兜底**：新增 `_sample_cgroup_cpu_metrics` 按代次校验后的容器 cgroup 读取 `cpu.max`（提取 `quota_cpus`）与 `cpu.stat`（计算 `usage_usec` 跨周期增量 CPU%）；`_collect_host_proc_process_snapshot` 新增按 `(host_pid, start_ticks)` 追踪进程级 `(utime+stime)` 增量 CPU%，解决长周期进程（如 `xray`）瞬时满载被生命周期均值稀释及无 `ps -eo pcpu` 时的漏采问题；`collect_runman_report` 与 `collect_container` 统一汇总 API、cgroup 增量与 `top_cpu_process` 并正确透传 `cpu_pressure_percent`、`cpu_pressure_sample_available` 与 `cpu_effective_cpus`。
     - **单核节点（如 `JINX`）失控 CPU 压力确认与自动限额 (`cpu_guard.py`)**：新增 `_container_cpu_pressure_confirmed`，在单核主机饱和（`single_core_host_cpu_saturation`）、单容器占满主机 $\ge 75\%$ 容量、容器 cgroup CPU PSI 达标或主机高负载（`busy >= 95%` / `load_1m >= logical_cpus`）时确认 CPU 压力，解决单核机器单线程跑满 100% 但内核 `/proc/pressure/cpu` `some avg10 < 5%` 导致计数被清空的问题；支持在 `cpu_effective_cpus <= 0` 时自动回退至 `cpu.max` 或主机逻辑核数，跨短暂 `warming` 周期保留候选计数，连续 2 次采样即抓取 `top_process` 并产生 `warning` 观察告警，满 300s 失控窗口自动下发 Tier 1 `cpu.max`（如单核 `50000 100000`）并完整回填读回验证字段（`readback_confirmed`、`original_limit`、`active_limit`、`actual_limit`）。

## 经营分析初次进入自动同步补位、后台独立业务日志与会话凭证加固（v1.8.20）

- **需求背景**：
  - 用户反馈进入经营分析页面时默认不会自动同步，且此前上游快照停留于 03:18:00 UTC，要求排查服务端日志并确认原因。
- **全链路落地与功能实现**：
  1. **页面进入智能静默补位同步 (`CommerceView.tsx`)**：
     - 用户初次切换或打开「经营分析」面板时，组件自动评估当前快照时效；若快照未就绪、标记为陈旧或距上次同步超过 5 分钟（300 秒），前端自动在后台向 `/api/v1/commerce/sync` 派发异步同步请求，并无感轮询状态直至完成无缝更新，彻底消除「点进来默认不刷新」的体验割裂。
  2. **后台独立业务日志与诊断透明化 (`server/commerce.py`)**：
     - 引入专用 `logger = logging.getLogger("narwhal.commerce")`，对后台自动定时轮询任务的唤醒、各账号调度、耗时以及错误完整输出至标准容器日志，支持管理员随时通过 `podman logs` 进行精准排查与审计。
  3. **会话持久化与跨上下文 Binding 防御 (`server/commerce.py`)**：
     - 在快照持久化 SQL 更新时引入 `row.get("binding") or binding(conn, username)`，在 `_auto_sync_loop` 中同步拉取 `binding` 字段，确保无论后台异步工作线程是否处于活跃会话上下文中，均能绝对匹配并持久化上游快照。

## 经营分析全自动后台静默轮询同步与前端免刷新实时联动（v1.8.19）

- **需求背景**：
  - 用户询问经营分析页面的数据是否可以自动同步，避免每次都需要人工点击「同步经营数据」。
- **全链路落地与功能实现**：
  1. **后台自动定时轮询引擎缺省自启与健壮性加固 (`server/commerce.py`)**：
     - 用户在配置并保存个人 API Key 时，系统自动在 `commerce_notification_settings` 表中初始化缺省自动同步规则（`auto_sync=1`, 轮询间隔 5 分钟，开启订单与退款实时 TG 推送）。
     - 重构 `_auto_sync_loop` 调度查询为 `LEFT JOIN`，确保无论用户是否曾手动提交过设置表单，后台均能自动为所有已配置 API Key 的账号按设定间隔（3/5/10/15/30 分钟）自动拉取上游快照与最新流水。
  2. **前端页面免刷新静默联动与状态透出 (`CommerceView.tsx`)**：
     - 新增轻量级快照版本监听器（每 30 秒探测一次快照同步时间戳变更），一旦后台自动同步完成，前端各标签页（GMV走势、日度月度、风控名单、忠诚度等）均自动无感刷新，无需人工按 F5。
     - 在顶部操作栏清晰透出当前后台自动同步状态胶囊标签（如 `● 后台自动定时同步中 (5 分钟/次)`），并将手动按钮明确标为「立即手动同步」，让自动与手动并存且一目了然。

## 已删除容器违规隔离归档闭环与经营退款极速买退对冲校准（v1.8.18）

- **需求背景**：
  1. **隔离容器被用户删除导致恢复流程卡死**：部分容器在收到违规通知后，用户直接在控制台删除了容器。此时宿主机上原容器已不复存在，管理员在面板中点击「容器已重装：核验并归档旧隔离」或「复核并恢复原实例网络」时，因各运行时驱动严格检查目标容器存在性而抛错，导致状态始终卡在 `未能验证旧容器身份已被替换；隔离记录仍待管理员复核，未改动任何容器网络。`。
  2. **月度经营退款数字虚高与对冲校准**：上游账单中，买家频繁在 24 小时内（通常 5~10 分钟）进行极速买退换 IP（`escrow_in` 搭配 $\ge 80\%$ 金额的 `escrow_deduct`），旧版逻辑将所有 `escrow_deduct` 简单计为退款，导致退款数字被重复试用放大数倍，GMV 与净收益失真。
- **全链路落地与功能实现**：
  1. **跨运行时旧实例缺席证明与删除归档闭环 (`client/network_quarantine.py`, `client/agent.py`, `server/abuse_api.py`, `QuarantinePanel.tsx`)**：
     - **Incus 驱动**：`prove_replaced()` 与 `release()` 在容器 404 时遍历 `/1.0/instances?recursion=2`；若旧 `instance_id` 与容器名均不存在，确认已被用户销毁并返回 `'none'`，不再强制要求新容器存在。
     - **Podman 驱动**：在容器名 inspect 失败且 `inspect self.instance_id` 返回 `no such container` 时，安全确认为已删除，返回 `'none'`。
     - **Runman 驱动**：新增 `inventory()` 机制查询 `/v1/inventory`；当 `/v1/network-quarantine` 因容器销毁报错时，若库存中旧 `instance_id` 及 VM UUID 均已消失，安全确认为已删除，返回 `'none'`。
     - **服务端与 Agent 协议放宽**：回执支持 `container_deleted=true` 与 `current_instance_id=none`，自动将告警与隔离记录归档为 `replaced` 并置为 `resolved`，提示语更新为 `管理员复核确认旧实例及容器已被用户删除；旧隔离记录已归档`。
     - **前端交互**：按钮与弹窗文案更新为「容器已重装或已删除：核验并归档旧隔离」，解除了管理员卡死死锁。
  2. **卖家 Escrow 账本智能对冲分类与真实经营统计 (`server/commerce.py`)**：
     - 新增 `_classify_seller_escrow` 机制，精准配对 24 小时内的极速试用换 IP（`escrow_in` 与 `escrow_deduct` 差额），将洗牌试用从有效 GMV 和退款中剥离，仅保留真正的中途退款，彻底消除退款虚高。
     - 深度富化母鸡维度风控与买家重点关注列表，正确绑定历史交易记录与已购在期 VM。

## 经营分析与运营中台全面强化：自动同步、TG实时提醒、日报月报、异常退款风控、一键拉黑与忠诚度奖励（v1.8.17）

- **需求背景**：
  - 用户要求强化经营分析能力：
    1. 支持自动同步上游 API 接口，有新的买入订单或退款流水时秒级推送到 Telegram 机器人。
    2. 提供「每日经营分析」与「每月经营分析」看板与定期播报。
    3. 构建「异常退款服务器（母鸡）」与「异常退款用户」风控模型，输出「重点关注买家清单」。
    4. 将买家一键拉黑（Blacklist）功能集成到经营分析中，识别频繁买退用户并阻断。
    5. 构建买家忠诚度评估体系（根据使用在期时长给出徽章标记），并在后台提供一键奖励（添加可用时长操作）。
- **全链路落地与功能实现**：
  1. **后台自动同步与增量比对引擎 (`server/commerce.py`, `server/app.py`)**：
     - 新增 `commerce_notification_settings` 表与后台异步轮询调度器，支持自定义同步间隔（默认 5 分钟，可选 3/5/10/15/30 分钟）。
     - 采用 `commerce_notified_events` 增量指纹比对机制，首次配置静默引导历史事件，后续新产生买入、续费或退款流水时即时格式化并推送到绑定的 Telegram 机器人频道。
     - 支持设置每日播报时间（默认 08:00 UTC+8）自动推送日度经营小结（GMV、退款金额、净收入、母鸡在售率），并于每月 1 日推送全月收支与热销母鸡排行。
  2. **异常退款分析与重点关注清单 (`server/commerce.py`, `CommerceView.tsx`)**：
     - **母鸡维度**：计算各母鸡退款率，对退款率 $\ge 15\%$ 或短期连续退款节点进行标红预警，提供线路与 IP 可用性排查建议。
     - **买家维度**：识别购买后 24 小时内极速退款的试用/羊毛党、以及历史退款率 $> 50\%$ 的用户，自动生成「重点关注清单」。
  3. **上游原生黑名单拉黑集成 (`server/commerce.py`, `openapi.yaml`)**：
     - 对接上游 `POST /vms/{id}/block-user`、`GET /machines/blocked-users` 与 `DELETE /machines/blocked-users/{user_id}`。
     - 支持在重点关注清单中一键拉黑违规买家（关停其所有自动续费并禁止新购），并在黑名单专区支持一键解除拉黑。
  4. **用户忠诚度评估与一键赠送时长 (`server/commerce.py`, `CommerceView.tsx`)**：
     - 基于在期天数、续费次数及履约记录自动计算买家忠诚等级（💎 钻石老客 / 🥇 黄金老客 / 🥈 常规履约）。
     - 对接上游 `POST /vms/{id}/compensate` 接口，在前端提供一键赠送可用时长（1~365 天）弹窗，自动计算预估扣减的托管余额并完成延期。
  5. **经营分析 UI 现代化重构 (`frontend/src/components/commerce/CommerceView.tsx`)**：
     - 升级为多标签页架构：`[📊 概览与走势]`、`[📅 日度与月度经营]`、`[🚨 异常退款与重点关注]`、`[👑 用户忠诚与奖励]`、`[🚫 黑名单管理]`、`[⚙️ 同步与推送设置]`。
     - 包含近 30 日 GMV/净收柱状走势图、近 12 个月月度统计表、一键补偿与拉黑弹窗。

## Socket / 代理异常深度采集与四维证据面板美化重构（v1.8.16）

- **需求背景**：
  - 用户反馈当前 Socket 滥用四维卡片“留白过多、不够美观”，且针对异常用户（如通过 Cloudflare WARP/多出口中继接入 SOCKS5、出站多目标 Web 服务的真实场景）需要进一步丰富采集信息以供人工排查与准确判断。
- **全链路落地与视觉/诊断增强**：
  1. **深度采集增强与协议参数脱敏 (`client/agent.py`)**：
     - **代理进程参数采集 (`_socks_process_commands`)**：自动捕获并脱敏记录代理进程（如 `gost`、`danted`、`xray`）的完整启动命令、监听参数（`-L`）与上游转发链（`-F`），自动掩码密码、令牌与用户凭据。
     - **入站访问端口映射 (`local_ports`)**：记录每个入站公网 IP 具体访问了容器的哪些本地端口（验证多个 Cloudflare IP 是否确实访问同一个 SOCKS5 代理端口）。
     - **中继网络智能识别与来源去重 (`_classify_source_network`)**：将 `104.28.0.0/16`、`2a09:bac0::/29`（Cloudflare WARP 出口）、iCloud Private Relay 及主要 IDC/机房网络自动归类，估算独立来源网络数，避免将同一 WARP 用户的多出口 IP 误判为多人共享。
     - **业务场景可能性推断 (`_build_socket_investigation`)**：自动评估「个人自用代理（含 WARP 二级代理）」、「多设备共用 / 小规模共享」、「商业共享 / 机场出口」、「自动化程序 / 爬虫中转」四类场景的可能性与具体事实依据。
  2. **证据面板美观度与留白充实重构 (`SocketAbuseEvidence.tsx`, `types.ts`)**：
     - **维度 1（状态拆解）**：新增 ESTABLISHED vs TIME_WAIT vs SYN_SENT 状态分布彩色占比条与双向并发对称性分析卡片（一目了然确认是否为 TCP 代理一进一出转发）。
     - **维度 2（入站并发源）**：卡片列表化渲染，透出来源网络标签（WARP/中继）与访问的本地端口，并展示来源网络去重透视。
     - **维度 3（出站与进程）**：结构化展示出站目标组织（Tencent、Alibaba、Google 等）聚合与访问端口分布。
     - **维度 4（包速率）**：新增网络流量形态分析卡片、PPS 对称比与单包开销分析，彻底消除下半部分大面积空白。
     - **运营分析与场景推断区**：新增 4 项场景评估卡片（带高/中/低概率进度条）、脱敏后的代理进程启动命令与一键复制按钮、展开式运维排查建议。

## 业务入站准入真实建连 IP 严格过滤与用户邮箱定时自动拉取匹配加固（v1.8.15）

- **需求背景**：
  - 用户核实 `业务入站准入 9/10 IP` 面板中显示的 IP 是真实建立连接 IP 还是被扫描 IP，并要求 `用户邮箱` 支持定时自动拉取匹配。
- **根因诊断与全链路修复**：
  1. **入站准入严格仅确认真实 `ESTABLISHED` 建连 IP (`client/admission_guard.py`, `client/admission_policy.py`, `AdmissionStatus.tsx`)**：
     - **原问题根因**：旧版在 `Guard.decision()` 收到首包 SYN（`confirmed: False` 15秒观察期）时即调用 `nft.admit()` 将该 IP 写入 nftables `@sources4`/`@sources6` 集合（120秒超时），随后 `_refresh_sources()` 把内核集合中的残留 IP (`kernel - seen`) 直接回填并提升为 `confirmed: True`，导致仅发送 SYN 探测包或 Cloudflare 边缘探测未完成三次握手的 IP 也被计入 `活跃并发业务来源`。
     - **修复措施**：
       - `Guard.decision()` 仅对已确认（`confirmed: True`）的来源调用 `nft.admit()`，并在 `Guard.update()` 中仅向内核 `@sources4`/`@sources6` 同步 `confirmed` 来源。
       - `_refresh_sources()` 移除从 `kernel - seen` 提升 `confirmed: True` 的逻辑；只有容器 `/proc/<pid>/net/tcp[6]` 在实际业务 `LISTEN` 端口上观测到 `state == '01'` (`ESTABLISHED`) 的公网 IP 才会转正为 `confirmed: True`（并标记 `active_established`）。
       - 前端 `AdmissionStatus.tsx` 明确展示 `已建连活跃业务来源 (confirmed/limit)`，标注每个 IP 是 `已建连(ESTABLISHED)` 还是 `空闲保持(120s内)`，并将 15 秒观察期内的未完成握手 SYN 探测单独统计显示。
  2. **用户邮箱定时自动拉取与多源匹配闭环 (`server/buyer_mapping.py`, `server/app.py`, `server/operations_api.py`, `ContainerDrawer.tsx`)**：
     - **高频定时与新实例即时触发**：后台自动拉取周期从 15 分钟缩短为 **3 分钟 (`INTERVAL = 180s`)**；当检测到活跃 UUID 实例尚未完成上游映射时，后台循环在 **30 秒内**自动触发即时同步 (`needs_urgent_sync`)。
     - **同母机双运行时 (`incus`/`podman` + `runman`) 全部匹配**：修复 `buyer_mapping.apply()` 对同一母机同时上报 `incus` 与 `runman` 同一 VM UUID 时误判为冲突而拒绝匹配的问题（仅拒绝跨不同 `host_id` 的重复 UUID），解决 `[Oracle]Tokyo arm` 等节点实例显示 `上游实例未匹配` 的问题。
     - **Podman 容器 UUID 名称与短 ID 双向关联**：`operations_api._candidate_vm_ids` 同时按 `container_id` 与 UUID `container_name` 匹配 `buyer_targets` 与 `service_inventory`。
     - **持久化用户邮箱目录 (`buyer_user_directory`) 与同 `user_id` 自动回填**：针对上游 `/machines/{id}/vms` 接口仅返回 `user_id` + `user_name` 而不返回 `user_email` 的情况，新增 `buyer_user_directory(user_id -> user_email, user_name)` 持久化字典，自动从历史 `buyer_targets` 与 `backups/monitor*.db` 备份库提取回填 `user_id -> user_email` 映射，并在手工补充任一容器邮箱时自动关联至该 `user_id` 名下所有容器。

## Socket 滥用复核处置按钮（封禁 / 忽略 / 跳过本次）与采集 IP 国家·省份·运营商 (ISP/ASN) 归属匹配（v1.8.14）

- **需求背景**：
  - 用户要求在 `疑似 Socket / 代理连接滥用` 人工复核告警卡片上直接增加 **「封禁」**、**「忽略」**、**「跳过本次」** 三个快捷处置按钮。
  - 同时要求对采集到的入站与出站公网 IP 自动匹配并展示 **国家 · 省份/地区 · 运营商 (ISP/ASN)**。
  - 修复截图案例中 `runman` 容器四维判断卡片：① 状态拆解连接数与出站活跃数口径对齐；② 区分正常双端口（如 `80/443` CDN/Web 节点）高外部 IP 访问与真正的多端口/高 UDP P2P 扩散。
- **全链路落地实现**：
  1. **「封禁 / 忽略 / 跳过本次」快捷处置闭环 (`SecurityAlertSection.tsx`, `AlertHistoryView.tsx`, `server/app.py`, `client/agent.py`)**：
     - **封禁 (`freeze_container`)**：一键向节点下发容器挂起冻结指令（支持 `incus`、`podman`、`runman`，Agent 自动按运行时解析当前容器 `pid` 与 `instance_id` 执行 cgroup / runtime 挂起定格），并将告警状态更新为 `remediated`（已处理），已冻结容器不再重复触发 `socket_abuse_suspected`。
     - **忽略 (`allow_silent`)**：建立静音放行规则，持续忽略该容器的同类观察提醒（可在告警历史随时恢复提醒）。
     - **跳过本次 (`dismiss_once`)**：仅跳过本轮活动告警，后续风险特征变化时仍可再次提醒。
  2. **采集 IP 国家 · 省份/地区 · 运营商 (ISP/ASN) 自动富化 (`client/agent.py`, `SocketAbuseEvidence.tsx`)**：
     - `_collect_socket_security` 与 `_apply_host_conntrack_security` 同步采集入站 `inbound_top_ips` 与出站 `outbound_top_ips`（含总连接数、已建连数、`SYN_RECV` / `SYN_SENT` 数及目标端口）。
     - 新增 `_enrich_socket_ips_geoip` 与 `_format_geoip_badge`：结合本地 TTL 缓存、公网 IP 归属查询（`ipwho.is`）与 MaxMind 离线库回退，将采集到的入站/出站 Top 公网 IP 自动解析为 `国家·省份/地区 · 运营商 ASxxxx`（如 `中国·江苏省 · China Mobile AS9808`、`美国·California · Cloudflare, Inc. AS13335`）。
     - 前端 `SocketAbuseEvidence.tsx` 在维度 2（入站并发业务源）和维度 3（出站目标与进程画像）中直接渲染每个采集 IP 的连接明细与 **国家 · 省份 · 运营商 (ISP/ASN)** 徽章。
  3. **四维指标口径对齐与 P2P 散度规则收敛 (`client/agent.py`)**：
     - `collect_runman_report` 在合并 `host_conntrack` 后重新执行 GeoIP 富化与 `_evaluate_socket_abuse`，并自动对齐 `tcp_established` 与 `total_sockets` 下界，消除状态拆解 `ESTABLISHED 4` 与出站活跃 `191` 不一致的问题。
     - 收敛 `p2p_or_outbound_fanout_abuse` 判定条件：要求 `outbound_unique_ips >= 120` 且同时满足 `udp_sockets >= 80` 或 `outbound_unique_ports >= 30` 或 `outbound_unique_ips >= 300`，避免仅访问 2 个 Web/CDN 端口（80/443）的正常代理或爬虫被误判为 P2P 扩散。

## Socket / SOCKS 连接滥用四维检测与判断依据引擎（v1.8.13 · 人工核验观察模式）

- **需求背景**：
  - 单纯的 `socket 总数`（如 `ops_policy_signal`: `socket 总数 2030，提醒门槛 500`）混杂了 `TIME_WAIT` 短连接回收堆积与外部被动扫描 `SYN_RECV`，不能直接据此判定滥用。
  - 用户要求按四维逻辑部署 Socket / SOCKS 滥用检测，在出现异常或高连接提醒时输出详细的**四维判断依据**，先由人工核对真实案例是否准确，后续再开启自动化处置。
- **全链路落地实现**：
  1. **底层 `/proc/<pid>/net` 证据增强 (`client/agent.py`: `_collect_socket_security`)**：
     - 新增 `syn_sent_count`、`outbound_syn_sent_unique_ips`（主动向外发起握手未完成的目标 IP 数）、`outbound_top_ports` 与 `sensitive_outbound_ports`（針對 `22/SSH, 23/Telnet, 25/SMTP, 445/SMB, 465/SMTPS, 587/SMTP-Sub, 1433/MSSQL, 3306/MySQL, 3389/RDP, 5432/PostgreSQL, 6379/Redis, 6667/IRC` 的连接数、活跃数、`SYN_SENT` 数与独立 IP 散度统计）。
  2. **四维交叉分析与分类判决引擎 (`client/agent.py`: `_evaluate_socket_abuse`)**：
     - 输出四大结构化维度（`dimensions`）与详细判断依据（`judgment_basis` / `compact_basis_text`）：
       - **① 连接状态拆解 (`state_breakdown`)**：区分 `ESTABLISHED` 真实活跃连接、`TIME_WAIT` 短连接等待内核回收占比、`SYN_SENT` 主动向外扫描与 `SYN_RECV` 外部入站探测。
       - **② 入站并发业务源 (`inbound_fanout`)**：聚焦 `inbound_established_unique_ips`（已排除仅 SYN 探测的扫描 IP）、入站活跃连接数、Top 来源 IP 与 SOCKS5 协议/认证状态。
       - **③ 出站目标与进程画像 (`outbound_profile`)**：分析外部目标 IP/端口散度、高危敏感端口命中明细及容器内主通信进程（`process/PID`）。
       - **④ 包速率与带宽特征 (`traffic_profile`)**：结合 `tx_pps` / `rx_pps` 与出站平均包长（`avg_tx_packet_size`）区分正常大包流媒体转发与高频小包扫描/泛洪。
     - 自动识别四大滥用形态（命中时产生 `socket_abuse_suspected` 观察告警，设置 `protection_only=True`、`auto_stop_eligible=False`，不自动停机或封禁）：
       - `outbound_scan_bruteforce`（对外端口扫描 / 敏感端口爆破）
       - `shared_proxy_socks_abuse`（多人共享 SOCKS / 代理节点滥用）
       - `p2p_or_outbound_fanout_abuse`（高散度出站连接 / 疑似 P2P 扩散）
       - `high_socket_packet_flood`（高连接伴随高频小包泛洪）
     - 对高 Socket 但未命中滥用特征的实例（如 `TIME_WAIT` 占比高、入站已建连仅 1~5 个 IP），明确给出 `倾向非滥用 · 正常业务/连接回收堆积`（`benign_high_sockets`）结论与具体排除理由。
  3. **服务端运维信号与连接告警证据注入 (`server/operations.py`, `server/connection_policy.py`, `server/app.py`, `server/buyer_notifications.py`)**：
     - `ops_policy_signal`（`实例使用情况超出提醒范围`）、`container_connection_count`、`socks_inbound_fanout`、`inbound_ip_fanout`、`outbound_fanout`、`outbound_sensitive_ports` 及 `socket_abuse_suspected` 全面附带 `socket_abuse` 四维证据，并在提醒文案中直接展示 `【四维判断依据】`。
     - `socket_abuse_suspected` 纳入自动触发有界深度取证（`queue_connection_alert_deep_samples`）及 `PROTECTION_ONLY_ALERT_TYPES`。
  4. **前端「Socket / 代理连接四维判断依据」可视化卡片 (`SocketAbuseEvidence.tsx`, `AlertHistoryView.tsx`, `SecurityAlertSection.tsx`, `ContainerDrawer.tsx`)**：
     - 在告警历史、仪表盘实时安全告警以及容器详情抽屉中直接渲染四维判断依据卡片，清晰展示结论标签、命中规则说明及 4 个维度的风险等级与核心指标药丸。

## 容器真实业务并发 IP 限制 · 业务端口聚焦与抗公网扫描 DoS 架构（v1.8.12）

- **需求背景**：
  - 用户提出深度架构诉求：“10IP入栈如果是扫描不是真实业务如何界定，我希望限制容器真实业务的并发IP，而不是被几十个IP的入栈扫描就限制”。
  - 若单纯统计首包 SYN，公网全网扫描器（如 Censys、Shodan、ZoomEye、Masscan）的随机探测包将迅速耗尽 10 个入站名额，导致合法业务用户被拒绝（扫描引发的 DoS）。
- **全链路落地与深度架构加固**：
  1. **业务监听端口动态聚焦 (`client/admission_linux.py` / `client/admission_observe.py`)**：
     - `observe.sockets(pid)` 在无感知兼容原有调用解包前提下，精确提取容器内实际处于 `LISTEN` 状态的端口列表（`listening_ports`）。
     - nftables 准入表底层新增内核快速旁路规则：`incoming meta l4proto tcp tcp dport != { listening_ports } return`。
     - **防扫描效果**：针对未开放业务端口的公网随机扫描（扫 22, 80, 443, 3389, 8080 等非业务端口），在内核态直接 return 绕过准入队列，**零入队、零占位、100% 免疫非业务端口扫描**。
  2. **基于 ESTABLISHED 真实会话的状态占位 (`client/admission_policy.py`)**：
     - 引入会话确认（`confirmed`）与试用期隔离机制（`PROBATION_GAP = 15s`）：
     - 只有在容器业务监听端口上**成功完成 TCP 三次握手进入 `ESTABLISHED` 状态**的来源 IP（通过内核 `/proc/<pid>/net/tcp` 提取的 `inbound` 验证），才被确认为**真实业务并发来源（Confirmed Business Source）**。
     - 针对业务端口的单向 SYN 探针、半开扫描（`SYN_RECV`）或握手后立即断开的探测探针，因未形成持续业务会话，在 15 秒试用期后自动被清理，**绝不占用持续业务并发配额**。
  3. **并发业务容量判决与精准拦截 (`client/admission_guard.py`)**：
     - 准入决策以 **“当前活跃已确认业务并发 IP”** 为判断基准（`confirmed_count < source_limit`）。
     - 当且仅当容器内部确实存在 $\ge 10$ 个不同的真实业务客户端同时保持活跃连接时，第 11 个新来源才会被拦截并触发 `inbound_source_blocked` 告警。
  4. **前端状态面板与文案精准回显 (`frontend/src/components/container/AdmissionStatus.tsx`)**：
     - 回显文案优化为 `业务入站准入 ${confirmedCount}/${sourceLimit} IP`。
     - 明确提示“已启用业务监听端口聚焦与真实已建立会话识别，公网扫描不消耗配额。超过上限的新来源连接已被自动阻断。”
  5. **全量验证保障**：
     - 新增非业务端口 50 次并发扫描零占位测试、未建立会话探针 15s 自动淘汰测试及真实 10 并发业务拦截测试。
     - 993 项单元与集成测试全部通过；13 项 Playwright E2E UI 脚本全部通过。

## 单容器多 IP 入站限制防护 · 默认 10 IP 阈值、超限阻断与告警（v1.8.11）

- **需求背景**：
  - 用户提出容器网络安全管控需求：“目前没有限制单容器多 IP 入站的能力，开发一下默认限制单容器 10 IP 入站，超过的阻断新连接并警告”。
- **架构设计与全链路落地**：
  1. **入站准入策略引擎与活跃来源滑动窗口 (`client/admission_policy.py`)**：
     - 新增 `DEFAULT_SOURCE_LIMIT = 10` 与 `source_limit_from_env()`，支持通过环境变量 `SECURITY_ADMISSION_SOURCE_LIMIT` 灵活配置（设为 0 时平滑回退为仅观察模式）。
     - 重构 `admit_source(src, now)`：维护容器当前活跃来源 IP 集合（容量上限 10）。
     - 超出 10 IP 的新增来源首包被严格判定为不放行（`accepted = False`），并计入 `blocked` 来源明细（包含 `first_seen`, `last_seen`, `packets`），递增 `blocked_packets` 计数器。
     - **智能空闲过期（Sliding Window Idle Expiry）**：活跃来源在 120 秒无流量交互后自动释放名额，新来源可平滑接替。
  2. **Linux 内核级双通道高效阻断与状态保护 (`client/admission_linux.py`)**：
     - 在 nftables 准入表内定义动态 set：`sources4` 与 `sources6`，配置 `timeout 120s; size 256;`。
     - **已有连接零损耗放行**：首条规则 `incoming ct state != new return` 确保已有合法连接、双向回包完全不受影响，不产生任何连接断开。
     - **内核快速通道更新**：`incoming ip saddr @sources4 update @sources4 { ip saddr timeout 120s }` 命中活跃集合自动在内核态续期 120s 快速通行。
     - **未知新流队列判决**：`incoming ct state new queue num {queue} bypass` 将未知新连接送入用户态 NFQUEUE 判定；若用户态服务重启使用 `bypass` 避免容器失联。
  3. **守卫判决与安全告警触发 (`client/admission_guard.py`)**：
     - `Guard` 初始化加载 `self.source_limit`（默认 10）。
     - NFQUEUE 回调中，对新入站流调用 `state.admit_source(src, now)`：超限直接 `return False`（内核直接丢弃该 SYN 包！），合法新流则同步写入 nftables 动态集合。
     - `alerts(container)`：当检测到 `source_limit_enforced` 为真且近 2 分钟存在有效阻断来源时，自动触发 `inbound_source_blocked` 级别为 `warning` 的告警，附带上限阈值、阻断来源数与被拦截 IP 样本。
  4. **服务端告警标准化与买家面板通知优化 (`server/admission_api.py` / `server/buyer_content.py`)**：
     - 告警标题格式化为 `单容器入站已达 10 IP 上限并阻断新连接`，提示已有活跃连接保持，空闲 120 秒自动释放。
     - 买家端友好说明超限阻断原因与合规建议，避免客户误解。
  5. **前端交互与状态面板重构 (`frontend/src/components/container/AdmissionStatus.tsx`)**：
     - 区分现代多 IP 限制（`isModernEnforced`）与历史旧版：状态栏清晰回显 `入站准入 ${sources.length}/${sourceLimit} IP`，并在超限阻断时高亮呈现 `已拦截 ${blocked.length} 个超限来源`。
     - 展开视图中以 Bento 双列网格清晰展示当前活跃入站来源列表（附首次观测时间）及近两分钟超限阻断来源列表（附拦截数据包数）。
  6. **全量验证保障**：
     - 补充针对 10-IP 限制、第 11 个来源拦截、重复探测计数、已有来源保持与 120s 空闲过期的全套单元测试。
     - 991 个单元测试全部通过（0 失败）；13 个 Playwright UI 端到端回归脚本全部通过。
