# 当前进展与待办

更新时间：2026-11-06（Asia/Shanghai）

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
