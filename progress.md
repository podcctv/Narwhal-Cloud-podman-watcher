# 当前进展与待办

更新时间：2026-11-04（Asia/Shanghai）

## 自动化三网可达性巡检与容器上线/舰队升级修复（v1.7.213）

- **Dockerfile 镜像依赖完善与版本递增**：在 `server/Dockerfile` 中补充 `COPY reach_monitor.py .`，满足 GitHub Actions 跨架构镜像 smoke-test 导入依赖与 GHCR 版本递增门禁。

- **容器列表全部被判定为旧快照未出现在最新清单根因与修复**：
  - 现象：仪表盘全集群 28 台主机均显示在“没有新鲜容器数据的主机”，展开提示“旧快照未出现在最新清单”，全部容器被隐藏。
  - 根因：此前为保活在线主机，在 `/api/v1/actions/poll` 与 `/api/v1/admission/` 中每 5~30 秒刷新 `hosts.last_seen`。但容器报告周期为 300 秒，前端 `containerFreshness.ts` 与 `HostContainerList.tsx` 之前将 `sample.timestamp` 与 `host.last_seen` 做强一致对比，导致心跳刷新后立即将 300 秒内上报的全部健康容器判定为“被更新报告遗漏的旧快照”并剔除。
  - 修复：服务端 `/api/v1/latest` 聚合 `SELECT host_id, MAX(ts) FROM reports GROUP BY host_id`，精确返回 `host_report_timestamp`；前端 `isCurrentContainerInventoryItem` 与 `newerHostReportExists` 严格比对真实的容器报告时间戳，彻底解决容器假性下线/隐藏问题。
- **舰队升级死锁修复**：
  - 现象：生产环境 25 台节点停留在旧版本（v1.7.203 等），由于历史 null-disk 异常曾导致 reports 中断，`ops_hosts.ts` 超过 900 秒，`server/fleet_updates.py` 严格校验 `0 <= now - ops_ts <= 900` 导致拒绝向活跃节点分发升级。
  - 修复：放宽节点升级候选门禁，只要 `now - last_seen <= 900` 即可接收更新；修复 `server/fleet_updates.py` 中对 `sqlite3.Row` 误调 `.get()` 导致的 `AttributeError`；解开全集群升级卡顿。
- **全球 18 区域与国内三网自动化每小时巡检与展示**：
  - 服务端新增 `server/reach_monitor.py`，后台每小时自动遍历集群节点，随机选取本机当前开放监听端口，调用 Globalping 发起 18 核心区域（含中国电信 AS4134、联通 AS4837、移动 AS9808）可达性与时延测试。
  - 新增专用表 `host_reachability`、`host_reachability_history` 与 `host_client_ips`，完全不破坏原有 `hosts` 表 5 列契约，避免影响现有单测与向下兼容性。
  - 提供 `GET /api/v1/reachability/summary`、`GET /api/v1/reachability/host/{host_id}` 与 `POST /api/v1/reachability/trigger` 接口。
  - **TCPPING 页面**：新增集群每小时自动化巡检总览卡片、国内三网时延对比、状态分布、一键重测及每台母机历史结果展开。
  - **宿主机卡片**：`<HostReachabilityBadge>` 支持从自动化数据库动态加载最新检测成果，展示所测端口、三网状态及平均时延。
- **验证结论**：
  - 前端 Vite 生产构建顺利通过（产物输出至 `server/static/`）。
  - Python `compileall` 无报错。
  - 全量 951 项单测全部通过（43 项按环境正常跳过）。

## Runman Rust v2 兼容（v1.7.211）

- 当前新增适配：Admission 准入保护、受限磁盘清理、PasarGuard 精确服务清理；Runman 网络证据只在 UUID 代次、init PID、guest 地址和 host veth 逐项匹配后启用。
- VMess、Trojan、测速规则的阻断/恢复状态现在生成 Runman 告警回执；面板/XMRig 的 UI 动作只接受 UUIDv4 代次及具体进程启动 tick 或文件指纹证据。
- GFW 公网端点扫描纳入 Runman 新鲜报告，并继续要求已核对的直接公网地址或明确 Host DNAT、实时监听及唯一容器归属；管理员重新打开 Runman 面板告警时会排队撤销先前域名放行。
- 遥测运行时选项和防火墙测速保护的默认选择已纳入 Runman。人工复核后的 SOCKS 指定 PID 停止保持可用，持久化自动停止策略仍明确关闭。
- 新增回归覆盖 Runman Admission 网络身份/veth、代次拒绝、PasarGuard guest exec、磁盘清理目标及文件系统锚定、Server Admission/PasarGuard 收据身份校验。
- 合并 fork `main` 的 `a908a87` 后，本机 `compileall`、全量单测（951 项，42 项按平台/环境条件跳过）、TypeScript 检查和 Vite 生产构建（2237 个模块）均通过。GitHub Actions [41766673744](https://github.com/podcctv/Narwhal-Cloud-podman-watcher/actions/runs/41766673744)（提交 `67029fb`）全绿：Python 3.11/3.12 兼容、浏览器回归、Python/Linux/OpenRC 测试、隔离网络准入、amd64/arm64 镜像冒烟及 GHCR 构建推送均通过。早先提交 `bbb46a7` 的 GHCR job 因合并版本门禁失败；版本已递增至 1.7.211，并由最终工作流验证通过。没有执行生产节点部署或实机验证。

## 全球三网可达性检测与节点心跳修复（v1.7.209）

- **生产服务器全员离线/空状态根因查明并修复**：
  - 生产环境主机上报包含 `"disk": null` 的容器数据时，`server/app.py` 中 `c.get("disk", {}).get("file")` 抛出 `AttributeError: 'NoneType' object has no attribute 'get'`，导致 `/api/v1/report` 500 异常与事务回滚。
  - 由于仅在 report 事务成功提交时更新 `hosts.last_seen`，所有运行容器的主机心跳超限（>900s）并被总览判定为 stale/离线隐藏，舰队波次升级同步停滞。
  - 修复：对 `server/app.py` 中的 `c.get("disk")` 和 `payload.get("disk")` 增加严格的字典类型防御校验；同时在 `/api/v1/actions/poll` 与 `/api/v1/admission/` 身份核验通过时原子刷新 `hosts.last_seen`，避免正常轮询动作的节点被假性标记离线。
- **开源 Reach Check 核心逻辑引入与轻量化三网可达性检测**：
  - 参考开源项目 `yt1988/reach-check` 核心思想，构建全球 18 个核心节点与国内三大运营商（中国电信 AS4134、中国联通 AS4837、中国移动 AS9808）的可达性探测引擎与可视化界面。
  - 呈现 DNS、TCP 建连、TLS 握手及首包 (TTFB) 耗时，自动判定网络状态（三网通畅·全球可达、疑似 GFW 阻断·国内异常、仅国内可达·海外受阻、部分受阻等），并提供系统性故障排查步骤。
  - **集成至 TCPPING 页面**：在顶栏无缝提供“全国 TCP Ping”与“全球三网可达性 (Reach Check)”标签切换，支持 URL 参数与集群主机预选。
  - **集成至宿主机卡片**：在在线与离线主机卡片顶部新增紧凑型 `<HostReachabilityBadge>`，直观展现国内三网通畅状态与平均延迟，点击一键唤起完整 18 区域探测弹窗与诊断。
- **安全审计与轻量化约束**：
  - **SSRF 防御**：严格阻断 RFC 1918 私网（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）、CGNAT（`100.64.0.0/10`）、环回（`127.0.0.0/8`）、链路本地（`169.254.0.0/16`）及 IPv6 ULA，严禁将私网拓扑提交给外部公共探针。
  - **浏览器端口安全**：自动跳过 WHATWG 浏览器受限高危端口，避免客户端 Fetch 异常。
  - **零后台开销**：客户端前端直连公共 Globalping 探针网络与浏览器本地探测，宿主机与服务端无额外常驻守护进程。
- **验证结论**：
  - 前端 Vite 生产构建顺利通过，产出静态资源与 bundle。
  - 本地 Python 全量 941 项单元测试全部通过（39 项环境跳过），新增容器空磁盘及动作轮询更新心跳单测。
  - 生产环境待自动发布与验证。

## Runman Rust v2 兼容（v1.7.208）

- 新增有界 upperdir/up allocated-block、普通文件逻辑字节及文件数指标，与 disk.img sparse 分配量分开上报；抽屉并列展示两种口径。遍历不完整、超出 50,000 项或实例代次变化时标记不可用。
- 面板/XMRig 清理通过 Server 最新报告代次验证，再由 Agent 复核精确进程启动 tick、服务 cgroup 和普通文件指纹；旧告警、软链接及缺少证据的目标拒绝动作。
- Runman upperdir 指标仍不承诺与 Podman SizeRw 逐字节一致；清理新增精确 SysVinit 脚本支持，仍限于本地 allowlist 和能安全停止/禁用的目标。
- Runman `edd4983` 与 Watcher `7be3e40` 已推送 fork `main`。Runman 格式/Clippy/单元与运行时集成检查、Rust v2 amd64/arm64 构建及 `continuous-rs` 发布、Agent/RFW amd64/arm64 测试和滚动 Release 均通过。
- Watcher `7be3e40` 的 Python 3.11/3.12 兼容、939 项单测（1 项跳过）、Linux/OpenRC 集成、前端构建与 Chromium 浏览器回归、隔离网络准入、amd64/arm64 镜像冒烟和 GHCR 构建均通过。
- 本机 `compileall`、Python 全量单测（939 项，38 项跳过）和 Vite 前端构建通过；Windows 环境无 cargo/rustfmt，因此 Rust 编译与格式结论来自 GitHub CI。
- 未在生产 Runman 节点部署或实机验证。

## 上游 Runman 适配（v1.7.206）

- 上游修复估算测试跨北京时间午夜时的日桶不稳定问题，并更新 GitHub Actions Node.js Action。
- 上游为 Runman 加入恶意进程（如 XMRig）和控制面板处置入口，绑定实例代次并通过 guest exec 执行，不停止整个客机；服务端告警动作队列与前端资源防护状态也纳入 Runman。
- 无策略时的母机防火墙默认服务策略纳入 Runman，启用默认测速拦截与协议规则。
- 上游进展记录当时报告 936 项测试通过；这不代表本次 v1.7.207 改动已运行测试。

## Runman Rust v2 兼容历史（v1.7.205）

- Runman Rust v2 新增 root-only /v1/stop-overload；它在生命周期锁内复核同一 UUID 代次、运行状态及实时连接阈值，再写入 Stopped desired state 并停止实例。
- Watcher 连续过载策略支持 Runman，队列动作携带实例代次；Agent 不使用通用容器 CLI，目标替换、恢复或证据过期均安全取消。
- 修复 UDP socket 未计入 Runman 总连接数造成样本被连接策略拒绝的缺陷。
- v1.7.205 时，Runman 尚未提供独立 upperdir 指标，也未具备端到端进程/文件代次校验的清理；相关能力现已补齐，但指标口径和 allowlist 范围仍有明确边界。
- 兼容性为源码与自动化验证，不代表已在生产 Runman 节点部署或实机验证。

- 基于 fork origin/main v1.7.202 完成 guest exec、代次绑定扫描与网络隔离、交互 shell 卡片/MOTD、单实例手动/自动限速、磁盘 I/O 和网络指标适配。
- 补齐自动滥用检测：需要两次新鲜相关证据并复核实例 UUID 代次和进程启动代次后，才隔离 Runman 自有 veth；服务端只接受 default 项目、规范 VM UUID 和 v4 实例代次。
- 补齐 SSH 认证前 Banner（含 sshd 配置/读回/重载校验）、guest UDP socket 计数与进程引用归因、CPU offender 采样、Runman 专属 cgroup-v2 CPU/内存/I/O guards、VMess/Trojan 与测速策略接入，以及管理员复核后的 SOCKS 指定 PID 停止。
- 按需与告警触发的 Runman 深度快照、容器连接证据时间线与运维历史回放、管理员定向用户登录提醒均绑定报告代次。
- Runman 分开报告 sparse disk.img 已分配块和 overlay upperdir/up 已分配块；不宣称等同 Podman writable layer。
- 前端从合并后的最新 main 重建静态资源；生产节点没有在本次源代码发布中升级或验证。

## Incus 卡住实例巡检与测试回归修复（v1.7.202）

- 修复 Incus 运行时健康检查门禁（`_incus_stop_guard` 与 `stop_preflight`）相关的单元测试回归。
- 重新构建前端静态资源至 `server/static/`，确保 13 项浏览器回归与 891 项全量测试完全通过。
- 解决生产环境因 CI 失败导致持续 15 分钟轮询重试拉取镜像的异常，平滑交付稳定版本。
