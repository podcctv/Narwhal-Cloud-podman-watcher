# 当前进展与待办

更新时间：2026-11-05（Asia/Shanghai）

## 阶段一：Rust/Incus 容器 cgroup 进程挂起冻结、出站 UDP 专项阻断与网卡反欺骗（v1.8.4）

- **阶段一（P0 · 核心防线）全链路落地**：
  - 需求背景：用户要求按“阶段 1、2、3 顺序实施”，全面升级 Rust (Runman)、Incus 与 Podman 容器的深度管控、网络封锁与应急阻断能力。
  - **核心特性实装**：
    1. **cgroup v2 进程冻结挂起与解冻 (`client/container_freeze.py`)**：
       - 精确绑定容器实例代次（Runman UUID / expected_start_ticks / Incus lxc.payload），定位专属 `cgroup` 边界。
       - 通过 `cgroup.freeze`（值 1/0）触发原子冻结/解冻，并在超时保护下轮询读回 `cgroup.events`（`frozen 1` / `frozen 0`），超时自动安全回滚。
       - 瞬间定格所有进程/线程，内存现场与取证状态完好保留，不杀进程、安全可逆；写入 `/var/lib/narwhal-agent/container-freeze.json` 状态日志。
    2. **出站 UDP 专项阻断黑洞 (`client/udp_guard.py`)**：
       - 借助 `nsenter -t <pid> -n` 精准进入容器网络命名空间，基于 nftables 表 `inet narwhal_udp_guard`（或 iptables fallback）构建出站 UDP 黑洞。
       - 阻断恶意 UDP 洪水与 DNS/NTP/CLDAP 放大攻击，同时精准放行回环 (`lo`)、已建立连接 (`ESTABLISHED,RELATED`)、可选 53 端口 DNS 解析与入站 TCP/SSH 管理通道，避免全断网误杀。
       - 写入 `/var/lib/narwhal-agent/udp-blackhole.json` 状态日志。
    3. **宿主机 Veth 源地址反欺骗校验 (`client/anti_spoof_guard.py`)**：
       - 在宿主机侧设置容器网卡接口 `net.ipv4.conf.<veth>.rp_filter=1`（严格逆向路径校验）。
       - 在宿主机 Forward 链注入 nftables 表 `inet narwhal_antispoof` 规则，严禁容器通过 Raw Socket 伪造未分配的源 IP 发包。
       - 写入 `/var/lib/narwhal-agent/anti-spoof.json` 状态日志。
    4. **Server API 契约与全状态遥测接入**：
       - `server/app.py` 中的 `set_container_disposition` 支持新指令：`freeze_container`、`unfreeze_container`、`apply_udp_blackhole`、`release_udp_blackhole`、`apply_anti_spoof`、`release_anti_spoof`。
       - `client/agent.py` 遥测上报集成 `freeze_guard`、`udp_blackhole` 与 `anti_spoof` 状态，实时回传至控制中心。
    5. **前端 UI 控件与状态徽章即时呈现**：
       - `ContainerStateBadges.tsx` 动态展示 `❄️ 进程已挂起`、`🛡️ UDP黑洞` 与 `🔒 源IP防伪造` 状态。
       - `ContainerDrawer.tsx` 新增专属“容器内核防护与应急阻断 (Phase 1 核心防线)”控制磁贴，支持一键挂起/解冻、一键实施/解除 UDP 阻断，并提示 Veth 防伪造保护状态。
- **验证结论**：
  - 前端 `npm run build` TypeScript 编译与 Vite 生产打包 100% 成功，产出 `ContainerDrawer-BQ943_mx.js` 等更新文件。
  - `python -m compileall` 零报错通过。
  - 10 项全新专项单元测试（`test_container_freeze.py`, `test_udp_guard.py`, `test_anti_spoof_guard.py`）与服务端集成单测（`test_server_runtime.py`）全部 100% 绿色通过。

## 全面实装 Cyberpunk Bento Glow 极客黑金卡片大盘与极简顶栏（v1.8.3）

- **痛点根治与顶层多层嵌套标题终极精简**：
  - 需求背景：用户反馈原页面顶层堆叠了 4-5 层重复标题与大段调度说明，导致屏幕纵向高度被过度挤占，必须向下滚动多屏才能看到第一台母机；母机卡片质感生硬、缺少现代设计感。
  - 用户审阅并批准了 `tcping_mockup_preview.html` 中的**方案一：极客黑金 Bento 卡片（Linear/Raycast 质感）**。
- **现代化 Bento Glow 架构核心特性**：
  1. **顶层多层嵌套彻底归一，直降 400px+ 纵向高度**：
     - 彻底切除 `activeTab === 'reach'` 下旧版冗余的 `<section className="tcp-r-hero">` 与 4 个大方块。
     - `ReachCheckPanel` 顶栏重构为流式现代化 Bento 顶栏：集成了 🌐 全球大盘标题、1小时自动轮询微标、4 枚紧凑流动 KPI 徽章（巡检主机、三网畅通、疑似受阻、探针配额）、省份测速跳转、API Key 绑定与一键全量巡检。
     - 将原先占半屏的配额调度说明收敛为优雅的单行微型信息条，用户打开页面首屏即可立刻查看多台母机卡片。
  2. **极客黑金 Bento Glow 现代卡片实装**：
     - 卡片外观采用 `rounded-2xl` 边缘微光、柔和深暗黑质感与多色发光呼吸灯（`.glow-emerald`、`.glow-rose`、`.glow-amber`、`.glow-purple`）。
     - 智能国家/地区旗帜识别（🇭🇰、🇯🇵、🇺🇸、🇸🇬、🇩🇪、🇬🇧、🇰🇷、🇹🇼、🇸🇪 等），机房地域一眼可知。
     - 三段式栅格精准解耦排版：
       - 左区 3 列：V4/V6 IP 双轨纵向排布，间距行高自洽，彻底根除徽章遮挡叠字。
       - 中区 3 列：V4/V6 可达性胶囊独立排布，清晰区分 IPv4 与 IPv6 判定。
       - 右区 6 列：三大运营商（电信 4134、联通 4837、移动 9808）与全球核心均延的 Bento Grid 磁贴，双轨时延多级平滑变色（绿/蓝/黄/红），超时明确标识。
     - 操作按钮永远常驻首屏右上侧，就地抽屉手风琴流畅展开。
- **验证结论**：
  - 前端 `npm run build` TypeScript 编译与 Vite 生产构建 100% 零报错通过，静态资源完整打包输出（`ReachCheckPanel-p2tEKNAf.js` 等）。
  - 后端全量 17 项可达性单测 `tests/test_reach_monitor.py` 100% 绿色通过。

## TCP PING 彻底告别超宽表格，全面重构为现代横向流式矩阵卡片（Horizon Flow Card）（v1.8.2）

- **痛点根除与全新卡片式交互架构**：
  - 需求背景：用户反馈原 9 列表格由于固定跨度太宽产生难看的横向滚动条；第一列公网 IP 与双栈徽章挤在一块发生叠字遮挡；操作按钮被推到表格最右侧，必须费力横向滚动才能看到和点击。
  - 用户审阅并批准了 `tcping_card_design_proposals.md` 中的**方案一：横向流式响应式矩阵卡片（Horizon Flow Card）**。
- **现代化卡片架构核心特性**：
  1. **彻底消除横向滚动条（0 水平溢出）**：
     - 彻底废弃带有 `overflow-x-auto` 的传统硬编码 `<table>` 结构，全面转向现代化 CSS Grid / Flexbox 独立卡片流（`space-y-3.5`）。
     - 无论是 1920 高清屏、1366 笔记本屏或平板移动端，卡片宽度自洽适配视口，不产生任何横向滚动条。
  2. **操作按钮永远常驻视口右侧首屏**：
     - 刷新与查看详情按钮固定置于每张卡片的头部右上方（`ml-auto`），与宿主机标题同排，用户无需滑动任何滚动条，一眼即见、直接可点。
  3. **彻底根除文字重叠与拥挤**：
     - 卡片内容划分为独立的 3 个栅格槽位：左区 3 列排布 V4/V6 公网 IP；中区 4 列清晰呈现 V4/V6 可达性胶囊；右区 5 列采用 4 分格微型数据磁贴展示电信、联通、移动与全球均延。
     - 各元素拥有自洽的边距与行高，彻底告别文字遮挡。
  4. **就地折叠手风琴（In-Place Seamless Accordion）**：
     - 点击“查看详情”后，卡片底部优雅平滑向下推开，一体化内嵌诊断结论条、IPv4/IPv6 切换、关键概览指标、排错建议与全球 18 节点分布卡片；再次点击平滑收起。
- **验证结论**：
  - 前端 `npm run build` TypeScript 编译与 Vite 生产构建 100% 零报错通过，静态资源完整打包输出（`ReachCheckPanel-C4R1iz-l.js` 等）。
  - 后端全量测试与可达性专项单测均保持完全兼容。

## TCP PING 页面交互重构、就地卡片展开、V4/V6 基准对齐与智能 ICMP 兜底（v1.8.1）

- **就地卡片展开（In-Place Accordion Sub-row）与移除冗余探测表单**：
  - 彻底移除无业务意义的“自定义目标实时探测”表单与预设按钮，将 TCP PING 页面完全收敛聚焦于集群母机巡检。
  - 重构“查看详情”逻辑：点击后直接在被选中的母机行下方展开 Accordion 子行（`<tr key={`${item.host_id}-details`}>`），就地呈现该宿主机的综合可达性判定、IPv4/IPv6 双栈切换、关键指标概览条、排错措施与全球各区域 18 节点探测明细，彻底终结以前需要从 28 台母机列表一直滑到底部查看的繁琐操作。
- **解决巡检时间“全显示刚刚或破折号”问题**：
  - 排查根因：服务端原先仅返回时间戳 `checked_at`，前端因读取未定义的 `checked_at_iso_utc8` 兜底降级全部显示为字符串“刚刚”。
  - 服务端改进：`get_reachability_summary` 与 `get_reachability_host` 新增 `checked_at_iso_utc8` 与 `checked_at_v6_iso_utc8` 字段，格式化为标准北京时间（UTC+8）。
  - 前端改进：新增 `formatInspectionTime` 动态计算相对时间（如 `刚刚`、`5分钟前`、`2小时前`）并在第一行展示精确时间 `HH:mm:ss`，Tooltip 悬浮呈现完整格式化时间。
- **彻底消除 V4 和 V6 跨列错位**：
  - 排查根因：表格在窄屏或运营商列中缺少 `whitespace-nowrap`，导致某些列中 V4 的 `ms` 发生折行（高度膨胀至 40px+），而邻列未折行（高度 20px），造成双栈行跨列高低不一严重错位。
  - 前端改进：所有表格列（开放端口、可达性判定、电信、联通、移动、全球均延、巡检时间）全部采用成对的 `h-6 flex items-center whitespace-nowrap` 固定高度容器包裹 V4 与 V6，确保双栈每行水平基线对齐到像素级。
- **操作列刷新按钮重构与即时响应**：
  - 按钮尺寸从原先极小的 `p-1`（12px 图标）扩大为清晰易按的 `px-2.5 py-1 text-xs`，增加显式文案 `刷新` / `检测中`。
  - 引入单机触发加载状态 `triggeringHostId` 与旋转图标动画，提供即时视觉反馈。
  - 服务端 `/api/v1/reachability/trigger` 针对指定 `host_id` 改为同步等待测试完成并直接在响应体中返回最新 `item`，前端无需盲目等待，测完立即可见。
- **解决误判“全网连接超时/端口未放行”与智能 ICMP Ping 兜底**：
  - 排查根因：原先端口发现逻辑遍历容器 report 的内部私有 `listening_ports: [22]`，如果宿主机未暴露该端口，就会导致探测该端口全网拒绝报连接超时。
  - 端口发现优化：严格过滤容器内部未映射端口，仅采集 `gfw_states` 已验证端点、容器 `network_exposure` 宿主机映射端口或宿主机防火墙监听端口。
  - 智能 ICMP 回退机制：当选取的 TCP 端口探测全网超时或被拒绝时，自动回退发起 ICMP Ping 探测。若主机网络良好 Ping 连通，自动将协议修正为 `PING` 且判定为正常通畅，消除误报。
- **验证结论**：
  - 前端 `npm run build` TypeScript + Vite 构建顺利通过，静态资源完整打包输出。
  - 全量 971 项后端单元测试 100% 绿色通过（`Ran 971 tests in 84.773s. OK (skipped=43)`）。
  - `tests/test_reach_monitor.py` 17 项可达性单测（含 ICMP 回退与时间格式化）全绿。

## 全面启用 SemVer 规范、双栈 IPv4/IPv6 并行探测与全景可达性（v1.8.0 里程碑）

- **全面启用 SemVer 2.0.0 规范，解决小版本累加膨胀问题**：
  - 针对历史自动化提交中补丁号单调递增至 222 的无序现象，制定清晰的 Major.Minor.Patch 规则：重大破坏性变更升 Major（2.0.0），重大业务模块或全链路子系统闭环升 Minor（1.8.0），日常 Bug 修复升 Patch（1.8.1+）且约束在 0~99 以内。
  - 随着全球 18 区域三网可达性、双栈探测、Token 调度与脱敏全功能集大成，正式晋级为 **v1.8.0** 里程碑。
- **双栈机器（IPv4 + IPv6）全链路探测与展示**：
  - 需求背景：部分高性能与优质线路宿主机具备双栈（IPv4 与 IPv6）公网 IP。旧版巡检仅提取首个可用 IP（默认偏好 IPv4），无法度量中国大陆三大运营商对宿主机 IPv6 栈的连通性与时延差异。
  - Token / 探针额度用量调研与数学建模优化：
    1. **额度限制约束**：Globalping 匿名公共 IP 接口严格限制每小时 250 点（Credits），每探测 1 个区域消耗 1 点。集群包含 28 台母机。若双栈机器无节制分别执行两轮 8 点（或 16 点）测试，每台消耗 16 点，28 台合计高达 $16 \times 28 = 448$ 点/小时，将迅速击穿 250 点上限并触发 HTTP 429。
    2. **精准分栈预算模型（Dual-Stack Smart Budgeting）**：
       - 单栈机器：分配 8 点（国内三网 3 节点 + 海外核心 5 节点）。
       - 双栈机器：在无专属 API Key 情况下，总点数严格锁定为 **8 点/台**：
         - **IPv4 栈**：分配 5 点（中国电信、中国联通、中国移动 + 亚太香港 + 美西洛杉矶）。
         - **IPv6 栈**：分配 3 点（中国电信、中国联通、中国移动）。
         - 单机合计点数：$5 + 3 = 8$ 点/台。
       - **集群全局消耗**：$28 \text{ 台} \times 8 \text{ 点/台} = 224 \text{ 点/小时} \le 250 \text{ 点/小时}$，安全余量 26 点/小时，在零触发 429 限流的前提下，实现集群所有双栈母机国内三网电信/联通/移动 V4 与 V6 毫秒级时延全覆盖！
       - 配置免费专属 API Key 后自动解锁全量 18 区域双栈探测。
  - 服务端改进（`server/reach_monitor.py`）：
    1. **数据表平滑迁移**：在 `host_reachability` 与 `host_reachability_history` 增加 `target_v6`, `port_v6`, `protocol_v6`, `verdict_v6`, `verdict_label_v6`, `verdict_desc_v6`, `stats_json_v6`, `results_json_v6`, `checked_at_v6` 等字段，`init_db` 内置自适应列探查与幂等迁移。
    2. **双栈目标发现引擎（`discover_host_targets`）**：遍历 `host_security` 接口清单、`reports` 网络地址、`gfw_states` 与 `host_client_ips`，精准识别并过滤私网/链路本地/Cloudflare 边缘 IP，同步提取验证过的公网 IPv4 与公网 IPv6。
    3. **自适应研判算法修正**：修复小样本（3 探针 / 5 探针 / 8 探针）预算模式下因探针数不足 14 而被误判为 `partial`（部分受阻）的 Bug；当国内三网全部通过且全部探针成功时，精准赋予“三网通畅”或“三网通畅·核心可达”绿色认证。
    4. **API 脱敏收敛**：`/api/v1/reachability/summary` 与 `/api/v1/reachability/host/{host_id}` 输出 `is_dual_stack`, `has_ipv6`, `target_v6`, `stats_v6`, `results_v6`；未登录访问时同时严格抹除 IPv4 与 IPv6 目标真实 IP。
  - 前端呈现改进（`ReachCheckPanel.tsx` & `HostReachabilityBadge.tsx`）：
    1. **集群巡检列表全景呈现**：
       - 宿主机列针对双栈母机展示高亮紫底 `双栈 IPv4/IPv6` 标识，纯 IPv6 机器展示 `纯 IPv6` 徽标。
       - 可达性判定列并列展示 V4 与 V6 双栈判定结果（如 `V4: 三网通畅`、`V6: 三网通畅`）。
       - 电信、联通、移动三大运营商列针对双栈机器分别提供 `V4: xxx ms` 与 `V6: xxx ms` 独立着色时延胶囊。
       - 全球均延列并列展示 V4 均延与 V6 均延。
    2. **18 区域明细双栈切换**：
       - 详情展开卡片支持一键在 `[IPv4 探测结果]` 与 `[IPv6 探测结果]` 之间无缝切换，动态联动展示各栈的 18 区域丢包、DNS/TCP 建连、TLS 及首包分段时延。
    3. **宿主机卡片徽标增强**：
       - Dashboard 宿主机卡片上的 `HostReachabilityBadge` 对双栈母机实时显示 `三网双栈 (V4: xxxms | V6: xxxms)`，一目了然。
- **验证结论**：
  - 前端 TypeScript / Vite 生产构建顺利通过，静态资源完整打包输出（`ReachCheckPanel-KKCSyHeO.js`, `Dashboard-BSVrg-b2.js` 等）。
  - `python -m compileall` 零报错通过。
  - `tests/test_reach_monitor.py` 扩展新增 3 项双栈发现、双栈预算调度与脱敏单测，15 项测试全量通过；`test_dashboard_auth.py` 与 `test_tcping.py` 68 项测试全绿。

## 未登录状态下三网可达性检测 IP 隐匿与测速按钮权限保护（v1.7.221）

- **未登录态安全边界加固与数据脱敏**：
  - 需求背景：三网可达性（Reach Check）在公开页面（`/tcping`）对访客开放时，需要避免暴露集群母机真实公网 IP，并严禁未授权访客触发测速操作消耗 Globalping 探针额度。
  - 服务端改进：
    1. 在 `server/dashboard_auth.py` 新增轻量级身份查询接口 `GET /api/v1/auth/status`，仅返回 `{ authenticated: bool, username?: str, role?: str }`，会话未登录时不抛出 401，不触发强制重定向。
    2. 中间件白名单放行公共只读端点：允许未登录用户 GET 查询 `/api/v1/reachability/summary`、`/api/v1/reachability/quota` 以及 `/api/v1/reachability/host/{host_id}`。
    3. 服务端脱敏零泄漏保障：当请求未携带有效登录会话时，`get_reachability_summary` 与 `get_reachability_host` 自动将母机 `target` IP 置空（`""`），同时将探测明细 `results[].ip` 置空，从根源杜绝未授权用户在网络抓包中窥探母机真实 IP。
    4. 动作严格权限收敛：`POST /api/v1/reachability/trigger`（全量/单机巡检）与 `POST /api/v1/reachability/settings`（API Key 保存）增加显式会话检查，未登录请求坚决返回 401。
  - 前端改进：
    1. `frontend/src/api/client.ts`：新增 `getAuthStatus`，支持无感知获取用户登录态。
    2. `ReachCheckPanel.tsx`：
       - 当用户未登录（`!isLoggedIn`）时，母机巡检列表隐藏宿主机 IP，18 区域明细卡片隐藏探针/目标 IP，快速选机隐藏 IP 标注，诊断总结与复制报告屏蔽真实 IP。
       - 隐藏管理员测速按钮：“立即全量巡检”、“配置 API Key”、表格行内“单独重新检测此机”。
       - 自定义探测面板中的“⚡ 开始可达性检测”测速按钮替换为友好的“登录后测速”引导链接，禁用未授权的表单输入与预设，杜绝未登录用户消耗配额。
    3. `TcpingPage.tsx` 与 `HostReachabilityBadge.tsx`：分别接入认证状态感知，Dashboard 弹窗保持完全可见，公开页面执行严格脱敏。
  - Rust Agent 接入支持确认：
    - 明确确认：当前 Watcher 的 Client Agent 早在 v1.7.197 ~ v1.7.211 已完整实现并更新支持 Runman Rust v2 的接入与全链路管控，覆盖自动探活、Socket 通信（`/run/narwhal-agent/connlimit.sock`）、代次锁、带宽保护、准入隔离与连接过载停止。
- **验证结论**：
  - 前端 TypeScript / Vite 生产构建顺利通过，静态产物完整更新（`ReachCheckPanel-PpWfvC8o.js`, `index-uykJ8cwr.js` 等）。
  - `python -m compileall` 零报错通过。
  - `tests/test_reach_monitor.py` 新增未登录脱敏与越权阻断测试，全量 12 项单测全绿。

## 探针配额受限彻底修复、平滑分散调度与历史快照保护（v1.7.220）

- **探针配额受限（HTTP 429）与“0 节点”展示根因评估与修复**：
  - 现象：生产环境母机卡片与 TCPPING 页面提示 `探针配额受限`；点击展开详情时展示 `各区域及运营商探测结果 0 节点`。
  - 根因分析：
    1. **并发突发消耗击穿 Globalping 限制**：Globalping 匿名公共 IP 接口严格限制每小时 250 点（Credits），每探测 1 个区域消耗 1 点。旧版巡检在几十秒内对集群全量 28 台母机并发请求，瞬间消耗高达数百点，迅速耗尽 250 点额度并触发 HTTP 429。
    2. **429 级联覆盖灾难（关键根因）**：当遇到 HTTP 429 时，旧版代码将空结果 `results: []` 与 `verdict_label: "探针配额受限"` 强行写入 `host_reachability` 表，将之前所有健康的测速数据与 18 区域时延历史记录彻底冲毁，导致前端详情显示为“0 节点”。
  - 修复：
    1. **历史快照绝对保护（Non-Destructive Guarantee）**：在 `perform_host_reach_check` 中，当触发限流或点数耗尽时，坚决不覆写 `host_reachability` 与历史表中的有效快照与区域明细；仅在没有任何历史数据的初始状态下记录排队中状态，彻底消灭“0 节点”空白情况。
    2. **平滑时序分散调度算法（Staggered Pacing Scheduler）**：将全集群 28 台母机均匀分散至 3600 秒的整点时间轴上（`间隔 = 3600 / 28 ≈ 128 秒/台`），每约 2 分钟仅测试 1 台母机，每小时稳定消耗 ~224 点，严格控于 250 点/小时上限内，杜绝突发 429。
    3. **自适应预算感知与降级（Credit-Aware Budgeting）**：引入 `_rate_limit_state` 实时跟踪 `X-Credits-Remaining` 与 `X-RateLimit-Reset`，并通过 `/v1/limits` 精确同步。当剩余点数 $< 8$ 时自动降级为中国三网 3 节点测试（仅消耗 3 点）；$< 3$ 点或遇到 429 时主动休眠退避，坚决不发送无谓请求。
    4. **支持配置免费专属 API Key**：支持通过环境变量、`system_settings` 表或 Web 界面直接配置 `GLOBALPING_API_KEY`（免费注册获取），一键升级至 500~2500+ 点/小时高额度。
    5. **前端配额态势仪表盘与空态友好呈现**：在 `ReachCheckPanel.tsx` 增加配额充裕/紧张/受限状态横幅、重置倒计时、平滑调度规划说明与一键 Key 配置弹窗；在遇到历史配额受限时显示排错指引与恢复说明，告别空态困惑。
- **验证结论**：
  - 前端 TypeScript / Vite 生产构建顺利通过，静态产物完整更新（`ReachCheckPanel-G_9YZIjx.js`, `index-Du5M1gRM.js` 等）。
  - `python -m compileall` 零报错通过。
  - `tests/test_reach_monitor.py` 10 项单元测试全量通过，覆盖非破坏性历史保留、预算感知降级、API Key 设置与平滑调度。

## 节点 Ping / 全球三网可达性全链路评估与完善修复（v1.7.219）

- **节点 Ping 与自动化巡检根因评估与修复**：
  - 现象：生产环境 13 台已测母机中，多达 7 台报告 `timeout: 全网连接超时/端口未放行`；NAT 节点（ZaoZhuang-BGP-NAT、MiaoYun-NAT）被错误记录为 Cloudflare Anycast IP 并导致探测失败；母机卡片与 TCPPING 页面部分时延数据显示为空白或破折号（—）；巡检单机执行耗时过长。
  - 根因分析：
    1. **Cloudflare CDN 代理 IP 污染**：母机通过 Caddy 反代或 Cloudflare 域名连接服务端时，`server/app.py` 之前直接读取 `x-forwarded-for`，未优先读取 `cf-connecting-ip`、`x-real-ip` 与 `x-narwhal-proxy-peer`。同时 `server/reach_monitor.py` 的 `is_public_ip` 未过滤 Cloudflare Anycast 网段（如 `104.16.0.0/13`, `162.158.0.0/15`, `172.64.0.0/13`），导致 Cloudflare 节点代理 IP 误被作为目标写入 `host_client_ips`，外部探测 Cloudflare 代理节点端口自然超时。
    2. **全表扫描磁盘 I/O 阻塞与历史陈旧端口污染**：`discover_host_open_ports()` 之前执行 `SELECT payload_json FROM reports WHERE host_id=?` 全表扫描，在 1.7GB 数据库中遍历数万条历史报告，单节点耗时达数十秒，导致循环卡死；同时收集了数月前的已关闭瞬态端口（如 33508、4443、11111）。
    3. **探测协议与端口服务类型不匹配**：Globalping 仅支持 `[ping, traceroute, dns, mtr, http]`，旧版对所有端口一律发 `type: "http"`。在探测 22 (SSH) 等非 HTTP 端口时，虽然 TCP 三次握手成功，但后续 HTTP 应用层解析抛出协议不匹配异常导致误报超时。此外对于 0 开放端口的主机缺乏 ICMP Ping 探测能力。
    4. **前后端字段命名契约不一致**：`server/reach_monitor.py` 在 `stats` 中仅提供 snake_case，缺少 `cnTelecomMs`、`cnUnicomMs`、`cnMobileMs`，导致前端详细表格中的电信、联通、移动时延全部显示为破折号（—），聚合卡片显示 0。
  - 修复：
    1. 在 `server/reach_monitor.py` 引入完整 Cloudflare 网段过滤与 `extract_client_ip()` 智能提取器，在 `server/app.py` 统一接入，杜绝 CDN 代理 IP 作为节点目标。
    2. 将 `discover_host_open_ports()` 优化为仅查询最新单条报告与最新 `host_security`，将端口发现耗时从 30s 缩减至 0.07s，并彻底过滤已关闭历史端口。
    3. 实现 TCP 握手（根据 `timings.tcp` 精确研判建连时延）与 ICMP Ping 双模自适应探针，对无开放公网端口的主机自适应切换为 `type: "ping"`，准确度量 18 区域丢包率与 RTT。
    4. 对齐前后端数据模型，`stats` 输出双格式并补充三大运营商独立毫秒数；`/api/v1/reachability/summary` 补充聚合统计字段；前端 `HostReachabilityBadge` 与 `ReachCheckPanel` 完善 ICMP 协议标识与数据水合。
- **验证结论**：
  - 前端 TypeScript / Vite 生产构建顺利通过，静态产物完整更新。
  - `python -m compileall` 零报错通过。
  - `tests/test_reach_monitor.py` 新增 SSRF/Cloudflare 过滤、真实 IP 提取、PING/TCP 解析全量通过。
  - 核心单测套件通过（155 测试全部 OK）。

## 容器采集 NameError 崩溃与节点长期停报快照根因修复（v1.7.218）

- **容器采集 NameError 与循环崩溃根因排查修复**：
  - 现象：生产环境全集群 26 台拥有容器的母机持续处于“仅保留过期历史快照”（容器采样停留于 15~17 小时前），母机心跳正常（v1.7.203）但容器数据全无上报，升级波次超时（`status: failed, Client 未在 20 分钟内回报升级结果`）。仅有无容器的纯 NAT 节点（MiaoYun-NAT、ZaoZhuang-BGP-NAT）升级成功并上报正常。
  - 根因分析：
    1. 在 `client/agent.py` 的 `collect_container()` 函数内（第 8886 行），调用 `_refine_socks_listener_evidence(..., instance_id=str(container.get('instance_id') or ''))` 时，直接引用了未在作用域内定义的变量 `container`，导致运行任意容器采集时直接抛出 `NameError: name 'container' is not defined`。
    2. 主循环 `for c in containers:` 缺少独立的异常捕获保护，单容器采集抛错直接穿透终止主进程，触发 systemd 每 5 秒重启并陷入无休止崩溃循环，`/api/v1/report` 完全无法发出。
    3. `client/agent.py` 顶层缺少 `from pathlib import Path` 导入，导致启动读取 `managed-update-result.json` 静默报错。
    4. `collect_security_summary()` 在 Hysteria 2 流量评估时存在未定义的 `traffic_direction` 隐患。
  - 修复：
    1. 在 `collect_container()` 签名中增加 `instance_id: str = ""` 参数，并将其传递至 `_refine_socks_listener_evidence`（兼容 `instance_id or container_id`）。
    2. 在 `main()` 的容器采集循环中传入 `instance_id`，并使用独立 `try...except` 块包裹容器扫描，捕获异常后生成降级存活快照，坚决不因单容器异常导致全量采集与上报中断。
    3. 修复 `client/agent.py` 顶层 `from pathlib import Path` 导入。
    4. 修复 `collect_security_summary` 中的 `traffic_direction` 流量偏向变量计算。
- **验证结论**：
  - 本地 Python 复现 `collect_container` 触发 `NameError`，修复后测试通过。
  - 新增 `test_collect_container_execution_safety` 与 `test_security_summary_hy2_traffic_direction_safety` 自动化回归用例。
  - 全量 958 项单元测试全部通过。

## 客户端更新免 apt/Podman 重复探测与错误诊断增强（v1.7.217）

- **无运行时/NAT 探针节点更新免 Podman/apt 检查修复**：
  - 现象：纯探针/NAT 节点（如 ZaoZhuang-BGP-NAT 等未安装 Docker/Podman/Incus 运行时的母机）在执行 `install-client.sh update` 时，由于脚本前置运行时探测命中 0，误触发 `apt-get update && apt-get install -y podman` 与 python-venv apt 安装，在旧系统或无外网源环境下直接抛出非零退出码导致更新回滚失败（`status: failed`）。
  - 修复：在 `scripts/install-client.sh` 中对 `MODE == "update"` 严格跳过 Podman、python3-venv、nftables 等系统级包管理器重复检查与安装。节点已有运行中的 python3-venv 与系统依赖，仅需安全替换 client agent 源码与 requirements；在 `scripts/managed-client-update.sh` 中增加异常退出码捕获，确保 `failure_message` 不为空。
- **验证结论**：
  - Python `compileall` 无报错。
  - `tests/test_managed_upgrade.py` 覆盖更新流水线全部通过。
  - 全量 956 项单元测试全部通过。

## 灰度多源晋级、升级即时回执与 pip 免探测提速（v1.7.216）

- **灰度发布多源验证与卡死根因修复**：
  - 现象：生产环境 Campaign 150 锁定灰度节点 RFC JINX，因该节点升级动作超时失败后仍持续上报心跳（`canary_fresh == True`），协调器既不轮换灰度角色，又因未校验集群中已有已验证节点（ZaoZhuang-BGP-NAT、MiaoYun-NAT 均已成功运行 v1.7.215 并达到 `verified`），导致 Campaign 长期卡在 `canary` 状态，拒绝向其余 25 台节点派发波次更新。
  - 修复：
    1. 在 `server/fleet_updates.py` 中重构晋级判定：当指定灰度节点尚未 verified 时，主动遍历本活动中所有达到 `status='verified'` 且通过健康观察期（`observed_healthy_version`）的候选节点，一旦存在任何已验证健康的节点，立即将灰度角色迁移至该节点并直接晋级至 `rollout`，解除全集群升级被单一慢节点阻断的死锁。
    2. 将动作超时回收阈值从 600 秒扩展至 1200 秒（20 分钟），充分对齐 systemd 的 15 分钟超时窗口并为多容器母机的首次全量采样预留裕度。
- **Client 启动即时心跳回执与 PyPI 免探测**：
  - 现象：客户端在完成升级脚本重启后，须等待首轮数十个容器采集完整遍历后才上报 `/api/v1/report`，在复杂母机上耗时偏长，容易超出服务端动作等待窗口。
  - 修复：
    1. 在 `client/agent.py` 启动阶段检测 `/opt/narwhal-monitor/managed-update-result.json`，若状态为 `installed` 则在容器采集循环启动前立即发送 `/api/v1/actions/result` 刷新 `running` 进度与当前版本，保活动作窗口。
    2. 在 `scripts/install-client.sh` 中优化常规 `update` 流程，避免在每次常规升级时重复执行 `pip install --upgrade pip`，消灭受限网络环境下的额外 PyPI 网络阻塞风险。
- **验证结论**：
  - Python `compileall` 无报错。
  - 新增 `test_campaign_promotes_when_any_campaign_node_is_verified` 覆盖多源灰度晋级场景。
  - 全量 956 项单元测试全部通过（0 失败，43 项按环境正常跳过）。

## 舰队波次升级死锁修复与容器采集并发/时延优化（v1.7.215）

- **舰队波次升级死锁根因修复**：
  - 现象：全集群 25 台节点停留在旧版本（v1.7.203），升级活动仅向首波 3 台节点分发动作后由于节点执行超时，`allow_new_wave` 保持 `False`，导致其余 22 台待升级主机永久被跳过。
  - 修复：重构 `server/fleet_updates.py` 波次终态判定。当当前波次所有节点均达到终态（`status in ('verified', 'failed')`）时，经验证节点 soak 巡检后立即递增 `rollout_wave`、清空 `wave_hosts` 并恢复 `allow_new_wave = True`。失败节点按退避进入 `retry_at` 等待重试，彻底解除 1~3 台慢节点对全集群升级进度的卡死；将超时回收阈值优化至 600 秒（10 分钟）。
- **Client 容器采集长耗时卡死与动作轮询饥饿解决**：
  - 现象：母机包含数十个容器时，单次采集耗时达数小时（`reports` 采样严重落后 15 小时，前端提示“仅保留过期历史快照”），导致升级指令在 30 分钟内无法被 client 轮询执行。
  - 根因：Incus 容器在未安装/未运行 `incus-agent` 时，每条 `exec` 阻塞 30 秒。空闲容器在 `/proc/net` 确认连接为 0 时仍重复触发 `ss` 回退探测；且 `process_security_actions` 仅在 `main` 循环末尾调用，容器扫描耗时长时无法轮询动作。
  - 修复：
    1. 在 `client/agent.py` 中引入 `_unresponsive_exec_containers` 熔断机制，单容器发生一次 exec 超时后当轮其余 exec 指令立即跳过。
    2. 消除空闲容器的假性回退，当 `pid > 0` 且 `/proc/net` 可读时严格信任内核套接字表，禁止多余容器内 `exec`。
    3. 默认运行时指令超时从 30s 缩短至 10s（下限 3s）。
    4. 在 `main` 循环入口及容器扫描遍历中每 10 秒（`action_poll_interval`）主动轮询并执行 `process_security_actions`，杜绝动作轮询饥饿。
- **Reach Check 全球三网可达性 0 节点即时水合与详情交互**：
  - 服务端 `/api/v1/reachability/summary` 在各主机结果中直接返回 18 区域探测详情数组 `results`。
  - 前端 `ReachCheckPanel.tsx` 挂载时自动从每小时巡检成果水合数据，消灭初始“0 节点”展示；快速选机或点击巡检列表“查看详情”即时切至对应母机 18 区域时延与三网网络状态。
- **验证结论**：
  - 前端 TypeScript 生产构建编译成功（产物输出至 `server/static/`）。
  - Python `compileall` 无报错。
  - 全量 955 项单元测试全部通过（0 失败，43 项按环境正常跳过）。

## 可达性后台巡检线程安全与 CGNAT SSRF 严格隔离（v1.7.214）

- **后台巡检跨线程 SQLite 对象共享异常修复**：
  - 现象：`server/reach_monitor.py` 在 `run_hourly_reach_cycle` 中将主事件循环创建的 `conn` 传递给 `asyncio.to_thread(perform_host_reach_check, conn, host_id)`，运行时抛出 `SQLite objects created in a thread can only be used in that same thread`，导致全集群自动化每小时检测结果未能写入 `host_reachability` 表，前端 TCPPING 可达性页面展示为 0 节点。
  - 修复：重构 worker 线程调用链，将 `db_factory` 传入 worker 并在其内部独立创建与 `finally: conn.close()`，严格杜绝跨线程共享连接。
- **Globalping 异步测量轮询防早退完善**：
  - 修正当 Globalping API 预分配 18 个探针占位槽（status: in-progress）时误判定为已完成的逻辑，严格校验 `status == "finished"` 或全量探针终态，确保准确获取各区域 TTFB、TCP、DNS 与 TLS 时延。
- **SSRF 策略补充 RFC 6598 CGNAT 过滤**：
  - 在 `is_public_ip` 中补充 `100.64.0.0/10` 运营商级 NAT 网段过滤，防止将运营商私有网络暴露给外部公共探针。
- **单元测试补充**：
  - 新增 `tests/test_reach_monitor.py` 覆盖 SSRF/CGNAT 防护、公网 IP/开放端口发现、18 区域时延与诊断判定、以及跨线程数据库执行验证。

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
