# 当前进展与待办

更新时间：2026-11-06（Asia/Shanghai）

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

## 重构三网时延徽章与全景浮窗 (Popover) · 根治折叠截断 Bug（v1.8.10）

- **缺陷根因排查与闭环修复**：
  1. **折叠卡片下点击时延截断变形 Bug 根治**：
     - **根因**：母鸡卡片外部带有样式类 `.ui-contain-card { contain: layout style; }` 与 `overflow: hidden`。依据 CSS 规范，`contain: layout` 会强制为所有后代元素（包括 `position: fixed`）重新创建包含块，导致旧弹窗完全无法覆盖全屏，而是被死死挤压在 40px 高度的折叠标题栏内，严重挤压变形；且徽章渲染在母鸡折叠 `<button>` 内部，触发按钮嵌套与事件冒泡冲突。
     - **修复**：
       - 采用 **`ReactDOM.createPortal(..., document.body)`** 将小浮窗彻底挂载至最顶层 `document.body`，彻底逃逸任何卡片级 `contain: layout` 和 `overflow: hidden` 限制。
       - 将徽章触发器重构为 `<span role="button" tabIndex={0}>`，消除 HTML 按钮嵌套非法语法，并在点击与键盘交互时通过 `e.stopPropagation()` 严格阻断母鸡折叠/展开事件冒泡。
       - 实装智能视口碰撞检测与自适应翻转（Auto Flip），当屏幕下方空间不足时自动向上翻转。
  2. **落地「方案 A：极光脉冲 · 拟态胶囊 (Aurora Bento Capsule)」交互体验**：
     - **极光脉冲徽章**：采用双脉冲呼吸微光指示点（绿/黄/红三态）、微光渐变边框、`三网可达 182.4ms [ICMP]`，并带有平滑旋转小箭头，视觉精致高雅。
     - **三网 Bento 独立网格浮窗**：
       - 中国电信（蓝点）、中国联通（天蓝点）、中国移动（紫点）三网专属色块，精确呈现各自独立时延与丢包状态。
       - 包含全球 18 节点均延、最优时延、GFW 阻断状态与双栈网络说明。
       - 双栈机器提供 IPv4 / IPv6 实时一键切栈查看。
       - 底部提供相对时间戳（如“10分钟前巡检”）与「全网拓扑 →」（以 Portal 方式呼出全功能 18 节点探针分析）和「TCP 测速」入口。
