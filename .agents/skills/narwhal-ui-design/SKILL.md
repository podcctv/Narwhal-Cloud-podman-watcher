---
name: narwhal-ui-design
description: >-
  Comprehensive UI/UX design system, information architecture, button and form
  specifications, responsive PC/Tablet/Mobile layout rules, and E2E regression
  contracts for the Narwhal Cloud Container Watcher web interface.
---

# Narwhal Cloud UI/UX Design & Interaction System (v2.0)

This skill defines the visual language, information architecture, unified button/form specifications, responsive layout standards (320px–1920px), and regression invariants for the **Narwhal Cloud Container Watcher** web interface. All frontend refactoring and new features must strictly adhere to these standards.

---

## 1. Visual Aesthetics & Design Tokens

### Color Palette (Deep Slate Dark Theme)
- **Canvas Background (`--color-dark`)**: `#020617` (`slate-950`)
- **Surface Hierarchy**:
  - **Level 1 Card / Panel (`--surface-1`)**: `#0F172A` (` bg-slate-900/75` with `border-slate-800`)
  - **Level 2 Elevated / Interactive Row (`--surface-2`)**: `#172033` (`bg-slate-900` / hover `bg-[#172033]`)
  - **Level 3 Input / Inset Well (`--surface-3`)**: `#020617` / `#0B1220` (`bg-slate-950/90` with `border-slate-700/80`)
  - **Glass Overlay**: `rgba(15, 23, 42, 0.82)` + `backdrop-filter: blur(12px)`
- **Brand & Accent**:
  - **Primary Sky/Cyan**: `#38BDF8` (`sky-400`), `#0EA5E9` (`sky-500`), focus ring `#7DD3FC` (`sky-300`)
- **Semantic Status Tokens** (Always pair color with explicit text label — never convey state by color alone):
  - **Healthy / Verified (`emerald`)**: Text `#86EFAC` (`emerald-300`), Bg `rgba(6, 78, 59, 0.35)`, Border `rgba(16, 185, 129, 0.35)`
  - **Warning / Awaiting Recheck / Cooling (`amber`)**: Text `#FCD34D` (`amber-300`), Bg `rgba(120, 53, 15, 0.35)`, Border `rgba(245, 158, 11, 0.35)`
  - **Critical / Failed / Quarantined (`rose`)**: Text `#FDA4AF` (`rose-300`), Bg `rgba(136, 19, 55, 0.35)`, Border `rgba(244, 63, 94, 0.4)`
  - **Protection / Protocol Guard (`violet` / `sky`)**: Text `#C4B5FD` (`violet-300`) or `#7DD3FC` (`sky-300`), Bg `rgba(76, 29, 149, 0.3)` / `rgba(12, 74, 110, 0.35)`
  - **Stale / Offline / Unverified (`slate`)**: Text `#CBD5E1` (`slate-300`), Bg `rgba(30, 41, 59, 0.65)`, Border `#475569` (`slate-600`)

### Typography & Numeric Discipline
- **UI & CJK Body**: `'Fira Sans', Inter, -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Microsoft YaHei', sans-serif`
- **Monospace & Telemetry**: `'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace`
- **Tabular Figures (`tabular-nums`)**: Mandatory on all metrics, countdowns, timestamps, IP counts, bitrates, percentages, and currency values to prevent horizontal layout jitter during 10s live polling.

---

## 2. Information Architecture & Functional Layout

### Global Application Shell (`AppHeader` + Main Container)
1. **Top Brand & Utility Bar (`.app-header-top`)**:
   - **Left**: Brand mark (`NW`) + Title (`Narwhal Monitor`) + Unified Version Badge (`v1.7.x`) + Subtitle.
   - **Right (`role="group" aria-label="看板工具"`)**:
     - Global Search trigger (`打开全局检索`, `Ctrl+K`)
     - Live Polling `CountdownTimer` (10s ring, `暂停自动刷新` / `恢复自动刷新`, `立即刷新`, last refresh timestamp)
     - Session Logout button (`退出登录`)
2. **Unified Primary Navigation (`nav[aria-label="主导航"]`)**:
   - 8 Core Console Tabs (`button`, active state marked via `aria-current="page"`):
     1. `总览看板` (`dashboard`)
     2. `安全告警` (`alerts` — with live active alert count badge)
     3. `用户排查` (`investigation`)
     4. `数据统计` (`stats`)
     5. `经营分析` (`commerce`)
     6. `运维中心` (`operations`)
     7. `母机防火墙` (`firewall`)
     8. `系统设置` (`settings`)
   - 1 Public Standalone Link (`a.app-tcp-link`): `全国 TCP 测试` / `TCP 测速` (`/tcping`)

### View-Specific Functional Hierarchy
1. **总览看板 (`Dashboard`)**:
   - **Row 1 — KPI Summary (`KpiGrid`)**: 4 cards (`在线主机`, `活跃容器`, `活动安全告警` [clickable jump to alerts], `已隐藏旧快照`).
   - **Row 2 — Critical Quarantine Gate (`QuarantinePanel`)**: Conditional high-priority region (`违规活动隔离 · 待管理员复核`) with instance verification, bidirectional isolation status, and manual review/restore flow.
   - **Row 3 — Active Security Alerts (`SecurityAlertSection`)**: Live actionable container/host alerts with inline evidence, SOCKS password review (`SocksPasswordReview`), customer notice (`UserNoticeAction`), and manual stop/remediate actions.
   - **Row 4 — Host Security Telemetry (`TelemetrySection`)**: Per-host cards with search + pagination, 6 summary tiles (Traffic/Conn, Access/Abuse, Auto Control/Rollback, Host Audit, GFW Reachability Timeline), and expandable deep-dive panels.
   - **Row 5 — Host & Container Inventory (`HostContainerList`)**:
     - Sticky/Unified `DashboardToolbar` (Search input + 8 semantic filter chips + Grid/Table/Detailed view switcher + Expand/Collapse current page hosts).
     - Host group cards (with `HostDiskPressure` warning, `HostBandwidthPanel` manual/auto bandwidth config, runtime breakdown, and container cards/table).
     - Separate collapsible **Offline / Stale Snapshot Verification Area** at the bottom (never mixed with live actionable containers).
2. **容器详情抽屉 (`ContainerDrawer`)**:
   - Right slide-over drawer (`max-w-2xl` on desktop, `100vw` full-screen sheet on mobile) with sticky header, identity & owner editor, live CPU/Memory & Network ECharts, Resource Guard (`cpu`/`memory`/`io`) readback status, `AdmissionStatus`, `ConnectionEvidenceTimeline`, `ProtocolGuardEvidence`, and `DiagnosticPanel`.
3. **安全告警 (`AlertHistoryView`)**:
   - Multi-dimensional filter bar (Status tabs + Severity select + Alert Type select + Host select + Keyword search + Reset) -> Paginated audit cards with recovery duration & disposition receipts.
4. **用户排查 (`UserInvestigationView`)**:
   - Mother-host scoped filter bar (Host + 7/30/90d window + User/Container query) -> 5-column summary strip -> Concentration notice -> Left/Top User comparison table + Right/Bottom Container lifetime table (default 4 rows, expandable) -> Slide-over container event history drawer.
5. **数据统计 (`StatsAnalyticsView`)**:
   - Time window toolbar -> 4 aggregate KPIs -> Top Rankings (Traffic, CPU, Inbound IPs, Outbound IPs) with click-to-inspect container drawer.
6. **经营分析 (`CommerceView`)**:
   - Personal API Key configuration bar -> 5 Balance & Revenue KPI groups (`可用余额（不可提现）`, `托管总余额`, `托管锁定价值`, `托管可用余额`, `平台佣金率`) -> Machine profitability table -> UTC daily ECharts bar trend & ledger filter table.
7. **运维中心 (`OperationsView`)**:
   - 14 sub-modules navigation (`1 采集健康` to `14 告警复盘`) organized as a scannable pill/grid selector -> Contextual workspace for health rescan, action rechecks, `DiskCleanupPanel` + `DatabaseGrowthTrend`, traffic ledger, business policies (preview before save), dynamic baseline, incident timeline, log discovery wizard, fleet upgrades (canary/rollout/rollback), service availability, service listener inventory, backups, RBAC users/audit, and alert replay.
8. **母机防火墙 (`FirewallView`)**:
   - Scope tabs (`单台母鸡策略` vs `全体母鸡默认模板`) -> `FirewallNodePicker` (with search, status filter, and dirty-draft switch guard `alertdialog`) -> Dual verification banner (`母机 RFW 状态` vs `容器保护状态`) -> Desired Rule Editor form & table -> Abuse & Speedtest/CN-Risk protocol switches -> Live RFW readback comparison.
9. **系统设置 (`SettingsView`)**:
   - 2-column desktop / 1-column mobile cards: Narwhal Push & Buyer Notification Policy form, AbuseIPDB IP Reputation key & live tester, Telegram Bot management & proxy status, and `BuyerNotificationsView` audit table.
10. **全国 TCP 测试 (`TcpingPage` & `TcpingManage`)**:
    - Public split layout: Left/Top Source Host Catalog (search + scrollable cards) + Right/Bottom Result Workspace (Scope toggle `省级运营商` / `全部节点`, View switcher `全国地图` / `三网对比` / `节点明细`, CSV export, and interactive node detail modal).

---

## 3. Unified Button Design System

All buttons must use `type="button"` (unless submitting a `<form>`), include `cursor-pointer` when enabled, `disabled:cursor-not-allowed disabled:opacity-50`, and visible keyboard focus (`focus-visible:outline-2 focus-visible:outline-sky-300 focus-visible:outline-offset-2`).

### Button Variants
1. **Primary CTA (`btn-primary`)**:
   - High-emphasis solid fill for main form submissions and primary workflow actions (`登录控制台`, `查询 / 刷新`, `保存并同步`, `保存并应用到这台母鸡`).
   - Style: `bg-sky-400 text-slate-950 font-semibold hover:bg-sky-300 active:bg-sky-500 shadow-xs`
2. **Secondary Action (`btn-secondary`)**:
   - Tinted sky surface for standard operational actions (`请求只读复扫`, `预览影响`, `加入期望规则`, `发现并预览格式`).
   - Style: `border border-sky-500/40 bg-sky-500/10 text-sky-200 font-medium hover:bg-sky-500/20 hover:border-sky-400`
3. **Neutral / Utility (`btn-neutral`)**:
   - Slate surface for refreshes, navigation returns, cancel buttons, and secondary toggles (`刷新`, `返回总览`, `取消`, `清空搜索`).
   - Style: `border border-slate-700 bg-slate-800/90 text-slate-200 font-medium hover:bg-slate-700 hover:border-slate-600`
4. **Danger / Destructive (`btn-danger`)**:
   - Rose surface for container stop, rule deletion, or quarantine actions (`人工决定停止`, `删除`, `清理恶意进程`).
   - Style: `border border-rose-500/40 bg-rose-500/15 text-rose-200 font-medium hover:bg-rose-500/25 hover:border-rose-400`
5. **Filter Chip / Segmented Toggle (`btn-chip`)**:
   - Used in toolbars and sub-navigation (`aria-pressed` or `aria-current="page"`).
   - Inactive: `border border-slate-800 bg-slate-950/60 text-slate-400 hover:bg-slate-800/60 hover:text-slate-200`
   - Active: `border border-sky-500/50 bg-sky-500/20 text-sky-200 shadow-xs` (or semantic color variant for risk/protocol chips).

### Button Size Tiers & Touch Ergonomics
- **Touch Target Rule**: Primary navigation, header tools, login submit, dialog actions, and mobile full-width actions MUST maintain `min-h-11` (`44px`) or `h-12` (`48px`) to satisfy WCAG 2.2 AA touch target guidelines and `test_header_ui.cjs` / `test_login_ui.cjs`.
- **Compact Toolbar Chips (`h-8` / `32px` or `min-h-9` / `36px`)**: Permitted only inside dense desktop data toolbars (`DashboardToolbar`) where `gap-1.5` separates chips.

---

## 4. Unified Form & Filter Control System

### Standard Form Controls
- **Text / Number / Password / Select (`input`, `select`, `textarea`)**:
  - Height: `min-h-11` (`44px`) for standalone forms (`LoginPage`, `UserInvestigationView`, `OperationsView`, `CommerceView`, `FirewallView`, `SettingsView`); `h-9` (`36px`) for dense inline table/toolbar filters.
  - Surface & Border: `w-full min-w-0 rounded-lg border border-slate-700 bg-slate-950/90 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 transition-colors`
  - Focus State: `focus:border-sky-400 focus:outline-hidden focus:ring-2 focus:ring-sky-400/25`
  - Disabled / Busy State: `disabled:cursor-not-allowed disabled:opacity-55`
- **Labels & Field Groups**:
  - Always associate `<label>` with control (either wrapping `<label className="block text-xs font-medium text-slate-300">Label<input className="mt-1.5 ..."/></label>` or explicit `htmlFor` + `id`).
  - Never rely on `placeholder` alone as the only label (except search inputs that have an explicit `aria-label`).
- **Password & Secret Inputs**:
  - Must provide an inline reveal toggle button (`aria-label="显示密码"` / `"隐藏密码"`, `aria-pressed`) with `pr-12` padding on the input so text never collides with the icon button.
- **Checkboxes & Toggle Switches**:
  - Wrap in a clickable `<label>` with `min-h-11 flex items-center gap-2.5 cursor-pointer select-none` so mobile users have a full 44px tap row.
- **Destructive / High-Impact Confirmation (`ConfirmDialog`)**:
  - Never use `window.confirm()` or `window.alert()`.
  - Always use `role="alertdialog"` with `Escape` key dismissal, initial focus on the safe `取消` button, and explicit action description (including scope, node/container identity, and that queuing an action does not equal verified completion).

---

## 5. Responsive Adaptation Standards (Desktop / Tablet / Mobile)

### Viewport Breakpoint Strategy
- **Mobile (`320px – 639px`)**:
  - **Zero Horizontal Overflow**: `document.documentElement.scrollWidth <= window.innerWidth` must hold at `320px`, `375px`, and `540px`.
  - **AppHeader**: Brand + tools wrap cleanly; primary navigation forms a 4-column × 2-row (+ TCP link) grid with `min-height: 44px` buttons and total header height `< 300px`. On `<1024px`, avoid `sticky` multi-row sub-headers that consume >30% of the viewport height.
  - **Grids & Forms**: Collapse multi-column forms into `grid-cols-1` (or `grid-cols-2` for compact KPI cards). Action buttons in form footers stack or wrap with `flex-wrap gap-2`.
  - **Data Tables & Long Strings**: Wrap tables in `overflow-x-auto` containers OR switch to stacked card rows; apply `min-w-0` on flex/grid children and `break-all` / `wrap-break-word` on container IDs, IPv6 addresses (`2001:db8:...`), file paths, and URLs.
  - **Drawers & Modals**: Slide-over drawers (`ContainerDrawer`, investigation history drawer) take `w-full max-w-full` on mobile; `alertdialog` modals fit within `90vh` with internal vertical scroll (`max-h-[calc(100vh-2rem)] overflow-y-auto`) so action buttons are never clipped off-screen.
- **Tablet (`640px – 1023px`, `sm:` / `md:`)**:
  - KPI grids use `sm:grid-cols-2` or `sm:grid-cols-4`.
  - Form filter bars use `sm:grid-cols-2` or `md:grid-cols-3`.
  - Split workspaces (`TcpingPage`, `FirewallView`, `UserInvestigationView`) stack vertically below `980px`/`1024px` so neither the catalog list nor the detail workspace is squeezed into a narrow column.
- **Desktop (`1024px – 1920px+`, `lg:` / `xl:`)**:
  - Main container `max-w-7xl` (`1280px`) or `max-w-[1536px]` (`AppHeader`, `UserInvestigationView`, wide operational tables).
  - Multi-panel master-detail layouts and dense data tables display side-by-side with clear visual hierarchy.

---

## 6. Strict Invariants & Anti-Patterns (Must Never Violate)

1. ❌ **Never Break E2E Accessibility Selectors**: Preserve existing `role`, `aria-label`, `aria-current`, `aria-pressed`, and button/heading texts asserted by `tests/test_*_ui.cjs` (e.g., `主导航`, `看板工具`, `打开全局检索`, `暂停自动刷新`, `恢复自动刷新`, `退出登录`, `登录控制台`, `选择防火墙节点`, `安全磁盘清理`, `违规活动隔离 · 待管理员复核`, `容器网络准入保护`, etc.).
2. ❌ **Never Eagerly Import Lazy Views in `LoginPage` / `App.tsx`**: `LoginPage` must never trigger chunk downloads for `Dashboard` or sub-views before authentication (`test_login_ui.cjs`).
3. ❌ **Never Fabricate Missing or Stale Telemetry**: Missing, expired, or unverified data must render as `未提供`, `未知`, `待核实`, or `采样过期`, never `0`, `正常`, or `已生效`.
4. ❌ **No Emoji Icons or Layout-Shifting Hovers**: Use **Lucide** SVG icons exclusively; never use `hover:scale-*` that shifts neighbor layout or triggers scrollbar flicker.
