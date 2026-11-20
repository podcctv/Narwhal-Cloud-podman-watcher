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

### Color Palette (RackNerd 2.0 Dual-Contrast: Light-Ice Workspace + Midnight Navy Headers)
- **Light-Ice Workspace Canvas (`--rn-soft` / `--surface-canvas`)**: `#f2f7ff` (radial sky glow `rgba(8, 123, 255, 0.07)` at top)
- **Midnight Navy Mastheads & Heroes**:
  - **Hero / Backdrop (`--rn-navy-0` / `--rn-navy-2`)**: `#02182f` -> `#031d3d` -> `#073365` (`.rn2-hero` radial gradient)
  - **Masthead (`AppHeader` / `ConsoleShell`)**: `#03182e` -> `#021428`
  - **Card Header Strip (`.rn2-card-head`)**: `linear-gradient(125deg, #163957, #0e233c 58%, #0c1c30)` with `#e6f4ff` text and `#54c7ff` eyebrow (blue variant `.rn2-card-head-blue`: `#0967bb -> #07376e`)
- **Light-Ice Surface Hierarchy**:
  - **Level 1 Card / Panel (`--surface-1` / `.rn2-card`)**: `#ffffff` with `1px solid #cedae7` (`--rn-line`), `border-radius: 14px`, `box-shadow: 0 5px 16px rgba(12, 37, 65, 0.07)`
  - **Level 2 Recessed Spec Strip (`--surface-2` / `.rn2-spec-strip`)**: `#f4f8fd` (`--rn-spec-bg`) with `#d2dfec` (`--rn-cell-line`) vertical dividers
  - **Level 3 Subtle Well / Input Hover (`--surface-3`)**: `#e8f1fb`, table header `#edf5fc`, border `#dce5ef` (`--rn-line-soft`)
  - **Ink Hierarchy**: Primary `#0b1636` (`--rn-ink`), Secondary `#31485e` (`--rn-slate`), Muted `#697b9c` (`--rn-muted`)
- **Brand, Accent & Primary CTA**:
  - **Electric Blue / Cyan / Sky**: `#087bff` (`--rn-blue`), `#0967bb` (`--rn-blue-deep`), `#00b6ec` (`--rn-cyan`), `#54c7ff` (`--rn-sky`, focus outline in dark zones)
  - **RackNerd Orange Primary CTA**: `linear-gradient(105deg, #ff6b00, #ff8100)` (`border: #ea5e00`, hover `#e05b00 -> #f06e00`, white text)
- **Semantic Status Pills (`.rn2-pill` / `StatusPill` — always paired with explicit text labels)**:
  - **Healthy / Verified (`rn2-pill-teal`)**: Text `#147468` (`--rn-teal`), Bg `#e6f7f4` (`--rn-teal-bg`), Border `#9de2d8`
  - **Informational / Active (`rn2-pill-blue`)**: Text `#0657b8`, Bg `#e8f3ff`, Border `#a9d1ff`
  - **Highlight / Action (`rn2-pill-orange`)**: Text `#b84800`, Bg `#fff3e8`, Border `#ffc899`
  - **Warning / Awaiting Recheck (`rn2-pill-amber`)**: Text `#9a5b00`, Bg `#fef6e4`, Border `#f7d58b`
  - **Critical / Failed / Quarantined (`rn2-pill-crimson`)**: Text `#b41835`, Bg `#ffeef1`, Border `#f9b8c4`
  - **Stale / Offline / Unverified (`rn2-pill-slate`)**: Text `#4a607a`, Bg `#eef3f9`, Border `#cbd7e6`

### Typography & Numeric Discipline
- **UI & CJK Body (`--font-sans`)**: `'Plus Jakarta Sans', 'PingFang SC', 'Microsoft YaHei', system-ui, sans-serif`
- **Monospace, Eyebrows & Telemetry (`--font-mono`)**: `'Inconsolata', 'Fira Code', ui-monospace, monospace`
- **Tabular Figures (`tabular-nums`)**: Mandatory on all metrics, countdowns, timestamps, IP counts, bitrates, percentages, and currency values to prevent horizontal layout jitter during 10s live polling.

### 2.0 Button & Form Token Classes (`frontend/src/v2/styles/theme-v2.css`)
- **Buttons (`.rn2-btn`, `min-height: 44px` / `.rn2-btn-sm` `36px`)**:
  - `.rn2-btn-orange`: High-emphasis primary submit/save/apply CTA (`#ff6b00 -> #ff8100`)
  - `.rn2-btn-blue`: Electric blue secondary operational action (`#087bff -> #0967bb`)
  - `.rn2-btn-navy`: Midnight navy action (`#163957 -> #0c1c30`)
  - `.rn2-btn-ghost`: Crisp `#ffffff` with `#cedae7` border (`rgba(255,255,255,0.08)` inside `.rn2-card-head` / `.rn2-hero` / `.rn2-dark-zone`)
  - `.rn2-btn-danger`: High-contrast crimson surface (`#fff1f2`, border `#fecdd3`, text `#be123c`)
- **Controls**: `.rn2-input` / `.rn2-select` (`min-height: 44px`, `#ffffff` fill, `#cedae7` border, `#087bff` focus ring), `.rn2-table-wrap` (responsive container with sticky `#f4f8fd` header). Legacy `.ui-*` classes map automatically to Light-Ice 2.0 tokens.

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

All buttons must use `type="button"` (unless submitting a `<form>`), include `cursor-pointer` when enabled, `disabled:cursor-not-allowed disabled:opacity-50`, and visible keyboard focus (`focus-visible:outline-2 focus-visible:outline-[#087bff] focus-visible:outline-offset-2`, or `#54c7ff` inside midnight headers).

### Button Variants
1. **Primary CTA (`.rn2-btn-orange` / `.ui-btn-primary`)**:
   - High-emphasis RackNerd Orange gradient fill for main form submissions and primary workflow actions (`登录控制台`, `查询 / 刷新`, `保存并同步`, `保存并应用到这台母鸡`).
   - Style: `rn2-btn rn2-btn-orange` (`linear-gradient(105deg, #ff6b00, #ff8100)` with `#ea5e00` border and `#ffffff` text)
2. **Secondary Action (`.rn2-btn-blue` / `.rn2-btn-navy` / `.ui-btn-secondary`)**:
   - Electric Blue or Midnight Navy surface for standard operational actions (`请求只读复扫`, `预览影响`, `加入期望规则`, `发现并预览格式`).
   - Style: `rn2-btn rn2-btn-blue` (`linear-gradient(125deg, #087bff, #0967bb)`) or `#e8f3ff` / `border-[#96c5ff]` / `text-[#0657b8]`
3. **Neutral / Utility (`.rn2-btn-ghost` / `.ui-btn-neutral`)**:
   - Crisp white Light-Ice surface for refreshes, navigation returns, cancel buttons, and secondary toggles (`刷新`, `返回总览`, `取消`, `清空搜索`).
   - Style: `rn2-btn rn2-btn-ghost` (`bg-white border-[#cedae7] text-[#0b1636] hover:bg-[#f4f8fd] hover:border-[#087bff]`, auto-darkened inside `.rn2-card-head` / `.rn2-hero`)
4. **Danger / Destructive (`.rn2-btn-danger` / `.ui-btn-danger`)**:
   - High-contrast Light-Ice rose surface for container stop, rule deletion, or quarantine actions (`人工决定停止`, `删除`, `清理恶意进程`).
   - Style: `rn2-btn rn2-btn-danger` (`bg-[#fff1f2] border-[#fecdd3] text-[#be123c] hover:bg-[#ffe4e6] hover:border-[#fb7185]`)
5. **Filter Chip / Segmented Toggle (`btn-chip`)**:
   - Used in toolbars and sub-navigation (`aria-pressed` or `aria-current="page"`).
   - Inactive: `border border-[#d2dfec] bg-[#f4f8fd] text-[#31485e] hover:border-[#087bff] hover:bg-[#e8f3ff] hover:text-[#08458c]`
   - Active: `border border-[#0867d6] bg-[#087bff] text-white shadow-xs` (or semantic Light-Ice color variant for risk/protocol chips).

### Button Size Tiers & Touch Ergonomics
- **Touch Target Rule**: Primary navigation, header tools, login submit, dialog actions, and mobile full-width actions MUST maintain `min-h-11` (`44px`) or `h-12` (`48px`) to satisfy WCAG 2.2 AA touch target guidelines and `test_header_ui.cjs` / `test_login_ui.cjs`.
- **Compact Toolbar Chips (`h-8` / `32px` or `min-h-9` / `36px`)**: Permitted only inside dense desktop data toolbars (`DashboardToolbar`) where `gap-1.5` separates chips.

---

## 4. Unified Form & Filter Control System

### Standard Form Controls
- **Text / Number / Password / Select (`input`, `select`, `textarea`)**:
  - Height: `min-h-11` (`44px`) for standalone forms (`LoginViewV2`, `UserInvestigationView`, `OperationsView`, `CommerceView`, `FirewallView`, `SettingsView`); `min-h-9` (`36px`, `.rn2-input-sm`) for dense inline table/toolbar filters.
  - Surface & Border (`.rn2-input` / `.rn2-select`): `w-full min-w-0 rounded-[10px] border border-[#cedae7] bg-white px-3 py-2 text-sm text-[#0b1636] placeholder:text-[#697b9c] transition-colors`
  - Focus State: `focus:border-[#087bff] focus:outline-hidden focus:ring-3 focus:ring-[#087bff]/16`
  - Disabled / Busy State: `disabled:cursor-not-allowed disabled:bg-[#f4f8fd] disabled:opacity-72`
- **Labels & Field Groups**:
  - Always associate `<label>` with control (either wrapping `<label className="block text-xs font-semibold text-[#31485e]">Label<input className="rn2-input mt-1.5"/></label>` or explicit `htmlFor` + `id`).
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
