---
name: narwhal-ui-design
description: >-
  Design standards, interaction patterns, component guidelines, and API contracts
  for the Narwhal Cloud Podman Watcher modern web interface.
---

# Narwhal Cloud UI Design & Interaction System

This skill defines the visual language, component architecture, and interaction standards for the **Narwhal Cloud Podman Watcher** web interface. All frontend development and modifications must strictly adhere to these guidelines.

---

## 1. Visual Aesthetics & Design Tokens

### Color Palette (Tailwind Dark Theme)
- **Background (`--bg`)**: `#020617` (Deep Slate / Navy Black)
- **Surfaces**:
  - Base Surface (`--surface-1`): `#0F172A` (Slate 900)
  - Secondary Surface (`--surface-2`): `#172033` (Card and Table Row hover)
  - Border / Muted Surface (`--surface-3`): `#1E293B` (Slate 800)
- **Borders (`--border`)**: `#334155` (Slate 700) with subtle glow on focus (`#0EA5E9`)
- **Accent & Brand**:
  - Primary Cyan/Sky: `#38BDF8` (`sky-400`), `#0EA5E9` (`sky-500`)
  - Accent Emerald: `#22C55E` (`emerald-500`)
- **Status & Semantics**:
  - Healthy / OK: `#22C55E` (text `#86EFAC`, bg `#052E16`, border `#166534`)
  - Warning / Alert: `#F59E0B` (text `#FCD34D`, bg `#451A03`, border `#92400E`)
  - Danger / Critical: `#EF4444` (text `#FCA5A5`, bg `#450A0A`, border `#991B1B`)
  - Info / Dispatched: `#38BDF8` (text `#7DD3FC`, bg `#082F49`, border `#0284C7`)
  - Offline / Stale: `#94A3B8` (text `#CBD5E1`, bg `#1E293B`, border `#475569`)

### Typography
- **Headings & Monospace Codes**: `Fira Code`, `ui-monospace`, `monospace`
- **Body & Labels**: `Fira Sans`, `Inter`, `system-ui`, `sans-serif`
- **Tabular Figures**: Always apply `font-variant-numeric: tabular-nums` (`tabular-nums` class) to timestamps, percentages, IP counts, bytes, and rates to prevent jitter during real-time updates.

---

## 2. Interaction Patterns

### Real-Time Live Polling Engine
- Default polling cycle: **10 seconds**.
- Top navigation must feature an interactive **Countdown Ring / Spinner** displaying seconds until next refresh.
- Provide a clear **Pause / Resume** toggle and an instant **Manual Refresh** button.
- Automatically pause or throttle refresh frequency when document visibility changes (`document.hidden`).

### Slide-Over Drawer for Container Inspection
- Rather than navigating away or showing disruptive modals, clicking any container card opens a **Slide-over Drawer (`ContainerDrawer`)** from the right.
- The drawer contains:
  1. Live telemetry & version badge (Client vs Server).
  2. Smooth **Apache ECharts** (CPU & Memory Dual-Line, RX & TX Area Chart).
  3. Inbound unique IP anomaly detector with progress bar against threshold.
  4. Process tree with CPU top consumer.
  5. Network exposure & NAT breakdown.
  6. SOCKS proxy and unauthorized panel pairing security checks.
  7. On-demand single-cycle diagnostic action button (`POST /api/v1/containers/diagnostics`) with progress polling.

### Keyboard-First Ergonomics
- `Ctrl+K` / `Cmd+K`: Opens **Command Palette / Quick Search** to instantly filter hosts and containers.
- `Escape`: Closes drawers, search modals, and overlays.

### Security Action Disposition Flow
- Alert remediation and dismissal must provide inline loading states.
- Replaces browser `confirm()` with customized confirmation dialogs and dynamic, self-dismissing Toast notifications.

---

## 3. Strict Prohibitions (Anti-Patterns)
1. ❌ **No Emoji Icons**: All icons must use SVG from the **Lucide** icon library.
2. ❌ **No Layout-Shifting Hovers**: Never use hover scale effects that shift adjacent elements or cause scrollbar flickering.
3. ❌ **No Low-Contrast Text**: Ensure all text passes WCAG 4.5:1 contrast against dark backgrounds.
4. ❌ **No Raw Unformatted Numbers**: Bytes must be formatted via `fmtBytes` (KB, MB, GB), and bitrates via `fmtMbps`.
