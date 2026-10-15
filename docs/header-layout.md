# Dashboard navigation (v1.7.31)

One brand/tools row and one unified navigation row replace the previous mixed
wrapping layout. Order: overview, security alerts, investigation, statistics,
commerce, operations, settings, public TCP PING. Existing actions and notification
routing remain unchanged. The active item has one consistent page indicator.

At 900 CSS pixels and below, tools get their own row and all eight destinations
form a four-column/two-row grid. Small screens retain readable labels instead
of squeezing icons and text. Navigation targets remain at least 44px; tools
are 48px high. Flexible widths and bounded brand text avoid horizontal clipping.

The global search Hook-order crash is fixed; search and Escape dismissal work
after tab switches. Browser verification covers 320–1920 CSS-pixel layouts,
including widths equivalent to 125%, 150% and 200% zoom on a 1440px display.

Synthetic checks: `python -m tests.tcping_auto_preview`, then
`node tests/test_header_ui.cjs` and `node tests/test_tcping_auto_ui.cjs`.
