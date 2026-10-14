# Public TCP measurement

`/tcping` is unauthenticated and separately lazy-loaded. `/tcping/manage` is an
authenticated administrator configuration page. No private monitoring or
commerce data is fetched by the public page. New jobs are disabled by default;
an administrator explicitly publishes owned host sources and enables the tool.

## What is measured

The selected owned VPS connects **outbound to Zstatic's mainland targets**.
Zstatic provides a target directory, not an API to execute tests from mainland
probes. This is not mainland-to-VPS testing, ICMP ping, throughput, an SLA, or a
purchase guarantee. Personal network testing/research only; directory attribution
is visible on the page. The initial official directory has 31 province groups,
93 province/carrier endpoints and 223 city endpoints (316 entries in total).
Counts follow the validated live directory rather than hardcoded marketing data.

Directory: https://www.zstaticcdn.com/api/v1/DescribeAllNodes
Upstream: https://www.zstaticcdn.com/

Province mode tests all province/carrier entries twice. City/all mode tests all
entries in that scope once. Four worker slots, 2.5-second killable DNS resolution,
1.5-second connection timeout, 180-second process deadline. DNS is excluded from
TCP latency. Only pinned public IPv4 addresses from the fixed Zstatic hostname
allowlist and TCP ports 80/443 are accepted. No application payload is sent.
Containerized Agents do not advertise the host-source capability.

The map shows the median of valid endpoint medians per province, with a tooltip
for completed/total coverage and carrier-specific coverage. Missing, failed and
successful results remain distinct. All endpoint rows are available in the
scrollable/filterable table. No random/example timings are displayed.

## Abuse limits and persistence

- Persistent physical-node cooldown: 15 minutes for province, 30 for city/all.
- One active task per node, coalesced requests; global maximum 2 active tasks
  and 20 newly admitted tasks per hour. Not based on spoofable client IP headers.
- Complete results reused for 15 minutes for the same source revision,
  directory generation and scope. Cooldown never clears when switching scopes.
- Agent OS lock, recent job IDs and local cooldown survive Agent restarts.
- Signed Agent transport plus per-job lease, node binding, directory/target
  hash, bounded batches, replay digest and terminal/late-report rejection.
- Worker runs separately from telemetry/security processing, without credentials
  in its environment or arguments. Watchdog kills its whole process group.
- Additive SQLite tables, 24-hour task/result retention, last-good directory
  fallback. Pause/withdraw cancels active tasks; withdrawing hides results.

## Sources and purchase navigation

Administrators associate a registered stable host identity with an opaque public
UUID, display name, region and optional HTTPS product URL. Product links are
ordinary external navigation, not automatic purchases or financial API calls.
For Narwhal's verified deploy route use
`https://dash.fuckip.me/deploy?machine_id=<exact machine UUID>`; optionally include
a validated `plan_id`. Never guess ownership from fuzzy names. No VM credentials,
customer identifiers, revenue, API keys or internal node identity are published.

## Map provenance

Local map asset: `frontend/src/china-map.json`.
Official Alibaba DataV GeoAtlas source:
https://geo.datav.aliyun.com/areas_v3/bound/100000_full.json
Atlas reference: https://datav.aliyun.com/portal/school/atlas/area_selector
Retrieved 2026-10-14. SHA-256:
`99adfeded5223848bbe37a0a12f8023e11ee12161c7800521c27db42fdeac275`.
The source contains provincial geometry (including HK/Macao/Taiwan, which have
no targets in this Zstatic directory) and maritime geometry. No ITDOG raster,
branding or private execution API is copied.

## Rollout

Build/test first, publish immutable versioned server and Agent images, back up
SQLite online and preserve existing server container/environment/mounts. Deploy
with public starts disabled, publish a canary source, upgrade the actual host
Agent, verify all 316 rows and continuing private telemetry, then extend to the
remaining supported owned hosts. Offline/old-version sources stay visibly
unavailable rather than measuring from the central server instead.
