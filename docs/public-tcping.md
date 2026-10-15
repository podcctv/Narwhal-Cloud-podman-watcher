# Public TCP measurement

`/tcping` is unauthenticated and separately lazy-loaded. `/tcping/manage` is an
authenticated administrator configuration page. No private monitoring or
commerce data is fetched by the public page. New jobs are disabled by default;
an administrator explicitly publishes owned host sources and enables the tool.

## Host rename synchronization (1.7.24)

Published sources remain bound to their immutable `node_id`. Renaming a host
in the overview updates its TCP PING association in the same report transaction.
The default public name follows the host name (up to the public 120-character
limit); separately configured public aliases, purchase links and visibility
are preserved. Startup repairs existing label mismatches using only a unique
matching node identity; missing/replaced nodes still show `来源已变更`.

Source IDs, completed results and physical-node cooldowns are not reset.
In-flight old-label leases are cancelled with an explicit rename explanation,
preserving measured rows. They are not rebound to a different host, and a rename
cannot bypass the cooldown or admit old-identity result batches.

## What is measured

As of 1.7.19, the owner can configure a Taiwan TCP target on port `36901`. Its
hostname is supplied through the server's `TCPING_TAIWAN_HOST` runtime
environment setting and is redacted from anonymous directory and job APIs. Do
not commit the hostname to source files. It is not a Zstatic node or an asserted
carrier measurement. The Zstatic counts remain
31/93/223; province mode now includes 94 targets (2 attempts each), city mode
223 and all mode 317 when the target is configured. The Agent accepts a
server-signed Taiwan/custom target only on the fixed port; DNS answers must be
public IPv4 addresses before a connection is attempted. Zstatic endpoints keep
their stricter suffix and port allowlist. Arbitrary client-supplied addresses
remain disallowed.
Cached directory migration preserves upstream freshness and historical job
targets. Historical results do not invent a Taiwan row; the page explains when
the selected record predates the new directory. The Taiwan geometry and label
are always visible, with colors driven only by actual test results.

The map uses ECharts `layoutCenter`/`layoutSize`, not independent box edges,
to preserve its geographic aspect ratio on wide and narrow panels.
Province, carrier and status filters share a pure filtering model across the
table and map. Clicking a province selects the dropdown (clicking it again
clears it); other provinces become neutral. Carrier changes recompute the map
from that carrier's actual results. Defaults are national/all carriers; Clear
resets all filters. Regression tests: Node 24
`node --experimental-strip-types --test frontend/tests/tcping-model.test.mjs`.

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
TCP latency. Zstatic endpoints use their fixed hostname allowlist and TCP ports
80/443; the signed Taiwan target uses its fixed port and rejects DNS answers
that are not public IPv4. No application payload is sent.
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

Build/test first, publish immutable versioned server images and pin native Agent revisions, back up
SQLite online and preserve existing server container/environment/mounts. Deploy
with public starts disabled, publish a canary source, upgrade the actual host
Agent, verify all 317 rows (316 Zstatic plus the configured Taiwan target) and continuing private telemetry, then extend to the
remaining supported owned hosts. Offline/old-version sources stay visibly
unavailable rather than measuring from the central server instead.

### Worker allocator compatibility (1.7.20)

Start the isolated worker with `MALLOC_ARENA_MAX=2` before Python/glibc startup.
On ARM64/Python 3.14, default per-thread arenas exhausted the existing 256 MiB
address-space limit during concurrent DNS subprocess creation. The limit,
four-worker concurrency, deadlines and cooldown are unchanged. The subprocess
integration test now exercises 317 real child creations without network traffic,
instead of returning every synthetic row directly from a thread.
