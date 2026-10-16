# Connection evidence and protection (v1.7.38)

## Meaning and defaults

`conn_count` remains a socket total: all TCP states plus UDP sockets. It is not
the number of users, requests or established TCP connections. New Clients report
`security.connection_metrics` with TCP established/pending/TIME_WAIT and UDP
separately, a sampling timestamp, and a boot/network-namespace/PID-start epoch.
The total and breakdown come from the same complete `/proc/PID/net` read. Shared
host-network, partial reads and legacy counts are notification-only.

- Warning: over 500; critical: over 1000 (configurable).
- Critical for 900 seconds: refresh evidence and escalate notifications once per
  episode. Never infer abuse or kill a process from an aggregate number alone.
- Stop protection: over 1500 for 900 seconds, at least three valid samples with
  gaps no greater than 600 seconds. These are operational defaults, not universal
  thresholds for every workload. Existing environment overrides are preserved.
- `CONNECTION_AUTO_STOP_ENABLED=false` pauses stop enforcement while preserving
  evidence, counters and notifications. The installer preserves this switch.

## Safety and receipts

Missing/stale/inconsistent samples, restart/metric-policy changes and recovery
break the continuous window. Duplicate/out-of-order samples do not extend it.
Old agents are alert-only until upgraded. Migration never imports a legacy
stop window as proof. Pending actions prevent duplicate stops; failures have
15-minute retry backoff and at most three automatic attempts per valid window.
At the node, schema, expiration, duration, current container epoch and current
socket threshold are checked again before stopping only the named instance.
Expired/legacy/recovered/restarted targets are refused. No instance is deleted.

There is no new blanket per-process kill or firewall rule. Existing independently
verified service-scoped abuse handling remains in place. Unattributed or mixed
business processes require operator review, not automatic throttling.

## Evidence and notification presentation

The Telegram card distinguishes episode age from verified critical-window time,
shows the stop threshold/window and why no action occurred, and displays TCP/UDP
breakdowns. Evidence refreshes at most every 15 minutes per incident, also on
critical escalation; at most ten requests are queued per host report. Pending
requests time out visibly. Snapshots over 15 minutes old are labelled historical,
and truncation is explicit. Public IP list counts do not include unmapped private
or NAT peers. The connection-only `policy_signal` is deduplicated; independent
HTTP/bandwidth signals remain and have readable Chinese descriptions.

Buyer notifications use the same policy facts and a persistent once-per-episode
escalation key. Unsent initial reminders are superseded, not delivered later as
stale duplicates. No notification claims a successful stop before a receipt.

## Rollout and rollback

Back up the database online and preserve server.env/Caddy configuration before
deployment. Publish and verify both Linux architectures, deploy Server first,
then use a signed managed Client canary and promote only after its new version
and core health are verified. Retain previous containers/Client snapshots. Verify
fresh metrics, business identities and public HTTPS after rollout. A rollback
may run the previous image with the additive table left in place; no destructive
schema migration or database restore is needed for a normal binary rollback.
