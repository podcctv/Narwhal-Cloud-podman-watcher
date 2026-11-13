# Sustained Runman resource restart

## Defaults and scope

The Server evaluates Runman containers only. It queues a restart when either
reported CPU or memory use is at least 90% continuously for 3600 seconds. The
window requires at least five fresh samples, with no report gap over 900
seconds. A successful restart starts a one-hour cooldown. Resource use is an
operational protection signal and is never classified as user abuse.

Only Client Agent v1.8.28 or newer is eligible. Older/custom Agents remain
read-only for this policy and receive no restart action.

Server settings can tune the policy. Duration and cooldown cannot be lowered
below one hour; thresholds are bounded to 1–100%; the maximum sample gap is
bounded to 60–1800 seconds.

| Setting | Default |
| --- | ---: |
| `RESOURCE_AUTO_RESTART_ENABLED` | `true` |
| `RESOURCE_RESTART_CPU_THRESHOLD_PERCENT` | `90` |
| `RESOURCE_RESTART_MEMORY_THRESHOLD_PERCENT` | `90` |
| `RESOURCE_RESTART_DURATION_SECONDS` | `3600` |
| `RESOURCE_RESTART_MAX_GAP_SECONDS` | `900` |
| `RESOURCE_RESTART_COOLDOWN_SECONDS` | `3600` |
| `RESOURCE_RESTART_MIN_SAMPLES` | `5` |

## Evidence and action

Each window is scoped to host, Runman UUID, and instance generation. Duplicate
or out-of-order samples do not extend it. Missing or stale metrics, a replaced
instance generation, an unverified node mapping, recovery below the threshold,
an expired action, or an existing pending action prevents a restart. CPU
requires a fresh Runman history sample; memory requires a positive memory
limit.

Before restarting, the Agent reads the root-only Runman inventory again under a
local exclusive lock, confirms the same UUID generation is still running and
still over the threshold, checks for a pending systemd job, and verifies that
the loaded unit is exactly `runman-<uuid>.service` in its expected systemd
cgroup. It then restarts that unit and confirms the unit is active with a new
MainPID. Existing per-device `io.max` limits on the exact `ct` cgroup are
restored and read back after restart. The disk image and guest files are not
deleted.

The current Runman socket API has no lifecycle-locked restart endpoint. The
Watcher serializes its own restart requests and checks systemd jobs, but a
separate Runman API lifecycle operation can race the final inventory check and
systemd request. A future Runman API endpoint holding the manager lifecycle
lock would close that remaining race. Missing systemd/cgroup evidence or a
failed resource-limit snapshot refuses the restart.

## Receipts

Action receipts are recorded as `ops_resource_guard`, a non-abuse protection
signal. Failed actions are retried no sooner than 15 minutes and no more than
three times per continuous overload window. The dashboard and investigation
history label the action as a container restart.
