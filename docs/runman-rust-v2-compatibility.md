# Runman Rust v2 compatibility

Updated for Watcher v1.7.200 and Runman Rust v2 inventory schema 1. This is a source-level compatibility matrix; it does not claim that a live Runman host was exercised.

## Supported

| Capability | Status and boundaries |
| --- | --- |
| Inventory and identity | Instance UUID, replacement generation, running state, image, IPs, CPU/memory limits and usage come from Runman's root-only Unix socket. Controls that can mutate a guest or network are bound to the current generation. |
| TCP connections and traffic | Fresh TCP state counts are checked against the instance generation. Cumulative byte counters feed Watcher's traffic ledger and rate calculations; a restart or new generation starts with a fresh baseline. |
| Resource and filesystem metrics | Fresh Runman history samples expose CPU, disk usage/read/write rates and IOPS, network rates, TCP/UDP flow counts and remote-IP count. Root and `/data` filesystem capacity use the generation-checked init PID and guest `df` fallback. |
| Process and security scans | The Watcher uses bounded guest exec for generic read-only process, listener, SOCKS and protocol inventory, and merges those results with Runman metrics. The endpoint binds UUID plus generation, limits each command to 90 seconds and caps combined output at 64 KiB. Specialized protocol guards and service actions have separate runtime gates listed below. |
| Shell card and MOTD | Watcher installs its interactive-shell card through generation-bound guest exec. It updates `/etc/motd` through checked procfs when possible and falls back to an atomic guest-exec update/create after rejecting symlinks and non-regular files. Shell delivery is reported separately from whether a user saw it. |
| Host firewall and temporary TCP limit | The Runman bridge participates in host RFW interface discovery/readback. Temporary TCP limits continue to require a live UUID, fresh connection evidence and matching generation. |
| Network quarantine | The Watcher can quarantine a Runman instance by lowering its Runman-owned host veth, recording desired state first, and reading the link state back. Release is generation-bound and reversible; Runman reapplies the recorded state after restart/heal. |
| Automatic abuse detection and quarantine | Runman is included in the bounded abuse scan. It requires two fresh corroborating samples, validates the current UUID generation and guest process incarnation, then quarantines only the instance-owned host veth; the alert API accepts only a canonical VM UUID, UUID v4 generation and the `default` project. |
| Per-instance bandwidth limits | Manual and automatic limits use `tc` in the instance's network namespace. The target is the current generation. Automatic limits start only when Watcher proves the dedicated network namespace, selected uplink path and fresh traffic sample; rates are policers, so packets above the rate are dropped. |

## Remaining boundaries

| Capability | Current boundary |
| --- | --- |
| SSH pre-authentication `Banner` | Not configured. The shell card runs after authentication in interactive shells; MOTD is also post-login and does not prove that SSH/PAM displayed it. Watcher does not edit `sshd_config`. |
| UDP sockets and per-protocol UDP attribution | Runman reports UDP conntrack flow counts from host monitoring, not guest UDP socket counts or per-process UDP attribution. `udp_sockets` remains unavailable/zero and must not be interpreted as a measured empty socket set. |
| Writable image-layer size | Runman uses an overlay on a sized `disk.img`; allocated disk capacity and guest filesystem usage are available, but a Podman-style writable image-layer size is not a comparable metric. |
| Dynamic CPU, memory and I/O guard changes | Watcher does not rewrite Runman's systemd cgroup limits or disk configuration. Runman owns those resource settings; its current Watcher API is read-only for them. |
| CPU offender attribution | Runman reports current CPU usage, but the Watcher's one-second per-process CPU attribution path is still limited to Incus and Podman. |
| Specialized protocol and speedtest guards | Read-only protocol inventory is available through guest exec; VMess/Trojan port-rule reconciliation and the speedtest endpoint guard remain gated to Incus/Podman pending Runman-specific namespace tests and readback coverage. |
| General destructive guest remediation | Existing queued process/service remediation actions do not all carry the evidence generation end-to-end. Automatic process/service deletion or restart therefore remains disabled for Runman. Network quarantine is separate and generation-bound. |

## Runtime requirements

- Runman must expose `/run/narwhal-agent/connlimit.sock` with root-only permissions, and Watcher must run with access to that socket. Older Runman builds without `/v1/exec` and `/v1/network-quarantine` can still provide supported read-only inventory, but scans, shell installation, quarantine and Runman bandwidth controls require the updated API.
- `CONTAINER_RUNTIMES` must be `auto` or include `runman`; a setting containing only `podman` excludes Runman inventory.
- Guest execution requires a running, managed instance and matching generation. Commands that exceed the timeout or output bound fail without being reported as successful.
- Filesystem/MOTD procfs access additionally requires a readable process root and stable init PID start ticks. When procfs cannot safely update MOTD, guest exec performs bounded regular-file/symlink checks before an atomic write.
- Network shaping and quarantine require an existing Runman veth and a verified, dedicated network namespace. Shared/unreadable namespaces, stale identities, missing interfaces or uncertain routes cause the operation to fail closed.
- No live SSH display or production node was verified as part of this source change.
