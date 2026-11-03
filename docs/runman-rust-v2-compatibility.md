# Runman Rust v2 compatibility

Updated for Watcher v1.7.204 and Runman Rust v2 inventory schema 1. This is a source-level compatibility matrix; it does not claim that a live Runman host was exercised.

## Supported

| Capability | Status and boundaries |
| --- | --- |
| Inventory and identity | Instance UUID, replacement generation, running state, image, IPs, CPU/memory limits and usage come from Runman's root-only Unix socket. Controls that can mutate a guest or network are bound to the current generation. |
| TCP connections and traffic | Fresh TCP state counts are checked against the instance generation. Cumulative byte counters feed Watcher's traffic ledger and rate calculations; a restart or new generation starts with a fresh baseline. |
| Resource and filesystem metrics | Fresh Runman history samples expose CPU, disk usage/read/write rates and IOPS, network rates, TCP/UDP flow counts and remote-IP count. Root and `/data` filesystem capacity use the generation-checked init PID and guest `df` fallback. |
| Process and security scans | The Watcher uses bounded guest exec for generic read-only process, listener, SOCKS and protocol inventory, and merges those results with Runman metrics. The endpoint binds UUID plus generation, limits each command to 90 seconds and caps combined output at 64 KiB. Manual and alert-triggered deep snapshots are also generation-bound and remain read-only. Specialized protocol guards and service actions have separate runtime gates listed below. |
| Connection evidence timeline and replay | Read-only history views accept Runman UUID targets and group samples by the latest verified instance generation, so restarts do not blend old and new instance evidence. Replay and operator feedback do not change enforcement policy. |
| Shell card and MOTD | Watcher installs its interactive-shell card through generation-bound guest exec. It updates `/etc/motd` through checked procfs when possible and falls back to an atomic guest-exec update/create after rejecting symlinks and non-regular files. Explicit per-user security notices can target Runman when the alert and latest report prove the same UUID generation; retries and delivery verification keep that generation. Shell delivery is reported separately from whether a user saw it. |
| SSH pre-authentication banner | For Runman only, Watcher can install a managed `sshd_config.d` drop-in and banner file through generation-bound guest exec when the active config includes that directory before `Match`. It preserves any operator `Banner`, validates with `sshd -t` and `sshd -T`, reloads the active service and checks readback. Missing OpenSSH, unsupported Include layout, operator directives or unavailable reload are reported without claiming activation. |
| Host firewall and temporary TCP limit | The Runman bridge participates in host RFW interface discovery/readback. Temporary TCP limits continue to require a live UUID, fresh connection evidence and matching generation. |
| Network quarantine | The Watcher can quarantine a Runman instance by lowering its Runman-owned host veth, recording desired state first, and reading the link state back. Release is generation-bound and reversible; Runman reapplies the recorded state after restart/heal. |
| Automatic abuse detection and quarantine | Runman is included in the bounded abuse scan. It requires two fresh corroborating samples, validates the current UUID generation and guest process incarnation, then quarantines only the instance-owned host veth; the alert API accepts only a canonical VM UUID, UUID v4 generation and the `default` project. |
| Per-instance bandwidth limits | Manual and automatic limits use `tc` in the instance's network namespace. The target is the current generation. Automatic limits start only when Watcher proves the dedicated network namespace, selected uplink path and fresh traffic sample; rates are policers, so packets above the rate are dropped. |
| UDP socket and process attribution | Rust inventory reports fresh guest network-namespace UDP socket counts when both IPv4/IPv6 TCP and UDP tables parse completely. Watcher attributes visible TCP and connected UDP table entries by socket inode; it reports UDP file-descriptor references for unconnected sockets. Shared inherited descriptors can appear for each owning process, so these are process references rather than unique network sockets. Missing procfs permissions or incomplete snapshots remain unavailable. |
| CPU offender attribution | A bounded one-second guest `/proc` CPU-time delta identifies the top process for Runman CPU pressure alerts. The generic container report also uses guest `ps` when available; unavailable process snapshots remain unknown. |
| Dynamic CPU, memory and I/O guards | Runman guards can lower and restore `cpu.max`, `memory.high` and per-device `io.max` on the verified `system.slice/runman-<uuid>.service/ct` cgroup. Every access rechecks the live PID start ticks, exact VM UUID and cgroup boundary. The guard remains unavailable when cgroup v2 controllers/files are absent or readback no longer matches the saved state. |
| Speed-test and VMess/Trojan guards | Explicitly selected Runman instances can receive the existing bounded speed-test service policy and protocol-specific network-namespace port rules. Rules require complete process/config/listener evidence and post-apply readback. Runman is selectable per saved policy; the no-policy automatic default still targets Incus/Podman only. |
| Reviewed SOCKS process stop | An administrator can explicitly stop only the reviewed SOCKS process PIDs after the server confirms a fresh matching Runman report generation. The Agent checks the live instance generation, review token and each PID start tick before signaling, then verifies the process is gone. It does not stop the guest or establish a persistent weak-password block. |

## Remaining boundaries

| Capability | Current boundary |
| --- | --- |
| Podman-style writable image-layer size | Runman exposes `disk.img` logical size and allocated host blocks, plus guest filesystem use. This is a useful sparse-disk allocation metric but is not equivalent to Podman's image writable-layer metric. |
| Sustained-overload automatic stop | Runman is not stopped automatically from connection alerts. The existing stop action has no Runman expected-generation precondition, so a replacement instance could otherwise be stopped after a race. Keep the per-instance manual connection limit and network quarantine available; automatic stop needs a generation-conditional Runman control API first. |
| General process/service cleanup | Broad panel-remediation and malware-cleanup jobs still remove service files, configs or binaries by process-family evidence. They are not enabled for Runman because their review/action contract does not yet carry exact per-file and per-process generations end to end. The narrower reviewed SOCKS stop above is supported. |

## Runtime requirements

- Runman must expose `/run/narwhal-agent/connlimit.sock` with root-only permissions, and Watcher must run with access to that socket. Older Runman builds without `/v1/exec` and `/v1/network-quarantine` can still provide supported read-only inventory, but scans, shell/SSH banner installation, reviewed SOCKS stop, quarantine and Runman bandwidth controls require the updated API.
- `CONTAINER_RUNTIMES` must be `auto` or include `runman`; a setting containing only `podman` excludes Runman inventory.
- Guest execution requires a running, managed instance and matching generation. Commands that exceed the timeout or output bound fail without being reported as successful.
- SSH Banner additionally requires OpenSSH server files and service-management support inside the guest. A configured banner file does not prove that every SSH client displayed it.
- Resource guards require cgroup v2 with the corresponding controller delegated to the exact Runman `ct` cgroup. Runman does not create missing controllers or invent a finite baseline.
- Filesystem/MOTD procfs access additionally requires a readable process root and stable init PID start ticks. When procfs cannot safely update MOTD, guest exec performs bounded regular-file/symlink checks before an atomic write.
- Network shaping and quarantine require an existing Runman veth and a verified, dedicated network namespace. Shared/unreadable namespaces, stale identities, missing interfaces or uncertain routes cause the operation to fail closed.
- No live SSH display or production node was verified as part of this source change.
