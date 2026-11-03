# Runman Rust v2 compatibility

Updated for Watcher v1.7.199 and the Runman Rust v2 inventory schema 1. This is a source-level compatibility matrix; it does not claim a live Runman host was exercised.

## Supported

| Capability | Status and boundaries |
| --- | --- |
| Instance inventory | UUID, instance generation, running state, image, IP addresses, CPU and memory limits/usage come from Runman's root-only Unix socket. |
| TCP connection evidence | Fresh TCP state counts from Runman's `/proc/<pid>/net` sampling are accepted only when the sample is valid and its generation matches the instance. |
| Host firewall integration | Watcher recognizes the Runman bridge for host RFW interface inventory/readback. This is host policy visibility, not per-container isolation. |
| Temporary TCP connection limit | Supported through the Runman connection-limit API, with UUID, running state, fresh counts, and instance generation checked before applying. |
| Traffic accounting and rates | Lifetime inbound/outbound byte totals are consumed as cumulative traffic counters. Watcher sends them to the traffic ledger and derives bytes/second between samples, keyed by UUID and instance generation. The first sample after Agent restart or a new generation establishes a baseline and reports zero rate. |
| Container filesystem space | Read-only `statvfs` of the root filesystem and a real `/data` directory through the generation-checked init PID. Root and `/data` total/available space feed the existing filesystem report fields. Symlinked or unavailable `/data` is left unavailable. |
| Post-login MOTD | Watcher can update a pre-existing regular `/etc/motd` through `/proc/<init_pid>/root`, after checking the init PID start ticks. It preserves the file mode/owner and verifies the atomic replacement. No Runman guest exec endpoint is used. |

## Not supported yet

| Capability | Why it remains unavailable |
| --- | --- |
| Interactive shell card (`/etc/profile.d` and `.bashrc`) | Not installed by this adapter. Unlike MOTD, it needs multiple shell startup files and a renderer script to be created or updated with correct ownership in Runman's user namespace. Runman has no guest exec API for validating the target shell environment, so Watcher reports shell delivery unsupported. |
| SSH pre-authentication `Banner` | The feature does not edit `sshd_config`; MOTD is a post-login mechanism. Whether SSH/PAM displays it is unverified and reported as such. |
| MOTD creation when absent | Runman containers may use user namespaces. Watcher refuses to create a missing file because host-root ownership may not map to guest root correctly. Existing file must be a bounded regular file, not a symlink. |
| Image writable-layer size and disk I/O rates | The current Runman watcher contract does not provide image-layer size or I/O counters. Root and `/data` filesystem space are supported separately through procfs. |
| Per-process metrics and attribution | No Runman-specific process inventory contract is available to Watcher; top CPU process and process-attributed network/security evidence remain unavailable. |
| In-container service/protocol scans and remediation | No guest exec/control API is exposed. Service restarts, process termination, protocol configuration scans, and service guard actions are not dispatched to Runman. |
| Per-container quarantine and bandwidth shaping | Existing Runman support is the TCP connection-limit API plus host RFW interface awareness. Those do not provide guest network isolation or per-instance traffic shaping. |
| UDP connection/security breakdown | Current Runman inventory reports TCP counts only; it does not supply UDP socket counts or per-protocol byte rates. |

## Runtime requirements

- Client must run on Linux with Unix socket support and access to `/run/narwhal-agent/connlimit.sock`; Runman creates a root-only directory/socket, so the local Watcher needs the matching host privileges.
- `CONTAINER_RUNTIMES` must be `auto` or include `runman`. Setting it to only `podman` excludes Runman inventory.
- Filesystem and MOTD collection additionally need an active Runman init PID, a host PID namespace or host `/proc` mount whose `NSpid` outer PID matches Runman's PID, readable process root, and a stable PID start-time sample. MOTD also requires an existing regular `/etc/motd` file.
- `login_display=unverified` is intentional. It means Watcher did not verify an SSH/PAM display path; it does not claim the MOTD was seen.
