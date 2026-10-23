# VMess inbound protection

The Agent automatically blocks a VMess inbound port for Incus and Podman
containers when it can prove all of the following in the same collection:

- The exact supported `xray`, `v2ray`, or `sing-box` process has all of its
  discovered configuration files completely readable, with no unparsed config
  directory or omitted endpoint, and its configuration declares a VMess inbound.
- The configured PID, protocol, transport, and port match a live listener.
- The live listener snapshot is complete, its process ownership is unambiguous,
  and the transport/port is not shared with another configured or live service.
- The container has an isolated network namespace and the host can use both
  `nsenter` and `nft` to apply and read back the rule.

This policy is VMess-only. VLESS inbounds are deliberately excluded and are
never blocked by this guard; a VLESS listener on another port does not inherit
the VMess rule.

For Xray/V2Ray, the Agent maps the configured transport method to the actual
TCP/UDP listener before associating a protocol with a socket. It handles both
current Xray `streamSettings.method` and legacy `network` names (for example,
WebSocket/gRPC to TCP and mKCP to UDP). XHTTP with TLS ALPN `h3` maps to UDP;
ambiguous mixed-ALPN XHTTP and MASQUE listeners remain unassociated unless the
live PID/port inventory can uniquely prove the transport. This prevents a
process using the same numeric port on both TCP and UDP from being guessed.

When those checks pass, the Agent creates a uniquely owned nftables table in
that container's network namespace and drops inbound packets for only the
confirmed TCP/UDP destination port. It does not stop, kill, restart, or delete
the process or container, and it does not change other ports. The existing
installer provides `nftables`, `iproute2`, and `util-linux` (for `nsenter`).
The Agent pins the verified namespace before applying rules so a reused PID
cannot redirect the operation to a different container.

If nftables rejects validation or application, the Agent reports a bounded
reason category (for example permission denied, unsupported kernel operation,
or rule-state conflict); it never includes raw command output or config paths
in customer-facing alerts. These distinctions help decide whether the Agent
needs the correct namespace/network capabilities or whether the host kernel
cannot support the rule. They do not authorize a broader RFW host rule.

## Recovery and rule removal

The guard removes its own port rules after a complete recovery scan confirms
that no supported VMess inbound remains. A complete recovery scan requires a
fully read protocol/config inventory, an available non-truncated live socket
snapshot, and a non-truncated service-listener inventory. In contrast, a
positively identified VMess process may be protected when an unrelated process'
configuration could not be read: the Agent evaluates completeness per exact
PID and engine for adding a rule, while retaining the global-completeness gate
for deciding that VMess is absent and releasing old rules. If another process
or endpoint remains incomplete, its endpoints stay pending and any existing
owned rules are preserved. The Agent checks the
previously guarded TCP/UDP ports against that live listener inventory before
removing the uniquely owned nftables table, then reads the table list back and
confirms that the table is absent. It never flushes unrelated firewall rules.

If a previously guarded port still has a listener, the Agent keeps the rule and
reports “VMess 端口恢复待核实” with the affected port. This avoids exposing a
VMess process that may still be serving from an already-loaded configuration.
If the scan is incomplete, the container namespace is unavailable/shared, or
rule deletion cannot be read back, the Agent does not claim recovery; it
preserves protection where possible and raises an operator-side verification
alert. These recovery alerts are protection-only and do not tell the customer
that they were abusive or send an abuse notice.

Once the listener disappears and a subsequent complete scan confirms absence,
the Agent removes only its own table. Other container services, ports, and
processes remain untouched. A full listener inventory hitting its collection
limit is treated as incomplete, so it cannot trigger automatic release.

This is a port-level network rule, not a process-level filter. If a different
service later reuses that exact transport/port before the next complete scan,
that service would also be blocked on the port. The Agent refuses ambiguous
initial matches and reconciles the rule on subsequent complete collections.
If collection is incomplete, it reports that protection is unverified and
preserves the last confirmed rule rather than claiming it was removed.

No rule is installed when VMess is loopback-only, when the configuration or
listener owner cannot be verified, or when the container shares the host or
another container's network namespace. Docker and host services are outside
this policy. Set `SECURITY_AUTO_BLOCK_VMESS=false` in the Agent environment to
disable automatic rule changes; the dashboard still reports the identified
protocol. Confirmed-block and unverified-protection states are also recorded in
the SSH banner while automatic protection is enabled.

When a rule is confirmed, the SSH banner explains which transport/port was
blocked and recommends migrating to VLESS + Reality + Vision. That is a
recommendation only; the Agent does not rewrite service configuration.

Confirmed VMess alerts include the exact Incus/Podman project and container,
plus the matched engine process name, PID, transport, and port. A customer
policy advisory is queued only when the Agent reports a read-back-confirmed
block and the server has a fresh, exact single-user recipient mapping. The
advisory is sent through the configured buyer notification API; the Agent also
places the alert in that container's SSH login banner. It explains that this is
a platform network policy, not a finding of customer abuse. Unverified blocks,
stale evidence, or machine-wide recipient mappings do not trigger a customer
message. No recipient mapping means the operator dashboard remains the source
of the alert and there is no broadcast fallback.

The enforcement remains a transport/port rule, not protocol inspection. The
guard must first establish a VMess-only listener with no configured or live
service collision; it does not attempt to identify VMess inside shared HTTPS
traffic. If the same port is later reused by another service, that service can
also be affected until the next complete reconciliation, so a dedicated
transport/port is required for safe isolation.
