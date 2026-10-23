# VMess inbound protection

The Agent automatically blocks a VMess inbound port for Incus and Podman
containers when it can prove all of the following in the same collection:

- A supported `xray`, `v2ray`, or `sing-box` process has a completely readable
  configuration declaring a VMess inbound.
- The configured PID, protocol, transport, and port match a live listener.
- The listener snapshot is complete, its process ownership is unambiguous, and
  the transport/port is not shared with another configured or live service.
- The container has an isolated network namespace and the host can use both
  `nsenter` and `nft` to apply and read back the rule.

When those checks pass, the Agent creates a uniquely owned nftables table in
that container's network namespace and drops inbound packets for only the
confirmed TCP/UDP destination port. It does not stop, kill, restart, or delete
the process or container, and it does not change other ports. The existing
installer provides `nftables`, `iproute2`, and `util-linux` (for `nsenter`).
The Agent pins the verified namespace before applying rules so a reused PID
cannot redirect the operation to a different container.

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
