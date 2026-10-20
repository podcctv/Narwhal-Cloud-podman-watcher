# Inbound source behaviour assessment (1.7.59)

This is a bounded, read-only evidence summary shown with a container deep
snapshot. It uses the last 10 minutes of existing signed Agent reports (up to
60 report rows); it adds no packet capture, new database table, or firewall
action. It does not modify the five-source admission policy.

## Evidence labels

- **Repeated bidirectional service-port activity**: the same public source IP
  appears in at least two conntrack observations at least 15 seconds apart,
  with established TCP flows, reply packets, and a destination port that the
  container reports as listening.
- **Repeated uncompleted multiport probe**: in at least two observations at
  least 15 seconds apart, the same source touches three or more container
  ports without a listening socket, and incomplete/unreplied TCP flows are at
  least three and at least twice the established-flow count.
- **Mixed clues**: both service-port and multiport-probe evidence are seen in
  the same history window.
- Otherwise the result is **insufficient evidence**. Missing or unavailable
  conntrack evidence is never counted as a clean/benign observation.

These labels describe transport behaviour, not user identity or malicious
intent. A port scanner can complete TCP handshakes; a legitimate client can
have failed or incomplete connections. Confirming the client's account/user
requires the service's own authentication or access logs correlated by source
IP, destination port, and time. AbuseIPDB's score is a separate historical
community-report signal and does not change the behaviour label or trigger
blocking.

The kernel exposes original/reply conntrack tuples and optional per-flow
packet/byte counters; per-flow accounting is disabled by default on Linux, so
missing counters are not treated as evidence of safety. The socket owner/state
inventory is supplementary and is not proof of remote identity.

References: [Linux conntrack netlink specification](https://kernel.org/doc/html/latest/netlink/specs/conntrack.html),
[Linux conntrack accounting sysctl](https://www.kernel.org/doc/html/latest/networking/nf_conntrack-sysctl.html),
[AbuseIPDB APIv2 documentation](https://docs.abuseipdb.com/).
