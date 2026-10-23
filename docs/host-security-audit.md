# Host security audit

The Agent periodically reports bounded, read-only security telemetry alongside
the existing monitoring data. It uses `SECURITY_MONITOR_ENABLED` and the normal
security-alert delivery rules. Detection is for review and notification only;
the audit does not isolate machines, block logins, stop services, or modify
configuration. A native Agent on a mother host runs the full host audit. An
Agent detected inside a child container is restricted to SSH-related checks
and is never presented as a full host audit.

## Checks and cadence

- A first successful report quietly establishes the integrity baseline. Later
  mother-host reports compare login-capable accounts, SSH public-key
  fingerprints, and hashes of SSH, sudo, PAM, firewall, cron, and systemd configuration. A
  separate six-hour snapshot hashes a bounded allowlist of Nginx, Traefik,
  Compose, GitLab Runner/CI, SSH, and WordPress configuration files. Only paths
  and hashes are retained; configuration contents and key material are not
  uploaded. Changes are emitted as review alerts, not compromise claims.
- Successful SSH logins are read from the system journal, or from
  `/var/log/auth.log`, `/var/log/secure`, or `/var/log/messages` when journald is
  unavailable. A warning is created for a first-seen public IP, account, or
  country. Country lookup uses the Agent's local MaxMind database only.
- Child-container Agents keep only the SSH-relevant portion: login-capable
  accounts, authorized-key fingerprints, successful SSH login sources, SSH
  daemon/client configuration hashes, the SSH PAM authentication files, and
  static checks for `PermitRootLogin yes` / `PasswordAuthentication yes`.
  They do not scan container OS packages, Python dependencies, application or
  CI configuration, CA stores, or local runtime image inventories. These
  unrun checks are reported as not applicable, not as clean/complete.
- Once per day, installed OS packages, Python package metadata, recognized
  dependency lockfiles, and Maven manifests are checked against the OSV API.
  Python metadata discovery includes bounded virtual-environment roots under
  common application directories. Maven manifests remain partial coverage
  because they do not resolve transitive dependencies or active profiles.
  Failed or partial scans retry hourly. The OSV scan is bounded to 1,200
  package candidates, 1,200 dependency files, 4,000 lockfile directories, 200
  retained findings, and 45 seconds of request time.
- Every six hours, a complementary static scan checks Python startup-file names
  associated with the October 2026 LiteLLM incident, affected Python CA-package
  version baselines, the Agent's default OpenSSL CA names, selected
  TLS/CI/container configuration patterns, and local Docker/Podman image
  repository digests/tags. It reads Python `.dist-info`
  metadata and selected text configuration only; it does not import Python
  packages, execute application binaries, enter containers, or read container
  environment variables. It never reads WordPress backup contents. This scan
  is bounded to 5,000 Python-root directories, 3,000 config directories, 800
  config files / 8 MiB total, the default CA listing, and 500 images per local
  runtime.

Package names, versions, and ecosystem names are sent over HTTPS to
`api.osv.dev` for advisory matching. Hostnames, IP addresses, configuration
contents, and account/key material are not included in those queries. Static
indicator results may include bounded file paths and line numbers so an
administrator can locate a finding; matching source lines, secret values, and
configuration bodies are never reported.

The host audit state is stored locally at
`/opt/narwhal-monitor/host-security-audit.json` with restrictive file
permissions. `NARWHAL_HOST_SECURITY_STATE_FILE` can override that path. SSH
journal/file cursors, integrity baselines, and indicator snapshots advance only
after the server acknowledges a report. Incomplete scans retain prior active
findings instead of clearing them.

## Coverage and interpretation

The dashboard labels scans complete, partial, unavailable, or not applicable
and shows their scope. Child-container cards say “SSH security check” and do
not display unrun host checks as clean. Unsupported package ecosystems, unreadable files, parser failures, or
safety limits reduce coverage; an incomplete scan must not clear existing
vulnerability or indicator alerts. When the Agent runs inside a container, the
audit is explicitly scoped to SSH security in that Agent environment and is
not represented as a host-filesystem audit. A local Docker/Podman image inventory is only available
when the Agent can query that runtime; Kubernetes, remote registries, images in
other runtimes, HTTPS live targets, and custom or encrypted configurations are
not scanned by default. Standalone Node.js, Go, .NET, nginx, or other upstream
binaries are not version-probed by executing application tools; OS package
versions may still be checked through OSV, but unmanaged runtimes and binaries
inside images are outside the current coverage. The audit does not test cloud
security groups or prove that a non-loopback listener is reachable from the
public Internet.

OSV and incident package matches are version/metadata matches, not proof of
execution or exploitation. Distribution backports, application-specific
virtual environments, image labels that differ from their digest, and
sitecustomize hooks generated by legitimate software can change interpretation.
The exact LiteLLM digest is treated as a high-priority exposure indicator, but
the existence of a local image does not mean it is running. A `sitecustomize.py`
or a static config-pattern match is a review clue, not proof of compromise or
effective configuration. The eMudhra check only names a root in the Agent's
default CA view: Google reports that the affected private keys belonged to
intermediate CAs and that it removed `emSign ECC Root CA - G3` from Chrome Root
Store, so root presence alone neither proves compromise nor proves a vulnerable
certificate path. This view does not represent Java, browser, or application
bundled trust stores. Confirm vendor advisories and runtime state before
remediation.
