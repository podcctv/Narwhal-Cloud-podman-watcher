# Customer login card (v1.7.31)

Version 2 uses a concrete title, cause, handling status and actionable advice.
It preserves the existing closed FLANKER HOSTING card, safe terminal wrapping,
severity colors, Beijing timestamps and the channel link.

Panel alerts include the detected component and unapproved domain; unrelated
listening ports, config paths and binary value/threshold counters are omitted.
Missing domain evidence does not assert that a specific domain is unauthorized.
Other alert causes retain their meaningful measurements. Typed numeric evidence
is shown as connections, utilization or duration, never generic observation or
reference-value fields. Diagnostic evidence remains available to administrators.

Execution is not recovery: executed actions explicitly await verification.
The existing two-clean-sample verification and stale-state handling are retained.
The most recent verified historical alert remains at least seven days after
recovery, including across Agent restarts. Known recovery times have a relative
age recalculated at login and a Beijing timestamp. Known first-detection times
allow an approximate alarm duration; legacy records do not invent missing dates.

Regression tests: `python -m unittest tests.test_security_banner_card -v`.
POSIX tests exercise the actual shell renderer through a PTY at several widths.
Successful delivery reports `security.motd_delivery.format_version=2` for rollout
verification; failed or disabled delivery does not claim the new format landed.
