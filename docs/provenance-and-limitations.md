# Provenance and claims boundary

## Historical source evidence

Four user-supplied private PHP snapshots were inspected: `_cmm_monitor.php`, `_cmm_monitor(1).php`, `_cmm_monitor(2).php`, and `_cmm_monitor(3).php`. All were **1,016 lines** and byte-identical. These names represent four copies of one snapshot, **not** a demonstrated chronological revision history. No snapshot alone authenticates the exact deployed date or production version.

The private source exhibits `probe_domain`, `emit_changes`, `run_uptime`, `run_integrity`, `directory_hash`, and JSON state operations, with literal 128-domain and 31-site inventories. The prior publication blueprint and LinkedIn exhibits were consulted for narrative context; they are not released verbatim here.

## Evidence classification

| Claim | Evidence level |
| --- | --- |
| PHP CLI code probes HTTPS and classifies several application-failure signatures | Present in historical source |
| Source has a six-hour uptime reminder setting | Present in historical source |
| Integrity mode passes a one-day reminder interval | Present in source, **but the historical reminder predicate excludes integrity** |
| Historical code includes 128 domains and 31 Elementor sites | Present in source inventories |
| A cPanel uptime schedule at minutes 0 and 30 was configured | Previously supplied supporting context, not independently established by the PHP source |
| Site remediation was performed across 31 installations | User-provided historical work context; not proven solely by this script |
| Public application tests pass | Independently executed tests on the new synthetic source only |
| Employer-owned source can be published | **Not established; not published** |

## What has been newly authored

Everything in this repository—PHP source, test harness, fixture configuration, synthetic plugin contents, documentation, automation examples, and diagrams—was newly written as a demonstrative implementation. It models selected architectural concepts without reproducing the private inventories, environment-specific versions, operational recipient addresses, original source code, or production state.

The original source was never imported into this repository. Its flaws are analyzed in `docs/audit-and-remediation.md`. Corrective behavior in the new implementation is **not** an assertion that historical production defects were fixed.

## Unsupported outcome claims

No measured uptime improvement, incident detection count, email delivery count, reduction in mean time to recovery, labor savings, SLA, or independently verified 24/7 operation is claimed. The new code is not deployed to employer infrastructure. No live network transport is included in the public implementation; live cURL functionality is deliberately outside this project.
