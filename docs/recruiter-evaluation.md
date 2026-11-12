# Hiring-review guide

**First 30 seconds:** This project demonstrates a PHP monitoring tool derived from a real business reliability problem: 128-domain historical scope, Elementor remediation context across 31 installations, stateful incident alerts, and integrity diagnostics. The demonstration is newly authored, offline, and testable.

## Evaluation by resume track

| Role | Strongest evidence | Practical limitation |
| --- | --- | --- |
| Software Engineer | Separated classifier, incident transition engine, filesystem hashing, defensively persisted JSON, CLI tests | Small single-process demo; not a fully deployed monitoring platform |
| IT Support Specialist | TLS/HTTP/application diagnosis, WordPress plugin checks, integrity consistency, failure-response thinking | No live operational connectivity in the public artifact |
| Data Analyst | Typed diagnostic results, normalized failure categories, deterministic time series of state changes | No historical production dataset or predictive analytics |
| Operations Coordinator | Structured event reporting, noise suppression, reproducible operational controls | No measured labor, SLA, or alert-delivery outcomes |

## Recommended technical review path

1. Run `bash examples/run-lifecycle.sh` to see operational semantics.
2. Inspect `StateEngine.php` for per-target reminder handling and change detection.
3. Inspect `StateStore.php` for complete-cycle locking and atomic replacement.
4. Review `Classifier.php` for status/body/redirect handling.
5. Run `bash examples/run-integrity-demo.sh` and inspect the fingerprint implementation.
6. Read the audit for acknowledged historical issues and scope boundaries.

**Scope boundary:** The demo intentionally excludes live cURL probing. Integrity checks additionally compare against a synthetic approved baseline; these hashes are not cryptographic proof of a genuine vendor release. The stdout outbox demonstrates retryable local reporting, not delivered email. These limits are documented rather than overstated.
