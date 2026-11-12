# CMM-17 validation — reproducible offline release

This document records the **CMM-17** local engineering validation followed by **CMM-CI-02** external multi-runtime certification of the approved release. Earlier remediation test counts remain historical. The independent execution report and evidence bundle retain detailed gate output and release identities.

## External certification — CMM-CI-02 (November 12, 2026)

The independent execution report and exact evidence ZIP are retained separately from this publication source archive. The final approved ZIP is `cmm17-ci02-validated-candidate.zip` (SHA-256 `013d532626e6b59d9dc13bb155c3a7b5f0f815108f5b7a813c0278bb881729a6`). The candidate added the authentic Composer lockfile and corrected two test-harness defects; application code, workflows, and dependency constraints were unchanged.

| Gate | PHP 8.2.32 | PHP 8.3.6 | PHP 8.4.24 |
| --- | --- | --- | --- |
| Regression tests | 334 pass | 334 pass | 334 pass |
| Xdebug in-process line coverage | 89.6% (1331/1486) | 89.6% (1331/1486) | 89.4% (1328/1486) |
| Composer strict validation and dependency install | PASS | PASS | PASS |
| PHPStan (`composer analyse`, configured level 1) | PASS | PASS | PASS |
| PHP syntax, SVG validation, publication scan, manifest verification | PASS | PASS | PASS |

All **30 final gates** passed, including clean release extraction and manifest validation. Composer 2.11.2 generated the real dependency lockfile with `phpstan/phpstan` 2.3.5. Coverage counts executable lines in-process, excluding separately invoked CLI subprocesses. These are **external execution-host results**, not GitHub-hosted Actions results. The publication itself still requires authorization and post-publication hosted CI verification.

## Executed local checks

| Check | Observed result |
| --- | --- |
| `php tests/run.php` | **334 passed, 0 failed**, including CMM-17 permanent regressions |
| `php tools/lint.php` | Full PHP source, tools, tests and fixtures pass syntax validation |
| `php tools/publication_scan.php --release .` | Strict publication scan succeeds with pinned PyYAML 6.0.3 available |
| `php tools/validate_svg.php` | All packaged static SVG files pass the restricted XML validator |
| `php tools/verify_manifest.php .` and `sha256sum -c MANIFEST.sha256` | Exact packaged payload and SHA-256 digests verified after building the archive |
| `bash examples/run-lifecycle.sh` and `bash examples/run-integrity-demo.sh` | Offline incident and synthetic integrity lifecycles execute |
| Independent ZIP-extraction audit | **69/69 checks passed**, including 2,650 classifier cases, end-to-end no-false-recovery scenarios, corrupt outbox rejection, 49 negative credential probes, positive scanner controls, and a 1,000-host simulation |
| Portable Unicode NFC comparison | **6,000 randomized samples**, zero mismatches with Python's NFC implementation in the compared sample |
| Independent state transition properties | **25,000** transitions, **62,580** generated events, zero unexpected failures |
| Fleet-scale tests | **1,000** synthetic failing hosts and **31** synthetic Elementor sites completed |

All test and stress runs use reserved synthetic hostnames, offline fixtures, and temporary state files; none request a live connection to company infrastructure. Failure of stdout, malformed persisted state, no-evidence content policies, structural HTML ambiguity, credential parser permutations, and missing schema-2 outboxes are covered by permanent regression tests or the independent audit.

## Health and persistence contracts

Healthy page status requires positive, interpretable content evidence; success codes alone and empty policy objects do not allow recovery. CSS computed-layout cases that cannot be verified offline remain unverified. A controlled endpoint may instead provide a machine-readable JSON health contract (`json_health.field` and `json_health.equals`), with exact schema validation, duplicate-key rejection and HTTP 200 required.

State writes validate against the same schema accepted by reads. Schema version 2 requires the event outbox. Legacy version 1 states with nonempty history but no outbox are rejected until an operator chooses the explicit backup-and-acknowledgment migration tool; missing undelivered event content cannot be reconstructed. Event engine and outbox share one field-length acceptance contract.

## Reproduce locally

```bash
python3 -m pip install -r requirements-security.txt
php tests/run.php
php tools/lint.php
php tools/validate_svg.php
php tools/publication_scan.php --release .
php tools/verify_manifest.php .
sha256sum -c MANIFEST.sha256
bash examples/run-lifecycle.sh
bash examples/run-integrity-demo.sh
```

Use an isolated Python virtual environment for the pinned YAML scanner in CI or production-like workstations.

## Remaining hosting and operational boundaries

- **Hosted GitHub Actions:** The included PHP 8.2/8.3/8.4 workflow was not run in GitHub during CMM-CI-02. Its hosted pass/fail outcome must be checked after repository publication.
- **Operational limits:** This repository is an independent, offline synthetic implementation. It does not establish live transport correctness, browser-equivalent rendering, actual message delivery, outage reduction, deployed scheduling, or measured business outcomes. At-least-once output delivery requires downstream event-ID deduplication.
- **Publishing rights:** Sanitization and successful static scanning do not authorize publishing employer intellectual property. Confirm rights to the independently authored demo and approval to disclose the employer name and historical scope before any GitHub write.

The external certification logs retain runtime-version evidence. The exact original archive checksum provides the immutable engineering baseline; any later documentation-only publication overlay has its own Git tree identity and must not be represented as the original ZIP.
