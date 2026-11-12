# CMM-17 — Architectural remediation and independent re-audit

**Project:** Multi-Site Infrastructure Monitoring & Automation  
**Input:** Version 16 synthetic educational demonstration and its independent 13-finding audit.  
**Scope:** Pure PHP health classification, incident-state and outbox integrity, release-screening tools, reproducibility, documentation and CI.  
**GitHub:** Unchanged. Original company code and infrastructure remain excluded.

## Engineering acceptance contract

A response may generate `recovered` only after positive application evidence. HTTP 200 alone is insufficient for an empty/control-only page, and bodyless/non-page success statuses cannot establish recovery without an explicit content contract. Ambiguous CSS/HTML, browser-directed navigation, invalid response structure, unrecognized server-error headings and unsupported presentation must remain unverified. Verified failure evidence remains an active incident. An explicit machine-readable `json_health` policy offers a deterministic alternative to the bounded HTML approximation.

Persisted incident history and queued delivery events form a single transaction. The writer uses the reader's exact validation contract and upgrades current state to schema version 2. A current state cannot silently lose the `outbox` field. Legacy version-1 files with a missing outbox and nonempty histories are deliberately rejected; optional, operator-acknowledged migration creates an original-byte backup and makes the possible loss of past undelivered alerts explicit.

Release scanning is defense-in-depth. YAML is parsed by a pinned, safe YAML loader with duplicate-key checks, Unicode-escaped key decoding and order-independent sequence-map inspection. PHP is tokenized to recognize literal assignments under sensitive lvalues. Short shell/text password assignments are also screened. All files are subject to the strict package scan, manifest completeness and separate rights review. Scanner success cannot prove there are no secrets or proprietary materials.

## Confirmed findings and resolutions

| Finding | Corrective mechanism | Verification |
|---|---|---|
| V16-01: No-op content policy | Reject empty/zero-evidence contracts at configuration and classifier boundaries | Invalid policies, blank 200/201, CLI recovery |
| V16-02: Control-only content | Remove Unicode control characters as well as separators from meaningful content | C0/C1/DEL and recovery cases |
| V16-03: Extended error banners | Structural prefix recognition for database, WordPress and server failures; unsupported error headings remain unknown | Long-trailing-text and server-heading cases |
| V16-04: Nearby guide suppresses real error | Distinguish explicit tutorial containment from ambiguous guide adjacency; ambiguity cannot prove health | Real-heading/guide regression and prior tutorial controls |
| V16-05: Missing outbox loses alerts | Schema version 2 requires an outbox; explicit backed-up legacy migration | Corrupt state rejection and migration round-trip |
| V16-06: YAML escaped keys | Safe parsed YAML mappings with decoded keys | `access\u0054oken` and quoted keys |
| V16-07: Reordered env entries | Inspect parsed `name`/`value` mappings regardless of order, nesting or flow layout | Environment map permutations |
| V16-08: PHP concatenation | PHP-token-sensitive lvalues, literal concatenation, array/object assignments | Array, property and short-literal regression |
| V16-09: Short shell/text secrets | Reject non-placeholder sensitive assignments regardless of password length | Shell and plain-text synthetic samples |
| V16-10: Preformatted server examples | Code-example context applies to server failure templates too | Tutorial example and active server error controls |
| V16-11: Engine/outbox mismatch | Shared `EventSchema` validates source issues before transition | Oversized code/detail and composed engine-outbox checks |
| V16-12: Unicode fallback incomplete | Complete canonical decomposition, ordering, recomposition and algorithmic Hangul using generated Unicode 15.1 tables | Canonical equivalence and independent randomized comparison |
| V16-13: Duplicated CSS implementation | Removed dead classifier CSS helpers; shared `InlineVisibility` remains | Reflection check and existing CSS regression suite |

## Architectural improvement beyond the original findings

The optional per-host `json_health` contract checks a top-level JSON field against an exact expected string. It requires HTTP 200, valid UTF-8, unique JSON object keys and an explicit match. Malformed data is unverified; a mismatched value is unhealthy. It never interprets CSS, browser events, scripts, remote resources or real WordPress content. This makes the demonstration useful for controlled machine-readable health endpoints while retaining the documented, conservative HTML subset.

The fault detector now treats credible unrecognized 5xx/server/database error headings as unverified rather than recovering merely because an exact vendor phrase was not recognized. Every supported mode continues to use synthetic inputs only; this repository does not claim deployed end-to-end health verification.

## Reproduction and release gates

From the repository root, after installing **Python 3** and the **pinned PyYAML** dependency for the YAML release gate:

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

To inspect a legacy migration without touching a real deployment, work on a *copy* of an old JSON state file and run:

```bash
php tools/migrate_legacy_state.php --state /path/to/synthetic-legacy-copy.json --acknowledge-unrecoverable-historical-alerts
```

The migration backs up the original input and acknowledges that any pending event absent from the legacy file cannot be reconstructed. Do not use this against an employer's real state without a separate operational review.

## External certification still required

Composer, PHPStan and the PHP 8.2/8.3/8.4 hosted CI matrix have not been observed passing in the local environment. `composer.lock` has not been fabricated. Xdebug is unavailable for reliable measured source coverage. The CI workflow describes the intended checks but does not substitute for their execution. Publication-rights authorization and inspection for protected employer materials remain separate, necessary approvals. **No GitHub write was authorized or performed.**
