# Version 9 independent audit — Version 10 remediation

This is a correction record for the independently written, **offline synthetic** monitoring portfolio project. It is not a claim that the historical employer-owned deployment was modified.

## Audit finding → actual correction → observed regression

| Finding | Remediation in Version 10 | Regression / evidence |
| --- | --- | --- |
| **V9-01** — missing `issues` silently discards a failure | Require `issues` for every nonempty persisted mode snapshot. An empty initial state remains valid; incomplete historical snapshots fail without rewriting. | `V9-01` flush and continued monitoring preserve the malformed file; current-schema validation test |
| **V9-02** — duplicate JSON members overwrite incident maps | New `UniqueJsonKeys` lexical check detects repeated object members, including Unicode escape equivalents, before associative JSON conversion. Also used for configuration loading. | `V9-02` duplicate state/configuration tests; original independent script |
| **V9-03** — compact JSON secrets bypass scanner | Recursively inspect structured JSON for sensitive credential-key labels, even if minified or nested, with an explicit fail result. | `V9-03` strict-scan negative tests and benign control |
| **V9-04** — commented CSS bypasses visibility checks | Remove complete CSS block comments before evaluating inline visibility declarations; unclosed comments do not establish visibility. | `V9-04` hidden-marker, precedence and full incident-to-response CLI checks |
| **V9-05** — oversized historical unverified target jams event admission | Apply the same 253-byte target limit to all prior inventory/unknown names that the event journal enforces. | `V9-05` in-memory history and immutable-state CLI negative tests |
| **V9-06** — unrelated mode configuration blocks a valid mode | Validate integrity-specific settings only for integrity; content-policy settings only for uptime. Shared top-level keys remain strictly checked. | `V9-06` both-mode CLI isolation test; revised selected-mode typo regression |
| **V9-07** — support form input examples generate false incidents | Exclude `<textarea>` contents from automatic application-error signatures; retain explicit page-content policy behavior. | `V9-07` healthy form and genuine error outside form control |
| **V9-08** — active SVG survives release scanning | Reject SVG event attributes, scripts, executable URLs, external fetches, dangerous embedded elements and entity directives in strict scans. | `V9-08` active-event, scripting, external-reference and static-control probes |

The original Version 9 eight-scenario independent reproduction script reported **0/8 defects still reproducible** against a rebuilt provisional Version 10 package. Regressions are now permanent in `tests/run.php`, including full CLI negative paths. These repairs improve the local synthetic demonstration; no external uptime or business outcomes are claimed.

## Persistence compatibility

**Incomplete state history is not automatically migrated.** A previously saved file with missing `issues` or duplicate JSON members is rejected unchanged, rather than guessing whether a failure was resolved. Preserve and reconcile a backup explicitly before resuming. Existing complete valid snapshots and clean first-run states remain supported.

## Confidence boundaries

- The strict scan checks recognized secret labels and specific SVG execution patterns; it does not prove universal absence of secrets or replace copyright/permissions review.
- HTML visibility remains an approximation, not a browser implementation of stylesheets or scripts.
- File-level stdout delivery retains at-least-once semantics, not confirmed downstream notification receipt.
- The application intentionally does **not** contact production websites or distribute employer code.
- Composer installation, dependency locking, PHPStan, Xdebug coverage and hosted CI must be completed in a compatible authorized environment. These are not recorded as passing.
