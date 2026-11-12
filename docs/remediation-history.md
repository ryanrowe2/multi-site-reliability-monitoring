# Remediation history and independent regression evidence

The original employer-owned source was reviewed privately, not included in this public demonstration. This record refers to **an independently written synthetic demonstration**, not modifications to that historical deployment. The detailed source-provenance assessment is in [audit and remediation](audit-and-remediation.md).

## Fifth independent audit: V5 → V6

The Version 5 audit reproduced ten current defects. Version 6 corrects each in the **new synthetic implementation**, with the `V5-` regression tests in `tests/run.php`. These changes do not modify or claim to repair employer-owned historical code.

| ID | Remediation | Verification |
| --- | --- | --- |
| V5-01 | Scope educational exemptions to their own article heading; recognize a second live failure in the same document | Pure classifier and two-execution CLI false-recovery regressions |
| V5-02 | Detect synthetic WordPress `define()` secrets, bearer headers, labeled credentials, and forbidden `wp-config.php` names | Isolated strict-release scanner negative fixtures |
| V5-03 | Validate all required outbox event fields, types, timestamps, and lengths at queue admission and read | Invalid persisted event blocks `flush` without state mutation; unrelated-mode negative case |
| V5-04 | Validate complete uptime and integrity histories before any state transaction, including flush | Cross-mode corrupt-history CLI and replay tests |
| V5-05 | Support unquoted inline styles, zero opacity, hidden ancestors, and implicit title text removal | Hidden-marker negative fixtures with visible control |
| V5-06 | Normalize Unicode spaces and formatting characters before applying minimum-visible-content thresholds | NBSP, zero-width, and narrow-space fixtures |
| V5-07 | Ignore navigation/footer documentation and article code samples for automatic outage signatures | Footer, navigation, tutorial, and real fatal-error controls |
| V5-08 | Emit explicit verification closure or retirement events for previously escalated gaps | Pure lifecycle, retirement, and two-execution CLI regressions |
| V5-09 | Normalize a terminal DNS dot before same-host redirect comparison | Safe same-host and lookalike-host controls |
| V5-10 | Persist the empty mode map as `{}` at the final serialization boundary | Fresh `flush` state-file regression |

Release-scan regex failures now fail closed, and the history validator is shared between transition and state-load paths to reduce drift. No claim is made that heuristic secret scanning can detect every possible credential or that offline page classification proves real network availability.

## Latest independent audit: V4 → V5

Version 5 addresses every confirmed issue in the 2026-11-11 Version 4 independent audit. Regression names are indexed in `tests/run.php` using `V4-xx` labels. Local regression results are documented in [validation](validation.md).

| ID | Original failure | Remediation | Executable regression evidence |
| --- | --- | --- | --- |
| V4-01 | Unrelated footer documentation text suppressed real WordPress/database errors, allowing false recovery | Detect standalone error signatures without a page-wide article flag; narrowly recognize a tutorial introduction inside the same article | `V4-01` WordPress 500→critical-page transition and database page |
| V4-02 | Elementor Core byte changes escaped integrity checks | Require `core_baseline_sha256` and independently hash the complete synthetic Core directory | `V4-02` unchanged-version Core mutation and absent digest |
| V4-03 | Text in hidden HTML elements satisfied visible-content assertions | Exclude head/script/style and explicit hidden/aria-hidden/inline-hidden descendants from bounded text extraction | `V4-03` five invisible cases and visible control |
| V4-04 | 201 and other non-200 successful responses escaped application-error detection | Scan all complete body-bearing 2xx responses for critical signatures | `V4-04` 201/202/207/299 cases |
| V4-05 | 206 Partial Content counted as a complete healthy page | Treat 206 as `unverified_partial_response`; preserve open incidents | `V4-05` partial-sentinel and state transition |
| V4-06 | A pristine baseline-matching site was assigned a sibling's integrity incident | Restrict cross-site divergence incidents to sites failing their own trusted synthetic baseline | `V4-06` one mutated site, one clean site |
| V4-07 | Explicit `issues: null` erased history | Reject explicit null; support absent legacy keys and previously returned empty object | `V4-07` invalid history |
| V4-08 | Corrupt other-mode pending alerts survived a successful transaction | Deeply validate pending entries and claims in **both** outbox modes on every access | `V4-08` cross-mode corruption and unchanged on-disk state |
| V4-09 | Impossible future claim blocked replay indefinitely | Validate claim tokens; reclaim leases outside the permitted wall-clock range while preserving pending IDs | `V4-09` far-future claim and malformed token |
| V4-10 | StateEngine could not consume its own empty-map output | Keep consistent in-memory arrays; convert empty maps to JSON objects solely in StateStore | `V4-10` two pure transitions |
| V4-11 | Persistent unverified targets never appeared in event-only alert streams | Add `unknown_history` and separate `verification_gap` / `verification_gap_reminder` events after configured thresholds | `V4-11` pure threshold/reminder sequence and CLI integration |
| V4-12 | Secret scan missed representative GitHub, Slack, npm formats | Extend strict-release patterns without storing any real token | `V4-12` three synthetic leak fixtures |
| V4-13 | Invalid prior `inventory` fields were silently discarded | Validate prior inventory and unknown lists without losing legitimate legacy compatibility | `V4-13` malformed inputs and legacy control |

## Earlier engineering iterations

Earlier rounds remedied original prototype limitations: atomic persistent state, incident retirement, retryable stdout outbox and replay, delivery batching and backpressure, safe redirect classification, configuration validation, deterministic directory fingerprints, tokenized synthetic plugin metadata, strict publication scanning, bounded JSON reads, a checked SHA-256 manifest, and offline CLI integration. These features are verified by the earlier `CMM-`, `NEW-`, and `V3-` tests in `tests/run.php`. The original source issues and newly written changes are distinctly labeled in [the historical audit](audit-and-remediation.md).

## Explicit external quality gates

The locally executable suite, PHP syntax checker, release scanner, manifest verifier, and demos have been run. **Composer dependency resolution, PHPStan, Xdebug coverage, and hosted PHP 8.2/8.3/8.4 checks have not been executed in this environment**, which lacks the binaries or access required. Neither a lockfile nor successful CI checks is fabricated. The application is still offline-only; stdout is a local handoff, not proof of downstream notification delivery. Legal authorization to publish employer-owned code is neither assumed nor needed for the independently written synthetic implementation.

## Version 6 independent audit remediated (Version 7 local package)

The subsequent independent audit isolated **9 findings**. See [the complete itemized evidence](v6-reaudit-remediation.md) for the implemented repairs and new unit/CLI/negative-path regressions. The original 14-scenario audit script returned no reproduced failures on a repaired temporary archive. These changes strengthen the standalone demonstration; they do not imply that the employer-owned production system or external CI was modified or tested.

## Seventh independent audit: V7 → V8

Seven confirmed defects from the Version 7 independent review were repaired in the independent demonstration. The original nine-scenario external regression script and new `V7-` tests in `tests/run.php` verify the results. See [the itemized Version 8 remediation report](v7-independent-audit-remediation.md) for reproduction mapping and an explicit legacy state migration warning.

## Ninth independent audit: V9 → V10

Eight additional defects in release Version 9 were reproduced independently, then corrected in a new Version 10 local package. They concern missing/duplicate persisted history, compact JSON credentials, CSS visibility comments, overlong historical names, unrelated-mode configuration validation, support-form examples and active SVG files. The permanent `V9-` regressions and original independent reproducer confirm the correction; see the [Version 10 correction record](v9-independent-audit-remediation.md) for evidence and remaining limits.

## Tenth independent audit: V10 → V11

Six further defects were reproduced against Version 10 and corrected in the Version 11 local package: duplicate response observation keys, failure banners with inline help, malformed-HTML fleet interruption, `data-*` visibility collisions, camelCase JSON credentials, and external stylesheet imports in SVG. New tests cover the original negative reproductions as well as related input-boundary and release-safety controls. The CI workflow now declares `permissions: contents: read`. Details and validation boundaries are in [the Version 11 remediation record](v10-independent-audit-remediation.md).


## Version 12 — Version 11 independent audit remediation

Six independent findings were corrected: prefixed server-error banners triggering false recoveries; tutorial examples triggering false incidents; inherited inline visibility; YAML secrets; generic PHP `define()` secrets; and entity-obfuscated SVG active links. The application now separates structural fault-region analysis into `HtmlFaultDetector`, and the release gate applies conservative YAML, PHP token, and static-SVG policies. Eight additional permanent regression tests cover the six findings and two related visibility-consistency cases, including end-to-end recovery continuity. The clean release evidence and external execution limits are documented in [Version 12 validation](validation.md) and [Version 11 audit remediation](v11-independent-audit-remediation.md).


## Version 13 — Version 12 independent-audit remediation

The fresh audit identified five failure classes: declaration text satisfying content checks; concealed details summaries treated as visible; missed 500/503 HTML banners; omitted HTML void elements; and credential-bearing JSON/YAML authorization or connection URI values escaping the release scan. Both markup consumers now share the full void-element list; summary visibility preserves explicit concealment, declarations are tokenized as markup, common standalone server error templates are classified as failures, and the scanner detects structured authorization/URI credentials. Sixteen new tests exercise the reported cases, healthy controls, and eight end-to-end recovery sequences. See [Version 13 remediation details](v12-independent-audit-remediation.md) and [current verification](validation.md).

## Version 13 independent audit → Version 14

Eight observed findings prompted a shared non-rendered-element policy, conservative unknown results for unsupported HTML and CSS escape syntax, tighter structurally grounded instructional-context checks, YAML environment-sequence secret scanning, credential-container JSON detection, and a separate static-SVG structure validator and CI gate. See the [issue-by-issue record](v13-independent-audit-remediation.md) and [current validation](validation.md). The original historical source remains unchanged.

## Version 14 independent audit → Version 15

The 11 reported issue classes prompted a conservative confirmation policy: empty HTTP 200 responses now fail the minimum visible-content check; meta refresh and ambiguous instructional/server-error regions remain unverified; unselected options cannot confirm health; inline anchor text within headings remains part of application-error banners; error-template recognition includes `500 - Internal Server Error`; and standalone preformatted error examples no longer create confirmed database incidents. The uptime-only verification settings are validated only for uptime, Unicode comparison uses optional ICU NFC with a portable fallback, and the scanner recognizes abbreviated `pass`/`pwd` keys while rejecting SVG inline styles. The [itemized remediation record](v14-independent-audit-remediation.md) and `V14-` tests describe the evidence.

## Version 15 comprehensive audit → Version 16

The independent 16-class audit identified recurring visibility, navigation, non-page 2xx recovery, error-evidence aggregation, sensitive-source screening, SVG static-policy, and state-writer defects. Version 16 uses one shared `InlineVisibility` evaluator, conservative unknown classification for unsupported CSS, decoded active meta refresh, non-page success contracts, an evidence scanner that does not stop at the first ambiguous example, expanded release security, and one state read/write schema. See [Version 16 remediation record](v15-comprehensive-remediation.md) for traceability and execution evidence. External Composer/PHPStan/Xdebug and hosted PHP matrix validation remain unverified.
