# Version 8 independent audit — Version 9 remediation

The original employer-owned infrastructure monitor, prior Version 8 ZIP, and GitHub remain unchanged. All modifications described here belong exclusively to the newly authored offline PHP portfolio demonstration.

| Finding | Corrective change | Permanent verification |
| --- | --- | --- |
| V8-01 — Valid JavaScript/CSS/textarea aborts scan | `Classifier::htmlTokens` now distinguishes markup and text and treats script/style/textarea/title content as raw-text or RCDATA up to a matching end tag; an ordinary text less-than sign is preserved | `V8-01` direct cases and CLI sibling-host incident test |
| V8-02 — nginx 504 generates false recovery | Error signatures recognize both `Gateway Timeout` and `Gateway Time-out`, with or without HTTP 504 text | `V8-02` direct positive/negative and two-step CLI lifecycle |
| V8-03 — Small backward clock change breaks claim exclusivity | Outbox stage grants bounded backward-clock tolerance when assessing authenticity of a future lease; far-future claims still recover | `V8-03` deterministic skew/expiry regression; earlier impossible-future tests |
| V8-04 — PHP array/object/short secrets not flagged | Strict scanner additionally inspects PHP lexical tokens for literal assignments to password/credential-like variable, array, property or constant keys; comments are ignored | `V8-04` staged-release scanner cases; original scanner tests |
| V8-05 — Incorrect inline CSS priority | Inline `display`, `visibility`, `opacity` values use last declaration of the highest `!important` priority | `V8-05` visible/hidden cascade controls |
| V8-06 — Historical incident too long to deliver | Persisted `code`, `detail`, and incident target lengths conform to event-outbox limits during history validation; malformed snapshots fail before committing | `V8-06` direct rejection and CLI file-preservation regression |
| V8-07 — Stale validation summary | `docs/validation.md` now opens with the current release evidence and links to historical-version records | Documentation link checks and final release review |

## Relevant design limits

- The HTML scanner now handles normal raw-text elements, but it is still a small, bounded lexer rather than a complete HTML5 tree builder or browser renderer. External CSS, scripts, and accessibility semantics are not computed.
- Claim timestamps use local wall-clock seconds, and the tolerance is finite. The outbox is a **single-host at-least-once stdout handoff**, not a distributed fencing or exactly-once delivery protocol. Downstream consumers should deduplicate on the event `id`.
- PHP token inspection recognizes common literal assignment patterns; generated strings, runtime-loaded secrets, obfuscation and ownership issues still require human review and specialized scanners.
- Rejecting malformed historical state is intentional. This implementation does not silently rewrite or discard incident histories; manual reconciliation must preserve queued events.
- External Composer/PHPStan/Xdebug/PHP-version CI checks remain unverified until an authorized compatible environment actually runs them.

All synthetic tests avoid company domains, original operational configuration, and real third-party infrastructure.
