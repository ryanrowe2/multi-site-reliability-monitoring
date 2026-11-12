# Version 13 — Version 12 independent-audit remediation

This document describes changes made to the **independently written offline demonstration**, not the original California Machinery Movers implementation. The Version 12 audit reproduced eight incorrect monitoring recoveries and three release-scan bypasses. The original production source is not included.

| Audit finding | Severity | Implemented remediation | Permanent regression evidence |
| --- | --- | --- | --- |
| V12-01 — DOCTYPE and XML declarations treated as visible text | High | The shared `Classifier::htmlTokens()` lexer treats document declarations and processing instructions as markup, with quote-aware termination and bracket tracking for internal DOCTYPE subsets. An unterminated declaration becomes `unverified_html` rather than positive health evidence. | Empty-body DOCTYPE/XML assertions, nonempty control, full CLI recovery matrix |
| V12-02 — Hidden details' summary was incorrectly revealed | High | The first direct summary can reveal text for a *merely collapsed* details element; explicit `hidden`, `aria-hidden=true`, `display:none`, and opacity-zero concealment remain effective. Both content and fault parsing enforce the rule. | Four explicit concealment variants, first-summary positive control, CLI false-recovery matrix |
| V12-03 — HTTP 200 with a server 500/503 error banner reported healthy | High | The structural fault detector recognizes common standalone `500 Internal Server Error` and `HTTP Error 503. The service is unavailable.` banners, while keeping explanatory tutorial contexts non-faults. | Pure classification and documentation controls; CLI 500-to-200 tests |
| V12-04 — Missing void-element handling concealed following siblings | Medium | Both HTML paths use one complete HTML void-element list (`area`, `base`, `br`, `col`, `embed`, `hr`, `img`, `input`, `link`, `meta`, `param`, `source`, `track`, `wbr`). | Tests for `track`, `param`, `col` and CLI error-banners after void elements |
| V12-05 — JSON/YAML authorization fields and password-bearing connection strings missed | Medium | Structured-key recognition now includes `authorization`. JSON values and YAML lines also detect credential-bearing URI userinfo without flagging ordinary public example URLs. | Isolated strict-release scanner negative cases and a benign positive control |

## Executed local checks

- Existing suite: 236/236 passing before the fixes.
- Expanded suite: **252/252 passing** on PHP 8.4.24 after the changes.
- Original independent Version 12 reproduction script: **11/11 previous defects no longer reproduced** against the repaired source and final archive.
- The final release verification also repeats PHP syntax checking, the strict publication scan, manifest completeness and file-hash verification, two offline demonstration scripts, documentation-link validation, and checks the clean extraction rather than trusting the working tree.

## Scope and remaining evidence

The HTML classifier is a bounded offline approximation, not a fully conformant browser layout engine. External CSS, JavaScript and real network transport are intentionally excluded. The scanner is a conservative heuristic rather than a proof that credentials or intellectual property are absent. Employer publication-rights review remains necessary.

Composer, PHPStan, an immutable dependency lockfile, Xdebug-measured coverage, and hosted PHP 8.2/8.3/8.4 CI have not been verified in this environment. No passing results are claimed for them. The repository must remain unpublished until separately authorized.
