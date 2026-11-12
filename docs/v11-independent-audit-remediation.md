# Version 11 independent audit → Version 12 remediation

The prior independent audit found **six reproducible defects** in Version 11. Version 12 changes the underlying fault-evidence architecture and improves the release scanner. No company hosts are contacted, no original company source is published, and GitHub is not modified.

| Finding | Implemented change | Regression evidence |
| --- | --- | --- |
| V11-01 — False recovery on prefixed database banner | `HtmlFaultDetector` recognizes structural database-error regions prefixed `Database Error:` and feeds the existing state engine a confirmed error instead of healthy | `V11-01` classifier plus two-run CLI lifecycle |
| V11-02 — Documentation example becomes incident | Evaluate text regions by element context, suppress adjacent instructional examples and link titles without suppressing independent error sections | `V11-02` instructional layouts and separate real-error region |
| V11-03 — Visibility inheritance incorrect | Separate inherited `visibility` from ancestor-enforced `display:none`/`opacity:0` and explicit hidden states | `V11-03` visible descendant and hard-hidden ancestor |
| V11-04 — YAML credential detection misses realistic values | Conservative YAML mapping and URL-userinfo inspection, including flow mappings and short passwords | `V11-04` nested accessToken, DB password, connection URL, flow mapping and safe control |
| V11-05 — Generic PHP define secret ignored | Token-aware scan of literal `define()` calls using normalized sensitive keys | `V11-05` synthetic APP_PASSWORD constant and safe control |
| V11-06 — SVG character-encoded executable link | Fail-closed static-SVG policy rejects entity references, links, scripts and external styles/resources | `V11-06` encoded-link rejection and safe SVG control |

## Architecture

`Classifier::classify()` handles transport, HTTP, redirect and configured content policies. It delegates application-error detection to `HtmlFaultDetector::detect()`, which processes a bounded, quote-aware HTML token stream into element-scoped text regions and evaluates faults in local instructional context. An explanatory passage in one structural section cannot silently suppress a later independent error section. Visibility remains an explicitly supported approximation and the source does not claim a full HTML5 parser, browser rendering, or universal error recognition.

`tools/publication_scan.php` performs format-aware checks on JSON, key/value-based YAML, PHP tokens and deliberately static SVG diagrams in addition to generic secret markers and file checks. Complex YAML, encoded obfuscation, or arbitrary secrets can still escape heuristic recognition; a green scan is not a confidentiality or legal guarantee.

## Verification boundaries

Permanent tests and the independent Version 11 negative-reproduction scenarios must pass on the clean final archive. Composer, PHPStan, Xdebug coverage and hosted PHP 8.2/8.3/8.4 jobs may be marked passing **only when executed**. The independent synthetic implementation is not deployed production code and does not demonstrate email delivery, uptime improvement or employer publication authorization.
