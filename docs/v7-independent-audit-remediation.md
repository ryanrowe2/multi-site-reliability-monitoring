# Version 7 independent audit — Version 8 corrective changes

The historical employer-owned monitor was neither edited nor published. These changes refer **only to this independently written synthetic PHP demonstration**. They were applied to a local copy of the Version 7 ZIP; the original ZIP and GitHub account were not modified.

| Audit ID | Corrective action | Regression evidence |
| --- | --- | --- |
| V7-01 (High) | Tokenize HTML with quote-aware tag boundaries; a `>` inside a single- or double-quoted attribute no longer truncates `hidden`/inline-style parsing. Malformed tags fail closed. | `V7-01` quoted-attribute and end-to-end false-recovery tests |
| V7-02 (High) | Scan literal secret-bearing PHP variable assignments in addition to environment, constant, bearer and platform token formats. | `V7-02` isolated scanner positive/negative fixtures and independent regression F |
| V7-03 (Medium) | Recognize nearby wrapped tutorial introductory paragraphs without exempting later independent failure headings. | `V7-03` nested intro, later error controls; independent B1 |
| V7-04 (Medium) | Exclude illustrative fatal-error `<pre>` blocks in instructional context even outside `<article>`; preserve standalone real fatal errors. | `V7-04` documentation and independent subsequent failure controls; independent B2 |
| V7-05 (Medium) | Normalize Unicode whitespace consistently in both observed visible text and configured content sentinel. | `V7-05` NBSP, thin and narrow spacing; independent C |
| V7-06 (Medium) | Detect 502/504 displayed gateway error templates with support-page negative controls. | `V7-06` proxy error and educational controls; independent D |
| V7-07 (Medium) | Forbid overlap between confirmed issue and unknown-history maps. When a previously failed target becomes unverified, suspend the last confirmed issue *inside* its unknown-history entry. Only a later healthy result generates recovery. | `V7-07` invalid persisted state, suspended failure, repeat failure, changed failure, retirement; independent E |

### State compatibility and migration

The Version 8 model enforces `issues` and `unknown_history` as disjoint target maps. Earlier Version 7 files may have stored the same target in both maps after an outage became unverified. Those snapshots **fail closed**, preserving the original file and pending outbox. They require explicit reviewed reconciliation; the CLI does **not** silently convert, delete, or overwrite them. New Version 8 states suspend an unresolved failure under `unknown_history[target].last_confirmed_issue` and preserve its original timestamps and code. A return to a matching confirmed failure does not manufacture a new incident; a verified recovery or target retirement closes it once.

### Execution and boundaries

`php tests/run.php` exercises all original and expanded regression paths, while the separate Version 7 independent test script tests nine independently authored scenarios. `php tools/lint.php` checks all application, test, tool **and fixture** PHP files. The publication scanner, SHA-256 manifest verifier, demonstration scripts and clean-extraction test suite must all pass against the final ZIP. The result cannot certify actual network reachability, browser-equivalent HTML rendering, employer operations, downstream alert delivery, or unavailable Composer/PHPStan/Xdebug/PHP-version CI checks.
