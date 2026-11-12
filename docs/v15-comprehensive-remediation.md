# Version 15 comprehensive independent audit → Version 16 remediation

**Scope:** all 16 confirmed issue classes from the independently generated `cmm-v15-comprehensive-audit/AUDIT_REPORT.md`. The historical business code was not changed or published. This is a separate synthetic offline implementation.

| ID | Change | Regression evidence |
|---|---|---|
| H-01 | Shared CSS evaluator recognizes fully transparent percentages/exponent opacity values | V16 CSS tests; randomized CSS re-audit |
| H-02 | Concealing or unsupported CSS cannot establish positive/negative health evidence without computed layout | V16 CSS and persisted-incident tests |
| H-03 | Decode HTML attribute references for active meta refresh | V16 meta-refresh test; independent end-to-end test |
| H-04 | Default non-200 2xx statuses, including 204/205, are unverified without an explicit host health policy | V16 status tests, end-to-end transition test |
| H-05 | Recognize displayed database/WordPress error headings with bounded trailing text | V16 banner test and independent lifecycle probe |
| H-06 | Normalize compact database/pass/auth/token aliases for JSON/YAML | V16 scanner tests; 54-case and 77-case matrices |
| H-07 | Detect YAML environment sequence/flow-style credential assignments | V16 scanner tests and 54-case matrix |
| H-08 | Inspect PHP source string tokens for database URLs containing userinfo passwords, regardless of variable name | V16 scanner tests and independent matrix |
| H-09 | Detect concatenated literal URLs, generic secret declarations and password heredocs | V16 scanner tests; prior scanner regression suite |
| H-10 | Fail-closed on CSS escape sequences inside static SVG | V16 scanner tests, SVG validator |
| M-01 | Continue scanning later evidence after an ambiguous documentation example | V16 later-banner test |
| M-02 | Skip refresh elements within templates; reject malformed refresh directives as navigation evidence | V16 inert/invalid refresh test |
| M-03 | Validate proposed state with the same read-side schema **before** writing/renaming | V16 invalid-write rollback test; independent CLI property probes |
| M-04 | Distinguish post-rename sync warning from precommit failure; commit remains successful | Namespaced filesystem fault-injection reproduction |
| L-01 | Require SVG root namespace and reject undeclared namespace prefixes | V16 scanner tests; SVG validation |
| L-02 | Remove stale Version 14 verification statement | `docs/validation.md` corrected |

## Engineering design decisions

- Shared CSS interpretation prevents the two existing structural HTML walkers from disagreeing on the most consequential hiding properties. These paths also share the HTML token lexer, exact attribute parsing, void-element list and inert-element policy. This is not a complete HTML5/CSS browser.
- A successful HTTP status is not automatically a verified application response. Explicit per-host assertions strengthen recovery evidence. Unsupported UI rendering and ambiguous markup are **unknown**, not healthy.
- State `write()` validates the same fully serialized JSON shape and incident/outbox records as `read()` before replacing any on-disk state. Post-rename directory sync failures are warnings about power-loss durability after a successful replacement.
- Publication scanning is intentionally conservative and accepts only restricted text/SVG file types. A passing scan is **not** a warranty against all credential obfuscation, proprietary materials, or unsafe public-distribution rights.

## Executed validation and boundaries

The repository's complete suite, independent negative reproductions, randomized CSS/credential matrices, state-transition properties, and clean-archive validations are recorded in the accompanying Version 16 release verification report. Composer, PHPStan, Xdebug and the hosted multi-PHP-version CI matrix remain unverified in this environment; do not report them as passed. The original private source and connected GitHub repositories remain untouched.
