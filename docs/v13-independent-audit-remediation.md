# Version 13 independent audit — Version 14 remediation

The Version 13 audit found eight failure classes in the **independently written offline portfolio demonstration**. Version 14 changes only that demonstration. All hosts, values and WordPress fixtures in the tests are synthetic. The original business source and GitHub repositories are unchanged.

| Finding | Verified remediation | Regression |
| --- | --- | --- |
| C13-01: inactive browser content proves health | Shared `Classifier::isNonRenderedElement()` excludes closed popovers, datalist, iframe/canvas/object/media fallback and non-rendered infrastructure in both visibility and error recognition | Paired content/error cases and full CLI false-recovery matrix |
| C13-02: error banner suppressed by nearby guide mention | Tutorial suppression now requires explicitly instructional neighboring prose in the same section; unrelated guide links and unavailable-guide text never suppress a genuine error heading | Error-banner classifier and full CLI tests |
| C13-03: prefixed tutorial headings cause incidents | The `Database Error:`/`WordPress Error:` prefix no longer bypasses local instructional-context evaluation | Prefixed tutorial classifier/CLI control |
| C13-04: HTML non-void `/>` bypasses a hidden ancestor | The shared lexer rejects ambiguous non-void self-closing HTML as `unverified_html`, not verified healthy; void tags remain allowed | Void/non-void classifier tests and CLI |
| C13-05: CSS escapes defeat visibility checks | Escaped inline styles are treated as unsupported, yielding `unverified_html` without ending an unresolved incident | Escaped style properties/values, CLI |
| C13-06: YAML environment secrets missed | Scanner now correlates `name:`/`value:` list entries and catches environment `KEY=value` and inline flow maps and direct environment lists | Three distinct YAML scanner negative tests |
| C13-07: JSON credential-container keys missed | Structured-key detection now includes normalized `credential(s)` and camelCase `databaseCredentials` | Nested and scalar JSON negative tests |
| C13-08: malformed SVG passes release gate | Added `StaticSvgValidator`, mandatory scanner rejection of malformed static XML, independent CLI validation of packaged diagrams and a GitHub Actions step | XML structure tests, separate SVG CLI check |

## Deliberate safety semantics

This demonstration cannot calculate browser layout, execute JavaScript, fetch remote stylesheets, or perform the complete HTML5 tree-construction algorithm. It treats unsupported ambiguous markup as **unverified**, never as proof of recovery. Non-rendered fallback/UI content cannot satisfy a required visible-text marker. The list of elements represents conservative mainstream browser defaults, not a promise of rendering equivalence under all CSS or browser configurations.

The static SVG validator implements a **restricted lexical XML subset** suitable for these two static diagrams; it is not a general XML 1.0 validator. It rejects DTDs, entities, active processing instructions, duplicate attributes, mismatched closing tags and unclosed markup. The release scanner separately rejects scripts, hyperlinks, CSS imports and remote resources.

YAML scanning covers the formats exercised by the audit, common nested mappings, flow maps and environment list assignments, but it is not a complete YAML parser. Manual content/IP review and an independent secret scanner remain appropriate before public release. These checks cannot establish legal permission to publish historical employer work product.

## Reproduce locally

```bash
php tests/run.php
php tools/lint.php
php tools/validate_svg.php
php tools/publication_scan.php --release .
php tools/verify_manifest.php .
sha256sum -c MANIFEST.sha256
bash examples/run-lifecycle.sh
bash examples/run-integrity-demo.sh
```

The original Version 13 independent reproduction program was also rerun against the repaired candidate from an isolated directory, with all 14 previously failing scenarios corrected. Its output and the full extracted-archive checks are recorded in the separate Version 14 release report.

## Certification limits

PHP 8.4 local validation is not evidence of a hosted PHP 8.2/8.3/8.4 matrix. Composer, PHPStan, dependency locking and measured Xdebug coverage remain unverified when their local executables are unavailable. A publication-rights review and explicit user approval remain necessary before GitHub changes.
