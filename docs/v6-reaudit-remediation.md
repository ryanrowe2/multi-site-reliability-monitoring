# Version 6 independent re-audit — remediation evidence

The **Version 6 independent audit** reported **nine confirmed findings** (three high, five medium, one low), supported by 14 isolated synthetic reproductions. The changes in this release are to the **new public demonstration**, not the confidential historical application. All tests below run without external infrastructure.

| Audit ID | Severity | Implemented correction | Regression evidence |
| --- | --- | --- | --- |
| V6-01 | High | Normalize HTML-entity-decoded Unicode separators and treat inline `<br>` as a continuation when matching constrained standalone WordPress/database errors | `V6-01 database/critical errors normalize HTML NBSP and inline breaks` |
| V6-02 | High | Treat native closed `<dialog>` and collapsed `<details>` as hidden, preserving the first visible direct `<summary>` | `V6-02 closed details and dialog`, `V6-02 CLI does not falsely recover` |
| V6-03 | High | Recognize PHP `putenv(...)` assignments and `const` declarations for secret-bearing names in the strict publication scanner | `V6-03 strict release scan detects PHP putenv and constant secrets` |
| V6-04 | Medium | Ignore ordinary `<pre>` examples when identifying database/WordPress error templates, while preserving standalone PHP fatal output | `V6-04/05 examples and help-link titles` and existing V5 PHP fatal display test |
| V6-05 | Medium | Exclude support-link text from automatic application-error evidence regardless of its surrounding HTML container | `V6-04/05 examples and help-link titles` |
| V6-06 | Medium | Exempt only an error heading immediately followed by an actual instructional introduction, in a common `<main>` as well as `<article>` context | `V6-06 instructional heading outside article` |
| V6-07 | Medium | Detect the constrained `503 Service Temporarily Unavailable` error-page variant | `V6-07 HTTP 200 service-temporarily-unavailable` |
| V6-08 | Medium | Enforce relationships among prior inventory, unverified targets, unverified history, and known incidents; reject incomplete current-format histories | `V6-08 inconsistent previous verification inventory`, `invalid history is rejected`, `incomplete current-format verification state` |
| V6-09 | Low | Decode persisted JSON with object/list identity intact before associative conversion, rejecting wrong envelope and nested collection shapes without rewriting | `V6-09 JSON list and object envelopes are not conflated` |

## Release-independent reproduction results

The original audit reproduction program was run against a **new temporary ZIP containing the repaired sources**. All **14/14** previously failing scenarios returned `NOT REPRODUCED`, including the end-to-end false recovery and unchanged-on-failure persisted state. This result does not imply coverage of every possible HTML document or every credential format.

## Validation scope and boundaries

The local tests execute on PHP 8.4 with deterministic synthetic fixtures. The HTML extractor is a hand-written, bounded approximation and does not evaluate CSS classes, external stylesheets, JavaScript, or browser layout. Content assertions remain policies over the extracted approximation rather than proofs of what a real user sees. The publication scanner looks for common unsafe content; it does not guarantee absence of secrets or employer-owned material. Human review remains mandatory.

No live requests are made. No original company inventory, credentials, source code, or historical incident state were added. No GitHub repository has been created or modified.

See [validation](validation.md) for commands/results and [provenance](provenance-and-limitations.md) for supported historical claims and ownership limits.
