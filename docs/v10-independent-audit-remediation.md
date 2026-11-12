# Version 10 independent audit → Version 11 remediation

The independent Version 10 audit identified six reproduced failures in the offline portfolio application. The corrections below were implemented in **Version 11** and validated against the original negative reproductions, permanent regression tests, and a clean extracted release archive.

| Audit ID | Root problem | Implemented correction | Verification |
| --- | --- | --- | --- |
| V10-01 | Duplicate host or nested JSON keys silently overwrote a previous observation | Enforce `UniqueJsonKeys::assertUnique` on the raw, bounded response before associative decoding | CLI regression covering duplicate host, nested property, and Unicode-escaped alias; state remains unchanged on rejection |
| V10-02 | Complete-line error-template anchoring missed real WordPress/database banners with inline assistance | Permit narrowly bounded inline assistance on known error banners; retain tutorial/link exclusions | Three direct application tests, tutorial controls, and HTTP 500 → error-page CLI lifecycle |
| V10-03 | One malformed HTML response threw an exception and aborted all host checks | Distinguish malformed HTML from invalid observations; classify only that host as `unverified_html`, preserving confirmed failures and continuing sibling checks | Malformed-markup/UTF-8 controls and two-host CLI integration |
| V10-04 | Substring-matching `style` / `aria-hidden` accidentally matched `data-*` attributes | Quote-aware exact HTML attribute tokenization and first-attribute semantics | Positive controls for `data-*` and negative controls for real `hidden`, `style`, `aria-hidden` |
| V10-05 | Credential scanner missed camelCase JSON keys | Normalize camelCase/acronym/snake-case/dashed key segmentation; reject sensitive nonempty scalar/compound values and duplicate JSON object members | Synthetic JSON release-scan regressions including nested, camelCase, numeric and duplicate keys |
| V10-06 | External CSS `@import` in SVG bypassed static-file policy | Forbid SVG `<style>`/`<link>` elements, CSS `@import`, and prior active/external-reference patterns | Adversarial SVG import, local style-block, and safe-static SVG controls |

**Further release hardening:** The hosted workflow explicitly declares `permissions: contents: read` to minimize its GitHub token permissions. The strict publication scanner now also rejects duplicate object names in published JSON rather than allowing last-value-wins parsing.

## Trust and implementation boundaries

- `unverified_html` is **not** a positive healthy response and cannot close a prior outage; it records a failed attempt to classify a response. JSON parsing and observation-schema failures still abort the full input batch and preserve the prior state.
- Error-page and HTML visibility checks remain deterministic approximations of rendered application behavior. The classifier does not execute JavaScript, calculate external CSS, perform HTTP requests, or provide a fully conforming HTML5 parser. Prefer explicit per-target health endpoints and content requirements for any future real-world implementation.
- Release scanning rejects representative structured secrets and active SVGs. It is deliberately conservative and cannot prove complete confidentiality or intellectual-property clearance.
- The original company source, infrastructure inventories, and operational credentials are absent from the public ZIP; the code is an independently written synthetic demonstration.

## Verification and external gates

`php tests/run.php`, `php tools/lint.php`, `php tools/publication_scan.php --release .`, `php tools/verify_manifest.php .`, `sha256sum -c MANIFEST.sha256`, and both offline demo scripts are the local gates. The original external negative-reproduction script is rerun against a fresh extraction and must report **zero of six defects reproduced**. A clean ZIP is checked against an explicit file list and all SHA-256 hashes. Exact results appear in [validation](validation.md) and the separately delivered Version 11 release report.

Composer is not installed in this runtime, and a network download attempt failed at DNS resolution. PHPStan, Xdebug coverage, Composer lockfile generation and the hosted 8.2/8.3/8.4 GitHub Actions matrix are therefore **not certified locally**. The repository remains unmodified on GitHub until separately authorized.
