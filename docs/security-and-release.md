# Publication safety and security boundary

This repository is independently authored from high-level monitoring concepts and contains **no original private company PHP source**. The public hostnames are under `example.com`, `example.org`, or similarly reserved test namespaces; plugin content and simulated observations are synthetic. Do not copy private inventory, operational recipients, production paths, credentials, or employer-owned artifacts into this package.

## Release validation

`php tools/publication_scan.php` is the **working-tree** scan and skips generated `.git/`, `vendor/`, `var/phpstan-cache/` and locally generated `composer.lock` files. `php tools/publication_scan.php --release DIRECTORY` instead examines **every actual publication payload** (including a packaged `composer.lock` if present) and refuses generated/private directories. The strict mode detects symlinks, unexpected file extensions, non-UTF-8/binary text, suspicious key markers (including synthetic AWS secret-access-key assignments) (including encrypted key headers), longer unquoted secret assignments, representative GitHub, Slack and npm token formats, unsafe filenames and non-example emails. Documentation, workflow YAML, SVGs and tests are within scope. Independent tests seed safe fake markers and verify rejection.

GitHub CI now builds a separate clean staging tree from `git archive HEAD` and scans that exact tracked release content with `--release`. The same clean staging step checks `sha256sum -c MANIFEST.sha256` and `php tools/verify_manifest.php` so both modified **and unlisted** publication files fail CI. Before publishing any ZIP, repeat all three checks on its independent fresh extraction. The hosted Actions commits are pinned to reviewed SHA values.

This is a **heuristic pre-publication gate**, not a comprehensive credential scanner or a substitute for reviewing code and data ownership. The release archive should be independently inspected after packaging; no separate private source directory belongs in that ZIP. Never run the scanner against an extracted tree that also contains unrelated private files and then dismiss hits as irrelevant.

## Runtime safeguards

- The executable CLI has **no network transport** and requires offline observations. The earlier untested illustrative cURL adapter has been removed.
- Hostnames must use reserved documentation/test suffixes. The allowed fixture root is inside the supplied config directory or packaged fictional fixtures.
- The classifier never follows redirects; same-origin redirects are **unverified**, not assumed failed or healthy. A request to a different host is an explicit failure classification without a follow-up request.
- Directory hashing and integrity diagnostics reject symlinks and handle invalid sites individually.
- State and lock symlinks are rejected, mode writes serialize with `flock`, and persistent events have at-least-once stdout replay semantics. File and directory fsync occur on supported POSIX filesystems.
- No API keys, real SMTP destinations, live cron commands or WordPress installations are distributed.

## Explicit limitations

A stdout write is not an external delivery acknowledgment; a failed acknowledgment can cause a duplicate replay. The 120-second lease is not a distributed leader-election service. A detached scheduler watchdog would be required to alert when the CLI never runs. Local filesystem reliability, hardware power-loss guarantees and source control permissions are outside the offline test suite. Real network monitoring and dynamic WordPress checks would require a separate authorized implementation and security review.

## Input-size and schema contracts

Configuration (1 MB), response observations (5 MB) and persisted state (5 MB) are read through a bounded, regular-file reader with pre-read size checks and bounded chunks. Oversized synthetic responses fail as controlled input errors rather than triggering a PHP out-of-memory fatal before the size check. The CLI validates unknown configuration keys, including nested reminder/expected-interval settings and integrity hash keys. Existing malformed outbox envelopes fail without resetting the journal. These safeguards do not promise safe decoding of every pathological JSON shape under arbitrarily tiny PHP memory limits.

## Version 6 audit: PHP-embedded secret patterns

Strict scanning now rejects representative credential-looking assignments embedded in PHP `putenv` strings and `const` declarations, in addition to existing WordPress constants, private-key markers, environment assignments and common token forms. Tests use entirely invented values. The scanner is intentionally a **heuristic warning gate**, not a comprehensive secret detector; review each new source file, fixture, documentation file, CI workflow, and license/ownership claim before any publication.

## Version 8 release gates

The strict publication scanner additionally recognizes ordinary PHP secret-bearing assignments such as a literal value assigned to a variable ending in `password`, `token`, `secret`, or `api_key`. Tests construct synthetic values at runtime so secret-shaped dummy assignments are not inadvertently included in the release. This heuristic is supplemental; human review and independent secret detection remain essential. The PHP syntax gate now scans all packaged PHP fixtures as well as application source, tests and tools.

## Version 9 PHP assignment scanning

The strict scanner adds PHP token inspection of literal credentials assigned through associative arrays, indexed variables and object properties, including short password literals. Comments and plain explanatory source strings are excluded from this syntactic check. Existing regex checks continue to cover other publication files and representative secret formats. These are heuristics and must **not** replace a separate full-source, ownership and confidentiality review.

## Version 10 publication safeguards

Strict scanning now inspects nested/minified JSON credential keys structurally rather than relying on line starts. It rejects static-SVG diagrams containing scripted elements, `on*` event attributes, executable or external `href` resources, entity declarations, and embedded active content. Both are conservative gates intended to produce reviewable failures; neither is a proof of complete information security. The automated tests construct synthetic strings at runtime to avoid packaging realistic credentials.

The JSON state reader rejects duplicate object members before associative decoding, including escaped spellings that resolve to the same key. Configuration loading uses the same safeguard. An incomplete persisted history does not silently become an empty incident history.

## Version 11 release-safety additions

The strict scanner normalizes camelCase and acronym/snake-case/dashed credential field names in JSON (including `dbPassword`, `accessToken`, `refreshToken`, and `jwtSecret` forms), rejects nonempty sensitive numeric/compound values, and rejects duplicate JSON object names before parsing. Synthetic regression values are built at test execution time. The SVG release policy is deliberately static-only: `<style>` and `<link>` nodes, CSS imports, external URL references, and executable content fail the scan. The CI workflow explicitly uses read-only repository token permissions.

**The scanner is still heuristic.** Use an independently maintained secret scanner and perform a human copyright/confidentiality review before any actual public GitHub publication.


## Version 12 release scanner controls

The release scan rejects nested YAML credential keys including `accessToken`, short passwords, database connection URLs containing userinfo, and representative flow-style YAML mappings. It also tokenizes PHP to inspect literal `define('APP_PASSWORD', '...')`-style constants beyond the fixed WordPress names. SVG inspection is **fail-closed and narrowly scoped** to the two static diagrams in this package: any entity reference, hyperlink attribute, active element, remote resource or scripting mechanism is rejected. The repository's own static `marker-end="url(#id)"` arrows remain permissible.

The YAML rules are intentionally conservative key/value checks, not a complete YAML parser; the SVG policy is a restrictive static-content filter, not a complete XML/SVG validator. Regex and token checks cannot prove all secrets are absent. A human rights/confidentiality review, independent secret scanner where available, and a clean archive review remain required before public release.


## Version 13 credential-bearing authorization and URLs

The strict scan now treats nonempty structured `authorization` fields in JSON/YAML as possible credentials and checks JSON scalar strings/YAML lines for scheme-prefixed connection URLs containing username/password userinfo. This closes the specific Version 12 independent-audit bypasses. Plain public example URLs remain accepted. The scanner is still deliberately heuristic; an independently maintained scanner, manual review, and employer work-product permission are required for publication.

## Version 14 release validation

The publication scan now identifies synthetic credentials in YAML `env` `name/value` sequences, Docker Compose-style `KEY=value` lists, and inline flow mappings, as well as JSON `credential(s)` container fields. The scanner also rejects malformed static-SVG XML structure. `php tools/validate_svg.php` is a separate CI step that verifies the two diagrams against the restricted, dependency-free static-XML grammar. This is not a comprehensive YAML or XML parser; an independent secret detector and human source/rights review remain essential.

## Version 15 publication controls

The structured-key policy now includes common `pass`/`pwd` abbreviations (including camelCase, underscores, environment lists, PHP literal variables, and structured JSON/YAML), with synthetic negative tests. Static SVG diagrams intentionally disallow **all inline `style` attributes**. That small allowlist eliminates CSS escape interpretation, including obfuscated external references, rather than depending on pattern recognition of every CSS URL syntax. Two packaged diagrams require no inline styles. The validator and strict publication scan both enforce the rule.

The scanner is a defense-in-depth gate, not proof that a package contains no credentials or protected company material. Manual review, a verified tracked-file manifest, and intellectual-property authorization remain separate release requirements.

## Version 16 release controls

The independent comprehensive audit discovered alias-normalization gaps (`DBPASS`, `PGPASSWORD`, `SERVICE_AUTH`, `db_uri`), PHP database connection-string literals (including adjacent concatenated tokens), YAML environment forms, and CSS-obfuscated SVG paint references. The scanner now checks these with broader structured-key aliases, executable PHP-token string inspection, the existing YAML policy, and a fail-closed static-SVG rule that rejects backslash escapes entirely. The SVG structure gate also requires the expected SVG namespace and rejects undeclared prefixes.

These controls were evaluated against the original 54-case synthetic scanner matrix and 77 new randomized/alias controls. **No content scanner can guarantee it finds every secret or prove intellectual-property rights.** The code remains a synthetic educational package; publish only after separate authorization and an independent human confidentiality review.

State persistence now applies **one identical validation contract to read and proposed write values** before atomic replacement. Directory `fsync` occurs after rename; if it fails, the state file is already committed, so the API reports a durability warning instead of falsely claiming the transaction was uncommitted. This does not guarantee preservation under unexpected power loss.

## CMM-17 structured release gate

Strict YAML/NEON scanning now uses a pinned Python 3 / PyYAML safe loader (`tools/scan_yaml.py` and `requirements-security.txt`). It decodes escaped keys, evaluates sequence mappings without assuming order, checks nested mappings and environment arrays, and rejects duplicate/unsupported mapping keys. Missing parser tooling fails the scan closed. CI installs the dependency in a dedicated virtual environment. PHP token screening covers concatenated string assignments under array and object properties; shell and text password checks no longer require long values. The scanner is still defense-in-depth and publication requires separate manual and legal review.
