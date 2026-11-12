# HTTPS diagnostics: a reproducible classifier

The original business utility used PHP cURL to classify TLS, connection, HTTP, redirect and application-level problems. The public application **does not perform network I/O**. It classifies synthetic observations using a deterministic pure function, allowing independent tests of the engineering decisions without contacting third-party sites.

## Input contract

Each observation has either `transport_error` (`connection`, `tls`, `timeout`) **or** a numeric HTTP `status_code` (100–599). The optional `body` is capped at 128 KiB. `redirect_location` is accepted as response metadata for any status (notably `201 Created`), but redirect logic applies only to 301/302/303/307/308. A transport error cannot have response fields. Invalid or unexpected properties fail closed.

| Observation | `healthy` | `code` | Meaning |
| --- | --- | --- | --- |
| TLS/connection/timeout | `false` | `transport_*` | Request could not establish a successful HTTP exchange |
| HTTP 404/500, or interim 1xx | `false` | `http_error` | Explicitly unsuccessful response |
| Redirect without destination | `false` | `unresolved_redirect` | Required Location missing |
| Redirect to different hostname | `false` | `unexpected_redirect` | Outside the authorized original hostname |
| HTTP downgrade, URL credentials, suspect redirect | `false` | `unsafe_redirect` | Security policy violation |
| Relative or same-host HTTPS redirect | `null` | `unverified_redirect` | Safe destination **not followed**; neither healthy nor confirmed failed |
| 201 with Location and no configured assertion | `true` | `healthy` | Ordinary success metadata, no 3xx redirect |
| Complete body-bearing 2xx with recognizable critical error-page signature | `false` | `application_*` | An error page disguised by HTTP 200 |
| Any complete 2xx with failed configured content assertion | `false` | `content_assertion_failed` | Minimum visible bytes or required sentinel missing |
| HTTP 206 Partial Content | `null` | `unverified_partial_response` | Partial bytes cannot establish a complete page |
| Complete 2xx with malformed or invalid-UTF-8 HTML | `null` | `unverified_html` | This target cannot be safely classified; sibling checks continue |
| Other eligible 2xx responses | `true` | `healthy` | No modeled failure detected |

A safe relative URL such as `/login` is **unknown** until the destination is fetched and classified. No redirect hops are followed. A prior failure remains open when its newest observation is unknown; unknown results cannot generate a recovery. Authentication redirects and login pages should not be equated to site failure without an explicit verification policy.

## Application checks

The classifier performs a bounded **approximation** of visitor-visible content. It excludes HTML head/script/style/template blocks and explicitly `hidden`, `aria-hidden=true`, `display:none`, and `visibility:hidden` descendants. It does not execute browser layout, external stylesheets, or JavaScript. The classifier normalizes the remaining text and checks the **entire bounded response** (up to 128 KiB) for known stand-alone WordPress/database/structured PHP/service-error messages, including failure blocks after navigation. Only an adjacent explanatory introduction immediately following a tutorial-style error heading can suppress that individual heading; unrelated footer help links never suppress an earlier critical error. These are fallible heuristics, not a browser renderer or formal proof of page correctness. For target-specific expectations, `content_policies` in `config/demo.json` can require a minimum visible-byte count or visitor-visible text sentinel. **Any complete 2xx response must satisfy an explicitly configured content requirement**, including 201/204/205; empty-by-design statuses remain healthy when no such assertion is configured. The default demo requires at least one visible byte on its 200 pages.

## Security boundary

The repository excludes the previously untested optional live cURL adapter entirely. Adding an authorized live transport would require controlled integration tests, DNS and IP-target restrictions, proxy policy, anti-rebinding protections and per-hop redirect authorization. No claim of such protections is made here.

## Second independent audit hardening

HTTP 206 is classified `unverified_partial_response` by default: partial bytes cannot establish a complete healthy page, even when a sentinel appears. A 300–399 status is **never considered proof of recovery**. Recognized redirect statuses with a safe same-host `Location` are `unverified_redirect`; other 3xx statuses (including 304 Not Modified and 300 Multiple Choices) return `unverified_http_status` and preserve any open incident. Cross-host and insecure redirects still raise specific failure codes without following them.

HTML classification strips head/title metadata, scripts, styles, templates, explicit inline-hidden elements (including quoted/unquoted `display:none`, `opacity:0`, `visibility:hidden`) and non-visible markup before checking minimum visible bytes or failure signatures. The full bounded visible body is evaluated for stand-alone, structured error messages; ordinary tutorials titled “Service Unavailable: how to troubleshoot” or “Fatal error: how to debug” are healthy. These remain bounded heuristics: they are not a browser renderer or an application correctness proof, and target-specific assertions should be configured where possible.

## Fifth independent audit hardening

Error-page signatures are evaluated across the whole bounded body without a document-wide educational exception. A tutorial introduction exempts only its own error heading. Navigation, footer, aside, and article code examples are ignored for automatic failure-signature recognition; main-body error messages remain detectable, including messages in diagnostic `<pre>` blocks. This is a deterministic approximation, not a full DOM/CSS renderer. When the result is safety-critical, configure explicit observed-content checks and independently verify application behavior.

The minimum-content assertion normalizes Unicode spaces and default-ignorable formatting characters; an HTML page consisting only of nonbreaking or zero-width spaces is not meaningful content. Explicit `contains` checks examine the bounded visible-text approximation, including quoted/unquoted inline-hidden handling. HTTPS redirect host comparisons also normalize a terminal DNS dot without allowing different hosts.

## Version 6 independent re-audit corrections

Known standalone WordPress/database error banners are normalized across HTML character entities, Unicode/nonbreaking spaces, and inline `<br>` continuations. The classifier recognizes a constrained `503 Service Temporarily Unavailable` variant. For text policies, closed `<dialog>` and collapsed `<details>` regions are excluded; the first direct `<summary>` in a closed details region remains visible. Full browser/CSS/JavaScript visibility is still outside the implementation's capabilities.

Documentation link titles and ordinary preformatted code samples are not interpreted as live application failures. A standalone PHP fatal-error display can still be recognized. A tutorial error heading followed immediately by an explanatory introduction is ignored only for that heading; a later independent error banner is still eligible for detection. This contextual policy deliberately trades completeness for fewer false incidents and is backed by paired positive and negative tests.

## Version 8 classifier hardening

The offline parser now recognizes quoted `>` characters inside HTML attribute values when extracting content; it excludes text in explicitly hidden tags rather than mistakenly accepting it as a visible sentinel. Unclosed HTML tags and comments are rejected instead of being counted as verified healthy. Content sentinels and visible text both normalize Unicode separator and format characters before comparison. Error-template checks recognize standalone `502 Bad Gateway` and `504 Gateway Timeout` pages while preserving negative cases for help content. A limited tutorial-context heuristic handles immediately nested explanation wrappers and preformatted PHP examples, without hiding a separate error elsewhere.

**Scope boundary:** This is still a bounded lexical classifier, not a browser rendering engine, semantic model, full HTML5 error-recovery parser, or guarantee of detecting every synthetic or actual failure page. Scripts and remote CSS are not executed. For production monitoring, actual application health endpoints and deliberate per-site assertions are preferable to generic page-text heuristics.

## Version 9 raw-text and error-template corrections

HTML tokenization now treats the body of `script`, `style`, `textarea`, and `title` according to raw-text/RCDATA-style boundaries, so legitimate JS/CSS source containing `<` does not abort monitoring. Text tokens are typed separately from markup tokens; only actual tags affect hidden-content state. Inline CSS resolves the final declaration at the highest local `!important` priority. The classifier also recognizes standard nginx `504 Gateway Time-out` banners served under HTTP 200. Independent regression tests include sibling-host continuity and a failed-to-healthy false-recovery negative case. This is still an offline approximation and not a full HTML5 browser implementation.

## Version 11 HTML safety and response integrity

The CLI rejects duplicate raw JSON keys in the `--responses` fixture, including nested properties and Unicode-escaped aliases, **before** associative JSON decoding can discard earlier observations. A contradictory fixture is an input error and does not mutate persistent state.

HTML attributes are tokenized by their **exact names**: `data-style` and `data-aria-hidden` cannot impersonate `style` or `aria-hidden`. An unclosed quoted attribute, malformed tag or malformed HTML comment is no longer a fleet-wide exception. The affected target is classified `unverified_html` (`healthy: null`); its prior confirmed failure remains unresolved and checks for other hosts continue. Invalid schema, unsupported observation keys, unbounded inputs and malformed JSON remain rejected as command errors.

Recognizable database and WordPress critical-error banners now tolerate narrowly bounded inline help labels (`Please`, `Try`, `Contact`, etc.) while retaining the separate tutorial/code/link exclusions. This is only a bounded offline heuristic, not a full DOM/browser renderer or a guarantee of detection across arbitrary page templates.


## Version 12 structural fault-region inspection

Application-error evidence is now processed through `src/Monitoring/HtmlFaultDetector.php` as an ordered stream of element-scoped text regions. This replaces the previous sequence of whole-document regular-expression rewrites. Real server error banners remain identifiable when prefixed with a diagnostic label (e.g., `Database Error:`). Tutorial introductions, `<a>` link titles, preformatted examples and help sections are evaluated in local structural context rather than acting as document-wide suppressors. An independent `<main>` or `<section>` error block remains eligible even when an earlier article is explanatory. The distinction is tested both at the classifier boundary and through incident-state CLI transitions.

Inline `visibility` is now modeled as an inheritable property: `visibility:visible` on a descendant overrides `visibility:hidden` from a parent; `display:none`, `opacity:0`, hidden attributes and closed dialog states still suppress descendant text. This is a deliberately bounded offline approximation, not computed browser CSS. CSS classes, remote stylesheets, JavaScript, and malformed HTML5 error recovery are outside this implementation. For high-confidence real website health, a dedicated HTTP health endpoint and synthetic content contract should be used.


## Version 13 tokenization and error-template controls

The lexer ignores `<!DOCTYPE ...>` and XML processing instructions when measuring visible text. Explicit `hidden`, `aria-hidden=true`, `display:none`, or zero opacity on a closed `<details>` still hides its first `<summary>`; the first summary of an otherwise ordinary collapsed details element remains visible. Both classification paths use the same full HTML void-element list so `<track>`, `<param>` and `<col>` cannot accidentally conceal subsequent siblings. A standalone HTTP 200 page showing `500 Internal Server Error` or `HTTP Error 503. The service is unavailable.` is classified as an application incident. Nearby explanatory tutorial content remains a documented heuristic limitation. See the [Version 12 audit remediation record](v12-independent-audit-remediation.md).

## Version 14 browser-default and ambiguous-markup controls

The two classification paths now use the same non-rendered HTML element policy: closed popovers, datalists, iframe/canvas/object fallback and media fallback cannot furnish visible success markers or application-error evidence. Nearby references to a guide do not excuse a genuine server-error heading; tutorial prefixes do not override explicit instructional context. Non-void HTML written as `<div/>` and escaped inline CSS declarations return `unverified_html`. They do **not** establish a recovery from a suspended failure. This is an intentionally conservative offline approximation, not computed browser visibility.

## Version 15: confirmation, ambiguity and content evidence

An HTTP 200 now requires at least one meaningful visitor-visible character even when no host-specific content policy is configured. This prevents an empty success response from closing a prior outage; deliberately bodyless 204/205 responses are still supported. A `contains` assertion remains the stronger recommended confirmation mechanism for a page-specific health contract. No offline heuristic establishes a production website's actual availability.

The classifier treats HTML `<meta http-equiv="refresh">` as `unverified_redirect`: observing only the intermediary page cannot prove the destination. Dropdown and option markup is excluded as success-marker evidence because browser selection state is not modeled. Error headings preserve text split by inline links. A visible server-error heading next to a generic instructional introduction is **unverified**, not automatically considered healthy or a verified failure, so it cannot close an unresolved incident. Uncorroborated preformatted database/WordPress error examples likewise remain unverified; tutorials with explicit local explanatory context can still be healthy. Additional `500 - Internal Server Error` and related separators are recognized.

Page content checks compare normalized Unicode spaces and canonical composed/decomposed sequences. When PHP's `intl` extension exists, native NFC is used. Otherwise a portable, non-lossy fallback handles 618 common two-codepoint canonical compositions (Latin, Greek and other lower-plane combinations). Less common canonical sequences may remain byte-distinct; install `ext-intl` for full NFC semantics.

The HTML tokenizer is a deliberately conservative subset: it cannot compute browser stylesheets, execute client scripts, determine option selection, or fully distinguish every troubleshooting page from an error template. Ambiguous cases remain unverified where the supported rules cannot justify a recovery. Use a stable application-specific sentinel or dedicated health endpoint for dependable results.

## Version 16: explicit positive evidence and shared CSS interpretation

The default offline website-root health contract now treats **HTTP 200 with meaningful rendered-approximation text** as a candidate healthy page. HTTP 201, 202, 204, 205, 207, 299 and other 2xx codes are **unverified** without an explicitly configured host content policy, even if the status is technically successful. An application-error banner still counts as a failure on every 2xx. An explicit `min_body_bytes` policy permits deliberately bodyless service endpoints; a `contains` policy strengthens page-health evidence. These are demonstration contracts, not claims about a remote production site.

Both visitor-text extraction and structural fault evidence now use the same `InlineVisibility` evaluator for CSS `display`, inherited `visibility`, `opacity`, and `content-visibility`. Fully transparent percentages, exponent forms, and `content-visibility:hidden` cannot supply a healthy sentinel. When CSS variables, calc expressions, clipping, transforms, filtering, class selectors or other unsupported properties make visibility uncertain, the entire observation becomes **`unverified_html`**, which preserves an unresolved incident rather than falsely reporting recovery.

HTML attribute character references are decoded when interpreting active meta refresh elements. A refresh inside `<template>` is inert, and a malformed non-navigation directive is ignored. The error detector scans all regions: an early ambiguous tutorial example no longer conceals a later definite failure; database/WordPress banners may contain trailing context while still being recognized.

An offline structural parser cannot model the browser's computed style cascade, dynamically generated content or client-side routing. For high-confidence automated recovery, configure a stable expected sentinel or use a purpose-built health response. Conservative uncertainty is an intentional reliability safeguard rather than a website outage claim.
