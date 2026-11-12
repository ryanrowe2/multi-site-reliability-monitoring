# Independent audit: historical implementation versus public demonstration

**Evidence basis:** the four private `_cmm_monitor*.php` files were SHA-256 identical; this inventory reviews that one 1,016-line snapshot. Line numbers reference the **private** source and are intentionally not linked to private domain data. Ratings refer to code/design risk, **not** confirmed real-world incidents. The public demo is independently written; no historical production file was modified.

| ID | Severity | Confirmed historical issue or limitation (private lines) | Decision in independent demo | Validation |
| --- | --- | --- | --- | --- |
| H01 | **High** | Invalid/unreadable JSON silently becomes an empty incident history (229–246), enabling false `new` alerts and lost recovery context. | Reject invalid state without replacement. | Invalid JSON, schema, and CLI preservation tests |
| H02 | **High** | `LOCK_EX` protects only a direct file write (249–263); no exclusive lock spans load → compare → write (975–1017). Concurrent runs can lose events. | Exclusive lock for full state transaction. | Two-process contention integration test |
| H03 | **High** | Writing JSON directly to the final file (249–263) is not an atomic replacement; interrupted writes can truncate valid history. | Same-directory temporary write and rename. | Persist/reload, invalid-state and CLI tests; crash injection not tested |
| H04 | **High** | cURL follows redirects (417–420) before destination-host verification (480–494); a third-party redirect could be requested before being rejected. | Offline CLI only; previously untested optional cURL adapter removed entirely. | Redirect classification and no-network CLI tests; no live adapter shipped |
| H05 | **High** | `directory_hash` calls `hash_file` on recursively discovered files without rejecting symlinks (368–388), potentially reading external file contents. | Reject symlinks in fixture traversal. | File and intermediate-directory symlink tests |
| H06 | **Medium** | Integrity mode passes an 86,400-second reminder interval (955–963), but actual reminder logic only runs for `mode === 'uptime'` (599–610). | Per-target reminders work for both modes. | 24-hour boundary test |
| H07 | **Medium** | A failed state write prints a warning (1007–1017) but the script still exits successfully. | Throw, print error to stderr, exit nonzero. | Failed-directory and invalid state CLI tests |
| H08 | **Medium** | One `last_reminder` timestamp is maintained per mode (558–560, 735–739), so a change or recovery can postpone reminders for unrelated persistent incidents. | Per-target `last_notified`. | Per-target reminder test |
| H09 | **Medium** | cURL results with a final HTTP 3xx are not explicitly rejected if no other fault is found (`code < 200 || code >= 400`, 469–477). | Same-host or relative 3xx is explicitly unknown; insecure/off-host 3xx is a confirmed fault. | Missing, same-host, off-host, unsafe redirect tests |
| H10 | **Medium** | Source embeds inventories and operational configuration directly (34–222, 806–910); public release would disclose internal infrastructure. | Omit original source and use invented hosts/files. | Publication scan plus archive review |
| H11 | **Medium** | Pro directory hashes are compared only against each other during a run (934–952). Uniform drift across all installations is invisible, and disagreement cannot identify the correct baseline. | Retain consistency comparison and add an independent synthetic approved baseline. | Uniformly modified and divergent fixture tests |
| H12 | **Medium** | Filesystem hash errors are not handled explicitly before JSON serialization (383–395). | Fingerprinting throws on unreadable/unsupported inputs and hash failures. | Content/hash/symlink tests; permission behavior is OS-dependent |
| H13 | **Medium** | Probing is sequential (760–776) with a 15-second per-request timeout (419–420), potentially conflicting with a 30-minute schedule under adverse conditions. | Offline fixture execution has no network latency; performance risk documented. | CLI integration tests; no production load benchmark |
| H14 | **Medium** | Production-specific Elementor version strings and a custom update-lock filename are hardcoded (834–910). They should not be represented as vendor defaults. | Synthetic configurable constraints. | Version/lock mismatch tests |
| H15 | **Low** | Error signature matching is based on a small literal list (500–522), which can miss unknown failures or match unrelated text. | Stable heuristic codes; limitation documented. | Critical page, database, normal page tests |
| H16 | **Low** | Human-facing uptime output lists affected URLs without describing the failure condition (638–651), limiting immediate troubleshooting context. | JSON events include normalized code and detail. | CLI event assertions |
| H17 | **Low** | `time()` is called inside alert comparison (552), so time-dependent behavior cannot be controlled directly for unit tests. | Pure transition function accepts injected UTC clock. | Six-hour/day reminder boundary tests |
| H18 | **Low** | A commented `test` alert branch exists (624) but the CLI entry point accepts only uptime and integrity (981–1004); its operational accessibility is unclear. | Documented, explicit two-mode CLI. | CLI help and invalid-mode tests |

## Assessment of nondefects and evidence limitations

- The original checks TLS peer and hostname verification (425–427). Those controls are *present*; they are not claimed absent.
- The original intentionally treats a recognizable application error page as an issue even when the status is 200. This design choice is preserved.
- A cross-site SHA-256 comparison is a legitimate **consistency** signal, even though it is not an independently verified approved baseline.
- It is not established that integrity checks ever ran on a recurring production schedule. The original contains an integrity mode, not a cron record for that mode.
- Multiple copies of identical source do not prove deployed history, and no production performance, logging, email-delivery or incident-outcome records were supplied for this review.

## Demo-only improvements and remaining risk

The new implementation adds schema validation, deterministic clocks, normalized results, per-target reminders, explicit errors, locks, atomic state replacement, fixture sanitization, symlink refusal, and isolated tests. These demonstrate a more maintainable design; **they do not establish repairs to production**.

No live cURL transport is shipped: its unvalidated SSRF and authorization boundaries were eliminated by removing the optional class. Cross-site and approved synthetic baseline hashes are not official vendor release signatures. No real deployment or external delivery guarantees are claimed.

## Independent public-implementation re-audit

A subsequent independent audit found 14 public-demonstration issues, which were addressed in the revised source and regression suite. This historical-source audit remains an account of the **original private snapshot**; the revisions to the public demonstration are documented separately in [the consolidated public remediation history](remediation-history.md).

## Latest independent review

The Version 6 independent audit identified nine additional issues in the public demonstration's HTML heuristics, release scanner, and persisted-state validation. Each has an implemented correction and a regression reference in [Version 6 re-audit remediation](v6-reaudit-remediation.md). All historical findings and current demonstration fixes remain distinct.
