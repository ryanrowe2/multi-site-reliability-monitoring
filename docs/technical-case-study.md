# Engineering case study — from recurring WordPress failures to stateful monitoring

## The operational problem

California Machinery Movers operated a collection of websites where problems with PHP, WordPress, and Elementor created a recurring maintenance concern. During IT support work, I investigated failures, addressed compatibility issues, and extended Elementor-related remediation across 31 installations. The broader environment required a repeatable way to notice significant failures without manually opening every site.

These are historical work-context statements; the independently reviewed source specifically establishes the **monitor's implemented behavior**. It does not by itself prove each remediation step, an uptime improvement, or a count of successfully delivered alerts.

## Why this became an automation problem

A periodic HTTP probe is easy to write. An operationally useful monitor has to answer harder questions: Did the request fail before HTTP? Did the certificate fail verification? Did a server return 200 while displaying a critical WordPress error? Did it redirect to an unexpected destination? And did the operator already know about the failure?

The original PHP script uses cURL with timeouts and TLS verification, evaluates status and redirect destination, and scans response bodies for known application-failure strings. It keeps the current incident map in JSON so subsequent checks can compare against the previous run. Its core concepts are `probe_domain`, `emit_changes`, `run_uptime`, `run_integrity`, and `directory_hash`.

## The central design decision: report transitions

The most important behavior is stateful incident reporting. A new problem should be surfaced; the identical problem should generally remain quiet; a changed failure should be surfaced again; and a recovery should be recorded. The original uptime design also includes a six-hour reminder window. The historical integrity mode supplies a one-day interval, although review found that the corresponding conditional was limited to uptime and therefore did not run for integrity.

This independently written demonstration implements a pure incident state engine with `new`, `changed`, `reminder`, `recovered`, and inventory `retired` events and per-target notification timestamps. Synthetic timestamps and responses make every transition independently inspectable. The event engine produces machine-readable JSON instead of representing changes only as console prose.

## A second operational question: did repaired sites stay consistent?

The source's distinct integrity mode inspects Elementor plugin presence, Core/Pro version metadata, a must-use update lock, and recursive directory content. Comparing sorted SHA-256 directory fingerprints provides a practical signal when sites thought to have matching plugin payloads diverge. A separately approved synthetic baseline can additionally flag a uniformly altered fleet. None of these hashes establishes that plugin contents are genuine or current.

The demo reproduces those concepts using fictional plugin fixtures, never a redistributed Elementor package. A copied fixture can be altered in one line to demonstrate a cross-site mismatch and then restored to show recovery.

## Deployment evidence and limits

The original system was a PHP CLI utility. Prior supporting context describes an uptime cron schedule configured in cPanel at minutes 0 and 30. The original source itself does not prove the schedule's execution history or the integrity mode's schedule. The public CLI is deliberately offline and requires no cPanel, credentials, or external websites.

The audit additionally identified risks from direct state-file writes, whole-cycle concurrency, silent malformed state resets, automatic redirects, and symlink-sensitive hashing. The newly written demonstration addresses those specific categories with locking, atomic state updates, validation, offline inputs, and deliberate refusal of symlinked content.

## Engineering tradeoffs

A small JSON state file makes local cron integration simple, but distributed monitoring needs a transactional shared store. A small body-signature set makes checks transparent, but semantic application health requires richer assertions. Cross-site hashes detect inconsistency, but not fleet-wide uniform corruption. A local demonstration offers excellent reproducibility while intentionally not exercising network behavior or asserting production hardening.

## Verification

The public package contains a dependency-free automated test harness, adversarial filesystem cases, and CLI integration tests. Run `php tests/run.php`, `php tools/lint.php`, and `php tools/publication_scan.php`. See `docs/validation.md` for the observed local results and the intentional no-live-network boundary.

## Lesson

The engineering value came from making periodic observations **operationally meaningful**: turning raw status codes, page errors, and filesystem inconsistencies into explainable incidents, reminders, and recoveries. The public artifact allows a reviewer to evaluate those decisions in executable form without exposing the employer's infrastructure.
