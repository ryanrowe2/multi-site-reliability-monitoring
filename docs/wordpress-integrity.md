# Synthetic WordPress and Elementor integrity checks

The public project includes fictional, **nonfunctional** plugin files only. It does not redistribute Elementor, connect to a real WordPress installation, or verify an official commercial software release.

## Checks performed per site

1. Require the expected Core path `wp-content/plugins/elementor/elementor.php`, its configured synthetic header version, and an independently approved **whole-Core-directory SHA-256 fingerprint** (`core_baseline_sha256`). This detects changed bytes even if the header stays the same.
2. Require exactly one canonical Pro directory named **`elementor-pro`**; a renamed prefix-matching directory (`elementor-pro-fake`) or backup copy does not silently qualify.
3. Check the Pro file header and tokenize the PHP source to locate **exactly one top-level literal `define('ELEMENTOR_PRO_VERSION', '...')` declaration and no other executable fixture code**. A matching text string in a comment does not pass. This is a static check, not runtime execution proof.
4. Require a nonempty synthetic must-use update-lock fixture matching the **mandatory** configured `update_lock_sha256`.
5. Compute a sorted SHA-256 digest over relative directory names, filenames and file-content hashes; reject symlinks.
6. Compare Pro directories against the **mandatory** synthetic `baseline_sha256` and Core directories against `core_baseline_sha256`. Identical but jointly altered copies fail the appropriate approved baseline. Cross-site Pro divergence is supplementary telemetry; **only sites that fail their own baseline generate incidents**.

A site with unreadable files or a path symlink produces its **own** `scan_error` incident while allowing valid sibling sites to complete. A missing entire site yields the missing plugin and lock checks, not a false clean result. Global invalid roots or malformed configurations still abort the run.

Version constraints, approved digests, and lock file hashes are synthetic reference values in `config/demo.json`. The lock fixture is only a **placeholder**; matching its hash does not show that WordPress loaded or honored actual update-lock logic. Likewise, SHA-256 agreement proves consistency with a configured example baseline, not an official vendor signature or package authenticity.

A changed asset can be tested with `bash examples/run-integrity-demo.sh`, which copies fixture trees into a temporary directory and restores them without editing the repository.

## Metadata and error handling checks

Plugin headers are recognized only in a **leading PHP block comment** before executable tokens, not in heredoc strings, later code, or arbitrary text. Version-declaration recognition requires a single, top-level literal `define()` statement after the opening PHP tag and leading header; conditional branches, functions and other executable source shapes are rejected. This validation does **not** execute PHP or establish a real runtime version. A mandatory approved digest independently attests the fixture bytes. Per-site scanner exceptions are reported using bounded categories such as `scan_error_unsafe_path`, `scan_error_hash`, `scan_error_unreadable` or `scan_error_invalid_fixture`; underlying private absolute paths and raw exceptions are never returned in CLI output. This metadata parsing is not a verification of plugin authenticity or runtime execution.
