# Version 14 independent audit — Version 15 correction record

**Source:** independent audit against the exact Version 14 ZIP. **Scope:** the separately authored, synthetic offline demonstration. Historical employer-owned source was not modified.

The independent audit reproduced **16 negative scenarios across 11 issue classes**. The Version 15 regression suite reproduces these as permanent tests (`V14-` labels in `tests/run.php`) and also re-runs the original independent Python verifier against the repackaged archive. A result of *not reproduced* means the specified failure did not recur under the test inputs; it is not a proof of general bug freedom.

| Finding | Repair | Observable regression |
| --- | --- | --- |
| V14-01 instructional header masks real server failure | Introductory text plus visible server-error banner becomes `unverified_html`, never an automatic recovery | Two classifier cases and CLI false-recovery sequences |
| V14-02 unselected option supplies success marker | Exclude selection-dependent `<select>`/`<option>` text from positive evidence | Selected/unselected controls and CLI |
| V14-03 HTML meta refresh ignored | Detect `http-equiv=refresh` as `unverified_redirect` on complete 2xx responses | Mixed case, relative/external targets and CLI |
| V14-04 `dbPass`/`mysql_pwd` miss scanner | Extend structured-key and literal-variable detection for `pass`/`pwd` abbreviations | YAML mapping/environment, JSON, PHP controls |
| V14-05 empty HTTP 200 can recover outage | Default meaningful-content minimum for HTTP 200, preserving bodyless 204/205 behavior | Empty, DOCTYPE, title-only, script-only checks |
| V14-06 inline anchor splits error heading | Accumulate anchor text inside displayed heading, exclude stand-alone help links | Inline-link real failure versus link-only control and CLI |
| V14-07 hyphenated 500 template missed | Support `500 - Internal Server Error`, `500: Internal Server Error` | Classifier and CLI |
| V14-08 standalone `<pre>` example false outage | Uncorroborated database/WordPress examples return `unverified_html`, while explanatory help contexts can be healthy | Uncorroborated and explained `<pre>` checks |
| V14-09 escaped external SVG CSS URL | Fail-closed static SVG rule forbids all inline style attributes | SVG validator and strict scanner |
| V14-10 uptime-only setting blocks integrity mode | Validate unverified thresholds only when the uptime mode is selected | Integrity succeeds, uptime rejects same invalid setting |
| V14-11 Unicode NFC mismatch | Optional `Normalizer::FORM_C`, with embedded common canonical composition fallback | Composed/decomposed café checks in both directions |

## Verification and limits

- The offline regression runner exercises the 11 repair areas, including six 500→200 CLI transitions, and the original 16-scenario independent harness is rerun against a newly built ZIP.
- The default content threshold is a safety improvement, **not positive proof** of a fully functional site; operational adopters should configure a meaningful page sentinel.
- An ambiguous HTML structure may be `unverified`, preserving an existing failure. This avoids false recovery but does not always prove an outage.
- The portable Unicode fallback does not claim to implement every Unicode NFC combination; the optional ICU extension provides complete NFC normalization.
- Static SVG syntax is deliberately restricted; inline CSS is unsupported by design.
- Composer/PHPStan, Xdebug coverage, and the hosted PHP-version matrix remain separately unverified until actually run.
- Employer publication rights and an independent human confidentiality review remain required before any GitHub release.
