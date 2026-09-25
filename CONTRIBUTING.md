# Contributing to SafeSurf

Thanks for wanting to help. SafeSurf is a PHP library that analyzes URLs for phishing indicators, and contributions of every size are welcome: a fix for a false positive, a new detection signal, better documentation, or a failing test that exposes a bug.

## Project overview

If you have not read it yet, start with [AGENTS.md](./AGENTS.md). It describes the architecture (src/ layout, the check classes, the scoring flow), the analysis contract, and the conventions this repo follows. The [docs/](./docs) folder explains the public behavior: checks, scoring, output fields, and the threat-feed plugin system.

In short: `SafeSurf::analyze()` orchestrates check classes from `src/Checks/`, services from `src/Service/`, and turns the collected signals into a verdict through `src/Analyzer/ResultScorer.php`.

## Getting set up

Requirements: PHP >= 8.0 with the `curl`, `openssl`, `dom`, and `libxml` extensions, plus Composer.

```bash
composer install
composer tests       # runs the PHPUnit suite
composer rector:dry-run   # checks code style (rector); rector process applies fixes
```

Most tests are pure and need no network. A few smoke tests reach a public IP (1.1.1.1) and may be slow; everything must still pass without live phishing sites.

## Ground rules

These come from AGENTS.md and are enforced in review:

- PHP >= 8.0 features only. No enums, readonly properties, or fibers.
- `declare(strict_types=1)`, `final class`, and static methods for Checks and Services. PSR-4 under the `SafeSurf\` namespace.
- New static data goes in `assets/*.php` with a loader in `Constants/DataFiles.php`. New configuration is a public `Config` property with a safe default, so existing callers keep working with named arguments.
- The output of `analyze()` is an API contract: add fields, never change or remove existing ones.
- Never let a single weak signal produce a Risky verdict on its own. If you add a scorer weight, keep it proportional, and read the correlation block in `ResultScorer.php` first.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, ...) in English.

## Security-sensitive code

SafeSurf fetches attacker-controlled URLs, so the fetching code is the most sensitive part of the codebase. Any new network operation must:

- Go through `Util/HttpClient.php` (scheme whitelist, DNS resolution first, private/loopback/metadata IP rejection, IP pinning, body size and timeout limits).
- Fail soft: a caught exception becomes an entry in the result's `errors[]`, never a fatal error.
- Have a TTL cache.
- Keep pure parsing separate from fetching (see `Content::analyzeHtml()` for the pattern), so it can be tested with HTML fixtures instead of network calls.

Do not add `CURLOPT_FOLLOWLOCATION` for user-supplied or redirect-derived URLs, and do not fetch arbitrary URLs outside `HttpClient`. If your change touches this area, explain the SSRF implications in your pull request description.

## Submitting changes

1. Open an issue first for anything larger than a small fix, so we can agree on the approach before you write the code.
2. Fork, create a branch, and make your change.
3. Add or update tests. Per-check unit tests live in `tests/` and use synthetic HTML or data fixtures. Tests must not depend on live phishing websites or unstable external services.
4. Run `composer tests` and `composer rector:dry-run`. Both must be clean.
5. Open a pull request with a short description of what changed and why. Link the issue it closes.

## Reporting bugs

Open a GitHub issue with:

- The URL or input that triggers the problem. If it is a live phishing or malicious URL, do not paste it in plain text; describe the domain pattern or use a defanged form like `hxxps://example[.]com`.
- The relevant slice of the `analyze()` output (fields, scores, `errors[]`).
- What you expected instead, and your PHP version.

False positives are bugs too. If SafeSurf flags a legitimate site as Risky, that report is exactly as valuable as a missed detection.

## Reporting vulnerabilities

Please do not open public issues for security vulnerabilities. See [SECURITY.md](./SECURITY.md) for the private reporting process.

## Data files

`assets/top-1m.csv` is refreshed by a GitHub workflow. Do not commit manual changes to it. Other data files (brands, risky TLDs, sensitive subdomain labels, and so on) do accept contributions; add an entry plus a test showing the new entry changes a real detection.

## Licensing

By contributing, you agree that your contributions are licensed under the MIT license that covers this project.
