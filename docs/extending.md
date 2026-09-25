# Extending SafeSurf

Guidance for the three most common extension points: threat-feed plugins, static data, and new detection checks. The codebase conventions are short:

- `declare(strict_types=1);`, `final class`, PHP 8.0-compatible syntax (avoid enums, readonly properties, fibers).
- PSR-4: `SafeSurf\` → `src/`.
- Checks and services use static methods; there is no instance state.

## Adding a threat-feed plugin

Documented in [Threat Feeds](threat-feeds.md#writing-a-plugin) — implement `ThreatFeedInterface`, write the class PHPDoc (it becomes `description` / `@feed-category` becomes `category` in the result), and register the instance via `Config::addThreatFeed(new MyFeed())` or the `ThreatFeeds` setup object. Feed-specific settings go through the per-feed option map (`ThreatFeeds::setOption()`), so no core changes are needed.

## Adding static data

Detection vocabulary lives in `assets/*.php` (return-a-PHP-array files) with lazy loaders in `SafeSurf\Constants\DataFiles`. To introduce a new data file:

1. Create `assets/my_data.php` returning `array<string, mixed>`.
2. Add a `public static function myData(): array` loader in `src/Constants/DataFiles.php` following the existing pattern.
3. Keep defaults safe: a bigger risky-TLD list creates more false positives; prefer evidence-backed entries.

Do not edit `assets/top-1m.csv` manually — it is refreshed automatically by a GitHub workflow.

## Adding a detection check

Follow the established pattern (see `src/Checks/Content.php`, `src/Checks/RootDomainCorrelation.php`):

1. **Create the check** in `src/Checks/` as a `final class` with static methods.
2. **Separate pure parsing from fetching.** Anything testable must not require a network: `Content::analyzeHtml()` / `Content::analyze()`, `RootDomainCorrelation::correlate()` / `RootDomainCorrelation::fetchRootData()`. Pure functions take already-fetched data and return the analysis.
3. **Network rules** (see [Security](security.md)):
   - Fetch through `SafeSurf\Util\HttpClient` — it provides scheme validation, private-IP rejection, IP pinning, and body caps.
   - Fixed-target protocols (like the raw UDP DNS client `Util\DnsQuery`) are allowed only when the destination is fixed/configurable via `Config`, never user input, with timeouts and response-size limits.
   - Wrap network work in try/catch and return `null` on failure instead of throwing.
4. **Wire it into the Analyzer**: call it inside `self::timed('<task_name>', ...)` so timing and error capture work, and wrap it in `self::cached('<key>', $ttl, ...)` when it performs network work. Use an existing TTL config field or add a new one (see below).
5. **Expose the output** in the `analyze()` response array as a new field or a new key inside an existing section.
6. **Score it** in `src/Analyzer/ResultScorer.php` following the weighting philosophy:
   - One ambiguous signal → small weight or a neutral reason only.
   - Strong, unambiguous indicators (raw IP, punycode, verified feed hit) → large weight.
   - Combo findings (correlation, login + brand text) → score only the co-occurrence, never the parts.
   - Add a plain-English reason string; these are shown to end users.
7. **Document it** in [Detection Checks](checks.md) and, if it changes scores, [Scoring & Verdicts](scoring.md).

### Adding configuration

Configuration is a single constructor-promoted value object. Add a **public property with a safe default** to `src/Config.php` — named-argument construction means existing user code keeps working. Follow the naming patterns: `enable<Thing>` (bool), `ttl<Thing>Seconds` (int), `<thing>TimeoutMs` (int).

## API compatibility rules

- The `analyze()` return array is a public contract: **add** fields, never rename, reshape, or remove existing ones. (Example: when threat feeds were introduced, the old PhishTank `phishing` field was kept alongside the new `threat_feeds` section.)
- New scorer behavior must stay proportional: re-reading the [Scoring & Verdicts](scoring.md) principles before touching weights is strongly recommended.

## Testing

Tests live in `tests/` (PHPUnit 10). Conventions:

- Pure checks get fixture-based tests with **no network**: synthetic HTML for `Content::analyzeHtml()`, synthetic DNS packets for `DnsQuery::buildQuery()/parseResponse()`, synthetic feed doubles for `FeedRunnerTest`.
- Existing examples to copy: `tests/JsSignalsTest.php`, `tests/SubdomainSignalsTest.php`, `tests/HomoglyphTest.php`, `tests/ResultScorerTest.php` (synthetic response arrays), `tests/FeedRunnerTest.php` (plugin + PHPDoc extraction).
- Network-dependent tests are smoke tests only (e.g. resolving `1.1.1.1`) and may be slow.

Run everything:

```bash
composer tests        # vendor/bin/phpunit tests/
```

A new check should land with its pure logic covered by fixture tests; do not write tests that depend on live phishing sites or other unstable external services.
