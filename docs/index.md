# SafeSurf Documentation

SafeSurf is a PHP 8+ library that analyzes a URL for phishing indicators and returns a transparent, JSON-ready report: every signal it inspected, the raw evidence it found, a risk/trust score breakdown, and a final verdict (**Safe**, **Suspicious**, or **Risky**).

It is a PHP-native rewrite of [urlvet/urlvet](https://github.com/urlvet/urlvet). A single call — `SafeSurf::analyze(string $url, ?Config $config): array` — runs the full pipeline and returns an associative array suitable for `json_encode()`.

## Documentation map

| Document | What it covers |
| --- | --- |
| [Getting Started](getting-started.md) | Requirements, installation, the CLI tool, first analysis in code, enabling the cache |
| [Configuration](configuration.md) | Every `Config` option, cache TTLs, static data assets |
| [Detection Checks](checks.md) | The signal catalog: what each check inspects, its thresholds, and its output fields |
| [Scoring & Verdicts](scoring.md) | How `risk_score`, `trust_score`, `final_score`, and the verdict are computed |
| [Output Reference](output-reference.md) | The complete `analyze()` result structure, field by field, with a real example |
| [Threat Feeds](threat-feeds.md) | Built-in feeds (PhishTank), the external plugin system, PHPDoc injection |
| [Security](security.md) | SSRF-safe fetching, IP pinning, body limits, operational notes |
| [Extending](extending.md) | Adding feed plugins, static data, new checks, and tests |

## The 60-second version

```php
use SafeSurf\SafeSurf;

$result = SafeSurf::analyze('https://example.com');

echo $result['result']['verdict'];     // "Safe" | "Suspicious" | "Risky"
echo $result['result']['final_score']; // 0-100
print_r($result['result']['reasons']); // good / neutral / bad reasons
```

Every check runs independently; a failed check (network timeout, missing service) never aborts the analysis — it is reported in `errors[]` and the result is marked `incomplete: true`.
