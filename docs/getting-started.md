# Getting Started

This guide walks through installing SafeSurf, running your first analysis from the CLI and from code, and enabling caching for repeated lookups.

- Requirements
- Installation
- Your first analysis (CLI)
- Your first analysis (PHP)
- Using a cache
- Interpreting the verdict
- Where to go next

## Requirements

| Requirement | Notes |
| --- | --- |
| PHP >= 8.0 | Strict types throughout; named arguments supported |
| ext-curl | All outbound HTTP goes through the bundled SSRF-safe `HttpClient` |
| ext-openssl | TLS certificate inspection |
| ext-dom + ext-libxml | HTML parsing for content analysis |
| ext-intl *(optional)* | Fast IDN/punycode decoding in the homoglyph check (falls back to the bundled domain parser) |

Network access is required for the live checks (HTTP, DNS, RDAP/WHOIS, TLS, threat feeds). Pure checks (URL structure, subdomain labels, homoglyph, entropy, typosquatting, keywords) work offline. The Public Suffix List (`storage/public_suffix_list.dat`) is downloaded automatically on first use if missing.

## Installation

Via Composer (Packagist):

```bash
composer require safesurf/safesurf
```

Or from the source repository:

```bash
git clone https://github.com/DikaArdnt/safesurf-php.git
cd safesurf-php
composer install
```

## Your first analysis (CLI)

The repository ships with a CLI helper that enables the file cache and pretty-prints the JSON result:

```bash
php examples/analyze.php https://example.com
```

Pass any URL as the argument. Results are cached in `storage/cache/`, so re-running the same URL is fast.

## Your first analysis (PHP)

Without a cache:

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use SafeSurf\SafeSurf;

$result = SafeSurf::analyze('https://example.com');

echo json_encode(
    $result,
    JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
) . PHP_EOL;
```

`SafeSurf::analyze()` accepts any `http`/`https` URL. Other schemes are rejected with `{"error": "invalid_url"}`. The return value is a plain associative array — see the [Output Reference](output-reference.md) for every field.

## Using a cache

Each check has its own cache entry and TTL, and the complete result is cached as a whole when nothing failed. Without a cache the library still works, but every call re-does all network work. The bundled adapter wraps [phpfastcache](https://github.com/PHPSocialNetwork/phpfastcache) (already a Composer dependency):

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Phpfastcache\CacheManager;
use Phpfastcache\Config\ConfigurationOption;
use SafeSurf\Cache\PhpFastCacheAdapter;
use SafeSurf\Config;
use SafeSurf\SafeSurf;

$pool = CacheManager::getInstance('Files', new ConfigurationOption([
    'path' => __DIR__ . '/storage/cache',
]));

$config = new Config(cache: new PhpFastCacheAdapter($pool));
$result = SafeSurf::analyze('https://example.com', $config);
```

Any implementation of `SafeSurf\Cache\CacheInterface` (`getJson(string $key): ?array`, `setJson(string $key, array $value, int $ttlSeconds): void`) works — Redis, Memcached, APCu, whatever fits your deployment. Cache keys and TTLs are listed in [Configuration](configuration.md#caching).

## Interpreting the verdict

The interesting part of the result is `result`:

```json
{
    "risk_score": 5,
    "trust_score": 100,
    "final_score": 98,
    "verdict": "Safe",
    "reasons": {
        "neutral_reasons": [
            "Standard, officially recognized domain extension."
        ],
        "good_reasons": [
            "Global Giant: Ranked #171 worldwide.",
            "Long-standing domain history (31 years 1 month)."
        ],
        "bad_reasons": []
    }
}
```

| Verdict | Final score | Meaning |
| --- | --- | --- |
| `Safe` | >= 65 | Nothing suspicious found; trust signals dominate |
| `Suspicious` | 30-64 | Mixed or weak signals; review the reasons before deciding |
| `Risky` | < 30 | Strong risk indicators present |

The `reasons` arrays are plain-English sentences meant to be shown to end users. How the scores are assembled is documented in [Scoring & Verdicts](scoring.md).

## Where to go next

- [Configuration](configuration.md) — tune timeouts, TTLs, threat feeds, and paths
- [Detection Checks](checks.md) — what SafeSurf actually inspects
- [Threat Feeds](threat-feeds.md) — plug in your own intelligence sources
- [Security](security.md) — the SSRF guarantees of the built-in HTTP client
