# SafeSurf (PHP Library)

A PHP 8+ library that analyzes a URL for phishing indicators and returns a transparent, JSON-ready report: every signal inspected, the raw evidence, a risk/trust score breakdown, and a final verdict of Safe, Suspicious, or Risky.

## Disclaimer

This project is a PHP-native rewrite of the repository [urlvet/urlvet](https://github.com/urlvet/urlvet).

SafeSurf for PHP focuses on transparent analysis results (reasons), scores, and verdicts.

## Features

- **URL signals**: known shorteners, raw-IP hosts, punycode, excessive length or depth, subdomain count, phishing keywords
- **Domain & DNS signals**: global traffic rank (top-1M), IP resolution, NS/MX validity, trusted/risky/hosting-platform TLD classification via the Public Suffix List
- **Registration data**: RDAP (WHOIS fallback) for domain age, expiry, registry status, and DNSSEC
- **Subdomain analysis**: sensitive labels (`login.`, `secure.`, `verify.`, ...), brand-name impersonation in subdomains, and root-domain vs subdomain correlation (parked root, off-domain redirect, content similarity, infrastructure split)
- **Homoglyph / IDN spoofing**: punycode decoding, mixed-script (Latin + Cyrillic/Greek/Armenian) and fullwidth lookalike detection, without flagging legitimate single-script IDNs
- **Typosquatting**: Levenshtein distance 1-2 and combo-squatting against the top-5000 domains
- **Domain randomness**: entropy and DGA heuristics for the domain label
- **TLS/SSL inspection**: issuer, certificate age, Certificate Transparency, chain validation, hostname match (probe pinned to a pre-resolved IP)
- **HTTP analysis**: manual per-hop redirect chain, final status, HSTS, cross-domain jump detection
- **Page content analysis**: login/payment/personal forms, forms submitting off-domain, hidden iframes, brand mismatch, favicon/meta-refresh/external-asset patterns, obfuscated or injected JavaScript, crypto-wallet hooks
- **Threat feeds**: PhishTank (optional API key) and external plugin feeds; each feed's PHPDoc is injected into the result as its description and category
- **Transparent scoring**: risk/trust/final scores (0-100) with plain-English reasons for every signal
- **Caching**: optional per-check TTL caching via phpfastcache, or any adapter implementing `SafeSurf\Cache\CacheInterface`

## Documentation

Full documentation lives in [`docs/`](./docs):

| Document                                       | Contents                                                          |
| ---------------------------------------------- | ----------------------------------------------------------------- |
| [Getting Started](./docs/getting-started.md)   | Installation, CLI usage, first analysis in code, caching          |
| [Configuration](./docs/configuration.md)       | Every `Config` option, cache TTLs, data assets                    |
| [Detection Checks](./docs/checks.md)           | The full signal catalog: what each check inspects and returns     |
| [Scoring & Verdicts](./docs/scoring.md)        | How the scores and the Safe/Suspicious/Risky verdict are computed |
| [Output Reference](./docs/output-reference.md) | The complete result structure, field by field, with real examples |
| [Threat Feeds](./docs/threat-feeds.md)         | Built-in feeds and the plugin system (PHPDoc injection)           |
| [Security](./docs/security.md)                 | SSRF-safe fetching, IP pinning, body limits                       |
| [Extending](./docs/extending.md)               | Adding feeds, data, checks, and tests                             |

## System Requirements

- PHP >= 8.0
- PHP extensions: `curl`, `openssl`, `dom`, `libxml`

## Installation

Via Composer / Packagist:

```bash
composer require safesurf/safesurf
```

Or from this source repository:

```bash
git clone https://github.com/DikaArdnt/safesurf-php.git
cd safesurf-php
composer install
```

## Quick Start

From the CLI (uses the file cache in `storage/cache` and pretty-prints the JSON):

```bash
php examples/analyze.php https://example.com
```

In your code:

```php
<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use SafeSurf\SafeSurf;

$result = SafeSurf::analyze('https://example.com');
echo $result['result']['verdict'];          // "Safe" | "Suspicious" | "Risky"
echo $result['result']['final_score'];      // 0-100
print_r($result['result']['reasons']);      // plain-English good/neutral/bad reasons
```

### With caching (recommended)

Any implementation of `SafeSurf\Cache\CacheInterface` works; the bundled adapter wraps phpfastcache (already a dependency):

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

## How the verdict works

The scorer combines weighted signals into `risk_score` and `trust_score`, then computes
`final_score = 50 + (trust − risk) / 2` (clamped to 0-100):

| Verdict      | Final score |
| ------------ | ----------- |
| `Safe`       | >= 65       |
| `Suspicious` | 30-64       |
| `Risky`      | < 30        |

Design principles: one weak signal never produces a Risky verdict on its own; strong indicators (raw IP, punycode, verified PhishTank listing, password form without TLS) carry heavy weights; correlation findings only score as combinations. See [Scoring & Verdicts](./docs/scoring.md) for the complete weight tables.

## Example output

Real output of `SafeSurf::analyze('https://example.com')`, trimmed. The full structure and field docs are in the [Output Reference](./docs/output-reference.md).

## Configuration

All options live in [`Config.php`](./src/Config.php) and are passed as named arguments. The most common ones:

- `cache`: cache adapter (see [Getting Started](./docs/getting-started.md#using-a-cache))
- Threat feeds: configured on the dedicated `ThreatFeeds` setup (`addThreatFeed()`, `withPhishTank()`, per-feed options); see [Threat Feeds](./docs/threat-feeds.md#registering-feeds-the-threatfeeds-setup)
- `enableRootDomainCorrelation` (default `true`), `rootCorrelationMaxHops`
- HTTP controls: `httpTimeoutMs`, `httpHeaderTimeoutMs`, `maxRedirects`, `userAgent`, `maxBodyBytes`
- Cache TTLs: `ttlDomainRankSeconds`, `ttlWhoisSeconds`, `ttlContentSeconds`, ... (full list in [Configuration](./docs/configuration.md); feed TTLs live on the `ThreatFeeds` setup)

## Threat Feed Plugins

Feeds implement `SafeSurf\Service\ThreatFeeds\ThreatFeedInterface`. The class PHPDoc of every feed is injected into the result: the summary becomes `threat_feeds.results[].description` and a `@feed-category` tag becomes `results[].category`, so consumers always know what each feed checks.

Severity mapping in the risk score: `phishing`/`malware` = 70, `blocked` = 25, `unwanted` = 20, `info` = 0. Full guide: [Threat Feeds](./docs/threat-feeds.md).

## Security & Operational Notes

- **SSRF protection**: every HTTP fetch resolves DNS first, rejects private/loopback/link-local/metadata IPs (including IPv4-mapped IPv6), pins the connection to the validated IP (`CURLOPT_RESOLVE`), never lets curl follow redirects (each hop is re-validated), and caps the download size. Details: [Security](./docs/security.md).
- TLS/SSL validation is best effort: some environments fail chain verification due to CA store or proxy configuration.
- Some modules need internet access on first use (PSL download, IANA RDAP bootstrap, PhishTank); the PSL is downloaded automatically to `storage/public_suffix_list.dat` if missing.
- Content analysis performs GET requests and HTML parsing. Enable caching to reduce load when scanning at volume.

## Development

Run the test suite:

```bash
composer tests
```

Run Rector to apply automatic code upgrades:

```bash
composer rector
```

Run Rector in dry-run mode to see what changes would be made without actually applying them:

```bash
composer rector:dry-run
```

Extension guide (new feeds, data files, checks): [Extending](./docs/extending.md).

## License

MIT License. See [LICENSE](./LICENSE) for details.
