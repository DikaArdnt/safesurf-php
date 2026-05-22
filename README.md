# SafeSurf (PHP Library)

## Disclaimer

This project is a PHP-native rewrite of the repository [abhizaik/urlvet](https://github.com/abhizaik/urlvet).

SafeSurf for PHP focuses on transparent analysis results (reasons), scores, and verdicts.

## Features

- Real-time URL analysis: redirect chain, HTTP status, HSTS
- Domain & DNS signals: rank (top-1m), IP resolution, NS/MX validity
- URL signals: keywords, URL shortener, excessive length/depth, subdomain count, punycode
- TLS/SSL signals: TLS presence, issuer, certificate age, chain validation (best effort)
- Page content (best effort): title, login/payment/personal form detection, hidden iframe, brand mismatch
- Threat feed: PhishTank (optional, depending on API availability)
- Optional caching via phpfastcache to speed up network lookups and data parsing

## System Requirements

- PHP >= 8.0
- PHP extensions: `curl`, `openssl`, `dom`, `libxml`

## Installation (via Composer / Packagist)

```bash
composer require safesurf/safesurf
```

## Installation (from this source repository)

```bash
git clone https://github.com/DikaArdnt/safesurf-php.git
cd safesurf-php
composer install
```

## Quick Start

```bash
php examples/analyze.php example.com
```

## Using in Your Code (without cache)

```php
<?php

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use SafeSurf\SafeSurf;

$result = SafeSurf::analyze('https://example.com');
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
```

## Using with phpfastcache Cache (recommended)

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
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
```

## Configuration

The main configuration is located in [Config.php](./src/Config.php). The most commonly used fields are:

- `cache`: cache implementation (optional). Ready-to-use adapter: [PhpFastCacheAdapter.php](./src/Cache/PhpFastCacheAdapter.php)
- `rankCsvPath`: path to `assets/top-1m.csv` for rank lookup
- `publicSuffixListPath`: PSL path (`storage/public_suffix_list.dat`), used to extract the registrable domain and TLD
- `httpTimeoutMs`, `httpHeaderTimeoutMs`, `maxRedirects`, `userAgent`: HTTP request controls
- Cache TTLs: `ttlDomainRankSeconds`, `ttlIpResolutionSeconds`, `ttlDnsValiditySeconds`, `ttlWhoisSeconds`, `ttlHttpCombinedSeconds`, `ttlTlsCombinedSeconds`, `ttlContentSeconds`, `ttlAnalyzeResultSeconds`
- PhishTank (optional): `phishTankApiKey`, `phishTankUserAgent`

## Output (Result Structure)

`SafeSurf::analyze()` returns an array that is suitable for `json_encode()`:

- `url`, `domain`
- `features`
  - `rank`
  - `tld`: `tld`, `is_trusted_tld`, `is_risky_tld`, `is_icann`
  - `url`: `url_shortener`, `uses_ip`, `contains_punycode`, `too_long`, `too_deep`, `has_homoglyph`, `subdomain_count`, `keywords`
- `infrastructure`: `ip_addresses`, `nameservers_valid`, `ns_hosts`, `mx_records_valid`, `mx_hosts`
- `domain_info`: RDAP/WHOIS results (may be `null` if lookup fails)
- `analysis`: redirect chain, HTTP status, HSTS
- `ssl_info` and `tls_info`: TLS/SSL summary
- `content_data`: HTML parsing summary (may be `null`)
- `domain_randomness`: entropy/randomness results for the domain label
- `typosquat_result`: typosquatting/combo-squatting results
- `phishing`: PhishTank check results (may be `null`)
- `result`: final score, verdict, and reasons
- `performance`: total time and timing list
- `incomplete`, `errors`: present if some tasks fail (network/timeouts)

## Security & Operational Notes

- SSRF protection: HTTP requests resolve IPs and reject private, link-local, and loopback IPs for target hosts/IPs.
- TLS/SSL validation is best effort: some environments may fail to verify the chain due to CA store or configuration issues.
- Some modules require internet access (IANA RDAP bootstrap, PSL download, PhishTank).
- Content analysis performs GET requests and HTML parsing; enable caching to reduce load.

## Development

Run tests:

```bash
cd safesurf-php
vendor/bin/phpunit
```

## License

MIT License. See [LICENSE](./LICENSE) for details.
