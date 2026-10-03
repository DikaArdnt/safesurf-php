# Configuration

All configuration lives in a single `SafeSurf\Config` value object. Every field is public and constructor-promoted, so options are passed as named arguments:

```php
use SafeSurf\Config;

$config = new Config(cache: $cacheAdapter);

$config->addThreatFeed(new MyCompanyFeed())  // external feed plugin
       ->threatFeedSetup()
       ->withPhishTank(true, 'your-key');     // built-in feed + API key
```

Fields you omit keep their defaults, so adding options in library upgrades is backward-compatible.

## Options

### Paths & data

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `cache` | `?CacheInterface` | `null` | Cache backend. `null` disables caching. See [Getting Started → Using a cache](getting-started.md#using-a-cache). |
| `rankCsvPath` | `string` | `assets/top-1m.csv` | Tranco-style global traffic ranking used by the rank lookup and the typosquatting check. The file ships with the library and is refreshed by a GitHub workflow — do not edit it manually. |
| `publicSuffixListPath` | `string` | `storage/public_suffix_list.dat` | Public Suffix List used for registrable-domain/TLD parsing. Downloaded automatically on first use if the file is missing. |

### HTTP fetching

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `httpTimeoutMs` | `int` | `5000` | Total request timeout per hop (ms). |
| `httpHeaderTimeoutMs` | `int` | `800` | Connect timeout per hop (ms), capped at 500 internally. |
| `maxRedirects` | `int` | `10` | Maximum redirect hops followed manually by the HTTP check. |
| `userAgent` | `string` | `SafeSurfPHP/1.0` | `User-Agent` sent by HTTP requests. |
| `maxBodyBytes` | `int` | `5242880` | Hard cap on downloaded response body (bytes, 5 MiB). The transfer is aborted once the cap is exceeded; the partial body is kept. |
| `dnsQueryTimeoutMs` | `int` | `2000` | Timeout for the raw UDP DNS client (`SafeSurf\Util\DnsQuery`) used against fixed, configured resolvers (e.g. DNS-based feed plugins). |

### Threat feeds

Threat-feed configuration does **not** live in `Config` constructor args — every setting lives on the dedicated `SafeSurf\Service\ThreatFeeds\ThreatFeeds` setup object, attached to every `Config` as `threatFeeds` (a default is created automatically). Configure it fluently via `Config::addThreatFeed()` / `Config::threatFeedSetup()`, or pass your own instance with `new Config(threatFeeds: $setup)`. Full guide: [Threat Feeds](threat-feeds.md#registering-feeds-the-threatfeeds-setup).

| Setting (on `ThreatFeeds`) | Default | Description |
| --- | --- | --- |
| `enablePhishTank` / `withPhishTank()` | `true` | PhishTank feed (community phishing database). `withPhishTank($enable, $apiKey, $userAgent)` sets the key and User-Agent in one call. |
| `phishTankApiKey` | `null` | Optional PhishTank application key. Without it the API works but is rate-limited. |
| `phishTankUserAgent` | `phishtank/SafeSurfPHP` | `User-Agent` for PhishTank API calls (PhishTank asks apps to identify themselves). |
| `plugins` / `addFeed()` | `[]` | External `ThreatFeedInterface` plugins to run alongside the built-ins. The former built-in Internet Positif / Trust+ check is available as a plugin; see [Threat Feeds](threat-feeds.md). |
| `ttlSeconds` / `withTtl()` | `10800` (3 h) | Shared cache TTL for every feed result; per-feed override via `setOption(name, 'ttl', seconds)`. |
| `options` / `setOption()` / `option()` | `[]` | Generic per-feed option map — the extension point for feed-specific settings (api keys, endpoints, ...) so they never become `Config` fields. |

### Subdomain correlation

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enableRootDomainCorrelation` | `bool` | `true` | For subdomain hosts, fetch the root (registrable) domain and correlate it with the subdomain (parked root, off-domain redirect, content similarity, infrastructure split). |
| `rootCorrelationMaxHops` | `int` | `3` | Maximum redirect hops followed when probing the root domain. |

### Cache TTLs (seconds)

Each check caches independently under its own key; a cached result is reused until its TTL expires.

| Field | Default | Cached item |
| --- | --- | --- |
| `ttlAnalyzeResultSeconds` | `86400` (1 day) | The complete `analyze()` result (only cached when `incomplete: false`) |
| `ttlDomainRankSeconds` | `86400` (1 day) | Traffic rank + typosquatting top-domain table |
| `ttlIpResolutionSeconds` | `10800` (3 h) | A/AAAA resolution per domain |
| `ttlDnsValiditySeconds` | `10800` (3 h) | NS/MX validity |
| `ttlWhoisSeconds` | `86400` (1 day) | RDAP/WHOIS domain info |
| `ttlHttpCombinedSeconds` | `10800` (3 h) | Redirect chain, HTTP status, HSTS |
| `ttlTlsCombinedSeconds` | `86400` (1 day) | TLS certificate inspection |
| `ttlContentSeconds` | `10800` (3 h) | HTML content analysis |
| `ttlRootDomainCorrelationSeconds` | `21600` (6 h) | Root-domain probe for the correlation check |

Threat-feed results (`threat_feed:<name>:<sha1(url)>`) are cached with the TTL from the `ThreatFeeds` setup (`ttlSeconds` / `withTtl()`, per-feed override via `setOption(name, 'ttl', ...)`) — see [Threat Feeds](threat-feeds.md#registering-feeds-the-threatfeeds-setup).

## Static data assets

SafeSurf ships its detection vocabulary as PHP arrays in `assets/`, lazily loaded through `SafeSurf\Constants\DataFiles`:

| File | Used by | Content |
| --- | --- | --- |
| `assets/brands.php` | Brand matching, subdomain impersonation, favicon/brand-text checks | brand name → title keywords + official domains |
| `assets/sensitive_subdomains.php` | Subdomain label analysis | sensitive label (login, secure, verify, …) → category |
| `assets/hosting_platforms.php` | TLD analysis | trusted PSL-private suffixes (github.io, vercel.app, …) that should not be penalized for being unranked/non-ICANN |
| `assets/risky_tlds.php` | TLD analysis | TLDs commonly abused for spam/phishing |
| `assets/trusted_tlds.php` | TLD analysis | high-trust TLDs (gov, edu, …) |
| `assets/url_keywords.php` | URL keyword scan | phishing keyword → category |
| `assets/url_shorteners.php` | Shortener detection | known URL-shortener domains |
| `assets/top-1m.csv` | Rank lookup, typosquatting | global top-1M domains, `rank,domain` per line |

To add your own entries (e.g. in-house brands), extend the arrays or point `Config::$rankCsvPath` at your own ranking file.
