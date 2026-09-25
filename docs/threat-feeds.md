# Threat Feeds

SafeSurf's threat-feed subsystem checks the analyzed URL against external blocklists. Everything is built on one contract, so built-in feeds and third-party plugins behave identically:

- **PhishTank** — community phishing database (built-in, on by default).
- **Your plugins** — any class implementing `ThreatFeedInterface`, registered through the dedicated `ThreatFeeds` setup.

The runner (`SafeSurf\Service\ThreatFeeds\FeedRunner`) executes every enabled feed, caches each feed's result separately, and isolates failures: a feed that throws only records an `error` on its own entry — other feeds and the analysis continue.

## The `ThreatFeedInterface` contract

```php
namespace SafeSurf\Service\ThreatFeeds;

interface ThreatFeedInterface
{
    public function name(): string;

    /**
     * @return array{listed: bool, severity: string, ...}|null
     *         null = "cannot be checked" (not applicable, service down)
     */
    public function check(string $url, Config $config): ?array;
}
```

- Return `null` when the feed cannot produce an answer (e.g. the host type is not applicable). The result entry will show `checked: false` with an explanatory `error`.
- Return an array with at least `listed` (bool) and `severity` when the feed answered. Extra keys become the `detail` payload.
- `severity` should be one of `phishing`, `malware`, `blocked`, `unwanted`, `info` (defaults to `blocked` when listed).

## PHPDoc injection: descriptions in the result

Every feed's **class-level PHPDoc is parsed and injected into the result** so consumers can always see what a feed actually checks:

- The docblock summary lines become `threat_feeds.results[].description`.
- A `@feed-category` tag becomes `results[].category` (default `external`).

This means plugin authors document their feed in the natural place, and the documentation travels with the result — no separate feed registry to keep in sync.

## Registering feeds: the `ThreatFeeds` setup

Everything threat-feed related — built-in toggles, plugins, TTLs, per-feed settings — lives in one dedicated object, `SafeSurf\Service\ThreatFeeds\ThreatFeeds`, so feed configuration never grows the `Config` constructor. Every `Config` already has one attached (as `Config::$threatFeeds`, created with safe defaults); configure it fluently:

```php
use SafeSurf\Config;

$config = new Config();

$config->addThreatFeed(new MyCompanyFeed())      // register a plugin
       ->threatFeedSetup()                       // same as $config->threatFeeds
       ->withPhishTank(false)                    // toggle the built-in
       ->withTtl(3600)                           // shared feed cache TTL
       ->setOption('mycompany', 'api_key', 'secret-123');  // per-feed setting
```

or supply your own instance up front:

```php
use SafeSurf\Service\ThreatFeeds\ThreatFeeds;

$setup = (new ThreatFeeds())
    ->withoutBuiltIns()                     // run plugins only
    ->addFeed(new MyCompanyFeed())
    ->withTtl(3600);

$config = new Config(threatFeeds: $setup);
```

Semantics worth knowing:

- **Single source of truth** — all feed settings (PhishTank toggle/key/User-Agent, plugins, TTLs, options) live on the `ThreatFeeds` instance; there are no `Config` constructor args for feeds.
- **Registration is name-based** — `addFeed()` skips a plugin whose `name()` is already registered, and the runner keeps the first occurrence of any name, so duplicates collapse and a plugin never shadows an enabled built-in.
- **`removeFeed(name)`** drops a plugin by name or disables a built-in (`removeFeed('phishtank')` ≡ `withPhishTank(false)`).
- **Per-feed options** — `setOption(feedName, key, value)` stores settings any feed can read, which is how new feeds get configured without new `Config` fields. The special `ttl` key (seconds) overrides the shared cache TTL for that one feed.

Per-feed options are read inside `check()`:

```php
public function check(string $url, Config $config): ?array
{
    $apiKey = $config->threatFeeds?->option($this->name(), 'api_key');
    // ...
}
```

## Writing a plugin

```php
<?php

use SafeSurf\Config;
use SafeSurf\Service\ThreatFeeds\ThreatFeedInterface;

/**
 * Flags URLs present in our internal security incident feed.
 *
 * @feed-category corporate-intel
 */
class MyCompanyFeed implements ThreatFeedInterface
{
    public function name(): string
    {
        return 'mycompany';
    }

    public function check(string $url, Config $config): ?array
    {
        // Return null when the feed cannot be checked.
        return ['listed' => true, 'severity' => 'phishing', 'source' => 'internal-feed'];
    }
}

$config = (new Config())->addThreatFeed(new MyCompanyFeed());
$result = SafeSurf::analyze('https://example.com', $config);

// $result['threat_feeds']['results'][0]['description'] === "Flags URLs present in our internal security incident feed."
// $result['threat_feeds']['results'][0]['category']    === "corporate-intel"
```

Plugin rules of thumb:

- Register instances (not class names) via `Config::addThreatFeed()` or the `ThreatFeeds` setup; duplicates of a name are skipped.
- Feed-specific settings come from the per-feed option map (`$config->threatFeeds?->option(...)`), not from new `Config` fields.
- Keep `check()` failure-safe: return `null` instead of throwing when the backend is unreachable (FeedRunner will also catch, but `null` communicates "not checked" more precisely).
- If your feed fetches anything over HTTP, route it through `SafeSurf\Util\HttpClient` — see [Security](security.md).

## Built-in feeds

### PhishTank (`ThreatFeeds::$enablePhishTank`, default on)

Posts the URL to the `checkurl.phishtank.com` API (`ThreatFeeds::$phishTankApiKey` optional but recommended — set it via `withPhishTank(true, 'your-key')`). Category: `phishing`.

`detail` fields: `in_database`, `phish_id`, `phish_detail_page`, `verified`, `verified_at`, `valid`, `target`, `from_cache`, `raw_response`.

Semantics worth knowing:

- `in_database: true, valid: true, verified: true` — confirmed phishing → **+200 risk**.
- `in_database: true, valid: true, verified: false` — reported and marked valid, awaiting verification → **+70 risk**.
- `in_database: true, valid: false` — unverified or community-rejected submission → **not scored** (this happens to legitimate domains; always read the reasons).

The PhishTank entry is also mirrored into the legacy top-level `phishing` field (shape unchanged) so older consumers keep working.

### Internet Positif / Trust+ (Example plugin)

The Indonesian Internet Positif (Trust+, formerly Nawala) DNS blocklist check shipped as an optional built-in feed in earlier releases. It was removed because the blocklist covers far more than phishing (porn, gambling, and other categories), which produced too many false positives for a general-purpose phishing scanner. If you still want it, register it as an external plugin — the resolver IPs and the definition of a "blocked" answer are then yours to control:

```php
<?php

use SafeSurf\Config;
use SafeSurf\Service\ThreatFeeds\ThreatFeedInterface;
use SafeSurf\Util\DnsQuery;
use SafeSurf\Util\DomainUtil;
use SafeSurf\Util\HttpClient;

/**
 * Checks hosts against Indonesia's Internet Positif (Trust+) DNS filter.
 *
 * @feed-category government-blocklist
 */
class InternetPositifFeed implements ThreatFeedInterface
{
    /** Filtering resolvers answer blocked names with a block-page IP or their own IP. */
    private const BLOCK_IPS = ['180.131.144.144'];
    private const RESOLVERS = ['180.131.144.144', '180.131.145.145'];

    public function name(): string
    {
        return 'internetpositif';
    }

    public function check(string $url, Config $config): ?array
    {
        $host = DomainUtil::hostFromUrl($url);
        if ($host === null || $host === '' || filter_var($host, FILTER_VALIDATE_IP)) {
            return null; // IP-literal hosts cannot be checked against a name-based filter
        }

        foreach (self::RESOLVERS as $resolver) {
            if (HttpClient::isPrivateIp($resolver)) {
                continue;
            }
            $resp = DnsQuery::query($resolver, $host, $config->dnsQueryTimeoutMs);
            if ($resp === null || $resp['status'] !== 'ok' || $resp['ips'] === []) {
                continue;
            }
            $listed = (bool) array_intersect($resp['ips'], self::BLOCK_IPS, self::RESOLVERS);
            return [
                'listed' => $listed,
                'severity' => $listed ? 'blocked' : 'info',
                'detail' => ['resolver' => $resolver, 'resolved_ips' => $resp['ips']],
            ];
        }
        return null; // resolvers unreachable: not checked
    }
}

$config = (new Config())->addThreatFeed(new InternetPositifFeed());
```

Notes for this feed:

- `SafeSurf\Util\DnsQuery` is a minimal raw UDP DNS client for querying a **fixed, operator-configured resolver IP** (never user input). Keep using it (or a fixed resolver list) if you adapt the example.
- A hit means the domain is blocked in Indonesia for any reason, not that it phishes; the scorer maps severity `blocked` to a moderate +25 risk signal.

## Scoring & caching

Severity-to-risk mapping (documented in [Scoring & Verdicts](scoring.md#threat-feeds)):

| severity | weight |
| --- | --- |
| `phishing` | 70 |
| `malware` | 70 |
| `blocked` | 25 |
| `unwanted` | 20 |
| `info` | 0 |

Each feed's result is cached independently under `threat_feed:<name>:<sha1(url)>` with the setup's shared TTL (`ThreatFeeds::$ttlSeconds`, default 3 h, set via `withTtl()`), so re-analyzing the same URL does not re-query your backend. `setOption(name, 'ttl', seconds)` overrides the TTL for one feed.
