# SafeSurf (phishing-detector): Agent Guide

A short guide for agents working in this repo. It is based on a scan of the project; do not invent structures or functions that do not exist.

## Overview

A PHP 8+ library (`safesurf/safesurf`, namespace `SafeSurf\`) that analyzes URLs and detects phishing indicators. Single entry point: `SafeSurf::analyze(string $url, ?Config $config): array`. It is a PHP rewrite of [urlvet/urlvet](https://github.com/urlvet/urlvet). The output is an associative array (`features`, `infrastructure`, `domain_info`, `analysis`, `content_data`, `result`), ready for `json_encode`.

## Folder structure and key files

```
src/
  SafeSurf.php                  # Static facade → Analyzer::analyze()
  Config.php                    # Configuration (constructor promotion, all fields public)
  Analyzer/
    Analyzer.php                # Orchestrates every check + cache + timing + error capture
    ResultScorer.php            # Multi-signal risk/trust scoring → Safe/Suspicious/Risky verdict
  Checks/                       # One class = one signal group (all static)
    UrlSignals.php              # IP host, punycode, URL length/depth, keywords, shorteners, subdomain count
    SubdomainSignals.php        # Sensitive labels in subdomains (login-, secure-, verify-...) + brand names in subdomains on unofficial domains
    TldSignals.php              # Trusted/risky/ICANN/hosting-platform TLD (via PSL)
    DnsSignals.php              # A/AAAA records, NS & MX validity
    TlsCombined.php             # TLS certificate: issuer, age, CT log, chain, hostname match (probe pinned to the resolved IP)
    HttpCombined.php            # Manual redirect chain, HTTP status, HSTS
    Content.php                 # Pure analyzeHtml() (no network): login/payment/personal forms, hidden iframes, brand mismatch, external or brand-mismatch favicon, external meta-refresh, external asset hosts, text sample
    JsSignals.php               # Inline JS heuristics: obfuscation (eval/atob/unescape/hex), form injection, JS redirect, crypto wallet hooks
    RootDomainCorrelation.php   # Root vs subdomain correlation: root active/parked, off-domain redirect, content similarity (shingle Jaccard), IP infrastructure (/24, /48)
    Brand.php                   # Brand match (title & body text) against official_domains + helpers namesInText()/officialDomainsFor()
    Homoglyph.php               # Homograph: punycode decode → mixed script (Latin+Cyrillic/Greek/Armenian) & fullwidth; single-script IDNs are not flagged
    Entropy.php                 # SLD randomness score (entropy, bigram, consonant runs, etc.)
  Service/
    Rank.php                    # Rank lookup in assets/top-1m.csv (Tranco-style, "rank,domain" per line)
    DomainInfo.php              # RDAP (IANA bootstrap + well-known) with WHOIS fallback (io-developer/php-whois): age, expiry, status, DNSSEC
    Typosquat.php               # Levenshtein (distance 1-2) against top-5000 domains + combosquat (brand SLD inside SLD)
    ThreatFeeds/                # Threat-feed plugin system
      ThreatFeedInterface.php   # Feed contract: name() + check(url, config) → ['listed'=>bool, 'severity'=>..., ...]|null; the feed's class PHPDoc is injected into the result
      FeedRunner.php            # Runs built-in + external plugin feeds (all settings from Config::$threatFeeds); dedupe by name, per-feed TTL via the 'ttl' option, extracts the class PHPDoc (summary + @feed-category tag) → description/category in the result; per-feed cache
      ThreatFeeds.php           # The single source of threat-feed configuration: built-in toggles + phishTankApiKey/UserAgent, plugins, TTL, per-feed options (setOption/option); fluent API; installed automatically on Config as Config::$threatFeeds
      PhishTank.php             # Built-in feed: PhishTank API (optional API key); the result is also exposed as the legacy 'phishing' field
  Cache/
    CacheInterface.php          # getJson/setJson
    PhpFastCacheAdapter.php     # phpfastcache adapter
  Util/
    DomainUtil.php              # normalizeUrl, hostFromUrl, registrableDomainFromUrl (PSL via Pdp), tldFromDomain
    HttpClient.php              # SSRF-safe curl wrapper: resolve DNS → block private IPs (including IPv4-mapped IPv6) → pin IP via CURLOPT_RESOLVE; http/https scheme whitelist; body size limit (CURLOPT_WRITEFUNCTION)
    DnsQuery.php                # Minimal UDP DNS client for querying a SPECIFIC resolver (target = fixed, operator-configured IP, not user input; random id, timeout, A-record parsing + compression pointer); usable by DNS-based feed plugins
  Constants/DataFiles.php       # Lazy loader for assets/*.php files
assets/                         # Static data (returned as PHP arrays)
  brands.php                    # brand => [title_keywords, official_domains]
  sensitive_subdomains.php      # Sensitive subdomain label => category (auth/security/verification/...)
  hosting_platforms.php         # Trusted PSL private domains (github.io, vercel.app, ...) → suppress rank-0/NS penalties
  risky_tlds.php, trusted_tlds.php, url_keywords.php, url_shorteners.php, top-1m.csv
storage/
  public_suffix_list.dat        # PSL (auto-downloaded when missing)
  cache/                        # phpfastcache Files
tests/                          # PHPUnit (AnalyzerSmokeTest.php)
examples/analyze.php            # CLI: php examples/analyze.php <url>
```

## Detection flow

1. `DomainUtil::normalizeUrl` → validate the http/https scheme.
2. `DomainUtil::registrableDomainFromUrl` (PSL, `Pdp\Rules`) → root/registrable domain; on failure → `error: invalid_domain`.
3. The full-result cache (`analyze_result:<url>`) is checked first.
4. Every check runs through `timed()` (a caught exception becomes `errors[]`, not fatal) and `cached()` (per-type TTL from Config).
5. Network-backed checks: Rank (local CSV), HttpCombined (HEAD→GET per hop, redirects followed manually), DNS (dns_get_record/gethostbynamel), RDAP/WHOIS, TLS (stream_socket_client, IP pinned first), Content (GET + DOMDocument), RootDomainCorrelation (GET root domain + parse title/text; subdomain hosts only), PhishTank (POST, optional), Typosquat (local vs top-5000 CSV). Pure, network-free checks: SubdomainSignals, JsSignals, Homoglyph, Entropy, Brand.
6. `ResultScorer::generate` turns features into `risk_score`, `trust_score`, `final_score` (0-100, formula `50 + (trust-risk)/2`), and `verdict` (Safe ≥65, Suspicious ≥30, Risky <30), plus `reasons` (good/neutral/bad). Principle: one weak indicator must never produce Risky on its own; strong signals (raw IP, punycode, verified PhishTank, password form without TLS) carry heavy weights. Root-vs-subdomain correlation signals (parked/inactive root + login form on the subdomain + weak reputation) only score as COMBO; an inactive root or different infrastructure alone stays neutral.
7. The result is cached only when no error occurred (`incomplete: false`).

## analyze() output fields added (contract: add, never change or remove)

- `features.subdomain`: labels, sensitive_labels, brand_hits, has_brand_impersonation (SubdomainSignals)
- `homoglyph_result`: decoded, mixed_scripts, fullwidth_chars, reasons (Homoglyph v2)
- `correlation`: root facts, shared_infrastructure (same_ip/same_network/different/unknown), content_similarity, content_relation, signals (RootDomainCorrelation; null for root hosts/IPs)
- `content_data.phishing_patterns`: favicon (is_external/brand_domain/brand_mismatch), meta_refresh, external_asset_hosts, brand_names_in_text, login_with_brand_text, js_signals
- `ssl_info.is_suspicious`, `tls_info.hostname_mismatch`, and `domain_info.status` are now scored
- `threat_feeds`: `{enabled_feeds, results[]}`; each entry: feed, description and category from the feed's class PHPDoc (summary + `@feed-category` tag), from_external_plugin, checked, listed, severity, detail, error. The PhishTank feed is still exposed through the legacy `phishing` field (shape unchanged); the scorer reads the PhishTank score from `phishing` and other feeds from `threat_feeds`.

## Threat-feed plugin system

- A feed is a class implementing `ThreatFeedInterface` (`name()`, `check(url, config)`) that returns `['listed' => bool, 'severity' => phishing|malware|blocked|unwanted|info, ...detail]`, or null when the check cannot run.
- External plugins are registered via `Config::addThreatFeed(new MyFeed())` or `new Config(threatFeeds: $setup)`. No other Config arguments exist for feeds FeedRunner extracts the plugin's class PHPDoc into `results[].description` and its `@feed-category` tag into `results[].category`; this is the "PHPDoc injected into result" mechanism.
- `ThreatFeeds` (always present at `Config::$threatFeeds`, created automatically in the Config constructor) is the ONLY source of feed settings: built-in toggles, the PhishTank API key, TTL (`ttlSeconds`/`withTtl`), and the generic per-feed option map (`setOption(name, key, value)`; feeds read via `$config->threatFeeds?->option(...)`; the `ttl` key overrides that feed's cache TTL). Do NOT add Config arguments for feed concerns; a new setting means a new property or option on ThreatFeeds.
- Built-in feeds: PhishTank only (default ON, `ThreatFeeds::$enablePhishTank`).
- Scorer weights per severity: phishing 70, malware 70, blocked 25, unwanted 20, info 0. The PhishTank entry is skipped because it is already scored via the `phishing` field.
- Per-feed cache: key `threat_feed:<name>:<sha1(url)>`, TTL from `ThreatFeeds` (`ttlSeconds`/`withTtl`; per-feed override via the `ttl` option). A feed that throws is caught by FeedRunner per feed, so other feeds are unaffected.

## Scanner security (MUST be preserved)

- Every HTTP fetch goes through `HttpClient::request`: validate the scheme (http/https only), resolve DNS first, reject private/loopback/link-local/metadata IPs (169.254.169.254) including IPv4-mapped IPv6, then pin the IP with `CURLOPT_RESOLVE` (anti DNS-rebinding). curl does NOT follow redirects; the chain is followed manually per hop so every destination is re-validated. A body size limit is enforced via `CURLOPT_WRITEFUNCTION` (Config `maxBodyBytes`).
- `TlsCombined` also pins the IP: the TLS probe targets the IP from `resolveFirstPublicIp`, not the hostname directly.
- Do not add functions that fetch arbitrary URLs without going through `HttpClient` or without private-IP validation and size/timeout limits.
- Never enable `CURLOPT_FOLLOWLOCATION` for URLs that come from user input or redirects (fixed trusted targets such as the IANA RDAP bootstrap are the exception).

## Running tests

```bash
composer tests        # = vendor/bin/phpunit tests/
vendor/bin/phpunit    # same (phpunit.xml)
```

```bash
composer rector    # = vendor/bin/rector process --ansi
composer rector:dry-run    # dry-run, no changes
```

- Tests MUST NOT depend on live phishing websites or unstable external services; use synthetic HTML/data fixtures for pure checks. The existing network tests (public IP 1.1.1.1) are smoke tests and may be slow.
- Per-check unit tests live in tests/: SubdomainSignalsTest, HomoglyphTest, JsSignalsTest, ContentAnalyzeHtmlTest (pure HTML fixtures), RootDomainCorrelationTest, ResultScorerTest (synthetic responses), HttpClientStaticTest, DnsQueryTest (synthetic packets), FeedRunnerTest (synthetic external plugins + PHPDoc). `Content::analyzeHtml()`, `RootDomainCorrelation::correlate()`, `DnsQuery::buildQuery/parseResponse`, and the feed logic are separated from fetching so they can be tested without network.
- `storage/test_psl.dat` is referenced by the smoke test; for IP URLs the PSL is not needed (it is not auto-created).

## Rules for agents

- Code style: `declare(strict_types=1)`, `final class`, static methods for Checks/Service, PHP >= 8.0 (avoid 8.1+ features: enums, readonly properties, fibers). PSR-4 namespace `SafeSurf\` → `src/`.
- Follow existing patterns: new static checks go in `src/Checks/`, new static data in `assets/` plus a loader in `Constants/DataFiles.php`, and new configuration is a public `Config.php` property with a safe default (backward compatible via named args).
- Every network operation in a new check must fail soft (try/catch → null), have a TTL cache, and go through `HttpClient`. The one exception is a UDP DNS query to a fixed, operator-configured resolver IP (the `DnsQuery` pattern, usable by DNS-based feed plugins): the connection target MUST be fixed or configurable, never user input, with a timeout and a response size limit.
- Keep pure parsing separate from fetching (the `Content::analyzeHtml` and `RootDomainCorrelation::correlate` pattern) so it can be tested with fixtures.
- The analyze() output is an API contract: add new fields, never change or remove old ones.
- Scorer: add weights proportionally; one weak indicator gets a small or neutral weight, a combination of indicators gets a large weight. Never let a single ambiguous signal produce a Risky verdict. Sensitive-label and brand signals in subdomains, an inactive root, and different infrastructure are combo signals; see the "Root-domain vs subdomain correlation" block in ResultScorer.
- Brand tokens for SubdomainSignals are derived from brands.php and FILTER generic SLDs (login, mail, secure, www, app, ...) so `login.example.com` is not treated as Yahoo impersonation.
- `assets/top-1m.csv` is updated by a GitHub workflow; do not commit CSV changes manually.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, ...), in English; see `git log`.
