# Output Reference

`SafeSurf::analyze()` returns an associative array designed for `json_encode()`. The shape below is a stable API contract: **fields are added, never changed or removed**. Consumers should tolerate unknown extra keys.

```
url, domain, features, infrastructure, domain_info, analysis, ssl_info,
tls_info, content_data, domain_randomness, homoglyph_result, correlation,
typosquat_result, phishing, threat_feeds, performance, result,
incomplete, errors
```

On an invalid input the call short-circuits: `{"error": "invalid_url"}` (unparseable URL / non-http scheme) or `{"error": "invalid_domain"}` (registrable domain cannot be determined).

## Top-level fields

| Field | Type | Content |
| --- | --- | --- |
| `url` | string | The normalized URL that was analyzed |
| `domain` | string | Registrable (root) domain per the Public Suffix List |
| `features` | object | URL-side signals: `rank`, `tld`, `url`, `subdomain` (see [Detection Checks](checks.md)) |
| `infrastructure` | object | `ip_addresses`, `nameservers_valid`, `ns_hosts`, `mx_records_valid`, `mx_hosts` |
| `domain_info` | object \| null | RDAP/WHOIS record: `domain`, `registrar`, `created`, `updated`, `expiry`, `nameservers`, `status`, `dnssec`, `raw`, `source` (`"RDAP"`/`"WHOIS"`), plus computed `age_days`, `age_human`, `expiry_days`, `expiry_human` |
| `analysis` | object | `redirection_result` (chain, `has_domain_jump`), `http_status`, `is_hsts_supported` |
| `ssl_info` | object | Full TLS certificate inspection result |
| `tls_info` | object | TLS summary: `present`, `issuer`, `age_days`, `hostname_mismatch` |
| `content_data` | object \| null | HTML analysis (null when the page could not be fetched or was not HTML) |
| `domain_randomness` | object | Entropy/randomness metrics for the SLD (informational) |
| `homoglyph_result` | object | Punycode-decoded domain, `mixed_scripts`, `fullwidth_chars`, `reasons` |
| `correlation` | object \| null | Root-domain vs subdomain correlation; **null** for root-domain or IP hosts |
| `typosquat_result` | object | Typosquat/combo-squat match info |
| `phishing` | object \| null | Legacy PhishTank field (same shape as `threat_feeds` phishtank `detail`) |
| `threat_feeds` | object | `{ enabled_feeds: string[], results: FeedResult[] }` — see [Threat Feeds](threat-feeds.md) |
| `performance` | object | `total_time` (formatted string) and `timings[]` sorted slowest-first (`task`, `time`) |
| `result` | object | Scored verdict: `risk_score`, `trust_score`, `final_score`, `verdict`, `reasons` — see [Scoring & Verdicts](scoring.md) |
| `incomplete` | bool | `true` when at least one check failed |
| `errors` | string[] | One entry per failed check: `"<check>: <message>"` |

## `features` sub-object

```json
{
    "rank": 171,
    "tld": {
        "tld": "com",
        "is_trusted_tld": false,
        "is_risky_tld": false,
        "is_icann": true,
        "is_hosting_platform": false
    },
    "url": {
        "url_shortener": false,
        "uses_ip": false,
        "contains_punycode": false,
        "too_long": false,
        "too_deep": false,
        "has_homoglyph": false,
        "subdomain_count": 0,
        "keywords": { "has_keywords": false, "found": [], "categories": [] }
    },
    "subdomain": {
        "labels": [],
        "subdomain_count": 0,
        "sensitive_labels": {},
        "has_sensitive_label": false,
        "brand_hits": [],
        "has_brand_impersonation": false
    }
}
```

`sensitive_labels` maps label → category (`{"login": "auth"}`); `brand_hits` entries carry `brand`, `token`, `label`.

## `threat_feeds.results[]` entry

| Field | Type | Content |
| --- | --- | --- |
| `feed` | string | Feed name (`phishtank`, your plugin's `name()`) |
| `description` | string | The feed class PHPDoc summary — injected automatically |
| `category` | string | The PHPDoc `@feed-category` tag, default `"external"` |
| `from_external_plugin` | bool | Registered as an external plugin (`ThreatFeeds::addFeed()` / `Config::addThreatFeed()`) |
| `checked` | bool | The feed produced a result |
| `error` | string \| null | Feed failure message (isolated per feed) |
| `listed` | bool | The URL is listed in the feed |
| `severity` | string | `phishing` / `malware` / `blocked` / `unwanted` / `info` |
| `detail` | object \| null | The raw feed payload |
| `from_cache` | bool | Served from the per-feed cache |

## Caching behavior

- Each check caches independently (keys like `domain_rank:<domain>`, `content_check:<url>`, `threat_feed:<name>:<sha1(url)>`) with the TTLs listed in [Configuration](configuration.md#cache-ttls-seconds).
- The complete result is cached under `analyze_result:<url>` **only when `incomplete` is false** — failed analyses are retried on the next call. A cached full result still reports a fresh `performance.total_time`.

## Complete example (real output)

`SafeSurf::analyze('https://example.com')` — long raw fields (`domain_info.raw`, `raw_response`) and the timing tail are elided for readability:

```json
{
    "url": "https://example.com",
    "domain": "example.com",
    "features": {
        "rank": 171,
        "tld": { "tld": "com", "is_trusted_tld": false, "is_risky_tld": false, "is_icann": true, "is_hosting_platform": false },
        "url": {
            "url_shortener": false, "uses_ip": false, "contains_punycode": false,
            "too_long": false, "too_deep": false, "has_homoglyph": false,
            "subdomain_count": 0,
            "keywords": { "has_keywords": false, "found": [], "categories": [] }
        },
        "subdomain": {
            "labels": [], "subdomain_count": 0, "sensitive_labels": [],
            "has_sensitive_label": false, "brand_hits": [], "has_brand_impersonation": false
        }
    },
    "infrastructure": {
        "ip_addresses": ["172.66.147.243", "104.20.23.154", "2606:4700:10::ac42:93f3", "2606:4700:10::6814:179a"],
        "nameservers_valid": true,
        "ns_hosts": ["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"],
        "mx_records_valid": false,
        "mx_hosts": []
    },
    "domain_info": {
        "domain": "EXAMPLE.COM",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "created": "1995-08-14T04:00:00+00:00",
        "updated": "2026-08-14T08:01:43+00:00",
        "expiry": "2027-08-13T04:00:00+00:00",
        "nameservers": ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"],
        "status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
        "dnssec": true,
        "raw": "…full RDAP JSON…",
        "source": "RDAP",
        "age_human": "31 years 1 month",
        "age_days": 11364,
        "expiry_human": "expires in 10 months",
        "expiry_days": 322
    },
    "analysis": {
        "redirection_result": {
            "is_redirected": false,
            "chain_length": 1,
            "chain": ["https://example.com"],
            "final_url": "https://example.com",
            "final_url_domain": "example.com",
            "has_domain_jump": false
        },
        "http_status": { "code": 200, "text": "OK", "success": true, "is_redirect": false },
        "is_hsts_supported": false
    },
    "ssl_info": {
        "domain": "example.com",
        "has_tls": true,
        "chain_valid": true,
        "issuer": "SSL Corporation",
        "not_before": "2026-07-29T22:10:08+00:00",
        "not_after": "2026-10-27T22:17:21+00:00",
        "age_days": 57,
        "fingerprint": "6153A96F…B02200",
        "is_suspicious": false,
        "reasons": [],
        "ct_logged": true,
        "known_bad_chain": false
    },
    "tls_info": { "present": true, "issuer": "SSL Corporation", "age_days": 57, "hostname_mismatch": false },
    "content_data": {
        "url": "https://example.com",
        "title": "Example Domain",
        "has_forms": false, "has_login_form": false, "has_payment_form": false, "has_personal_form": false,
        "form_count": 0, "forms": [], "iframes": [],
        "has_hidden_iframe": false, "has_tracking": false,
        "fetch_duration": 30108929,
        "brand_check": { "brand_found": "", "is_mismatch": false, "detected_names": [] },
        "text_sample": "Example DomainThis domain is for use in documentation examples without needing permission. Avoid use in operations.Learn more",
        "favicon": { "href": "data:,", "is_external": false, "external_host": "", "brand_domain": "", "brand_mismatch": false },
        "phishing_patterns": {
            "favicon_external": false,
            "favicon_brand_mismatch": false,
            "meta_refresh_external": false,
            "meta_refresh": { "present": false, "delay_seconds": null, "target": "", "is_external": false },
            "external_asset_hosts": [],
            "external_asset_count": 0,
            "brand_names_in_text": [],
            "login_with_brand_text": false,
            "js_signals": {
                "script_count": 0,
                "has_obfuscation": false, "has_eval_atob": false, "has_form_injection": false,
                "has_js_redirect": false, "disables_context_menu": false, "has_crypto_wallet_hooks": false,
                "suspicious_score": 0, "reasons": []
            }
        }
    },
    "domain_randomness": {
        "domain": "example.com", "label": "example", "length": 7,
        "entropy": 2.5216406363433186, "entropy_per_char": 0.3602343766204741,
        "normalized_entropy": 0.0605009236917598,
        "vowel_ratio": 0.42857142857142855, "digit_ratio": 0, "unique_char_ratio": 0.8571428571428571,
        "longest_consonant_run": 3, "bigram_englishiness": 0.16666666666666666,
        "randomness_score": 0.3567918975896066, "is_suspicious": false, "reasons": []
    },
    "homoglyph_result": {
        "domain": "example.com", "decoded": "example.com", "has_homoglyph": false,
        "mixed_scripts": [], "fullwidth_chars": [], "scripts": ["latin"], "reasons": []
    },
    "correlation": null,
    "typosquat_result": { "is_suspicious": false },
    "phishing": {
        "in_database": true,
        "phish_id": 7366538,
        "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=7366538",
        "verified": false, "verified_at": "", "valid": false, "target": "",
        "from_cache": false,
        "raw_response": "…full API JSON…"
    },
    "threat_feeds": {
        "enabled_feeds": ["phishtank"],
        "results": [
            {
                "feed": "phishtank",
                "description": "Community-driven phishing database (phishtank.com).",
                "category": "phishing",
                "from_external_plugin": false,
                "checked": true,
                "error": null,
                "listed": false,
                "severity": "info",
                "detail": { "in_database": true, "phish_id": 7366538, "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=7366538", "verified": false, "verified_at": "", "valid": false, "target": "", "from_cache": false, "raw_response": "…" },
                "from_cache": false
            }
        ]
    },
    "performance": {
        "total_time": "3.31s",
        "timings": [
            { "task": "threat_feeds_check", "time": "1.86s" },
            { "task": "whois_lookup", "time": "921.91ms" },
            { "task": "typosquat_check", "time": "126.58ms" },
            { "task": "http_combined_check", "time": "87.57ms" },
            { "task": "tls_combined_check", "time": "84.50ms" }
        ]
    },
    "result": {
        "risk_score": 5,
        "trust_score": 100,
        "final_score": 98,
        "verdict": "Safe",
        "reasons": {
            "neutral_reasons": [
                "Standard, officially recognized domain extension.",
                "No email server configured for this domain."
            ],
            "good_reasons": [
                "Global Giant: Ranked #171 worldwide.",
                "Long-standing domain history (31 years 1 month).",
                "Domain expiry within expires in 10 months (moderate coverage).",
                "Advanced DNS security enabled (DNSSEC)."
            ],
            "bad_reasons": []
        }
    },
    "incomplete": false,
    "errors": []
}
```

> **Note on `phishing.in_database: true`:** example.com appears in the PhishTank database but with `valid: false` and `verified: false` — an unverified community submission. The scorer only counts PhishTank entries that are both valid and verified (or at least valid), so this does not affect the verdict. This is a good example of why consumers should read the reasons instead of reacting to a single flag.

## A Risky verdict (real output, `result` section)

`SafeSurf::analyze('https://kua.lat')` (a URL shortener on a risky TLD serving a hidden iframe):

```json
{
    "result": {
        "risk_score": 95,
        "trust_score": 43,
        "final_score": 24,
        "verdict": "Risky",
        "reasons": {
            "neutral_reasons": ["Operational for 1 year 7 months."],
            "good_reasons": [
                "Enforces strict HTTPS security (HSTS Enabled).",
                "Domain expiry within expires in 4 months (moderate coverage).",
                "Advanced DNS security enabled (DNSSEC)."
            ],
            "bad_reasons": [
                "Very low traffic volume.",
                "High-risk domain extension detected (often associated with spam).",
                "URL Shortener detected (hides the true destination).",
                "WARNING: Hidden iframe detected (often used for background credential theft or clickjacking)."
            ]
        }
    }
}
```
