# Detection Checks

`SafeSurf::analyze()` runs every check below through a timing/error wrapper: a check that throws (network down, timeout, malformed data) is captured into `errors[]` and reported as `incomplete: true` — it never aborts the analysis. Checks that hit the network go through the SSRF-safe `HttpClient` (see [Security](security.md)) and are cached with per-check TTLs.

Quick overview:

| Check | Network | Output location | Purpose |
| --- | --- | --- | --- |
| [URL structure](#url-structure-signals) | no | `features.url` | Shortener, raw IP, punycode, length/depth, subdomain count, keywords |
| [Traffic rank](#traffic-rank) | no (local CSV) | `features.rank` | Global popularity from the top-1M list |
| [TLD signals](#tld-signals) | no | `features.tld` | Trusted / risky / ICANN / hosting-platform classification |
| [Subdomain labels](#subdomain-label-signals) | no | `features.subdomain` | Sensitive labels + brand names embedded in subdomains |
| [Homoglyph / IDN spoofing](#homoglyph--idn-spoofing) | no | `homoglyph_result` | Mixed-script and fullwidth lookalike characters |
| [Domain randomness](#domain-randomness) | no | `domain_randomness` | Entropy heuristics for algorithmically generated domains |
| [Typosquatting](#typosquatting) | no (local CSV) | `typosquat_result` | Levenshtein distance 1-2 and combo-squatting vs top-5000 domains |
| [DNS signals](#dns-signals) | DNS | `infrastructure` | A/AAAA addresses, NS and MX validity |
| [HTTP analysis](#http-analysis) | HTTP | `analysis` | Redirect chain, final status, HSTS |
| [TLS / SSL](#tls--ssl) | TCP+TLS | `ssl_info`, `tls_info` | Certificate issuer, age, CT logs, chain, hostname match |
| [Content analysis](#content-analysis) | HTTP GET | `content_data` | Forms, hidden iframes, brand mismatch, favicon/meta-refresh/assets, inline-JS heuristics |
| [Root-domain correlation](#root-domain-correlation) | HTTP | `correlation` | Root vs subdomain: parked root, off-domain redirect, content similarity, infrastructure split |
| [Threat feeds](threat-feeds.md) | HTTP/DNS | `threat_feeds`, `phishing` | PhishTank, external plugins |

## URL structure signals

Pure string analysis of the normalized URL.

| Signal | Threshold | Meaning |
| --- | --- | --- |
| `url_shortener` | domain in `assets/url_shorteners.php` | Hides the real destination |
| `uses_ip` | host is a raw IPv4/IPv6 address | Legitimate sites rarely serve logins from bare IPs |
| `contains_punycode` | any `xn--` label or non-ASCII character in the host | Possible IDN spoofing (see also [Homoglyph](#homoglyph--idn-spoofing)) |
| `too_long` | URL longer than 75 characters | Long URLs hide the real host |
| `too_deep` | more than 5 `/` in the URL | Deep paths hide the real page |
| `subdomain_count` | labels before the registrable domain | More than 2 subdomains is flagged |
| `keywords` | exact word match from `assets/url_keywords.php` | Words like `login`, `verify`, `secure`, `update` split on non-alphanumerics |

Output:

```json
"keywords": { "has_keywords": false, "found": [], "categories": [] }
```

`found` lists the matched keywords; `categories` groups them by category from the data file.

## Traffic rank

`features.rank` is the domain's position in the bundled top-1M CSV (`0` = unranked). The score gives strong trust to top-10k domains and treats unranked domains as a mild negative — unless the suffix is a known hosting platform (github.io, vercel.app, …), where unranked personal/project pages are normal.

## TLD signals

`features.tld` classifies the registrable domain's public suffix using the PSL plus the static lists:

- `is_trusted_tld` — government/education style TLDs (`trusted_tlds.php`): strong trust signal.
- `is_risky_tld` — TLDs frequently abused for spam (`risky_tlds.php`): risk signal.
- `is_icann` — the suffix is an official ICANN registry suffix; non-ICANN suffixes are penalized *unless* they are a known hosting platform.
- `is_hosting_platform` — trusted PSL-private suffix (`hosting_platforms.php`). Hosting-platform subdomains suppress the unranked, missing-NS and non-ICANN penalties.

## Subdomain label signals

Analyzes only the labels between the host and the registrable domain (pure, no network):

- `sensitive_labels` — labels present in `assets/sensitive_subdomains.php` (e.g. `login`, `secure`, `verify`, `account`), mapped to a category. A signal, not a verdict.
- `brand_hits` — brand tokens (derived from `assets/brands.php`, filtered so generic SLDs like `mail` or `login` never match) found inside subdomain labels while the registrable domain is *not* official for that brand. Example: `paypal-secure.example.com` hits the `paypal` brand; `login.yahoo.com` does not (Yahoo is official there).

Generic service words (`www`, `app`, `api`, `cdn`, `docs`, …) are excluded from brand tokens so ordinary infrastructure subdomains are never flagged as impersonation.

## Homoglyph / IDN spoofing

`homoglyph_result` decodes punycode labels (`xn--…`) to Unicode and flags only genuinely deceptive combinations:

- **Mixed scripts in one domain** — Latin mixed with Cyrillic, Greek, or Armenian (e.g. a Cyrillic `а` inside `аpple.com`).
- **Fullwidth lookalikes** — characters in the U+FF01-U+FF5E range (e.g. `ｅxample.com`).

Single-script IDNs such as `münchen.de` are *not* flagged — plain punycode presence is reported separately via `features.url.contains_punycode`. Output fields: `decoded`, `mixed_scripts`, `fullwidth_chars`, `scripts`, `reasons`.

## Domain randomness

`domain_randomness` scores the SLD for algorithmically generated (DGA-like) names: Shannon entropy, normalized entropy, vowel/digit/unique-character ratios, longest consonant-or-digit run, and English bigram frequency. `is_suspicious` turns on when the composite randomness score exceeds ~0.50 (short labels get a raised threshold), a run is >= 6, or digits dominate.

This field is **informational**: the scorer does not consume it, because randomness alone produces too many false positives for brandable names.

## Typosquatting

`typosquat_result` compares the input SLD (minimum length 4) against the top-5000 domains from the ranking CSV:

- **Typosquatting** — Levenshtein distance 1-2 from a top-domain SLD (e.g. `gooogle.com` vs `google`).
- **Combo-squatting** — the input SLD *contains* a top-brand SLD of length >= 6 (e.g. `secure-paypal-login.com`).

Output: `is_suspicious`, `matched_domain`, `matched_brand`, `distance`, `is_combo_squat`.

## DNS signals

`infrastructure` gathers:

- `ip_addresses` — A and AAAA records of the registrable domain.
- `nameservers_valid` / `ns_hosts` — NS records exist and at least one nameserver resolves. Missing NS is penalized except on hosting platforms (they run the whole zone).
- `mx_records_valid` / `mx_hosts` — MX records exist and at least one exchange resolves. Missing MX is a weak signal (many fine sites receive no mail).

## HTTP analysis

`analysis` follows the redirect chain **hop by hop** (HEAD first, GET fallback per hop; every hop is re-validated by `HttpClient` — curl itself never follows redirects):

```json
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
```

`has_domain_jump` is true when any hop leaves the original registrable domain — a classic bait-and-switch pattern. If the target itself does not send `Strict-Transport-Security`, the root domain is probed over HTTPS as a fallback before reporting `is_hsts_supported`.

## TLS / SSL

`ssl_info` (detailed) and `tls_info` (summary) come from a raw `ssl://` probe pinned to a pre-resolved public IP of the domain:

| Field | Meaning |
| --- | --- |
| `has_tls` / `present` | A TLS session was established on port 443 |
| `issuer` | Certificate issuer organization or CN |
| `not_before`, `not_after`, `age_days` | Validity window |
| `chain_valid` | Full verification (trusted CA + hostname) succeeded in a second connection |
| `hostname_mismatch` | Certificate does not match the domain |
| `ct_logged` | Certificate carries a Certificate Transparency timestamp |
| `is_suspicious` / `reasons` | Expired, not-yet-valid, > 398-day validity, missing CT, blacklisted fingerprint |

## Content analysis

`content_data` is produced by fetching the page (body capped at `maxBodyBytes`) and parsing it with DOMDocument. The parser itself (`Content::analyzeHtml()`) is pure and testable with fixture HTML.

| Field | Meaning |
| --- | --- |
| `title`, `text_sample` | Page title and first ~300 words of visible text (used for brand checks and root similarity) |
| `forms[]` | Per form: `action`, `method`, input summaries, `has_password`, `has_user_like`, `has_payment`, `has_personal`, `is_external` (action leaves the host), `is_hidden` |
| `has_login_form` / `has_payment_form` / `has_personal_form` | Aggregated form signals |
| `iframes[]`, `has_hidden_iframe` | Zero-size / `display:none` / `visibility:hidden` / `opacity:0` iframes |
| `has_tracking` | 1x1 or 0x0 tracking pixels |
| `brand_check` | Brand found in the title/body vs official domains: `brand_found`, `is_mismatch`, `detected_names` |
| `favicon` | `href`, `is_external`, `external_host`, `brand_domain`, `brand_mismatch` |
| `phishing_patterns` | See below |

`phishing_patterns` collects the page-level phishing tells:

- `favicon_external`, `favicon_brand_mismatch` — favicon hotlinked from another host, especially from a brand's official domain on an unrelated page (site-clone indicator).
- `meta_refresh` / `meta_refresh_external` — `<meta http-equiv="refresh">` redirecting off-domain.
- `external_asset_hosts`, `external_asset_count` — scripts/links/images loaded from other hosts (up to 10 hosts listed).
- `brand_names_in_text`, `login_with_brand_text` — brand names mentioned in the text on an unofficial domain, combined with a login form (credential-harvesting pattern).
- `js_signals` — inline `<script>` heuristics (see below).

### JavaScript signals (`js_signals`)

Static heuristics over inline script bodies — conservative by design, each hit is a weak signal:

| Field | Detects |
| --- | --- |
| `has_eval_atob` | `eval(atob(...))` decoder pattern |
| `has_obfuscation` | Packer-style obfuscation: `unescape()` write, `String.fromCharCode` + eval, long hex/`%u` escape runs, large encoded blobs |
| `has_form_injection` | Script writes a `<form>`/password input into the DOM |
| `has_js_redirect` | Hard `location` assignment to an absolute URL |
| `disables_context_menu` | Right-click / devtools / F12 blocking |
| `has_crypto_wallet_hooks` | `ethereum.request`, `signTransaction`, `eth_sendTransaction` |
| `suspicious_score` | 0.0-1.0 weighted combination of the above |

## Root-domain correlation

Only runs for subdomain hosts (e.g. `secure.shop.example.com`), never for root domains or raw IPs, and only when `enableRootDomainCorrelation` is on.

1. `fetchRootData()` fetches the root domain (following up to `rootCorrelationMaxHops` redirects, one plain-HTTP retry) and extracts title, text sample, parked-page markers ("domain for sale", "welcome to nginx", …).
2. `correlate()` (pure) combines the root facts with the subdomain page and IP sets:

| Field | Meaning |
| --- | --- |
| `root.reachable`, `root.is_active` | Root answered with real content (not parked/empty) |
| `root.is_parked_or_empty` | Placeholder/default-server page |
| `root.redirects_off_domain`, `root.final_domain` | Root redirects away to another registrable domain |
| `shared_infrastructure` | `same_ip` / `same_network` (shared /24 IPv4 or /48 IPv6) / `different` / `unknown` |
| `content_similarity` | Jaccard similarity over 3-word shingles of both text samples (0.0-1.0) |
| `content_relation` | `same` (>= 0.6) / `partial` (>= 0.25) / `divergent` / `unknown` |
| `signals` | Boolean summary: `root_unreachable`, `root_inactive`, `root_parked_or_empty`, `root_redirects_off_domain`, `infrastructure_split`, `content_divergent` |

Every correlation finding is a *signal* only — the scorer combines them with rank, domain age, and login-form detection into [combo signals](scoring.md#combo-signals); an inactive root or split infrastructure alone stays neutral.

## Threat feeds

PhishTank and external plugin feeds are documented in [Threat Feeds](threat-feeds.md). The PhishTank result is additionally exposed under the legacy `phishing` field.
