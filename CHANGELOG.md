# Changelog

All notable changes to `SafeSurf` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-10-16

### Added

- **Urlvet Alignment & Asset Porting**:
  - Added customer site platform registry (`customer_site_hosts.php`) supporting website builders (Weebly, Wix, GoDaddy Sites, Carrd, Webflow, Blogger ccTLDs, etc.).
  - Added provider subdomains dataset (`provider_subdomains.php`) to distinguish operator endpoints from user sites.
  - Added IP hostname services dataset (`ip_hostname_services.php`) detecting wildcard DNS-to-IP services (`sslip.io`, `nip.io`, `traefik.me`, `cprapid.com`, `plesk.page`).
  - Added user upload and provider service hosts (`user_upload_hosts.php`, `provider_service_hosts.php`).
  - Added link-in-bio user page hosts (`user_page_hosts.php`).
  - Added path-based short links dataset (`short_link_paths.php`).
  - Added marketing form endpoints list (`marketing_form_hosts.php`) for Mailchimp, HubSpot, Klaviyo, Brevo, and ConvertKit.
  - Added dynamic DNS provider registry (`ddns_providers.php`).
- **Enhanced Detection Capabilities**:
  - Added URL parts typosquatting & combo-squatting analysis (`embedded_domain`, `subdomain_brand`, `path_brand`).
  - Added `genericBrandNames` filter in `Typosquat` to eliminate false-positive combo-squats on common vocabulary words (e.g., "crypto", "united", "global", "online", "booking").
  - Added multi-step login intent heuristics (`looksLikeLoginText`) checking for submit labels such as "Next", "Continue", "Verify", and "Sign in".
  - Added marketing form service action exemption in `Content::analyzeHtml()`, preventing newsletter subscriptions from being penalized as suspicious external form submissions.
  - Added provider block detection (Cloudflare takedowns, HTTP 451, legal blocks) and inline script redirect forensics (`detectScriptRedirect`).
  - Added executable extension detection on user upload hosts (`downloadedProgram`).
  - Added email address in query/fragment detection (`victimAddressInLink`).
  - Added fake crypto trading platform title template detection (`tradingScamTitle`).
  - Added WordPress system page path heuristics (`isWordPressSystemPage`).
- **Exceptions & False-Positive Suppression System (`applyExceptions`)**:
  - Implemented centralized exception engine in `Analyzer::applyExceptions()` aligned with `urlvet`.
  - Added bare URL exemption for URL shorteners and provider service endpoints (e.g. `https://storage.googleapis.com/` homepage vs bucket path).
  - Added brand title contextualization (`Brand::withoutOwnAddress()`), preventing default platform hostnames (e.g. `octocat.github.io`) from falsely claiming the provider's brand.
  - Added populated `official_domain` in brand mismatch results.
  - Added legitimate cross-domain redirection exemptions for vouched/top-ranked destinations and same-brand domain jumps (e.g. `wa.me` -> `api.whatsapp.com`, Blogger ccTLD shifts).
  - Added top-ranked domain exemptions suppressing risky TLD, excessive depth/length, and security keyword penalties on globally trusted sites.
- **Unit Tests & Quality Tooling**:
  - Added unit test cases for `customerSitePlatform`, `ipHostname`, `isBareUrl`, and `userContentHost` in `tests/DomainUtilTest.php`.

### Changed

- **Fixed Traffic Rank Trust Score Inversion**:
  - Corrected Tranco top-1M rank trust scoring: Top 10,000 gives `+90`, Top 50,000 gives `+50`, and Top 1,000,000 gives `+20`.
- **Refined Credential Form Detection**:
  - Standalone email or username inputs no longer trigger `has_login_form` unless accompanied by active login intent or an explicit password field.
- **RDAP / WHOIS Isolation for Hosted Sites**:
  - `DomainInfo::lookup()` skips WHOIS/RDAP queries on customer site builders so new phishing pages cannot falsely inherit the platform domain's multi-year registration age.
- **Refined TLS Hostname Mismatch Scoring**:
  - Standardized TLS hostname mismatch risk weight to `+25` points.

### Security

- **XXE (XML External Entity) Hardening**:
  - Added `LIBXML_NONET` to all `DOMDocument::loadHTML()` calls in `Content.php` and `RootDomainCorrelation.php` to prevent external entity resolution and local file disclosure via PHP stream wrappers.
- **cURL Protocol Restriction**:
  - Enforced `CURLOPT_PROTOCOLS` restricted strictly to `CURLPROTO_HTTP | CURLPROTO_HTTPS`, blocking `file://`, `gopher://`, `phar://`, and other alternative transport handlers.
- **SSRF & IP Evasion Protection**:
  - Enhanced IP validation in `HttpClient` and `DnsQuery` to reject IPv4-compatible IPv6 addresses, RFC 5737/7526 benchmark blocks, and cloud metadata endpoints (`169.254.169.254`).
- **CRLF & Null Byte Injection Prevention**:
  - `DomainUtil::normalizeUrl()` rejects URLs containing control characters (`\r`, `\n`, `\0`), preventing HTTP response splitting and header injection.

---

## [2.0.0] - 2026-10-01

### Added

- Added a pluggable threat-feed system through:
  - `ThreatFeedInterface`
  - `FeedRunner`
  - `ThreatFeeds`
  - `Config::addThreatFeed()`
- Added support for external threat-feed plugins.
- Added per-feed configuration options and TTL overrides.
- Added feed result metadata, including descriptions and categories extracted from feed PHPDoc.
- Added sensitive subdomain detection for labels such as `login`, `secure`, and `verify`.
- Added brand impersonation detection in subdomains.
- Added inline JavaScript heuristics for:
  - Obfuscation using `eval`, `atob`, `unescape`, and hexadecimal patterns
  - Form injection
  - JavaScript redirects
  - Cryptocurrency wallet hooks
- Added root-domain and subdomain correlation checks:
  - Parked or inactive root domains
  - Off-domain redirects
  - Content similarity using shingle-based Jaccard comparison
  - Shared IPv4 `/24` and IPv6 `/48` infrastructure
- Added improved homoglyph and IDN spoofing detection:
  - Punycode decoding
  - Mixed Latin, Cyrillic, Greek, and Armenian script detection
  - Fullwidth character detection
- Added external favicon and brand-mismatch favicon detection.
- Added external meta-refresh detection.
- Added external asset-host analysis.
- Added brand-text analysis around login forms.
- Added `DnsQuery`, a minimal UDP DNS client for fixed, operator-configured resolvers.
- Added unit tests covering pure detection checks.
- Added Rector tooling (`composer rector`, `composer rector:dry-run`).
- Added comprehensive documentation in the `docs/` directory.
- Added `AGENTS.md` with repository guidance for contributors and coding agents.

### Changed

- Expanded `ResultScorer` to include:
  - Threat-feed severity
  - Suspicious TLS configuration
  - TLS hostname mismatches
  - Problematic domain registry statuses
  - Root-domain and subdomain correlation signals
- Updated scoring behavior so that a single weak signal cannot produce a `Risky` verdict by itself.
- Improved homoglyph detection to avoid flagging legitimate single-script internationalized domain names.
- Improved content analysis for phishing-related HTML patterns.
- Updated the top one million domain ranking dataset.
- Updated the README with the complete feature set, configuration options, security notes, and usage examples.
- Refined threat-feed configuration with fluent setup methods and per-feed options.

### Security

- Added HTTP and HTTPS scheme validation before DNS resolution.
- Improved SSRF protection for IPv4-mapped IPv6 and IPv4-compatible IPv6 addresses.
- Added strict HTTP response body-size enforcement using `CURLOPT_WRITEFUNCTION`.
- Improved handling of intentionally truncated response bodies.
- Pinned TLS probes to the already validated resolved IP address.
- Reduced the risk of DNS rebinding between DNS resolution and TLS connection establishment.

---

## [1.0.0] - 2026-04-28

### Added

- Initial release of SafeSurf for PHP.
- Real-time URL analysis (redirect chains, HTTP status, HSTS enforcement).
- Domain & DNS signals (top-1M rank, IP resolution, NS/MX record validity).
- URL signals (keywords, shorteners, length/depth thresholds, subdomain count, punycode).
- TLS/SSL checks (presence, issuer, certificate age, chain validation).
- Page content inspection (titles, form inspection, hidden iframes, brand mismatch).
- Built-in PhishTank threat feed support.
- Caching adapter via `phpfastcache` for fast lookups.
- Configurable scoring with plain-English reasons and Safe / Suspicious / Risky verdicts.
