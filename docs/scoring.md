# Scoring & Verdicts

`ResultScorer::generate()` turns the raw features into four numbers and three lists of reasons:

```json
{
    "risk_score": 95,
    "trust_score": 43,
    "final_score": 24,
    "verdict": "Risky",
    "reasons": {
        "neutral_reasons": ["..."],
        "good_reasons": ["..."],
        "bad_reasons": ["..."]
    }
}
```

- `risk_score` (0-100) — sum of all risk weights, clamped.
- `trust_score` (0-100) — sum of all trust weights, clamped.
- `final_score` — `50 + (trust_score - risk_score) / 2`, clamped to 0-100. A page with no signals at all sits at 50.
- `verdict` — `Safe` (>= 65), `Suspicious` (30-64), `Risky` (< 30).

## Design principles

1. **One weak signal must never produce a Risky verdict on its own.** Weak indicators (keywords, sensitive subdomain labels, no MX, inactive root) are weighted small or recorded as neutral reasons.
2. **Strong indicators carry large weights**: raw IP host, punycode, homoglyph, verified PhishTank listing, password form without TLS (+100 to +200).
3. **Correlation findings are combo-only**: the classic subdomain-phishing pattern (unused root + login page on the subdomain + weak reputation) only scores when the pieces appear together.
4. **Legitimate-atypical is protected**: hosting-platform subdomains (github.io, …) are not punished for being unranked or lacking NS records; IDNs in a single script are not flagged as homoglyphs.

## Trust weights

| Signal | Weight | Reason example |
| --- | --- | --- |
| Rank 1-10,000 | +90 | "Global Giant: Ranked #171 worldwide." |
| Rank 10,001-50,000 | +50 | "Well-known website (#23450 worldwide)." |
| Rank 50,001-1,000,000 | +20 | "Low-traffic but indexed website (#120300 worldwide)." |
| Trusted TLD (gov/edu) | +100 | "High-trust official domain extension (Gov/Edu)." |
| HSTS enabled | +20 | "Enforces strict HTTPS security (HSTS Enabled)." |
| Domain age > 5 years | +25 | "Long-standing domain history (10 years)." |
| Domain age 3-5 years | +15 | "Operational for 4 years." |
| Domain age 1-3 years | +10 | "Operational for 2 years." |
| Expiry > 5 years | +25 | "Domain expiry is long-term secured." |
| Expiry 1-5 years | +15 | "Domain expiry is well-established." |
| Expiry 90 days - 1 year | +8 | "Domain expiry within 10 months (moderate coverage)." |
| DNSSEC enabled | +10 | "Advanced DNS security enabled (DNSSEC)." |
| Verified brand match on page | +20 | "Verified brand matching: GitHub" |

## Risk weights

### URL & infrastructure

| Signal | Weight |
| --- | --- |
| Raw IP address in URL | +100 |
| Wildcard IP hostname service (`nip.io`, `sslip.io`, `traefik.me`) | +100 |
| Punycode/non-ASCII host | +100 |
| Homoglyph (mixed script / fullwidth lookalikes) | +60 |
| URL shortener (redirecting to unranked destination) | +25 |
| Excessively deep path (> 5 segments) | +30 |
| URL longer than 75 characters | +20 |
| More than 2 subdomain labels | +15 |
| Security keywords in URL | +10 |
| Unranked domain (non-hosting-platform) | +10 |
| Risky TLD (on unranked / non-trusted domains) | +20 |
| Non-ICANN, non-hosting suffix | +30 |
| NS records missing/invalid (non-hosting) | +10 |
| No MX records | +5 (neutral reason) |

### Domain age & registry

| Signal | Weight |
| --- | --- |
| Domain <= 30 days old | +25 |
| Domain <= 90 days old | +15 |
| Registry status hold / pendingDelete / redemptionPeriod | +25 |

### HTTP & TLS

| Signal | Weight |
| --- | --- |
| Redirect chain longer than 3 hops | +40 |
| Cross-domain redirect (destination differs and is unvouched) | +50 |
| TLS certificate suspicious (expired, not yet valid, > 398-day validity, no CT log, blacklisted fingerprint) | +20 |
| TLS hostname mismatch | +25 |

### Page content & malware patterns

| Signal | Weight |
| --- | --- |
| Login form on a domain that is neither established nor older than 1 year | +50 |
| Fake crypto trading platform title template | +50 |
| Mail sign-in page hosted on free website builder / platform | +30 |
| Payment fields (card, CVV, …) | +30 |
| Hidden iframe | +40 |
| Form submits off-domain (non-marketing) with password/payment/personal data | +80 |
| Form submits email/username off-domain | +20 |
| Password form over plain HTTP (no TLS) | +200 |
| Brand mismatch (mentions brand X, hosted elsewhere) | +100 |
| Login form + brand names in text on an unofficial domain | +30 |
| Favicon hotlinked from a brand's official domain (with login/brand-mismatch) | +20 |
| Meta-refresh redirect off-domain | +10 |
| Script redirect sending visitors to raw IP or from user upload host | +60 (+30 if general cross-domain) |
| Provider block (Cloudflare / host takedown for phishing/malware) | +100 (+40 for generic takedown) |
| WordPress system page (`/wp-content/`, etc.) with planted login | +30 (+30 if login form) |
| Victim email address in query or hash fragment | +20 |
| Downloaded program on user upload host (e.g. GitHub releases, cloud storage) | Cap at Suspicious |
| JS injects credential form (with login form present) | +20 |
| Heavily obfuscated JS (`eval(atob())` or score >= 0.4) | +10 |
| Crypto wallet API hooks | +15 |

### Typosquatting & URL parts forensics

| Signal | Weight |
| --- | --- |
| Embedded domain (`login.paypal.com.attacker.com`) | +60 |
| Typosquatting (Levenshtein distance 1-2 from a top-5000 domain) | +40 |
| Combo-squatting on non-generic brands (`paypal-security.com`) | +20 (+40 on hosting platform) |
| Subdomain brand impersonation (`paypal.attacker.com`) | +20 to +40 |
| Path brand impersonation on unranked domain (`attacker.com/paypal/login`) | +20 (+40 if login form) |
| Brand token embedded in subdomain of an unofficial domain | +15 (+10 on hosting platforms) |

## False-positive suppression engine (`applyExceptions`)

Before generating final scores, the analyzer applies contextual exemptions to eliminate false alarms:
1. **Top-ranked domain exemptions**: Sites in the Top-1M or on trusted TLDs (.gov/.edu) are exempt from risky TLD, URL length/depth, and URL keyword penalties.
2. **Shortener bare URLs**: A bare shortener URL (`https://bit.ly/`) is its homepage, not a masked destination.
3. **Provider endpoints**: The bare address of cloud storage (`https://storage.googleapis.com/`) inherits the owning provider's rank.
4. **Legitimate domain jumps**: Redirects between domains owned by the same brand (`wa.me` -> `api.whatsapp.com`, Blogger ccTLDs, Google domains) or pointing to vouched/ranked destinations do not trigger domain jump penalties.
5. **Marketing forms**: External form submissions pointing to established marketing platforms (Mailchimp, HubSpot, Klaviyo, Brevo, ConvertKit) are exempted unless they collect passwords or payment data.
6. **Brand title context**: `Brand::withoutOwnAddress()` removes the site's own host from its title so that default hostnames like `octocat.github.io` do not claim the provider's brand.



### Threat feeds

| Signal | Weight |
| --- | --- |
| PhishTank: valid **and** verified | +200 (+ "Reported Target" reason) |
| PhishTank: valid, not yet verified | +70 |
| Other feed listed with severity `phishing` / `malware` | +70 |
| Other feed listed with severity `blocked` | +25 |
| Other feed listed with severity `unwanted` | +20 |
| Other feed listed with severity `info` | 0 |

PhishTank entries with `in_database: true` but `valid: false` (unverified, community-rejected, or pending reports) are **not** scored. The PhishTank feed itself is scored via the legacy `phishing` field; other feeds via `threat_feeds.results[]`.

## Combo signals (root-domain vs subdomain correlation)

These fire only when the individual findings **co-occur** on a subdomain host. `weakRootReputation` means unranked or <= 1 year old.

| Combination | Weight |
| --- | --- |
| Root inactive + login form on subdomain + weak reputation | +25 |
| … and root additionally parked/empty | +5 |
| Root redirects off-domain + login form on subdomain + weak reputation | +15 |
| Content divergent + login form on subdomain | +5 |

On their own, an inactive root, a parked root, split infrastructure, or divergent content each produce **neutral** reasons only.

## Worked examples

**`https://example.com`** (real output): rank 171 (+90), trusted-neutral TLD, 31 years old (+15), DNSSEC (+10), expiry < 1 year (+8), HSTS off, no forms, no bad signals → risk 5, trust 100, **final 98 → Safe**.

**`https://kua.lat`** (real output): unranked (+10), `.lat` risky TLD (+20), URL shortener (+25), hidden iframe (+40) vs some trust (HSTS +20, DNSSEC +10, moderate age/expiry) → risk 95, trust 43, **final 24 → Risky**.

Notice that neither example needed any single +100 signal — mid-weight signals accumulating is how the scale is meant to be used. A verdict of Suspicious usually means "a few mid-weight signals or one strong-but-unconfirmed signal"; check `reasons.bad_reasons` to see which.
