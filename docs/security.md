# Security

SafeSurf is a scanner: it fetches attacker-influenced URLs and follows redirects chosen by remote servers. Its fetch pipeline is designed so that analyzing a malicious URL cannot turn the scanner into a tool for attacking your own network (SSRF), nor into a download amplifier.

## The safe fetch pipeline

Every check that needs HTTP goes through `SafeSurf\Util\HttpClient::request()`, which enforces, in order:

1. **Scheme whitelist** — only `http` and `https` are ever fetched, no matter what the original input or a redirect claims. Anything else returns `blocked_scheme`.
2. **DNS resolution first** — the host is resolved to a public IP *before* connecting (`resolveFirstPublicIp()`).
3. **Private-range rejection** — resolved IPs are checked against private, loopback, link-local (including the cloud metadata endpoint 169.254.169.254), CGNAT, benchmark, multicast, and reserved ranges. IPv6 is checked natively (unique-local, link-local, loopback) **and** in its IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible forms, which are re-validated as the embedded IPv4 address. A literal IP in the URL goes through the same check.
4. **IP pinning** — the resolved IP is forced onto the connection with `CURLOPT_RESOLVE` (`host:port:ip`). This defeats DNS rebinding: a second, malicious DNS answer between validation and connection cannot redirect the request to an internal host.
5. **No curl redirects** — `CURLOPT_FOLLOWLOCATION` is always off. Redirects are followed manually by the caller (HTTP check, root-domain correlation): every hop is a fresh request that re-runs validation from step 1.
6. **Body size cap** — a `CURLOPT_WRITEFUNCTION` accumulates the body and aborts the transfer once `Config::$maxBodyBytes` (default 5 MiB) is exceeded; the partial body is kept and the write-error code (23) is not treated as a transport failure.
7. **Timeouts** — per-request (`httpTimeoutMs`) and connect (`httpHeaderTimeoutMs`) timeouts bound every request.

The TLS check (`TlsCombined`) pins its `ssl://` probe to the pre-resolved public IP as well, so certificate inspection cannot be aimed at an internal host either.

## Exceptions to `HttpClient` (and why they are safe)

| Component | Destination | Why it is safe |
| --- | --- | --- |
| `DomainInfo` (RDAP) | IANA bootstrap (`data.iana.org`) + registry RDAP servers, followed with `CURLOPT_FOLLOWLOCATION` | Fixed, registry-operated infrastructure — never user input; TLS verification is on |
| `PhishTank` | `checkurl.phishtank.com` (fixed URL) | Fixed trusted target |
| DNS-based feed plugins | Raw UDP DNS (`SafeSurf\Util\DnsQuery`) to fixed, operator-configured resolver IPs | Resolver IPs come from the plugin's own configuration, never from user input; must be public IPs; bounded timeout and response size |

Do not add new network calls that bypass these rules: anything fetching user-influenced URLs must go through `HttpClient`, and any fixed-target client must keep its target out of user control.

## Handling hostile content

- HTML parsing uses `DOMDocument` with `LIBXML_NOERROR | LIBXML_NOWARNING`; malformed markup cannot crash the analysis.
- Body caps (`maxBodyBytes`) and text sampling (~300 words) bound memory use.
- All check failures are caught by the `timed()` wrapper and become `errors[]` entries; the library never lets a hostile target turn into a fatal error in the caller's process.
- Results are cached **only** when complete (`incomplete: false`), so poisoned partial results do not stick.

## Operational notes

- TLS chain validation is best effort: some environments (missing CA store, corporate proxies) fail the chain check even for legitimate sites; `ssl_info.reasons` says what failed.
- `ssl_info` inspection connects with certificate *capture* disabled verification for evidence collection, then performs a second, fully verifying connection for `chain_valid` — the first connection is what allows inspecting deliberately broken certificates.
- Some modules require internet access on first use: the PSL download, IANA RDAP bootstrap, PhishTank. Offline environments should pre-seed `storage/public_suffix_list.dat` and rely on pure checks.
- Enable caching when scanning at volume — it reduces both latency and load on the third-party services.

## Responsible use

SafeSurf performs active probing (HTTP GET/HEAD, TLS handshake, DNS) of the URLs you analyze. Scan URLs you have a legitimate interest in inspecting, respect the terms of the third-party services it queries (PhishTank in particular requires a registered user agent / API key for production use), and do not use the library to attack or enumerate systems you do not own.
