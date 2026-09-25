# Security Policy

## Supported versions

Only the latest release receives security fixes. Since this is a security-focused library, upgrade promptly when a patch is published; older branches do not get backports.

## Reporting a vulnerability

Report security issues privately by email to **[dika@kua.lat](mailto:dika@kua.lat)**.

Do not open a public GitHub issue, pull request, or discussion for something that could be exploited. Please include:

- A description of the vulnerability and the impact you believe it has.
- The affected version or commit.
- A minimal proof of concept: a URL, a code snippet, or a test that reproduces it.
- Any mitigation you have found.

You will get an acknowledgment within 72 hours. After that, we will work with you to confirm the issue, develop a fix, and agree on a disclosure date. We ask for up to 90 days before public disclosure, and we will credit you in the release notes if you want to be named.

## What counts as a vulnerability in SafeSurf

SafeSurf fetches URLs that are often attacker-controlled, so the highest-value targets are the boundaries where remote input reaches the scanner:

- **SSRF bypasses.** Any way to make the scanner connect to a private, loopback, link-local, or metadata address (for example 169.254.169.254), including through redirects, IPv4-mapped IPv6 addresses, DNS rebinding between resolution and request, or unusual URL forms that evade `Util/HttpClient.php` validation.
- **TLS validation bypasses.** Ways to make `TlsCombined` accept an invalid chain or a hostname mismatch.
- **Response parsing bugs.** Memory exhaustion or crashes through oversized bodies, deeply nested HTML, decompression bombs, or malformed DNS/RDAP/WHOIS responses.
- **Cache poisoning.** Ways to make one URL's cached analysis be returned for a different URL.
- **Injection via analyzed content.** Unsafe handling of attacker-supplied strings in results, for example when the output is embedded into HTML or logs downstream.

Scoring quality issues (a verdict that is too lenient, a false positive, a missing indicator) are not handled through this policy. Report those as regular GitHub issues, per CONTRIBUTING.md.

## Testing your report

You may test against URLs you control or public sites you have permission to test. Do not test against systems you do not own, and do not use the library against live phishing infrastructure in ways that could expose other people. If you need a controlled environment, point the scanner at a local HTTP server; note that `HttpClient` blocks private IPs by design, so set up an explicit exception in your own test harness rather than modifying the validation.

## Design notes

The fetch path is deliberately hardened (scheme whitelist, resolve-then-pin via `CURLOPT_RESOLVE`, manual redirect hops, body size limit). The design is documented in [docs/security.md](./docs/security.md). Understanding it first will make both finding and reporting issues easier.
