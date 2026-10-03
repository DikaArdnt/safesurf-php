<?php

declare(strict_types=1);

namespace SafeSurf\Analyzer;

use SafeSurf\Checks\Content;
use SafeSurf\Checks\DnsSignals;
use SafeSurf\Checks\Entropy;
use SafeSurf\Checks\Homoglyph;
use SafeSurf\Checks\HttpCombined;
use SafeSurf\Checks\RootDomainCorrelation;
use SafeSurf\Checks\SubdomainSignals;
use SafeSurf\Checks\TldSignals;
use SafeSurf\Checks\TlsCombined;
use SafeSurf\Checks\UrlSignals;
use SafeSurf\Config;
use SafeSurf\Service\DomainInfo;
use SafeSurf\Service\Rank;
use SafeSurf\Service\ThreatFeeds\FeedRunner;
use SafeSurf\Service\Typosquat;
use SafeSurf\Util\DomainUtil;

final class Analyzer
{
    public static function analyze(string $rawUrl, ?Config $config = null): array
    {
        $config ??= new Config();
        $t0 = microtime(true);

        $normalized = DomainUtil::normalizeUrl($rawUrl);
        if ($normalized === null) {
            return ['error' => 'invalid_url'];
        }

        try {
            $domain = DomainUtil::registrableDomainFromUrl($normalized, $config->publicSuffixListPath);
        } catch (\Throwable) {
            $domain = null;
        }

        if ($domain === null || $domain === '') {
            return ['error' => 'invalid_domain'];
        }

        // The enabled-flags fingerprint is part of the cache key so toggling
        // features never serves a result produced under a different feature set.
        $flagSet = implode(',', [
            (int) $config->enableRank,
            (int) $config->enableDns,
            (int) $config->enableHttp,
            (int) $config->enableTls,
            (int) $config->enableContent,
            (int) $config->enableWhois,
            (int) $config->enableThreatFeeds,
            (int) $config->enableRootDomainCorrelation,
        ]);
        $resultKey = "analyze_result:$normalized:$flagSet";
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($resultKey);
            if (is_array($cached)) {
                $cached['performance']['total_time'] = self::formatDuration(microtime(true) - $t0);
                return $cached;
            }
        }

        $timings = [];
        $errors = [];

        $rank = $config->enableRank ? self::timed('domain_rank', $timings, fn() => self::cached("domain_rank:$domain", $config->ttlDomainRankSeconds, $config, fn() => Rank::lookup($domain, $config)), $errors) : null;

        $http = $config->enableHttp ? self::timed('http_combined_check', $timings, fn() => self::cached("http_combined:$normalized", $config->ttlHttpCombinedSeconds, $config, fn() => HttpCombined::check($normalized, $config)), $errors) : null;

        $usesIp = self::timed('ip_check', $timings, fn() => UrlSignals::usesIp($normalized), $errors);

        $ips = $config->enableDns ? self::timed('ip_resolution', $timings, fn() => self::cached("ip_resolution:$domain", $config->ttlIpResolutionSeconds, $config, fn() => DnsSignals::ipAddresses($domain)), $errors) : null;

        $puny = self::timed('punycode_check', $timings, fn() => UrlSignals::containsPunycode($normalized), $errors);

        $tld = self::timed('tld_check', $timings, fn() => TldSignals::info($domain, $config), $errors);

        $isShortener = self::timed('shortener_check', $timings, fn() => UrlSignals::isUrlShortener($domain), $errors);

        $tooLong = self::timed('url_structure_check', $timings, fn() => UrlSignals::tooLong($normalized), $errors);
        $tooDeep = self::timed('url_structure_check_2', $timings, fn() => UrlSignals::tooDeep($normalized), $errors);

        $kw = self::timed('keywords_check', $timings, fn() => UrlSignals::keywordMatches($normalized), $errors);

        $dns = $config->enableDns ? self::timed('dns_validity_check', $timings, fn() => self::cached("dns_validity:$domain", $config->ttlDnsValiditySeconds, $config, function () use ($domain) {
            $ns = DnsSignals::nsValidity($domain);
            $mx = DnsSignals::mxValidity($domain);
            return [
                'ns_valid' => (bool) $ns['valid'],
                'ns_hosts' => $ns['hosts'],
                'mx_valid' => (bool) $mx['valid'],
                'mx_hosts' => $mx['hosts'],
            ];
        }), $errors) : null;

        $subCount = self::timed('subdomain_check', $timings, fn() => UrlSignals::subdomainCount($normalized, $config), $errors);

        $subdomainSignals = self::timed('subdomain_signals_check', $timings, fn() => SubdomainSignals::analyze($normalized, $domain, $config), $errors);

        $domainInfo = $config->enableWhois ? self::timed('whois_lookup', $timings, fn() => DomainInfo::lookup($domain, $config), $errors) : null;

        $tlsCombined = $config->enableTls ? self::timed('tls_combined_check', $timings, fn() => self::cached("tls_combined:$domain", $config->ttlTlsCombinedSeconds, $config, fn() => TlsCombined::check($domain)), $errors) : null;

        $entropy = self::timed('entropy_check', $timings, fn() => Entropy::analyzeDomainRandomness($domain), $errors);

        $content = $config->enableContent ? self::timed('content_check', $timings, fn() => self::cached("content_check:$normalized", $config->ttlContentSeconds, $config, fn() => Content::analyze($normalized, $config)), $errors) : null;

        $homoglyph = self::timed('homoglyph_check', $timings, fn() => Homoglyph::analyze($domain), $errors);

        $host = DomainUtil::hostFromUrl($normalized) ?? '';
        $correlation = null;
        $rootData = null;
        $isSubdomainHost = $host !== '' && $host !== $domain && !filter_var($host, FILTER_VALIDATE_IP);
        if ($isSubdomainHost && $config->enableRootDomainCorrelation) {
            $rootData = self::timed('root_domain_correlation', $timings, fn() => self::cached("root_correlation:$domain", $config->ttlRootDomainCorrelationSeconds, $config, fn() => RootDomainCorrelation::fetchRootData($domain, $config)), $errors);
        }

        if ($isSubdomainHost) {
            $subIps = $config->enableDns ? self::timed('subdomain_ip_resolution', $timings, fn() => self::cached("ip_resolution:$host", $config->ttlIpResolutionSeconds, $config, fn() => DnsSignals::ipAddresses($host)), $errors) : null;
            $correlation = RootDomainCorrelation::correlate(
                is_array($rootData) ? $rootData : null,
                is_array($content) ? $content : null,
                is_array($subIps) ? array_values($subIps) : [],
                is_array($ips) ? array_values($ips) : []
            );
        }

        $threatFeeds = $config->enableThreatFeeds ? self::timed('threat_feeds_check', $timings, fn() => FeedRunner::run($normalized, $config), $errors) : null;

        // Preserve the legacy 'phishing' field (PhishTank result shape).
        $phish = null;
        foreach (is_array($threatFeeds) ? ($threatFeeds['results'] ?? []) : [] as $tf) {
            if (is_array($tf) && ($tf['feed'] ?? '') === 'phishtank' && ($tf['checked'] ?? false)) {
                $phish = $tf['detail'];
                break;
            }
        }

        $typo = self::timed('typosquat_check', $timings, fn() => Typosquat::check($domain, $config), $errors);

        $timingsList = self::timingsToList($timings);
        $resp = [
            'url' => $normalized,
            'domain' => $domain,
            'features' => [
                'rank' => $rank !== null ? (int) $rank : null,
                'tld' => [
                    'tld' => (string) ($tld['tld'] ?? ''),
                    'is_trusted_tld' => !empty($tld['trusted']),
                    'is_risky_tld' => !empty($tld['risky']),
                    'is_icann' => !empty($tld['icann']),
                    'is_hosting_platform' => !empty($tld['hosting_platform']),
                ],
                'url' => [
                    'url_shortener' => (bool) $isShortener,
                    'uses_ip' => (bool) $usesIp,
                    'contains_punycode' => (bool) $puny,
                    'too_long' => (bool) $tooLong,
                    'too_deep' => (bool) $tooDeep,
                    'has_homoglyph' => (bool) ($homoglyph['has_homoglyph'] ?? false),
                    'subdomain_count' => (int) $subCount,
                    'keywords' => [
                        'has_keywords' => (bool) ($kw['present'] ?? false),
                        'found' => $kw['matches'] ?? [],
                        'categories' => $kw['categories'] ?? [],
                    ],
                ],
                'subdomain' => is_array($subdomainSignals) ? $subdomainSignals : [],
            ],
            'infrastructure' => [
                'ip_addresses' => is_array($ips) ? array_values($ips) : [],
                'nameservers_valid' => $dns['ns_valid'] ?? null,
                'ns_hosts' => $dns['ns_hosts'] ?? [],
                'mx_records_valid' => $dns['mx_valid'] ?? null,
                'mx_hosts' => $dns['mx_hosts'] ?? [],
            ],
            'domain_info' => $domainInfo,
            'analysis' => [
                'redirection_result' => $http['redirection_result'] ?? [
                    'is_redirected' => false,
                    'chain_length' => 1,
                    'chain' => [$normalized],
                    'final_url' => $normalized,
                    'final_url_domain' => DomainUtil::hostFromUrl($normalized) ?? '',
                    'has_domain_jump' => false,
                ],
                'http_status' => [
                    'code' => (int) ($http['status_code'] ?? 0),
                    'text' => (string) ($http['status_text'] ?? ''),
                    'success' => (bool) ($http['status_success'] ?? false),
                    'is_redirect' => (bool) ($http['status_is_redirect'] ?? false),
                ],
                'is_hsts_supported' => (bool) ($http['supports_hsts'] ?? false),
            ],
            'ssl_info' => $tlsCombined['ssl_info'] ?? null,
            'tls_info' => $tlsCombined['tls_info'] ?? null,
            'content_data' => $content,
            'domain_randomness' => $entropy,
            'homoglyph_result' => is_array($homoglyph) ? $homoglyph : null,
            'correlation' => $correlation,
            'typosquat_result' => $typo,
            'phishing' => $phish,
            'threat_feeds' => $threatFeeds,
            'performance' => [
                'total_time' => self::formatDuration(microtime(true) - $t0),
                'timings' => $timingsList,
            ],
            'result' => [],
            'incomplete' => count($errors) > 0,
            'errors' => array_values($errors),
        ];

        $resp['result'] = ResultScorer::generate($resp);

        if ($config->cache !== null && empty($resp['incomplete'])) {
            $config->cache->setJson($resultKey, $resp, $config->ttlAnalyzeResultSeconds);
        }

        return $resp;
    }

    private static function cached(string $key, int $ttlSeconds, Config $config, callable $fetch): mixed
    {
        if ($config->cache === null) {
            return $fetch();
        }
        $cached = $config->cache->getJson($key);
        if ($cached !== null) {
            return $cached;
        }
        $val = $fetch();
        if ($val !== null) {
            $config->cache->setJson($key, $val, $ttlSeconds);
        }
        return $val;
    }

    private static function timed(string $name, array &$timings, callable $fn, array &$errors): mixed
    {
        $t0 = microtime(true);
        try {
            $val = $fn();
        } catch (\Throwable $e) {
            $errors[] = "$name: " . $e->getMessage();
            $val = null;
        }
        $timings[$name] = microtime(true) - $t0;
        return $val;
    }

    private static function timingsToList(array $timings): array
    {
        $list = [];
        foreach ($timings as $task => $seconds) {
            $list[] = ['task' => (string) $task, 'time' => self::formatDuration((float) $seconds), 'dur' => (float) $seconds];
        }
        usort($list, fn($a, $b) => ($b['dur'] <=> $a['dur']));
        foreach ($list as &$row) {
            unset($row['dur']);
        }
        return $list;
    }

    private static function formatDuration(float $seconds): string
    {
        if ($seconds >= 1.0) {
            return sprintf('%.2fs', $seconds);
        }
        return sprintf('%.2fms', $seconds * 1000.0);
    }
}
