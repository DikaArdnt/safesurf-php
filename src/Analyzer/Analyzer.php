<?php

declare(strict_types=1);

namespace SafeSurf\Analyzer;

use SafeSurf\Checks\Content;
use SafeSurf\Checks\DnsSignals;
use SafeSurf\Checks\Entropy;
use SafeSurf\Checks\Homoglyph;
use SafeSurf\Checks\HttpCombined;
use SafeSurf\Checks\TldSignals;
use SafeSurf\Checks\TlsCombined;
use SafeSurf\Checks\UrlSignals;
use SafeSurf\Config;
use SafeSurf\Service\DomainInfo;
use SafeSurf\Service\Rank;
use SafeSurf\Service\ThreatFeeds\PhishTank;
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

        $resultKey = "analyze_result:$normalized";
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($resultKey);
            if (is_array($cached)) {
                $cached['performance']['total_time'] = self::formatDuration(microtime(true) - $t0);
                return $cached;
            }
        }

        $timings = [];
        $errors = [];

        $rank = self::timed('domain_rank', $timings, function () use ($domain, $config) {
            return self::cached("domain_rank:$domain", $config->ttlDomainRankSeconds, $config, fn () => Rank::lookup($domain, $config));
        }, $errors);

        $http = self::timed('http_combined_check', $timings, function () use ($normalized, $config) {
            return self::cached("http_combined:$normalized", $config->ttlHttpCombinedSeconds, $config, fn () => HttpCombined::check($normalized, $config));
        }, $errors);

        $usesIp = self::timed('ip_check', $timings, fn () => UrlSignals::usesIp($normalized), $errors);

        $ips = self::timed('ip_resolution', $timings, function () use ($domain, $config) {
            return self::cached("ip_resolution:$domain", $config->ttlIpResolutionSeconds, $config, fn () => DnsSignals::ipAddresses($domain));
        }, $errors);

        $puny = self::timed('punycode_check', $timings, fn () => UrlSignals::containsPunycode($normalized), $errors);

        $tld = self::timed('tld_check', $timings, fn () => TldSignals::info($domain, $config), $errors);

        $isShortener = self::timed('shortener_check', $timings, fn () => UrlSignals::isUrlShortener($domain), $errors);

        $tooLong = self::timed('url_structure_check', $timings, fn () => UrlSignals::tooLong($normalized), $errors);
        $tooDeep = self::timed('url_structure_check_2', $timings, fn () => UrlSignals::tooDeep($normalized), $errors);

        $kw = self::timed('keywords_check', $timings, fn () => UrlSignals::keywordMatches($normalized), $errors);

        $dns = self::timed('dns_validity_check', $timings, function () use ($domain, $config) {
            return self::cached("dns_validity:$domain", $config->ttlDnsValiditySeconds, $config, function () use ($domain) {
                $ns = DnsSignals::nsValidity($domain);
                $mx = DnsSignals::mxValidity($domain);
                return [
                    'ns_valid' => (bool) $ns['valid'],
                    'ns_hosts' => $ns['hosts'],
                    'mx_valid' => (bool) $mx['valid'],
                    'mx_hosts' => $mx['hosts'],
                ];
            });
        }, $errors);

        $subCount = self::timed('subdomain_check', $timings, fn () => UrlSignals::subdomainCount($normalized, $config), $errors);

        $domainInfo = self::timed('whois_lookup', $timings, function () use ($domain, $config) {
            return DomainInfo::lookup($domain, $config);
        }, $errors);

        $tlsCombined = self::timed('tls_combined_check', $timings, function () use ($domain, $config) {
            return self::cached("tls_combined:$domain", $config->ttlTlsCombinedSeconds, $config, fn () => TlsCombined::check($domain));
        }, $errors);

        $entropy = self::timed('entropy_check', $timings, fn () => Entropy::analyzeDomainRandomness($domain), $errors);

        $content = self::timed('content_check', $timings, function () use ($normalized, $config) {
            return self::cached("content_check:$normalized", $config->ttlContentSeconds, $config, fn () => Content::analyze($normalized, $config));
        }, $errors);

        $homoglyph = self::timed('homoglyph_check', $timings, fn () => Homoglyph::hasHomoglyphs($domain), $errors);

        $phish = self::timed('phishtank_check', $timings, function () use ($normalized, $config) {
            $cacheKey = "phishtank:$normalized";
            if ($config->cache !== null) {
                $cached = $config->cache->getJson($cacheKey);
                if (is_array($cached)) {
                    $cached['from_cache'] = true;
                    return $cached;
                }
            }
            $val = PhishTank::check($normalized, $config);
            if (is_array($val) && $config->cache !== null) {
                $config->cache->setJson($cacheKey, $val, $config->ttlPhishTankSeconds);
            }
            return $val;
        }, $errors);

        $typo = self::timed('typosquat_check', $timings, fn () => Typosquat::check($domain, $config), $errors);

        $timingsList = self::timingsToList($timings);
        $resp = [
            'url' => $normalized,
            'domain' => $domain,
            'features' => [
                'rank' => (int) $rank,
                'tld' => [
                    'tld' => (string) ($tld['tld'] ?? ''),
                    'is_trusted_tld' => !empty($tld['trusted']),
                    'is_risky_tld' => !empty($tld['risky']),
                    'is_icann' => !empty($tld['icann']),
                ],
                'url' => [
                    'url_shortener' => (bool) $isShortener,
                    'uses_ip' => (bool) $usesIp,
                    'contains_punycode' => (bool) $puny,
                    'too_long' => (bool) $tooLong,
                    'too_deep' => (bool) $tooDeep,
                    'has_homoglyph' => (bool) $homoglyph,
                    'subdomain_count' => (int) $subCount,
                    'keywords' => [
                        'has_keywords' => (bool) ($kw['present'] ?? false),
                        'found' => $kw['matches'] ?? [],
                        'categories' => $kw['categories'] ?? [],
                    ],
                ],
            ],
            'infrastructure' => [
                'ip_addresses' => is_array($ips) ? array_values($ips) : [],
                'nameservers_valid' => (bool) ($dns['ns_valid'] ?? false),
                'ns_hosts' => $dns['ns_hosts'] ?? [],
                'mx_records_valid' => (bool) ($dns['mx_valid'] ?? false),
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
            'ssl_info' => $tlsCombined['ssl_info'] ?? [],
            'tls_info' => $tlsCombined['tls_info'] ?? [],
            'content_data' => $content,
            'domain_randomness' => $entropy,
            'typosquat_result' => $typo,
            'phishing' => $phish,
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
        usort($list, fn ($a, $b) => ($b['dur'] <=> $a['dur']));
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

