<?php

declare(strict_types=1);

namespace SafeSurf\Analyzer;

use SafeSurf\Checks\Brand;
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
use SafeSurf\Constants\DataFiles;
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

        $rank = self::timed('domain_rank', $timings, fn() => self::cached("domain_rank:$domain", $config->ttlDomainRankSeconds, $config, fn() => Rank::lookup($domain, $config)), $errors);

        $http = self::timed('http_combined_check', $timings, fn() => self::cached("http_combined:$normalized", $config->ttlHttpCombinedSeconds, $config, fn() => HttpCombined::check($normalized, $config)), $errors);

        $finalRedirectRank = 0;
        if (is_array($http) && !empty($http['redirection_result']['has_domain_jump'])) {
            $finalRegDomain = (string) ($http['redirection_result']['final_registrable_domain'] ?? '');
            if ($finalRegDomain !== '' && $finalRegDomain !== $domain) {
                $finalRedirectRank = self::timed('redirect_destination_rank', $timings, fn() => self::cached("domain_rank:$finalRegDomain", $config->ttlDomainRankSeconds, $config, fn() => Rank::lookup($finalRegDomain, $config)), $errors);
            }
        }
        if (is_array($http) && isset($http['redirection_result']) && is_array($http['redirection_result'])) {
            $http['redirection_result']['final_url_rank'] = (int) $finalRedirectRank;
        }

        $usesIp = self::timed('ip_check', $timings, fn() => UrlSignals::usesIp($normalized), $errors);

        $ips = self::timed('ip_resolution', $timings, fn() => self::cached("ip_resolution:$domain", $config->ttlIpResolutionSeconds, $config, fn() => DnsSignals::ipAddresses($domain)), $errors);

        $puny = self::timed('punycode_check', $timings, fn() => UrlSignals::containsPunycode($normalized), $errors);

        $tld = self::timed('tld_check', $timings, fn() => TldSignals::info($domain, $config), $errors);

        $isShortener = self::timed('shortener_check', $timings, fn() => UrlSignals::isUrlShortener($domain, $normalized), $errors);

        $tooLong = self::timed('url_structure_check', $timings, fn() => UrlSignals::tooLong($normalized), $errors);
        $tooDeep = self::timed('url_structure_check_2', $timings, fn() => UrlSignals::tooDeep($normalized), $errors);

        $kw = self::timed('keywords_check', $timings, fn() => UrlSignals::keywordMatches($normalized), $errors);

        $dns = self::timed('dns_validity_check', $timings, fn() => self::cached("dns_validity:$domain", $config->ttlDnsValiditySeconds, $config, function () use ($domain) {
            $ns = DnsSignals::nsValidity($domain);
            $mx = DnsSignals::mxValidity($domain);
            return [
                'ns_valid' => (bool) $ns['valid'],
                'ns_hosts' => $ns['hosts'],
                'mx_valid' => (bool) $mx['valid'],
                'mx_hosts' => $mx['hosts'],
            ];
        }), $errors);

        $subCount = self::timed('subdomain_check', $timings, fn() => UrlSignals::subdomainCount($normalized, $config), $errors);

        $subdomainSignals = self::timed('subdomain_signals_check', $timings, fn() => SubdomainSignals::analyze($normalized, $domain, $config), $errors);

        $domainInfo = self::timed('whois_lookup', $timings, fn() => DomainInfo::lookup($domain, $config), $errors);

        $tlsCombined = self::timed('tls_combined_check', $timings, fn() => self::cached("tls_combined:$domain", $config->ttlTlsCombinedSeconds, $config, fn() => TlsCombined::check($domain)), $errors);

        $entropy = self::timed('entropy_check', $timings, fn() => Entropy::analyzeDomainRandomness($domain), $errors);

        $content = self::timed('content_check', $timings, fn() => self::cached("content_check:$normalized", $config->ttlContentSeconds, $config, fn() => Content::analyze($normalized, $config)), $errors);

        $homoglyph = self::timed('homoglyph_check', $timings, fn() => Homoglyph::analyze($domain), $errors);

        $host = DomainUtil::hostFromUrl($normalized) ?? '';
        $correlation = null;
        $rootData = null;
        $isSubdomainHost = $host !== '' && $host !== $domain && !filter_var($host, FILTER_VALIDATE_IP);
        if ($isSubdomainHost && $config->enableRootDomainCorrelation) {
            $rootData = self::timed('root_domain_correlation', $timings, fn() => self::cached("root_correlation:$domain", $config->ttlRootDomainCorrelationSeconds, $config, fn() => RootDomainCorrelation::fetchRootData($domain, $config)), $errors);
        }

        if ($isSubdomainHost) {
            $subIps = self::timed('subdomain_ip_resolution', $timings, fn() => self::cached("ip_resolution:$host", $config->ttlIpResolutionSeconds, $config, fn() => DnsSignals::ipAddresses($host)), $errors);
            $correlation = RootDomainCorrelation::correlate(
                is_array($rootData) ? $rootData : null,
                is_array($content) ? $content : null,
                is_array($subIps) ? array_values($subIps) : [],
                is_array($ips) ? array_values($ips) : []
            );
        }

        $threatFeeds = self::timed('threat_feeds_check', $timings, fn() => FeedRunner::run($normalized, $config), $errors);

        // Preserve the legacy 'phishing' field (PhishTank result shape).
        $phish = null;
        foreach (is_array($threatFeeds) ? ($threatFeeds['results'] ?? []) : [] as $tf) {
            if (is_array($tf) && ($tf['feed'] ?? '') === 'phishtank' && ($tf['checked'] ?? false)) {
                $phish = $tf['detail'];
                break;
            }
        }

        $typo = self::timed('typosquat_check', $timings, fn() => Typosquat::check($domain, $config, $normalized), $errors);

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

        self::applyExceptions($resp, $config);

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

    private static function applyExceptions(array &$resp, Config $config): void
    {
        $rawUrl = (string) ($resp['url'] ?? '');
        $domain = (string) ($resp['domain'] ?? '');
        $host = DomainUtil::hostFromUrl($rawUrl) ?? $domain;
        $isBare = DomainUtil::isBareUrl($rawUrl);
        $rank = (int) ($resp['features']['rank'] ?? 0);
        $tld = (string) ($resp['features']['tld']['tld'] ?? '');
        $tldTrusted = !empty($resp['features']['tld']['is_trusted_tld']);
        $isHosting = !empty($resp['features']['tld']['is_hosting_platform']);

        // 1. Bare address of a provider's own endpoint takes the owning domain's rank.
        $providerServiceHosts = DataFiles::providerServiceHosts();
        if (isset($providerServiceHosts[$host]) && $isBare && $rank === 0) {
            $rank = Rank::lookup($tld !== '' ? $tld : $domain);
            $resp['features']['rank'] = $rank;
        }

        // 2. A user's page on a link-in-bio service (linktr.ee/someone) is theirs, not the service's.
        $userPageHosts = DataFiles::userPageHosts();
        $trimmedHost = preg_replace('/^www\./i', '', $host) ?? $host;
        if (!$isBare && isset($userPageHosts[$trimmedHost])) {
            $resp['features']['rank'] = 0;
            $rank = 0;
            $resp['features']['tld']['tld'] = $trimmedHost;
            $resp['features']['tld']['is_hosting_platform'] = true;
            $isHosting = true;
        }

        // 3. Typosquatting exceptions
        if (isset($resp['typosquat_result']) && is_array($resp['typosquat_result'])) {
            $ts = &$resp['typosquat_result'];
            $pathBrand = (string) ($ts['path_brand'] ?? '');
            if ($tldTrusted && $pathBrand !== '' && self::loginPath($rawUrl)) {
                $ts = [
                    'is_suspicious' => false,
                    'matched_domain' => '',
                    'matched_brand' => '',
                    'distance' => 0,
                    'is_combo_squat' => false,
                    'combo_brand' => '',
                    'combo_exact' => false,
                    'subdomain_brand' => '',
                    'subdomain_brand_exact' => false,
                    'embedded_domain' => '',
                    'path_brand' => $pathBrand,
                    'reasons' => [],
                ];
            } elseif (($rank > 0 && $rank <= 100000) || $tldTrusted) {
                $ts = [
                    'is_suspicious' => false,
                    'matched_domain' => '',
                    'matched_brand' => '',
                    'distance' => 0,
                    'is_combo_squat' => false,
                    'combo_brand' => '',
                    'combo_exact' => false,
                    'subdomain_brand' => '',
                    'subdomain_brand_exact' => false,
                    'embedded_domain' => '',
                    'path_brand' => '',
                    'reasons' => [],
                ];
            } elseif ($rank > 0) {
                $age = $resp['domain_info']['age_days'] ?? null;
                $hasAge = ($age !== null && $age > 0);
                $asks = !empty($resp['content_data']['has_login_form']) || !empty($resp['content_data']['has_payment_form']);
                $kwPresent = !empty($resp['features']['url']['keywords']['has_keywords']);
                $corroborated = ($hasAge && $age <= 2 * 365) || $asks || $kwPresent;

                if (!empty($ts['is_suspicious']) && (empty($ts['is_combo_squat']) || !empty($ts['combo_exact']) || !$corroborated)) {
                    $ts['is_suspicious'] = false;
                    $ts['is_combo_squat'] = false;
                    $ts['combo_exact'] = false;
                }
                if (!$corroborated) {
                    $ts['path_brand'] = '';
                    if (!empty($ts['subdomain_brand_exact'])) {
                        $ts['subdomain_brand'] = '';
                        $ts['subdomain_brand_exact'] = false;
                    }
                }
            }
            unset($ts);
        }

        // 4. If top-ranked domain (rank > 0) or trusted TLD:
        if ($rank > 0 || $tldTrusted) {
            $resp['features']['tld']['is_risky_tld'] = false;
            $resp['features']['url']['keywords'] = [
                'has_keywords' => false,
                'found' => [],
                'categories' => [],
            ];
        }

        // 5. Long, deep URLs are normal on big sites
        if ($rank > 0) {
            $resp['features']['url']['too_long'] = false;
            $resp['features']['url']['too_deep'] = false;
        }

        // 6. Only a verified organisation can register on a restricted registry
        if ($tldTrusted && isset($resp['content_data']['brand_check']) && is_array($resp['content_data']['brand_check'])) {
            if (!empty($resp['content_data']['brand_check']['is_mismatch'])) {
                $resp['content_data']['brand_check']['is_mismatch'] = false;
                $resp['content_data']['brand_check']['brand_found'] = '';
            }
        }

        // 7. applyBrandContext
        self::applyBrandContext($resp, $host, $rank, $tldTrusted, $isHosting);

        // 8. Redirects: domain jump exemptions
        if (isset($resp['analysis']['redirection_result']) && is_array($resp['analysis']['redirection_result'])) {
            $redir = &$resp['analysis']['redirection_result'];
            $hasJump = !empty($redir['has_domain_jump']);
            $finalUrl = (string) ($redir['final_url'] ?? '');
            $finalHost = (string) ($redir['final_url_domain'] ?? (DomainUtil::hostFromUrl($finalUrl) ?? ''));

            if ($hasJump) {
                if ($rank > 0 && (self::isVouchedDestination($finalUrl) || self::sameBrand($domain, $finalHost))) {
                    $redir['has_domain_jump'] = false;
                } elseif (self::sameBlog($host, $finalHost)) {
                    $redir['has_domain_jump'] = false;
                } elseif ($isHosting && self::sameBrand($tld, $finalHost)) {
                    $redir['has_domain_jump'] = false;
                    if (isset($resp['typosquat_result']) && is_array($resp['typosquat_result'])) {
                        $matched = (string) ($resp['typosquat_result']['matched_domain'] ?? '');
                        if (!empty($resp['typosquat_result']['is_combo_squat']) && self::brandRuns($matched, $finalHost)) {
                            $resp['typosquat_result'] = [
                                'is_suspicious' => false,
                                'matched_domain' => '',
                                'matched_brand' => '',
                                'distance' => 0,
                                'is_combo_squat' => false,
                                'combo_brand' => '',
                                'combo_exact' => false,
                                'subdomain_brand' => '',
                                'subdomain_brand_exact' => false,
                                'embedded_domain' => '',
                                'path_brand' => '',
                                'reasons' => [],
                            ];
                        }
                    }
                }
            }
            unset($redir);
        }

        // 9. Shortener bare URL exemption
        if (!empty($resp['features']['url']['url_shortener']) && $isBare) {
            $resp['features']['url']['url_shortener'] = false;
        }
    }

    private static function applyBrandContext(array &$resp, string $initialHost, int $rank, bool $tldTrusted, bool $isHostingPlatform): void
    {
        if (!isset($resp['content_data']) || !is_array($resp['content_data'])) {
            return;
        }

        $content = &$resp['content_data'];
        $host = DomainUtil::hostFromUrl((string) ($content['url'] ?? '')) ?? $initialHost;
        $finalHost = (string) ($resp['analysis']['redirection_result']['final_url_domain'] ?? '');
        if ($finalHost !== '') {
            $host = $finalHost;
        }

        $title = (string) ($content['title'] ?? '');
        if ($title !== '') {
            $content['brand_check'] = Brand::checkMismatch($host, $title);
        }

        $userPageHosts = DataFiles::userPageHosts();
        $trimmedHost = preg_replace('/^www\./i', '', $host) ?? $host;
        $hasLogin = !empty($content['has_login_form']);
        $hasPayment = !empty($content['has_payment_form']);

        if (isset($userPageHosts[$trimmedHost]) && !$hasLogin && !$hasPayment) {
            $content['brand_check']['is_mismatch'] = false;
            $content['brand_check']['brand_found'] = '';
            $content['brand_check']['official_domain'] = '';
            $content['brand_check']['detected_names'] = [];
            return;
        }

        $isMismatch = !empty($content['brand_check']['is_mismatch']);
        $isUserContent = DomainUtil::userContentHost($host) !== null;

        if ($isMismatch && $rank > 0 && $rank <= 100000 && !$isUserContent) {
            $content['brand_check']['is_mismatch'] = false;
            $content['brand_check']['brand_found'] = '';
            $content['brand_check']['official_domain'] = '';
            $content['brand_check']['detected_names'] = [];
        } elseif (!$isMismatch && $rank === 0 && !$tldTrusted && ($isHostingPlatform || $hasLogin || $hasPayment)) {
            $loose = Brand::checkMismatch($host, $title);
            if (!empty($loose['is_mismatch'])) {
                $content['brand_check']['is_mismatch'] = true;
                $content['brand_check']['brand_found'] = $loose['brand_found'];
                $content['brand_check']['official_domain'] = $loose['official_domain'] ?? '';
            }
        }
        unset($content);
    }

    private static function loginPath(string $url): bool
    {
        $path = parse_url($url, PHP_URL_PATH);
        if (!is_string($path) || $path === '') {
            return false;
        }
        return (bool) preg_match('/(?i)(log[-_]?in|log[-_]?on|sign[-_]?in|signon|verif|auth|secure|account|webscr|wallet|update)/', $path);
    }

    private static function isVouchedDestination(string $finalUrl): bool
    {
        $domain = DomainUtil::registrableDomainFromUrl($finalUrl);
        if ($domain === null || $domain === '') {
            return false;
        }
        if (Rank::lookup($domain) > 0) {
            return true;
        }
        $tld = TldSignals::check($domain);
        return !empty($tld['trusted']);
    }

    private static function sameBlog(string $a, string $b): bool
    {
        $blog = function (string $h): string {
            $h = preg_replace('/^www\./i', '', strtolower($h)) ?? strtolower($h);
            if (str_ends_with($h, '.blogspot.com')) {
                return substr($h, 0, -strlen('.blogspot.com'));
            }
            $p = DomainUtil::customerSitePlatform($h);
            if ($p !== null && str_starts_with($p, 'blogspot.')) {
                return substr($h, 0, -strlen('.' . $p));
            }
            return '';
        };
        $blogA = $blog($a);
        return $blogA !== '' && $blogA === $blog($b);
    }

    private static function sameBrand(string $fromDomain, string $toHost): bool
    {
        $brands = DataFiles::brands();
        foreach ($brands as $entry) {
            $domains = $entry['official_domains'] ?? [];
            if (!is_array($domains)) {
                continue;
            }
            $platforms = $entry['platforms'] ?? [];
            $allFrom = is_array($platforms) ? array_merge($domains, $platforms) : $domains;
            if (self::hostInDomains($fromDomain, $allFrom) && self::hostInDomains($toHost, $domains)) {
                return true;
            }
        }
        return false;
    }

    private static function brandRuns(string $officialDomain, string $host): bool
    {
        $brands = DataFiles::brands();
        foreach ($brands as $entry) {
            $domains = $entry['official_domains'] ?? [];
            if (!is_array($domains)) {
                continue;
            }
            if (self::hostInDomains($officialDomain, $domains) && self::hostInDomains($host, $domains)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param list<string> $domains
     */
    private static function hostInDomains(string $host, array $domains): bool
    {
        $host = strtolower($host);
        foreach ($domains as $d) {
            if (!is_string($d) || $d === '') {
                continue;
            }
            $d = strtolower($d);
            if ($host === $d || str_ends_with($host, '.' . $d)) {
                return true;
            }
        }
        return false;
    }
}
