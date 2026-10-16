<?php

declare(strict_types=1);

namespace SafeSurf\Service;

use SafeSurf\Config;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;

final class Typosquat
{
    private const TOP_N = 5000;
    private const MIN_SLD_LEN = 4;
    private const MIN_COMBO_LEN = 6;
    private const EMBEDDED_RANK = 100000;

    /** @var array<string, true> */
    private static array $genericBrandNames = [
        'battle' => true, 'gemini' => true, 'indeed' => true, 'kraken' => true, 'ledger' => true,
        'notion' => true, 'office' => true, 'origin' => true, 'phantom' => true, 'signal' => true,
        'stripe' => true, 'netbank' => true, 'medicare' => true, 'proton' => true, 'messenger' => true,
        'freelancer' => true, 'incometax' => true,
        'canada' => true, 'united' => true, 'orange' => true, 'target' => true, 'booking' => true,
        'spectrum' => true, 'sunrise' => true, 'fidelity' => true, 'emirates' => true, 'regions' => true,
        'discover' => true, 'square' => true, 'citizens' => true, 'nationwide' => true, 'vanguard' => true,
        'interac' => true, 'revolut' => true,
        'sparkasse' => true, 'volksbank' => true, 'raiffeisen' => true, 'minecraft' => true,
        'crypto' => true, 'blockchain' => true, 'turkiye' => true, 'charter' => true, 'secureserver' => true, 'ankama' => true,
    ];

    /** @var array<int, array{sld: string, official_domains: array<string>}>|null */
    private static ?array $comboBrands = null;

    public static function check(string $domain, Config $config, ?string $url = null): array
    {
        $domain = strtolower(trim($domain));
        $res = [
            'is_suspicious' => false,
            'matched_domain' => '',
            'matched_brand' => '',
            'distance' => 0,
            'is_combo_squat' => false,
            'combo_exact' => false,
            'subdomain_brand' => '',
            'subdomain_brand_exact' => false,
            'embedded_domain' => '',
            'path_brand' => '',
        ];

        $inputSld = self::extractSld($domain, $config);
        if (strlen($inputSld) >= self::MIN_SLD_LEN) {
            // A well-known domain cannot be a typosquat of another.
            $domainRank = Rank::lookup($domain, $config);
            if ($domainRank === 0) {
                [$entries, $sldSet] = self::topEntries($config);
                if (!isset($sldSet[$inputSld])) {
                    $inputLen = strlen($inputSld);
                    foreach ($entries as $e) {
                        $brandSld = $e['sld'];
                        $brandLen = strlen($brandSld);

                        $maxDist = ($inputLen >= 6 && $brandLen >= 6) ? 2 : 1;
                        if (abs($inputLen - $brandLen) <= $maxDist) {
                            $dist = levenshtein($inputSld, $brandSld);
                            if ($dist >= 1 && $dist <= $maxDist) {
                                $res['is_suspicious'] = true;
                                $res['matched_domain'] = $e['domain'];
                                $res['matched_brand'] = $brandSld;
                                $res['distance'] = $dist;
                                break;
                            }
                        }
                    }

                    if (!$res['is_suspicious']) {
                        foreach (self::comboBrands($config) as $cb) {
                            if (str_contains($inputSld, $cb['sld']) && !self::isOfficial($domain, $cb['official_domains'])) {
                                $res['is_suspicious'] = true;
                                $res['matched_domain'] = $cb['official_domains'][0] ?? '';
                                $res['matched_brand'] = $cb['sld'];
                                $res['is_combo_squat'] = true;
                                $res['combo_exact'] = ($inputSld === $cb['sld']);
                                break;
                            }
                        }
                    }
                }
            }
        }

        if ($url !== null) {
            self::checkUrlParts($url, $domain, $config, $res);
        }

        return $res;
    }

    public static function checkUrlParts(string $url, string $domain, Config $config, array &$res): void
    {
        $parts = @parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return;
        }

        $host = strtolower((string) $parts['host']);
        $domain = strtolower($domain);
        $bare = preg_replace('/^www\./i', '', $host) ?? $host;

        if ($bare !== $domain && str_ends_with($bare, ".$domain")) {
            $prefix = substr($bare, 0, -strlen(".$domain"));
            $prefix = trim($prefix, '.');
            if ($prefix !== '' && $prefix !== 'www') {
                $labels = explode('.', $prefix);
                // A popular domain spelled out in front: google.com in accounts.google.com.example.fr
                $labelCount = count($labels);
                for ($i = 0; $i < $labelCount - 1 && empty($res['embedded_domain']); $i++) {
                    $candidate = implode('.', array_slice($labels, $i));
                    $r = Rank::lookup($candidate, $config);
                    if ($r > 0 && $r <= self::EMBEDDED_RANK) {
                        $res['embedded_domain'] = $candidate;
                    }
                }

                foreach ($labels as $label) {
                    $brand = self::brandIn($label, $config);
                    if ($brand !== null && !self::isOfficial($host, $brand['official_domains'])) {
                        $res['subdomain_brand'] = $brand['sld'];
                        $res['subdomain_brand_exact'] = ($label === $brand['sld']);
                        break;
                    }
                }
            }
        }

        $path = strtolower((string) ($parts['path'] ?? '') . '?' . (string) ($parts['query'] ?? ''));
        if (strlen($path) > 2) {
            $brand = self::brandIn($path, $config);
            if ($brand !== null && !self::isOfficial($host, $brand['official_domains'])) {
                $res['path_brand'] = $brand['sld'];
            }
        }
    }

    private static function brandIn(string $s, Config $config): ?array
    {
        foreach (self::comboBrands($config) as $b) {
            if (str_contains($s, $b['sld'])) {
                return $b;
            }
        }
        return null;
    }

    private static function comboBrands(Config $config): array
    {
        if (self::$comboBrands !== null) {
            return self::$comboBrands;
        }

        $seen = [];
        $out = [];
        foreach (DataFiles::brands() as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $official = $entry['official_domains'] ?? [];
            if (!is_array($official)) {
                continue;
            }
            foreach ($official as $d) {
                if (!is_string($d) || $d === '') {
                    continue;
                }
                $sld = self::extractSld($d, $config);
                if (isset(self::$genericBrandNames[$sld]) || strlen($sld) < self::MIN_COMBO_LEN || isset($seen[$sld])) {
                    continue;
                }
                $seen[$sld] = true;
                $out[] = ['sld' => $sld, 'official_domains' => $official];
            }
        }

        usort($out, function (array $a, array $b): int {
            $lenA = strlen($a['sld']);
            $lenB = strlen($b['sld']);
            if ($lenA !== $lenB) {
                return $lenB <=> $lenA;
            }
            return strcmp($a['sld'], $b['sld']);
        });

        return self::$comboBrands = $out;
    }

    private static function isOfficial(string $domain, array $officialDomains): bool
    {
        $domain = strtolower($domain);
        foreach ($officialDomains as $d) {
            $d = strtolower((string) $d);
            if ($domain === $d || str_ends_with($domain, ".$d")) {
                return true;
            }
        }
        return false;
    }

    private static function topEntries(Config $config): array
    {
        $cacheKey = 'typosquat_top_entries:' . self::TOP_N;
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached) && isset($cached['entries'], $cached['sld_set']) && is_array($cached['entries']) && is_array($cached['sld_set'])) {
                return [$cached['entries'], $cached['sld_set']];
            }
        }

        $domains = Rank::topDomains(self::TOP_N, $config);
        $entries = [];
        $set = [];

        foreach ($domains as $d) {
            $sld = self::extractSld($d, $config);
            if (strlen($sld) < self::MIN_SLD_LEN) {
                continue;
            }
            $entries[] = ['domain' => $d, 'sld' => $sld];
            $set[$sld] = true;
        }

        if ($config->cache !== null) {
            $config->cache->setJson($cacheKey, ['entries' => $entries, 'sld_set' => $set], $config->ttlDomainRankSeconds);
        }

        return [$entries, $set];
    }

    private static function extractSld(string $domain, Config $config): string
    {
        $domain = strtolower(trim($domain));
        $domain = rtrim($domain, '.');
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return $domain;
        }

        $platform = DomainUtil::customerSitePlatform($domain);
        if ($platform !== null && $platform !== '') {
            $rest = substr($domain, 0, -strlen(".$platform"));
            return trim($rest, '.');
        }

        try {
            $reg = DomainUtil::registrableDomainFromUrl("https://$domain", $config->publicSuffixListPath);
        } catch (\Throwable) {
            $reg = null;
        }
        if ($reg === null || $reg === '') {
            $reg = $domain;
        }

        $parts = explode('.', $reg);
        return $parts[0] ?? $reg;
    }
}
