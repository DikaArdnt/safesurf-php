<?php

declare(strict_types=1);

namespace SafeSurf\Service;

use SafeSurf\Config;
use SafeSurf\Util\DomainUtil;

final class Typosquat
{
    private const TOP_N = 5000;
    private const MIN_SLD_LEN = 4;

    public static function check(string $domain, Config $config): array
    {
        $domain = strtolower(trim($domain));
        $inputSld = self::extractSld($domain, $config);
        if (strlen($inputSld) < self::MIN_SLD_LEN) {
            return ['is_suspicious' => false];
        }

        [$entries, $sldSet] = self::topEntries($config);
        if (isset($sldSet[$inputSld])) {
            return ['is_suspicious' => false];
        }

        foreach ($entries as $e) {
            $brandSld = $e['sld'];

            $dist = levenshtein($inputSld, $brandSld);
            if ($dist >= 1 && $dist <= 2) {
                return [
                    'is_suspicious' => true,
                    'matched_domain' => $e['domain'],
                    'matched_brand' => $brandSld,
                    'distance' => $dist,
                    'is_combo_squat' => false,
                ];
            }

            if (strlen($brandSld) >= 6 && str_contains($inputSld, $brandSld)) {
                return [
                    'is_suspicious' => true,
                    'matched_domain' => $e['domain'],
                    'matched_brand' => $brandSld,
                    'distance' => 0,
                    'is_combo_squat' => true,
                ];
            }
        }

        return ['is_suspicious' => false];
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

