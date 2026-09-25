<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;

final class SubdomainSignals
{
    private static ?array $brandTokens = null;

    public static function analyze(string $url, string $registrableDomain, Config $config): array
    {
        $out = [
            'labels' => [],
            'subdomain_count' => 0,
            'sensitive_labels' => [],
            'has_sensitive_label' => false,
            'brand_hits' => [],
            'has_brand_impersonation' => false,
        ];

        $host = DomainUtil::hostFromUrl($url);
        if ($host === null || $host === '') {
            return $out;
        }
        $host = rtrim($host, '.');
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $out;
        }

        $registrableDomain = strtolower(trim($registrableDomain));
        if ($registrableDomain === '' || $host === $registrableDomain || !str_ends_with($host, ".$registrableDomain")) {
            return $out;
        }

        $sub = substr($host, 0, -strlen(".$registrableDomain"));
        $labels = array_values(array_filter(explode('.', $sub), fn($l) => $l !== ''));
        $out['labels'] = $labels;
        $out['subdomain_count'] = count($labels);

        $sensitive = DataFiles::sensitiveSubdomains();
        $brandTokens = self::brandTokens();

        foreach ($labels as $label) {
            $label = strtolower($label);
            if ($label === '') {
                continue;
            }

            if (isset($sensitive[$label])) {
                $out['sensitive_labels'][$label] = $sensitive[$label];
            }

            foreach (self::labelTokens($label) as $token) {
                if (!isset($brandTokens[$token])) {
                    continue;
                }
                foreach ($brandTokens[$token] as $brandName) {
                    $official = self::officialDomainsFor($brandName);
                    if (self::isOfficialDomain($registrableDomain, $official)) {
                        continue;
                    }
                    $out['brand_hits'][] = [
                        'brand' => $brandName,
                        'token' => $token,
                        'label' => $label,
                    ];
                }
            }
        }

        $out['brand_hits'] = self::dedupeBrandHits($out['brand_hits']);
        $out['has_sensitive_label'] = $out['sensitive_labels'] !== [];
        $out['has_brand_impersonation'] = $out['brand_hits'] !== [];

        return $out;
    }

    /**
     * @return list<string>
     */
    public static function labelTokens(string $label): array
    {
        $label = strtolower($label);
        $parts = preg_split('/[^a-z0-9]+/', $label) ?: [];
        $tokens = [];
        foreach ($parts as $p) {
            if ($p !== '') {
                $tokens[] = $p;
            }
        }
        return $tokens;
    }

    /**
     * @return array<string, list<string>>
     */
    public static function brandTokens(): array
    {
        if (self::$brandTokens !== null) {
            return self::$brandTokens;
        }

        $sensitive = DataFiles::sensitiveSubdomains();
        $generic = [
            'www', 'www2', 'web', 'app', 'api', 'cdn', 'static', 'assets',
            'img', 'images', 'docs', 'portal', 'shop', 'store', 'cloud',
            'site', 'online', 'org', 'net', 'com', 'edu', 'gov',
        ];

        $map = [];
        foreach (DataFiles::brands() as $brandName => $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $tokens = [];

            $words = preg_split('/[^a-z0-9]+/i', strtolower((string) $brandName)) ?: [];
            foreach ($words as $w) {
                if (strlen($w) >= 4 && $w !== 'mail' && $w !== 'official') {
                    $tokens[] = $w;
                }
            }

            $official = $entry['official_domains'] ?? [];
            if (is_array($official)) {
                foreach ($official as $domain) {
                    if (!is_string($domain) || $domain === '') {
                        continue;
                    }
                    $sld = strtolower(explode('.', $domain)[0] ?? '');
                    if (strlen($sld) < 4 || isset($sensitive[$sld]) || in_array($sld, $generic, true)) {
                        continue;
                    }
                    $tokens[] = $sld;
                }
            }

            foreach (array_unique($tokens) as $t) {
                $map[$t][] = (string) $brandName;
            }
        }

        return self::$brandTokens = $map;
    }

    /**
     * @return list<string>
     */
    private static function officialDomainsFor(string $brandName): array
    {
        $entry = DataFiles::brands()[$brandName] ?? null;
        if (!is_array($entry)) {
            return [];
        }
        $official = $entry['official_domains'] ?? [];
        return is_array($official) ? array_values(array_map('strtolower', $official)) : [];
    }

    private static function isOfficialDomain(string $domain, array $officialDomains): bool
    {
        foreach ($officialDomains as $official) {
            if (!is_string($official) || $official === '') {
                continue;
            }
            if ($domain === $official || str_ends_with($domain, ".$official")) {
                return true;
            }
        }
        return false;
    }

    private static function dedupeBrandHits(array $hits): array
    {
        $seen = [];
        $out = [];
        foreach ($hits as $h) {
            if (!is_array($h)) {
                continue;
            }
            $key = (string) ($h['brand'] ?? '') . '|' . (string) ($h['token'] ?? '');
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $out[] = $h;
        }
        return $out;
    }
}
