<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Constants\DataFiles;

final class Brand
{
    public static function checkMismatch(string $domain, string $pageTitle): array
    {
        $domain = strtolower($domain);
        $pageTitle = self::withoutOwnAddress(strtolower($pageTitle), $domain);

        $res = [
            'brand_found' => '',
            'official_domain' => '',
            'is_mismatch' => false,
            'detected_names' => [],
        ];

        $brands = DataFiles::brands();
        foreach ($brands as $brandName => $entry) {
            $keywords = $entry['title_keywords'] ?? [];
            $official = $entry['official_domains'] ?? [];
            if (!is_array($keywords) || !is_array($official)) {
                continue;
            }

            foreach ($keywords as $kw) {
                if (!is_string($kw) || $kw === '') {
                    continue;
                }
                if (str_contains($pageTitle, strtolower($kw))) {
                    $res['detected_names'][] = $brandName;
                    if (!self::isOfficialDomain($domain, $official)) {
                        $res['brand_found'] = $brandName;
                        $res['is_mismatch'] = true;
                        if (!empty($official[0]) && is_string($official[0])) {
                            $res['official_domain'] = $official[0];
                        }
                    }
                    break;
                }
            }
        }

        $res['detected_names'] = array_values(array_unique($res['detected_names']));
        return $res;
    }

    /**
     * @return list<string>
     */
    public static function namesInText(string $text): array
    {
        $text = strtolower($text);
        if ($text === '') {
            return [];
        }

        $found = [];
        foreach (DataFiles::brands() as $brandName => $entry) {
            $keywords = $entry['title_keywords'] ?? [];
            if (!is_array($keywords)) {
                continue;
            }
            foreach ($keywords as $kw) {
                if (!is_string($kw) || $kw === '') {
                    continue;
                }
                if (str_contains($text, strtolower($kw))) {
                    $found[] = $brandName;
                    break;
                }
            }
        }

        return $found;
    }

    /**
     * @return list<string>
     */
    public static function officialDomainsFor(string $brandName): array
    {
        $entry = DataFiles::brands()[$brandName] ?? null;
        if (!is_array($entry)) {
            return [];
        }
        $official = $entry['official_domains'] ?? [];
        if (!is_array($official)) {
            return [];
        }
        return array_values(array_map(
            fn($d) => is_string($d) ? strtolower($d) : '',
            $official
        ));
    }

    private static function withoutOwnAddress(string $title, string $host): string
    {
        $host = preg_replace('/^www\./i', '', $host) ?? $host;
        if ($host === '') {
            return $title;
        }
        $title = str_ireplace('www.' . $host, ' ', $title);
        return str_ireplace($host, ' ', $title);
    }

    private static function isOfficialDomain(string $domain, array $officialDomains): bool
    {
        foreach ($officialDomains as $official) {
            if (!is_string($official) || $official === '') {
                continue;
            }
            $official = strtolower($official);
            if ($domain === $official || str_ends_with($domain, ".$official")) {
                return true;
            }
        }
        return false;
    }
}
