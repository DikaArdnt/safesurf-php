<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Constants\DataFiles;

final class Brand
{
    public static function checkMismatch(string $domain, string $pageTitle): array
    {
        $domain = strtolower($domain);
        $pageTitle = strtolower($pageTitle);

        $res = [
            'brand_found' => '',
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
                    }
                    break;
                }
            }
        }

        $res['detected_names'] = array_values(array_unique($res['detected_names']));
        return $res;
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

