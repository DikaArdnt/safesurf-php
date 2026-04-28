<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;

final class UrlSignals
{
    public static function usesIp(string $url): bool
    {
        $host = DomainUtil::hostFromUrl($url);
        if ($host === null) {
            return false;
        }
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    public static function containsPunycode(string $url): bool
    {
        $host = DomainUtil::hostFromUrl($url);
        if ($host === null) {
            return false;
        }

        foreach (explode('.', $host) as $label) {
            if (str_starts_with($label, 'xn--')) {
                return true;
            }
            if (preg_match('/[^\\x00-\\x7F]/', $label) === 1) {
                return true;
            }
        }
        return false;
    }

    public static function tooLong(string $url): bool
    {
        return strlen($url) > 75;
    }

    public static function tooDeep(string $url): bool
    {
        return substr_count($url, '/') > 5;
    }

    public static function keywordMatches(string $url): array
    {
        $lower = strtolower($url);
        $words = preg_split('/[^a-z0-9]+/', $lower) ?: [];

        $keywords = DataFiles::urlKeywords();
        $matches = [];
        $categories = [];

        foreach ($words as $w) {
            if ($w === '') {
                continue;
            }
            if (!array_key_exists($w, $keywords)) {
                continue;
            }
            $matches[] = $w;
            $cat = $keywords[$w];
            $categories[$cat] ??= [];
            $categories[$cat][] = $w;
        }

        return [
            'present' => count($matches) > 0,
            'matches' => $matches,
            'categories' => $categories,
        ];
    }

    public static function isUrlShortener(string $domain): bool
    {
        $domain = strtolower($domain);
        return isset(DataFiles::urlShorteners()[$domain]);
    }

    public static function subdomainCount(string $url, Config $config): int
    {
        $host = DomainUtil::hostFromUrl($url);
        if ($host === null || $host === '') {
            return 0;
        }
        $host = rtrim($host, '.');
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return 0;
        }
        if (!str_contains($host, '.')) {
            return 0;
        }

        try {
            $reg = DomainUtil::registrableDomainFromUrl("https://$host", $config->publicSuffixListPath);
        } catch (\Throwable) {
            $reg = null;
        }

        if ($reg === null || $reg === '' || $reg === $host) {
            return 0;
        }

        if (!str_ends_with($host, ".$reg")) {
            return 0;
        }

        $sub = substr($host, 0, -strlen(".$reg"));
        $sub = trim($sub, '.');
        if ($sub === '') {
            return 0;
        }
        return count(explode('.', $sub));
    }
}

