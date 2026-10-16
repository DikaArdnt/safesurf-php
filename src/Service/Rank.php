<?php

declare(strict_types=1);

namespace SafeSurf\Service;

use SafeSurf\Config;

final class Rank
{
    /** @var array<string, int> */
    private static array $memoryCache = [];

    public static function lookup(string $domain, Config $config): int
    {
        $domain = strtolower(trim($domain));
        if ($domain === '') {
            return 0;
        }

        if (isset(self::$memoryCache[$domain])) {
            return self::$memoryCache[$domain];
        }

        if (!is_file($config->rankCsvPath)) {
            return 0;
        }

        $cacheKey = "domain_rank:$domain";
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached) && isset($cached['rank'])) {
                return self::$memoryCache[$domain] = (int) $cached['rank'];
            }
        }

        $rank = 0;
        $fh = @fopen($config->rankCsvPath, 'rb');
        if (!is_resource($fh)) {
            return 0;
        }

        while (($line = fgets($fh)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $pos = strpos($line, ',');
            if ($pos === false) {
                continue;
            }
            $d = strtolower(trim(substr($line, $pos + 1)));
            if ($d === $domain) {
                $rank = (int) substr($line, 0, $pos);
                break;
            }
        }
        fclose($fh);

        self::$memoryCache[$domain] = $rank;

        if ($config->cache !== null) {
            $config->cache->setJson($cacheKey, ['rank' => $rank], $config->ttlDomainRankSeconds);
        }

        return $rank;
    }

    public static function topDomains(int $n, Config $config): array
    {
        if ($n <= 0 || !is_file($config->rankCsvPath)) {
            return [];
        }

        $cacheKey = "top_domains:$n";
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached) && isset($cached['domains']) && is_array($cached['domains'])) {
                return $cached['domains'];
            }
        }

        $domains = [];
        $fh = @fopen($config->rankCsvPath, 'rb');
        if (!is_resource($fh)) {
            return [];
        }

        while (count($domains) < $n && ($line = fgets($fh)) !== false) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $pos = strpos($line, ',');
            if ($pos === false) {
                continue;
            }
            $d = strtolower(trim(substr($line, $pos + 1)));
            if ($d !== '') {
                $domains[] = $d;
            }
        }
        fclose($fh);

        $domains = array_values(array_unique($domains));

        if ($config->cache !== null) {
            $config->cache->setJson($cacheKey, ['domains' => $domains], $config->ttlDomainRankSeconds);
        }

        return $domains;
    }
}
