<?php

declare(strict_types=1);

namespace SafeSurf;

use SafeSurf\Cache\CacheInterface;

final class Config
{
    public function __construct(
        public ?CacheInterface $cache = null,
        public string $rankCsvPath = __DIR__ . '/../assets/top-1m.csv',
        public string $publicSuffixListPath = __DIR__ . '/../storage/public_suffix_list.dat',
        public int $httpTimeoutMs = 5000,
        public int $httpHeaderTimeoutMs = 800,
        public int $maxRedirects = 10,
        public string $userAgent = 'SafeSurfPHP/1.0',
        public int $ttlDomainRankSeconds = 86400,
        public int $ttlIpResolutionSeconds = 10800,
        public int $ttlDnsValiditySeconds = 10800,
        public int $ttlWhoisSeconds = 86400,
        public int $ttlHttpCombinedSeconds = 10800,
        public int $ttlTlsCombinedSeconds = 86400,
        public int $ttlPhishTankSeconds = 10800,
        public int $ttlContentSeconds = 10800,
        public int $ttlAnalyzeResultSeconds = 86400,
        public ?string $phishTankApiKey = null,
        public string $phishTankUserAgent = 'phishtank/SafeSurfPHP'
    ) {
    }
}
