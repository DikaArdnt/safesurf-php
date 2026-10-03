<?php

declare(strict_types=1);

namespace SafeSurf;

use SafeSurf\Cache\CacheInterface;
use SafeSurf\Service\ThreatFeeds\ThreatFeedInterface;
use SafeSurf\Service\ThreatFeeds\ThreatFeeds;

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
        public int $ttlContentSeconds = 10800,
        public int $ttlAnalyzeResultSeconds = 86400,
        public int $maxBodyBytes = 5242880,
        public bool $enableRootDomainCorrelation = true,
        public int $rootCorrelationMaxHops = 3,
        public int $ttlRootDomainCorrelationSeconds = 21600,
        public int $dnsQueryTimeoutMs = 2000,
        public ?ThreatFeeds $threatFeeds = null,
        /** Feature toggles: a disabled check is skipped entirely and its result field turns null/neutral. All default to true (full analysis). */
        public bool $enableRank = true,
        public bool $enableDns = true,
        public bool $enableHttp = true,
        public bool $enableTls = true,
        public bool $enableContent = true,
        public bool $enableWhois = true,
        public bool $enableThreatFeeds = true
    ) {
        $this->threatFeeds ??= new ThreatFeeds();
    }

    public function threatFeedSetup(): ThreatFeeds
    {
        return $this->threatFeeds;
    }

    public function addThreatFeed(ThreatFeedInterface ...$feeds): self
    {
        $this->threatFeeds->addFeed(...$feeds);
        return $this;
    }
}
