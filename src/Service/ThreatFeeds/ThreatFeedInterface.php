<?php

declare(strict_types=1);

namespace SafeSurf\Service\ThreatFeeds;

use SafeSurf\Config;

interface ThreatFeedInterface
{
    public function name(): string;

    public function check(string $url, Config $config): ?array;
}
