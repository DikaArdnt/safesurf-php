<?php

declare(strict_types=1);

namespace SafeSurf;

use SafeSurf\Analyzer\Analyzer;

final class SafeSurf
{
    public static function analyze(string $url, ?Config $config = null): array
    {
        return Analyzer::analyze($url, $config);
    }
}

