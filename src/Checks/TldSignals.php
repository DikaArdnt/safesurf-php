<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;

final class TldSignals
{
    public static function info(string $domain, Config $config): array
    {
        $t = DomainUtil::tldFromDomain($domain, $config->publicSuffixListPath);
        $tld = strtolower((string) ($t['tld'] ?? ''));
        $icann = (bool) ($t['icann'] ?? false);

        $trusted = isset(DataFiles::trustedTlds()[$tld]);
        $risky = isset(DataFiles::riskyTlds()[$tld]);

        return ['tld' => $tld, 'icann' => $icann, 'trusted' => $trusted, 'risky' => $risky];
    }
}

