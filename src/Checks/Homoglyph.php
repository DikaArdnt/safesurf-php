<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class Homoglyph
{
    public static function hasHomoglyphs(string $domain): bool
    {
        if ($domain === '') {
            return false;
        }
        if (preg_match('/\\p{L}/u', $domain) !== 1) {
            return false;
        }
        return preg_match('/[^\\x00-\\x7F]/u', $domain) === 1;
    }
}

