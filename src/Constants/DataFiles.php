<?php

declare(strict_types=1);

namespace SafeSurf\Constants;

final class DataFiles
{
    private static ?array $riskyTlds = null;
    private static ?array $trustedTlds = null;
    private static ?array $urlShorteners = null;
    private static ?array $urlKeywords = null;
    private static ?array $brands = null;

    public static function riskyTlds(): array
    {
        if (self::$riskyTlds !== null) {
            return self::$riskyTlds;
        }
        self::$riskyTlds = require __DIR__ . '/../../assets/risky_tlds.php';
        return self::$riskyTlds;
    }

    public static function trustedTlds(): array
    {
        if (self::$trustedTlds !== null) {
            return self::$trustedTlds;
        }
        self::$trustedTlds = require __DIR__ . '/../../assets/trusted_tlds.php';
        return self::$trustedTlds;
    }

    public static function urlShorteners(): array
    {
        if (self::$urlShorteners !== null) {
            return self::$urlShorteners;
        }
        self::$urlShorteners = require __DIR__ . '/../../assets/url_shorteners.php';
        return self::$urlShorteners;
    }

    public static function urlKeywords(): array
    {
        if (self::$urlKeywords !== null) {
            return self::$urlKeywords;
        }
        self::$urlKeywords = require __DIR__ . '/../../assets/url_keywords.php';
        return self::$urlKeywords;
    }

    public static function brands(): array
    {
        if (self::$brands !== null) {
            return self::$brands;
        }
        self::$brands = require __DIR__ . '/../../assets/brands.php';
        return self::$brands;
    }
}
