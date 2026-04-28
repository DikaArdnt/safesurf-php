<?php

declare(strict_types=1);

namespace SafeSurf\Util;

use Pdp\CannotProcessHost;
use Pdp\Idna;
use Pdp\ResourceUri;
use Pdp\Rules;

final class DomainUtil
{
    private static ?Rules $rules = null;

    public static function normalizeUrl(string $rawUrl): ?string
    {
        $rawUrl = trim($rawUrl);
        if ($rawUrl === '') {
            return null;
        }
        if (!str_contains($rawUrl, '://')) {
            $rawUrl = "http://$rawUrl";
        }
        $parts = @parse_url($rawUrl);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }
        if (!in_array(strtolower((string) $parts['scheme']), ['http', 'https'], true)) {
            return null;
        }

        return $rawUrl;
    }

    public static function hostFromUrl(string $url): ?string
    {
        $parts = @parse_url($url);
        if (!is_array($parts) || empty($parts['host'])) {
            return null;
        }
        return strtolower((string) $parts['host']);
    }

    public static function registrableDomainFromUrl(string $url, string $pslPath): ?string
    {
        $host = self::hostFromUrl($url);
        if ($host === null || $host === '') {
            return null;
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }

        $rules = self::rules($pslPath);
        try {
            $asciiHost = Idna::toAscii($host, Idna::IDNA2008_ASCII)->result();
        } catch (CannotProcessHost) {
            $asciiHost = $host;
        }

        try {
            $resolved = $rules->resolve($asciiHost);
            $reg = $resolved->registrableDomain();
            if ($reg !== null) {
                return strtolower($reg->toString());
            }
        } catch (\Throwable) {
        }

        $parts = explode('.', $asciiHost);
        if (count($parts) < 2) {
            return strtolower($asciiHost);
        }
        return strtolower($parts[count($parts) - 2] . '.' . $parts[count($parts) - 1]);
    }

    public static function tldFromDomain(string $domain, string $pslPath): array
    {
        $domain = strtolower(trim($domain));
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['tld' => '', 'icann' => false];
        }

        $rules = self::rules($pslPath);
        try {
            $ascii = Idna::toAscii($domain, Idna::IDNA2008_ASCII)->result();
        } catch (CannotProcessHost) {
            $ascii = $domain;
        }

        try {
            $resolved = $rules->resolve($ascii);
            $suffix = $resolved->suffix();
            return ['tld' => strtolower($suffix->toString()), 'icann' => $suffix->isICANN()];
        } catch (\Throwable) {
        }

        $parts = explode('.', $ascii);
        return ['tld' => strtolower((string) end($parts)), 'icann' => true];
    }

    public static function ensurePublicSuffixList(string $pslPath): string
    {
        if (is_file($pslPath) && filesize($pslPath) > 0) {
            return $pslPath;
        }

        $dir = dirname($pslPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        $raw = @file_get_contents(ResourceUri::PUBLIC_SUFFIX_LIST_URI);
        if (!is_string($raw) || $raw === '') {
            throw new \RuntimeException('Failed to download public suffix list');
        }

        $ok = @file_put_contents($pslPath, $raw);
        if ($ok === false) {
            throw new \RuntimeException('Failed to write public suffix list to disk');
        }

        return $pslPath;
    }

    private static function rules(string $pslPath): Rules
    {
        if (self::$rules !== null) {
            return self::$rules;
        }
        $pslPath = self::ensurePublicSuffixList($pslPath);
        self::$rules = Rules::fromPath($pslPath);
        return self::$rules;
    }
}
