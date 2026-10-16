<?php

declare(strict_types=1);

namespace SafeSurf\Util;

use SafeSurf\Constants\DataFiles;
use Pdp\CannotProcessHost;
use Pdp\Idna;
use Pdp\ResourceUri;
use Pdp\Rules;
use Pdp\SyntaxError;
use Pdp\UnableToResolveDomain;

final class DomainUtil
{
    /** @var array<string, Rules> */
    private static array $rulesCache = [];

    public static function normalizeUrl(string $rawUrl): ?string
    {
        $rawUrl = trim($rawUrl);
        if ($rawUrl === '' || preg_match('/[\x00-\x1F\x7F]/', $rawUrl) === 1) {
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

    public static function customerSitePlatform(string $host): ?string
    {
        $host = strtolower(trim($host));
        $customerHosts = DataFiles::customerSiteHosts();
        $providerSubdomains = DataFiles::providerSubdomains();

        foreach ($customerHosts as $suffix => $true) {
            if (!str_ends_with($host, ".$suffix")) {
                continue;
            }
            $rest = substr($host, 0, -strlen(".$suffix"));
            $dot = strrpos($rest, '.');
            $subLabel = $dot !== false ? substr($rest, $dot + 1) : $rest;
            if (isset($providerSubdomains[$suffix][$subLabel])) {
                return null;
            }
            return $suffix;
        }
        return null;
    }

    public static function customerSite(string $host): ?string
    {
        $platform = self::customerSitePlatform($host);
        if ($platform === null) {
            return null;
        }
        $rest = substr($host, 0, -strlen(".$platform"));
        $rest = preg_replace('/^www\./i', '', $rest) ?? $rest;
        if ($rest === 'www' || $rest === '') {
            return $platform;
        }
        return $rest . '.' . $platform;
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

        $customerSite = self::customerSite($host);
        if ($customerSite !== null && $customerSite !== '') {
            return $customerSite;
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
            if ($reg !== null && $reg->toString() !== '') {
                return strtolower($reg->toString());
            }
        } catch (\Throwable) {
        }

        try {
            $icannReg = $rules->getICANNDomain($asciiHost)->registrableDomain();
            if ($icannReg !== null && $icannReg->toString() !== '') {
                return strtolower($icannReg->toString());
            }
        } catch (SyntaxError) {
            return null;
        } catch (UnableToResolveDomain) {
            // Valid host but no ICANN suffix is known; fall through.
        }

        $parts = explode('.', $asciiHost);
        if (count($parts) < 2) {
            return strtolower($asciiHost);
        }
        return strtolower($parts[count($parts) - 2] . '.' . $parts[count($parts) - 1]);
    }

    public static function isHostingSuffix(string $suffix): bool
    {
        $suffix = strtolower(trim($suffix));
        $platforms = DataFiles::hostingPlatforms();
        for ($d = $suffix; $d !== ''; ) {
            if (isset($platforms[$d])) {
                return true;
            }
            $dot = strpos($d, '.');
            if ($dot === false) {
                break;
            }
            $d = substr($d, $dot + 1);
        }
        return false;
    }

    public static function tldFromDomain(string $domain, string $pslPath): array
    {
        $domain = strtolower(trim($domain));
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['tld' => '', 'icann' => false];
        }

        $platform = self::customerSitePlatform($domain);
        if ($platform !== null) {
            return ['tld' => $platform, 'icann' => false];
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
            if ($suffix->toString() !== '') {
                return ['tld' => strtolower($suffix->toString()), 'icann' => $suffix->isICANN()];
            }
        } catch (\Throwable) {
        }

       try {
            $icannSuffix = $rules->getICANNDomain($ascii)->suffix();
            if ($icannSuffix->toString() !== '') {
                return ['tld' => strtolower($icannSuffix->toString()), 'icann' => true];
            }
        } catch (\Throwable) {
        }

        $parts = explode('.', $ascii);
        return ['tld' => strtolower((string) end($parts)), 'icann' => true];
    }

    public static function ipHostname(string $host): ?array
    {
        $host = strtolower(trim($host));
        $services = DataFiles::ipHostnameServices();
        foreach ($services as $s => $true) {
            if (!str_ends_with($host, ".$s")) {
                continue;
            }
            $rest = substr($host, 0, -strlen(".$s"));
            if (preg_match_all('/(?:^|[.-])(\d{1,3}[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3})(?:[.-]|$)/', $rest, $matches)) {
                foreach ($matches[1] as $candidate) {
                    $ipCandidate = str_replace('-', '.', $candidate);
                    if (filter_var($ipCandidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                        return ['service' => $s, 'ip' => $ipCandidate];
                    }
                }
            }
            return ['service' => $s, 'ip' => ''];
        }
        return null;
    }

    public static function isBareUrl(string $url): bool
    {
        $parts = @parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        $path = trim((string) ($parts['path'] ?? ''), '/');
        $query = (string) ($parts['query'] ?? '');
        $fragment = (string) ($parts['fragment'] ?? '');
        return $path === '' && $query === '' && $fragment === '';
    }

    public static function userContentHost(string $host): ?string
    {
        $host = strtolower(trim($host));
        if (isset(DataFiles::providerServiceHosts()[$host])) {
            return $host;
        }
        $uploadHosts = DataFiles::userUploadHosts();
        for ($d = $host; $d !== ''; ) {
            if (isset($uploadHosts[$d])) {
                return $d;
            }
            $dot = strpos($d, '.');
            if ($dot === false) {
                break;
            }
            $d = substr($d, $dot + 1);
        }
        return null;
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

        $ctx = stream_context_create([
            'http' => [
                'timeout' => 10,
                'user_agent' => 'SafeSurfPHP/1.0',
                'follow_location' => 1,
                'max_redirects' => 3,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $raw = @file_get_contents(ResourceUri::PUBLIC_SUFFIX_LIST_URI, false, $ctx);
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
        if (isset(self::$rulesCache[$pslPath])) {
            return self::$rulesCache[$pslPath];
        }
        $pslPath = self::ensurePublicSuffixList($pslPath);
        return self::$rulesCache[$pslPath] = Rules::fromPath($pslPath);
    }
}
