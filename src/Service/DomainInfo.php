<?php

declare(strict_types=1);

namespace SafeSurf\Service;

use Iodev\Whois\Factory as WhoisFactory;
use SafeSurf\Config;

final class DomainInfo
{
    private static ?array $bootstrap = null;
    private static int $bootstrapExpiresAt = 0;

    private static array $wellKnownRdap = [
        'com' => 'https://rdap.verisign.com/com/v1',
        'net' => 'https://rdap.verisign.com/net/v1',
        'org' => 'https://rdap.pir.org/rdap/org/v1',
        'io' => 'https://rdap.nic.io/v1',
        'co' => 'https://rdap.nic.co/v1',
        'me' => 'https://rdap.nic.me/v1',
        'tv' => 'https://rdap.nic.tv/v1',
        'cc' => 'https://rdap.nic.cc/v1',
    ];

    public static function lookup(string $domain, Config $config): ?array
    {
        $domain = strtolower(trim($domain));
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return null;
        }

        $cacheKey = "whois_lookup:$domain";
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $rdap = self::fetchRdap($domain, $config);
        if ($rdap !== null) {
            $rdap['age_human'] = self::domainAgeHuman($rdap['created'] ?? null);
            $rdap['age_days'] = self::domainAgeDays($rdap['created'] ?? null);
            if ($config->cache !== null) {
                $config->cache->setJson($cacheKey, $rdap, $config->ttlWhoisSeconds);
            }
            return $rdap;
        }

        $whois = self::fetchWhois($domain);
        if ($whois !== null) {
            $whois['age_human'] = self::domainAgeHuman($whois['created'] ?? null);
            $whois['age_days'] = self::domainAgeDays($whois['created'] ?? null);
            if ($config->cache !== null) {
                $config->cache->setJson($cacheKey, $whois, $config->ttlWhoisSeconds);
            }
            return $whois;
        }

        return null;
    }

    private static function fetchRdap(string $domain, Config $config): ?array
    {
        $parts = explode('.', $domain);
        if (count($parts) < 2) {
            return null;
        }
        $tld = strtolower((string) end($parts));

        $server = self::rdapServer($tld, $config);
        if ($server === null) {
            return null;
        }

        $url = rtrim($server, '/') . "/domain/$domain";
        $json = self::httpGetJson($url, 3.0, $config);
        if (!is_array($json)) {
            return null;
        }

        $registrar = '';
        if (isset($json['entities']) && is_array($json['entities'])) {
            foreach ($json['entities'] as $ent) {
                if (!is_array($ent)) {
                    continue;
                }
                $roles = $ent['roles'] ?? [];
                if (!is_array($roles) || !in_array('registrar', $roles, true)) {
                    continue;
                }
                $v = $ent['vcardArray'] ?? null;
                if (is_array($v) && count($v) >= 2 && is_array($v[1])) {
                    foreach ($v[1] as $item) {
                        if (!is_array($item) || count($item) < 4) {
                            continue;
                        }
                        if (($item[0] ?? null) === 'fn' && is_string($item[3] ?? null)) {
                            $registrar = (string) $item[3];
                            break 2;
                        }
                    }
                }
            }
        }

        $created = null;
        $updated = null;
        $expiry = null;

        if (isset($json['events']) && is_array($json['events'])) {
            foreach ($json['events'] as $ev) {
                if (!is_array($ev)) {
                    continue;
                }
                $action = $ev['eventAction'] ?? null;
                $date = $ev['eventDate'] ?? null;
                if (!is_string($action) || !is_string($date)) {
                    continue;
                }
                $ts = strtotime($date);
                if ($ts === false) {
                    continue;
                }
                $iso = gmdate('c', $ts);
                if ($action === 'registration') {
                    $created = $iso;
                } elseif ($action === 'last changed') {
                    $updated = $iso;
                } elseif ($action === 'expiration') {
                    $expiry = $iso;
                }
            }
        }

        $nameservers = [];
        if (isset($json['nameservers']) && is_array($json['nameservers'])) {
            foreach ($json['nameservers'] as $ns) {
                if (is_array($ns) && isset($ns['ldhName']) && is_string($ns['ldhName'])) {
                    $nameservers[] = strtolower($ns['ldhName']);
                }
            }
        }

        $status = [];
        if (isset($json['status']) && is_array($json['status'])) {
            foreach ($json['status'] as $st) {
                if (is_string($st) && $st !== '') {
                    $status[] = $st;
                }
            }
        }

        $dnssec = false;
        if (isset($json['secureDNS']) && is_array($json['secureDNS'])) {
            $dnssec = !empty($json['secureDNS']['delegationSigned']);
        }

        return [
            'domain' => (string) ($json['ldhName'] ?? $domain),
            'registrar' => $registrar,
            'created' => $created,
            'updated' => $updated,
            'expiry' => $expiry,
            'nameservers' => array_values(array_unique($nameservers)),
            'status' => array_values(array_unique($status)),
            'dnssec' => $dnssec,
            'raw' => json_encode($json, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'source' => 'RDAP',
        ];
    }

    private static function rdapServer(string $tld, Config $config): ?string
    {
        $tld = strtolower($tld);
        if (isset(self::$wellKnownRdap[$tld])) {
            return self::$wellKnownRdap[$tld];
        }

        $now = time();
        if (self::$bootstrap !== null && $now < self::$bootstrapExpiresAt) {
            return self::$bootstrap[$tld] ?? null;
        }

        $cacheKey = 'rdap_bootstrap';
        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached) && isset($cached['map'], $cached['expires_at']) && is_array($cached['map'])) {
                self::$bootstrap = $cached['map'];
                self::$bootstrapExpiresAt = (int) $cached['expires_at'];
                if ($now < self::$bootstrapExpiresAt) {
                    return self::$bootstrap[$tld] ?? null;
                }
            }
        }

        $json = self::httpGetJson('https://data.iana.org/rdap/dns.json', 5.0, $config);
        if (!is_array($json) || !isset($json['services']) || !is_array($json['services'])) {
            return null;
        }

        $map = [];
        foreach ($json['services'] as $service) {
            if (!is_array($service) || count($service) !== 2) {
                continue;
            }
            $tlds = $service[0] ?? null;
            $servers = $service[1] ?? null;
            if (!is_array($tlds) || !is_array($servers) || count($servers) === 0) {
                continue;
            }
            $server = rtrim((string) $servers[0], '/');
            foreach ($tlds as $tt) {
                if (is_string($tt) && $tt !== '') {
                    $map[strtolower($tt)] = $server;
                }
            }
        }

        self::$bootstrap = $map;
        self::$bootstrapExpiresAt = $now + 86400;

        if ($config->cache !== null) {
            $config->cache->setJson($cacheKey, ['map' => $map, 'expires_at' => self::$bootstrapExpiresAt], 86400);
        }

        return $map[$tld] ?? null;
    }

    private static function httpGetJson(string $url, float $timeoutSeconds, Config $config): ?array
    {
        $ch = curl_init();
        if ($ch === false) {
            return null;
        }
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => $timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => min(2.0, $timeoutSeconds),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => $config->userAgent,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $raw = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

        // Deprecated in PHP 8.5, but we want to support older versions as well.
        if (function_exists('curl_close')) {
            curl_close($ch);
        }

        if ($errno !== 0 || !is_string($raw) || $raw === '' || $status < 200 || $status >= 300) {
            return null;
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }
        return is_array($decoded) ? $decoded : null;
    }

    private static function fetchWhois(string $domain): ?array
    {
        try {
            $whois = WhoisFactory::get()->createWhois();
            $info = $whois->loadDomainInfo($domain);
        } catch (\Throwable) {
            return null;
        }

        if (!is_object($info) || empty($info->domainName)) {
            return null;
        }

        $created = !empty($info->creationDate) ? gmdate('c', (int) $info->creationDate) : null;
        $updated = !empty($info->updatedDate) ? gmdate('c', (int) $info->updatedDate) : null;
        $expiry = !empty($info->expirationDate) ? gmdate('c', (int) $info->expirationDate) : null;

        $dnssec = false;
        if (isset($info->dnssec) && is_string($info->dnssec)) {
            $dnssec = strtolower(trim($info->dnssec)) === 'signed' || strtolower(trim($info->dnssec)) === 'yes' || strtolower(trim($info->dnssec)) === 'true';
        }

        $raw = '';
        try {
            $resp = $info->getResponse();
            if (is_object($resp) && isset($resp->text) && is_string($resp->text)) {
                $raw = $resp->text;
            }
        } catch (\Throwable) {
        }

        return [
            'domain' => (string) $info->domainName,
            'registrar' => (string) ($info->registrar ?? ''),
            'created' => $created,
            'updated' => $updated,
            'expiry' => $expiry,
            'nameservers' => array_values(array_unique(array_map('strtolower', is_array($info->nameServers ?? null) ? $info->nameServers : []))),
            'status' => array_values(array_unique(is_array($info->states ?? null) ? $info->states : [])),
            'dnssec' => $dnssec,
            'raw' => $raw,
            'source' => 'WHOIS',
        ];
    }

    private static function domainAgeDays(?string $createdIso): int
    {
        if (!is_string($createdIso) || $createdIso === '') {
            return 0;
        }
        $ts = strtotime($createdIso);
        if ($ts === false) {
            return 0;
        }
        $now = time();
        if ($ts > $now) {
            return 0;
        }
        return (int) floor(($now - $ts) / 86400);
    }

    private static function domainAgeHuman(?string $createdIso): string
    {
        if (!is_string($createdIso) || $createdIso === '') {
            return '';
        }
        $ts = strtotime($createdIso);
        if ($ts === false) {
            return '';
        }
        $now = time();
        if ($ts > $now) {
            return 'not yet registered';
        }

        $created = new \DateTimeImmutable("@$ts");
        $nowDt = new \DateTimeImmutable("@$now");
        $diff = $created->diff($nowDt);

        $years = (int) $diff->y;
        $months = (int) $diff->m;
        $days = (int) floor(($now - $ts) / 86400);

        if ($years <= 0 && $months <= 0) {
            if ($days === 0) {
                return 'today';
            }
            if ($days === 1) {
                return '1 day old';
            }
            if ($days < 30) {
                return $days . ' days old';
            }
            return 'less than a month old';
        }

        $parts = [];
        if ($years > 0) {
            $parts[] = $years === 1 ? '1 year' : ($years . ' years');
        }
        if ($months > 0) {
            $parts[] = $months === 1 ? '1 month' : ($months . ' months');
        }
        return implode(' ', $parts);
    }
}
