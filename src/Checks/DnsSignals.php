<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class DnsSignals
{
    public static function ipAddresses(string $domain): array
    {
        $domain = trim($domain);
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return [];
        }
        $ips = [];
        $ipsv4 = @gethostbynamel($domain);
        $ipsv6 = @dns_get_record($domain, DNS_AAAA);
        if (\is_array($ipsv4)) {
            $ips = array_merge($ips, $ipsv4);
        }
        if (\is_array($ipsv6)) {
            foreach ($ipsv6 as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }
        if (!\is_array($ips)) {
            return [];
        }
        $out = [];
        foreach ($ips as $ip) {
            if (\is_string($ip) && $ip !== '') {
                $out[] = $ip;
            }
        }
        return array_values(array_unique($out));
    }

    public static function nsValidity(string $domain): array
    {
        $domain = trim($domain);
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['valid' => false, 'hosts' => []];
        }

        $records = @dns_get_record($domain, DNS_NS);
        if (!is_array($records) || count($records) === 0) {
            return ['valid' => false, 'hosts' => []];
        }

        $hosts = [];
        $valid = false;
        foreach ($records as $r) {
            if (!is_array($r) || !isset($r['target']) || !is_string($r['target'])) {
                continue;
            }
            $host = rtrim(strtolower($r['target']), '.');
            if ($host === '') {
                continue;
            }
            $hosts[] = $host;
            if (!$valid) {
                $ips = @gethostbynamel($host);
                if (is_array($ips) && count($ips) > 0) {
                    $valid = true;
                }
            }
        }

        return ['valid' => $valid, 'hosts' => array_values(array_unique($hosts))];
    }

    public static function mxValidity(string $domain): array
    {
        $domain = trim($domain);
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['valid' => false, 'hosts' => []];
        }

        $records = @dns_get_record($domain, DNS_MX);
        if (!is_array($records) || count($records) === 0) {
            return ['valid' => false, 'hosts' => []];
        }

        $hosts = [];
        $valid = false;
        foreach ($records as $r) {
            if (!is_array($r) || !isset($r['target']) || !is_string($r['target'])) {
                continue;
            }
            $host = rtrim(strtolower($r['target']), '.');
            if ($host === '') {
                continue;
            }
            $hosts[] = $host;
            if (!$valid) {
                $ips = @gethostbynamel($host);
                if (is_array($ips) && count($ips) > 0) {
                    $valid = true;
                }
            }
        }

        return ['valid' => $valid, 'hosts' => array_values(array_unique($hosts))];
    }
}

