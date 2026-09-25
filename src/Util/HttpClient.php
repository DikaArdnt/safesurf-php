<?php

declare(strict_types=1);

namespace SafeSurf\Util;

use SafeSurf\Config;

final class HttpClient
{
    public static function fetchHeadOrGet(string $url, Config $config): array
    {
        $res = self::request('HEAD', $url, $config);
        if ($res['error'] !== null) {
            $res = self::request('GET', $url, $config, true);
        }
        return $res;
    }

    public static function request(string $method, string $url, Config $config, bool $discardBody = false): array
    {
        $host = DomainUtil::hostFromUrl($url);
        if ($host === null) {
            return self::err('invalid_host');
        }

        $scheme = strtolower((string) (parse_url($url, PHP_URL_SCHEME) ?? ''));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return self::err('blocked_scheme');
        }

        $ip = null;
        if (!filter_var($host, FILTER_VALIDATE_IP)) {
            $ip = self::resolveFirstPublicIp($host);
            if ($ip === null) {
                return self::err('dns_resolution_failed');
            }
        } else {
            $ip = $host;
            if (self::isPrivateIp($ip)) {
                return self::err('ssrf_blocked');
            }
        }

        $headers = [];
        $body = '';
        $truncated = false;
        $maxBytes = max(1, $config->maxBodyBytes);

        $ch = curl_init();
        if ($ch === false) {
            return self::err('curl_init_failed');
        }

        $opts = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT_MS => $config->httpTimeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min(500, $config->httpHeaderTimeoutMs),
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT => $config->userAgent,
            CURLOPT_HTTPHEADER => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: en-US,en;q=0.9',
            ],
            CURLOPT_HEADERFUNCTION => function ($ch, string $headerLine) use (&$headers): int {
                $len = strlen($headerLine);
                $headerLine = trim($headerLine);
                if ($headerLine === '' || !str_contains($headerLine, ':')) {
                    return $len;
                }
                [$k, $v] = explode(':', $headerLine, 2);
                $k = strtolower(trim($k));
                $v = trim($v);
                $headers[$k][] = $v;
                return $len;
            },
            CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$body, &$truncated, $maxBytes, $discardBody): int {
                if ($discardBody) {
                    return strlen($chunk);
                }
                $room = $maxBytes - strlen($body);
                if (strlen($chunk) > $room) {
                    if ($room > 0) {
                        $body .= substr($chunk, 0, $room);
                    }
                    $truncated = true;
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ];

        if (strtoupper($method) === 'HEAD') {
            $opts[CURLOPT_NOBODY] = true;
        }

        $parts = parse_url($url);
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        if ($host !== $ip) {
            $opts[CURLOPT_RESOLVE] = ["{$host}:{$port}:{$ip}"];
        }

        curl_setopt_array($ch, $opts);
        curl_exec($ch);
        $errno = curl_errno($ch);
        $err = null;
        // 23 = CURLE_WRITE_ERROR: body cap reached, not a transport failure.
        if ($errno !== 0 && $errno !== 23) {
            $err = curl_error($ch);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

        if ($err !== null) {
            return self::err($err);
        }

        return [
            'status' => $status,
            'headers' => $headers,
            'body' => $discardBody ? '' : $body,
            'error' => null,
            'resolved_ip' => $ip,
            'truncated' => $truncated,
        ];
    }

    public static function resolveFirstPublicIp(string $host): ?string
    {
        $host = trim($host);
        if ($host === '') {
            return null;
        }
        $records = @dns_get_record($host, DNS_A + DNS_AAAA);
        if (!is_array($records)) {
            $records = [];
        }

        $ips = [];
        foreach ($records as $r) {
            if (!is_array($r)) {
                continue;
            }
            if (isset($r['ip']) && is_string($r['ip'])) {
                $ips[] = $r['ip'];
            }
            if (isset($r['ipv6']) && is_string($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }

        foreach ($ips as $ip) {
            if (!self::isPrivateIp($ip)) {
                return $ip;
            }
        }

        return null;
    }

    public static function isPrivateIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $n = ip2long($ip);
            if ($n === false) {
                return true;
            }
            $u = (int) sprintf('%u', $n);

            $ranges = [
                ['0.0.0.0', 8],
                ['10.0.0.0', 8],
                ['100.64.0.0', 10],
                ['127.0.0.0', 8],
                ['169.254.0.0', 16],
                ['172.16.0.0', 12],
                ['192.0.0.0', 24],
                ['192.168.0.0', 16],
                ['198.18.0.0', 15],
                ['224.0.0.0', 4],
                ['240.0.0.0', 4],
            ];

            foreach ($ranges as [$base, $cidr]) {
                $bn = ip2long($base);
                if ($bn === false) {
                    continue;
                }
                $bu = (int) sprintf('%u', $bn);
                $mask = $cidr === 0 ? 0 : (0xFFFFFFFF << (32 - $cidr)) & 0xFFFFFFFF;
                if (($u & $mask) === ($bu & $mask)) {
                    return true;
                }
            }
            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $bin = @inet_pton($ip);
            if (!is_string($bin) || strlen($bin) !== 16) {
                return true;
            }

            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible forms must be
            // validated as the embedded IPv4 address.
            if (substr($bin, 0, 10) === str_repeat("\0", 10) && (ord($bin[10]) === 0xFF || ord($bin[10]) === 0) && ord($bin[11]) === 0xFF) {
                $v4 = long2ip((int) (unpack('N', substr($bin, 12))[1] ?? 0));
                if (is_string($v4)) {
                    return self::isPrivateIp($v4);
                }
                return true;
            }

            $firstByte = ord($bin[0]);
            $secondByte = ord($bin[1]);

            if ($ip === '::1') {
                return true;
            }
            if (($firstByte & 0xFE) === 0xFC) {
                return true;
            }
            if ($firstByte === 0xFE && ($secondByte & 0xC0) === 0x80) {
                return true;
            }

            return false;
        }

        return true;
    }

    private static function err(string $msg): array
    {
        return ['status' => 0, 'headers' => [], 'body' => '', 'error' => $msg, 'resolved_ip' => null, 'truncated' => false];
    }
}
