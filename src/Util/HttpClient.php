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

        $cleanHost = trim($host, '[]');

        $ip = null;
        if (!filter_var($cleanHost, FILTER_VALIDATE_IP)) {
            $ip = self::resolveFirstPublicIp($cleanHost);
            if ($ip === null) {
                return self::err('dns_resolution_failed');
            }
        } else {
            $ip = $cleanHost;
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
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
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
        if ($cleanHost !== $ip) {
            $resolveIp = str_contains($ip, ':') ? "[$ip]" : $ip;
            $opts[CURLOPT_RESOLVE] = ["{$cleanHost}:{$port}:{$resolveIp}"];
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
        $ip = trim($ip, '[]');

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
                ['192.0.2.0', 24],
                ['192.88.99.0', 24],
                ['192.168.0.0', 16],
                ['198.18.0.0', 15],
                ['198.51.100.0', 24],
                ['203.0.113.0', 24],
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

            // Unspecified address (::)
            if ($bin === str_repeat("\0", 16)) {
                return true;
            }

            // Loopback address (::1)
            if ($bin === (str_repeat("\0", 15) . "\x01")) {
                return true;
            }

            // IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96), SIIT (::ffff:0:a.b.c.d)
            if (substr($bin, 0, 10) === str_repeat("\0", 10)) {
                $b10 = ord($bin[10]);
                $b11 = ord($bin[11]);
                if (($b10 === 0x00 && $b11 === 0x00) || ($b10 === 0xFF && $b11 === 0xFF) || ($b10 === 0xFF && $b11 === 0x00)) {
                    $v4 = long2ip((int) (unpack('N', substr($bin, 12))[1] ?? 0));
                    if (is_string($v4)) {
                        return self::isPrivateIp($v4);
                    }
                    return true;
                }
            }

            // Well-Known Prefix for IPv4/IPv6 translation (64:ff9b::/96)
            if (str_starts_with($bin, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00")) {
                $v4 = long2ip((int) (unpack('N', substr($bin, 12))[1] ?? 0));
                if (is_string($v4)) {
                    return self::isPrivateIp($v4);
                }
                return true;
            }

            $firstByte = ord($bin[0]);
            $secondByte = ord($bin[1]);

            // Multicast (ff00::/8)
            if ($firstByte === 0xFF) {
                return true;
            }

            // Unique Local Address (fc00::/7)
            if (($firstByte & 0xFE) === 0xFC) {
                return true;
            }

            // Link-Local Unicast (fe80::/10)
            if ($firstByte === 0xFE && ($secondByte & 0xC0) === 0x80) {
                return true;
            }

            // Discard prefix (100::/64)
            if (str_starts_with($bin, "\x01\x00\x00\x00\x00\x00\x00\x00")) {
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
