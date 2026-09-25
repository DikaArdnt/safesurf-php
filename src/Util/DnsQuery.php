<?php

declare(strict_types=1);

namespace SafeSurf\Util;

final class DnsQuery
{
    private const TYPE_A = 1;
    private const TYPE_CNAME = 5;

    /**
     * Query A records for $name against $serverIp.
     *
     * @return array{status: string, ips: list<string>}|null status is one of
     *   'ok', 'nxdomain', 'servfail', 'refused', 'rcode_N'; null on transport
     *   failure or malformed reply.
     */
    public static function query(string $serverIp, string $name, int $timeoutMs): ?array
    {
        if (!filter_var($serverIp, FILTER_VALIDATE_IP)) {
            return null;
        }

        $packet = self::buildQuery($name);
        if ($packet === null) {
            return null;
        }

        $sock = @stream_socket_client(
            "udp://{$serverIp}:53",
            $errno,
            $errstr,
            max(0.1, $timeoutMs / 1000)
        );
        if ($sock === false) {
            return null;
        }

        $sec = intdiv($timeoutMs, 1000);
        $usec = ($timeoutMs % 1000) * 1000;
        stream_set_timeout($sock, max(1, $sec), $usec);

        $sent = @fwrite($sock, $packet);
        if ($sent !== strlen($packet)) {
            fclose($sock);
            return null;
        }

        $resp = @fread($sock, 4096);
        fclose($sock);
        if (!is_string($resp) || strlen($resp) < 12) {
            return null;
        }

        return self::parseResponse($resp, substr($packet, 0, 2));
    }

    /**
     * @return string|null
     */
    public static function buildQuery(string $name): ?string
    {
        $name = strtolower(rtrim(trim($name), '.'));
        if ($name === '' || strlen($name) > 253) {
            return null;
        }

        $qname = '';
        foreach (explode('.', $name) as $label) {
            $len = strlen($label);
            if ($len === 0 || $len > 63 || preg_match('/^[a-z0-9-]+$/', $label) !== 1) {
                return null;
            }
            $qname .= chr($len) . $label;
        }
        $qname .= "\x00";

        // Random 16-bit id, flags: RD=1, QDCOUNT=1.
        return random_bytes(2) . "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" . $qname . "\x00\x01\x00\x01";
    }

    /**
     * @param string $raw
     * @param string $queryIdFirst2Bytes
     * @return array{status: string, ips: list<string>}|null
     */
    public static function parseResponse(string $raw, string $queryIdFirst2Bytes): ?array
    {
        if (strlen($raw) < 12 || strlen($queryIdFirst2Bytes) !== 2) {
            return null;
        }
        if (!hash_equals($queryIdFirst2Bytes, substr($raw, 0, 2))) {
            return null;
        }

        $flags = self::u16($raw, 2);
        if ($flags === null || ($flags & 0x8000) === 0) {
            return null; // not a response (QR bit unset)
        }

        $rcode = $flags & 0x0F;
        $status = $rcode === 0 ? 'ok' : ($rcode === 3 ? 'nxdomain' : ($rcode === 2 ? 'servfail' : ($rcode === 5 ? 'refused' : 'rcode_' . $rcode)));
        if ($rcode !== 0) {
            return ['status' => $status, 'ips' => []];
        }

        $qdcount = self::u16($raw, 4) ?? 0;
        $ancount = self::u16($raw, 6) ?? 0;

        $offset = 12;
        for ($i = 0; $i < $qdcount; $i++) {
            $offset = self::skipName($raw, $offset);
            if ($offset === null) {
                return null;
            }
            $offset += 4; // QTYPE + QCLASS
            if ($offset > strlen($raw)) {
                return null;
            }
        }

        $ips = [];
        for ($i = 0; $i < $ancount; $i++) {
            $offset = self::skipName($raw, $offset);
            if ($offset === null) {
                break;
            }
            if ($offset + 10 > strlen($raw)) {
                break;
            }
            $type = self::u16($raw, $offset) ?? 0;
            $rdlength = self::u16($raw, $offset + 8) ?? 0;
            $rdata = $offset + 10;
            if ($type === self::TYPE_A && $rdlength === 4 && $rdata + 4 <= strlen($raw)) {
                $ips[] = sprintf('%u.%u.%u.%u', ord($raw[$rdata]), ord($raw[$rdata + 1]), ord($raw[$rdata + 2]), ord($raw[$rdata + 3]));
            }
            // CNAME (and others) are skipped; filtering resolvers normally
            // answer block-page checks with a direct A record.
            $offset = $rdata + $rdlength;
        }

        return ['status' => $status, 'ips' => $ips];
    }

    private static function u16(string $buf, int $offset): ?int
    {
        if ($offset + 2 > strlen($buf)) {
            return null;
        }
        $v = unpack('n', substr($buf, $offset, 2));
        return is_array($v) ? (int) $v[1] : null;
    }

    /**
     * @return int|null
     */
    private static function skipName(string $buf, int $offset): ?int
    {
        while (true) {
            if ($offset >= strlen($buf)) {
                return null;
            }
            $len = ord($buf[$offset]);
            if ($len === 0) {
                return $offset + 1;
            }
            if (($len & 0xC0) === 0xC0) {
                return $offset + 2;
            }
            $offset += 1 + $len;
        }
    }
}
