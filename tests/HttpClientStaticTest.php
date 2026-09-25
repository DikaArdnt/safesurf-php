<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Config;
use SafeSurf\Util\HttpClient;

final class HttpClientStaticTest extends TestCase
{
    public function testPrivateIpv4Ranges(): void
    {
        foreach (['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.5', '169.254.169.254', '0.0.0.0', '100.64.0.1', '::1', 'fe80::1', 'fd12:3456::1'] as $ip) {
            $this->assertTrue(HttpClient::isPrivateIp($ip), "$ip should be private");
        }
    }

    public function testPublicIpsNotPrivate(): void
    {
        foreach (['8.8.8.8', '1.1.1.1', '93.184.216.34', '2001:4860:4860::8888'] as $ip) {
            $this->assertFalse(HttpClient::isPrivateIp($ip), "$ip should be public");
        }
    }

    public function testIpv4MappedIpv6TreatedAsPrivate(): void
    {
        $this->assertTrue(HttpClient::isPrivateIp('::ffff:127.0.0.1'));
        $this->assertTrue(HttpClient::isPrivateIp('::ffff:169.254.169.254'));
        $this->assertTrue(HttpClient::isPrivateIp('::ffff:192.168.0.1'));
        // A mapped *public* IPv4 stays public.
        $this->assertFalse(HttpClient::isPrivateIp('::ffff:8.8.8.8'));
    }

    public function testNonHttpSchemesBlocked(): void
    {
        $config = new Config();

        $ftp = HttpClient::request('GET', 'ftp://example.com/file', $config);
        $this->assertSame('blocked_scheme', $ftp['error']);

        $gopher = HttpClient::request('GET', 'gopher://example.com/x', $config);
        $this->assertSame('blocked_scheme', $gopher['error']);
    }
}
