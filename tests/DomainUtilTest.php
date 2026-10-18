<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Config;
use SafeSurf\Util\DomainUtil;

final class DomainUtilTest extends TestCase
{
    private function pslPath(): string
    {
        return (new Config())->publicSuffixListPath;
    }

    public function testStandardDomain(): void
    {
        $this->assertSame('example.com', DomainUtil::registrableDomainFromUrl('https://www.example.com/path', $this->pslPath()));
        $this->assertSame('wa.me', DomainUtil::registrableDomainFromUrl('https://wa.me/628123', $this->pslPath()));
        $this->assertSame('bar.vercel.app', DomainUtil::registrableDomainFromUrl('https://foo.bar.vercel.app', $this->pslPath()));
    }

    /**
     * Hosts that are themselves a public/private suffix node used to resolve to
     * an empty registrable domain, which made the analyzer report
     * invalid_domain for legitimate services.
     */
    public function testSuffixNodeHostsResolveToUnderlyingDomain(): void
    {
        $this->assertSame('amazonaws.com', DomainUtil::registrableDomainFromUrl('https://s3.amazonaws.com', $this->pslPath()));
        $this->assertSame('amazonaws.com', DomainUtil::registrableDomainFromUrl('https://amazonaws.com', $this->pslPath()));
        $this->assertSame('cloudfront.net', DomainUtil::registrableDomainFromUrl('https://cloudfront.net', $this->pslPath()));
        $this->assertSame('github.io', DomainUtil::registrableDomainFromUrl('https://github.io', $this->pslPath()));
        $this->assertSame('herokuapp.com', DomainUtil::registrableDomainFromUrl('https://herokuapp.com', $this->pslPath()));
    }

    public function testInvalidHostReturnsNull(): void
    {
        $this->assertNull(DomainUtil::registrableDomainFromUrl('http://not a url', $this->pslPath()));
    }

    public function testIpHostReturnsItself(): void
    {
        $this->assertSame('1.1.1.1', DomainUtil::registrableDomainFromUrl('https://1.1.1.1/', $this->pslPath()));
    }

    public function testTldOfSuffixNodeHostIsIcann(): void
    {
        $t = DomainUtil::tldFromDomain('amazonaws.com', $this->pslPath());
        $this->assertSame('com', $t['tld']);
        $this->assertTrue($t['icann']);

        $t2 = DomainUtil::tldFromDomain('wa.me', $this->pslPath());
        $this->assertSame('me', $t2['tld']);
        $this->assertTrue($t2['icann']);
    }

    public function testNormalizeUrlRejectsControlCharacters(): void
    {
        $this->assertNull(DomainUtil::normalizeUrl("http://example.com\r\nHost: evil.com"));
        $this->assertNull(DomainUtil::normalizeUrl("http://example\0.com"));
        $this->assertSame('http://example.com/path', DomainUtil::normalizeUrl('http://example.com/path'));
    }

    public function testCustomerSitePlatform(): void
    {
        $this->assertSame('weebly.com', DomainUtil::customerSitePlatform('my-shop.weebly.com'));
        $this->assertSame('blogspot.co.id', DomainUtil::customerSitePlatform('myblog.blogspot.co.id'));
        $this->assertSame('my-shop.weebly.com', DomainUtil::customerSite('my-shop.weebly.com'));
        // Reserved subdomain on provider is not a customer site
        $this->assertNull(DomainUtil::customerSite('login.squarespace.com'));
    }

    public function testIpHostnameServices(): void
    {
        $res = DomainUtil::ipHostname('192.168.1.1.nip.io');
        $this->assertNotNull($res);
        $this->assertSame('nip.io', $res['service']);
        $this->assertSame('192.168.1.1', $res['ip']);

        $res2 = DomainUtil::ipHostname('example.com');
        $this->assertNull($res2);
    }

    public function testIsBareUrl(): void
    {
        $this->assertTrue(DomainUtil::isBareUrl('https://example.com'));
        $this->assertTrue(DomainUtil::isBareUrl('https://example.com/'));
        $this->assertFalse(DomainUtil::isBareUrl('https://example.com/page'));
        $this->assertFalse(DomainUtil::isBareUrl('https://example.com/?q=test'));
        $this->assertFalse(DomainUtil::isBareUrl('https://example.com/#anchor'));
    }

    public function testUserContentHost(): void
    {
        $this->assertSame('storage.googleapis.com', DomainUtil::userContentHost('storage.googleapis.com'));
        $this->assertSame('raw.githubusercontent.com', DomainUtil::userContentHost('raw.githubusercontent.com'));
        $this->assertSame('gitlab.com', DomainUtil::userContentHost('sub.gitlab.com'));
        $this->assertNull(DomainUtil::userContentHost('example.com'));
    }

    public function testRegistrableDomainDefaultPslPath(): void
    {
        $this->assertSame('example.com', DomainUtil::registrableDomainFromUrl('https://www.example.com/path'));
        $this->assertSame('wa.me', DomainUtil::registrableDomainFromUrl('https://wa.me/628123'));
        $t = DomainUtil::tldFromDomain('example.com');
        $this->assertSame('com', $t['tld']);
        $this->assertTrue($t['icann']);
    }
}
