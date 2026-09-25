<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\SubdomainSignals;
use SafeSurf\Config;

final class SubdomainSignalsTest extends TestCase
{
    private Config $config;

    protected function setUp(): void
    {
        $this->config = new Config();
    }

    public function testSensitiveLabelDetected(): void
    {
        $out = SubdomainSignals::analyze('https://login.example.com/', 'example.com', $this->config);
        $this->assertTrue($out['has_sensitive_label']);
        $this->assertSame('auth', $out['sensitive_labels']['login'] ?? null);
        $this->assertFalse($out['has_brand_impersonation']);
    }

    public function testMultipleSensitiveLabels(): void
    {
        $out = SubdomainSignals::analyze('https://secure.verify.example.com/', 'example.com', $this->config);
        $this->assertTrue($out['has_sensitive_label']);
        $this->assertSame('security', $out['sensitive_labels']['secure'] ?? null);
        $this->assertSame('verification', $out['sensitive_labels']['verify'] ?? null);
        $this->assertSame(2, $out['subdomain_count']);
    }

    public function testBrandInSubdomainDetected(): void
    {
        $out = SubdomainSignals::analyze('https://secure-paypal.example.com/', 'example.com', $this->config);
        $this->assertTrue($out['has_brand_impersonation']);
        $this->assertSame('PayPal', $out['brand_hits'][0]['brand'] ?? null);
        $this->assertSame('paypal', $out['brand_hits'][0]['token'] ?? null);
    }

    public function testBrandTokenInsideCompoundLabel(): void
    {
        $out = SubdomainSignals::analyze('https://account-verify-apple.example.com/', 'example.com', $this->config);
        $this->assertTrue($out['has_brand_impersonation']);
        $tokens = array_column($out['brand_hits'], 'token');
        $this->assertContains('apple', $tokens);
    }

    public function testBrandOnOfficialDomainNotImpersonation(): void
    {
        $out = SubdomainSignals::analyze('https://secure.paypal.com/', 'paypal.com', $this->config);
        $this->assertFalse($out['has_brand_impersonation']);
    }

    public function testPlainSubdomainNoSignals(): void
    {
        $out = SubdomainSignals::analyze('https://blog.example.com/', 'example.com', $this->config);
        $this->assertFalse($out['has_sensitive_label']);
        $this->assertFalse($out['has_brand_impersonation']);
        $this->assertSame(['blog'], $out['labels']);
    }

    public function testRootDomainItselfYieldsNoSignals(): void
    {
        $out = SubdomainSignals::analyze('https://example.com/', 'example.com', $this->config);
        $this->assertSame([], $out['labels']);
        $this->assertSame(0, $out['subdomain_count']);
    }

    public function testIpHostSkipped(): void
    {
        $out = SubdomainSignals::analyze('https://1.2.3.4/', '1.2.3.4', $this->config);
        $this->assertSame([], $out['labels']);
    }
}
