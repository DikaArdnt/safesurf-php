<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\RootDomainCorrelation;

final class RootDomainCorrelationTest extends TestCase
{
    public function testParkedDetectionByMarker(): void
    {
        $this->assertTrue(RootDomainCorrelation::isParkedOrEmpty('This domain is for sale', 'buy it now'));
        $this->assertTrue(RootDomainCorrelation::isParkedOrEmpty('Welcome to nginx!', ''));
        $this->assertTrue(RootDomainCorrelation::isParkedOrEmpty('Apache2 Ubuntu Default Page', 'it works'));
    }

    public function testEmptyPageDetection(): void
    {
        $this->assertTrue(RootDomainCorrelation::isParkedOrEmpty('', ''));
        $this->assertTrue(RootDomainCorrelation::isParkedOrEmpty('', 'hello world'));
    }

    public function testActiveSiteNotParked(): void
    {
        $this->assertFalse(RootDomainCorrelation::isParkedOrEmpty(
            'Example Corp',
            'We build tools for teams our products include dashboards and reports for managers'
        ));
    }

    public function testTextSimilarityIdentical(): void
    {
        $text = 'welcome to example corp we sell tools and hardware for everyone';
        $this->assertSame(1.0, RootDomainCorrelation::textSimilarity($text, $text));
    }

    public function testTextSimilarityDisjoint(): void
    {
        $a = 'alpha beta gamma delta epsilon zeta eta theta';
        $b = 'one two three four five six seven eight';
        $this->assertSame(0.0, RootDomainCorrelation::textSimilarity($a, $b));
    }

    public function testTextSimilarityPartial(): void
    {
        $a = 'the quick brown fox jumps over the lazy dog near the river bank';
        $b = 'the quick brown fox jumps over the lazy dog far away from here';
        $sim = RootDomainCorrelation::textSimilarity($a, $b);
        $this->assertGreaterThan(0.25, $sim);
        $this->assertLessThan(1.0, $sim);
    }

    public function testCompareInfrastructure(): void
    {
        $this->assertSame('same_ip', RootDomainCorrelation::compareInfrastructure(['93.184.216.34'], ['93.184.216.34']));
        $this->assertSame('same_network', RootDomainCorrelation::compareInfrastructure(['93.184.216.34'], ['93.184.216.99']));
        $this->assertSame('different', RootDomainCorrelation::compareInfrastructure(['93.184.216.34'], ['9.9.9.9']));
        $this->assertSame('unknown', RootDomainCorrelation::compareInfrastructure([], ['9.9.9.9']));
    }

    public function testCompareInfrastructureIpv6(): void
    {
        $this->assertSame('same_network', RootDomainCorrelation::compareInfrastructure(['2606:4700::6810:85e5'], ['2606:4700::6810:9f21']));
        $this->assertSame('different', RootDomainCorrelation::compareInfrastructure(['2606:4700::6810:85e5'], ['2a00:1450:4009:81f::200e']));
    }

    public function testCorrelateParkedRootWithLoginSubdomain(): void
    {
        $rootData = [
            'domain' => 'example.com',
            'reachable' => true,
            'status_code' => 200,
            'is_active' => false,
            'redirect_chain' => [],
            'redirects_off_domain' => false,
            'final_domain' => 'example.com',
            'title' => 'Welcome to nginx!',
            'text_sample' => 'welcome to nginx',
            'is_parked_or_empty' => true,
        ];
        $subContent = [
            'title' => 'Sign in',
            'text_sample' => 'sign in to your account enter your email and password to continue securely',
        ];

        $out = RootDomainCorrelation::correlate($rootData, $subContent, ['203.0.113.10'], ['198.51.100.7']);

        $this->assertNotNull($out);
        $this->assertTrue($out['signals']['root_inactive']);
        $this->assertTrue($out['signals']['root_parked_or_empty']);
        $this->assertTrue($out['signals']['infrastructure_split']);
        $this->assertSame('different', $out['shared_infrastructure']);
        $this->assertSame('divergent', $out['content_relation']);
    }

    public function testCorrelateHealthyRoot(): void
    {
        $rootData = [
            'domain' => 'example.com',
            'reachable' => true,
            'status_code' => 200,
            'is_active' => true,
            'redirect_chain' => [],
            'redirects_off_domain' => false,
            'final_domain' => 'example.com',
            'title' => 'Example Corp',
            'text_sample' => 'welcome to example corp we sell tools and hardware for everyone',
            'is_parked_or_empty' => false,
        ];
        $subContent = [
            'title' => 'Account',
            'text_sample' => 'welcome to example corp we sell tools and hardware for your account settings',
        ];

        $out = RootDomainCorrelation::correlate($rootData, $subContent, ['93.184.216.34'], ['93.184.216.34']);

        $this->assertFalse($out['signals']['root_inactive']);
        $this->assertFalse($out['signals']['infrastructure_split']);
        $this->assertSame('same_ip', $out['shared_infrastructure']);
        $this->assertNotSame('divergent', $out['content_relation']);
    }

    public function testCorrelateNullRootData(): void
    {
        $this->assertNull(RootDomainCorrelation::correlate(null, null, [], []));
    }
}
