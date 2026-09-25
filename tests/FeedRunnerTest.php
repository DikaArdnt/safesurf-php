<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Analyzer\ResultScorer;
use SafeSurf\Config;
use SafeSurf\Service\ThreatFeeds\FeedRunner;
use SafeSurf\Service\ThreatFeeds\ThreatFeedInterface;
use SafeSurf\Service\ThreatFeeds\ThreatFeeds;

/**
 * Blocks URLs listed in the fictional Acme blocklist used for plugin tests.
 *
 * @feed-category test-blocklist
 */
class FakeAcmeBlocklist implements ThreatFeedInterface
{
    public bool $throw = false;
    public bool $returnNull = false;

    public function name(): string
    {
        return 'acme-blocklist';
    }

    public function check(string $url, Config $config): ?array
    {
        if ($this->throw) {
            throw new \RuntimeException('acme exploded');
        }
        if ($this->returnNull) {
            return null;
        }
        return [
            'listed' => str_contains($url, 'bad.example'),
            'severity' => 'phishing',
            'source' => 'acme-fixture',
        ];
    }
}

final class FeedRunnerTest extends TestCase
{
    public function testExternalPluginPhpDocInjectedIntoResult(): void
    {
        $config = new Config(
            threatFeeds: (new ThreatFeeds())->withoutBuiltIns()->addFeed(new FakeAcmeBlocklist())
        );

        $out = FeedRunner::run('https://bad.example/login', $config);

        $this->assertSame(['acme-blocklist'], $out['enabled_feeds']);
        $this->assertCount(1, $out['results']);

        $entry = $out['results'][0];
        $this->assertSame('acme-blocklist', $entry['feed']);
        // PHPDoc summary of the plugin class, injected into the result.
        $this->assertSame(
            'Blocks URLs listed in the fictional Acme blocklist used for plugin tests.',
            $entry['description']
        );
        // @feed-category tag from the PHPDoc.
        $this->assertSame('test-blocklist', $entry['category']);
        $this->assertTrue($entry['from_external_plugin']);
        $this->assertTrue($entry['checked']);
        $this->assertTrue($entry['listed']);
        $this->assertSame('phishing', $entry['severity']);
        $this->assertSame('acme-fixture', $entry['detail']['source'] ?? null);
    }

    public function testPluginReturningNullMarkedUnchecked(): void
    {
        $plugin = new FakeAcmeBlocklist();
        $plugin->returnNull = true;
        $config = new Config(threatFeeds: (new ThreatFeeds())->withoutBuiltIns()->addFeed($plugin));

        $out = FeedRunner::run('https://example.org/', $config);
        $entry = $out['results'][0];

        $this->assertFalse($entry['checked']);
        $this->assertNotNull($entry['error']);
        $this->assertFalse($entry['listed']);
    }

    public function testPluginThrowingIsContained(): void
    {
        $plugin = new FakeAcmeBlocklist();
        $plugin->throw = true;
        $config = new Config(threatFeeds: (new ThreatFeeds())->withoutBuiltIns()->addFeed($plugin));

        $out = FeedRunner::run('https://example.org/', $config);
        $entry = $out['results'][0];

        $this->assertFalse($entry['checked']);
        $this->assertSame('acme exploded', $entry['error']);
    }

    public function testBuiltInFeedsAbsentWhenDisabled(): void
    {
        $config = new Config(threatFeeds: (new ThreatFeeds())->withoutBuiltIns());
        $out = FeedRunner::run('https://example.org/', $config);
        $this->assertSame([], $out['enabled_feeds']);
        $this->assertSame([], $out['results']);
    }

    public function testBuiltInFeedDescriptionComesFromClassPhpDoc(): void
    {
        // Default setup: PhishTank on.
        $out = FeedRunner::run('https://example.org/', new Config());

        $this->assertContains('phishtank', $out['enabled_feeds']);
        $entry = $out['results'][0];
        $this->assertSame('phishtank', $entry['feed']);
        $this->assertStringContainsString('Community-driven phishing database', $entry['description']);
        $this->assertSame('phishing', $entry['category']);
        $this->assertFalse($entry['from_external_plugin']);
        // The real network call may fail in CI — unchecked is acceptable.
        $this->assertArrayHasKey('checked', $entry);
    }

    public function testNonPluginObjectsIgnored(): void
    {
        $plugin = new FakeAcmeBlocklist();
        // Non-interface entries can only appear via direct property writes;
        // the runner must skip them.
        $setup = (new ThreatFeeds())->withoutBuiltIns();
        $setup->plugins = [new \stdClass(), $plugin];
        $config = new Config(threatFeeds: $setup);

        $out = FeedRunner::run('https://example.org/', $config);
        $this->assertSame(['acme-blocklist'], $out['enabled_feeds']);
    }

    public function testScorerScoresPluginFeedNotPhishtankTwice(): void
    {
        $resp = $this->minimalResp();
        $resp['threat_feeds'] = [
            'enabled_feeds' => ['phishtank', 'acme-blocklist'],
            'results' => [
                // phishtank listed here but 'phishing' field is null — the
                // feed entry must be skipped to avoid double counting.
                ['feed' => 'phishtank', 'checked' => true, 'listed' => true, 'severity' => 'phishing', 'category' => 'phishing'],
                ['feed' => 'acme-blocklist', 'checked' => true, 'listed' => true, 'severity' => 'phishing', 'category' => 'test-blocklist'],
                ['feed' => 'unlisted-feed', 'checked' => true, 'listed' => false, 'severity' => 'blocked', 'category' => 'x'],
            ],
        ];

        $result = ResultScorer::generate($resp);
        $badReasons = implode(' | ', $result['reasons']['bad_reasons']);
        $this->assertStringContainsString("Threat feed 'acme-blocklist' (test-blocklist)", $badReasons);
        $this->assertStringNotContainsString('phishtank', $badReasons);
        // phishing(70) applied exactly once; rank-0 base risk (+10) included.
        $this->assertSame(80, $result['risk_score']);
    }

    private function minimalResp(): array
    {
        return [
            'url' => 'https://example.org/',
            'domain' => 'example.org',
            'features' => [
                'rank' => 0,
                'tld' => ['tld' => 'org', 'is_trusted_tld' => false, 'is_risky_tld' => false, 'is_icann' => true, 'is_hosting_platform' => false],
                'url' => [
                    'url_shortener' => false, 'uses_ip' => false, 'contains_punycode' => false,
                    'too_long' => false, 'too_deep' => false, 'has_homoglyph' => false,
                    'subdomain_count' => 0,
                    'keywords' => ['has_keywords' => false, 'found' => [], 'categories' => []],
                ],
                'subdomain' => [],
            ],
            'infrastructure' => ['nameservers_valid' => true, 'mx_records_valid' => true, 'ip_addresses' => [], 'ns_hosts' => [], 'mx_hosts' => []],
            'domain_info' => null,
            'analysis' => [
                'redirection_result' => ['is_redirected' => false, 'chain_length' => 1, 'chain' => [], 'final_url' => '', 'final_url_domain' => '', 'has_domain_jump' => false],
                'http_status' => ['code' => 200, 'text' => 'OK', 'success' => true, 'is_redirect' => false],
                'is_hsts_supported' => false,
            ],
            'ssl_info' => [],
            'tls_info' => [],
            'content_data' => null,
            'domain_randomness' => [],
            'homoglyph_result' => null,
            'correlation' => null,
            'typosquat_result' => ['is_suspicious' => false],
            'phishing' => null,
            'threat_feeds' => null,
        ];
    }
}
