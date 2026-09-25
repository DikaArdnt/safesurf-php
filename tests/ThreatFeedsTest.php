<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Config;
use SafeSurf\Service\ThreatFeeds\FeedRunner;
use SafeSurf\Service\ThreatFeeds\ThreatFeedInterface;
use SafeSurf\Service\ThreatFeeds\ThreatFeeds;

/**
 * Synthetic plugin feed used by the ThreatFeeds setup tests.
 *
 * @feed-category setup-test
 */
class FakeSetupFeed implements ThreatFeedInterface
{
    public ?array $seenOptions = null;

    public function name(): string
    {
        return 'setup-feed';
    }

    public function check(string $url, Config $config): ?array
    {
        $this->seenOptions = [
            'api_key' => $config->threatFeeds?->option('setup-feed', 'api_key'),
            'ttl' => $config->threatFeeds?->option('setup-feed', 'ttl'),
        ];
        return ['listed' => str_contains($url, 'bad.example'), 'severity' => 'blocked'];
    }
}

final class ThreatFeedsTest extends TestCase
{
    public function testAddFeedRegistersAndDedupesByName(): void
    {
        $a = new FakeSetupFeed();
        $b = new FakeSetupFeed();
        $setup = new ThreatFeeds();
        $out = $setup->withoutBuiltIns()->addFeed($a)->addFeed($a, $b);

        $this->assertSame($setup, $out);
        $this->assertSame([$a], $setup->plugins);
        $this->assertTrue($setup->hasFeed('setup-feed'));
        $this->assertSame($a, $setup->feed('setup-feed'));
    }

    public function testRemoveFeedDropsPluginAndDisablesBuiltIn(): void
    {
        $plugin = new FakeSetupFeed();
        $setup = (new ThreatFeeds())->addFeed($plugin);
        $this->assertTrue($setup->hasFeed('phishtank'));
        $this->assertTrue($setup->hasFeed('setup-feed'));

        $setup->removeFeed('setup-feed')->removeFeed('phishtank');

        $this->assertSame([], $setup->plugins);
        $this->assertFalse($setup->hasFeed('setup-feed'));
        $this->assertFalse($setup->hasFeed('phishtank'));
        $this->assertNull($setup->feed('setup-feed'));
    }

    public function testConfigAlwaysHasAThreatFeedsSetup(): void
    {
        $config = new Config();
        $this->assertInstanceOf(ThreatFeeds::class, $config->threatFeeds);
        $this->assertTrue($config->threatFeeds->enablePhishTank);
        $this->assertSame($config->threatFeeds, $config->threatFeedSetup());

        $custom = (new ThreatFeeds())->withoutBuiltIns();
        $pinned = new Config(threatFeeds: $custom);
        $this->assertSame($custom, $pinned->threatFeedSetup());
    }

    public function testWithPhishTankSetsKeyAndUserAgent(): void
    {
        $setup = (new ThreatFeeds())->withPhishTank(true, 'app-key-1', 'my-app/1.0');
        $this->assertTrue($setup->enablePhishTank);
        $this->assertSame('app-key-1', $setup->phishTankApiKey);
        $this->assertSame('my-app/1.0', $setup->phishTankUserAgent);
    }

    public function testConfigAddThreatFeedAppendsToSetup(): void
    {
        $added = new FakeSetupFeed();
        $config = new Config(threatFeeds: (new ThreatFeeds())->withPhishTank(false));

        $config->addThreatFeed($added);
        $out = FeedRunner::run('https://example.org/', $config);

        // PhishTank stays off; the added plugin runs.
        $this->assertSame(['setup-feed'], $out['enabled_feeds']);
        $this->assertTrue($out['results'][0]['from_external_plugin']);
        $this->assertNotNull($added->seenOptions);
        $this->assertFalse($config->threatFeedSetup()->enablePhishTank);
    }

    public function testRunnerUsesAttachedSetupWithPluginsOnly(): void
    {
        $plugin = new FakeSetupFeed();
        $config = new Config(
            threatFeeds: (new ThreatFeeds())->withoutBuiltIns()->addFeed($plugin)
        );

        $out = FeedRunner::run('https://bad.example/x', $config);

        $this->assertSame(['setup-feed'], $out['enabled_feeds']);
        $entry = $out['results'][0];
        $this->assertSame('setup-test', $entry['category']);
        $this->assertTrue($entry['from_external_plugin']);
        $this->assertTrue($entry['checked']);
        $this->assertTrue($entry['listed']);
    }

    public function testConfigHelpersComposeFluently(): void
    {
        $plugin = new FakeSetupFeed();
        $config = new Config();

        $config->addThreatFeed($plugin)
               ->threatFeedSetup()
               ->withPhishTank(false)
               ->setOption('setup-feed', 'api_key', 'k-1');

        $out = FeedRunner::run('https://example.org/', $config);

        $this->assertSame(['setup-feed'], $out['enabled_feeds']);
        $this->assertSame('k-1', $plugin->seenOptions['api_key']);
    }

    public function testRunnerDedupesSameNamePluginsToOneEntry(): void
    {
        $config = new Config(
            threatFeeds: (new ThreatFeeds())
                ->withoutBuiltIns()
                ->addFeed(new FakeSetupFeed(), new FakeSetupFeed())
        );

        $out = FeedRunner::run('https://example.org/', $config);

        $this->assertSame(['setup-feed'], $out['enabled_feeds']);
        $this->assertCount(1, $out['results']);
    }

    public function testPluginReadsPerFeedOptionsAndFeedGetsPerFeedTtl(): void
    {
        $plugin = new FakeSetupFeed();
        $cache = new ArrayCache();
        $config = new Config(
            cache: $cache,
            threatFeeds: (new ThreatFeeds())
                ->withoutBuiltIns()
                ->withTtl(900)
                ->addFeed($plugin)
                ->setOption('setup-feed', 'api_key', 'secret-123')
                ->setOption('setup-feed', 'ttl', 120)
        );

        FeedRunner::run('https://example.org/', $config);

        $this->assertSame('secret-123', $plugin->seenOptions['api_key']);
        $this->assertSame(120, $plugin->seenOptions['ttl']);

        $key = 'threat_feed:setup-feed:' . sha1('https://example.org/');
        $this->assertArrayHasKey($key, $cache->ttls);
        $this->assertSame(120, $cache->ttls[$key]);

        // Second run is served from the per-feed cache entry.
        $second = FeedRunner::run('https://example.org/', $config);
        $this->assertTrue($second['results'][0]['from_cache']);
    }

    public function testFeedWithoutTtlOptionUsesSharedTtl(): void
    {
        $plugin = new FakeSetupFeed();
        $cache = new ArrayCache();
        $config = new Config(
            cache: $cache,
            threatFeeds: (new ThreatFeeds())->withoutBuiltIns()->withTtl(900)->addFeed($plugin)
        );

        FeedRunner::run('https://example.org/', $config);

        $key = 'threat_feed:setup-feed:' . sha1('https://example.org/');
        $this->assertSame(900, $cache->ttls[$key]);
    }

    public function testWithTtlSetsSharedCacheTtl(): void
    {
        $setup = (new ThreatFeeds())
            ->withPhishTank(false)
            ->withTtl(300);

        $this->assertFalse($setup->enablePhishTank);
        $this->assertSame(300, $setup->ttlSeconds);
        $this->assertSame('198.51.100.255', $setup->option('setup-feed', 'missing', '198.51.100.255'));
    }
}
