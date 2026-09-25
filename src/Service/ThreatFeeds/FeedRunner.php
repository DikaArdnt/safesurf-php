<?php

declare(strict_types=1);

namespace SafeSurf\Service\ThreatFeeds;

use SafeSurf\Config;

final class FeedRunner
{
    /** @var array<class-string, array{description: string, category: string}> */
    private static array $descriptions = [];

    /**
     * @return array{enabled_feeds: list<string>, results: list<array<string, mixed>>}
     */
    public static function run(string $normalizedUrl, Config $config): array
    {
        $config->threatFeeds ??= new ThreatFeeds();
        $feeds = self::resolveFeeds($config->threatFeeds);

        $results = [];
        $enabled = [];
        foreach ($feeds as $feed) {
            $enabled[] = $feed->name();
            $results[] = self::runFeed($feed, $normalizedUrl, $config, $config->threatFeeds);
        }

        return ['enabled_feeds' => $enabled, 'results' => $results];
    }

    /**
     * @return array{description: string, category: string}
     */
    public static function describeFeed(object $feed): array
    {
        $class = $feed::class;
        if (isset(self::$descriptions[$class])) {
            return self::$descriptions[$class];
        }

        $doc = (new \ReflectionClass($feed))->getDocComment();
        $summaryLines = [];
        $category = 'external';
        $summaryDone = false;

        if (is_string($doc) && $doc !== '') {
            foreach (explode("\n", $doc) as $line) {
                $line = trim((string) preg_replace('/^\s*\/?\*+\/?\s?/', '', $line));
                if ($line === '' || $line === '/**' || $line === '*/') {
                    if ($summaryLines !== []) {
                        $summaryDone = true;
                    }
                    continue;
                }
                if ($line[0] === '@') {
                    if (preg_match('/^@feed-category\s+(\S+)/', $line, $m) === 1) {
                        $category = (string) $m[1];
                    }
                    continue;
                }
                if (!$summaryDone) {
                    $summaryLines[] = $line;
                }
            }
        }

        $description = implode(' ', $summaryLines);
        $meta = [
            'description' => $description !== '' ? $description : $feed->name(),
            'category' => $category,
        ];
        self::$descriptions[$class] = $meta;
        return $meta;
    }

    /**
     * @return list<ThreatFeedInterface>
     */
    private static function resolveFeeds(ThreatFeeds $setup): array
    {
        $feeds = [];
        if ($setup->enablePhishTank) {
            $feeds[] = new PhishTank();
        }
        foreach ($setup->plugins as $plugin) {
            if ($plugin instanceof ThreatFeedInterface) {
                $feeds[] = $plugin;
            }
        }

        // Dedupe by feed name: first occurrence wins.
        $seen = [];
        $unique = [];
        foreach ($feeds as $feed) {
            $name = $feed->name();
            if (!is_string($name) || $name === '' || isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $unique[] = $feed;
        }
        return $unique;
    }

    /**
     * @return array<string, mixed>
     */
    private static function runFeed(ThreatFeedInterface $feed, string $url, Config $config, ThreatFeeds $setup): array
    {
        $meta = self::describeFeed($feed);
        $name = $feed->name();
        $cacheKey = "threat_feed:$name:" . sha1($url);

        $entry = [
            'feed' => $name,
            'description' => $meta['description'],
            'category' => $meta['category'],
            'from_external_plugin' => in_array($feed, $setup->plugins, true),
            'checked' => false,
            'error' => null,
            'listed' => false,
            'severity' => 'info',
            'detail' => null,
        ];

        if ($config->cache !== null) {
            $cached = $config->cache->getJson($cacheKey);
            if (is_array($cached) && array_key_exists('detail', $cached)) {
                $entry['from_cache'] = true;
                return self::finalize($entry, $cached['detail']);
            }
        }

        try {
            $val = $feed->check($url, $config);
        } catch (\Throwable $e) {
            $entry['error'] = $e->getMessage();
            return $entry;
        }

        $ttl = max(1, (int) $setup->option($name, 'ttl', $setup->ttlSeconds));
        if ($config->cache !== null && $val !== null) {
            $config->cache->setJson($cacheKey, ['detail' => $val], $ttl);
        }
        if ($val !== null) {
            $entry['from_cache'] = false;
        }

        return self::finalize($entry, $val);
    }

    /**
     * @param array<string, mixed> $entry
     * @return array<string, mixed>
     */
    private static function finalize(array $entry, ?array $val): array
    {
        if ($val === null) {
            $entry['error'] ??= 'not checked (feed unavailable or host not applicable)';
            return $entry;
        }

        $entry['checked'] = true;
        $entry['listed'] = !empty($val['listed']);
        $entry['detail'] = $val;

        $severity = $val['severity'] ?? ($entry['listed'] ? 'blocked' : 'info');
        $entry['severity'] = is_string($severity) ? $severity : 'info';
        if (isset($val['category']) && is_string($val['category']) && $val['category'] !== '') {
            $entry['category'] = $val['category'];
        }

        return $entry;
    }
}
