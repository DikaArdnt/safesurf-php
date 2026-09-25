<?php

declare(strict_types=1);

namespace SafeSurf\Service\ThreatFeeds;

use SafeSurf\Config;

final class ThreatFeeds
{
    /** @var list<ThreatFeedInterface> external plugins, in registration order */
    public array $plugins = [];

    /** Enable the PhishTank feed (community phishing database, phishtank.com). */
    public bool $enablePhishTank = true;

    /**
     * Optional PhishTank application key. Without it the API works but is
     * rate-limited; PhishTank asks apps to identify themselves.
     */
    public ?string $phishTankApiKey = null;

    /** User-Agent sent on PhishTank API calls. */
    public string $phishTankUserAgent = 'phishtank/SafeSurfPHP';

    /** Shared cache TTL (seconds) for every feed result; per-feed override via setOption(name, 'ttl', ...). */
    public int $ttlSeconds = 10800;

    /** @var array<string, array<string, mixed>> per-feed options keyed by feed name() — the extension point for feed-specific settings */
    public array $options = [];

    public function addFeed(ThreatFeedInterface ...$feeds): static
    {
        foreach ($feeds as $feed) {
            $name = $feed->name();
            if (!is_string($name) || $name === '' || $this->pluginIndex($name) !== null) {
                continue;
            }
            $this->plugins[] = $feed;
        }
        return $this;
    }

    public function removeFeed(string $name): static
    {
        $index = $this->pluginIndex($name);
        if ($index !== null) {
            array_splice($this->plugins, $index, 1);
            return $this;
        }
        if ($name === 'phishtank') {
            $this->enablePhishTank = false;
        }
        return $this;
    }

    public function hasFeed(string $name): bool
    {
        if ($this->pluginIndex($name) !== null) {
            return true;
        }
        return ($name === 'phishtank' && $this->enablePhishTank);
    }

    public function feed(string $name): ?ThreatFeedInterface
    {
        $index = $this->pluginIndex($name);
        if ($index !== null) {
            return $this->plugins[$index];
        }
        if ($name === 'phishtank' && $this->enablePhishTank) {
            return new PhishTank();
        }
        return null;
    }

    public function withPhishTank(bool $enable = true, ?string $apiKey = null, ?string $userAgent = null): static
    {
        $this->enablePhishTank = $enable;
        if ($apiKey !== null) {
            $this->phishTankApiKey = $apiKey;
        }
        if ($userAgent !== null) {
            $this->phishTankUserAgent = $userAgent;
        }
        return $this;
    }

    public function withoutBuiltIns(): static
    {
        $this->enablePhishTank = false;
        return $this;
    }

    public function withTtl(int $seconds): static
    {
        $this->ttlSeconds = max(1, $seconds);
        return $this;
    }

    public function setOption(string $feedName, string $key, mixed $value): static
    {
        $this->options[$feedName][$key] = $value;
        return $this;
    }

    public function option(string $feedName, string $key, mixed $default = null): mixed
    {
        return $this->options[$feedName][$key] ?? $default;
    }

    private function pluginIndex(string $name): ?int
    {
        foreach ($this->plugins as $i => $plugin) {
            if ($plugin instanceof ThreatFeedInterface && $plugin->name() === $name) {
                return $i;
            }
        }
        return null;
    }
}
