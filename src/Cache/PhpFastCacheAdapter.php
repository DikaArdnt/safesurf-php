<?php

declare(strict_types=1);

namespace SafeSurf\Cache;

use DateInterval;
use Phpfastcache\Core\Pool\ExtendedCacheItemPoolInterface;

final class PhpFastCacheAdapter implements CacheInterface
{
    public function __construct(
        private ExtendedCacheItemPoolInterface $pool
    ) {
    }

    public function getJson(string $key): mixed
    {
        $item = $this->pool->getItem($this->normalizeKey($key));
        if (!$item->isHit()) {
            return null;
        }

        $raw = $item->get();
        if (!is_string($raw) || $raw === '') {
            return null;
        }

        try {
            return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }
    }

    public function setJson(string $key, mixed $value, int $ttlSeconds): void
    {
        $item = $this->pool->getItem($this->normalizeKey($key));
        $item->set(json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        if ($ttlSeconds > 0) {
            $item->expiresAfter(new DateInterval("PT{$ttlSeconds}S"));
        }
        $this->pool->save($item);
    }

    private function normalizeKey(string $key): string
    {
        $key = preg_replace('/[^A-Za-z0-9_.-]/', '_', $key) ?? $key;
        if ($key === '') {
            $key = 'safesurf';
        }
        return $key;
    }
}
