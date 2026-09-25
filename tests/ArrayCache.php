<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use SafeSurf\Cache\CacheInterface;

final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $store = [];

    /** @var array<string, int> */
    public array $ttls = [];

    public function getJson(string $key): mixed
    {
        return $this->store[$key] ?? null;
    }

    public function setJson(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->store[$key] = $value;
        $this->ttls[$key] = $ttlSeconds;
    }
}
