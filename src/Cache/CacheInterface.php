<?php

declare(strict_types=1);

namespace SafeSurf\Cache;

interface CacheInterface
{
    public function getJson(string $key): mixed;

    public function setJson(string $key, mixed $value, int $ttlSeconds): void;
}

