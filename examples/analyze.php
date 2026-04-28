<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Phpfastcache\CacheManager;
use Phpfastcache\Config\ConfigurationOption;
use SafeSurf\Cache\PhpFastCacheAdapter;
use SafeSurf\Config;
use SafeSurf\SafeSurf;

$url = $argv[1] ?? 'example.com';

$pool = CacheManager::getInstance('Files', new ConfigurationOption([
    'path' => __DIR__ . '/../storage/cache',
]));

$cache = new PhpFastCacheAdapter($pool);
$config = new Config(cache: $cache);

$result = SafeSurf::analyze($url, $config);

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;

