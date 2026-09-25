<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\ValueObject\PhpVersion;
use Rector\Set\ValueObject\LevelSetList;

return RectorConfig::configure()
   ->withPaths([
      __DIR__ . '/src',
      __DIR__ . '/tests'
   ])
   ->withPhpVersion(PhpVersion::PHP_80)
   ->withSets([
      LevelSetList::UP_TO_PHP_80,
   ]);;
