<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Analyzer\Analyzer;
use SafeSurf\Config;

final class AnalyzerSmokeTest extends TestCase
{
    public function testInvalidUrl(): void
    {
        $out = Analyzer::analyze('not a url');
        $this->assertArrayHasKey('error', $out);
    }

    public function testAnalyzeIpUrl(): void
    {
        $config = new Config(publicSuffixListPath: __DIR__ . '/../storage/test_psl.dat');
        $out = Analyzer::analyze('https://1.1.1.1', $config);
        $this->assertArrayHasKey('url', $out);
        $this->assertArrayHasKey('domain', $out);
        $this->assertArrayHasKey('result', $out);
        $this->assertArrayHasKey('performance', $out);
    }
}

