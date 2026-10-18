<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\TldSignals;
use SafeSurf\Checks\UrlSignals;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Service\Rank;

final class ShortenerAndRankTest extends TestCase
{
    public function testDataFilesGet(): void
    {
        $shorteners = DataFiles::get('url_shorteners');
        $this->assertIsArray($shorteners);
        $this->assertArrayHasKey('bit.ly', $shorteners);

        $shortPaths = DataFiles::get('short_link_paths');
        $this->assertIsArray($shortPaths);
        $this->assertSame($shortPaths, DataFiles::shortLinkPaths());

        $this->assertNull(DataFiles::get('non_existent_key'));
    }

    public function testUrlSignalsIsShortener(): void
    {
        $this->assertTrue(UrlSignals::isUrlShortener('bit.ly'));
        $this->assertTrue(UrlSignals::isUrlShortener('wa.me'));
        $this->assertFalse(UrlSignals::isUrlShortener('google.com'));

        // Short link path checking
        $this->assertTrue(UrlSignals::isUrlShortener('flowcode.com', 'https://flowcode.com/p/123456'));
    }

    public function testRankLookupDefaultConfig(): void
    {
        $rank = Rank::lookup('google.com');
        $this->assertGreaterThan(0, $rank);

        $zeroRank = Rank::lookup('non-existent-random-domain-12345.xyz');
        $this->assertSame(0, $zeroRank);
    }

    public function testTldSignalsDefaultConfigAndCheckAlias(): void
    {
        $info = TldSignals::info('example.gov');
        $this->assertSame('gov', $info['tld']);
        $this->assertTrue($info['trusted']);

        $check = TldSignals::check('example.gov');
        $this->assertSame($info, $check);
    }
}
