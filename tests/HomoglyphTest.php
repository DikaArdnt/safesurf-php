<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\Homoglyph;

final class HomoglyphTest extends TestCase
{
    public function testPlainAsciiDomainIsNotHomoglyph(): void
    {
        $this->assertFalse(Homoglyph::analyze('example.com')['has_homoglyph']);
    }

    public function testMixedLatinCyrillicDetected(): void
    {
        // xn--pple-43d.com decodes to аpple.com with a Cyrillic 'а'.
        $out = Homoglyph::analyze('xn--pple-43d.com');
        $this->assertTrue($out['has_homoglyph']);
        $this->assertContains('latin', $out['mixed_scripts']);
        $this->assertContains('cyrillic', $out['mixed_scripts']);
    }

    public function testMixedLatinGreekDetected(): void
    {
        // οoogle.com — Greek omicron followed by Latin letters.
        $out = Homoglyph::analyze('οoogle.com');
        $this->assertTrue($out['has_homoglyph']);
        $this->assertContains('greek', $out['mixed_scripts']);
    }

    public function testSingleScriptIdnNotFlagged(): void
    {
        // münchen.de — pure Latin script with diacritics, legitimate IDN.
        $this->assertFalse(Homoglyph::analyze('xn--mnchen-3ya.de')['has_homoglyph']);
        // Pure Cyrillic label (рф is the .рф TLD in punycode).
        $this->assertFalse(Homoglyph::analyze('xn--p1ai')['has_homoglyph']);
    }

    public function testFullwidthLookalikeDetected(): void
    {
        $out = Homoglyph::analyze('ａpple.com');
        $this->assertTrue($out['has_homoglyph']);
        $this->assertNotEmpty($out['fullwidth_chars']);
    }

    public function testBackwardCompatibleHelper(): void
    {
        $this->assertTrue(Homoglyph::hasHomoglyphs('xn--pple-43d.com'));
        $this->assertFalse(Homoglyph::hasHomoglyphs('xn--mnchen-3ya.de'));
    }
}
