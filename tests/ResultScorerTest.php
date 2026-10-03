<?php

declare(strict_types=1);

namespace SafeSurf\Tests;

use PHPUnit\Framework\TestCase;
use SafeSurf\Analyzer\ResultScorer;

final class ResultScorerTest extends TestCase
{
    private function makeResp(array $overrides = []): array
    {
        $base = [
            'url' => 'https://example.org/',
            'domain' => 'example.org',
            'features' => [
                'rank' => 5000,
                'tld' => [
                    'tld' => 'org',
                    'is_trusted_tld' => false,
                    'is_risky_tld' => false,
                    'is_icann' => true,
                    'is_hosting_platform' => false,
                ],
                'url' => [
                    'url_shortener' => false,
                    'uses_ip' => false,
                    'contains_punycode' => false,
                    'too_long' => false,
                    'too_deep' => false,
                    'has_homoglyph' => false,
                    'subdomain_count' => 0,
                    'keywords' => ['has_keywords' => false, 'found' => [], 'categories' => []],
                ],
                'subdomain' => [
                    'labels' => [],
                    'subdomain_count' => 0,
                    'sensitive_labels' => [],
                    'has_sensitive_label' => false,
                    'brand_hits' => [],
                    'has_brand_impersonation' => false,
                ],
            ],
            'infrastructure' => [
                'ip_addresses' => ['93.184.216.34'],
                'nameservers_valid' => true,
                'ns_hosts' => ['ns1.example.org'],
                'mx_records_valid' => true,
                'mx_hosts' => ['mx.example.org'],
            ],
            'domain_info' => [
                'age_days' => 3650,
                'age_human' => '10 years',
                'expiry_days' => 720,
                'expiry_human' => 'expires in 2 years',
                'dnssec' => false,
                'status' => ['ok'],
            ],
            'analysis' => [
                'redirection_result' => [
                    'is_redirected' => false,
                    'chain_length' => 1,
                    'chain' => ['https://example.org/'],
                    'final_url' => 'https://example.org/',
                    'final_url_domain' => 'example.org',
                    'has_domain_jump' => false,
                ],
                'http_status' => ['code' => 200, 'text' => 'OK', 'success' => true, 'is_redirect' => false],
                'is_hsts_supported' => true,
            ],
            'ssl_info' => ['has_tls' => true, 'is_suspicious' => false, 'reasons' => []],
            'tls_info' => ['present' => true, 'hostname_mismatch' => false],
            'content_data' => null,
            'domain_randomness' => ['is_suspicious' => false],
            'homoglyph_result' => null,
            'correlation' => null,
            'typosquat_result' => ['is_suspicious' => false],
            'phishing' => null,
        ];

        return array_replace_recursive($base, $overrides);
    }

    public function testEstablishedSiteIsSafe(): void
    {
        $result = ResultScorer::generate($this->makeResp());
        $this->assertSame('Safe', $result['verdict']);
        $this->assertGreaterThanOrEqual(65, $result['final_score']);
    }

    public function testPhishingComboIsRisky(): void
    {
        $resp = $this->makeResp([
            'features' => [
                'rank' => 0,
                'subdomain' => [
                    'labels' => ['secure-paypal'],
                    'subdomain_count' => 1,
                    'sensitive_labels' => ['secure' => 'security'],
                    'has_sensitive_label' => true,
                    'brand_hits' => [['brand' => 'PayPal', 'token' => 'paypal', 'label' => 'secure-paypal']],
                    'has_brand_impersonation' => true,
                ],
            ],
            'domain_info' => [
                'age_days' => 4,
                'age_human' => '4 days old',
                'expiry_days' => 90,
                'expiry_human' => 'expires in 3 months',
                'status' => ['ok'],
            ],
            'content_data' => [
                'has_login_form' => true,
                'has_forms' => true,
                'forms' => [
                    ['is_external' => true, 'has_password' => true],
                ],
                'brand_check' => ['is_mismatch' => true, 'brand_found' => 'PayPal', 'detected_names' => ['PayPal']],
                'phishing_patterns' => [
                    'login_with_brand_text' => true,
                    'favicon_brand_mismatch' => true,
                    'meta_refresh_external' => false,
                    'brand_names_in_text' => ['PayPal'],
                    'js_signals' => ['has_eval_atob' => true, 'has_form_injection' => false, 'suspicious_score' => 0.4],
                ],
            ],
        ]);

        $result = ResultScorer::generate($resp);
        $this->assertSame('Risky', $result['verdict']);
        $badReasons = implode(' | ', $result['reasons']['bad_reasons']);
        $this->assertStringContainsString('PayPal', $badReasons);
    }

    public function testCorrelationAloneDoesNotFlipEstablishedSite(): void
    {
        // Established, ranked, old domain whose root is parked and whose
        // subdomain serves a login page — suspicious pattern, but the strong
        // reputation must keep the verdict from becoming Risky.
        $resp = $this->makeResp([
            'features' => [
                'rank' => 5000,
                'url' => ['subdomain_count' => 1],
                'subdomain' => [
                    'labels' => ['login'],
                    'subdomain_count' => 1,
                    'sensitive_labels' => ['login' => 'auth'],
                    'has_sensitive_label' => true,
                    'brand_hits' => [],
                    'has_brand_impersonation' => false,
                ],
            ],
            'content_data' => [
                'has_login_form' => true,
                'has_forms' => true,
                'forms' => [['is_external' => false, 'has_password' => true]],
                'brand_check' => ['is_mismatch' => false, 'brand_found' => '', 'detected_names' => []],
                'phishing_patterns' => [
                    'login_with_brand_text' => false,
                    'favicon_brand_mismatch' => false,
                    'meta_refresh_external' => false,
                    'brand_names_in_text' => [],
                    'js_signals' => ['has_eval_atob' => false, 'has_form_injection' => false, 'suspicious_score' => 0.0],
                ],
            ],
            'correlation' => [
                'root' => [
                    'domain' => 'example.org',
                    'reachable' => true,
                    'is_active' => false,
                    'is_parked_or_empty' => true,
                    'status_code' => 200,
                    'redirects_off_domain' => false,
                    'final_domain' => 'example.org',
                    'title' => 'Welcome to nginx!',
                ],
                'shared_infrastructure' => 'same_ip',
                'content_similarity' => 0.1,
                'content_relation' => 'divergent',
                'signals' => [
                    'root_unreachable' => false,
                    'root_inactive' => true,
                    'root_parked_or_empty' => true,
                    'root_redirects_off_domain' => false,
                    'infrastructure_split' => false,
                    'content_divergent' => true,
                ],
            ],
        ]);

        $result = ResultScorer::generate($resp);
        $this->assertNotSame('Risky', $result['verdict']);
        $this->assertSame('Safe', $result['verdict']);
    }

    public function testCorrelationComboWithWeakReputationIsRisky(): void
    {
        // Same parked-root + subdomain login pattern, but now on an unranked,
        // freshly registered domain — the combo must be punished.
        $resp = $this->makeResp([
            'features' => [
                'rank' => 0,
                'url' => ['subdomain_count' => 1],
                'subdomain' => [
                    'labels' => ['login'],
                    'subdomain_count' => 1,
                    'sensitive_labels' => ['login' => 'auth'],
                    'has_sensitive_label' => true,
                    'brand_hits' => [],
                    'has_brand_impersonation' => false,
                ],
            ],
            'domain_info' => [
                'age_days' => 3,
                'age_human' => '3 days old',
                'expiry_days' => 361,
                'expiry_human' => 'expires in 1 year',
                'status' => ['ok'],
            ],
            'content_data' => [
                'has_login_form' => true,
                'has_forms' => true,
                'forms' => [['is_external' => false, 'has_password' => true]],
                'brand_check' => ['is_mismatch' => false, 'brand_found' => '', 'detected_names' => []],
                'phishing_patterns' => [
                    'login_with_brand_text' => false,
                    'favicon_brand_mismatch' => false,
                    'meta_refresh_external' => false,
                    'brand_names_in_text' => [],
                    'js_signals' => ['has_eval_atob' => false, 'has_form_injection' => false, 'suspicious_score' => 0.0],
                ],
            ],
            'correlation' => [
                'root' => [
                    'domain' => 'example.org',
                    'reachable' => true,
                    'is_active' => false,
                    'is_parked_or_empty' => true,
                    'status_code' => 200,
                    'redirects_off_domain' => false,
                    'final_domain' => 'example.org',
                    'title' => 'Welcome to nginx!',
                ],
                'shared_infrastructure' => 'different',
                'content_similarity' => 0.0,
                'content_relation' => 'divergent',
                'signals' => [
                    'root_unreachable' => false,
                    'root_inactive' => true,
                    'root_parked_or_empty' => true,
                    'root_redirects_off_domain' => false,
                    'infrastructure_split' => true,
                    'content_divergent' => true,
                ],
            ],
        ]);

        $result = ResultScorer::generate($resp);
        $this->assertSame('Risky', $result['verdict']);
        $badReasons = implode(' | ', $result['reasons']['bad_reasons']);
        $this->assertStringContainsString('Root domain is unused', $badReasons);
    }

    public function testTlsSuspiciousAndHoldStatusScored(): void
    {
        $resp = $this->makeResp([
            'analysis' => ['is_hsts_supported' => false],
            'ssl_info' => ['has_tls' => true, 'is_suspicious' => true, 'reasons' => ['certificate expired']],
            'tls_info' => ['present' => true, 'hostname_mismatch' => true],
            'domain_info' => [
                'age_days' => 3650,
                'age_human' => '10 years',
                'expiry_days' => 720,
                'expiry_human' => 'expires in 2 years',
                'dnssec' => false,
                'status' => ['clientTransferProhibited', 'clientHold'],
            ],
        ]);

        $result = ResultScorer::generate($resp);
        // TLS-suspicious (20) + hostname mismatch (25) + registry hold (25).
        $this->assertSame(70, $result['risk_score']);
        $badReasons = implode(' | ', $result['reasons']['bad_reasons']);
        $this->assertStringContainsString('certificate expired', $badReasons);
        $this->assertStringContainsString('clientHold', $badReasons);
    }
}
