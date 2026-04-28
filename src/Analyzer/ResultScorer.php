<?php

declare(strict_types=1);

namespace SafeSurf\Analyzer;

final class ResultScorer
{
    public static function generate(array $resp): array
    {
        $neutral = [];
        $good = [];
        $bad = [];
        $trust = 0;
        $risk = 0;

        $rank = (int) (($resp['features']['rank'] ?? 0));
        if ($rank === 0) {
            $bad[] = 'Very low traffic volume.';
            $risk += 20;
        } elseif ($rank > 0 && $rank <= 10000) {
            $good[] = sprintf('Global Giant: Ranked #%d worldwide.', $rank);
            $trust += 90;
        } elseif ($rank > 50000) {
            $good[] = sprintf('Established website with moderate popularity (#%d).', $rank);
            $trust += 50;
        } else {
            $good[] = sprintf('Niche website with standard traffic volume (#%d).', $rank);
            $trust += 20;
        }

        $tldInfo = $resp['features']['tld'] ?? [];
        $isRisky = !empty($tldInfo['is_risky_tld']);
        $isTrusted = !empty($tldInfo['is_trusted_tld']);
        $isIcann = !empty($tldInfo['is_icann']);

        if ($isRisky) {
            $bad[] = 'High-risk domain extension detected (often associated with spam).';
            $risk += 20;
        }

        if ($isTrusted) {
            $good[] = 'High-trust official domain extension (Gov/Edu).';
            $trust += 100;
        } elseif ($isIcann && !$isRisky) {
            $neutral[] = 'Standard, officially recognized domain extension.';
        }

        if (!$isIcann) {
            $bad[] = 'Unregulated or non-standard domain extension.';
            $risk += 30;
        }

        if (!empty($resp['analysis']['is_hsts_supported'])) {
            $good[] = 'Enforces strict HTTPS security (HSTS Enabled).';
            $trust += 20;
        }

        $urlChecks = $resp['features']['url'] ?? [];

        if (!empty($urlChecks['url_shortener'])) {
            $bad[] = 'URL Shortener detected (hides the true destination).';
            $risk += 25;
        }

        if (!empty($urlChecks['uses_ip'])) {
            $bad[] = 'Raw IP address usage detected (common evasion tactic).';
            $risk += 100;
        }

        if (!empty($urlChecks['contains_punycode'])) {
            $bad[] = 'Punycode characters detected (potential phishing spoof).';
            $risk += 100;
        }

        if (!empty($urlChecks['too_deep'])) {
            $bad[] = 'Excessively deep URL path (potential request hiding).';
            $risk += 30;
        }

        if (!empty($urlChecks['too_long'])) {
            $bad[] = 'URL length exceeds standard limits (potential buffer overflow/hiding).';
            $risk += 20;
        }

        $subCount = (int) ($urlChecks['subdomain_count'] ?? 0);
        if ($subCount > 2) {
            $bad[] = 'Suspicious number of subdomains detected.';
            $risk += 15;
        }

        $kw = $urlChecks['keywords'] ?? [];
        $kwFound = $kw['found'] ?? [];
        if (!empty($kw['has_keywords']) && is_array($kwFound) && count($kwFound) > 0) {
            $bad[] = sprintf('Sensitive security keywords found in URL: %s', implode(', ', $kwFound));
            $risk += 10;
        }

        if (empty($resp['infrastructure']['nameservers_valid'])) {
            $bad[] = 'Incomplete or missing DNS configuration.';
            $risk += 10;
        }

        if (empty($resp['infrastructure']['mx_records_valid'])) {
            $neutral[] = 'No email server configured for this domain.';
            $risk += 5;
        }

        $di = $resp['domain_info'] ?? null;
        if (is_array($di)) {
            $ageDays = (int) ($di['age_days'] ?? 0);
            $ageHuman = (string) ($di['age_human'] ?? '');
            if ($ageDays > 0 && $ageDays <= 30) {
                $bad[] = sprintf('Newly created domain (%s old). High Risk.', $ageHuman);
                $risk += 25;
            } elseif ($ageDays > 0 && $ageDays <= 365) {
                $bad[] = sprintf('Young domain (%s old). Use caution.', $ageHuman);
                $risk += 15;
            } elseif ($ageDays > 0 && $ageDays <= 1825) {
                $neutral[] = sprintf('Operational for %s.', $ageHuman);
                $trust += 5;
            } elseif ($ageDays > 0) {
                $good[] = sprintf('Long-standing domain history (%s).', $ageHuman);
                $trust += 15;
            }

            if (!empty($di['dnssec'])) {
                $good[] = 'Advanced DNS security enabled (DNSSEC).';
                $trust += 10;
            } else {
                $neutral[] = 'Standard DNS security (DNSSEC not enabled).';
            }
        }

        $redir = $resp['analysis']['redirection_result'] ?? [];
        if (!empty($redir['is_redirected'])) {
            $chainLen = (int) ($redir['chain_length'] ?? 0);
            if ($chainLen > 3) {
                $bad[] = sprintf('Excessive redirection chain detected (%d hops).', $chainLen);
                $risk += 40;
            }
            if (!empty($redir['has_domain_jump'])) {
                $bad[] = 'Cross-domain redirection detected (destination differs from source).';
                $finalHost = (string) ($redir['final_url_domain'] ?? '');
                if ($finalHost !== '') {
                    $bad[] = sprintf('Final Destination: %s. Check Report for more info.', $finalHost);
                }
                $risk += 50;
            }
        }

        if (!empty($urlChecks['has_homoglyph'])) {
            $bad[] = 'Homoglyph attack detected (deceptive visual characters).';
            $risk += 60;
        }

        $typo = $resp['typosquat_result'] ?? [];
        if (is_array($typo) && !empty($typo['is_suspicious'])) {
            if (!empty($typo['is_combo_squat'])) {
                $bad[] = sprintf(
                    "Combo-squatting detected: domain contains brand name '%s' but is not the official site.",
                    (string) ($typo['matched_brand'] ?? '')
                );
                $risk += 20;
            } else {
                $bad[] = sprintf(
                    "Typosquatting detected: domain closely resembles '%s' (%d character difference).",
                    (string) ($typo['matched_domain'] ?? ''),
                    (int) ($typo['distance'] ?? 0)
                );
                $risk += 40;
            }
        }

        $phish = $resp['phishing'] ?? null;
        if (is_array($phish) && !empty($phish['in_database'])) {
            if (!empty($phish['valid']) && !empty($phish['verified'])) {
                $bad[] = 'CONFIRMED PHISHING: This is a verified phishing URL.';
                $risk += 200;
                if (!empty($phish['target'])) {
                    $bad[] = 'Reported Target: ' . (string) $phish['target'];
                }
            } elseif (!empty($phish['valid']) && empty($phish['verified'])) {
                $bad[] = 'This URL has been reported as phishing, awaiting community verification.';
                $risk += 70;
            }
        }

        $content = $resp['content_data'] ?? null;
        if (is_array($content)) {
            if (!empty($content['has_login_form'])) {
                $isEstablished = $rank > 0 && $rank <= 100000;
                $isOld = is_array($di) && (int) ($di['age_days'] ?? 0) > 365;
                if (!$isEstablished && !$isOld) {
                    $bad[] = 'SUSPICIOUS: Login form detected on a new or unranked domain.';
                    $risk += 50;
                } else {
                    $neutral[] = 'Page contains a login form.';
                }
            }

            if (!empty($content['has_payment_form'])) {
                $bad[] = 'WARNING: Payment-related fields detected (credit card, CVV, etc.).';
                $risk += 30;
            }

            if (!empty($content['has_personal_form'])) {
                $neutral[] = 'Page requests personal information (address, phone, etc.).';
            }

            if (!empty($content['has_hidden_iframe'])) {
                $bad[] = 'WARNING: Hidden iframe detected (often used for background credential theft or clickjacking).';
                $risk += 40;
            }

            if (!empty($content['has_tracking'])) {
                $neutral[] = 'Background tracking elements (1x1 pixels) detected.';
            }

            $bc = $content['brand_check'] ?? [];
            if (is_array($bc) && !empty($bc['is_mismatch'])) {
                $bad[] = sprintf("BRAND MISMATCH: Page mentions '%s' but is hosted on an unofficial domain.", (string) ($bc['brand_found'] ?? ''));
                $risk += 100;
            } elseif (is_array($bc) && !empty($bc['detected_names'])) {
                $names = $bc['detected_names'];
                if (is_array($names) && count($names) > 0) {
                    $good[] = sprintf('Verified brand matching: %s', implode(', ', $names));
                    $trust += 20;
                }
            }

            if (!empty($content['has_forms']) && !empty($content['forms']) && is_array($content['forms'])) {
                foreach ($content['forms'] as $f) {
                    if (!is_array($f)) {
                        continue;
                    }
                    if (!empty($f['is_external'])) {
                        $bad[] = 'CRITICAL: Form submits data to a different domain (common phishing tactic).';
                        $risk += 80;
                    }
                    if (!empty($f['has_password']) && empty($resp['ssl_info']['has_tls'])) {
                        $bad[] = 'DANGEROUS: Password form detected over insecure connection!';
                        $risk += 200;
                    }
                }
            }
        }

        $risk = self::clamp($risk);
        $trust = self::clamp($trust);

        $final = self::clamp(50 + (int) round(($trust - $risk) * 0.5));
        $verdict = 'Safe';
        if ($final < 30) {
            $verdict = 'Risky';
        } elseif ($final < 65) {
            $verdict = 'Suspicious';
        }

        return [
            'risk_score' => $risk,
            'trust_score' => $trust,
            'final_score' => $final,
            'verdict' => $verdict,
            'reasons' => [
                'neutral_reasons' => array_values($neutral),
                'good_reasons' => array_values($good),
                'bad_reasons' => array_values($bad),
            ],
        ];
    }

    private static function clamp(int $score): int
    {
        return max(0, min(100, $score));
    }
}

