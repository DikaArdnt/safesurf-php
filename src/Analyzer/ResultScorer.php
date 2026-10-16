<?php

declare(strict_types=1);

namespace SafeSurf\Analyzer;

use SafeSurf\Checks\Brand;
use SafeSurf\Checks\Content;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;

final class ResultScorer
{
    private const SAFE_THRESHOLD = 65;
    private const RISKY_THRESHOLD = 30;
    private const WELL_KNOWN_RANK = 100000;

    public static function generate(array $resp): array
    {
        $neutral = [];
        $good = [];
        $bad = [];
        $trust = 0;
        $risk = 0;
        $confirmed = false;
        $capAtSuspicious = false;

        $url = (string) ($resp['url'] ?? '');
        $host = DomainUtil::hostFromUrl($url) ?? '';
        $rank = (int) ($resp['features']['rank'] ?? 0);
        $tldInfo = $resp['features']['tld'] ?? [];
        $isHostingPlatform = !empty($tldInfo['is_hosting_platform']);
        $tldStr = (string) ($tldInfo['tld'] ?? '');
        $di = $resp['domain_info'] ?? null;
        $ageDays = is_array($di) && isset($di['age_days']) ? (int) $di['age_days'] : null;
        $ageHuman = is_array($di) ? (string) ($di['age_human'] ?? '') : '';

        // --- 1. Popularity & Rank ---
        if ($rank === 0) {
            $providerService = DataFiles::providerServiceHosts()[$host] ?? null;
            $cleanHost = preg_replace('/^www\./i', '', $host) ?? $host;
            $userPageService = DataFiles::userPageHosts()[$cleanHost] ?? null;
            $store = DomainUtil::userContentHost($host);

            if ($providerService !== null) {
                $neutral[] = sprintf('File hosted on %s (anyone can upload here).', $providerService);
            } elseif ($userPageService !== null) {
                $neutral[] = sprintf('A page on %s, where anyone can make one.', $userPageService);
            } elseif ($store !== null && $isHostingPlatform) {
                $neutral[] = sprintf('Stored on %s, where anyone can upload files.', $store);
            } elseif ($isHostingPlatform) {
                $neutral[] = sprintf('Unranked subdomain on %s (normal for personal or project pages).', $tldStr !== '' ? $tldStr : 'hosting platform');
            } elseif ($ageDays !== null && $ageDays > 90) {
                $neutral[] = 'Not among the top 1M sites (normal for small sites).';
            } else {
                $bad[] = 'Very low traffic volume.';
                $risk += 10;
            }
        } elseif ($rank > 0 && $rank <= 10000) {
            $good[] = sprintf('Global Giant: Ranked #%d worldwide.', $rank);
            $trust += 90;
        } elseif ($rank <= 50000) {
            $good[] = sprintf('Well-known website (#%d worldwide).', $rank);
            $trust += 50;
        } else {
            $good[] = sprintf('Low-traffic but indexed website (#%d worldwide).', $rank);
            $trust += 20;
        }

        // --- 2. TLD ---
        $isRisky = !empty($tldInfo['is_risky_tld']);
        $isTrusted = !empty($tldInfo['is_trusted_tld']);
        $isIcann = !empty($tldInfo['is_icann']);

        if ($isRisky) {
            if ($rank > 0 || $isTrusted) {
                // Top-ranked or trusted domains: name/tld heuristics don't indicate risk
            } else {
                $bad[] = 'High-risk domain extension detected (often associated with spam).';
                $risk += 20;
            }
        }

        $typo = $resp['typosquat_result'] ?? [];
        if ($isTrusted && !empty($typo['path_brand'])) {
            $bad[] = sprintf("A '%s' sign-in page under a government or university address, which suggests the site was hacked.", (string) $typo['path_brand']);
            $risk += 60;
        } elseif ($isTrusted) {
            $good[] = 'High-trust official domain extension (Gov/Edu).';
            $trust += 100;
        } elseif ($isIcann && !$isRisky) {
            $neutral[] = 'Standard, officially recognized domain extension.';
        }

        if (!$isIcann) {
            if ($isHostingPlatform) {
                // PSL private entry but operated by a reputable hosting company
            } else {
                $bad[] = 'Unregulated or non-standard domain extension.';
                $risk += 30;
            }
        }

        // --- 3. Security Protocols (HSTS) ---
        if (!empty($resp['analysis']['is_hsts_supported'])) {
            if ($ageDays !== null && $ageDays <= 30) {
                $neutral[] = 'Sends an HSTS header, which on a domain this new says little.';
            } else {
                $good[] = 'Enforces strict HTTPS security (HSTS Enabled).';
                $trust += 20;
            }
        }

        // --- 4. URL Structure / Obfuscation ---
        $urlChecks = $resp['features']['url'] ?? [];
        $redirInfo = $resp['analysis']['redirection_result'] ?? [];
        $finalUrlRank = (int) ($redirInfo['final_url_rank'] ?? 0);

        if (!empty($urlChecks['url_shortener'])) {
            if ($rank > 0 && $finalUrlRank > 0) {
                $neutral[] = 'URL Shortener operated by an established domain.';
            } else {
                $bad[] = 'URL Shortener detected (hides the true destination).';
                $risk += 25;
            }
        }

        if (!empty($urlChecks['uses_ip'])) {
            $bad[] = 'Raw IP address usage detected (common evasion tactic).';
            $risk += 100;
        }

        $ipHost = DomainUtil::ipHostname($host);
        if ($ipHost !== null) {
            $service = $ipHost['service'];
            $ipAddr = $ipHost['ip'];
            if ($ipAddr !== '') {
                $bad[] = sprintf('The address is a bare server (%s) written as a name on %s, which turns any IP address into a name.', $ipAddr, $service);
            } else {
                $bad[] = sprintf('The address is on %s, which turns any IP address into a name.', $service);
            }
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

        // --- 5. Infrastructure Forensics ---
        if (empty($resp['infrastructure']['nameservers_valid'])) {
            if ($isHostingPlatform) {
                // Platform manages entire DNS zone
            } else {
                $bad[] = 'Incomplete or missing DNS configuration.';
                $risk += 10;
            }
        }

        if (empty($resp['infrastructure']['mx_records_valid']) && !$isHostingPlatform) {
            $neutral[] = 'No email server configured for this domain.';
            $risk += 5;
        }

        // --- 6. Domain History ---
        if (is_array($di)) {
            $cleanHost = preg_replace('/^www\./i', '', $host) ?? $host;
            $isUserPage = isset(DataFiles::userPageHosts()[$cleanHost]) && !DomainUtil::isBareUrl($url);
            $isCustSub = $cleanHost !== $tldStr && str_ends_with($cleanHost, ".$tldStr");
            $isHostingReg = $isHostingPlatform && ($isUserPage || $isCustSub);

            if ($isHostingReg && $ageDays !== null) {
                $neutral[] = sprintf("The domain's age is %s's, not this site's.", $tldStr !== '' ? $tldStr : 'the platform');
            } else {
                if ($ageDays === null) {
                    $neutral[] = "Registration date not published by this domain's registry.";
                } elseif ($ageDays <= 30) {
                    $bad[] = sprintf('Registered %s. Phishing sites are usually brand new.', self::ago($ageHuman));
                    $risk += 25;
                } elseif ($ageDays <= 90) {
                    $bad[] = sprintf('Young domain, registered %s. Use caution.', self::ago($ageHuman));
                    $risk += 15;
                } elseif ($ageDays <= 365) {
                    $neutral[] = sprintf('Fairly new domain (%s old).', $ageHuman);
                } elseif (($rank === 0 || $rank > self::WELL_KNOWN_RANK) && self::kitLoginPath($url)) {
                    $neutral[] = sprintf("The domain is %s old, but this link is a sign-in page that looks planted in it, so its age isn't counted.", $ageHuman);
                } elseif ($ageDays <= 1095) { // 3 years
                    $good[] = sprintf('Operational for %s.', $ageHuman);
                    $trust += 10;
                } elseif ($ageDays <= 1825) { // 5 years
                    $good[] = sprintf('Operational for %s.', $ageHuman);
                    $trust += 15;
                } else {
                    $good[] = sprintf('Long-standing domain history (%s).', $ageHuman);
                    $trust += 25;
                }

                if (!empty($di['dnssec'])) {
                    $good[] = 'Advanced DNS security enabled (DNSSEC).';
                    $trust += 10;
                } else {
                    $neutral[] = 'Standard DNS security (DNSSEC not enabled).';
                }
            }

            $statuses = $di['status'] ?? [];
            if (is_array($statuses)) {
                $badStatuses = [];
                foreach ($statuses as $st) {
                    if (!is_string($st)) {
                        continue;
                    }
                    $stLower = strtolower($st);
                    if (str_contains($stLower, 'hold') || str_contains($stLower, 'pendingdelete') || str_contains($stLower, 'redemptionperiod')) {
                        $badStatuses[] = $st;
                    }
                }
                if ($badStatuses !== []) {
                    $bad[] = sprintf('Domain registry status is problematic (%s).', implode(', ', $badStatuses));
                    $risk += 25;
                }
            }
        }

        // --- 7. Redirection Analysis ---
        $redir = $resp['analysis']['redirection_result'] ?? [];
        if (!empty($redir['is_redirected'])) {
            $chainLen = (int) ($redir['chain_length'] ?? 1);
            $hops = max(0, $chainLen - 1);
            if ($hops > 3 && !empty($redir['has_domain_jump'])) {
                $bad[] = sprintf('Excessive redirection chain detected (%d hops).', $hops);
                $risk += 40;
            }
            if (!empty($redir['has_domain_jump'])) {
                $finalHost = (string) ($redir['final_url_domain'] ?? '');
                if ($rank > 0 && $finalUrlRank > 0) {
                    $neutral[] = sprintf('Cross-domain redirection to established domain: %s (#%d worldwide).', $finalHost, $finalUrlRank);
                } else {
                    $bad[] = 'Cross-domain redirection detected (destination differs from source).';
                    if ($finalHost !== '') {
                        $bad[] = sprintf('Final Destination: %s. Check Report for more info.', $finalHost);
                    }
                    $risk += 50;
                }
            }
        }

        // --- 8. Homoglyphs ---
        if (!empty($urlChecks['has_homoglyph'])) {
            $bad[] = 'Homoglyph attack detected (deceptive visual characters).';
            $risk += 60;
        }

        // --- 9. Typosquatting / Combo-squatting ---
        if (is_array($typo) && !empty($typo['is_suspicious'])) {
            if (!empty($typo['is_combo_squat'])) {
                $bad[] = sprintf("Combo-squatting detected: domain contains brand name '%s' but is not the official site.", (string) ($typo['matched_brand'] ?? ''));
                $risk += $isHostingPlatform ? 40 : 20;
                $bare = self::brandPageIsBare($resp);
                if ($bare !== '') {
                    $bad[] = sprintf("Uses the name '%s' on a little-known site, and the page %s.", (string) ($typo['matched_brand'] ?? ''), $bare);
                    $risk += 20;
                }
            } else {
                $bad[] = sprintf(
                    "Typosquatting detected: domain closely resembles '%s' (%d character difference).",
                    (string) ($typo['matched_domain'] ?? ''),
                    (int) ($typo['distance'] ?? 0)
                );
                $risk += 40;
            }
        }

        if (is_array($typo)) {
            if (!empty($typo['embedded_domain'])) {
                $bad[] = sprintf("The address starts like %s but belongs to %s.", (string) $typo['embedded_domain'], (string) ($resp['domain'] ?? ''));
                $risk += 60;
            }
            if (!empty($typo['subdomain_brand']) && empty($typo['embedded_domain'])) {
                $bare = self::brandPageIsBare($resp);
                if ($bare !== '') {
                    $bad[] = sprintf("A subdomain is named after '%s' on a little-known site, and the page %s.", (string) $typo['subdomain_brand'], $bare);
                    $risk += 20;
                }
                if (!empty($typo['subdomain_brand_exact'])) {
                    $bad[] = sprintf("A subdomain is named '%s', on a site that isn't theirs.", (string) $typo['subdomain_brand']);
                    $risk += 20;
                } else {
                    $bad[] = sprintf("A subdomain uses the brand name '%s', on a site that isn't theirs.", (string) $typo['subdomain_brand']);
                    $risk += 40;
                }
            }
            if (!empty($typo['path_brand'])) {
                $content = $resp['content_data'] ?? null;
                if (is_array($content) && !empty($content['has_login_form'])) {
                    $bad[] = sprintf("The link's path names '%s' and the page asks you to log in, on a site that isn't theirs.", (string) $typo['path_brand']);
                    $risk += 40;
                } else {
                    $bad[] = sprintf("The link's path names '%s', on a site that isn't theirs.", (string) $typo['path_brand']);
                    $risk += 20;
                }
            }
        }

        // --- 10. Threat Intelligence (PhishTank & Threat Feeds) ---
        $phish = $resp['phishing'] ?? null;
        if (is_array($phish) && !empty($phish['in_database'])) {
            if (!empty($phish['valid']) && !empty($phish['verified'])) {
                $bad[] = 'CONFIRMED PHISHING: This is a verified phishing URL.';
                $risk += 200;
                $confirmed = true;
                if (!empty($phish['target'])) {
                    $bad[] = 'Reported Target: ' . (string) $phish['target'];
                }
            } elseif (!empty($phish['valid']) && empty($phish['verified'])) {
                $bad[] = 'This URL has been reported as phishing, awaiting community verification.';
                $risk += 70;
            }
        }

        $threatFeeds = $resp['threat_feeds'] ?? [];
        if (is_array($threatFeeds) && isset($threatFeeds['results']) && is_array($threatFeeds['results'])) {
            $severityWeights = ['phishing' => 70, 'malware' => 70, 'blocked' => 25, 'unwanted' => 20, 'info' => 0];
            foreach ($threatFeeds['results'] as $tf) {
                if (!is_array($tf) || empty($tf['checked']) || empty($tf['listed'])) {
                    continue;
                }
                $feedName = (string) ($tf['feed'] ?? '');
                if ($feedName === 'phishtank') {
                    continue; // already scored via 'phishing'
                }
                $severity = (string) ($tf['severity'] ?? 'blocked');
                $weight = $severityWeights[$severity] ?? 25;
                $bad[] = sprintf("Threat feed '%s' (%s) reports this %s.", $feedName, (string) ($tf['category'] ?? 'external'), $severity);
                $risk += $weight;
                if ($severity === 'phishing' || $severity === 'malware') {
                    $confirmed = true;
                }
            }
        }

        if (self::victimAddressInLink($url)) {
            $bad[] = 'The link carries an email address for the page to fill in, a common way phishing pages tailor a login to each target.';
            $risk += 20;
        }

        // --- 11. Page Content & Phishing Signals ---
        $content = $resp['content_data'] ?? null;
        if (is_array($content)) {
            $title = (string) ($content['title'] ?? '');
            if ($rank === 0 && preg_match('/(?i)\btrading (platform|app|bot|software)\b.{0,20}\bofficial (website|site|gateway|page)\b|^immediate [a-z0-9 ]{2,20}(?:™|®)?\s*[|:-]\s*(the )?official\b/', $title)) {
                $bad[] = 'The page uses the title template of fake crypto trading platforms ("AI Trading Platform | Official Website"), a common investment scam.';
                $risk += 50;
            }

            if (!empty($content['has_login_form'])) {
                $isEstablished = $rank > 0 && $rank <= self::WELL_KNOWN_RANK;
                $isOld = $ageDays !== null && $ageDays > 365;

                if (!$isEstablished && !$isOld) {
                    $bad[] = 'SUSPICIOUS: Login form detected on a new or unranked domain.';
                    $risk += 50;
                } else {
                    $neutral[] = 'Page contains a login form.';
                }

                if ($isHostingPlatform && preg_match('/(?i)\b(web ?mail|mail ?(authentication|verification|login|portal)|e-?mail (verification|authentication|login|sign[ -]?in|portal)|mailbox|password protect(ion|ed)|verify your (e-?mail|mailbox|account)|sign ?in ?to (your )?(web)?mail)\b/', $title)) {
                    $bad[] = sprintf("An email sign-in page on %s, free hosting where real mail providers don't put their logins.", $tldStr !== '' ? $tldStr : 'free hosting');
                    $risk += 30;
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

            if (!empty($content['provider_block']) && is_array($content['provider_block'])) {
                $pb = $content['provider_block'];
                $pbReason = (string) ($pb['reason'] ?? '');
                $pbProvider = (string) ($pb['provider'] ?? 'The hosting provider');
                if ($pbReason === 'phishing' || $pbReason === 'malware') {
                    $bad[] = sprintf('%s has flagged this page as suspected %s and shows a warning instead of it.', $pbProvider, $pbReason);
                    $risk += 100;
                } else {
                    $bad[] = sprintf('%s has taken this site down.', $pbProvider);
                    $risk += 40;
                }
            }

            if (!empty($content['script_redirect']) && is_array($content['script_redirect'])) {
                $sr = $content['script_redirect'];
                if (!empty($sr['to_ip'])) {
                    $bad[] = 'Page uses a script to send visitors on to a raw IP address (common in spam and phishing redirectors).';
                    $risk += 60;
                } elseif (!empty($sr['cross_domain']) && DomainUtil::userContentHost($host) !== null) {
                    $targetHost = DomainUtil::hostFromUrl((string) ($sr['target'] ?? '')) ?? 'another site';
                    $bad[] = sprintf('A file anyone could upload here immediately sends visitors on to another site: %s.', $targetHost);
                    $risk += 60;
                } elseif (!empty($sr['cross_domain'])) {
                    $targetHost = DomainUtil::hostFromUrl((string) ($sr['target'] ?? '')) ?? 'another site';
                    $bad[] = sprintf('Page immediately sends visitors on to another site: %s.', $targetHost);
                    $risk += 30;
                }
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
                    $marketing = !empty($f['is_marketing']) && empty($f['has_password']) && empty($f['has_payment']);
                    if (!empty($f['is_external']) && !$marketing) {
                        if (!empty($f['has_password']) || !empty($f['has_payment']) || !empty($f['has_personal'])) {
                            $bad[] = 'CRITICAL: Form submits data to a different domain (common phishing tactic).';
                            $risk += 80;
                        } elseif (!empty($f['has_user_like'])) {
                            $bad[] = 'Form sends an email address or username to a different domain.';
                            $risk += 20;
                        }
                    }
                    if (!empty($f['has_password']) && empty($resp['ssl_info']['has_tls'])) {
                        $bad[] = 'DANGEROUS: Password form detected over insecure connection!';
                        $risk += 200;
                    }
                }
            }
        }

        // --- 12. Certificate & TLS ---
        $sslInfo = $resp['ssl_info'] ?? [];
        $tlsInfo = $resp['tls_info'] ?? [];
        if (is_array($tlsInfo) && !empty($tlsInfo['hostname_mismatch'])) {
            $bad[] = 'TLS certificate does not match the domain name.';
            $risk += 25;
        }

        if (is_array($sslInfo) && !empty($sslInfo['is_suspicious'])) {
            $reasons = $sslInfo['reasons'] ?? [];
            $reasonText = is_array($reasons) && $reasons !== [] ? implode('; ', $reasons) : 'certificate issues';
            $bad[] = sprintf('TLS certificate is suspicious (%s).', $reasonText);
            $risk += 20;
        }

        // --- 13. Hacked-site Paths ---
        if (self::isWordPressSystemPage($url)) {
            $bad[] = 'Page sits inside a WordPress system folder, where phishing kits are hidden on hacked sites.';
            $risk += 30;
            if (is_array($content) && !empty($content['has_login_form'])) {
                $bad[] = 'That page asks visitors to log in.';
                $risk += 30;
            }
        }

        // --- 14. Program Downloads ---
        $progExt = self::downloadedProgram($resp);
        if ($progExt !== null) {
            $uHost = self::uploadHost($resp);
            if ($uHost !== null) {
                $bad[] = sprintf('Downloads a program (%s) that a user uploaded to %s. Nothing confirms it comes from the software\'s publisher.', $progExt, $uHost);
                $capAtSuspicious = true;
            } elseif ($rank === 0) {
                $bad[] = sprintf('Downloads a program (%s) from a little-known site.', $progExt);
                $risk += 40;
            } else {
                $neutral[] = sprintf('Link downloads a program (%s).', $progExt);
            }
        }

        // --- Subdomain Signals (SafeSurf) ---
        $subSignals = $resp['features']['subdomain'] ?? [];
        $isSubdomainHost = is_array($subSignals) && (int) ($subSignals['subdomain_count'] ?? 0) > 0;
        if ($isSubdomainHost) {
            $sensitiveLabels = $subSignals['sensitive_labels'] ?? [];
            if (is_array($sensitiveLabels) && $sensitiveLabels !== []) {
                $neutral[] = sprintf('Subdomain uses sensitive label(s): %s.', implode(', ', array_keys($sensitiveLabels)));
            }

            $brandHits = $subSignals['brand_hits'] ?? [];
            if (is_array($brandHits) && $brandHits !== []) {
                $hitBrands = [];
                foreach ($brandHits as $hit) {
                    if (is_array($hit) && !empty($hit['brand'])) {
                        $hitBrands[] = (string) $hit['brand'];
                    }
                }
                if ($hitBrands !== []) {
                    $bad[] = sprintf('Brand name(s) %s embedded in subdomain while the domain is unofficial.', implode(', ', array_unique($hitBrands)));
                    $risk += $isHostingPlatform ? 10 : 15;
                }
            }
        }

        // --- Root Domain Correlation (SafeSurf) ---
        $corr = $resp['correlation'] ?? null;
        $corrSignals = is_array($corr) ? ($corr['signals'] ?? []) : [];
        $hasLogin = is_array($content) && !empty($content['has_login_form']);
        $weakRootReputation = $rank === 0 || ($ageDays !== null && $ageDays <= 365);

        if (is_array($corrSignals)) {
            $rootInactive = !empty($corrSignals['root_inactive']);
            $rootParked = !empty($corrSignals['root_parked_or_empty']);
            $rootRedirectsAway = !empty($corrSignals['root_redirects_off_domain']);
            $infraSplit = !empty($corrSignals['infrastructure_split']);
            $contentDivergent = !empty($corrSignals['content_divergent']);

            if ($rootInactive) {
                $neutral[] = 'Root domain appears inactive, parked or unreachable while analyzing a subdomain.';
            }
            if ($infraSplit) {
                $neutral[] = 'Subdomain and root domain are hosted on different infrastructure.';
            }

            if ($rootInactive && $hasLogin && $weakRootReputation) {
                $bad[] = 'SUSPICIOUS: Root domain is unused while the subdomain serves a login page.';
                $risk += 25;
                if ($rootParked) {
                    $bad[] = 'Root domain is parked or shows placeholder content.';
                    $risk += 5;
                }
            }

            if ($rootRedirectsAway && $hasLogin && $weakRootReputation) {
                $bad[] = sprintf(
                    'Root domain redirects away to %s while the subdomain serves interactive content.',
                    (string) ($corr['root']['final_domain'] ?? 'another domain')
                );
                $risk += 15;
            }

            if ($contentDivergent && $hasLogin) {
                $neutral[] = 'Subdomain content differs significantly from the root domain.';
                $risk += 5;
            }
        }

        // --- Phishing Patterns (SafeSurf) ---
        if (is_array($content)) {
            $pp = $content['phishing_patterns'] ?? [];
            if (is_array($pp)) {
                if (!empty($pp['login_with_brand_text'])) {
                    $brands = $pp['brand_names_in_text'] ?? [];
                    if ($rank > 0 && $rank <= 10000) {
                        $neutral[] = sprintf(
                            'Page mixes a login form with brand mention(s) %s, but the domain is globally established.',
                            is_array($brands) && $brands !== [] ? implode(', ', $brands) : '(unknown)'
                        );
                    } else {
                        $bad[] = sprintf(
                            'Login form combined with brand mention(s) %s in page text on an unofficial domain.',
                            is_array($brands) && $brands !== [] ? implode(', ', $brands) : '(unknown)'
                        );
                        $risk += 30;
                    }
                }

                if (!empty($pp['favicon_brand_mismatch'])) {
                    $bc = $content['brand_check'] ?? [];
                    if ($hasLogin || (is_array($bc) && !empty($bc['is_mismatch']))) {
                        $bad[] = 'Favicon hotlinked from a brand official domain on an unrelated page (possible site clone).';
                        $risk += 20;
                    } else {
                        $neutral[] = 'Favicon loaded from a third-party brand domain.';
                    }
                }

                if (!empty($pp['meta_refresh_external'])) {
                    $bad[] = 'Meta-refresh redirect pointing to another domain.';
                    $risk += 10;
                }

                $js = $pp['js_signals'] ?? [];
                if (is_array($js)) {
                    if (!empty($js['has_form_injection']) && $hasLogin) {
                        $bad[] = 'JavaScript injects a credential form into the page.';
                        $risk += 20;
                    }
                    if (!empty($js['has_eval_atob']) || (!empty($js['has_obfuscation']) && (float) ($js['suspicious_score'] ?? 0) >= 0.4)) {
                        $bad[] = 'Heavily obfuscated JavaScript detected.';
                        $risk += 10;
                    }
                    if (!empty($js['has_crypto_wallet_hooks'])) {
                        $bad[] = 'Cryptocurrency wallet API hooks detected.';
                        $risk += 15;
                    }
                }
            }
        }

        // --- Score Normalization ---
        $risk = self::clamp($risk);
        $trust = self::clamp($trust);

        $final = self::clamp(50 + (int) round(($trust - $risk) * 0.5));
        if ($capAtSuspicious && $final >= self::SAFE_THRESHOLD) {
            $final = self::SAFE_THRESHOLD - 1;
        }
        if ($confirmed && $final >= self::RISKY_THRESHOLD) {
            $final = self::RISKY_THRESHOLD - 1;
        }

        $verdict = 'Safe';
        if ($final < self::RISKY_THRESHOLD) {
            $verdict = 'Risky';
        } elseif ($final < self::SAFE_THRESHOLD) {
            $verdict = 'Suspicious';
        }

        return [
            'risk_score' => $risk,
            'trust_score' => $trust,
            'final_score' => $final,
            'verdict' => $verdict,
            'reasons' => [
                'neutral_reasons' => array_values(array_unique($neutral)),
                'good_reasons' => array_values(array_unique($good)),
                'bad_reasons' => array_values(array_unique($bad)),
            ],
        ];
    }

    public static function isWordPressSystemPage(string $url): bool
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        if (!preg_match('#(?i)/wp-(?:content|includes|admin)/#', $path)) {
            return false;
        }
        $p = strtolower(rtrim($path, '/'));
        foreach (['/wp-admin', '/wp-admin/index.php', '/wp-admin/admin-ajax.php', '/wp-admin/admin-post.php'] as $entry) {
            if (str_ends_with($p, $entry)) {
                return false;
            }
        }
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $staticAssetExts = [
            'css' => true, 'js' => true, 'mjs' => true, 'map' => true, 'png' => true, 'jpg' => true, 'jpeg' => true,
            'gif' => true, 'webp' => true, 'avif' => true, 'svg' => true, 'ico' => true, 'bmp' => true,
            'woff' => true, 'woff2' => true, 'ttf' => true, 'otf' => true, 'eot' => true,
            'mp4' => true, 'webm' => true, 'mp3' => true, 'pdf' => true, 'zip' => true, 'json' => true, 'xml' => true, 'txt' => true,
        ];
        return !isset($staticAssetExts[$ext]);
    }

    public static function victimAddressInLink(string $url): bool
    {
        $parts = @parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        $fragment = (string) ($parts['fragment'] ?? '');
        if (preg_match('/(?i)\[\[-?e-?mail-?\]\]|\{\{\s*e-?mail\s*\}\}|##e-?mail##|%e-?mail%/i', $fragment)) {
            return true;
        }
        $emailRe = '/^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}$/i';
        if ($fragment !== '') {
            $tokens = preg_split('/[#&=?\/!;,]+/', $fragment) ?: [];
            foreach ($tokens as $tok) {
                if (preg_match($emailRe, $tok) || preg_match($emailRe, self::fromBase64($tok))) {
                    return true;
                }
            }
        }

        $query = (string) ($parts['query'] ?? '');
        if ($query !== '') {
            parse_str($query, $params);
            $honestParams = [
                'email' => true, 'e-mail' => true, 'e_mail' => true, 'mail' => true, 'e' => true, 'em' => true,
                'emailaddress' => true, 'email_address' => true, 'address' => true, 'recipient' => true,
                'subscriber' => true, 'to' => true, 'from' => true, 'user' => true, 'username' => true,
                'login' => true, 'contact' => true, 'invite' => true, 'invitee' => true, 'q' => true,
            ];
            $path = (string) ($parts['path'] ?? '');
            $mailingPage = (bool) preg_match('/(?i)unsubscribe|opt-?out|preferences|subscri|newsletter|invite|verify|confirm|reset/', $path);

            foreach ($params as $name => $val) {
                $nameLower = strtolower((string) $name);
                $isHonest = isset($honestParams[$nameLower]);
                $vals = is_array($val) ? $val : [$val];
                foreach ($vals as $v) {
                    if (!is_string($v)) {
                        continue;
                    }
                    if (preg_match($emailRe, self::fromBase64($v)) || (!$isHonest && !$mailingPage && preg_match($emailRe, $v))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static function kitLoginPath(string $url): bool
    {
        $parts = @parse_url($url);
        if (!is_array($parts)) {
            return false;
        }
        $path = (string) ($parts['path'] ?? '');
        if (preg_match('#(?i)/owa/.*\.php\b#', $path)) {
            return true;
        }
        if (!self::loginPathWordsMatch($url)) {
            return false;
        }
        if (preg_match('/[0-9a-f]{16,}/i', $path)) {
            return true;
        }
        $query = (string) ($parts['query'] ?? '');
        if ($query !== '') {
            parse_str($query, $params);
            $skip = ['token' => true, 'code' => true, 'key' => true, 'reset' => true, 'confirm' => true, 'verify' => true, 'signature' => true, 'sig' => true, 'state' => true, 'nonce' => true];
            foreach ($params as $name => $val) {
                if (isset($skip[strtolower((string) $name)])) {
                    continue;
                }
                $vals = is_array($val) ? $val : [$val];
                foreach ($vals as $v) {
                    if (is_string($v) && preg_match('/[0-9a-f]{16,}/i', $v)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static function loginPathWordsMatch(string $url): bool
    {
        $path = (string) parse_url($url, PHP_URL_PATH);
        return (bool) preg_match('#(?i)(log[-_]?in|log[-_]?on|sign[-_]?in|signon|verif|auth|secure|account|webscr|wallet|update)#', $path);
    }

    private static function fromBase64(string $s): string
    {
        $s = ltrim($s, '$~!*');
        if (strlen($s) < 8) {
            return '';
        }
        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $s), true);
        return is_string($decoded) ? $decoded : '';
    }

    private static function ago(string $ageHuman): string
    {
        if ($ageHuman === 'today') {
            return $ageHuman;
        }
        return $ageHuman . ' ago';
    }

    private static function brandPageIsBare(array $resp): string
    {
        $rank = (int) ($resp['features']['rank'] ?? 0);
        $c = $resp['content_data'] ?? null;
        if ($rank > 0 || !is_array($c)) {
            return '';
        }
        if (!empty($c['file_name'])) {
            return '';
        }
        if (!empty($c['has_login_form']) || !empty($c['has_payment_form'])) {
            return 'asks you to log in or pay';
        }
        $title = (string) ($c['title'] ?? '');
        if (str_starts_with($title, 'Index of /')) {
            return 'is a bare file listing';
        }
        if (trim($title) === '' && empty($c['has_forms'])) {
            return 'is blank';
        }
        return '';
    }

    private static function servedOverHttps(array $resp): bool
    {
        $url = (string) ($resp['url'] ?? '');
        $finalUrl = (string) ($resp['analysis']['redirection_result']['final_url'] ?? '');
        $urlHost = DomainUtil::hostFromUrl($url);
        $finalHost = DomainUtil::hostFromUrl($finalUrl);

        return str_starts_with($url, 'https://') ||
            (str_starts_with($finalUrl, 'https://') && $finalHost !== null && $finalHost === $urlHost);
    }

    private static function downloadedProgram(array $resp): ?string
    {
        $candidates = [$resp['url'] ?? ''];
        $finalUrl = $resp['analysis']['redirection_result']['final_url'] ?? null;
        if (is_string($finalUrl) && $finalUrl !== '') {
            $candidates[] = $finalUrl;
        }
        $fileName = $resp['content_data']['file_name'] ?? null;
        if (is_string($fileName) && $fileName !== '') {
            $candidates[] = $fileName;
        }
        foreach ($candidates as $c) {
            $ext = Content::executableExt((string) $c);
            if ($ext !== null) {
                return $ext;
            }
        }
        return null;
    }

    private static function uploadHost(array $resp): ?string
    {
        if (!empty($resp['features']['tld']['is_hosting_platform'])) {
            return (string) ($resp['features']['tld']['tld'] ?? '');
        }
        $hosts = [];
        $urlHost = DomainUtil::hostFromUrl((string) ($resp['url'] ?? ''));
        if ($urlHost !== null) {
            $hosts[] = $urlHost;
        }
        $finalHost = (string) ($resp['analysis']['redirection_result']['final_url_domain'] ?? '');
        if ($finalHost !== '') {
            $hosts[] = $finalHost;
        }
        foreach ($hosts as $h) {
            $store = DomainUtil::userContentHost($h);
            if ($store !== null) {
                return $store;
            }
        }
        return null;
    }

    private static function clamp(int $score): int
    {
        return max(0, min(100, $score));
    }
}
