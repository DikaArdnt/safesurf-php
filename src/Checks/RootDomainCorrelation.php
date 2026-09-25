<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Util\DomainUtil;
use SafeSurf\Util\HttpClient;

final class RootDomainCorrelation
{
    public static function fetchRootData(string $registrableDomain, Config $config): ?array
    {
        $domain = strtolower(trim($registrableDomain));
        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return null;
        }

        $chain = [];
        $current = "https://$domain";
        $lastResp = null;

        $maxHops = max(1, $config->rootCorrelationMaxHops);
        for ($i = 0; $i <= $maxHops; $i++) {
            $resp = HttpClient::request('GET', $current, $config, false);
            $lastResp = $resp;

            if ($resp['error'] !== null) {
                if ($i === 0 && str_starts_with($current, 'https://')) {
                    $current = "http://$domain";
                    continue;
                }
                break;
            }

            $status = (int) $resp['status'];
            if ($status < 300 || $status >= 400) {
                break;
            }

            $loc = $resp['headers']['location'][0] ?? null;
            if (!is_string($loc) || trim($loc) === '') {
                break;
            }

            $next = self::resolveRedirect($current, $loc);
            if ($next === null || in_array($next, $chain, true)) {
                break;
            }
            $chain[] = $next;
            $current = $next;
        }

        $hadError = $lastResp !== null && $lastResp['error'] !== null;

        $finalUrl = $chain === [] ? ("https://$domain") : $chain[count($chain) - 1];
        $finalDomain = $domain;
        try {
            $reg = DomainUtil::registrableDomainFromUrl($finalUrl, $config->publicSuffixListPath);
            if (is_string($reg) && $reg !== '') {
                $finalDomain = $reg;
            }
        } catch (\Throwable) {
        }

        $body = '';
        $statusCode = 0;
        $contentType = '';
        if (!$hadError && is_array($lastResp)) {
            $statusCode = (int) $lastResp['status'];
            $body = (string) ($lastResp['body'] ?? '');
            $contentType = (string) ($lastResp['headers']['content-type'][0] ?? '');
        }

        $title = '';
        $textSample = '';
        if ($body !== '' && (str_contains($contentType, 'html') || $contentType === '' || str_contains($body, '<'))) {
            $parsed = self::parseHtmlBasics($body);
            $title = $parsed['title'];
            $textSample = $parsed['text_sample'];
        }

        $parked = self::isParkedOrEmpty($title, $textSample);
        $isHtml = $textSample !== '' || $title !== '';
        $isActive = !$hadError
            && $statusCode >= 200
            && $statusCode < 300
            && !$parked
            && ($isHtml || strlen($body) > 2048);

        return [
            'domain' => $domain,
            'reachable' => !$hadError,
            'status_code' => $statusCode,
            'is_active' => $isActive,
            'redirect_chain' => $chain,
            'redirects_off_domain' => $finalDomain !== $domain,
            'final_domain' => $finalDomain,
            'title' => $title,
            'text_sample' => $textSample,
            'is_parked_or_empty' => $parked,
        ];
    }

    /**
     * Pure correlation of root-domain facts with the analyzed subdomain page.
     *
     * @param array|null $rootData   result of fetchRootData()
     * @param array|null $subContent content_data of the analyzed URL (may be null)
     * @param list<string> $subHostIps IPs resolved for the analyzed host
     * @param list<string> $rootIps   IPs resolved for the registrable domain
     */
    public static function correlate(?array $rootData, ?array $subContent, array $subHostIps, array $rootIps): ?array
    {
        if ($rootData === null) {
            return null;
        }

        $infra = self::compareInfrastructure($subHostIps, $rootIps);

        $similarity = null;
        $relation = 'unknown';
        $subText = is_array($subContent) ? (string) ($subContent['text_sample'] ?? '') : '';
        $rootText = (string) ($rootData['text_sample'] ?? '');
        if ($subText !== '' && $rootText !== '') {
            $similarity = self::textSimilarity($rootText, $subText);
            $relation = $similarity >= 0.6 ? 'same' : ($similarity >= 0.25 ? 'partial' : 'divergent');
        }

        $rootInactive = empty($rootData['reachable']) || empty($rootData['is_active']);

        return [
            'root' => [
                'domain' => (string) ($rootData['domain'] ?? ''),
                'reachable' => (bool) ($rootData['reachable'] ?? false),
                'is_active' => (bool) ($rootData['is_active'] ?? false),
                'is_parked_or_empty' => (bool) ($rootData['is_parked_or_empty'] ?? false),
                'status_code' => (int) ($rootData['status_code'] ?? 0),
                'redirects_off_domain' => (bool) ($rootData['redirects_off_domain'] ?? false),
                'final_domain' => (string) ($rootData['final_domain'] ?? ''),
                'title' => (string) ($rootData['title'] ?? ''),
            ],
            'shared_infrastructure' => $infra,
            'content_similarity' => $similarity,
            'content_relation' => $relation,
            'signals' => [
                'root_unreachable' => empty($rootData['reachable']),
                'root_inactive' => $rootInactive,
                'root_parked_or_empty' => (bool) ($rootData['is_parked_or_empty'] ?? false),
                'root_redirects_off_domain' => (bool) ($rootData['redirects_off_domain'] ?? false),
                'infrastructure_split' => $infra === 'different',
                'content_divergent' => $relation === 'divergent',
            ],
        ];
    }

    /**
     * @param list<string> $ipsA
     * @param list<string> $ipsB
     */
    public static function compareInfrastructure(array $ipsA, array $ipsB): string
    {
        $a = self::normalizeIps($ipsA);
        $b = self::normalizeIps($ipsB);
        if ($a === [] || $b === []) {
            return 'unknown';
        }

        foreach ($a as $ip) {
            if (in_array($ip, $b, true)) {
                return 'same_ip';
            }
        }

        $netsA = self::networksOf($a);
        $netsB = self::networksOf($b);
        foreach ($netsA as $net) {
            if (in_array($net, $netsB, true)) {
                return 'same_network';
            }
        }

        return 'different';
    }

    public static function textSimilarity(string $textA, string $textB): float
    {
        $shinglesA = self::shingles($textA);
        $shinglesB = self::shingles($textB);
        if ($shinglesA === [] || $shinglesB === []) {
            return 0.0;
        }

        $inter = count(array_intersect($shinglesA, $shinglesB));
        $union = count(array_unique(array_merge($shinglesA, $shinglesB)));
        return $union === 0 ? 0.0 : round($inter / $union, 3);
    }

    public static function isParkedOrEmpty(string $title, string $text): bool
    {
        $title = strtolower(trim($title));
        $text = strtolower(trim($text));

        $hay = "$title $text";

        $markers = [
            'domain for sale', 'domain is for sale', 'buy this domain', 'this domain is available',
            'parked', 'parking', 'sedoparking', 'godaddy', 'afternic', 'dan.com',
            'future home of', 'coming soon', 'under construction', 'site not published',
            'welcome to nginx', 'apache2 ubuntu default page', 'it works!',
            'default web page', 'index of /', 'test page for',
            'domain parked', 'website coming soon', 'this website is for sale',
            'loader', 'no configuration', 'web server is being configured',
        ];
        foreach ($markers as $m) {
            if (str_contains($hay, $m)) {
                return true;
            }
        }

        $wordCount = $text === '' ? 0 : count(preg_split('/\s+/u', $text) ?: []);
        if ($title === '' && $wordCount <= 5) {
            return true;
        }

        return false;
    }

    /**
     * @return array{title: string, text_sample: string}
     */
    private static function parseHtmlBasics(string $body): array
    {
        if (strlen($body) > 1024 * 1024) {
            $body = substr($body, 0, 1024 * 1024);
        }

        $doc = new \DOMDocument();
        $prev = libxml_use_internal_errors(true);
        $ok = $doc->loadHTML($body, LIBXML_NOERROR | LIBXML_NOWARNING);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if (!$ok) {
            return ['title' => '', 'text_sample' => ''];
        }

        $xp = new \DOMXPath($doc);
        $titleNode = $xp->query('//title')->item(0);
        $title = $titleNode instanceof \DOMNode ? trim($titleNode->textContent) : '';
        $textSample = self::plainText($xp);

        return ['title' => $title, 'text_sample' => $textSample];
    }

    private static function plainText(\DOMXPath $xp): string
    {
        $body = $xp->query('//body')->item(0);
        if (!$body instanceof \DOMNode) {
            return '';
        }

        $clone = $body->cloneNode(true);
        $remove = $xp->query('.//script | .//style | .//noscript', $clone);
        if ($remove !== false && $remove->length > 0) {
            foreach (iterator_to_array($remove) as $n) {
                if ($n->parentNode !== null) {
                    $n->parentNode->removeChild($n);
                }
            }
        }

        $text = preg_replace('/\s+/u', ' ', trim($clone->textContent)) ?? '';
        $words = preg_split('/ /u', $text) ?: [];
        if (count($words) > 300) {
            $words = array_slice($words, 0, 300);
        }
        return implode(' ', $words);
    }

    /**
     * @return list<string>
     */
    private static function shingles(string $text): array
    {
        $words = preg_split('/[^a-z0-9]+/u', strtolower($text)) ?: [];
        $words = array_values(array_filter($words, fn($w) => $w !== ''));
        if (count($words) < 3) {
            return $words === [] ? [] : [implode(' ', $words)];
        }

        $out = [];
        $n = count($words);
        for ($i = 0; $i + 2 < $n; $i++) {
            $out[] = $words[$i] . ' ' . $words[$i + 1] . ' ' . $words[$i + 2];
        }
        return $out;
    }

    /**
     * @param list<string> $ips
     * @return list<string>
     */
    private static function normalizeIps(array $ips): array
    {
        $out = [];
        foreach ($ips as $ip) {
            if (!is_string($ip) || $ip === '') {
                continue;
            }
            $packed = @inet_pton(trim($ip));
            if ($packed === false) {
                continue;
            }
            $out[] = strtolower(trim($ip));
        }
        return array_values(array_unique($out));
    }

    /**
     * @param list<string> $ips
     * @return list<string>
     */
    private static function networksOf(array $ips): array
    {
        $nets = [];
        foreach ($ips as $ip) {
            $packed = @inet_pton($ip);
            if ($packed === false) {
                continue;
            }
            $len = strlen($packed);
            if ($len === 4) {
                $nets[] = substr($packed, 0, 3);
            } elseif ($len === 16) {
                $nets[] = substr($packed, 0, 6);
            }
        }
        return $nets;
    }

    private static function resolveRedirect(string $base, string $loc): ?string
    {
        $loc = trim($loc);
        if ($loc === '') {
            return null;
        }
        if (preg_match('#^https?://#i', $loc)) {
            return $loc;
        }

        $bp = @parse_url($base);
        if (!is_array($bp) || empty($bp['scheme']) || empty($bp['host'])) {
            return null;
        }

        $scheme = (string) $bp['scheme'];
        $host = (string) $bp['host'];
        $port = isset($bp['port']) ? (':' . (int) $bp['port']) : '';

        if (str_starts_with($loc, '//')) {
            return "$scheme:$loc";
        }
        if (!str_starts_with($loc, '/')) {
            $loc = "/$loc";
        }
        return "$scheme://$host$port$loc";
    }
}
