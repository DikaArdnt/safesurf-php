<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Constants\DataFiles;
use SafeSurf\Util\DomainUtil;
use SafeSurf\Util\HttpClient;

final class Content
{
    private const MAX_TEXT_SAMPLE_WORDS = 300;

    public static function analyze(string $pageUrl, Config $config): ?array
    {
        $start = microtime(true);

        $resp = HttpClient::request('GET', $pageUrl, $config, false);
        if ($resp['error'] !== null) {
            return null;
        }

        $body = (string) ($resp['body'] ?? '');
        $status = (int) ($resp['status'] ?? 200);
        $headers = is_array($resp['headers'] ?? null) ? $resp['headers'] : [];

        $out = self::analyzeHtml($body, $pageUrl, $config, $status, $headers);
        if (is_array($out)) {
            $out['fetch_duration'] = (int) round((microtime(true) - $start) * 1_000_000_000);
        }

        return $out;
    }

    public static function analyzeHtml(string $body, string $pageUrl, Config $config, int $status = 200, array $headers = []): ?array
    {
        if ($body === '') {
            return null;
        }
        if (strlen($body) > 5 * 1024 * 1024) {
            $body = substr($body, 0, 5 * 1024 * 1024);
        }

        $pageHost = DomainUtil::hostFromUrl($pageUrl) ?? '';

        $doc = new \DOMDocument();
        $prev = libxml_use_internal_errors(true);
        $ok = $doc->loadHTML($body, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if ($ok === false) {
            return null;
        }

        $xp = new \DOMXPath($doc);

        $titleNode = $xp->query('//title')->item(0);
        $title = $titleNode instanceof \DOMNode ? trim($titleNode->textContent) : '';

        $forms = [];
        $formNodes = $xp->query('//form');
        if ($formNodes !== false) {
            foreach ($formNodes as $formNode) {
                if (!$formNode instanceof \DOMElement) {
                    continue;
                }
                $forms[] = self::extractFormInfo($formNode, $pageUrl, $pageHost, $config);
            }
        }

        $iframes = [];
        $hasHiddenIframe = false;
        $iframeNodes = $xp->query('//iframe');
        if ($iframeNodes !== false) {
            foreach ($iframeNodes as $iframeNode) {
                if (!$iframeNode instanceof \DOMElement) {
                    continue;
                }
                $src = trim($iframeNode->getAttribute('src'));
                $w = trim($iframeNode->getAttribute('width'));
                $h = trim($iframeNode->getAttribute('height'));
                $style = trim($iframeNode->getAttribute('style'));
                $hidden = self::isHiddenElement($iframeNode, $style, $w, $h);
                $iframes[] = [
                    'src' => $src,
                    'is_hidden' => $hidden,
                    'width' => $w,
                    'height' => $h,
                ];
                if ($hidden) {
                    $hasHiddenIframe = true;
                }
            }
        }

        $hasTracking = false;
        $imgNodes = $xp->query('//img');
        if ($imgNodes !== false) {
            foreach ($imgNodes as $imgNode) {
                if (!$imgNode instanceof \DOMElement) {
                    continue;
                }
                $w = trim($imgNode->getAttribute('width'));
                $h = trim($imgNode->getAttribute('height'));
                if (($w === '1' && $h === '1') || ($w === '0' && $h === '0')) {
                    $hasTracking = true;
                    break;
                }
            }
        }

        $hasLogin = false;
        $hasPayment = false;
        $hasPersonal = false;

        foreach ($forms as $f) {
            if (!is_array($f)) {
                continue;
            }
            if (!empty($f['has_password']) || (!empty($f['has_user_like']) && !empty($f['login_intent']))) {
                $hasLogin = true;
            }
            if (!empty($f['has_payment'])) {
                $hasPayment = true;
            }
            if (!empty($f['has_personal'])) {
                $hasPersonal = true;
            }
        }

        $favicon = self::analyzeFavicon($xp, $pageUrl, $pageHost, $config);
        $assets = self::analyzeExternalAssets($xp, $pageUrl, $pageHost, $config);
        $metaRefresh = self::analyzeMetaRefresh($doc, $pageUrl, $pageHost, $config);
        $textSample = self::extractTextSample($xp);
        $jsSignals = JsSignals::analyzeHtml($body);

        $scripts = [];
        $scriptNodes = $xp->query('//script');
        if ($scriptNodes !== false) {
            foreach ($scriptNodes as $sNode) {
                if ($sNode instanceof \DOMElement && !$sNode->hasAttribute('src')) {
                    $scripts[] = $sNode->textContent;
                }
            }
        }

        $brandCheck = Brand::checkMismatch($pageHost, $title);
        $brandsInText = Brand::namesInText($textSample);

        $faviconBrandMismatch = false;
        if (!empty($favicon['brand_domain'])) {
            $faviconBrandMismatch = !self::sameHost($favicon['brand_domain'], $pageHost, $config);
        }
        $favicon['brand_mismatch'] = $faviconBrandMismatch;

        $nonOfficialBrandText = [];
        foreach ($brandsInText as $brandName) {
            $official = Brand::officialDomainsFor($brandName);
            if (!self::hostIsOfficial($pageHost, $official, $config)) {
                $nonOfficialBrandText[] = $brandName;
            }
        }

        $loginWithBrandText = $hasLogin && $nonOfficialBrandText !== [];

        $scriptRedirect = self::detectScriptRedirect($scripts, !empty($metaRefresh['target']) ? (string) $metaRefresh['target'] : null, $pageHost, strlen($textSample), $config);
        $providerBlock = self::detectProviderBlock($status, $title, $headers);

        $contentType = null;
        if (!empty($headers['content-type'])) {
            $ct = is_array($headers['content-type']) ? (string) $headers['content-type'][0] : (string) $headers['content-type'];
            $contentType = trim(explode(';', $ct)[0]);
        }

        $fileName = self::extractFileName($pageUrl, $headers);

        return [
            'url' => $pageUrl,
            'title' => $title,
            'has_forms' => count($forms) > 0,
            'has_login_form' => $hasLogin,
            'has_payment_form' => $hasPayment,
            'has_personal_form' => $hasPersonal,
            'form_count' => count($forms),
            'forms' => $forms,
            'iframes' => $iframes,
            'has_hidden_iframe' => $hasHiddenIframe,
            'has_tracking' => $hasTracking,
            'fetch_duration' => 0,
            'brand_check' => $brandCheck,
            'text_sample' => $textSample,
            'favicon' => $favicon,
            'content_type' => $contentType,
            'file_name' => $fileName,
            'script_redirect' => $scriptRedirect,
            'provider_block' => $providerBlock,
            'phishing_patterns' => [
                'favicon_external' => !empty($favicon['is_external']),
                'favicon_brand_mismatch' => $faviconBrandMismatch,
                'meta_refresh_external' => !empty($metaRefresh['is_external']),
                'meta_refresh' => $metaRefresh,
                'external_asset_hosts' => $assets['hosts'],
                'external_asset_count' => $assets['count'],
                'brand_names_in_text' => $nonOfficialBrandText,
                'login_with_brand_text' => $loginWithBrandText,
                'js_signals' => $jsSignals,
                'script_redirect' => $scriptRedirect,
                'provider_block' => $providerBlock,
            ],
        ];
    }

    private static function extractFileName(string $pageUrl, array $headers): ?string
    {
        if (!empty($headers['content-disposition'])) {
            $cd = is_array($headers['content-disposition']) ? implode(';', $headers['content-disposition']) : (string) $headers['content-disposition'];
            if (preg_match('/filename\*?=(?:UTF-8\'\')?["\']?([^";\r\n]+)["\']?/i', $cd, $m)) {
                return trim($m[1]);
            }
        }
        $path = (string) (parse_url($pageUrl, PHP_URL_PATH) ?? '');
        $base = basename($path);
        if ($base !== '' && $base !== '/' && str_contains($base, '.')) {
            return $base;
        }
        return null;
    }

    public static function detectProviderBlock(int $statusCode, string $title, array $headers): ?array
    {
        if (preg_match('/^suspected\s+(phishing|malware)\s*\|\s*cloudflare$/i', trim($title), $m)) {
            return ['provider' => 'Cloudflare', 'reason' => strtolower($m[1])];
        }
        if ($statusCode === 451) {
            $server = '';
            foreach ($headers['server'] ?? [] as $s) {
                $server .= ' ' . $s;
            }
            $provider = str_contains(strtolower($server), 'vercel') ? 'Vercel' : 'The hosting provider';
            return ['provider' => $provider, 'reason' => 'blocked'];
        }
        return null;
    }

    public static function detectScriptRedirect(array $scripts, ?string $metaRefreshTarget, string $pageHost, int $visibleTextLen, Config $config): ?array
    {
        $found = null;
        $thinPage = $visibleTextLen < 200;

        $consider = function (string $target, bool $fromScript) use (&$found, $pageHost, $thinPage, $config): void {
            $target = trim($target);
            if ($target === '') {
                return;
            }
            $parts = @parse_url($target);
            if (!is_array($parts) || empty($parts['host'])) {
                return;
            }
            $scheme = strtolower((string) ($parts['scheme'] ?? ''));
            if ($scheme !== 'http' && $scheme !== 'https' && $scheme !== '') {
                return;
            }
            $host = strtolower((string) $parts['host']);
            $toIp = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && !HttpClient::isPrivateIp($host);
            $crossDomain = !self::sameHost($host, $pageHost, $config);

            if (!$toIp && (!$crossDomain || ($fromScript && !$thinPage))) {
                return;
            }
            $r = ['target' => $target, 'to_ip' => $toIp, 'cross_domain' => $crossDomain];
            if ($found === null || ($toIp && empty($found['to_ip']))) {
                $found = $r;
            }
        };

        if ($metaRefreshTarget !== null && $metaRefreshTarget !== '') {
            $consider($metaRefreshTarget, false);
        }

        foreach ($scripts as $js) {
            if (!preg_match('/location(?:\.href)?\s*=[^=]|location\.(?:replace|assign)\s*\(/i', $js)) {
                continue;
            }
            if (preg_match_all('/location(?:\.href)?\s*=\s*["\']([^"\']+)["\']|location\.(?:replace|assign)\s*\(\s*["\']([^"\']+)["\']/i', $js, $m, PREG_SET_ORDER)) {
                foreach ($m as $match) {
                    $tgt = $match[1] !== '' ? $match[1] : ($match[2] ?? '');
                    $consider($tgt, true);
                }
            }
            if ($found !== null && !empty($found['to_ip'])) {
                continue;
            }
            if (preg_match_all('/["\'\/](\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?["\'\/:?]/', $js, $ipMatches)) {
                foreach ($ipMatches[1] as $rawIp) {
                    if (filter_var($rawIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && !HttpClient::isPrivateIp($rawIp)) {
                        $found = ['target' => $rawIp, 'to_ip' => true, 'cross_domain' => true];
                        break;
                    }
                }
            }
        }

        return $found;
    }

    public static function executableExt(string $nameOrUrl): ?string
    {
        $path = (string) (parse_url($nameOrUrl, PHP_URL_PATH) ?? $nameOrUrl);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === '') {
            return null;
        }
        $ext = ".$ext";
        $execExts = [
            '.exe' => true, '.msi' => true, '.scr' => true, '.bat' => true, '.cmd' => true, '.pif' => true,
            '.vbs' => true, '.jse' => true, '.wsf' => true, '.ps1' => true, '.hta' => true, '.jar' => true,
            '.apk' => true, '.xapk' => true, '.dmg' => true, '.pkg' => true, '.deb' => true, '.rpm' => true,
            '.appimage' => true, '.lnk' => true, '.iso' => true,
        ];
        return isset($execExts[$ext]) ? $ext : null;
    }

    public static function isMarketingFormService(string $action): bool
    {
        $host = DomainUtil::hostFromUrl($action);
        if ($host === null || $host === '') {
            return false;
        }
        $hosts = DataFiles::marketingFormHosts();
        for ($d = $host; $d !== ''; ) {
            if (isset($hosts[$d])) {
                return true;
            }
            $dot = strpos($d, '.');
            if ($dot === false) {
                break;
            }
            $d = substr($d, $dot + 1);
        }
        return false;
    }

    public static function asksPersonal(string $s): bool
    {
        $words = preg_split('/[^A-Za-z0-9]+/', $s) ?: [];
        $personalWords = [
            'address' => true, 'street' => true, 'phone' => true, 'telephone' => true, 'mobile' => true,
            'ssn' => true, 'dob' => true, 'birth' => true, 'birthday' => true, 'birthdate' => true,
            'city' => true, 'zip' => true, 'zipcode' => true, 'postal' => true, 'postcode' => true, 'state' => true,
        ];
        $addressOf = ['email' => true, 'e' => true, 'mail' => true, 'ip' => true, 'web' => true, 'wallet' => true];

        foreach ($words as $i => $w) {
            $wLower = strtolower($w);
            if (!isset($personalWords[$wLower])) {
                continue;
            }
            if ($wLower === 'address' && $i > 0 && isset($addressOf[strtolower((string) ($words[$i - 1] ?? ''))])) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static function analyzeFavicon(\DOMXPath $xp, string $pageUrl, string $pageHost, Config $config): array
    {
        $out = [
            'href' => '',
            'is_external' => false,
            'external_host' => '',
            'brand_domain' => '',
        ];

        $links = $xp->query('//link');
        if ($links === false) {
            return $out;
        }

        $href = '';
        foreach ($links as $link) {
            if (!$link instanceof \DOMElement) {
                continue;
            }
            $rel = strtolower(trim($link->getAttribute('rel')));
            if ($rel === '' || !str_contains($rel, 'icon')) {
                continue;
            }
            $candidate = trim($link->getAttribute('href'));
            if ($candidate === '' || $candidate === '#') {
                continue;
            }
            $href = $candidate;
            break;
        }

        if ($href === '') {
            return $out;
        }

        $out['href'] = $href;

        $abs = self::absoluteUrl($pageUrl, $href);
        $host = DomainUtil::hostFromUrl($abs) ?? '';
        if ($host !== '' && $pageHost !== '' && !self::sameHost($host, $pageHost, $config)) {
            $out['is_external'] = true;
            $out['external_host'] = $host;
            $brandDomain = self::brandOfficialHost($host);
            if ($brandDomain !== null) {
                $out['brand_domain'] = $brandDomain;
            }
        }

        return $out;
    }

    private static function brandOfficialHost(string $host): ?string
    {
        foreach (DataFiles::brands() as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $official = $entry['official_domains'] ?? [];
            if (!is_array($official)) {
                continue;
            }
            foreach ($official as $domain) {
                if (!is_string($domain) || $domain === '') {
                    continue;
                }
                $domain = strtolower($domain);
                if ($host === $domain || str_ends_with($host, ".$domain")) {
                    return $domain;
                }
            }
        }
        return null;
    }

    private static function analyzeExternalAssets(\DOMXPath $xp, string $pageUrl, string $pageHost, Config $config): array
    {
        $hosts = [];
        $count = 0;

        $nodes = $xp->query('//script[@src] | //link[@href] | //img[@src]');
        if ($nodes === false || $pageHost === '') {
            return ['hosts' => [], 'count' => 0];
        }

        foreach ($nodes as $n) {
            if (!$n instanceof \DOMElement) {
                continue;
            }
            $tag = strtolower($n->tagName);
            $raw = $tag === 'link' ? trim($n->getAttribute('href')) : trim($n->getAttribute('src'));
            if ($raw === '' || str_starts_with($raw, 'data:')) {
                continue;
            }
            $abs = self::absoluteUrl($pageUrl, $raw);
            $host = DomainUtil::hostFromUrl($abs) ?? '';
            if ($host === '' || self::sameHost($host, $pageHost, $config)) {
                continue;
            }
            $count++;
            if (count($hosts) < 10) {
                $hosts[$host] = true;
            }
        }

        return ['hosts' => array_keys($hosts), 'count' => $count];
    }

    private static function analyzeMetaRefresh(\DOMDocument $doc, string $pageUrl, string $pageHost, Config $config): array
    {
        $out = [
            'present' => false,
            'delay_seconds' => null,
            'target' => '',
            'is_external' => false,
        ];

        $xp = new \DOMXPath($doc);
        $nodes = $xp->query('//meta[translate(@http-equiv, "REFSH", "refsh") = "refresh"]');
        if ($nodes === false || $nodes->length === 0) {
            return $out;
        }

        $meta = $nodes->item(0);
        if (!$meta instanceof \DOMElement) {
            return $out;
        }

        $content = trim($meta->getAttribute('content'));
        if ($content === '') {
            return $out;
        }

        $out['present'] = true;
        if (preg_match('/^(\d+)/', $content, $m)) {
            $out['delay_seconds'] = (int) $m[1];
        }

        if (preg_match('/url\s*=\s*[\'"]?([^\'";\s]+)/i', $content, $m)) {
            $target = trim($m[1]);
            $abs = self::absoluteUrl($pageUrl, $target);
            $out['target'] = $abs;
            $targetHost = DomainUtil::hostFromUrl($abs) ?? '';
            if ($targetHost !== '' && $pageHost !== '') {
                $out['is_external'] = !self::sameHost($targetHost, $pageHost, $config);
            }
        }

        return $out;
    }

    private static function extractTextSample(\DOMXPath $xp): string
    {
        $body = $xp->query('//body')->item(0);
        if (!$body instanceof \DOMElement) {
            return '';
        }

        $clone = $body->cloneNode(true);
        $xpClone = new \DOMXPath($clone->ownerDocument ?? new \DOMDocument());
        $drop = $xpClone->query('.//script | .//style | .//noscript', $clone);
        if ($drop !== false) {
            foreach ($drop as $d) {
                if ($d instanceof \DOMNode && $d->parentNode !== null) {
                    $d->parentNode->removeChild($d);
                }
            }
        }

        $text = (string) $clone->textContent;
        $words = preg_split('/\s+/u', trim($text)) ?: [];
        $slice = array_slice($words, 0, self::MAX_TEXT_SAMPLE_WORDS);
        return implode(' ', $slice);
    }

    private static function absoluteUrl(string $baseUrl, string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '' || $raw === '#') {
            return $baseUrl;
        }
        if (preg_match('#^https?://#i', $raw)) {
            return $raw;
        }

        $base = @parse_url($baseUrl);
        if (!is_array($base) || empty($base['scheme']) || empty($base['host'])) {
            return $raw;
        }
        $scheme = (string) $base['scheme'];
        $host = (string) $base['host'];
        $port = isset($base['port']) ? (':' . (int) $base['port']) : '';

        if (str_starts_with($raw, '//')) {
            return "$scheme:$raw";
        }
        if (str_starts_with($raw, '/')) {
            return "$scheme://$host$port$raw";
        }

        $path = (string) ($base['path'] ?? '/');
        $dir = substr($path, 0, strrpos($path, '/') !== false ? (int) strrpos($path, '/') + 1 : 0);
        return "$scheme://$host$port/$dir$raw";
    }

    private static function hostIsOfficial(string $host, array $officialDomains, Config $config): bool
    {
        if ($host === '') {
            return false;
        }
        foreach ($officialDomains as $official) {
            if (!is_string($official) || $official === '') {
                continue;
            }
            if (self::sameHost($official, $host, $config)) {
                return true;
            }
        }
        return false;
    }

    private static function extractFormInfo(\DOMElement $form, string $baseUrl, string $pageHost, Config $config): array
    {
        $style = trim($form->getAttribute('style'));
        $w = trim($form->getAttribute('width'));
        $h = trim($form->getAttribute('height'));

        $method = strtoupper(trim($form->getAttribute('method')));
        if ($method === '') {
            $method = 'GET';
        }

        $rawAction = trim($form->getAttribute('action'));
        $action = self::resolveAction($baseUrl, $rawAction);

        $external = false;
        $actionHost = DomainUtil::hostFromUrl($action) ?? '';
        if ($actionHost !== '' && $pageHost !== '') {
            $external = !self::sameHost($actionHost, $pageHost, $config);
        }

        $info = [
            'action' => $action,
            'method' => $method,
            'inputs' => [],
            'has_password' => false,
            'has_user_like' => false,
            'has_payment' => false,
            'has_personal' => false,
            'login_intent' => false,
            'is_marketing' => self::isMarketingFormService($action),
            'submit_texts' => [],
            'is_external' => $external,
            'is_hidden' => self::isHiddenElement($form, $style, $w, $h),
        ];

        if (preg_match('/(?:login|signin|auth)/i', $action)) {
            $info['login_intent'] = true;
        }

        $nodes = $form->getElementsByTagName('*');
        foreach ($nodes as $n) {
            if (!$n instanceof \DOMElement) {
                continue;
            }
            $tag = strtolower($n->tagName);

            if ($tag === 'input') {
                $type = strtolower(trim($n->getAttribute('type')));
                $name = trim($n->getAttribute('name'));
                $placeholder = trim($n->getAttribute('placeholder'));
                $aria = trim($n->getAttribute('aria-label'));
                $id = trim($n->getAttribute('id'));
                $auto = strtolower(trim($n->getAttribute('autocomplete')));
                $inputmode = strtolower(trim($n->getAttribute('inputmode')));

                $info['inputs'][] = self::fmtInputSummary($type, $name, $placeholder, $aria, $id);

                if ($type === 'submit' || $type === 'button') {
                    $v = trim($n->getAttribute('value'));
                    if ($v !== '') {
                        $info['submit_texts'][] = $v;
                        if (self::looksLikeLoginText($v)) {
                            $info['login_intent'] = true;
                        }
                    }
                }

                $hay = strtolower("$name $id $placeholder $aria $auto $inputmode");

                if ($type === 'password' || str_contains($hay, 'pass') || str_contains($auto, 'password') || str_contains($hay, 'pin') || str_contains($hay, 'secret')) {
                    $info['has_password'] = true;
                }

                if ($type === 'email' || str_contains($hay, 'user') || str_contains($hay, 'login') || str_contains($hay, 'email') || str_contains($auto, 'username') || str_contains($auto, 'email')) {
                    $info['has_user_like'] = true;
                }

                if (
                    str_contains($hay, 'card') || str_contains($hay, 'cvv') || str_contains($hay, 'cvc') || str_contains($hay, 'expiry') || str_contains($hay, 'credit') ||
                    str_contains($hay, 'money') || str_contains($hay, 'pay') || str_contains($hay, 'billing') || str_contains($hay, 'checkout') || str_contains($hay, 'payment') ||
                    str_contains($auto, 'cc-') || str_contains($hay, 'cardnumber')
                ) {
                    $info['has_payment'] = true;
                }

                if (
                    $type === 'tel' ||
                    self::asksPersonal($name) ||
                    self::asksPersonal($id) ||
                    self::asksPersonal($placeholder) ||
                    str_contains($auto, 'postal-code') || str_contains($auto, 'street-address') || str_contains($auto, 'tel')
                ) {
                    $info['has_personal'] = true;
                }
            }

            if ($tag === 'button' || $tag === 'a' || $tag === 'label') {
                $txt = trim($n->textContent);
                if ($txt !== '') {
                    $l = strtolower($txt);
                    if ($tag === 'button' || $tag === 'a') {
                        $info['submit_texts'][] = $txt;
                        if (self::looksLikeLoginText($l)) {
                            $info['login_intent'] = true;
                        }
                        if (str_contains($l, 'pay') || str_contains($l, 'buy') || str_contains($l, 'checkout') || str_contains($l, 'order')) {
                            $info['has_payment'] = true;
                        }
                    }
                    if ($tag === 'label') {
                        if (str_contains($l, 'password')) {
                            $info['has_password'] = true;
                        }
                        if (str_contains($l, 'username') || str_contains($l, 'email')) {
                            $info['has_user_like'] = true;
                        }
                        if (str_contains($l, 'sign in') || str_contains($l, 'login')) {
                            $info['login_intent'] = true;
                        }
                        if (str_contains($l, 'card') || str_contains($l, 'cvv') || str_contains($l, 'expiry') || str_contains($l, 'credit')) {
                            $info['has_payment'] = true;
                        }
                        if (self::asksPersonal($l)) {
                            $info['has_personal'] = true;
                        }
                    }
                }
            }
        }

        $info['submit_texts'] = array_values(array_unique($info['submit_texts']));
        return $info;
    }

    private static function sameHost(string $a, string $b, Config $config): bool
    {
        if (strcasecmp($a, $b) === 0) {
            return true;
        }
        try {
            $da = DomainUtil::registrableDomainFromUrl("https://$a", $config->publicSuffixListPath);
            $db = DomainUtil::registrableDomainFromUrl("https://$b", $config->publicSuffixListPath);
        } catch (\Throwable) {
            return false;
        }
        return $da !== null && $db !== null && strcasecmp($da, $db) === 0;
    }

    private static function resolveAction(string $baseUrl, string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '' || $raw === '#') {
            return $baseUrl;
        }
        if (preg_match('#^https?://#i', $raw)) {
            return $raw;
        }

        $base = @parse_url($baseUrl);
        if (!is_array($base) || empty($base['scheme']) || empty($base['host'])) {
            return $raw;
        }
        $scheme = (string) $base['scheme'];
        $host = (string) $base['host'];
        $port = isset($base['port']) ? (':' . (int) $base['port']) : '';

        if (str_starts_with($raw, '//')) {
            return "$scheme:$raw";
        }
        if (str_starts_with($raw, '/')) {
            return "$scheme://$host$port$raw";
        }

        $path = (string) ($base['path'] ?? '/');
        $dir = substr($path, 0, strrpos($path, '/') !== false ? (int) strrpos($path, '/') + 1 : 0);
        return "$scheme://$host$port/$dir$raw";
    }

    private static function fmtInputSummary(string $type, string $name, string $placeholder, string $aria, string $id): string
    {
        $parts = [];
        if ($type !== '') {
            $parts[] = "type=$type";
        }
        if ($name !== '') {
            $parts[] = "name=$name";
        }
        if ($id !== '') {
            $parts[] = "id=$id";
        }
        if ($placeholder !== '') {
            $parts[] = "ph=$placeholder";
        }
        if ($aria !== '') {
            $parts[] = "aria=$aria";
        }
        return implode('|', $parts);
    }

    public static function looksLikeLoginText(string $s): bool
    {
        $s = strtolower(trim($s));
        $keywords = ['login', 'log in', 'sign in', 'signin', 'sign-on', 'signon', 'next', 'continue', 'verify'];
        foreach ($keywords as $k) {
            if (str_contains($s, $k)) {
                return true;
            }
        }
        return false;
    }

    private static function isHiddenElement(\DOMElement $n, string $style, string $w, string $h): bool
    {
        if ($n->hasAttribute('hidden')) {
            return true;
        }
        if (strtolower($n->getAttribute('type')) === 'hidden') {
            return true;
        }

        $style = strtolower($style);
        if (
            str_contains($style, 'display:none') || str_contains($style, 'visibility:hidden') || str_contains($style, 'opacity:0') ||
            str_contains($style, 'width:0') || str_contains($style, 'height:0')
        ) {
            return true;
        }

        if ($w === '0' || $h === '0') {
            return true;
        }

        return false;
    }
}
