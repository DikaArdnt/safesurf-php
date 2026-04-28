<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Util\DomainUtil;
use SafeSurf\Util\HttpClient;

final class Content
{
    public static function analyze(string $pageUrl, Config $config): ?array
    {
        $start = microtime(true);

        $resp = HttpClient::request('GET', $pageUrl, $config, false);
        if ($resp['error'] !== null) {
            return null;
        }

        $body = (string) ($resp['body'] ?? '');
        if ($body === '') {
            return null;
        }
        if (strlen($body) > 5 * 1024 * 1024) {
            $body = substr($body, 0, 5 * 1024 * 1024);
        }

        $pageHost = DomainUtil::hostFromUrl($pageUrl) ?? '';

        $doc = new \DOMDocument();
        $prev = libxml_use_internal_errors(true);
        $ok = $doc->loadHTML($body, LIBXML_NOERROR | LIBXML_NOWARNING);
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
            if (!empty($f['has_password']) || !empty($f['has_user_like'])) {
                $hasLogin = true;
            }
            if (!empty($f['has_payment'])) {
                $hasPayment = true;
            }
            if (!empty($f['has_personal'])) {
                $hasPersonal = true;
            }
        }

        $brandCheck = Brand::checkMismatch($pageHost, $title);

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
            'fetch_duration' => (int) round((microtime(true) - $start) * 1_000_000_000),
            'brand_check' => $brandCheck,
        ];
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
            'submit_texts' => [],
            'is_external' => $external,
            'is_hidden' => self::isHiddenElement($form, $style, $w, $h),
        ];

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

                $info['inputs'][] = self::fmtInputSummary($type, $name, $placeholder, $aria, $id);

                $hay = strtolower("$name $id $placeholder $aria");

                if ($type === 'password' || str_contains($hay, 'pass')) {
                    $info['has_password'] = true;
                }

                if ($type === 'email' || str_contains($hay, 'user') || str_contains($hay, 'login') || str_contains($hay, 'email')) {
                    $info['has_user_like'] = true;
                }

                if (str_contains($hay, 'card') || str_contains($hay, 'cvv') || str_contains($hay, 'expiry') || str_contains($hay, 'credit') ||
                    str_contains($hay, 'money') || str_contains($hay, 'pay') || str_contains($hay, 'billing') || str_contains($hay, 'checkout') || str_contains($hay, 'payment')) {
                    $info['has_payment'] = true;
                }

                if (str_contains($hay, 'address') || str_contains($hay, 'phone') || str_contains($hay, 'ssn') || str_contains($hay, 'dob') ||
                    str_contains($hay, 'birth') || str_contains($hay, 'city') || str_contains($hay, 'zip') || str_contains($hay, 'state')) {
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
                            $info['has_user_like'] = true;
                        }
                        if (str_contains($l, 'pay') || str_contains($l, 'buy') || str_contains($l, 'checkout') || str_contains($l, 'order')) {
                            $info['has_payment'] = true;
                        }
                    }
                    if ($tag === 'label') {
                        if (str_contains($l, 'password')) {
                            $info['has_password'] = true;
                        }
                        if (str_contains($l, 'username') || str_contains($l, 'email') || str_contains($l, 'sign in')) {
                            $info['has_user_like'] = true;
                        }
                        if (str_contains($l, 'card') || str_contains($l, 'cvv') || str_contains($l, 'expiry') || str_contains($l, 'credit')) {
                            $info['has_payment'] = true;
                        }
                        if (str_contains($l, 'address') || str_contains($l, 'phone') || str_contains($l, 'zip')) {
                            $info['has_personal'] = true;
                        }
                    }
                }
            }
        }

        if (!$info['has_user_like']) {
            $a = strtolower($info['action']);
            if (str_contains($a, 'login') || str_contains($a, 'signin') || str_contains($a, 'auth')) {
                $info['has_user_like'] = true;
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
            return "$scheme://$host$port/$raw";
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

    private static function looksLikeLoginText(string $s): bool
    {
        $s = strtolower(trim($s));
        $keywords = ['login', 'log in', 'sign in', 'signin', 'submit', 'sign-on', 'signon', 'sign up', 'signup'];
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
        if (str_contains($style, 'display:none') || str_contains($style, 'visibility:hidden') || str_contains($style, 'opacity:0') ||
            str_contains($style, 'width:0') || str_contains($style, 'height:0')) {
            return true;
        }

        if ($w === '0' || $h === '0') {
            return true;
        }

        return false;
    }
}

