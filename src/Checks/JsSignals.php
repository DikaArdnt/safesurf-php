<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class JsSignals
{
    public static function analyzeHtml(string $html): array
    {
        $out = [
            'script_count' => 0,
            'has_obfuscation' => false,
            'has_eval_atob' => false,
            'has_form_injection' => false,
            'has_js_redirect' => false,
            'disables_context_menu' => false,
            'has_crypto_wallet_hooks' => false,
            'suspicious_score' => 0.0,
            'reasons' => [],
        ];

        if (trim($html) === '') {
            return $out;
        }

        $scripts = self::extractInlineScripts($html);
        $out['script_count'] = count($scripts);
        if ($scripts === []) {
            return $out;
        }

        $joined = implode("\n", $scripts);
        $reasons = [];

        // eval(atob(...)) / unescape(...) / long \x hex or %u escapes = classic packer obfuscation.
        $escapeRun = (int) preg_match_all('/(?:\\\\x[0-9a-fA-F]{2}){8,}/', $joined);
        $pctRun = (int) preg_match_all('/(?:%u[0-9a-fA-F]{4}){6,}/', $joined);
        $obfuscationHits = 0;
        if (preg_match('/eval\s*\(\s*atob\s*\(/i', $joined) === 1) {
            $out['has_eval_atob'] = true;
            $obfuscationHits += 2;
            $reasons[] = 'eval(atob(...)) decoder pattern';
        }
        if (preg_match('/eval\s*\(\s*unescape\s*\(|document\.write\s*\(\s*unescape\s*\(/i', $joined) === 1) {
            $obfuscationHits += 1;
            $reasons[] = 'eval/document.write with unescape()';
        }
        if (preg_match('/String\.fromCharCode\s*\(/i', $joined) === 1 && preg_match('/eval\s*\(|innerHTML|document\.write/i', $joined) === 1) {
            $obfuscationHits += 1;
            $reasons[] = 'String.fromCharCode used with eval/write';
        }
        if ($escapeRun >= 1 || $pctRun >= 1) {
            $obfuscationHits += 1;
            $reasons[] = 'long hex/unicode escape sequences';
        }
        if (preg_match('/\bp\s*=\s*\[[\'"][A-Za-z0-9+\/=]{80,}/', $joined) === 1) {
            $obfuscationHits += 1;
            $reasons[] = 'large embedded encoded blob';
        }
        if ($obfuscationHits > 0) {
            $out['has_obfuscation'] = true;
        }

        // DOM injection of credential-harvesting forms.
        if (
            preg_match('/(?:document\.write|innerHTML|insertAdjacentHTML|appendChild)\s*\(/i', $joined) === 1 &&
            preg_match('/<\s*(form|input)[^>]{0,200}(?:password|type\s*=\s*["\']?password)/i', $joined) === 1
        ) {
            $out['has_form_injection'] = true;
            $reasons[] = 'script injects a form/password input into the DOM';
        }

        // Hard redirects (location replacement) to an absolute URL.
        if (preg_match('/(?:location(?:\.href|\.replace|\.assign)?|window\.location)\s*=\s*["\']https?:\/\//i', $joined) === 1) {
            $out['has_js_redirect'] = true;
            $reasons[] = 'hard JavaScript redirect to absolute URL';
        }

        // Anti-inspection tricks seen in phishing kits.
        if (preg_match('/contextmenu|oncontextmenu|devtools|keydown.*123|F12/i', $joined) === 1) {
            $out['disables_context_menu'] = true;
        }

        // Crypto wallet drainer hooks (ethereum/ethereum.request/signTransaction).
        if (preg_match('/ethereum\s*\.\s*(?:request|enable)|signTransaction|eth_sendTransaction/i', $joined) === 1) {
            $out['has_crypto_wallet_hooks'] = true;
            $reasons[] = 'crypto wallet API hooks';
        }

        $score = 0.0;
        $score += $out['has_eval_atob'] ? 0.4 : 0.0;
        $score += $out['has_obfuscation'] && !$out['has_eval_atob'] ? 0.25 : 0.0;
        $score += $out['has_form_injection'] ? 0.4 : 0.0;
        $score += $out['has_js_redirect'] ? 0.15 : 0.0;
        $score += $out['disables_context_menu'] ? 0.1 : 0.0;
        $score += $out['has_crypto_wallet_hooks'] ? 0.3 : 0.0;

        $out['suspicious_score'] = round(min(1.0, $score), 2);
        $out['reasons'] = $reasons !== [] ? array_values(array_unique($reasons)) : [];

        return $out;
    }

    /**
     * @return list<string>
     */
    public static function extractInlineScripts(string $html): array
    {
        if (preg_match_all('#<script\b[^>]*>(.*?)</script>#is', $html, $m) !== false && !empty($m[1])) {
            $bodies = [];
            foreach ($m[1] as $body) {
                if (is_string($body) && trim($body) !== '') {
                    $bodies[] = $body;
                }
            }
            return $bodies;
        }
        return [];
    }
}
