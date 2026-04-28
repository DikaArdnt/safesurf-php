<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

use SafeSurf\Config;
use SafeSurf\Util\DomainUtil;
use SafeSurf\Util\HttpClient;

final class HttpCombined
{
    public static function check(string $rawUrl, Config $config): array
    {
        $redirects = [];
        $current = $rawUrl;
        $lastResponse = null;

        for ($i = 0; $i < $config->maxRedirects; $i++) {
            $resp = HttpClient::fetchHeadOrGet($current, $config);
            $lastResponse = $resp;

            if ($resp['error'] !== null) {
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

            $next = self::resolveUrl($current, $loc);
            if ($next === null) {
                break;
            }

            $redirects[] = $next;
            $current = $next;
        }

        $chain = array_merge([$rawUrl], $redirects);
        $finalUrl = $chain[count($chain) - 1] ?? $rawUrl;
        $finalHost = DomainUtil::hostFromUrl($finalUrl) ?? '';

        $origDomain = null;
        $hasJump = false;
        try {
            $origDomain = DomainUtil::registrableDomainFromUrl($rawUrl, $config->publicSuffixListPath);
        } catch (\Throwable) {
            $origDomain = null;
        }

        if ($origDomain !== null && $origDomain !== '') {
            foreach (array_slice($chain, 1) as $u) {
                try {
                    $d = DomainUtil::registrableDomainFromUrl($u, $config->publicSuffixListPath);
                } catch (\Throwable) {
                    $d = null;
                }
                if ($d !== null && $d !== '' && $d !== $origDomain) {
                    $hasJump = true;
                    break;
                }
            }
        }

        $statusCode = 0;
        $statusText = '';
        $success = false;
        $isRedirect = false;
        $supportsHsts = false;

        if (is_array($lastResponse) && $lastResponse['error'] === null) {
            $statusCode = (int) $lastResponse['status'];
            $statusText = self::statusText($statusCode);
            $success = $statusCode >= 200 && $statusCode < 300;
            $isRedirect = $statusCode >= 300 && $statusCode < 400;

            $scheme = strtolower((string) (parse_url($finalUrl, PHP_URL_SCHEME) ?? ''));
            if ($scheme === 'https') {
                $supportsHsts = isset($lastResponse['headers']['strict-transport-security']);
            }
        }

        if (!$supportsHsts) {
            if ($origDomain !== null && $origDomain !== '') {
                $hstsResp = HttpClient::request('HEAD', "https://$origDomain", $config, true);
                if ($hstsResp['error'] === null) {
                    $supportsHsts = isset($hstsResp['headers']['strict-transport-security']);
                }
            }
        }

        return [
            'redirection_result' => [
                'is_redirected' => count($redirects) > 0,
                'chain_length' => count($chain),
                'chain' => $chain,
                'final_url' => $finalUrl,
                'final_url_domain' => $finalHost,
                'has_domain_jump' => $hasJump,
            ],
            'status_code' => $statusCode,
            'status_text' => $statusText,
            'status_success' => $success,
            'status_is_redirect' => $isRedirect,
            'supports_hsts' => $supportsHsts,
            'error' => $lastResponse['error'] ?? null,
        ];
    }

    private static function resolveUrl(string $base, string $loc): ?string
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

        $path = (string) ($bp['path'] ?? '/');
        if (!str_starts_with($loc, '/')) {
            $dir = rtrim(substr($path, 0, strrpos($path, '/') !== false ? (int) strrpos($path, '/') + 1 : 0), '/');
            $dir = $dir === '' ? '' : ($dir . '/');
            $loc = "/$dir$loc";
        }

        $loc = self::normalizePath($loc);
        return "$scheme://$host$port$loc";
    }

    private static function normalizePath(string $path): string
    {
        $path = preg_replace('#/+#', '/', $path) ?? $path;
        $parts = explode('/', $path);
        $out = [];
        foreach ($parts as $p) {
            if ($p === '' || $p === '.') {
                continue;
            }
            if ($p === '..') {
                array_pop($out);
                continue;
            }
            $out[] = $p;
        }
        return '/' . implode('/', $out);
    }

    private static function statusText(int $code): string
    {
        $map = [
            200 => 'OK',
            201 => 'Created',
            202 => 'Accepted',
            204 => 'No Content',
            301 => 'Moved Permanently',
            302 => 'Found',
            303 => 'See Other',
            307 => 'Temporary Redirect',
            308 => 'Permanent Redirect',
            400 => 'Bad Request',
            401 => 'Unauthorized',
            403 => 'Forbidden',
            404 => 'Not Found',
            408 => 'Request Timeout',
            429 => 'Too Many Requests',
            500 => 'Internal Server Error',
            502 => 'Bad Gateway',
            503 => 'Service Unavailable',
            504 => 'Gateway Timeout',
        ];
        return $map[$code] ?? '';
    }
}

