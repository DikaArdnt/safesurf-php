<?php

declare(strict_types=1);

namespace SafeSurf\Service\ThreatFeeds;

use SafeSurf\Config;

final class PhishTank
{
    private const API_URL = 'https://checkurl.phishtank.com/checkurl/';

    public static function check(string $targetUrl, Config $config): ?array
    {
        $data = [
            'url' => $targetUrl,
            'format' => 'json',
        ];
        if (is_string($config->phishTankApiKey) && $config->phishTankApiKey !== '') {
            $data['app_key'] = $config->phishTankApiKey;
        }

        $ch = curl_init();
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_URL => self::API_URL,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                "User-Agent: {$config->phishTankUserAgent}",
            ],
            CURLOPT_TIMEOUT_MS => 5000,
            CURLOPT_CONNECTTIMEOUT_MS => 1000,
        ]);

        $raw = curl_exec($ch);
        $errno = curl_errno($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

        // Deprecated in PHP 8.5, but we want to support older versions as well.
        if (function_exists('curl_close')) {
            curl_close($ch);
        }

        if ($errno !== 0 || !is_string($raw) || $raw === '' || $status !== 200) {
            return null;
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }
        if (!is_array($decoded)) {
            return null;
        }

        $meta = $decoded['meta'] ?? null;
        if (is_array($meta) && isset($meta['status']) && is_string($meta['status']) && $meta['status'] !== '' && $meta['status'] !== 'success') {
            return null;
        }

        $results = $decoded['results'] ?? null;
        if (!is_array($results)) {
            return null;
        }

        $inDb = !empty($results['in_database']);

        $compact = null;
        try {
            $compact = json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (\Throwable) {
            $compact = null;
        }

        $out = [
            'in_database' => $inDb,
            'phish_id' => 0,
            'phish_detail_page' => '',
            'verified' => false,
            'verified_at' => '',
            'valid' => false,
            'target' => '',
            'from_cache' => false,
            'raw_response' => $compact,
        ];

        if ($inDb) {
            $out['phish_id'] = (int) ($results['phish_id'] ?? 0);
            $out['phish_detail_page'] = (string) ($results['phish_detail_page'] ?? '');
            $out['verified'] = self::parseBoolField($results['verified'] ?? null);
            $out['verified_at'] = (string) ($results['verified_at'] ?? '');
            $out['valid'] = self::parseBoolField($results['valid'] ?? null);
            $out['target'] = (string) ($results['target'] ?? '');
        }

        return $out;
    }

    private static function parseBoolField(mixed $raw): bool
    {
        if (is_bool($raw)) {
            return $raw;
        }
        if (is_string($raw)) {
            $s = strtolower(trim($raw));
            return $s === 'y' || $s === 'true' || $s === '1';
        }
        if (is_int($raw)) {
            return $raw !== 0;
        }
        return false;
    }
}

