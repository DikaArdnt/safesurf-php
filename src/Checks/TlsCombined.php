<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class TlsCombined
{
    private static array $knownBadFingerprints = [
        'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF' => true,
    ];

    public static function check(string $domain): array
    {
        $domain = strtolower(trim($domain));
        $sslInfo = [
            'domain' => $domain,
            'has_tls' => false,
            'chain_valid' => false,
            'issuer' => '',
            'not_before' => null,
            'not_after' => null,
            'age_days' => 0,
            'fingerprint' => '',
            'is_suspicious' => false,
            'reasons' => [],
            'ct_logged' => false,
            'known_bad_chain' => false,
        ];

        $tlsInfo = [
            'present' => false,
            'issuer' => '',
            'age_days' => 0,
            'hostname_mismatch' => false,
        ];

        if ($domain === '' || filter_var($domain, FILTER_VALIDATE_IP)) {
            return ['tls_info' => $tlsInfo, 'ssl_info' => $sslInfo, 'error' => 'invalid_domain'];
        }

        $cert = null;
        $err = null;

        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $domain,
            ],
        ]);

        $fp = @stream_socket_client(
            "ssl://$domain:443",
            $errno,
            $errstr,
            5.0,
            STREAM_CLIENT_CONNECT,
            $ctx
        );

        if (!is_resource($fp)) {
            $sslInfo['has_tls'] = false;
            $sslInfo['reasons'][] = 'TLS connection failed: ' . ($errstr !== '' ? $errstr : (string) $errno);
            return ['tls_info' => $tlsInfo, 'ssl_info' => $sslInfo, 'error' => $errstr !== '' ? $errstr : (string) $errno];
        }

        $params = stream_context_get_params($fp);
        fclose($fp);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if ($cert === null) {
            $sslInfo['reasons'][] = 'no peer certificates';
            return ['tls_info' => $tlsInfo, 'ssl_info' => $sslInfo, 'error' => null];
        }

        $sslInfo['has_tls'] = true;
        $tlsInfo['present'] = true;

        $parsed = @openssl_x509_parse($cert);
        if (is_array($parsed)) {
            $issuer = '';
            if (isset($parsed['issuer']) && is_array($parsed['issuer'])) {
                $issuer = (string) ($parsed['issuer']['O'] ?? $parsed['issuer']['CN'] ?? '');
            }
            $sslInfo['issuer'] = $issuer;
            $tlsInfo['issuer'] = $issuer;

            $nb = isset($parsed['validFrom_time_t']) ? (int) $parsed['validFrom_time_t'] : null;
            $na = isset($parsed['validTo_time_t']) ? (int) $parsed['validTo_time_t'] : null;
            $sslInfo['not_before'] = $nb !== null ? gmdate('c', $nb) : null;
            $sslInfo['not_after'] = $na !== null ? gmdate('c', $na) : null;
            if ($nb !== null) {
                $sslInfo['age_days'] = (int) floor((time() - $nb) / 86400);
                $tlsInfo['age_days'] = $sslInfo['age_days'];
            }

            if ($nb !== null && $na !== null) {
                $validityDays = (int) floor(($na - $nb) / 86400);
                if ($validityDays > 398) {
                    $sslInfo['reasons'][] = 'unusually long validity period';
                }
            }

            if ($na !== null && time() > $na) {
                $sslInfo['is_suspicious'] = true;
                $sslInfo['reasons'][] = 'certificate expired';
            }
            if ($nb !== null && time() < $nb) {
                $sslInfo['is_suspicious'] = true;
                $sslInfo['reasons'][] = 'certificate not yet valid';
            }
        }

        if (function_exists('openssl_x509_fingerprint')) {
            $fpHex = @openssl_x509_fingerprint($cert, 'sha256');
            if (is_string($fpHex) && $fpHex !== '') {
                $sslInfo['fingerprint'] = strtoupper(str_replace(':', '', $fpHex));
            }
        }

        if ($sslInfo['fingerprint'] !== '' && isset(self::$knownBadFingerprints[$sslInfo['fingerprint']])) {
            $sslInfo['is_suspicious'] = true;
            $sslInfo['known_bad_chain'] = true;
            $sslInfo['reasons'][] = 'certificate fingerprint is blacklisted';
        }

        if (function_exists('openssl_x509_check_host')) {
            $ok = @openssl_x509_check_host($cert, $domain, 0);
            $tlsInfo['hostname_mismatch'] = $ok === false;
        }

        if (isset($parsed['extensions']) && is_array($parsed['extensions']) && in_array('1.3.6.1.4.1.11129.2.4.2', array_keys($parsed['extensions']))) {
            $sslInfo['ct_logged'] = true;
        } else {
            $sslInfo['is_suspicious'] = true;
            $sslInfo['reasons'][] = 'certificate does not contain CT log extension';
        }


        $sslInfo['chain_valid'] = self::verifyChain($domain);
        if (!$sslInfo['chain_valid']) {
            $sslInfo['reasons'][] = 'cert chain invalid';
        }

        $sslInfo['reasons'] = array_values(array_unique($sslInfo['reasons']));

        return ['tls_info' => $tlsInfo, 'ssl_info' => $sslInfo, 'error' => $err];
    }

    private static function verifyChain(string $domain): bool
    {
        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => false,
                'verify_peer' => true,
                'verify_peer_name' => true,
                'SNI_enabled' => true,
                'peer_name' => $domain,
                'allow_self_signed' => false,
            ],
        ]);

        $fp = @stream_socket_client(
            "ssl://$domain:443",
            $errno,
            $errstr,
            5.0,
            STREAM_CLIENT_CONNECT,
            $ctx
        );

        if (!is_resource($fp)) {
            return false;
        }
        fclose($fp);
        return true;
    }
}
