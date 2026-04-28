<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class Entropy
{
    private const MAX_ALPHABET_BITS = 5.954196310386875;

    private static array $commonBigrams = [
        'th' => true, 'he' => true, 'in' => true, 'er' => true, 'an' => true, 're' => true, 'on' => true, 'at' => true, 'en' => true, 'nd' => true,
        'ti' => true, 'es' => true, 'or' => true, 'te' => true, 'of' => true, 'ed' => true, 'is' => true, 'it' => true, 'al' => true, 'ar' => true,
        'st' => true, 'to' => true, 'nt' => true, 'ng' => true, 'se' => true, 'ha' => true, 'as' => true, 'ou' => true, 'io' => true, 'le' => true,
    ];

    public static function analyzeDomainRandomness(string $domain): array
    {
        $label = self::extractSld($domain);
        $s = self::sanitizeLabel($label);

        $ent = self::shannonEntropy($s);
        $epc = $s === '' ? 0.0 : ($ent / self::runeLength($s));
        $normE = self::normalizedEntropy($s);
        $vRatio = self::vowelRatio($s);
        $dRatio = self::digitRatio($s);
        $uRatio = self::uniqueCharRatio($s);
        $longRun = self::longestConsonantRunLength($s);
        $bigram = self::bigramEnglishiness($s);

        $longRunNorm = min($longRun / 6.0, 1.0);

        $score = 0.0;
        $score += 0.25 * $normE;
        $score += 0.15 * (1.0 - $vRatio);
        $score += 0.15 * $dRatio;
        $score += 0.20 * (1.0 - $bigram);
        $score += 0.10 * (1.0 - $uRatio);
        $score += 0.15 * $longRunNorm;

        $score = max(0.0, min(1.0, $score));

        $len = self::runeLength($s);
        $baseThreshold = 0.50;
        $adjThreshold = $baseThreshold;
        if ($len > 0 && $len < 6) {
            $boost = 0.10 * ((6.0 - $len) / 5.0);
            $adjThreshold = $baseThreshold + $boost;
        }

        $isSusp = false;
        $reasons = [];

        if ($score > $adjThreshold) {
            $isSusp = true;
            $reasons[] = sprintf('high randomness score=%.3f>threshold=%.3f', $score, $adjThreshold);
        }

        if ($longRun >= 6) {
            $isSusp = true;
            $reasons[] = sprintf('long consonant/digit run=%d', $longRun);
        }

        if ($dRatio > 0.5 && $len >= 6) {
            $isSusp = true;
            $reasons[] = sprintf('high digit ratio=%.2f', $dRatio);
        }

        if ($uRatio < 0.25 && $len >= 6) {
            $reasons[] = sprintf('low unique-char-ratio=%.2f', $uRatio);
        }

        $reasons = array_values(array_unique($reasons));

        return [
            'domain' => $domain,
            'label' => $label,
            'length' => $len,
            'entropy' => $ent,
            'entropy_per_char' => $epc,
            'normalized_entropy' => $normE,
            'vowel_ratio' => $vRatio,
            'digit_ratio' => $dRatio,
            'unique_char_ratio' => $uRatio,
            'longest_consonant_run' => $longRun,
            'bigram_englishiness' => $bigram,
            'randomness_score' => $score,
            'is_suspicious' => $isSusp,
            'reasons' => $reasons,
        ];
    }

    private static function extractSld(string $domain): string
    {
        $domain = strtolower(trim($domain));
        $domain = preg_replace('#^https?://#', '', $domain) ?? $domain;
        $domain = preg_split('/[\\/?#]/', $domain)[0] ?? $domain;
        $domain = explode(':', $domain)[0] ?? $domain;
        $parts = explode('.', $domain);
        if (count($parts) >= 2) {
            return $parts[count($parts) - 2];
        }
        return implode('', $parts);
    }

    private static function sanitizeLabel(string $label): string
    {
        $label = strtolower($label);
        $out = '';
        $len = strlen($label);
        for ($i = 0; $i < $len; $i++) {
            $c = $label[$i];
            if (($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '-') {
                $out .= $c;
            }
        }
        return $out;
    }

    private static function shannonEntropy(string $s): float
    {
        if ($s === '') {
            return 0.0;
        }
        $freq = [];
        $total = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $freq[$c] = ($freq[$c] ?? 0) + 1;
            $total++;
        }

        $H = 0.0;
        foreach ($freq as $count) {
            $p = $count / $total;
            $H -= $p * (log($p, 2));
        }
        return $H;
    }

    private static function normalizedEntropy(string $s): float
    {
        if ($s === '') {
            return 0.0;
        }
        $epc = self::shannonEntropy($s) / self::runeLength($s);
        return $epc / self::MAX_ALPHABET_BITS;
    }

    private static function runeLength(string $s): int
    {
        return strlen($s);
    }

    private static function bigramEnglishiness(string $s): float
    {
        $letters = preg_replace('/[^a-z]/', '', strtolower($s)) ?? '';
        $n = strlen($letters);
        if ($n < 2) {
            return 0.0;
        }
        $found = 0;
        $total = 0;
        for ($i = 0; $i < $n - 1; $i++) {
            $bg = $letters[$i] . $letters[$i + 1];
            $total++;
            if (isset(self::$commonBigrams[$bg])) {
                $found++;
            }
        }
        return $total === 0 ? 0.0 : ($found / $total);
    }

    private static function uniqueCharRatio(string $s): float
    {
        $seen = [];
        $total = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            if (($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '-') {
                $seen[$c] = true;
                $total++;
            }
        }
        return $total === 0 ? 0.0 : (count($seen) / $total);
    }

    private static function vowelRatio(string $s): float
    {
        $vowels = ['a' => true, 'e' => true, 'i' => true, 'o' => true, 'u' => true];
        $count = 0;
        $total = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            if (!(($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '-')) {
                continue;
            }
            $total++;
            if (isset($vowels[$c])) {
                $count++;
            }
        }
        return $total === 0 ? 0.0 : ($count / $total);
    }

    private static function digitRatio(string $s): float
    {
        $count = 0;
        $total = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            if (!(($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '-')) {
                continue;
            }
            $total++;
            if ($c >= '0' && $c <= '9') {
                $count++;
            }
        }
        return $total === 0 ? 0.0 : ($count / $total);
    }

    private static function longestConsonantRunLength(string $s): int
    {
        $vowels = ['a' => true, 'e' => true, 'i' => true, 'o' => true, 'u' => true];
        $max = 0;
        $cur = 0;
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            if (!(($c >= 'a' && $c <= 'z') || ($c >= '0' && $c <= '9') || $c === '-')) {
                $cur = 0;
                continue;
            }
            if (($c >= '0' && $c <= '9') || (($c >= 'a' && $c <= 'z') && !isset($vowels[$c]))) {
                $cur++;
            } else {
                $max = max($max, $cur);
                $cur = 0;
            }
        }
        return max($max, $cur);
    }
}

