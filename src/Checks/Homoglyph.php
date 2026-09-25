<?php

declare(strict_types=1);

namespace SafeSurf\Checks;

final class Homoglyph
{
    public static function analyze(string $domain): array
    {
        $out = [
            'domain' => $domain,
            'decoded' => $domain,
            'has_homoglyph' => false,
            'mixed_scripts' => [],
            'fullwidth_chars' => [],
            'scripts' => [],
            'reasons' => [],
        ];

        $domain = strtolower(trim($domain));
        if ($domain === '') {
            return $out;
        }

        $decodedLabels = [];
        foreach (explode('.', $domain) as $label) {
            $decodedLabels[] = self::decodeLabel($label);
        }
        $decoded = implode('.', $decodedLabels);
        $out['decoded'] = $decoded;

        $scripts = [];
        $fullwidth = [];
        foreach (mb_str_split($decoded) ?: [] as $ch) {
            $script = self::scriptOf($ch);
            if ($script !== null && $script !== 'common') {
                $scripts[$script] = true;
            }
            if (self::isFullwidth($ch)) {
                $fullwidth[] = $ch;
            }
        }

        $out['scripts'] = array_keys($scripts);
        $out['fullwidth_chars'] = array_values(array_unique($fullwidth));

        $hasLatin = isset($scripts['latin']);
        $spoofScripts = array_values(array_intersect(array_keys($scripts), ['cyrillic', 'greek', 'armenian']));

        if ($hasLatin && $spoofScripts !== []) {
            $out['mixed_scripts'] = array_merge(['latin'], $spoofScripts);
            $out['has_homoglyph'] = true;
            $out['reasons'][] = sprintf('mixed scripts in one domain (%s)', implode(' + ', $out['mixed_scripts']));
        }

        if ($out['fullwidth_chars'] !== []) {
            $out['has_homoglyph'] = true;
            $out['reasons'][] = sprintf('fullwidth lookalike characters (%s)', implode(' ', $out['fullwidth_chars']));
        }

        return $out;
    }

    public static function hasHomoglyphs(string $domain): bool
    {
        return self::analyze($domain)['has_homoglyph'];
    }

    private static function decodeLabel(string $label): string
    {
        $lower = strtolower($label);
        if (!str_starts_with($lower, 'xn--')) {
            return $label;
        }

        if (function_exists('idn_to_utf8')) {
            $decoded = @idn_to_utf8($label, IDNA_NONTRANSITIONAL_TO_UNICODE, INTL_IDNA_VARIANT_UTS46);
            if (is_string($decoded) && $decoded !== '') {
                return $decoded;
            }
        }

        try {
            return \Pdp\Idna::toUnicode($label, \Pdp\Idna::IDNA2008_UNICODE)->result();
        } catch (\Throwable) {
            return $label;
        }
    }

    private static function scriptOf(string $ch): ?string
    {
        $cp = mb_ord($ch, 'UTF-8');
        if ($cp === false) {
            return null;
        }

        if ($cp >= 0x41 && $cp <= 0x5A) {
            return 'latin';
        }
        if ($cp >= 0x61 && $cp <= 0x7A) {
            return 'latin';
        }
        if (($cp >= 0xC0 && $cp <= 0x24F) || ($cp >= 0x1E00 && $cp <= 0x1EFF) || ($cp >= 0x2C60 && $cp <= 0x2C7F)) {
            return 'latin';
        }
        if (($cp >= 0x400 && $cp <= 0x52F) || ($cp >= 0x2DE0 && $cp <= 0x2DFF) || ($cp >= 0xA640 && $cp <= 0xA69F)) {
            return 'cyrillic';
        }
        if (($cp >= 0x370 && $cp <= 0x3FF) || ($cp >= 0x1F00 && $cp <= 0x1FFF)) {
            return 'greek';
        }
        if ($cp >= 0x530 && $cp <= 0x58F) {
            return 'armenian';
        }
        if ($cp >= 0x3040 && $cp <= 0x30FF) {
            return 'han-kana';
        }
        if ($cp >= 0x4E00 && $cp <= 0x9FFF) {
            return 'han-kana';
        }
        if ($cp >= 0xAC00 && $cp <= 0xD7AF) {
            return 'hangul';
        }
        if ($cp >= 0x620 && $cp <= 0x64F) {
            return 'arabic';
        }
        if ($cp >= 0x900 && $cp <= 0x97F) {
            return 'devanagari';
        }
        if ($cp >= 0xE00 && $cp <= 0xE7F) {
            return 'thai';
        }
        return 'common';
    }

    private static function isFullwidth(string $ch): bool
    {
        $cp = mb_ord($ch, 'UTF-8');
        return $cp !== false && $cp >= 0xFF01 && $cp <= 0xFF5E;
    }
}
