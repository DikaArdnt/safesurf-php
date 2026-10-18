<?php

declare(strict_types=1);

namespace SafeSurf\Constants;

final class DataFiles
{
    private static ?array $riskyTlds = null;
    private static ?array $trustedTlds = null;
    private static ?array $urlShorteners = null;
    private static ?array $urlKeywords = null;
    private static ?array $brands = null;
    private static ?array $hostingPlatforms = null;
    private static ?array $sensitiveSubdomains = null;
    private static ?array $customerSiteHosts = null;
    private static ?array $providerSubdomains = null;
    private static ?array $ipHostnameServices = null;
    private static ?array $ddnsProviders = null;
    private static ?array $userUploadHosts = null;
    private static ?array $providerServiceHosts = null;
    private static ?array $userPageHosts = null;
    private static ?array $shortLinkPaths = null;
    private static ?array $marketingFormHosts = null;

    public static function riskyTlds(): array
    {
        if (self::$riskyTlds !== null) {
            return self::$riskyTlds;
        }
        self::$riskyTlds = require __DIR__ . '/../../assets/risky_tlds.php';
        return self::$riskyTlds;
    }

    public static function trustedTlds(): array
    {
        if (self::$trustedTlds !== null) {
            return self::$trustedTlds;
        }
        self::$trustedTlds = require __DIR__ . '/../../assets/trusted_tlds.php';
        return self::$trustedTlds;
    }

    public static function hostingPlatforms(): array
    {
        if (self::$hostingPlatforms !== null) {
            return self::$hostingPlatforms;
        }
        self::$hostingPlatforms = require __DIR__ . '/../../assets/hosting_platforms.php';
        return self::$hostingPlatforms;
    }

    public static function urlShorteners(): array
    {
        if (self::$urlShorteners !== null) {
            return self::$urlShorteners;
        }
        self::$urlShorteners = require __DIR__ . '/../../assets/url_shorteners.php';
        return self::$urlShorteners;
    }

    public static function urlKeywords(): array
    {
        if (self::$urlKeywords !== null) {
            return self::$urlKeywords;
        }
        self::$urlKeywords = require __DIR__ . '/../../assets/url_keywords.php';
        return self::$urlKeywords;
    }

    public static function sensitiveSubdomains(): array
    {
        if (self::$sensitiveSubdomains !== null) {
            return self::$sensitiveSubdomains;
        }
        self::$sensitiveSubdomains = require __DIR__ . '/../../assets/sensitive_subdomains.php';
        return self::$sensitiveSubdomains;
    }

    public static function brands(): array
    {
        if (self::$brands !== null) {
            return self::$brands;
        }
        self::$brands = require __DIR__ . '/../../assets/brands.php';
        return self::$brands;
    }

    public static function customerSiteHosts(): array
    {
        if (self::$customerSiteHosts !== null) {
            return self::$customerSiteHosts;
        }
        self::$customerSiteHosts = require __DIR__ . '/../../assets/customer_site_hosts.php';
        return self::$customerSiteHosts;
    }

    public static function providerSubdomains(): array
    {
        if (self::$providerSubdomains !== null) {
            return self::$providerSubdomains;
        }
        self::$providerSubdomains = require __DIR__ . '/../../assets/provider_subdomains.php';
        return self::$providerSubdomains;
    }

    public static function ipHostnameServices(): array
    {
        if (self::$ipHostnameServices !== null) {
            return self::$ipHostnameServices;
        }
        self::$ipHostnameServices = require __DIR__ . '/../../assets/ip_hostname_services.php';
        return self::$ipHostnameServices;
    }

    public static function ddnsProviders(): array
    {
        if (self::$ddnsProviders !== null) {
            return self::$ddnsProviders;
        }
        self::$ddnsProviders = require __DIR__ . '/../../assets/ddns_providers.php';
        return self::$ddnsProviders;
    }

    public static function userUploadHosts(): array
    {
        if (self::$userUploadHosts !== null) {
            return self::$userUploadHosts;
        }
        self::$userUploadHosts = require __DIR__ . '/../../assets/user_upload_hosts.php';
        return self::$userUploadHosts;
    }

    public static function providerServiceHosts(): array
    {
        if (self::$providerServiceHosts !== null) {
            return self::$providerServiceHosts;
        }
        self::$providerServiceHosts = require __DIR__ . '/../../assets/provider_service_hosts.php';
        return self::$providerServiceHosts;
    }

    public static function userPageHosts(): array
    {
        if (self::$userPageHosts !== null) {
            return self::$userPageHosts;
        }
        self::$userPageHosts = require __DIR__ . '/../../assets/user_page_hosts.php';
        return self::$userPageHosts;
    }

    public static function shortLinkPaths(): array
    {
        if (self::$shortLinkPaths !== null) {
            return self::$shortLinkPaths;
        }
        self::$shortLinkPaths = require __DIR__ . '/../../assets/short_link_paths.php';
        return self::$shortLinkPaths;
    }

    public static function marketingFormHosts(): array
    {
        if (self::$marketingFormHosts !== null) {
            return self::$marketingFormHosts;
        }
        self::$marketingFormHosts = require __DIR__ . '/../../assets/marketing_form_hosts.php';
        return self::$marketingFormHosts;
    }

    public static function get(string $key): ?array
    {
        return match ($key) {
            'risky_tlds', 'riskyTlds' => self::riskyTlds(),
            'trusted_tlds', 'trustedTlds' => self::trustedTlds(),
            'hosting_platforms', 'hostingPlatforms' => self::hostingPlatforms(),
            'url_shorteners', 'urlShorteners' => self::urlShorteners(),
            'url_keywords', 'urlKeywords' => self::urlKeywords(),
            'sensitive_subdomains', 'sensitiveSubdomains' => self::sensitiveSubdomains(),
            'brands' => self::brands(),
            'customer_site_hosts', 'customerSiteHosts' => self::customerSiteHosts(),
            'provider_subdomains', 'providerSubdomains' => self::providerSubdomains(),
            'ip_hostname_services', 'ipHostnameServices' => self::ipHostnameServices(),
            'ddns_providers', 'ddnsProviders' => self::ddnsProviders(),
            'user_upload_hosts', 'userUploadHosts' => self::userUploadHosts(),
            'provider_service_hosts', 'providerServiceHosts' => self::providerServiceHosts(),
            'user_page_hosts', 'userPageHosts' => self::userPageHosts(),
            'short_link_paths', 'shortLinkPaths' => self::shortLinkPaths(),
            'marketing_form_hosts', 'marketingFormHosts' => self::marketingFormHosts(),
            default => null,
        };
    }
}

