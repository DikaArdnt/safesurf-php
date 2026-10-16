<?php

declare(strict_types=1);

// ProviderSubdomains are subdomains a CustomerSiteHosts provider keeps for
// itself (account.squarespace.com). They, and anything under them, stay the
// provider's site and keep its rank.

return [
    'systeme.io' => [
        'help' => true,
        'api' => true,
        'app' => true,
        'blog' => true,
        'status' => true,
        'affiliate' => true,
        'community' => true,
        'academy' => true,
        'developer' => true,
    ],
    'flazio.com' => [
        'app' => true,
        'help' => true,
        'blog' => true,
        'api' => true,
    ],
    'squarespace.com' => [
        'account' => true,
        'login' => true,
        'support' => true,
        'help' => true,
        'domains' => true,
        'status' => true,
        'engineering' => true,
        'forum' => true,
        'developers' => true,
        'api' => true,
        'static' => true,
        'static1' => true,
        'images' => true,
        'assets' => true,
        'designer' => true,
        'commerce' => true,
        'pages' => true,
        'investors' => true,
        'newsroom' => true,
        'careers' => true,
        'config' => true,
        'mail' => true,
    ],
];
