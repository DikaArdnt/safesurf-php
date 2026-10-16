<?php

declare(strict_types=1);

// IPHostnameServices resolve any name with an IP address in it to that
// address, so a link on one is a link to a bare server.

return [
    'sslip.io' => true,
    'nip.io' => true,
    'xip.io' => true,
    'traefik.me' => true,
    'nip.direct' => true,
    // Server names hosting panels give every machine from its IP
    // (login.50-6-193-131.cprapid.com).
    'cprapid.com' => true,
    'cpanel.site' => true,
    'plesk.page' => true,
    'cloud-xip.com' => true,
    'host.secureserver.net' => true,
];
