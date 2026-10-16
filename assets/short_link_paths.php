<?php

declare(strict_types=1);

// ShortLinkPaths are sites whose other pages are their own, but where links
// under these paths only redirect: QR code services and the like.

return [
    'flowcode.com' => ['/p/'], // Flowcode QR codes
    // Email click tracking: the newsletter service's own pages stay its own.
    'list-manage.com' => ['/track/click'], // Mailchimp
    'awstrack.me' => ['/L0/'], // Amazon SES
    'rs6.net' => ['/tn.jsp'], // Constant Contact
    'mjt.lu' => ['/lnk/'], // Mailjet
    'sendibm3.com' => ['/mk/cl/'], // Brevo
    'elasticemail.com' => ['/tracking/click'],
    'soundestlink.com' => ['/ce/c/'], // Omnisend
    'fdske.com' => ['/e/c/'], // FreshMail
];
