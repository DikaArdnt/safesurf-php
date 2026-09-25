<?php

declare(strict_types=1);

// Sensitive subdomain labels frequently abused by phishing kits when combined
// with other signals (login forms, brand impersonation, young/unranked root
// domains). A hit alone is NOT a phishing verdict — the scorer only uses these
// as combo modifiers.
return [
  // Authentication
  'login' => 'auth',
  'log-in' => 'auth',
  'signin' => 'auth',
  'sign-in' => 'auth',
  'signon' => 'auth',
  'sign-on' => 'auth',
  'sso' => 'auth',
  'auth' => 'auth',
  'authenticate' => 'auth',
  'authentication' => 'auth',
  'identity' => 'auth',
  'credentials' => 'auth',
  'credential' => 'auth',
  'password' => 'auth',
  'passwd' => 'auth',
  'passcode' => 'auth',
  'session' => 'auth',
  'otp' => 'auth',
  'mfa' => 'auth',
  '2fa' => 'auth',

  // Security-flavored labels
  'secure' => 'security',
  'security' => 'security',
  'safety' => 'security',
  'protected' => 'security',
  'shield' => 'security',
  'lock' => 'security',

  // Verification / urgency
  'verify' => 'verification',
  'verification' => 'verification',
  'verified' => 'verification',
  'validate' => 'verification',
  'validation' => 'verification',
  'confirm' => 'verification',
  'confirmation' => 'verification',
  'activate' => 'verification',
  'activation' => 'verification',
  'unlock' => 'verification',
  'unblock' => 'verification',
  'recovery' => 'verification',
  'recover' => 'verification',
  'restore' => 'verification',
  'reset' => 'verification',
  'update' => 'verification',
  'renew' => 'verification',
  'suspend' => 'verification',
  'limited' => 'verification',

  // Account / billing
  'account' => 'account',
  'accounts' => 'account',
  'myaccount' => 'account',
  'my-account' => 'account',
  'profile' => 'account',
  'member' => 'account',
  'membership' => 'account',
  'dashboard' => 'account',
  'portal' => 'account',
  'billing' => 'account',
  'invoice' => 'account',
  'payment' => 'finance',
  'pay' => 'finance',
  'checkout' => 'finance',
  'wallet' => 'finance',
  'bank' => 'finance',
  'banking' => 'finance',
  'card' => 'finance',

  // Mail
  'webmail' => 'mail',
  'mail' => 'mail',
  'email' => 'mail',
  'imap' => 'mail',
  'smtp' => 'mail',
  'inbox' => 'mail',

  // Support-lookalike
  'support' => 'support',
  'help' => 'support',
  'service' => 'support',
  'care' => 'support',
  'contact' => 'support',
];
