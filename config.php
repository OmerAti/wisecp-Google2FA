<?php
return [
    'created_at' => 1781267040,
    'meta'       => [
        'name'         => "Google2FA",
        'version'      => "1.0.0",
        'author'       => "Ömer ATABER - OmerAti",
        'opening-type' => "normal",
    ],
    'show_on_adminArea'  => true,
    'show_on_clientArea' => true,
    'status'             => false,
    'access_ps'          => [],
    'settings'           => [
        'issuer'              => 'WISECP',
        'enforce_after_login' => true,
        'time_window'         => 1,
        'encryption_key'      => '',
    ],
];
