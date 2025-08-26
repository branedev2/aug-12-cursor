<?php
// {fact rule=insecure-file-permissions@v1.0 defects=1}
// Examples for php-laravel-cookie-long-timeout (CWE-1004)
// This file contains examples of secure and insecure session timeout configurations in Laravel

// ========== VULNERABLE EXAMPLES ==========

function bad_case_1() {
    // config/session.php
    return [
        'driver' => 'file',
        'lifetime' => 120, // 2 hours in minutes
        // ruleid: php-laravel-cookie-long-timeout
        'expire_on_close' => false,
        'encrypt' => false,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => false,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_2() {
    // config/session.php
    return [
        'driver' => 'redis',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 240, // 4 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => 'default',
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_3() {
    // config/session.php with extremely long timeout
    return [
        'driver' => 'database',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 1440, // 24 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => 'mysql',
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_4() {
    // config/session.php with default Laravel value (too long for high-security apps)
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 60, // 1 hour in minutes - default Laravel value
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_5() {
    // config/session.php with a week-long timeout
    return [
        'driver' => 'cookie',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 10080, // 7 days in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_6() {
    // config/session.php with a month-long timeout
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 43200, // 30 days in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_7() {
    // config/session.php with a year-long timeout
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 525600, // 365 days in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_8() {
    // config/session.php with 45 minutes timeout (too long for high-security apps)
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 45, // 45 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_9() {
    // config/session.php with 8 hours timeout
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 480, // 8 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_10() {
    // config/session.php with 12 hours timeout
    $config = [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => 720, // 12 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
    
    return $config;
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_11() {
    // config/session.php with 6 hours timeout and dynamic configuration
    $timeout = 6 * 60; // 6 hours in minutes
    
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 6 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_12() {
    // config/session.php with 3 hours timeout using constant
    define('SESSION_TIMEOUT', 180); // 3 hours in minutes
    
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => SESSION_TIMEOUT,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_13() {
    // config/session.php with 2 hours timeout using environment variable
    // Assuming $_ENV['SESSION_LIFETIME'] = 120
    $timeout = isset($_ENV['SESSION_LIFETIME']) ? $_ENV['SESSION_LIFETIME'] : 120;
    
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 2 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_14() {
    // config/session.php with 90 minutes timeout
    $hours = 1.5; // 1.5 hours
    $minutes = $hours * 60; // Convert to minutes
    
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => $minutes, // 90 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_15() {
    // config/session.php with 4 hours timeout using calculation
    $baseTimeout = 60; // 1 hour in minutes
    $multiplier = 4;
    
    return [
        'driver' => 'file',
        // ruleid: php-laravel-cookie-long-timeout
        'lifetime' => $baseTimeout * $multiplier, // 4 hours in minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

// ========== SECURE EXAMPLES ==========

function good_case_1() {
    // config/session.php with 5 minutes timeout (good for high-security apps)
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 5, // 5 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_2() {
    // config/session.php with 2 minutes timeout (good for high-security apps)
    return [
        'driver' => 'redis',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 2, // 2 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => 'default',
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_3() {
    // config/session.php with 15 minutes timeout (good for low-risk apps)
    return [
        'driver' => 'database',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 15, // 15 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => 'mysql',
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_4() {
    // config/session.php with 20 minutes timeout (good for low-risk apps)
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 20, // 20 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_5() {
    // config/session.php with 30 minutes timeout (maximum for low-risk apps)
    return [
        'driver' => 'cookie',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 30, // 30 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_6() {
    // config/session.php with 3 minutes timeout using constant
    define('SECURE_SESSION_TIMEOUT', 3); // 3 minutes
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => SECURE_SESSION_TIMEOUT,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_7() {
    // config/session.php with 4 minutes timeout using environment variable
    // Assuming $_ENV['SECURE_SESSION_LIFETIME'] = 4
    $timeout = isset($_ENV['SECURE_SESSION_LIFETIME']) ? $_ENV['SECURE_SESSION_LIFETIME'] : 4;
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 4 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_8() {
    // config/session.php with 25 minutes timeout using calculation
    $baseTimeout = 5; // 5 minutes
    $multiplier = 5;
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => $baseTimeout * $multiplier, // 25 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_9() {
    // config/session.php with 10 minutes timeout
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 10, // 10 minutes
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_10() {
    // config/session.php with 5 minutes timeout and expire on close
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 5, // 5 minutes
        'expire_on_close' => true, // Additional security - session expires when browser closes
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_11() {
    // config/session.php with 4 minutes timeout for banking application
    $appType = 'banking'; // High security application
    $timeout = ($appType === 'banking') ? 4 : 20; // 4 minutes for banking, 20 for others
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 4 minutes for banking app
        'expire_on_close' => true,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_12() {
    // config/session.php with 3 minutes timeout for admin section
    $isAdminSection = true;
    $timeout = $isAdminSection ? 3 : 15; // 3 minutes for admin, 15 for regular users
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 3 minutes for admin section
        'expire_on_close' => true,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_13() {
    // config/session.php with 5 minutes timeout and additional security settings
    return [
        'driver' => 'redis',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 5, // 5 minutes
        'expire_on_close' => true,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => 'default',
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true, // Only transmit over HTTPS
        'http_only' => true, // Cookie not accessible via JavaScript
        'same_site' => 'strict', // Prevent CSRF attacks
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_14() {
    // config/session.php with 12 minutes timeout for medium-risk application
    $riskLevel = 'medium';
    
    $timeout = 0;
    switch ($riskLevel) {
        case 'high':
            $timeout = 5; // 5 minutes for high-risk
            break;
        case 'medium':
            $timeout = 12; // 12 minutes for medium-risk
            break;
        case 'low':
            $timeout = 30; // 30 minutes for low-risk
            break;
    }
    
    return [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => $timeout, // 12 minutes for medium-risk
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_15() {
    // config/session.php with 5 minutes timeout and session regeneration
    $config = [
        'driver' => 'file',
        // ok: php-laravel-cookie-long-timeout
        'lifetime' => 5, // 5 minutes
        'expire_on_close' => true,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100], // 2% chance of session regeneration on each request
        'cookie' => 'laravel_session',
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
    
    return $config;
}
// {/fact}