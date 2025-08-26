<?php

namespace App\Config;
// {fact rule=insecure-cookie@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // config/session.php
    return [
        'driver' => 'file',
        'lifetime' => 120,
        // ruleid: php-laravel-cookie-secure-set
        'secure' => false,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_2() {
    // Creating a custom configuration file with insecure cookie settings
    $config = [
        'cookie' => [
            'name' => 'laravel_session',
            'path' => '/',
            'domain' => null,
            // ruleid: php-laravel-cookie-secure-set
            'secure' => false,
            'http_only' => true,
        ]
    ];
    return $config;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_3() {
    // Using Config::set to modify cookie security at runtime
    \Config::set('session.secure', false);
    
    // ruleid: php-laravel-cookie-secure-set
    $settings = \Config::get('session');
    return $settings;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_4() {
    // Using config() helper to set insecure cookie
    // ruleid: php-laravel-cookie-secure-set
    config(['session.secure' => false]);
    return config('session');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_5() {
    // Explicitly setting cookie with secure false in a controller
    $cookie = cookie(
        'name', 
        'value', 
        60, 
        '/', 
        null, 
        // ruleid: php-laravel-cookie-secure-set
        false, 
        true
    );
    return response('Hello')->cookie($cookie);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_6() {
    // Using Cookie facade with insecure settings
    // ruleid: php-laravel-cookie-secure-set
    \Cookie::make('name', 'value', 60, '/', null, false, true);
    return response('Cookie set');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_7() {
    // Creating a response with an insecure cookie
    $response = new \Illuminate\Http\Response('Hello');
    // ruleid: php-laravel-cookie-secure-set
    $response->withCookie(cookie('name', 'value', 60, '/', null, false));
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_8() {
    // Setting multiple cookies with one being insecure
    $cookies = [
        'safe_cookie' => cookie('safe', 'value', 60, '/', null, true),
        // ruleid: php-laravel-cookie-secure-set
        'unsafe_cookie' => cookie('unsafe', 'value', 60, '/', null, false),
    ];
    return response('Multiple cookies')->withCookies($cookies);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_9() {
    // Creating a session configuration with environment check but defaulting to insecure
    $isSecure = env('SECURE_COOKIES', false);
    
    // ruleid: php-laravel-cookie-secure-set
    return [
        'driver' => 'file',
        'secure' => $isSecure,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_10() {
    // Using a ternary operator but defaulting to insecure
    $environment = app()->environment();
    
    // ruleid: php-laravel-cookie-secure-set
    $config = [
        'secure' => $environment === 'production' ? false : false,
        'http_only' => true,
    ];
    return $config;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_11() {
    // Setting cookie parameters with a variable for secure but assigning false
    $secureParam = false;
    
    // ruleid: php-laravel-cookie-secure-set
    return [
        'cookie' => [
            'secure' => $secureParam,
            'http_only' => true,
        ]
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_12() {
    // Using array_merge to combine configurations with insecure setting
    $defaultConfig = ['lifetime' => 120, 'http_only' => true];
    
    // ruleid: php-laravel-cookie-secure-set
    $finalConfig = array_merge($defaultConfig, [
        'secure' => false,
    ]);
    return $finalConfig;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_13() {
    // Creating a middleware that sets insecure cookies
    $request = request();
    $response = next($request);
    
    // ruleid: php-laravel-cookie-secure-set
    $cookie = cookie('tracking', 'value', 60, '/', null, false, false);
    $response->headers->setCookie($cookie);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_14() {
    // Using a switch statement but all paths lead to insecure
    $env = app()->environment();
    
    switch ($env) {
        case 'production':
            $secure = false;
            break;
        case 'staging':
            $secure = false;
            break;
        default:
            $secure = false;
    }
    
    // ruleid: php-laravel-cookie-secure-set
    return [
        'secure' => $secure,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_15() {
    // Using a function to determine security but returning false
    $determineSecure = function() {
        return false;
    };
    
    // ruleid: php-laravel-cookie-secure-set
    $config = [
        'secure' => $determineSecure(),
        'http_only' => true,
    ];
    return $config;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // config/session.php with secure cookies
    // ok: php-laravel-cookie-secure-set
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'secure' => true,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_2() {
    // Creating a custom configuration file with secure cookie settings
    // ok: php-laravel-cookie-secure-set
    $config = [
        'cookie' => [
            'name' => 'laravel_session',
            'path' => '/',
            'domain' => null,
            'secure' => true,
            'http_only' => true,
        ]
    ];
    return $config;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_3() {
    // Using Config::set to ensure cookie security at runtime
    // ok: php-laravel-cookie-secure-set
    \Config::set('session.secure', true);
    $settings = \Config::get('session');
    return $settings;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_4() {
    // Using config() helper to set secure cookie
    // ok: php-laravel-cookie-secure-set
    config(['session.secure' => true]);
    return config('session');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_5() {
    // Explicitly setting cookie with secure true in a controller
    // ok: php-laravel-cookie-secure-set
    $cookie = cookie(
        'name', 
        'value', 
        60, 
        '/', 
        null, 
        true, 
        true
    );
    return response('Hello')->cookie($cookie);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_6() {
    // Using Cookie facade with secure settings
    // ok: php-laravel-cookie-secure-set
    \Cookie::make('name', 'value', 60, '/', null, true, true);
    return response('Cookie set');
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_7() {
    // Creating a response with a secure cookie
    $response = new \Illuminate\Http\Response('Hello');
    // ok: php-laravel-cookie-secure-set
    $response->withCookie(cookie('name', 'value', 60, '/', null, true));
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_8() {
    // Setting multiple cookies with all being secure
    // ok: php-laravel-cookie-secure-set
    $cookies = [
        'cookie1' => cookie('cookie1', 'value', 60, '/', null, true),
        'cookie2' => cookie('cookie2', 'value', 60, '/', null, true),
    ];
    return response('Multiple cookies')->withCookies($cookies);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_9() {
    // Creating a session configuration with environment check defaulting to secure
    $isSecure = env('SECURE_COOKIES', true);
    
    // ok: php-laravel-cookie-secure-set
    return [
        'driver' => 'file',
        'secure' => $isSecure,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_10() {
    // Using a ternary operator defaulting to secure
    $environment = app()->environment();
    
    // ok: php-laravel-cookie-secure-set
    $config = [
        'secure' => $environment === 'local' ? false : true,
        'http_only' => true,
    ];
    return $config;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_11() {
    // Setting cookie parameters with a variable for secure and assigning true
    $secureParam = true;
    
    // ok: php-laravel-cookie-secure-set
    return [
        'cookie' => [
            'secure' => $secureParam,
            'http_only' => true,
        ]
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_12() {
    // Using array_merge to combine configurations with secure setting
    $defaultConfig = ['lifetime' => 120, 'http_only' => true];
    
    // ok: php-laravel-cookie-secure-set
    $finalConfig = array_merge($defaultConfig, [
        'secure' => true,
    ]);
    return $finalConfig;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_13() {
    // Creating a middleware that sets secure cookies
    $request = request();
    $response = next($request);
    
    // ok: php-laravel-cookie-secure-set
    $cookie = cookie('tracking', 'value', 60, '/', null, true, true);
    $response->headers->setCookie($cookie);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_14() {
    // Using a switch statement with all paths leading to secure
    $env = app()->environment();
    
    switch ($env) {
        case 'local':
            $secure = app()->isLocal() ? false : true;
            break;
        case 'testing':
            $secure = true;
            break;
        default:
            $secure = true;
    }
    
    // ok: php-laravel-cookie-secure-set
    return [
        'secure' => $secure,
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_15() {
    // Using a function to determine security and returning true
    $determineSecure = function() {
        return true;
    };
    
    // ok: php-laravel-cookie-secure-set
    $config = [
        'secure' => $determineSecure(),
        'http_only' => true,
    ];
    return $config;
}
// {/fact}