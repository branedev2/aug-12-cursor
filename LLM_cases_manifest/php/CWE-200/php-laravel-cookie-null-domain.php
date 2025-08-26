<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Config;
// {fact rule=sensitive-information-leak@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Setting cookie with explicit domain in config/session.php
    $config = [
        'name' => 'laravel_session',
        'secure' => true,
        'httpOnly' => true,
        // ruleid: php-laravel-cookie-null-domain
        'domain' => 'example.com', // Explicitly setting domain instead of null
        'path' => '/',
        'sameSite' => 'lax',
    ];
    
    return $config;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_2() {
    // Setting cookie with explicit domain in a controller
    // ruleid: php-laravel-cookie-null-domain
    return Cookie::make('name', 'value', 60, '/', 'example.com', true, true, false, 'lax');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_3() {
    // Setting cookie with explicit subdomain
    $cookieJar = new \Illuminate\Cookie\CookieJar();
    // ruleid: php-laravel-cookie-null-domain
    $cookie = $cookieJar->make('name', 'value', 60, '/', 'api.example.com', true, true, false, 'lax');
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_4() {
    // Setting cookie with explicit domain in config array
    $sessionConfig = [
        'driver' => 'file',
        'lifetime' => 120,
        // ruleid: php-laravel-cookie-null-domain
        'domain' => 'example.org',
        'secure' => true,
    ];
    
    Config::set('session', $sessionConfig);
    return $sessionConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_5() {
    // Setting cookie with explicit domain in a service provider
    $config = config('session');
    $config['domain'] = 'myapp.com';
    // ruleid: php-laravel-cookie-null-domain
    Config::set('session.domain', 'myapp.com');
    
    return $config;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_6(Request $request) {
    // Setting cookie with explicit domain using queue
    // ruleid: php-laravel-cookie-null-domain
    Cookie::queue('name', 'value', 60, '/', 'example.net', true, true, false, 'lax');
    
    return response('Cookie set');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_7() {
    // Setting cookie with explicit domain in .env file simulation
    $envConfig = [
        'SESSION_DOMAIN' => 'example.com',
    ];
    
    // ruleid: php-laravel-cookie-null-domain
    $domain = $envConfig['SESSION_DOMAIN'];
    $cookieConfig = ['domain' => $domain];
    
    return $cookieConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_8() {
    // Setting cookie with explicit domain in a response
    $response = new \Illuminate\Http\Response('Content');
    // ruleid: php-laravel-cookie-null-domain
    $response->withCookie(cookie('name', 'value', 60, '/', 'example.com'));
    
    return $response;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_9() {
    // Setting cookie with explicit domain using Cookie facade's forever method
    // ruleid: php-laravel-cookie-null-domain
    Cookie::forever('name', 'value', '/', 'example.com', true, true, false, 'lax');
    
    return response('Cookie set forever');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_10() {
    // Setting cookie with explicit domain in a middleware
    $middleware = new class {
        public function handle($request, $next) {
            // ruleid: php-laravel-cookie-null-domain
            Cookie::make('name', 'value', 60, '/', 'example.com', true, true, false, 'lax');
            return $next($request);
        }
    };
    
    return $middleware;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_11() {
    // Setting cookie with explicit domain using array syntax
    $cookieParams = [
        'name' => 'cookie_name',
        'value' => 'cookie_value',
        'minutes' => 60,
        'path' => '/',
        // ruleid: php-laravel-cookie-null-domain
        'domain' => 'example.com',
        'secure' => true,
        'httpOnly' => true,
        'raw' => false,
        'sameSite' => 'lax',
    ];
    
    $cookie = Cookie::make(
        $cookieParams['name'],
        $cookieParams['value'],
        $cookieParams['minutes'],
        $cookieParams['path'],
        $cookieParams['domain'],
        $cookieParams['secure'],
        $cookieParams['httpOnly'],
        $cookieParams['raw'],
        $cookieParams['sameSite']
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_12() {
    // Setting cookie with explicit domain using a variable
    $domain = 'example.com';
    
    // ruleid: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60, '/', $domain, true, true, false, 'lax');
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_13() {
    // Setting cookie with explicit domain in a conditional
    $isProduction = true;
    
    if ($isProduction) {
        $domain = 'example.com';
    } else {
        $domain = 'localhost';
    }
    
    // ruleid: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60, '/', $domain, true, true, false, 'lax');
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_14() {
    // Setting cookie with explicit domain using environment variable
    $domain = getenv('COOKIE_DOMAIN') ?: 'example.com';
    
    // ruleid: php-laravel-cookie-null-domain
    $cookieConfig = [
        'domain' => $domain,
        'secure' => true,
        'httpOnly' => true,
    ];
    
    return $cookieConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_15() {
    // Setting cookie with explicit domain using a function
    function getDomain() {
        return 'example.com';
    }
    
    // ruleid: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60, '/', getDomain(), true, true, false, 'lax');
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // Setting cookie with null domain in config/session.php
    $config = [
        'name' => 'laravel_session',
        'secure' => true,
        'httpOnly' => true,
        // ok: php-laravel-cookie-null-domain
        'domain' => null, // Correctly setting domain to null
        'path' => '/',
        'sameSite' => 'lax',
    ];
    
    return $config;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_2() {
    // Setting cookie with null domain in a controller
    // ok: php-laravel-cookie-null-domain
    return Cookie::make('name', 'value', 60, '/', null, true, true, false, 'lax');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_3() {
    // Setting cookie with null domain
    $cookieJar = new \Illuminate\Cookie\CookieJar();
    // ok: php-laravel-cookie-null-domain
    $cookie = $cookieJar->make('name', 'value', 60, '/', null, true, true, false, 'lax');
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_4() {
    // Setting cookie with null domain in config array
    $sessionConfig = [
        'driver' => 'file',
        'lifetime' => 120,
        // ok: php-laravel-cookie-null-domain
        'domain' => null,
        'secure' => true,
    ];
    
    Config::set('session', $sessionConfig);
    return $sessionConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_5() {
    // Setting cookie with null domain in a service provider
    $config = config('session');
    // ok: php-laravel-cookie-null-domain
    Config::set('session.domain', null);
    
    return $config;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_6(Request $request) {
    // Setting cookie with null domain using queue
    // ok: php-laravel-cookie-null-domain
    Cookie::queue('name', 'value', 60, '/', null, true, true, false, 'lax');
    
    return response('Cookie set');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_7() {
    // Not setting domain at all (defaults to null in Laravel)
    $cookieConfig = [
        'secure' => true,
        'httpOnly' => true,
        // Domain is not set, which is fine
    ];
    
    // ok: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60, '/', null, true, true, false, 'lax');
    
    return $cookieConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_8() {
    // Setting cookie with null domain in a response
    $response = new \Illuminate\Http\Response('Content');
    // ok: php-laravel-cookie-null-domain
    $response->withCookie(cookie('name', 'value', 60, '/', null));
    
    return $response;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_9() {
    // Setting cookie with null domain using Cookie facade's forever method
    // ok: php-laravel-cookie-null-domain
    Cookie::forever('name', 'value', '/', null, true, true, false, 'lax');
    
    return response('Cookie set forever');
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_10() {
    // Setting cookie with null domain in a middleware
    $middleware = new class {
        public function handle($request, $next) {
            // ok: php-laravel-cookie-null-domain
            Cookie::make('name', 'value', 60, '/', null, true, true, false, 'lax');
            return $next($request);
        }
    };
    
    return $middleware;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_11() {
    // Setting cookie with null domain using array syntax
    $cookieParams = [
        'name' => 'cookie_name',
        'value' => 'cookie_value',
        'minutes' => 60,
        'path' => '/',
        // ok: php-laravel-cookie-null-domain
        'domain' => null,
        'secure' => true,
        'httpOnly' => true,
        'raw' => false,
        'sameSite' => 'lax',
    ];
    
    $cookie = Cookie::make(
        $cookieParams['name'],
        $cookieParams['value'],
        $cookieParams['minutes'],
        $cookieParams['path'],
        $cookieParams['domain'],
        $cookieParams['secure'],
        $cookieParams['httpOnly'],
        $cookieParams['raw'],
        $cookieParams['sameSite']
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_12() {
    // Setting cookie with null domain using a variable
    $domain = null;
    
    // ok: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60, '/', $domain, true, true, false, 'lax');
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_13() {
    // Setting cookie with null domain in a conditional
    $isProduction = true;
    
    // ok: php-laravel-cookie-null-domain
    $domain = null; // Always use null for domain
    $cookie = Cookie::make('name', 'value', 60, '/', $domain, true, true, false, 'lax');
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_14() {
    // Setting cookie with null domain using environment variable
    // ok: php-laravel-cookie-null-domain
    $cookieConfig = [
        'domain' => null, // Explicitly set to null
        'secure' => true,
        'httpOnly' => true,
    ];
    
    return $cookieConfig;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_15() {
    // Using the default cookie configuration without specifying domain
    // ok: php-laravel-cookie-null-domain
    $cookie = Cookie::make('name', 'value', 60);
    
    return $cookie;
}
// {/fact}