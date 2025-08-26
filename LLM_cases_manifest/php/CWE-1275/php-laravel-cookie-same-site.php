<?php
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
// Test cases for php-laravel-cookie-same-site (CWE-1275)
// This file demonstrates various Laravel cookie configurations with and without proper same_site attributes

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Missing same_site attribute in config/session.php
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => false,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', false),
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_2() {
    // Cookie configuration with same_site set to 'none'
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'cookie',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'none',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_3() {
    // Cookie configuration with same_site set to null
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'redis',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => null,
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_4() {
    // Cookie configuration with empty string for same_site
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => '',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_5() {
    // Cookie configuration with same_site set to false
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => false,
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_6() {
    // Cookie configuration in config/app.php missing same_site
    // ruleid: php-laravel-cookie-same-site
    return [
        'name' => env('APP_NAME', 'Laravel'),
        'env' => env('APP_ENV', 'production'),
        'debug' => env('APP_DEBUG', false),
        'url' => env('APP_URL', 'http://localhost'),
        'timezone' => 'UTC',
        'locale' => 'en',
        'fallback_locale' => 'en',
        'key' => env('APP_KEY'),
        'cipher' => 'AES-256-CBC',
        'providers' => [
            // Service providers
        ],
        'aliases' => [
            // Class aliases
        ],
        'cookie' => [
            'secure' => true,
            'http_only' => true,
        ],
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_7() {
    // Cookie configuration with same_site set to an invalid value
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'invalid_value',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_8() {
    // Cookie middleware configuration missing same_site
    // ruleid: php-laravel-cookie-same-site
    $middleware = [
        \Illuminate\Cookie\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
        \App\Http\Middleware\VerifyCsrfToken::class,
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ];
    
    $cookieOptions = [
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
    ];
    
    return [$middleware, $cookieOptions];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_9() {
    // Cookie configuration in bootstrap file missing same_site
    // ruleid: php-laravel-cookie-same-site
    $app = new Illuminate\Foundation\Application(
        $_ENV['APP_BASE_PATH'] ?? dirname(__DIR__)
    );
    
    $app->singleton(
        Illuminate\Contracts\Http\Kernel::class,
        App\Http\Kernel::class
    );
    
    $app->singleton(
        Illuminate\Contracts\Console\Kernel::class,
        App\Console\Kernel::class
    );
    
    $app->singleton(
        Illuminate\Contracts\Debug\ExceptionHandler::class,
        App\Exceptions\Handler::class
    );
    
    $app['config']->set('session', [
        'driver' => 'file',
        'lifetime' => 120,
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
        'secure' => true,
        'http_only' => true,
    ]);
    
    return $app;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_10() {
    // Direct cookie creation without same_site
    // ruleid: php-laravel-cookie-same-site
    $cookie = cookie(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true    // httpOnly
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_11() {
    // Using CookieJar without same_site
    // ruleid: php-laravel-cookie-same-site
    $cookieJar = app('cookie');
    
    $cookie = $cookieJar->make(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true    // httpOnly
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_12() {
    // Response with cookie without same_site
    // ruleid: php-laravel-cookie-same-site
    $response = new \Illuminate\Http\Response('Hello World');
    $response->withCookie(cookie(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true    // httpOnly
    ));
    
    return $response;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_13() {
    // Config in service provider without same_site
    // ruleid: php-laravel-cookie-same-site
    class AppServiceProvider extends \Illuminate\Support\ServiceProvider
    {
        public function boot()
        {
            config([
                'session.secure' => true,
                'session.http_only' => true,
                'session.cookie' => 'my_app_session',
                'session.lifetime' => 120,
            ]);
        }
    }
    
    return new AppServiceProvider(app());
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_14() {
    // Using env variables but missing same_site
    // ruleid: php-laravel-cookie-same-site
    return [
        'driver' => env('SESSION_DRIVER', 'file'),
        'lifetime' => env('SESSION_LIFETIME', 120),
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => env('SESSION_CONNECTION', null),
        'table' => env('SESSION_TABLE', 'sessions'),
        'store' => env('SESSION_STORE', null),
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}

function bad_case_15() {
    // Queue cookie without same_site
    // ruleid: php-laravel-cookie-same-site
    $cookieQueue = app(\Illuminate\Cookie\CookieJar::class);
    
    $cookieQueue->queue(
        cookie(
            'name',
            'value',
            60,     // minutes
            '/',    // path
            null,   // domain
            true,   // secure
            true    // httpOnly
        )
    );
    
    return $cookieQueue;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

// True Negatives (Secure Code)

function good_case_1() {
    // Cookie configuration with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'lax',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_2() {
    // Cookie configuration with same_site set to 'strict'
    // ok: php-laravel-cookie-same-site
    return [
        'driver' => 'redis',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'strict',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_3() {
    // Cookie configuration with same_site set to uppercase 'LAX'
    // ok: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'LAX',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_4() {
    // Cookie configuration with same_site set to uppercase 'STRICT'
    // ok: php-laravel-cookie-same-site
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => 'STRICT',
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_5() {
    // Cookie configuration with same_site set from environment variable (assuming it's set to 'lax' or 'strict')
    // ok: php-laravel-cookie-same-site
    $sameSite = env('SESSION_SAME_SITE', 'lax');
    
    return [
        'driver' => 'file',
        'lifetime' => 120,
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => null,
        'table' => 'sessions',
        'store' => null,
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => $sameSite,
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_6() {
    // Cookie configuration in config/app.php with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    return [
        'name' => env('APP_NAME', 'Laravel'),
        'env' => env('APP_ENV', 'production'),
        'debug' => env('APP_DEBUG', false),
        'url' => env('APP_URL', 'http://localhost'),
        'timezone' => 'UTC',
        'locale' => 'en',
        'fallback_locale' => 'en',
        'key' => env('APP_KEY'),
        'cipher' => 'AES-256-CBC',
        'providers' => [
            // Service providers
        ],
        'aliases' => [
            // Class aliases
        ],
        'cookie' => [
            'secure' => true,
            'http_only' => true,
            'same_site' => 'lax',
        ],
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_7() {
    // Cookie middleware configuration with same_site set to 'strict'
    // ok: php-laravel-cookie-same-site
    $middleware = [
        \Illuminate\Cookie\Middleware\EncryptCookies::class,
        \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        \Illuminate\Session\Middleware\StartSession::class,
        \Illuminate\View\Middleware\ShareErrorsFromSession::class,
        \App\Http\Middleware\VerifyCsrfToken::class,
        \Illuminate\Routing\Middleware\SubstituteBindings::class,
    ];
    
    $cookieOptions = [
        'path' => '/',
        'domain' => null,
        'secure' => true,
        'http_only' => true,
        'same_site' => 'strict',
    ];
    
    return [$middleware, $cookieOptions];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_8() {
    // Cookie configuration in bootstrap file with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    $app = new Illuminate\Foundation\Application(
        $_ENV['APP_BASE_PATH'] ?? dirname(__DIR__)
    );
    
    $app->singleton(
        Illuminate\Contracts\Http\Kernel::class,
        App\Http\Kernel::class
    );
    
    $app->singleton(
        Illuminate\Contracts\Console\Kernel::class,
        App\Console\Kernel::class
    );
    
    $app->singleton(
        Illuminate\Contracts\Debug\ExceptionHandler::class,
        App\Exceptions\Handler::class
    );
    
    $app['config']->set('session', [
        'driver' => 'file',
        'lifetime' => 120,
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
        'secure' => true,
        'http_only' => true,
        'same_site' => 'lax',
    ]);
    
    return $app;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_9() {
    // Direct cookie creation with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    $cookie = cookie(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true,   // httpOnly
        false,  // raw
        'lax'   // sameSite
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_10() {
    // Using CookieJar with same_site set to 'strict'
    // ok: php-laravel-cookie-same-site
    $cookieJar = app('cookie');
    
    $cookie = $cookieJar->make(
        'name',
        'value',
        60,       // minutes
        '/',      // path
        null,     // domain
        true,     // secure
        true,     // httpOnly
        false,    // raw
        'strict'  // sameSite
    );
    
    return $cookie;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_11() {
    // Response with cookie with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    $response = new \Illuminate\Http\Response('Hello World');
    $response->withCookie(cookie(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true,   // httpOnly
        false,  // raw
        'lax'   // sameSite
    ));
    
    return $response;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_12() {
    // Config in service provider with same_site set to 'strict'
    // ok: php-laravel-cookie-same-site
    class AppServiceProvider extends \Illuminate\Support\ServiceProvider
    {
        public function boot()
        {
            config([
                'session.secure' => true,
                'session.http_only' => true,
                'session.cookie' => 'my_app_session',
                'session.lifetime' => 120,
                'session.same_site' => 'strict',
            ]);
        }
    }
    
    return new AppServiceProvider(app());
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_13() {
    // Using env variables with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    return [
        'driver' => env('SESSION_DRIVER', 'file'),
        'lifetime' => env('SESSION_LIFETIME', 120),
        'expire_on_close' => false,
        'encrypt' => true,
        'files' => storage_path('framework/sessions'),
        'connection' => env('SESSION_CONNECTION', null),
        'table' => env('SESSION_TABLE', 'sessions'),
        'store' => env('SESSION_STORE', null),
        'lottery' => [2, 100],
        'cookie' => env('SESSION_COOKIE', 'laravel_session'),
        'path' => '/',
        'domain' => env('SESSION_DOMAIN', null),
        'secure' => env('SESSION_SECURE_COOKIE', true),
        'http_only' => true,
        'same_site' => env('SESSION_SAME_SITE', 'lax'),
    ];
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_14() {
    // Queue cookie with same_site set to 'strict'
    // ok: php-laravel-cookie-same-site
    $cookieQueue = app(\Illuminate\Cookie\CookieJar::class);
    
    $cookieQueue->queue(
        cookie(
            'name',
            'value',
            60,       // minutes
            '/',      // path
            null,     // domain
            true,     // secure
            true,     // httpOnly
            false,    // raw
            'strict'  // sameSite
        )
    );
    
    return $cookieQueue;
}
// {/fact}
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}

function good_case_15() {
    // Using Cookie facade with same_site set to 'lax'
    // ok: php-laravel-cookie-same-site
    $cookie = \Illuminate\Support\Facades\Cookie::make(
        'name',
        'value',
        60,     // minutes
        '/',    // path
        null,   // domain
        true,   // secure
        true,   // httpOnly
        false,  // raw
        'lax'   // sameSite
    );
    
    return $cookie;
}
// {/fact}