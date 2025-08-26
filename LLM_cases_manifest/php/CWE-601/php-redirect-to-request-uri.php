<?php
/**
 * Test cases for PHP redirect to request URI vulnerability (CWE-601)
 * 
 * This file contains examples of vulnerable and secure implementations
 * related to redirecting to REQUEST_URI in PHP applications.
 */

// ==================== VULNERABLE EXAMPLES ====================

/**
 * Directly redirects to REQUEST_URI without validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    // Direct redirection to REQUEST_URI without any validation
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $_SERVER['REQUEST_URI']);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with minimal string manipulation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    $uri = $_SERVER['REQUEST_URI'];
    // ruleid: php-redirect-to-request-uri
    header("Location: $uri");
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with concatenation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    $baseUrl = "https://example.com";
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $baseUrl . $_SERVER['REQUEST_URI']);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with string interpolation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    // ruleid: php-redirect-to-request-uri
    header("Location: https://example.com{$_SERVER['REQUEST_URI']}");
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI after basic string operations
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    $uri = trim($_SERVER['REQUEST_URI']);
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $uri);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with conditional logic
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    $uri = $_SERVER['REQUEST_URI'];
    if (strpos($uri, "account") !== false) {
        // ruleid: php-redirect-to-request-uri
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Redirects to REQUEST_URI with variable assignment in a loop
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    $redirectUrl = "";
    for ($i = 0; $i < 1; $i++) {
        $redirectUrl = $_SERVER['REQUEST_URI'];
    }
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $redirectUrl);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with ternary operator
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    $uri = isset($_GET['page']) ? $_GET['page'] : $_SERVER['REQUEST_URI'];
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $uri);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with string replacement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    $uri = str_replace("old", "new", $_SERVER['REQUEST_URI']);
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $uri);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with switch statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    $action = $_GET['action'] ?? 'default';
    switch ($action) {
        case 'login':
            $redirect = '/login';
            break;
        default:
            $redirect = $_SERVER['REQUEST_URI'];
            break;
    }
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $redirect);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with array access
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    $urls = [
        'home' => '/home',
        'current' => $_SERVER['REQUEST_URI']
    ];
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $urls['current']);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with string concatenation in a function
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    function getRedirectUrl() {
        return $_SERVER['REQUEST_URI'];
    }
    // ruleid: php-redirect-to-request-uri
    header("Location: " . getRedirectUrl());
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI using http_redirect function
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    // ruleid: php-redirect-to-request-uri
    if (function_exists('http_redirect')) {
        http_redirect($_SERVER['REQUEST_URI']);
    } else {
        header("Location: " . $_SERVER['REQUEST_URI']);
        exit();
    }
}
// {/fact}

/**
 * Redirects to REQUEST_URI with string formatting
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    $uri = $_SERVER['REQUEST_URI'];
    $formatted = sprintf("Location: %s", $uri);
    // ruleid: php-redirect-to-request-uri
    header($formatted);
    exit();
}
// {/fact}

/**
 * Redirects to REQUEST_URI with multiple variables
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    $prefix = "https://example.com";
    $uri = $_SERVER['REQUEST_URI'];
    $suffix = "";
    $redirectUrl = $prefix . $uri . $suffix;
    // ruleid: php-redirect-to-request-uri
    header("Location: " . $redirectUrl);
    exit();
}
// {/fact}

// ==================== SECURE EXAMPLES ====================

/**
 * Validates REQUEST_URI to prevent open redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    $uri = $_SERVER['REQUEST_URI'];
    // ok: php-redirect-to-request-uri
    if (substr($uri, 0, 1) === '/' && substr($uri, 0, 2) !== '//') {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses parse_url to validate the URI
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    $uri = $_SERVER['REQUEST_URI'];
    $parsed = parse_url($uri);
    // ok: php-redirect-to-request-uri
    if (empty($parsed['host']) && substr($uri, 0, 1) === '/') {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses whitelist of allowed paths
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    $uri = $_SERVER['REQUEST_URI'];
    $allowedPaths = ['/home', '/login', '/dashboard', '/profile'];
    // ok: php-redirect-to-request-uri
    if (in_array($uri, $allowedPaths)) {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses regex to validate the URI format
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    $uri = $_SERVER['REQUEST_URI'];
    // ok: php-redirect-to-request-uri
    if (preg_match('/^\/[a-zA-Z0-9\/_-]+$/', $uri)) {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses hardcoded redirect URL
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    // ok: php-redirect-to-request-uri
    header("Location: /dashboard");
    exit();
}
// {/fact}

/**
 * Uses relative path with validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    $uri = $_SERVER['REQUEST_URI'];
    // ok: php-redirect-to-request-uri
    if (strpos($uri, '//') === false && strpos($uri, ':') === false) {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses URL builder to create safe URLs
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    $baseUrl = "https://example.com";
    $path = "/dashboard";
    // ok: php-redirect-to-request-uri
    header("Location: " . $baseUrl . $path);
    exit();
}
// {/fact}

/**
 * Uses filter_var to validate URL
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    $uri = $_SERVER['REQUEST_URI'];
    $fullUrl = "https://example.com" . $uri;
    // ok: php-redirect-to-request-uri
    if (filter_var($fullUrl, FILTER_VALIDATE_URL) && 
        parse_url($fullUrl, PHP_URL_HOST) === 'example.com') {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses strict path validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    $uri = $_SERVER['REQUEST_URI'];
    // ok: php-redirect-to-request-uri
    if (substr($uri, 0, 1) === '/' && 
        substr($uri, 0, 2) !== '//' && 
        strpos($uri, ':') === false) {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses URL components to build safe URL
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    $components = parse_url($_SERVER['REQUEST_URI']);
    // ok: php-redirect-to-request-uri
    if (isset($components['path']) && !isset($components['host'])) {
        $safePath = $components['path'];
        header("Location: " . $safePath);
        exit();
    }
}
// {/fact}

/**
 * Uses absolute URL with domain validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    $uri = $_SERVER['REQUEST_URI'];
    $fullUrl = "https://example.com" . $uri;
    $host = parse_url($fullUrl, PHP_URL_HOST);
    // ok: php-redirect-to-request-uri
    if ($host === 'example.com') {
        header("Location: " . $fullUrl);
        exit();
    }
}
// {/fact}

/**
 * Uses path normalization
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    $uri = $_SERVER['REQUEST_URI'];
    $normalizedPath = '/';
    
    if (substr($uri, 0, 1) === '/') {
        $segments = explode('/', $uri);
        $validSegments = [];
        
        foreach ($segments as $segment) {
            if ($segment !== '' && $segment !== '.' && $segment !== '..') {
                $validSegments[] = $segment;
            }
        }
        
        if (!empty($validSegments)) {
            $normalizedPath = '/' . implode('/', $validSegments);
        }
    }
    
    // ok: php-redirect-to-request-uri
    header("Location: " . $normalizedPath);
    exit();
}
// {/fact}

/**
 * Uses whitelist of allowed patterns
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    $uri = $_SERVER['REQUEST_URI'];
    $allowedPatterns = [
        '/^\/product\/\d+$/',
        '/^\/category\/[a-z0-9-]+$/',
        '/^\/page\/[a-z0-9-]+$/'
    ];
    
    $isAllowed = false;
    foreach ($allowedPatterns as $pattern) {
        if (preg_match($pattern, $uri)) {
            $isAllowed = true;
            break;
        }
    }
    
    // ok: php-redirect-to-request-uri
    if ($isAllowed) {
        header("Location: " . $uri);
        exit();
    }
}
// {/fact}

/**
 * Uses URL sanitization function
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    $uri = $_SERVER['REQUEST_URI'];
    
    function sanitizeUrl($url) {
        // Remove any protocol and domain parts
        $path = preg_replace('/^(?:https?:\/\/)?(?:[^\/]+)(.*)$/', '$1', $url);
        
        // Ensure it starts with a slash
        if (substr($path, 0, 1) !== '/') {
            $path = '/' . $path;
        }
        
        // Prevent double-slash at the beginning
        if (substr($path, 0, 2) === '//') {
            return '/';
        }
        
        return $path;
    }
    
    $safeUri = sanitizeUrl($uri);
    
    // ok: php-redirect-to-request-uri
    header("Location: " . $safeUri);
    exit();
}
// {/fact}

/**
 * Uses URL builder with query parameters
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    $page = $_GET['page'] ?? 'home';
    $allowedPages = ['home', 'about', 'contact', 'products'];
    
    // ok: php-redirect-to-request-uri
    if (in_array($page, $allowedPages)) {
        $queryParams = [];
        foreach ($_GET as $key => $value) {
            if ($key !== 'page') {
                $queryParams[$key] = $value;
            }
        }
        
        $url = '/' . $page;
        if (!empty($queryParams)) {
            $url .= '?' . http_build_query($queryParams);
        }
        
        header("Location: " . $url);
        exit();
    }
}
// {/fact}
?>