<?php
/**
 * Test cases for php-cookie-without-http-only-flag (CWE-1004)
 * This file contains examples of secure and insecure cookie settings in PHP
 */
// {fact rule=insecure-file-permissions@v1.0 defects=1}

// BAD CASES - Cookies without HttpOnly flag

function bad_case_1() {
    // Simple case of setting a cookie without HttpOnly flag
    // ruleid: php-cookie-without-http-only-flag
    setcookie("user_id", "12345", time() + 3600);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_2() {
    // Setting a cookie with path and domain but no HttpOnly
    // ruleid: php-cookie-without-http-only-flag
    setcookie("session_token", "abc123xyz", time() + 86400, "/", "example.com", true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_3() {
    // Setting a cookie with secure flag but not HttpOnly
    $value = "sensitive_data";
    $expiry = time() + 3600;
    // ruleid: php-cookie-without-http-only-flag
    setcookie("auth_token", $value, $expiry, "/", "", true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_4() {
    // Using setrawcookie without HttpOnly flag
    $username = "john_doe";
    // ruleid: php-cookie-without-http-only-flag
    setrawcookie("username", rawurlencode($username), time() + 7200);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_5() {
    // Setting cookie with explicit httponly parameter set to false
    // ruleid: php-cookie-without-http-only-flag
    setcookie("remember_me", "1", time() + 2592000, "/", "", false, false);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_6() {
    // Setting cookie with options array but missing httponly
    $options = [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => 'example.com',
        'secure' => true,
        'samesite' => 'Strict'
    ];
    // ruleid: php-cookie-without-http-only-flag
    setcookie("preferences", json_encode(['theme' => 'dark']), $options);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_7() {
    // Setting cookie with httponly explicitly set to false in options array
    $options = [
        'expires' => time() + 3600,
        'path' => '/',
        'httponly' => false
    ];
    // ruleid: php-cookie-without-http-only-flag
    setcookie("cart_id", "cart_" . uniqid(), $options);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_8() {
    // Setting cookie in a conditional block without HttpOnly
    $user_id = 42;
    if ($user_id > 0) {
        // ruleid: php-cookie-without-http-only-flag
        setcookie("last_login", time(), time() + 86400);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_9() {
    // Setting multiple cookies, none with HttpOnly
    // ruleid: php-cookie-without-http-only-flag
    setcookie("user_lang", "en", time() + 31536000);
    // ruleid: php-cookie-without-http-only-flag
    setcookie("user_region", "US", time() + 31536000);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_10() {
    // Using header() function to set cookie without HttpOnly
    $expiry = gmdate('D, d M Y H:i:s T', time() + 3600);
    // ruleid: php-cookie-without-http-only-flag
    header("Set-Cookie: analytics_id=12345; expires={$expiry}; path=/; secure");
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_11() {
    // Setting cookie with dynamic name but no HttpOnly
    $cookieName = "user_" . rand(1000, 9999);
    // ruleid: php-cookie-without-http-only-flag
    setcookie($cookieName, "dynamic_value", time() + 3600);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_12() {
    // Setting cookie inside a try-catch block without HttpOnly
    try {
        $value = generateToken(); // Assume this function exists
        // ruleid: php-cookie-without-http-only-flag
        setcookie("csrf_token", $value, time() + 1800);
    } catch (Exception $e) {
        error_log($e->getMessage());
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_13() {
    // Setting cookie with a loop for multiple users without HttpOnly
    $users = ['alice', 'bob', 'charlie'];
    foreach ($users as $user) {
        // ruleid: php-cookie-without-http-only-flag
        setcookie("last_visit_" . $user, time(), time() + 86400);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_14() {
    // Setting cookie with a switch statement without HttpOnly
    $userType = "admin";
    switch ($userType) {
        case "admin":
            // ruleid: php-cookie-without-http-only-flag
            setcookie("admin_session", "admin_" . uniqid(), time() + 1800);
            break;
        case "user":
            // ruleid: php-cookie-without-http-only-flag
            setcookie("user_session", "user_" . uniqid(), time() + 3600);
            break;
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_15() {
    // Setting cookie with complex expiration calculation but no HttpOnly
    $expiration = time() + (60 * 60 * 24 * 30); // 30 days
    $value = base64_encode("user_data_here");
    // ruleid: php-cookie-without-http-only-flag
    setcookie("persistent_login", $value, $expiration, "/", "example.com", true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

// GOOD CASES - Cookies with HttpOnly flag properly set

function good_case_1() {
    // Simple case of setting a cookie with HttpOnly flag
    // ok: php-cookie-without-http-only-flag
    setcookie("user_id", "12345", time() + 3600, "/", "", false, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_2() {
    // Setting a cookie with path, domain, secure and HttpOnly flags
    // ok: php-cookie-without-http-only-flag
    setcookie("session_token", "abc123xyz", time() + 86400, "/", "example.com", true, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_3() {
    // Setting a cookie with variables and HttpOnly flag
    $value = "sensitive_data";
    $expiry = time() + 3600;
    // ok: php-cookie-without-http-only-flag
    setcookie("auth_token", $value, $expiry, "/", "", true, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_4() {
    // Using setrawcookie with HttpOnly flag
    $username = "john_doe";
    // ok: php-cookie-without-http-only-flag
    setrawcookie("username", rawurlencode($username), time() + 7200, "/", "", false, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_5() {
    // Setting cookie with options array including httponly
    $options = [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => 'example.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ];
    // ok: php-cookie-without-http-only-flag
    setcookie("preferences", json_encode(['theme' => 'dark']), $options);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_6() {
    // Setting cookie in a conditional block with HttpOnly
    $user_id = 42;
    if ($user_id > 0) {
        // ok: php-cookie-without-http-only-flag
        setcookie("last_login", time(), time() + 86400, "/", "", false, true);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_7() {
    // Setting multiple cookies, all with HttpOnly
    // ok: php-cookie-without-http-only-flag
    setcookie("user_lang", "en", time() + 31536000, "/", "", false, true);
    // ok: php-cookie-without-http-only-flag
    setcookie("user_region", "US", time() + 31536000, "/", "", false, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_8() {
    // Using header() function to set cookie with HttpOnly
    $expiry = gmdate('D, d M Y H:i:s T', time() + 3600);
    // ok: php-cookie-without-http-only-flag
    header("Set-Cookie: analytics_id=12345; expires={$expiry}; path=/; secure; HttpOnly");
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_9() {
    // Setting cookie with dynamic name and HttpOnly
    $cookieName = "user_" . rand(1000, 9999);
    // ok: php-cookie-without-http-only-flag
    setcookie($cookieName, "dynamic_value", time() + 3600, "/", "", false, true);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_10() {
    // Setting cookie inside a try-catch block with HttpOnly
    try {
        $value = generateToken(); // Assume this function exists
        // ok: php-cookie-without-http-only-flag
        setcookie("csrf_token", $value, time() + 1800, "/", "", true, true);
    } catch (Exception $e) {
        error_log($e->getMessage());
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_11() {
    // Setting cookie with a loop for multiple users with HttpOnly
    $users = ['alice', 'bob', 'charlie'];
    foreach ($users as $user) {
        // ok: php-cookie-without-http-only-flag
        setcookie("last_visit_" . $user, time(), time() + 86400, "/", "", false, true);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_12() {
    // Setting cookie with a switch statement with HttpOnly
    $userType = "admin";
    switch ($userType) {
        case "admin":
            // ok: php-cookie-without-http-only-flag
            setcookie("admin_session", "admin_" . uniqid(), time() + 1800, "/", "", true, true);
            break;
        case "user":
            // ok: php-cookie-without-http-only-flag
            setcookie("user_session", "user_" . uniqid(), time() + 3600, "/", "", true, true);
            break;
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_13() {
    // Setting session cookie parameters with HttpOnly
    // ok: php-cookie-without-http-only-flag
    session_set_cookie_params([
        'lifetime' => 3600,
        'path' => '/',
        'domain' => 'example.com',
        'secure' => true,
        'httponly' => true
    ]);
    session_start();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_14() {
    // Using older style session_set_cookie_params with HttpOnly
    // ok: php-cookie-without-http-only-flag
    session_set_cookie_params(3600, '/', 'example.com', true, true);
    session_start();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_15() {
    // Setting cookie with complex expiration calculation and HttpOnly
    $expiration = time() + (60 * 60 * 24 * 30); // 30 days
    $value = base64_encode("user_data_here");
    // ok: php-cookie-without-http-only-flag
    setcookie("persistent_login", $value, $expiration, "/", "example.com", true, true);
}
// {/fact}

// Helper function for examples
function generateToken() {
    return bin2hex(random_bytes(16));
}
?>