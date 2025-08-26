<?php
/**
 * Test cases for WordPress Open Redirect vulnerability detection
 * Rule ID: php-wp-open-redirect-audit
 * CWE: CWE-601
 */

// True Positive Examples (Vulnerable Code)

/**
 * Redirects user to a URL specified in the GET parameter without validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL specified in the POST parameter without validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    // Get redirect URL from POST parameter
    $redirect_url = isset($_POST['redirect_to']) ? $_POST['redirect_to'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL specified in a cookie without validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    // Get redirect URL from cookie
    $redirect_url = isset($_COOKIE['return_url']) ? $_COOKIE['return_url'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL specified in HTTP header without validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    // Get redirect URL from HTTP Referer header
    $redirect_url = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with minimal processing but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    // Get redirect URL from GET parameter and trim whitespace
    $redirect_url = isset($_GET['redirect']) ? trim($_GET['redirect']) : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with string concatenation but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    // Get redirect URL from GET parameter and append a query parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] . '?source=wordpress' : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with status code but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url, 301);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with conditional logic but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    $is_logged_in = true; // Assume this is set elsewhere
    
    if (!empty($redirect_url) && $is_logged_in) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with array access but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    // Get redirect URL from GET parameter in a more complex way
    $params = $_GET;
    $redirect_url = isset($params['redirect']) ? $params['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with urldecode but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    // Get redirect URL from GET parameter and URL decode it
    $redirect_url = isset($_GET['redirect']) ? urldecode($_GET['redirect']) : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with string replacement but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    // Get redirect URL from GET parameter and replace http with https
    $redirect_url = isset($_GET['redirect']) ? str_replace('http://', 'https://', $_GET['redirect']) : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with base64 decode but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    // Get redirect URL from GET parameter and base64 decode it
    $encoded_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    $redirect_url = base64_decode($encoded_url);
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with JSON decode but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    // Get redirect URL from POST parameter as JSON
    $json_data = isset($_POST['data']) ? $_POST['data'] : '{}';
    $data = json_decode($json_data, true);
    $redirect_url = isset($data['redirect_url']) ? $data['redirect_url'] : '';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with multiple parameters but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    // Get redirect URL from GET parameter and add query parameters
    $base_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    $user_id = 123;
    $redirect_url = $base_url . '?user=' . $user_id . '&action=login';
    
    if (!empty($redirect_url)) {
        // ruleid: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a URL with ternary operator but no validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    // Get redirect URL using ternary operator
    $redirect_url = isset($_GET['redirect']) ? 
        (empty($_GET['redirect']) ? home_url() : $_GET['redirect']) : 
        home_url();
    
    // ruleid: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

// True Negative Examples (Safe Code)

/**
 * Safely redirects user to a URL specified in the GET parameter using wp_safe_redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL specified in the POST parameter using wp_safe_redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    // Get redirect URL from POST parameter
    $redirect_url = isset($_POST['redirect_to']) ? $_POST['redirect_to'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL specified in a cookie using wp_safe_redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    // Get redirect URL from cookie
    $redirect_url = isset($_COOKIE['return_url']) ? $_COOKIE['return_url'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL specified in HTTP header using wp_safe_redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    // Get redirect URL from HTTP Referer header
    $redirect_url = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL with status code using wp_safe_redirect
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url, 301);
        exit;
    }
}
// {/fact}

/**
 * Redirects user to a hardcoded URL which is safe
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    $redirect_url = 'https://example.com/dashboard';
    
    // ok: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

/**
 * Redirects user to a URL constructed from site URL which is safe
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    $redirect_url = site_url('/dashboard');
    
    // ok: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

/**
 * Redirects user to a URL constructed from home URL which is safe
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    $redirect_url = home_url('/login');
    
    // ok: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

/**
 * Redirects user to a URL constructed from admin URL which is safe
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    $redirect_url = admin_url('admin.php?page=settings');
    
    // ok: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

/**
 * Safely redirects user to a URL after validating it's on the same domain
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    // Validate URL is on the same domain
    if (!empty($redirect_url) && strpos($redirect_url, home_url()) === 0) {
        // ok: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    } else {
        wp_redirect(home_url());
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL after validating it against a whitelist
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    // Whitelist of allowed domains
    $allowed_domains = array(
        'example.com',
        'trusted-site.org',
        'partner.com'
    );
    
    // Parse URL to get domain
    $parsed_url = parse_url($redirect_url);
    $domain = isset($parsed_url['host']) ? $parsed_url['host'] : '';
    
    // Check if domain is in whitelist
    if (!empty($domain) && in_array($domain, $allowed_domains)) {
        // ok: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    } else {
        wp_redirect(home_url());
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL after sanitizing it
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    // Sanitize URL
    $redirect_url = esc_url_raw($redirect_url);
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        wp_safe_redirect($redirect_url);
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL with conditional logic and validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    $is_logged_in = true; // Assume this is set elsewhere
    
    // Check if URL is internal
    $is_internal = strpos($redirect_url, home_url()) === 0;
    
    if (!empty($redirect_url) && $is_logged_in && $is_internal) {
        // ok: php-wp-open-redirect-audit
        wp_redirect($redirect_url);
        exit;
    } else {
        wp_redirect(home_url());
        exit;
    }
}
// {/fact}

/**
 * Safely redirects user to a URL from a predefined list
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    // Get redirect key from GET parameter
    $redirect_key = isset($_GET['page']) ? $_GET['page'] : 'home';
    
    // Map of allowed redirect destinations
    $redirect_map = array(
        'home' => home_url(),
        'login' => wp_login_url(),
        'admin' => admin_url(),
        'profile' => admin_url('profile.php')
    );
    
    // Get URL from map or default to home
    $redirect_url = isset($redirect_map[$redirect_key]) ? $redirect_map[$redirect_key] : home_url();
    
    // ok: php-wp-open-redirect-audit
    wp_redirect($redirect_url);
    exit;
}
// {/fact}

/**
 * Uses wp_safe_redirect with fallback
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    // Get redirect URL from GET parameter
    $redirect_url = isset($_GET['redirect']) ? $_GET['redirect'] : '';
    
    if (!empty($redirect_url)) {
        // ok: php-wp-open-redirect-audit
        if (!wp_safe_redirect($redirect_url)) {
            // Fallback to home URL if safe redirect fails
            wp_redirect(home_url());
        }
        exit;
    }
}
// {/fact}
?>