<?php
// PHP Session Poisoning Test Cases
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
// Rule ID: php-tainted-session
// CWE-284: Improper Access Control

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Using GET parameter directly as session ID
    $user_id = $_GET['user_id'];
    
    // ruleid: php-tainted-session
    session_id($user_id);
    session_start();
    
    $_SESSION['authenticated'] = true;
    echo "Session started with ID: " . session_id();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_2() {
    // Using POST parameter directly as session name
    $session_name = $_POST['session_name'];
    
    // ruleid: php-tainted-session
    session_name($session_name);
    session_start();
    
    $_SESSION['user_role'] = 'admin';
    echo "Session started with name: " . session_name();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_3() {
    // Using cookie value directly as session ID
    $session_id = $_COOKIE['custom_session_id'];
    
    // ruleid: php-tainted-session
    session_id($session_id);
    session_start();
    
    $_SESSION['logged_in'] = true;
    echo "Session started with cookie-provided ID";
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_4() {
    // Using HTTP header value directly as session ID
    $headers = getallheaders();
    $session_id = $headers['X-Session-ID'];
    
    // ruleid: php-tainted-session
    session_id($session_id);
    session_start();
    
    $_SESSION['permissions'] = ['read', 'write', 'admin'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_5() {
    // Using request parameter with minimal transformation
    $user_id = $_REQUEST['uid'];
    $session_key = "sess_" . $user_id;
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['account_type'] = 'premium';
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_6() {
    // Using concatenated user input for session ID
    $username = $_GET['username'];
    $timestamp = $_GET['timestamp'];
    $session_key = $username . "_" . $timestamp;
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['last_login'] = time();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_7() {
    // Using JSON-encoded user input for session ID
    $json_data = file_get_contents('php://input');
    $data = json_decode($json_data, true);
    $user_token = $data['token'];
    
    // ruleid: php-tainted-session
    session_id($user_token);
    session_start();
    
    $_SESSION['api_access'] = true;
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_8() {
    // Using base64 encoded user input
    $encoded_id = $_POST['encoded_session'];
    $session_key = base64_decode($encoded_id);
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['user_data'] = ['name' => 'John', 'email' => 'john@example.com'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_9() {
    // Using URL parameter with conditional logic
    $session_key = isset($_GET['session_key']) ? $_GET['session_key'] : md5(uniqid());
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    if (isset($_GET['admin']) && $_GET['admin'] === 'true') {
        $_SESSION['is_admin'] = true;
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_10() {
    // Using multiple parameters to construct session ID
    $app = $_GET['app'];
    $user = $_GET['user'];
    $device = $_GET['device'];
    
    $session_key = $app . '-' . $user . '-' . $device;
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['app_context'] = $app;
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_11() {
    // Using user input with hashing (still tainted)
    $user_token = $_POST['token'];
    $session_key = md5($user_token);
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['token_hash'] = $session_key;
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_12() {
    // Using user input with string manipulation
    $user_id = $_GET['id'];
    $session_key = substr($user_id, 0, 32);
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    foreach ($_GET as $key => $value) {
        $_SESSION['param_' . $key] = $value;
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_13() {
    // Using user input with array access
    $params = $_REQUEST;
    $session_key = $params['session_token'];
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['login_time'] = date('Y-m-d H:i:s');
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_14() {
    // Using user input with ternary and default
    $session_key = !empty($_COOKIE['remember_token']) ? $_COOKIE['remember_token'] : $_GET['token'];
    
    // ruleid: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['remember_me'] = isset($_COOKIE['remember_token']);
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}

function bad_case_15() {
    // Using user input with regex validation (still tainted)
    $user_token = $_POST['session_token'];
    
    if (preg_match('/^[a-zA-Z0-9]{32}$/', $user_token)) {
        // ruleid: php-tainted-session
        session_id($user_token);
        session_start();
        
        $_SESSION['validated_token'] = true;
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

function good_case_1() {
    // Using server-generated session ID
    // ok: php-tainted-session
    session_start();
    
    $_SESSION['user_id'] = $_GET['user_id'];
    echo "Session started with auto-generated ID: " . session_id();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_2() {
    // Using cryptographically secure random session ID
    $secure_id = bin2hex(random_bytes(16));
    
    // ok: php-tainted-session
    session_id($secure_id);
    session_start();
    
    $_SESSION['user'] = $_POST['username'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_3() {
    // Using server-side configuration for session name
    // ok: php-tainted-session
    session_name('APP_SESSION');
    session_start();
    
    $_SESSION['preferences'] = $_POST['preferences'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_4() {
    // Using UUID for session ID
    $uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
    
    // ok: php-tainted-session
    session_id($uuid);
    session_start();
    
    $_SESSION['data'] = $_REQUEST['data'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_5() {
    // Using predefined session configuration
    ini_set('session.use_strict_mode', 1);
    
    // ok: php-tainted-session
    session_start();
    
    if (isset($_GET['reset']) && $_GET['reset'] === '1') {
        session_regenerate_id(true);
    }
    
    $_SESSION['last_activity'] = time();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_6() {
    // Using server timestamp for session ID
    $timestamp = time();
    $server_secret = 'SERVER_SECRET_KEY';
    $session_key = md5($timestamp . $server_secret);
    
    // ok: php-tainted-session
    session_id($session_key);
    session_start();
    
    $_SESSION['client_ip'] = $_SERVER['REMOTE_ADDR'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_7() {
    // Using environment-specific session name
    $env = getenv('APP_ENV') ?: 'production';
    
    // ok: php-tainted-session
    session_name('APP_' . $env);
    session_start();
    
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_8() {
    // Using session regeneration after login
    // ok: php-tainted-session
    session_start();
    
    if ($_POST['username'] === 'admin' && $_POST['password'] === 'correct_password') {
        session_regenerate_id(true);
        $_SESSION['logged_in'] = true;
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_9() {
    // Using server-side session with custom storage
    $handler = new SessionHandler();
    session_set_save_handler($handler, true);
    
    // ok: php-tainted-session
    session_start();
    
    $_SESSION['visit_count'] = ($_SESSION['visit_count'] ?? 0) + 1;
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_10() {
    // Using secure session configuration
    ini_set('session.use_cookies', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    
    // ok: php-tainted-session
    session_start();
    
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_11() {
    // Using server-side session with validation
    // ok: php-tainted-session
    session_start();
    
    if (!isset($_SESSION['initialized'])) {
        $_SESSION['initialized'] = true;
        $_SESSION['created'] = time();
        $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
    } else if ($_SESSION['user_ip'] !== $_SERVER['REMOTE_ADDR']) {
        // IP changed, potential session hijacking
        session_regenerate_id(true);
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_12() {
    // Using hardcoded session name with auto-generated ID
    // ok: php-tainted-session
    session_name('SECURE_SESSION');
    session_start();
    
    if (isset($_POST['logout']) && $_POST['logout'] === 'true') {
        session_destroy();
    } else {
        $_SESSION['authenticated'] = check_auth($_POST['username'], $_POST['password']);
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_13() {
    // Using server-side session with timeout
    // ok: php-tainted-session
    session_start();
    
    $timeout = 1800; // 30 minutes
    
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > $timeout)) {
        session_unset();
        session_destroy();
        session_start();
    }
    
    $_SESSION['last_activity'] = time();
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_14() {
    // Using session with server-side fingerprinting
    // ok: php-tainted-session
    session_start();
    
    $fingerprint = md5($_SERVER['HTTP_USER_AGENT'] . $_SERVER['REMOTE_ADDR']);
    
    if (!isset($_SESSION['fingerprint'])) {
        $_SESSION['fingerprint'] = $fingerprint;
    } else if ($_SESSION['fingerprint'] !== $fingerprint) {
        // Potential session hijacking
        session_regenerate_id(true);
        $_SESSION['fingerprint'] = $fingerprint;
    }
}
// {/fact}
// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}

function good_case_15() {
    // Using session with fixed name and rotating IDs
    // ok: php-tainted-session
    session_name('APP_SESSION');
    session_start();
    
    // Rotate session ID periodically
    if (!isset($_SESSION['created']) || time() - $_SESSION['created'] > 3600) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
    
    $_SESSION['page_views'] = ($_SESSION['page_views'] ?? 0) + 1;
}
// {/fact}

// Helper function for good_case_12
function check_auth($username, $password) {
    // In a real application, this would check against a database
    return ($username === 'valid_user' && $password === 'valid_password');
}
?>