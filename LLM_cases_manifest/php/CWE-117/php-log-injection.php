<?php
// {fact rule=ldap-injection@v1.0 defects=1}
// PHP Log Injection Test Cases
// Rule ID: php-log-injection

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // User input directly logged without sanitization
    $username = $_GET['username'];
    
    // ruleid: php-log-injection
    error_log("User login attempt: " . $username);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_2() {
    // POST data directly logged without sanitization
    $searchQuery = $_POST['search'];
    
    // ruleid: php-log-injection
    file_put_contents('search_log.txt', date('Y-m-d H:i:s') . " - Search query: " . $searchQuery . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_3() {
    // HTTP header directly logged without sanitization
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    
    // ruleid: php-log-injection
    syslog(LOG_INFO, "User agent: " . $userAgent);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_4() {
    // Cookie data directly logged without sanitization
    $sessionId = $_COOKIE['PHPSESSID'];
    
    // ruleid: php-log-injection
    trigger_error("Session ID accessed: " . $sessionId, E_USER_NOTICE);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_5() {
    // Request URI directly logged without sanitization
    $requestUri = $_SERVER['REQUEST_URI'];
    
    // ruleid: php-log-injection
    openlog("webapp", LOG_PID | LOG_PERROR, LOG_USER);
    syslog(LOG_WARNING, "Page accessed: " . $requestUri);
    closelog();
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_6() {
    // Multiple user inputs concatenated and logged without sanitization
    $email = $_POST['email'];
    $action = $_GET['action'];
    
    // ruleid: php-log-injection
    error_log("Action '" . $action . "' performed by user: " . $email);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_7() {
    // User input in JSON data logged without sanitization
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $username = $jsonData['username'];
    
    // ruleid: php-log-injection
    file_put_contents('api_log.txt', date('Y-m-d H:i:s') . " - API access by: " . $username . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_8() {
    // Referer header directly logged without sanitization
    $referer = $_SERVER['HTTP_REFERER'];
    
    // ruleid: php-log-injection
    error_log("Request came from: " . $referer);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_9() {
    // User input processed but still vulnerable
    $userId = $_GET['id'];
    $userId = trim($userId); // Trimming doesn't prevent log injection
    
    // ruleid: php-log-injection
    error_log("User profile accessed: " . $userId);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_10() {
    // User input in an array logged without sanitization
    $params = $_GET;
    $queryString = http_build_query($params);
    
    // ruleid: php-log-injection
    file_put_contents('query_log.txt', date('Y-m-d H:i:s') . " - Query: " . $queryString . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_11() {
    // Remote IP address logged without sanitization
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    
    // ruleid: php-log-injection
    error_log("Access from IP: " . $ipAddress);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_12() {
    // Form data with minimal processing logged without sanitization
    $password = $_POST['password'];
    $maskedPassword = substr($password, 0, 3) . '***';
    
    // ruleid: php-log-injection
    error_log("Password attempt (masked): " . $maskedPassword);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_13() {
    // User input in URL parameters logged without sanitization
    parse_str($_SERVER['QUERY_STRING'], $params);
    $sortBy = $params['sort'];
    
    // ruleid: php-log-injection
    file_put_contents('sort_log.txt', date('Y-m-d H:i:s') . " - Sorted by: " . $sortBy . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_14() {
    // User input with conditional logging but still vulnerable
    $action = $_GET['action'];
    
    if ($action == 'login' || $action == 'logout') {
        $username = $_POST['username'] ?? 'unknown';
        // ruleid: php-log-injection
        error_log("User " . $username . " performed action: " . $action);
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_15() {
    // User input in custom header logged without sanitization
    $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? 'none';
    
    // ruleid: php-log-injection
    file_put_contents('api_access.log', date('Y-m-d H:i:s') . " - API key used: " . $apiKey . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // User input properly sanitized before logging
    $username = $_GET['username'];
    $sanitizedUsername = str_replace(["\r", "\n"], '', $username);
    
    // ok: php-log-injection
    error_log("User login attempt: " . $sanitizedUsername);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_2() {
    // POST data properly sanitized before logging
    $searchQuery = $_POST['search'];
    $sanitizedQuery = htmlentities($searchQuery, ENT_QUOTES, 'UTF-8');
    
    // ok: php-log-injection
    file_put_contents('search_log.txt', date('Y-m-d H:i:s') . " - Search query: " . $sanitizedQuery . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_3() {
    // HTTP header properly sanitized before logging
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $sanitizedUserAgent = preg_replace('/[\r\n]/', '', $userAgent);
    
    // ok: php-log-injection
    syslog(LOG_INFO, "User agent: " . $sanitizedUserAgent);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_4() {
    // Cookie data properly sanitized before logging
    $sessionId = $_COOKIE['PHPSESSID'] ?? '';
    $sanitizedSessionId = substr(preg_replace('/[^\w-]/', '', $sessionId), 0, 32);
    
    // ok: php-log-injection
    trigger_error("Session ID accessed: " . $sanitizedSessionId, E_USER_NOTICE);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_5() {
    // Request URI properly sanitized before logging
    $requestUri = $_SERVER['REQUEST_URI'];
    $sanitizedUri = str_replace(["\r", "\n", "\t"], '', $requestUri);
    
    // ok: php-log-injection
    openlog("webapp", LOG_PID | LOG_PERROR, LOG_USER);
    syslog(LOG_WARNING, "Page accessed: " . $sanitizedUri);
    closelog();
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_6() {
    // Multiple user inputs properly sanitized before logging
    $email = $_POST['email'] ?? '';
    $action = $_GET['action'] ?? '';
    
    $sanitizedEmail = filter_var($email, FILTER_SANITIZE_EMAIL);
    $sanitizedAction = preg_replace('/[^\w-]/', '', $action);
    
    // ok: php-log-injection
    error_log("Action '" . $sanitizedAction . "' performed by user: " . $sanitizedEmail);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_7() {
    // User input in JSON data properly sanitized before logging
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $username = $jsonData['username'] ?? 'anonymous';
    $sanitizedUsername = preg_replace('/[\r\n\t"]/', '', $username);
    
    // ok: php-log-injection
    file_put_contents('api_log.txt', date('Y-m-d H:i:s') . " - API access by: " . $sanitizedUsername . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_8() {
    // Referer header properly sanitized before logging
    $referer = $_SERVER['HTTP_REFERER'] ?? '';
    $sanitizedReferer = filter_var($referer, FILTER_SANITIZE_URL);
    $sanitizedReferer = str_replace(["\r", "\n"], '', $sanitizedReferer);
    
    // ok: php-log-injection
    error_log("Request came from: " . $sanitizedReferer);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_9() {
    // User input properly validated and sanitized
    $userId = $_GET['id'] ?? '';
    if (!is_numeric($userId)) {
        $userId = 'invalid';
    }
    
    // ok: php-log-injection
    error_log("User profile accessed: " . $userId);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_10() {
    // User input in an array properly sanitized before logging
    $params = $_GET;
    array_walk_recursive($params, function(&$value) {
        $value = str_replace(["\r", "\n"], '', $value);
    });
    $queryString = http_build_query($params);
    
    // ok: php-log-injection
    file_put_contents('query_log.txt', date('Y-m-d H:i:s') . " - Query: " . $queryString . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_11() {
    // Remote IP address validated before logging
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $sanitizedIp = filter_var($ipAddress, FILTER_VALIDATE_IP);
    if ($sanitizedIp === false) {
        $sanitizedIp = 'invalid-ip';
    }
    
    // ok: php-log-injection
    error_log("Access from IP: " . $sanitizedIp);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_12() {
    // Using a dedicated logging library with built-in sanitization
    $password = $_POST['password'];
    $maskedPassword = substr($password, 0, 1) . '***';
    
    // Simulating a logging library with sanitization
    function secure_log($message) {
        $sanitized = str_replace(["\r", "\n"], '', $message);
        error_log($sanitized);
    }
    
    // ok: php-log-injection
    secure_log("Password attempt (masked): " . $maskedPassword);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_13() {
    // User input in URL parameters properly sanitized before logging
    parse_str($_SERVER['QUERY_STRING'], $params);
    $sortBy = $params['sort'] ?? 'default';
    $allowedSortValues = ['name', 'date', 'price', 'default'];
    
    if (!in_array($sortBy, $allowedSortValues)) {
        $sortBy = 'default';
    }
    
    // ok: php-log-injection
    file_put_contents('sort_log.txt', date('Y-m-d H:i:s') . " - Sorted by: " . $sortBy . "\n", FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_14() {
    // User input with conditional logging and proper sanitization
    $action = $_GET['action'] ?? '';
    $sanitizedAction = preg_replace('/[^\w-]/', '', $action);
    
    if ($sanitizedAction == 'login' || $sanitizedAction == 'logout') {
        $username = $_POST['username'] ?? 'unknown';
        $sanitizedUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        
        // ok: php-log-injection
        error_log("User " . $sanitizedUsername . " performed action: " . $sanitizedAction);
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_15() {
    // User input in custom header properly sanitized before logging
    $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? 'none';
    $sanitizedApiKey = preg_replace('/[^\w\-\.]/', '', $apiKey);
    
    // Only log a portion of the API key for security
    $maskedApiKey = substr($sanitizedApiKey, 0, 4) . '********';
    
    // ok: php-log-injection
    file_put_contents('api_access.log', date('Y-m-d H:i:s') . " - API key used: " . $maskedApiKey . "\n", FILE_APPEND);
}
// {/fact}
?>