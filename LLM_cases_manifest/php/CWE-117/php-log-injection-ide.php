<?php
// PHP Log Injection Examples
// Rule ID: php-log-injection-ide
// {fact rule=ldap-injection@v1.0 defects=1}
// CWE-117: Improper Output Neutralization for Logs

// TRUE POSITIVES (Vulnerable Code)

// Bad Case 1: Direct logging of GET parameter
function bad_case_1() {
    $userInput = $_GET['username'];
    // ruleid: php-log-injection-ide
    error_log("User login attempt: " . $userInput);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 2: POST data logged directly
function bad_case_2() {
    $message = $_POST['message'];
    // ruleid: php-log-injection-ide
    error_log("Message received: " . $message);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 3: HTTP header logged without sanitization
function bad_case_3() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    // ruleid: php-log-injection-ide
    error_log("User agent: " . $userAgent);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 4: Cookie value logged directly
function bad_case_4() {
    $sessionId = $_COOKIE['sessionid'];
    // ruleid: php-log-injection-ide
    error_log("Session ID: " . $sessionId);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 5: Request URI logged without sanitization
function bad_case_5() {
    $requestUri = $_SERVER['REQUEST_URI'];
    // ruleid: php-log-injection-ide
    error_log("Request URI: " . $requestUri);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 6: Using syslog with unsanitized input
function bad_case_6() {
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    // ruleid: php-log-injection-ide
    syslog(LOG_WARNING, "Connection from IP: " . $ipAddress);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 7: Using file_put_contents for logging with unsanitized input
function bad_case_7() {
    $query = $_GET['search'];
    $logFile = 'search_log.txt';
    $logMessage = date('Y-m-d H:i:s') . " - Search query: " . $query . "\n";
    // ruleid: php-log-injection-ide
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 8: Using fwrite for logging with unsanitized input
function bad_case_8() {
    $username = $_POST['username'];
    $logFile = fopen('access_log.txt', 'a');
    $logMessage = date('Y-m-d H:i:s') . " - Login attempt: " . $username . "\n";
    // ruleid: php-log-injection-ide
    fwrite($logFile, $logMessage);
    fclose($logFile);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 9: Using custom logger with unsanitized input
function bad_case_9() {
    $referrer = $_SERVER['HTTP_REFERER'];
    $logger = new Logger();
    // ruleid: php-log-injection-ide
    $logger->log("Referrer: " . $referrer);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 10: Logging with string interpolation
function bad_case_10() {
    $email = $_POST['email'];
    // ruleid: php-log-injection-ide
    error_log("New subscription from email: $email");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 11: Logging with concatenation after minimal processing
function bad_case_11() {
    $comment = $_POST['comment'];
    $trimmed = trim($comment);
    // ruleid: php-log-injection-ide
    error_log("New comment: " . $trimmed);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 12: Logging with concatenation in a conditional block
function bad_case_12() {
    if (isset($_GET['error'])) {
        $errorCode = $_GET['error'];
        // ruleid: php-log-injection-ide
        error_log("Error occurred with code: " . $errorCode);
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 13: Logging with concatenation in a loop
function bad_case_13() {
    $items = $_POST['items'];
    foreach ($items as $item) {
        // ruleid: php-log-injection-ide
        error_log("Processing item: " . $item);
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 14: Logging with concatenation after type casting
function bad_case_14() {
    $userId = (int)$_GET['user_id'];
    $action = $_GET['action']; // This is still unsanitized
    // ruleid: php-log-injection-ide
    error_log("User $userId performed action: $action");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

// Bad Case 15: Logging with concatenation using a switch statement
function bad_case_15() {
    $operation = $_POST['operation'];
    switch ($operation) {
        case 'add':
            $value = $_POST['value'];
            // ruleid: php-log-injection-ide
            error_log("Add operation with value: " . $value);
            break;
        case 'delete':
            $id = $_POST['id'];
            // ruleid: php-log-injection-ide
            error_log("Delete operation with ID: " . $id);
            break;
        default:
            // ruleid: php-log-injection-ide
            error_log("Unknown operation: " . $operation);
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// TRUE NEGATIVES (Safe Code)

// Good Case 1: Sanitizing input before logging with str_replace
function good_case_1() {
    $userInput = $_GET['username'];
    $sanitized = str_replace(["\r", "\n"], '', $userInput);
    // ok: php-log-injection-ide
    error_log("User login attempt: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 2: Using htmlentities for sanitization
function good_case_2() {
    $message = $_POST['message'];
    $sanitized = htmlentities($message, ENT_QUOTES, 'UTF-8');
    // ok: php-log-injection-ide
    error_log("Message received: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 3: Using preg_replace to remove problematic characters
function good_case_3() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $sanitized = preg_replace('/[\r\n]/', '', $userAgent);
    // ok: php-log-injection-ide
    error_log("User agent: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 4: Using filter_var for sanitization
function good_case_4() {
    $email = $_POST['email'];
    $sanitized = filter_var($email, FILTER_SANITIZE_EMAIL);
    // ok: php-log-injection-ide
    error_log("Email provided: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 5: Using json_encode for complex data
function good_case_5() {
    $userData = $_POST['user_data'];
    $sanitized = json_encode($userData);
    // ok: php-log-injection-ide
    error_log("User data: " . $sanitized);
}
// {/fact}

// Good Case 6: Using a dedicated sanitization function
function sanitizeForLog($input) {
    return str_replace(["\r", "\n", "\t"], ' ', $input);
}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_6() {
    $query = $_GET['search'];
    $sanitized = sanitizeForLog($query);
    // ok: php-log-injection-ide
    error_log("Search query: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 7: Using a custom logger with built-in sanitization
function good_case_7() {
    $referrer = $_SERVER['HTTP_REFERER'];
    $logger = new SecureLogger();
    // ok: php-log-injection-ide
    $logger->logSanitized("Referrer", $referrer);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 8: Using a PSR-3 compatible logger
function good_case_8() {
    $username = $_POST['username'];
    $logger = new \Psr\Log\Logger();
    // PSR-3 loggers typically handle sanitization internally
    // ok: php-log-injection-ide
    $logger->info("Login attempt", ['username' => $username]);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 9: Using Monolog with context
function good_case_9() {
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $logger = new \Monolog\Logger('security');
    // Monolog handles context data properly
    // ok: php-log-injection-ide
    $logger->warning("Connection attempt", ['ip' => $ipAddress]);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 10: Using a custom sanitization class
function good_case_10() {
    $comment = $_POST['comment'];
    $sanitizer = new InputSanitizer();
    $sanitized = $sanitizer->forLogging($comment);
    // ok: php-log-injection-ide
    error_log("New comment: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 11: Using multiple sanitization techniques
function good_case_11() {
    $input = $_GET['input'];
    $sanitized = htmlspecialchars(
        str_replace(["\r", "\n"], '', 
        trim($input)
    ));
    // ok: php-log-injection-ide
    error_log("Received input: " . $sanitized);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 12: Using type casting for numeric values
function good_case_12() {
    $userId = (int)$_GET['user_id'];
    // Integer casting ensures no injection is possible
    // ok: php-log-injection-ide
    error_log("User ID accessed: " . $userId);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 13: Using a whitelist approach
function good_case_13() {
    $action = $_GET['action'];
    $allowedActions = ['view', 'edit', 'delete'];
    
    if (in_array($action, $allowedActions)) {
        // ok: php-log-injection-ide
        error_log("Action performed: " . $action);
    } else {
        // ok: php-log-injection-ide
        error_log("Invalid action attempted");
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 14: Using sprintf with proper formatting
function good_case_14() {
    $username = $_POST['username'];
    $sanitized = str_replace(["\r", "\n"], '', $username);
    // ok: php-log-injection-ide
    error_log(sprintf("Login attempt by user: %s", $sanitized));
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// Good Case 15: Using a dedicated logging library with context
function good_case_15() {
    $requestData = [
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'referrer' => $_SERVER['HTTP_REFERER'] ?? 'direct'
    ];
    
    $logger = new SecurityLogger();
    // Context data is handled safely by the logger
    // ok: php-log-injection-ide
    $logger->logRequest("User request", $requestData);
}
// {/fact}

// Mock classes for examples
class Logger {
    public function log($message) {
        error_log($message);
    }
}

class SecureLogger {
    public function logSanitized($type, $message) {
        $sanitized = str_replace(["\r", "\n"], '', $message);
        error_log("$type: $sanitized");
    }
}

class InputSanitizer {
    public function forLogging($input) {
        return preg_replace('/[\r\n\t\f\v]/', ' ', $input);
    }
}

class SecurityLogger {
    public function logRequest($message, $context) {
        // Sanitize all context values
        foreach ($context as $key => $value) {
            $context[$key] = str_replace(["\r", "\n"], '', $value);
        }
        error_log($message . ': ' . json_encode($context));
    }
}
?>