<?php
/**
 * Test cases for php-insecure-logging-config rule
 * This rule detects insecure PHP logging configurations that could expose sensitive information
 */
// {fact rule=ldap-injection@v1.0 defects=1}

// TRUE POSITIVES (Insecure configurations)

function bad_case_1() {
    // Setting error reporting to E_ALL in production environment
    // ruleid: php-insecure-logging-config
    error_reporting(E_ALL);
    
    // Application code
    $user = getUserData();
    processUserRequest($user);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_2() {
    // Enabling display_errors in production
    // ruleid: php-insecure-logging-config
    ini_set('display_errors', 1);
    
    // Process sensitive payment information
    $payment = processPayment($_POST['cc_number']);
    return $payment;
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_3() {
    // Using ini_alter (alias of ini_set) to show all errors
    // ruleid: php-insecure-logging-config
    ini_alter('display_errors', 'On');
    ini_alter('error_reporting', E_ALL);
    
    // Database operations
    $conn = connectToDatabase();
    $result = $conn->query("SELECT * FROM users");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_4() {
    // Combination of multiple insecure settings
    // ruleid: php-insecure-logging-config
    error_reporting(E_ALL | E_STRICT);
    ini_set('display_errors', 'On');
    ini_set('log_errors', 0);
    
    // Process authentication
    authenticateUser($_POST['username'], $_POST['password']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_5() {
    // Setting error_log to a publicly accessible location
    // ruleid: php-insecure-logging-config
    ini_set('error_log', '/var/www/html/errors.log');
    
    // Process API request
    $apiKey = $_GET['api_key'];
    makeExternalRequest($apiKey);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_6() {
    if (isset($_GET['debug']) && $_GET['debug'] == 1) {
        // Enabling verbose errors based on user input
        // ruleid: php-insecure-logging-config
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    }
    
    // Process sensitive data
    $userData = getUserProfile($_SESSION['user_id']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_7() {
    // Disabling error logging completely
    // ruleid: php-insecure-logging-config
    error_reporting(0);
    ini_set('log_errors', 0);
    
    // Critical operation without any error tracking
    transferFunds($_POST['amount'], $_POST['destination']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_8() {
    // Setting insecure error handling in a class method
    class ErrorManager {
        public function enableDebugMode() {
            // ruleid: php-insecure-logging-config
            ini_set('display_errors', 'On');
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        }
    }
    
    $manager = new ErrorManager();
    $manager->enableDebugMode();
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_9() {
    // Using conditionals but still setting insecure config
    $environment = getEnvironment();
    if ($environment == 'development' || $environment == 'production') {
        // ruleid: php-insecure-logging-config
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    }
    
    processUserData($_POST);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_10() {
    // Setting error reporting based on request parameter
    $level = isset($_GET['level']) ? $_GET['level'] : E_ALL;
    
    // ruleid: php-insecure-logging-config
    error_reporting($level);
    
    // Process database operations
    $db = new Database();
    $users = $db->query("SELECT * FROM users");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_11() {
    // Insecure configuration with HTML display
    // ruleid: php-insecure-logging-config
    ini_set('html_errors', 1);
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
    
    // Process file uploads
    handleFileUpload($_FILES['document']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_12() {
    // Logging to a custom handler but with insecure settings
    function customErrorHandler($errno, $errstr, $errfile, $errline) {
        echo "<b>Error:</b> [$errno] $errstr<br>";
        echo "Error on line $errline in $errfile<br>";
    }
    
    // ruleid: php-insecure-logging-config
    set_error_handler("customErrorHandler");
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
    
    // Process sensitive operation
    validateUserCredentials($_POST['username'], $_POST['password']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_13() {
    // Insecure configuration in a try-catch block
    try {
        // ruleid: php-insecure-logging-config
        ini_set('display_errors', 'On');
        error_reporting(E_ALL);
        
        // Process payment
        $payment = new PaymentProcessor();
        $payment->process($_POST['amount'], $_POST['card_number']);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_14() {
    // Multiple ini_set calls with insecure values
    // ruleid: php-insecure-logging-config
    ini_set('log_errors_max_len', 0); // No maximum length for logged errors
    ini_set('ignore_repeated_errors', 0);
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    
    // Process sensitive user information
    updateUserProfile($_POST['user_data']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=1}

function bad_case_15() {
    // Using constants but still insecure
    define('DEBUG_MODE', true);
    
    if (DEBUG_MODE) {
        // ruleid: php-insecure-logging-config
        error_reporting(E_ALL);
        ini_set('display_errors', 'On');
    }
    
    // Process authentication token
    validateToken($_GET['token']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

// TRUE NEGATIVES (Secure configurations)

function good_case_1() {
    // Proper error reporting for production
    // ok: php-insecure-logging-config
    error_reporting(E_ERROR | E_PARSE);
    ini_set('display_errors', 0);
    
    // Application code
    $user = getUserData();
    processUserRequest($user);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_2() {
    // Disabling display errors but logging them
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/var/log/php/error.log');
    
    // Process sensitive payment information
    $payment = processPayment($_POST['cc_number']);
    return $payment;
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_3() {
    // Environment-specific configuration
    $environment = getEnvironment();
    
    if ($environment === 'development') {
        // Development-only settings
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    } else {
        // ok: php-insecure-logging-config
        error_reporting(E_ERROR | E_PARSE);
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
    }
    
    // Database operations
    $conn = connectToDatabase();
    $result = $conn->query("SELECT * FROM users");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_4() {
    // Custom error handler that logs securely
    function secureErrorHandler($errno, $errstr, $errfile, $errline) {
        $logFile = '/var/log/php/secure_errors.log';
        $message = date('Y-m-d H:i:s') . " - Error [$errno]: $errstr in $errfile on line $errline\n";
        error_log($message, 3, $logFile);
        
        // Display generic error to user
        if ($errno == E_ERROR) {
            header('HTTP/1.1 500 Internal Server Error');
            echo "An error occurred. Please try again later.";
        }
        
        return true;
    }
    
    // ok: php-insecure-logging-config
    set_error_handler("secureErrorHandler");
    ini_set('display_errors', 0);
    
    // Process authentication
    authenticateUser($_POST['username'], $_POST['password']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_5() {
    // Secure logging configuration
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/var/log/php/errors.log');
    error_reporting(E_ERROR | E_PARSE | E_CORE_ERROR);
    
    // Process API request
    $apiKey = $_GET['api_key'];
    makeExternalRequest($apiKey);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_6() {
    // Proper configuration with IP-based restrictions
    $allowedIPs = ['127.0.0.1', '192.168.1.100'];
    $clientIP = $_SERVER['REMOTE_ADDR'];
    
    if (in_array($clientIP, $allowedIPs)) {
        // Debug mode for specific IPs only
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    } else {
        // ok: php-insecure-logging-config
        error_reporting(E_ERROR);
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
    }
    
    // Process sensitive data
    $userData = getUserProfile($_SESSION['user_id']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_7() {
    // Using a configuration class with secure defaults
    class LogConfig {
        public static function setupProduction() {
            // ok: php-insecure-logging-config
            error_reporting(E_ERROR | E_PARSE);
            ini_set('display_errors', 0);
            ini_set('log_errors', 1);
            ini_set('error_log', '/var/log/php/production_errors.log');
        }
    }
    
    LogConfig::setupProduction();
    
    // Critical operation with proper error handling
    transferFunds($_POST['amount'], $_POST['destination']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_8() {
    // Using try-catch with secure logging
    try {
        // ok: php-insecure-logging-config
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
        
        // Process payment
        $payment = new PaymentProcessor();
        $payment->process($_POST['amount'], $_POST['card_number']);
    } catch (Exception $e) {
        // Log exception securely
        error_log('Payment processing error: ' . $e->getMessage());
        
        // Show generic error to user
        echo "Payment processing failed. Please try again later.";
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_9() {
    // Secure configuration with detailed logging but no display
    // ok: php-insecure-logging-config
    error_reporting(E_ALL);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', '/var/log/php/detailed_errors.log');
    
    // Process database operations
    $db = new Database();
    $users = $db->query("SELECT * FROM users");
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_10() {
    // Proper configuration for different environments
    $config = [
        'development' => [
            'error_reporting' => E_ALL,
            'display_errors' => 1,
            'log_errors' => 1
        ],
        'production' => [
            'error_reporting' => E_ERROR | E_PARSE,
            'display_errors' => 0,
            'log_errors' => 1
        ]
    ];
    
    $env = getEnvironment();
    
    // ok: php-insecure-logging-config
    error_reporting($config[$env]['error_reporting']);
    ini_set('display_errors', $config[$env]['display_errors']);
    ini_set('log_errors', $config[$env]['log_errors']);
    
    // Process file uploads
    handleFileUpload($_FILES['document']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_11() {
    // Using a custom error logger with sanitization
    class SecureLogger {
        private $logFile;
        
        public function __construct($logFile) {
            $this->logFile = $logFile;
        }
        
        public function log($message) {
            // Sanitize message before logging
            $sanitized = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
            error_log(date('Y-m-d H:i:s') . " - $sanitized\n", 3, $this->logFile);
        }
    }
    
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    
    $logger = new SecureLogger('/var/log/php/app_errors.log');
    
    try {
        validateUserCredentials($_POST['username'], $_POST['password']);
    } catch (Exception $e) {
        $logger->log($e->getMessage());
        echo "Authentication failed. Please try again.";
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_12() {
    // Proper configuration with error suppression
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    error_reporting(E_ERROR | E_PARSE);
    
    // Suppress warnings for specific operations but log them
    $result = @file_get_contents('https://api.example.com/data');
    if ($result === false) {
        error_log('Failed to fetch data from API');
        return false;
    }
    
    return processApiResult($result);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_13() {
    // Secure configuration with rate limiting for error logging
    class RateLimitedLogger {
        private $logFile;
        private $maxLogsPerMinute;
        private $cacheFile;
        
        public function __construct($logFile, $maxLogsPerMinute = 10) {
            $this->logFile = $logFile;
            $this->maxLogsPerMinute = $maxLogsPerMinute;
            $this->cacheFile = sys_get_temp_dir() . '/error_count.tmp';
        }
        
        public function log($message) {
            if ($this->canLog()) {
                error_log(date('Y-m-d H:i:s') . " - $message\n", 3, $this->logFile);
            }
        }
        
        private function canLog() {
            // Rate limiting logic
            // Implementation details omitted for brevity
            return true;
        }
    }
    
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    
    $logger = new RateLimitedLogger('/var/log/php/rate_limited_errors.log');
    
    // Process payment
    $payment = new PaymentProcessor();
    try {
        $payment->process($_POST['amount'], $_POST['card_number']);
    } catch (Exception $e) {
        $logger->log($e->getMessage());
        echo "Payment processing failed.";
    }
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_14() {
    // Secure configuration with context-aware error handling
    // ok: php-insecure-logging-config
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    error_reporting(E_ERROR | E_PARSE);
    
    function handleError($errno, $errstr, $errfile, $errline) {
        $errorTypes = [
            E_ERROR => 'Fatal Error',
            E_WARNING => 'Warning',
            E_PARSE => 'Parse Error',
            E_NOTICE => 'Notice'
        ];
        
        $type = isset($errorTypes[$errno]) ? $errorTypes[$errno] : 'Unknown Error';
        $message = "$type: $errstr in $errfile on line $errline";
        
        // Log detailed error for admins
        error_log($message);
        
        // Show appropriate message based on error type
        if ($errno == E_ERROR || $errno == E_PARSE) {
            echo "A system error occurred. Please try again later.";
        }
        
        return true;
    }
    
    set_error_handler('handleError');
    
    // Update user profile
    updateUserProfile($_POST['user_data']);
}
// {/fact}
// {fact rule=ldap-injection@v1.0 defects=0}

function good_case_15() {
    // Configuration with secure defaults and environment check
    $isProduction = (getenv('APP_ENV') === 'production');
    
    // ok: php-insecure-logging-config
    if ($isProduction) {
        error_reporting(E_ERROR | E_PARSE);
        ini_set('display_errors', 0);
        ini_set('log_errors', 1);
        ini_set('error_log', '/var/log/php/production_errors.log');
    } else {
        // Development environment can have more verbose errors
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
        ini_set('log_errors', 1);
        ini_set('error_log', '/var/log/php/development_errors.log');
    }
    
    // Process authentication token
    validateToken($_GET['token']);
}
// {/fact}

// Helper functions (implementations omitted for brevity)
function getUserData() { /* ... */ }
function processUserRequest($user) { /* ... */ }
function processPayment($ccNumber) { /* ... */ }
function connectToDatabase() { /* ... */ }
function authenticateUser($username, $password) { /* ... */ }
function getUserProfile($userId) { /* ... */ }
function transferFunds($amount, $destination) { /* ... */ }
function getEnvironment() { /* ... */ }
function handleFileUpload($file) { /* ... */ }
function validateUserCredentials($username, $password) { /* ... */ }
function updateUserProfile($userData) { /* ... */ }
function validateToken($token) { /* ... */ }
function makeExternalRequest($apiKey) { /* ... */ }
function processApiResult($result) { /* ... */ }
?>