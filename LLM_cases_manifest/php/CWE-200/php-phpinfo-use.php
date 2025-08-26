<?php
/**
 * Test cases for php-phpinfo-use rule
 * 
 * This file contains examples of both vulnerable and secure code
 * related to the use of phpinfo() function in PHP.
 */
// {fact rule=sensitive-information-leak@v1.0 defects=1}

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Simple direct call to phpinfo
    // ruleid: php-phpinfo-use
    phpinfo();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_2() {
    if (isset($_GET['debug']) && $_GET['debug'] === 'true') {
        // Conditional execution of phpinfo based on GET parameter
        // ruleid: php-phpinfo-use
        phpinfo();
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_3() {
    // Using phpinfo with specific section parameter
    // ruleid: php-phpinfo-use
    phpinfo(INFO_MODULES);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_4() {
    // Using phpinfo in an admin page
    if ($_SESSION['user_role'] === 'admin') {
        echo "<h1>System Information</h1>";
        // ruleid: php-phpinfo-use
        phpinfo(INFO_CONFIGURATION);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_5() {
    // Using phpinfo in a try-catch block
    try {
        // ruleid: php-phpinfo-use
        phpinfo();
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_6() {
    // Using phpinfo with variable control
    $show_info = true;
    if ($show_info) {
        // ruleid: php-phpinfo-use
        phpinfo(INFO_ENVIRONMENT);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_7() {
    // Using phpinfo in a function that's called conditionally
    function display_system_info() {
        // ruleid: php-phpinfo-use
        phpinfo();
    }
    
    if (isset($_GET['action']) && $_GET['action'] === 'sysinfo') {
        display_system_info();
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_8() {
    // Using phpinfo with output buffering
    ob_start();
    // ruleid: php-phpinfo-use
    phpinfo();
    $info = ob_get_clean();
    
    // Store in log file
    file_put_contents('system_info.log', $info);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_9() {
    // Using phpinfo in a switch statement
    $action = $_GET['action'] ?? '';
    
    switch ($action) {
        case 'info':
            // ruleid: php-phpinfo-use
            phpinfo();
            break;
        default:
            echo "No action specified";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_10() {
    // Using phpinfo with multiple flags combined
    // ruleid: php-phpinfo-use
    phpinfo(INFO_GENERAL | INFO_CONFIGURATION | INFO_MODULES);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_11() {
    // Using phpinfo in an AJAX response
    if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
        ob_start();
        // ruleid: php-phpinfo-use
        phpinfo();
        $info = ob_get_clean();
        echo json_encode(['system_info' => $info]);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_12() {
    // Using phpinfo with a custom wrapper function
    function get_system_info() {
        ob_start();
        // ruleid: php-phpinfo-use
        phpinfo();
        return ob_get_clean();
    }
    
    $info = get_system_info();
    echo "<div class='system-info'>" . $info . "</div>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_13() {
    // Using phpinfo in a development environment check
    $environment = getenv('APP_ENV') ?: 'development';
    
    if ($environment === 'development') {
        echo "<h2>Development Environment Information</h2>";
        // ruleid: php-phpinfo-use
        phpinfo();
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_14() {
    // Using phpinfo with error reporting configuration
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    
    // ruleid: php-phpinfo-use
    phpinfo(INFO_VARIABLES);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_15() {
    // Using phpinfo in a class method
    class SystemDiagnostics {
        public function showInfo() {
            // ruleid: php-phpinfo-use
            phpinfo();
        }
    }
    
    $diagnostics = new SystemDiagnostics();
    $diagnostics->showInfo();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

// True Negatives (Secure Code)

function good_case_1() {
    // Using ini_get to retrieve specific configuration values
    // ok: php-phpinfo-use
    $memory_limit = ini_get('memory_limit');
    $max_execution_time = ini_get('max_execution_time');
    
    echo "Memory Limit: " . $memory_limit . "<br>";
    echo "Max Execution Time: " . $max_execution_time . "<br>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_2() {
    // Displaying only specific PHP version information
    // ok: php-phpinfo-use
    echo "PHP Version: " . PHP_VERSION . "<br>";
    echo "PHP OS: " . PHP_OS . "<br>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_3() {
    // Using get_loaded_extensions instead of phpinfo
    // ok: php-phpinfo-use
    $extensions = get_loaded_extensions();
    echo "<h2>Loaded Extensions</h2>";
    echo "<ul>";
    foreach ($extensions as $extension) {
        echo "<li>" . htmlspecialchars($extension) . "</li>";
    }
    echo "</ul>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_4() {
    // Checking specific extension availability
    // ok: php-phpinfo-use
    if (extension_loaded('gd')) {
        echo "GD Library is available<br>";
        $gd_info = gd_info();
        echo "GD Version: " . $gd_info['GD Version'] . "<br>";
    } else {
        echo "GD Library is not available<br>";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_5() {
    // Using php_uname instead of phpinfo for system information
    // ok: php-phpinfo-use
    echo "System: " . php_uname('s') . "<br>";
    echo "Host: " . php_uname('n') . "<br>";
    echo "Release: " . php_uname('r') . "<br>";
    echo "Version: " . php_uname('v') . "<br>";
    echo "Machine: " . php_uname('m') . "<br>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_6() {
    // Creating a custom system info function without phpinfo
    // ok: php-phpinfo-use
    function get_safe_system_info() {
        $info = [
            'PHP Version' => PHP_VERSION,
            'OS' => PHP_OS,
            'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Unknown',
            'Memory Limit' => ini_get('memory_limit'),
            'Upload Max Filesize' => ini_get('upload_max_filesize')
        ];
        
        return $info;
    }
    
    $system_info = get_safe_system_info();
    foreach ($system_info as $key => $value) {
        echo htmlspecialchars($key) . ": " . htmlspecialchars($value) . "<br>";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_7() {
    // Using specific environment checks instead of phpinfo
    // ok: php-phpinfo-use
    $timezone = date_default_timezone_get();
    $error_reporting = error_reporting();
    $display_errors = ini_get('display_errors');
    
    echo "Timezone: " . $timezone . "<br>";
    echo "Error Reporting Level: " . $error_reporting . "<br>";
    echo "Display Errors: " . $display_errors . "<br>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_8() {
    // Checking database connection info safely
    // ok: php-phpinfo-use
    try {
        $pdo = new PDO('mysql:host=localhost;dbname=test', 'username', 'password');
        echo "Database connection successful<br>";
        echo "PDO Driver Name: " . $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) . "<br>";
        echo "Server Version: " . $pdo->getAttribute(PDO::ATTR_SERVER_VERSION) . "<br>";
    } catch (PDOException $e) {
        echo "Database connection failed: " . $e->getMessage();
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_9() {
    // Displaying server variables safely
    // ok: php-phpinfo-use
    $safe_server_vars = [
        'SERVER_SOFTWARE',
        'SERVER_PROTOCOL',
        'REQUEST_METHOD',
        'DOCUMENT_ROOT',
        'HTTP_ACCEPT_LANGUAGE'
    ];
    
    echo "<h2>Selected Server Information</h2>";
    echo "<ul>";
    foreach ($safe_server_vars as $var) {
        if (isset($_SERVER[$var])) {
            echo "<li>" . htmlspecialchars($var) . ": " . htmlspecialchars($_SERVER[$var]) . "</li>";
        }
    }
    echo "</ul>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_10() {
    // Using function_exists to check for available functions
    // ok: php-phpinfo-use
    $functions_to_check = ['imagecreate', 'curl_init', 'mysqli_connect', 'simplexml_load_file'];
    
    echo "<h2>Function Availability</h2>";
    echo "<ul>";
    foreach ($functions_to_check as $function) {
        echo "<li>" . htmlspecialchars($function) . ": " . (function_exists($function) ? 'Available' : 'Not Available') . "</li>";
    }
    echo "</ul>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_11() {
    // Checking session configuration
    // ok: php-phpinfo-use
    $session_config = [
        'Session Save Path' => ini_get('session.save_path'),
        'Session Name' => ini_get('session.name'),
        'Session Cookie Lifetime' => ini_get('session.cookie_lifetime'),
        'Session Cookie Path' => ini_get('session.cookie_path'),
        'Session Cookie Domain' => ini_get('session.cookie_domain'),
        'Session Cookie Secure' => ini_get('session.cookie_secure'),
        'Session Cookie HttpOnly' => ini_get('session.cookie_httponly')
    ];
    
    echo "<h2>Session Configuration</h2>";
    foreach ($session_config as $key => $value) {
        echo htmlspecialchars($key) . ": " . htmlspecialchars($value) . "<br>";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_12() {
    // Using a custom debug page with controlled information
    // ok: php-phpinfo-use
    if (isset($_GET['debug']) && $_GET['debug'] === 'true' && $_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
        echo "<h1>Debug Information</h1>";
        echo "<p>PHP Version: " . PHP_VERSION . "</p>";
        echo "<p>Memory Usage: " . memory_get_usage(true) / 1024 / 1024 . " MB</p>";
        echo "<p>Peak Memory Usage: " . memory_get_peak_usage(true) / 1024 / 1024 . " MB</p>";
        echo "<p>Execution Time: " . microtime(true) - $_SERVER['REQUEST_TIME_FLOAT'] . " seconds</p>";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_13() {
    // Using phpversion() instead of phpinfo()
    // ok: php-phpinfo-use
    $php_version = phpversion();
    $php_major_version = phpversion('mysqli');
    
    echo "PHP Version: " . $php_version . "<br>";
    echo "MySQLi Extension Version: " . ($php_major_version ?: 'Not installed') . "<br>";
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_14() {
    // Creating a custom diagnostic class without phpinfo
    // ok: php-phpinfo-use
    class SafeDiagnostics {
        public function getSystemInfo() {
            return [
                'PHP Version' => PHP_VERSION,
                'Operating System' => PHP_OS,
                'Server API' => php_sapi_name(),
                'Memory Limit' => ini_get('memory_limit'),
                'Max Execution Time' => ini_get('max_execution_time'),
                'Upload Max Filesize' => ini_get('upload_max_filesize'),
                'Post Max Size' => ini_get('post_max_size')
            ];
        }
        
        public function displaySystemInfo() {
            $info = $this->getSystemInfo();
            echo "<table border='1'>";
            echo "<tr><th>Setting</th><th>Value</th></tr>";
            foreach ($info as $key => $value) {
                echo "<tr><td>" . htmlspecialchars($key) . "</td><td>" . htmlspecialchars($value) . "</td></tr>";
            }
            echo "</table>";
        }
    }
    
    $diagnostics = new SafeDiagnostics();
    $diagnostics->displaySystemInfo();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_15() {
    // Using a logging approach instead of displaying info directly
    // ok: php-phpinfo-use
    function log_system_info() {
        $log_data = [
            'timestamp' => date('Y-m-d H:i:s'),
            'php_version' => PHP_VERSION,
            'os' => PHP_OS,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time')
        ];
        
        error_log("System Info: " . json_encode($log_data));
        return true;
    }
    
    if (isset($_GET['check_system']) && $_GET['check_system'] === 'true') {
        if (log_system_info()) {
            echo "System information has been logged. Check server logs for details.";
        }
    }
}
// {/fact}
?>