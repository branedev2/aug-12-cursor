<?php
// PHP Path Traversal Vulnerability Examples
// {fact rule=path-traversal@v1.0 defects=1}
// Rule ID: php-path-traversal
// CWE-35 and CWE-22

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Direct use of GET parameter in file operations
    $file = $_GET['file'];
    // ruleid: php-path-traversal
    include($file);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_2() {
    // Using POST data in file_get_contents without validation
    $filename = $_POST['filename'];
    // ruleid: php-path-traversal
    $content = file_get_contents($filename);
    echo $content;
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_3() {
    // Using REQUEST parameter in fopen
    $logfile = $_REQUEST['log'];
    // ruleid: php-path-traversal
    $handle = fopen($logfile, 'r');
    while (!feof($handle)) {
        echo fgets($handle);
    }
    fclose($handle);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_4() {
    // Using COOKIE data in file operations
    $template = $_COOKIE['template'];
    // ruleid: php-path-traversal
    require_once($template);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_5() {
    // Using SERVER variable in file operations
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $logPath = "logs/" . $userAgent . ".log";
    // ruleid: php-path-traversal
    file_put_contents($logPath, "User visited at " . date('Y-m-d H:i:s'));
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_6() {
    // Using header value in file operations with minimal processing
    $language = $_SERVER['HTTP_ACCEPT_LANGUAGE'];
    $langFile = strtolower($language) . ".php";
    // ruleid: php-path-traversal
    include_once($langFile);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_7() {
    // Using GET parameter with concatenation
    $directory = "uploads/";
    $file = $directory . $_GET['document'];
    // ruleid: php-path-traversal
    readfile($file);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_8() {
    // Using POST parameter with string replacement but still vulnerable
    $filename = str_replace(" ", "_", $_POST['filename']);
    // ruleid: php-path-traversal
    $data = file_get_contents("data/" . $filename);
    echo $data;
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_9() {
    // Using REQUEST parameter in unlink
    $tempFile = $_REQUEST['temp'];
    // ruleid: php-path-traversal
    unlink($tempFile);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_10() {
    // Using GET parameter in file_exists check
    $configFile = $_GET['config'];
    // ruleid: php-path-traversal
    if (file_exists($configFile)) {
        include($configFile);
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_11() {
    // Using POST parameter in scandir
    $dir = $_POST['directory'];
    // ruleid: php-path-traversal
    $files = scandir($dir);
    foreach ($files as $file) {
        echo $file . "<br>";
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_12() {
    // Using GET parameter in glob
    $pattern = $_GET['pattern'];
    // ruleid: php-path-traversal
    $files = glob($pattern);
    foreach ($files as $file) {
        echo $file . "<br>";
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_13() {
    // Using REQUEST parameter in file_put_contents
    $logfile = $_REQUEST['logfile'];
    $message = "Log entry: " . date('Y-m-d H:i:s');
    // ruleid: php-path-traversal
    file_put_contents($logfile, $message, FILE_APPEND);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_14() {
    // Using GET parameter in is_readable check
    $file = $_GET['file'];
    // ruleid: php-path-traversal
    if (is_readable($file)) {
        $contents = file_get_contents($file);
        echo $contents;
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

function bad_case_15() {
    // Using POST parameter in require with ternary operator
    $module = isset($_POST['module']) ? $_POST['module'] : 'default';
    // ruleid: php-path-traversal
    require("modules/" . $module . ".php");
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// TRUE NEGATIVES (Safe Code)

function good_case_1() {
    // Using whitelist for file inclusion
    $allowed_files = ['profile', 'settings', 'dashboard'];
    $file = $_GET['file'];
    
    // ok: php-path-traversal
    if (in_array($file, $allowed_files)) {
        include("templates/" . $file . ".php");
    } else {
        echo "Invalid file requested";
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_2() {
    // Using realpath to validate file is within allowed directory
    $requested_file = $_POST['filename'];
    $base_dir = "/var/www/allowed_files/";
    $real_path = realpath($base_dir . $requested_file);
    
    // ok: php-path-traversal
    if ($real_path && strpos($real_path, $base_dir) === 0) {
        $content = file_get_contents($real_path);
        echo $content;
    } else {
        echo "Invalid file path";
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_3() {
    // Using basename to strip directory components
    $filename = $_REQUEST['log'];
    $safe_filename = basename($filename);
    
    // ok: php-path-traversal
    $handle = fopen("logs/" . $safe_filename, 'r');
    while (!feof($handle)) {
        echo fgets($handle);
    }
    fclose($handle);
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_4() {
    // Using strict file extension validation
    $template = $_COOKIE['template'];
    $template = preg_replace('/[^a-zA-Z0-9_-]/', '', $template);
    
    // ok: php-path-traversal
    require_once("templates/" . $template . ".php");
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_5() {
    // Using sanitization and fixed directory
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $safeAgent = preg_replace('/[^a-zA-Z0-9]/', '_', $userAgent);
    
    // ok: php-path-traversal
    file_put_contents("logs/useragents/" . $safeAgent . ".log", "Visit at " . date('Y-m-d H:i:s'));
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_6() {
    // Using whitelist for language files
    $allowed_languages = ['en', 'fr', 'de', 'es'];
    $language = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
    
    // ok: php-path-traversal
    if (in_array($language, $allowed_languages)) {
        include_once("languages/" . $language . ".php");
    } else {
        include_once("languages/en.php");
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_7() {
    // Using sanitization and validation for file access
    $document = $_GET['document'];
    $document = preg_replace('/[^a-zA-Z0-9_-]/', '', $document);
    
    // ok: php-path-traversal
    if (!empty($document) && file_exists("uploads/" . $document . ".pdf")) {
        readfile("uploads/" . $document . ".pdf");
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_8() {
    // Using pathinfo to extract filename and enforce extension
    $filename = $_POST['filename'];
    $info = pathinfo($filename);
    $safe_filename = preg_replace('/[^a-zA-Z0-9_-]/', '', $info['filename']) . ".txt";
    
    // ok: php-path-traversal
    $data = file_get_contents("data/" . $safe_filename);
    echo $data;
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_9() {
    // Using whitelist for temp file deletion
    $allowed_temps = ['cache', 'session', 'upload'];
    $temp_type = $_REQUEST['temp'];
    
    // ok: php-path-traversal
    if (in_array($temp_type, $allowed_temps)) {
        unlink("tmp/" . $temp_type . "_temp.dat");
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_10() {
    // Using strict validation for config files
    $config = $_GET['config'];
    $valid_configs = ['app', 'database', 'mail', 'cache'];
    
    // ok: php-path-traversal
    if (in_array($config, $valid_configs)) {
        $configFile = "config/" . $config . ".php";
        if (file_exists($configFile)) {
            include($configFile);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_11() {
    // Using predefined directories only
    $dir_id = $_POST['directory'];
    $directories = [
        'public' => 'public_files',
        'shared' => 'shared_docs',
        'templates' => 'template_files'
    ];
    
    // ok: php-path-traversal
    if (isset($directories[$dir_id])) {
        $files = scandir($directories[$dir_id]);
        foreach ($files as $file) {
            if ($file != '.' && $file != '..') {
                echo $file . "<br>";
            }
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_12() {
    // Using fixed directory and sanitized pattern
    $search = $_GET['pattern'];
    $safe_search = preg_replace('/[^a-zA-Z0-9_*]/', '', $search);
    
    // ok: php-path-traversal
    $files = glob("uploads/" . $safe_search);
    foreach ($files as $file) {
        echo basename($file) . "<br>";
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_13() {
    // Using fixed log files based on type
    $log_type = $_REQUEST['logfile'];
    $valid_logs = ['error', 'access', 'debug'];
    
    // ok: php-path-traversal
    if (in_array($log_type, $valid_logs)) {
        $message = "Log entry: " . date('Y-m-d H:i:s');
        file_put_contents("logs/" . $log_type . ".log", $message, FILE_APPEND);
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_14() {
    // Using hash verification for secure file access
    $file_hash = $_GET['file'];
    $hash_to_file = [
        'a1b2c3' => 'document1.pdf',
        'd4e5f6' => 'document2.pdf',
        'g7h8i9' => 'document3.pdf'
    ];
    
    // ok: php-path-traversal
    if (isset($hash_to_file[$file_hash]) && is_readable("secure_docs/" . $hash_to_file[$file_hash])) {
        $contents = file_get_contents("secure_docs/" . $hash_to_file[$file_hash]);
        echo $contents;
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

function good_case_15() {
    // Using strict module name validation
    $module = isset($_POST['module']) ? $_POST['module'] : 'default';
    $valid_modules = ['user', 'admin', 'guest', 'default'];
    
    // ok: php-path-traversal
    if (in_array($module, $valid_modules)) {
        require("modules/" . $module . ".php");
    } else {
        require("modules/default.php");
    }
}
// {/fact}
?>