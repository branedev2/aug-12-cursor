<?php
// {fact rule=insecure-configuration@v1.0 defects=1}
// Examples for php-allow-url-fopen-or-include rule
// This is a configuration/usage issue related to PHP's allow_url_fopen and allow_url_include settings

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Using user input directly in include with allow_url_include enabled
    $template = $_GET['template'];
    // ruleid: php-allow-url-fopen-or-include
    include($template); // Could include remote file like http://attacker.com/malicious.php
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_2() {
    // Using user input directly in require with allow_url_include enabled
    $module = $_POST['module'];
    // ruleid: php-allow-url-fopen-or-include
    require($module); // Could require remote file like http://attacker.com/malicious.php
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_3() {
    // Using user input directly in include_once with allow_url_include enabled
    $component = $_REQUEST['component'];
    // ruleid: php-allow-url-fopen-or-include
    include_once($component); // Could include remote file like http://attacker.com/malicious.php
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_4() {
    // Using user input directly in require_once with allow_url_include enabled
    $library = $_COOKIE['library'];
    // ruleid: php-allow-url-fopen-or-include
    require_once($library); // Could require remote file like http://attacker.com/malicious.php
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_5() {
    // Using user input directly in file_get_contents with allow_url_fopen enabled
    $url = $_GET['url'];
    // ruleid: php-allow-url-fopen-or-include
    $content = file_get_contents($url); // Could read from http://internal-network/sensitive-data
    echo $content;
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_6() {
    // Using user input in file_get_contents after minimal processing
    $url = 'http://' . $_GET['domain'] . '/api/data';
    // ruleid: php-allow-url-fopen-or-include
    $data = file_get_contents($url); // Still vulnerable to SSRF
    return json_decode($data);
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_7() {
    // Using user input in fopen with allow_url_fopen enabled
    $file_path = $_GET['file'];
    // ruleid: php-allow-url-fopen-or-include
    $handle = fopen($file_path, 'r'); // Could open http://internal-service/config
    if ($handle) {
        $content = fread($handle, 8192);
        fclose($handle);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_8() {
    // Using user input in readfile with allow_url_fopen enabled
    $document = $_POST['document'];
    header('Content-Type: application/pdf');
    // ruleid: php-allow-url-fopen-or-include
    readfile($document); // Could read from http://internal-network/sensitive.pdf
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_9() {
    // Using user input in file with allow_url_fopen enabled
    $log_url = $_GET['log_url'];
    // ruleid: php-allow-url-fopen-or-include
    $lines = file($log_url); // Could read from http://internal-service/logs
    foreach ($lines as $line) {
        echo htmlspecialchars($line) . "<br>";
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_10() {
    // Using user input in include with string concatenation
    $theme = $_GET['theme'];
    // ruleid: php-allow-url-fopen-or-include
    include("http://themes.example.com/" . $theme . ".php"); // Still vulnerable to SSRF
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_11() {
    // Using user input from HTTP header in include
    $headers = getallheaders();
    $template = $headers['X-Template'];
    // ruleid: php-allow-url-fopen-or-include
    include($template); // Could include remote file specified in header
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_12() {
    // Using user input in file_get_contents with variable interpolation
    $api = $_GET['api'];
    // ruleid: php-allow-url-fopen-or-include
    $response = file_get_contents("http://$api/endpoint"); // Variable interpolation still allows SSRF
    echo $response;
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_13() {
    // Using user input in include with ternary operator
    $page = isset($_GET['page']) ? $_GET['page'] : 'default';
    // ruleid: php-allow-url-fopen-or-include
    include($page); // Could include remote file if page parameter contains URL
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_14() {
    // Using user input in file_get_contents after JSON decoding
    $request_body = file_get_contents('php://input');
    $json_data = json_decode($request_body, true);
    $resource_url = $json_data['resource_url'];
    // ruleid: php-allow-url-fopen-or-include
    $content = file_get_contents($resource_url); // Could access internal resources
    echo $content;
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=1}

function bad_case_15() {
    // Using user input in require with path traversal and remote URL
    $module = $_GET['module'];
    $path = "modules/$module";
    // ruleid: php-allow-url-fopen-or-include
    require($path); // Could require remote file if module contains URL
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // Using whitelist validation before include
    $template = $_GET['template'];
    $allowed_templates = ['home', 'about', 'contact', 'products'];
    
    // ok: php-allow-url-fopen-or-include
    if (in_array($template, $allowed_templates)) {
        include("templates/{$template}.php");
    } else {
        include("templates/default.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_2() {
    // Using regex pattern matching to ensure only local files are included
    $module = $_POST['module'];
    
    // ok: php-allow-url-fopen-or-include
    if (preg_match('/^[a-zA-Z0-9_\-]+$/', $module)) {
        require("modules/{$module}.php");
    } else {
        require("modules/default.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_3() {
    // Using filter_var to validate URL and custom whitelist for domains
    $url = $_GET['url'];
    $allowed_domains = ['api.example.com', 'cdn.example.com'];
    
    // ok: php-allow-url-fopen-or-include
    if (filter_var($url, FILTER_VALIDATE_URL)) {
        $host = parse_url($url, PHP_URL_HOST);
        if (in_array($host, $allowed_domains)) {
            $content = file_get_contents($url);
            echo $content;
        }
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_4() {
    // Using basename to ensure only filename is used, not full path or URL
    $file = $_GET['file'];
    $safe_file = basename($file);
    
    // ok: php-allow-url-fopen-or-include
    include("templates/{$safe_file}.php");
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_5() {
    // Using hardcoded file paths instead of user input
    $page_id = $_GET['page_id'];
    $page_map = [
        '1' => 'home.php',
        '2' => 'about.php',
        '3' => 'contact.php'
    ];
    
    // ok: php-allow-url-fopen-or-include
    if (isset($page_map[$page_id])) {
        include("pages/" . $page_map[$page_id]);
    } else {
        include("pages/404.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_6() {
    // Using a switch statement with hardcoded cases
    $section = $_GET['section'];
    
    // ok: php-allow-url-fopen-or-include
    switch ($section) {
        case 'news':
            include("sections/news.php");
            break;
        case 'events':
            include("sections/events.php");
            break;
        default:
            include("sections/home.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_7() {
    // Using a custom function to validate file paths
    $component = $_REQUEST['component'];
    
    function is_valid_component($name) {
        return preg_match('/^[a-zA-Z0-9_\-]+$/', $name) && file_exists("components/{$name}.php");
    }
    
    // ok: php-allow-url-fopen-or-include
    if (is_valid_component($component)) {
        include_once("components/{$component}.php");
    } else {
        include_once("components/default.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_8() {
    // Using cURL instead of file_get_contents with proper validation
    $api_endpoint = $_GET['endpoint'];
    $allowed_endpoints = ['users', 'products', 'orders'];
    
    // ok: php-allow-url-fopen-or-include
    if (in_array($api_endpoint, $allowed_endpoints)) {
        $ch = curl_init("https://api.example.com/{$api_endpoint}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        $response = curl_exec($ch);
        curl_close($ch);
        echo $response;
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_9() {
    // Using a mapping array to translate user input to file paths
    $template_name = $_POST['template'];
    $template_map = [
        'blue' => 'blue_theme.php',
        'red' => 'red_theme.php',
        'green' => 'green_theme.php'
    ];
    
    // ok: php-allow-url-fopen-or-include
    if (isset($template_map[$template_name])) {
        include("themes/" . $template_map[$template_name]);
    } else {
        include("themes/default_theme.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_10() {
    // Using intval to ensure numeric input for file selection
    $report_id = intval($_GET['report_id']);
    
    // ok: php-allow-url-fopen-or-include
    if ($report_id > 0 && $report_id < 100) {
        include("reports/report_{$report_id}.php");
    } else {
        include("reports/invalid_report.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_11() {
    // Using a database to map IDs to file paths
    $page_id = $_GET['id'];
    
    // Simulating database query
    $db_pages = [
        '1' => 'home.php',
        '2' => 'about.php',
        '3' => 'contact.php'
    ];
    
    // ok: php-allow-url-fopen-or-include
    if (isset($db_pages[$page_id])) {
        $page_file = "pages/" . $db_pages[$page_id];
        require_once($page_file);
    } else {
        require_once("pages/404.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_12() {
    // Using filter_input with validation
    $module = filter_input(INPUT_GET, 'module', FILTER_SANITIZE_STRING);
    $allowed_modules = ['dashboard', 'profile', 'settings'];
    
    // ok: php-allow-url-fopen-or-include
    if (in_array($module, $allowed_modules)) {
        include_once("modules/{$module}.php");
    } else {
        include_once("modules/default.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_13() {
    // Using stream_context_create with options to restrict URL access
    $url = $_GET['api_url'];
    $allowed_hosts = ['api.example.com', 'api.trusted-partner.com'];
    
    // ok: php-allow-url-fopen-or-include
    $host = parse_url($url, PHP_URL_HOST);
    if (in_array($host, $allowed_hosts)) {
        $opts = [
            'http' => [
                'method' => 'GET',
                'timeout' => 5,
                'follow_location' => 0
            ]
        ];
        $context = stream_context_create($opts);
        $data = file_get_contents($url, false, $context);
        echo $data;
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_14() {
    // Using a custom class to handle file inclusion securely
    $widget = $_GET['widget'];
    
    class WidgetLoader {
        private $allowed_widgets = ['calendar', 'weather', 'news'];
        
        public function load($widget_name) {
            if (in_array($widget_name, $this->allowed_widgets)) {
                include("widgets/{$widget_name}.php");
                return true;
            }
            return false;
        }
    }
    
    $loader = new WidgetLoader();
    // ok: php-allow-url-fopen-or-include
    if (!$loader->load($widget)) {
        include("widgets/default.php");
    }
}
// {/fact}
// {fact rule=insecure-configuration@v1.0 defects=0}

function good_case_15() {
    // Using a hash map for secure file mapping with cryptographic verification
    $file_id = $_GET['file_id'];
    
    $file_map = [
        'a7f5839' => ['path' => 'documents/report1.php', 'hash' => 'PLACEHOLDER_SECRET_32_CHARS'],
        'b8e7291' => ['path' => 'documents/report2.php', 'hash' => 'PLACEHOLDER_SECRET_32_CHARS'],
        'c9d6102' => ['path' => 'documents/report3.php', 'hash' => 'PLACEHOLDER_SECRET_32_CHARS']
    ];
    
    // ok: php-allow-url-fopen-or-include
    if (isset($file_map[$file_id])) {
        $file_info = $file_map[$file_id];
        $file_path = $file_info['path'];
        
        // Verify file integrity before including
        if (md5_file($file_path) === $file_info['hash']) {
            include($file_path);
        } else {
            include('documents/error.php');
        }
    } else {
        include('documents/not_found.php');
    }
}
// {/fact}
?>