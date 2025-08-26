<?php
// {fact rule=sendfile-injection@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Direct inclusion of user input from GET parameter
    $page = $_GET['page'];
    // ruleid: php-file-inclusion
    include($page);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_2() {
    // Using POST data for file inclusion
    $template = $_POST['template'];
    // ruleid: php-file-inclusion
    require($template);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_3() {
    // Using request headers for file inclusion
    $headers = getallheaders();
    $theme = $headers['X-Theme'];
    // ruleid: php-file-inclusion
    include_once($theme);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_4() {
    // Using cookie data for file inclusion
    $layout = $_COOKIE['layout'];
    // ruleid: php-file-inclusion
    require_once($layout);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_5() {
    // Using concatenation with user input
    $lang = $_GET['lang'];
    $path = "languages/" . $lang . ".php";
    // ruleid: php-file-inclusion
    include($path);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_6() {
    // Using server variables that can be manipulated
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $logFile = "logs/" . $userAgent . ".log";
    // ruleid: php-file-inclusion
    require($logFile);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_7() {
    // Using input after basic transformation
    $module = strtolower($_GET['module']);
    // ruleid: php-file-inclusion
    include_once("modules/$module.php");
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_8() {
    // Using input with variable variables
    $type = $_GET['type'];
    $filename = "template_$type";
    // ruleid: php-file-inclusion
    include($$filename); // Using the value of the variable named by $filename
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_9() {
    // Using input with array access
    $options = $_POST['options'];
    // ruleid: php-file-inclusion
    require($options['theme']);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_10() {
    // Using input after JSON processing
    $config = json_decode($_POST['config'], true);
    // ruleid: php-file-inclusion
    include_once($config['template_path']);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_11() {
    // Using input with ternary operator
    $view = isset($_GET['view']) ? $_GET['view'] : 'default';
    // ruleid: php-file-inclusion
    require_once($view . '.php');
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_12() {
    // Using input with string replacement
    $component = str_replace('../', '', $_GET['component']);
    // Still vulnerable despite basic attempt at sanitization
    // ruleid: php-file-inclusion
    include("components/$component.php");
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_13() {
    // Using input with multiple variables
    $category = $_GET['category'];
    $id = $_GET['id'];
    $path = "content/$category/$id.php";
    // ruleid: php-file-inclusion
    require($path);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_14() {
    // Using input from session data (which originally came from user input)
    session_start();
    $theme = $_SESSION['user_theme']; // Assuming this was set from user input earlier
    // ruleid: php-file-inclusion
    include("themes/$theme/index.php");
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

function bad_case_15() {
    // Using input with switch statement
    $action = $_GET['action'];
    switch($action) {
        case 'view':
            $file = $_GET['file'];
            // ruleid: php-file-inclusion
            include($file);
            break;
        default:
            include('default.php');
            break;
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

function good_case_1() {
    // Using constant string for inclusion
    // ok: php-file-inclusion
    include('header.php');
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_2() {
    // Using constant string with concatenation
    $theme = 'default';
    // ok: php-file-inclusion
    require('themes/' . $theme . '/index.php');
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_3() {
    // Using whitelist validation
    $page = $_GET['page'];
    $allowed_pages = ['home', 'about', 'contact'];
    if (in_array($page, $allowed_pages)) {
        // ok: php-file-inclusion
        include_once($page . '.php');
    } else {
        include_once('home.php');
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_4() {
    // Using realpath to validate path is within allowed directory
    $template = $_GET['template'];
    $allowedDir = realpath('./templates/');
    $requestedFile = realpath($allowedDir . '/' . $template . '.php');
    
    if ($requestedFile && strpos($requestedFile, $allowedDir) === 0 && file_exists($requestedFile)) {
        // ok: php-file-inclusion
        require($requestedFile);
    } else {
        require('./templates/default.php');
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_5() {
    // Using switch statement with hardcoded cases
    $section = $_GET['section'];
    switch($section) {
        case 'products':
            // ok: php-file-inclusion
            include('products.php');
            break;
        case 'services':
            include('services.php');
            break;
        default:
            include('home.php');
            break;
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_6() {
    // Using array mapping for secure inclusion
    $module = $_GET['module'];
    $modules = [
        'users' => 'users.php',
        'products' => 'products.php',
        'orders' => 'orders.php'
    ];
    
    if (isset($modules[$module])) {
        // ok: php-file-inclusion
        require_once($modules[$module]);
    } else {
        require_once('dashboard.php');
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_7() {
    // Using constant defined in configuration
    define('TEMPLATE_PATH', 'templates/default.php');
    // ok: php-file-inclusion
    include(TEMPLATE_PATH);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_8() {
    // Using class constants for inclusion
    class Config {
        const HEADER_TEMPLATE = 'header.php';
        const FOOTER_TEMPLATE = 'footer.php';
    }
    
    // ok: php-file-inclusion
    require_once(Config::HEADER_TEMPLATE);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_9() {
    // Using basename to strip directory traversal attempts
    $file = $_GET['file'];
    $safe_file = basename($file);
    // ok: php-file-inclusion
    include_once("uploads/" . $safe_file);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_10() {
    // Using preg_match for strict validation
    $component = $_GET['component'];
    if (preg_match('/^[a-zA-Z0-9_]+$/', $component)) {
        // ok: php-file-inclusion
        require("components/$component.php");
    } else {
        require("components/default.php");
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_11() {
    // Using filter_input for validation
    $page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_STRING);
    $allowed_pages = ['home', 'about', 'contact'];
    
    if (in_array($page, $allowed_pages)) {
        // ok: php-file-inclusion
        include("pages/$page.php");
    } else {
        include("pages/home.php");
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_12() {
    // Using configuration array
    $config = [
        'templates' => [
            'header' => 'header.php',
            'footer' => 'footer.php',
            'sidebar' => 'sidebar.php'
        ]
    ];
    
    // ok: php-file-inclusion
    include($config['templates']['header']);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_13() {
    // Using function to determine template path
    function get_template_path($name) {
        $templates = [
            'blog' => 'blog.php',
            'shop' => 'shop.php',
            'gallery' => 'gallery.php'
        ];
        
        return isset($templates[$name]) ? $templates[$name] : 'default.php';
    }
    
    $template_name = $_GET['template'];
    $template_path = get_template_path($template_name);
    
    // ok: php-file-inclusion
    require_once($template_path);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_14() {
    // Using environment configuration
    $env = getenv('APP_ENV') ?: 'production';
    $config_files = [
        'development' => 'config.dev.php',
        'testing' => 'config.test.php',
        'production' => 'config.prod.php'
    ];
    
    // ok: php-file-inclusion
    include($config_files[$env]);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

function good_case_15() {
    // Using strict type checking and validation
    $module = $_GET['module'] ?? '';
    if (is_string($module) && ctype_alnum($module) && file_exists("modules/$module.php")) {
        // ok: php-file-inclusion
        require_once("modules/$module.php");
    } else {
        require_once("modules/default.php");
    }
}
// {/fact}
?>