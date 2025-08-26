<?php
/**
 * Test cases for php-extract-user-data rule
 * This rule detects unsafe usage of extract() function with user-controlled data
 */
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Direct extraction of GET parameters without safeguards
    $userData = $_GET;
    // ruleid: php-extract-user-data
    extract($userData);
    
    echo "Welcome, $username!";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_2() {
    // Direct extraction of POST parameters
    $formData = $_POST;
    // ruleid: php-extract-user-data
    extract($formData);
    
    $query = "SELECT * FROM users WHERE id = $user_id";
    $result = mysqli_query($conn, $query);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_3() {
    // Extraction from JSON data in request body
    $jsonData = json_decode(file_get_contents('php://input'), true);
    // ruleid: php-extract-user-data
    extract($jsonData);
    
    $config['debug'] = $debug;
    $config['admin'] = $admin;
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_4() {
    // Extraction from cookie data
    $cookieData = $_COOKIE;
    // ruleid: php-extract-user-data
    extract($cookieData);
    
    if ($authenticated) {
        echo "You are logged in as $role";
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_5() {
    // Extraction from request headers
    $headers = getallheaders();
    // ruleid: php-extract-user-data
    extract($headers);
    
    echo "Your browser is: $User_Agent";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_6() {
    // Extraction with minimal processing
    $userData = array_merge($_GET, $_POST);
    // ruleid: php-extract-user-data
    extract($userData);
    
    $template = "templates/$theme/index.php";
    include($template);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_7() {
    // Extraction after JSON decode from a specific parameter
    $jsonString = $_POST['user_data'];
    $userData = json_decode($jsonString, true);
    // ruleid: php-extract-user-data
    extract($userData);
    
    echo "Settings saved for $username with level $access_level";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_8() {
    // Extraction with array filtering but still unsafe
    $inputData = $_GET;
    $filteredData = array_filter($inputData, function($value) {
        return !empty($value);
    });
    // ruleid: php-extract-user-data
    extract($filteredData);
    
    $db->query("UPDATE settings SET value = '$setting_value' WHERE name = '$setting_name'");
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_9() {
    // Extraction from serialized data
    $serializedData = $_POST['serialized_config'];
    $config = unserialize($serializedData);
    // ruleid: php-extract-user-data
    extract($config);
    
    if ($is_admin) {
        echo "Welcome to admin panel";
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_10() {
    // Extraction with prefix but still unsafe
    $userData = $_REQUEST;
    // ruleid: php-extract-user-data
    extract($userData, EXTR_PREFIX_ALL, "user");
    
    echo "Your settings: $user_theme, $user_language";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_11() {
    // Extraction from URL parameters in a custom way
    parse_str($_SERVER['QUERY_STRING'], $params);
    // ruleid: php-extract-user-data
    extract($params);
    
    $file = "data/$category/$item.php";
    include($file);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_12() {
    // Extraction after some transformation
    $userData = array_map('trim', $_POST);
    // ruleid: php-extract-user-data
    extract($userData);
    
    $userPrefs->save($theme, $layout, $fontSize);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_13() {
    // Extraction from session that could be initially set from user input
    session_start();
    $userSettings = $_SESSION['user_settings']; // Could be set from user input earlier
    // ruleid: php-extract-user-data
    extract($userSettings);
    
    echo "Display mode: $mode, Items per page: $items_per_page";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_14() {
    // Extraction with conditional but still unsafe
    $inputData = $_GET;
    if (!empty($inputData)) {
        // ruleid: php-extract-user-data
        extract($inputData);
        
        $template = new Template($theme);
        $template->render($view);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_15() {
    // Extraction with type casting but still unsafe for overwriting
    $id = (int)$_GET['id'];
    $data = [
        'id' => $id,
        'action' => $_GET['action']
    ];
    // ruleid: php-extract-user-data
    extract($data);
    
    if ($action == 'delete') {
        deleteRecord($id);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

// True Negative Examples (Safe Code)

function good_case_1() {
    // Using EXTR_SKIP flag to prevent overwriting
    $userData = $_GET;
    // ok: php-extract-user-data
    extract($userData, EXTR_SKIP);
    
    echo "Welcome, $username!";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_2() {
    // Using EXTR_SKIP flag with POST data
    $formData = $_POST;
    // ok: php-extract-user-data
    extract($formData, EXTR_SKIP);
    
    $query = "SELECT * FROM users WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_3() {
    // Using hardcoded array, not user input
    $config = [
        'debug' => false,
        'admin' => false,
        'theme' => 'default'
    ];
    // ok: php-extract-user-data
    extract($config);
    
    echo "Theme: $theme";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_4() {
    // Using EXTR_PREFIX_ALL with EXTR_SKIP for cookie data
    $cookieData = $_COOKIE;
    // ok: php-extract-user-data
    extract($cookieData, EXTR_PREFIX_ALL | EXTR_SKIP, "cookie");
    
    echo "Cookie settings: $cookie_theme";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_5() {
    // Manual variable assignment instead of extract
    $userData = $_POST;
    // ok: php-extract-user-data
    $username = isset($userData['username']) ? htmlspecialchars($userData['username']) : '';
    $email = isset($userData['email']) ? filter_var($userData['email'], FILTER_SANITIZE_EMAIL) : '';
    
    echo "User: $username, Email: $email";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_6() {
    // Using whitelist for extraction
    $allowedKeys = ['theme', 'language'];
    $userData = array_intersect_key($_GET, array_flip($allowedKeys));
    // ok: php-extract-user-data
    extract($userData, EXTR_SKIP);
    
    echo "Selected theme: " . (isset($theme) ? $theme : 'default');
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_7() {
    // Using extract with non-user data
    $dbResult = $db->query("SELECT username, email, role FROM users WHERE id = 1")->fetch_assoc();
    // ok: php-extract-user-data
    extract($dbResult);
    
    echo "User: $username, Role: $role";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_8() {
    // Using extract with validated data
    $themeOptions = ['light', 'dark', 'blue'];
    $theme = in_array($_GET['theme'], $themeOptions) ? $_GET['theme'] : 'light';
    $validatedData = ['theme' => $theme];
    // ok: php-extract-user-data
    extract($validatedData);
    
    echo "Using theme: $theme";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_9() {
    // Using extract with system configuration
    $config = parse_ini_file('config.ini');
    // ok: php-extract-user-data
    extract($config);
    
    $db = new Database($db_host, $db_user, $db_pass);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_10() {
    // Using extract with constant data
    define('APP_CONFIG', [
        'version' => '1.0',
        'name' => 'MyApp',
        'debug' => false
    ]);
    // ok: php-extract-user-data
    extract(APP_CONFIG);
    
    echo "Running $name version $version";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_11() {
    // Using extract with sanitized data
    $userData = $_POST;
    $sanitized = [];
    foreach ($userData as $key => $value) {
        $sanitized[$key] = htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }
    // ok: php-extract-user-data
    extract($sanitized, EXTR_SKIP);
    
    echo "Profile updated for $name";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_12() {
    // Using extract with type-enforced data
    $id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $typedData = [
        'id' => $id,
        'page' => $page
    ];
    // ok: php-extract-user-data
    extract($typedData);
    
    echo "Viewing item $id on page $page";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_13() {
    // Using extract with default values that can't be overridden
    $defaults = [
        'theme' => 'default',
        'lang' => 'en',
        'items_per_page' => 10
    ];
    $userPrefs = array_merge($defaults, $_GET);
    // ok: php-extract-user-data
    extract($defaults);
    
    // Using the extracted variables with user preferences separately
    $selectedTheme = in_array($userPrefs['theme'], ['default', 'dark', 'light']) ? $userPrefs['theme'] : $theme;
    echo "Using theme: $selectedTheme";
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_14() {
    // Using extract with EXTR_IF_EXISTS to only update existing variables
    $defaultConfig = [
        'debug' => false,
        'cache' => true,
        'timeout' => 30
    ];
    extract($defaultConfig);
    
    $userConfig = $_POST['config'] ?? [];
    // ok: php-extract-user-data
    extract($userConfig, EXTR_IF_EXISTS);
    
    echo "Debug mode: " . ($debug ? 'on' : 'off');
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_15() {
    // Using extract with completely hardcoded data in a loop
    $months = [
        1 => 'January',
        2 => 'February',
        3 => 'March'
    ];
    
    foreach ($months as $num => $name) {
        $monthData = [
            'number' => $num,
            'name' => $name,
            'days' => ($num == 2) ? 28 : 30
        ];
        // ok: php-extract-user-data
        extract($monthData);
        
        echo "Month $number is $name with $days days<br>";
    }
}
// {/fact}
?>