<?php

/**
 * True Positive Examples (Vulnerable Code)
 */
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 1: Basic failure to check return value
function bad_case_1() {
    $encrypted_data = $_POST['encrypted_data'];
    $key = "some_encryption_key";
    $iv = base64_decode($_POST['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    echo "Decrypted data: " . $decrypted;
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 2: Using loose comparison (== false) instead of strict comparison
function bad_case_2() {
    $encrypted_data = $_GET['data'];
    $key = getenv('ENCRYPTION_KEY');
    $iv = base64_decode($_GET['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted == false) {
        echo "Decryption failed";
    } else {
        echo "Decrypted data: " . $decrypted;
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 3: Checking for empty value instead of false
function bad_case_3() {
    $encrypted_data = $_COOKIE['encrypted_data'];
    $key = "my_secret_key";
    $iv = base64_decode($_COOKIE['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if (empty($decrypted)) {
        echo "Decryption failed";
    } else {
        echo "Decrypted data: " . $decrypted;
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 4: Using in ternary without proper validation
function bad_case_4() {
    $encrypted_data = $_REQUEST['encrypted'];
    $key = file_get_contents('/path/to/key.txt');
    $iv = base64_decode($_REQUEST['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $result = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv) ? "Success" : "Error";
    echo $result;
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 5: Using in conditional without strict comparison
function bad_case_5() {
    $encrypted_data = $_POST['token'];
    $key = "application_secret_key";
    $iv = base64_decode($_POST['vector']);
    
    // ruleid: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted) {
        $user_data = json_decode($decrypted, true);
        echo "Welcome, " . $user_data['username'];
    } else {
        echo "Invalid token";
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 6: Using in a complex expression without validation
function bad_case_6() {
    $encrypted_data = $_GET['payload'];
    $key = "encryption_key_123";
    $iv = base64_decode($_GET['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $user_id = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv) . "_verified";
    $query = "SELECT * FROM users WHERE user_id = '$user_id'";
    // Execute query...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 7: Using with error suppression
function bad_case_7() {
    $encrypted_data = $_POST['secure_data'];
    $key = "master_key_456";
    $iv = base64_decode($_POST['initialization_vector']);
    
    // ruleid: php-openssl-decrypt-validate
    $decrypted = @openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    process_data($decrypted);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 8: Using in array assignment without validation
function bad_case_8() {
    $encrypted_username = $_GET['username'];
    $encrypted_password = $_GET['password'];
    $key = "system_key_789";
    $iv = base64_decode($_GET['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $credentials = [
        'username' => openssl_decrypt($encrypted_username, 'aes-256-cbc', $key, 0, $iv),
        'password' => openssl_decrypt($encrypted_password, 'aes-256-cbc', $key, 0, $iv)
    ];
    
    authenticate_user($credentials['username'], $credentials['password']);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 9: Using in string interpolation without validation
function bad_case_9() {
    $encrypted_message = $_POST['message'];
    $key = "communication_key";
    $iv = base64_decode($_POST['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    echo "Message received: " . openssl_decrypt($encrypted_message, 'aes-256-cbc', $key, 0, $iv);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 10: Using in a loop without validation
function bad_case_10() {
    $encrypted_items = json_decode($_POST['items'], true);
    $key = "inventory_key";
    $iv = base64_decode($_POST['iv']);
    
    foreach ($encrypted_items as $item) {
        // ruleid: php-openssl-decrypt-validate
        $decrypted_item = openssl_decrypt($item, 'aes-256-cbc', $key, 0, $iv);
        add_to_cart($decrypted_item);
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 11: Using with switch statement without proper validation
function bad_case_11() {
    $encrypted_role = $_GET['role'];
    $key = "role_encryption_key";
    $iv = base64_decode($_GET['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $role = openssl_decrypt($encrypted_role, 'aes-256-cbc', $key, 0, $iv);
    
    switch ($role) {
        case 'admin':
            show_admin_panel();
            break;
        case 'user':
            show_user_dashboard();
            break;
        default:
            show_login_page();
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 12: Using with multiple decryptions without validation
function bad_case_12() {
    $encrypted_header = $_POST['header'];
    $encrypted_body = $_POST['body'];
    $key = "message_key";
    $iv = base64_decode($_POST['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $header = openssl_decrypt($encrypted_header, 'aes-256-cbc', $key, 0, $iv);
    // ruleid: php-openssl-decrypt-validate
    $body = openssl_decrypt($encrypted_body, 'aes-256-cbc', $key, 0, $iv);
    
    display_message($header, $body);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 13: Using with nested function calls without validation
function bad_case_13() {
    $encrypted_data = $_COOKIE['user_data'];
    $key = "cookie_encryption_key";
    $iv = base64_decode($_COOKIE['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    process_user_data(json_decode(openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv), true));
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 14: Using with try-catch but no specific validation
function bad_case_14() {
    $encrypted_data = $_GET['secure_payload'];
    $key = "transaction_key";
    $iv = base64_decode($_GET['iv']);
    
    try {
        // ruleid: php-openssl-decrypt-validate
        $transaction_data = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
        process_transaction($transaction_data);
    } catch (Exception $e) {
        log_error($e->getMessage());
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// Example 15: Using with concatenation without validation
function bad_case_15() {
    $encrypted_first_name = $_POST['first_name'];
    $encrypted_last_name = $_POST['last_name'];
    $key = "name_encryption_key";
    $iv = base64_decode($_POST['iv']);
    
    // ruleid: php-openssl-decrypt-validate
    $full_name = openssl_decrypt($encrypted_first_name, 'aes-256-cbc', $key, 0, $iv) . " " . 
                 openssl_decrypt($encrypted_last_name, 'aes-256-cbc', $key, 0, $iv);
    
    update_user_name($full_name);
}
// {/fact}

/**
 * True Negative Examples (Secure Code)
 */
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 1: Proper validation with strict comparison
function good_case_1() {
    $encrypted_data = $_POST['encrypted_data'];
    $key = "some_encryption_key";
    $iv = base64_decode($_POST['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        echo "Decryption failed";
        return;
    }
    echo "Decrypted data: " . $decrypted;
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 2: Using strict comparison with error handling
function good_case_2() {
    $encrypted_data = $_GET['data'];
    $key = getenv('ENCRYPTION_KEY');
    $iv = base64_decode($_GET['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        error_log("Decryption failed for user input");
        echo "Invalid data provided";
        return;
    }
    process_data($decrypted);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 3: Using strict comparison with ternary operator
function good_case_3() {
    $encrypted_data = $_COOKIE['encrypted_data'];
    $key = "my_secret_key";
    $iv = base64_decode($_COOKIE['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    $result = ($decrypted === false) ? "Decryption failed" : "Decrypted: " . $decrypted;
    echo $result;
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 4: Storing result and validating before use
function good_case_4() {
    $encrypted_data = $_REQUEST['encrypted'];
    $key = file_get_contents('/path/to/key.txt');
    $iv = base64_decode($_REQUEST['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        throw new Exception("Decryption failed");
    }
    return json_decode($decrypted, true);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 5: Validating in a complex condition
function good_case_5() {
    $encrypted_data = $_POST['token'];
    $key = "application_secret_key";
    $iv = base64_decode($_POST['vector']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false || !is_string($decrypted)) {
        echo "Invalid token";
        return;
    }
    
    $user_data = json_decode($decrypted, true);
    echo "Welcome, " . $user_data['username'];
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 6: Using with try-catch and validation
function good_case_6() {
    try {
        $encrypted_data = $_GET['payload'];
        $key = "encryption_key_123";
        $iv = base64_decode($_GET['iv']);
        
        // ok: php-openssl-decrypt-validate
        $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
        if ($decrypted === false) {
            throw new Exception("Decryption failed");
        }
        
        $user_id = $decrypted . "_verified";
        $query = "SELECT * FROM users WHERE user_id = '$user_id'";
        // Execute query...
    } catch (Exception $e) {
        error_log($e->getMessage());
        echo "An error occurred";
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 7: Using with multiple validations
function good_case_7() {
    $encrypted_data = $_POST['secure_data'];
    $key = "master_key_456";
    $iv = base64_decode($_POST['initialization_vector']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        log_error("Decryption failed");
        return null;
    }
    
    if (!validate_data_format($decrypted)) {
        log_error("Invalid data format after decryption");
        return null;
    }
    
    return process_data($decrypted);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 8: Using in array with validation
function good_case_8() {
    $encrypted_username = $_GET['username'];
    $encrypted_password = $_GET['password'];
    $key = "system_key_789";
    $iv = base64_decode($_GET['iv']);
    
    // ok: php-openssl-decrypt-validate
    $username = openssl_decrypt($encrypted_username, 'aes-256-cbc', $key, 0, $iv);
    if ($username === false) {
        echo "Invalid username encryption";
        return;
    }
    
    // ok: php-openssl-decrypt-validate
    $password = openssl_decrypt($encrypted_password, 'aes-256-cbc', $key, 0, $iv);
    if ($password === false) {
        echo "Invalid password encryption";
        return;
    }
    
    $credentials = [
        'username' => $username,
        'password' => $password
    ];
    
    authenticate_user($credentials['username'], $credentials['password']);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 9: Using with loop and validation
function good_case_9() {
    $encrypted_items = json_decode($_POST['items'], true);
    $key = "inventory_key";
    $iv = base64_decode($_POST['iv']);
    
    $cart_items = [];
    foreach ($encrypted_items as $item) {
        // ok: php-openssl-decrypt-validate
        $decrypted_item = openssl_decrypt($item, 'aes-256-cbc', $key, 0, $iv);
        if ($decrypted_item === false) {
            log_error("Failed to decrypt item");
            continue;
        }
        $cart_items[] = $decrypted_item;
    }
    
    if (empty($cart_items)) {
        echo "No valid items found";
        return;
    }
    
    process_cart($cart_items);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 10: Using with switch and validation
function good_case_10() {
    $encrypted_role = $_GET['role'];
    $key = "role_encryption_key";
    $iv = base64_decode($_GET['iv']);
    
    // ok: php-openssl-decrypt-validate
    $role = openssl_decrypt($encrypted_role, 'aes-256-cbc', $key, 0, $iv);
    if ($role === false) {
        show_error("Invalid role data");
        return;
    }
    
    switch ($role) {
        case 'admin':
            show_admin_panel();
            break;
        case 'user':
            show_user_dashboard();
            break;
        default:
            show_login_page();
    }
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 11: Using with nested functions and validation
function good_case_11() {
    $encrypted_data = $_COOKIE['user_data'];
    $key = "cookie_encryption_key";
    $iv = base64_decode($_COOKIE['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        set_error_cookie("Invalid user data");
        redirect_to_login();
        return;
    }
    
    $user_data = json_decode($decrypted, true);
    if ($user_data === null) {
        set_error_cookie("Malformed user data");
        redirect_to_login();
        return;
    }
    
    process_user_data($user_data);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 12: Using with concatenation and validation
function good_case_12() {
    $encrypted_first_name = $_POST['first_name'];
    $encrypted_last_name = $_POST['last_name'];
    $key = "name_encryption_key";
    $iv = base64_decode($_POST['iv']);
    
    // ok: php-openssl-decrypt-validate
    $first_name = openssl_decrypt($encrypted_first_name, 'aes-256-cbc', $key, 0, $iv);
    if ($first_name === false) {
        echo "Invalid first name encryption";
        return;
    }
    
    // ok: php-openssl-decrypt-validate
    $last_name = openssl_decrypt($encrypted_last_name, 'aes-256-cbc', $key, 0, $iv);
    if ($last_name === false) {
        echo "Invalid last name encryption";
        return;
    }
    
    $full_name = $first_name . " " . $last_name;
    update_user_name($full_name);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 13: Using with different cipher method and validation
function good_case_13() {
    $encrypted_data = $_POST['message'];
    $key = hash('sha256', 'secret_passphrase', true);
    $iv = substr(hash('sha256', 'iv_seed', true), 0, 16);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        log_security_event("Decryption failure", $_SERVER['REMOTE_ADDR']);
        echo "Message could not be decrypted";
        return;
    }
    
    process_message($decrypted);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 14: Using with variable function and validation
function good_case_14() {
    $encrypted_action = $_GET['action'];
    $key = "action_key";
    $iv = base64_decode($_GET['iv']);
    
    // ok: php-openssl-decrypt-validate
    $action = openssl_decrypt($encrypted_action, 'aes-256-cbc', $key, 0, $iv);
    if ($action === false) {
        echo "Invalid action specified";
        return;
    }
    
    if (!function_exists($action)) {
        echo "Unknown action";
        return;
    }
    
    // Only call if it's a valid function and decryption succeeded
    $action();
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// Example 15: Using with custom error handling
function good_case_15() {
    $encrypted_data = $_REQUEST['payload'];
    $key = get_encryption_key_from_config();
    $iv = base64_decode($_REQUEST['iv']);
    
    // ok: php-openssl-decrypt-validate
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
    if ($decrypted === false) {
        $error_code = openssl_error_string();
        custom_error_handler("Decryption failed: " . ($error_code ?: "Unknown error"));
        return null;
    }
    
    return parse_decrypted_data($decrypted);
}
// {/fact}

// Helper functions to prevent undefined function errors
function process_data($data) {}
function authenticate_user($username, $password) {}
function add_to_cart($item) {}
function show_admin_panel() {}
function show_user_dashboard() {}
function show_login_page() {}
function display_message($header, $body) {}
function process_user_data($data) {}
function process_transaction($data) {}
function update_user_name($name) {}
function log_error($message) {}
function validate_data_format($data) { return true; }
function process_cart($items) {}
function show_error($message) {}
function set_error_cookie($message) {}
function redirect_to_login() {}
function log_security_event($message, $ip) {}
function process_message($message) {}
function get_encryption_key_from_config() { return "config_key"; }
function custom_error_handler($message) {}
function parse_decrypted_data($data) { return $data; }
?>