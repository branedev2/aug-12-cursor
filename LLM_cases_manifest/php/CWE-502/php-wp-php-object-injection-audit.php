<?php
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
// This file contains test cases for PHP Object Injection vulnerabilities in WordPress
// specifically focusing on unserialize() usage with user input

// True Positive Cases (Vulnerable Code)

function bad_case_1() {
    // Direct unserialize of GET parameter without sanitization
    $user_data = $_GET['user_data'];
    
    // ruleid: php-wp-php-object-injection-audit
    $obj = unserialize($user_data);
    
    echo "Welcome back, " . $obj->username;
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_2() {
    // POST data unserialized without validation
    $serialized_settings = $_POST['settings'];
    
    // ruleid: php-wp-php-object-injection-audit
    $settings = unserialize($serialized_settings);
    
    update_option('site_settings', $settings);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_3() {
    // Cookie data unserialized directly
    $user_preferences = $_COOKIE['user_prefs'];
    
    // ruleid: php-wp-php-object-injection-audit
    $prefs = unserialize($user_preferences);
    
    foreach ($prefs as $key => $value) {
        echo "<p>Preference $key: $value</p>";
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_4() {
    // Request header unserialized
    $headers = getallheaders();
    $custom_data = $headers['X-Custom-Data'];
    
    // ruleid: php-wp-php-object-injection-audit
    $data = unserialize(base64_decode($custom_data));
    
    process_custom_data($data);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_5() {
    // Unserialization in a loop with multiple inputs
    foreach ($_GET as $key => $value) {
        if (strpos($key, 'widget_') === 0) {
            // ruleid: php-wp-php-object-injection-audit
            $widget = unserialize($value);
            register_widget($widget);
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_6() {
    // Unserialization with minimal processing
    $data = $_POST['user_meta'];
    $encoded = str_replace(' ', '+', $data);
    
    // ruleid: php-wp-php-object-injection-audit
    $user_meta = unserialize(base64_decode($encoded));
    
    update_user_meta(get_current_user_id(), 'preferences', $user_meta);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_7() {
    // Unserialization in AJAX handler
    $ajax_data = $_POST['ajax_data'];
    
    // ruleid: php-wp-php-object-injection-audit
    $obj = unserialize($ajax_data);
    
    wp_send_json_success(array(
        'message' => 'Processed: ' . $obj->message
    ));
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_8() {
    // Unserialization with conditional
    if (isset($_REQUEST['import_data']) && !empty($_REQUEST['import_data'])) {
        $import_data = $_REQUEST['import_data'];
        
        // ruleid: php-wp-php-object-injection-audit
        $data = unserialize($import_data);
        
        if ($data && is_object($data)) {
            import_from_object($data);
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_9() {
    // Unserialization from database where data originally came from user
    global $wpdb;
    $user_id = $_GET['user_id'];
    $serialized_data = $wpdb->get_var(
        $wpdb->prepare("SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = 'serialized_prefs'", $user_id)
    );
    
    // ruleid: php-wp-php-object-injection-audit
    $prefs = unserialize($serialized_data);
    
    display_user_preferences($prefs);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_10() {
    // Unserialization with ternary operator
    $data = isset($_POST['config']) ? $_POST['config'] : '';
    
    // ruleid: php-wp-php-object-injection-audit
    $config = !empty($data) ? unserialize($data) : new stdClass();
    
    apply_configuration($config);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_11() {
    // Unserialization with multiple operations
    $raw_data = $_POST['plugin_data'];
    $cleaned = trim(stripslashes($raw_data));
    
    // ruleid: php-wp-php-object-injection-audit
    $plugin_data = unserialize($cleaned);
    
    activate_plugin($plugin_data);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_12() {
    // Unserialization in a switch statement
    $action = $_GET['action'];
    $payload = $_POST['payload'];
    
    switch ($action) {
        case 'import':
            // ruleid: php-wp-php-object-injection-audit
            $data = unserialize($payload);
            import_data($data);
            break;
        case 'export':
            export_data();
            break;
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_13() {
    // Unserialization with error suppression
    $user_data = $_GET['backup'];
    
    // ruleid: php-wp-php-object-injection-audit
    $backup = @unserialize($user_data);
    
    if ($backup !== false) {
        restore_from_backup($backup);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_14() {
    // Unserialization with nested array access
    if (isset($_POST['form_data']['settings'])) {
        $settings_data = $_POST['form_data']['settings'];
        
        // ruleid: php-wp-php-object-injection-audit
        $settings = unserialize($settings_data);
        
        foreach ($settings as $setting) {
            update_option($setting->name, $setting->value);
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}

function bad_case_15() {
    // Unserialization with file upload
    if (isset($_FILES['data_file']) && $_FILES['data_file']['error'] == UPLOAD_ERR_OK) {
        $file_content = file_get_contents($_FILES['data_file']['tmp_name']);
        
        // ruleid: php-wp-php-object-injection-audit
        $imported_data = unserialize($file_content);
        
        process_imported_data($imported_data);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

// True Negative Cases (Safe Code)

function good_case_1() {
    // Using allowed_classes => false to prevent object instantiation
    $user_data = $_GET['user_data'];
    
    // ok: php-wp-php-object-injection-audit
    $data = unserialize($user_data, ['allowed_classes' => false]);
    
    echo "Welcome back, " . htmlspecialchars($data['username']);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_2() {
    // Validating serialized data format before unserializing
    $serialized_settings = $_POST['settings'];
    
    if (!is_string($serialized_settings) || !preg_match('/^a:\d+:{.*}$/', $serialized_settings)) {
        wp_die('Invalid data format');
    }
    
    // ok: php-wp-php-object-injection-audit
    $settings = unserialize($serialized_settings, ['allowed_classes' => false]);
    
    update_option('site_settings', $settings);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_3() {
    // Using json_decode instead of unserialize
    $user_preferences = $_COOKIE['user_prefs'];
    
    // ok: php-wp-php-object-injection-audit
    $prefs = json_decode($user_preferences, true);
    
    if (is_array($prefs)) {
        foreach ($prefs as $key => $value) {
            echo "<p>Preference " . htmlspecialchars($key) . ": " . htmlspecialchars($value) . "</p>";
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_4() {
    // Using safe serialization alternative
    $headers = getallheaders();
    $custom_data = isset($headers['X-Custom-Data']) ? $headers['X-Custom-Data'] : '';
    
    // ok: php-wp-php-object-injection-audit
    $data = maybe_unserialize(wp_unslash($custom_data));
    
    if (is_array($data)) {
        process_custom_data($data);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_5() {
    // Using WordPress built-in sanitization
    foreach ($_GET as $key => $value) {
        if (strpos($key, 'widget_') === 0) {
            // ok: php-wp-php-object-injection-audit
            $widget_data = sanitize_text_field($value);
            $widget = json_decode($widget_data, true);
            if (is_array($widget)) {
                register_widget_data($widget);
            }
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_6() {
    // Using explicit data structure instead of unserialization
    $data = $_POST['user_meta'];
    
    // ok: php-wp-php-object-injection-audit
    $user_meta = array();
    
    if (!empty($data) && is_array($data)) {
        foreach ($data as $key => $value) {
            $user_meta[sanitize_key($key)] = sanitize_text_field($value);
        }
    }
    
    update_user_meta(get_current_user_id(), 'preferences', $user_meta);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_7() {
    // Using JSON for data exchange in AJAX
    $ajax_data = $_POST['ajax_data'];
    
    // ok: php-wp-php-object-injection-audit
    $obj = json_decode(stripslashes($ajax_data), true);
    
    if (is_array($obj) && isset($obj['message'])) {
        wp_send_json_success(array(
            'message' => 'Processed: ' . sanitize_text_field($obj['message'])
        ));
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_8() {
    // Using WordPress serialization functions
    if (isset($_REQUEST['import_data']) && !empty($_REQUEST['import_data'])) {
        $import_data = wp_unslash($_REQUEST['import_data']);
        
        // ok: php-wp-php-object-injection-audit
        $data = maybe_unserialize($import_data);
        
        if (is_array($data)) {
            import_from_array($data);
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_9() {
    // Safe unserialization of known data structure
    global $wpdb;
    $user_id = absint($_GET['user_id']);
    $serialized_data = $wpdb->get_var(
        $wpdb->prepare("SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = 'serialized_prefs'", $user_id)
    );
    
    // ok: php-wp-php-object-injection-audit
    $prefs = is_serialized($serialized_data) ? unserialize($serialized_data) : array();
    
    if (!is_array($prefs)) {
        $prefs = array();
    }
    
    display_user_preferences($prefs);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_10() {
    // Using JSON for configuration
    $data = isset($_POST['config']) ? $_POST['config'] : '';
    
    // ok: php-wp-php-object-injection-audit
    $config = !empty($data) ? json_decode($data, true) : array();
    
    if (is_array($config)) {
        apply_configuration($config);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_11() {
    // Using explicit validation before processing
    $raw_data = $_POST['plugin_data'];
    
    // ok: php-wp-php-object-injection-audit
    $plugin_data = array();
    
    if (!empty($raw_data) && is_string($raw_data)) {
        $decoded = json_decode($raw_data, true);
        if (is_array($decoded) && isset($decoded['name'], $decoded['version'])) {
            $plugin_data = array(
                'name' => sanitize_text_field($decoded['name']),
                'version' => sanitize_text_field($decoded['version'])
            );
        }
    }
    
    activate_plugin_safe($plugin_data);
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_12() {
    // Using safe data handling in a switch statement
    $action = sanitize_key($_GET['action']);
    $payload = $_POST['payload'];
    
    switch ($action) {
        case 'import':
            // ok: php-wp-php-object-injection-audit
            $data = json_decode($payload, true);
            if (is_array($data)) {
                import_data($data);
            }
            break;
        case 'export':
            export_data();
            break;
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_13() {
    // Using WordPress nonce verification and safe data handling
    $user_data = $_GET['backup'];
    
    if (!wp_verify_nonce($_GET['_wpnonce'], 'restore_backup')) {
        wp_die('Security check failed');
    }
    
    // ok: php-wp-php-object-injection-audit
    $backup = json_decode(base64_decode($user_data), true);
    
    if (is_array($backup)) {
        restore_from_backup_safe($backup);
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_14() {
    // Using safe data structure validation
    if (isset($_POST['form_data']['settings'])) {
        $settings_data = $_POST['form_data']['settings'];
        
        // ok: php-wp-php-object-injection-audit
        $settings = array();
        
        if (is_array($settings_data)) {
            foreach ($settings_data as $key => $value) {
                $settings[sanitize_key($key)] = sanitize_text_field($value);
            }
        }
        
        foreach ($settings as $name => $value) {
            update_option($name, $value);
        }
    }
}
// {/fact}
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}

function good_case_15() {
    // Safe file upload handling
    if (isset($_FILES['data_file']) && $_FILES['data_file']['error'] == UPLOAD_ERR_OK) {
        $file_content = file_get_contents($_FILES['data_file']['tmp_name']);
        
        // ok: php-wp-php-object-injection-audit
        $imported_data = json_decode($file_content, true);
        
        if (is_array($imported_data)) {
            foreach ($imported_data as &$item) {
                if (is_array($item)) {
                    array_walk_recursive($item, function(&$value) {
                        $value = sanitize_text_field($value);
                    });
                } else {
                    $item = sanitize_text_field($item);
                }
            }
            process_imported_data_safe($imported_data);
        }
    }
}
// {/fact}

// Helper functions to avoid undefined function errors
function process_custom_data($data) {}
function register_widget($widget) {}
function update_user_meta($user_id, $meta_key, $meta_value) {}
function wp_send_json_success($data) {}
function import_from_object($data) {}
function display_user_preferences($prefs) {}
function apply_configuration($config) {}
function activate_plugin($plugin_data) {}
function import_data($data) {}
function export_data() {}
function restore_from_backup($backup) {}
function update_option($option, $value) {}
function process_imported_data($data) {}
function register_widget_data($widget) {}
function import_from_array($data) {}
function activate_plugin_safe($plugin_data) {}
function restore_from_backup_safe($backup) {}
function process_imported_data_safe($data) {}
function wp_unslash($data) { return $data; }
function maybe_unserialize($data) { return $data; }
function is_serialized($data) { return true; }
function wp_verify_nonce($nonce, $action) { return true; }
function wp_die($message) {}
function sanitize_text_field($text) { return $text; }
function sanitize_key($key) { return $key; }
function absint($number) { return (int)$number; }
function getallheaders() { return []; }
?>