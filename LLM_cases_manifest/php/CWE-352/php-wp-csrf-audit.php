<?php
/**
 * Test cases for WordPress CSRF vulnerability detection
 * Rule ID: php-wp-csrf-audit
 * CWE: CWE-352
 */

// Simulating WordPress environment
if (!function_exists('check_ajax_referer')) {
    function check_ajax_referer($action = -1, $query_arg = false, $die = true) {
        // This is a mock implementation for testing purposes
        if ($die) {
            // In real WordPress, this would verify the nonce and die if invalid
            return true;
        } else {
            // When $die is false, it just returns false without terminating execution
            return false;
        }
    }
}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

// TRUE POSITIVES - Vulnerable code examples

function bad_case_1() {
    // Using false as the third argument can lead to CSRF vulnerability
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('my_action', 'security', false);
    
    // Process form submission without proper CSRF protection
    if (isset($_POST['submit'])) {
        update_user_meta(get_current_user_id(), 'user_preference', $_POST['preference']);
        echo "User preferences updated!";
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_2() {
    // Using 0 as the third argument has the same effect as false
    if (isset($_POST['update_settings'])) {
        // ruleid: php-wp-csrf-audit
        check_ajax_referer('update_site_settings', 'nonce', 0);
        
        // Update site settings without proper CSRF protection
        update_option('site_title', $_POST['title']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_3() {
    // Using a variable that evaluates to false
    $die_on_fail = 0;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // ruleid: php-wp-csrf-audit
        check_ajax_referer('delete_post', 'security_token', $die_on_fail);
        
        // Delete post without proper CSRF protection
        wp_delete_post($_POST['post_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_4() {
    // Using an expression that evaluates to false
    $user_role = 'subscriber';
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('change_role', 'security', ($user_role === 'admin'));
    
    // Change user role without proper CSRF protection
    if (isset($_POST['user_id']) && isset($_POST['new_role'])) {
        wp_update_user([
            'ID' => $_POST['user_id'],
            'role' => $_POST['new_role']
        ]);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_5() {
    // Using a ternary operator that evaluates to false
    $is_admin = false;
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('update_plugin', 'nonce', $is_admin ? true : false);
    
    // Update plugin without proper CSRF protection
    if (isset($_POST['plugin_id'])) {
        activate_plugin($_POST['plugin_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_6() {
    // Using a constant that evaluates to false
    define('VERIFY_NONCE', false);
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('bulk_action', 'security', VERIFY_NONCE);
    
    // Perform bulk action without proper CSRF protection
    if (isset($_POST['action']) && isset($_POST['items'])) {
        foreach ($_POST['items'] as $item) {
            perform_action($_POST['action'], $item);
        }
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_7() {
    // Using a function that returns false
    function should_verify() {
        return false;
    }
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('import_data', 'security', should_verify());
    
    // Import data without proper CSRF protection
    if (isset($_FILES['import_file'])) {
        process_import_file($_FILES['import_file']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_8() {
    // Using a more complex expression that evaluates to false
    $user_level = 1;
    $min_level = 5;
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('export_data', 'nonce', ($user_level >= $min_level));
    
    // Export data without proper CSRF protection
    if (isset($_POST['export_type'])) {
        generate_export_file($_POST['export_type']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_9() {
    // Using a variable assigned to false
    $verify = false;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // ruleid: php-wp-csrf-audit
        check_ajax_referer('update_user', 'security', $verify);
        
        // Update user without proper CSRF protection
        if (isset($_POST['user_id']) && isset($_POST['user_data'])) {
            update_user_data($_POST['user_id'], $_POST['user_data']);
        }
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_10() {
    // Using a conditional assignment that results in false
    $is_ajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
    $verify = $is_ajax ? false : true;
    
    if ($is_ajax) {
        // ruleid: php-wp-csrf-audit
        check_ajax_referer('ajax_action', 'nonce', $verify);
        
        // Process AJAX request without proper CSRF protection
        process_ajax_request($_POST);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_11() {
    // Using an array access that evaluates to false
    $settings = ['verify_nonce' => false];
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('save_comment', 'security', $settings['verify_nonce']);
    
    // Save comment without proper CSRF protection
    if (isset($_POST['comment_text']) && isset($_POST['post_id'])) {
        wp_insert_comment([
            'comment_post_ID' => $_POST['post_id'],
            'comment_content' => $_POST['comment_text']
        ]);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_12() {
    // Using a class property that evaluates to false
    class RequestHandler {
        public $verify_nonce = false;
    }
    
    $handler = new RequestHandler();
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('upload_image', 'nonce', $handler->verify_nonce);
    
    // Upload image without proper CSRF protection
    if (isset($_FILES['image'])) {
        handle_image_upload($_FILES['image']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_13() {
    // Using a bitwise operation that evaluates to 0
    $flag1 = 1;
    $flag2 = 1;
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('update_settings', 'security', $flag1 & ~$flag2);
    
    // Update settings without proper CSRF protection
    if (isset($_POST['settings'])) {
        update_site_settings($_POST['settings']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_14() {
    // Using a comparison that evaluates to false
    $current_user_id = 5;
    $admin_id = 1;
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('delete_user', 'nonce', $current_user_id === $admin_id);
    
    // Delete user without proper CSRF protection
    if (isset($_POST['user_id'])) {
        wp_delete_user($_POST['user_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=1}

function bad_case_15() {
    // Using logical operators that evaluate to false
    $is_admin = false;
    $is_editor = false;
    
    // ruleid: php-wp-csrf-audit
    check_ajax_referer('publish_post', 'security', $is_admin || $is_editor);
    
    // Publish post without proper CSRF protection
    if (isset($_POST['post_id'])) {
        wp_publish_post($_POST['post_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

// TRUE NEGATIVES - Secure code examples

function good_case_1() {
    // Using true as the third argument ensures proper CSRF protection
    // ok: php-wp-csrf-audit
    check_ajax_referer('my_action', 'security', true);
    
    // Process form submission with proper CSRF protection
    if (isset($_POST['submit'])) {
        update_user_meta(get_current_user_id(), 'user_preference', $_POST['preference']);
        echo "User preferences updated!";
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_2() {
    // Using 1 as the third argument has the same effect as true
    if (isset($_POST['update_settings'])) {
        // ok: php-wp-csrf-audit
        check_ajax_referer('update_site_settings', 'nonce', 1);
        
        // Update site settings with proper CSRF protection
        update_option('site_title', $_POST['title']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_3() {
    // Using a variable that evaluates to true
    $die_on_fail = true;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // ok: php-wp-csrf-audit
        check_ajax_referer('delete_post', 'security_token', $die_on_fail);
        
        // Delete post with proper CSRF protection
        wp_delete_post($_POST['post_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_4() {
    // Using the default value (which is true) by omitting the third argument
    // ok: php-wp-csrf-audit
    check_ajax_referer('change_role', 'security');
    
    // Change user role with proper CSRF protection
    if (isset($_POST['user_id']) && isset($_POST['new_role'])) {
        wp_update_user([
            'ID' => $_POST['user_id'],
            'role' => $_POST['new_role']
        ]);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_5() {
    // Using an expression that evaluates to true
    $user_role = 'admin';
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('update_plugin', 'nonce', ($user_role === 'admin'));
    
    // Update plugin with proper CSRF protection
    if (isset($_POST['plugin_id'])) {
        activate_plugin($_POST['plugin_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_6() {
    // Using a constant that evaluates to true
    define('VERIFY_NONCE', true);
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('bulk_action', 'security', VERIFY_NONCE);
    
    // Perform bulk action with proper CSRF protection
    if (isset($_POST['action']) && isset($_POST['items'])) {
        foreach ($_POST['items'] as $item) {
            perform_action($_POST['action'], $item);
        }
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_7() {
    // Using a function that returns true
    function should_verify() {
        return true;
    }
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('import_data', 'security', should_verify());
    
    // Import data with proper CSRF protection
    if (isset($_FILES['import_file'])) {
        process_import_file($_FILES['import_file']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_8() {
    // Using a more complex expression that evaluates to true
    $user_level = 10;
    $min_level = 5;
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('export_data', 'nonce', ($user_level >= $min_level));
    
    // Export data with proper CSRF protection
    if (isset($_POST['export_type'])) {
        generate_export_file($_POST['export_type']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_9() {
    // Using a variable assigned to true
    $verify = true;
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // ok: php-wp-csrf-audit
        check_ajax_referer('update_user', 'security', $verify);
        
        // Update user with proper CSRF protection
        if (isset($_POST['user_id']) && isset($_POST['user_data'])) {
            update_user_data($_POST['user_id'], $_POST['user_data']);
        }
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_10() {
    // Using a conditional assignment that results in true
    $is_ajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest';
    $verify = $is_ajax ? true : false;
    
    if ($is_ajax) {
        // ok: php-wp-csrf-audit
        check_ajax_referer('ajax_action', 'nonce', $verify);
        
        // Process AJAX request with proper CSRF protection
        process_ajax_request($_POST);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_11() {
    // Using an array access that evaluates to true
    $settings = ['verify_nonce' => true];
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('save_comment', 'security', $settings['verify_nonce']);
    
    // Save comment with proper CSRF protection
    if (isset($_POST['comment_text']) && isset($_POST['post_id'])) {
        wp_insert_comment([
            'comment_post_ID' => $_POST['post_id'],
            'comment_content' => $_POST['comment_text']
        ]);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_12() {
    // Using a class property that evaluates to true
    class RequestHandler {
        public $verify_nonce = true;
    }
    
    $handler = new RequestHandler();
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('upload_image', 'nonce', $handler->verify_nonce);
    
    // Upload image with proper CSRF protection
    if (isset($_FILES['image'])) {
        handle_image_upload($_FILES['image']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_13() {
    // Using a bitwise operation that evaluates to non-zero (true)
    $flag1 = 1;
    $flag2 = 2;
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('update_settings', 'security', $flag1 | $flag2);
    
    // Update settings with proper CSRF protection
    if (isset($_POST['settings'])) {
        update_site_settings($_POST['settings']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_14() {
    // Using a comparison that evaluates to true
    $current_user_id = 1;
    $admin_id = 1;
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('delete_user', 'nonce', $current_user_id === $admin_id);
    
    // Delete user with proper CSRF protection
    if (isset($_POST['user_id'])) {
        wp_delete_user($_POST['user_id']);
    }
}
// {/fact}
// {fact rule=coral-csrf-rule@v1.0 defects=0}

function good_case_15() {
    // Using logical operators that evaluate to true
    $is_admin = true;
    $is_editor = false;
    
    // ok: php-wp-csrf-audit
    check_ajax_referer('publish_post', 'security', $is_admin || $is_editor);
    
    // Publish post with proper CSRF protection
    if (isset($_POST['post_id'])) {
        wp_publish_post($_POST['post_id']);
    }
}
// {/fact}
?>