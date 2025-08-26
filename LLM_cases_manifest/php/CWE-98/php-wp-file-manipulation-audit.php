<?php
/**
 * Test cases for php-wp-file-manipulation-audit rule
 * 
 * This file contains examples of vulnerable and secure code patterns
 * related to file manipulation in WordPress.
 */

/**
 * True Positive Cases (Vulnerable Code)
 */
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 1: Unvalidated file inclusion from GET parameter
function bad_case_1() {
    // Direct inclusion of file from user input without validation
    $template = $_GET['template'];
    // ruleid: php-wp-file-manipulation-audit
    include($template);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 2: Unvalidated file deletion from POST parameter
function bad_case_2() {
    // Direct file deletion from user input without validation
    $file_to_delete = $_POST['file'];
    // ruleid: php-wp-file-manipulation-audit
    unlink($file_to_delete);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 3: Unvalidated file_get_contents from REQUEST parameter
function bad_case_3() {
    // Reading file content from user input without validation
    $file_path = $_REQUEST['file_path'];
    // ruleid: php-wp-file-manipulation-audit
    $content = file_get_contents($file_path);
    echo $content;
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 4: Unvalidated file_put_contents from COOKIE data
function bad_case_4() {
    // Writing to file from cookie data without validation
    $file_path = $_COOKIE['save_path'];
    $content = "Some content to save";
    // ruleid: php-wp-file-manipulation-audit
    file_put_contents($file_path, $content);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 5: Unvalidated require_once from GET parameter
function bad_case_5() {
    // Including file from user input without validation
    $plugin = $_GET['plugin'];
    // ruleid: php-wp-file-manipulation-audit
    require_once($plugin);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 6: Unvalidated fopen from POST parameter
function bad_case_6() {
    // Opening file from user input without validation
    $log_file = $_POST['log_file'];
    // ruleid: php-wp-file-manipulation-audit
    $handle = fopen($log_file, 'w');
    fwrite($handle, "Log entry");
    fclose($handle);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 7: Unvalidated readfile from GET parameter
function bad_case_7() {
    // Reading file from user input without validation
    $download = $_GET['download'];
    // ruleid: php-wp-file-manipulation-audit
    readfile($download);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 8: Unvalidated file operation with rename from POST
function bad_case_8() {
    // Renaming file from user input without validation
    $old_name = $_POST['old_name'];
    $new_name = $_POST['new_name'];
    // ruleid: php-wp-file-manipulation-audit
    rename($old_name, $new_name);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 9: Unvalidated copy operation from REQUEST
function bad_case_9() {
    // Copying file from user input without validation
    $source = $_REQUEST['source'];
    $destination = $_REQUEST['destination'];
    // ruleid: php-wp-file-manipulation-audit
    copy($source, $destination);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 10: Unvalidated file_exists check from GET parameter
function bad_case_10() {
    // Checking file existence from user input without validation
    $check_file = $_GET['check_file'];
    // ruleid: php-wp-file-manipulation-audit
    if (file_exists($check_file)) {
        echo "File exists!";
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 11: Unvalidated is_readable check from POST parameter
function bad_case_11() {
    // Checking if file is readable from user input without validation
    $file_to_read = $_POST['file_to_read'];
    // ruleid: php-wp-file-manipulation-audit
    if (is_readable($file_to_read)) {
        echo "File is readable!";
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 12: Unvalidated glob pattern from GET parameter
function bad_case_12() {
    // Using glob with user input without validation
    $pattern = $_GET['pattern'];
    // ruleid: php-wp-file-manipulation-audit
    $files = glob($pattern);
    foreach ($files as $file) {
        echo $file . "<br>";
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 13: Unvalidated rmdir from POST parameter
function bad_case_13() {
    // Removing directory from user input without validation
    $dir_to_remove = $_POST['dir'];
    // ruleid: php-wp-file-manipulation-audit
    rmdir($dir_to_remove);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 14: Unvalidated mkdir from REQUEST parameter
function bad_case_14() {
    // Creating directory from user input without validation
    $new_dir = $_REQUEST['new_dir'];
    // ruleid: php-wp-file-manipulation-audit
    mkdir($new_dir, 0755);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=1}

// Case 15: Unvalidated file inclusion with require from HTTP header
function bad_case_15() {
    // Including file from HTTP header without validation
    $headers = getallheaders();
    $template = $headers['X-Template-Path'];
    // ruleid: php-wp-file-manipulation-audit
    require($template);
}
// {/fact}

/**
 * True Negative Cases (Secure Code)
 */
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 1: Validated file inclusion with sanitization
function good_case_1() {
    $template = $_GET['template'];
    // Sanitize and validate the input
    $template = sanitize_file_name($template);
    $allowed_templates = ['template1.php', 'template2.php', 'template3.php'];
    
    // ok: php-wp-file-manipulation-audit
    if (in_array($template, $allowed_templates)) {
        include(TEMPLATEPATH . '/' . $template);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 2: Validated file deletion with path traversal prevention
function good_case_2() {
    $file_to_delete = $_POST['file'];
    // Sanitize and validate the input
    $file_to_delete = sanitize_file_name($file_to_delete);
    $upload_dir = wp_upload_dir();
    $safe_path = path_join($upload_dir['basedir'], $file_to_delete);
    
    // Prevent path traversal
    if (strpos(realpath($safe_path), realpath($upload_dir['basedir'])) === 0) {
        // ok: php-wp-file-manipulation-audit
        unlink($safe_path);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 3: Validated file_get_contents with whitelisting
function good_case_3() {
    $file_path = $_REQUEST['file_path'];
    // Sanitize and validate the input
    $file_path = sanitize_file_name($file_path);
    $allowed_files = ['config.txt', 'info.txt', 'data.txt'];
    
    // ok: php-wp-file-manipulation-audit
    if (in_array($file_path, $allowed_files)) {
        $content = file_get_contents(ABSPATH . 'wp-content/uploads/' . $file_path);
        echo $content;
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 4: Validated file_put_contents with path validation
function good_case_4() {
    $file_path = $_COOKIE['save_path'];
    // Sanitize and validate the input
    $file_path = sanitize_file_name($file_path);
    $upload_dir = wp_upload_dir();
    $safe_path = path_join($upload_dir['basedir'], $file_path);
    
    // Ensure the path is within the uploads directory
    if (strpos(realpath($safe_path), realpath($upload_dir['basedir'])) === 0) {
        $content = "Some content to save";
        // ok: php-wp-file-manipulation-audit
        file_put_contents($safe_path, $content);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 5: Validated require_once with extension check
function good_case_5() {
    $plugin = $_GET['plugin'];
    // Sanitize and validate the input
    $plugin = sanitize_file_name($plugin);
    
    // Ensure it's a PHP file in the plugins directory
    if (preg_match('/^[a-zA-Z0-9_-]+\.php$/', $plugin)) {
        $plugin_path = WP_PLUGIN_DIR . '/' . $plugin;
        
        // ok: php-wp-file-manipulation-audit
        if (file_exists($plugin_path)) {
            require_once($plugin_path);
        }
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 6: Validated fopen with path restriction
function good_case_6() {
    $log_file = $_POST['log_file'];
    // Sanitize and validate the input
    $log_file = sanitize_file_name($log_file);
    $log_dir = WP_CONTENT_DIR . '/logs/';
    $safe_path = $log_dir . $log_file;
    
    // Ensure the path is within the logs directory
    if (strpos(realpath($safe_path), realpath($log_dir)) === 0) {
        // ok: php-wp-file-manipulation-audit
        $handle = fopen($safe_path, 'w');
        fwrite($handle, "Log entry");
        fclose($handle);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 7: Validated readfile with file type check
function good_case_7() {
    $download = $_GET['download'];
    // Sanitize and validate the input
    $download = sanitize_file_name($download);
    $upload_dir = wp_upload_dir();
    $safe_path = path_join($upload_dir['basedir'], $download);
    
    // Check if it's an allowed file type
    $allowed_extensions = ['pdf', 'txt', 'doc', 'docx'];
    $file_extension = pathinfo($safe_path, PATHINFO_EXTENSION);
    
    if (in_array($file_extension, $allowed_extensions) && 
        strpos(realpath($safe_path), realpath($upload_dir['basedir'])) === 0) {
        // ok: php-wp-file-manipulation-audit
        readfile($safe_path);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 8: Validated rename with directory restriction
function good_case_8() {
    $old_name = $_POST['old_name'];
    $new_name = $_POST['new_name'];
    
    // Sanitize and validate the input
    $old_name = sanitize_file_name($old_name);
    $new_name = sanitize_file_name($new_name);
    
    $upload_dir = wp_upload_dir();
    $safe_old_path = path_join($upload_dir['basedir'], $old_name);
    $safe_new_path = path_join($upload_dir['basedir'], $new_name);
    
    // Ensure both paths are within the uploads directory
    if (strpos(realpath($safe_old_path), realpath($upload_dir['basedir'])) === 0 &&
        strpos($safe_new_path, $upload_dir['basedir']) === 0) {
        // ok: php-wp-file-manipulation-audit
        rename($safe_old_path, $safe_new_path);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 9: Validated copy with extension whitelist
function good_case_9() {
    $source = $_REQUEST['source'];
    $destination = $_REQUEST['destination'];
    
    // Sanitize and validate the input
    $source = sanitize_file_name($source);
    $destination = sanitize_file_name($destination);
    
    $upload_dir = wp_upload_dir();
    $safe_source = path_join($upload_dir['basedir'], $source);
    $safe_destination = path_join($upload_dir['basedir'], $destination);
    
    // Check file extension
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
    $file_extension = pathinfo($safe_source, PATHINFO_EXTENSION);
    
    if (in_array($file_extension, $allowed_extensions) && 
        strpos(realpath($safe_source), realpath($upload_dir['basedir'])) === 0 &&
        strpos($safe_destination, $upload_dir['basedir']) === 0) {
        // ok: php-wp-file-manipulation-audit
        copy($safe_source, $safe_destination);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 10: Validated file_exists with path normalization
function good_case_10() {
    $check_file = $_GET['check_file'];
    // Sanitize and validate the input
    $check_file = sanitize_file_name($check_file);
    $theme_dir = get_template_directory();
    $safe_path = path_join($theme_dir, $check_file);
    
    // Normalize paths and check if within theme directory
    $real_safe_path = realpath($safe_path);
    $real_theme_dir = realpath($theme_dir);
    
    if ($real_safe_path && strpos($real_safe_path, $real_theme_dir) === 0) {
        // ok: php-wp-file-manipulation-audit
        if (file_exists($real_safe_path)) {
            echo "File exists!";
        }
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 11: Validated is_readable with database lookup
function good_case_11() {
    $file_id = intval($_POST['file_id']);
    
    // Get file path from database using the ID
    global $wpdb;
    $file_path = $wpdb->get_var($wpdb->prepare(
        "SELECT file_path FROM {$wpdb->prefix}files WHERE id = %d",
        $file_id
    ));
    
    if ($file_path) {
        // ok: php-wp-file-manipulation-audit
        if (is_readable($file_path)) {
            echo "File is readable!";
        }
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 12: Validated glob with fixed directory and pattern
function good_case_12() {
    $file_type = $_GET['file_type'];
    // Sanitize and validate the input
    $allowed_types = ['php', 'js', 'css', 'txt'];
    
    if (in_array($file_type, $allowed_types)) {
        $upload_dir = wp_upload_dir();
        // ok: php-wp-file-manipulation-audit
        $files = glob($upload_dir['basedir'] . '/*.' . $file_type);
        foreach ($files as $file) {
            echo basename($file) . "<br>";
        }
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 13: Validated rmdir with ownership check
function good_case_13() {
    $user_id = get_current_user_id();
    $dir_name = sanitize_file_name($_POST['dir']);
    
    // Get user's directory from database
    global $wpdb;
    $user_dir = $wpdb->get_var($wpdb->prepare(
        "SELECT directory_path FROM {$wpdb->prefix}user_directories WHERE user_id = %d AND dir_name = %s",
        $user_id,
        $dir_name
    ));
    
    if ($user_dir && is_dir($user_dir)) {
        // ok: php-wp-file-manipulation-audit
        rmdir($user_dir);
    }
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 14: Validated mkdir with fixed parent directory
function good_case_14() {
    $new_dir = sanitize_file_name($_REQUEST['new_dir']);
    // Prevent directory traversal
    $new_dir = basename($new_dir);
    
    $user_id = get_current_user_id();
    $user_base_dir = WP_CONTENT_DIR . '/user_files/' . $user_id;
    
    // Create user base directory if it doesn't exist
    if (!is_dir($user_base_dir)) {
        mkdir($user_base_dir, 0755, true);
    }
    
    $full_path = $user_base_dir . '/' . $new_dir;
    
    // ok: php-wp-file-manipulation-audit
    mkdir($full_path, 0755);
}
// {/fact}
// {fact rule=sendfile-injection@v1.0 defects=0}

// Case 15: Validated file inclusion with nonce check
function good_case_15() {
    // Verify nonce for security
    if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'include-template')) {
        $template = sanitize_file_name($_GET['template']);
        $theme_dir = get_template_directory();
        $template_path = $theme_dir . '/templates/' . $template;
        
        // Check if the file exists and is within the templates directory
        if (file_exists($template_path) && 
            strpos(realpath($template_path), realpath($theme_dir . '/templates/')) === 0) {
            // ok: php-wp-file-manipulation-audit
            include($template_path);
        }
    }
}
// {/fact}
?>