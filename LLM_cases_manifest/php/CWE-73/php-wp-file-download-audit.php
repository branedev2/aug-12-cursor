<?php
/**
 * Test cases for php-wp-file-download-audit rule
 * CWE-73: External Control of File Name or Path
 */
// {fact rule=insecure-cookie@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // User input directly used to determine file path
    $file = $_GET['file'];
    
    // ruleid: php-wp-file-download-audit
    $content = file_get_contents($file);
    echo $content;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_2() {
    // User input with minimal transformation
    $file = $_POST['document'] . '.pdf';
    
    // ruleid: php-wp-file-download-audit
    $data = file_get_contents($file);
    wp_send_json(['content' => $data]);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_3() {
    // User input from request headers
    $file = $_SERVER['HTTP_X_REQUESTED_FILE'];
    $path = "uploads/" . $file;
    
    // ruleid: php-wp-file-download-audit
    readfile($path);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_4() {
    // User input from cookie
    $file = $_COOKIE['last_viewed'];
    
    // ruleid: php-wp-file-download-audit
    include($file);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_5() {
    // User input with directory concatenation
    $username = $_GET['username'];
    $file_path = "/var/www/user_files/" . $username . "/profile.txt";
    
    // ruleid: php-wp-file-download-audit
    $content = file_get_contents($file_path);
    echo $content;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_6() {
    // User input with variable interpolation
    $doc_id = $_REQUEST['doc_id'];
    $file = "documents/$doc_id.txt";
    
    // ruleid: php-wp-file-download-audit
    $fp = fopen($file, "r");
    while (!feof($fp)) {
        echo fgets($fp);
    }
    fclose($fp);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_7() {
    // User input with multiple parameters combined
    $year = $_GET['year'];
    $month = $_GET['month'];
    $report = $_GET['report'];
    $file_path = "reports/$year/$month/$report.pdf";
    
    // ruleid: php-wp-file-download-audit
    readfile($file_path);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_8() {
    // User input with array access
    $files = $_POST['files'];
    $index = $_GET['index'];
    $file = $files[$index];
    
    // ruleid: php-wp-file-download-audit
    require_once($file);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_9() {
    // User input with ternary operator
    $file = isset($_GET['file']) ? $_GET['file'] : 'default.txt';
    
    // ruleid: php-wp-file-download-audit
    $content = file_get_contents($file);
    echo $content;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_10() {
    // User input with string replacement
    $file = str_replace(' ', '_', $_POST['filename']);
    
    // ruleid: php-wp-file-download-audit
    include_once($file);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_11() {
    // User input with WordPress specific function
    $attachment_id = $_GET['attachment'];
    $file = get_attached_file($attachment_id);
    
    // ruleid: php-wp-file-download-audit
    $content = file_get_contents($file);
    echo $content;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_12() {
    // User input with JSON handling
    $request_body = file_get_contents('php://input');
    $data = json_decode($request_body, true);
    $file = $data['document'];
    
    // ruleid: php-wp-file-download-audit
    readfile($file);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_13() {
    // User input with URL parameters
    parse_str($_SERVER['QUERY_STRING'], $params);
    $file = $params['download'];
    
    // ruleid: php-wp-file-download-audit
    $content = file_get_contents($file);
    header('Content-Type: application/octet-stream');
    echo $content;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_14() {
    // User input with switch statement
    $type = $_GET['type'];
    switch ($type) {
        case 'pdf':
            $file = 'documents/pdf/' . $_GET['name'];
            break;
        case 'doc':
            $file = 'documents/doc/' . $_GET['name'];
            break;
        default:
            $file = 'documents/other/' . $_GET['name'];
    }
    
    // ruleid: php-wp-file-download-audit
    readfile($file);
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_15() {
    // User input with WordPress nonce (still vulnerable)
    if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'download_file')) {
        $file = $_GET['file'];
        
        // ruleid: php-wp-file-download-audit
        $content = file_get_contents($file);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// True Negative Examples (Safe Code)

function good_case_1() {
    // Whitelist of allowed files
    $allowed_files = ['report1.pdf', 'report2.pdf', 'report3.pdf'];
    $requested_file = $_GET['file'];
    
    if (in_array($requested_file, $allowed_files)) {
        $file = 'safe_directory/' . $requested_file;
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_2() {
    // Using WordPress sanitization functions
    $file = sanitize_file_name($_POST['document']);
    $allowed_path = WP_CONTENT_DIR . '/uploads/safe/';
    $full_path = $allowed_path . $file;
    
    // Verify the path is within allowed directory
    if (strpos(realpath($full_path), realpath($allowed_path)) === 0) {
        // ok: php-wp-file-download-audit
        $data = file_get_contents($full_path);
        wp_send_json(['content' => $data]);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_3() {
    // Using numeric ID to fetch file from database
    $attachment_id = intval($_GET['id']);
    
    // Get file path from WordPress database using the ID
    $file = get_attached_file($attachment_id);
    
    if ($file && file_exists($file) && current_user_can('read_post', $attachment_id)) {
        // ok: php-wp-file-download-audit
        readfile($file);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_4() {
    // Using a hash to identify files instead of direct paths
    $file_hash = preg_replace('/[^a-f0-9]/', '', $_GET['file_hash']);
    
    // Map hash to actual file path using a secure lookup
    $file_map = [
        'a1b2c3d4' => '/var/www/safe_files/document1.pdf',
        'e5f6g7h8' => '/var/www/safe_files/document2.pdf'
    ];
    
    if (isset($file_map[$file_hash])) {
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file_map[$file_hash]);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_5() {
    // Using WordPress capabilities to restrict access
    if (current_user_can('download_files')) {
        // Hardcoded file path, not influenced by user input
        $file = WP_CONTENT_DIR . '/uploads/reports/annual_report.pdf';
        
        // ok: php-wp-file-download-audit
        readfile($file);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_6() {
    // Using database to retrieve file path
    global $wpdb;
    
    $file_id = intval($_GET['file_id']);
    $file_path = $wpdb->get_var($wpdb->prepare(
        "SELECT file_path FROM {$wpdb->prefix}secure_files WHERE id = %d AND user_id = %d",
        $file_id,
        get_current_user_id()
    ));
    
    if ($file_path) {
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file_path);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_7() {
    // Using WordPress media functions
    $attachment_id = intval($_REQUEST['attachment_id']);
    
    if (wp_attachment_is_image($attachment_id) && current_user_can('read_post', $attachment_id)) {
        $file = get_attached_file($attachment_id);
        
        // ok: php-wp-file-download-audit
        readfile($file);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_8() {
    // Using a strict regex pattern to validate input
    $filename = $_GET['file'];
    if (preg_match('/^[a-zA-Z0-9_-]+\.pdf$/', $filename)) {
        $file = WP_CONTENT_DIR . '/secure_downloads/' . $filename;
        
        // Verify file exists within the intended directory
        if (file_exists($file) && dirname(realpath($file)) === realpath(WP_CONTENT_DIR . '/secure_downloads')) {
            // ok: php-wp-file-download-audit
            $content = file_get_contents($file);
            echo $content;
        }
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_9() {
    // Using WordPress nonce and basename to ensure safety
    if (isset($_GET['_wpnonce']) && wp_verify_nonce($_GET['_wpnonce'], 'download_file')) {
        $requested_file = $_GET['file'];
        $filename = basename($requested_file); // Only get filename, not path
        $safe_dir = WP_CONTENT_DIR . '/downloads/';
        $file = $safe_dir . $filename;
        
        // Additional check to ensure file is in the expected directory
        if (file_exists($file) && strpos(realpath($file), realpath($safe_dir)) === 0) {
            // ok: php-wp-file-download-audit
            readfile($file);
        }
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_10() {
    // Using a secure token system
    $token = $_GET['token'];
    
    // Verify token and get associated file path from database
    global $wpdb;
    $file_path = $wpdb->get_var($wpdb->prepare(
        "SELECT file_path FROM {$wpdb->prefix}download_tokens WHERE token = %s AND expires > %d",
        $token,
        time()
    ));
    
    if ($file_path && file_exists($file_path)) {
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file_path);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_11() {
    // Using WordPress transients for temporary file access
    $access_key = sanitize_key($_GET['access']);
    $file_data = get_transient('file_download_' . $access_key);
    
    if ($file_data && isset($file_data['path']) && file_exists($file_data['path'])) {
        // ok: php-wp-file-download-audit
        readfile($file_data['path']);
        // Delete the transient after use
        delete_transient('file_download_' . $access_key);
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_12() {
    // Hardcoded file paths with no user input
    $report_type = 'annual';
    $year = '2023';
    
    $file = WP_CONTENT_DIR . "/reports/{$report_type}_{$year}.pdf";
    
    if (file_exists($file)) {
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_13() {
    // Using WordPress options to store file paths
    $file_key = sanitize_key($_GET['file_key']);
    $allowed_files = get_option('secure_download_files', []);
    
    if (isset($allowed_files[$file_key])) {
        $file = $allowed_files[$file_key];
        
        if (file_exists($file)) {
            // ok: php-wp-file-download-audit
            readfile($file);
        }
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_14() {
    // Using WordPress upload directory functions
    $upload_dir = wp_upload_dir();
    $year = date('Y');
    $month = date('m');
    
    // Fixed filename, not from user input
    $filename = 'monthly_report.pdf';
    $file = $upload_dir['basedir'] . "/{$year}/{$month}/{$filename}";
    
    if (file_exists($file)) {
        // ok: php-wp-file-download-audit
        $content = file_get_contents($file);
        echo $content;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_15() {
    // Using WordPress shortcode parameter with validation
    function secure_download_shortcode($atts) {
        $atts = shortcode_atts(['id' => 0], $atts, 'secure_download');
        $file_id = intval($atts['id']);
        
        if ($file_id > 0) {
            $file = get_post_meta($file_id, '_secure_file_path', true);
            
            if ($file && file_exists($file) && current_user_can('download_file_' . $file_id)) {
                // ok: php-wp-file-download-audit
                $content = file_get_contents($file);
                return $content;
            }
        }
        
        return 'File not found or access denied.';
    }
    
    add_shortcode('secure_download', 'secure_download_shortcode');
    
    // Usage example (not part of the function but shown for clarity)
    // [secure_download id="123"]
    
    return 'Shortcode registered';
}
// {/fact}
?>