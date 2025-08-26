<?php
/**
 * Test cases for WordPress AJAX hooks vulnerability detection
 * Rule ID: php-wp-ajax-no-auth-and-auth-hooks-audit
 * CWE: CWE-285
 */

/**
 * TRUE POSITIVES (Vulnerable Code)
 */
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 1: Basic AJAX action without any authentication check
function bad_case_1() {
    add_action('wp_ajax_update_user_profile', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $user_id = intval($_POST['user_id']);
        $new_role = sanitize_text_field($_POST['new_role']);
        
        // No capability check before updating user role
        wp_update_user([
            'ID' => $user_id,
            'role' => $new_role
        ]);
        
        wp_send_json_success('User role updated');
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 2: AJAX nopriv action for sensitive operation
function bad_case_2() {
    add_action('wp_ajax_nopriv_delete_post', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $post_id = intval($_POST['post_id']);
        
        // Allowing unauthenticated users to delete posts
        wp_delete_post($post_id, true);
        
        wp_send_json_success('Post deleted');
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 3: Both authenticated and unauthenticated hooks for sensitive data
function bad_case_3() {
    // Hook for logged-in users
    add_action('wp_ajax_get_user_data', 'get_sensitive_user_data');
    
    // Same hook for non-logged-in users
    // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
    add_action('wp_ajax_nopriv_get_user_data', 'get_sensitive_user_data');
    
    function get_sensitive_user_data() {
        $user_id = intval($_REQUEST['user_id']);
        $user_data = get_userdata($user_id);
        wp_send_json($user_data);
    }
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 4: AJAX action with insufficient capability check
function bad_case_4() {
    add_action('wp_ajax_update_options', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        // Only checking if user is logged in, not specific capability
        if (is_user_logged_in()) {
            update_option('site_title', sanitize_text_field($_POST['site_title']));
            wp_send_json_success('Options updated');
        } else {
            wp_send_json_error('Not logged in');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 5: AJAX action with no authentication in a class context
function bad_case_5() {
    class AdminAjaxHandler {
        public function __construct() {
            add_action('wp_ajax_update_settings', array($this, 'handle_settings_update'));
        }
        
        public function handle_settings_update() {
            // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
            $settings = $_POST['settings'];
            update_option('plugin_settings', $settings);
            wp_send_json_success('Settings updated');
        }
    }
    
    new AdminAjaxHandler();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 6: Multiple AJAX hooks with no auth checks
function bad_case_6() {
    function register_ajax_actions() {
        add_action('wp_ajax_create_post', 'create_post_callback');
        add_action('wp_ajax_update_post', 'update_post_callback');
        add_action('wp_ajax_delete_post', 'delete_post_callback');
    }
    
    function create_post_callback() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $title = sanitize_text_field($_POST['title']);
        $content = wp_kses_post($_POST['content']);
        
        wp_insert_post([
            'post_title' => $title,
            'post_content' => $content,
            'post_status' => 'publish'
        ]);
        
        wp_send_json_success('Post created');
    }
    
    register_ajax_actions();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 7: AJAX action for file operations without proper checks
function bad_case_7() {
    add_action('wp_ajax_upload_file', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!empty($_FILES['file'])) {
            $upload_dir = wp_upload_dir();
            $uploaded_file = $_FILES['file'];
            $destination = $upload_dir['path'] . '/' . $uploaded_file['name'];
            
            move_uploaded_file($uploaded_file['tmp_name'], $destination);
            wp_send_json_success('File uploaded');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 8: AJAX action for database operations without proper checks
function bad_case_8() {
    add_action('wp_ajax_run_query', function() {
        global $wpdb;
        
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $table = $_POST['table'];
        $query = "SELECT * FROM $table LIMIT 100";
        
        $results = $wpdb->get_results($query);
        wp_send_json($results);
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 9: AJAX action with anonymous function but no auth check
function bad_case_9() {
    add_action('wp_ajax_export_data', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $data_type = $_REQUEST['type'];
        
        $data = [];
        if ($data_type === 'users') {
            $users = get_users();
            foreach ($users as $user) {
                $data[] = [
                    'id' => $user->ID,
                    'email' => $user->user_email,
                    'role' => $user->roles[0]
                ];
            }
        }
        
        wp_send_json($data);
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 10: AJAX action with both hooks but sensitive operation
function bad_case_10() {
    function register_email_actions() {
        add_action('wp_ajax_send_email', 'send_email_handler');
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        add_action('wp_ajax_nopriv_send_email', 'send_email_handler');
    }
    
    function send_email_handler() {
        $to = sanitize_email($_POST['to']);
        $subject = sanitize_text_field($_POST['subject']);
        $message = wp_kses_post($_POST['message']);
        
        wp_mail($to, $subject, $message);
        wp_send_json_success('Email sent');
    }
    
    register_email_actions();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 11: AJAX action with conditional but incomplete auth
function bad_case_11() {
    add_action('wp_ajax_manage_users', function() {
        $action = $_POST['action_type'];
        
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        if ($action === 'view') {
            // No capability check for viewing users
            $users = get_users();
            wp_send_json($users);
        } elseif ($action === 'delete' && current_user_can('delete_users')) {
            // This part has proper check but the view action doesn't
            wp_delete_user($_POST['user_id']);
            wp_send_json_success('User deleted');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 12: AJAX action in a plugin with no auth check
function bad_case_12() {
    class MyPlugin {
        public function init() {
            add_action('wp_ajax_save_plugin_data', array($this, 'save_data'));
        }
        
        public function save_data() {
            // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
            $data = $_POST['plugin_data'];
            update_option('my_plugin_data', $data);
            wp_send_json_success('Data saved');
        }
    }
    
    $plugin = new MyPlugin();
    $plugin->init();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 13: AJAX action with nopriv for user registration without validation
function bad_case_13() {
    // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
    add_action('wp_ajax_nopriv_register_user', function() {
        $username = sanitize_user($_POST['username']);
        $email = sanitize_email($_POST['email']);
        $password = $_POST['password'];
        
        // No validation or rate limiting for user registration
        $user_id = wp_create_user($username, $password, $email);
        
        if (!is_wp_error($user_id)) {
            wp_send_json_success('User registered');
        } else {
            wp_send_json_error($user_id->get_error_message());
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 14: AJAX action for importing data without proper checks
function bad_case_14() {
    add_action('wp_ajax_import_data', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (isset($_FILES['import_file'])) {
            $file = $_FILES['import_file'];
            $content = file_get_contents($file['tmp_name']);
            $data = json_decode($content, true);
            
            foreach ($data as $item) {
                // Importing data without proper validation or capability check
                wp_insert_post([
                    'post_title' => $item['title'],
                    'post_content' => $item['content'],
                    'post_status' => 'publish'
                ]);
            }
            
            wp_send_json_success('Data imported');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=1}

// Example 15: AJAX action for system operations without proper checks
function bad_case_15() {
    add_action('wp_ajax_system_info', function() {
        // ruleid: php-wp-ajax-no-auth-and-auth-hooks-audit
        $info_type = $_REQUEST['type'];
        
        if ($info_type === 'phpinfo') {
            ob_start();
            phpinfo();
            $info = ob_get_clean();
            wp_send_json(['info' => $info]);
        } elseif ($info_type === 'server') {
            wp_send_json($_SERVER);
        }
    });
}
// {/fact}

/**
 * TRUE NEGATIVES (Secure Code)
 */
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 1: AJAX action with proper capability check
function good_case_1() {
    add_action('wp_ajax_update_user_profile', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('edit_users')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $user_id = intval($_POST['user_id']);
        $new_role = sanitize_text_field($_POST['new_role']);
        
        wp_update_user([
            'ID' => $user_id,
            'role' => $new_role
        ]);
        
        wp_send_json_success('User role updated');
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 2: AJAX nopriv action for non-sensitive operation
function good_case_2() {
    // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
    add_action('wp_ajax_nopriv_get_public_posts', function() {
        $args = [
            'post_type' => 'post',
            'post_status' => 'publish',
            'posts_per_page' => 10
        ];
        
        $posts = get_posts($args);
        $public_posts = [];
        
        foreach ($posts as $post) {
            $public_posts[] = [
                'id' => $post->ID,
                'title' => $post->post_title,
                'excerpt' => $post->post_excerpt
            ];
        }
        
        wp_send_json($public_posts);
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 3: Separate handlers for authenticated and unauthenticated users
function good_case_3() {
    // Hook for logged-in users with proper capability check
    add_action('wp_ajax_get_user_data', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('edit_users')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $user_id = intval($_REQUEST['user_id']);
        $user_data = get_userdata($user_id);
        wp_send_json($user_data);
    });
    
    // Different, limited handler for non-logged-in users
    add_action('wp_ajax_nopriv_get_user_data', function() {
        $user_id = intval($_REQUEST['user_id']);
        
        // Only return public information for non-logged-in users
        $user = get_user_by('id', $user_id);
        if ($user) {
            wp_send_json([
                'display_name' => $user->display_name,
                'user_url' => $user->user_url
            ]);
        } else {
            wp_send_json_error('User not found');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 4: AJAX action with proper capability check
function good_case_4() {
    add_action('wp_ajax_update_options', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('manage_options')) {
            wp_send_json_error('You do not have permission to update options', 403);
            return;
        }
        
        update_option('site_title', sanitize_text_field($_POST['site_title']));
        wp_send_json_success('Options updated');
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 5: AJAX action with proper authentication in a class context
function good_case_5() {
    class AdminAjaxHandler {
        public function __construct() {
            add_action('wp_ajax_update_settings', array($this, 'handle_settings_update'));
        }
        
        public function handle_settings_update() {
            // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
            if (!current_user_can('manage_options')) {
                wp_send_json_error('Permission denied', 403);
                return;
            }
            
            $settings = $_POST['settings'];
            update_option('plugin_settings', $settings);
            wp_send_json_success('Settings updated');
        }
    }
    
    new AdminAjaxHandler();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 6: Multiple AJAX hooks with proper auth checks
function good_case_6() {
    function register_ajax_actions() {
        add_action('wp_ajax_create_post', 'create_post_callback');
        add_action('wp_ajax_update_post', 'update_post_callback');
        add_action('wp_ajax_delete_post', 'delete_post_callback');
    }
    
    function create_post_callback() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('publish_posts')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $title = sanitize_text_field($_POST['title']);
        $content = wp_kses_post($_POST['content']);
        
        wp_insert_post([
            'post_title' => $title,
            'post_content' => $content,
            'post_status' => 'publish'
        ]);
        
        wp_send_json_success('Post created');
    }
    
    register_ajax_actions();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 7: AJAX action for file operations with proper checks
function good_case_7() {
    add_action('wp_ajax_upload_file', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('upload_files')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        if (!empty($_FILES['file'])) {
            // Use WordPress built-in file handling
            $file_id = media_handle_upload('file', 0);
            
            if (is_wp_error($file_id)) {
                wp_send_json_error($file_id->get_error_message());
            } else {
                wp_send_json_success(['file_id' => $file_id]);
            }
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 8: AJAX action for database operations with proper checks
function good_case_8() {
    add_action('wp_ajax_run_query', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        global $wpdb;
        
        // Whitelist allowed tables
        $allowed_tables = ['posts', 'postmeta', 'terms'];
        $table = $_POST['table'];
        
        if (!in_array($table, $allowed_tables)) {
            wp_send_json_error('Invalid table specified');
            return;
        }
        
        $table_name = $wpdb->prefix . $table;
        $results = $wpdb->get_results("SELECT * FROM $table_name LIMIT 100");
        wp_send_json($results);
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 9: AJAX action with anonymous function and proper auth check
function good_case_9() {
    add_action('wp_ajax_export_data', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $data_type = $_REQUEST['type'];
        
        $data = [];
        if ($data_type === 'users' && current_user_can('list_users')) {
            $users = get_users();
            foreach ($users as $user) {
                $data[] = [
                    'id' => $user->ID,
                    'email' => $user->user_email,
                    'role' => $user->roles[0]
                ];
            }
        }
        
        wp_send_json($data);
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 10: Different handlers for authenticated and unauthenticated users
function good_case_10() {
    // Handler for authenticated users
    add_action('wp_ajax_send_email', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('publish_posts')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $to = sanitize_email($_POST['to']);
        $subject = sanitize_text_field($_POST['subject']);
        $message = wp_kses_post($_POST['message']);
        
        wp_mail($to, $subject, $message);
        wp_send_json_success('Email sent');
    });
    
    // Handler for unauthenticated users - limited functionality
    add_action('wp_ajax_nopriv_send_email', function() {
        // Only allow contact form submissions to a fixed address
        $to = get_option('admin_email');
        $subject = 'Contact Form: ' . sanitize_text_field($_POST['subject']);
        $message = wp_kses_post($_POST['message']);
        $from_email = sanitize_email($_POST['email']);
        
        $headers = ['From: ' . $from_email];
        
        // Add rate limiting
        $ip = $_SERVER['REMOTE_ADDR'];
        $transient_key = 'contact_form_' . md5($ip);
        
        if (get_transient($transient_key)) {
            wp_send_json_error('Please wait before sending another message');
            return;
        }
        
        wp_mail($to, $subject, $message, $headers);
        set_transient($transient_key, 1, 300); // 5 minute cooldown
        
        wp_send_json_success('Message sent');
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 11: AJAX action with comprehensive capability checks
function good_case_11() {
    add_action('wp_ajax_manage_users', function() {
        $action = $_POST['action_type'];
        
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if ($action === 'view') {
            if (!current_user_can('list_users')) {
                wp_send_json_error('Permission denied', 403);
                return;
            }
            
            $users = get_users();
            wp_send_json($users);
        } elseif ($action === 'delete') {
            if (!current_user_can('delete_users')) {
                wp_send_json_error('Permission denied', 403);
                return;
            }
            
            wp_delete_user($_POST['user_id']);
            wp_send_json_success('User deleted');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 12: AJAX action in a plugin with proper auth check
function good_case_12() {
    class MyPlugin {
        public function init() {
            add_action('wp_ajax_save_plugin_data', array($this, 'save_data'));
        }
        
        public function save_data() {
            // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
            if (!current_user_can('manage_options')) {
                wp_send_json_error('Permission denied', 403);
                return;
            }
            
            $data = $_POST['plugin_data'];
            update_option('my_plugin_data', $data);
            wp_send_json_success('Data saved');
        }
    }
    
    $plugin = new MyPlugin();
    $plugin->init();
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 13: AJAX action for user registration with proper validation
function good_case_13() {
    add_action('wp_ajax_nopriv_register_user', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        // Check if registration is allowed
        if (!get_option('users_can_register')) {
            wp_send_json_error('Registration is disabled');
            return;
        }
        
        // Add rate limiting
        $ip = $_SERVER['REMOTE_ADDR'];
        $transient_key = 'registration_' . md5($ip);
        
        if (get_transient($transient_key)) {
            wp_send_json_error('Please wait before trying to register again');
            return;
        }
        
        $username = sanitize_user($_POST['username']);
        $email = sanitize_email($_POST['email']);
        $password = $_POST['password'];
        
        // Validate password strength
        if (strlen($password) < 8) {
            wp_send_json_error('Password must be at least 8 characters');
            return;
        }
        
        $user_id = wp_create_user($username, $password, $email);
        
        if (!is_wp_error($user_id)) {
            // Set rate limit
            set_transient($transient_key, 1, 300); // 5 minute cooldown
            wp_send_json_success('User registered');
        } else {
            wp_send_json_error($user_id->get_error_message());
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 14: AJAX action for importing data with proper checks
function good_case_14() {
    add_action('wp_ajax_import_data', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('import')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        if (isset($_FILES['import_file'])) {
            // Validate file type
            $file = $_FILES['import_file'];
            $file_type = wp_check_filetype($file['name']);
            
            if ($file_type['ext'] !== 'json') {
                wp_send_json_error('Only JSON files are allowed');
                return;
            }
            
            $content = file_get_contents($file['tmp_name']);
            $data = json_decode($content, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                wp_send_json_error('Invalid JSON file');
                return;
            }
            
            foreach ($data as $item) {
                // Validate required fields
                if (empty($item['title']) || empty($item['content'])) {
                    continue;
                }
                
                wp_insert_post([
                    'post_title' => sanitize_text_field($item['title']),
                    'post_content' => wp_kses_post($item['content']),
                    'post_status' => 'draft' // Set as draft for review
                ]);
            }
            
            wp_send_json_success('Data imported');
        }
    });
}
// {/fact}
// {fact rule=improper-authentication@v1.0 defects=0}

// Example 15: AJAX action for system operations with proper checks
function good_case_15() {
    add_action('wp_ajax_system_info', function() {
        // ok: php-wp-ajax-no-auth-and-auth-hooks-audit
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied', 403);
            return;
        }
        
        $info_type = $_REQUEST['type'];
        $allowed_types = ['wp_version', 'php_version', 'plugins'];
        
        if (!in_array($info_type, $allowed_types)) {
            wp_send_json_error('Invalid information type requested');
            return;
        }
        
        $info = [];
        
        if ($info_type === 'wp_version') {
            $info['version'] = get_bloginfo('version');
        } elseif ($info_type === 'php_version') {
            $info['version'] = phpversion();
        } elseif ($info_type === 'plugins') {
            $active_plugins = get_option('active_plugins');
            $info['active_plugins'] = $active_plugins;
        }
        
        wp_send_json($info);
    });
}
// {/fact}
?>