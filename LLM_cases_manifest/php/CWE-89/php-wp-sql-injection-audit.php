<?php
// WordPress SQL Injection Examples

// Simulating WordPress environment
global $wpdb;
class WPDB {
    public function prepare($query, ...$args) {
        // This simulates the prepare function
        return vsprintf(str_replace('%s', "'%s'", $query), $args);
    }
    
    public function query($sql) {
        // This simulates executing the query
        return $sql;
    }
    
    public function get_results($sql) {
        // This simulates getting results
        return $sql;
    }
    
    public function get_var($sql) {
        // This simulates getting a single variable
        return $sql;
    }
    
    public function get_row($sql) {
        // This simulates getting a row
        return $sql;
    }
}
$wpdb = new WPDB();

// WordPress sanitization functions
function sanitize_text_field($input) {
    return htmlspecialchars(trim($input));
}

function esc_sql($input) {
    return addslashes($input);
}

function absint($input) {
    return abs(intval($input));
}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// ========== VULNERABLE EXAMPLES ==========

function bad_case_1() {
    // Direct use of $_GET in SQL query without sanitization
    $user_id = $_GET['user_id'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->query("SELECT * FROM wp_users WHERE ID = $user_id");
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // Using $_POST in SQL query with string concatenation
    $username = $_POST['username'];
    $sql = "SELECT * FROM wp_users WHERE user_login = '" . $username . "'";
    
    // ruleid: php-wp-sql-injection-audit
    $user = $wpdb->get_row($sql);
    
    return $user;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // Using $_REQUEST in LIKE clause without proper escaping
    $search_term = $_REQUEST['search'];
    $query = "SELECT * FROM wp_posts WHERE post_title LIKE '%" . $search_term . "%'";
    
    // ruleid: php-wp-sql-injection-audit
    $posts = $wpdb->get_results($query);
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // Using HTTP_REFERER in SQL query
    $referer = $_SERVER['HTTP_REFERER'];
    $sql = "INSERT INTO wp_logs (referer_url) VALUES ('" . $referer . "')";
    
    // ruleid: php-wp-sql-injection-audit
    $wpdb->query($sql);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // Using $_COOKIE in SQL query
    $user_preference = $_COOKIE['user_pref'];
    $sql = "UPDATE wp_user_meta SET preference = '" . $user_preference . "' WHERE user_id = 1";
    
    // ruleid: php-wp-sql-injection-audit
    $wpdb->query($sql);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // Incorrect use of $wpdb->prepare with unescaped variables
    $status = $_GET['status'];
    $type = $_GET['type'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM wp_posts WHERE post_status = '%s' AND post_type = $type", $status)
    );
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // Using multiple user inputs in ORDER BY clause
    $sort_field = $_GET['sort'];
    $sort_dir = $_GET['direction'];
    
    // ruleid: php-wp-sql-injection-audit
    $users = $wpdb->get_results("SELECT * FROM wp_users ORDER BY $sort_field $sort_dir");
    
    return $users;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // Using user input in LIMIT clause
    $limit = $_GET['limit'];
    
    // ruleid: php-wp-sql-injection-audit
    $posts = $wpdb->get_results("SELECT * FROM wp_posts LIMIT $limit");
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // Using user input in IN clause
    $categories = $_POST['categories'];
    
    // ruleid: php-wp-sql-injection-audit
    $posts = $wpdb->get_results("SELECT * FROM wp_posts WHERE post_category IN ($categories)");
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // Partial sanitization but still vulnerable
    $user_id = intval($_GET['user_id']);
    $meta_key = $_GET['meta_key']; // This is not sanitized
    
    // ruleid: php-wp-sql-injection-audit
    $meta_value = $wpdb->get_var("SELECT meta_value FROM wp_usermeta WHERE user_id = $user_id AND meta_key = '$meta_key'");
    
    return $meta_value;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // Using HTTP headers in SQL query
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $sql = "INSERT INTO wp_visitor_logs (user_agent) VALUES ('" . $user_agent . "')";
    
    // ruleid: php-wp-sql-injection-audit
    $wpdb->query($sql);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // Using user input in JOIN condition
    $table_suffix = $_GET['table'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->get_results("SELECT * FROM wp_posts p JOIN wp_postmeta_$table_suffix pm ON p.ID = pm.post_id");
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // Using user input in GROUP BY clause
    $group_field = $_POST['group_by'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->get_results("SELECT COUNT(*) as count, $group_field FROM wp_posts GROUP BY $group_field");
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // Using user input in HAVING clause
    $min_count = $_GET['min_count'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->get_results("SELECT post_author, COUNT(*) as post_count FROM wp_posts GROUP BY post_author HAVING post_count > $min_count");
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // Using user input in subquery
    $status = $_REQUEST['status'];
    
    // ruleid: php-wp-sql-injection-audit
    $results = $wpdb->get_results("SELECT * FROM wp_posts WHERE ID IN (SELECT post_id FROM wp_postmeta WHERE meta_value = '$status')");
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// ========== SECURE EXAMPLES ==========

function good_case_1() {
    // Using $wpdb->prepare correctly with placeholders
    $user_id = $_GET['user_id'];
    
    // ok: php-wp-sql-injection-audit
    $results = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_users WHERE ID = %d", $user_id));
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using $wpdb->prepare with multiple parameters
    $username = $_POST['username'];
    $email = $_POST['email'];
    
    // ok: php-wp-sql-injection-audit
    $user = $wpdb->get_row($wpdb->prepare("SELECT * FROM wp_users WHERE user_login = %s AND user_email = %s", $username, $email));
    
    return $user;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using $wpdb->prepare with LIKE clause
    $search_term = $_REQUEST['search'];
    
    // ok: php-wp-sql-injection-audit
    $posts = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE post_title LIKE %s", '%' . $wpdb->esc_like($search_term) . '%'));
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Properly sanitizing HTTP_REFERER
    $referer = $_SERVER['HTTP_REFERER'];
    
    // ok: php-wp-sql-injection-audit
    $wpdb->query($wpdb->prepare("INSERT INTO wp_logs (referer_url) VALUES (%s)", $referer));
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Properly sanitizing cookie data
    $user_preference = $_COOKIE['user_pref'];
    
    // ok: php-wp-sql-injection-audit
    $wpdb->query($wpdb->prepare("UPDATE wp_user_meta SET preference = %s WHERE user_id = %d", $user_preference, 1));
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using absint for numeric values
    $user_id = absint($_GET['user_id']);
    
    // ok: php-wp-sql-injection-audit
    $meta = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_usermeta WHERE user_id = %d", $user_id));
    
    return $meta;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Sanitizing sort parameters with a whitelist
    $sort_field = $_GET['sort'];
    $allowed_fields = ['display_name', 'user_registered', 'ID'];
    
    if (!in_array($sort_field, $allowed_fields)) {
        $sort_field = 'ID'; // Default safe value
    }
    
    $sort_dir = $_GET['direction'] === 'DESC' ? 'DESC' : 'ASC';
    
    // ok: php-wp-sql-injection-audit
    $users = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_users ORDER BY %s %s", $sort_field, $sort_dir));
    
    return $users;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Sanitizing LIMIT parameter
    $limit = absint($_GET['limit']);
    
    if ($limit <= 0) {
        $limit = 10; // Default safe value
    }
    
    // ok: php-wp-sql-injection-audit
    $posts = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts LIMIT %d", $limit));
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Sanitizing IN clause parameters
    $category_ids = $_POST['categories'];
    $sanitized_ids = array_map('absint', explode(',', $category_ids));
    $placeholders = implode(',', array_fill(0, count($sanitized_ids), '%d'));
    
    // ok: php-wp-sql-injection-audit
    $posts = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE post_category IN ($placeholders)", ...$sanitized_ids));
    
    return $posts;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Sanitizing all inputs
    $user_id = absint($_GET['user_id']);
    $meta_key = sanitize_text_field($_GET['meta_key']);
    
    // ok: php-wp-sql-injection-audit
    $meta_value = $wpdb->get_var($wpdb->prepare("SELECT meta_value FROM wp_usermeta WHERE user_id = %d AND meta_key = %s", $user_id, $meta_key));
    
    return $meta_value;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Sanitizing HTTP headers
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    // ok: php-wp-sql-injection-audit
    $wpdb->query($wpdb->prepare("INSERT INTO wp_visitor_logs (user_agent) VALUES (%s)", $user_agent));
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Sanitizing table name with whitelist
    $table_suffix = $_GET['table'];
    $allowed_suffixes = ['us', 'eu', 'asia'];
    
    if (!in_array($table_suffix, $allowed_suffixes)) {
        $table_suffix = 'us'; // Default safe value
    }
    
    $table_name = 'wp_postmeta_' . $table_suffix;
    
    // ok: php-wp-sql-injection-audit
    $results = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts p JOIN $table_name pm ON p.ID = pm.post_id WHERE p.post_status = %s", 'publish'));
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Sanitizing GROUP BY field with whitelist
    $group_field = $_POST['group_by'];
    $allowed_fields = ['post_author', 'post_status', 'post_type'];
    
    if (!in_array($group_field, $allowed_fields)) {
        $group_field = 'post_author'; // Default safe value
    }
    
    // ok: php-wp-sql-injection-audit
    $results = $wpdb->get_results($wpdb->prepare("SELECT COUNT(*) as count, %s FROM wp_posts GROUP BY %s", $group_field, $group_field));
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Sanitizing HAVING clause
    $min_count = absint($_GET['min_count']);
    
    // ok: php-wp-sql-injection-audit
    $results = $wpdb->get_results($wpdb->prepare("SELECT post_author, COUNT(*) as post_count FROM wp_posts GROUP BY post_author HAVING post_count > %d", $min_count));
    
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Sanitizing subquery parameters
    $status = sanitize_text_field($_REQUEST['status']);
    
    // ok: php-wp-sql-injection-audit
    $results = $wpdb->get_results($wpdb->prepare("SELECT * FROM wp_posts WHERE ID IN (SELECT post_id FROM wp_postmeta WHERE meta_value = %s)", $status));
    
    return $results;
}
// {/fact}
?>