<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}
// Examples for php-pgsql-sql-injection rule
// This file contains 15 vulnerable examples and 15 secure examples

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Basic SQL injection vulnerability with GET parameter
    $user_id = $_GET['user_id'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // SQL injection with POST parameter and string concatenation
    $username = $_POST['username'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // SQL injection with REQUEST parameter and interpolation
    $product_id = $_REQUEST['product_id'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "DELETE FROM products WHERE id = $product_id";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // SQL injection with COOKIE parameter
    $user_role = $_COOKIE['user_role'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM permissions WHERE role = '$user_role'";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // SQL injection with SERVER parameter
    $referer = $_SERVER['HTTP_REFERER'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "INSERT INTO access_logs (referer) VALUES ('$referer')";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // SQL injection with multiple parameters and complex query
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $category = $_POST['category'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE price BETWEEN $min_price AND $max_price AND category = '$category'";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // SQL injection with partial sanitization (still vulnerable)
    $user_id = $_GET['user_id'];
    $user_id = str_replace("'", "", $user_id); // Insufficient sanitization
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE id = $user_id";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // SQL injection with variable reassignment
    $order_field = $_GET['order_by'];
    $direction = $_GET['direction'];
    
    if ($direction != 'ASC' && $direction != 'DESC') {
        $direction = 'ASC';
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products ORDER BY $order_field $direction";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // SQL injection with JSON data
    $json_data = file_get_contents('php://input');
    $data = json_decode($json_data, true);
    $email = $data['email'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE email = '$email'";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // SQL injection with conditional query building
    $search = $_GET['search'];
    $type = $_GET['type'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE 1=1";
    
    if (!empty($search)) {
        $query .= " AND name LIKE '%$search%'";
    }
    
    if (!empty($type)) {
        $query .= " AND type = '$type'";
    }
    
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // SQL injection with array parameter
    $ids = $_POST['ids'];
    $id_list = implode(',', $ids);
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE id IN ($id_list)";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // SQL injection with header information
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "INSERT INTO analytics (user_agent, timestamp) VALUES ('$user_agent', NOW())";
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // SQL injection with multiple operations
    $username = $_POST['username'];
    $email = $_POST['email'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    
    // First query
    $check_query = "SELECT COUNT(*) FROM users WHERE username = '$username'";
    // ruleid: php-pgsql-sql-injection
    $check_result = pg_query($conn, $check_query);
    $count = pg_fetch_row($check_result)[0];
    
    if ($count == 0) {
        // Second query
        $insert_query = "INSERT INTO users (username, email) VALUES ('$username', '$email')";
        // ruleid: php-pgsql-sql-injection
        pg_query($conn, $insert_query);
    }
    
    pg_close($conn);
    return $count;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // SQL injection with switch statement
    $action = $_GET['action'];
    $id = $_GET['id'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "";
    
    switch ($action) {
        case 'view':
            $query = "SELECT * FROM products WHERE id = $id";
            break;
        case 'delete':
            $query = "DELETE FROM products WHERE id = $id";
            break;
        default:
            $query = "SELECT COUNT(*) FROM products WHERE id = $id";
    }
    
    // ruleid: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // SQL injection with try-catch block
    $category_id = $_GET['category_id'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    
    try {
        $query = "SELECT * FROM categories WHERE id = $category_id";
        // ruleid: php-pgsql-sql-injection
        $result = pg_query($conn, $query);
        return $result;
    } catch (Exception $e) {
        error_log($e->getMessage());
        return false;
    } finally {
        pg_close($conn);
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // Using pg_query_params with parameter binding
    $user_id = $_GET['user_id'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE id = $1";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($user_id));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using pg_query_params with multiple parameters
    $username = $_POST['username'];
    $email = $_POST['email'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE username = $1 AND email = $2";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($username, $email));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using pg_query_params with input validation
    $product_id = $_REQUEST['product_id'];
    $product_id = filter_var($product_id, FILTER_VALIDATE_INT);
    
    if ($product_id === false) {
        return false;
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "DELETE FROM products WHERE id = $1";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($product_id));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Using pg_query_params with COOKIE parameter
    $user_role = $_COOKIE['user_role'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM permissions WHERE role = $1";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($user_role));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Using pg_query_params with SERVER parameter
    $referer = $_SERVER['HTTP_REFERER'];
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "INSERT INTO access_logs (referer) VALUES ($1)";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($referer));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using pg_query_params with multiple parameters and complex query
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $category = $_POST['category'];
    
    $min_price = filter_var($min_price, FILTER_VALIDATE_FLOAT);
    $max_price = filter_var($max_price, FILTER_VALIDATE_FLOAT);
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE price BETWEEN $1 AND $2 AND category = $3";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($min_price, $max_price, $category));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Using pg_query with hardcoded values (no user input)
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE active = TRUE ORDER BY created_at DESC LIMIT 10";
    // ok: php-pgsql-sql-injection
    $result = pg_query($conn, $query);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Using pg_query_params with conditional query building
    $search = $_GET['search'];
    $type = $_GET['type'];
    
    $params = array();
    $param_index = 1;
    $query = "SELECT * FROM products WHERE 1=1";
    
    if (!empty($search)) {
        $query .= " AND name LIKE $" . $param_index;
        $params[] = '%' . $search . '%';
        $param_index++;
    }
    
    if (!empty($type)) {
        $query .= " AND type = $" . $param_index;
        $params[] = $type;
        $param_index++;
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, $params);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Using pg_query_params with JSON data
    $json_data = file_get_contents('php://input');
    $data = json_decode($json_data, true);
    $email = $data['email'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM users WHERE email = $1";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($email));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Using pg_query_params with array parameter
    $ids = $_POST['ids'];
    
    // Create parameterized query with the correct number of placeholders
    $placeholders = array();
    $params = array();
    
    foreach ($ids as $index => $id) {
        $placeholder_index = $index + 1;
        $placeholders[] = '$' . $placeholder_index;
        $params[] = $id;
    }
    
    $placeholder_string = implode(',', $placeholders);
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE id IN ($placeholder_string)";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, $params);
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Using pg_query_params with header information
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "INSERT INTO analytics (user_agent, timestamp) VALUES ($1, NOW())";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($user_agent));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Using pg_query_params with multiple operations
    $username = $_POST['username'];
    $email = $_POST['email'];
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    
    // First query
    $check_query = "SELECT COUNT(*) FROM users WHERE username = $1";
    // ok: php-pgsql-sql-injection
    $check_result = pg_query_params($conn, $check_query, array($username));
    $count = pg_fetch_row($check_result)[0];
    
    if ($count == 0) {
        // Second query
        $insert_query = "INSERT INTO users (username, email) VALUES ($1, $2)";
        // ok: php-pgsql-sql-injection
        pg_query_params($conn, $insert_query, array($username, $email));
    }
    
    pg_close($conn);
    return $count;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Using pg_query_params with switch statement
    $action = $_GET['action'];
    $id = $_GET['id'];
    $id = filter_var($id, FILTER_VALIDATE_INT);
    
    if ($id === false) {
        return false;
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "";
    
    switch ($action) {
        case 'view':
            $query = "SELECT * FROM products WHERE id = $1";
            break;
        case 'delete':
            $query = "DELETE FROM products WHERE id = $1";
            break;
        default:
            $query = "SELECT COUNT(*) FROM products WHERE id = $1";
    }
    
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array($id));
    pg_close($conn);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Using pg_query_params with try-catch block
    $category_id = $_GET['category_id'];
    $category_id = filter_var($category_id, FILTER_VALIDATE_INT);
    
    if ($category_id === false) {
        return false;
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    
    try {
        $query = "SELECT * FROM categories WHERE id = $1";
        // ok: php-pgsql-sql-injection
        $result = pg_query_params($conn, $query, array($category_id));
        return $result;
    } catch (Exception $e) {
        error_log($e->getMessage());
        return false;
    } finally {
        pg_close($conn);
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Using pg_query_params with input validation and sanitization
    $search_term = $_GET['search'];
    
    // Validate and sanitize input
    $search_term = filter_var($search_term, FILTER_SANITIZE_STRING);
    
    if (empty($search_term)) {
        return array();
    }
    
    $conn = pg_connect("host=localhost dbname=testdb user=postgres password=postgres");
    $query = "SELECT * FROM products WHERE name ILIKE $1 OR description ILIKE $1";
    // ok: php-pgsql-sql-injection
    $result = pg_query_params($conn, $query, array('%' . $search_term . '%'));
    pg_close($conn);
    return $result;
}
// {/fact}
?>