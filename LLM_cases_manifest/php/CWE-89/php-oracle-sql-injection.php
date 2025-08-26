<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}
// PHP Oracle SQL Injection Test Cases

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Direct use of GET parameter in SQL query
    $id = $_GET['id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users WHERE id = $id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_fetch_all($stmt, $res);
    oci_free_statement($stmt);
    oci_close($conn);
    return $res;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // POST parameter used in SQL query with string concatenation
    $username = $_POST['username'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM employees WHERE username = '" . $username . "'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // Request parameter used in SQL query with interpolation
    $email = $_REQUEST['email'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "DELETE FROM subscribers WHERE email = '$email'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // Cookie value used in SQL query
    $user_id = $_COOKIE['user_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "UPDATE user_sessions SET last_active = SYSDATE WHERE user_id = $user_id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // Header value used in SQL query
    $api_key = $_SERVER['HTTP_X_API_KEY'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM api_users WHERE api_key = '$api_key'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // Multiple parameters combined in SQL query
    $min_age = $_GET['min_age'];
    $max_age = $_GET['max_age'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM customers WHERE age BETWEEN $min_age AND $max_age";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // User input in ORDER BY clause
    $sort_column = $_GET['sort'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products ORDER BY $sort_column";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // User input in LIKE clause
    $search = $_POST['search'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM articles WHERE title LIKE '%$search%'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // User input in IN clause
    $categories = $_GET['categories'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE category_id IN ($categories)";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // User input in JOIN condition
    $table_name = $_GET['table'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users JOIN $table_name ON users.id = $table_name.user_id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // User input with minimal processing
    $user_id = trim($_POST['user_id']);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM user_logs WHERE user_id = $user_id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // User input with insufficient sanitization
    $product_id = str_replace("'", "", $_GET['product_id']);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE id = $product_id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // User input in stored procedure call
    $status = $_POST['status'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "BEGIN update_order_status($status); END;";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // User input in dynamic table name
    $year = $_GET['year'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM sales_$year WHERE amount > 1000";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // User input with PDO Oracle
    $user_id = $_GET['id'];
    $conn = new PDO('oci:dbname=//localhost:1521/XE', 'username', 'password');
    $query = "SELECT * FROM users WHERE id = $user_id";
    // ruleid: php-oracle-sql-injection
    $stmt = $conn->query($query);
    $result = $stmt->fetchAll();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negatives (Secure Code)

function good_case_1() {
    // Using bind variables with oci_bind_by_name
    $id = $_GET['id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users WHERE id = :id";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':id', $id);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using multiple bind variables
    $username = $_POST['username'];
    $email = $_POST['email'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users WHERE username = :username AND email = :email";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':username', $username);
    oci_bind_by_name($stmt, ':email', $email);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using bind variables with PDO
    $email = $_REQUEST['email'];
    $conn = new PDO('oci:dbname=//localhost:1521/XE', 'username', 'password');
    $query = "DELETE FROM subscribers WHERE email = :email";
    $stmt = $conn->prepare($query);
    // ok: php-oracle-sql-injection
    $stmt->bindParam(':email', $email);
    $stmt->execute();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Using bind variables with numeric indexes
    $user_id = $_COOKIE['user_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "UPDATE user_sessions SET last_active = SYSDATE WHERE user_id = :1";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':1', $user_id);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Using bind variables with different data types
    $api_key = $_SERVER['HTTP_X_API_KEY'];
    $active = 1;
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM api_users WHERE api_key = :api_key AND active = :active";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':api_key', $api_key);
    oci_bind_by_name($stmt, ':active', $active, -1, SQLT_INT);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using bind variables for range queries
    $min_age = $_GET['min_age'];
    $max_age = $_GET['max_age'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM customers WHERE age BETWEEN :min_age AND :max_age";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':min_age', $min_age);
    oci_bind_by_name($stmt, ':max_age', $max_age);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Validating column name against whitelist
    $allowed_columns = ['name', 'price', 'date_added'];
    $sort_column = $_GET['sort'];
    
    if (!in_array($sort_column, $allowed_columns)) {
        $sort_column = 'name'; // Default safe value
    }
    
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products ORDER BY $sort_column";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Using bind variables with LIKE
    $search = $_POST['search'];
    $search_param = '%' . $search . '%';
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM articles WHERE title LIKE :search";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':search', $search_param);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Converting comma-separated list to bind variables
    $category_ids = explode(',', $_GET['categories']);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    
    $placeholders = [];
    $binds = [];
    foreach ($category_ids as $i => $id) {
        $placeholder = ":cat$i";
        $placeholders[] = $placeholder;
        $binds[$placeholder] = $id;
    }
    
    $query = "SELECT * FROM products WHERE category_id IN (" . implode(',', $placeholders) . ")";
    $stmt = oci_parse($conn, $query);
    
    // ok: php-oracle-sql-injection
    foreach ($binds as $placeholder => $value) {
        oci_bind_by_name($stmt, $placeholder, $binds[$placeholder]);
    }
    
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Validating table name against whitelist
    $allowed_tables = ['orders', 'payments', 'shipments'];
    $table_name = $_GET['table'];
    
    if (!in_array($table_name, $allowed_tables)) {
        $table_name = 'orders'; // Default safe value
    }
    
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users JOIN $table_name ON users.id = $table_name.user_id";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Type casting to ensure numeric input
    $user_id = (int)$_POST['user_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM user_logs WHERE user_id = $user_id";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Using bind variables with stored procedure
    $status = $_POST['status'];
    $order_id = $_POST['order_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "BEGIN update_order_status(:order_id, :status); END;";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':order_id', $order_id);
    oci_bind_by_name($stmt, ':status', $status);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Validating year input with regex before using in table name
    $year = $_GET['year'];
    if (!preg_match('/^[0-9]{4}$/', $year)) {
        $year = date('Y'); // Default to current year if invalid
    }
    
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM sales_$year WHERE amount > 1000";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Using PDO with prepared statements
    $user_id = $_GET['id'];
    $conn = new PDO('oci:dbname=//localhost:1521/XE', 'username', 'password');
    $query = "SELECT * FROM users WHERE id = :id";
    $stmt = $conn->prepare($query);
    // ok: php-oracle-sql-injection
    $stmt->bindParam(':id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    $result = $stmt->fetchAll();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Using bind variables with transaction
    $product_id = $_POST['product_id'];
    $quantity = $_POST['quantity'];
    $user_id = $_SESSION['user_id'];
    
    $conn = oci_connect('username', 'password', 'localhost/XE');
    oci_set_client_info($conn, 'Shopping Cart Update');
    
    $query = "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (:user_id, :product_id, :quantity)";
    $stmt = oci_parse($conn, $query);
    
    // ok: php-oracle-sql-injection
    oci_bind_by_name($stmt, ':user_id', $user_id);
    oci_bind_by_name($stmt, ':product_id', $product_id);
    oci_bind_by_name($stmt, ':quantity', $quantity);
    
    oci_execute($stmt, OCI_DEFAULT); // Start transaction
    oci_commit($conn);
    oci_close($conn);
}
// {/fact}
?>