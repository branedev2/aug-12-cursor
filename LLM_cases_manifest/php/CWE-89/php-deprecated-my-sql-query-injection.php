<?php
/**
 * Test cases for php-deprecated-my-sql-query-injection rule
 * These examples demonstrate vulnerable and secure usage of mysql functions
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}

// ======== TRUE POSITIVES (Vulnerable Code) ========

// Direct use of $_GET parameter in mysql_query
function bad_case_1() {
    $id = $_GET['id'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM users WHERE id = $id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Direct use of $_POST parameter in mysql_query
function bad_case_2() {
    $username = $_POST['username'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM users WHERE username = '$username'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_REQUEST parameter in mysql_query with string concatenation
function bad_case_3() {
    $email = $_REQUEST['email'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    $query = "SELECT * FROM users WHERE email = '" . $email . "'";
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using HTTP header value in mysql_query
function bad_case_4() {
    $headers = getallheaders();
    $user_agent = $headers['User-Agent'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("INSERT INTO logs (user_agent) VALUES ('$user_agent')");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using cookie value in mysql_query
function bad_case_5() {
    $user_id = $_COOKIE['user_id'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM sessions WHERE user_id = $user_id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_GET parameter with string interpolation
function bad_case_6() {
    $product_id = $_GET['product_id'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("DELETE FROM products WHERE id = $product_id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using multiple $_POST parameters in mysql_query
function bad_case_7() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM users WHERE username = '$username' AND password = '$password'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_GET parameter in mysql_query with variable query
function bad_case_8() {
    $sort = $_GET['sort'];
    $order = $_GET['order'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    $query = "SELECT * FROM products ORDER BY $sort $order";
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_POST parameter in mysql_query with partial sanitization (still vulnerable)
function bad_case_9() {
    $user_id = $_POST['user_id'];
    $user_id = trim($user_id); // Trimming doesn't prevent SQL injection
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("UPDATE users SET active = 1 WHERE id = $user_id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_GET parameter in mysql_query with string operations
function bad_case_10() {
    $search = $_GET['search'];
    $search = strtolower($search); // String operation doesn't prevent SQL injection
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM products WHERE LOWER(name) LIKE '%$search%'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_REQUEST parameter in mysql_query with conditional logic
function bad_case_11() {
    $category = $_REQUEST['category'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    if (!empty($category)) {
        $query = "SELECT * FROM products WHERE category = '$category'";
    } else {
        $query = "SELECT * FROM products";
    }
    
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_GET parameter in mysql_query with array access
function bad_case_12() {
    $ids = $_GET['ids'];
    $index = $_GET['index'];
    $id = $ids[$index]; // Still tainted
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM products WHERE id = $id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_POST parameter in mysql_query with function call
function bad_case_13() {
    $date = $_POST['date'];
    $formatted_date = date('Y-m-d', strtotime($date)); // Still tainted for SQL injection
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM events WHERE event_date = '$formatted_date'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_GET parameter in mysql_query with ternary operator
function bad_case_14() {
    $status = isset($_GET['status']) ? $_GET['status'] : 'active';
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM orders WHERE status = '$status'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using $_REQUEST parameter in mysql_query with switch statement
function bad_case_15() {
    $action = $_REQUEST['action'];
    $id = $_REQUEST['id'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    switch ($action) {
        case 'delete':
            $query = "DELETE FROM items WHERE id = $id";
            break;
        case 'update':
            $query = "UPDATE items SET status = 'updated' WHERE id = $id";
            break;
        default:
            $query = "SELECT * FROM items WHERE id = $id";
    }
    
    // ruleid: php-deprecated-my-sql-query-injection
    $result = mysql_query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// ======== TRUE NEGATIVES (Secure Code) ========

// Using MySQLi with prepared statements
function good_case_1() {
    $id = $_GET['id'];
    $mysqli = new mysqli('localhost', 'user', 'password', 'database');
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using PDO with prepared statements
function good_case_2() {
    $username = $_POST['username'];
    $pdo = new PDO('mysql:host=localhost;dbname=database', 'user', 'password');
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysql_query with proper integer sanitization
function good_case_3() {
    $id = $_REQUEST['id'];
    $id = intval($id); // Proper sanitization for integers
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    // ok: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM users WHERE id = $id");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysql_query with proper string sanitization
function good_case_4() {
    $username = $_POST['username'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    $username = mysql_real_escape_string($username); // Proper sanitization for strings
    
    // ok: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM users WHERE username = '$username'");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using MySQLi with multiple parameters in prepared statement
function good_case_5() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $mysqli = new mysqli('localhost', 'user', 'password', 'database');
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using PDO with named parameters
function good_case_6() {
    $product_id = $_GET['product_id'];
    $pdo = new PDO('mysql:host=localhost;dbname=database', 'user', 'password');
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $pdo->prepare("DELETE FROM products WHERE id = :id");
    $stmt->bindParam(':id', $product_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->rowCount();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysql_query with hardcoded values (no user input)
function good_case_7() {
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    // ok: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM settings WHERE active = 1");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using MySQLi with prepared statement and LIKE operator
function good_case_8() {
    $search = $_GET['search'];
    $mysqli = new mysqli('localhost', 'user', 'password', 'database');
    $search = "%$search%";
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $mysqli->prepare("SELECT * FROM products WHERE name LIKE ?");
    $stmt->bind_param("s", $search);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using PDO with prepared statement and multiple conditions
function good_case_9() {
    $category = $_POST['category'];
    $min_price = $_POST['min_price'];
    $pdo = new PDO('mysql:host=localhost;dbname=database', 'user', 'password');
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $pdo->prepare("SELECT * FROM products WHERE category = ? AND price >= ?");
    $stmt->execute([$category, $min_price]);
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysql_query with proper sanitization for multiple parameters
function good_case_10() {
    $name = $_REQUEST['name'];
    $email = $_REQUEST['email'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    $name = mysql_real_escape_string($name);
    $email = mysql_real_escape_string($email);
    
    // ok: php-deprecated-my-sql-query-injection
    $result = mysql_query("INSERT INTO users (name, email) VALUES ('$name', '$email')");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using MySQLi with prepared statement and conditional logic
function good_case_11() {
    $category = $_REQUEST['category'];
    $mysqli = new mysqli('localhost', 'user', 'password', 'database');
    
    if (!empty($category)) {
        // ok: php-deprecated-my-sql-query-injection
        $stmt = $mysqli->prepare("SELECT * FROM products WHERE category = ?");
        $stmt->bind_param("s", $category);
    } else {
        // ok: php-deprecated-my-sql-query-injection
        $stmt = $mysqli->prepare("SELECT * FROM products");
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using PDO with prepared statement and array parameters
function good_case_12() {
    $ids = $_GET['ids'];
    $pdo = new PDO('mysql:host=localhost;dbname=database', 'user', 'password');
    
    // Convert string of comma-separated ids to array
    $id_array = explode(',', $ids);
    $placeholders = implode(',', array_fill(0, count($id_array), '?'));
    
    // ok: php-deprecated-my-sql-query-injection
    $stmt = $pdo->prepare("SELECT * FROM products WHERE id IN ($placeholders)");
    $stmt->execute($id_array);
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysql_query with whitelist validation
function good_case_13() {
    $sort = $_GET['sort'];
    $connection = mysql_connect('localhost', 'user', 'password');
    mysql_select_db('database');
    
    // Whitelist validation
    $allowed_columns = ['name', 'price', 'date_added'];
    if (!in_array($sort, $allowed_columns)) {
        $sort = 'name'; // Default safe value
    }
    
    // ok: php-deprecated-my-sql-query-injection
    $result = mysql_query("SELECT * FROM products ORDER BY $sort ASC");
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using MySQLi with transaction and prepared statements
function good_case_14() {
    $user_id = $_POST['user_id'];
    $amount = $_POST['amount'];
    
    $mysqli = new mysqli('localhost', 'user', 'password', 'database');
    $mysqli->begin_transaction();
    
    try {
        // ok: php-deprecated-my-sql-query-injection
        $stmt1 = $mysqli->prepare("UPDATE accounts SET balance = balance - ? WHERE user_id = ?");
        $stmt1->bind_param("di", $amount, $user_id);
        $stmt1->execute();
        
        // ok: php-deprecated-my-sql-query-injection
        $stmt2 = $mysqli->prepare("INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, 'withdrawal')");
        $stmt2->bind_param("id", $user_id, $amount);
        $stmt2->execute();
        
        $mysqli->commit();
        return true;
    } catch (Exception $e) {
        $mysqli->rollback();
        return false;
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using PDO with prepared statement and error handling
function good_case_15() {
    $email = $_REQUEST['email'];
    
    try {
        $pdo = new PDO('mysql:host=localhost;dbname=database', 'user', 'password');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // ok: php-deprecated-my-sql-query-injection
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        return false;
    }
}
// {/fact}
?>