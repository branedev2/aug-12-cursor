<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}
// Test cases for php-mysqli-sql-injection rule (CWE-89)

// ===== TRUE POSITIVES (Vulnerable Code) =====

// Direct inclusion of GET parameter in SQL query
function bad_case_1() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = $id";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Direct inclusion of POST parameter in SQL query
function bad_case_2() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $username = $_POST['username'];
    $query = "SELECT * FROM users WHERE username = '$username'";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using REQUEST parameter directly in query
function bad_case_3() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $category = $_REQUEST['category'];
    $query = "SELECT * FROM products WHERE category = '$category' ORDER BY name";
    // ruleid: php-mysqli-sql-injection
    $mysqli->query($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using HTTP header in SQL query
function bad_case_4() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $headers = getallheaders();
    $user_agent = $headers['User-Agent'];
    $query = "INSERT INTO access_logs (user_agent, access_time) VALUES ('$user_agent', NOW())";
    // ruleid: php-mysqli-sql-injection
    $mysqli->query($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using cookie value in SQL query
function bad_case_5() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $user_id = $_COOKIE['user_id'];
    $query = "SELECT * FROM user_preferences WHERE user_id = $user_id";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Concatenating multiple user inputs in a query
function bad_case_6() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $query = "SELECT * FROM products WHERE price >= $min_price AND price <= $max_price";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using user input in a subquery
function bad_case_7() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $department = $_POST['department'];
    $query = "SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = '$department')";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in UPDATE statement
function bad_case_8() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $new_status = $_POST['status'];
    $order_id = $_GET['order_id'];
    $query = "UPDATE orders SET status = '$new_status' WHERE id = $order_id";
    // ruleid: php-mysqli-sql-injection
    $mysqli->query($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in DELETE statement
function bad_case_9() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $comment_id = $_REQUEST['comment_id'];
    $query = "DELETE FROM comments WHERE id = $comment_id";
    // ruleid: php-mysqli-sql-injection
    $mysqli->query($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in INSERT statement with multiple values
function bad_case_10() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $username = $_POST['username'];
    $email = $_POST['email'];
    $query = "INSERT INTO users (username, email) VALUES ('$username', '$email')";
    // ruleid: php-mysqli-sql-injection
    $mysqli->query($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in LIKE clause
function bad_case_11() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $search = $_GET['search'];
    $query = "SELECT * FROM products WHERE name LIKE '%$search%'";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in ORDER BY clause
function bad_case_12() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $sort_column = $_GET['sort'];
    $query = "SELECT * FROM users ORDER BY $sort_column ASC";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input in LIMIT clause
function bad_case_13() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $limit = $_GET['limit'];
    $query = "SELECT * FROM products LIMIT $limit";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input with basic string manipulation
function bad_case_14() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $user_id = $_GET['user_id'];
    $user_id = trim($user_id);
    $query = "SELECT * FROM users WHERE id = $user_id";
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Using input with conditional logic
function bad_case_15() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $status = $_GET['status'];
    $user_id = $_GET['user_id'];
    
    $query = "SELECT * FROM orders WHERE user_id = $user_id";
    if (!empty($status)) {
        $query .= " AND status = '$status'";
    }
    
    // ruleid: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// ===== TRUE NEGATIVES (Secure Code) =====

// Using prepared statement with bind_param for integer
function good_case_1() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $id = $_GET['id'];
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with bind_param for string
function good_case_2() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $username = $_POST['username'];
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with multiple parameters
function good_case_3() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $stmt = $mysqli->prepare("SELECT * FROM products WHERE price >= ? AND price <= ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("dd", $min_price, $max_price);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysqli_real_escape_string for input sanitization
function good_case_4() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $search = $_GET['search'];
    $search = $mysqli->real_escape_string($search);
    $query = "SELECT * FROM products WHERE name LIKE '%$search%'";
    // ok: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement for INSERT
function good_case_5() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $username = $_POST['username'];
    $email = $_POST['email'];
    $stmt = $mysqli->prepare("INSERT INTO users (username, email) VALUES (?, ?)");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    return $stmt->affected_rows;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement for UPDATE
function good_case_6() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $new_status = $_POST['status'];
    $order_id = $_GET['order_id'];
    $stmt = $mysqli->prepare("UPDATE orders SET status = ? WHERE id = ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("si", $new_status, $order_id);
    $stmt->execute();
    return $stmt->affected_rows;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement for DELETE
function good_case_7() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $comment_id = $_REQUEST['comment_id'];
    $stmt = $mysqli->prepare("DELETE FROM comments WHERE id = ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("i", $comment_id);
    $stmt->execute();
    return $stmt->affected_rows;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with LIKE clause
function good_case_8() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $search = $_GET['search'];
    $search = "%$search%";  // Adding wildcards before binding
    $stmt = $mysqli->prepare("SELECT * FROM products WHERE name LIKE ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("s", $search);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with ORDER BY (using whitelist)
function good_case_9() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $sort = $_GET['sort'];
    
    // Whitelist validation
    $allowed_columns = ['name', 'price', 'date_added'];
    if (!in_array($sort, $allowed_columns)) {
        $sort = 'name';  // Default safe value
    }
    
    $query = "SELECT * FROM products ORDER BY $sort ASC";
    // ok: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with LIMIT and OFFSET
function good_case_10() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    
    $stmt = $mysqli->prepare("SELECT * FROM products LIMIT ? OFFSET ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("ii", $limit, $offset);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with subquery
function good_case_11() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $department = $_POST['department'];
    $stmt = $mysqli->prepare("SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = ?)");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("s", $department);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with JOIN
function good_case_12() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $user_id = $_GET['user_id'];
    $stmt = $mysqli->prepare("SELECT o.*, p.name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = ?");
    // ok: php-mysqli-sql-injection
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with conditional query building
function good_case_13() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $user_id = $_GET['user_id'];
    $status = isset($_GET['status']) ? $_GET['status'] : null;
    
    if ($status !== null) {
        $stmt = $mysqli->prepare("SELECT * FROM orders WHERE user_id = ? AND status = ?");
        // ok: php-mysqli-sql-injection
        $stmt->bind_param("is", $user_id, $status);
    } else {
        $stmt = $mysqli->prepare("SELECT * FROM orders WHERE user_id = ?");
        // ok: php-mysqli-sql-injection
        $stmt->bind_param("i", $user_id);
    }
    
    $stmt->execute();
    $result = $stmt->get_result();
    return $result;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using prepared statement with multiple value sets
function good_case_14() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $usernames = $_POST['usernames'];
    $emails = $_POST['emails'];
    
    $stmt = $mysqli->prepare("INSERT INTO users (username, email) VALUES (?, ?)");
    // ok: php-mysqli-sql-injection
    
    for ($i = 0; $i < count($usernames); $i++) {
        $stmt->bind_param("ss", $usernames[$i], $emails[$i]);
        $stmt->execute();
    }
    
    return true;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Using mysqli_real_escape_string with complex query
function good_case_15() {
    $mysqli = new mysqli("localhost", "user", "password", "database");
    $search = $_GET['search'];
    $category = $_GET['category'];
    
    $search = $mysqli->real_escape_string($search);
    $category = $mysqli->real_escape_string($category);
    
    $query = "SELECT p.*, c.name as category_name 
              FROM products p 
              JOIN categories c ON p.category_id = c.id 
              WHERE p.name LIKE '%$search%' AND c.name = '$category'";
    
    // ok: php-mysqli-sql-injection
    $result = $mysqli->query($query);
    return $result;
}
// {/fact}
?>