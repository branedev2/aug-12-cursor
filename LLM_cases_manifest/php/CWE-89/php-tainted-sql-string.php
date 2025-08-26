<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}
// Test cases for php-tainted-sql-string (CWE-89: SQL Injection)

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Direct use of GET parameter in SQL query
    $user_id = $_GET['user_id'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // POST parameter in SQL query with string concatenation
    $username = $_POST['username'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // Using REQUEST parameter with minimal processing
    $product_id = $_REQUEST['product_id'];
    $product_id = trim($product_id); // Trimming doesn't prevent SQL injection
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "DELETE FROM products WHERE id = " . $product_id;
    $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // Using HTTP header in SQL query
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "INSERT INTO access_logs (user_agent, access_time) VALUES ('" . $user_agent . "', NOW())";
    mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // Using cookie value in SQL query
    $user_preference = $_COOKIE['preference'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "UPDATE user_preferences SET theme = '" . $user_preference . "' WHERE user_id = 1";
    $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // Multiple parameters in one query
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $category = $_POST['category'];
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM products WHERE price BETWEEN " . $min_price . " AND " . $max_price . 
             " AND category = '" . $category . "'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // Using JSON data from POST request
    $data = json_decode(file_get_contents('php://input'), true);
    $search_term = $data['search'];
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "SELECT * FROM articles WHERE title LIKE '%" . $search_term . "%'";
    $result = $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // Using input with string manipulation
    $email = strtolower($_POST['email']);
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM subscribers WHERE email = '" . $email . "'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // Using input in a more complex query with ORDER BY
    $sort_column = $_GET['sort'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "SELECT id, name, price FROM products ORDER BY " . $sort_column;
    $result = $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // Using input in LIMIT clause
    $limit = $_GET['limit'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM recent_posts LIMIT " . $limit;
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // Using input in a subquery
    $department = $_POST['department'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = '" . $department . "')";
    $result = $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // Using input with conditional logic
    $status = $_GET['status'];
    $user_id = $_SESSION['user_id'];
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    if ($status == 'active') {
        // ruleid: php-tainted-sql-string
        $query = "UPDATE users SET last_active = NOW() WHERE id = " . $user_id;
    } else {
        // ruleid: php-tainted-sql-string
        $query = "UPDATE users SET status = '" . $status . "' WHERE id = " . $user_id;
    }
    
    mysqli_query($conn, $query);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // Using input with array access
    $filters = $_POST['filters'];
    $category_id = $filters['category'];
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $sql = "SELECT * FROM products WHERE category_id = " . $category_id;
    $result = $conn->query($sql);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // Using input with string interpolation
    $product_name = $_GET['product'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ruleid: php-tainted-sql-string
    $query = "SELECT * FROM products WHERE name LIKE '%$product_name%'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // Using input with concatenation in a loop
    $ids = $_POST['ids'];
    $id_array = explode(',', $ids);
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    $query = "SELECT * FROM products WHERE id IN (";
    foreach ($id_array as $index => $id) {
        if ($index > 0) {
            $query .= ", ";
        }
        // ruleid: php-tainted-sql-string
        $query .= $id;
    }
    $query .= ")";
    
    $result = $conn->query($query);
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negatives (Safe Code)

function good_case_1() {
    // Using prepared statements with mysqli
    $user_id = $_GET['user_id'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE id = ?");
    mysqli_stmt_bind_param($stmt, "i", $user_id);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    mysqli_stmt_close($stmt);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using prepared statements with mysqli OOP style
    $username = $_POST['username'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $stmt->close();
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using mysqli_real_escape_string as recommended
    $product_id = $_REQUEST['product_id'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_product_id = mysqli_real_escape_string($conn, $product_id);
    $query = "DELETE FROM products WHERE id = '" . $safe_product_id . "'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Using real_escape_string with mysqli OOP style
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_user_agent = $conn->real_escape_string($user_agent);
    $query = "INSERT INTO access_logs (user_agent, access_time) VALUES ('" . $safe_user_agent . "', NOW())";
    $conn->query($query);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Using addslashes as recommended
    $user_preference = $_COOKIE['preference'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_preference = addslashes($user_preference);
    $query = "UPDATE user_preferences SET theme = '" . $safe_preference . "' WHERE user_id = 1";
    mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using prepared statements with multiple parameters
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $category = $_POST['category'];
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $stmt = $conn->prepare("SELECT * FROM products WHERE price BETWEEN ? AND ? AND category = ?");
    $stmt->bind_param("dds", $min_price, $max_price, $category);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $stmt->close();
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Using prepared statements with JSON data
    $data = json_decode(file_get_contents('php://input'), true);
    $search_term = $data['search'];
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $stmt = mysqli_prepare($conn, "SELECT * FROM articles WHERE title LIKE ?");
    $search_pattern = "%" . $search_term . "%";
    mysqli_stmt_bind_param($stmt, "s", $search_pattern);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    mysqli_stmt_close($stmt);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Using sanitization with string manipulation
    $email = strtolower($_POST['email']);
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_email = $conn->real_escape_string($email);
    $query = "SELECT * FROM subscribers WHERE email = '" . $safe_email . "'";
    $result = $conn->query($query);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Using whitelisting for ORDER BY clause
    $sort_column = $_GET['sort'];
    $allowed_columns = ['id', 'name', 'price', 'date_added'];
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    if (in_array($sort_column, $allowed_columns)) {
        $query = "SELECT id, name, price FROM products ORDER BY " . $sort_column;
        $result = mysqli_query($conn, $query);
    } else {
        $query = "SELECT id, name, price FROM products ORDER BY id";
        $result = mysqli_query($conn, $query);
    }
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Using casting for numeric input
    $limit = $_GET['limit'];
    $conn = new mysqli("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_limit = (int)$limit;
    $query = "SELECT * FROM recent_posts LIMIT " . $safe_limit;
    $result = $conn->query($query);
    
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Using prepared statements with subquery
    $department = $_POST['department'];
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $stmt = mysqli_prepare($conn, "SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = ?)");
    mysqli_stmt_bind_param($stmt, "s", $department);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    mysqli_stmt_close($stmt);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Using prepared statements with conditional logic
    $status = $_GET['status'];
    $user_id = $_SESSION['user_id'];
    
    $conn = new mysqli("localhost", "user", "password", "database");
    
    if ($status == 'active') {
        // ok: php-tainted-sql-string
        $stmt = $conn->prepare("UPDATE users SET last_active = NOW() WHERE id = ?");
        $stmt->bind_param("i", $user_id);
    } else {
        // ok: php-tainted-sql-string
        $stmt = $conn->prepare("UPDATE users SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $status, $user_id);
    }
    
    $stmt->execute();
    $stmt->close();
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Using sanitization with array access
    $filters = $_POST['filters'];
    $category_id = $filters['category'];
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    // ok: php-tainted-sql-string
    $safe_category_id = mysqli_real_escape_string($conn, $category_id);
    $query = "SELECT * FROM products WHERE category_id = '" . $safe_category_id . "'";
    $result = mysqli_query($conn, $query);
    
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Using PDO prepared statements
    $product_name = $_GET['product'];
    
    $dsn = "mysql:host=localhost;dbname=database";
    $pdo = new PDO($dsn, "user", "password");
    
    // ok: php-tainted-sql-string
    $stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :name");
    $stmt->bindValue(':name', '%' . $product_name . '%');
    $stmt->execute();
    $results = $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Using prepared statements with a loop
    $ids = $_POST['ids'];
    $id_array = explode(',', $ids);
    
    $conn = mysqli_connect("localhost", "user", "password", "database");
    
    $placeholders = implode(',', array_fill(0, count($id_array), '?'));
    
    // ok: php-tainted-sql-string
    $stmt = mysqli_prepare($conn, "SELECT * FROM products WHERE id IN ($placeholders)");
    
    $types = str_repeat('i', count($id_array));
    mysqli_stmt_bind_param($stmt, $types, ...$id_array);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    mysqli_stmt_close($stmt);
    mysqli_close($conn);
}
// {/fact}
?>