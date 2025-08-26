<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}
// Test cases for PHP Oracle SQL Injection vulnerability detection
// Rule ID: php-oracle-sql-injection-ide

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Direct injection of GET parameter into Oracle query
    $id = $_GET['id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users WHERE user_id = $id";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_fetch_all($stmt, $results);
    oci_free_statement($stmt);
    oci_close($conn);
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // POST parameter injection with string concatenation
    $username = $_POST['username'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM employees WHERE username = '" . $username . "'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // Injection via REQUEST with minimal processing
    $search = trim($_REQUEST['search']);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE product_name LIKE '%" . $search . "%'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // Injection via COOKIE with variable interpolation
    $filter = $_COOKIE['filter'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM orders WHERE status = '$filter'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // Injection via HTTP_REFERER header
    $referrer = $_SERVER['HTTP_REFERER'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "INSERT INTO access_logs (page, referrer) VALUES ('home', '$referrer')";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // Injection with multiple concatenated parameters
    $min = $_GET['min'];
    $max = $_GET['max'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE price BETWEEN " . $min . " AND " . $max;
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // Injection via HTTP_USER_AGENT header
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "INSERT INTO visitor_stats (browser) VALUES ('$userAgent')";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // Injection with minimal processing (lowercase)
    $category = strtolower($_GET['category']);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE category = '$category'";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // Injection with ORDER BY clause
    $sortColumn = $_GET['sort'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM employees ORDER BY " . $sortColumn;
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // Injection with conditional logic
    $status = $_POST['status'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM orders";
    if (!empty($status)) {
        $query .= " WHERE status = '$status'";
    }
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // Injection using PDO with Oracle
    $id = $_GET['id'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "SELECT * FROM users WHERE id = $id";
    // ruleid: php-oracle-sql-injection-ide
    $stmt = $pdo->query($query);
    $results = $stmt->fetchAll();
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // Injection with multiple parameters and string formatting
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = sprintf("SELECT * FROM customers WHERE first_name = '%s' AND last_name = '%s'", 
                    $firstName, $lastName);
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // Injection with JSON data
    $data = json_decode($_POST['data'], true);
    $userId = $data['user_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "DELETE FROM users WHERE id = $userId";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // Injection with array parameter
    $ids = $_GET['ids'];
    $idList = implode(',', $ids);
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE id IN ($idList)";
    $stmt = oci_parse($conn, $query);
    // ruleid: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // Injection with PDO exec
    $email = $_POST['email'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "UPDATE users SET verified = 1 WHERE email = '$email'";
    // ruleid: php-oracle-sql-injection-ide
    $pdo->exec($query);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Safe Code)

function good_case_1() {
    // Using bind parameters with oci_bind_by_name
    $id = $_GET['id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM users WHERE user_id = :id";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':id', $id);
    oci_execute($stmt);
    oci_fetch_all($stmt, $results);
    oci_free_statement($stmt);
    oci_close($conn);
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using bind parameters with multiple bindings
    $username = $_POST['username'];
    $status = $_POST['status'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM employees WHERE username = :username AND status = :status";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':username', $username);
    oci_bind_by_name($stmt, ':status', $status);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using PDO with prepared statements
    $search = $_REQUEST['search'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "SELECT * FROM products WHERE product_name LIKE :search";
    $stmt = $pdo->prepare($query);
    // ok: php-oracle-sql-injection-ide
    $stmt->bindValue(':search', '%' . $search . '%');
    $stmt->execute();
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Using bind parameters with integer casting
    $filter = (int)$_COOKIE['filter'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM orders WHERE status_id = :filter";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':filter', $filter);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Using bind parameters with HTTP header data
    $referrer = $_SERVER['HTTP_REFERER'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "INSERT INTO access_logs (page, referrer) VALUES ('home', :referrer)";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':referrer', $referrer);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using bind parameters with multiple numeric values
    $min = $_GET['min'];
    $max = $_GET['max'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products WHERE price BETWEEN :min AND :max";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':min', $min);
    oci_bind_by_name($stmt, ':max', $max);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Using bind parameters with HTTP_USER_AGENT
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "INSERT INTO visitor_stats (browser) VALUES (:browser)";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':browser', $userAgent);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Using whitelist for column names
    $sortColumn = $_GET['sort'];
    $allowedColumns = ['name', 'date', 'price', 'quantity'];
    
    if (!in_array($sortColumn, $allowedColumns)) {
        $sortColumn = 'name'; // Default safe value
    }
    
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM products ORDER BY " . $sortColumn;
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Using PDO with named parameters
    $status = $_POST['status'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "SELECT * FROM orders WHERE status = :status";
    $stmt = $pdo->prepare($query);
    // ok: php-oracle-sql-injection-ide
    $stmt->bindParam(':status', $status);
    $stmt->execute();
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Using bind parameters with conditional query building
    $status = $_POST['status'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    
    if (!empty($status)) {
        $query = "SELECT * FROM orders WHERE status = :status";
        $stmt = oci_parse($conn, $query);
        // ok: php-oracle-sql-injection-ide
        oci_bind_by_name($stmt, ':status', $status);
    } else {
        $query = "SELECT * FROM orders";
        $stmt = oci_parse($conn, $query);
    }
    
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Using PDO with positional parameters
    $id = $_GET['id'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "SELECT * FROM users WHERE id = ?";
    $stmt = $pdo->prepare($query);
    // ok: php-oracle-sql-injection-ide
    $stmt->bindParam(1, $id);
    $stmt->execute();
    return $stmt->fetchAll();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Using bind parameters with multiple string values
    $firstName = $_POST['first_name'];
    $lastName = $_POST['last_name'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "SELECT * FROM customers WHERE first_name = :first_name AND last_name = :last_name";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':first_name', $firstName);
    oci_bind_by_name($stmt, ':last_name', $lastName);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Using bind parameters with JSON data
    $data = json_decode($_POST['data'], true);
    $userId = $data['user_id'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    $query = "DELETE FROM users WHERE id = :id";
    $stmt = oci_parse($conn, $query);
    // ok: php-oracle-sql-injection-ide
    oci_bind_by_name($stmt, ':id', $userId);
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Using bind parameters with array values
    $ids = $_GET['ids'];
    $conn = oci_connect('username', 'password', 'localhost/XE');
    
    // Create a query with the right number of placeholders
    $placeholders = [];
    $bindValues = [];
    
    for ($i = 0; $i < count($ids); $i++) {
        $placeholder = ":id" . $i;
        $placeholders[] = $placeholder;
        $bindValues[$placeholder] = $ids[$i];
    }
    
    $query = "SELECT * FROM products WHERE id IN (" . implode(',', $placeholders) . ")";
    $stmt = oci_parse($conn, $query);
    
    // ok: php-oracle-sql-injection-ide
    foreach ($bindValues as $placeholder => $value) {
        oci_bind_by_name($stmt, $placeholder, $bindValues[$placeholder]);
    }
    
    oci_execute($stmt);
    oci_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Using PDO prepared statement with exec
    $email = $_POST['email'];
    $dsn = 'oci:dbname=//localhost:1521/XE';
    $pdo = new PDO($dsn, 'username', 'password');
    $query = "UPDATE users SET verified = 1 WHERE email = :email";
    $stmt = $pdo->prepare($query);
    // ok: php-oracle-sql-injection-ide
    $stmt->bindParam(':email', $email);
    $stmt->execute();
}
// {/fact}
?>