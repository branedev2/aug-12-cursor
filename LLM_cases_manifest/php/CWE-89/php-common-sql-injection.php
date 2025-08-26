<?php

/**
 * True Positive Examples (Vulnerable Code)
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 1: Basic SQL injection with MySQL using $_GET parameter
function bad_case_1() {
    $conn = new mysqli("localhost", "user", "password", "database");
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    // ruleid: php-common-sql-injection
    $result = $conn->query($query);
    
    while($row = $result->fetch_assoc()) {
        echo "Name: " . $row["name"];
    }
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 2: SQL injection with PDO using $_POST parameter
function bad_case_2() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $username = $_POST['username'];
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    // ruleid: php-common-sql-injection
    $stmt = $pdo->query($query);
    
    foreach ($stmt as $row) {
        echo $row['email'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 3: SQL injection with mysqli_query using $_REQUEST parameter
function bad_case_3() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $product_id = $_REQUEST['product_id'];
    $query = "DELETE FROM products WHERE id = " . $product_id;
    // ruleid: php-common-sql-injection
    mysqli_query($conn, $query);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 4: SQL injection with string concatenation and $_COOKIE parameter
function bad_case_4() {
    $conn = new mysqli("localhost", "user", "password", "database");
    $sort_by = $_COOKIE['sort'];
    $query = "SELECT * FROM products ORDER BY " . $sort_by;
    // ruleid: php-common-sql-injection
    $result = $conn->query($query);
    
    while($row = $result->fetch_assoc()) {
        echo "Product: " . $row["name"] . "<br>";
    }
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 5: SQL injection with SQLite3 using $_GET parameter
function bad_case_5() {
    $db = new SQLite3('database.sqlite');
    $category = $_GET['category'];
    $query = "SELECT * FROM products WHERE category = '" . $category . "'";
    // ruleid: php-common-sql-injection
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ": $" . $row['price'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 6: SQL injection with PDO exec using $_POST parameter
function bad_case_6() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $email = $_POST['email'];
    $query = "UPDATE users SET verified = 1 WHERE email = '" . $email . "'";
    // ruleid: php-common-sql-injection
    $pdo->exec($query);
    echo "User verified successfully";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 7: SQL injection with mysqli_multi_query using $_GET parameter
function bad_case_7() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $search = $_GET['search'];
    $query = "SELECT * FROM products WHERE name LIKE '%" . $search . "%'; ";
    $query .= "UPDATE search_log SET count = count + 1 WHERE term = '" . $search . "'";
    // ruleid: php-common-sql-injection
    mysqli_multi_query($conn, $query);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 8: SQL injection with HTTP headers
function bad_case_8() {
    $conn = new mysqli("localhost", "user", "password", "database");
    $headers = getallheaders();
    $user_agent = $headers['User-Agent'];
    $query = "INSERT INTO access_logs (user_agent, access_time) VALUES ('" . $user_agent . "', NOW())";
    // ruleid: php-common-sql-injection
    $conn->query($query);
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 9: SQL injection with minimal processing of input
function bad_case_9() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $user_id = trim($_GET['user_id']);
    $query = "SELECT * FROM users WHERE id = " . $user_id . " LIMIT 1";
    // ruleid: php-common-sql-injection
    $stmt = $pdo->query($query);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "Welcome " . $user['name'];
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 10: SQL injection with string interpolation
function bad_case_10() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $date = $_POST['date'];
    $query = "SELECT * FROM events WHERE event_date = '$date'";
    // ruleid: php-common-sql-injection
    $result = mysqli_query($conn, $query);
    while($row = mysqli_fetch_assoc($result)) {
        echo $row['event_name'] . "<br>";
    }
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 11: SQL injection with multiple parameters
function bad_case_11() {
    $db = new SQLite3('database.sqlite');
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $query = "SELECT * FROM products WHERE price >= " . $min_price . " AND price <= " . $max_price;
    // ruleid: php-common-sql-injection
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ": $" . $row['price'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 12: SQL injection with JSON data from request
function bad_case_12() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $json_data = file_get_contents('php://input');
    $data = json_decode($json_data, true);
    $username = $data['username'];
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    // ruleid: php-common-sql-injection
    $stmt = $pdo->query($query);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode($user);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 13: SQL injection with conditional query building
function bad_case_13() {
    $conn = new mysqli("localhost", "user", "password", "database");
    $status = isset($_GET['status']) ? $_GET['status'] : 'active';
    $query = "SELECT * FROM orders WHERE status = '" . $status . "'";
    
    if (isset($_GET['date'])) {
        $date = $_GET['date'];
        $query .= " AND order_date = '" . $date . "'";
    }
    
    // ruleid: php-common-sql-injection
    $result = $conn->query($query);
    
    while($row = $result->fetch_assoc()) {
        echo "Order #" . $row["id"] . "<br>";
    }
    $conn->close();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 14: SQL injection with array parameter
function bad_case_14() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $product_ids = $_POST['product_ids'];
    $ids_string = implode(',', $product_ids);
    $query = "SELECT * FROM products WHERE id IN (" . $ids_string . ")";
    // ruleid: php-common-sql-injection
    $stmt = $pdo->query($query);
    
    foreach ($stmt as $row) {
        echo $row['name'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

// Example 15: SQL injection with URL parameter manipulation
function bad_case_15() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $sort = $_GET['sort'] ?? 'id';
    $direction = $_GET['direction'] ?? 'ASC';
    
    $query = "SELECT * FROM products ORDER BY " . $sort . " " . $direction . " LIMIT 10 OFFSET " . (($page - 1) * 10);
    // ruleid: php-common-sql-injection
    $result = mysqli_query($conn, $query);
    
    while($row = mysqli_fetch_assoc($result)) {
        echo $row['name'] . "<br>";
    }
    mysqli_close($conn);
}
// {/fact}

/**
 * True Negative Examples (Secure Code)
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 1: Secure query with PDO prepared statement
function good_case_1() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = ?";
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->execute([$id]);
    
    while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Name: " . $row["name"];
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 2: Secure query with mysqli prepared statement
function good_case_2() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $username = $_POST['username'];
    $query = "SELECT * FROM users WHERE username = ?";
    // ok: php-common-sql-injection
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    while($row = mysqli_fetch_assoc($result)) {
        echo $row['email'] . "<br>";
    }
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 3: Secure query with PDO named parameters
function good_case_3() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $product_id = $_REQUEST['product_id'];
    $query = "DELETE FROM products WHERE id = :id";
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':id', $product_id, PDO::PARAM_INT);
    $stmt->execute();
    echo "Product deleted successfully";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 4: Secure query with SQLite3 prepared statement
function good_case_4() {
    $db = new SQLite3('database.sqlite');
    $category = $_GET['category'];
    $query = "SELECT * FROM products WHERE category = :category";
    // ok: php-common-sql-injection
    $stmt = $db->prepare($query);
    $stmt->bindValue(':category', $category, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ": $" . $row['price'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 5: Secure query with mysqli prepared statement and multiple parameters
function good_case_5() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $email = $_POST['email'];
    $status = $_POST['status'];
    $query = "UPDATE users SET status = ? WHERE email = ?";
    // ok: php-common-sql-injection
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "ss", $status, $email);
    mysqli_stmt_execute($stmt);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 6: Secure query with PDO execute array
function good_case_6() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $search = $_GET['search'];
    $query = "SELECT * FROM products WHERE name LIKE ?";
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->execute(['%' . $search . '%']);
    
    foreach ($stmt as $row) {
        echo $row['name'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 7: Secure query with mysqli prepared statement and HTTP headers
function good_case_7() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $headers = getallheaders();
    $user_agent = $headers['User-Agent'];
    $query = "INSERT INTO access_logs (user_agent, access_time) VALUES (?, NOW())";
    // ok: php-common-sql-injection
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $user_agent);
    mysqli_stmt_execute($stmt);
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 8: Secure query with PDO and JSON data
function good_case_8() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $json_data = file_get_contents('php://input');
    $data = json_decode($json_data, true);
    $username = $data['username'];
    $query = "SELECT * FROM users WHERE username = :username";
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':username', $username, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo json_encode($user);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 9: Secure query with SQLite3 and multiple bind parameters
function good_case_9() {
    $db = new SQLite3('database.sqlite');
    $min_price = $_GET['min_price'];
    $max_price = $_GET['max_price'];
    $query = "SELECT * FROM products WHERE price >= :min AND price <= :max";
    // ok: php-common-sql-injection
    $stmt = $db->prepare($query);
    $stmt->bindValue(':min', $min_price, SQLITE3_FLOAT);
    $stmt->bindValue(':max', $max_price, SQLITE3_FLOAT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ": $" . $row['price'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 10: Secure query with mysqli prepared statement and conditional query building
function good_case_10() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $status = isset($_GET['status']) ? $_GET['status'] : 'active';
    $has_date = isset($_GET['date']);
    
    if ($has_date) {
        $query = "SELECT * FROM orders WHERE status = ? AND order_date = ?";
        // ok: php-common-sql-injection
        $stmt = mysqli_prepare($conn, $query);
        $date = $_GET['date'];
        mysqli_stmt_bind_param($stmt, "ss", $status, $date);
    } else {
        $query = "SELECT * FROM orders WHERE status = ?";
        // ok: php-common-sql-injection
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $status);
    }
    
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    while($row = mysqli_fetch_assoc($result)) {
        echo "Order #" . $row["id"] . "<br>";
    }
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 11: Secure query with PDO and array parameters
function good_case_11() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $product_ids = $_POST['product_ids'];
    
    // Create placeholders for each ID
    $placeholders = implode(',', array_fill(0, count($product_ids), '?'));
    $query = "SELECT * FROM products WHERE id IN ($placeholders)";
    
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->execute($product_ids);
    
    foreach ($stmt as $row) {
        echo $row['name'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 12: Secure query with mysqli prepared statement and pagination
function good_case_12() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $sort = $_GET['sort'] ?? 'id';
    
    // Whitelist validation for sort column
    $allowed_columns = ['id', 'name', 'price', 'date_added'];
    if (!in_array($sort, $allowed_columns)) {
        $sort = 'id'; // Default to safe value
    }
    
    $direction = $_GET['direction'] ?? 'ASC';
    if ($direction !== 'ASC' && $direction !== 'DESC') {
        $direction = 'ASC'; // Default to safe value
    }
    
    $offset = ($page - 1) * 10;
    $query = "SELECT * FROM products ORDER BY $sort $direction LIMIT 10 OFFSET ?";
    // ok: php-common-sql-injection
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "i", $offset);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    
    while($row = mysqli_fetch_assoc($result)) {
        echo $row['name'] . "<br>";
    }
    mysqli_close($conn);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 13: Secure query with PDO and type casting
function good_case_13() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $user_id = (int)$_GET['user_id']; // Type casting to integer
    $query = "SELECT * FROM users WHERE id = $user_id LIMIT 1";
    // ok: php-common-sql-injection
    $stmt = $pdo->query($query);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    echo "Welcome " . $user['name'];
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 14: Secure query with PDO and prepared statement for LIKE query
function good_case_14() {
    $pdo = new PDO('mysql:host=localhost;dbname=testdb', 'username', 'password');
    $search = $_GET['search'];
    $search_param = '%' . $search . '%';
    $query = "SELECT * FROM products WHERE name LIKE :search OR description LIKE :search";
    // ok: php-common-sql-injection
    $stmt = $pdo->prepare($query);
    $stmt->bindParam(':search', $search_param, PDO::PARAM_STR);
    $stmt->execute();
    
    foreach ($stmt as $row) {
        echo $row['name'] . ": " . $row['description'] . "<br>";
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// Example 15: Secure query with mysqli prepared statement and transaction
function good_case_15() {
    $conn = mysqli_connect("localhost", "user", "password", "database");
    mysqli_autocommit($conn, FALSE);
    
    $user_id = $_POST['user_id'];
    $amount = $_POST['amount'];
    
    $query1 = "UPDATE accounts SET balance = balance - ? WHERE user_id = ?";
    // ok: php-common-sql-injection
    $stmt1 = mysqli_prepare($conn, $query1);
    mysqli_stmt_bind_param($stmt1, "di", $amount, $user_id);
    mysqli_stmt_execute($stmt1);
    
    $query2 = "INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, 'withdrawal')";
    // ok: php-common-sql-injection
    $stmt2 = mysqli_prepare($conn, $query2);
    mysqli_stmt_bind_param($stmt2, "id", $user_id, $amount);
    mysqli_stmt_execute($stmt2);
    
    mysqli_commit($conn);
    mysqli_close($conn);
}
// {/fact}
?>