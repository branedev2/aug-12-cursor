<?php
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positives (Vulnerable Code)

function bad_case_1() {
    // Direct injection of GET parameter into SQLite3 query
    $db = new SQLite3('database.db');
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['email'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2() {
    // POST data directly used in query with string concatenation
    $db = new SQLite3('users.db');
    $username = $_POST['username'];
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    // ruleid: php-sqlite3-sql-injection-ide
    $result = $db->exec($query);
    
    echo "User updated successfully";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3() {
    // Request parameter used in LIKE clause
    $db = new SQLite3('products.db');
    $search = $_REQUEST['search'];
    $query = "SELECT * FROM products WHERE name LIKE '%" . $search . "%'";
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    $products = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $products[] = $row;
    }
    echo json_encode($products);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4() {
    // Cookie value used in ORDER BY clause
    $db = new SQLite3('orders.db');
    $sortColumn = $_COOKIE['sort_by'];
    $query = "SELECT * FROM orders ORDER BY " . $sortColumn;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo $row['order_id'] . ' - ' . $row['total'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5() {
    // HTTP header value used in query
    $db = new SQLite3('logs.db');
    $headers = getallheaders();
    $userAgent = $headers['User-Agent'];
    $query = "INSERT INTO access_logs (user_agent, timestamp) VALUES ('" . $userAgent . "', " . time() . ")";
    // ruleid: php-sqlite3-sql-injection-ide
    $db->exec($query);
    
    echo "Log entry created";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6() {
    // Multiple GET parameters used in query
    $db = new SQLite3('products.db');
    $category = $_GET['category'];
    $minPrice = $_GET['min_price'];
    $query = "SELECT * FROM products WHERE category = '" . $category . "' AND price >= " . $minPrice;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7() {
    // JSON POST data used in query
    $db = new SQLite3('customers.db');
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $customerId = $jsonData['customer_id'];
    $query = "DELETE FROM customers WHERE id = " . $customerId;
    // ruleid: php-sqlite3-sql-injection-ide
    $db->exec($query);
    
    echo "Customer deleted";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8() {
    // Input processed but still vulnerable
    $db = new SQLite3('blog.db');
    $tagId = $_GET['tag_id'];
    $limit = intval($_GET['limit']); // This one is safe
    $query = "SELECT * FROM posts WHERE tag_id = " . $tagId . " LIMIT " . $limit;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo '<h2>' . $row['title'] . '</h2>';
        echo '<p>' . $row['content'] . '</p>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9() {
    // Input used in complex query
    $db = new SQLite3('inventory.db');
    $locationId = $_POST['location_id'];
    $query = "SELECT i.name, i.quantity, l.name as location 
              FROM inventory i 
              JOIN locations l ON i.location_id = l.id 
              WHERE l.id = " . $locationId;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    $items = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $items[] = $row;
    }
    echo json_encode($items);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10() {
    // Input used in UPDATE statement
    $db = new SQLite3('users.db');
    $userId = $_POST['user_id'];
    $status = $_POST['status'];
    $query = "UPDATE users SET status = '" . $status . "' WHERE id = " . $userId;
    // ruleid: php-sqlite3-sql-injection-ide
    $db->exec($query);
    
    echo "User status updated";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11() {
    // Input used in IN clause
    $db = new SQLite3('products.db');
    $categoryIds = $_GET['category_ids']; // Expecting something like "1,2,3"
    $query = "SELECT * FROM products WHERE category_id IN (" . $categoryIds . ")";
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ' - $' . $row['price'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12() {
    // Input used with minimal processing
    $db = new SQLite3('comments.db');
    $postId = trim($_GET['post_id']);
    $query = "SELECT * FROM comments WHERE post_id = " . $postId . " ORDER BY created_at DESC";
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo '<div class="comment">';
        echo '<p>' . $row['content'] . '</p>';
        echo '<small>By: ' . $row['author'] . '</small>';
        echo '</div>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13() {
    // Input used in subquery
    $db = new SQLite3('orders.db');
    $userId = $_GET['user_id'];
    $query = "SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE department_id = " . $userId . ")";
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    $orders = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $orders[] = $row;
    }
    echo json_encode($orders);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14() {
    // Input used in JOIN condition
    $db = new SQLite3('employees.db');
    $departmentId = $_POST['department_id'];
    $query = "SELECT e.name, e.position, d.name as department 
              FROM employees e 
              JOIN departments d ON e.department_id = d.id 
              WHERE d.id = " . $departmentId;
    // ruleid: php-sqlite3-sql-injection-ide
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ' - ' . $row['position'] . ' (' . $row['department'] . ')<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15() {
    // Input used in CREATE TABLE statement
    $db = new SQLite3('dynamic.db');
    $tableName = $_POST['table_name'];
    $query = "CREATE TABLE IF NOT EXISTS " . $tableName . " (id INTEGER PRIMARY KEY, name TEXT, value TEXT)";
    // ruleid: php-sqlite3-sql-injection-ide
    $db->exec($query);
    
    echo "Table created successfully";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negatives (Safe Code)

function good_case_1() {
    // Using prepared statement with parameter binding
    $db = new SQLite3('database.db');
    $id = $_GET['id'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM users WHERE id = :id');
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['email'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2() {
    // Using prepared statement with positional parameters
    $db = new SQLite3('users.db');
    $username = $_POST['username'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->bindValue(1, $username, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo $row['name'] . ': ' . $row['email'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3() {
    // Using prepared statement with multiple parameters
    $db = new SQLite3('products.db');
    $category = $_REQUEST['category'];
    $minPrice = $_REQUEST['min_price'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM products WHERE category = :category AND price >= :price');
    $stmt->bindValue(':category', $category, SQLITE3_TEXT);
    $stmt->bindValue(':price', $minPrice, SQLITE3_FLOAT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4() {
    // Using prepared statement with LIKE clause
    $db = new SQLite3('products.db');
    $search = $_GET['search'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM products WHERE name LIKE :search');
    $stmt->bindValue(':search', '%' . $search . '%', SQLITE3_TEXT);
    $results = $stmt->execute();
    
    $products = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $products[] = $row;
    }
    echo json_encode($products);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5() {
    // Using prepared statement for INSERT
    $db = new SQLite3('logs.db');
    $headers = getallheaders();
    $userAgent = $headers['User-Agent'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('INSERT INTO access_logs (user_agent, timestamp) VALUES (:user_agent, :timestamp)');
    $stmt->bindValue(':user_agent', $userAgent, SQLITE3_TEXT);
    $stmt->bindValue(':timestamp', time(), SQLITE3_INTEGER);
    $stmt->execute();
    
    echo "Log entry created";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6() {
    // Using prepared statement for DELETE
    $db = new SQLite3('customers.db');
    $jsonData = json_decode(file_get_contents('php://input'), true);
    $customerId = $jsonData['customer_id'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('DELETE FROM customers WHERE id = :id');
    $stmt->bindValue(':id', $customerId, SQLITE3_INTEGER);
    $stmt->execute();
    
    echo "Customer deleted";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7() {
    // Using prepared statement with ORDER BY (using whitelist)
    $db = new SQLite3('orders.db');
    $sortColumn = $_COOKIE['sort_by'];
    
    // Whitelist of allowed columns
    $allowedColumns = ['id', 'date', 'total', 'status'];
    if (!in_array($sortColumn, $allowedColumns)) {
        $sortColumn = 'id'; // Default safe value
    }
    
    // ok: php-sqlite3-sql-injection-ide
    $query = "SELECT * FROM orders ORDER BY " . $sortColumn;
    $results = $db->query($query);
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo $row['order_id'] . ' - ' . $row['total'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8() {
    // Using prepared statement with complex query
    $db = new SQLite3('inventory.db');
    $locationId = $_POST['location_id'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT i.name, i.quantity, l.name as location 
                         FROM inventory i 
                         JOIN locations l ON i.location_id = l.id 
                         WHERE l.id = :location_id');
    $stmt->bindValue(':location_id', $locationId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    $items = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $items[] = $row;
    }
    echo json_encode($items);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9() {
    // Using prepared statement for UPDATE
    $db = new SQLite3('users.db');
    $userId = $_POST['user_id'];
    $status = $_POST['status'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('UPDATE users SET status = :status WHERE id = :id');
    $stmt->bindValue(':status', $status, SQLITE3_TEXT);
    $stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
    $stmt->execute();
    
    echo "User status updated";
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10() {
    // Using input validation and prepared statement
    $db = new SQLite3('comments.db');
    $postId = $_GET['post_id'];
    
    if (!is_numeric($postId)) {
        die("Invalid post ID");
    }
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM comments WHERE post_id = :post_id ORDER BY created_at DESC');
    $stmt->bindValue(':post_id', $postId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo '<div class="comment">';
        echo '<p>' . htmlspecialchars($row['content']) . '</p>';
        echo '<small>By: ' . htmlspecialchars($row['author']) . '</small>';
        echo '</div>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11() {
    // Using prepared statement with IN clause and array parameters
    $db = new SQLite3('products.db');
    $categoryIds = explode(',', $_GET['category_ids']);
    
    // Prepare placeholders for each ID
    $placeholders = implode(',', array_fill(0, count($categoryIds), '?'));
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare("SELECT * FROM products WHERE category_id IN ($placeholders)");
    
    // Bind each value
    foreach ($categoryIds as $index => $id) {
        $stmt->bindValue($index + 1, $id, SQLITE3_INTEGER);
    }
    
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ' - $' . $row['price'] . '<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12() {
    // Using prepared statement with subquery
    $db = new SQLite3('orders.db');
    $userId = $_GET['user_id'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM orders WHERE user_id IN (SELECT id FROM users WHERE department_id = :dept_id)');
    $stmt->bindValue(':dept_id', $userId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    $orders = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $orders[] = $row;
    }
    echo json_encode($orders);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13() {
    // Using prepared statement with JOIN condition
    $db = new SQLite3('employees.db');
    $departmentId = $_POST['department_id'];
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT e.name, e.position, d.name as department 
                         FROM employees e 
                         JOIN departments d ON e.department_id = d.id 
                         WHERE d.id = :dept_id');
    $stmt->bindValue(':dept_id', $departmentId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ' - ' . $row['position'] . ' (' . $row['department'] . ')<br>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14() {
    // Using filter_input for validation before query
    $db = new SQLite3('blog.db');
    $tagId = filter_input(INPUT_GET, 'tag_id', FILTER_VALIDATE_INT);
    $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT) ?: 10;
    
    if ($tagId === false || $tagId === null) {
        die("Invalid tag ID");
    }
    
    // ok: php-sqlite3-sql-injection-ide
    $stmt = $db->prepare('SELECT * FROM posts WHERE tag_id = :tag_id LIMIT :limit');
    $stmt->bindValue(':tag_id', $tagId, SQLITE3_INTEGER);
    $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        echo '<h2>' . htmlspecialchars($row['title']) . '</h2>';
        echo '<p>' . htmlspecialchars($row['content']) . '</p>';
    }
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15() {
    // Using whitelist for table name
    $db = new SQLite3('dynamic.db');
    $tableName = $_POST['table_name'];
    
    // Whitelist of allowed table names
    $allowedTables = ['user_data', 'product_data', 'order_data', 'log_data'];
    
    if (!in_array($tableName, $allowedTables)) {
        die("Invalid table name");
    }
    
    // ok: php-sqlite3-sql-injection-ide
    $query = "CREATE TABLE IF NOT EXISTS " . $tableName . " (id INTEGER PRIMARY KEY, name TEXT, value TEXT)";
    $db->exec($query);
    
    echo "Table created successfully";
}
// {/fact}
?>