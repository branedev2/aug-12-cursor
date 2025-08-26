<?php
/**
 * Test cases for PHP SQLite3 SQL Injection vulnerability detection
 * Rule ID: php-sqlite3-sql-injection
 * CWE: CWE-89
 */

// ==================== VULNERABLE CASES ====================

/**
 * Direct use of GET parameter in SQLite3 query without sanitization
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1() {
    $db = new SQLite3('database.sqlite');
    $id = $_GET['id'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM users WHERE id = $id");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['email'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using POST data directly in a query
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2() {
    $db = new SQLite3('database.sqlite');
    $username = $_POST['username'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM users WHERE username = '$username'");
    
    $user = $results->fetchArray();
    echo "Welcome, " . $user['name'];
    $db->close();
}
// {/fact}

/**
 * Using HTTP header in a query
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3() {
    $db = new SQLite3('database.sqlite');
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    
    // ruleid: php-sqlite3-sql-injection
    $db->query("INSERT INTO access_logs (user_agent, timestamp) VALUES ('$userAgent', datetime('now'))");
    
    echo "Access logged";
    $db->close();
}
// {/fact}

/**
 * Using cookie data in a query
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4() {
    $db = new SQLite3('database.sqlite');
    $sessionId = $_COOKIE['session_id'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM sessions WHERE session_id = '$sessionId'");
    
    if ($results->fetchArray()) {
        echo "Session valid";
    }
    $db->close();
}
// {/fact}

/**
 * Using request data with string concatenation
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5() {
    $db = new SQLite3('database.sqlite');
    $category = $_REQUEST['category'];
    $query = "SELECT * FROM products WHERE category = '" . $category . "'";
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query($query);
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using multiple GET parameters in a complex query
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6() {
    $db = new SQLite3('database.sqlite');
    $minPrice = $_GET['min_price'];
    $maxPrice = $_GET['max_price'];
    $category = $_GET['category'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM products WHERE price >= $minPrice AND price <= $maxPrice AND category = '$category'");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters in an UPDATE statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7() {
    $db = new SQLite3('database.sqlite');
    $newEmail = $_POST['email'];
    $userId = $_POST['user_id'];
    
    // ruleid: php-sqlite3-sql-injection
    $db->query("UPDATE users SET email = '$newEmail' WHERE id = $userId");
    
    echo "Email updated successfully";
    $db->close();
}
// {/fact}

/**
 * Using query parameters in a DELETE statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8() {
    $db = new SQLite3('database.sqlite');
    $commentId = $_GET['comment_id'];
    
    // ruleid: php-sqlite3-sql-injection
    $db->query("DELETE FROM comments WHERE id = $commentId");
    
    echo "Comment deleted";
    $db->close();
}
// {/fact}

/**
 * Using query parameters with minimal processing
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9() {
    $db = new SQLite3('database.sqlite');
    $search = strtolower($_GET['search']);
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM products WHERE LOWER(name) LIKE '%$search%'");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters with insufficient escaping
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10() {
    $db = new SQLite3('database.sqlite');
    $username = str_replace("'", "''", $_POST['username']); // Insufficient for complete protection
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM users WHERE username = '$username'");
    
    $user = $results->fetchArray();
    echo "Welcome, " . $user['name'];
    $db->close();
}
// {/fact}

/**
 * Using query parameters in a JOIN statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11() {
    $db = new SQLite3('database.sqlite');
    $orderId = $_GET['order_id'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT o.id, p.name, o.quantity FROM orders o JOIN products p ON o.product_id = p.id WHERE o.id = $orderId");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['quantity'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters in a GROUP BY statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12() {
    $db = new SQLite3('database.sqlite');
    $field = $_GET['group_by'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT $field, COUNT(*) as count FROM products GROUP BY $field");
    
    while ($row = $results->fetchArray()) {
        echo $row[$field] . ': ' . $row['count'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters in an ORDER BY statement
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13() {
    $db = new SQLite3('database.sqlite');
    $sortField = $_GET['sort'];
    $sortOrder = $_GET['order'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM products ORDER BY $sortField $sortOrder");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters in a LIMIT clause
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14() {
    $db = new SQLite3('database.sqlite');
    $limit = $_GET['limit'];
    $offset = $_GET['offset'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM products LIMIT $limit OFFSET $offset");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using query parameters in a complex subquery
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15() {
    $db = new SQLite3('database.sqlite');
    $categoryId = $_GET['category_id'];
    
    // ruleid: php-sqlite3-sql-injection
    $results = $db->query("SELECT * FROM products WHERE id IN (SELECT product_id FROM product_categories WHERE category_id = $categoryId)");
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

// ==================== SAFE CASES ====================

/**
 * Using prepared statement with bindValue and explicit type for GET parameter
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1() {
    $db = new SQLite3('database.sqlite');
    $id = $_GET['id'];
    
    $stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['email'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with bindParam and explicit type for POST data
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2() {
    $db = new SQLite3('database.sqlite');
    $username = $_POST['username'];
    
    $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
    // ok: php-sqlite3-sql-injection
    $stmt->bindParam(':username', $username, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    $user = $results->fetchArray();
    echo "Welcome, " . $user['name'];
    $db->close();
}
// {/fact}

/**
 * Using prepared statement for HTTP header data
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3() {
    $db = new SQLite3('database.sqlite');
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    
    $stmt = $db->prepare("INSERT INTO access_logs (user_agent, timestamp) VALUES (:user_agent, datetime('now'))");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':user_agent', $userAgent, SQLITE3_TEXT);
    $stmt->execute();
    
    echo "Access logged";
    $db->close();
}
// {/fact}

/**
 * Using prepared statement for cookie data
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4() {
    $db = new SQLite3('database.sqlite');
    $sessionId = $_COOKIE['session_id'];
    
    $stmt = $db->prepare("SELECT * FROM sessions WHERE session_id = :session_id");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':session_id', $sessionId, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    if ($results->fetchArray()) {
        echo "Session valid";
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with request data
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5() {
    $db = new SQLite3('database.sqlite');
    $category = $_REQUEST['category'];
    
    $stmt = $db->prepare("SELECT * FROM products WHERE category = :category");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':category', $category, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with multiple GET parameters
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6() {
    $db = new SQLite3('database.sqlite');
    $minPrice = $_GET['min_price'];
    $maxPrice = $_GET['max_price'];
    $category = $_GET['category'];
    
    $stmt = $db->prepare("SELECT * FROM products WHERE price >= :min_price AND price <= :max_price AND category = :category");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':min_price', $minPrice, SQLITE3_FLOAT);
    $stmt->bindValue(':max_price', $maxPrice, SQLITE3_FLOAT);
    $stmt->bindValue(':category', $category, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement for UPDATE with input validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7() {
    $db = new SQLite3('database.sqlite');
    $newEmail = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $userId = filter_input(INPUT_POST, 'user_id', FILTER_VALIDATE_INT);
    
    if ($newEmail && $userId) {
        $stmt = $db->prepare("UPDATE users SET email = :email WHERE id = :id");
        // ok: php-sqlite3-sql-injection
        $stmt->bindValue(':email', $newEmail, SQLITE3_TEXT);
        $stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo "Email updated successfully";
    } else {
        echo "Invalid input";
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement for DELETE with input validation
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8() {
    $db = new SQLite3('database.sqlite');
    $commentId = filter_input(INPUT_GET, 'comment_id', FILTER_VALIDATE_INT);
    
    if ($commentId) {
        $stmt = $db->prepare("DELETE FROM comments WHERE id = :id");
        // ok: php-sqlite3-sql-injection
        $stmt->bindValue(':id', $commentId, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo "Comment deleted";
    } else {
        echo "Invalid comment ID";
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with LIKE pattern
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9() {
    $db = new SQLite3('database.sqlite');
    $search = strtolower($_GET['search']);
    $searchPattern = '%' . $search . '%';
    
    $stmt = $db->prepare("SELECT * FROM products WHERE LOWER(name) LIKE :search");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':search', $searchPattern, SQLITE3_TEXT);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with both validation and sanitization
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10() {
    $db = new SQLite3('database.sqlite');
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    
    if ($username) {
        $stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
        // ok: php-sqlite3-sql-injection
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $results = $stmt->execute();
        
        $user = $results->fetchArray();
        echo "Welcome, " . $user['name'];
    } else {
        echo "Invalid username";
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with JOIN
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11() {
    $db = new SQLite3('database.sqlite');
    $orderId = filter_input(INPUT_GET, 'order_id', FILTER_VALIDATE_INT);
    
    $stmt = $db->prepare("SELECT o.id, p.name, o.quantity FROM orders o JOIN products p ON o.product_id = p.id WHERE o.id = :order_id");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':order_id', $orderId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': ' . $row['quantity'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using whitelist validation for dynamic column names
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12() {
    $db = new SQLite3('database.sqlite');
    $field = $_GET['group_by'];
    
    // Whitelist validation for column names
    $allowedFields = ['category', 'supplier', 'status'];
    if (in_array($field, $allowedFields)) {
        $stmt = $db->prepare("SELECT $field, COUNT(*) as count FROM products GROUP BY $field");
        // ok: php-sqlite3-sql-injection
        $results = $stmt->execute();
        
        while ($row = $results->fetchArray()) {
            echo $row[$field] . ': ' . $row['count'] . '<br>';
        }
    } else {
        echo "Invalid field";
    }
    $db->close();
}
// {/fact}

/**
 * Using whitelist validation for ORDER BY parameters
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13() {
    $db = new SQLite3('database.sqlite');
    $sortField = $_GET['sort'];
    $sortOrder = $_GET['order'];
    
    // Whitelist validation
    $allowedFields = ['name', 'price', 'date_added'];
    $allowedOrders = ['ASC', 'DESC'];
    
    if (in_array($sortField, $allowedFields) && in_array(strtoupper($sortOrder), $allowedOrders)) {
        $stmt = $db->prepare("SELECT * FROM products ORDER BY $sortField " . strtoupper($sortOrder));
        // ok: php-sqlite3-sql-injection
        $results = $stmt->execute();
        
        while ($row = $results->fetchArray()) {
            echo $row['name'] . ': $' . $row['price'] . '<br>';
        }
    } else {
        echo "Invalid sort parameters";
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with LIMIT and OFFSET
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14() {
    $db = new SQLite3('database.sqlite');
    $limit = filter_input(INPUT_GET, 'limit', FILTER_VALIDATE_INT);
    $offset = filter_input(INPUT_GET, 'offset', FILTER_VALIDATE_INT);
    
    // Set defaults and validate ranges
    $limit = ($limit && $limit > 0 && $limit <= 100) ? $limit : 10;
    $offset = ($offset && $offset >= 0) ? $offset : 0;
    
    $stmt = $db->prepare("SELECT * FROM products LIMIT :limit OFFSET :offset");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
    $stmt->bindValue(':offset', $offset, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}

/**
 * Using prepared statement with subquery
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15() {
    $db = new SQLite3('database.sqlite');
    $categoryId = filter_input(INPUT_GET, 'category_id', FILTER_VALIDATE_INT);
    
    $stmt = $db->prepare("SELECT * FROM products WHERE id IN (SELECT product_id FROM product_categories WHERE category_id = :category_id)");
    // ok: php-sqlite3-sql-injection
    $stmt->bindValue(':category_id', $categoryId, SQLITE3_INTEGER);
    $results = $stmt->execute();
    
    while ($row = $results->fetchArray()) {
        echo $row['name'] . ': $' . $row['price'] . '<br>';
    }
    $db->close();
}
// {/fact}
?>