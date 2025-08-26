<?php
// Import necessary CodeIgniter classes
use CodeIgniter\Controller;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\Database\ConnectionInterface;

/**
 * True Positive Examples (Vulnerable Code)
 */
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_1()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM users WHERE id = " . $userId);
    
    $results = $query->getResult();
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_2()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $username = $request->getPost('username');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $sql = "SELECT * FROM users WHERE username = '" . $username . "'";
    $query = $db->query($sql);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_3()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $sortColumn = $request->getGet('sort');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products ORDER BY " . $sortColumn);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_4()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $tableName = $request->getGet('table');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM " . $tableName);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_5()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $id = $request->getGet('id');
    $name = $request->getGet('name');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("UPDATE users SET name = '$name' WHERE id = $id");
    
    return $query;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_6()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $searchTerm = $request->getGet('search');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products WHERE name LIKE '%" . $searchTerm . "%'");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_7()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $ids = $request->getGet('ids'); // Expecting comma-separated list
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM users WHERE id IN (" . $ids . ")");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_8()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $limit = $request->getGet('limit');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products LIMIT " . $limit);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_9()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    $field = $request->getGet('field');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT $field FROM users WHERE id = $userId");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_10()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $email = $request->getPost('email');
    $password = $request->getPost('password');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM users WHERE email = '$email' AND password = '$password'");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_11()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $condition = $request->getGet('condition');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products WHERE " . $condition);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_12()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    
    // Attempt to sanitize but still vulnerable
    $userId = trim($userId);
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("DELETE FROM users WHERE id = " . $userId);
    
    return $query;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_13()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $table = $request->getGet('table');
    $column = $request->getGet('column');
    $value = $request->getGet('value');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM $table WHERE $column = '$value'");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_14()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $joinTable = $request->getGet('join');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products JOIN " . $joinTable . " ON products.id = " . $joinTable . ".product_id");
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

function bad_case_15()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $groupBy = $request->getGet('group');
    
    // ruleid: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT category, COUNT(*) as count FROM products GROUP BY " . $groupBy);
    
    return $query->getResult();
}
// {/fact}

/**
 * True Negative Examples (Safe Code)
 */
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_1()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    
    // ok: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM users WHERE id = ?", [$userId]);
    
    $results = $query->getResult();
    return $results;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_2()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $username = $request->getPost('username');
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('users');
    $builder->where('username', $username);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_3()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $sortColumn = $request->getGet('sort');
    
    // Validate sort column against allowed list
    $allowedColumns = ['name', 'price', 'date_added'];
    if (!in_array($sortColumn, $allowedColumns)) {
        $sortColumn = 'name'; // Default safe value
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM products ORDER BY " . $sortColumn);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_4()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $tableName = $request->getGet('table');
    
    // Validate table name against allowed list
    $allowedTables = ['products', 'categories', 'tags'];
    if (!in_array($tableName, $allowedTables)) {
        $tableName = 'products'; // Default safe value
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT * FROM " . $tableName);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_5()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $id = $request->getGet('id');
    $name = $request->getGet('name');
    
    // ok: php-codeigniter-sql-injection-ide
    $query = $db->query("UPDATE users SET name = ? WHERE id = ?", [$name, $id]);
    
    return $query;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_6()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $searchTerm = $request->getGet('search');
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('products');
    $builder->like('name', $searchTerm);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_7()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $ids = $request->getGet('ids'); // Expecting comma-separated list
    $idArray = explode(',', $ids);
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('users');
    $builder->whereIn('id', $idArray);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_8()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $limit = $request->getGet('limit');
    
    // Validate limit is a number
    if (!is_numeric($limit) || $limit < 1) {
        $limit = 10; // Default safe value
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('products');
    $builder->limit($limit);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_9()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    $field = $request->getGet('field');
    
    // Validate field against allowed list
    $allowedFields = ['name', 'email', 'created_at'];
    if (!in_array($field, $allowedFields)) {
        $field = 'name'; // Default safe value
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $query = $db->query("SELECT $field FROM users WHERE id = ?", [$userId]);
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_10()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $email = $request->getPost('email');
    $password = $request->getPost('password');
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('users');
    $builder->where('email', $email);
    $builder->where('password', $password);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_11()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $minPrice = $request->getGet('min_price');
    $maxPrice = $request->getGet('max_price');
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('products');
    if (is_numeric($minPrice)) {
        $builder->where('price >=', $minPrice);
    }
    if (is_numeric($maxPrice)) {
        $builder->where('price <=', $maxPrice);
    }
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_12()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $userId = $request->getGet('id');
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('users');
    $builder->where('id', $userId);
    $builder->delete();
    
    return true;
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_13()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $table = $request->getGet('table');
    $column = $request->getGet('column');
    $value = $request->getGet('value');
    
    // Validate table and column against allowed lists
    $allowedTables = ['products', 'categories'];
    $allowedColumns = ['name', 'description', 'status'];
    
    if (!in_array($table, $allowedTables)) {
        $table = 'products';
    }
    
    if (!in_array($column, $allowedColumns)) {
        $column = 'name';
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table($table);
    $builder->where($column, $value);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_14()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $joinTable = $request->getGet('join');
    
    // Validate join table against allowed list
    $allowedJoinTables = ['categories', 'suppliers', 'inventory'];
    if (!in_array($joinTable, $allowedJoinTables)) {
        $joinTable = 'categories';
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('products');
    $builder->join($joinTable, "products.id = {$joinTable}.product_id");
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

function good_case_15()
{
    $db = \Config\Database::connect();
    $request = \Config\Services::request();
    
    $groupBy = $request->getGet('group');
    
    // Validate group by column against allowed list
    $allowedGroupColumns = ['category', 'supplier', 'status'];
    if (!in_array($groupBy, $allowedGroupColumns)) {
        $groupBy = 'category';
    }
    
    // ok: php-codeigniter-sql-injection-ide
    $builder = $db->table('products');
    $builder->select("$groupBy, COUNT(*) as count");
    $builder->groupBy($groupBy);
    $query = $builder->get();
    
    return $query->getResult();
}
// {/fact}