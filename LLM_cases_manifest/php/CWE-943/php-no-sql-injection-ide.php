<?php
// {fact rule=nosql-injection@v1.0 defects=1}
// This file contains examples of NoSQL injection vulnerabilities in PHP
// focusing on MongoDB and DynamoDB interactions

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // MongoDB NoSQL injection via GET parameter
    $username = $_GET['username'];
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    $filter = ['username' => $username];
    $query = new MongoDB\Driver\Query($filter);
    
    // ruleid: php-no-sql-injection-ide
    $cursor = $manager->executeQuery('mydb.users', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_2() {
    // MongoDB NoSQL injection via POST parameter with direct object construction
    $userId = $_POST['id'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->findOne(['_id' => $userId]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_3() {
    // MongoDB NoSQL injection via JSON string construction
    $searchTerm = $_GET['search'];
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    $queryString = '{"name": "' . $searchTerm . '"}';
    $filter = json_decode($queryString, true);
    $query = new MongoDB\Driver\Query($filter);
    
    // ruleid: php-no-sql-injection-ide
    $cursor = $manager->executeQuery('mydb.products', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_4() {
    // MongoDB NoSQL injection with operator in query
    $minAge = $_POST['min_age'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find(['age' => ['$gt' => $minAge]]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_5() {
    // MongoDB NoSQL injection with request header
    $apiKey = $_SERVER['HTTP_X_API_KEY'];
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    $filter = ['api_key' => $apiKey];
    $query = new MongoDB\Driver\Query($filter);
    
    // ruleid: php-no-sql-injection-ide
    $cursor = $manager->executeQuery('mydb.api_users', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_6() {
    // DynamoDB NoSQL injection with cookie value
    $sessionId = $_COOKIE['session_id'];
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ruleid: php-no-sql-injection-ide
    $result = $dynamodb->getItem([
        'TableName' => 'Sessions',
        'Key' => ['session_id' => ['S' => $sessionId]]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_7() {
    // MongoDB NoSQL injection with array construction
    $tags = explode(',', $_GET['tags']);
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->blog->posts;
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find(['tags' => ['$in' => $tags]]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_8() {
    // MongoDB NoSQL injection with string interpolation
    $category = $_POST['category'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    $queryString = "{'category': '$category'}";
    $filter = json_decode($queryString, true);
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find($filter);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_9() {
    // DynamoDB NoSQL injection with complex query
    $userId = $_GET['user_id'];
    $status = $_GET['status'];
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ruleid: php-no-sql-injection-ide
    $result = $dynamodb->query([
        'TableName' => 'Orders',
        'KeyConditionExpression' => 'user_id = :uid AND order_status = :status',
        'ExpressionAttributeValues' => [
            ':uid' => ['S' => $userId],
            ':status' => ['S' => $status]
        ]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_10() {
    // MongoDB NoSQL injection with regex
    $searchPattern = $_POST['pattern'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->library->books;
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find([
        'title' => ['$regex' => $searchPattern]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_11() {
    // MongoDB NoSQL injection with projection
    $username = $_GET['username'];
    $fields = $_GET['fields'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    $fieldsArray = explode(',', $fields);
    $projection = [];
    foreach ($fieldsArray as $field) {
        $projection[$field] = 1;
    }
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->findOne(
        ['username' => $username],
        ['projection' => $projection]
    );
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_12() {
    // DynamoDB NoSQL injection with update expression
    $productId = $_POST['product_id'];
    $newPrice = $_POST['price'];
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ruleid: php-no-sql-injection-ide
    $result = $dynamodb->updateItem([
        'TableName' => 'Products',
        'Key' => ['product_id' => ['S' => $productId]],
        'UpdateExpression' => 'SET price = :p',
        'ExpressionAttributeValues' => [
            ':p' => ['N' => $newPrice]
        ]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_13() {
    // MongoDB NoSQL injection with aggregation pipeline
    $department = $_GET['department'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->company->employees;
    
    $pipeline = [
        ['$match' => ['department' => $department]],
        ['$group' => ['_id' => '$position', 'count' => ['$sum' => 1]]]
    ];
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->aggregate($pipeline);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_14() {
    // MongoDB NoSQL injection with sort operation
    $sortField = $_GET['sort_by'];
    $sortDir = $_GET['sort_dir'] === 'desc' ? -1 : 1;
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    $options = [
        'sort' => [$sortField => $sortDir]
    ];
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find([], $options);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=1}

function bad_case_15() {
    // MongoDB NoSQL injection with multiple conditions
    $minPrice = $_POST['min_price'];
    $maxPrice = $_POST['max_price'];
    $category = $_POST['category'];
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    // ruleid: php-no-sql-injection-ide
    $result = $collection->find([
        'price' => [
            '$gte' => $minPrice,
            '$lte' => $maxPrice
        ],
        'category' => $category
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // MongoDB safe query with parameter casting
    $username = (string)$_GET['username'];
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    
    // ok: php-no-sql-injection-ide
    $filter = ['username' => htmlspecialchars($username, ENT_QUOTES, 'UTF-8')];
    $query = new MongoDB\Driver\Query($filter);
    $cursor = $manager->executeQuery('mydb.users', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_2() {
    // MongoDB safe query with validation
    $userId = $_POST['id'];
    
    // Input validation
    if (!preg_match('/^[0-9a-f]{24}$/', $userId)) {
        die("Invalid user ID format");
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->findOne(['_id' => new MongoDB\BSON\ObjectId($userId)]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_3() {
    // MongoDB safe query with whitelisting
    $searchTerm = $_GET['search'];
    $allowedFields = ['name', 'category', 'tags'];
    
    $field = $_GET['field'];
    if (!in_array($field, $allowedFields, true)) {
        $field = 'name'; // Default to a safe field
    }
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    
    // ok: php-no-sql-injection-ide
    $filter = [$field => htmlspecialchars($searchTerm, ENT_QUOTES, 'UTF-8')];
    $query = new MongoDB\Driver\Query($filter);
    $cursor = $manager->executeQuery('mydb.products', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_4() {
    // MongoDB safe query with numeric validation
    $minAge = $_POST['min_age'];
    
    // Validate that it's a number
    if (!is_numeric($minAge)) {
        die("Age must be a number");
    }
    
    $minAge = (int)$minAge;
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find(['age' => ['$gt' => $minAge]]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_5() {
    // MongoDB safe query with header validation
    $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
    
    // Validate API key format
    if (!preg_match('/^[A-Za-z0-9]{32}$/', $apiKey)) {
        die("Invalid API key format");
    }
    
    $manager = new MongoDB\Driver\Manager("mongodb://localhost:27017");
    
    // ok: php-no-sql-injection-ide
    $filter = ['api_key' => $apiKey];
    $query = new MongoDB\Driver\Query($filter);
    $cursor = $manager->executeQuery('mydb.api_users', $query);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_6() {
    // DynamoDB safe query with cookie validation
    $sessionId = $_COOKIE['session_id'] ?? '';
    
    // Validate session ID format
    if (!preg_match('/^[A-Za-z0-9]{26}$/', $sessionId)) {
        die("Invalid session ID");
    }
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ok: php-no-sql-injection-ide
    $result = $dynamodb->getItem([
        'TableName' => 'Sessions',
        'Key' => ['session_id' => ['S' => $sessionId]]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_7() {
    // MongoDB safe query with array validation
    $tagsInput = $_GET['tags'] ?? '';
    $tags = explode(',', $tagsInput);
    
    // Validate each tag
    $validatedTags = [];
    foreach ($tags as $tag) {
        $tag = trim($tag);
        if (preg_match('/^[A-Za-z0-9\-_]{1,20}$/', $tag)) {
            $validatedTags[] = $tag;
        }
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->blog->posts;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find(['tags' => ['$in' => $validatedTags]]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_8() {
    // MongoDB safe query with enum validation
    $category = $_POST['category'];
    
    $validCategories = ['electronics', 'books', 'clothing', 'food'];
    if (!in_array($category, $validCategories, true)) {
        $category = 'electronics'; // Default to a safe category
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find(['category' => $category]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_9() {
    // DynamoDB safe query with parameter validation
    $userId = $_GET['user_id'] ?? '';
    $status = $_GET['status'] ?? '';
    
    // Validate user ID
    if (!preg_match('/^[A-Za-z0-9]{10}$/', $userId)) {
        die("Invalid user ID");
    }
    
    // Validate status
    $validStatuses = ['pending', 'shipped', 'delivered', 'cancelled'];
    if (!in_array($status, $validStatuses, true)) {
        die("Invalid status");
    }
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ok: php-no-sql-injection-ide
    $result = $dynamodb->query([
        'TableName' => 'Orders',
        'KeyConditionExpression' => 'user_id = :uid AND order_status = :status',
        'ExpressionAttributeValues' => [
            ':uid' => ['S' => $userId],
            ':status' => ['S' => $status]
        ]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_10() {
    // MongoDB safe query with regex validation
    $searchPattern = $_POST['pattern'] ?? '';
    
    // Escape regex special characters
    $searchPattern = preg_quote($searchPattern, '/');
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->library->books;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find([
        'title' => ['$regex' => $searchPattern, '$options' => 'i']
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_11() {
    // MongoDB safe query with projection validation
    $username = htmlspecialchars($_GET['username'] ?? '', ENT_QUOTES, 'UTF-8');
    $fieldsInput = $_GET['fields'] ?? '';
    
    $allowedFields = ['name', 'email', 'age', 'location'];
    $fieldsArray = explode(',', $fieldsInput);
    
    $projection = [];
    foreach ($fieldsArray as $field) {
        $field = trim($field);
        if (in_array($field, $allowedFields, true)) {
            $projection[$field] = 1;
        }
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->users->profiles;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->findOne(
        ['username' => $username],
        ['projection' => $projection]
    );
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_12() {
    // DynamoDB safe update with validation
    $productId = $_POST['product_id'] ?? '';
    $newPrice = $_POST['price'] ?? '';
    
    // Validate product ID
    if (!preg_match('/^[A-Z0-9]{10}$/', $productId)) {
        die("Invalid product ID");
    }
    
    // Validate price
    if (!is_numeric($newPrice) || $newPrice < 0 || $newPrice > 10000) {
        die("Invalid price");
    }
    
    $sdk = new Aws\Sdk([
        'region' => 'us-west-2',
        'version' => 'latest'
    ]);
    $dynamodb = $sdk->createDynamoDb();
    
    // ok: php-no-sql-injection-ide
    $result = $dynamodb->updateItem([
        'TableName' => 'Products',
        'Key' => ['product_id' => ['S' => $productId]],
        'UpdateExpression' => 'SET price = :p',
        'ExpressionAttributeValues' => [
            ':p' => ['N' => (string)$newPrice]
        ]
    ]);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_13() {
    // MongoDB safe aggregation with validation
    $department = $_GET['department'] ?? '';
    
    $validDepartments = ['engineering', 'marketing', 'sales', 'hr', 'finance'];
    if (!in_array($department, $validDepartments, true)) {
        die("Invalid department");
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->company->employees;
    
    $pipeline = [
        ['$match' => ['department' => $department]],
        ['$group' => ['_id' => '$position', 'count' => ['$sum' => 1]]]
    ];
    
    // ok: php-no-sql-injection-ide
    $result = $collection->aggregate($pipeline);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_14() {
    // MongoDB safe sort with validation
    $sortField = $_GET['sort_by'] ?? 'name';
    $sortDir = $_GET['sort_dir'] ?? 'asc';
    
    // Validate sort field
    $allowedSortFields = ['name', 'price', 'date_added'];
    if (!in_array($sortField, $allowedSortFields, true)) {
        $sortField = 'name'; // Default to a safe field
    }
    
    // Validate sort direction
    $sortDir = strtolower($sortDir) === 'desc' ? -1 : 1;
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    $options = [
        'sort' => [$sortField => $sortDir]
    ];
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find([], $options);
}
// {/fact}
// {fact rule=nosql-injection@v1.0 defects=0}

function good_case_15() {
    // MongoDB safe query with multiple validated conditions
    $minPrice = $_POST['min_price'] ?? '0';
    $maxPrice = $_POST['max_price'] ?? '1000';
    $category = $_POST['category'] ?? '';
    
    // Validate prices
    if (!is_numeric($minPrice)) $minPrice = 0;
    if (!is_numeric($maxPrice)) $maxPrice = 1000;
    
    $minPrice = (float)$minPrice;
    $maxPrice = (float)$maxPrice;
    
    // Validate category
    $validCategories = ['electronics', 'books', 'clothing', 'food'];
    if (!in_array($category, $validCategories, true)) {
        die("Invalid category");
    }
    
    $client = new MongoDB\Client('mongodb://localhost:27017');
    $collection = $client->store->products;
    
    // ok: php-no-sql-injection-ide
    $result = $collection->find([
        'price' => [
            '$gte' => $minPrice,
            '$lte' => $maxPrice
        ],
        'category' => $category
    ]);
}
// {/fact}
?>