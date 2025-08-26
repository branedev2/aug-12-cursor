# PHP Hardcoded Credentials Examples

```php
<?php
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// True Positives (Vulnerable Code)

// Database connections with hardcoded credentials
function bad_case_1() {
    // MySQL connection with hardcoded credentials
    $host = "localhost";
    $username = "admin";
    // ruleid: php-hardcoded-credentials-basic-ide
    $password = "Password123!";
    $database = "customer_data";
    
    $conn = new mysqli($host, $username, $password, $database);
    
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    $result = $conn->query("SELECT * FROM users");
    $conn->close();
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_2() {
    // PDO connection with hardcoded credentials
    $host = "db.example.com";
    $db = "financial_records";
    $user = "finance_admin";
    // ruleid: php-hardcoded-credentials-basic-ide
    $pass = "S3cureP@ssw0rd!";
    
    $dsn = "mysql:host=$host;dbname=$db";
    $pdo = new PDO($dsn, $user, $pass);
    
    $stmt = $pdo->query("SELECT * FROM transactions");
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// API authentication with hardcoded credentials
function bad_case_3() {
    // REST API call with hardcoded API key
    $url = "https://api.example.com/v1/data";
    // ruleid: php-hardcoded-credentials-basic-ide
    $apiKey = "ak_live_51KdJk2JKLjn23KJN32kjnKJN32jk";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $apiKey",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

function bad_case_4() {
    // OAuth authentication with hardcoded client secret
    $clientId = "client_12345";
    // ruleid: php-hardcoded-credentials-basic-ide
    $clientSecret = "cs_7a8b9c0d1e2f3g4h5i6j7k8l9m";
    $tokenUrl = "https://oauth.example.com/token";
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'client_credentials',
        'client_id' => $clientId,
        'client_secret' => $clientSecret
    ]));
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Cloud service configurations with hardcoded credentials
function bad_case_5() {
    // AWS S3 access with hardcoded credentials
    require 'vendor/autoload.php';
    
    use Aws\S3\S3Client;
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $s3 = new S3Client([
        'version' => 'latest',
        'region' => 'us-west-2',
        'credentials' => [
            'key' => 'AKIA_PLACEHOLDER_ACCESS_KEY',
            'secret' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        ]
    ]);
    
    $objects = $s3->listObjects([
        'Bucket' => 'my-bucket'
    ]);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// SMTP/Email configurations with hardcoded credentials
function bad_case_6() {
    // PHPMailer with hardcoded SMTP credentials
    require 'vendor/autoload.php';
    
    use PHPMailer\PHPMailer\PHPMailer;
    
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->SMTPAuth = true;
    $mail->Username = 'company.notifications@example.com';
    // ruleid: php-hardcoded-credentials-basic-ide
    $mail->Password = 'NotificationMailPwd123!';
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;
    
    $mail->setFrom('company.notifications@example.com', 'Company Notifications');
    $mail->addAddress('recipient@example.com');
    $mail->Subject = 'Important Notification';
    $mail->Body = 'This is an important notification.';
    
    $mail->send();
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// File system operations with hardcoded credentials
function bad_case_7() {
    // FTP connection with hardcoded credentials
    $ftpServer = "ftp.example.com";
    $ftpUser = "ftpuser";
    // ruleid: php-hardcoded-credentials-basic-ide
    $ftpPassword = "FtpP@ssw0rd!";
    
    $conn = ftp_connect($ftpServer);
    $login = ftp_login($conn, $ftpUser, $ftpPassword);
    
    if ($login) {
        $files = ftp_nlist($conn, ".");
        ftp_close($conn);
        return $files;
    }
    
    return false;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// SSH connections with hardcoded credentials
function bad_case_8() {
    // SSH2 connection with hardcoded credentials
    $host = 'ssh.example.com';
    $port = 22;
    $username = 'admin';
    // ruleid: php-hardcoded-credentials-basic-ide
    $password = 'SshAdm1nP@ss';
    
    $connection = ssh2_connect($host, $port);
    if (ssh2_auth_password($connection, $username, $password)) {
        $stream = ssh2_exec($connection, 'ls -la');
        stream_set_blocking($stream, true);
        $output = stream_get_contents($stream);
        fclose($stream);
        return $output;
    }
    
    return false;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Database connection string with embedded credentials
function bad_case_9() {
    // Connection string with embedded credentials
    // ruleid: php-hardcoded-credentials-basic-ide
    $connectionString = "mongodb://dbadmin:M0ng0P@ssw0rd!@mongodb.example.com:27017/admin";
    
    $client = new MongoDB\Client($connectionString);
    $collection = $client->selectCollection('users', 'profiles');
    $result = $collection->find();
    
    return $result;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// API key in configuration array
function bad_case_10() {
    // API configuration with hardcoded key
    $config = [
        'api_url' => 'https://payments.example.com/api/v2',
        'merchant_id' => 'MERCH123456',
        // ruleid: php-hardcoded-credentials-basic-ide
        'api_key' => 'sk_test_PLACEHOLDER_KEY',
        'timeout' => 30
    ];
    
    $ch = curl_init($config['api_url'] . '/transactions');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-API-Key: {$config['api_key']}",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Hardcoded JWT secret
function bad_case_11() {
    require_once 'vendor/autoload.php';
    use Firebase\JWT\JWT;
    
    $userId = 12345;
    $payload = [
        'sub' => $userId,
        'name' => 'John Doe',
        'iat' => time(),
        'exp' => time() + 3600
    ];
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $jwtSecret = "j3H5d7fA9sK2l4P6m8N0qR5t7V9w1Y3z";
    
    $jwt = JWT::encode($payload, $jwtSecret, 'HS256');
    
    return $jwt;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Redis connection with hardcoded password
function bad_case_12() {
    $redis = new Redis();
    $redis->connect('redis.example.com', 6379);
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $redis->auth('R3d1sP@ssw0rd!');
    
    $redis->set('user:1:session', 'active');
    $sessionStatus = $redis->get('user:1:session');
    
    return $sessionStatus;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// GraphQL API with hardcoded token
function bad_case_13() {
    $url = 'https://api.example.com/graphql';
    $query = '
        query {
            users {
                id
                name
                email
            }
        }
    ';
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['query' => $query]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $token",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Elasticsearch client with hardcoded credentials
function bad_case_14() {
    require 'vendor/autoload.php';
    
    $hosts = [
        'https://elasticsearch.example.com:9200'
    ];
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $client = Elasticsearch\ClientBuilder::create()
        ->setHosts($hosts)
        ->setBasicAuthentication('elastic', 'El@st1cP@ssw0rd!')
        ->build();
    
    $params = [
        'index' => 'my_index',
        'body' => [
            'query' => [
                'match_all' => (object)[]
            ]
        ]
    ];
    
    $response = $client->search($params);
    return $response;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Hardcoded encryption key
function bad_case_15() {
    $data = "Sensitive customer information";
    
    // ruleid: php-hardcoded-credentials-basic-ide
    $encryptionKey = "a1b2c3d4e5f6g7h8i9j0klmnopqrstuv";
    $iv = random_bytes(16);
    
    $encrypted = openssl_encrypt(
        $data,
        'AES-256-CBC',
        $encryptionKey,
        0,
        $iv
    );
    
    $result = base64_encode($iv . $encrypted);
    return $result;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// True Negatives (Secure Code)

// Database connection using environment variables
function good_case_1() {
    // MySQL connection with credentials from environment variables
    $host = "localhost";
    $username = getenv('DB_USERNAME');
    // ok: php-hardcoded-credentials-basic-ide
    $password = getenv('DB_PASSWORD');
    $database = "customer_data";
    
    $conn = new mysqli($host, $username, $password, $database);
    
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    
    $result = $conn->query("SELECT * FROM users");
    $conn->close();
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_2() {
    // PDO connection with credentials from configuration file
    $config = include 'config.php';
    $host = $config['db_host'];
    $db = $config['db_name'];
    $user = $config['db_user'];
    // ok: php-hardcoded-credentials-basic-ide
    $pass = $config['db_pass'];
    
    $dsn = "mysql:host=$host;dbname=$db";
    $pdo = new PDO($dsn, $user, $pass);
    
    $stmt = $pdo->query("SELECT * FROM transactions");
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// API authentication with credentials from environment
function good_case_3() {
    // REST API call with API key from environment
    $url = "https://api.example.com/v1/data";
    // ok: php-hardcoded-credentials-basic-ide
    $apiKey = getenv('API_KEY');
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $apiKey",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

function good_case_4() {
    // OAuth authentication with client secret from secure storage
    $clientId = $_ENV['OAUTH_CLIENT_ID'];
    // ok: php-hardcoded-credentials-basic-ide
    $clientSecret = $_ENV['OAUTH_CLIENT_SECRET'];
    $tokenUrl = "https://oauth.example.com/token";
    
    $ch = curl_init($tokenUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'client_credentials',
        'client_id' => $clientId,
        'client_secret' => $clientSecret
    ]));
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Cloud service configurations with secure credential management
function good_case_5() {
    // AWS S3 access with credentials from environment
    require 'vendor/autoload.php';
    
    use Aws\S3\S3Client;
    
    // ok: php-hardcoded-credentials-basic-ide
    $s3 = new S3Client([
        'version' => 'latest',
        'region' => getenv('AWS_REGION'),
        'credentials' => [
            'key' => getenv('AWS_ACCESS_KEY_ID'),
            'secret' => getenv('AWS_SECRET_ACCESS_KEY')
        ]
    ]);
    
    $objects = $s3->listObjects([
        'Bucket' => getenv('S3_BUCKET_NAME')
    ]);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// SMTP/Email configurations with secure credentials
function good_case_6() {
    // PHPMailer with SMTP credentials from configuration
    require 'vendor/autoload.php';
    
    use PHPMailer\PHPMailer\PHPMailer;
    
    $config = include 'mail_config.php';
    
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = $config['smtp_host'];
    $mail->SMTPAuth = true;
    $mail->Username = $config['smtp_username'];
    // ok: php-hardcoded-credentials-basic-ide
    $mail->Password = $config['smtp_password'];
    $mail->SMTPSecure = 'tls';
    $mail->Port = 587;
    
    $mail->setFrom($config['from_email'], $config['from_name']);
    $mail->addAddress('recipient@example.com');
    $mail->Subject = 'Important Notification';
    $mail->Body = 'This is an important notification.';
    
    $mail->send();
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// File system operations with secure credentials
function good_case_7() {
    // FTP connection with credentials from environment variables
    $ftpServer = getenv('FTP_SERVER');
    $ftpUser = getenv('FTP_USERNAME');
    // ok: php-hardcoded-credentials-basic-ide
    $ftpPassword = getenv('FTP_PASSWORD');
    
    $conn = ftp_connect($ftpServer);
    $login = ftp_login($conn, $ftpUser, $ftpPassword);
    
    if ($login) {
        $files = ftp_nlist($conn, ".");
        ftp_close($conn);
        return $files;
    }
    
    return false;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// SSH connections with secure credentials
function good_case_8() {
    // SSH2 connection with credentials from secure storage
    $config = include 'ssh_config.php';
    $host = $config['ssh_host'];
    $port = $config['ssh_port'];
    $username = $config['ssh_username'];
    // ok: php-hardcoded-credentials-basic-ide
    $password = $config['ssh_password'];
    
    $connection = ssh2_connect($host, $port);
    if (ssh2_auth_password($connection, $username, $password)) {
        $stream = ssh2_exec($connection, 'ls -la');
        stream_set_blocking($stream, true);
        $output = stream_get_contents($stream);
        fclose($stream);
        return $output;
    }
    
    return false;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Database connection string with secure credentials
function good_case_9() {
    // Connection string with credentials from environment
    $dbUser = getenv('MONGO_USERNAME');
    // ok: php-hardcoded-credentials-basic-ide
    $dbPass = getenv('MONGO_PASSWORD');
    $dbHost = getenv('MONGO_HOST');
    $connectionString = "mongodb://$dbUser:$dbPass@$dbHost:27017/admin";
    
    $client = new MongoDB\Client($connectionString);
    $collection = $client->selectCollection('users', 'profiles');
    $result = $collection->find();
    
    return $result;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// API key in configuration from secure source
function good_case_10() {
    // API configuration with key from environment
    $config = [
        'api_url' => getenv('PAYMENT_API_URL'),
        'merchant_id' => getenv('MERCHANT_ID'),
        // ok: php-hardcoded-credentials-basic-ide
        'api_key' => getenv('PAYMENT_API_KEY'),
        'timeout' => 30
    ];
    
    $ch = curl_init($config['api_url'] . '/transactions');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "X-API-Key: {$config['api_key']}",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// JWT secret from secure storage
function good_case_11() {
    require_once 'vendor/autoload.php';
    use Firebase\JWT\JWT;
    
    $userId = 12345;
    $payload = [
        'sub' => $userId,
        'name' => 'John Doe',
        'iat' => time(),
        'exp' => time() + 3600
    ];
    
    // ok: php-hardcoded-credentials-basic-ide
    $jwtSecret = getenv('JWT_SECRET_KEY');
    
    $jwt = JWT::encode($payload, $jwtSecret, 'HS256');
    
    return $jwt;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Redis connection with password from configuration
function good_case_12() {
    $redis = new Redis();
    $redis->connect($_ENV['REDIS_HOST'], $_ENV['REDIS_PORT']);
    
    // ok: php-hardcoded-credentials-basic-ide
    $redis->auth($_ENV['REDIS_PASSWORD']);
    
    $redis->set('user:1:session', 'active');
    $sessionStatus = $redis->get('user:1:session');
    
    return $sessionStatus;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// GraphQL API with token from secure storage
function good_case_13() {
    $url = getenv('GRAPHQL_API_URL');
    $query = '
        query {
            users {
                id
                name
                email
            }
        }
    ';
    
    // ok: php-hardcoded-credentials-basic-ide
    $token = getenv('GRAPHQL_API_TOKEN');
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['query' => $query]));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: Bearer $token",
        "Content-Type: application/json"
    ]);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Elasticsearch client with credentials from environment
function good_case_14() {
    require 'vendor/autoload.php';
    
    $hosts = [
        getenv('ELASTICSEARCH_HOST')
    ];
    
    // ok: php-hardcoded-credentials-basic-ide
    $client = Elasticsearch\ClientBuilder::create()
        ->setHosts($hosts)
        ->setBasicAuthentication(
            getenv('ELASTICSEARCH_USERNAME'),
            getenv('ELASTICSEARCH_PASSWORD')
        )
        ->build();
    
    $params = [
        'index' => 'my_index',
        'body' => [
            'query' => [
                'match_all' => (object)[]
            ]
        ]
    ];
    
    $response = $client->search($params);
    return $response;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Encryption with key from secure storage
function good_case_15() {
    $data = "Sensitive customer information";
    
    // ok: php-hardcoded-credentials-basic-ide
    $encryptionKey = getenv('ENCRYPTION_KEY');
    $iv = random_bytes(16);
    
    $encrypted = openssl_encrypt(
        $data,
        'AES-256-CBC',
        $encryptionKey,
        0,
        $iv
    );
    
    $result = base64_encode($iv . $encrypted);
    return $result;
}
// {/fact}
?>