<?php
/**
 * Test cases for php-insecure-socket-usage rule
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 */
// {fact rule=sensitive-information-leak@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code)

function bad_case_1() {
    // Taking user input directly from GET parameter
    $host = $_GET['host'];
    $port = $_GET['port'];
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($socket, $host, $port);
    
    $message = "Hello Server";
    socket_write($socket, $message, strlen($message));
    
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_2() {
    // Taking user input directly from POST parameter
    $host = $_POST['server'];
    $port = 80;
    
    // ruleid: php-insecure-socket-usage
    $fp = fsockopen($host, $port, $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $out = "GET / HTTP/1.1\r\n";
        $out .= "Host: $host\r\n";
        $out .= "Connection: Close\r\n\r\n";
        fwrite($fp, $out);
        while (!feof($fp)) {
            echo fgets($fp, 128);
        }
        fclose($fp);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_3() {
    // Taking user input from HTTP header
    $headers = getallheaders();
    $host = $headers['X-Forward-Host'];
    $port = intval($_GET['port']);
    $protocol = $_GET['protocol'] ?? 'tcp';
    
    // ruleid: php-insecure-socket-usage
    $socket = stream_socket_client("$protocol://$host:$port", $errno, $errstr, 30);
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($socket, "GET / HTTP/1.0\r\nHost: $host\r\n\r\n");
        while (!feof($socket)) {
            echo fread($socket, 1024);
        }
        fclose($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_4() {
    // Taking user input from cookie
    $host = $_COOKIE['preferred_server'];
    $port = 25; // SMTP port
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false) {
        echo "socket_create() failed: " . socket_strerror(socket_last_error()) . "\n";
    }
    
    $result = socket_connect($socket, $host, $port);
    if ($result === false) {
        echo "socket_connect() failed: " . socket_strerror(socket_last_error($socket)) . "\n";
    }
    
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_5() {
    // Taking user input from JSON POST data
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    $host = $data['target_host'];
    $port = $data['target_port'];
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($socket, "Test message", 12, 0, $host, $port);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_6() {
    // Taking user input from query string with minimal processing
    $host = trim($_GET['destination']);
    $port = 443;
    
    // ruleid: php-insecure-socket-usage
    $context = stream_context_create();
    $socket = stream_socket_client("ssl://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($socket, "GET / HTTP/1.1\r\nHost: $host\r\n\r\n");
        while (!feof($socket)) {
            echo fread($socket, 4096);
        }
        fclose($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_7() {
    // Taking user input with string concatenation
    $subdomain = $_GET['subdomain'];
    $domain = "example.com";
    $host = $subdomain . "." . $domain;
    $port = 21; // FTP port
    
    // ruleid: php-insecure-socket-usage
    $conn_id = ftp_connect($host, $port);
    if ($conn_id) {
        echo "Connected to $host on port $port";
        ftp_close($conn_id);
    } else {
        echo "Could not connect to $host on port $port";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_8() {
    // Taking user input with variable variables
    $param_name = 'server_addr';
    $host = $_REQUEST[$$param_name];
    $port = 22; // SSH port
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $result = socket_connect($socket, $host, $port);
    
    if ($result) {
        socket_write($socket, "Hello Server\n");
        socket_close($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_9() {
    // Taking user input with array access
    $params = $_GET;
    $host = $params['host'];
    $port = isset($params['port']) ? intval($params['port']) : 80;
    $type = isset($params['type']) ? $params['type'] : SOCK_STREAM;
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, $type, SOL_TCP);
    socket_bind($socket, $host, $port);
    socket_listen($socket, 5);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_10() {
    // Taking user input with ternary operator
    $host = isset($_POST['host']) ? $_POST['host'] : 'localhost';
    $port = isset($_POST['port']) ? intval($_POST['port']) : 8080;
    
    // ruleid: php-insecure-socket-usage
    $fp = stream_socket_client("tcp://$host:$port", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($fp, "Hello, world!");
        echo fread($fp, 1024);
        fclose($fp);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_11() {
    // Taking user input with string interpolation
    $host = $_GET['hostname'];
    $port = 3306; // MySQL port
    
    // ruleid: php-insecure-socket-usage
    $socket = "tcp://{$host}:{$port}";
    $conn = stream_socket_client($socket, $errno, $errstr, 30);
    
    if (!$conn) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($conn, "SELECT 1");
        fclose($conn);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_12() {
    // Taking user input with switch statement
    $server_type = $_GET['server_type'];
    
    switch ($server_type) {
        case 'web':
            $host = $_GET['web_server'];
            $port = 80;
            break;
        case 'mail':
            $host = $_GET['mail_server'];
            $port = 25;
            break;
        default:
            $host = $_GET['custom_server'];
            $port = intval($_GET['custom_port']);
    }
    
    // ruleid: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($socket, $host, $port);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_13() {
    // Taking user input with foreach loop
    $params = [];
    foreach ($_GET as $key => $value) {
        $params[$key] = $value;
    }
    
    $host = $params['target'];
    $port = 5432; // PostgreSQL port
    
    // ruleid: php-insecure-socket-usage
    $conn_string = "host=$host port=$port dbname=test user=postgres password=secret";
    $dbconn = pg_connect($conn_string);
    
    if (!$dbconn) {
        echo "Failed to connect to PostgreSQL";
    } else {
        pg_close($dbconn);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_14() {
    // Taking user input with list destructuring
    $input = explode(':', $_GET['connection']);
    list($host, $port) = count($input) > 1 ? $input : [$input[0], 6379]; // Redis default port
    
    // ruleid: php-insecure-socket-usage
    $redis = new Redis();
    $redis->connect($host, $port);
    $redis->set("test", "Hello Redis");
    $redis->close();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

function bad_case_15() {
    // Taking user input with error suppression
    $host = $_POST['endpoint'] ?? 'localhost';
    $port = @$_POST['port'] ?: 11211; // Memcached default port
    
    // ruleid: php-insecure-socket-usage
    $memcache = new Memcache;
    $memcache->connect($host, $port);
    $memcache->set('key', 'value');
    $memcache->close();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

// TRUE NEGATIVES (Safe Code)

function good_case_1() {
    // Using filter_var for IP validation
    $host = filter_var($_GET['host'], FILTER_VALIDATE_IP);
    if ($host === false) {
        die("Invalid IP address");
    }
    $port = filter_var($_GET['port'], FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'max_range' => 65535]
    ]);
    if ($port === false) {
        die("Invalid port number");
    }
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($socket, $host, $port);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_2() {
    // Using whitelist for allowed hosts
    $allowed_hosts = ['api.example.com', 'cdn.example.com', 'db.example.com'];
    $host = $_POST['server'];
    
    if (!in_array($host, $allowed_hosts, true)) {
        die("Unauthorized host");
    }
    
    $port = 80;
    
    // ok: php-insecure-socket-usage
    $fp = fsockopen($host, $port, $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $out = "GET / HTTP/1.1\r\n";
        $out .= "Host: $host\r\n";
        $out .= "Connection: Close\r\n\r\n";
        fwrite($fp, $out);
        while (!feof($fp)) {
            echo fgets($fp, 128);
        }
        fclose($fp);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_3() {
    // Using regex pattern matching for domain validation
    $host = $_GET['host'];
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/', $host)) {
        die("Invalid hostname format");
    }
    
    $port = filter_var($_GET['port'], FILTER_VALIDATE_INT);
    if ($port === false || $port < 1 || $port > 65535) {
        die("Invalid port number");
    }
    
    // ok: php-insecure-socket-usage
    $socket = stream_socket_client("tcp://$host:$port", $errno, $errstr, 30);
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($socket, "GET / HTTP/1.0\r\nHost: $host\r\n\r\n");
        while (!feof($socket)) {
            echo fread($socket, 1024);
        }
        fclose($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_4() {
    // Using hardcoded values instead of user input
    $host = '192.168.1.100';
    $port = 25;
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if ($socket === false) {
        echo "socket_create() failed: " . socket_strerror(socket_last_error()) . "\n";
    }
    
    $result = socket_connect($socket, $host, $port);
    if ($result === false) {
        echo "socket_connect() failed: " . socket_strerror(socket_last_error($socket)) . "\n";
    }
    
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_5() {
    // Using environment variables instead of user input
    $host = getenv('API_SERVER_HOST');
    $port = getenv('API_SERVER_PORT') ? intval(getenv('API_SERVER_PORT')) : 443;
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($socket, "Test message", 12, 0, $host, $port);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_6() {
    // Using configuration file instead of user input
    $config = parse_ini_file('config.ini');
    $host = $config['server_host'];
    $port = $config['server_port'];
    
    // ok: php-insecure-socket-usage
    $context = stream_context_create();
    $socket = stream_socket_client("ssl://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
    
    if (!$socket) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($socket, "GET / HTTP/1.1\r\nHost: $host\r\n\r\n");
        while (!feof($socket)) {
            echo fread($socket, 4096);
        }
        fclose($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_7() {
    // Using DNS lookup validation before connecting
    $host = $_GET['hostname'];
    $ip = gethostbyname($host);
    
    // Validate that the IP is in an allowed range
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        die("Invalid or restricted IP address");
    }
    
    $port = 21;
    
    // ok: php-insecure-socket-usage
    $conn_id = ftp_connect($ip, $port);
    if ($conn_id) {
        echo "Connected to $ip on port $port";
        ftp_close($conn_id);
    } else {
        echo "Could not connect to $ip on port $port";
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_8() {
    // Using a custom validation function
    $host = $_REQUEST['server_addr'];
    
    function is_valid_host($host) {
        // Check if it's a valid IP
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return true;
        }
        
        // Check if it's a valid hostname
        if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$/', $host)) {
            return true;
        }
        
        return false;
    }
    
    if (!is_valid_host($host)) {
        die("Invalid host");
    }
    
    $port = 22;
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $result = socket_connect($socket, $host, $port);
    
    if ($result) {
        socket_write($socket, "Hello Server\n");
        socket_close($socket);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_9() {
    // Using a whitelist for both host and port
    $allowed_hosts = ['api1.example.com', 'api2.example.com'];
    $allowed_ports = [80, 443, 8080];
    
    $host = $_GET['host'];
    $port = intval($_GET['port']);
    
    if (!in_array($host, $allowed_hosts, true)) {
        die("Unauthorized host");
    }
    
    if (!in_array($port, $allowed_ports, true)) {
        die("Unauthorized port");
    }
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_bind($socket, $host, $port);
    socket_listen($socket, 5);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_10() {
    // Using database for allowed hosts validation
    $host = $_POST['host'];
    $port = intval($_POST['port']);
    
    // Simulating database check
    $allowed_hosts = ['db.example.com', 'cache.example.com', 'queue.example.com'];
    
    if (!in_array($host, $allowed_hosts)) {
        die("Host not in allowed list");
    }
    
    if ($port < 1024 || $port > 49151) {
        die("Port not in allowed range");
    }
    
    // ok: php-insecure-socket-usage
    $fp = stream_socket_client("tcp://$host:$port", $errno, $errstr, 30);
    if (!$fp) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($fp, "Hello, world!");
        echo fread($fp, 1024);
        fclose($fp);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_11() {
    // Using constants for connection details
    define('DB_HOST', '10.0.0.5');
    define('DB_PORT', 3306);
    
    // ok: php-insecure-socket-usage
    $socket = "tcp://" . DB_HOST . ":" . DB_PORT;
    $conn = stream_socket_client($socket, $errno, $errstr, 30);
    
    if (!$conn) {
        echo "$errstr ($errno)<br />\n";
    } else {
        fwrite($conn, "SELECT 1");
        fclose($conn);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_12() {
    // Using class properties for connection details
    class ServerConfig {
        public static $host = '192.168.0.10';
        public static $port = 5432;
    }
    
    // ok: php-insecure-socket-usage
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    socket_connect($socket, ServerConfig::$host, ServerConfig::$port);
    socket_close($socket);
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_13() {
    // Using a configuration array
    $config = [
        'web' => ['host' => 'web.internal', 'port' => 80],
        'mail' => ['host' => 'mail.internal', 'port' => 25],
        'db' => ['host' => 'db.internal', 'port' => 5432]
    ];
    
    $server_type = $_GET['server_type'];
    
    if (!array_key_exists($server_type, $config)) {
        die("Invalid server type");
    }
    
    $host = $config[$server_type]['host'];
    $port = $config[$server_type]['port'];
    
    // ok: php-insecure-socket-usage
    $conn_string = "host=$host port=$port dbname=test user=postgres password=secret";
    $dbconn = pg_connect($conn_string);
    
    if (!$dbconn) {
        echo "Failed to connect to PostgreSQL";
    } else {
        pg_close($dbconn);
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_14() {
    // Using service discovery instead of direct user input
    $service_name = $_GET['service'];
    
    // Simulating service discovery
    $service_registry = [
        'cache' => ['host' => '10.0.0.1', 'port' => 6379],
        'queue' => ['host' => '10.0.0.2', 'port' => 5672],
        'search' => ['host' => '10.0.0.3', 'port' => 9200]
    ];
    
    if (!isset($service_registry[$service_name])) {
        die("Unknown service");
    }
    
    $host = $service_registry[$service_name]['host'];
    $port = $service_registry[$service_name]['port'];
    
    // ok: php-insecure-socket-usage
    $redis = new Redis();
    $redis->connect($host, $port);
    $redis->set("test", "Hello Redis");
    $redis->close();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

function good_case_15() {
    // Using dependency injection for connection details
    class ConnectionManager {
        private $host;
        private $port;
        
        public function __construct($host = 'localhost', $port = 11211) {
            $this->host = $host;
            $this->port = $port;
        }
        
        public function getHost() {
            return $this->host;
        }
        
        public function getPort() {
            return $this->port;
        }
    }
    
    $manager = new ConnectionManager('memcache.internal', 11211);
    
    // ok: php-insecure-socket-usage
    $memcache = new Memcache;
    $memcache->connect($manager->getHost(), $manager->getPort());
    $memcache->set('key', 'value');
    $memcache->close();
}
// {/fact}
?>