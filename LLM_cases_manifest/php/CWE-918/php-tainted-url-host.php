<?php
// {fact rule=server-side-request-forgery@v1.0 defects=1}
// Test cases for php-tainted-url-host rule
// This rule detects potential SSRF vulnerabilities where user input is used in the host part of a URL

// TRUE POSITIVES (Vulnerable code)

function bad_case_1() {
    // User input directly used in host part of URL
    $userInput = $_GET['server'];
    $url = "https://" . $userInput . "/api/data";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_2() {
    // User input from POST data used in host with minimal transformation
    $userInput = $_POST['domain'];
    $host = $userInput . ".example.org";
    $url = "http://" . $host . "/resource";
    // ruleid: php-tainted-url-host
    $ch = curl_init($url);
    curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_3() {
    // User input from REQUEST used in host part
    $server = $_REQUEST['server_name'];
    $port = "8080";
    $url = "https://" . $server . ":" . $port . "/api/v2/data";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    return $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_4() {
    // User input from HTTP header used in host
    $headers = getallheaders();
    $customHost = $headers['X-Custom-Host'];
    $url = "http://" . $customHost . "/service";
    // ruleid: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_5() {
    // User input with string concatenation in URL
    $subdomain = $_GET['sub'];
    $domain = "example.com";
    $url = "https://" . $subdomain . "." . $domain . "/path";
    // ruleid: php-tainted-url-host
    $data = file_get_contents($url);
    echo $data;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_6() {
    // User input from cookie used in host
    $targetSystem = $_COOKIE['preferred_system'];
    $url = "http://" . $targetSystem . ".internal.network/status";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    return json_decode($response, true);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_7() {
    // User input with string interpolation
    $server = $_GET['server'];
    $url = "https://{$server}/api/resource";
    // ruleid: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_8() {
    // User input with sprintf formatting
    $host = $_POST['hostname'];
    $url = sprintf("http://%s/endpoint", $host);
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_9() {
    // User input with multiple parts
    $subdomain = $_GET['sub'];
    $domain = $_GET['domain'];
    $tld = $_GET['tld'];
    $url = "https://" . $subdomain . "." . $domain . "." . $tld . "/api";
    // ruleid: php-tainted-url-host
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_10() {
    // User input with conditional logic
    $env = $_GET['environment'];
    $host = ($env == 'prod') ? 'production-api' : $env;
    $url = "https://" . $host . ".example.com/data";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    return $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_11() {
    // User input with array access
    $params = $_POST['config'];
    $server = $params['server'];
    $url = "http://" . $server . "/api/v1/resource";
    // ruleid: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_12() {
    // User input with some sanitization but still vulnerable
    $host = $_GET['host'];
    $host = str_replace(['<', '>', '"', "'"], '', $host);
    $url = "https://" . $host . "/api/data";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_13() {
    // User input with ternary operator
    $useCustom = $_GET['custom'] ?? false;
    $host = $useCustom ? $_GET['host'] : 'default.example.com';
    $url = "https://" . $host . "/service";
    // ruleid: php-tainted-url-host
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_14() {
    // User input with variable variables
    $source = $_GET['source'];
    $hostParam = 'host_' . $source;
    $host = $_GET[$hostParam];
    $url = "http://" . $host . "/api";
    // ruleid: php-tainted-url-host
    $response = file_get_contents($url);
    return $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

function bad_case_15() {
    // User input with JSON data
    $jsonData = $_POST['config'];
    $config = json_decode($jsonData, true);
    $host = $config['server']['host'];
    $url = "https://" . $host . "/api/v2/data";
    // ruleid: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    $response = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// TRUE NEGATIVES (Safe code)

function good_case_1() {
    // Hardcoded host
    $url = "https://api.example.com/data";
    // ok: php-tainted-url-host
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_2() {
    // User input only in path, not host
    $resource = $_GET['resource'];
    $url = "https://api.example.com/" . $resource;
    // ok: php-tainted-url-host
    $ch = curl_init($url);
    curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_3() {
    // Allowlist validation for host
    $server = $_GET['server'];
    $allowedServers = ['api1.example.com', 'api2.example.com', 'api3.example.com'];
    // ok: php-tainted-url-host
    if (in_array($server, $allowedServers)) {
        $url = "https://" . $server . "/api/data";
        $response = file_get_contents($url);
        return $response;
    }
    return "Invalid server";
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_4() {
    // Using parse_url to validate URL
    $inputUrl = $_GET['url'];
    $parsedUrl = parse_url($inputUrl);
    // ok: php-tainted-url-host
    if ($parsedUrl && $parsedUrl['host'] === 'api.example.com') {
        $response = file_get_contents($inputUrl);
        echo $response;
    } else {
        echo "Invalid URL";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_5() {
    // Using environment variables for host
    $host = getenv('API_HOST');
    $url = "https://" . $host . "/api/v1/data";
    // ok: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    $response = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_6() {
    // Using configuration file for host
    $config = include 'config.php';
    $host = $config['api_host'];
    $url = "https://" . $host . "/service";
    // ok: php-tainted-url-host
    $response = file_get_contents($url);
    return json_decode($response, true);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_7() {
    // Using regex pattern matching for validation
    $server = $_GET['server'];
    // ok: php-tainted-url-host
    if (preg_match('/^(app|api|web)\.example\.com$/', $server)) {
        $url = "https://" . $server . "/resource";
        $data = file_get_contents($url);
        echo $data;
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_8() {
    // Using switch statement for allowlist
    $environment = $_GET['env'];
    switch ($environment) {
        case 'dev':
            $host = 'dev-api.example.com';
            break;
        case 'staging':
            $host = 'staging-api.example.com';
            break;
        case 'prod':
            $host = 'api.example.com';
            break;
        default:
            $host = 'test-api.example.com';
    }
    $url = "https://" . $host . "/data";
    // ok: php-tainted-url-host
    $ch = curl_init($url);
    curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_9() {
    // Using domain mapping for safety
    $service = $_GET['service'];
    $domainMap = [
        'users' => 'users-api.example.com',
        'products' => 'products-api.example.com',
        'orders' => 'orders-api.example.com'
    ];
    // ok: php-tainted-url-host
    if (isset($domainMap[$service])) {
        $host = $domainMap[$service];
        $url = "https://" . $host . "/api";
        $response = file_get_contents($url);
        return $response;
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_10() {
    // Using constants for host
    define('API_HOST', 'api.example.com');
    $resource = $_GET['resource'];
    $url = "https://" . API_HOST . "/v1/" . $resource;
    // ok: php-tainted-url-host
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    $response = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_11() {
    // Using class property for host
    class ApiClient {
        private $host = 'api.example.com';
        
        public function fetchData($resource) {
            $url = "https://" . $this->host . "/api/" . $resource;
            // ok: php-tainted-url-host
            return file_get_contents($url);
        }
    }
    
    $client = new ApiClient();
    $data = $client->fetchData($_GET['resource']);
    echo $data;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_12() {
    // Using DNS lookup validation
    $server = $_GET['server'];
    // ok: php-tainted-url-host
    if ($server === 'api.example.com' || $server === 'backup-api.example.com') {
        $ip = gethostbyname($server);
        if ($ip !== $server) { // DNS resolution succeeded
            $url = "https://" . $server . "/data";
            $response = file_get_contents($url);
            echo $response;
        }
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_13() {
    // Using URL builder class
    class SafeUrlBuilder {
        private $baseHost = 'api.example.com';
        
        public function buildUrl($path) {
            return "https://" . $this->baseHost . "/" . ltrim($path, '/');
        }
    }
    
    $builder = new SafeUrlBuilder();
    $path = $_GET['path'];
    $url = $builder->buildUrl($path);
    // ok: php-tainted-url-host
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_14() {
    // Using configuration array for multiple environments
    $environments = [
        'dev' => 'dev-api.example.com',
        'test' => 'test-api.example.com',
        'prod' => 'api.example.com'
    ];
    
    $env = $_GET['environment'] ?? 'dev';
    // ok: php-tainted-url-host
    if (isset($environments[$env])) {
        $host = $environments[$env];
        $url = "https://" . $host . "/service";
        $response = file_get_contents($url);
        return $response;
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

function good_case_15() {
    // Using domain suffix validation
    $subdomain = $_GET['system'];
    $validDomain = "example.com";
    // ok: php-tainted-url-host
    if (preg_match('/^[a-z0-9-]+$/', $subdomain)) {
        $host = $subdomain . "." . $validDomain;
        $url = "https://" . $host . "/api";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        $response = curl_exec($ch);
    }
}
// {/fact}
?>