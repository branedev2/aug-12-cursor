<?php
// PHP SSRF (Server-Side Request Forgery) Examples
// Rule ID: php-ssrf
// {fact rule=server-side-request-forgery@v1.0 defects=1}
// CWE: CWE-918

// True Positive Examples (Vulnerable Code)

// Example 1: Basic SSRF with file_get_contents
function bad_case_1() {
    $url = $_GET['url'];
    // ruleid: php-ssrf
    $content = file_get_contents($url);
    echo $content;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 2: SSRF with cURL
function bad_case_2() {
    $url = $_POST['target'];
    $ch = curl_init();
    // ruleid: php-ssrf
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 3: SSRF with HTTP request from header
function bad_case_3() {
    $headers = getallheaders();
    $url = $headers['X-Forwarded-Host'];
    // ruleid: php-ssrf
    $data = file_get_contents($url);
    return $data;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 4: SSRF with minimal processing
function bad_case_4() {
    $url = $_GET['api_endpoint'] . "/data.json";
    // ruleid: php-ssrf
    $response = file_get_contents($url);
    echo json_decode($response, true);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 5: SSRF with stream_context_create
function bad_case_5() {
    $url = $_COOKIE['resource'];
    $opts = array(
        'http' => array(
            'method' => "GET",
            'header' => "Accept-language: en\r\n"
        )
    );
    $context = stream_context_create($opts);
    // ruleid: php-ssrf
    $content = file_get_contents($url, false, $context);
    echo $content;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 6: SSRF with cURL and variable concatenation
function bad_case_6() {
    $host = $_GET['host'];
    $path = "/api/v1/users";
    $url = "https://" . $host . $path;
    $ch = curl_init();
    // ruleid: php-ssrf
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 7: SSRF with fopen
function bad_case_7() {
    $url = $_REQUEST['document_url'];
    // ruleid: php-ssrf
    $handle = fopen($url, "r");
    $contents = "";
    while (!feof($handle)) {
        $contents .= fread($handle, 8192);
    }
    fclose($handle);
    echo $contents;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 8: SSRF with variable overwriting
function bad_case_8() {
    $url = "https://api.example.com/data";
    if (isset($_GET['custom_endpoint'])) {
        $url = $_GET['custom_endpoint'];
    }
    // ruleid: php-ssrf
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 9: SSRF with JSON input
function bad_case_9() {
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    $url = $data['webhook_url'];
    // ruleid: php-ssrf
    $response = file_get_contents($url);
    echo json_encode(['status' => 'success', 'response' => $response]);
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 10: SSRF with Guzzle HTTP client
function bad_case_10() {
    $client = new \GuzzleHttp\Client();
    $url = $_GET['service_url'];
    // ruleid: php-ssrf
    $response = $client->request('GET', $url);
    $body = $response->getBody();
    echo $body;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 11: SSRF with base64 encoded URL
function bad_case_11() {
    $encoded_url = $_POST['encoded_endpoint'];
    $url = base64_decode($encoded_url);
    // ruleid: php-ssrf
    $content = file_get_contents($url);
    echo $content;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 12: SSRF with XML input (XXE + SSRF)
function bad_case_12() {
    $xml_data = file_get_contents('php://input');
    $xml = simplexml_load_string($xml_data);
    $url = (string)$xml->url;
    // ruleid: php-ssrf
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 13: SSRF with session stored URL
function bad_case_13() {
    session_start();
    if (isset($_GET['remember_service'])) {
        $_SESSION['service_url'] = $_GET['remember_service'];
    }
    
    if (isset($_SESSION['service_url'])) {
        // ruleid: php-ssrf
        $data = file_get_contents($_SESSION['service_url']);
        echo $data;
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 14: SSRF with URL in query fragment
function bad_case_14() {
    $fragment = $_SERVER['QUERY_STRING'];
    parse_str($fragment, $params);
    $url = $params['callback_url'];
    // ruleid: php-ssrf
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=1}

// Example 15: SSRF with stream wrapper
function bad_case_15() {
    $resource = $_GET['resource'];
    // ruleid: php-ssrf
    $stream = fopen($resource, 'r');
    $content = stream_get_contents($stream);
    fclose($stream);
    echo $content;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// True Negative Examples (Safe Code)

// Example 1: Whitelist validation
function good_case_1() {
    $url = $_GET['url'];
    $allowed_domains = ['api.example.com', 'cdn.example.com'];
    $parsed_url = parse_url($url);
    
    if (isset($parsed_url['host']) && in_array($parsed_url['host'], $allowed_domains)) {
        // ok: php-ssrf
        $content = file_get_contents($url);
        echo $content;
    } else {
        echo "Invalid domain requested";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 2: Using parse_url to validate URL scheme
function good_case_2() {
    $url = $_POST['target'];
    $parsed_url = parse_url($url);
    
    if (isset($parsed_url['scheme']) && in_array($parsed_url['scheme'], ['http', 'https']) && 
        isset($parsed_url['host']) && !in_array($parsed_url['host'], ['localhost', '127.0.0.1'])) {
        // ok: php-ssrf
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        echo $response;
    } else {
        echo "Invalid URL scheme or host";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 3: Hardcoded URL (no user input)
function good_case_3() {
    $url = "https://api.example.com/data.json";
    // ok: php-ssrf
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 4: IP address validation
function good_case_4() {
    $server = $_GET['server'];
    $parsed_url = parse_url($server);
    
    if (isset($parsed_url['host'])) {
        $ip = gethostbyname($parsed_url['host']);
        // Check if IP is not in private ranges
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            echo "Access to internal networks is not allowed";
            return;
        }
        
        // ok: php-ssrf
        $content = file_get_contents($server);
        echo $content;
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 5: Using a fixed base URL with validated path
function good_case_5() {
    $path = $_GET['path'];
    // Validate path contains only allowed characters
    if (preg_match('/^[a-zA-Z0-9\/_-]+$/', $path)) {
        $base_url = "https://api.example.com";
        $url = $base_url . $path;
        // ok: php-ssrf
        $response = file_get_contents($url);
        echo $response;
    } else {
        echo "Invalid path requested";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 6: Using a predefined mapping for URLs
function good_case_6() {
    $service_id = $_POST['service'];
    $service_map = [
        'weather' => 'https://weather-api.example.com',
        'news' => 'https://news-api.example.com',
        'sports' => 'https://sports-api.example.com'
    ];
    
    if (array_key_exists($service_id, $service_map)) {
        $url = $service_map[$service_id] . "/data";
        // ok: php-ssrf
        $response = file_get_contents($url);
        echo $response;
    } else {
        echo "Unknown service requested";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 7: Using DNS resolution validation
function good_case_7() {
    $hostname = $_GET['hostname'];
    // Validate hostname format
    if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/', $hostname)) {
        $ip = gethostbyname($hostname);
        // Check if IP is public
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $url = "https://" . $hostname . "/api/data";
            // ok: php-ssrf
            $response = file_get_contents($url);
            echo $response;
        } else {
            echo "Hostname resolves to a private IP address";
        }
    } else {
        echo "Invalid hostname format";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 8: Using a proxy service
function good_case_8() {
    $target_url = $_GET['url'];
    // Instead of directly accessing the URL, send it to a proxy service
    $proxy_url = "https://internal-proxy.example.com/fetch";
    $data = ['target' => $target_url];
    
    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    $context = stream_context_create($options);
    // ok: php-ssrf
    $result = file_get_contents($proxy_url, false, $context);
    echo $result;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 9: URL validation with regex
function good_case_9() {
    $url = $_POST['webhook'];
    // Only allow specific domain patterns
    if (preg_match('/^https:\/\/([\w-]+\.)*example\.com\/[\w\/-]*$/', $url)) {
        // ok: php-ssrf
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        echo $response;
    } else {
        echo "Invalid webhook URL";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 10: Using a URL builder with fixed components
function good_case_10() {
    $resource_id = $_GET['id'];
    // Validate resource ID is numeric
    if (is_numeric($resource_id)) {
        $api_base = "https://api.example.com";
        $endpoint = "/resources/";
        $url = $api_base . $endpoint . $resource_id;
        // ok: php-ssrf
        $response = file_get_contents($url);
        echo $response;
    } else {
        echo "Invalid resource ID";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 11: Using a hash-based verification system
function good_case_11() {
    $url = $_GET['url'];
    $signature = $_GET['signature'];
    $secret_key = "YOUR_SECRET_KEY";
    
    // Verify the URL hasn't been tampered with
    $expected_signature = hash_hmac('sha256', $url, $secret_key);
    
    if (hash_equals($expected_signature, $signature)) {
        $parsed_url = parse_url($url);
        // Additional validation
        if (isset($parsed_url['host']) && substr($parsed_url['host'], -12) === '.example.com') {
            // ok: php-ssrf
            $response = file_get_contents($url);
            echo $response;
        } else {
            echo "URL not from allowed domain";
        }
    } else {
        echo "URL signature verification failed";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 12: Using a URL builder with parameter validation
function good_case_12() {
    $action = $_GET['action'];
    $id = $_GET['id'];
    
    // Validate parameters
    if (!in_array($action, ['view', 'edit', 'delete']) || !preg_match('/^[0-9]+$/', $id)) {
        echo "Invalid parameters";
        return;
    }
    
    $url = "https://api.example.com/records/{$action}/{$id}";
    // ok: php-ssrf
    $response = file_get_contents($url);
    echo $response;
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 13: Using a service registry
function good_case_13() {
    $service_name = $_POST['service'];
    
    // Service registry with predefined URLs
    $registry = [
        'users' => 'https://users.example.com/api',
        'products' => 'https://products.example.com/api',
        'orders' => 'https://orders.example.com/api'
    ];
    
    if (array_key_exists($service_name, $registry)) {
        $url = $registry[$service_name];
        // ok: php-ssrf
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);
        echo $response;
    } else {
        echo "Unknown service requested";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 14: Using URL validation library
function good_case_14() {
    $url = $_GET['url'];
    
    // This is a placeholder for a URL validation library function
    function validateUrl($url) {
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            return false;
        }
        
        // Check scheme
        if (!in_array($parsed['scheme'], ['http', 'https'])) {
            return false;
        }
        
        // Check for private IPs
        $ip = gethostbyname($parsed['host']);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        
        // Check domain against whitelist
        $allowed_domains = ['api.example.com', 'cdn.example.com', 'public-api.example.org'];
        if (!in_array($parsed['host'], $allowed_domains)) {
            return false;
        }
        
        return true;
    }
    
    if (validateUrl($url)) {
        // ok: php-ssrf
        $response = file_get_contents($url);
        echo $response;
    } else {
        echo "URL validation failed";
    }
}
// {/fact}
// {fact rule=server-side-request-forgery@v1.0 defects=0}

// Example 15: Using environment configuration for URLs
function good_case_15() {
    $endpoint = $_GET['endpoint'];
    
    // Load configuration from environment or config file
    $config = [
        'api_base' => getenv('API_BASE_URL') ?: 'https://api.example.com',
        'allowed_endpoints' => ['users', 'products', 'orders', 'reports']
    ];
    
    if (in_array($endpoint, $config['allowed_endpoints'])) {
        $url = $config['api_base'] . '/' . $endpoint;
        // ok: php-ssrf
        $response = file_get_contents($url);
        echo $response;
    } else {
        echo "Invalid endpoint requested";
    }
}
// {/fact}
?>