<?php
/**
 * Test cases for php-curl-ssl-verifypeer-off rule
 * This rule detects when SSL certificate verification is disabled in cURL requests
 */
// {fact rule=insecure-cookie@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable code examples)

function bad_case_1() {
    // Simple case of disabling SSL verification
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_2() {
    // Using 0 instead of false
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_3() {
    // Using a variable that's set to false
    $verify = false;
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_4() {
    // Using curl_setopt_array with SSL verification disabled
    $ch = curl_init();
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://example.com/api',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_5() {
    // Disabling both VERIFYPEER and setting VERIFYHOST to 0
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_6() {
    // Disabling verification in a loop for multiple URLs
    $urls = ['https://example1.com', 'https://example2.com'];
    $responses = [];
    
    foreach ($urls as $url) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // ruleid: php-curl-ssl-verifypeer-off
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $responses[] = curl_exec($ch);
        curl_close($ch);
    }
    
    return $responses;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_7() {
    // Using a ternary operator that evaluates to false
    $isProduction = false;
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $isProduction ? true : false);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_8() {
    // Disabling verification based on environment condition
    $environment = 'development';
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    if ($environment === 'development') {
        // ruleid: php-curl-ssl-verifypeer-off
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    }
    
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_9() {
    // Using curl_setopt_array with a prepared options array
    $options = [
        CURLOPT_URL => 'https://example.com/api',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_TIMEOUT => 30
    ];
    
    $ch = curl_init();
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_10() {
    // Disabling verification in a try-catch block
    try {
        $ch = curl_init('https://example.com/api');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        // ruleid: php-curl-ssl-verifypeer-off
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    } catch (Exception $e) {
        return null;
    }
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_11() {
    // Using a function that returns false
    function getVerificationSetting() {
        return false;
    }
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, getVerificationSetting());
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_12() {
    // Using a constant that's set to false
    define('VERIFY_SSL', false);
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, VERIFY_SSL);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_13() {
    // Using class property that's set to false
    class ApiClient {
        private $verifySSL = false;
        
        public function makeRequest() {
            $ch = curl_init('https://example.com/api');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            // ruleid: php-curl-ssl-verifypeer-off
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifySSL);
            $response = curl_exec($ch);
            curl_close($ch);
            return $response;
        }
    }
    
    $client = new ApiClient();
    return $client->makeRequest();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_14() {
    // Using bitwise operations that evaluate to 0
    $securityLevel = 2;
    $disableFlag = 2;
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $securityLevel & $disableFlag ? true : false);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=1}

function bad_case_15() {
    // Using a configuration array from a database (simulated)
    function getConfigFromDb() {
        return [
            'timeout' => 30,
            'verify_ssl' => false,
            'follow_redirects' => true
        ];
    }
    
    $config = getConfigFromDb();
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ruleid: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $config['verify_ssl']);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

// TRUE NEGATIVES (Secure code examples)

function good_case_1() {
    // Simple case of enabling SSL verification (default behavior)
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_2() {
    // Using 1 instead of true
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_3() {
    // Using a variable that's set to true
    $verify = true;
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_4() {
    // Using curl_setopt_array with SSL verification enabled
    $ch = curl_init();
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://example.com/api',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 30
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_5() {
    // Enabling both VERIFYPEER and setting VERIFYHOST to 2
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_6() {
    // Not setting CURLOPT_SSL_VERIFYPEER at all (defaults to true)
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    // No explicit CURLOPT_SSL_VERIFYPEER setting, so it defaults to true
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_7() {
    // Using a ternary operator that evaluates to true
    $isProduction = true;
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $isProduction ? true : false);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_8() {
    // Setting verification based on environment condition
    $environment = 'production';
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    // ok: php-curl-ssl-verifypeer-off
    if ($environment === 'production') {
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    } else {
        // Even in development, we keep verification on
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    }
    
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_9() {
    // Using curl_setopt_array with a prepared options array
    $options = [
        CURLOPT_URL => 'https://example.com/api',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_TIMEOUT => 30
    ];
    
    $ch = curl_init();
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_10() {
    // Using a custom CA certificate
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_CAINFO, '/path/to/ca-bundle.crt');
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_11() {
    // Using a function that returns true
    function getVerificationSetting() {
        return true;
    }
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, getVerificationSetting());
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_12() {
    // Using a constant that's set to true
    define('VERIFY_SSL', true);
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, VERIFY_SSL);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_13() {
    // Using class property that's set to true
    class SecureApiClient {
        private $verifySSL = true;
        
        public function makeRequest() {
            $ch = curl_init('https://example.com/api');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            // ok: php-curl-ssl-verifypeer-off
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $this->verifySSL);
            $response = curl_exec($ch);
            curl_close($ch);
            return $response;
        }
    }
    
    $client = new SecureApiClient();
    return $client->makeRequest();
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_14() {
    // Using bitwise operations that evaluate to non-zero
    $securityLevel = 3;
    $enableFlag = 1;
    
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $securityLevel & $enableFlag ? true : false);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
// {fact rule=insecure-cookie@v1.0 defects=0}

function good_case_15() {
    // Using a configuration array from a database (simulated)
    function getSecureConfigFromDb() {
        return [
            'timeout' => 30,
            'verify_ssl' => true,
            'follow_redirects' => true
        ];
    }
    
    $config = getSecureConfigFromDb();
    $ch = curl_init('https://example.com/api');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    // ok: php-curl-ssl-verifypeer-off
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $config['verify_ssl']);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
// {/fact}
?>