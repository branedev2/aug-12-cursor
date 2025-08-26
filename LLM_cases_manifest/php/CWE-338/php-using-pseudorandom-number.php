I'll create 30 examples (15 true positives and 15 true negatives) for the PHP rule "php-using-pseudorandom-number" which detects the use of non-cryptographic PRNGs in security-sensitive scenarios.

This is a configuration/usage issue related to CWE-338 (Use of Cryptographically Weak Pseudo-Random Number Generator). The rule detects when insecure random number generation functions like `rand()`, `mt_rand()`, or `uniqid()` are used in security contexts where cryptographically secure random numbers are required.

```php
<?php
// {fact rule=weak-random-number-generation@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Generate a token for password reset using insecure random function
    $token = md5(uniqid(rand(), true));
    // ruleid: php-using-pseudorandom-number
    $resetLink = "https://example.com/reset-password?token=" . $token;
    
    // Send the reset link to the user
    mail("user@example.com", "Password Reset", "Click here to reset your password: $resetLink");
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_2() {
    // Generate a session ID using mt_rand()
    $sessionId = "";
    for ($i = 0; $i < 32; $i++) {
        // ruleid: php-using-pseudorandom-number
        $sessionId .= chr(mt_rand(0, 255));
    }
    
    // Set the session ID
    session_id(bin2hex($sessionId));
    session_start();
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_3() {
    // Generate an API key using rand()
    $apiKey = "";
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    
    for ($i = 0; $i < 32; $i++) {
        // ruleid: php-using-pseudorandom-number
        $apiKey .= $chars[rand(0, strlen($chars) - 1)];
    }
    
    // Store the API key in the database
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)");
    $stmt->execute([1, $apiKey]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_4() {
    // Generate a CSRF token using uniqid
    // ruleid: php-using-pseudorandom-number
    $_SESSION['csrf_token'] = md5(uniqid());
    
    echo '<form method="post">';
    echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
    echo '<input type="submit" value="Submit">';
    echo '</form>';
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_5() {
    // Generate an encryption key using mt_rand()
    $key = "";
    for ($i = 0; $i < 32; $i++) {
        // ruleid: php-using-pseudorandom-number
        $key .= chr(mt_rand(0, 255));
    }
    
    // Use the key for encryption
    $data = "Sensitive information";
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_6() {
    // Generate a random password using rand()
    $password = "";
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    
    for ($i = 0; $i < 12; $i++) {
        // ruleid: php-using-pseudorandom-number
        $password .= $chars[rand(0, strlen($chars) - 1)];
    }
    
    // Hash the password and store it
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    echo "Your new password is: $password";
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_7() {
    // Generate a nonce for OAuth using mt_rand()
    // ruleid: php-using-pseudorandom-number
    $nonce = md5(mt_rand());
    
    $oauth_params = [
        'oauth_consumer_key' => 'consumer_key',
        'oauth_nonce' => $nonce,
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_timestamp' => time(),
        'oauth_version' => '1.0'
    ];
    
    // Use the nonce in OAuth request
    $signature_base_string = "GET&https%3A%2F%2Fapi.example.com&" . http_build_query($oauth_params);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_8() {
    // Generate a salt for password hashing using rand()
    $salt = "";
    for ($i = 0; $i < 16; $i++) {
        // ruleid: php-using-pseudorandom-number
        $salt .= chr(rand(33, 126));
    }
    
    // Use the salt in a custom hashing function
    $password = "user_password";
    $hashedPassword = hash('sha256', $password . $salt);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_9() {
    // Generate a random filename for uploaded file using uniqid
    $uploadedFile = $_FILES['document'];
    $fileExtension = pathinfo($uploadedFile['name'], PATHINFO_EXTENSION);
    
    // ruleid: php-using-pseudorandom-number
    $newFilename = uniqid() . '.' . $fileExtension;
    
    // Move the uploaded file to a secure location
    move_uploaded_file($uploadedFile['tmp_name'], '/var/www/uploads/' . $newFilename);
    
    // Store the filename in the database for sensitive documents
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO secure_documents (filename) VALUES (?)");
    $stmt->execute([$newFilename]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_10() {
    // Generate initialization vector for encryption using mt_rand()
    $iv = '';
    for ($i = 0; $i < 16; $i++) {
        // ruleid: php-using-pseudorandom-number
        $iv .= chr(mt_rand(0, 255));
    }
    
    // Use the IV for encryption
    $data = "Confidential data";
    $key = "ThisIsASecretKey";
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_11() {
    // Generate a random challenge for two-factor authentication
    // ruleid: php-using-pseudorandom-number
    $challenge = '';
    for ($i = 0; $i < 6; $i++) {
        $challenge .= rand(0, 9);
    }
    
    // Send the challenge to the user's phone
    $phone = "1234567890";
    $message = "Your authentication code is: $challenge";
    // sendSMS($phone, $message);
    
    // Store the challenge for verification
    $_SESSION['2fa_challenge'] = $challenge;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_12() {
    // Generate a JWT token with insecure jti (JWT ID) claim
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    
    $payload = [
        'sub' => '1234567890',
        'name' => 'John Doe',
        'iat' => time(),
        'exp' => time() + 3600,
        // ruleid: php-using-pseudorandom-number
        'jti' => md5(uniqid(mt_rand(), true))
    ];
    
    $headerEncoded = base64_encode(json_encode($header));
    $payloadEncoded = base64_encode(json_encode($payload));
    $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", 'secret', true);
    $signatureEncoded = base64_encode($signature);
    
    $jwt = "$headerEncoded.$payloadEncoded.$signatureEncoded";
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_13() {
    // Generate a random seed for a cryptographic operation
    // ruleid: php-using-pseudorandom-number
    $seed = rand(1, 1000000);
    
    // Use the seed to derive a key
    $key = hash('sha256', (string)$seed);
    
    // Use the key for encryption
    $data = "Top secret information";
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_14() {
    // Generate a random UUID using mt_rand()
    // ruleid: php-using-pseudorandom-number
    $uuid = sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
    
    // Use the UUID as a unique identifier for a secure document
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO secure_documents (uuid, content) VALUES (?, ?)");
    $stmt->execute([$uuid, "Sensitive document content"]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

function bad_case_15() {
    // Generate a random salt for HMAC using uniqid
    // ruleid: php-using-pseudorandom-number
    $salt = uniqid('', true);
    
    // Use the salt in HMAC for API authentication
    $message = "api_key=12345&timestamp=" . time();
    $signature = hash_hmac('sha256', $message, $salt);
    
    // Send the request with the signature
    $url = "https://api.example.com/secure-endpoint?$message&signature=$signature";
    file_get_contents($url);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // Generate a token for password reset using secure random function
    // ok: php-using-pseudorandom-number
    $token = bin2hex(random_bytes(32));
    
    $resetLink = "https://example.com/reset-password?token=" . $token;
    
    // Send the reset link to the user
    mail("user@example.com", "Password Reset", "Click here to reset your password: $resetLink");
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_2() {
    // Generate a session ID using random_bytes()
    // ok: php-using-pseudorandom-number
    $sessionId = random_bytes(32);
    
    // Set the session ID
    session_id(bin2hex($sessionId));
    session_start();
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_3() {
    // Generate an API key using random_bytes()
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    $apiKey = "";
    
    // ok: php-using-pseudorandom-number
    $bytes = random_bytes(32);
    
    for ($i = 0; $i < 32; $i++) {
        $apiKey .= $chars[ord($bytes[$i]) % strlen($chars)];
    }
    
    // Store the API key in the database
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)");
    $stmt->execute([1, $apiKey]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_4() {
    // Generate a CSRF token using random_bytes
    // ok: php-using-pseudorandom-number
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    echo '<form method="post">';
    echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';
    echo '<input type="submit" value="Submit">';
    echo '</form>';
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_5() {
    // Generate an encryption key using random_bytes()
    // ok: php-using-pseudorandom-number
    $key = random_bytes(32);
    
    // Use the key for encryption
    $data = "Sensitive information";
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_6() {
    // Generate a random password using random_int()
    $password = "";
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    
    for ($i = 0; $i < 12; $i++) {
        // ok: php-using-pseudorandom-number
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    
    // Hash the password and store it
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    echo "Your new password is: $password";
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_7() {
    // Generate a nonce for OAuth using random_bytes()
    // ok: php-using-pseudorandom-number
    $nonce = bin2hex(random_bytes(16));
    
    $oauth_params = [
        'oauth_consumer_key' => 'consumer_key',
        'oauth_nonce' => $nonce,
        'oauth_signature_method' => 'HMAC-SHA1',
        'oauth_timestamp' => time(),
        'oauth_version' => '1.0'
    ];
    
    // Use the nonce in OAuth request
    $signature_base_string = "GET&https%3A%2F%2Fapi.example.com&" . http_build_query($oauth_params);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_8() {
    // Generate a salt for password hashing using random_bytes()
    // ok: php-using-pseudorandom-number
    $salt = random_bytes(16);
    
    // Use the salt in a custom hashing function
    $password = "user_password";
    $hashedPassword = hash('sha256', $password . bin2hex($salt));
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_9() {
    // Generate a random filename for uploaded file using random_bytes
    $uploadedFile = $_FILES['document'];
    $fileExtension = pathinfo($uploadedFile['name'], PATHINFO_EXTENSION);
    
    // ok: php-using-pseudorandom-number
    $newFilename = bin2hex(random_bytes(16)) . '.' . $fileExtension;
    
    // Move the uploaded file to a secure location
    move_uploaded_file($uploadedFile['tmp_name'], '/var/www/uploads/' . $newFilename);
    
    // Store the filename in the database for sensitive documents
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO secure_documents (filename) VALUES (?)");
    $stmt->execute([$newFilename]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_10() {
    // Generate initialization vector for encryption using random_bytes()
    // ok: php-using-pseudorandom-number
    $iv = random_bytes(16);
    
    // Use the IV for encryption
    $data = "Confidential data";
    $key = "ThisIsASecretKey";
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_11() {
    // Generate a random challenge for two-factor authentication using random_int()
    $challenge = '';
    
    for ($i = 0; $i < 6; $i++) {
        // ok: php-using-pseudorandom-number
        $challenge .= random_int(0, 9);
    }
    
    // Send the challenge to the user's phone
    $phone = "1234567890";
    $message = "Your authentication code is: $challenge";
    // sendSMS($phone, $message);
    
    // Store the challenge for verification
    $_SESSION['2fa_challenge'] = $challenge;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_12() {
    // Generate a JWT token with secure jti (JWT ID) claim
    $header = [
        'alg' => 'HS256',
        'typ' => 'JWT'
    ];
    
    $payload = [
        'sub' => '1234567890',
        'name' => 'John Doe',
        'iat' => time(),
        'exp' => time() + 3600,
        // ok: php-using-pseudorandom-number
        'jti' => bin2hex(random_bytes(16))
    ];
    
    $headerEncoded = base64_encode(json_encode($header));
    $payloadEncoded = base64_encode(json_encode($payload));
    $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", 'secret', true);
    $signatureEncoded = base64_encode($signature);
    
    $jwt = "$headerEncoded.$payloadEncoded.$signatureEncoded";
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_13() {
    // Generate a random seed for a cryptographic operation using random_bytes
    // ok: php-using-pseudorandom-number
    $seed = random_bytes(32);
    
    // Use the seed to derive a key
    $key = hash('sha256', $seed);
    
    // Use the key for encryption
    $data = "Top secret information";
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_14() {
    // Generate a random UUID using random_bytes()
    // ok: php-using-pseudorandom-number
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // Set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // Set bits 6-7 to 10
    
    $uuid = vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    
    // Use the UUID as a unique identifier for a secure document
    $db = new PDO("mysql:host=localhost;dbname=app", "user", "password");
    $stmt = $db->prepare("INSERT INTO secure_documents (uuid, content) VALUES (?, ?)");
    $stmt->execute([$uuid, "Sensitive document content"]);
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

function good_case_15() {
    // Generate a random salt for HMAC using random_bytes
    // ok: php-using-pseudorandom-number
    $salt = bin2hex(random_bytes(32));
    
    // Use the salt in HMAC for API authentication
    $message = "api_key=12345&timestamp=" . time();
    $signature = hash_hmac('sha256', $message, $salt);
    
    // Send the request with the signature
    $url = "https://api.example.com/secure-endpoint?$message&signature=$signature";
    file_get_contents($url);
}
// {/fact}
?>