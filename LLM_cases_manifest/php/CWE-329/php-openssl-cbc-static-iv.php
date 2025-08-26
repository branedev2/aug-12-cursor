<?php
// {fact rule=static-initialization-vector@v1.0 defects=1}

// TRUE POSITIVES - Vulnerable code using static IVs

function bad_case_1() {
    $plaintext = "This is a secret message";
    $key = "ThisIsA32ByteKeyForAES256CBCMode!";
    // ruleid: php-openssl-cbc-static-iv
    $iv = "1234567890123456"; // Static IV
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_2() {
    $data = "Sensitive information";
    $encryption_key = hash('sha256', 'secret_key', true);
    // ruleid: php-openssl-cbc-static-iv
    $iv = "abcdefghijklmnop"; // Hardcoded static IV
    $encrypted = openssl_encrypt($data, 'AES-128-CBC', $encryption_key, 0, $iv);
    echo "Encrypted: " . $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_3() {
    $message = $_POST['user_message'];
    $secret_key = getenv('APP_SECRET_KEY');
    // ruleid: php-openssl-cbc-static-iv
    $static_iv = hex2bin("PLACEHOLDER_SECRET_32_CHARS"); // Static IV in hex
    $ciphertext = openssl_encrypt($message, 'AES-256-CBC', $secret_key, OPENSSL_RAW_DATA, $static_iv);
    return base64_encode($ciphertext);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_4() {
    $config = [
        'key' => 'my-secure-encryption-key-12345',
        // ruleid: php-openssl-cbc-static-iv
        'iv' => 'constant-iv-value' // Static IV defined in configuration
    ];
    
    $data = file_get_contents('sensitive_file.txt');
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $config['key'], 0, $config['iv']);
    file_put_contents('encrypted_data.enc', $encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_5() {
    class Encryptor {
        private $key;
        // ruleid: php-openssl-cbc-static-iv
        private $iv = "ThisIsMyStaticIV"; // Static IV as class property
        
        public function __construct($key) {
            $this->key = $key;
        }
        
        public function encrypt($data) {
            return openssl_encrypt($data, 'AES-256-CBC', $this->key, 0, $this->iv);
        }
    }
    
    $encryptor = new Encryptor("SecretKey123456789012345678901234");
    return $encryptor->encrypt("Secret data");
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_6() {
    define('ENCRYPTION_IV', 'staticIVfor16byte'); // Defined constant for IV
    $key = hash('sha256', 'encryption_key');
    $data = $_GET['data'];
    
    // ruleid: php-openssl-cbc-static-iv
    $encrypted = openssl_encrypt($data, 'AES-128-CBC', $key, 0, ENCRYPTION_IV);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_7() {
    $user_data = [
        'name' => $_POST['name'],
        'ssn' => $_POST['ssn']
    ];
    
    $json = json_encode($user_data);
    $encryption_key = getenv('ENCRYPTION_KEY');
    // ruleid: php-openssl-cbc-static-iv
    $iv = str_repeat("A", 16); // Static IV using repeated character
    
    $encrypted = openssl_encrypt($json, 'AES-256-CBC', $encryption_key, 0, $iv);
    store_encrypted_data($encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_8() {
    function get_encryption_iv() {
        // ruleid: php-openssl-cbc-static-iv
        return "FixedIVForEncrypt"; // Function that returns a static IV
    }
    
    $data = $_POST['credit_card'];
    $key = fetch_encryption_key();
    $iv = get_encryption_iv();
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_9() {
    $data = file_get_contents('php://input');
    $key = hash('sha256', $_ENV['SECRET_KEY'], true);
    // ruleid: php-openssl-cbc-static-iv
    $iv = base64_decode("AAECAwQFBgcICQoLDA0ODw=="); // Static IV encoded in base64
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    echo base64_encode($encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_10() {
    // Encryption function with static IV
    function encrypt_data($data, $key) {
        // ruleid: php-openssl-cbc-static-iv
        $iv = "0123456789abcdef"; // Static IV inside function
        return openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    }
    
    $user_message = $_POST['message'];
    $encryption_key = get_key_from_config();
    $encrypted = encrypt_data($user_message, $encryption_key);
    store_message($encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_11() {
    $encryption_settings = [
        'algorithm' => 'AES-256-CBC',
        'key' => hash('sha256', 'master_key', true),
        // ruleid: php-openssl-cbc-static-iv
        'iv' => substr(hash('sha256', 'static_salt', true), 0, 16) // Derived but still static IV
    ];
    
    $data = $_GET['user_data'];
    $encrypted = openssl_encrypt(
        $data,
        $encryption_settings['algorithm'],
        $encryption_settings['key'],
        0,
        $encryption_settings['iv']
    );
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_12() {
    // Global static IV
    global $GLOBAL_IV;
    if (!isset($GLOBAL_IV)) {
        // ruleid: php-openssl-cbc-static-iv
        $GLOBAL_IV = "GlobalStaticIValue";
    }
    
    $data = $_POST['password'];
    $key = getenv('PASSWORD_ENCRYPTION_KEY');
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $GLOBAL_IV);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_13() {
    $user_id = $_SESSION['user_id'];
    $data = $_POST['confidential_data'];
    
    // ruleid: php-openssl-cbc-static-iv
    $iv = md5('fixed_string', true); // Using hash of fixed string as IV - still static
    $key = get_user_encryption_key($user_id);
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, substr($iv, 0, 16));
    save_encrypted_data($user_id, $encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_14() {
    // Using environment variable for IV, but it's still static across multiple encryptions
    // ruleid: php-openssl-cbc-static-iv
    $static_iv = getenv('ENCRYPTION_IV') ?: "DefaultStaticIV123";
    
    $plaintext = $_GET['text_to_encrypt'];
    $key = getenv('ENCRYPTION_KEY');
    
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $static_iv);
    echo $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=1}

function bad_case_15() {
    class StaticIVEncryptor {
        private $key;
        
        public function __construct($key) {
            $this->key = $key;
        }
        
        public function encrypt($data) {
            // ruleid: php-openssl-cbc-static-iv
            $iv = "StaticIVInMethod!"; // Static IV in method
            return openssl_encrypt($data, 'AES-256-CBC', $this->key, 0, $iv);
        }
    }
    
    $encryptor = new StaticIVEncryptor($_ENV['APP_KEY']);
    $encrypted = $encryptor->encrypt($_POST['secret_message']);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

// TRUE NEGATIVES - Secure code using random IVs

function good_case_1() {
    $plaintext = "This is a secret message";
    $key = "ThisIsA32ByteKeyForAES256CBCMode!";
    // ok: php-openssl-cbc-static-iv
    $iv = openssl_random_pseudo_bytes(16); // Random IV
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    // Store IV with ciphertext for decryption
    $result = base64_encode($iv . $encrypted);
    return $result;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_2() {
    $data = "Sensitive information";
    $encryption_key = hash('sha256', 'secret_key', true);
    // ok: php-openssl-cbc-static-iv
    $iv_length = openssl_cipher_iv_length('AES-128-CBC');
    $iv = openssl_random_pseudo_bytes($iv_length);
    
    $encrypted = openssl_encrypt($data, 'AES-128-CBC', $encryption_key, 0, $iv);
    echo "Encrypted: " . $encrypted . " IV: " . base64_encode($iv);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_3() {
    $message = $_POST['user_message'];
    $secret_key = getenv('APP_SECRET_KEY');
    
    // ok: php-openssl-cbc-static-iv
    $iv = random_bytes(16); // Using random_bytes for IV generation
    $ciphertext = openssl_encrypt($message, 'AES-256-CBC', $secret_key, OPENSSL_RAW_DATA, $iv);
    
    // Store IV with ciphertext
    $encrypted_data = base64_encode($iv . $ciphertext);
    return $encrypted_data;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_4() {
    $config = [
        'key' => 'my-secure-encryption-key-12345'
    ];
    
    $data = file_get_contents('sensitive_file.txt');
    // ok: php-openssl-cbc-static-iv
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $config['key'], 0, $iv);
    
    // Save both IV and encrypted data
    file_put_contents('encrypted_data.enc', base64_encode($iv) . '|' . $encrypted);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_5() {
    class SecureEncryptor {
        private $key;
        
        public function __construct($key) {
            $this->key = $key;
        }
        
        public function encrypt($data) {
            // ok: php-openssl-cbc-static-iv
            $iv = random_bytes(16); // Generate new IV for each encryption
            $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->key, 0, $iv);
            return [
                'iv' => base64_encode($iv),
                'data' => $encrypted
            ];
        }
    }
    
    $encryptor = new SecureEncryptor("SecretKey123456789012345678901234");
    return $encryptor->encrypt("Secret data");
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_6() {
    $key = hash('sha256', 'encryption_key');
    $data = $_GET['data'];
    
    // ok: php-openssl-cbc-static-iv
    $iv_size = openssl_cipher_iv_length('AES-128-CBC');
    $iv = openssl_random_pseudo_bytes($iv_size);
    
    $encrypted = openssl_encrypt($data, 'AES-128-CBC', $key, 0, $iv);
    return ['iv' => base64_encode($iv), 'encrypted' => $encrypted];
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_7() {
    $user_data = [
        'name' => $_POST['name'],
        'ssn' => $_POST['ssn']
    ];
    
    $json = json_encode($user_data);
    $encryption_key = getenv('ENCRYPTION_KEY');
    
    // ok: php-openssl-cbc-static-iv
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($json, 'AES-256-CBC', $encryption_key, 0, $iv);
    
    // Store both IV and encrypted data
    store_encrypted_data(['iv' => bin2hex($iv), 'data' => $encrypted]);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_8() {
    function get_random_iv() {
        // ok: php-openssl-cbc-static-iv
        return random_bytes(16); // Function that returns a random IV
    }
    
    $data = $_POST['credit_card'];
    $key = fetch_encryption_key();
    $iv = get_random_iv();
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    return ['encrypted' => $encrypted, 'iv' => base64_encode($iv)];
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_9() {
    $data = file_get_contents('php://input');
    $key = hash('sha256', $_ENV['SECRET_KEY'], true);
    
    // ok: php-openssl-cbc-static-iv
    $iv_length = openssl_cipher_iv_length('AES-256-CBC');
    $iv = openssl_random_pseudo_bytes($iv_length);
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    echo json_encode([
        'iv' => base64_encode($iv),
        'encrypted' => base64_encode($encrypted)
    ]);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_10() {
    // Encryption function with random IV
    function encrypt_data($data, $key) {
        // ok: php-openssl-cbc-static-iv
        $iv = openssl_random_pseudo_bytes(16); // Random IV inside function
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        return [
            'iv' => base64_encode($iv),
            'encrypted' => $encrypted
        ];
    }
    
    $user_message = $_POST['message'];
    $encryption_key = get_key_from_config();
    $result = encrypt_data($user_message, $encryption_key);
    store_message($result);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_11() {
    $encryption_settings = [
        'algorithm' => 'AES-256-CBC',
        'key' => hash('sha256', 'master_key', true)
    ];
    
    $data = $_GET['user_data'];
    
    // ok: php-openssl-cbc-static-iv
    $iv = random_bytes(16); // Generate fresh IV for each encryption
    
    $encrypted = openssl_encrypt(
        $data,
        $encryption_settings['algorithm'],
        $encryption_settings['key'],
        0,
        $iv
    );
    
    return ['encrypted' => $encrypted, 'iv' => bin2hex($iv)];
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_12() {
    $data = $_POST['password'];
    $key = getenv('PASSWORD_ENCRYPTION_KEY');
    
    // ok: php-openssl-cbc-static-iv
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    
    // Store IV with encrypted data for later decryption
    $_SESSION['password_iv'] = base64_encode($iv);
    return $encrypted;
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_13() {
    $user_id = $_SESSION['user_id'];
    $data = $_POST['confidential_data'];
    $key = get_user_encryption_key($user_id);
    
    // ok: php-openssl-cbc-static-iv
    $iv_size = openssl_cipher_iv_length('AES-256-CBC');
    $iv = random_bytes($iv_size);
    
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
    save_encrypted_data($user_id, [
        'iv' => base64_encode($iv),
        'data' => $encrypted
    ]);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_14() {
    // Using a unique IV for each encryption operation
    $plaintext = $_GET['text_to_encrypt'];
    $key = getenv('ENCRYPTION_KEY');
    
    // ok: php-openssl-cbc-static-iv
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', $key, 0, $iv);
    
    // Return both IV and encrypted data
    echo json_encode([
        'iv' => base64_encode($iv),
        'ciphertext' => $encrypted
    ]);
}
// {/fact}
// {fact rule=static-initialization-vector@v1.0 defects=0}

function good_case_15() {
    class SecureIVEncryptor {
        private $key;
        
        public function __construct($key) {
            $this->key = $key;
        }
        
        public function encrypt($data) {
            // ok: php-openssl-cbc-static-iv
            $iv = random_bytes(16); // Generate new IV for each encryption
            $encrypted = openssl_encrypt($data, 'AES-256-CBC', $this->key, 0, $iv);
            
            // Return both IV and encrypted data in a structured format
            return [
                'iv' => bin2hex($iv),
                'encrypted' => $encrypted,
                'timestamp' => time()
            ];
        }
    }
    
    $encryptor = new SecureIVEncryptor($_ENV['APP_KEY']);
    $encrypted_data = $encryptor->encrypt($_POST['secret_message']);
    return $encrypted_data;
}
// {/fact}
?>