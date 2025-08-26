<?php
/**
 * Test cases for php-weak-crypto rule
 * This file contains examples of secure and insecure cryptographic implementations in PHP
 */
// {fact rule=clear-text-credentials@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    $password = "user_password";
    $salt = "static_salt";
    
    // ruleid: php-weak-crypto
    $hash = md5($password . $salt);
    
    return $hash;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_2() {
    $data = "sensitive information";
    $key = "encryption_key";
    
    // ruleid: php-weak-crypto
    $encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
    
    return base64_encode($encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_3() {
    $password = $_POST['password'];
    
    // ruleid: php-weak-crypto
    $hash = sha1($password);
    
    // Store hash in database
    $db->query("INSERT INTO users (password_hash) VALUES ('$hash')");
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_4() {
    $data = file_get_contents("sensitive_file.txt");
    $key = "my_secret_key";
    
    // ruleid: php-weak-crypto
    $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);
    $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
    
    return base64_encode($iv . $encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_5() {
    $password = $_GET['password'];
    $username = $_GET['username'];
    
    // ruleid: php-weak-crypto
    $token = md5($username . time());
    
    setcookie("auth_token", $token, time() + 3600);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_6() {
    $message = "This is a secret message";
    $key = "secret_key";
    
    // ruleid: php-weak-crypto
    $hmac = hash_hmac("md5", $message, $key);
    
    return $hmac;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_7() {
    $password = $_POST['new_password'];
    
    // ruleid: php-weak-crypto
    $hash = crypt($password); // Uses DES by default which is weak
    
    // Store in database
    $db->query("UPDATE users SET password = '$hash' WHERE id = 1");
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_8() {
    $data = $_POST['credit_card'];
    $key = "encryption_key";
    
    // ruleid: php-weak-crypto
    $encrypted = openssl_encrypt($data, 'des-ede3-cbc', $key, 0);
    
    return $encrypted;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_9() {
    $password = "user_password";
    
    // ruleid: php-weak-crypto
    $hash = hash('md4', $password);
    
    return $hash;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_10() {
    $data = file_get_contents("sensitive_data.txt");
    $key = "encryption_key";
    
    // ruleid: php-weak-crypto
    $encrypted = openssl_encrypt($data, 'rc4', $key, 0);
    
    file_put_contents("encrypted_data.bin", $encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_11() {
    $user_input = $_POST['data'];
    
    // ruleid: php-weak-crypto
    $checksum = crc32($user_input);
    
    // Verify data integrity using checksum (insecure for cryptographic purposes)
    if ($checksum == $_POST['checksum']) {
        echo "Data verified!";
    }
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_12() {
    $password = $_POST['password'];
    $username = $_POST['username'];
    
    // ruleid: php-weak-crypto
    $hash = md5($password . $username);
    
    if (checkPasswordInDatabase($hash)) {
        echo "Login successful";
    }
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_13() {
    $data = $_POST['sensitive_data'];
    $key = getEncryptionKey();
    
    // ruleid: php-weak-crypto
    $iv = openssl_random_pseudo_bytes(8);
    $encrypted = openssl_encrypt($data, 'blowfish', $key, 0, $iv);
    
    storeEncryptedData($encrypted, $iv);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_14() {
    $password = $_GET['password'];
    $iterations = 1000;
    $salt = random_bytes(16);
    
    // ruleid: php-weak-crypto
    $hash = hash_pbkdf2('sha1', $password, $salt, $iterations, 32);
    
    return $hash;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=1}

function bad_case_15() {
    $message = $_POST['message'];
    $signature = $_POST['signature'];
    $public_key = openssl_pkey_get_public(file_get_contents('public.key'));
    
    // ruleid: php-weak-crypto
    $verify = openssl_verify($message, base64_decode($signature), $public_key, OPENSSL_ALGO_MD5);
    
    if ($verify == 1) {
        echo "Signature verified!";
    }
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    $password = "user_password";
    
    // ok: php-weak-crypto
    $hash = password_hash($password, PASSWORD_BCRYPT);
    
    return $hash;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_2() {
    $data = "sensitive information";
    $key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    
    // ok: php-weak-crypto
    $encrypted = sodium_crypto_secretbox($data, $nonce, $key);
    
    return base64_encode($nonce . $encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_3() {
    $password = $_POST['password'];
    
    // ok: php-weak-crypto
    $hash = password_hash($password, PASSWORD_ARGON2ID);
    
    // Store hash in database
    $db->query("INSERT INTO users (password_hash) VALUES ('$hash')");
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_4() {
    $data = file_get_contents("sensitive_file.txt");
    $key = random_bytes(32);
    
    // ok: php-weak-crypto
    $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $data,
        '', // additional data
        random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
        $key
    );
    
    return base64_encode($encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_5() {
    $password = $_GET['password'];
    $username = $_GET['username'];
    
    // ok: php-weak-crypto
    $token = bin2hex(random_bytes(32));
    
    setcookie("auth_token", $token, time() + 3600);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_6() {
    $message = "This is a secret message";
    $key = random_bytes(32);
    
    // ok: php-weak-crypto
    $hmac = hash_hmac("sha256", $message, $key);
    
    return $hmac;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_7() {
    $password = $_POST['new_password'];
    
    // ok: php-weak-crypto
    $hash = password_hash($password, PASSWORD_DEFAULT);
    
    // Store in database
    $db->query("UPDATE users SET password = '$hash' WHERE id = 1");
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_8() {
    $data = $_POST['credit_card'];
    $key = random_bytes(32);
    $iv = random_bytes(16);
    
    // ok: php-weak-crypto
    $encrypted = openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);
    
    return ['encrypted' => $encrypted, 'iv' => base64_encode($iv), 'tag' => base64_encode($tag)];
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_9() {
    $password = "user_password";
    
    // ok: php-weak-crypto
    $hash = hash('sha3-256', $password);
    
    return $hash;
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_10() {
    $data = file_get_contents("sensitive_data.txt");
    $key = sodium_crypto_secretbox_keybytes();
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    
    // ok: php-weak-crypto
    $encrypted = sodium_crypto_secretbox($data, $nonce, $key);
    
    file_put_contents("encrypted_data.bin", $nonce . $encrypted);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_11() {
    $user_input = $_POST['data'];
    $key = random_bytes(32);
    
    // ok: php-weak-crypto
    $hmac = hash_hmac('sha256', $user_input, $key);
    
    // Verify data integrity using HMAC
    if (hash_equals($hmac, $_POST['hmac'])) {
        echo "Data verified!";
    }
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_12() {
    $password = $_POST['password'];
    
    // Retrieve stored hash from database
    $stored_hash = getStoredHash($_POST['username']);
    
    // ok: php-weak-crypto
    if (password_verify($password, $stored_hash)) {
        echo "Login successful";
    }
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_13() {
    $data = $_POST['sensitive_data'];
    $key = getEncryptionKey();
    
    // ok: php-weak-crypto
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $encrypted = sodium_crypto_secretbox($data, $nonce, $key);
    
    storeEncryptedData($encrypted, $nonce);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_14() {
    $password = $_GET['password'];
    $iterations = 10000;
    $salt = random_bytes(16);
    
    // ok: php-weak-crypto
    $hash = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
    
    return bin2hex($hash);
}
// {/fact}
// {fact rule=clear-text-credentials@v1.0 defects=0}

function good_case_15() {
    $message = $_POST['message'];
    $signature = $_POST['signature'];
    $public_key = openssl_pkey_get_public(file_get_contents('public.key'));
    
    // ok: php-weak-crypto
    $verify = openssl_verify($message, base64_decode($signature), $public_key, OPENSSL_ALGO_SHA256);
    
    if ($verify == 1) {
        echo "Signature verified!";
    }
}
// {/fact}
?>