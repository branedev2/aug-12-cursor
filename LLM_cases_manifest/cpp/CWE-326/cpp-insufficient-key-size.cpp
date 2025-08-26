#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <cstring>
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    // Using RSA with insufficient key size (512 bits)
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    // ruleid: cpp-insufficient-key-size
    RSA_generate_key_ex(rsa, 512, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_2() {
    // Using AES with insufficient key size (64 bits)
    unsigned char key[8]; // 64-bit key
    RAND_bytes(key, sizeof(key));
    
    // ruleid: cpp-insufficient-key-size
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 64, &aes_key);
    
    // Use the key for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_3() {
    // Using DSA with insufficient key size (512 bits)
    DSA* dsa = DSA_new();
    
    // ruleid: cpp-insufficient-key-size
    DSA_generate_parameters_ex(dsa, 512, nullptr, 0, nullptr, nullptr, nullptr);
    DSA_generate_key(dsa);
    
    // Use the key for signing
    // ...
    
    DSA_free(dsa);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_4() {
    // Using DH with insufficient key size (512 bits)
    DH* dh = DH_new();
    
    // ruleid: cpp-insufficient-key-size
    DH_generate_parameters_ex(dh, 512, DH_GENERATOR_2, nullptr);
    DH_generate_key(dh);
    
    // Use the key for key exchange
    // ...
    
    DH_free(dh);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_5() {
    // Using ECC with insufficient key size (112 bits)
    EC_KEY* key = nullptr;
    
    // ruleid: cpp-insufficient-key-size
    key = EC_KEY_new_by_curve_name(NID_secp112r1); // 112-bit curve
    EC_KEY_generate_key(key);
    
    // Use the key for ECDSA
    // ...
    
    EC_KEY_free(key);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_6() {
    // Using custom RSA key generation with insufficient bits
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    // ruleid: cpp-insufficient-key-size
    int bits = 768; // Insufficient key size
    RSA_generate_key_ex(rsa, bits, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_7() {
    // Using EVP interface with insufficient RSA key size
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    
    // ruleid: cpp-insufficient-key-size
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024); // 1024 bits is now considered insufficient
    EVP_PKEY_keygen(ctx, &pkey);
    
    // Use the key for operations
    // ...
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_8() {
    // Using DES for encryption (56-bit key)
    DES_cblock key;
    DES_key_schedule schedule;
    
    // Generate random key
    RAND_bytes((unsigned char*)&key, sizeof(DES_cblock));
    
    // ruleid: cpp-insufficient-key-size
    DES_set_key_checked(&key, &schedule);
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_9() {
    // Using Blowfish with insufficient key size (32 bits)
    BF_KEY bf_key;
    unsigned char key[4]; // 32-bit key
    RAND_bytes(key, sizeof(key));
    
    // ruleid: cpp-insufficient-key-size
    BF_set_key(&bf_key, 4, key);
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_10() {
    // Using RC4 with insufficient key size (40 bits)
    RC4_KEY rc4_key;
    unsigned char key[5]; // 40-bit key
    RAND_bytes(key, sizeof(key));
    
    // ruleid: cpp-insufficient-key-size
    RC4_set_key(&rc4_key, 5, key);
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_11() {
    // Using CAST with insufficient key size (40 bits)
    CAST_KEY cast_key;
    unsigned char key[5]; // 40-bit key
    RAND_bytes(key, sizeof(key));
    
    // ruleid: cpp-insufficient-key-size
    CAST_set_key(&cast_key, 5, key);
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_12() {
    // Using ECC with insufficient curve (secp160r1 - 160 bits)
    EC_KEY* key = nullptr;
    
    // ruleid: cpp-insufficient-key-size
    key = EC_KEY_new_by_curve_name(NID_secp160r1);
    EC_KEY_generate_key(key);
    
    // Use the key for ECDSA
    // ...
    
    EC_KEY_free(key);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_13() {
    // Using Triple DES with 2 keys (effectively 112 bits)
    DES_cblock key1, key2;
    DES_key_schedule ks1, ks2, ks3;
    
    // Generate random keys
    RAND_bytes((unsigned char*)&key1, sizeof(DES_cblock));
    RAND_bytes((unsigned char*)&key2, sizeof(DES_cblock));
    
    // ruleid: cpp-insufficient-key-size
    DES_set_key_checked(&key1, &ks1);
    DES_set_key_checked(&key2, &ks2);
    DES_set_key_checked(&key1, &ks3); // Reusing key1 makes this 2-key 3DES (112 bits)
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_14() {
    // Using RSA with insufficient key size from a configuration value
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    int config_key_size = 512; // This could come from a config file
    
    // ruleid: cpp-insufficient-key-size
    RSA_generate_key_ex(rsa, config_key_size, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=1}

void bad_case_15() {
    // Using custom ECC curve with insufficient size
    EC_GROUP* group = EC_GROUP_new(EC_GF2m_simple_method());
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
    
    // Set up a 112-bit curve
    BN_hex2bn(&p, "DB7C2ABF62E35E668076BEAD208B");
    BN_hex2bn(&a, "DB7C2ABF62E35E668076BEAD2088");
    BN_hex2bn(&b, "659EF8BA043916EEDE8911702B22");
    
    // ruleid: cpp-insufficient-key-size
    EC_GROUP_set_curve_GF2m(group, p, a, b, nullptr);
    
    // Use for key generation
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_generate_key(key);
    
    // Cleanup
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_KEY_free(key);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

// True Negative Examples (Secure Code)

void good_case_1() {
    // Using RSA with adequate key size (2048 bits)
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    // ok: cpp-insufficient-key-size
    RSA_generate_key_ex(rsa, 2048, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_2() {
    // Using AES with adequate key size (256 bits)
    unsigned char key[32]; // 256-bit key
    RAND_bytes(key, sizeof(key));
    
    // ok: cpp-insufficient-key-size
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);
    
    // Use the key for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_3() {
    // Using DSA with adequate key size (2048 bits)
    DSA* dsa = DSA_new();
    
    // ok: cpp-insufficient-key-size
    DSA_generate_parameters_ex(dsa, 2048, nullptr, 0, nullptr, nullptr, nullptr);
    DSA_generate_key(dsa);
    
    // Use the key for signing
    // ...
    
    DSA_free(dsa);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_4() {
    // Using DH with adequate key size (2048 bits)
    DH* dh = DH_new();
    
    // ok: cpp-insufficient-key-size
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, nullptr);
    DH_generate_key(dh);
    
    // Use the key for key exchange
    // ...
    
    DH_free(dh);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_5() {
    // Using ECC with adequate key size (256 bits)
    EC_KEY* key = nullptr;
    
    // ok: cpp-insufficient-key-size
    key = EC_KEY_new_by_curve_name(NID_secp256k1); // 256-bit curve
    EC_KEY_generate_key(key);
    
    // Use the key for ECDSA
    // ...
    
    EC_KEY_free(key);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_6() {
    // Using custom RSA key generation with adequate bits
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    // ok: cpp-insufficient-key-size
    int bits = 4096; // Strong key size
    RSA_generate_key_ex(rsa, bits, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_7() {
    // Using EVP interface with adequate RSA key size
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    
    // ok: cpp-insufficient-key-size
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072); // 3072 bits is adequate
    EVP_PKEY_keygen(ctx, &pkey);
    
    // Use the key for operations
    // ...
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_8() {
    // Using AES-GCM with adequate key size (256 bits)
    unsigned char key[32]; // 256-bit key
    RAND_bytes(key, sizeof(key));
    
    // ok: cpp-insufficient-key-size
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, nullptr);
    
    // Use for encryption
    // ...
    
    EVP_CIPHER_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_9() {
    // Using ChaCha20 with adequate key size (256 bits)
    unsigned char key[32]; // 256-bit key
    unsigned char nonce[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(nonce, sizeof(nonce));
    
    // ok: cpp-insufficient-key-size
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, nonce);
    
    // Use for encryption
    // ...
    
    EVP_CIPHER_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_10() {
    // Using ECC with strong curve (P-384)
    EC_KEY* key = nullptr;
    
    // ok: cpp-insufficient-key-size
    key = EC_KEY_new_by_curve_name(NID_secp384r1); // 384-bit curve
    EC_KEY_generate_key(key);
    
    // Use the key for ECDSA
    // ...
    
    EC_KEY_free(key);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_11() {
    // Using RSA with adequate key size from a configuration value
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    
    int config_key_size = 4096; // This could come from a config file
    
    // ok: cpp-insufficient-key-size
    RSA_generate_key_ex(rsa, config_key_size, e, nullptr);
    
    // Use the key for encryption
    // ...
    
    RSA_free(rsa);
    BN_free(e);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_12() {
    // Using Triple DES with 3 unique keys (effectively 168 bits)
    DES_cblock key1, key2, key3;
    DES_key_schedule ks1, ks2, ks3;
    
    // Generate random keys
    RAND_bytes((unsigned char*)&key1, sizeof(DES_cblock));
    RAND_bytes((unsigned char*)&key2, sizeof(DES_cblock));
    RAND_bytes((unsigned char*)&key3, sizeof(DES_cblock));
    
    // ok: cpp-insufficient-key-size
    DES_set_key_checked(&key1, &ks1);
    DES_set_key_checked(&key2, &ks2);
    DES_set_key_checked(&key3, &ks3); // Using 3 unique keys (168 bits)
    
    // Use for encryption
    // ...
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_13() {
    // Using EdDSA (Ed25519) with adequate key size (256 bits)
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    
    // ok: cpp-insufficient-key-size
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    
    // Use for signing
    // ...
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_14() {
    // Using X25519 for key exchange (256 bits)
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    
    // ok: cpp-insufficient-key-size
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    
    // Use for key exchange
    // ...
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}
// {/fact}
// {fact rule=cryptographic-key-generator@v1.0 defects=0}

void good_case_15() {
    // Using custom ECC curve with adequate size
    EC_GROUP* group = EC_GROUP_new(EC_GF2m_simple_method());
    BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
    
    // Set up a 256-bit curve
    BN_hex2bn(&p, "FFFFFFFFPLACEHOLDER_SECRET_32_CHARSFFFFFFFFFFFFFFFFFFFFFFFF");
    BN_hex2bn(&a, "FFFFFFFFPLACEHOLDER_SECRET_32_CHARSFFFFFFFFFFFFFFFFFFFFFFFC");
    BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    
    // ok: cpp-insufficient-key-size
    EC_GROUP_set_curve_GF2m(group, p, a, b, nullptr);
    
    // Use for key generation
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_generate_key(key);
    
    // Cleanup
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_KEY_free(key);
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "Cryptographic key size examples" << std::endl;
    return 0;
}