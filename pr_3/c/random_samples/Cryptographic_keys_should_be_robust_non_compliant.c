#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/rsa.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    std::unique_ptr<Botan::RandomNumberGenerator>   rng(new Botan::System_RNG);
    Botan::RSA_PrivateKey                           rsaKey(*rng, 1024); // Noncompliant
}
// {/fact}

#include <botan/dl_group.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    Botan::DL_Group("dsa/botan/1024"); // Noncompliant
}
// {/fact}

#include <botan/ec_group.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    Botan::EC_Group("secp160k1"); // Noncompliant
}
// {/fact}

#include <cryptopp/rsa.h>
#include <cryptopp/rng.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    CryptoPP::AutoSeededRandomPool  rng;
    CryptoPP::InvertibleRSAFunction rsa_trapdoor;

    rsa_trapdoor.GenerateRandomWithKeySize(rng, 1024); // Noncompliant
}
// {/fact}



#include <cryptopp/dsa.h>
#include <cryptopp/rng.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
cryptopp::autoseededrandompool rng;
cryptopp::dsa::privatekey      dsa_private_key;

dsa_private_key.GenerateRandomWithKeySize(rng, 1024); // Noncompliant
// {/fact}

#include <cryptopp/dh.h>
#include <cryptopp/rng.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
cryptopp::autoseededrandompool rng;
CryptoPP::DH                   dh;

dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, 1024); // Noncompliant
// {/fact}

#include <cryptopp/osrng.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void ecnrypt() {
    CryptoPP::ASN1::secp112r1(); // Noncompliant
}
// {/fact}

#include <openssl/rsa.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    RSA* rsa_key_pair = RSA_new();
    BIGNUM* exponent  = BSA_new();

    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsa_key_pair, 1024, exponent, NULL); // Noncompliant
}
// {/fact}

#include <openssl/dsa.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    DSA* dsa_params = DSA_new();
    DSA_generate_parameters_ex(dsa_params, 1024, NULL, 0, NULL, NULL, NULL); // Noncompliant
}
// {/fact}

#include <openssl/dh.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    DH* dh_params = DH_new();
    DH_generate_parameters_ex(dh_params, 1024, DH_GENERATOR_2, NULL); // Noncompliant
}
// {/fact}

#include <botan/ec_group.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp112r1); // Noncompliant
}
// {/fact}