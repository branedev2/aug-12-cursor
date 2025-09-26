#include <botan/cipher_mode.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
  Botan::Cipher_Mode::create("AES-256/ECB", Botan::ENCRYPTION); // Noncompliant
}
// {/fact}

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
  std::unique_ptr<Botan::RandomNumberGenerator>   rng(new Botan::AutoSeeded_RNG);
  Botan::RSA_PrivateKey                           rsaKey(*rng.get(), 2048);

  Botan::PK_Encryptor_EME(rsaKey, *rng.get(), "PKCS1v15"); // Noncompliant
}
// {/fact}
// {fact rule=insecure-cryptography@v1.0 defects=1}
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

voic encrypt() {
  CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(); // Noncompliant
}
// {/fact}
#include <cryptopp/rsa.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
  CryptoPP::RSAES<CryptoPP::PKCS1v15>::Encryptor(); // Noncompliant
}
// {/fact}

#include <openssl/evp.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
  EVP_aes_128_cbc(); // Noncompliant
}
// {/fact}
#include <openssl/rsa.h>
// {fact rule=insecure-cryptography@v1.0 defects=1}
void encrypt() {
  RSA_public_decrypt(flen, from, to, key, RSA_SSLV23_PADDING); // Noncompliant
}
// {/fact}