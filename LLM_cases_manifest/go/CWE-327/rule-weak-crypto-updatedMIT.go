package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_1() {
	data := []byte("sensitive data")
	
	// ruleid: rule-weak-crypto-updatedMIT
	hash := md5.Sum(data)
	fmt.Printf("%x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_2() {
	password := []byte("user-password")
	
	// ruleid: rule-weak-crypto-updatedMIT
	hash := sha1.Sum(password)
	fmt.Printf("SHA1 hash: %x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_3() {
	key := []byte("12345678") // 8-byte key for DES
	plaintext := []byte("sensitive information that needs encryption")
	
	// ruleid: rule-weak-crypto-updatedMIT
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	// Create initialization vector
	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	
	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	
	fmt.Printf("Encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_4() {
	key := []byte("weak-rc4-key")
	message := []byte("message to encrypt")
	
	// ruleid: rule-weak-crypto-updatedMIT
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	encrypted := make([]byte, len(message))
	cipher.XORKeyStream(encrypted, message)
	
	fmt.Printf("RC4 encrypted: %x\n", encrypted)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_5() {
	data := []byte("user data")
	
	// ruleid: rule-weak-crypto-updatedMIT
	hasher := md5.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	
	fmt.Printf("MD5 hash: %x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_6() {
	password := "user123"
	salt := "static-salt"
	
	// ruleid: rule-weak-crypto-updatedMIT
	hasher := sha1.New()
	hasher.Write([]byte(password + salt))
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	fmt.Printf("Salted SHA1: %s\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_7() {
	// Triple DES (3DES) is also considered weak
	key := []byte("123456781234567812345678") // 24-byte key for 3DES
	plaintext := []byte("data to encrypt with 3DES")
	
	// ruleid: rule-weak-crypto-updatedMIT
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	
	// Create initialization vector
	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	
	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	
	fmt.Printf("3DES Encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_8() {
	filename := "document.txt"
	
	// Calculate MD5 checksum of a file
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	
	// ruleid: rule-weak-crypto-updatedMIT
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		panic(err)
	}
	
	checksum := h.Sum(nil)
	fmt.Printf("MD5 checksum: %x\n", checksum)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_9() {
	// Using SHA1 for HMAC
	key := []byte("secret-key")
	message := []byte("message-to-authenticate")
	
	// ruleid: rule-weak-crypto-updatedMIT
	mac := sha1.New()
	mac.Write(key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	
	fmt.Printf("HMAC-SHA1: %x\n", expectedMAC)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_10() {
	// Using MD5 for key derivation
	password := []byte("user-password")
	salt := []byte("random-salt")
	
	// ruleid: rule-weak-crypto-updatedMIT
	hasher := md5.New()
	hasher.Write(password)
	hasher.Write(salt)
	key := hasher.Sum(nil)
	
	fmt.Printf("Derived key: %x\n", key)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_11() {
	// Using RC4 for stream encryption with custom implementation
	key := []byte("weak-encryption-key")
	plaintext := []byte("sensitive data to encrypt")
	
	// ruleid: rule-weak-crypto-updatedMIT
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	ciphertext := make([]byte, len(plaintext))
	rc4Cipher.XORKeyStream(ciphertext, plaintext)
	
	// Using the same key for decryption (which is typical for RC4)
	decryptCipher, _ := rc4.NewCipher(key)
	decrypted := make([]byte, len(ciphertext))
	decryptCipher.XORKeyStream(decrypted, ciphertext)
	
	fmt.Printf("RC4 encryption/decryption complete\n")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_12() {
	// Using SHA1 for password verification
	storedHash := "PLACEHOLDER_SECRET_40_CHARS" // SHA1 hash of "password"
	userInput := "password"
	
	// ruleid: rule-weak-crypto-updatedMIT
	hasher := sha1.New()
	hasher.Write([]byte(userInput))
	calculatedHash := hex.EncodeToString(hasher.Sum(nil))
	
	if calculatedHash == storedHash {
		fmt.Println("Password correct!")
	} else {
		fmt.Println("Password incorrect!")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_13() {
	// Using MD5 for token generation
	username := "user123"
	timestamp := "1634567890"
	
	// ruleid: rule-weak-crypto-updatedMIT
	tokenGenerator := md5.New()
	tokenGenerator.Write([]byte(username + timestamp))
	token := hex.EncodeToString(tokenGenerator.Sum(nil))
	
	fmt.Printf("Generated token: %s\n", token)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_14() {
	// Using DES in ECB mode (even worse than CBC)
	key := []byte("12345678") // 8-byte key
	plaintext := []byte("This is a secret message that needs protection")
	
	// Pad plaintext to be a multiple of block size
	padding := des.BlockSize - (len(plaintext) % des.BlockSize)
	paddedPlaintext := append(plaintext, make([]byte, padding)...)
	
	// ruleid: rule-weak-crypto-updatedMIT
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	ciphertext := make([]byte, len(paddedPlaintext))
	
	// Manually implement ECB mode (which is insecure)
	for i := 0; i < len(paddedPlaintext); i += des.BlockSize {
		block.Encrypt(ciphertext[i:i+des.BlockSize], paddedPlaintext[i:i+des.BlockSize])
	}
	
	fmt.Printf("DES-ECB encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_15() {
	// Using SHA1 for PBKDF2 (weak hash function in key derivation)
	password := []byte("user-password")
	salt := []byte("random-salt")
	iterations := 10000
	keyLen := 32
	
	// ruleid: rule-weak-crypto-updatedMIT
	derivedKey := pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
	
	fmt.Printf("PBKDF2 with SHA1: %x\n", derivedKey)
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_1() {
	data := []byte("sensitive data")
	
	// ok: rule-weak-crypto-updatedMIT
	hash := sha256.Sum256(data)
	fmt.Printf("%x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_2() {
	password := []byte("user-password")
	
	// ok: rule-weak-crypto-updatedMIT
	hash := sha512.Sum512(password)
	fmt.Printf("SHA512 hash: %x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_3() {
	key := []byte("AES-256-requires-32-bytes-long-key!")
	plaintext := []byte("sensitive information that needs encryption")
	
	// ok: rule-weak-crypto-updatedMIT
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	// Create nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	
	// Create GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	
	// Encrypt and seal
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	
	fmt.Printf("AES-GCM Encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_4() {
	password := []byte("user-password")
	
	// ok: rule-weak-crypto-updatedMIT
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("Bcrypt hash: %s\n", hashedPassword)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_5() {
	data := []byte("user data")
	
	// ok: rule-weak-crypto-updatedMIT
	hasher := sha256.New()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	
	fmt.Printf("SHA256 hash: %x\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_6() {
	password := "user123"
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		panic(err)
	}
	
	// ok: rule-weak-crypto-updatedMIT
	hasher := sha512.New()
	hasher.Write([]byte(password))
	hasher.Write(salt)
	hash := hex.EncodeToString(hasher.Sum(nil))
	
	fmt.Printf("Salted SHA512: %s\n", hash)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_7() {
	key := []byte("chacha20poly1305-requires-32-byte-key")
	plaintext := []byte("data to encrypt with ChaCha20-Poly1305")
	
	// ok: rule-weak-crypto-updatedMIT
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	
	// Create nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	
	// Encrypt and authenticate
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	
	fmt.Printf("ChaCha20-Poly1305 Encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_8() {
	filename := "document.txt"
	
	// Calculate SHA256 checksum of a file
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	
	// ok: rule-weak-crypto-updatedMIT
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		panic(err)
	}
	
	checksum := h.Sum(nil)
	fmt.Printf("SHA256 checksum: %x\n", checksum)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_9() {
	// Using SHA256 for HMAC
	key := []byte("secret-key")
	message := []byte("message-to-authenticate")
	
	// ok: rule-weak-crypto-updatedMIT
	mac := sha256.New()
	mac.Write(key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	
	fmt.Printf("HMAC-SHA256: %x\n", expectedMAC)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_10() {
	// Using PBKDF2 with SHA256 for key derivation
	password := []byte("user-password")
	salt := []byte("random-salt")
	iterations := 10000
	keyLen := 32
	
	// ok: rule-weak-crypto-updatedMIT
	derivedKey := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	
	fmt.Printf("Derived key: %x\n", derivedKey)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_11() {
	// Using AES-CTR for stream encryption
	key := []byte("AES-256-requires-32-bytes-long-key!")
	plaintext := []byte("sensitive data to encrypt")
	
	// ok: rule-weak-crypto-updatedMIT
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	// Create IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	
	// Create CTR stream
	stream := cipher.NewCTR(block, iv)
	
	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)
	
	fmt.Printf("AES-CTR encryption complete\n")
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_12() {
	// Using bcrypt for password verification
	storedHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" // bcrypt hash of "password"
	userInput := []byte("password")
	
	// ok: rule-weak-crypto-updatedMIT
	err := bcrypt.CompareHashAndPassword([]byte(storedHash), userInput)
	if err == nil {
		fmt.Println("Password correct!")
	} else {
		fmt.Println("Password incorrect!")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_13() {
	// Using SHA256 for token generation
	username := "user123"
	timestamp := "1634567890"
	
	// ok: rule-weak-crypto-updatedMIT
	tokenGenerator := sha256.New()
	tokenGenerator.Write([]byte(username + timestamp))
	token := hex.EncodeToString(tokenGenerator.Sum(nil))
	
	fmt.Printf("Generated token: %s\n", token)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_14() {
	// Using AES in GCM mode with proper key size
	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	
	plaintext := []byte("This is a secret message that needs protection")
	
	// ok: rule-weak-crypto-updatedMIT
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	// GCM provides authenticated encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	
	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	
	// Encrypt and authenticate
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	
	fmt.Printf("AES-GCM encrypted: %x\n", ciphertext)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_15() {
	// Using SHA512 for PBKDF2 (strong hash function in key derivation)
	password := []byte("user-password")
	salt := []byte("random-salt")
	iterations := 10000
	keyLen := 32
	
	// ok: rule-weak-crypto-updatedMIT
	derivedKey := pbkdf2.Key(password, salt, iterations, keyLen, sha512.New)
	
	fmt.Printf("PBKDF2 with SHA512: %x\n", derivedKey)
}
// {/fact}

func main() {
	// This function is just a placeholder to make the code compilable
	fmt.Println("Cryptographic examples")
}