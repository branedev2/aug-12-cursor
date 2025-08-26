package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// BAD CASES - Using math/rand for security-sensitive operations

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_1() {
	// Using math/rand for generating session tokens
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[mathrand.Intn(len(letters))]
	}
	sessionToken := string(b)
	fmt.Println("Generated session token:", sessionToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_2() {
	// Using math/rand for generating password reset tokens
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	resetToken := fmt.Sprintf("%d", mathrand.Int63())
	fmt.Println("Password reset token:", resetToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_3() {
	// Using math/rand for generating API keys
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	const keyLength = 32
	bytes := make([]byte, keyLength)
	for i := 0; i < keyLength; i++ {
		bytes[i] = byte(mathrand.Intn(256))
	}
	apiKey := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println("API key:", apiKey)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_4() {
	// Using math/rand for generating random IDs
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	randomID := mathrand.Int63()
	fmt.Println("User ID:", randomID)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_5() {
	// Using math/rand for generating OTP codes
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	otp := mathrand.Intn(1000000)
	fmt.Printf("OTP: %06d\n", otp)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_6() {
	// Using math/rand for generating random filenames
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	filename := fmt.Sprintf("file-%d.tmp", mathrand.Int63())
	f, _ := os.Create(filename)
	defer f.Close()
	fmt.Println("Created file:", filename)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_7() {
	// Using math/rand for generating encryption keys
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(mathrand.Intn(256))
	}
	fmt.Println("Encryption key:", hex.EncodeToString(key))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_8() {
	// Using math/rand for generating random salts for password hashing
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(mathrand.Intn(256))
	}
	password := "mypassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+string(salt)), bcrypt.DefaultCost)
	fmt.Println("Hashed password:", string(hashedPassword))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_9() {
	// Using math/rand for generating CSRF tokens
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	csrfToken := fmt.Sprintf("%x", mathrand.Int63())
	fmt.Println("CSRF token:", csrfToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_10() {
	// Using math/rand in an HTTP handler for generating secure tokens
	http.HandleFunc("/generate-token", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: rule-weakrandsource-updatedMIT
		mathrand.Seed(time.Now().UnixNano())
		token := fmt.Sprintf("%x", mathrand.Int63())
		w.Write([]byte(token))
	})
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_11() {
	// Using math/rand for generating initialization vectors for encryption
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(mathrand.Intn(256))
	}
	fmt.Println("Initialization vector:", hex.EncodeToString(iv))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_12() {
	// Using math/rand for generating random database passwords
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	password := make([]byte, 16)
	for i := range password {
		password[i] = chars[mathrand.Intn(len(chars))]
	}
	db, _ := sql.Open("mysql", fmt.Sprintf("user:%s@tcp(127.0.0.1:3306)/db", string(password)))
	defer db.Close()
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_13() {
	// Using math/rand for generating random nonces
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	nonce := mathrand.Uint64()
	fmt.Println("Nonce:", nonce)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_14() {
	// Using math/rand for generating random JWT secrets
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	jwtSecret := make([]byte, 64)
	for i := range jwtSecret {
		jwtSecret[i] = byte(mathrand.Intn(256))
	}
	fmt.Println("JWT secret:", base64.StdEncoding.EncodeToString(jwtSecret))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=1}
func bad_case_15() {
	// Using math/rand for generating random UUIDs
	// ruleid: rule-weakrandsource-updatedMIT
	mathrand.Seed(time.Now().UnixNano())
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		mathrand.Int31n(0x100000000),
		mathrand.Int31n(0x10000),
		0x4000|mathrand.Int31n(0x1000), // Version 4
		0x8000|mathrand.Int31n(0x4000), // Variant is 10
		mathrand.Int31n(0x100000000))
	fmt.Println("UUID:", uuid)
}
// {/fact}

// GOOD CASES - Using crypto/rand for security-sensitive operations

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_1() {
	// Using crypto/rand for generating session tokens
	// ok: rule-weakrandsource-updatedMIT
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	sessionToken := string(b)
	fmt.Println("Generated session token:", sessionToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_2() {
	// Using crypto/rand for generating password reset tokens
	// ok: rule-weakrandsource-updatedMIT
	n, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		log.Fatal(err)
	}
	resetToken := fmt.Sprintf("%d", n)
	fmt.Println("Password reset token:", resetToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_3() {
	// Using crypto/rand for generating API keys
	// ok: rule-weakrandsource-updatedMIT
	const keyLength = 32
	bytes := make([]byte, keyLength)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	apiKey := base64.StdEncoding.EncodeToString(bytes)
	fmt.Println("API key:", apiKey)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_4() {
	// Using crypto/rand for generating random IDs
	// ok: rule-weakrandsource-updatedMIT
	n, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		log.Fatal(err)
	}
	randomID := n.Int64()
	fmt.Println("User ID:", randomID)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_5() {
	// Using crypto/rand for generating OTP codes
	// ok: rule-weakrandsource-updatedMIT
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		log.Fatal(err)
	}
	otp := int(n.Int64())
	fmt.Printf("OTP: %06d\n", otp)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_6() {
	// Using crypto/rand for generating random filenames
	// ok: rule-weakrandsource-updatedMIT
	n, err := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	if err != nil {
		log.Fatal(err)
	}
	filename := fmt.Sprintf("file-%d.tmp", n.Int64())
	f, _ := os.Create(filename)
	defer f.Close()
	fmt.Println("Created file:", filename)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_7() {
	// Using crypto/rand for generating encryption keys
	// ok: rule-weakrandsource-updatedMIT
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Encryption key:", hex.EncodeToString(key))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_8() {
	// Using crypto/rand for generating random salts for password hashing
	// ok: rule-weakrandsource-updatedMIT
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
	}
	password := "mypassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+string(salt)), bcrypt.DefaultCost)
	fmt.Println("Hashed password:", string(hashedPassword))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_9() {
	// Using crypto/rand for generating CSRF tokens
	// ok: rule-weakrandsource-updatedMIT
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	csrfToken := fmt.Sprintf("%x", b)
	fmt.Println("CSRF token:", csrfToken)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_10() {
	// Using crypto/rand in an HTTP handler for generating secure tokens
	http.HandleFunc("/generate-token", func(w http.ResponseWriter, r *http.Request) {
		// ok: rule-weakrandsource-updatedMIT
		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}
		token := fmt.Sprintf("%x", b)
		w.Write([]byte(token))
	})
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_11() {
	// Using crypto/rand for generating initialization vectors for encryption
	// ok: rule-weakrandsource-updatedMIT
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Initialization vector:", hex.EncodeToString(iv))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_12() {
	// Using crypto/rand for generating random database passwords
	// ok: rule-weakrandsource-updatedMIT
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	password := make([]byte, 16)
	_, err := rand.Read(password)
	if err != nil {
		log.Fatal(err)
	}
	for i := range password {
		password[i] = chars[int(password[i])%len(chars)]
	}
	db, _ := sql.Open("mysql", fmt.Sprintf("user:%s@tcp(127.0.0.1:3306)/db", string(password)))
	defer db.Close()
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_13() {
	// Using crypto/rand for generating random nonces
	// ok: rule-weakrandsource-updatedMIT
	nonce := make([]byte, 8)
	_, err := rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}
	nonceValue := uint64(nonce[0]) | uint64(nonce[1])<<8 | uint64(nonce[2])<<16 | uint64(nonce[3])<<24 |
		uint64(nonce[4])<<32 | uint64(nonce[5])<<40 | uint64(nonce[6])<<48 | uint64(nonce[7])<<56
	fmt.Println("Nonce:", nonceValue)
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_14() {
	// Using crypto/rand for generating random JWT secrets
	// ok: rule-weakrandsource-updatedMIT
	jwtSecret := make([]byte, 64)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("JWT secret:", base64.StdEncoding.EncodeToString(jwtSecret))
}
// {/fact}

// {fact rule=weak-random-number-generation@v1.0 defects=0}
func good_case_15() {
	// Using crypto/rand for generating random UUIDs
	// ok: rule-weakrandsource-updatedMIT
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		log.Fatal(err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	fmt.Printf("UUID: %x-%x-%x-%x-%x\n",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("Running test cases for math/rand vs crypto/rand usage")
}