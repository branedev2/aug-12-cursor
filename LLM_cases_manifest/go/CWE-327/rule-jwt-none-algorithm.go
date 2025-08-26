package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
)

// BAD CASES - Using 'none' algorithm which is insecure

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_1() {
	// Creating a JWT token with 'none' algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"user_id": 123,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	// ruleid: rule-jwt-none-algorithm
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	fmt.Println("Generated token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Parsing and accepting a JWT with 'none' algorithm
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	// ruleid: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodNone); ok {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Fprintf(w, "Welcome %s!", claims["name"])
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_3() {
	// Explicitly setting up JWT parser to accept 'none' algorithm
	parser := &jwt.Parser{
		SkipClaimsValidation: true,
	}

	tokenString := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxMjMsImV4cCI6MTcxNjIzOTAyMn0."

	// ruleid: rule-jwt-none-algorithm
	token, _ := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodNone); ok {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})

	if token.Valid {
		fmt.Println("Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Creating a custom JWT with 'none' algorithm
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}
	
	claims := map[string]interface{}{
		"sub": "1234567890",
		"name": "John Doe",
		"iat": 1516239022,
	}
	
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsJSON)
	
	// ruleid: rule-jwt-none-algorithm
	tokenString := headerEncoded + "." + claimsEncoded + "."
	
	fmt.Fprintf(w, "Generated token: %s", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_5() {
	// Using lestrrat-go/jwx library with 'none' algorithm
	payload := []byte(`{"user_id": 123}`)
	
	// ruleid: rule-jwt-none-algorithm
	signed, _ := jws.Sign(payload, jwa.NoSignature, nil)
	
	fmt.Println("Signed JWT:", string(signed))
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Accepting a token with 'none' algorithm in a verification function
	tokenString := r.URL.Query().Get("token")
	
	// ruleid: rule-jwt-none-algorithm
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == "none" {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return []byte("secret"), nil
	})
	
	if err == nil {
		fmt.Fprintf(w, "Token verified")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_7() {
	// Creating a token with 'none' algorithm using custom implementation
	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"John Doe"}`
	
	headerEncoded := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	
	// ruleid: rule-jwt-none-algorithm
	token := headerEncoded + "." + payloadEncoded + "."
	
	fmt.Println("Token:", token)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Configuring JWT middleware to accept 'none' algorithm
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	
	// ruleid: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.Alg() {
		case "none":
			return jwt.UnsafeAllowNoneSignatureType, nil
		case "HS256":
			return []byte("secret"), nil
		default:
			return nil, fmt.Errorf("unexpected algorithm: %s", token.Method.Alg())
		}
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Valid token")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_9() {
	// Creating a JWT with 'none' algorithm for testing purposes
	claims := jwt.MapClaims{
		"user": "admin",
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}
	
	// ruleid: rule-jwt-none-algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	
	fmt.Println("Test token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Function that accepts multiple algorithms including 'none'
	tokenString := r.URL.Query().Get("token")
	
	// ruleid: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		alg := token.Header["alg"]
		if alg == "none" {
			return jwt.UnsafeAllowNoneSignatureType, nil
		} else if alg == "HS256" {
			return []byte("secret"), nil
		}
		return nil, fmt.Errorf("unsupported algorithm")
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_11() {
	// Creating a JWT token with 'none' algorithm and custom claims
	type CustomClaims struct {
		UserID   int    `json:"user_id"`
		Username string `json:"username"`
		jwt.StandardClaims
	}
	
	claims := CustomClaims{
		UserID:   1001,
		Username: "admin",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	}
	
	// ruleid: rule-jwt-none-algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	
	fmt.Println("Generated token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Accepting a token with 'none' algorithm in a switch statement
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	
	// ruleid: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodNone:
			return jwt.UnsafeAllowNoneSignatureType, nil
		case *jwt.SigningMethodHMAC:
			return []byte("secret"), nil
		default:
			return nil, fmt.Errorf("unexpected signing method")
		}
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Valid token")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_13() {
	// Creating a token with 'none' algorithm for development environment
	isDevEnvironment := true
	
	var token *jwt.Token
	if isDevEnvironment {
		// ruleid: rule-jwt-none-algorithm
		token = jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"user": "developer",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		fmt.Println("Dev token:", tokenString)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": "user",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString([]byte("secret"))
		fmt.Println("Prod token:", tokenString)
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Accepting a token with 'none' algorithm based on request parameter
	tokenString := r.URL.Query().Get("token")
	allowNone := r.URL.Query().Get("debug") == "true"
	
	var keyFunc jwt.Keyfunc
	if allowNone {
		// ruleid: rule-jwt-none-algorithm
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodNone); ok {
				return jwt.UnsafeAllowNoneSignatureType, nil
			}
			return []byte("secret"), nil
		}
	} else {
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
				return []byte("secret"), nil
			}
			return nil, fmt.Errorf("unexpected signing method")
		}
	}
	
	token, _ := jwt.Parse(tokenString, keyFunc)
	
	if token.Valid {
		fmt.Fprintf(w, "Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_15() {
	// Creating a JWT with 'none' algorithm using string manipulation
	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"user":"admin","exp":1716239022}`
	
	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
	
	// ruleid: rule-jwt-none-algorithm
	tokenString := headerBase64 + "." + payloadBase64 + "."
	
	fmt.Println("Token:", tokenString)
}
// {/fact}

// GOOD CASES - Using secure algorithms instead of 'none'

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_1() {
	// Creating a JWT token with HS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": 123,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})
	
	// ok: rule-jwt-none-algorithm
	tokenString, _ := token.SignedString([]byte("secret_key"))
	fmt.Println("Generated token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Parsing JWT with secure algorithm
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	
	// ok: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret_key"), nil
	})
	
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Fprintf(w, "Welcome %s!", claims["name"])
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_3() {
	// Setting up JWT parser to reject 'none' algorithm
	parser := &jwt.Parser{
		SkipClaimsValidation: false,
	}
	
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjMsImV4cCI6MTcxNjIzOTAyMn0.signature"
	
	// ok: rule-jwt-none-algorithm
	token, _ := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret_key"), nil
	})
	
	if token.Valid {
		fmt.Println("Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Creating a JWT with RS256 algorithm
	privateKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`))
	
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "1234567890",
		"name": "John Doe",
		"iat": 1516239022,
	})
	
	// ok: rule-jwt-none-algorithm
	tokenString, _ := token.SignedString(privateKey)
	
	fmt.Fprintf(w, "Generated token: %s", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_5() {
	// Using lestrrat-go/jwx library with secure algorithm
	payload := []byte(`{"user_id": 123}`)
	secretKey := []byte("secret")
	
	// ok: rule-jwt-none-algorithm
	signed, _ := jws.Sign(payload, jwa.HS256, secretKey)
	
	fmt.Println("Signed JWT:", string(signed))
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Explicitly rejecting 'none' algorithm in verification function
	tokenString := r.URL.Query().Get("token")
	
	// ok: rule-jwt-none-algorithm
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == "none" {
			return nil, fmt.Errorf("'none' algorithm not allowed")
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	
	if err == nil {
		fmt.Fprintf(w, "Token verified")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_7() {
	// Creating a token with HS256 algorithm
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"John Doe"}`
	
	headerEncoded := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	
	// Create signature
	signingString := headerEncoded + "." + payloadEncoded
	h := hmac.New(sha256.New, []byte("secret"))
	h.Write([]byte(signingString))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	
	// ok: rule-jwt-none-algorithm
	token := headerEncoded + "." + payloadEncoded + "." + signature
	
	fmt.Println("Token:", token)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Configuring JWT middleware to only accept secure algorithms
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	
	// ok: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return []byte("secret"), nil
		case *jwt.SigningMethodRSA:
			publicKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`))
			return publicKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Valid token")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_9() {
	// Creating a JWT with ES256 algorithm for testing purposes
	privateKey, _ := jwt.ParseECPrivateKeyFromPEM([]byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH4Uv...
-----END EC PRIVATE KEY-----`))
	
	claims := jwt.MapClaims{
		"user": "admin",
		"exp":  time.Now().Add(time.Hour * 24).Unix(),
	}
	
	// ok: rule-jwt-none-algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, _ := token.SignedString(privateKey)
	
	fmt.Println("Test token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Function that accepts only secure algorithms
	tokenString := r.URL.Query().Get("token")
	
	// ok: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("algorithm header not found")
		}
		
		if alg == "none" {
			return nil, fmt.Errorf("'none' algorithm not allowed")
		} else if alg == "HS256" {
			return []byte("secret"), nil
		} else if alg == "RS256" {
			publicKey, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`))
			return publicKey, nil
		}
		return nil, fmt.Errorf("unsupported algorithm")
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_11() {
	// Creating a JWT token with HS512 algorithm and custom claims
	type CustomClaims struct {
		UserID   int    `json:"user_id"`
		Username string `json:"username"`
		jwt.StandardClaims
	}
	
	claims := CustomClaims{
		UserID:   1001,
		Username: "admin",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	}
	
	// ok: rule-jwt-none-algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, _ := token.SignedString([]byte("very_secure_secret_key"))
	
	fmt.Println("Generated token:", tokenString)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Explicitly checking and rejecting 'none' algorithm
	tokenString := r.Header.Get("Authorization")
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	
	// Parse without validating signature first to check algorithm
	token, _ := jwt.Parse(tokenString, nil)
	
	// ok: rule-jwt-none-algorithm
	if token.Header["alg"] == "none" {
		http.Error(w, "Invalid token algorithm", http.StatusUnauthorized)
		return
	}
	
	// Now validate with proper key
	validToken, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret"), nil
	})
	
	if validToken.Valid {
		fmt.Fprintf(w, "Valid token")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_13() {
	// Creating a token with appropriate algorithm for different environments
	isDevEnvironment := true
	
	var token *jwt.Token
	if isDevEnvironment {
		// ok: rule-jwt-none-algorithm
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": "developer",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		tokenString, _ := token.SignedString([]byte("dev_secret"))
		fmt.Println("Dev token:", tokenString)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"user": "user",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		// In production, would use RSA private key
		tokenString, _ := token.SignedString([]byte("prod_secret"))
		fmt.Println("Prod token:", tokenString)
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using environment variables for JWT secret
	tokenString := r.URL.Query().Get("token")
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "fallback_secret" // Only for demonstration
	}
	
	// ok: rule-jwt-none-algorithm
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})
	
	if token.Valid {
		fmt.Fprintf(w, "Token is valid")
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_15() {
	// Using JWK for token verification
	jwkSet, _ := jwk.Parse([]byte(`{
		"keys": [
			{
				"kty": "RSA",
				"kid": "key1",
				"use": "sig",
				"alg": "RS256",
				"n": "...",
				"e": "AQAB"
			}
		]
	}`))
	
	key, _ := jwkSet.LookupKeyID("key1")
	var rawKey interface{}
	_ = key.Raw(&rawKey)
	
	// ok: rule-jwt-none-algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "1234567890",
		"name": "John Doe",
		"iat": 1516239022,
	})
	
	tokenString, _ := token.SignedString(rawKey)
	fmt.Println("Token:", tokenString)
}
// {/fact}

func main() {
	// Main function to prevent compiler errors
	fmt.Println("JWT Security Examples")
}