package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt/v4"
)

// BAD CASES - These should be detected as vulnerable

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_1() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusBadRequest)
			return
		}

		// Using claims without verification
		username := claims["username"].(string)
		fmt.Fprintf(w, "Welcome %s", username)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_2() {
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(tokenString, &jwt.StandardClaims{})
		if err != nil {
			http.Error(w, "Error parsing token", http.StatusBadRequest)
			return
		}

		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			// Using claims without verification
			if claims.Subject == "admin" {
				fmt.Fprintf(w, "Admin access granted")
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_3() {
	http.HandleFunc("/user-info", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "No session cookie", http.StatusBadRequest)
			return
		}
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(cookie.Value, jwt.MapClaims{})
		
		claims, _ := token.Claims.(jwt.MapClaims)
		userId := claims["user_id"].(string)
		
		fmt.Fprintf(w, "User ID: %s", userId)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_4() {
	type CustomClaims struct {
		Role string `json:"role"`
		jwt.StandardClaims
	}
	
	http.HandleFunc("/role-check", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, &CustomClaims{})
		
		if claims, ok := token.Claims.(*CustomClaims); ok {
			if claims.Role == "manager" {
				fmt.Fprintf(w, "Manager dashboard")
			} else {
				fmt.Fprintf(w, "Employee dashboard")
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_5() {
	http.HandleFunc("/extract-email", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.FormValue("id_token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}
		
		claims, _ := token.Claims.(jwt.MapClaims)
		email := claims["email"].(string)
		
		fmt.Fprintf(w, "Email: %s", email)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_6() {
	http.HandleFunc("/process-token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		tokenString := r.FormValue("token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, &jwt.RegisteredClaims{})
		
		if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
			if time.Now().Unix() > claims.ExpiresAt.Unix() {
				http.Error(w, "Token expired", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "Token ID: %s", claims.ID)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_7() {
	type UserClaims struct {
		Username string `json:"username"`
		Admin    bool   `json:"admin"`
		jwt.RegisteredClaims
	}
	
	http.HandleFunc("/check-admin", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-Auth-Token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, &UserClaims{})
		
		if claims, ok := token.Claims.(*UserClaims); ok {
			if claims.Admin {
				fmt.Fprintf(w, "Admin access granted for %s", claims.Username)
			} else {
				http.Error(w, "Admin access required", http.StatusForbidden)
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_8() {
	http.HandleFunc("/token-debug", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("debug_token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Failed to parse token", http.StatusBadRequest)
			return
		}
		
		claims, _ := token.Claims.(jwt.MapClaims)
		for key, val := range claims {
			fmt.Fprintf(w, "%s: %v\n", key, val)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_9() {
	http.HandleFunc("/api/v1/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		tokenString := r.Header.Get("X-JWT-Token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, &jwt.StandardClaims{})
		
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			if claims.Issuer != "trusted-auth-server" {
				http.Error(w, "Invalid issuer", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "Subject: %s", claims.Subject)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_10() {
	http.HandleFunc("/extract-permissions", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization header", http.StatusBadRequest)
			return
		}
		tokenString := authHeader[7:]
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		
		claims, _ := token.Claims.(jwt.MapClaims)
		if permissions, ok := claims["permissions"].([]interface{}); ok {
			fmt.Fprintf(w, "Permissions: %v", permissions)
		} else {
			http.Error(w, "No permissions found", http.StatusBadRequest)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_11() {
	http.HandleFunc("/user-profile", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "No auth token provided", http.StatusBadRequest)
			return
		}
		
		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(cookie.Value, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}
		
		claims, _ := token.Claims.(jwt.MapClaims)
		userId := claims["sub"].(string)
		name := claims["name"].(string)
		
		fmt.Fprintf(w, "User %s (ID: %s)", name, userId)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_12() {
	type OrganizationClaims struct {
		OrgID   string   `json:"org_id"`
		OrgName string   `json:"org_name"`
		Roles   []string `json:"roles"`
		jwt.RegisteredClaims
	}
	
	http.HandleFunc("/org-data", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-Organization-Token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, &OrganizationClaims{})
		
		if claims, ok := token.Claims.(*OrganizationClaims); ok {
			fmt.Fprintf(w, "Organization: %s (ID: %s)", claims.OrgName, claims.OrgID)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_13() {
	http.HandleFunc("/token-info", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("token")
		if tokenString == "" {
			http.Error(w, "Token parameter required", http.StatusBadRequest)
			return
		}
		
		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Error(w, "Failed to parse token", http.StatusBadRequest)
			return
		}
		
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"subject": "%v", "issuer": "%v"}`, claims["sub"], claims["iss"])
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_14() {
	http.HandleFunc("/check-scope", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, _ := jwt.ParseUnverified(tokenString, jwt.MapClaims{})
		
		claims, _ := token.Claims.(jwt.MapClaims)
		if scopes, ok := claims["scope"].(string); ok {
			if strings.Contains(scopes, "admin:read") {
				fmt.Fprintf(w, "Admin read access granted")
			} else {
				http.Error(w, "Insufficient scope", http.StatusForbidden)
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=1}
func bad_case_15() {
	http.HandleFunc("/api/metadata", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-API-Token")
		
		// ruleid: rule-jwt-go-parse-unverified
		token, err := jwt.ParseUnverified(tokenString, &jwt.RegisteredClaims{})
		if err != nil {
			http.Error(w, "Invalid token format", http.StatusBadRequest)
			return
		}
		
		if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
			if claims.Audience.Contains("api:metadata") {
				fmt.Fprintf(w, "Metadata access granted")
			} else {
				http.Error(w, "Invalid audience", http.StatusUnauthorized)
			}
		}
	})
}
// {/fact}

// GOOD CASES - These should not be detected as vulnerable

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_1() {
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		
		secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusBadRequest)
			return
		}
		
		username := claims["username"].(string)
		fmt.Fprintf(w, "Welcome %s", username)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_2() {
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["sub"] != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		fmt.Fprintf(w, "Admin access granted")
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_3() {
	http.HandleFunc("/user-info", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "No session cookie", http.StatusBadRequest)
			return
		}
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET_KEY")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		userId := claims["user_id"].(string)
		fmt.Fprintf(w, "User ID: %s", userId)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_4() {
	type CustomClaims struct {
		Role string `json:"role"`
		jwt.StandardClaims
	}
	
	http.HandleFunc("/role-check", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("token")
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		if claims, ok := token.Claims.(*CustomClaims); ok {
			if claims.Role == "manager" {
				fmt.Fprintf(w, "Manager dashboard")
			} else {
				fmt.Fprintf(w, "Employee dashboard")
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_5() {
	http.HandleFunc("/extract-email", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.FormValue("id_token")
		
		// First parse without verification to get the key ID
		parser := jwt.Parser{SkipClaimsValidation: true}
		token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Get the key ID from the token header
			if kid, ok := token.Header["kid"].(string); ok {
				// Fetch the public key based on the key ID
				publicKey := fetchPublicKey(kid) // Assume this function exists
				return publicKey, nil
			}
			return nil, fmt.Errorf("no key ID found in token")
		})
		
		// ok: rule-jwt-go-parse-unverified
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		email := claims["email"].(string)
		fmt.Fprintf(w, "Email: %s", email)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_6() {
	http.HandleFunc("/process-token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseMultipartForm(10 << 20)
		tokenString := r.FormValue("token")
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		
		if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
			fmt.Fprintf(w, "Token ID: %s", claims.ID)
		} else {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_7() {
	type UserClaims struct {
		Username string `json:"username"`
		Admin    bool   `json:"admin"`
		jwt.RegisteredClaims
	}
	
	http.HandleFunc("/check-admin", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-Auth-Token")
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		if claims, ok := token.Claims.(*UserClaims); ok {
			if claims.Admin {
				fmt.Fprintf(w, "Admin access granted for %s", claims.Username)
			} else {
				http.Error(w, "Admin access required", http.StatusForbidden)
			}
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_8() {
	http.HandleFunc("/token-debug", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("debug_token")
		
		// Parse token to verify signature first
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_DEBUG_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		// Now we know the token is valid, we can safely use its claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims format", http.StatusBadRequest)
			return
		}
		
		for key, val := range claims {
			fmt.Fprintf(w, "%s: %v\n", key, val)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_9() {
	http.HandleFunc("/api/v1/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		tokenString := r.Header.Get("X-JWT-Token")
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			// Get the public key for verification
			publicKeyPEM, err := ioutil.ReadFile("public_key.pem")
			if err != nil {
				return nil, err
			}
			
			publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
			if err != nil {
				return nil, err
			}
			
			return publicKey, nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
			if claims.Issuer != "trusted-auth-server" {
				http.Error(w, "Invalid issuer", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "Subject: %s", claims.Subject)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_10() {
	http.HandleFunc("/extract-permissions", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Invalid authorization header", http.StatusBadRequest)
			return
		}
		tokenString := authHeader[7:]
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims format", http.StatusBadRequest)
			return
		}
		
		if permissions, ok := claims["permissions"].([]interface{}); ok {
			fmt.Fprintf(w, "Permissions: %v", permissions)
		} else {
			http.Error(w, "No permissions found", http.StatusBadRequest)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_11() {
	// Using ParseWithClaims with a custom validation function
	type CustomClaims struct {
		Permissions []string `json:"permissions"`
		jwt.StandardClaims
	}
	
	http.HandleFunc("/validate-permissions", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		
		claims := &CustomClaims{}
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		// Check if the token has the required permission
		hasPermission := false
		for _, perm := range claims.Permissions {
			if perm == "read:data" {
				hasPermission = true
				break
			}
		}
		
		if hasPermission {
			fmt.Fprintf(w, "Access granted")
		} else {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
		}
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_12() {
	// Using JWT with RSA public key validation
	http.HandleFunc("/secure-endpoint", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-Access-Token")
		
		// Load public key
		publicKeyBytes, err := ioutil.ReadFile("public.pem")
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the algorithm
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			
			return publicKey, nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		userId := claims["sub"].(string)
		fmt.Fprintf(w, "Authenticated user: %s", userId)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_13() {
	// Using JWT with expiration validation
	http.HandleFunc("/time-sensitive", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.URL.Query().Get("token")
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil {
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorExpired != 0 {
					http.Error(w, "Token has expired", http.StatusUnauthorized)
					return
				}
			}
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		fmt.Fprintf(w, "Valid token for user: %v", claims["sub"])
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_14() {
	// Using JWT with audience validation
	http.HandleFunc("/audience-check", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		
		expectedAudience := "api.myservice.com"
		
		// ok: rule-jwt-go-parse-unverified
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		// Check audience
		if aud, ok := claims["aud"].(string); !ok || aud != expectedAudience {
			http.Error(w, "Invalid audience", http.StatusUnauthorized)
			return
		}
		
		fmt.Fprintf(w, "Token validated for audience: %s", expectedAudience)
	})
}
// {/fact}

// {fact rule=insufficient-data-authenticity-verification@v1.0 defects=0}
func good_case_15() {
	// Using JWT with a custom parser and validation options
	http.HandleFunc("/custom-validation", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("X-Token")
		
		parser := &jwt.Parser{
			ValidMethods:         []string{"HS256", "RS256"},
			SkipClaimsValidation: false,
		}
		
		// ok: rule-jwt-go-parse-unverified
		token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Check if the token uses the expected algorithm
			switch token.Method.(type) {
			case *jwt.SigningMethodHMAC:
				return []byte(os.Getenv("JWT_HMAC_SECRET")), nil
			case *jwt.SigningMethodRSA:
				publicKeyPEM, err := ioutil.ReadFile("rsa_public.pem")
				if err != nil {
					return nil, err
				}
				return jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
			default:
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		})
		
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid claims", http.StatusBadRequest)
			return
		}
		
		fmt.Fprintf(w, "Successfully validated token for subject: %v", claims["sub"])
	})
}
// {/fact}

// Helper function for good_case_5
func fetchPublicKey(kid string) *rsa.PublicKey {
	// In a real implementation, this would fetch the key from a JWKS endpoint or similar
	// For this example, we'll just return a dummy key
	return &rsa.PublicKey{}
}

func main() {
	// Main function to satisfy Go compiler
	log.Println("Starting server on port 8080")
	http.ListenAndServe(":8080", nil)
}