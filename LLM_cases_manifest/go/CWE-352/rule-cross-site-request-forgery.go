package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var (
	store        = sessions.NewCookieStore([]byte("something-very-secret"))
	tokenStorage = make(map[string]string)
	tokenMutex   sync.Mutex
)

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		
		// ruleid: rule-cross-site-request-forgery
		// Directly processing POST data without CSRF validation
		updateUserProfile(username, email)
		
		fmt.Fprintf(w, "Profile updated for %s", username)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ruleid: rule-cross-site-request-forgery
		// No CSRF protection when transferring money
		amount := r.FormValue("amount")
		toAccount := r.FormValue("toAccount")
		
		transferMoney(amount, toAccount)
		fmt.Fprintf(w, "Transferred %s to account %s", amount, toAccount)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ruleid: rule-cross-site-request-forgery
		// Changing password without CSRF protection
		newPassword := r.FormValue("newPassword")
		
		changeUserPassword(newPassword)
		fmt.Fprintf(w, "Password updated successfully")
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Deleting a resource without CSRF protection
	if r.Method == "POST" {
		resourceID := r.FormValue("resourceID")
		
		deleteResource(resourceID)
		fmt.Fprintf(w, "Resource %s deleted", resourceID)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Adding a new admin user without CSRF protection
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		
		addAdminUser(username, email)
		fmt.Fprintf(w, "Admin user %s added", username)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Submitting a form with AJAX but no CSRF protection
	if r.Method == "POST" {
		if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
			comment := r.FormValue("comment")
			postID := r.FormValue("postID")
			
			addComment(comment, postID)
			fmt.Fprintf(w, "Comment added to post %s", postID)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using JSON content type but still vulnerable to CSRF
	if r.Method == "POST" && r.Header.Get("Content-Type") == "application/json" {
		var data struct {
			Action string `json:"action"`
			UserID string `json:"userId"`
		}
		
		// Parse JSON body
		// Assuming we've parsed the JSON into data
		
		if data.Action == "disable" {
			disableUser(data.UserID)
			fmt.Fprintf(w, "User %s disabled", data.UserID)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using a custom header but not sufficient for CSRF protection
	if r.Method == "POST" {
		if r.Header.Get("X-Custom-Header") == "SomeValue" {
			action := r.FormValue("action")
			targetID := r.FormValue("targetID")
			
			performAction(action, targetID)
			fmt.Fprintf(w, "Action %s performed on %s", action, targetID)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using cookies for authentication but no CSRF protection
	if r.Method == "POST" {
		cookie, err := r.Cookie("session")
		if err == nil && isValidSession(cookie.Value) {
			setting := r.FormValue("setting")
			value := r.FormValue("value")
			
			updateSetting(setting, value)
			fmt.Fprintf(w, "Setting %s updated to %s", setting, value)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using a referer check which is not sufficient
	if r.Method == "POST" {
		referer := r.Header.Get("Referer")
		if referer != "" && (referer == "https://example.com/settings" || referer == "http://localhost:8080/settings") {
			setting := r.FormValue("setting")
			value := r.FormValue("value")
			
			updateSetting(setting, value)
			fmt.Fprintf(w, "Setting %s updated to %s", setting, value)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using a token but not validating it properly
	if r.Method == "POST" {
		token := r.FormValue("token")
		if token != "" {
			// Token exists but not validated against expected value
			action := r.FormValue("action")
			targetID := r.FormValue("targetID")
			
			performAction(action, targetID)
			fmt.Fprintf(w, "Action %s performed on %s", action, targetID)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using a token that's predictable
	if r.Method == "POST" {
		token := r.FormValue("token")
		expectedToken := fmt.Sprintf("%d", time.Now().Day()) // Predictable token
		
		if token == expectedToken {
			email := r.FormValue("email")
			subscribeToNewsletter(email)
			fmt.Fprintf(w, "%s subscribed to newsletter", email)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using same token for all users
	if r.Method == "POST" {
		token := r.FormValue("token")
		staticToken := "static-token-for-all-users" // Same token for all users
		
		if token == staticToken {
			message := r.FormValue("message")
			recipient := r.FormValue("recipient")
			
			sendMessage(message, recipient)
			fmt.Fprintf(w, "Message sent to %s", recipient)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using token but with timing attack vulnerability
	if r.Method == "POST" {
		token := r.FormValue("token")
		session, _ := store.Get(r, "session")
		expectedToken, _ := session.Values["csrf_token"].(string)
		
		// Vulnerable to timing attacks
		if token == expectedToken {
			userID := r.FormValue("userID")
			role := r.FormValue("role")
			
			updateUserRole(userID, role)
			fmt.Fprintf(w, "User %s role updated to %s", userID, role)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-cross-site-request-forgery
	// Using token but not requiring it for all state-changing operations
	if r.Method == "POST" {
		action := r.FormValue("action")
		
		// Only checking token for certain actions
		if action == "delete" {
			token := r.FormValue("token")
			session, _ := store.Get(r, "session")
			expectedToken, _ := session.Values["csrf_token"].(string)
			
			if token == expectedToken {
				resourceID := r.FormValue("resourceID")
				deleteResource(resourceID)
				fmt.Fprintf(w, "Resource %s deleted", resourceID)
				return
			}
		} else {
			// No CSRF check for other actions
			resourceID := r.FormValue("resourceID")
			performOtherAction(action, resourceID)
			fmt.Fprintf(w, "Action %s performed on %s", action, resourceID)
		}
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ok: rule-cross-site-request-forgery
		// Validating CSRF token before processing
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		username := r.FormValue("username")
		email := r.FormValue("email")
		
		updateUserProfile(username, email)
		fmt.Fprintf(w, "Profile updated for %s", username)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ok: rule-cross-site-request-forgery
		// Using a secure random token for CSRF protection
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		amount := r.FormValue("amount")
		toAccount := r.FormValue("toAccount")
		
		transferMoney(amount, toAccount)
		fmt.Fprintf(w, "Transferred %s to account %s", amount, toAccount)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ok: rule-cross-site-request-forgery
		// Using double submit cookie pattern for CSRF protection
		token := r.FormValue("csrf_token")
		cookie, err := r.Cookie("csrf_token")
		
		if err != nil || subtle.ConstantTimeCompare([]byte(token), []byte(cookie.Value)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		newPassword := r.FormValue("newPassword")
		changeUserPassword(newPassword)
		fmt.Fprintf(w, "Password updated successfully")
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ok: rule-cross-site-request-forgery
		// Using token from request header
		token := r.Header.Get("X-CSRF-Token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		resourceID := r.FormValue("resourceID")
		deleteResource(resourceID)
		fmt.Fprintf(w, "Resource %s deleted", resourceID)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ok: rule-cross-site-request-forgery
		// Using per-session token stored in memory
		token := r.FormValue("csrf_token")
		userID := getUserIDFromSession(r)
		
		tokenMutex.Lock()
		expectedToken, exists := tokenStorage[userID]
		tokenMutex.Unlock()
		
		if !exists || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		username := r.FormValue("username")
		email := r.FormValue("email")
		
		addAdminUser(username, email)
		fmt.Fprintf(w, "Admin user %s added", username)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using SameSite cookie attribute for CSRF protection
	if r.Method == "POST" {
		// Assuming the session cookie has SameSite=Strict set
		session, _ := store.Get(r, "session")
		if session.IsNew {
			http.Error(w, "Invalid session", http.StatusForbidden)
			return
		}
		
		comment := r.FormValue("comment")
		postID := r.FormValue("postID")
		
		addComment(comment, postID)
		fmt.Fprintf(w, "Comment added to post %s", postID)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using custom request header with CORS for AJAX requests
	if r.Method == "POST" {
		// Custom header that can't be set by cross-site requests due to CORS
		if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			http.Error(w, "AJAX requests only", http.StatusForbidden)
			return
		}
		
		// Additional CSRF token validation
		token := r.Header.Get("X-CSRF-Token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		var data struct {
			Action string `json:"action"`
			UserID string `json:"userId"`
		}
		
		// Parse JSON body
		// Assuming we've parsed the JSON into data
		
		if data.Action == "disable" {
			disableUser(data.UserID)
			fmt.Fprintf(w, "User %s disabled", data.UserID)
		}
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Generating a new token for each form
	if r.Method == "GET" {
		// Generate a new token
		token := generateCSRFToken()
		
		// Store token in session
		session, _ := store.Get(r, "session")
		session.Values["csrf_token"] = token
		session.Save(r, w)
		
		// Render form with token
		tmpl := template.Must(template.New("form").Parse(`
			<form method="post" action="/submit">
				<input type="hidden" name="csrf_token" value="{{.Token}}">
				<input type="text" name="name">
				<button type="submit">Submit</button>
			</form>
		`))
		
		tmpl.Execute(w, map[string]string{"Token": token})
	} else if r.Method == "POST" {
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		// Process form submission
		name := r.FormValue("name")
		fmt.Fprintf(w, "Hello, %s", name)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a middleware for CSRF protection
	if r.Method == "POST" {
		// In a real application, this would be handled by middleware
		// but for this example, we'll include the check inline
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		setting := r.FormValue("setting")
		value := r.FormValue("value")
		
		updateSetting(setting, value)
		fmt.Fprintf(w, "Setting %s updated to %s", setting, value)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a time-limited token
	if r.Method == "POST" {
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		tokenData, ok := session.Values["csrf_token_data"].(map[string]interface{})
		
		if !ok {
			http.Error(w, "Invalid session", http.StatusForbidden)
			return
		}
		
		expectedToken, ok := tokenData["token"].(string)
		expiryTime, ok2 := tokenData["expiry"].(int64)
		
		if !ok || !ok2 || time.Now().Unix() > expiryTime || 
		   subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid or expired CSRF token", http.StatusForbidden)
			return
		}
		
		email := r.FormValue("email")
		subscribeToNewsletter(email)
		fmt.Fprintf(w, "%s subscribed to newsletter", email)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a token with user-specific salt
	if r.Method == "POST" {
		token := r.FormValue("csrf_token")
		userID := getUserIDFromSession(r)
		
		// Get user-specific salt from database
		salt := getUserSalt(userID)
		
		// Generate expected token using the same algorithm as when it was created
		expectedToken := generateTokenWithSalt(userID, salt)
		
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		message := r.FormValue("message")
		recipient := r.FormValue("recipient")
		
		sendMessage(message, recipient)
		fmt.Fprintf(w, "Message sent to %s", recipient)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a synchronizer token pattern with constant-time comparison
	if r.Method == "POST" {
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		userID := r.FormValue("userID")
		role := r.FormValue("role")
		
		updateUserRole(userID, role)
		fmt.Fprintf(w, "User %s role updated to %s", userID, role)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a token in a custom header for API requests
	if r.Method == "POST" {
		token := r.Header.Get("X-CSRF-Token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		// Process API request
		action := r.FormValue("action")
		resourceID := r.FormValue("resourceID")
		
		performAction(action, resourceID)
		fmt.Fprintf(w, "Action %s performed on %s", action, resourceID)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using a token with per-form uniqueness
	if r.Method == "POST" {
		token := r.FormValue("csrf_token")
		formID := r.FormValue("form_id")
		
		session, _ := store.Get(r, "session")
		tokensMap, ok := session.Values["csrf_tokens"].(map[string]string)
		
		if !ok {
			http.Error(w, "Invalid session", http.StatusForbidden)
			return
		}
		
		expectedToken, exists := tokensMap[formID]
		
		if !exists || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		// Remove used token to prevent replay
		delete(tokensMap, formID)
		session.Values["csrf_tokens"] = tokensMap
		session.Save(r, w)
		
		// Process form
		data := r.FormValue("data")
		processFormData(formID, data)
		fmt.Fprintf(w, "Form %s processed successfully", formID)
	}
}
// {/fact}

// {fact rule=cross-site-request-forgery@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// ok: rule-cross-site-request-forgery
	// Using both token validation and SameSite cookies
	if r.Method == "POST" {
		// Check if the session cookie has SameSite attribute
		// This would be set when creating the cookie
		
		// Also validate CSRF token
		token := r.FormValue("csrf_token")
		session, _ := store.Get(r, "session")
		expectedToken, ok := session.Values["csrf_token"].(string)
		
		if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		
		// Process the request
		action := r.FormValue("action")
		resourceID := r.FormValue("resourceID")
		
		performAction(action, resourceID)
		fmt.Fprintf(w, "Action %s performed on %s", action, resourceID)
	}
}
// {/fact}

// Helper functions

func generateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func getUserIDFromSession(r *http.Request) string {
	session, _ := store.Get(r, "session")
	userID, _ := session.Values["user_id"].(string)
	return userID
}

func getUserSalt(userID string) string {
	// In a real application, this would fetch from a database
	return "user-specific-salt-" + userID
}

func generateTokenWithSalt(userID, salt string) string {
	// In a real application, this would use a proper HMAC
	return "generated-token-for-" + userID + "-with-salt-" + salt
}

func updateUserProfile(username, email string) {
	// Implementation not relevant for this example
}

func transferMoney(amount, toAccount string) {
	// Implementation not relevant for this example
}

func changeUserPassword(newPassword string) {
	// Implementation not relevant for this example
}

func deleteResource(resourceID string) {
	// Implementation not relevant for this example
}

func addAdminUser(username, email string) {
	// Implementation not relevant for this example
}

func addComment(comment, postID string) {
	// Implementation not relevant for this example
}

func disableUser(userID string) {
	// Implementation not relevant for this example
}

func performAction(action, targetID string) {
	// Implementation not relevant for this example
}

func updateSetting(setting, value string) {
	// Implementation not relevant for this example
}

func subscribeToNewsletter(email string) {
	// Implementation not relevant for this example
}

func sendMessage(message, recipient string) {
	// Implementation not relevant for this example
}

func updateUserRole(userID, role string) {
	// Implementation not relevant for this example
}

func performOtherAction(action, resourceID string) {
	// Implementation not relevant for this example
}

func processFormData(formID, data string) {
	// Implementation not relevant for this example
}

func isValidSession(sessionID string) bool {
	// Implementation not relevant for this example
	return true
}

func main() {
	r := mux.NewRouter()
	
	// Register handlers
	http.ListenAndServe(":8080", r)
}