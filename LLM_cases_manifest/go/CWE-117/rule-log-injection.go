package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	"github.com/asaskevich/govalidator"
)

// True Positives (Vulnerable Code)

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// ruleid: rule-log-injection
	log.Printf("User login attempt: %s", username)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	logger := logrus.New()
	// ruleid: rule-log-injection
	logger.Infof("Request from user agent: %s", userAgent)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	email := r.Form.Get("email")
	// ruleid: rule-log-injection
	log.Printf("Password reset requested for email: %s", email)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	searchQuery := r.URL.Query().Get("q")
	// ruleid: rule-log-injection
	fmt.Printf("Search query received: %s\n", searchQuery)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	sessionID := cookie.Value
	// ruleid: rule-log-injection
	log.Printf("Session activity: %s", sessionID)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	filename := r.FormValue("filename")
	// ruleid: rule-log-injection
	log.Printf("File upload attempt: %s", filename)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.RemoteAddr
	action := r.URL.Query().Get("action")
	// ruleid: rule-log-injection
	log.Printf("IP %s performed action: %s", ipAddress, action)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return
	}
	// ruleid: rule-log-injection
	log.Printf("Received JSON data with ID: %s", data["id"])
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	// ruleid: rule-log-injection
	log.Printf("Request referred from: %s", referer)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	comments := r.Form.Get("comments")
	logger := logrus.New()
	// ruleid: rule-log-injection
	logger.WithFields(logrus.Fields{
		"section": "feedback",
	}).Infof("User feedback: %s", comments)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "" {
		// ruleid: rule-log-injection
		log.Printf("Auth attempt with token: %s", token)
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	
	if username == "" || password == "" {
		// ruleid: rule-log-injection
		log.Printf("Failed login attempt with username: %s", username)
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		return
	}
	
	// ruleid: rule-log-injection
	log.Printf("Message from %s: %s", requestData.Name, requestData.Message)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	query := r.URL.RawQuery
	// ruleid: rule-log-injection
	log.Printf("Raw query parameters: %s", query)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method
	// ruleid: rule-log-injection
	log.Printf("Request %s %s", method, path)
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=log-injection@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// Sanitize input using HTML escaping
	// ok: rule-log-injection
	log.Printf("User login attempt: %s", html.EscapeString(username))
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	logger := logrus.New()
	// Sanitize input using regexp
	re := regexp.MustCompile("[^a-zA-Z0-9 .,_-]")
	sanitizedUserAgent := re.ReplaceAllString(userAgent, "")
	// ok: rule-log-injection
	logger.Infof("Request from user agent: %s", sanitizedUserAgent)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	email := r.Form.Get("email")
	// Validate email format
	if govalidator.IsEmail(email) {
		// ok: rule-log-injection
		log.Printf("Password reset requested for email: %s", email)
	} else {
		log.Print("Invalid email format in password reset request")
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	searchQuery := r.URL.Query().Get("q")
	// Sanitize by removing newlines and carriage returns
	sanitized := strings.ReplaceAll(searchQuery, "\n", "")
	sanitized = strings.ReplaceAll(sanitized, "\r", "")
	// ok: rule-log-injection
	fmt.Printf("Search query received: %s\n", sanitized)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return
	}
	sessionID := cookie.Value
	// Validate session ID format (assuming it's a hexadecimal string)
	if govalidator.IsHexadecimal(sessionID) {
		// ok: rule-log-injection
		log.Printf("Session activity: %s", sessionID)
	} else {
		log.Print("Invalid session ID format")
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	filename := r.FormValue("filename")
	// Use bluemonday to sanitize HTML/scripts
	p := bluemonday.UGCPolicy()
	sanitizedFilename := p.Sanitize(filename)
	// ok: rule-log-injection
	log.Printf("File upload attempt: %s", sanitizedFilename)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.RemoteAddr
	action := r.URL.Query().Get("action")
	// Whitelist approach - only allow specific actions
	allowedActions := map[string]bool{"view": true, "edit": true, "delete": true}
	if allowedActions[action] {
		// ok: rule-log-injection
		log.Printf("IP %s performed action: %s", ipAddress, action)
	} else {
		log.Printf("IP %s attempted invalid action", ipAddress)
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return
	}
	// Validate ID format
	id := data["id"]
	if govalidator.IsAlphanumeric(id) {
		// ok: rule-log-injection
		log.Printf("Received JSON data with ID: %s", id)
	} else {
		log.Print("Received JSON data with invalid ID format")
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	// Truncate long URLs to prevent log flooding
	maxLen := 100
	if len(referer) > maxLen {
		referer = referer[:maxLen] + "..."
	}
	// Remove any control characters
	referer = removeControlChars(referer)
	// ok: rule-log-injection
	log.Printf("Request referred from: %s", referer)
}
// {/fact}

func removeControlChars(s string) string {
	return regexp.MustCompile("[\x00-\x1F\x7F]").ReplaceAllString(s, "")
}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	comments := r.Form.Get("comments")
	logger := logrus.New()
	// Sanitize with HTML escaping
	sanitizedComments := html.EscapeString(comments)
	// ok: rule-log-injection
	logger.WithFields(logrus.Fields{
		"section": "feedback",
	}).Infof("User feedback: %s", sanitizedComments)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token != "" {
		// Only log a prefix of the token for security
		if len(token) > 10 {
			// ok: rule-log-injection
			log.Printf("Auth attempt with token prefix: %s...", token[:10])
		} else {
			log.Print("Auth attempt with malformed token")
		}
	}
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	
	if username == "" || password == "" {
		// Sanitize username before logging
		sanitizedUsername := sanitizeUsername(username)
		// ok: rule-log-injection
		log.Printf("Failed login attempt with username: %s", sanitizedUsername)
	}
}
// {/fact}

func sanitizeUsername(username string) string {
	// Remove any characters that aren't alphanumeric, underscore, or dot
	re := regexp.MustCompile("[^a-zA-Z0-9_.]")
	return re.ReplaceAllString(username, "")
}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Name    string `json:"name"`
		Message string `json:"message"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		return
	}
	
	// Sanitize both fields
	p := bluemonday.UGCPolicy()
	sanitizedName := p.Sanitize(requestData.Name)
	sanitizedMessage := p.Sanitize(requestData.Message)
	
	// ok: rule-log-injection
	log.Printf("Message from %s: %s", sanitizedName, sanitizedMessage)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	query := r.URL.RawQuery
	// Don't log raw query parameters directly, extract and validate individual parameters
	values := r.URL.Query()
	safeParams := make(map[string]string)
	
	for key, vals := range values {
		if len(vals) > 0 {
			// Sanitize each parameter value
			safeParams[key] = html.EscapeString(vals[0])
		}
	}
	
	// Convert safe parameters to JSON for structured logging
	safeParamsJSON, _ := json.Marshal(safeParams)
	// ok: rule-log-injection
	log.Printf("Query parameters: %s", safeParamsJSON)
}
// {/fact}

// {fact rule=log-injection@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method
	
	// Validate HTTP method
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true}
	if !validMethods[method] {
		method = "INVALID"
	}
	
	// Sanitize path
	sanitizedPath := sanitizePath(path)
	
	// ok: rule-log-injection
	log.Printf("Request %s %s", method, sanitizedPath)
}
// {/fact}

func sanitizePath(path string) string {
	// Remove any potentially dangerous sequences
	path = strings.ReplaceAll(path, "\n", "")
	path = strings.ReplaceAll(path, "\r", "")
	// Limit length
	if len(path) > 100 {
		path = path[:100] + "..."
	}
	return path
}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Add other handlers
	http.ListenAndServe(":8080", nil)
}