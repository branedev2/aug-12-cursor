package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/gorilla/mux"
)

var (
	// Session store for examples
	store = sessions.NewCookieStore([]byte("something-very-secret"))
	db    *sql.DB
)

// True Positive Examples (Vulnerable Code)

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from query parameter
	user = r.URL.Query().Get("user")
	
	// Second assignment from form data
	if r.Method == "POST" {
		user = r.FormValue("username")
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Hello, %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from session
	session, _ := store.Get(r, "session-name")
	if val, ok := session.Values["user"].(string); ok {
		user = val
	}
	
	// Second assignment from header
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		user = strings.TrimPrefix(authHeader, "Bearer ")
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Welcome back, %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from cookie
	cookie, err := r.Cookie("user")
	if err == nil {
		user = cookie.Value
	}
	
	// Second assignment from JSON body
	if r.Method == "POST" {
		var data map[string]string
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &data)
		if username, ok := data["username"]; ok {
			user = username
		}
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "User profile for: %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from path parameter
	vars := mux.Vars(r)
	if username, ok := vars["username"]; ok {
		user = username
	}
	
	// Second assignment from query parameter
	if queryUser := r.URL.Query().Get("user"); queryUser != "" {
		user = queryUser
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Showing data for: %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from session
	session, _ := store.Get(r, "session-name")
	if val, ok := session.Values["user"].(string); ok {
		user = val
	}
	
	// Second assignment from form
	if r.Method == "POST" {
		user = r.FormValue("username")
	}
	
	// Third assignment from query parameter
	if queryUser := r.URL.Query().Get("as_user"); queryUser != "" {
		user = queryUser
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Acting as: %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// First assignment from basic auth
	username, _, ok := r.BasicAuth()
	if ok {
		user = username
	}
	
	// Second assignment from cookie
	cookie, err := r.Cookie("preferred_username")
	if err == nil {
		user = cookie.Value
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	row := db.QueryRow("SELECT email FROM users WHERE username = ?", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	var userId string
	
	// First assignment from header
	userId = r.Header.Get("X-User-ID")
	
	// Second assignment from query parameter
	if id := r.URL.Query().Get("user_id"); id != "" {
		userId = id
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "User ID: %s", userId)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	var userRole string
	
	// First assignment from session
	session, _ := store.Get(r, "session-name")
	if val, ok := session.Values["role"].(string); ok {
		userRole = val
	}
	
	// Second assignment from query parameter for debugging
	if role := r.URL.Query().Get("debug_role"); role != "" {
		userRole = role
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	if userRole == "admin" {
		fmt.Fprintf(w, "Welcome, administrator")
	} else {
		fmt.Fprintf(w, "Insufficient permissions")
	}
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	var userEmail string
	
	// First assignment from form
	userEmail = r.FormValue("email")
	
	// Second assignment from JSON body
	if r.Header.Get("Content-Type") == "application/json" {
		var data map[string]string
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &data)
		if email, ok := data["email"]; ok {
			userEmail = email
		}
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Subscription status for: %s", userEmail)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	var userToken string
	
	// First assignment from header
	userToken = r.Header.Get("X-Auth-Token")
	
	// Second assignment from cookie
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		userToken = cookie.Value
	}
	
	// Third assignment from query parameter
	if token := r.URL.Query().Get("token"); token != "" {
		userToken = token
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Token validation status: %s", validateToken(userToken))
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	var userPreference string
	
	// First assignment from cookie
	cookie, err := r.Cookie("theme")
	if err == nil {
		userPreference = cookie.Value
	}
	
	// Second assignment from query parameter
	if theme := r.URL.Query().Get("theme"); theme != "" {
		userPreference = theme
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Using theme: %s", userPreference)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	var userLanguage string
	
	// First assignment from header
	userLanguage = r.Header.Get("Accept-Language")
	
	// Second assignment from query parameter
	if lang := r.URL.Query().Get("lang"); lang != "" {
		userLanguage = lang
	}
	
	// Third assignment from cookie
	cookie, err := r.Cookie("language")
	if err == nil {
		userLanguage = cookie.Value
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Content language: %s", userLanguage)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	var userCountry string
	
	// First assignment from header
	userCountry = r.Header.Get("X-Country")
	
	// Second assignment from IP geolocation (simplified)
	userCountry = getCountryFromIP(r.RemoteAddr)
	
	// Third assignment from query parameter
	if country := r.URL.Query().Get("country"); country != "" {
		userCountry = country
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Content for region: %s", userCountry)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	var userDevice string
	
	// First assignment from user agent
	userDevice = r.UserAgent()
	
	// Second assignment from header
	if device := r.Header.Get("X-Device-Type"); device != "" {
		userDevice = device
	}
	
	// Third assignment from query parameter
	if device := r.URL.Query().Get("device"); device != "" {
		userDevice = device
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Optimized for: %s", userDevice)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	var userTimezone string
	
	// First assignment from cookie
	cookie, err := r.Cookie("timezone")
	if err == nil {
		userTimezone = cookie.Value
	}
	
	// Second assignment from form
	if r.Method == "POST" {
		userTimezone = r.FormValue("timezone")
	}
	
	// Third assignment from query parameter
	if tz := r.URL.Query().Get("tz"); tz != "" {
		userTimezone = tz
	}
	
	// ruleid: rule-handler-assignment-from-multiple-sources
	fmt.Fprintf(w, "Time in your zone: %s", getTimeInZone(userTimezone))
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	user := r.URL.Query().Get("user")
	
	// Using the user variable consistently from a single source
	fmt.Fprintf(w, "Hello, %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	var user string
	
	// ok: rule-handler-assignment-from-multiple-sources
	// Single source of truth - session
	session, _ := store.Get(r, "session-name")
	if val, ok := session.Values["user"].(string); ok {
		user = val
	} else {
		user = "anonymous"
	}
	
	fmt.Fprintf(w, "Welcome back, %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Prioritizing sources with clear fallback logic
	var user string
	
	cookie, err := r.Cookie("user")
	if err == nil {
		user = cookie.Value
	} else if r.Method == "POST" {
		var data map[string]string
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &data)
		if username, ok := data["username"]; ok {
			user = username
		} else {
			user = "guest"
		}
	} else {
		user = "guest"
	}
	
	fmt.Fprintf(w, "User profile for: %s", user)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using different variables for different sources
	vars := mux.Vars(r)
	pathUser := vars["username"]
	queryUser := r.URL.Query().Get("user")
	
	// Clear logic for which one to use
	if pathUser != "" {
		fmt.Fprintf(w, "Path user: %s", pathUser)
	} else if queryUser != "" {
		fmt.Fprintf(w, "Query user: %s", queryUser)
	} else {
		fmt.Fprintf(w, "No user specified")
	}
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a struct to track source and value
	type UserInfo struct {
		Username string
		Source   string
	}
	
	var userInfo UserInfo
	
	session, _ := store.Get(r, "session-name")
	if val, ok := session.Values["user"].(string); ok {
		userInfo = UserInfo{val, "session"}
	} else if r.Method == "POST" {
		userInfo = UserInfo{r.FormValue("username"), "form"}
	} else if queryUser := r.URL.Query().Get("as_user"); queryUser != "" {
		userInfo = UserInfo{queryUser, "query"}
	} else {
		userInfo = UserInfo{"guest", "default"}
	}
	
	fmt.Fprintf(w, "Acting as: %s (source: %s)", userInfo.Username, userInfo.Source)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Single source with validation
	username, _, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	
	row := db.QueryRow("SELECT email FROM users WHERE username = ?", username)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using configuration to determine which source to use
	var userId string
	
	config := getConfig()
	if config.UseHeaderForUserId {
		userId = r.Header.Get("X-User-ID")
	} else {
		userId = r.URL.Query().Get("user_id")
	}
	
	fmt.Fprintf(w, "User ID: %s", userId)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Single source with clear error handling
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}
	
	userRole, ok := session.Values["role"].(string)
	if !ok {
		http.Error(w, "Role not found in session", http.StatusBadRequest)
		return
	}
	
	if userRole == "admin" {
		fmt.Fprintf(w, "Welcome, administrator")
	} else {
		fmt.Fprintf(w, "Insufficient permissions")
	}
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using content type to determine parsing strategy, but storing in separate variables
	var formEmail, jsonEmail string
	var emailToUse string
	
	if r.Method == "POST" {
		if r.Header.Get("Content-Type") == "application/json" {
			var data map[string]string
			body, _ := ioutil.ReadAll(r.Body)
			json.Unmarshal(body, &data)
			jsonEmail = data["email"]
			emailToUse = jsonEmail
		} else {
			formEmail = r.FormValue("email")
			emailToUse = formEmail
		}
	}
	
	fmt.Fprintf(w, "Subscription status for: %s", emailToUse)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a function to determine the token source
	userToken := getAuthToken(r)
	fmt.Fprintf(w, "Token validation status: %s", validateToken(userToken))
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a single source with default
	userPreference := r.URL.Query().Get("theme")
	if userPreference == "" {
		userPreference = "default"
	}
	
	fmt.Fprintf(w, "Using theme: %s", userPreference)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a function to get language with clear priority
	userLanguage := getPreferredLanguage(r)
	fmt.Fprintf(w, "Content language: %s", userLanguage)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a dedicated function for country determination
	userCountry := determineUserCountry(r)
	fmt.Fprintf(w, "Content for region: %s", userCountry)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using a struct to track device information
	deviceInfo := detectDeviceInfo(r)
	fmt.Fprintf(w, "Optimized for: %s", deviceInfo.Type)
}
// {/fact}

// {fact rule=authentication-bypass-by-alternate-name@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// ok: rule-handler-assignment-from-multiple-sources
	// Using environment variable as default with clear override
	userTimezone := os.Getenv("DEFAULT_TIMEZONE")
	
	if tz := r.URL.Query().Get("tz"); tz != "" {
		userTimezone = tz
	}
	
	fmt.Fprintf(w, "Time in your zone: %s", getTimeInZone(userTimezone))
}
// {/fact}

// Helper functions
func validateToken(token string) string {
	return "valid"
}

func getTimeInZone(timezone string) string {
	return "12:00 PM"
}

func getCountryFromIP(ip string) string {
	return "US"
}

func getConfig() struct{ UseHeaderForUserId bool } {
	return struct{ UseHeaderForUserId bool }{true}
}

func getAuthToken(r *http.Request) string {
	// Priority: 1. Header, 2. Cookie, 3. Query param
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return token
	}
	
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		return cookie.Value
	}
	
	return r.URL.Query().Get("token")
}

func getPreferredLanguage(r *http.Request) string {
	// Priority: 1. Query param, 2. Cookie, 3. Accept-Language header
	if lang := r.URL.Query().Get("lang"); lang != "" {
		return lang
	}
	
	cookie, err := r.Cookie("language")
	if err == nil {
		return cookie.Value
	}
	
	return r.Header.Get("Accept-Language")
}

func determineUserCountry(r *http.Request) string {
	// Priority: 1. Query param, 2. Header, 3. IP geolocation
	if country := r.URL.Query().Get("country"); country != "" {
		return country
	}
	
	if country := r.Header.Get("X-Country"); country != "" {
		return country
	}
	
	return getCountryFromIP(r.RemoteAddr)
}

type DeviceInfo struct {
	Type    string
	Browser string
}

func detectDeviceInfo(r *http.Request) DeviceInfo {
	deviceType := "desktop"
	
	// Use header if available
	if device := r.Header.Get("X-Device-Type"); device != "" {
		deviceType = device
	} else if device := r.URL.Query().Get("device"); device != "" {
		// Fall back to query param
		deviceType = device
	} else {
		// Fall back to user agent detection
		userAgent := r.UserAgent()
		if strings.Contains(strings.ToLower(userAgent), "mobile") {
			deviceType = "mobile"
		}
	}
	
	return DeviceInfo{
		Type:    deviceType,
		Browser: "unknown",
	}
}

func main() {
	// This is just a placeholder main function
	http.HandleFunc("/", good_case_1)
	http.ListenAndServe(":8080", nil)
}