package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
)

var (
	store = sessions.NewCookieStore([]byte("something-very-secret"))
	db    *sql.DB
)

// True Positive Examples

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Getting role from a URL parameter
	role := r.URL.Query().Get("role")
	
	// ruleid: rule-incorrect-authorization
	if role == "admin" {
		// Allow admin actions
		fmt.Fprintf(w, "Admin panel access granted")
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Getting user type from a cookie
	cookie, err := r.Cookie("userType")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-incorrect-authorization
	if cookie.Value == "premium" {
		// Allow premium features
		fmt.Fprintf(w, "Premium content access granted")
	} else {
		http.Error(w, "Subscription required", http.StatusPaymentRequired)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Getting authorization level from header
	authLevel := r.Header.Get("X-Auth-Level")
	
	// ruleid: rule-incorrect-authorization
	if authLevel == "3" {
		// Allow high-level operations
		fmt.Fprintf(w, "High-level operation permitted")
	} else {
		http.Error(w, "Insufficient privileges", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Parse JSON from request body
	var requestData struct {
		UserID int    `json:"userId"`
		Role   string `json:"role"`
	}
	
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	
	err = json.Unmarshal(body, &requestData)
	if err != nil {
		http.Error(w, "Error parsing JSON", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-incorrect-authorization
	if requestData.Role == "manager" {
		// Allow manager actions
		fmt.Fprintf(w, "Manager operations allowed")
	} else {
		http.Error(w, "Not authorized for manager operations", http.StatusUnauthorized)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user permissions from URL parameters
	canEdit := r.URL.Query().Get("canEdit")
	
	// ruleid: rule-incorrect-authorization
	if canEdit == "true" {
		// Allow edit operations
		fmt.Fprintf(w, "Edit permission granted")
	} else {
		http.Error(w, "Read-only access", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get access token from header
	accessToken := r.Header.Get("X-Access-Token")
	
	// ruleid: rule-incorrect-authorization
	if accessToken == "special-token-for-api" {
		// Allow API access
		fmt.Fprintf(w, "API access granted")
	} else {
		http.Error(w, "Invalid API token", http.StatusUnauthorized)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user ID from query parameter
	userIDStr := r.URL.Query().Get("userId")
	resourceOwnerIDStr := r.URL.Query().Get("resourceOwnerId")
	
	userID, _ := strconv.Atoi(userIDStr)
	resourceOwnerID, _ := strconv.Atoi(resourceOwnerIDStr)
	
	// ruleid: rule-incorrect-authorization
	if userID == resourceOwnerID {
		// Allow resource access
		fmt.Fprintf(w, "Resource access granted to owner")
	} else {
		http.Error(w, "You don't own this resource", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get permission level from form data
	r.ParseForm()
	permissionLevel := r.FormValue("permissionLevel")
	
	// ruleid: rule-incorrect-authorization
	if permissionLevel == "advanced" {
		// Allow advanced operations
		fmt.Fprintf(w, "Advanced operations allowed")
	} else {
		http.Error(w, "Basic access only", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Check if admin flag is set in URL
	isAdmin := r.URL.Query().Get("isAdmin")
	
	// ruleid: rule-incorrect-authorization
	if isAdmin == "1" {
		// Show admin dashboard
		fmt.Fprintf(w, "Admin dashboard displayed")
	} else {
		fmt.Fprintf(w, "User dashboard displayed")
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get authorization data from a custom header
	authData := r.Header.Get("X-User-Permissions")
	
	// ruleid: rule-incorrect-authorization
	if strings.Contains(authData, "delete") {
		// Allow deletion
		fmt.Fprintf(w, "Delete operation permitted")
	} else {
		http.Error(w, "Cannot delete: insufficient permissions", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestedUserID := vars["id"]
	
	// Get the requesting user's ID from query parameter
	requestingUserID := r.URL.Query().Get("requestingUserId")
	
	// ruleid: rule-incorrect-authorization
	if requestedUserID == requestingUserID {
		// Allow access to user profile
		fmt.Fprintf(w, "Profile access granted")
	} else {
		http.Error(w, "Cannot access other users' profiles", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get organization ID from cookie
	orgCookie, err := r.Cookie("orgId")
	if err != nil {
		http.Error(w, "Organization cookie not found", http.StatusBadRequest)
		return
	}
	
	// Get resource organization from URL
	resourceOrg := r.URL.Query().Get("resourceOrg")
	
	// ruleid: rule-incorrect-authorization
	if orgCookie.Value == resourceOrg {
		// Allow organization-specific access
		fmt.Fprintf(w, "Organization resource access granted")
	} else {
		http.Error(w, "Resource belongs to another organization", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// JWT token from query parameter (very bad practice)
	tokenString := r.URL.Query().Get("token")
	
	// Parse the token without verification
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("some-key"), nil
	})
	
	claims, _ := token.Claims.(jwt.MapClaims)
	role := claims["role"].(string)
	
	// ruleid: rule-incorrect-authorization
	if role == "superuser" {
		// Allow superuser actions
		fmt.Fprintf(w, "Superuser access granted")
	} else {
		http.Error(w, "Superuser privileges required", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get department from header
	department := r.Header.Get("X-Department")
	
	// Get resource type from URL
	resourceType := r.URL.Query().Get("resourceType")
	
	// ruleid: rule-incorrect-authorization
	if department == "finance" && resourceType == "financial-report" {
		// Allow access to financial reports
		fmt.Fprintf(w, "Financial report access granted")
	} else {
		http.Error(w, "Department not authorized for this resource", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get API key from header
	apiKey := r.Header.Get("X-API-Key")
	
	// ruleid: rule-incorrect-authorization
	if apiKey == "admin-api-key-123" {
		// Allow admin API operations
		fmt.Fprintf(w, "Admin API access granted")
	} else if apiKey == "user-api-key-456" {
		// Allow regular user API operations
		fmt.Fprintf(w, "User API access granted")
	} else {
		http.Error(w, "Invalid API key", http.StatusUnauthorized)
	}
}
// {/fact}

// True Negative Examples

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if role, ok := session.Values["role"].(string); ok && role == "admin" {
		// Allow admin actions
		fmt.Fprintf(w, "Admin panel access granted")
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if userType, ok := session.Values["userType"].(string); ok && userType == "premium" {
		// Allow premium features
		fmt.Fprintf(w, "Premium content access granted")
	} else {
		http.Error(w, "Subscription required", http.StatusPaymentRequired)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if authLevel, ok := session.Values["authLevel"].(string); ok && authLevel == "3" {
		// Allow high-level operations
		fmt.Fprintf(w, "High-level operation permitted")
	} else {
		http.Error(w, "Insufficient privileges", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	userID, ok1 := session.Values["userID"].(int)
	role, ok2 := session.Values["role"].(string)
	
	// ok: rule-incorrect-authorization
	if ok1 && ok2 && role == "manager" {
		// Allow manager actions
		fmt.Fprintf(w, "Manager operations allowed for user %d", userID)
	} else {
		http.Error(w, "Not authorized for manager operations", http.StatusUnauthorized)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if canEdit, ok := session.Values["canEdit"].(bool); ok && canEdit {
		// Allow edit operations
		fmt.Fprintf(w, "Edit permission granted")
	} else {
		http.Error(w, "Read-only access", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	tokenString := r.Header.Get("Authorization")
	if !strings.HasPrefix(tokenString, "Bearer ") {
		http.Error(w, "Invalid token format", http.StatusUnauthorized)
		return
	}
	
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	
	// Verify the token with proper signature checking
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	
	// ok: rule-incorrect-authorization
	if role, ok := claims["role"].(string); ok && role == "admin" {
		// Allow admin actions
		fmt.Fprintf(w, "Admin access granted via verified JWT")
	} else {
		http.Error(w, "Admin privileges required", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get authenticated user ID from session
	userID, ok := session.Values["userID"].(int)
	if !ok {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	
	// Get resource ID from URL
	vars := mux.Vars(r)
	resourceIDStr := vars["resourceId"]
	resourceID, err := strconv.Atoi(resourceIDStr)
	if err != nil {
		http.Error(w, "Invalid resource ID", http.StatusBadRequest)
		return
	}
	
	// Query database to check if user owns the resource
	var ownerID int
	err = db.QueryRow("SELECT owner_id FROM resources WHERE id = $1", resourceID).Scan(&ownerID)
	if err != nil {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}
	
	// ok: rule-incorrect-authorization
	if userID == ownerID {
		// Allow resource access
		fmt.Fprintf(w, "Resource access granted to owner")
	} else {
		http.Error(w, "You don't own this resource", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get user permissions from session
	permissions, ok := session.Values["permissions"].([]string)
	if !ok {
		http.Error(w, "No permissions found", http.StatusUnauthorized)
		return
	}
	
	// Check if user has the required permission
	hasPermission := false
	for _, perm := range permissions {
		if perm == "delete_posts" {
			hasPermission = true
			break
		}
	}
	
	// ok: rule-incorrect-authorization
	if hasPermission {
		// Allow deletion
		fmt.Fprintf(w, "Delete operation permitted")
	} else {
		http.Error(w, "Cannot delete: insufficient permissions", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get user ID and requested resource ID
	userID, ok1 := session.Values["userID"].(int)
	if !ok1 {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	
	vars := mux.Vars(r)
	requestedUserIDStr := vars["id"]
	requestedUserID, err := strconv.Atoi(requestedUserIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// Check if user is an admin
	isAdmin, ok2 := session.Values["isAdmin"].(bool)
	
	// ok: rule-incorrect-authorization
	if userID == requestedUserID || (ok2 && isAdmin) {
		// Allow access to user profile
		fmt.Fprintf(w, "Profile access granted")
	} else {
		http.Error(w, "Cannot access other users' profiles", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get organization ID from session
	orgID, ok := session.Values["orgID"].(string)
	if !ok {
		http.Error(w, "Organization not found in session", http.StatusUnauthorized)
		return
	}
	
	// Get resource ID from URL
	vars := mux.Vars(r)
	resourceID := vars["resourceId"]
	
	// Query database to check if resource belongs to the organization
	var resourceOrg string
	err = db.QueryRow("SELECT org_id FROM resources WHERE id = $1", resourceID).Scan(&resourceOrg)
	if err != nil {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}
	
	// ok: rule-incorrect-authorization
	if orgID == resourceOrg {
		// Allow organization-specific access
		fmt.Fprintf(w, "Organization resource access granted")
	} else {
		http.Error(w, "Resource belongs to another organization", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get department from session
	department, ok1 := session.Values["department"].(string)
	if !ok1 {
		http.Error(w, "Department not found in session", http.StatusUnauthorized)
		return
	}
	
	// Get resource type from URL
	vars := mux.Vars(r)
	resourceType := vars["type"]
	
	// Query database for department permissions
	var hasAccess bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM department_permissions WHERE department = $1 AND resource_type = $2)", 
		department, resourceType).Scan(&hasAccess)
	if err != nil {
		http.Error(w, "Error checking permissions", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if hasAccess {
		// Allow access to the resource
		fmt.Fprintf(w, "Department resource access granted")
	} else {
		http.Error(w, "Department not authorized for this resource", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get user roles from session
	roles, ok := session.Values["roles"].([]string)
	if !ok {
		http.Error(w, "Roles not found in session", http.StatusUnauthorized)
		return
	}
	
	// Check if user has any of the required roles
	requiredRoles := []string{"admin", "manager", "supervisor"}
	hasRequiredRole := false
	
	for _, userRole := range roles {
		for _, reqRole := range requiredRoles {
			if userRole == reqRole {
				hasRequiredRole = true
				break
			}
		}
		if hasRequiredRole {
			break
		}
	}
	
	// ok: rule-incorrect-authorization
	if hasRequiredRole {
		// Allow privileged operation
		fmt.Fprintf(w, "Privileged operation permitted")
	} else {
		http.Error(w, "Insufficient privileges", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
		return
	}
	
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	
	// Verify token with proper signature checking
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	
	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	
	// Get user ID from token
	userID, ok := claims["sub"].(string)
	if !ok {
		http.Error(w, "User ID not found in token", http.StatusUnauthorized)
		return
	}
	
	// Get resource ID from URL
	vars := mux.Vars(r)
	resourceID := vars["id"]
	
	// Query database to check if user has access to the resource
	var hasAccess bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM resource_permissions WHERE user_id = $1 AND resource_id = $2)", 
		userID, resourceID).Scan(&hasAccess)
	if err != nil {
		http.Error(w, "Error checking permissions", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if hasAccess {
		// Allow resource access
		fmt.Fprintf(w, "Resource access granted")
	} else {
		http.Error(w, "Access denied to this resource", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Get session from server-side store
	session, err := store.Get(r, "session-name")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}
	
	// Get user subscription level from session
	subscriptionLevel, ok := session.Values["subscriptionLevel"].(string)
	if !ok {
		http.Error(w, "Subscription level not found", http.StatusUnauthorized)
		return
	}
	
	// Define subscription tiers and their access levels
	subscriptionTiers := map[string]int{
		"free": 1,
		"basic": 2,
		"premium": 3,
		"enterprise": 4,
	}
	
	// Get content tier from URL
	vars := mux.Vars(r)
	contentTierStr := vars["tier"]
	contentTier, err := strconv.Atoi(contentTierStr)
	if err != nil {
		http.Error(w, "Invalid content tier", http.StatusBadRequest)
		return
	}
	
	userTier, exists := subscriptionTiers[subscriptionLevel]
	if !exists {
		http.Error(w, "Invalid subscription level", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-incorrect-authorization
	if userTier >= contentTier {
		// Allow access to content
		fmt.Fprintf(w, "Content access granted for subscription level: %s", subscriptionLevel)
	} else {
		http.Error(w, "Please upgrade your subscription to access this content", http.StatusPaymentRequired)
	}
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Get API key from header
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		http.Error(w, "API key required", http.StatusUnauthorized)
		return
	}
	
	// Verify API key against database and get associated role
	var role string
	err := db.QueryRow("SELECT role FROM api_keys WHERE key_hash = $1 AND is_active = true", 
		hashAPIKey(apiKey)).Scan(&role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
		} else {
			http.Error(w, "Server error", http.StatusInternalServerError)
		}
		return
	}
	
	// ok: rule-incorrect-authorization
	if role == "admin" {
		// Allow admin API operations
		fmt.Fprintf(w, "Admin API access granted")
	} else if role == "user" {
		// Allow regular user API operations
		fmt.Fprintf(w, "User API access granted")
	} else {
		http.Error(w, "Unknown role", http.StatusForbidden)
	}
}
// {/fact}

// Helper function for API key hashing
func hashAPIKey(apiKey string) string {
	// In a real implementation, this would use a secure hashing algorithm
	return "hashed_" + apiKey
}

func main() {
	// Initialize database connection
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	// Set up router
	r := mux.NewRouter()
	
	// Register handlers
	r.HandleFunc("/bad1", bad_case_1).Methods("GET")
	r.HandleFunc("/bad2", bad_case_2).Methods("GET")
	// ... register other handlers
	
	// Start server
	log.Fatal(http.ListenAndServe(":8080", r))
}