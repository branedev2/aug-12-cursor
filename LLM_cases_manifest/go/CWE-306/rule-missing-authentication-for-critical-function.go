package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// Database connection for examples
var db *sql.DB

// Session store for authentication examples
var store = sessions.NewCookieStore([]byte("something-very-secret"))

// User represents a user in the system
type User struct {
	ID       int
	Username string
	Password string
	Role     string
}

// AdminAction represents an administrative action
type AdminAction struct {
	Action string
	Target string
}

// True Positive Examples (Vulnerable Code)

// bad_case_1 exposes a critical admin function without any authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-missing-authentication-for-critical-function
	deleteUserID := r.URL.Query().Get("id")
	if deleteUserID != "" {
		_, err := db.Exec("DELETE FROM users WHERE id = ?", deleteUserID)
		if err != nil {
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "User %s deleted successfully", deleteUserID)
	}
}
// {/fact}

// bad_case_2 allows direct access to system configuration without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		// ruleid: rule-missing-authentication-for-critical-function
		configFile, err := os.Create("/etc/app/config.json")
		if err != nil {
			http.Error(w, "Failed to open config file", http.StatusInternalServerError)
			return
		}
		defer configFile.Close()
		
		config := map[string]string{
			"dbHost": r.FormValue("dbHost"),
			"dbUser": r.FormValue("dbUser"),
			"dbPass": r.FormValue("dbPass"),
		}
		
		encoder := json.NewEncoder(configFile)
		err = encoder.Encode(config)
		if err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Configuration updated successfully")
	}
}
// {/fact}

// bad_case_3 allows anyone to reset user passwords
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		username := r.FormValue("username")
		newPassword := r.FormValue("newPassword")
		
		// ruleid: rule-missing-authentication-for-critical-function
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		
		_, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
		if err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Password for %s reset successfully", username)
	}
}
// {/fact}

// bad_case_4 allows direct access to user data export without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	
	// ruleid: rule-missing-authentication-for-critical-function
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		http.Error(w, "Failed to query user data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	userData := make(map[string]interface{})
	for rows.Next() {
		var id int
		var username, email, address, creditCard string
		err := rows.Scan(&id, &username, &email, &address, &creditCard)
		if err != nil {
			http.Error(w, "Failed to scan user data", http.StatusInternalServerError)
			return
		}
		userData["id"] = id
		userData["username"] = username
		userData["email"] = email
		userData["address"] = address
		userData["creditCard"] = creditCard
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userData)
}
// {/fact}

// bad_case_5 allows direct access to system shutdown without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ruleid: rule-missing-authentication-for-critical-function
		fmt.Fprintf(w, "System shutdown initiated")
		go func() {
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}()
	}
}
// {/fact}

// bad_case_6 allows anyone to create admin users
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		// ruleid: rule-missing-authentication-for-critical-function
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		
		_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", username, hashedPassword)
		if err != nil {
			http.Error(w, "Failed to create admin user", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Admin user %s created successfully", username)
	}
}
// {/fact}

// bad_case_7 allows direct access to database backup without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-missing-authentication-for-critical-function
	backupFile, err := os.Create("/tmp/db_backup.sql")
	if err != nil {
		http.Error(w, "Failed to create backup file", http.StatusInternalServerError)
		return
	}
	defer backupFile.Close()
	
	// Execute database backup command
	cmd := "mysqldump -u root -p'password' mydb > /tmp/db_backup.sql"
	_, err = fmt.Fprintf(backupFile, "-- Backup command: %s\n", cmd)
	if err != nil {
		http.Error(w, "Failed to write to backup file", http.StatusInternalServerError)
		return
	}
	
	// In a real scenario, we would execute the command here
	
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=db_backup.sql")
	http.ServeFile(w, r, "/tmp/db_backup.sql")
}
// {/fact}

// bad_case_8 allows direct access to user impersonation without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	
	// ruleid: rule-missing-authentication-for-critical-function
	var user User
	err := db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		http.Error(w, "Failed to find user", http.StatusInternalServerError)
		return
	}
	
	// Create a session for the impersonated user
	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username
	session.Values["role"] = user.Role
	session.Save(r, w)
	
	fmt.Fprintf(w, "Now impersonating user: %s", user.Username)
}
// {/fact}

// bad_case_9 allows direct access to API key generation without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ruleid: rule-missing-authentication-for-critical-function
		// Generate a random API key
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			http.Error(w, "Failed to generate API key", http.StatusInternalServerError)
			return
		}
		
		apiKey := base64.StdEncoding.EncodeToString(b)
		
		// Store the API key in the database
		_, err = db.Exec("INSERT INTO api_keys (key, created_at) VALUES (?, NOW())", apiKey)
		if err != nil {
			http.Error(w, "Failed to store API key", http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"apiKey": apiKey})
	}
}
// {/fact}

// bad_case_10 allows direct access to log files without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	logFile := r.URL.Query().Get("file")
	
	// ruleid: rule-missing-authentication-for-critical-function
	file, err := os.Open("/var/log/" + logFile)
	if err != nil {
		http.Error(w, "Failed to open log file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	w.Header().Set("Content-Type", "text/plain")
	io.Copy(w, file)
}
// {/fact}

// bad_case_11 allows direct execution of system commands without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	
	// ruleid: rule-missing-authentication-for-critical-function
	output, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		http.Error(w, "Failed to execute command", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}
// {/fact}

// bad_case_12 allows direct modification of user roles without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		userID := r.FormValue("userID")
		newRole := r.FormValue("role")
		
		// ruleid: rule-missing-authentication-for-critical-function
		_, err = db.Exec("UPDATE users SET role = ? WHERE id = ?", newRole, userID)
		if err != nil {
			http.Error(w, "Failed to update user role", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "User %s role updated to %s", userID, newRole)
	}
}
// {/fact}

// bad_case_13 allows direct access to payment processing without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		amount, _ := strconv.ParseFloat(r.FormValue("amount"), 64)
		fromAccount := r.FormValue("fromAccount")
		toAccount := r.FormValue("toAccount")
		
		// ruleid: rule-missing-authentication-for-critical-function
		_, err = db.Exec("UPDATE accounts SET balance = balance - ? WHERE account_number = ?", amount, fromAccount)
		if err != nil {
			http.Error(w, "Failed to process payment (debit)", http.StatusInternalServerError)
			return
		}
		
		_, err = db.Exec("UPDATE accounts SET balance = balance + ? WHERE account_number = ?", amount, toAccount)
		if err != nil {
			http.Error(w, "Failed to process payment (credit)", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Payment of %.2f processed successfully", amount)
	}
}
// {/fact}

// bad_case_14 allows direct access to bulk user deletion without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// ruleid: rule-missing-authentication-for-critical-function
		_, err := db.Exec("DELETE FROM users WHERE last_login < DATE_SUB(NOW(), INTERVAL 1 YEAR)")
		if err != nil {
			http.Error(w, "Failed to delete inactive users", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Inactive users deleted successfully")
	}
}
// {/fact}

// bad_case_15 allows direct access to system settings without authentication
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		// ruleid: rule-missing-authentication-for-critical-function
		settings := make(map[string]string)
		for key, values := range r.Form {
			settings[key] = values[0]
		}
		
		settingsJSON, err := json.Marshal(settings)
		if err != nil {
			http.Error(w, "Failed to marshal settings", http.StatusInternalServerError)
			return
		}
		
		err = os.WriteFile("/etc/app/settings.json", settingsJSON, 0644)
		if err != nil {
			http.Error(w, "Failed to write settings file", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "System settings updated successfully")
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// good_case_1 properly authenticates before allowing user deletion
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated and is an admin
	userID, ok := session.Values["userID"].(int)
	role, roleOk := session.Values["role"].(string)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok || !roleOk || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	deleteUserID := r.URL.Query().Get("id")
	if deleteUserID != "" {
		_, err := db.Exec("DELETE FROM users WHERE id = ?", deleteUserID)
		if err != nil {
			http.Error(w, "Failed to delete user", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "User %s deleted successfully", deleteUserID)
	}
}
// {/fact}

// good_case_2 properly authenticates before allowing system configuration changes
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		configFile, err := os.Create("/etc/app/config.json")
		if err != nil {
			http.Error(w, "Failed to open config file", http.StatusInternalServerError)
			return
		}
		defer configFile.Close()
		
		config := map[string]string{
			"dbHost": r.FormValue("dbHost"),
			"dbUser": r.FormValue("dbUser"),
			"dbPass": r.FormValue("dbPass"),
		}
		
		encoder := json.NewEncoder(configFile)
		err = encoder.Encode(config)
		if err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Configuration updated successfully")
	}
}
// {/fact}

// good_case_3 properly authenticates before allowing password reset
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated
		userID, ok := session.Values["userID"].(int)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		// Only allow users to reset their own password or admins to reset any password
		targetUsername := r.FormValue("username")
		role, roleOk := session.Values["role"].(string)
		username, usernameOk := session.Values["username"].(string)
		
		if (!roleOk || role != "admin") && (!usernameOk || username != targetUsername) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		newPassword := r.FormValue("newPassword")
		
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		
		_, err = db.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, targetUsername)
		if err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Password for %s reset successfully", targetUsername)
	}
}
// {/fact}

// good_case_4 properly authenticates before allowing user data export
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated
	userID, ok := session.Values["userID"].(int)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Only allow users to access their own data or admins to access any data
	targetUserID := r.URL.Query().Get("id")
	role, roleOk := session.Values["role"].(string)
	
	if (!roleOk || role != "admin") && (strconv.Itoa(userID) != targetUserID) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", targetUserID)
	if err != nil {
		http.Error(w, "Failed to query user data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	userData := make(map[string]interface{})
	for rows.Next() {
		var id int
		var username, email, address, creditCard string
		err := rows.Scan(&id, &username, &email, &address, &creditCard)
		if err != nil {
			http.Error(w, "Failed to scan user data", http.StatusInternalServerError)
			return
		}
		userData["id"] = id
		userData["username"] = username
		userData["email"] = email
		userData["address"] = address
		userData["creditCard"] = creditCard
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userData)
}
// {/fact}

// good_case_5 properly authenticates before allowing system shutdown
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Additional verification with a special token for critical operations
		token := r.FormValue("confirmationToken")
		var storedToken string
		err := db.QueryRow("SELECT shutdown_token FROM admin_tokens WHERE user_id = ?", userID).Scan(&storedToken)
		if err != nil || token != storedToken {
			http.Error(w, "Invalid confirmation token", http.StatusUnauthorized)
			return
		}
		
		fmt.Fprintf(w, "System shutdown initiated")
		go func() {
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}()
	}
}
// {/fact}

// good_case_6 properly authenticates before allowing admin user creation
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		
		_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", username, hashedPassword)
		if err != nil {
			http.Error(w, "Failed to create admin user", http.StatusInternalServerError)
			return
		}
		
		// Log the admin creation action
		_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'create_admin', ?)", userID, username)
		if err != nil {
			log.Printf("Failed to log admin action: %v", err)
		}
		
		fmt.Fprintf(w, "Admin user %s created successfully", username)
	}
}
// {/fact}

// good_case_7 properly authenticates before allowing database backup
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated and is an admin
	userID, ok := session.Values["userID"].(int)
	role, roleOk := session.Values["role"].(string)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok || !roleOk || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Additional verification with a special token for database operations
	token := r.FormValue("dbToken")
	var storedToken string
	err := db.QueryRow("SELECT db_token FROM admin_tokens WHERE user_id = ?", userID).Scan(&storedToken)
	if err != nil || token != storedToken {
		http.Error(w, "Invalid database token", http.StatusUnauthorized)
		return
	}
	
	backupFile, err := os.Create("/tmp/db_backup.sql")
	if err != nil {
		http.Error(w, "Failed to create backup file", http.StatusInternalServerError)
		return
	}
	defer backupFile.Close()
	
	// Execute database backup command
	cmd := "mysqldump -u root -p'password' mydb > /tmp/db_backup.sql"
	_, err = fmt.Fprintf(backupFile, "-- Backup command: %s\n", cmd)
	if err != nil {
		http.Error(w, "Failed to write to backup file", http.StatusInternalServerError)
		return
	}
	
	// In a real scenario, we would execute the command here
	
	// Log the backup action
	_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'database_backup', 'full')", userID)
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
	
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=db_backup.sql")
	http.ServeFile(w, r, "/tmp/db_backup.sql")
}
// {/fact}

// good_case_8 properly authenticates before allowing user impersonation
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated and is an admin
	userID, ok := session.Values["userID"].(int)
	role, roleOk := session.Values["role"].(string)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok || !roleOk || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	targetUserID := r.URL.Query().Get("id")
	
	// Log the impersonation attempt
	_, err := db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'impersonate', ?)", userID, targetUserID)
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
	
	var user User
	err = db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", targetUserID).Scan(&user.ID, &user.Username, &user.Role)
	if err != nil {
		http.Error(w, "Failed to find user", http.StatusInternalServerError)
		return
	}
	
	// Create a session for the impersonated user, but mark it as impersonated
	impersonationSession, _ := store.Get(r, "impersonation")
	impersonationSession.Values["userID"] = user.ID
	impersonationSession.Values["username"] = user.Username
	impersonationSession.Values["role"] = user.Role
	impersonationSession.Values["impersonatedBy"] = userID
	impersonationSession.Save(r, w)
	
	fmt.Fprintf(w, "Now impersonating user: %s", user.Username)
}
// {/fact}

// good_case_9 properly authenticates before allowing API key generation
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Generate a random API key
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			http.Error(w, "Failed to generate API key", http.StatusInternalServerError)
			return
		}
		
		apiKey := base64.StdEncoding.EncodeToString(b)
		
		// Store the API key in the database with reference to who created it
		_, err = db.Exec("INSERT INTO api_keys (key, created_by, created_at) VALUES (?, ?, NOW())", apiKey, userID)
		if err != nil {
			http.Error(w, "Failed to store API key", http.StatusInternalServerError)
			return
		}
		
		// Log the API key generation
		_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'generate_api_key', 'system')", userID)
		if err != nil {
			log.Printf("Failed to log admin action: %v", err)
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"apiKey": apiKey})
	}
}
// {/fact}

// good_case_10 properly authenticates before allowing access to log files
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated and is an admin
	userID, ok := session.Values["userID"].(int)
	role, roleOk := session.Values["role"].(string)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok || !roleOk || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	logFile := r.URL.Query().Get("file")
	
	// Validate the log file name to prevent directory traversal
	if strings.Contains(logFile, "..") || strings.Contains(logFile, "/") {
		http.Error(w, "Invalid log file name", http.StatusBadRequest)
		return
	}
	
	// Log the access to log files
	_, err := db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'view_logs', ?)", userID, logFile)
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
	
	file, err := os.Open("/var/log/" + logFile)
	if err != nil {
		http.Error(w, "Failed to open log file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	w.Header().Set("Content-Type", "text/plain")
	io.Copy(w, file)
}
// {/fact}

// good_case_11 properly authenticates before allowing command execution
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session")
	
	// Check if user is authenticated and is an admin
	userID, ok := session.Values["userID"].(int)
	role, roleOk := session.Values["role"].(string)
	
	// ok: rule-missing-authentication-for-critical-function
	if !ok || !roleOk || role != "admin" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Additional verification with a special token for command execution
	token := r.FormValue("cmdToken")
	var storedToken string
	err := db.QueryRow("SELECT cmd_token FROM admin_tokens WHERE user_id = ?", userID).Scan(&storedToken)
	if err != nil || token != storedToken {
		http.Error(w, "Invalid command token", http.StatusUnauthorized)
		return
	}
	
	command := r.URL.Query().Get("cmd")
	
	// Validate the command to prevent dangerous operations
	allowedCommands := []string{"ls", "ps", "df", "uptime", "free"}
	commandAllowed := false
	for _, allowed := range allowedCommands {
		if strings.HasPrefix(command, allowed) {
			commandAllowed = true
			break
		}
	}
	
	if !commandAllowed {
		http.Error(w, "Command not allowed", http.StatusForbidden)
		return
	}
	
	// Log the command execution
	_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'execute_command', ?)", userID, command)
	if err != nil {
		log.Printf("Failed to log admin action: %v", err)
	}
	
	output, err := exec.Command("sh", "-c", command).Output()
	if err != nil {
		http.Error(w, "Failed to execute command", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}
// {/fact}

// good_case_12 properly authenticates before allowing role modification
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		targetUserID := r.FormValue("userID")
		newRole := r.FormValue("role")
		
		// Validate the role
		allowedRoles := []string{"user", "editor", "admin"}
		roleAllowed := false
		for _, allowed := range allowedRoles {
			if newRole == allowed {
				roleAllowed = true
				break
			}
		}
		
		if !roleAllowed {
			http.Error(w, "Invalid role", http.StatusBadRequest)
			return
		}
		
		// Log the role modification
		_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'modify_role', ?)", userID, targetUserID)
		if err != nil {
			log.Printf("Failed to log admin action: %v", err)
		}
		
		_, err = db.Exec("UPDATE users SET role = ? WHERE id = ?", newRole, targetUserID)
		if err != nil {
			http.Error(w, "Failed to update user role", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "User %s role updated to %s", targetUserID, newRole)
	}
}
// {/fact}

// good_case_13 properly authenticates before allowing payment processing
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated
		userID, ok := session.Values["userID"].(int)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		amount, _ := strconv.ParseFloat(r.FormValue("amount"), 64)
		fromAccount := r.FormValue("fromAccount")
		toAccount := r.FormValue("toAccount")
		
		// Verify that the user owns the source account
		var accountOwnerID int
		err = db.QueryRow("SELECT user_id FROM accounts WHERE account_number = ?", fromAccount).Scan(&accountOwnerID)
		if err != nil || accountOwnerID != userID {
			http.Error(w, "Unauthorized account access", http.StatusUnauthorized)
			return
		}
		
		// Use a transaction to ensure atomicity
		tx, err := db.Begin()
		if err != nil {
			http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
			return
		}
		
		_, err = tx.Exec("UPDATE accounts SET balance = balance - ? WHERE account_number = ?", amount, fromAccount)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Failed to process payment (debit)", http.StatusInternalServerError)
			return
		}
		
		_, err = tx.Exec("UPDATE accounts SET balance = balance + ? WHERE account_number = ?", amount, toAccount)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Failed to process payment (credit)", http.StatusInternalServerError)
			return
		}
		
		// Log the transaction
		_, err = tx.Exec("INSERT INTO transaction_logs (user_id, from_account, to_account, amount) VALUES (?, ?, ?, ?)", 
			userID, fromAccount, toAccount, amount)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Failed to log transaction", http.StatusInternalServerError)
			return
		}
		
		err = tx.Commit()
		if err != nil {
			http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Payment of %.2f processed successfully", amount)
	}
}
// {/fact}

// good_case_14 properly authenticates before allowing bulk user deletion
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Additional verification with a special token for bulk operations
		token := r.FormValue("bulkToken")
		var storedToken string
		err := db.QueryRow("SELECT bulk_token FROM admin_tokens WHERE user_id = ?", userID).Scan(&storedToken)
		if err != nil || token != storedToken {
			http.Error(w, "Invalid bulk operation token", http.StatusUnauthorized)
			return
		}
		
		// Get count of users to be deleted for logging
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM users WHERE last_login < DATE_SUB(NOW(), INTERVAL 1 YEAR)").Scan(&count)
		if err != nil {
			http.Error(w, "Failed to count inactive users", http.StatusInternalServerError)
			return
		}
		
		// Log the bulk deletion
		_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'bulk_delete', ?)", 
			userID, fmt.Sprintf("%d inactive users", count))
		if err != nil {
			log.Printf("Failed to log admin action: %v", err)
		}
		
		_, err = db.Exec("DELETE FROM users WHERE last_login < DATE_SUB(NOW(), INTERVAL 1 YEAR)")
		if err != nil {
			http.Error(w, "Failed to delete inactive users", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "%d inactive users deleted successfully", count)
	}
}
// {/fact}

// good_case_15 properly authenticates before allowing system settings changes
// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Get the session
		session, _ := store.Get(r, "session")
		
		// Check if user is authenticated and is an admin
		userID, ok := session.Values["userID"].(int)
		role, roleOk := session.Values["role"].(string)
		
		// ok: rule-missing-authentication-for-critical-function
		if !ok || !roleOk || role != "admin" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}
		
		// Log the settings change
		_, err = db.Exec("INSERT INTO admin_logs (admin_id, action, target) VALUES (?, 'update_settings', 'system')", userID)
		if err != nil {
			log.Printf("Failed to log admin action: %v", err)
		}
		
		settings := make(map[string]string)
		for key, values := range r.Form {
			settings[key] = values[0]
		}
		
		settingsJSON, err := json.Marshal(settings)
		if err != nil {
			http.Error(w, "Failed to marshal settings", http.StatusInternalServerError)
			return
		}
		
		err = os.WriteFile("/etc/app/settings.json", settingsJSON, 0644)
		if err != nil {
			http.Error(w, "Failed to write settings file", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "System settings updated successfully")
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	router := mux.NewRouter()
	
	// Register all the handlers
	router.HandleFunc("/admin/delete-user", bad_case_1)
	router.HandleFunc("/admin/config", bad_case_2)
	router.HandleFunc("/reset-password", bad_case_3)
	router.HandleFunc("/user-data", bad_case_4)
	router.HandleFunc("/system/shutdown", bad_case_5)
	router.HandleFunc("/admin/create", bad_case_6)
	router.HandleFunc("/db/backup", bad_case_7)
	router.HandleFunc("/impersonate", bad_case_8)
	router.HandleFunc("/api/generate-key", bad_case_9)
	router.HandleFunc("/logs", bad_case_10)
	router.HandleFunc("/exec", bad_case_11)
	router.HandleFunc("/admin/modify-role", bad_case_12)
	router.HandleFunc("/payment/process", bad_case_13)
	router.HandleFunc("/admin/bulk-delete", bad_case_14)
	router.HandleFunc("/admin/settings", bad_case_15)
	
	router.HandleFunc("/secure/admin/delete-user", good_case_1)
	router.HandleFunc("/secure/admin/config", good_case_2)
	router.HandleFunc("/secure/reset-password", good_case_3)
	router.HandleFunc("/secure/user-data", good_case_4)
	router.HandleFunc("/secure/system/shutdown", good_case_5)
	router.HandleFunc("/secure/admin/create", good_case_6)
	router.HandleFunc("/secure/db/backup", good_case_7)
	router.HandleFunc("/secure/impersonate", good_case_8)
	router.HandleFunc("/secure/api/generate-key", good_case_9)
	router.HandleFunc("/secure/logs", good_case_10)
	router.HandleFunc("/secure/exec", good_case_11)
	router.HandleFunc("/secure/admin/modify-role", good_case_12)
	router.HandleFunc("/secure/payment/process", good_case_13)
	router.HandleFunc("/secure/admin/bulk-delete", good_case_14)
	router.HandleFunc("/secure/admin/settings", good_case_15)
	
	log.Fatal(http.ListenAndServe(":8080", router))
}