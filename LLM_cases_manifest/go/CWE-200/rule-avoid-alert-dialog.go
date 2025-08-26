package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/webview/webview"
	_ "github.com/go-sql-driver/mysql"
)

// True Positives (Vulnerable Code)

// bad_case_1 displays user's social security number in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	ssn := r.URL.Query().Get("ssn")
	if ssn == "" {
		ssn = "123-45-6789" // Default SSN for testing
	}
	
	// Create webview instance
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("User Information")
	wv.SetSize(800, 600, webview.HintNone)
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('User SSN: %s');", ssn))
	
	wv.Run()
	fmt.Fprintf(w, "Window closed")
}
// {/fact}

// bad_case_2 displays credit card information in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("cardNumber")
	expiryDate := r.FormValue("expiryDate")
	cvv := r.FormValue("cvv")
	
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("Payment Information")
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Payment processed with card: %s, expiry: %s, CVV: %s');", 
		cardNumber, expiryDate, cvv))
	
	wv.Run()
}
// {/fact}

// bad_case_3 displays database credentials in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_3() {
	username := "admin"
	password := "super_secret_password"
	
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("Database Connection")
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Connected to database with username: %s and password: %s');", 
		username, password))
	
	wv.Run()
}
// {/fact}

// bad_case_4 displays API key in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_4(r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = "sk_test_PLACEHOLDER_KEY"
	}
	
	wv := webview.New(false)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Using API key: %s for transaction');", apiKey))
	
	wv.Run()
}
// {/fact}

// bad_case_5 displays user login credentials in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		wv := webview.New(true)
		defer wv.Destroy()
		
		// ruleid: rule-avoid-alert-dialog
		wv.Eval(fmt.Sprintf("alert('Login attempt with username: %s and password: %s');", 
			username, password))
		
		wv.Run()
	}
}
// {/fact}

// bad_case_6 displays authentication token in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_6(r *http.Request) {
	authToken := r.Header.Get("Authorization")
	if strings.HasPrefix(authToken, "Bearer ") {
		token := strings.TrimPrefix(authToken, "Bearer ")
		
		wv := webview.New(true)
		defer wv.Destroy()
		
		// ruleid: rule-avoid-alert-dialog
		wv.Eval(fmt.Sprintf("alert('User authenticated with token: %s');", token))
		
		wv.Run()
	}
}
// {/fact}

// bad_case_7 displays encrypted data and encryption key in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_7() {
	key := []byte("AES256Key-32Characters1234567890")
	plaintext := []byte("sensitive_data_to_be_encrypted")
	
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Encrypted data: %s\\nKey used: %s');", 
		encoded, string(key)))
	
	wv.Run()
}
// {/fact}

// bad_case_8 displays session information in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	var store = sessions.NewCookieStore([]byte("something-very-secret"))
	session, _ := store.Get(r, "session-name")
	
	// Set some session values
	session.Values["authenticated"] = true
	session.Values["userId"] = "12345"
	session.Save(r, w)
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Session established with ID: %s, Auth status: %t');", 
		session.Values["userId"], session.Values["authenticated"]))
	
	wv.Run()
}
// {/fact}

// bad_case_9 displays database query results with PII in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_9() {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	rows, err := db.Query("SELECT name, email, phone FROM users LIMIT 5")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	
	var results string
	for rows.Next() {
		var name, email, phone string
		if err := rows.Scan(&name, &email, &phone); err != nil {
			log.Fatal(err)
		}
		results += fmt.Sprintf("Name: %s, Email: %s, Phone: %s\n", name, email, phone)
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('User data from database:\\n%s');", results))
	
	wv.Run()
}
// {/fact}

// bad_case_10 displays system environment variables in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_10() {
	homeDir := os.Getenv("HOME")
	sshKey := os.Getenv("SSH_KEY")
	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('System information:\\nHome: %s\\nSSH Key: %s\\nAWS Secret: %s');", 
		homeDir, sshKey, awsSecret))
	
	wv.Run()
}
// {/fact}

// bad_case_11 displays user input with potential XSS in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("message")
	if userInput == "" {
		userInput = "<script>alert('XSS')</script>"
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('User message: %s');", userInput))
	
	wv.Run()
}
// {/fact}

// bad_case_12 displays file content in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		filename = "/etc/passwd"
	}
	
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('File content of %s:\\n%s');", filename, string(content)))
	
	wv.Run()
}
// {/fact}

// bad_case_13 displays health check information with system details in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_13() {
	hostname, _ := os.Hostname()
	currentUser := os.Getenv("USER")
	processID := os.Getpid()
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('System health check:\\nHostname: %s\\nUser: %s\\nPID: %d');", 
		hostname, currentUser, processID))
	
	wv.Run()
}
// {/fact}

// bad_case_14 displays error details with stack trace in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			errorDetails := fmt.Sprintf("Panic: %v\nStack trace: %s", r, "stack trace details here")
			
			wv := webview.New(true)
			defer wv.Destroy()
			
			// ruleid: rule-avoid-alert-dialog
			wv.Eval(fmt.Sprintf("alert('Application error:\\n%s');", errorDetails))
			
			wv.Run()
		}
	}()
	
	// Trigger a panic for demonstration
	var ptr *int
	*ptr = 42 // This will cause a nil pointer dereference
}
// {/fact}

// bad_case_15 displays network configuration in an alert dialog
// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_15() {
	interfaces, _ := net()
	var networkInfo string
	
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			networkInfo += fmt.Sprintf("Interface: %s, Address: %s\n", 
				iface.Name, addr.String())
		}
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// ruleid: rule-avoid-alert-dialog
	wv.Eval(fmt.Sprintf("alert('Network configuration:\\n%s');", networkInfo))
	
	wv.Run()
}
// {/fact}

// True Negatives (Secure Code)

// good_case_1 uses a secure logging mechanism instead of alert dialog for SSN
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	ssn := r.URL.Query().Get("ssn")
	if ssn == "" {
		ssn = "123-45-6789" // Default SSN for testing
	}
	
	// ok: rule-avoid-alert-dialog
	log.Printf("Processing request for SSN: %s", maskSSN(ssn))
	
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("User Information")
	wv.SetSize(800, 600, webview.HintNone)
	
	// Using a non-sensitive message in alert
	wv.Eval("alert('User information processed successfully');")
	
	wv.Run()
	fmt.Fprintf(w, "Window closed")
}
// {/fact}

// Helper function to mask SSN
func maskSSN(ssn string) string {
	if len(ssn) >= 9 {
		return "XXX-XX-" + ssn[len(ssn)-4:]
	}
	return "XXX-XX-XXXX"
}

// good_case_2 uses a secure UI element instead of alert for payment info
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("cardNumber")
	expiryDate := r.FormValue("expiryDate")
	cvv := r.FormValue("cvv")
	
	// Mask sensitive data
	maskedCard := "XXXX-XXXX-XXXX-" + cardNumber[len(cardNumber)-4:]
	
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("Payment Information")
	
	// ok: rule-avoid-alert-dialog
	// Using HTML to create a secure UI element instead of alert
	wv.Navigate("data:text/html,<!DOCTYPE html><html><body><div class='notification'>Payment processed with card ending in " + 
		cardNumber[len(cardNumber)-4:] + "</div></body></html>")
	
	// Log securely
	log.Printf("Payment processed with card: %s", maskedCard)
	
	wv.Run()
}
// {/fact}

// good_case_3 uses secure logging instead of alert for database credentials
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_3() {
	username := "admin"
	password := "super_secret_password"
	
	// ok: rule-avoid-alert-dialog
	// Log connection attempt without exposing full credentials
	log.Printf("Database connection attempt with username: %s", username)
	
	wv := webview.New(true)
	defer wv.Destroy()
	wv.SetTitle("Database Connection")
	
	// Using a non-sensitive message in UI
	wv.Eval("alert('Database connection established');")
	
	wv.Run()
}
// {/fact}

// good_case_4 uses secure handling of API key
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_4(r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = "sk_test_PLACEHOLDER_KEY"
	}
	
	// ok: rule-avoid-alert-dialog
	// Mask API key for logging
	maskedKey := apiKey[:4] + "..." + apiKey[len(apiKey)-4:]
	log.Printf("Using API key: %s for transaction", maskedKey)
	
	wv := webview.New(false)
	defer wv.Destroy()
	
	// Using a non-sensitive message in UI
	wv.Eval("alert('API request completed');")
	
	wv.Run()
}
// {/fact}

// good_case_5 uses secure handling of login credentials
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		
		// ok: rule-avoid-alert-dialog
		// Log authentication attempt without exposing password
		log.Printf("Login attempt for user: %s", username)
		
		wv := webview.New(true)
		defer wv.Destroy()
		
		// Using a non-sensitive message in UI
		wv.Eval("alert('Login attempt processed');")
		
		wv.Run()
	}
}
// {/fact}

// good_case_6 uses secure handling of authentication token
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_6(r *http.Request) {
	authToken := r.Header.Get("Authorization")
	if strings.HasPrefix(authToken, "Bearer ") {
		token := strings.TrimPrefix(authToken, "Bearer ")
		
		// ok: rule-avoid-alert-dialog
		// Log token usage without exposing the token
		log.Printf("Authentication with token: %s...%s", 
			token[:5], token[len(token)-5:])
		
		wv := webview.New(true)
		defer wv.Destroy()
		
		// Using a non-sensitive message in UI
		wv.Eval("alert('User authenticated successfully');")
		
		wv.Run()
	}
}
// {/fact}

// good_case_7 uses secure handling of encrypted data
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_7() {
	key := []byte("AES256Key-32Characters1234567890")
	plaintext := []byte("sensitive_data_to_be_encrypted")
	
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	
	// ok: rule-avoid-alert-dialog
	// Log encryption operation without exposing the key
	log.Printf("Data encrypted successfully. Result length: %d bytes", len(encoded))
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Using a non-sensitive message in UI
	wv.Eval("alert('Data encrypted successfully');")
	
	wv.Run()
}
// {/fact}

// good_case_8 uses secure handling of session information
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	var store = sessions.NewCookieStore([]byte("something-very-secret"))
	session, _ := store.Get(r, "session-name")
	
	// Set some session values
	session.Values["authenticated"] = true
	session.Values["userId"] = "12345"
	session.Save(r, w)
	
	// ok: rule-avoid-alert-dialog
	// Log session creation without exposing sensitive details
	log.Printf("Session established for user ID: %s", session.Values["userId"])
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Using a non-sensitive message in UI
	wv.Eval("alert('Session established');")
	
	wv.Run()
}
// {/fact}

// good_case_9 uses secure handling of database query results
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_9() {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	rows, err := db.Query("SELECT name, email, phone FROM users LIMIT 5")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	
	// ok: rule-avoid-alert-dialog
	// Process data securely
	var users []map[string]string
	for rows.Next() {
		var name, email, phone string
		if err := rows.Scan(&name, &email, &phone); err != nil {
			log.Fatal(err)
		}
		
		// Mask email for display
		atIndex := strings.Index(email, "@")
		maskedEmail := email[:2] + "..." + email[atIndex:]
		
		user := map[string]string{
			"name":  name,
			"email": maskedEmail,
			"phone": phone[:3] + "-XXX-XXXX",
		}
		users = append(users, user)
		
		// Log securely
		log.Printf("Retrieved user: %s with email: %s", name, maskedEmail)
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Display data in a secure UI component, not an alert
	htmlContent := "<html><body><h2>User Data</h2><ul>"
	for _, user := range users {
		htmlContent += fmt.Sprintf("<li>%s (%s)</li>", user["name"], user["email"])
	}
	htmlContent += "</ul></body></html>"
	
	wv.Navigate("data:text/html," + htmlContent)
	wv.Run()
}
// {/fact}

// good_case_10 uses secure handling of environment variables
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_10() {
	homeDir := os.Getenv("HOME")
	sshKey := os.Getenv("SSH_KEY")
	awsSecret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	
	// ok: rule-avoid-alert-dialog
	// Log non-sensitive info only
	log.Printf("Application running with home directory: %s", homeDir)
	if sshKey != "" {
		log.Printf("SSH key is configured")
	}
	if awsSecret != "" {
		log.Printf("AWS credentials are configured")
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Using a non-sensitive message in UI
	wv.Eval("alert('System configuration loaded');")
	
	wv.Run()
}
// {/fact}

// good_case_11 uses secure handling of user input with potential XSS
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("message")
	if userInput == "" {
		userInput = "<script>alert('XSS')</script>"
	}
	
	// ok: rule-avoid-alert-dialog
	// Sanitize input for logging
	sanitizedInput := strings.ReplaceAll(userInput, "<", "&lt;")
	sanitizedInput = strings.ReplaceAll(sanitizedInput, ">", "&gt;")
	log.Printf("Received user message: %s", sanitizedInput)
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Display sanitized content in a secure UI component
	htmlContent := fmt.Sprintf("<html><body><div>Message received: %s</div></body></html>", 
		sanitizedInput)
	wv.Navigate("data:text/html," + htmlContent)
	
	wv.Run()
}
// {/fact}

// good_case_12 uses secure handling of file content
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		filename = "/etc/passwd"
	}
	
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}
	
	// ok: rule-avoid-alert-dialog
	// Log file access without exposing content
	log.Printf("File accessed: %s, size: %d bytes", filename, len(content))
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Display file content in a secure UI component, not an alert
	htmlContent := fmt.Sprintf("<html><body><h2>File: %s</h2><pre>%s</pre></body></html>", 
		filename, string(content))
	wv.Navigate("data:text/html," + htmlContent)
	
	wv.Run()
}
// {/fact}

// good_case_13 uses secure handling of health check information
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_13() {
	hostname, _ := os.Hostname()
	currentUser := os.Getenv("USER")
	processID := os.Getpid()
	
	// ok: rule-avoid-alert-dialog
	// Log system information securely
	log.Printf("System health check - Hostname: %s, User: %s, PID: %d", 
		hostname, currentUser, processID)
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Display system info in a secure UI component
	htmlContent := fmt.Sprintf("<html><body><h2>System Health</h2><ul>"+
		"<li>Hostname: %s</li>"+
		"<li>User: %s</li>"+
		"<li>PID: %d</li>"+
		"</ul></body></html>", hostname, currentUser, processID)
	wv.Navigate("data:text/html," + htmlContent)
	
	wv.Run()
}
// {/fact}

// good_case_14 uses secure handling of error details
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			errorDetails := fmt.Sprintf("Panic: %v\nStack trace: %s", r, "stack trace details here")
			
			// ok: rule-avoid-alert-dialog
			// Log error details securely
			log.Printf("Application error: %v", r)
			
			wv := webview.New(true)
			defer wv.Destroy()
			
			// Display a generic error message to the user
			wv.Eval("alert('An error occurred. Please contact support.');")
			
			// Log detailed error for developers
			fmt.Println(errorDetails)
			
			wv.Run()
		}
	}()
	
	// Trigger a panic for demonstration
	var ptr *int
	*ptr = 42 // This will cause a nil pointer dereference
}
// {/fact}

// good_case_15 uses secure handling of network configuration
// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_15() {
	interfaces, _ := net()
	
	// ok: rule-avoid-alert-dialog
	// Log network information securely
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			log.Printf("Network interface: %s, Address: %s", 
				iface.Name, addr.String())
		}
	}
	
	wv := webview.New(true)
	defer wv.Destroy()
	
	// Display a summary in a secure UI component
	htmlContent := "<html><body><h2>Network Configuration</h2><ul>"
	for _, iface := range interfaces {
		htmlContent += fmt.Sprintf("<li>Interface: %s</li>", iface.Name)
	}
	htmlContent += "</ul><p>Details logged to application log</p></body></html>"
	
	wv.Navigate("data:text/html," + htmlContent)
	wv.Run()
}
// {/fact}

// Helper function to simulate network interfaces
func net() ([]interface{}, error) {
	// This is a mock function to avoid compilation errors
	return []interface{}{}, nil
}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/good1", good_case_1)
	http.ListenAndServe(":8080", nil)
}