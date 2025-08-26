package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	x := 10
	y := 5
	
	if x > y {
		// ruleid: rule-useless-if-body
		fmt.Println("Processing data...")
		log.Println("Operation completed")
	} else {
		fmt.Println("Processing data...")
		log.Println("Operation completed")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	userInput := "test"
	
	if len(userInput) > 0 {
		// ruleid: rule-useless-if-body
		result := userInput + " processed"
		fmt.Println(result)
	} else {
		result := userInput + " processed"
		fmt.Println(result)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	if username == "admin" {
		// ruleid: rule-useless-if-body
		w.Write([]byte("Welcome to the system"))
		log.Println("User accessed the system")
	} else {
		w.Write([]byte("Welcome to the system"))
		log.Println("User accessed the system")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	file, err := os.Open("config.txt")
	if err != nil {
		// ruleid: rule-useless-if-body
		log.Println("Error occurred")
		return
	} else {
		log.Println("Error occurred")
		return
	}
	defer file.Close()
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	age, err := strconv.Atoi(r.URL.Query().Get("age"))
	
	if err == nil && age >= 18 {
		// ruleid: rule-useless-if-body
		w.Write([]byte("Access granted"))
		log.Println("User granted access")
		saveAuditLog("access_granted")
	} else {
		w.Write([]byte("Access granted"))
		log.Println("User granted access")
		saveAuditLog("access_granted")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	config := loadConfiguration()
	
	if config.Debug {
		// ruleid: rule-useless-if-body
		fmt.Println("Starting application...")
		initializeSystem()
		fmt.Println("System ready")
	} else {
		fmt.Println("Starting application...")
		initializeSystem()
		fmt.Println("System ready")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	if action == "delete" {
		// ruleid: rule-useless-if-body
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "processing"}`))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "processing"}`))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	data := []int{1, 2, 3, 4, 5}
	
	if len(data) > 3 {
		// ruleid: rule-useless-if-body
		result := 0
		for _, v := range data {
			result += v
		}
		fmt.Println("Sum:", result)
	} else {
		result := 0
		for _, v := range data {
			result += v
		}
		fmt.Println("Sum:", result)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	if validateCredentials(username, password) {
		// ruleid: rule-useless-if-body
		session := createSession()
		w.Header().Set("Set-Cookie", "session="+session)
		w.Write([]byte("Logged in"))
	} else {
		session := createSession()
		w.Header().Set("Set-Cookie", "session="+session)
		w.Write([]byte("Logged in"))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	err := connectToDatabase()
	
	if err != nil {
		// ruleid: rule-useless-if-body
		log.Println("Database connection failed")
		fallbackToLocalStorage()
		notifyAdmin("DB connection issue")
	} else {
		log.Println("Database connection failed")
		fallbackToLocalStorage()
		notifyAdmin("DB connection issue")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")
	
	if fileType == "pdf" || fileType == "doc" {
		// ruleid: rule-useless-if-body
		w.Header().Set("Content-Type", "application/octet-stream")
		data := loadFileData(fileType)
		w.Write(data)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		data := loadFileData(fileType)
		w.Write(data)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	retries := 3
	success := false
	
	for i := 0; i < retries && !success; i++ {
		if i > 0 {
			// ruleid: rule-useless-if-body
			log.Printf("Retry attempt %d", i)
			success = attemptOperation()
		} else {
			log.Printf("Retry attempt %d", i)
			success = attemptOperation()
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	userRole := getUserRole(r)
	
	if userRole == "admin" || userRole == "manager" {
		// ruleid: rule-useless-if-body
		data := loadDashboardData()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		logAccess(r, "dashboard")
	} else {
		data := loadDashboardData()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		logAccess(r, "dashboard")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	settings := loadUserSettings()
	
	if settings.DarkMode {
		// ruleid: rule-useless-if-body
		theme := "standard"
		applyTheme(theme)
		saveUserPreference("theme", theme)
	} else {
		theme := "standard"
		applyTheme(theme)
		saveUserPreference("theme", theme)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := checkAuth(r)
	
	if isAuthenticated {
		// ruleid: rule-useless-if-body
		template := loadTemplate("main")
		data := prepareTemplateData(r)
		renderTemplate(w, template, data)
	} else {
		template := loadTemplate("main")
		data := prepareTemplateData(r)
		renderTemplate(w, template, data)
	}
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	x := 10
	y := 5
	
	// ok: rule-useless-if-body
	if x > y {
		fmt.Println("x is greater than y")
	} else {
		fmt.Println("x is not greater than y")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	userInput := "test"
	
	// ok: rule-useless-if-body
	if len(userInput) > 0 {
		result := userInput + " is not empty"
		fmt.Println(result)
	} else {
		result := userInput + " is empty"
		fmt.Println(result)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// ok: rule-useless-if-body
	if username == "admin" {
		w.Write([]byte("Welcome, administrator"))
		log.Println("Admin accessed the system")
	} else {
		w.Write([]byte("Welcome, user"))
		log.Println("Regular user accessed the system")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	file, err := os.Open("config.txt")
	
	// ok: rule-useless-if-body
	if err != nil {
		log.Println("Error opening file:", err)
		return
	} else {
		log.Println("File opened successfully")
		defer file.Close()
		// Process file
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	age, err := strconv.Atoi(r.URL.Query().Get("age"))
	
	// ok: rule-useless-if-body
	if err == nil && age >= 18 {
		w.Write([]byte("Access granted - you are an adult"))
		log.Println("Adult user granted access")
		saveAuditLog("adult_access")
	} else {
		w.Write([]byte("Access denied - adults only"))
		log.Println("Underage user denied access")
		saveAuditLog("underage_attempt")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	config := loadConfiguration()
	
	// ok: rule-useless-if-body
	if config.Debug {
		fmt.Println("Starting application in DEBUG mode...")
		initializeDebugSystem()
		fmt.Println("Debug system ready")
	} else {
		fmt.Println("Starting application in PRODUCTION mode...")
		initializeProductionSystem()
		fmt.Println("Production system ready")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	// ok: rule-useless-if-body
	if action == "delete" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "deleting"}`))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "unknown action"}`))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	data := []int{1, 2, 3, 4, 5}
	
	// ok: rule-useless-if-body
	if len(data) > 3 {
		result := 0
		for _, v := range data {
			result += v
		}
		fmt.Println("Sum of many items:", result)
	} else {
		result := 0
		for _, v := range data {
			result += v * 2
		}
		fmt.Println("Doubled sum of few items:", result)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	// ok: rule-useless-if-body
	if validateCredentials(username, password) {
		session := createSession()
		w.Header().Set("Set-Cookie", "session="+session)
		w.Write([]byte("Logged in successfully"))
	} else {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("Invalid credentials. Please try again."))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	err := connectToDatabase()
	
	// ok: rule-useless-if-body
	if err != nil {
		log.Println("Database connection failed:", err)
		fallbackToLocalStorage()
		notifyAdmin("DB connection issue: " + err.Error())
	} else {
		log.Println("Database connected successfully")
		initializeTables()
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")
	
	// ok: rule-useless-if-body
	if fileType == "pdf" || fileType == "doc" {
		w.Header().Set("Content-Type", "application/octet-stream")
		data := loadFileData(fileType)
		w.Write(data)
	} else {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Unsupported file type"))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	retries := 3
	success := false
	
	for i := 0; i < retries && !success; i++ {
		// ok: rule-useless-if-body
		if i > 0 {
			log.Printf("Retry attempt %d after failure", i)
			time.Sleep(time.Second * time.Duration(i))
			success = attemptOperation()
		} else {
			log.Printf("Initial attempt")
			success = attemptOperation()
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	userRole := getUserRole(r)
	
	// ok: rule-useless-if-body
	if userRole == "admin" || userRole == "manager" {
		data := loadAdminDashboardData()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		logAccess(r, "admin_dashboard")
	} else {
		data := loadUserDashboardData()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		logAccess(r, "user_dashboard")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	settings := loadUserSettings()
	
	// ok: rule-useless-if-body
	if settings.DarkMode {
		theme := "dark"
		applyTheme(theme)
		saveUserPreference("theme", theme)
	} else {
		theme := "light"
		applyTheme(theme)
		saveUserPreference("theme", theme)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := checkAuth(r)
	
	// ok: rule-useless-if-body
	if isAuthenticated {
		template := loadTemplate("dashboard")
		data := prepareAuthenticatedData(r)
		renderTemplate(w, template, data)
	} else {
		template := loadTemplate("login")
		data := prepareAnonymousData()
		renderTemplate(w, template, data)
	}
}
// {/fact}

// Helper functions to make the examples compile

func saveAuditLog(action string) {}
func loadConfiguration() struct{ Debug bool } { return struct{ Debug bool }{Debug: true} }
func initializeSystem() {}
func initializeDebugSystem() {}
func initializeProductionSystem() {}
func validateCredentials(username, password string) bool { return true }
func createSession() string { return "session123" }
func connectToDatabase() error { return nil }
func fallbackToLocalStorage() {}
func notifyAdmin(msg string) {}
func loadFileData(fileType string) []byte { return []byte("data") }
func attemptOperation() bool { return true }
func getUserRole(r *http.Request) string { return "user" }
func loadDashboardData() []byte { return []byte("data") }
func loadAdminDashboardData() []byte { return []byte("admin data") }
func loadUserDashboardData() []byte { return []byte("user data") }
func logAccess(r *http.Request, page string) {}
func loadUserSettings() struct{ DarkMode bool } { return struct{ DarkMode bool }{DarkMode: true} }
func applyTheme(theme string) {}
func saveUserPreference(key, value string) {}
func checkAuth(r *http.Request) bool { return true }
func loadTemplate(name string) string { return name }
func prepareTemplateData(r *http.Request) map[string]interface{} { return nil }
func prepareAuthenticatedData(r *http.Request) map[string]interface{} { return nil }
func prepareAnonymousData() map[string]interface{} { return nil }
func renderTemplate(w http.ResponseWriter, template string, data map[string]interface{}) {}
func initializeTables() {}