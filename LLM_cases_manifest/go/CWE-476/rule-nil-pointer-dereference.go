package main

import (
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

	_ "github.com/go-sql-driver/mysql"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_1() {
	var ptr *string
	// ruleid: rule-nil-pointer-dereference
	fmt.Println(*ptr) // Dereferencing nil pointer without checking
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_2() {
	var user *User
	// ruleid: rule-nil-pointer-dereference
	name := user.Name // Accessing struct field without nil check
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_3() {
	file, err := os.Open("nonexistent.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		// Missing return statement
	}
	// ruleid: rule-nil-pointer-dereference
	data, _ := ioutil.ReadAll(file) // file is nil here if the open failed
	fmt.Println(string(data))
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_4() {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		// Missing return statement
	}
	// ruleid: rule-nil-pointer-dereference
	rows, _ := db.Query("SELECT * FROM users") // db could be nil
	defer rows.Close()
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_5() {
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		var data *ResponseData
		// Function that might return nil data
		data = fetchDataFromDB()
		// ruleid: rule-nil-pointer-dereference
		w.Write([]byte(data.Message)) // No nil check before accessing data.Message
	})
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_6() {
	var m map[string]string
	// ruleid: rule-nil-pointer-dereference
	m["key"] = "value" // Writing to nil map without initialization
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_7() {
	var slice []int
	// ruleid: rule-nil-pointer-dereference
	slice[0] = 1 // Accessing nil slice without initialization
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_8() {
	var mu *sync.Mutex
	// ruleid: rule-nil-pointer-dereference
	mu.Lock() // Using method on nil mutex
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_9() {
	result, err := riskyOperation()
	if err != nil {
		fmt.Println("Operation failed:", err)
		// Missing return statement
	}
	// ruleid: rule-nil-pointer-dereference
	fmt.Println(*result) // result could be nil here
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_10() {
	var ch chan int
	// ruleid: rule-nil-pointer-dereference
	ch <- 5 // Sending to nil channel
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_11() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		user := getUserByID(userID) // May return nil
		// ruleid: rule-nil-pointer-dereference
		fmt.Fprintf(w, "Username: %s", user.Username) // No nil check
	})
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_12() {
	var handler *http.ServeMux
	// ruleid: rule-nil-pointer-dereference
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	}) // Using method on nil ServeMux
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_13() {
	var config *Config
	loadConfig() // This function should set the config but might fail
	// ruleid: rule-nil-pointer-dereference
	port := config.ServerPort // No check if config was loaded successfully
	fmt.Println("Server port:", port)
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_14() {
	items := getItems() // May return nil
	// ruleid: rule-nil-pointer-dereference
	for _, item := range items { // No nil check before ranging over items
		fmt.Println(item)
	}
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=1}
func bad_case_15() {
	var err error
	var ptr *string
	
	if someCondition() {
		ptr, err = getString()
	}
	
	if err != nil {
		fmt.Println("Error:", err)
		// Missing return statement
	}
	
	// ruleid: rule-nil-pointer-dereference
	fmt.Println(*ptr) // ptr might still be nil if someCondition() was false
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_1() {
	var ptr *string
	if ptr != nil {
		// ok: rule-nil-pointer-dereference
		fmt.Println(*ptr) // Safe: only dereference after nil check
	} else {
		fmt.Println("Pointer is nil")
	}
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_2() {
	var user *User
	if user != nil {
		// ok: rule-nil-pointer-dereference
		name := user.Name // Safe: only access field after nil check
		fmt.Println(name)
	} else {
		fmt.Println("User is nil")
	}
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_3() {
	file, err := os.Open("nonexistent.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return // Properly return on error
	}
	// ok: rule-nil-pointer-dereference
	data, _ := ioutil.ReadAll(file) // Safe: file is not nil here
	fmt.Println(string(data))
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_4() {
	db, err := sql.Open("mysql", "user:password@/dbname")
	if err != nil {
		fmt.Println("Failed to connect to database:", err)
		return // Properly return on error
	}
	// ok: rule-nil-pointer-dereference
	rows, _ := db.Query("SELECT * FROM users") // Safe: db is not nil here
	defer rows.Close()
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_5() {
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		data := fetchDataFromDB()
		if data != nil {
			// ok: rule-nil-pointer-dereference
			w.Write([]byte(data.Message)) // Safe: nil check before accessing data.Message
		} else {
			w.Write([]byte("No data available"))
		}
	})
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_6() {
	m := make(map[string]string) // Initialize map before use
	// ok: rule-nil-pointer-dereference
	m["key"] = "value" // Safe: map is initialized
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_7() {
	slice := make([]int, 1) // Initialize slice with length before use
	// ok: rule-nil-pointer-dereference
	slice[0] = 1 // Safe: slice is initialized
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_8() {
	mu := &sync.Mutex{} // Initialize mutex
	// ok: rule-nil-pointer-dereference
	mu.Lock() // Safe: mutex is initialized
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_9() {
	result, err := riskyOperation()
	if err != nil {
		fmt.Println("Operation failed:", err)
		return // Properly return on error
	}
	if result != nil {
		// ok: rule-nil-pointer-dereference
		fmt.Println(*result) // Safe: checked result is not nil
	} else {
		fmt.Println("Result is nil")
	}
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_10() {
	ch := make(chan int) // Initialize channel before use
	// ok: rule-nil-pointer-dereference
	ch <- 5 // Safe: channel is initialized
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_11() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("id")
		user := getUserByID(userID)
		if user != nil {
			// ok: rule-nil-pointer-dereference
			fmt.Fprintf(w, "Username: %s", user.Username) // Safe: nil check before access
		} else {
			fmt.Fprintf(w, "User not found")
		}
	})
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_12() {
	handler := http.NewServeMux() // Initialize ServeMux
	// ok: rule-nil-pointer-dereference
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	}) // Safe: handler is initialized
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_13() {
	var config *Config
	err := loadConfigSafely(&config) // Pass by reference to ensure config is set
	if err != nil || config == nil {
		fmt.Println("Failed to load config")
		return
	}
	// ok: rule-nil-pointer-dereference
	port := config.ServerPort // Safe: checked config is not nil
	fmt.Println("Server port:", port)
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_14() {
	items := getItems()
	if items != nil {
		// ok: rule-nil-pointer-dereference
		for _, item := range items { // Safe: nil check before ranging
			fmt.Println(item)
		}
	} else {
		fmt.Println("No items found")
	}
}
// {/fact}

// {fact rule=inconsistent-null-check@v1.0 defects=0}
func good_case_15() {
	var ptr *string
	
	if someCondition() {
		var err error
		ptr, err = getString()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
	}
	
	if ptr != nil {
		// ok: rule-nil-pointer-dereference
		fmt.Println(*ptr) // Safe: checked ptr is not nil
	} else {
		fmt.Println("Pointer is nil")
	}
}
// {/fact}

// Helper types and functions for the examples

type User struct {
	Name     string
	Username string
}

type ResponseData struct {
	Message string
}

type Config struct {
	ServerPort int
}

func fetchDataFromDB() *ResponseData {
	// Simulating a function that might return nil
	if someCondition() {
		return &ResponseData{Message: "Hello"}
	}
	return nil
}

func getUserByID(id string) *User {
	// Simulating a function that might return nil
	if id == "1" {
		return &User{Name: "John", Username: "john_doe"}
	}
	return nil
}

func riskyOperation() (*int, error) {
	// Simulating a function that might return nil and error
	if someCondition() {
		val := 42
		return &val, nil
	}
	return nil, errors.New("operation failed")
}

func getItems() []string {
	// Simulating a function that might return nil
	if someCondition() {
		return []string{"item1", "item2"}
	}
	return nil
}

func loadConfig() {
	// Simulating a function that might fail to set a global variable
}

func loadConfigSafely(config **Config) error {
	// Simulating a safer function that explicitly sets the config
	if someCondition() {
		*config = &Config{ServerPort: 8080}
		return nil
	}
	return errors.New("failed to load config")
}

func getString() (*string, error) {
	// Simulating a function that might return nil and error
	if someCondition() {
		s := "hello"
		return &s, nil
	}
	return nil, errors.New("failed to get string")
}

func someCondition() bool {
	// Simulating some condition that might be true or false
	return false
}

func main() {
	// Main function to avoid compilation errors
	fmt.Println("Nil pointer dereference examples")
}