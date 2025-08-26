package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// TRUE POSITIVES - These should be detected by the rule

// bad_case_1 demonstrates a simple case of redundant if condition
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	x := 10
	
	// ruleid: rule-useless-if-conditional
	if x > 5 {
		if x > 5 {
			fmt.Println("x is greater than 5")
		}
	}
}
// {/fact}

// bad_case_2 demonstrates redundant condition with a variable
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	userAge := 25
	
	// ruleid: rule-useless-if-conditional
	if userAge >= 18 {
		fmt.Println("Checking age verification...")
		if userAge >= 18 {
			fmt.Println("User is an adult")
		}
	}
}
// {/fact}

// bad_case_3 demonstrates redundant condition in a function call context
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	value := "test"
	
	// ruleid: rule-useless-if-conditional
	if len(value) > 0 {
		fmt.Println("Value has content")
		if len(value) > 0 {
			fmt.Println("Processing value:", value)
		}
	}
}
// {/fact}

// bad_case_4 demonstrates redundant condition with HTTP request parameter
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	// ruleid: rule-useless-if-conditional
	if query != "" {
		fmt.Println("Query provided")
		if query != "" {
			fmt.Fprintf(w, "You searched for: %s", query)
		}
	}
}
// {/fact}

// bad_case_5 demonstrates redundant condition with boolean variable
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	isEnabled := true
	
	// ruleid: rule-useless-if-conditional
	if isEnabled {
		fmt.Println("Feature is enabled")
		if isEnabled {
			fmt.Println("Activating feature")
		}
	}
}
// {/fact}

// bad_case_6 demonstrates redundant condition with function call
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	filename := "data.txt"
	
	// ruleid: rule-useless-if-conditional
	if fileExists(filename) {
		fmt.Println("File found")
		if fileExists(filename) {
			fmt.Println("Reading file content")
		}
	}
}
// {/fact}

// bad_case_7 demonstrates redundant condition with complex expression
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	a, b := 5, 10
	
	// ruleid: rule-useless-if-conditional
	if a < b && a > 0 {
		fmt.Println("Condition met")
		if a < b && a > 0 {
			fmt.Println("Processing with values:", a, b)
		}
	}
}
// {/fact}

// bad_case_8 demonstrates redundant condition with string comparison
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	status := "active"
	
	// ruleid: rule-useless-if-conditional
	if status == "active" {
		fmt.Println("Status is active")
		if status == "active" {
			fmt.Println("Performing active status operations")
		}
	}
}
// {/fact}

// bad_case_9 demonstrates redundant condition with multiple statements
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	count := 42
	
	// ruleid: rule-useless-if-conditional
	if count > 10 {
		fmt.Println("Count is significant")
		fmt.Println("Performing initial checks")
		if count > 10 {
			fmt.Println("Processing high count value")
		}
	}
}
// {/fact}

// bad_case_10 demonstrates redundant condition with method call
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	text := "Hello World"
	
	// ruleid: rule-useless-if-conditional
	if strings.Contains(text, "Hello") {
		fmt.Println("Text contains greeting")
		if strings.Contains(text, "Hello") {
			fmt.Println("Processing greeting message")
		}
	}
}
// {/fact}

// bad_case_11 demonstrates redundant condition with negation
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	isEmpty := false
	
	// ruleid: rule-useless-if-conditional
	if !isEmpty {
		fmt.Println("Container has content")
		if !isEmpty {
			fmt.Println("Processing container content")
		}
	}
}
// {/fact}

// bad_case_12 demonstrates redundant condition with type conversion
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	value := "42"
	
	// ruleid: rule-useless-if-conditional
	if _, err := strconv.Atoi(value); err == nil {
		fmt.Println("Value is a valid integer")
		if _, err := strconv.Atoi(value); err == nil {
			fmt.Println("Converting and processing integer value")
		}
	}
}
// {/fact}

// bad_case_13 demonstrates redundant condition with environment variable
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	debugMode := os.Getenv("DEBUG_MODE") == "true"
	
	// ruleid: rule-useless-if-conditional
	if debugMode {
		fmt.Println("Debug mode is active")
		if debugMode {
			fmt.Println("Enabling verbose logging")
		}
	}
}
// {/fact}

// bad_case_14 demonstrates redundant condition with multiple variables
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	x, y := 10, 20
	
	// ruleid: rule-useless-if-conditional
	if x < y {
		fmt.Println("x is less than y")
		if x < y {
			fmt.Println("Processing with x and y")
		}
	}
}
// {/fact}

// bad_case_15 demonstrates redundant condition with HTTP method check
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-useless-if-conditional
	if r.Method == http.MethodPost {
		fmt.Println("POST request received")
		if r.Method == http.MethodPost {
			fmt.Println("Processing POST data")
		}
	}
}
// {/fact}

// Helper function for examples
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// TRUE NEGATIVES - These should NOT be detected by the rule

// good_case_1 demonstrates different conditions in nested if
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	x := 10
	
	// ok: rule-useless-if-conditional
	if x > 5 {
		if x > 8 {
			fmt.Println("x is greater than 8")
		}
	}
}
// {/fact}

// good_case_2 demonstrates different variables in nested if
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	userAge := 25
	userConsent := true
	
	// ok: rule-useless-if-conditional
	if userAge >= 18 {
		if userConsent {
			fmt.Println("User is an adult and has given consent")
		}
	}
}
// {/fact}

// good_case_3 demonstrates if-else structure without redundancy
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	value := "test"
	
	// ok: rule-useless-if-conditional
	if len(value) > 0 {
		fmt.Println("Value has content")
	} else {
		fmt.Println("Value is empty")
	}
}
// {/fact}

// good_case_4 demonstrates proper nested conditions with HTTP request
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	filter := r.URL.Query().Get("filter")
	
	// ok: rule-useless-if-conditional
	if query != "" {
		if filter != "" {
			fmt.Fprintf(w, "Searching for %s with filter %s", query, filter)
		} else {
			fmt.Fprintf(w, "Searching for %s without filters", query)
		}
	}
}
// {/fact}

// good_case_5 demonstrates proper use of boolean variables
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	isEnabled := true
	isConfigured := true
	
	// ok: rule-useless-if-conditional
	if isEnabled {
		if isConfigured {
			fmt.Println("Feature is enabled and configured")
		} else {
			fmt.Println("Feature is enabled but not configured")
		}
	}
}
// {/fact}

// good_case_6 demonstrates proper use of function calls
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	filename := "data.txt"
	
	// ok: rule-useless-if-conditional
	if fileExists(filename) {
		content, err := os.ReadFile(filename)
		if err == nil {
			fmt.Println("File content:", string(content))
		}
	}
}
// {/fact}

// good_case_7 demonstrates proper nested conditions with different expressions
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	a, b := 5, 10
	
	// ok: rule-useless-if-conditional
	if a < b {
		if a > 0 {
			fmt.Println("a is positive and less than b")
		}
	}
}
// {/fact}

// good_case_8 demonstrates proper use of string comparison
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	status := "active"
	userRole := "admin"
	
	// ok: rule-useless-if-conditional
	if status == "active" {
		if userRole == "admin" {
			fmt.Println("Active admin user")
		} else {
			fmt.Println("Active regular user")
		}
	}
}
// {/fact}

// good_case_9 demonstrates proper sequential conditions
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	count := 42
	
	// ok: rule-useless-if-conditional
	if count > 10 {
		fmt.Println("Count is significant")
	}
	
	if count > 40 {
		fmt.Println("Count is very high")
	}
}
// {/fact}

// good_case_10 demonstrates proper use of method calls
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	text := "Hello World"
	
	// ok: rule-useless-if-conditional
	if strings.Contains(text, "Hello") {
		if strings.Contains(text, "World") {
			fmt.Println("Text contains both Hello and World")
		}
	}
}
// {/fact}

// good_case_11 demonstrates proper use of negation
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	isEmpty := false
	isRequired := true
	
	// ok: rule-useless-if-conditional
	if !isEmpty {
		if isRequired {
			fmt.Println("Content is required and present")
		}
	}
}
// {/fact}

// good_case_12 demonstrates proper error handling
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	value := "42"
	
	// ok: rule-useless-if-conditional
	if num, err := strconv.Atoi(value); err == nil {
		if num > 0 {
			fmt.Println("Positive integer:", num)
		}
	}
}
// {/fact}

// good_case_13 demonstrates proper use of environment variables
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	debugMode := os.Getenv("DEBUG_MODE") == "true"
	verboseMode := os.Getenv("VERBOSE") == "true"
	
	// ok: rule-useless-if-conditional
	if debugMode {
		if verboseMode {
			fmt.Println("Debug mode with verbose logging")
		} else {
			fmt.Println("Debug mode with standard logging")
		}
	}
}
// {/fact}

// good_case_14 demonstrates proper use of multiple variables
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	x, y, z := 10, 20, 15
	
	// ok: rule-useless-if-conditional
	if x < y {
		if z > x {
			fmt.Println("z is between x and y")
		}
	}
}
// {/fact}

// good_case_15 demonstrates proper HTTP method handling
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// ok: rule-useless-if-conditional
	if r.Method == http.MethodPost {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			fmt.Println("Processing JSON POST request")
		} else {
			fmt.Println("Processing non-JSON POST request")
		}
	}
}
// {/fact}

func main() {
	// Main function to prevent compiler errors
	fmt.Println("Test cases for useless if conditional rule")
}