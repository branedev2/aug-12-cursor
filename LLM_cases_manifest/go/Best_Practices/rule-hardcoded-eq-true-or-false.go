package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// TRUE POSITIVES (Vulnerable/Bad Cases)

// bad_case_1 demonstrates an if statement with a hardcoded true condition
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	username := "admin"
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if true {
		fmt.Println("This block will always execute")
	}
	
	fmt.Println("Processing for user:", username)
}
// {/fact}

// bad_case_2 demonstrates an if statement with a hardcoded false condition
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	data := fetchUserData()
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if false {
		processData(data)
	}
}
// {/fact}

// bad_case_3 demonstrates comparing a boolean variable to true
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	isAdmin := checkUserPermissions()
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if isAdmin == true {
		grantAdminAccess()
	}
}
// {/fact}

// bad_case_4 demonstrates comparing a boolean variable to false
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	isValid := validateInput("user input")
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if isValid == false {
		showError("Invalid input")
	}
}
// {/fact}

// bad_case_5 demonstrates comparing a function result to true
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-hardcoded-eq-true-or-false
	if hasPermission("read") == true {
		readFile("secret.txt")
	}
}
// {/fact}

// bad_case_6 demonstrates comparing a function result to false
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	// ruleid: rule-hardcoded-eq-true-or-false
	if isUserBlocked("john") == false {
		allowAccess("john")
	}
}
// {/fact}

// bad_case_7 demonstrates comparing a complex expression to true
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	a, b := 5, 10
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if (a < b && a > 0) == true {
		fmt.Println("a is between 0 and b")
	}
}
// {/fact}

// bad_case_8 demonstrates comparing a complex expression to false
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	username := "admin"
	password := "password123"
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if (username == "admin" && password == "admin123") == false {
		fmt.Println("Invalid credentials")
	}
}
// {/fact}

// bad_case_9 demonstrates comparing a boolean variable to true in an else-if
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	status := getServerStatus()
	
	if status == "down" {
		restartServer()
	// ruleid: rule-hardcoded-eq-true-or-false
	} else if isMaintenanceMode() == true {
		skipHealthCheck()
	}
}
// {/fact}

// bad_case_10 demonstrates comparing a boolean map value to false
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	features := map[string]bool{
		"darkMode": true,
		"betaFeatures": false,
	}
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if features["betaFeatures"] == false {
		showStableUI()
	}
}
// {/fact}

// bad_case_11 demonstrates comparing a boolean channel value to true
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	done := make(chan bool)
	
	go func() {
		processData()
		done <- true
	}()
	
	result := <-done
	// ruleid: rule-hardcoded-eq-true-or-false
	if result == true {
		fmt.Println("Processing completed successfully")
	}
}
// {/fact}

// bad_case_12 demonstrates comparing a struct field to false
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	type User struct {
		IsActive bool
	}
	
	user := User{IsActive: true}
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if user.IsActive == false {
		deactivateAccount()
	}
}
// {/fact}

// bad_case_13 demonstrates comparing a boolean pointer to true
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	enabled := new(bool)
	*enabled = true
	
	// ruleid: rule-hardcoded-eq-true-or-false
	if *enabled == true {
		enableFeature()
	}
}
// {/fact}

// bad_case_14 demonstrates comparing a boolean in a switch case
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	isLoggedIn := checkLoginStatus()
	
	switch {
	// ruleid: rule-hardcoded-eq-true-or-false
	case isLoggedIn == true:
		showDashboard()
	default:
		redirectToLogin()
	}
}
// {/fact}

// bad_case_15 demonstrates comparing a boolean in a ternary-like if statement
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	isAdmin := checkAdminStatus()
	
	message := ""
	// ruleid: rule-hardcoded-eq-true-or-false
	if isAdmin == true {
		message = "Welcome, admin!"
	} else {
		message = "Welcome, user!"
	}
	
	fmt.Println(message)
}
// {/fact}

// TRUE NEGATIVES (Safe/Good Cases)

// good_case_1 demonstrates using a boolean variable directly in an if statement
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	isAdmin := checkUserPermissions()
	
	// ok: rule-hardcoded-eq-true-or-false
	if isAdmin {
		grantAdminAccess()
	}
}
// {/fact}

// good_case_2 demonstrates using the negation of a boolean variable
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	isValid := validateInput("user input")
	
	// ok: rule-hardcoded-eq-true-or-false
	if !isValid {
		showError("Invalid input")
	}
}
// {/fact}

// good_case_3 demonstrates using a function result directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	// ok: rule-hardcoded-eq-true-or-false
	if hasPermission("read") {
		readFile("secret.txt")
	}
}
// {/fact}

// good_case_4 demonstrates using the negation of a function result
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	// ok: rule-hardcoded-eq-true-or-false
	if !isUserBlocked("john") {
		allowAccess("john")
	}
}
// {/fact}

// good_case_5 demonstrates using a complex expression directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	a, b := 5, 10
	
	// ok: rule-hardcoded-eq-true-or-false
	if a < b && a > 0 {
		fmt.Println("a is between 0 and b")
	}
}
// {/fact}

// good_case_6 demonstrates using the negation of a complex expression
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	username := "admin"
	password := "password123"
	
	// ok: rule-hardcoded-eq-true-or-false
	if !(username == "admin" && password == "admin123") {
		fmt.Println("Invalid credentials")
	}
}
// {/fact}

// good_case_7 demonstrates using a boolean variable in an else-if
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	status := getServerStatus()
	
	if status == "down" {
		restartServer()
	// ok: rule-hardcoded-eq-true-or-false
	} else if isMaintenanceMode() {
		skipHealthCheck()
	}
}
// {/fact}

// good_case_8 demonstrates using a boolean map value directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	features := map[string]bool{
		"darkMode": true,
		"betaFeatures": false,
	}
	
	// ok: rule-hardcoded-eq-true-or-false
	if !features["betaFeatures"] {
		showStableUI()
	}
}
// {/fact}

// good_case_9 demonstrates using a boolean channel value directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	done := make(chan bool)
	
	go func() {
		processData()
		done <- true
	}()
	
	result := <-done
	// ok: rule-hardcoded-eq-true-or-false
	if result {
		fmt.Println("Processing completed successfully")
	}
}
// {/fact}

// good_case_10 demonstrates using a struct field directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	type User struct {
		IsActive bool
	}
	
	user := User{IsActive: true}
	
	// ok: rule-hardcoded-eq-true-or-false
	if !user.IsActive {
		deactivateAccount()
	}
}
// {/fact}

// good_case_11 demonstrates using a boolean pointer directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	enabled := new(bool)
	*enabled = true
	
	// ok: rule-hardcoded-eq-true-or-false
	if *enabled {
		enableFeature()
	}
}
// {/fact}

// good_case_12 demonstrates comparing non-boolean values
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	age := 25
	
	// ok: rule-hardcoded-eq-true-or-false
	if age == 18 {
		fmt.Println("You just became an adult")
	}
}
// {/fact}

// good_case_13 demonstrates using a boolean in a switch statement directly
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	isLoggedIn := checkLoginStatus()
	
	switch {
	// ok: rule-hardcoded-eq-true-or-false
	case isLoggedIn:
		showDashboard()
	default:
		redirectToLogin()
	}
}
// {/fact}

// good_case_14 demonstrates using a boolean in a ternary-like if statement
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	isAdmin := checkAdminStatus()
	
	message := ""
	// ok: rule-hardcoded-eq-true-or-false
	if isAdmin {
		message = "Welcome, admin!"
	} else {
		message = "Welcome, user!"
	}
	
	fmt.Println(message)
}
// {/fact}

// good_case_15 demonstrates comparing a boolean to another boolean variable
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	userWantsNotifications := true
	settingEnabled := getUserSetting("notifications")
	
	// ok: rule-hardcoded-eq-true-or-false
	if settingEnabled == userWantsNotifications {
		fmt.Println("Notification preferences match user's desires")
	}
}
// {/fact}

// Helper functions to make the examples compile
func checkUserPermissions() bool {
	return true
}

func grantAdminAccess() {
	// Implementation
}

func validateInput(input string) bool {
	return len(input) > 0
}

func showError(message string) {
	// Implementation
}

func hasPermission(permission string) bool {
	return true
}

func readFile(filename string) {
	// Implementation
}

func isUserBlocked(username string) bool {
	return false
}

func allowAccess(username string) {
	// Implementation
}

func fetchUserData() []byte {
	return []byte("data")
}

func processData(data []byte) {
	// Implementation
}

func getServerStatus() string {
	return "up"
}

func restartServer() {
	// Implementation
}

func isMaintenanceMode() bool {
	return false
}

func skipHealthCheck() {
	// Implementation
}

func showStableUI() {
	// Implementation
}

func processData() {
	// Implementation
}

func deactivateAccount() {
	// Implementation
}

func enableFeature() {
	// Implementation
}

func checkLoginStatus() bool {
	return true
}

func showDashboard() {
	// Implementation
}

func redirectToLogin() {
	// Implementation
}

func checkAdminStatus() bool {
	return true
}

func getUserSetting(setting string) bool {
	return true
}

func main() {
	// Main function to prevent compiler errors
}