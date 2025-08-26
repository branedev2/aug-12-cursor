package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"
)

// User represents a user in the system
type User struct {
	Username  string
	Password  string
	IsAdmin   bool
	Email     string
	FirstName string
	LastName  string
}

// UserActions contains methods that can be called on users
type UserActions struct {
	User User
}

func (ua *UserActions) ViewProfile() {
	fmt.Println("Viewing profile for:", ua.User.Username)
}

func (ua *UserActions) DeleteAccount() {
	fmt.Println("Deleting account for:", ua.User.Username)
}

func (ua *UserActions) MakeAdmin() {
	fmt.Println("Making user admin:", ua.User.Username)
	ua.User.IsAdmin = true
}

// Product represents a product in the system
type Product struct {
	Name        string
	Price       float64
	Description string
	InStock     bool
}

// VULNERABLE EXAMPLES

// bad_case_1 directly uses user input for reflection method calls
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "john", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
}
// {/fact}

// bad_case_2 uses POST data for reflection method calls
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	methodName := r.PostFormValue("method")
	ua := &UserActions{
		User: User{Username: "alice", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(methodName).Call([]reflect.Value{})
}
// {/fact}

// bad_case_3 uses header data for reflection field access
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	fieldName := r.Header.Get("X-Field-Access")
	
	user := User{
		Username: "bob",
		Password: "secret123",
		IsAdmin:  false,
		Email:    "bob@example.com",
	}
	
	val := reflect.ValueOf(user)
	// ruleid: rule-unsafe-reflection
	field := val.FieldByName(fieldName)
	fmt.Fprintf(w, "Field value: %v", field.Interface())
}
// {/fact}

// bad_case_4 uses JSON data for reflection method calls
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Action string `json:"action"`
	}
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	ua := &UserActions{
		User: User{Username: "charlie", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(data.Action).Call([]reflect.Value{})
}
// {/fact}

// bad_case_5 uses cookie data for reflection field access
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("field_access")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	fieldName := cookie.Value
	user := User{
		Username: "dave",
		Password: "password123",
		IsAdmin:  false,
	}
	
	// ruleid: rule-unsafe-reflection
	field := reflect.ValueOf(user).FieldByName(fieldName)
	fmt.Fprintf(w, "Field value: %v", field.Interface())
}
// {/fact}

// bad_case_6 uses URL path for reflection method calls
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	methodName := parts[2]
	ua := &UserActions{
		User: User{Username: "eve", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(methodName).Call([]reflect.Value{})
}
// {/fact}

// bad_case_7 uses minimal input validation but still vulnerable
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	// Simple check but not enough
	if action != "" {
		ua := &UserActions{
			User: User{Username: "frank", IsAdmin: false},
		}
		
		// ruleid: rule-unsafe-reflection
		reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
	}
}
// {/fact}

// bad_case_8 uses reflection to set field values from user input
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	fieldName := r.URL.Query().Get("field")
	fieldValue := r.URL.Query().Get("value")
	
	user := User{
		Username: "grace",
		IsAdmin:  false,
	}
	
	val := reflect.ValueOf(&user).Elem()
	// ruleid: rule-unsafe-reflection
	field := val.FieldByName(fieldName)
	if field.IsValid() && field.CanSet() {
		field.SetString(fieldValue)
	}
	
	fmt.Fprintf(w, "User: %+v", user)
}
// {/fact}

// bad_case_9 uses reflection with multiple user inputs
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	objType := r.URL.Query().Get("type")
	fieldName := r.URL.Query().Get("field")
	
	var obj interface{}
	if objType == "user" {
		obj = User{Username: "henry", IsAdmin: false}
	} else {
		obj = Product{Name: "Laptop", Price: 999.99}
	}
	
	val := reflect.ValueOf(obj)
	// ruleid: rule-unsafe-reflection
	field := val.FieldByName(fieldName)
	fmt.Fprintf(w, "Field value: %v", field.Interface())
}
// {/fact}

// bad_case_10 uses reflection with input from URL fragment
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	fragment := r.URL.Fragment
	
	ua := &UserActions{
		User: User{Username: "ian", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(fragment).Call([]reflect.Value{})
}
// {/fact}

// bad_case_11 uses reflection with input from query parameters with transformation
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	// Simple transformation doesn't make it safe
	methodName := strings.Title(action)
	
	ua := &UserActions{
		User: User{Username: "jack", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(methodName).Call([]reflect.Value{})
}
// {/fact}

// bad_case_12 uses reflection with input from a form field
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	fieldName := r.Form.Get("field_name")
	user := User{
		Username: "karen",
		Password: "securepass",
		IsAdmin:  false,
	}
	
	// ruleid: rule-unsafe-reflection
	field := reflect.ValueOf(user).FieldByName(fieldName)
	fmt.Fprintf(w, "Field value: %v", field.Interface())
}
// {/fact}

// bad_case_13 uses reflection with input from multiple sources
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	var methodName string
	
	// Try to get method name from different sources
	if name := r.URL.Query().Get("method"); name != "" {
		methodName = name
	} else if name := r.Header.Get("X-Method"); name != "" {
		methodName = name
	} else {
		methodName = "ViewProfile" // Default
	}
	
	ua := &UserActions{
		User: User{Username: "larry", IsAdmin: false},
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(methodName).Call([]reflect.Value{})
}
// {/fact}

// bad_case_14 uses reflection with input from a JSON body with some processing
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	var data struct {
		FieldAccess string `json:"field_access"`
	}
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Simple processing doesn't make it safe
	fieldName := strings.TrimSpace(data.FieldAccess)
	
	user := User{
		Username: "mike",
		Password: "mikepass123",
		IsAdmin:  false,
	}
	
	// ruleid: rule-unsafe-reflection
	field := reflect.ValueOf(user).FieldByName(fieldName)
	fmt.Fprintf(w, "Field value: %v", field.Interface())
}
// {/fact}

// bad_case_15 uses reflection with input from URL parameters with conditional logic
// {fact rule=unsafe-reflection@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	userID := r.URL.Query().Get("user_id")
	
	ua := &UserActions{
		User: User{Username: userID, IsAdmin: false},
	}
	
	if action == "" {
		action = "ViewProfile" // Default action
	}
	
	// ruleid: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
}
// {/fact}

// SAFE EXAMPLES

// good_case_1 uses a whitelist of allowed methods
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "john", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	allowedMethods := map[string]bool{
		"ViewProfile": true,
	}
	
	if allowedMethods[action] {
		reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
	} else {
		http.Error(w, "Unauthorized method", http.StatusForbidden)
	}
}
// {/fact}

// good_case_2 uses a switch statement instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "alice", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	switch action {
	case "ViewProfile":
		ua.ViewProfile()
	case "DeleteAccount":
		ua.DeleteAccount()
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}
// {/fact}

// good_case_3 uses a map of functions instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "bob", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	actions := map[string]func(){
		"ViewProfile":   ua.ViewProfile,
		"DeleteAccount": ua.DeleteAccount,
	}
	
	if fn, exists := actions[action]; exists {
		fn()
	} else {
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}
// {/fact}

// good_case_4 directly accesses fields instead of using reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	fieldName := r.URL.Query().Get("field")
	
	user := User{
		Username:  "charlie",
		Email:     "charlie@example.com",
		FirstName: "Charlie",
		LastName:  "Brown",
	}
	
	// ok: rule-unsafe-reflection
	var fieldValue string
	switch fieldName {
	case "Username":
		fieldValue = user.Username
	case "Email":
		fieldValue = user.Email
	case "FirstName":
		fieldValue = user.FirstName
	case "LastName":
		fieldValue = user.LastName
	default:
		fieldValue = "Field not accessible"
	}
	
	fmt.Fprintf(w, "Field value: %s", fieldValue)
}
// {/fact}

// good_case_5 uses a validation function to check method names
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "dave", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	if isValidMethod(action) {
		reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
	} else {
		http.Error(w, "Invalid method", http.StatusBadRequest)
	}
}
// {/fact}

// Helper function for good_case_5
func isValidMethod(name string) bool {
	validMethods := []string{"ViewProfile", "DeleteAccount"}
	for _, method := range validMethods {
		if method == name {
			return true
		}
	}
	return false
}

// good_case_6 uses a regex pattern to validate method names
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "eve", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	validPattern := regexp.MustCompile(`^(ViewProfile|DeleteAccount)$`)
	if validPattern.MatchString(action) {
		reflect.ValueOf(ua).MethodByName(action).Call([]reflect.Value{})
	} else {
		http.Error(w, "Invalid method", http.StatusBadRequest)
	}
}
// {/fact}

// good_case_7 uses constants instead of user input
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	const METHOD_VIEW_PROFILE = "ViewProfile"
	
	ua := &UserActions{
		User: User{Username: "frank", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	reflect.ValueOf(ua).MethodByName(METHOD_VIEW_PROFILE).Call([]reflect.Value{})
}
// {/fact}

// good_case_8 uses an enum-like approach for method selection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	actionParam := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "grace", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	var methodName string
	switch actionParam {
	case "view":
		methodName = "ViewProfile"
	case "delete":
		methodName = "DeleteAccount"
	default:
		methodName = "ViewProfile" // Default safe method
	}
	
	reflect.ValueOf(ua).MethodByName(methodName).Call([]reflect.Value{})
}
// {/fact}

// good_case_9 uses direct method calls based on user input
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "henry", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	if action == "view" {
		ua.ViewProfile()
	} else if action == "delete" {
		ua.DeleteAccount()
	} else {
		ua.ViewProfile() // Default action
	}
}
// {/fact}

// good_case_10 uses a factory pattern instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "ian", IsAdmin: false},
	}
	
	// ok: rule-unsafe-reflection
	executeAction := func(actionName string) {
		switch actionName {
		case "ViewProfile":
			ua.ViewProfile()
		case "DeleteAccount":
			ua.DeleteAccount()
		default:
			fmt.Fprintf(w, "Unknown action: %s", actionName)
		}
	}
	
	executeAction(action)
}
// {/fact}

// good_case_11 uses a command pattern instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "jack", IsAdmin: false},
	}
	
	// Command interface
	type Command interface {
		Execute()
	}
	
	// Concrete commands
	type ViewProfileCommand struct {
		userActions *UserActions
	}
	
	func (c *ViewProfileCommand) Execute() {
		c.userActions.ViewProfile()
	}
	
	type DeleteAccountCommand struct {
		userActions *UserActions
	}
	
	func (c *DeleteAccountCommand) Execute() {
		c.userActions.DeleteAccount()
	}
	
	// ok: rule-unsafe-reflection
	var cmd Command
	switch action {
	case "ViewProfile":
		cmd = &ViewProfileCommand{userActions: ua}
	case "DeleteAccount":
		cmd = &DeleteAccountCommand{userActions: ua}
	default:
		cmd = &ViewProfileCommand{userActions: ua}
	}
	
	cmd.Execute()
}
// {/fact}

// good_case_12 uses a strategy pattern instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "karen", IsAdmin: false},
	}
	
	// Strategy interface
	type ActionStrategy interface {
		PerformAction()
	}
	
	// Concrete strategies
	type ViewProfileStrategy struct {
		userActions *UserActions
	}
	
	func (s *ViewProfileStrategy) PerformAction() {
		s.userActions.ViewProfile()
	}
	
	type DeleteAccountStrategy struct {
		userActions *UserActions
	}
	
	func (s *DeleteAccountStrategy) PerformAction() {
		s.userActions.DeleteAccount()
	}
	
	// ok: rule-unsafe-reflection
	var strategy ActionStrategy
	switch action {
	case "ViewProfile":
		strategy = &ViewProfileStrategy{userActions: ua}
	case "DeleteAccount":
		strategy = &DeleteAccountStrategy{userActions: ua}
	default:
		strategy = &ViewProfileStrategy{userActions: ua}
	}
	
	strategy.PerformAction()
}
// {/fact}

// good_case_13 uses a struct field mapping approach instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	fieldName := r.URL.Query().Get("field")
	
	user := User{
		Username:  "larry",
		Email:     "larry@example.com",
		FirstName: "Larry",
		LastName:  "Smith",
	}
	
	// ok: rule-unsafe-reflection
	fieldGetters := map[string]func(User) string{
		"Username":  func(u User) string { return u.Username },
		"Email":     func(u User) string { return u.Email },
		"FirstName": func(u User) string { return u.FirstName },
		"LastName":  func(u User) string { return u.LastName },
	}
	
	if getter, exists := fieldGetters[fieldName]; exists {
		fmt.Fprintf(w, "Field value: %s", getter(user))
	} else {
		fmt.Fprintf(w, "Field not accessible")
	}
}
// {/fact}

// good_case_14 uses an interface-based approach instead of reflection
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "mike", IsAdmin: false},
	}
	
	// ActionExecutor interface
	type ActionExecutor interface {
		ExecuteViewProfile()
		ExecuteDeleteAccount()
	}
	
	// Adapter that implements ActionExecutor
	type UserActionsAdapter struct {
		ua *UserActions
	}
	
	func (a *UserActionsAdapter) ExecuteViewProfile() {
		a.ua.ViewProfile()
	}
	
	func (a *UserActionsAdapter) ExecuteDeleteAccount() {
		a.ua.DeleteAccount()
	}
	
	adapter := &UserActionsAdapter{ua: ua}
	
	// ok: rule-unsafe-reflection
	switch action {
	case "ViewProfile":
		adapter.ExecuteViewProfile()
	case "DeleteAccount":
		adapter.ExecuteDeleteAccount()
	default:
		adapter.ExecuteViewProfile()
	}
}
// {/fact}

// good_case_15 uses a declarative approach with a configuration map
// {fact rule=unsafe-reflection@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	
	ua := &UserActions{
		User: User{Username: "nancy", IsAdmin: false},
	}
	
	// Define allowed actions and their corresponding methods
	type ActionConfig struct {
		MethodName string
		IsAdmin    bool
	}
	
	// ok: rule-unsafe-reflection
	actionConfigs := map[string]ActionConfig{
		"view":   {MethodName: "ViewProfile", IsAdmin: false},
		"delete": {MethodName: "DeleteAccount", IsAdmin: false},
		"admin":  {MethodName: "MakeAdmin", IsAdmin: true},
	}
	
	if config, exists := actionConfigs[action]; exists {
		if config.IsAdmin && !ua.User.IsAdmin {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		reflect.ValueOf(ua).MethodByName(config.MethodName).Call([]reflect.Value{})
	} else {
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	http.HandleFunc("/bad3", bad_case_3)
	http.HandleFunc("/bad4", bad_case_4)
	http.HandleFunc("/bad5", bad_case_5)
	http.HandleFunc("/bad6", bad_case_6)
	http.HandleFunc("/bad7", bad_case_7)
	http.HandleFunc("/bad8", bad_case_8)
	http.HandleFunc("/bad9", bad_case_9)
	http.HandleFunc("/bad10", bad_case_10)
	http.HandleFunc("/bad11", bad_case_11)
	http.HandleFunc("/bad12", bad_case_12)
	http.HandleFunc("/bad13", bad_case_13)
	http.HandleFunc("/bad14", bad_case_14)
	http.HandleFunc("/bad15", bad_case_15)
	
	http.HandleFunc("/good1", good_case_1)
	http.HandleFunc("/good2", good_case_2)
	http.HandleFunc("/good3", good_case_3)
	http.HandleFunc("/good4", good_case_4)
	http.HandleFunc("/good5", good_case_5)
	http.HandleFunc("/good6", good_case_6)
	http.HandleFunc("/good7", good_case_7)
	http.HandleFunc("/good8", good_case_8)
	http.HandleFunc("/good9", good_case_9)
	http.HandleFunc("/good10", good_case_10)
	http.HandleFunc("/good11", good_case_11)
	http.HandleFunc("/good12", good_case_12)
	http.HandleFunc("/good13", good_case_13)
	http.HandleFunc("/good14", good_case_14)
	http.HandleFunc("/good15", good_case_15)
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}