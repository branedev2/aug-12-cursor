package main

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// BAD CASES - These should trigger the rule

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("url")
	
	// Use user input directly in HTTP request
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(userInput)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from POST form
	r.ParseForm()
	userInput := r.Form.Get("target_url")
	
	client := &http.Client{}
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequest("GET", userInput, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input from header
	userInput := r.Header.Get("X-Target-URL")
	
	// Construct URL with user input
	targetURL := "http://" + userInput + "/api/data"
	
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input from cookie
	cookie, err := r.Cookie("target_host")
	if err != nil {
		fmt.Fprintf(w, "Cookie not found")
		return
	}
	
	userInput := cookie.Value
	targetURL := fmt.Sprintf("https://%s/resource", userInput)
	
	client := &http.Client{}
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL path parameter
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		fmt.Fprintf(w, "Invalid path")
		return
	}
	
	userInput := pathParts[2]
	targetURL := "https://" + userInput + ".example.com/api"
	
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get user input from JSON body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(w, "Error reading body: %v", err)
		return
	}
	defer r.Body.Close()
	
	// Simple parsing for demonstration
	userInput := string(body)
	userInput = strings.TrimSpace(userInput)
	userInput = strings.Trim(userInput, "\"")
	
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequest("GET", userInput, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get multiple parameters and construct URL
	host := r.URL.Query().Get("host")
	path := r.URL.Query().Get("path")
	
	targetURL := fmt.Sprintf("http://%s/%s", host, path)
	
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get user input with some basic processing
	userInput := r.URL.Query().Get("endpoint")
	
	// Simple transformation doesn't make it safe
	processedInput := strings.ReplaceAll(userInput, " ", "-")
	targetURL := "https://" + processedInput + ".api.example.com"
	
	client := &http.Client{}
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequest("POST", targetURL, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("api_url")
	
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequestWithContext(ctx, "GET", userInput, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter with conditional logic
	userInput := r.URL.Query().Get("target")
	
	var targetURL string
	if strings.HasPrefix(userInput, "api-") {
		targetURL = "https://" + userInput + ".internal.example.com"
	} else {
		targetURL = "https://" + userInput + ".external.example.com"
	}
	
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("callback")
	
	// Using a map to determine the URL - still tainted
	endpoints := map[string]string{
		"users": "api.example.com/users",
		"products": "api.example.com/products",
		"default": "api.example.com",
	}
	
	baseURL, ok := endpoints[userInput]
	if !ok {
		baseURL = endpoints["default"]
	}
	
	targetURL := "https://" + baseURL + "/callback?source=" + userInput
	
	// ruleid: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter and use in a loop
	services := r.URL.Query()["service"]
	
	for _, service := range services {
		targetURL := "http://" + service + ".internal/healthcheck"
		
		// ruleid: rule-tainted-url-host
		resp, err := http.Get(targetURL)
		if err != nil {
			fmt.Fprintf(w, "Error checking %s: %v\n", service, err)
			continue
		}
		defer resp.Body.Close()
		
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(w, "Service %s status: %s\n", service, body)
	}
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter with some URL parsing
	userInput := r.URL.Query().Get("proxy_to")
	
	parsedURL, err := url.Parse(userInput)
	if err != nil {
		fmt.Fprintf(w, "Invalid URL: %v", err)
		return
	}
	
	// Still vulnerable as we're using the parsed URL directly
	client := &http.Client{}
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter with context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	userInput := r.URL.Query().Get("endpoint")
	
	// ruleid: rule-tainted-url-host
	req, err := http.NewRequestWithContext(ctx, "GET", userInput, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter and use with http.Client.Get
	userInput := r.URL.Query().Get("fetch")
	
	client := &http.Client{}
	// ruleid: rule-tainted-url-host
	resp, err := client.Get(userInput)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// GOOD CASES - These should not trigger the rule

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Use hardcoded URL - no user input
	// ok: rule-tainted-url-host
	resp, err := http.Get("https://api.example.com/data")
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input but only use as a path parameter in a hardcoded domain
	resource := r.URL.Query().Get("resource")
	
	// ok: rule-tainted-url-host
	resp, err := http.Get("https://api.example.com/" + resource)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Validate user input against an allowlist
	userInput := r.URL.Query().Get("environment")
	
	// Allowlist of permitted hosts
	allowedHosts := map[string]bool{
		"production": true,
		"staging": true,
		"development": true,
	}
	
	if !allowedHosts[userInput] {
		fmt.Fprintf(w, "Invalid environment")
		return
	}
	
	targetURL := fmt.Sprintf("https://%s.api.example.com/status", userInput)
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Use regex pattern to validate user input
	userInput := r.URL.Query().Get("subdomain")
	
	// Validate with regex - only alphanumeric characters
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !validPattern.MatchString(userInput) {
		fmt.Fprintf(w, "Invalid subdomain format")
		return
	}
	
	targetURL := fmt.Sprintf("https://%s.example.com/api", userInput)
	
	client := &http.Client{}
	// ok: rule-tainted-url-host
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Use a map to translate user input to safe URLs
	userInput := r.URL.Query().Get("service")
	
	// Map of allowed services to their URLs
	serviceURLs := map[string]string{
		"users": "https://users-api.example.com",
		"products": "https://products-api.example.com",
		"orders": "https://orders-api.example.com",
	}
	
	targetURL, ok := serviceURLs[userInput]
	if !ok {
		fmt.Fprintf(w, "Invalid service")
		return
	}
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Use environment variables for URLs
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "https://default-api.example.com" // Fallback
	}
	
	resource := r.URL.Query().Get("resource")
	targetURL := apiURL + "/api/" + resource
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Validate user input with a switch statement
	userInput := r.URL.Query().Get("region")
	
	var baseURL string
	switch userInput {
	case "us-east":
		baseURL = "https://api-east.example.com"
	case "us-west":
		baseURL = "https://api-west.example.com"
	case "eu":
		baseURL = "https://api-eu.example.com"
	default:
		fmt.Fprintf(w, "Invalid region")
		return
	}
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(baseURL + "/status")
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Use URL builder with fixed host
	baseURL, err := url.Parse("https://api.example.com")
	if err != nil {
		fmt.Fprintf(w, "Error parsing base URL: %v", err)
		return
	}
	
	// Get user input for path only
	path := r.URL.Query().Get("path")
	
	// Safely append path to fixed host
	baseURL.Path = path
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(baseURL.String())
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Use context with fixed URL
	ctx := r.Context()
	
	// ok: rule-tainted-url-host
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.example.com/data", nil)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	// Add query parameters from user input
	q := req.URL.Query()
	q.Add("filter", r.URL.Query().Get("filter"))
	req.URL.RawQuery = q.Encode()
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Use a configuration file for allowed hosts
	userInput := r.URL.Query().Get("endpoint")
	
	// Simulate reading from a config file
	allowedEndpoints := []string{"api1", "api2", "api3"}
	
	isAllowed := false
	for _, endpoint := range allowedEndpoints {
		if endpoint == userInput {
			isAllowed = true
			break
		}
	}
	
	if !isAllowed {
		fmt.Fprintf(w, "Endpoint not allowed")
		return
	}
	
	targetURL := fmt.Sprintf("https://%s.internal.example.com", userInput)
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Use numeric ID to select from predefined URLs
	idStr := r.URL.Query().Get("id")
	
	// Convert to int and validate
	id := 0
	_, err := fmt.Sscanf(idStr, "%d", &id)
	if err != nil || id < 1 || id > 3 {
		fmt.Fprintf(w, "Invalid ID")
		return
	}
	
	// Map of allowed IDs to URLs
	urls := map[int]string{
		1: "https://api1.example.com",
		2: "https://api2.example.com",
		3: "https://api3.example.com",
	}
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(urls[id])
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Use a builder pattern with validation
	baseURL := "https://api.example.com"
	
	// Get user input for path components
	resource := r.URL.Query().Get("resource")
	id := r.URL.Query().Get("id")
	
	// Validate resource type
	validResources := map[string]bool{"users": true, "products": true, "orders": true}
	if !validResources[resource] {
		fmt.Fprintf(w, "Invalid resource type")
		return
	}
	
	// Validate ID format (numeric only)
	idPattern := regexp.MustCompile(`^[0-9]+$`)
	if !idPattern.MatchString(id) {
		fmt.Fprintf(w, "Invalid ID format")
		return
	}
	
	targetURL := fmt.Sprintf("%s/%s/%s", baseURL, resource, id)
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(targetURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Use URL parsing to ensure fixed host
	userInput := r.URL.Query().Get("url")
	
	// Parse the URL
	parsedURL, err := url.Parse(userInput)
	if err != nil {
		fmt.Fprintf(w, "Invalid URL: %v", err)
		return
	}
	
	// Override the host with a fixed value
	parsedURL.Host = "api.example.com"
	parsedURL.Scheme = "https"
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(parsedURL.String())
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Use a service locator pattern
	serviceName := r.URL.Query().Get("service")
	
	// Service locator function
	getServiceURL := func(name string) (string, error) {
		services := map[string]string{
			"auth": "https://auth.example.com",
			"billing": "https://billing.example.com",
			"profile": "https://profile.example.com",
		}
		
		url, ok := services[name]
		if !ok {
			return "", fmt.Errorf("unknown service: %s", name)
		}
		return url, nil
	}
	
	serviceURL, err := getServiceURL(serviceName)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(serviceURL + "/api/status")
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Read URLs from a trusted configuration file
	// Simulating reading from a config file
	configReader := bufio.NewReader(strings.NewReader(`
		{
			"api": "https://api.example.com",
			"auth": "https://auth.example.com",
			"cdn": "https://cdn.example.com"
		}
	`))
	
	// Parse the config (simplified for example)
	config := make(map[string]string)
	config["api"] = "https://api.example.com"
	config["auth"] = "https://auth.example.com"
	config["cdn"] = "https://cdn.example.com"
	
	// Get service from user input
	service := r.URL.Query().Get("service")
	
	// Check if service exists in config
	serviceURL, ok := config[service]
	if !ok {
		fmt.Fprintf(w, "Invalid service")
		return
	}
	
	// ok: rule-tainted-url-host
	resp, err := http.Get(serviceURL)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Fprintf(w, "Response: %s", body)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Additional handlers would be registered here
	http.ListenAndServe(":8080", nil)
}