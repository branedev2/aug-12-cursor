package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Getting user input from URL parameter
	targetURL := r.URL.Query().Get("url")
	
	// Using user input directly in HTTP request
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Getting user input from POST form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	apiEndpoint := r.PostForm.Get("endpoint")
	client := &http.Client{}
	
	// ruleid: rule-ssrf-updatedMIT
	req, err := http.NewRequest("GET", apiEndpoint, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Getting user input from header
	targetHost := r.Header.Get("X-Forward-Host")
	
	// Constructing URL with user input
	targetURL := fmt.Sprintf("https://%s/api/data", targetHost)
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Getting user input from JSON body
	var requestData struct {
		ServiceURL string `json:"service_url"`
	}
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := client.Get(requestData.ServiceURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Getting user input from URL parameter and doing minimal processing
	targetURL := r.URL.Query().Get("proxy_to")
	targetURL = strings.TrimSpace(targetURL)
	
	// Still vulnerable despite trimming
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Getting user input from cookie
	cookie, err := r.Cookie("api_endpoint")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Using cookie value directly in HTTP request
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Post(cookie.Value, "application/json", strings.NewReader("{}"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Getting user input and appending to base URL
	path := r.URL.Query().Get("path")
	baseURL := "https://api.example.com"
	
	// Still vulnerable as path can contain "../" or protocol handlers
	fullURL := baseURL + path
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(fullURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Getting multiple parameters and constructing URL
	host := r.URL.Query().Get("host")
	port := r.URL.Query().Get("port")
	path := r.URL.Query().Get("path")
	
	// Constructing URL with multiple user inputs
	targetURL := fmt.Sprintf("http://%s:%s/%s", host, port, path)
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Getting user input and using in custom HTTP client
	targetURL := r.URL.Query().Get("target")
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// ruleid: rule-ssrf-updatedMIT
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	req.Header.Set("User-Agent", "CustomClient/1.0")
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Getting user input from URL parameter with protocol check
	targetURL := r.URL.Query().Get("url")
	
	// Checking for http/https but still vulnerable to other protocols or IP-based attacks
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Getting user input and using in URL parsing
	targetURL := r.URL.Query().Get("url")
	
	// Parsing URL but not validating host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(parsedURL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Getting user input from path parameter
	pathParts := strings.Split(r.URL.Path, "/")
	if len(pathParts) < 3 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Using path parameter in URL
	targetService := pathParts[2]
	targetURL := fmt.Sprintf("http://%s.internal.example.com/api", targetService)
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Getting user input and using in a PUT request
	targetURL := r.URL.Query().Get("webhook")
	payload := `{"status": "completed"}`
	
	// ruleid: rule-ssrf-updatedMIT
	req, err := http.NewRequest("PUT", targetURL, strings.NewReader(payload))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Getting user input and using in a custom transport
	targetURL := r.URL.Query().Get("url")
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := client.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Getting user input and using in context
	targetURL := r.URL.Query().Get("url")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	client := &http.Client{}
	
	// ruleid: rule-ssrf-updatedMIT
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using a whitelist of allowed URLs
	targetKey := r.URL.Query().Get("key")
	
	// Map of allowed URLs
	allowedURLs := map[string]string{
		"users":   "https://api.example.com/users",
		"orders":  "https://api.example.com/orders",
		"products": "https://api.example.com/products",
	}
	
	// Check if the key exists in the whitelist
	targetURL, exists := allowedURLs[targetKey]
	if !exists {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Using a safe transport that blocks dangerous IPs
	targetURL := r.URL.Query().Get("url")
	
	// Parse the URL to validate the host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	
	// Only allow specific domains
	if parsedURL.Hostname() != "api.example.com" && parsedURL.Hostname() != "cdn.example.com" {
		http.Error(w, "Unauthorized domain", http.StatusForbidden)
		return
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Using the SafeTransport from the rule example
	targetURL := r.URL.Query().Get("url")
	
	// Validate URL format
	_, err := url.ParseRequestURI(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}
	
	const clientConnectTimeout = time.Second * 10
	httpClient := &http.Client{
		Transport: SafeTransport(clientConnectTimeout),
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Using a server-side map for URLs
	keyParam := r.URL.Query().Get("key")
	
	// Convert to integer for additional safety
	var key int
	_, err := fmt.Sscanf(keyParam, "%d", &key)
	if err != nil {
		http.Error(w, "Invalid key format", http.StatusBadRequest)
		return
	}
	
	// Server-side map of URLs
	urlMap := map[int]string{
		1: "https://api.example.com/users",
		2: "https://api.example.com/products",
		3: "https://api.example.com/orders",
	}
	
	targetURL, exists := urlMap[key]
	if !exists {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Using a fixed base URL with validated path
	path := r.URL.Query().Get("path")
	
	// Validate path format (alphanumeric and slashes only)
	if !isValidPath(path) {
		http.Error(w, "Invalid path format", http.StatusBadRequest)
		return
	}
	
	// Construct URL with fixed base
	baseURL := "https://api.example.com"
	targetURL := fmt.Sprintf("%s/%s", baseURL, path)
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Using environment variables for URLs
	serviceKey := r.URL.Query().Get("service")
	
	// Get URL from environment variables
	envKey := fmt.Sprintf("%s_SERVICE_URL", strings.ToUpper(serviceKey))
	targetURL := os.Getenv(envKey)
	
	// Check if URL exists in environment
	if targetURL == "" {
		http.Error(w, "Service not configured", http.StatusNotFound)
		return
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Using a custom HTTP client with IP validation
	targetURL := r.URL.Query().Get("url")
	
	// Parse URL to extract host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
	
	// Resolve hostname to IP
	ips, err := net.LookupIP(parsedURL.Hostname())
	if err != nil || len(ips) == 0 {
		http.Error(w, "Could not resolve hostname", http.StatusBadRequest)
		return
	}
	
	// Check if any IP is disallowed
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
			http.Error(w, "Disallowed IP address", http.StatusForbidden)
			return
		}
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Using a fixed URL with parameterized query
	userID := r.URL.Query().Get("user_id")
	
	// Validate userID format
	if !isValidUserID(userID) {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}
	
	// Construct URL with fixed base and query parameter
	targetURL := fmt.Sprintf("https://api.example.com/users?id=%s", url.QueryEscape(userID))
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using a URL builder with validation
	host := "api.example.com" // Fixed host
	path := r.URL.Query().Get("path")
	
	// Validate path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	
	if strings.Contains(path, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Build URL with fixed scheme and host
	targetURL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path,
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Using a proxy service pattern
	resourceType := r.URL.Query().Get("type")
	resourceID := r.URL.Query().Get("id")
	
	// Validate resource type
	allowedTypes := map[string]bool{
		"users":    true,
		"products": true,
		"orders":   true,
	}
	
	if !allowedTypes[resourceType] {
		http.Error(w, "Invalid resource type", http.StatusBadRequest)
		return
	}
	
	// Validate resource ID format
	if !isValidResourceID(resourceID) {
		http.Error(w, "Invalid resource ID", http.StatusBadRequest)
		return
	}
	
	// Construct URL with validated components
	targetURL := fmt.Sprintf("https://api.example.com/%s/%s", resourceType, resourceID)
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Using a configuration-based approach
	serviceName := r.URL.Query().Get("service")
	
	// Load configuration from a secure source
	config := loadServiceConfig()
	
	// Check if service exists in configuration
	serviceConfig, exists := config.Services[serviceName]
	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	
	// Use pre-configured URL
	targetURL := serviceConfig.URL
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using a domain whitelist with path validation
	domain := r.URL.Query().Get("domain")
	path := r.URL.Query().Get("path")
	
	// Whitelist of allowed domains
	allowedDomains := map[string]bool{
		"api.example.com":  true,
		"cdn.example.com":  true,
		"auth.example.com": true,
	}
	
	if !allowedDomains[domain] {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		return
	}
	
	// Validate path
	if !isValidPath(path) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Construct URL with validated components
	targetURL := fmt.Sprintf("https://%s/%s", domain, path)
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Using URL signing for trusted URLs
	signedURL := r.URL.Query().Get("signed_url")
	
	// Verify signature and extract actual URL
	targetURL, valid := verifyAndExtractURL(signedURL)
	if !valid {
		http.Error(w, "Invalid or expired URL signature", http.StatusForbidden)
		return
	}
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using a service discovery pattern
	serviceID := r.URL.Query().Get("service_id")
	
	// Get service details from service registry
	serviceDetails, err := getServiceFromRegistry(serviceID)
	if err != nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	
	// Use pre-registered service URL
	targetURL := serviceDetails.URL
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using a fixed set of endpoints with parameterized paths
	endpoint := r.URL.Query().Get("endpoint")
	resourceID := r.URL.Query().Get("id")
	
	// Map of allowed endpoints
	endpoints := map[string]string{
		"users":    "https://api.example.com/users/",
		"products": "https://api.example.com/products/",
		"orders":   "https://api.example.com/orders/",
	}
	
	baseURL, exists := endpoints[endpoint]
	if !exists {
		http.Error(w, "Invalid endpoint", http.StatusBadRequest)
		return
	}
	
	// Validate resource ID
	if !isValidResourceID(resourceID) {
		http.Error(w, "Invalid resource ID", http.StatusBadRequest)
		return
	}
	
	// Construct URL with validated components
	targetURL := baseURL + url.PathEscape(resourceID)
	
	// ok: rule-ssrf-updatedMIT
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	io.Copy(w, resp.Body)
}
// {/fact}

// Helper functions

// IsDisallowedIP parses the ip to determine if we should allow the HTTP client to continue
func IsDisallowedIP(hostIP string) bool {
	ip := net.ParseIP(hostIP)
	return ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate()
}

// SafeTransport uses the net.Dial to connect, then if successful check if the resolved
// ip address is disallowed.
func SafeTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.DialTimeout(network, addr, timeout)
			if err != nil {
				return nil, err
			}
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if IsDisallowedIP(ip) {
				return nil, errors.New("ip address is not allowed")
			}
			return c, err
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			c, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{})
			if err != nil {
				return nil, err
			}

			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if IsDisallowedIP(ip) {
				return nil, errors.New("ip address is not allowed")
			}

			err = c.Handshake()
			if err != nil {
				return c, err
			}

			return c, c.Handshake()
		},
		TLSHandshakeTimeout: timeout,
	}
}

func isValidPath(path string) bool {
	// Simple validation - no ".." and only alphanumeric plus some special chars
	return !strings.Contains(path, "..") && !strings.Contains(path, "//")
}

func isValidUserID(id string) bool {
	// Simple validation - only alphanumeric
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return len(id) > 0 && len(id) < 64
}

func isValidResourceID(id string) bool {
	// Simple validation - only alphanumeric and hyphens
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
			return false
		}
	}
	return len(id) > 0 && len(id) < 64
}

func verifyAndExtractURL(signedURL string) (string, bool) {
	// In a real implementation, this would verify a signature
	// For this example, we'll just check a prefix and return a hardcoded URL
	if strings.HasPrefix(signedURL, "SIGNED:") {
		return "https://api.example.com/data", true
	}
	return "", false
}

type ServiceConfig struct {
	URL string
}

type Config struct {
	Services map[string]ServiceConfig
}

func loadServiceConfig() Config {
	// In a real implementation, this would load from a secure source
	return Config{
		Services: map[string]ServiceConfig{
			"users":    {URL: "https://api.example.com/users"},
			"products": {URL: "https://api.example.com/products"},
		},
	}
}

type ServiceDetails struct {
	URL string
}

func getServiceFromRegistry(serviceID string) (ServiceDetails, error) {
	// In a real implementation, this would query a service registry
	services := map[string]ServiceDetails{
		"user-service":    {URL: "https://users.example.com/api"},
		"product-service": {URL: "https://products.example.com/api"},
	}
	
	service, exists := services[serviceID]
	if !exists {
		return ServiceDetails{}, errors.New("service not found")
	}
	
	return service, nil
}

func main() {
	// Main function to start the server
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Add other handlers...
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}