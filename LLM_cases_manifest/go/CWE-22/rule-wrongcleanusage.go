package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Getting user input from URL parameter
	userPath := r.URL.Query().Get("path")
	
	// Using path.Clean for sanitization which is vulnerable
	// ruleid: rule-wrongcleanusage
	cleanPath := path.Clean(userPath)
	
	// Using the cleaned path to access files
	data, err := ioutil.ReadFile(cleanPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Getting user input from form data
	r.ParseForm()
	userPath := r.Form.Get("filepath")
	
	// Using filepath.Clean which is not safe against path traversal
	// ruleid: rule-wrongcleanusage
	cleanPath := filepath.Clean(userPath)
	
	// Opening file with cleaned path
	file, err := os.Open(cleanPath)
	if err != nil {
		http.Error(w, "Cannot open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Getting path from header
	userPath := r.Header.Get("X-File-Path")
	
	// Using Clean in a variable assignment
	// ruleid: rule-wrongcleanusage
	sanitizedPath := path.Clean(userPath)
	
	// Using the path to create a file
	file, err := os.Create(sanitizedPath)
	if err != nil {
		http.Error(w, "Cannot create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	file.WriteString("New content")
	fmt.Fprintf(w, "File created at %s", sanitizedPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Getting path from cookie
	cookie, err := r.Cookie("filePath")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	userPath := cookie.Value
	
	// Using Clean directly in a function call
	// ruleid: rule-wrongcleanusage
	fileInfo, err := os.Stat(filepath.Clean(userPath))
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "File size: %d bytes", fileInfo.Size())
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL path
	userPath := r.URL.Path[1:] // Remove leading slash
	
	baseDir := "/var/www/files"
	// Using Clean to join paths
	// ruleid: rule-wrongcleanusage
	fullPath := filepath.Clean(filepath.Join(baseDir, userPath))
	
	// Reading directory contents
	files, err := ioutil.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}
	
	for _, file := range files {
		fmt.Fprintf(w, "%s\n", file.Name())
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Getting multiple paths from query parameters
	paths := r.URL.Query()["paths"]
	
	for _, userPath := range paths {
		// Using Clean in a loop
		// ruleid: rule-wrongcleanusage
		cleanPath := path.Clean(userPath)
		
		// Checking if file exists
		if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
			fmt.Fprintf(w, "File %s does not exist\n", cleanPath)
		} else {
			fmt.Fprintf(w, "File %s exists\n", cleanPath)
		}
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Getting path from JSON request body
	var requestData struct {
		FilePath string `json:"filePath"`
	}
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Using Clean with string concatenation
	// ruleid: rule-wrongcleanusage
	cleanPath := filepath.Clean("./uploads/" + requestData.FilePath)
	
	// Removing file
	err := os.Remove(cleanPath)
	if err != nil {
		http.Error(w, "Cannot remove file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "File %s removed successfully", cleanPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Getting path with conditional logic
	var userPath string
	if r.Method == "POST" {
		r.ParseForm()
		userPath = r.Form.Get("path")
	} else {
		userPath = r.URL.Query().Get("path")
	}
	
	// Using Clean with a conditional
	if len(userPath) > 0 {
		// ruleid: rule-wrongcleanusage
		cleanPath := path.Clean(userPath)
		
		// Creating directory
		err := os.MkdirAll(cleanPath, 0755)
		if err != nil {
			http.Error(w, "Cannot create directory", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Directory %s created", cleanPath)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Getting path from a custom header with default value
	userPath := r.Header.Get("X-Target-Path")
	if userPath == "" {
		userPath = "default/path"
	}
	
	// Using Clean with string manipulation
	// ruleid: rule-wrongcleanusage
	cleanPath := filepath.Clean(strings.TrimPrefix(userPath, "/"))
	
	// Checking permissions
	file, err := os.OpenFile(cleanPath, os.O_RDWR, 0)
	if err != nil {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "File %s opened with write permissions", cleanPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL with multiple parameters
	filename := r.URL.Query().Get("file")
	directory := r.URL.Query().Get("dir")
	
	// Using Clean with multiple parameters
	// ruleid: rule-wrongcleanusage
	fullPath := filepath.Clean(filepath.Join(directory, filename))
	
	// Writing to file
	err := ioutil.WriteFile(fullPath, []byte("Content"), 0644)
	if err != nil {
		http.Error(w, "Cannot write to file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "Content written to %s", fullPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Getting path from referer header
	referer := r.Header.Get("Referer")
	userPath := strings.TrimPrefix(referer, "http://example.com/files/")
	
	// Using Clean with environment variable
	baseDir := os.Getenv("FILE_BASE_DIR")
	// ruleid: rule-wrongcleanusage
	fullPath := filepath.Clean(filepath.Join(baseDir, userPath))
	
	// Checking if it's a directory
	fileInfo, err := os.Stat(fullPath)
	if err != nil || !fileInfo.IsDir() {
		http.Error(w, "Not a directory", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Directory %s is valid", fullPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL fragment
	url := r.URL.String()
	parts := strings.Split(url, "#")
	var fragment string
	if len(parts) > 1 {
		fragment = parts[1]
	}
	
	// Using Clean with a ternary-like operation
	userPath := fragment
	if userPath == "" {
		userPath = "index.html"
	}
	
	// ruleid: rule-wrongcleanusage
	cleanPath := path.Clean(userPath)
	
	// Reading file with specific options
	file, err := os.OpenFile(cleanPath, os.O_RDONLY, 0)
	if err != nil {
		http.Error(w, "File not accessible", http.StatusForbidden)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Getting path from a combination of parameters
	category := r.URL.Query().Get("category")
	id := r.URL.Query().Get("id")
	userPath := fmt.Sprintf("data/%s/%s.json", category, id)
	
	// Using Clean with formatted string
	// ruleid: rule-wrongcleanusage
	cleanPath := filepath.Clean(userPath)
	
	// Checking file existence before reading
	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}
	
	data, _ := ioutil.ReadFile(cleanPath)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Getting path from base64 encoded parameter
	encodedPath := r.URL.Query().Get("encoded_path")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		http.Error(w, "Invalid path encoding", http.StatusBadRequest)
		return
	}
	userPath := string(decodedBytes)
	
	// Using Clean with decoded path
	// ruleid: rule-wrongcleanusage
	cleanPath := path.Clean(userPath)
	
	// Appending to file
	file, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Cannot open file for appending", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	file.WriteString("Appended content")
	fmt.Fprintf(w, "Content appended to %s", cleanPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Getting path from multiple sources with fallbacks
	var userPath string
	
	// Try to get from header first
	userPath = r.Header.Get("X-Path")
	
	// If not in header, try query parameter
	if userPath == "" {
		userPath = r.URL.Query().Get("path")
	}
	
	// If still not found, try form data
	if userPath == "" {
		r.ParseForm()
		userPath = r.Form.Get("path")
	}
	
	// Default if all else fails
	if userPath == "" {
		userPath = "default/path.txt"
	}
	
	// Using Clean with the resolved path
	// ruleid: rule-wrongcleanusage
	cleanPath := filepath.Clean(userPath)
	
	// Getting file info
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		http.Error(w, "File not accessible", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "File: %s, Size: %d bytes, Modified: %s", 
		cleanPath, fileInfo.Size(), fileInfo.ModTime())
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Getting user input from URL parameter
	userPath := r.URL.Query().Get("path")
	
	// Using filepath.FromSlash for safe path handling
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Additional validation to ensure path is within allowed directory
	baseDir := "/var/www/files"
	fullPath := filepath.Join(baseDir, safePath)
	
	// Ensure the path doesn't escape the base directory
	if !strings.HasPrefix(fullPath, baseDir) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Getting user input from form data
	r.ParseForm()
	userPath := r.Form.Get("filepath")
	
	// Using filepath.FromSlash and additional validation
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Whitelist approach - only allow specific directories
	allowedDirs := []string{"public", "shared", "downloads"}
	isAllowed := false
	
	for _, dir := range allowedDirs {
		if strings.HasPrefix(safePath, dir+"/") || safePath == dir {
			isAllowed = true
			break
		}
	}
	
	if !isAllowed {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	file, err := os.Open(safePath)
	if err != nil {
		http.Error(w, "Cannot open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Getting path from header
	userPath := r.Header.Get("X-File-Path")
	
	// Using filepath.FromSlash for safe path handling
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Restrict to specific file extensions
	if !strings.HasSuffix(safePath, ".txt") && !strings.HasSuffix(safePath, ".log") {
		http.Error(w, "Only .txt and .log files are allowed", http.StatusBadRequest)
		return
	}
	
	// Using the path to create a file in a specific directory
	file, err := os.Create("./uploads/" + safePath)
	if err != nil {
		http.Error(w, "Cannot create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	file.WriteString("New content")
	fmt.Fprintf(w, "File created at %s", safePath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Getting path from cookie
	cookie, err := r.Cookie("filePath")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	userPath := cookie.Value
	
	// Using filepath.FromSlash directly in a function call
	// ok: rule-wrongcleanusage
	fileInfo, err := os.Stat(filepath.FromSlash(userPath))
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	// Additional check to prevent accessing hidden files
	if strings.HasPrefix(filepath.Base(userPath), ".") {
		http.Error(w, "Access to hidden files is not allowed", http.StatusForbidden)
		return
	}
	
	fmt.Fprintf(w, "File size: %d bytes", fileInfo.Size())
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL path
	userPath := r.URL.Path[1:] // Remove leading slash
	
	baseDir := "/var/www/files"
	
	// Using filepath.FromSlash to handle the path safely
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	fullPath := filepath.Join(baseDir, safePath)
	
	// Ensure the path doesn't escape the base directory
	absBaseDir, _ := filepath.Abs(baseDir)
	absFullPath, _ := filepath.Abs(fullPath)
	
	if !strings.HasPrefix(absFullPath, absBaseDir) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Reading directory contents
	files, err := ioutil.ReadDir(fullPath)
	if err != nil {
		http.Error(w, "Cannot read directory", http.StatusInternalServerError)
		return
	}
	
	for _, file := range files {
		fmt.Fprintf(w, "%s\n", file.Name())
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Getting multiple paths from query parameters
	paths := r.URL.Query()["paths"]
	
	for _, userPath := range paths {
		// Using filepath.FromSlash in a loop
		// ok: rule-wrongcleanusage
		safePath := filepath.FromSlash(userPath)
		
		// Validate path is within allowed directory
		if strings.Contains(safePath, "..") {
			fmt.Fprintf(w, "Path %s contains invalid sequences\n", userPath)
			continue
		}
		
		// Checking if file exists
		if _, err := os.Stat("./public/" + safePath); os.IsNotExist(err) {
			fmt.Fprintf(w, "File %s does not exist\n", safePath)
		} else {
			fmt.Fprintf(w, "File %s exists\n", safePath)
		}
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Getting path from JSON request body
	var requestData struct {
		FilePath string `json:"filePath"`
	}
	
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Using filepath.FromSlash with string concatenation
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(requestData.FilePath)
	
	// Validate the path doesn't contain any directory traversal attempts
	if strings.Contains(safePath, "..") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	fullPath := "./uploads/" + safePath
	
	// Removing file
	err := os.Remove(fullPath)
	if err != nil {
		http.Error(w, "Cannot remove file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "File %s removed successfully", safePath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Getting path with conditional logic
	var userPath string
	if r.Method == "POST" {
		r.ParseForm()
		userPath = r.Form.Get("path")
	} else {
		userPath = r.URL.Query().Get("path")
	}
	
	// Using filepath.FromSlash with a conditional
	if len(userPath) > 0 {
		// ok: rule-wrongcleanusage
		safePath := filepath.FromSlash(userPath)
		
		// Validate path doesn't contain prohibited characters
		if strings.ContainsAny(safePath, "\\:*?\"<>|") {
			http.Error(w, "Path contains invalid characters", http.StatusBadRequest)
			return
		}
		
		// Creating directory in a safe location
		fullPath := filepath.Join("./user_dirs", safePath)
		err := os.MkdirAll(fullPath, 0755)
		if err != nil {
			http.Error(w, "Cannot create directory", http.StatusInternalServerError)
			return
		}
		
		fmt.Fprintf(w, "Directory %s created", safePath)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Getting path from a custom header with default value
	userPath := r.Header.Get("X-Target-Path")
	if userPath == "" {
		userPath = "default/path"
	}
	
	// Using filepath.FromSlash with string manipulation
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(strings.TrimPrefix(userPath, "/"))
	
	// Validate path is alphanumeric plus some safe characters
	for _, char := range safePath {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !strings.ContainsRune("_-./", char) {
			http.Error(w, "Path contains invalid characters", http.StatusBadRequest)
			return
		}
	}
	
	// Checking permissions
	file, err := os.OpenFile("./data/"+safePath, os.O_RDWR, 0)
	if err != nil {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "File %s opened with write permissions", safePath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL with multiple parameters
	filename := r.URL.Query().Get("file")
	directory := r.URL.Query().Get("dir")
	
	// Using filepath.FromSlash with multiple parameters
	// ok: rule-wrongcleanusage
	safeDir := filepath.FromSlash(directory)
	safeFile := filepath.FromSlash(filename)
	
	// Validate directory is in whitelist
	allowedDirs := map[string]bool{"public": true, "shared": true, "temp": true}
	if !allowedDirs[safeDir] {
		http.Error(w, "Directory not allowed", http.StatusForbidden)
		return
	}
	
	// Validate filename doesn't start with dot (hidden file)
	if strings.HasPrefix(safeFile, ".") {
		http.Error(w, "Hidden files not allowed", http.StatusForbidden)
		return
	}
	
	fullPath := filepath.Join(safeDir, safeFile)
	
	// Writing to file
	err := ioutil.WriteFile(fullPath, []byte("Content"), 0644)
	if err != nil {
		http.Error(w, "Cannot write to file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "Content written to %s", fullPath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Getting path from referer header
	referer := r.Header.Get("Referer")
	userPath := strings.TrimPrefix(referer, "http://example.com/files/")
	
	// Using filepath.FromSlash with environment variable
	baseDir := os.Getenv("FILE_BASE_DIR")
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	fullPath := filepath.Join(baseDir, safePath)
	
	// Ensure path is within base directory
	absBaseDir, _ := filepath.Abs(baseDir)
	absFullPath, _ := filepath.Abs(fullPath)
	
	if !strings.HasPrefix(absFullPath, absBaseDir) {
		http.Error(w, "Path traversal attempt detected", http.StatusForbidden)
		return
	}
	
	// Checking if it's a directory
	fileInfo, err := os.Stat(fullPath)
	if err != nil || !fileInfo.IsDir() {
		http.Error(w, "Not a directory", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Directory %s is valid", safePath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Getting path from URL fragment
	url := r.URL.String()
	parts := strings.Split(url, "#")
	var fragment string
	if len(parts) > 1 {
		fragment = parts[1]
	}
	
	// Using filepath.FromSlash with a ternary-like operation
	userPath := fragment
	if userPath == "" {
		userPath = "index.html"
	}
	
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Restrict to specific directory
	fullPath := filepath.Join("./public", safePath)
	
	// Ensure path doesn't escape public directory
	absPublicDir, _ := filepath.Abs("./public")
	absFullPath, _ := filepath.Abs(fullPath)
	
	if !strings.HasPrefix(absFullPath, absPublicDir) {
		http.Error(w, "Invalid path", http.StatusForbidden)
		return
	}
	
	// Reading file with specific options
	file, err := os.OpenFile(fullPath, os.O_RDONLY, 0)
	if err != nil {
		http.Error(w, "File not accessible", http.StatusForbidden)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Getting path from a combination of parameters
	category := r.URL.Query().Get("category")
	id := r.URL.Query().Get("id")
	
	// Validate category and id
	validCategories := map[string]bool{"news": true, "events": true, "products": true}
	if !validCategories[category] {
		http.Error(w, "Invalid category", http.StatusBadRequest)
		return
	}
	
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(id) {
		http.Error(w, "Invalid ID format", http.StatusBadRequest)
		return
	}
	
	userPath := fmt.Sprintf("data/%s/%s.json", category, id)
	
	// Using filepath.FromSlash with formatted string
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Checking file existence before reading
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}
	
	data, _ := ioutil.ReadFile(safePath)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Getting path from base64 encoded parameter
	encodedPath := r.URL.Query().Get("encoded_path")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		http.Error(w, "Invalid path encoding", http.StatusBadRequest)
		return
	}
	userPath := string(decodedBytes)
	
	// Using filepath.FromSlash with decoded path
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Validate path is within allowed directory
	if strings.Contains(safePath, "..") || strings.HasPrefix(safePath, "/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Ensure we're in a specific directory
	fullPath := filepath.Join("./logs", safePath)
	
	// Appending to file
	file, err := os.OpenFile(fullPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		http.Error(w, "Cannot open file for appending", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	file.WriteString("Appended content")
	fmt.Fprintf(w, "Content appended to %s", safePath)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Getting path from multiple sources with fallbacks
	var userPath string
	
	// Try to get from header first
	userPath = r.Header.Get("X-Path")
	
	// If not in header, try query parameter
	if userPath == "" {
		userPath = r.URL.Query().Get("path")
	}
	
	// If still not found, try form data
	if userPath == "" {
		r.ParseForm()
		userPath = r.Form.Get("path")
	}
	
	// Default if all else fails
	if userPath == "" {
		userPath = "default/path.txt"
	}
	
	// Using filepath.FromSlash with the resolved path
	// ok: rule-wrongcleanusage
	safePath := filepath.FromSlash(userPath)
	
	// Validate path doesn't contain prohibited sequences
	if strings.Contains(safePath, "..") || strings.Contains(safePath, "//") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// Ensure path is within a specific directory
	fullPath := filepath.Join("./user_files", safePath)
	
	// Getting file info
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "File not accessible", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "File: %s, Size: %d bytes, Modified: %s", 
		safePath, fileInfo.Size(), fileInfo.ModTime())
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// ... other handlers
	http.HandleFunc("/good1", good_case_1)
	http.HandleFunc("/good2", good_case_2)
	// ... other handlers
	http.ListenAndServe(":8080", nil)
}