package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Directly using user input in file path
	filename := r.URL.Query().Get("filename")
	
	// ruleid: rule-path-traversal
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Using path.Join with user input
	userDir := r.URL.Query().Get("dir")
	filename := r.URL.Query().Get("file")
	
	filePath := path.Join("data", userDir, filename)
	
	// ruleid: rule-path-traversal
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join with user input
	username := r.URL.Query().Get("user")
	
	userFilePath := filepath.Join("users", username, "profile.txt")
	
	// ruleid: rule-path-traversal
	file, err := os.Open(userFilePath)
	if err != nil {
		http.Error(w, "User profile not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Using string concatenation with user input
	template := r.URL.Query().Get("template")
	
	// ruleid: rule-path-traversal
	templateFile, err := os.Open("templates/" + template)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	defer templateFile.Close()
	
	content, _ := ioutil.ReadAll(templateFile)
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Using POST data for file path
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	configFile := r.PostForm.Get("config")
	
	// ruleid: rule-path-traversal
	data, err := ioutil.ReadFile("configs/" + configFile)
	if err != nil {
		http.Error(w, "Config not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Using header value for file path
	logFile := r.Header.Get("X-Log-File")
	
	// ruleid: rule-path-traversal
	f, err := os.Open("logs/" + logFile)
	if err != nil {
		http.Error(w, "Log not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fmt.Fprintln(w, scanner.Text())
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Using cookie value for file path
	cookie, err := r.Cookie("theme")
	if err != nil {
		http.Error(w, "Theme cookie not found", http.StatusBadRequest)
		return
	}
	
	themePath := cookie.Value
	
	// ruleid: rule-path-traversal
	themeData, err := ioutil.ReadFile("themes/" + themePath + ".css")
	if err != nil {
		http.Error(w, "Theme not found", http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "text/css")
	w.Write(themeData)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Using multiple user inputs to construct path
	category := r.URL.Query().Get("category")
	id := r.URL.Query().Get("id")
	
	filePath := filepath.Join("data", category, id+".json")
	
	// ruleid: rule-path-traversal
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	
	io.Copy(w, file)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Using URL path for file access
	filePath := r.URL.Path[len("/files/"):]
	
	// ruleid: rule-path-traversal
	content, err := ioutil.ReadFile("storage/" + filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Using user input for file creation
	filename := r.URL.Query().Get("backup")
	
	// ruleid: rule-path-traversal
	file, err := os.Create("backups/" + filename)
	if err != nil {
		http.Error(w, "Could not create backup", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "Backup file created: %s", filename)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Using user input for directory listing
	dirPath := r.URL.Query().Get("dir")
	
	// ruleid: rule-path-traversal
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Could not list directory", http.StatusInternalServerError)
		return
	}
	
	for _, file := range files {
		fmt.Fprintf(w, "%s\n", file.Name())
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Using user input for file stat
	reportName := r.URL.Query().Get("report")
	
	// ruleid: rule-path-traversal
	fileInfo, err := os.Stat("reports/" + reportName)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	
	fmt.Fprintf(w, "Report: %s, Size: %d bytes", reportName, fileInfo.Size())
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Using user input for file removal
	tempFile := r.URL.Query().Get("temp")
	
	// ruleid: rule-path-traversal
	err := os.Remove("temp/" + tempFile)
	if err != nil {
		http.Error(w, "Could not remove file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "Removed temporary file: %s", tempFile)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Using user input for file append
	logName := r.URL.Query().Get("log")
	message := r.URL.Query().Get("message")
	
	// ruleid: rule-path-traversal
	file, err := os.OpenFile("logs/"+logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Could not open log file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	file.WriteString(message + "\n")
	fmt.Fprintf(w, "Log entry added to %s", logName)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Using user input with minimal processing
	assetPath := r.URL.Query().Get("asset")
	cleanPath := strings.Replace(assetPath, " ", "_", -1)
	
	// ruleid: rule-path-traversal
	asset, err := ioutil.ReadFile("assets/" + cleanPath)
	if err != nil {
		http.Error(w, "Asset not found", http.StatusNotFound)
		return
	}
	
	w.Write(asset)
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Clean and validating against allowlist
	filename := r.URL.Query().Get("filename")
	cleanPath := filepath.Clean(filename)
	
	// Validate against allowlist
	allowedFiles := map[string]bool{
		"report1.pdf": true,
		"report2.pdf": true,
		"report3.pdf": true,
	}
	
	// ok: rule-path-traversal
	if allowedFiles[cleanPath] {
		data, err := ioutil.ReadFile("reports/" + cleanPath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Unauthorized access", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Using regex validation for filenames
	filename := r.URL.Query().Get("file")
	
	// Validate filename format (alphanumeric + underscore only)
	validFilename := regexp.MustCompile(`^[a-zA-Z0-9_]+\.txt$`).MatchString(filename)
	
	// ok: rule-path-traversal
	if validFilename {
		data, err := ioutil.ReadFile(filepath.Join("data", filename))
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Base to extract filename only
	userFilename := r.URL.Query().Get("document")
	
	// Extract just the base filename, removing any path components
	safeFilename := filepath.Base(userFilename)
	
	// ok: rule-path-traversal
	content, err := ioutil.ReadFile(filepath.Join("documents", safeFilename))
	if err != nil {
		http.Error(w, "Document not found", http.StatusNotFound)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Using ID to look up filename from a map
	fileID := r.URL.Query().Get("id")
	
	// Map IDs to actual filenames
	fileMap := map[string]string{
		"1": "report2022.pdf",
		"2": "budget2023.xlsx",
		"3": "presentation.pptx",
	}
	
	filename, exists := fileMap[fileID]
	
	// ok: rule-path-traversal
	if exists {
		data, err := ioutil.ReadFile(filepath.Join("secure_files", filename))
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Checking if path is within allowed directory
	requestedPath := r.URL.Query().Get("path")
	cleanPath := filepath.Clean(requestedPath)
	
	// Get absolute paths
	basePath, _ := filepath.Abs("public_files")
	targetPath, _ := filepath.Abs(filepath.Join("public_files", cleanPath))
	
	// Check if target path is within base path
	// ok: rule-path-traversal
	if strings.HasPrefix(targetPath, basePath) {
		data, err := ioutil.ReadFile(targetPath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Access denied", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Using a UUID for filename to avoid path traversal
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	// Generate a random filename instead of using user input
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	filename := hex.EncodeToString(randomBytes) + ".txt"
	
	userContent := r.PostForm.Get("content")
	
	// ok: rule-path-traversal
	err := ioutil.WriteFile(filepath.Join("user_uploads", filename), []byte(userContent), 0644)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "File saved as: %s", filename)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Using a limited set of options with a switch statement
	reportType := r.URL.Query().Get("type")
	
	var filePath string
	
	// ok: rule-path-traversal
	switch reportType {
	case "sales":
		filePath = "reports/sales_report.pdf"
	case "inventory":
		filePath = "reports/inventory_report.pdf"
	case "finance":
		filePath = "reports/finance_report.pdf"
	default:
		http.Error(w, "Invalid report type", http.StatusBadRequest)
		return
	}
	
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Using a safe subdirectory check
	username := r.URL.Query().Get("user")
	filename := r.URL.Query().Get("file")
	
	// Validate username format
	if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}
	
	// Validate filename and ensure it doesn't contain path traversal
	cleanFilename := filepath.Base(filename)
	
	// ok: rule-path-traversal
	if regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`).MatchString(cleanFilename) {
		filePath := filepath.Join("user_files", username, cleanFilename)
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using a hash-based approach for file access
	fileID := r.URL.Query().Get("id")
	
	// Validate that ID is a valid hash (e.g., SHA-256)
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fileID) {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}
	
	// Use first two characters as subdirectory for better organization
	subdir := fileID[:2]
	
	// ok: rule-path-traversal
	filePath := filepath.Join("secure_storage", subdir, fileID)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Using content addressing with base64 encoding
	contentID := r.URL.Query().Get("content")
	
	// Validate that content ID is a valid base64 string
	if _, err := base64.StdEncoding.DecodeString(contentID); err != nil {
		http.Error(w, "Invalid content ID", http.StatusBadRequest)
		return
	}
	
	// ok: rule-path-traversal
	filePath := filepath.Join("content_store", contentID[:2], contentID)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Content not found", http.StatusNotFound)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Using numeric IDs for file access
	fileID := r.URL.Query().Get("file_id")
	
	// Validate that ID is numeric
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(fileID) {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}
	
	// Map numeric IDs to filenames
	fileMap := map[string]string{
		"1": "document1.pdf",
		"2": "document2.pdf",
		"3": "document3.pdf",
	}
	
	filename, exists := fileMap[fileID]
	
	// ok: rule-path-traversal
	if exists {
		data, err := ioutil.ReadFile(filepath.Join("documents", filename))
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		w.Write(data)
	} else {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using a database to retrieve file paths
	userID := r.URL.Query().Get("user_id")
	
	// Validate user ID format
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(userID) {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// In a real app, this would be a database lookup
	// For this example, we'll simulate with a map
	userFiles := map[string]string{
		"123": "user123_profile.jpg",
		"456": "user456_profile.jpg",
		"789": "user789_profile.jpg",
	}
	
	filename, exists := userFiles[userID]
	
	// ok: rule-path-traversal
	if exists {
		data, err := ioutil.ReadFile(filepath.Join("user_images", filename))
		if err != nil {
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(data)
	} else {
		http.Error(w, "User not found", http.StatusNotFound)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Using a safe file extension check
	filename := r.URL.Query().Get("image")
	
	// Extract file extension
	ext := filepath.Ext(filename)
	
	// Check if extension is allowed
	allowedExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
	}
	
	// ok: rule-path-traversal
	if allowedExts[strings.ToLower(ext)] {
		// Use only the base filename and append the validated extension
		safeFilename := filepath.Base(filename)
		imagePath := filepath.Join("images", safeFilename)
		
		data, err := ioutil.ReadFile(imagePath)
		if err != nil {
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}
		
		w.Header().Set("Content-Type", "image/"+strings.TrimPrefix(ext, "."))
		w.Write(data)
	} else {
		http.Error(w, "Invalid image format", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using a safe directory traversal prevention with path normalization
	requestedPath := r.URL.Query().Get("path")
	
	// Normalize the path
	cleanPath := filepath.Clean(requestedPath)
	
	// Ensure the path doesn't start with .. or /
	if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	
	// ok: rule-path-traversal
	filePath := filepath.Join("public_docs", cleanPath)
	
	// Double-check that the final path is still within the intended directory
	absBase, _ := filepath.Abs("public_docs")
	absPath, _ := filepath.Abs(filePath)
	
	if !strings.HasPrefix(absPath, absBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using a combination of techniques for maximum security
	category := r.URL.Query().Get("category")
	filename := r.URL.Query().Get("file")
	
	// Validate category against allowlist
	validCategories := map[string]bool{
		"reports": true,
		"images":  true,
		"docs":    true,
	}
	
	if !validCategories[category] {
		http.Error(w, "Invalid category", http.StatusBadRequest)
		return
	}
	
	// Clean and validate filename
	cleanFilename := filepath.Base(filename)
	
	// Ensure filename only contains allowed characters
	if !regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`).MatchString(cleanFilename) {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	
	// ok: rule-path-traversal
	filePath := filepath.Join("content", category, cleanFilename)
	
	// Final safety check - ensure path is within intended directory
	absBase, _ := filepath.Abs(filepath.Join("content", category))
	absPath, _ := filepath.Abs(filePath)
	
	if !strings.HasPrefix(absPath, absBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}
	
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	w.Write(data)
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
	
	http.ListenAndServe(":8080", nil)
}