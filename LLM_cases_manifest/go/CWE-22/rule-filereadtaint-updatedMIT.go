package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// BAD CASES - These should be detected as vulnerable

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Reading user input directly from URL parameter
	filename := r.URL.Query().Get("filename")
	
	// ruleid: rule-filereadtaint-updatedMIT
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Reading user input from form submission
	r.ParseForm()
	userPath := r.Form.Get("path")
	
	// ruleid: rule-filereadtaint-updatedMIT
	file, err := os.Open(userPath)
	if err != nil {
		http.Error(w, "Error opening file", 500)
		return
	}
	defer file.Close()
	
	data, _ := ioutil.ReadAll(file)
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Reading user input from header
	filename := r.Header.Get("X-Filename")
	basePath := "/var/www/files/"
	
	// Attempted path construction but still vulnerable
	fullPath := basePath + filename
	
	// ruleid: rule-filereadtaint-updatedMIT
	content, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Reading user input from URL path
	filename := r.PathValue("file")
	
	// Attempting to sanitize but still vulnerable
	cleanPath := strings.Replace(filename, "..", "", -1)
	
	// ruleid: rule-filereadtaint-updatedMIT
	f, err := os.Open("./data/" + cleanPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	defer f.Close()
	
	io.Copy(w, f)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Reading user input from cookie
	cookie, err := r.Cookie("file_preference")
	if err != nil {
		http.Error(w, "Cookie not found", 400)
		return
	}
	
	userFile := cookie.Value
	
	// ruleid: rule-filereadtaint-updatedMIT
	data, err := ioutil.ReadFile("/opt/app/configs/" + userFile)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Reading user input from POST body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request", 400)
		return
	}
	
	filename := string(body)
	
	// ruleid: rule-filereadtaint-updatedMIT
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		http.Error(w, "Error opening file", 500)
		return
	}
	defer file.Close()
	
	content, _ := ioutil.ReadAll(file)
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join but still vulnerable
	userDir := r.URL.Query().Get("directory")
	userFile := r.URL.Query().Get("file")
	
	// ruleid: rule-filereadtaint-updatedMIT
	filePath := filepath.Join("/var/data/", userDir, userFile)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Using path manipulation but still vulnerable
	filename := r.URL.Query().Get("name")
	ext := r.URL.Query().Get("type")
	
	// ruleid: rule-filereadtaint-updatedMIT
	fullPath := fmt.Sprintf("./storage/%s.%s", filename, ext)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Using multiple parameters to construct path
	category := r.URL.Query().Get("category")
	id := r.URL.Query().Get("id")
	
	// ruleid: rule-filereadtaint-updatedMIT
	filePath := "./documents/" + category + "/" + id + ".pdf"
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Document not found", 404)
		return
	}
	defer file.Close()
	
	io.Copy(w, file)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Using a switch statement but still vulnerable
	fileType := r.URL.Query().Get("type")
	fileName := r.URL.Query().Get("name")
	
	var basePath string
	switch fileType {
	case "image":
		basePath = "./images/"
	case "document":
		basePath = "./documents/"
	default:
		basePath = "./misc/"
	}
	
	// ruleid: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile(basePath + fileName)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Using conditional logic but still vulnerable
	filename := r.URL.Query().Get("file")
	
	var fullPath string
	if strings.HasSuffix(filename, ".txt") {
		fullPath = "./text/" + filename
	} else if strings.HasSuffix(filename, ".pdf") {
		fullPath = "./pdfs/" + filename
	} else {
		fullPath = "./other/" + filename
	}
	
	// ruleid: rule-filereadtaint-updatedMIT
	data, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Using string concatenation in a loop
	parts := r.URL.Query()["parts"]
	
	path := "./storage"
	for _, part := range parts {
		path += "/" + part
	}
	
	// ruleid: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile(path)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Using a map to determine file location but still vulnerable
	fileID := r.URL.Query().Get("id")
	
	locations := map[string]string{
		"config": "./configs/",
		"log":    "./logs/",
		"data":   "./data/",
	}
	
	fileType := r.URL.Query().Get("type")
	basePath, ok := locations[fileType]
	if !ok {
		basePath = "./misc/"
	}
	
	// ruleid: rule-filereadtaint-updatedMIT
	file, err := os.Open(basePath + fileID)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	defer file.Close()
	
	io.Copy(w, file)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Using string formatting but still vulnerable
	year := r.URL.Query().Get("year")
	month := r.URL.Query().Get("month")
	report := r.URL.Query().Get("report")
	
	// ruleid: rule-filereadtaint-updatedMIT
	filePath := fmt.Sprintf("./reports/%s/%s/%s.pdf", year, month, report)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Report not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Using a builder pattern but still vulnerable
	username := r.URL.Query().Get("user")
	document := r.URL.Query().Get("doc")
	
	var pathBuilder strings.Builder
	pathBuilder.WriteString("./users/")
	pathBuilder.WriteString(username)
	pathBuilder.WriteString("/documents/")
	pathBuilder.WriteString(document)
	
	// ruleid: rule-filereadtaint-updatedMIT
	data, err := os.ReadFile(pathBuilder.String())
	if err != nil {
		http.Error(w, "Document not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// GOOD CASES - These should not be detected as vulnerable

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using a whitelist of allowed files
	filename := r.URL.Query().Get("file")
	
	allowedFiles := map[string]string{
		"profile": "profile.txt",
		"terms":   "terms.txt",
		"about":   "about.txt",
	}
	
	actualFile, exists := allowedFiles[filename]
	if !exists {
		http.Error(w, "File not found", 404)
		return
	}
	
	// ok: rule-filereadtaint-updatedMIT
	data, err := ioutil.ReadFile("./static/" + actualFile)
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Base to extract only the filename
	userFilename := r.URL.Query().Get("filename")
	
	// ok: rule-filereadtaint-updatedMIT
	safeFilename := filepath.Base(userFilename)
	content, err := ioutil.ReadFile("./uploads/" + safeFilename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Using a random ID instead of user input
	userFilename := r.URL.Query().Get("filename")
	
	// Generate random ID for filename
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		http.Error(w, "Server error", 500)
		return
	}
	randomID := hex.EncodeToString(id)
	
	// Store mapping of random ID to original filename (not shown)
	
	// ok: rule-filereadtaint-updatedMIT
	data, err := ioutil.ReadFile("./files/" + randomID)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Using a fixed set of files with numeric IDs
	fileID := r.URL.Query().Get("id")
	
	// Validate that fileID is numeric
	for _, char := range fileID {
		if char < '0' || char > '9' {
			http.Error(w, "Invalid file ID", 400)
			return
		}
	}
	
	// ok: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile("./resources/" + fileID + ".txt")
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Using a secure path construction with validation
	filename := r.URL.Query().Get("file")
	basePath := "/var/www/files/"
	
	// Construct and validate the full path
	fullPath := filepath.Join(basePath, filepath.Base(filename))
	
	// Ensure the path is within the allowed directory
	// ok: rule-filereadtaint-updatedMIT
	if !strings.HasPrefix(fullPath, basePath) {
		http.Error(w, "Invalid path", 400)
		return
	}
	
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Using hardcoded file paths
	fileType := r.URL.Query().Get("type")
	
	var filePath string
	switch fileType {
	case "terms":
		filePath = "./static/terms.txt"
	case "privacy":
		filePath = "./static/privacy.txt"
	case "about":
		filePath = "./static/about.txt"
	default:
		filePath = "./static/default.txt"
	}
	
	// ok: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Using a UUID for file storage
	userFilename := r.URL.Query().Get("filename")
	
	// Generate a UUID (simplified for example)
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		http.Error(w, "Server error", 500)
		return
	}
	uuid := hex.EncodeToString(id)
	
	// Store mapping between UUID and original filename (not shown)
	// Save file content with UUID name (not shown)
	
	// ok: rule-filereadtaint-updatedMIT
	data, err := os.ReadFile("./storage/" + uuid)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	// Set the original filename for download
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(userFilename))
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Using a database to retrieve the actual file path
	userRequestedID := r.URL.Query().Get("id")
	
	// In a real app, this would be a database lookup
	// Here we simulate with a map
	filePaths := map[string]string{
		"1": "./documents/report1.pdf",
		"2": "./documents/report2.pdf",
		"3": "./documents/report3.pdf",
	}
	
	actualPath, exists := filePaths[userRequestedID]
	if !exists {
		http.Error(w, "File not found", 404)
		return
	}
	
	// ok: rule-filereadtaint-updatedMIT
	file, err := os.Open(actualPath)
	if err != nil {
		http.Error(w, "Error opening file", 500)
		return
	}
	defer file.Close()
	
	io.Copy(w, file)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using a fixed directory with validation
	filename := r.URL.Query().Get("file")
	
	// Validate filename contains only allowed characters
	for _, char := range filename {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '-' || char == '_' || char == '.') {
			http.Error(w, "Invalid filename", 400)
			return
		}
	}
	
	// ok: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile("./public/" + filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Using a hash of the content as the filename
	// In a real app, this would be done when the file is uploaded
	contentHash := r.URL.Query().Get("hash")
	
	// Validate hash format (should be hex)
	for _, char := range contentHash {
		if !((char >= '0' && char <= '9') || 
			 (char >= 'a' && char <= 'f') || 
			 (char >= 'A' && char <= 'F')) {
			http.Error(w, "Invalid hash", 400)
			return
		}
	}
	
	// ok: rule-filereadtaint-updatedMIT
	data, err := ioutil.ReadFile("./content/" + contentHash)
	if err != nil {
		http.Error(w, "Content not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Using predefined templates with no user input in path
	templateName := r.URL.Query().Get("template")
	
	// Map template names to actual files
	templates := map[string]string{
		"welcome": "welcome.html",
		"error":   "error.html",
		"info":    "info.html",
	}
	
	filename, exists := templates[templateName]
	if !exists {
		filename = "default.html"
	}
	
	// ok: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile("./templates/" + filename)
	if err != nil {
		http.Error(w, "Template not found", 500)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using a secure temporary file approach
	userFilename := r.URL.Query().Get("filename")
	
	// Create a temporary file with a secure random name
	tempFile, err := ioutil.TempFile("./uploads", "upload-*")
	if err != nil {
		http.Error(w, "Server error", 500)
		return
	}
	defer tempFile.Close()
	
	// Store mapping between temp file and original name (not shown)
	// Write content to temp file (not shown)
	
	// ok: rule-filereadtaint-updatedMIT
	content, err := ioutil.ReadFile(tempFile.Name())
	if err != nil {
		http.Error(w, "Error reading file", 500)
		return
	}
	
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(userFilename))
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Using a content addressing system
	contentID := r.URL.Query().Get("id")
	
	// Validate ID format (simplified)
	if len(contentID) != 32 {
		http.Error(w, "Invalid content ID", 400)
		return
	}
	
	// Create a two-level directory structure from the content ID
	// This is a common pattern in content-addressed storage
	dir1 := contentID[0:2]
	dir2 := contentID[2:4]
	filename := contentID[4:]
	
	// ok: rule-filereadtaint-updatedMIT
	filePath := path.Join("./storage", dir1, dir2, filename)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Content not found", 404)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using a secure file serving approach with content type validation
	fileID := r.URL.Query().Get("id")
	
	// Validate file ID is numeric
	for _, char := range fileID {
		if char < '0' || char > '9' {
			http.Error(w, "Invalid file ID", 400)
			return
		}
	}
	
	// ok: rule-filereadtaint-updatedMIT
	filePath := "./secure_files/" + fileID
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	
	// Determine content type (simplified)
	contentType := http.DetectContentType(content)
	
	// Only allow specific content types
	allowedTypes := map[string]bool{
		"text/plain":               true,
		"application/pdf":          true,
		"image/jpeg":               true,
		"image/png":                true,
		"application/octet-stream": true,
	}
	
	if !allowedTypes[contentType] {
		http.Error(w, "Unsupported content type", 415)
		return
	}
	
	w.Header().Set("Content-Type", contentType)
	w.Write(content)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using a completely static approach with no user input
	// This is the most secure way to serve files
	
	// ok: rule-filereadtaint-updatedMIT
	http.ServeFile(w, r, "./static/index.html")
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