I'll create a comprehensive set of examples for the rule-ziparchive-updatedMIT vulnerability (CWE-22), which deals with zip slip/path traversal vulnerabilities when extracting zip archives in Go.

```go
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"crypto/rand"
	"encoding/hex"
)

// BAD CASES - Vulnerable to zip slip / path traversal

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Accepting a zip file from an HTTP request
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a temporary file to store the uploaded zip
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy the uploaded file to the temporary file
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	// Open the zip file for reading
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Error opening zip file", http.StatusInternalServerError)
		return
	}
	defer zipReader.Close()

	// Extract to a destination directory
	destDir := "./extracted_files"
	os.MkdirAll(destDir, 0755)

	// Vulnerable extraction - doesn't validate paths
	for _, file := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, file.Name)

		// Create directory tree
		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		// Extract file
		outFile, err := os.Create(destPath)
		if err != nil {
			continue
		}
		defer outFile.Close()

		rc, err := file.Open()
		if err != nil {
			continue
		}
		defer rc.Close()

		_, err = io.Copy(outFile, rc)
		if err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "File %s uploaded and extracted successfully", header.Filename)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get zip file URL from request
	zipURL := r.URL.Query().Get("zipurl")
	if zipURL == "" {
		http.Error(w, "Missing zip URL", http.StatusBadRequest)
		return
	}

	// Download the zip file
	resp, err := http.Get(zipURL)
	if err != nil {
		http.Error(w, "Failed to download zip", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Create a temporary file to store the downloaded zip
	tempFile, err := ioutil.TempFile("", "download-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy the downloaded file to the temporary file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	// Open the zip file for reading
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Error opening zip file", http.StatusInternalServerError)
		return
	}
	defer zipReader.Close()

	// Extract to a destination directory
	destDir := "/var/www/uploads"
	
	// Vulnerable extraction - doesn't validate paths
	for _, f := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		filePath := filepath.Join(destDir, f.Name)
		
		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			continue
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			continue
		}
		defer dstFile.Close()

		fileInArchive, err := f.Open()
		if err != nil {
			continue
		}
		defer fileInArchive.Close()

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "Zip file downloaded and extracted successfully")
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get the zip file from the request
	file, _, err := r.FormFile("archive")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the entire file into memory
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	// Create a reader from the file bytes
	zipReader, err := zip.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		http.Error(w, "Error reading zip file", http.StatusInternalServerError)
		return
	}

	// Extract to a destination directory specified in the request
	destDir := r.FormValue("destination")
	if destDir == "" {
		destDir = "./default_extract_dir"
	}

	// Vulnerable extraction - doesn't validate paths and uses user-controlled destination
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		path := filepath.Join(destDir, zipFile.Name)

		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(path, zipFile.Mode())
			continue
		}

		// Make directory for file
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			continue
		}

		// Extract file
		fileReader, err := zipFile.Open()
		if err != nil {
			continue
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "Archive extracted successfully to %s", destDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get the zip file path from a request parameter
	zipFilePath := r.URL.Query().Get("zipfile")
	if zipFilePath == "" {
		http.Error(w, "Missing zip file path", http.StatusBadRequest)
		return
	}

	// Open the zip file
	reader, err := zip.OpenReader(zipFilePath)
	if err != nil {
		http.Error(w, "Failed to open zip file", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Get extraction directory from request
	extractDir := r.URL.Query().Get("extractdir")
	if extractDir == "" {
		extractDir = "./extracted"
	}

	// Ensure extraction directory exists
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		http.Error(w, "Failed to create extraction directory", http.StatusInternalServerError)
		return
	}

	// Vulnerable extraction without path validation
	for _, file := range reader.File {
		// ruleid: rule-ziparchive-updatedMIT
		targetPath := filepath.Join(extractDir, file.Name)
		
		// Handle directories
		if file.FileInfo().IsDir() {
			os.MkdirAll(targetPath, file.Mode())
			continue
		}
		
		// Create parent directories if needed
		os.MkdirAll(filepath.Dir(targetPath), 0755)
		
		// Extract file
		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			continue
		}
		
		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			continue
		}
	}
	
	fmt.Fprintf(w, "Extracted zip file to %s", extractDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Process uploaded zip file with custom extraction logic
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save the uploaded file temporarily
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open the zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract only specific file types based on extensions
	allowedExtensions := map[string]bool{".txt": true, ".jpg": true, ".png": true}
	extractDir := "./uploads/" + header.Filename + "_extracted"
	
	// Create extraction directory
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		http.Error(w, "Failed to create extraction directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction - filters by extension but doesn't validate paths
	for _, zipFile := range zipReader.File {
		ext := filepath.Ext(zipFile.Name)
		if !allowedExtensions[ext] {
			continue // Skip files with disallowed extensions
		}
		
		// ruleid: rule-ziparchive-updatedMIT
		outPath := filepath.Join(extractDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(outPath, 0755)
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	
	fmt.Fprintf(w, "Extracted allowed files from %s to %s", header.Filename, extractDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Extract zip file with custom size limit
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Read file into memory with size limit
	maxSize := int64(10 * 1024 * 1024) // 10MB limit
	fileBytes, err := ioutil.ReadAll(io.LimitReader(file, maxSize))
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	
	// Create zip reader from bytes
	zipReader, err := zip.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	
	// Extract to destination directory
	destDir := r.FormValue("destination")
	if destDir == "" {
		destDir = "./extracted_files"
	}
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction - has size limit but no path validation
	totalExtracted := 0
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		written, err := io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			continue
		}
		
		totalExtracted += int(written)
	}
	
	fmt.Fprintf(w, "Extracted %d bytes from zip archive", totalExtracted)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Process zip file with custom error handling
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with custom error handling
	destDir := "./uploads/extracted"
	errors := []string{}
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with error collection
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, zipFile.Mode()); err != nil {
				errors = append(errors, fmt.Sprintf("Failed to create directory %s: %v", zipFile.Name, err))
			}
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create directory structure for %s: %v", zipFile.Name, err))
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to create file %s: %v", zipFile.Name, err))
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			errors = append(errors, fmt.Sprintf("Failed to open file in archive %s: %v", zipFile.Name, err))
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to extract file %s: %v", zipFile.Name, err))
		}
	}
	
	if len(errors) > 0 {
		fmt.Fprintf(w, "Extracted with %d errors: %s", len(errors), strings.Join(errors[:min(3, len(errors))], "; "))
	} else {
		fmt.Fprintf(w, "Extracted all files successfully")
	}
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Extract zip with custom file naming
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract with prefix based on original filename
	destDir := "./uploads"
	prefix := strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename)) + "_"
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with custom naming
	for _, zipFile := range zipReader.File {
		// Add prefix to filename but still vulnerable to path traversal
		fileName := prefix + zipFile.Name
		
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, fileName)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	
	fmt.Fprintf(w, "Extracted files with prefix '%s'", prefix)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Extract only specific files from zip based on request
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Get list of files to extract
	filesToExtract := r.Form["extract_files"]
	if len(filesToExtract) == 0 {
		http.Error(w, "No files specified for extraction", http.StatusBadRequest)
		return
	}
	
	// Create a map for quick lookup
	extractMap := make(map[string]bool)
	for _, f := range filesToExtract {
		extractMap[f] = true
	}
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination
	destDir := "./uploads/selective"
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable selective extraction
	extractedCount := 0
	for _, zipFile := range zipReader.File {
		// Only extract files that were requested
		if !extractMap[zipFile.Name] {
			continue
		}
		
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedCount++
		}
	}
	
	fmt.Fprintf(w, "Extracted %d requested files", extractedCount)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Extract zip with custom permissions
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with custom permissions
	destDir := "./uploads/custom_perms"
	fileMode := os.FileMode(0644)
	dirMode := os.FileMode(0755)
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, dirMode); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with custom permissions
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Handle directories with custom permissions
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, dirMode)
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), dirMode); err != nil {
			continue
		}
		
		// Extract file with custom permissions
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	
	fmt.Fprintf(w, "Extracted files with custom permissions")
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Extract zip with progress reporting
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with progress tracking
	destDir := "./uploads/" + header.Filename + "_contents"
	totalFiles := len(zipReader.File)
	extractedFiles := 0
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with progress tracking
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedFiles++
		}
	}
	
	fmt.Fprintf(w, "Extracted %d of %d files from archive", extractedFiles, totalFiles)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Extract zip with filtering by file size
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Get max file size from request
	maxSizeStr := r.FormValue("maxsize")
	maxSize := int64(1024 * 1024) // Default 1MB
	if maxSizeStr != "" {
		if parsedSize, err := strconv.ParseInt(maxSizeStr, 10, 64); err == nil {
			maxSize = parsedSize
		}
	}
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with size filtering
	destDir := "./uploads/size_filtered"
	skippedFiles := 0
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with size filtering
	for _, zipFile := range zipReader.File {
		// Skip files larger than max size
		if zipFile.UncompressedSize64 > uint64(maxSize) {
			skippedFiles++
			continue
		}
		
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	
	fmt.Fprintf(w, "Extracted files (skipped %d files exceeding %d bytes)", skippedFiles, maxSize)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Extract zip with custom timestamp handling
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with timestamp preservation
	destDir := "./uploads/timestamped"
	preserveTimestamps := r.FormValue("preserve_timestamps") == "true"
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with timestamp handling
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			if preserveTimestamps {
				os.Chtimes(destPath, zipFile.Modified, zipFile.Modified)
			}
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		// Preserve original timestamp if requested
		if preserveTimestamps && err == nil {
			os.Chtimes(destPath, zipFile.Modified, zipFile.Modified)
		}
	}
	
	fmt.Fprintf(w, "Extracted files with %s timestamps", 
		map[bool]string{true: "preserved", false: "current"}[preserveTimestamps])
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Extract zip with custom error handling and logging
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Create a log file for extraction errors
	logFile, err := os.OpenFile("extraction_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "Error creating log file", http.StatusInternalServerError)
		return
	}
	defer logFile.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		fmt.Fprintf(logFile, "Error creating temp file: %v\n", err)
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		fmt.Fprintf(logFile, "Error saving file: %v\n", err)
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		fmt.Fprintf(logFile, "Invalid zip file: %v\n", err)
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with logging
	destDir := "./uploads/logged"
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		fmt.Fprintf(logFile, "Failed to create destination directory: %v\n", err)
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with logging
	successCount := 0
	errorCount := 0
	
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Log extraction attempt
		fmt.Fprintf(logFile, "Extracting: %s\n", zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			if err := os.MkdirAll(destPath, zipFile.Mode()); err != nil {
				fmt.Fprintf(logFile, "  Error creating directory: %v\n", err)
				errorCount++
			} else {
				successCount++
			}
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			fmt.Fprintf(logFile, "  Error creating directory structure: %v\n", err)
			errorCount++
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			fmt.Fprintf(logFile, "  Error creating output file: %v\n", err)
			errorCount++
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			fmt.Fprintf(logFile, "  Error opening file in archive: %v\n", err)
			errorCount++
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			fmt.Fprintf(logFile, "  Error extracting file content: %v\n", err)
			errorCount++
		} else {
			fmt.Fprintf(logFile, "  Successfully extracted\n")
			successCount++
		}
	}
	
	fmt.Fprintf(w, "Extraction complete: %d successful, %d failed (see log for details)", 
		successCount, errorCount)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Extract zip with custom handling for duplicate filenames
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract to destination with duplicate handling
	destDir := "./uploads/deduped"
	extractedFiles := make(map[string]bool)
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Vulnerable extraction with duplicate handling
	duplicateCount := 0
	
	for _, zipFile := range zipReader.File {
		// ruleid: rule-ziparchive-updatedMIT
		destPath := filepath.Join(destDir, zipFile.Name)
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Check if we've already extracted a file with this name
		if extractedFiles[destPath] {
			// Handle duplicate by adding a suffix
			duplicateCount++
			ext := filepath.Ext(destPath)
			baseName := strings.TrimSuffix(destPath, ext)
			destPath = fmt.Sprintf("%s_(%d)%s", baseName, duplicateCount, ext)
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedFiles[destPath] = true
		}
	}
	
	fmt.Fprintf(w, "Extracted files (handled %d duplicates)", duplicateCount)
}
// {/fact}

// GOOD CASES - Safe implementations

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Accepting a zip file from an HTTP request with path validation
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create a temporary file to store the uploaded zip
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy the uploaded file to the temporary file
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	// Open the zip file for reading
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Error opening zip file", http.StatusInternalServerError)
		return
	}
	defer zipReader.Close()

	// Extract to a destination directory
	destDir := "./extracted_files"
	os.MkdirAll(destDir, 0755)

	// Safe extraction - validates paths
	for _, file := range zipReader.File {
		// Get the file path
		filePath := file.Name
		
		// Validate the file path - ensure it doesn't contain path traversal
		// ok: rule-ziparchive-updatedMIT
		if !isValidPath(filePath) {
			continue // Skip this file
		}
		
		destPath := filepath.Join(destDir, filePath)
		
		// Ensure the destination path is still within the target directory
		// ok: rule-ziparchive-updatedMIT
		destPathAbs, err := filepath.Abs(destPath)
		if err != nil {
			continue
		}
		destDirAbs, err := filepath.Abs(destDir)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(destPathAbs, destDirAbs) {
			// Path traversal detected, skip this file
			continue
		}

		// Create directory tree
		if file.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0755)
			continue
		}

		// Extract file
		outFile, err := os.Create(destPath)
		if err != nil {
			continue
		}
		defer outFile.Close()

		rc, err := file.Open()
		if err != nil {
			continue
		}
		defer rc.Close()

		_, err = io.Copy(outFile, rc)
		if err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "File %s uploaded and extracted safely", header.Filename)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get zip file URL from request with path validation
	zipURL := r.URL.Query().Get("zipurl")
	if zipURL == "" {
		http.Error(w, "Missing zip URL", http.StatusBadRequest)
		return
	}

	// Download the zip file
	resp, err := http.Get(zipURL)
	if err != nil {
		http.Error(w, "Failed to download zip", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Create a temporary file to store the downloaded zip
	tempFile, err := ioutil.TempFile("", "download-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy the downloaded file to the temporary file
	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		http.Error(w, "Error copying file", http.StatusInternalServerError)
		return
	}

	// Open the zip file for reading
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Error opening zip file", http.StatusInternalServerError)
		return
	}
	defer zipReader.Close()

	// Extract to a destination directory
	destDir := "/var/www/uploads"
	
	// Safe extraction with path validation
	for _, f := range zipReader.File {
		// Validate file path
		// ok: rule-ziparchive-updatedMIT
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			// Path traversal attempt detected, skip this file
			continue
		}
		
		filePath := filepath.Join(destDir, f.Name)
		
		// Double-check the final path is still within the destination directory
		// ok: rule-ziparchive-updatedMIT
		absDestDir, _ := filepath.Abs(destDir)
		absFilePath, _ := filepath.Abs(filePath)
		if !strings.HasPrefix(absFilePath, absDestDir) {
			// Path traversal detected, skip this file
			continue
		}
		
		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			continue
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			continue
		}
		defer dstFile.Close()

		fileInArchive, err := f.Open()
		if err != nil {
			continue
		}
		defer fileInArchive.Close()

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "Zip file downloaded and extracted safely")
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get the zip file from the request with safe extraction
	file, _, err := r.FormFile("archive")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read the entire file into memory
	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	// Create a reader from the file bytes
	zipReader, err := zip.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		http.Error(w, "Error reading zip file", http.StatusInternalServerError)
		return
	}

	// Extract to a destination directory specified in the request
	destDir := r.FormValue("destination")
	if destDir == "" {
		destDir = "./default_extract_dir"
	}
	
	// Create a unique subdirectory for this extraction to prevent path traversal
	// ok: rule-ziparchive-updatedMIT
	extractID := generateRandomString(8)
	extractDir := filepath.Join(destDir, extractID)
	
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		http.Error(w, "Failed to create extraction directory", http.StatusInternalServerError)
		return
	}

	// Safe extraction with path validation
	for _, zipFile := range zipReader.File {
		// Normalize the file path and check for path traversal attempts
		// ok: rule-ziparchive-updatedMIT
		cleanedPath := filepath.Clean(zipFile.Name)
		if strings.Contains(cleanedPath, "..") || strings.HasPrefix(cleanedPath, "/") {
			// Path traversal attempt detected, skip this file
			continue
		}
		
		// Join with the unique extraction directory
		destPath := filepath.Join(extractDir, cleanedPath)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absExtractDir, _ := filepath.Abs(extractDir)
		absDestPath, _ := filepath.Abs(destPath)
		if !strings.HasPrefix(absDestPath, absExtractDir) {
			// Path traversal detected, skip this file
			continue
		}

		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}

		// Make directory for file
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}

		// Extract file
		fileReader, err := zipFile.Open()
		if err != nil {
			continue
		}
		defer fileReader.Close()

		targetFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		defer targetFile.Close()

		if _, err := io.Copy(targetFile, fileReader); err != nil {
			continue
		}
	}

	fmt.Fprintf(w, "Archive extracted safely to %s", extractDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get the zip file path from a request parameter with safe extraction
	zipFilePath := r.URL.Query().Get("zipfile")
	if zipFilePath == "" {
		http.Error(w, "Missing zip file path", http.StatusBadRequest)
		return
	}

	// Open the zip file
	reader, err := zip.OpenReader(zipFilePath)
	if err != nil {
		http.Error(w, "Failed to open zip file", http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Get extraction directory from request
	extractDir := r.URL.Query().Get("extractdir")
	if extractDir == "" {
		extractDir = "./extracted"
	}

	// Ensure extraction directory exists
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		http.Error(w, "Failed to create extraction directory", http.StatusInternalServerError)
		return
	}
	
	// Get absolute path of extraction directory for validation
	// ok: rule-ziparchive-updatedMIT
	absExtractDir, err := filepath.Abs(extractDir)
	if err != nil {
		http.Error(w, "Failed to resolve extraction directory path", http.StatusInternalServerError)
		return
	}

	// Safe extraction with path validation
	for _, file := range reader.File {
		// Clean the file path and check for path traversal
		// ok: rule-ziparchive-updatedMIT
		fileName := filepath.Clean(file.Name)
		if strings.Contains(fileName, "..") || strings.HasPrefix(fileName, "/") {
			// Path traversal attempt detected, skip this file
			continue
		}
		
		targetPath := filepath.Join(extractDir, fileName)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absTargetPath, err := filepath.Abs(targetPath)
		if err != nil {
			continue
		}
		
		if !strings.HasPrefix(absTargetPath, absExtractDir) {
			// Path traversal detected, skip this file
			continue
		}
		
		// Handle directories
		if file.FileInfo().IsDir() {
			os.MkdirAll(targetPath, file.Mode())
			continue
		}
		
		// Create parent directories if needed
		os.MkdirAll(filepath.Dir(targetPath), 0755)
		
		// Extract file
		outFile, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if err != nil {
			continue
		}
		
		rc, err := file.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			continue
		}
	}
	
	fmt.Fprintf(w, "Safely extracted zip file to %s", extractDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Process uploaded zip file with safe extraction and file type filtering
	file, header, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save the uploaded file temporarily
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open the zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Extract only specific file types based on extensions
	allowedExtensions := map[string]bool{".txt": true, ".jpg": true, ".png": true}
	
	// Create a unique extraction directory
	// ok: rule-ziparchive-updatedMIT
	extractID := generateRandomString(10)
	extractDir := filepath.Join("./uploads", extractID)
	
	// Create extraction directory
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		http.Error(w, "Failed to create extraction directory", http.StatusInternalServerError)
		return
	}
	
	// Get absolute path of extraction directory for validation
	// ok: rule-ziparchive-updatedMIT
	absExtractDir, err := filepath.Abs(extractDir)
	if err != nil {
		http.Error(w, "Failed to resolve extraction directory path", http.StatusInternalServerError)
		return
	}
	
	// Safe extraction with extension filtering and path validation
	extractedCount := 0
	for _, zipFile := range zipReader.File {
		// Check file extension
		ext := filepath.Ext(zipFile.Name)
		if !allowedExtensions[ext] {
			continue // Skip files with disallowed extensions
		}
		
		// Clean the file path and check for path traversal
		// ok: rule-ziparchive-updatedMIT
		fileName := filepath.Clean(zipFile.Name)
		if strings.Contains(fileName, "..") || strings.HasPrefix(fileName, "/") {
			// Path traversal attempt detected, skip this file
			continue
		}
		
		outPath := filepath.Join(extractDir, fileName)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absOutPath, err := filepath.Abs(outPath)
		if err != nil {
			continue
		}
		
		if !strings.HasPrefix(absOutPath, absExtractDir) {
			// Path traversal detected, skip this file
			continue
		}
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(outPath, 0755)
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedCount++
		}
	}
	
	fmt.Fprintf(w, "Safely extracted %d allowed files from %s to %s", 
		extractedCount, header.Filename, extractDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Extract zip with size limits and safe path handling
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Read file into memory with size limit
	maxSize := int64(10 * 1024 * 1024) // 10MB limit
	fileBytes, err := ioutil.ReadAll(io.LimitReader(file, maxSize))
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	
	// Create zip reader from bytes
	zipReader, err := zip.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	
	// Create a unique extraction directory
	// ok: rule-ziparchive-updatedMIT
	extractID := generateRandomString(12)
	destDir := filepath.Join("./extracted_files", extractID)
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Get absolute path of extraction directory for validation
	// ok: rule-ziparchive-updatedMIT
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		http.Error(w, "Failed to resolve extraction directory path", http.StatusInternalServerError)
		return
	}
	
	// Safe extraction with size limits and path validation
	totalExtracted := 0
	maxFileSize := int64(1024 * 1024) // 1MB per file
	
	for _, zipFile := range zipReader.File {
		// Skip files larger than the per-file limit
		if zipFile.UncompressedSize64 > uint64(maxFileSize) {
			continue
		}
		
		// Clean the file path and check for path traversal
		// ok: rule-ziparchive-updatedMIT
		fileName := filepath.Clean(zipFile.Name)
		if strings.Contains(fileName, "..") || strings.HasPrefix(fileName, "/") {
			// Path traversal attempt detected, skip this file
			continue
		}
		
		destPath := filepath.Join(destDir, fileName)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absDestPath, err := filepath.Abs(destPath)
		if err != nil {
			continue
		}
		
		if !strings.HasPrefix(absDestPath, absDestDir) {
			// Path traversal detected, skip this file
			continue
		}
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file with size limit
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		written, err := io.Copy(outFile, io.LimitReader(rc, maxFileSize))
		outFile.Close()
		rc.Close()
		
		if err != nil {
			os.Remove(destPath) // Clean up partial file
			continue
		}
		
		totalExtracted += int(written)
	}
	
	fmt.Fprintf(w, "Safely extracted %d bytes from zip archive to %s", totalExtracted, destDir)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Process zip file with safe extraction and random file renaming
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Create a unique extraction directory
	// ok: rule-ziparchive-updatedMIT
	extractID := generateRandomString(8)
	destDir := filepath.Join("./uploads", extractID)
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Safe extraction with file renaming
	fileMap := make(map[string]string) // Map original names to new names
	
	for _, zipFile := range zipReader.File {
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			continue
		}
		
		// Generate a random filename but keep the extension
		ext := filepath.Ext(zipFile.Name)
		// ok: rule-ziparchive-updatedMIT
		randomName := generateRandomString(16) + ext
		destPath := filepath.Join(destDir, randomName)
		
		// Store the mapping
		fileMap[zipFile.Name] = randomName
		
		// Extract file with the random name
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err != nil {
			os.Remove(destPath) // Clean up partial file
		}
	}
	
	// Create a manifest file with the name mappings
	manifestPath := filepath.Join(destDir, "manifest.json")
	manifestData, _ := json.MarshalIndent(fileMap, "", "  ")
	ioutil.WriteFile(manifestPath, manifestData, 0644)
	
	fmt.Fprintf(w, "Safely extracted %d files with randomized names", len(fileMap))
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Extract zip with whitelist directory validation
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Create extraction directory
	destDir := "./uploads/whitelist_extract"
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Define whitelist of allowed top-level directories
	// ok: rule-ziparchive-updatedMIT
	allowedDirs := map[string]bool{
		"images": true,
		"docs":   true,
		"data":   true,
	}
	
	// Safe extraction with whitelist validation
	extractedCount := 0
	skippedCount := 0
	
	for _, zipFile := range zipReader.File {
		// Get the top-level directory
		// ok: rule-ziparchive-updatedMIT
		pathParts := strings.SplitN(filepath.ToSlash(zipFile.Name), "/", 2)
		if len(pathParts) < 1 {
			skippedCount++
			continue
		}
		
		topDir := pathParts[0]
		
		// Check if top directory is in whitelist
		if !allowedDirs[topDir] {
			skippedCount++
			continue
		}
		
		// Clean the file path and check for path traversal
		// ok: rule-ziparchive-updatedMIT
		fileName := filepath.Clean(zipFile.Name)
		if strings.Contains(fileName, "..") || strings.HasPrefix(fileName, "/") {
			skippedCount++
			continue
		}
		
		destPath := filepath.Join(destDir, fileName)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absDestDir, _ := filepath.Abs(destDir)
		absDestPath, _ := filepath.Abs(destPath)
		if !strings.HasPrefix(absDestPath, absDestDir) {
			skippedCount++
			continue
		}
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			skippedCount++
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			skippedCount++
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			skippedCount++
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedCount++
		} else {
			skippedCount++
		}
	}
	
	fmt.Fprintf(w, "Safely extracted %d files (skipped %d) using whitelist directories", 
		extractedCount, skippedCount)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Extract only specific files from zip based on request with safe path handling
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Get list of files to extract
	filesToExtract := r.Form["extract_files"]
	if len(filesToExtract) == 0 {
		http.Error(w, "No files specified for extraction", http.StatusBadRequest)
		return
	}
	
	// Create a map for quick lookup
	extractMap := make(map[string]bool)
	for _, f := range filesToExtract {
		// ok: rule-ziparchive-updatedMIT
		cleanPath := filepath.Clean(f)
		if !strings.Contains(cleanPath, "..") && !strings.HasPrefix(cleanPath, "/") {
			extractMap[cleanPath] = true
		}
	}
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
	
	// Open zip archive
	zipReader, err := zip.OpenReader(tempFile.Name())
	if err != nil {
		http.Error(w, "Invalid zip file", http.StatusBadRequest)
		return
	}
	defer zipReader.Close()
	
	// Create a unique extraction directory
	// ok: rule-ziparchive-updatedMIT
	extractID := generateRandomString(10)
	destDir := filepath.Join("./uploads/selective", extractID)
	
	// Ensure destination exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		http.Error(w, "Failed to create destination directory", http.StatusInternalServerError)
		return
	}
	
	// Get absolute path of extraction directory for validation
	// ok: rule-ziparchive-updatedMIT
	absDestDir, err := filepath.Abs(destDir)
	if err != nil {
		http.Error(w, "Failed to resolve extraction directory path", http.StatusInternalServerError)
		return
	}
	
	// Safe selective extraction
	extractedCount := 0
	for _, zipFile := range zipReader.File {
		// Clean the file path
		// ok: rule-ziparchive-updatedMIT
		cleanName := filepath.Clean(zipFile.Name)
		
		// Only extract files that were requested
		if !extractMap[cleanName] {
			continue
		}
		
		// Check for path traversal
		if strings.Contains(cleanName, "..") || strings.HasPrefix(cleanName, "/") {
			continue
		}
		
		destPath := filepath.Join(destDir, cleanName)
		
		// Verify the final path is still within our extraction directory
		// ok: rule-ziparchive-updatedMIT
		absDestPath, err := filepath.Abs(destPath)
		if err != nil {
			continue
		}
		
		if !strings.HasPrefix(absDestPath, absDestDir) {
			continue
		}
		
		// Skip directories
		if zipFile.FileInfo().IsDir() {
			os.MkdirAll(destPath, zipFile.Mode())
			continue
		}
		
		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			continue
		}
		
		// Extract file
		outFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, zipFile.Mode())
		if err != nil {
			continue
		}
		
		rc, err := zipFile.Open()
		if err != nil {
			outFile.Close()
			continue
		}
		
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		
		if err == nil {
			extractedCount++
		}
	}
	
	fmt.Fprintf(w, "Safely extracted %d requested files", extractedCount)
}
// {/fact}

func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Extract zip with flat directory structure (no subdirectories)
	file, _, err := r.FormFile("zipfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// Save to temporary file
	tempFile, err := ioutil.TempFile("", "upload-*.zip")
	if err != nil {
		http.Error(w, "Error creating temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()
	
	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.