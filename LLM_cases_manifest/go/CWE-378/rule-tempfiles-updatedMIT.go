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
	"path/filepath"
	"time"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_1() {
	// Creating a file directly in /tmp without using os.CreateTemp
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create("/tmp/config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	data := []byte("sensitive configuration data")
	if _, err := file.Write(data); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_2() {
	// Creating a file in /var/tmp with a predictable name
	filename := fmt.Sprintf("/var/tmp/app_log_%d.txt", time.Now().Unix())
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString("Application log data"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_3() {
	// Creating a file in /tmp with a partially randomized name but still insecure
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Fatal(err)
	}
	randomString := hex.EncodeToString(randomBytes)
	
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(fmt.Sprintf("/tmp/data_%s.bin", randomString))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.Write([]byte("Binary data")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_4() {
	// Using ioutil.WriteFile to write to /tmp
	data := []byte("temporary data that needs to be stored")
	// ruleid: rule-tempfiles-updatedMIT
	if err := ioutil.WriteFile("/tmp/app_data.txt", data, 0644); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Creating a temporary file based on user input
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(fmt.Sprintf("/tmp/user_%s.dat", username))
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	if _, err := file.WriteString("User data"); err != nil {
		http.Error(w, "Failed to write data", http.StatusInternalServerError)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_6() {
	// Using os.OpenFile with O_CREATE flag in /tmp
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.OpenFile("/tmp/application.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString(fmt.Sprintf("Log entry at %s\n", time.Now())); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Processing uploaded file and saving to /tmp
	file, header, err := r.FormFile("uploadedFile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// ruleid: rule-tempfiles-updatedMIT
	tempFile, err := os.Create("/tmp/" + header.Filename)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()
	
	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_8() {
	// Creating multiple files in /tmp
	for i := 1; i <= 3; i++ {
		// ruleid: rule-tempfiles-updatedMIT
		file, err := os.Create(fmt.Sprintf("/tmp/chunk_%d.dat", i))
		if err != nil {
			log.Fatal(err)
		}
		
		if _, err := file.WriteString(fmt.Sprintf("Data chunk %d", i)); err != nil {
			log.Fatal(err)
		}
		file.Close()
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_9() {
	// Creating a file with a timestamp-based name in /var/tmp
	timestamp := time.Now().Format("20060102_150405")
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(fmt.Sprintf("/var/tmp/backup_%s.tar.gz", timestamp))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.Write([]byte("Backup data")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_10() {
	// Using a variable to store the path but still insecure
	tempDir := "/tmp"
	filename := "database_dump.sql"
	fullPath := filepath.Join(tempDir, filename)
	
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(fullPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString("SQL dump data"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Creating a file in /tmp with content from HTTP request
	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-tempfiles-updatedMIT
	err := ioutil.WriteFile("/tmp/user_content.txt", []byte(content), 0644)
	if err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_12() {
	// Creating a file with permissions in /tmp
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.OpenFile("/tmp/secure_data.bin", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.Write([]byte("Sensitive data with restricted permissions")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_13() {
	// Creating a hidden file in /tmp
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create("/tmp/.hidden_config")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString("Hidden configuration data"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_14() {
	// Creating a file in a subdirectory of /tmp
	dirPath := "/tmp/app_data"
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		log.Fatal(err)
	}
	
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(filepath.Join(dirPath, "settings.json"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString(`{"setting": "value"}`); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
func bad_case_15() {
	// Using a constant for the path but still insecure
	const tempFilePath = "/var/tmp/app_state.json"
	
	// ruleid: rule-tempfiles-updatedMIT
	file, err := os.Create(tempFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString(`{"state": "running"}`); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_1() {
	// Using os.CreateTemp properly with a pattern
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	data := []byte("sensitive configuration data")
	if _, err := file.Write(data); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_2() {
	// Using os.CreateTemp with a specific directory
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp(os.TempDir(), "app_log_*.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.WriteString("Application log data"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_3() {
	// Using os.CreateTemp with an empty pattern
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.Write([]byte("Binary data")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_4() {
	// Using os.CreateTemp and then writing with ioutil.WriteFile
	// ok: rule-tempfiles-updatedMIT
	tempFile, err := os.CreateTemp("", "app_data_*.txt")
	if err != nil {
		log.Fatal(err)
	}
	tempFile.Close() // Close before writing with WriteFile
	
	data := []byte("temporary data that needs to be stored")
	if err := ioutil.WriteFile(tempFile.Name(), data, 0644); err != nil {
		log.Fatal(err)
	}
	
	defer os.Remove(tempFile.Name()) // Clean up
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Creating a temporary file for user data using os.CreateTemp
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", fmt.Sprintf("user_%s_*.dat", username))
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.WriteString("User data"); err != nil {
		http.Error(w, "Failed to write data", http.StatusInternalServerError)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_6() {
	// Creating a temporary log file with os.CreateTemp
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", "application-*.log")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.WriteString(fmt.Sprintf("Log entry at %s\n", time.Now())); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Processing uploaded file and saving to a secure temporary location
	file, header, err := r.FormFile("uploadedFile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	// ok: rule-tempfiles-updatedMIT
	tempFile, err := os.CreateTemp("", header.Filename+"-*")
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name()) // Clean up
	defer tempFile.Close()
	
	if _, err := io.Copy(tempFile, file); err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_8() {
	// Creating multiple temporary files securely
	var tempFiles []string
	
	for i := 1; i <= 3; i++ {
		// ok: rule-tempfiles-updatedMIT
		file, err := os.CreateTemp("", fmt.Sprintf("chunk_%d_*.dat", i))
		if err != nil {
			log.Fatal(err)
		}
		
		if _, err := file.WriteString(fmt.Sprintf("Data chunk %d", i)); err != nil {
			log.Fatal(err)
		}
		file.Close()
		
		tempFiles = append(tempFiles, file.Name())
	}
	
	// Clean up
	for _, filename := range tempFiles {
		os.Remove(filename)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_9() {
	// Creating a backup file with timestamp using os.CreateTemp
	timestamp := time.Now().Format("20060102_150405")
	
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", fmt.Sprintf("backup_%s_*.tar.gz", timestamp))
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.Write([]byte("Backup data")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_10() {
	// Using a custom directory but still using os.CreateTemp
	tempDir := os.TempDir() // Using system's temp dir
	
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp(tempDir, "database_dump_*.sql")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.WriteString("SQL dump data"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Creating a temporary file with content from HTTP request
	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}
	
	// ok: rule-tempfiles-updatedMIT
	tempFile, err := os.CreateTemp("", "user_content_*.txt")
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tempFile.Name()) // Clean up
	defer tempFile.Close()
	
	if _, err := tempFile.WriteString(content); err != nil {
		http.Error(w, "Failed to write content", http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_12() {
	// Creating a temporary file with restricted permissions
	// ok: rule-tempfiles-updatedMIT
	file, err := os.CreateTemp("", "secure_data_*.bin")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	// Set permissions after creation
	if err := os.Chmod(file.Name(), 0600); err != nil {
		log.Fatal(err)
	}
	
	if _, err := file.Write([]byte("Sensitive data with restricted permissions")); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_13() {
	// Creating a temporary directory and file within it
	// ok: rule-tempfiles-updatedMIT
	tempDir, err := os.MkdirTemp("", "app_config_*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempDir) // Clean up the directory and its contents
	
	configFile := filepath.Join(tempDir, "config.json")
	if err := ioutil.WriteFile(configFile, []byte("Configuration data"), 0644); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_14() {
	// Creating a file in a custom directory (not /tmp or /var/tmp)
	customDir := "./data"
	if err := os.MkdirAll(customDir, 0755); err != nil {
		log.Fatal(err)
	}
	
	// This is safe because it's not in /tmp or /var/tmp
	// ok: rule-tempfiles-updatedMIT
	file, err := os.Create(filepath.Join(customDir, "settings.json"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	
	if _, err := file.WriteString(`{"setting": "value"}`); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
func good_case_15() {
	// Using ioutil.TempFile (which is a wrapper around os.CreateTemp)
	// ok: rule-tempfiles-updatedMIT
	file, err := ioutil.TempFile("", "app_state_*.json")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(file.Name()) // Clean up
	defer file.Close()
	
	if _, err := file.WriteString(`{"state": "running"}`); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

func main() {
	// This function is just a placeholder to make the file compilable
	fmt.Println("This file contains examples of secure and insecure temporary file handling")
}