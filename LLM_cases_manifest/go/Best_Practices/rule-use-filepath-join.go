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

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	// Using path.Join for file operations
	baseDir := "/var/data"
	fileName := "config.json"
	
	// ruleid: rule-use-filepath-join
	fullPath := path.Join(baseDir, fileName)
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(data))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Using path.Join with user input from HTTP request
	baseDir := "/var/logs"
	fileName := r.URL.Query().Get("file")
	
	// ruleid: rule-use-filepath-join
	logPath := path.Join(baseDir, fileName)
	content, err := ioutil.ReadFile(logPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	w.Write(content)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	// Using path.Join in a loop for multiple files
	baseDir := "C:\\Users\\admin\\Documents"
	files := []string{"report1.txt", "report2.txt", "report3.txt"}
	
	for _, file := range files {
		// ruleid: rule-use-filepath-join
		fullPath := path.Join(baseDir, file)
		_, err := os.Stat(fullPath)
		if err != nil {
			fmt.Printf("File %s does not exist\n", fullPath)
		} else {
			fmt.Printf("File %s exists\n", fullPath)
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Using path.Join with multiple path components
	baseDir := "/var/www"
	subDir := r.URL.Query().Get("folder")
	fileName := r.URL.Query().Get("file")
	
	// ruleid: rule-use-filepath-join
	fullPath := path.Join(baseDir, subDir, fileName)
	
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "Cannot open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	content, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Cannot read file", http.StatusInternalServerError)
		return
	}
	w.Write(content)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	// Using path.Join for creating directories
	rootDir := "/opt/app"
	dirName := "data"
	
	// ruleid: rule-use-filepath-join
	newDir := path.Join(rootDir, dirName)
	err := os.MkdirAll(newDir, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	fmt.Printf("Created directory: %s\n", newDir)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	// Using path.Join for writing to a file
	configDir := "/etc/myapp"
	configFile := "settings.conf"
	
	// ruleid: rule-use-filepath-join
	configPath := path.Join(configDir, configFile)
	
	data := []byte("key=value\n")
	err := ioutil.WriteFile(configPath, data, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
	fmt.Printf("Wrote to file: %s\n", configPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Using path.Join with a variable number of path components
	basePath := "/var/data"
	pathParts := strings.Split(r.URL.Path, "/")
	
	// ruleid: rule-use-filepath-join
	fullPath := path.Join(append([]string{basePath}, pathParts...)...)
	
	_, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "Path not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "Path exists: %s", fullPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	// Using path.Join for checking if a directory exists
	homeDir := "/home/user"
	appDir := ".myapp"
	
	// ruleid: rule-use-filepath-join
	appPath := path.Join(homeDir, appDir)
	
	info, err := os.Stat(appPath)
	if err != nil || !info.IsDir() {
		err = os.Mkdir(appPath, 0755)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}
	}
	fmt.Printf("Application directory: %s\n", appPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Using path.Join for serving static files
	staticDir := "./static"
	requestedFile := r.URL.Path[1:] // Remove leading slash
	
	// ruleid: rule-use-filepath-join
	filePath := path.Join(staticDir, requestedFile)
	
	http.ServeFile(w, r, filePath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	// Using path.Join for renaming files
	sourceDir := "/tmp/uploads"
	destDir := "/var/data"
	fileName := "report.pdf"
	
	// ruleid: rule-use-filepath-join
	sourcePath := path.Join(sourceDir, fileName)
	// ruleid: rule-use-filepath-join
	destPath := path.Join(destDir, fileName)
	
	err := os.Rename(sourcePath, destPath)
	if err != nil {
		fmt.Println("Error moving file:", err)
		return
	}
	fmt.Printf("Moved %s to %s\n", sourcePath, destPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	// Using path.Join with environment variables
	tempDir := os.Getenv("TEMP")
	appName := "myapp"
	fileName := "cache.dat"
	
	// ruleid: rule-use-filepath-join
	cachePath := path.Join(tempDir, appName, fileName)
	
	_, err := os.Stat(cachePath)
	if os.IsNotExist(err) {
		fmt.Printf("Cache file does not exist: %s\n", cachePath)
	} else {
		fmt.Printf("Cache file exists: %s\n", cachePath)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Using path.Join for file upload
	uploadDir := "./uploads"
	fileName := r.FormValue("filename")
	
	// ruleid: rule-use-filepath-join
	uploadPath := path.Join(uploadDir, fileName)
	
	file, err := os.Create(uploadPath)
	if err != nil {
		http.Error(w, "Cannot create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "File will be saved to: %s", uploadPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	// Using path.Join for removing files
	logsDir := "/var/log/myapp"
	oldLog := "app.log.old"
	
	// ruleid: rule-use-filepath-join
	logPath := path.Join(logsDir, oldLog)
	
	err := os.Remove(logPath)
	if err != nil {
		fmt.Println("Error removing file:", err)
		return
	}
	fmt.Printf("Removed file: %s\n", logPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	// Using path.Join for checking file permissions
	configDir := "/etc/myapp"
	configFile := "config.json"
	
	// ruleid: rule-use-filepath-join
	configPath := path.Join(configDir, configFile)
	
	info, err := os.Stat(configPath)
	if err != nil {
		fmt.Println("Error accessing file:", err)
		return
	}
	
	mode := info.Mode().Perm()
	fmt.Printf("File %s has permissions: %o\n", configPath, mode)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	// Using path.Join with conditional path components
	baseDir := "/var/data"
	env := "production"
	var dataDir string
	
	if env == "production" {
		dataDir = "prod"
	} else {
		dataDir = "dev"
	}
	
	// ruleid: rule-use-filepath-join
	fullPath := path.Join(baseDir, dataDir, "config.json")
	
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(data))
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	// Using filepath.Join for file operations
	baseDir := "/var/data"
	fileName := "config.json"
	
	// ok: rule-use-filepath-join
	fullPath := filepath.Join(baseDir, fileName)
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(data))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join with user input from HTTP request
	baseDir := "/var/logs"
	fileName := r.URL.Query().Get("file")
	
	// ok: rule-use-filepath-join
	logPath := filepath.Join(baseDir, fileName)
	content, err := ioutil.ReadFile(logPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	w.Write(content)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	// Using filepath.Join in a loop for multiple files
	baseDir := "C:\\Users\\admin\\Documents"
	files := []string{"report1.txt", "report2.txt", "report3.txt"}
	
	for _, file := range files {
		// ok: rule-use-filepath-join
		fullPath := filepath.Join(baseDir, file)
		_, err := os.Stat(fullPath)
		if err != nil {
			fmt.Printf("File %s does not exist\n", fullPath)
		} else {
			fmt.Printf("File %s exists\n", fullPath)
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join with multiple path components
	baseDir := "/var/www"
	subDir := r.URL.Query().Get("folder")
	fileName := r.URL.Query().Get("file")
	
	// ok: rule-use-filepath-join
	fullPath := filepath.Join(baseDir, subDir, fileName)
	
	file, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, "Cannot open file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	content, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Cannot read file", http.StatusInternalServerError)
		return
	}
	w.Write(content)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	// Using filepath.Join for creating directories
	rootDir := "/opt/app"
	dirName := "data"
	
	// ok: rule-use-filepath-join
	newDir := filepath.Join(rootDir, dirName)
	err := os.MkdirAll(newDir, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	fmt.Printf("Created directory: %s\n", newDir)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	// Using filepath.Join for writing to a file
	configDir := "/etc/myapp"
	configFile := "settings.conf"
	
	// ok: rule-use-filepath-join
	configPath := filepath.Join(configDir, configFile)
	
	data := []byte("key=value\n")
	err := ioutil.WriteFile(configPath, data, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
	fmt.Printf("Wrote to file: %s\n", configPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join with a variable number of path components
	basePath := "/var/data"
	pathParts := strings.Split(r.URL.Path, "/")
	
	// ok: rule-use-filepath-join
	fullPath := filepath.Join(append([]string{basePath}, pathParts...)...)
	
	_, err := os.Stat(fullPath)
	if err != nil {
		http.Error(w, "Path not found", http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, "Path exists: %s", fullPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	// Using filepath.Join for checking if a directory exists
	homeDir := "/home/user"
	appDir := ".myapp"
	
	// ok: rule-use-filepath-join
	appPath := filepath.Join(homeDir, appDir)
	
	info, err := os.Stat(appPath)
	if err != nil || !info.IsDir() {
		err = os.Mkdir(appPath, 0755)
		if err != nil {
			fmt.Println("Error creating directory:", err)
			return
		}
	}
	fmt.Printf("Application directory: %s\n", appPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join for serving static files
	staticDir := "./static"
	requestedFile := r.URL.Path[1:] // Remove leading slash
	
	// ok: rule-use-filepath-join
	filePath := filepath.Join(staticDir, requestedFile)
	
	http.ServeFile(w, r, filePath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	// Using filepath.Join for renaming files
	sourceDir := "/tmp/uploads"
	destDir := "/var/data"
	fileName := "report.pdf"
	
	// ok: rule-use-filepath-join
	sourcePath := filepath.Join(sourceDir, fileName)
	// ok: rule-use-filepath-join
	destPath := filepath.Join(destDir, fileName)
	
	err := os.Rename(sourcePath, destPath)
	if err != nil {
		fmt.Println("Error moving file:", err)
		return
	}
	fmt.Printf("Moved %s to %s\n", sourcePath, destPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	// Using filepath.Join with environment variables
	tempDir := os.Getenv("TEMP")
	appName := "myapp"
	fileName := "cache.dat"
	
	// ok: rule-use-filepath-join
	cachePath := filepath.Join(tempDir, appName, fileName)
	
	_, err := os.Stat(cachePath)
	if os.IsNotExist(err) {
		fmt.Printf("Cache file does not exist: %s\n", cachePath)
	} else {
		fmt.Printf("Cache file exists: %s\n", cachePath)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using filepath.Join for file upload
	uploadDir := "./uploads"
	fileName := r.FormValue("filename")
	
	// ok: rule-use-filepath-join
	uploadPath := filepath.Join(uploadDir, fileName)
	
	file, err := os.Create(uploadPath)
	if err != nil {
		http.Error(w, "Cannot create file", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	
	fmt.Fprintf(w, "File will be saved to: %s", uploadPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	// Using filepath.Join for removing files
	logsDir := "/var/log/myapp"
	oldLog := "app.log.old"
	
	// ok: rule-use-filepath-join
	logPath := filepath.Join(logsDir, oldLog)
	
	err := os.Remove(logPath)
	if err != nil {
		fmt.Println("Error removing file:", err)
		return
	}
	fmt.Printf("Removed file: %s\n", logPath)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	// Using filepath.Join for checking file permissions
	configDir := "/etc/myapp"
	configFile := "config.json"
	
	// ok: rule-use-filepath-join
	configPath := filepath.Join(configDir, configFile)
	
	info, err := os.Stat(configPath)
	if err != nil {
		fmt.Println("Error accessing file:", err)
		return
	}
	
	mode := info.Mode().Perm()
	fmt.Printf("File %s has permissions: %o\n", configPath, mode)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	// Using filepath.Join with conditional path components
	baseDir := "/var/data"
	env := "production"
	var dataDir string
	
	if env == "production" {
		dataDir = "prod"
	} else {
		dataDir = "dev"
	}
	
	// ok: rule-use-filepath-join
	fullPath := filepath.Join(baseDir, dataDir, "config.json")
	
	data, err := ioutil.ReadFile(fullPath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Println(string(data))
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("File path joining examples")
}