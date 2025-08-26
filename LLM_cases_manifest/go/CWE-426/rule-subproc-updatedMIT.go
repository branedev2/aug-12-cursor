package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	filename := r.URL.Query().Get("filename")
	
	// Direct command injection vulnerability
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("cat", filename)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	command := r.Form.Get("command")
	
	// Command injection with shell
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	path := r.URL.Query().Get("path")
	
	// Command injection with string concatenation
	cmdStr := "ls -la " + path
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", "-c", cmdStr)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input from header
	userAgent := r.Header.Get("User-Agent")
	
	// Command injection with formatted string
	cmdStr := fmt.Sprintf("echo %s > /tmp/user_agents.log", userAgent)
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("bash", "-c", cmdStr)
	err := cmd.Run()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "User agent logged")
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input from cookie
	cookie, err := r.Cookie("preference")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Command injection with user input as command name
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command(cookie.Value)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	host := r.URL.Query().Get("host")
	
	// Command injection with multiple arguments
	args := []string{"-c", "ping -c 1 " + host}
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", args...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	filename := r.Form.Get("filename")
	
	// Command injection with variable in CommandContext
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("grep", "error", filename)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	searchTerm := r.URL.Query().Get("search")
	filename := r.URL.Query().Get("file")
	
	// Command injection with multiple user inputs
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("grep", searchTerm, filename)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input from POST body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}
	
	// Command injection with user input from request body
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("echo", string(body))
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	format := r.URL.Query().Get("format")
	
	// Command injection with string manipulation
	cmdArgs := []string{"-c"}
	if format == "json" {
		cmdArgs = append(cmdArgs, "ls -la --format=json")
	} else {
		cmdArgs = append(cmdArgs, "ls -la --format="+format)
	}
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	username := r.URL.Query().Get("username")
	
	// Command injection with string building
	var cmdBuilder strings.Builder
	cmdBuilder.WriteString("id ")
	cmdBuilder.WriteString(username)
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", "-c", cmdBuilder.String())
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	path := r.URL.Query().Get("path")
	
	// Command injection with conditional logic
	var cmdName string
	var cmdArgs []string
	
	if strings.HasSuffix(path, ".txt") {
		cmdName = "cat"
		cmdArgs = []string{path}
	} else {
		cmdName = "ls"
		cmdArgs = []string{"-la", path}
	}
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command(cmdName, cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	ip := r.URL.Query().Get("ip")
	
	// Command injection with multiple commands
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("sh", "-c", "ping -c 1 "+ip+" && echo 'Ping completed'")
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	filename := r.URL.Query().Get("filename")
	
	// Command injection with relative path
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command("cat", "./"+filename)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	command := r.URL.Query().Get("cmd")
	args := r.URL.Query().Get("args")
	
	// Command injection with separate command and args
	argsList := strings.Split(args, " ")
	
	// ruleid: rule-subproc-updatedMIT
	cmd := exec.Command(command, argsList...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using hardcoded command and arguments
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/ls", "-la", "/var/log")
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it to create a temporary file
	userData := r.URL.Query().Get("data")
	
	// Create a temporary file in a restricted directory
	// ok: rule-subproc-updatedMIT
	f, err := ioutil.TempFile("/tmp", "temp-*.dat")
	if err != nil {
		http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(f.Name())
	
	if _, err := f.WriteString(userData); err != nil {
		http.Error(w, "Error writing to file", http.StatusInternalServerError)
		return
	}
	
	if err := f.Close(); err != nil {
		http.Error(w, "Error closing file", http.StatusInternalServerError)
		return
	}
	
	// Pass the full path to the binary and the name of the temporary file
	cmd := exec.Command("/bin/cat", f.Name())
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input but validate against a whitelist
	action := r.URL.Query().Get("action")
	
	// Whitelist of allowed commands
	allowedActions := map[string][]string{
		"list": {"/bin/ls", "-la", "/public"},
		"date": {"/bin/date"},
		"echo": {"/bin/echo", "Hello, World!"},
	}
	
	// Check if the action is in the whitelist
	cmdArgs, ok := allowedActions[action]
	if !ok {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it to select a predefined command
	fileType := r.URL.Query().Get("type")
	
	var cmdName string
	var cmdArgs []string
	
	// Use a switch statement to select predefined commands
	switch fileType {
	case "text":
		cmdName = "/bin/find"
		cmdArgs = []string{"/var/data", "-name", "*.txt"}
	case "image":
		cmdName = "/bin/find"
		cmdArgs = []string{"/var/data", "-name", "*.jpg", "-o", "-name", "*.png"}
	case "document":
		cmdName = "/bin/find"
		cmdArgs = []string{"/var/data", "-name", "*.pdf", "-o", "-name", "*.doc"}
	default:
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command(cmdName, cmdArgs...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input but hash it to create a safe filename
	filename := r.URL.Query().Get("filename")
	
	// Create a hash of the filename
	hasher := md5.New()
	hasher.Write([]byte(filename))
	hashedName := hex.EncodeToString(hasher.Sum(nil))
	
	// Use the hash to create a safe path
	safePath := filepath.Join("/var/data", hashedName+".txt")
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/cat", safePath)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Using a native Go function instead of OS command
	filename := r.URL.Query().Get("filename")
	
	// Validate the filename against a whitelist of allowed files
	allowedFiles := map[string]bool{
		"data1.txt": true,
		"data2.txt": true,
		"data3.txt": true,
	}
	
	if !allowedFiles[filename] {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	
	// Use native Go file operations instead of OS commands
	// ok: rule-subproc-updatedMIT
	data, err := ioutil.ReadFile(filepath.Join("/var/data", filename))
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	
	w.Write(data)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it to select from predefined arguments
	sortOrder := r.URL.Query().Get("sort")
	
	var sortArg string
	
	// Map user input to predefined arguments
	switch sortOrder {
	case "name":
		sortArg = "-n"
	case "time":
		sortArg = "-t"
	case "size":
		sortArg = "-S"
	default:
		sortArg = ""
	}
	
	// Construct command with validated argument
	args := []string{"-la"}
	if sortArg != "" {
		args = append(args, sortArg)
	}
	args = append(args, "/var/data")
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/ls", args...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Using a constant command with no user input
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/date", "+%Y-%m-%d %H:%M:%S")
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "Current time: %s", output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it for application logic, not command execution
	format := r.URL.Query().Get("format")
	
	// Execute a fixed command
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/ls", "-la", "/var/data")
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	// Use the user input for formatting the output, not for the command
	if format == "html" {
		fmt.Fprintf(w, "<pre>%s</pre>", output)
	} else {
		w.Write(output)
	}
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Using environment variables for configuration
	logDir := os.Getenv("LOG_DIRECTORY")
	if logDir == "" {
		logDir = "/var/log" // Default value
	}
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/ls", "-la", logDir)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it to create a file with native Go functions
	content := r.URL.Query().Get("content")
	
	// Create a temporary file with Go's native functions
	// ok: rule-subproc-updatedMIT
	f, err := ioutil.TempFile("/tmp", "user-content-*.txt")
	if err != nil {
		http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(f.Name())
	
	if _, err := f.WriteString(content); err != nil {
		http.Error(w, "Error writing to file", http.StatusInternalServerError)
		return
	}
	
	if err := f.Close(); err != nil {
		http.Error(w, "Error closing file", http.StatusInternalServerError)
		return
	}
	
	fmt.Fprintf(w, "File created successfully: %s", f.Name())
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using a configuration file to get command parameters
	configFile, err := os.Open("/etc/app/commands.conf")
	if err != nil {
		http.Error(w, "Error opening configuration file", http.StatusInternalServerError)
		return
	}
	defer configFile.Close()
	
	scanner := bufio.NewScanner(configFile)
	scanner.Scan()
	cmdLine := scanner.Text()
	
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		http.Error(w, "Invalid command configuration", http.StatusInternalServerError)
		return
	}
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command(parts[0], parts[1:]...)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input but use it to select a file from a restricted directory
	fileID := r.URL.Query().Get("id")
	
	// Validate that the ID is numeric
	for _, char := range fileID {
		if char < '0' || char > '9' {
			http.Error(w, "Invalid file ID", http.StatusBadRequest)
			return
		}
	}
	
	// Construct a safe filename based on the validated ID
	safeFilename := "file_" + fileID + ".txt"
	safePath := filepath.Join("/var/data", safeFilename)
	
	// ok: rule-subproc-updatedMIT
	cmd := exec.Command("/bin/cat", safePath)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}
	
	w.Write(output)
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using a native Go function to implement functionality
	// that would otherwise require an OS command
	dirPath := "/var/data"
	
	// ok: rule-subproc-updatedMIT
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "Error reading directory", http.StatusInternalServerError)
		return
	}
	
	var result strings.Builder
	for _, file := range files {
		result.WriteString(fmt.Sprintf("%s\t%d\t%s\n", file.Mode(), file.Size(), file.Name()))
	}
	
	fmt.Fprintf(w, result.String())
}
// {/fact}

// {fact rule=untrusted-search-path@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using a predefined set of commands with no user input
	commands := []struct {
		name string
		args []string
	}{
		{"/bin/hostname", nil},
		{"/bin/date", nil},
		{"/bin/uname", []string{"-a"}},
	}
	
	var result strings.Builder
	
	for _, cmd := range commands {
		// ok: rule-subproc-updatedMIT
		output, err := exec.Command(cmd.name, cmd.args...).Output()
		if err != nil {
			result.WriteString(fmt.Sprintf("Error executing %s: %v\n", cmd.name, err))
			continue
		}
		result.WriteString(fmt.Sprintf("%s output:\n%s\n", cmd.name, output))
	}
	
	fmt.Fprintf(w, result.String())
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