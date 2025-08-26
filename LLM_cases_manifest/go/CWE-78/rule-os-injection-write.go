package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("command")
	
	// Create a command
	cmd := exec.Command("bash", "-c", "echo 'Running command'")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(userInput)) // Vulnerable: writing unsanitized user input to command stdin
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	r.ParseForm()
	userCommand := r.Form.Get("cmd")
	
	cmd := exec.Command("sh")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	io.WriteString(stdin, userCommand) // Vulnerable: writing unsanitized user input to command stdin
	stdin.Close()
	
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "Output: %s", output)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input from header
	userScript := r.Header.Get("X-Custom-Script")
	
	cmd := exec.Command("python", "-c", "print('Hello')")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(userScript)) // Vulnerable: writing unsanitized user input from header
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Script executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input from cookie
	cookie, err := r.Cookie("userCommand")
	if err != nil {
		return
	}
	
	cmd := exec.Command("powershell.exe")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	io.WriteString(stdin, cookie.Value) // Vulnerable: writing unsanitized cookie value
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "PowerShell command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input from POST body
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()
	
	cmd := exec.Command("node")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write(body) // Vulnerable: writing unsanitized POST body
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Node.js script executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get multiple parameters and join them
	command := r.URL.Query().Get("cmd")
	args := r.URL.Query().Get("args")
	
	fullCommand := command + " " + args
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(fullCommand)) // Vulnerable: writing unsanitized joined input
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user input and do minimal transformation
	userInput := r.URL.Query().Get("input")
	transformedInput := strings.ReplaceAll(userInput, "script", "") // Insufficient sanitization
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(transformedInput)) // Vulnerable: insufficient sanitization
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL path parameter
	pathParts := strings.Split(r.URL.Path, "/")
	userInput := pathParts[len(pathParts)-1]
	
	cmd := exec.Command("perl")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	io.WriteString(stdin, "print('"+userInput+"');") // Vulnerable: unsanitized path parameter
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Perl script executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input and encode it (but still vulnerable)
	userInput := r.URL.Query().Get("script")
	encodedInput := strings.ReplaceAll(userInput, "'", "\\'") // Insufficient escaping
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(encodedInput)) // Vulnerable: insufficient escaping
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get user input indirectly
	r.ParseForm()
	filename := r.Form.Get("filename")
	content, _ := os.ReadFile(filename) // Read file content based on user input
	
	cmd := exec.Command("python")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write(content) // Vulnerable: writing content from user-specified file
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Python script executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input with conditional logic
	action := r.URL.Query().Get("action")
	var commandInput string
	
	if action == "backup" {
		commandInput = "tar -czf backup.tar.gz " + r.URL.Query().Get("dir")
	} else {
		commandInput = r.URL.Query().Get("customCmd")
	}
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(commandInput)) // Vulnerable: writing unsanitized input after conditional logic
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get user input from multiple sources
	header := r.Header.Get("X-Command")
	param := r.URL.Query().Get("param")
	
	commandString := header + " " + param
	
	cmd := exec.Command("sh")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	io.WriteString(stdin, commandString) // Vulnerable: writing unsanitized combined input
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input and process in a loop
	params := r.URL.Query()["commands"]
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	for _, param := range params {
		// ruleid: rule-os-injection-write
		stdin.Write([]byte(param + "\n")) // Vulnerable: writing unsanitized input in a loop
	}
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Commands executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get user input and use with a template
	username := r.URL.Query().Get("username")
	
	template := "echo 'Checking user: %s'; id %s; whoami"
	commandStr := fmt.Sprintf(template, username, username)
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ruleid: rule-os-injection-write
	stdin.Write([]byte(commandStr)) // Vulnerable: writing formatted string with unsanitized input
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "User checked")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get user input and use a writer wrapper
	userInput := r.URL.Query().Get("input")
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	writer := bufio.NewWriter(stdin)
	// ruleid: rule-os-injection-write
	writer.WriteString(userInput) // Vulnerable: writing unsanitized input via a writer
	writer.Flush()
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Use hardcoded command only
	cmd := exec.Command("bash", "-c", "echo 'Running fixed command'")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte("echo Hello World")) // Safe: using hardcoded command
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Use a whitelist of allowed commands
	userChoice := r.URL.Query().Get("option")
	
	allowedCommands := map[string]string{
		"list": "ls -la",
		"date": "date",
		"disk": "df -h",
	}
	
	command, exists := allowedCommands[userChoice]
	if !exists {
		command = "echo 'Invalid option'"
	}
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte(command)) // Safe: using command from whitelist
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Use native Go functionality instead of shell commands
	filename := r.URL.Query().Get("file")
	
	// Instead of writing a command to get file info, use Go's native functionality
	fileInfo, err := os.Stat(filename)
	
	// ok: rule-os-injection-write
	// No Write() to command stdin used, using native Go functionality
	
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
	} else {
		fmt.Fprintf(w, "File size: %d bytes", fileInfo.Size())
	}
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Generate a unique identifier for user-provided filename
	originalFilename := r.URL.Query().Get("filename")
	
	// Generate a random filename instead of using user input directly
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	safeFilename := hex.EncodeToString(randomBytes) + filepath.Ext(originalFilename)
	
	// ok: rule-os-injection-write
	// No Write() to command stdin with user input
	
	fmt.Fprintf(w, "File will be saved as: %s", safeFilename)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Use command arguments instead of stdin for fixed operations
	cmd := exec.Command("grep", "error", "/var/log/app.log")
	
	// ok: rule-os-injection-write
	// No Write() to command stdin with user input
	
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "Log errors: %s", output)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Validate input against strict pattern before use
	userInput := r.URL.Query().Get("id")
	
	// Strict validation - only allow digits
	matched, _ := regexp.MatchString("^[0-9]+$", userInput)
	if !matched {
		fmt.Fprintf(w, "Invalid input")
		return
	}
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte("echo User ID: " + userInput)) // Safe: input strictly validated to digits only
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Use a fixed script with parameterized values
	username := r.URL.Query().Get("username")
	
	// Instead of injecting the username into a command, pass it as an argument
	cmd := exec.Command("python", "-c", "import sys; print(f'Hello, {sys.argv[1]}')", username)
	
	// ok: rule-os-injection-write
	// No Write() to command stdin with user input
	
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "Output: %s", output)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Use full path to executable and fixed commands
	cmd := exec.Command("/usr/bin/bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte("echo 'System status'; uptime; df -h")) // Safe: using hardcoded commands
	stdin.Close()
	
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "System info: %s", output)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Use a configuration file instead of direct user input
	configFile := "/etc/app/commands.conf"
	
	// Read commands from a trusted configuration file
	commandBytes, _ := os.ReadFile(configFile)
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write(commandBytes) // Safe: commands from trusted configuration
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Configuration commands executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Use environment variables for configuration
	scriptPath := os.Getenv("APP_SCRIPT_PATH")
	if scriptPath == "" {
		scriptPath = "/usr/local/bin/default_script.sh" // Default if not configured
	}
	
	// Execute the script directly instead of via stdin
	cmd := exec.Command(scriptPath)
	
	// ok: rule-os-injection-write
	// No Write() to command stdin with user input
	
	cmd.Run()
	fmt.Fprintf(w, "Script executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Use a template with fixed placeholders
	template := "echo 'Report for %s'; date; echo 'End of report'"
	
	// Get the current date in a safe format
	currentDate := "2023-10-15" // In a real app, would use time.Now().Format("2006-01-02")
	
	commandStr := fmt.Sprintf(template, currentDate)
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte(commandStr)) // Safe: using template with safe, internally generated values
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Report generated")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Use a builder pattern with validation
	commandBuilder := strings.Builder{}
	
	// Add fixed commands to the builder
	commandBuilder.WriteString("echo 'Starting process'\n")
	commandBuilder.WriteString("date\n")
	commandBuilder.WriteString("echo 'Process complete'\n")
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte(commandBuilder.String())) // Safe: using builder with hardcoded commands
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Process executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Use an enum approach for commands
	action := r.URL.Query().Get("action")
	
	var commandStr string
	switch action {
	case "backup":
		commandStr = "tar -czf /tmp/backup.tar.gz /var/www/html"
	case "cleanup":
		commandStr = "find /tmp -type f -name '*.tmp' -delete"
	case "status":
		commandStr = "systemctl status nginx"
	default:
		commandStr = "echo 'Unknown action'"
	}
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte(commandStr)) // Safe: using predefined commands based on validated input
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "Action executed")
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Use a dedicated library function instead of shell commands
	
	// ok: rule-os-injection-write
	// No Write() to command stdin used, using native functionality
	
	// Example: Instead of using 'find' command, use filepath.Walk
	matches := []string{}
	filepath.Walk("/var/log", func(path string, info os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".log") {
			matches = append(matches, path)
		}
		return nil
	})
	
	fmt.Fprintf(w, "Found logs: %v", matches)
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Use a command factory with fixed commands
	getCommand := func(cmdType string) string {
		commands := map[string]string{
			"network": "ifconfig",
			"disk":    "df -h",
			"memory":  "free -m",
			"cpu":     "top -bn1 | head -n 20",
		}
		cmd, exists := commands[cmdType]
		if !exists {
			return "echo 'Invalid command type'"
		}
		return cmd
	}
	
	cmdType := r.URL.Query().Get("type")
	commandStr := getCommand(cmdType)
	
	cmd := exec.Command("bash")
	stdin, _ := cmd.StdinPipe()
	
	// ok: rule-os-injection-write
	stdin.Write([]byte(commandStr)) // Safe: using predefined commands from a factory
	stdin.Close()
	
	cmd.Run()
	fmt.Fprintf(w, "System info retrieved")
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Add other handlers
	http.ListenAndServe(":8080", nil)
}