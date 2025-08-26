package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"

	"github.com/asaskevich/govalidator"
	"github.com/dop251/goja"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	
	// ruleid: rule-code-injection
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "Output: %s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	command := r.Form.Get("command")
	args := r.Form.Get("args")
	
	// ruleid: rule-code-injection
	cmd := exec.Command(command, args)
	cmd.Run()
	fmt.Fprintf(w, "Command executed")
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	userInput := r.Header.Get("X-Custom-Command")
	
	// ruleid: rule-code-injection
	syscall.Exec("/bin/sh", []string{"/bin/sh", "-c", userInput}, os.Environ())
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	script := r.URL.Query().Get("script")
	vm := goja.New()
	
	// ruleid: rule-code-injection
	_, err := vm.RunString(script)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "Script executed")
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Command string `json:"command"`
	}
	
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-code-injection
	cmd := exec.Command("sh", "-c", data.Command)
	cmd.Run()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("command")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-code-injection
	proc, err := os.StartProcess("/bin/bash", []string{"-c", cookie.Value}, &os.ProcAttr{})
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	proc.Wait()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	cmdName := r.URL.Query().Get("cmd")
	cmdArgs := strings.Split(r.URL.Query().Get("args"), ",")
	
	// ruleid: rule-code-injection
	cmd := exec.Command(cmdName, cmdArgs...)
	output, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	
	// Some processing that doesn't sanitize
	command = strings.TrimSpace(command)
	
	// ruleid: rule-code-injection
	attr := &syscall.ProcAttr{
		Dir:   ".",
		Env:   os.Environ(),
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
	}
	pid, err := syscall.ForkExec("/bin/sh", []string{"/bin/sh", "-c", command}, attr)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "Process ID: %d", pid)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	scriptContent := r.FormValue("script")
	vm := goja.New()
	
	// ruleid: rule-code-injection
	vm.RunString(scriptContent)
	fmt.Fprintf(w, "Script executed successfully")
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]string
	
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-code-injection
	cmd := exec.Command(requestData["binary"], requestData["argument"])
	cmd.Run()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	command := ""
	for _, part := range r.URL.Query()["parts"] {
		command += part + " "
	}
	
	// ruleid: rule-code-injection
	cmd := exec.Command("bash", "-c", command)
	cmd.Run()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	
	// ruleid: rule-code-injection
	attr := &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	}
	proc, _ := os.StartProcess("/bin/sh", []string{"/bin/sh", "-c", userAgent}, attr)
	proc.Wait()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	var data struct {
		ScriptCode string `json:"code"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	vm := goja.New()
	
	// ruleid: rule-code-injection
	_, err = vm.RunScript("user-script.js", data.ScriptCode)
	if err != nil {
		fmt.Fprintf(w, "Script error: %v", err)
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	if referer == "" {
		http.Error(w, "Referer header required", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-code-injection
	syscall.StartProcess("/usr/bin/curl", []string{"curl", referer}, &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2},
	})
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	for key, values := range r.Form {
		if key == "command" && len(values) > 0 {
			// ruleid: rule-code-injection
			cmd := exec.Command("sh", "-c", values[0])
			cmd.Run()
			break
		}
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=code-injection@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using a whitelist of allowed commands
	command := r.URL.Query().Get("cmd")
	allowedCommands := map[string]bool{"ls": true, "date": true, "echo": true}
	
	// ok: rule-code-injection
	if allowedCommands[command] {
		cmd := exec.Command(command)
		output, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(w, "Error: %v", err)
			return
		}
		fmt.Fprintf(w, "Output: %s", output)
	} else {
		fmt.Fprintf(w, "Command not allowed")
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userInput := r.Form.Get("input")
	
	// Using command with fixed arguments, user input as data not command
	// ok: rule-code-injection
	cmd := exec.Command("echo", userInput)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "Output: %s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	userInput := r.Header.Get("X-Custom-Input")
	
	// Sanitizing input with regexp
	// ok: rule-code-injection
	re := regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	if !re.MatchString(userInput) {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	cmd := exec.Command("grep", userInput, "logfile.txt")
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	script := r.URL.Query().Get("script")
	
	// Using a sandbox with limited functionality
	vm := goja.New()
	
	// ok: rule-code-injection
	vm.Set("console", map[string]interface{}{
		"log": func(call goja.FunctionCall) goja.Value {
			return goja.Undefined()
		},
	})
	
	// Disable access to sensitive objects
	vm.Set("require", goja.Undefined())
	vm.Set("process", goja.Undefined())
	
	_, err := vm.RunString(script)
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Command string `json:"command"`
	}
	
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Using a switch statement with fixed commands
	// ok: rule-code-injection
	var cmd *exec.Cmd
	switch data.Command {
	case "list_files":
		cmd = exec.Command("ls", "-la")
	case "show_date":
		cmd = exec.Command("date")
	case "disk_space":
		cmd = exec.Command("df", "-h")
	default:
		http.Error(w, "Command not recognized", http.StatusBadRequest)
		return
	}
	
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("filename")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Sanitizing input by escaping special characters
	// ok: rule-code-injection
	filename := html.EscapeString(cookie.Value)
	cmd := exec.Command("cat", filename)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	cmdName := r.URL.Query().Get("cmd")
	
	// Validating input with govalidator
	// ok: rule-code-injection
	if !govalidator.IsAlphanumeric(cmdName) {
		http.Error(w, "Invalid command name", http.StatusBadRequest)
		return
	}
	
	// Using the validated input in a fixed command structure
	cmd := exec.Command("find", "/var/logs", "-name", cmdName)
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	command := r.URL.Query().Get("cmd")
	
	// Using a whitelist of allowed patterns
	// ok: rule-code-injection
	allowedPatterns := []*regexp.Regexp{
		regexp.MustCompile(`^date$`),
		regexp.MustCompile(`^ls [a-zA-Z0-9_\-\.\/]+$`),
		regexp.MustCompile(`^cat [a-zA-Z0-9_\-\.\/]+$`),
	}
	
	allowed := false
	for _, pattern := range allowedPatterns {
		if pattern.MatchString(command) {
			allowed = true
			break
		}
	}
	
	if allowed {
		parts := strings.Split(command, " ")
		var cmd *exec.Cmd
		if len(parts) > 1 {
			cmd = exec.Command(parts[0], parts[1:]...)
		} else {
			cmd = exec.Command(parts[0])
		}
		output, _ := cmd.Output()
		fmt.Fprintf(w, "%s", output)
	} else {
		http.Error(w, "Command not allowed", http.StatusForbidden)
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	scriptContent := r.FormValue("script")
	
	// Using a custom interpreter with limited functionality
	// ok: rule-code-injection
	safeInterpreter := func(script string) string {
		// This is a simplified example of a safe interpreter
		// In real scenarios, use a proper sandbox or DSL
		result := "Script executed safely"
		return result
	}
	
	output := safeInterpreter(scriptContent)
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]string
	
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestData)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Using predefined commands with user input as parameters
	// ok: rule-code-injection
	action := requestData["action"]
	switch action {
	case "search":
		term := requestData["term"]
		// Sanitize the search term
		term = regexp.MustCompile(`[^a-zA-Z0-9 ]`).ReplaceAllString(term, "")
		cmd := exec.Command("grep", term, "/var/log/app.log")
		output, _ := cmd.Output()
		fmt.Fprintf(w, "%s", output)
	default:
		http.Error(w, "Action not supported", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Using command arguments properly separated, not shell interpolation
	searchTerm := r.URL.Query().Get("term")
	
	// ok: rule-code-injection
	cmd := exec.Command("find", ".", "-name", searchTerm)
	output, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(w, "Error: %v", err)
		return
	}
	fmt.Fprintf(w, "%s", output)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	userAgent := r.Header.Get("User-Agent")
	
	// Logging user agent safely, not executing it
	// ok: rule-code-injection
	fmt.Fprintf(w, "Your User-Agent: %s", userAgent)
	
	// If we need to do something with the user agent
	cmd := exec.Command("echo", "User agent logged")
	cmd.Run()
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	var data struct {
		ScriptCode string `json:"code"`
	}
	
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Using a template engine instead of direct script execution
	// ok: rule-code-injection
	template := fmt.Sprintf("Template with data: %s", html.EscapeString(data.ScriptCode))
	fmt.Fprintf(w, template)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	referer := r.Header.Get("Referer")
	
	// Validating URL before using it
	// ok: rule-code-injection
	if govalidator.IsURL(referer) {
		// Using the URL safely, not as a command
		fmt.Fprintf(w, "Referer URL: %s", referer)
	} else {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
	}
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userInput := r.Form.Get("input")
	
	// Using string replacement to sanitize input
	// ok: rule-code-injection
	sanitized := strings.ReplaceAll(userInput, ";", "")
	sanitized = strings.ReplaceAll(sanitized, "&", "")
	sanitized = strings.ReplaceAll(sanitized, "|", "")
	
	// Using the sanitized input as data, not as a command
	fmt.Fprintf(w, "Your input: %s", sanitized)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Add more handlers as needed
	http.ListenAndServe(":8080", nil)
}