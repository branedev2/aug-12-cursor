package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("input")
	
	// Creating a template with user input directly as HTML
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse("<div>" + userInput + "</div>")
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("comment")
	
	// Using user input directly in JavaScript context
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<script>var userComment = "` + userInput + `";</script>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	userStyle := r.URL.Query().Get("style")
	
	// Using user input directly in CSS
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<style>body { ` + userStyle + ` }</style>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("name")
	
	// Creating HTML content with user input and then using it as a template
	htmlContent := "<h1>Hello, " + userInput + "!</h1>"
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(htmlContent)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("id")
	
	// Using user input in HTML attribute
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div id="` + userInput + `">Content</div>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("X-Custom-Header")
	
	// Using HTTP header in template
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div data-header="` + header + `">Header content</div>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-preference")
	var userPref string
	if err == nil {
		userPref = cookie.Value
	}
	
	// Using cookie value in template
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div class="` + userPref + `">User preference</div>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("url")
	
	// Using user input in href attribute
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<a href="` + userInput + `">Click here</a>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("event")
	
	// Using user input in event handler
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<button onclick="` + userInput + `()">Click me</button>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("content")
	
	// Creating dynamic template with user input
	templateString := "<div>" + userInput + "</div>"
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(templateString)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("script")
	
	// Directly embedding user input in script tag
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<script>` + userInput + `</script>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("title")
	
	// Using user input in title tag
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<title>` + userInput + `</title>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("meta")
	
	// Using user input in meta tag
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<meta name="description" content="` + userInput + `">`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("svg")
	
	// Using user input in SVG content
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<svg>` + userInput + `</svg>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	part1 := r.URL.Query().Get("part1")
	part2 := r.URL.Query().Get("part2")
	
	// Concatenating multiple user inputs in template
	tmpl := template.New("example")
	// ruleid: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div>` + part1 + `</div><span>` + part2 + `</span>`)
	
	tmpl.Execute(w, nil)
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("input")
	
	// Using template actions to safely handle user input
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div>{{.}}</div>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("comment")
	
	// Escaping user input for JavaScript context
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<script>var userComment = {{.}};</script>`)
	
	tmpl.Execute(w, template.JSEscapeString(userInput))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	userStyle := r.URL.Query().Get("style")
	
	// Sanitizing CSS input before using it
	sanitizedStyle := sanitizeCSS(userStyle)
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<style>body { {{.}} }</style>`)
	
	tmpl.Execute(w, sanitizedStyle)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("name")
	
	// Using HTML template with proper context
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<h1>Hello, {{.}}!</h1>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("id")
	
	// Using template actions for HTML attributes
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div id="{{.}}">Content</div>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("X-Custom-Header")
	
	// Using template actions for header data
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div data-header="{{.}}">Header content</div>`)
	
	tmpl.Execute(w, header)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-preference")
	var userPref string
	if err == nil {
		userPref = cookie.Value
	}
	
	// Using template actions for cookie values
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div class="{{.}}">User preference</div>`)
	
	tmpl.Execute(w, userPref)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("url")
	
	// Validating URL before using in template
	if !isValidURL(userInput) {
		userInput = "#" // Default safe URL
	}
	
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<a href="{{.}}">Click here</a>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("event")
	
	// Validating event handler name against whitelist
	allowedEvents := map[string]bool{"showAlert": true, "hideElement": true}
	if !allowedEvents[userInput] {
		userInput = "showAlert" // Default safe event
	}
	
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<button onclick="{{.}}()">Click me</button>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("content")
	
	// Using template with data structure
	data := struct {
		Content string
	}{
		Content: userInput,
	}
	
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div>{{.Content}}</div>`)
	
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("script")
	
	// Using proper JS escaping for user input in script
	tmpl := template.New("example").Funcs(template.FuncMap{
		"safeJS": func(s string) template.JS {
			return template.JS(template.JSEscapeString(s))
		},
	})
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<script>console.log({{.}});</script>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	userInput := r.FormValue("title")
	
	// Using template action for title
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<title>{{.}}</title>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("meta")
	
	// Using template action for meta content
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<meta name="description" content="{{.}}">`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("svg")
	
	// Using template action for SVG content with validation
	if !isValidSVGContent(userInput) {
		userInput = "" // Empty if invalid
	}
	
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<svg>{{.}}</svg>`)
	
	tmpl.Execute(w, userInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	part1 := r.URL.Query().Get("part1")
	part2 := r.URL.Query().Get("part2")
	
	// Using template actions for multiple inputs
	data := struct {
		Part1 string
		Part2 string
	}{
		Part1: part1,
		Part2: part2,
	}
	
	tmpl := template.New("example")
	// ok: rule-html-template-insecure-types
	tmpl, _ = tmpl.Parse(`<div>{{.Part1}}</div><span>{{.Part2}}</span>`)
	
	tmpl.Execute(w, data)
}
// {/fact}

// Helper functions for the examples

func sanitizeCSS(input string) string {
	// Simple CSS sanitization example
	// In a real application, use a proper CSS sanitization library
	disallowed := []string{"expression", "javascript:", "behavior", "vbscript", "mocha:", "livescript:"}
	result := strings.ToLower(input)
	
	for _, term := range disallowed {
		result = strings.ReplaceAll(result, term, "")
	}
	
	return result
}

func isValidURL(url string) bool {
	// Simple URL validation example
	// In a real application, use a proper URL validation library
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "/")
}

func isValidSVGContent(content string) bool {
	// Simple SVG validation example
	// In a real application, use a proper SVG validation library
	disallowed := []string{"<script", "javascript:", "onload=", "onerror="}
	lowerContent := strings.ToLower(content)
	
	for _, term := range disallowed {
		if strings.Contains(lowerContent, term) {
			return false
		}
	}
	
	return true
}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/good1", good_case_1)
	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}