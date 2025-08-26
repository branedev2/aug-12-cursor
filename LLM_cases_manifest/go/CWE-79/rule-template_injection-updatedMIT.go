package main

import (
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"strings"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("name")
	
	// Create a template with user input directly marked as HTML
	// ruleid: rule-template_injection-updatedMIT
	tmpl := template.HTML(userInput)
	
	// Render the template
	fmt.Fprintf(w, "<div>%s</div>", tmpl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	r.ParseForm()
	userComment := r.Form.Get("comment")
	
	// Construct a template with user input
	t := template.New("webpage")
	t, _ = t.Parse("<div>{{.}}</div>")
	
	// ruleid: rule-template_injection-updatedMIT
	data := template.HTML(userComment)
	t.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input from header
	userAgent := r.Header.Get("User-Agent")
	
	// Create a template with user input directly marked as JS
	// ruleid: rule-template_injection-updatedMIT
	tmpl := template.JS(userAgent)
	
	// Render the template
	fmt.Fprintf(w, "<script>var agent = %s;</script>", tmpl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input from cookie
	cookie, err := r.Cookie("user-theme")
	var theme string
	if err == nil {
		theme = cookie.Value
	} else {
		theme = "default"
	}
	
	// ruleid: rule-template_injection-updatedMIT
	cssStyle := template.CSS(theme)
	
	// Render the template
	fmt.Fprintf(w, "<style>body { %s }</style>", cssStyle)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	profileURL := r.URL.Query().Get("profile")
	
	// ruleid: rule-template_injection-updatedMIT
	safeURL := template.URL(profileURL)
	
	// Render the template
	fmt.Fprintf(w, "<a href=\"%s\">View Profile</a>", safeURL)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get user input from POST body
	r.ParseForm()
	htmlContent := r.Form.Get("content")
	
	// Process the input (doesn't sanitize)
	processedContent := strings.ReplaceAll(htmlContent, "bad", "good")
	
	// ruleid: rule-template_injection-updatedMIT
	safeHTML := template.HTML(processedContent)
	
	t := template.New("content")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, safeHTML)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("search")
	
	// Construct dynamic HTML with user input
	htmlStr := "<div class='search-results'>Results for: " + userInput + "</div>"
	
	// ruleid: rule-template_injection-updatedMIT
	tmpl := template.HTML(htmlStr)
	
	// Render the template
	t := template.New("search")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, tmpl)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	attributeValue := r.URL.Query().Get("attr")
	
	// ruleid: rule-template_injection-updatedMIT
	safeAttr := template.HTMLAttr(attributeValue)
	
	// Render the template
	fmt.Fprintf(w, "<div %s>Content</div>", safeAttr)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input from multiple sources
	r.ParseForm()
	title := r.Form.Get("title")
	content := r.URL.Query().Get("content")
	
	// Combine inputs
	fullHTML := "<h1>" + title + "</h1><p>" + content + "</p>"
	
	// ruleid: rule-template_injection-updatedMIT
	safeHTML := template.HTML(fullHTML)
	
	// Render the template
	t := template.New("page")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, safeHTML)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	db, _ := sql.Open("mysql", "user:password@/dbname")
	rows, _ := db.Query("SELECT content FROM posts WHERE id = ?", r.URL.Query().Get("id"))
	
	var content string
	if rows.Next() {
		rows.Scan(&content)
	}
	
	// ruleid: rule-template_injection-updatedMIT
	safeContent := template.HTML(content)
	
	// Render the template
	t := template.New("post")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, safeContent)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter and process it
	userInput := r.URL.Query().Get("message")
	processedInput := strings.ToUpper(userInput)
	
	// ruleid: rule-template_injection-updatedMIT
	safeHTML := template.HTML(processedInput)
	
	// Render the template
	fmt.Fprintf(w, "<div>%s</div>", safeHTML)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	r.ParseForm()
	userName := r.Form.Get("username")
	
	// Create a welcome message
	welcomeMsg := fmt.Sprintf("<h2>Welcome, %s!</h2>", userName)
	
	// ruleid: rule-template_injection-updatedMIT
	safeWelcome := template.HTML(welcomeMsg)
	
	// Render the template
	t := template.New("welcome")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, safeWelcome)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	scriptContent := r.URL.Query().Get("script")
	
	// ruleid: rule-template_injection-updatedMIT
	safeScript := template.JS(scriptContent)
	
	// Render the template
	fmt.Fprintf(w, "<script>%s</script>", safeScript)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get user input from multiple parameters
	firstName := r.URL.Query().Get("first")
	lastName := r.URL.Query().Get("last")
	
	// Combine inputs
	fullName := firstName + " " + lastName
	
	// Create HTML with user input
	profileHTML := "<div class='profile'>" + fullName + "</div>"
	
	// ruleid: rule-template_injection-updatedMIT
	safeProfile := template.HTML(profileHTML)
	
	// Render the template
	t := template.New("profile")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, safeProfile)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	cssClass := r.URL.Query().Get("theme")
	
	// Create a CSS rule with user input
	cssRule := "body { background-color: " + cssClass + "; }"
	
	// ruleid: rule-template_injection-updatedMIT
	safeCSS := template.CSS(cssRule)
	
	// Render the template
	fmt.Fprintf(w, "<style>%s</style>", safeCSS)
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("name")
	
	// ok: rule-template_injection-updatedMIT
	// HTML escape the user input
	safeInput := html.EscapeString(userInput)
	
	// Render the template
	fmt.Fprintf(w, "<div>%s</div>", safeInput)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	r.ParseForm()
	userComment := r.Form.Get("comment")
	
	// Construct a template with user input
	t := template.New("webpage")
	t, _ = t.Parse("<div>{{.}}</div>")
	
	// ok: rule-template_injection-updatedMIT
	// Use the input as is, html/template will automatically escape it
	t.Execute(w, userComment)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get user input from header
	userAgent := r.Header.Get("User-Agent")
	
	// ok: rule-template_injection-updatedMIT
	// Use template.JSEscape for JavaScript context
	safeAgent := template.JSEscape(userAgent)
	
	// Render the template
	fmt.Fprintf(w, "<script>var agent = \"%s\";</script>", safeAgent)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get user input from cookie
	cookie, err := r.Cookie("user-theme")
	var theme string
	if err == nil {
		theme = cookie.Value
	} else {
		theme = "default"
	}
	
	// ok: rule-template_injection-updatedMIT
	// Validate against a whitelist of allowed themes
	allowedThemes := map[string]string{
		"dark":  "background-color: #333; color: #fff;",
		"light": "background-color: #fff; color: #333;",
	}
	
	cssStyle, ok := allowedThemes[theme]
	if !ok {
		cssStyle = allowedThemes["light"] // Default to light theme
	}
	
	// Render the template
	fmt.Fprintf(w, "<style>body { %s }</style>", cssStyle)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	profileURL := r.URL.Query().Get("profile")
	
	// ok: rule-template_injection-updatedMIT
	// Validate URL format and domain
	if !strings.HasPrefix(profileURL, "https://trusted-domain.com/") {
		profileURL = "https://trusted-domain.com/default"
	}
	
	// Render the template
	fmt.Fprintf(w, "<a href=\"%s\">View Profile</a>", profileURL)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Get user input from POST body
	r.ParseForm()
	htmlContent := r.Form.Get("content")
	
	// ok: rule-template_injection-updatedMIT
	// Use a template with automatic escaping
	t := template.New("content")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, htmlContent) // html/template automatically escapes
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	userInput := r.URL.Query().Get("search")
	
	// ok: rule-template_injection-updatedMIT
	// Create a template with proper context
	t := template.New("search")
	t, _ = t.Parse("<div class='search-results'>Results for: {{.}}</div>")
	t.Execute(w, userInput) // Automatically escaped
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	attributeValue := r.URL.Query().Get("attr")
	
	// ok: rule-template_injection-updatedMIT
	// Validate attribute against whitelist
	allowedAttrs := map[string]bool{
		"data-theme-dark":  true,
		"data-theme-light": true,
	}
	
	if !allowedAttrs[attributeValue] {
		attributeValue = "data-theme-light" // Default
	}
	
	// Render the template
	fmt.Fprintf(w, "<div %s>Content</div>", attributeValue)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input from multiple sources
	r.ParseForm()
	title := r.Form.Get("title")
	content := r.URL.Query().Get("content")
	
	// ok: rule-template_injection-updatedMIT
	// Use a template with automatic escaping
	t := template.New("page")
	t, _ = t.Parse("<h1>{{.Title}}</h1><p>{{.Content}}</p>")
	
	data := struct {
		Title   string
		Content string
	}{
		Title:   title,
		Content: content,
	}
	
	t.Execute(w, data) // Automatically escaped
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	db, _ := sql.Open("mysql", "user:password@/dbname")
	rows, _ := db.Query("SELECT content FROM posts WHERE id = ?", r.URL.Query().Get("id"))
	
	var content string
	if rows.Next() {
		rows.Scan(&content)
	}
	
	// ok: rule-template_injection-updatedMIT
	// Use a template with automatic escaping
	t := template.New("post")
	t, _ = t.Parse("{{.}}")
	t.Execute(w, content) // Automatically escaped
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter and process it
	userInput := r.URL.Query().Get("message")
	processedInput := strings.ToUpper(userInput)
	
	// ok: rule-template_injection-updatedMIT
	// Use template.HTMLEscapeString for HTML context
	safeHTML := template.HTMLEscapeString(processedInput)
	
	// Render the template
	fmt.Fprintf(w, "<div>%s</div>", safeHTML)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Get user input from form
	r.ParseForm()
	userName := r.Form.Get("username")
	
	// ok: rule-template_injection-updatedMIT
	// Use a template with automatic escaping
	t := template.New("welcome")
	t, _ = t.Parse("<h2>Welcome, {{.}}!</h2>")
	t.Execute(w, userName) // Automatically escaped
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	scriptContent := r.URL.Query().Get("script")
	
	// ok: rule-template_injection-updatedMIT
	// Use template.JSEscape for JavaScript context
	safeScript := template.JSEscape(scriptContent)
	
	// Render the template
	fmt.Fprintf(w, "<script>\"%s\"</script>", safeScript)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Get user input from multiple parameters
	firstName := r.URL.Query().Get("first")
	lastName := r.URL.Query().Get("last")
	
	// ok: rule-template_injection-updatedMIT
	// Use a template with automatic escaping
	t := template.New("profile")
	t, _ = t.Parse("<div class='profile'>{{.First}} {{.Last}}</div>")
	
	data := struct {
		First string
		Last  string
	}{
		First: firstName,
		Last:  lastName,
	}
	
	t.Execute(w, data) // Automatically escaped
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Get user input from URL parameter
	theme := r.URL.Query().Get("theme")
	
	// ok: rule-template_injection-updatedMIT
	// Use a whitelist of allowed CSS values
	allowedThemes := map[string]string{
		"dark":  "background-color: #333; color: #fff;",
		"light": "background-color: #fff; color: #333;",
		"blue":  "background-color: #0066cc; color: #fff;",
	}
	
	cssRule, ok := allowedThemes[theme]
	if !ok {
		cssRule = allowedThemes["light"] // Default to light theme
	}
	
	// Render the template
	fmt.Fprintf(w, "<style>body { %s }</style>", cssRule)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Additional handlers would be defined here
	http.ListenAndServe(":8080", nil)
}