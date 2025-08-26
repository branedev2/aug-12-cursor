package main

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"os"
	"strings"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl := template.New("welcome")
	tmpl, _ = tmpl.Parse("<h1>Hello, {{.}}!</h1>")
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, name)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	tmpl := template.New("comment")
	tmpl, _ = tmpl.Parse(`<div class="comment">{{.}}</div>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, comment)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	tmpl := template.New("profile")
	tmpl, _ = tmpl.Parse(`
		<div class="profile">
			<h2>User Profile</h2>
			<p>Username: {{.}}</p>
		</div>
	`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.ExecuteTemplate(w, "profile", username)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	tmpl := template.New("search")
	tmpl, _ = tmpl.Parse(`
		<div class="search-results">
			<h3>Search Results for: {{.}}</h3>
			<p>No results found.</p>
		</div>
	`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, searchTerm)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	title := r.PostFormValue("title")
	content := r.PostFormValue("content")
	
	data := struct {
		Title   string
		Content string
	}{
		Title:   title,
		Content: content,
	}
	
	tmpl := template.New("article")
	tmpl, _ = tmpl.Parse(`
		<article>
			<h1>{{.Title}}</h1>
			<div>{{.Content}}</div>
		</article>
	`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("message")
	
	// ruleid: rule-reflected-cross-site-scripting
	fmt.Fprintf(w, "<div>%s</div>", userInput)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("X-Custom-Header")
	tmpl := template.New("header")
	tmpl, _ = tmpl.Parse(`<div class="header-value">{{.}}</div>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, header)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-preference")
	var preference string
	if err == nil {
		preference = cookie.Value
	} else {
		preference = "default"
	}
	
	tmpl := template.New("preference")
	tmpl, _ = tmpl.Parse(`<div>Your preference: {{.}}</div>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, preference)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	referer := r.Referer()
	tmpl := template.New("referer")
	tmpl, _ = tmpl.Parse(`<p>You came from: {{.}}</p>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, referer)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	userAgent := r.UserAgent()
	tmpl := template.New("agent")
	tmpl, _ = tmpl.Parse(`<p>Your browser: {{.}}</p>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, userAgent)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	filename := r.MultipartForm.File["upload"][0].Filename
	tmpl := template.New("upload")
	tmpl, _ = tmpl.Parse(`<p>Uploaded file: {{.}}</p>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, filename)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	
	// Even with some processing, it's still vulnerable
	processedEmail := strings.ToLower(strings.TrimSpace(email))
	
	tmpl := template.New("email")
	tmpl, _ = tmpl.Parse(`<p>Your email: {{.}}</p>`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, processedEmail)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	name := r.URL.Query().Get("name")
	
	data := map[string]string{
		"id":   id,
		"name": name,
	}
	
	tmpl := template.New("user")
	tmpl, _ = tmpl.Parse(`
		<div>
			<p>ID: {{.id}}</p>
			<p>Name: {{.name}}</p>
		</div>
	`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	
	// Creating HTML content dynamically
	htmlContent := "<div>" + message + "</div>"
	
	// ruleid: rule-reflected-cross-site-scripting
	fmt.Fprint(w, htmlContent)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	customCSS := r.URL.Query().Get("theme")
	
	tmpl := template.New("theme")
	tmpl, _ = tmpl.Parse(`
		<style>
			body {
				background-color: {{.}};
			}
		</style>
		<p>Custom theme applied!</p>
	`)
	
	// ruleid: rule-reflected-cross-site-scripting
	tmpl.Execute(w, customCSS)
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	
	// ok: rule-reflected-cross-site-scripting
	escapedName := template.HTMLEscapeString(name)
	
	tmpl := template.New("welcome")
	tmpl, _ = tmpl.Parse("<h1>Hello, {{.}}!</h1>")
	tmpl.Execute(w, escapedName)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	
	tmpl := template.New("comment")
	
	// ok: rule-reflected-cross-site-scripting
	tmpl = template.Must(tmpl.Parse(`<div class="comment">{{.}}</div>`))
	
	// Using the auto-escaping feature of html/template
	tmpl.Execute(w, comment)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// Input validation
	if strings.ContainsAny(username, "<>\"'&") {
		http.Error(w, "Invalid username", http.StatusBadRequest)
		return
	}
	
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("profile").Parse(`
		<div class="profile">
			<h2>User Profile</h2>
			<p>Username: {{.}}</p>
		</div>
	`))
	
	tmpl.Execute(w, username)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	
	// ok: rule-reflected-cross-site-scripting
	escapedSearchTerm := html.EscapeString(searchTerm)
	
	fmt.Fprintf(w, `
		<div class="search-results">
			<h3>Search Results for: %s</h3>
			<p>No results found.</p>
		</div>
	`, escapedSearchTerm)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	title := r.PostFormValue("title")
	content := r.PostFormValue("content")
	
	// ok: rule-reflected-cross-site-scripting
	data := struct {
		Title   string
		Content template.HTML // Explicitly marking as pre-escaped HTML
	}{
		Title:   template.HTMLEscapeString(title),
		Content: template.HTML(template.HTMLEscapeString(content)),
	}
	
	tmpl := template.Must(template.New("article").Parse(`
		<article>
			<h1>{{.Title}}</h1>
			<div>{{.Content}}</div>
		</article>
	`))
	
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("message")
	
	// ok: rule-reflected-cross-site-scripting
	sanitizedInput := template.HTMLEscapeString(userInput)
	
	fmt.Fprintf(w, "<div>%s</div>", sanitizedInput)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("X-Custom-Header")
	
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("header").Parse(`<div class="header-value">{{.}}</div>`))
	
	// html/template automatically escapes the input
	tmpl.Execute(w, header)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-preference")
	var preference string
	if err == nil {
		preference = cookie.Value
	} else {
		preference = "default"
	}
	
	// Whitelist validation
	validPreferences := map[string]bool{"light": true, "dark": true, "system": true, "default": true}
	if !validPreferences[preference] {
		preference = "default"
	}
	
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("preference").Parse(`<div>Your preference: {{.}}</div>`))
	tmpl.Execute(w, preference)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	referer := r.Referer()
	
	// ok: rule-reflected-cross-site-scripting
	safeReferer := template.JSEscapeString(referer)
	
	// Using JS escape for JavaScript context
	fmt.Fprintf(w, `
		<script>
			const referer = "%s";
			console.log("Referer:", referer);
		</script>
		<p>You came from: %s</p>
	`, safeReferer, html.EscapeString(referer))
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	userAgent := r.UserAgent()
	
	// Create a template with auto-escaping
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("agent").Parse(`<p>Your browser: {{.}}</p>`))
	
	tmpl.Execute(w, userAgent)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	
	if len(r.MultipartForm.File["upload"]) == 0 {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	
	filename := r.MultipartForm.File["upload"][0].Filename
	
	// ok: rule-reflected-cross-site-scripting
	safeFilename := template.HTMLEscapeString(filename)
	
	fmt.Fprintf(w, "<p>Uploaded file: %s</p>", safeFilename)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	
	// Process and validate email
	processedEmail := strings.ToLower(strings.TrimSpace(email))
	
	// Simple email validation
	if !strings.Contains(processedEmail, "@") || !strings.Contains(processedEmail, ".") {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}
	
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("email").Parse(`<p>Your email: {{.}}</p>`))
	
	tmpl.Execute(w, processedEmail)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	name := r.URL.Query().Get("name")
	
	// ok: rule-reflected-cross-site-scripting
	data := map[string]interface{}{
		"id":   template.HTMLEscapeString(id),
		"name": template.HTMLEscapeString(name),
	}
	
	tmpl := template.Must(template.New("user").Parse(`
		<div>
			<p>ID: {{.id}}</p>
			<p>Name: {{.name}}</p>
		</div>
	`))
	
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	
	// ok: rule-reflected-cross-site-scripting
	tmpl := template.Must(template.New("message").Parse("<div>{{.}}</div>"))
	
	// Using the built-in auto-escaping of html/template
	tmpl.Execute(w, message)
}
// {/fact}

// {fact rule=reflected-cross-site-scripting@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	customCSS := r.URL.Query().Get("theme")
	
	// Validate against a whitelist of allowed values
	allowedThemes := map[string]bool{
		"light":  true,
		"dark":   true,
		"blue":   true,
		"green":  true,
		"purple": true,
	}
	
	// ok: rule-reflected-cross-site-scripting
	if !allowedThemes[customCSS] {
		customCSS = "light" // Default theme
	}
	
	tmpl := template.Must(template.New("theme").Parse(`
		<style>
			body {
				background-color: {{.}};
			}
		</style>
		<p>Custom theme applied!</p>
	`))
	
	tmpl.Execute(w, customCSS)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// ... other handlers
	http.HandleFunc("/good1", good_case_1)
	http.HandleFunc("/good2", good_case_2)
	// ... other handlers
	
	http.ListenAndServe(":8080", nil)
}