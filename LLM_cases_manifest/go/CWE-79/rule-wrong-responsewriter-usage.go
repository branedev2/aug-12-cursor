package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"text/template" as texttemplate
)

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte("<h1>Hello, " + username + "!</h1>"))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	w.Header().Set("Content-Type", "text/html")
	// ruleid: rule-wrong-responsewriter-usage
	fmt.Fprintf(w, "<div class='comment'>%s</div>", comment)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	content := r.URL.Query().Get("content")
	html := "<article><h2>" + title + "</h2><p>" + content + "</p></article>"
	// ruleid: rule-wrong-responsewriter-usage
	io.WriteString(w, html)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	defer db.Close()
	
	id := r.URL.Query().Get("id")
	var name, bio string
	err := db.QueryRow("SELECT name, bio FROM users WHERE id = ?", id).Scan(&name, &bio)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte(fmt.Sprintf("<h1>%s</h1><div>%s</div>", name, bio)))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	// ruleid: rule-wrong-responsewriter-usage
	fmt.Fprintf(w, "Search results for: <strong>%s</strong>", searchTerm)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("X-Custom-Header")
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte("<div>Header value: " + header + "</div>"))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-data")
	var userData string
	if err == nil {
		userData = cookie.Value
	} else {
		userData = "No user data found"
	}
	// ruleid: rule-wrong-responsewriter-usage
	io.WriteString(w, "<p>User data: "+userData+"</p>")
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.Form.Get("email")
	// ruleid: rule-wrong-responsewriter-usage
	fmt.Fprintf(w, "<p>Thank you! Confirmation email sent to %s</p>", email)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	userAgent := r.UserAgent()
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte("<p>You are using: " + userAgent + "</p>"))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	tmpl := texttemplate.New("page")
	tmpl, _ = tmpl.Parse("<h1>Hello {{.Name}}</h1>")
	data := map[string]string{"Name": r.URL.Query().Get("name")}
	// ruleid: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data) // text/template doesn't escape HTML
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	htmlContent := "<div class='alert'>" + message + "</div>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte(htmlContent))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	var buffer strings.Builder
	buffer.WriteString("<div class='profile'>")
	buffer.WriteString("<h2>Welcome, " + username + "</h2>")
	buffer.WriteString("</div>")
	// ruleid: rule-wrong-responsewriter-usage
	io.WriteString(w, buffer.String())
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	referer := r.Referer()
	// ruleid: rule-wrong-responsewriter-usage
	fmt.Fprintf(w, "<p>You came from: %s</p>", referer)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	filename := r.FormValue("filename")
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte("<p>File uploaded: " + filename + "</p>"))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	comment := r.URL.Query().Get("comment")
	rating := r.URL.Query().Get("rating")
	
	htmlResponse := fmt.Sprintf(`
		<div class="review" data-id="%s">
			<div class="rating">%s/5</div>
			<div class="comment">%s</div>
		</div>
	`, id, rating, comment)
	
	// ruleid: rule-wrong-responsewriter-usage
	w.Write([]byte(htmlResponse))
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	tmpl := template.Must(template.New("welcome").Parse("<h1>Hello, {{.}}!</h1>"))
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, username)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	comment := r.FormValue("comment")
	tmpl := template.Must(template.New("comment").Parse("<div class='comment'>{{.}}</div>"))
	w.Header().Set("Content-Type", "text/html")
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, comment)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	title := r.URL.Query().Get("title")
	content := r.URL.Query().Get("content")
	
	tmpl := template.Must(template.New("article").Parse("<article><h2>{{.Title}}</h2><p>{{.Content}}</p></article>"))
	data := struct {
		Title   string
		Content string
	}{
		Title:   title,
		Content: content,
	}
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	defer db.Close()
	
	id := r.URL.Query().Get("id")
	var name, bio string
	err := db.QueryRow("SELECT name, bio FROM users WHERE id = ?", id).Scan(&name, &bio)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	
	tmpl := template.Must(template.New("profile").Parse("<h1>{{.Name}}</h1><div>{{.Bio}}</div>"))
	data := struct {
		Name string
		Bio  string
	}{
		Name: name,
		Bio:  bio,
	}
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	tmpl := template.Must(template.New("search").Parse("Search results for: <strong>{{.}}</strong>"))
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, searchTerm)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// JSON responses are safe from XSS
	header := r.Header.Get("X-Custom-Header")
	data := map[string]string{"header": header}
	w.Header().Set("Content-Type", "application/json")
	// ok: rule-wrong-responsewriter-usage
	json.NewEncoder(w).Encode(data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user-data")
	var userData string
	if err == nil {
		userData = cookie.Value
	} else {
		userData = "No user data found"
	}
	
	tmpl := template.Must(template.New("user").Parse("<p>User data: {{.}}</p>"))
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, userData)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.Form.Get("email")
	
	tmpl := template.Must(template.New("email").Parse("<p>Thank you! Confirmation email sent to {{.}}</p>"))
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, email)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Plain text response is safe
	userAgent := r.UserAgent()
	w.Header().Set("Content-Type", "text/plain")
	// ok: rule-wrong-responsewriter-usage
	w.Write([]byte("You are using: " + userAgent))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tmpl := template.New("page")
	tmpl, _ = tmpl.Parse("<h1>Hello {{.Name}}</h1>")
	data := map[string]string{"Name": name}
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	tmpl := template.Must(template.New("alert").Parse("<div class='alert'>{{.}}</div>"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, message)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using a predefined set of values is safe
	theme := r.URL.Query().Get("theme")
	validThemes := map[string]bool{"light": true, "dark": true, "blue": true}
	
	if !validThemes[theme] {
		theme = "light" // Default safe value
	}
	
	// ok: rule-wrong-responsewriter-usage
	w.Write([]byte("<div class='theme-" + theme + "'>Content</div>"))
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	referer := r.Referer()
	tmpl := template.Must(template.New("referer").Parse("<p>You came from: {{.}}</p>"))
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, referer)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using a template with multiple fields
	r.ParseMultipartForm(10 << 20)
	filename := r.FormValue("filename")
	filesize := r.FormValue("filesize")
	
	tmpl := template.Must(template.New("upload").Parse(`
		<div class="upload-result">
			<p>File uploaded: {{.Filename}}</p>
			<p>Size: {{.Filesize}} bytes</p>
		</div>
	`))
	
	data := struct {
		Filename string
		Filesize string
	}{
		Filename: filename,
		Filesize: filesize,
	}
	
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data)
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	comment := r.URL.Query().Get("comment")
	rating := r.URL.Query().Get("rating")
	
	tmpl := template.Must(template.New("review").Parse(`
		<div class="review" data-id="{{.ID}}">
			<div class="rating">{{.Rating}}/5</div>
			<div class="comment">{{.Comment}}</div>
		</div>
	`))
	
	data := struct {
		ID      string
		Rating  string
		Comment string
	}{
		ID:      id,
		Rating:  rating,
		Comment: comment,
	}
	
	// ok: rule-wrong-responsewriter-usage
	tmpl.Execute(w, data)
}
// {/fact}