package main

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_1() {
	// Using http.FileServer directly on a directory
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/files/", http.FileServer(http.Dir("/var/www/files")))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_2() {
	// Using http.FileServer with StripPrefix but still exposing directory listing
	fileServer := http.FileServer(http.Dir("./static"))
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/static/", http.StripPrefix("/static/", fileServer))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_3() {
	// Using http.FileServer in a custom mux
	mux := http.NewServeMux()
	// ruleid: rule-httptrace-fileserver-as-handler
	mux.Handle("/assets/", http.FileServer(http.Dir("./public")))
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_4() {
	// Using http.FileServer with a variable path
	docRoot := "./documents"
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/docs/", http.StripPrefix("/docs/", http.FileServer(http.Dir(docRoot))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_5() {
	// Using http.FileServer at root path
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/", http.FileServer(http.Dir("./webroot")))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_6() {
	// Using http.FileServer with multiple handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", apiHandler)
	// ruleid: rule-httptrace-fileserver-as-handler
	mux.Handle("/downloads/", http.StripPrefix("/downloads/", http.FileServer(http.Dir("./files"))))
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_7() {
	// Using http.FileServer with a function that returns a handler
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/content/", getFileServer("/content/", "./content"))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_8() {
	// Using http.FileServer with a custom server
	mux := http.NewServeMux()
	// ruleid: rule-httptrace-fileserver-as-handler
	mux.Handle("/public/", http.StripPrefix("/public/", http.FileServer(http.Dir("./public"))))
	
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_9() {
	// Using http.FileServer with a variable and function call
	dir := getDocumentRoot()
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(dir))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_10() {
	// Using http.FileServer with a custom handler wrapper
	fs := http.FileServer(http.Dir("./uploads"))
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/uploads/", logRequest(http.StripPrefix("/uploads/", fs)))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_11() {
	// Using http.FileServer with a nested directory
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("./static/images"))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_12() {
	// Using http.FileServer with embedded filesystem but still allowing directory listing
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/embedded/", http.StripPrefix("/embedded/", http.FileServer(http.FS(os.DirFS("./data")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_13() {
	// Using http.FileServer with a conditional setup
	env := os.Getenv("ENVIRONMENT")
	var dir string
	if env == "production" {
		dir = "/var/www/production"
	} else {
		dir = "./development"
	}
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/env/", http.StripPrefix("/env/", http.FileServer(http.Dir(dir))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_14() {
	// Using http.FileServer with multiple file servers
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./static/css"))))
	// ruleid: rule-httptrace-fileserver-as-handler
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("./static/js"))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=1}
func bad_case_15() {
	// Using http.FileServer with a goroutine
	go func() {
		mux := http.NewServeMux()
		// ruleid: rule-httptrace-fileserver-as-handler
		mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("./assets"))))
		http.ListenAndServe(":8081", mux)
	}()
	
	http.HandleFunc("/", homeHandler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_1() {
	// Using a custom handler that prevents directory listing
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/files/", http.StripPrefix("/files/", noDirectoryListing(http.FileServer(http.Dir("./files")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_2() {
	// Using a custom handler that checks for specific files
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/downloads/", http.StripPrefix("/downloads/", onlyAllowedFiles(http.FileServer(http.Dir("./downloads")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_3() {
	// Using a custom handler that implements authentication
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/secure/", http.StripPrefix("/secure/", authMiddleware(http.FileServer(http.Dir("./secure")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_4() {
	// Using a custom handler that serves specific files only
	// ok: rule-httptrace-fileserver-as-handler
	http.HandleFunc("/download/", serveSpecificFilesOnly)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_5() {
	// Using a custom file server implementation
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/files/", http.StripPrefix("/files/", customSecureFileServer("./files")))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_6() {
	// Using a handler that serves a single file
	// ok: rule-httptrace-fileserver-as-handler
	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/images/logo.png")
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_7() {
	// Using a custom handler with access control
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/documents/", http.StripPrefix("/documents/", accessControlMiddleware(http.FileServer(http.Dir("./docs")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_8() {
	// Using a handler that serves files with proper content type validation
	// ok: rule-httptrace-fileserver-as-handler
	http.HandleFunc("/download/", serveFilesWithContentTypeCheck)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_9() {
	// Using a custom handler with path validation
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/assets/", http.StripPrefix("/assets/", validatePathMiddleware(http.FileServer(http.Dir("./assets")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_10() {
	// Using a handler that serves only specific file extensions
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/media/", http.StripPrefix("/media/", allowedExtensionsOnly(http.FileServer(http.Dir("./media")), []string{".jpg", ".png", ".gif"})))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_11() {
	// Using a handler with rate limiting
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/downloads/", http.StripPrefix("/downloads/", rateLimitMiddleware(noDirectoryListing(http.FileServer(http.Dir("./downloads"))))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_12() {
	// Using a handler with logging and security checks
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/files/", http.StripPrefix("/files/", logAndSecurityCheck(http.FileServer(http.Dir("./files")))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_13() {
	// Using ServeContent for controlled file serving
	// ok: rule-httptrace-fileserver-as-handler
	http.HandleFunc("/download/file", func(w http.ResponseWriter, r *http.Request) {
		filename := filepath.Clean(r.URL.Query().Get("file"))
		if !isAllowedFile(filename) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		
		file, err := os.Open(filepath.Join("./files", filename))
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer file.Close()
		
		stat, err := file.Stat()
		if err != nil {
			http.Error(w, "File error", http.StatusInternalServerError)
			return
		}
		
		http.ServeContent(w, r, filename, stat.ModTime(), file)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_14() {
	// Using a custom file system implementation with security checks
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/secure/", http.StripPrefix("/secure/", http.FileServer(secureFileSystem{fs: http.Dir("./secure")})))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=exposure-through-directory-listing@v1.0 defects=0}
func good_case_15() {
	// Using a handler with whitelist of allowed files
	// ok: rule-httptrace-fileserver-as-handler
	http.Handle("/public/", http.StripPrefix("/public/", whitelistedFilesOnly(http.FileServer(http.Dir("./public")), []string{
		"index.html",
		"about.html",
		"styles.css",
		"script.js",
		"logo.png",
	})))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// Helper functions and types for the examples

func apiHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API endpoint")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Home page")
}

func getFileServer(prefix, dir string) http.Handler {
	return http.StripPrefix(prefix, http.FileServer(http.Dir(dir)))
}

func getDocumentRoot() string {
	return "./documents"
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}

func noDirectoryListing(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Error(w, "Directory listing not allowed", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func onlyAllowedFiles(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAllowedFile(r.URL.Path) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func isAllowedFile(path string) bool {
	allowedFiles := map[string]bool{
		"file1.pdf": true,
		"file2.pdf": true,
		"image.jpg": true,
	}
	filename := filepath.Base(path)
	return allowedFiles[filename]
}

func authMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if !validateToken(token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func validateToken(token string) bool {
	// Implement token validation logic
	return token != ""
}

func serveSpecificFilesOnly(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	allowedFiles := map[string]string{
		"report.pdf":  "./files/report.pdf",
		"manual.pdf":  "./files/manual.pdf",
		"readme.txt":  "./files/readme.txt",
	}
	
	if filepath, ok := allowedFiles[filename]; ok {
		http.ServeFile(w, r, filepath)
		return
	}
	
	http.Error(w, "File not found", http.StatusNotFound)
}

func customSecureFileServer(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		
		path := filepath.Join(dir, r.URL.Path)
		info, err := os.Stat(path)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		
		if info.IsDir() {
			http.Error(w, "Directory listing not allowed", http.StatusForbidden)
			return
		}
		
		http.ServeFile(w, r, path)
	})
}

func accessControlMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := getUserFromSession(r)
		if !userHasAccess(user, r.URL.Path) {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func getUserFromSession(r *http.Request) string {
	// Get user from session
	return r.Header.Get("X-User")
}

func userHasAccess(user, path string) bool {
	// Check if user has access to the path
	return user != ""
}

func serveFilesWithContentTypeCheck(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	path := filepath.Join("./files", filename)
	
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	
	// Check file extension
	ext := filepath.Ext(filename)
	allowedExts := map[string]bool{
		".pdf":  true,
		".txt":  true,
		".png":  true,
		".jpg":  true,
	}
	
	if !allowedExts[ext] {
		http.Error(w, "File type not allowed", http.StatusForbidden)
		return
	}
	
	http.ServeFile(w, r, path)
}

func validatePathMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "//") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func allowedExtensionsOnly(handler http.Handler, allowedExts []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ext := filepath.Ext(r.URL.Path)
		allowed := false
		for _, allowedExt := range allowedExts {
			if ext == allowedExt {
				allowed = true
				break
			}
		}
		
		if !allowed {
			http.Error(w, "File type not allowed", http.StatusForbidden)
			return
		}
		
		handler.ServeHTTP(w, r)
	})
}

func rateLimitMiddleware(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if !checkRateLimit(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func checkRateLimit(ip string) bool {
	// Implement rate limiting logic
	return true
}

func logAndSecurityCheck(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Access attempt: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		
		// Security checks
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		if strings.Contains(r.URL.Path, "..") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		
		if strings.HasSuffix(r.URL.Path, "/") {
			http.Error(w, "Directory listing not allowed", http.StatusForbidden)
			return
		}
		
		handler.ServeHTTP(w, r)
	})
}

type secureFileSystem struct {
	fs http.FileSystem
}

func (sfs secureFileSystem) Open(name string) (http.File, error) {
	// Prevent directory listing
	if strings.HasSuffix(name, "/") {
		return nil, os.ErrPermission
	}
	
	// Check for path traversal attempts
	if strings.Contains(name, "..") {
		return nil, os.ErrPermission
	}
	
	file, err := sfs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	
	// Check if it's a directory
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if stat.IsDir() {
		file.Close()
		return nil, os.ErrPermission
	}
	
	return file, nil
}

func whitelistedFilesOnly(handler http.Handler, allowedFiles []string) http.Handler {
	allowedMap := make(map[string]bool)
	for _, file := range allowedFiles {
		allowedMap[file] = true
	}
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filename := filepath.Base(r.URL.Path)
		if !allowedMap[filename] {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func main() {
	// This is just a placeholder main function
	fmt.Println("Server examples")
}