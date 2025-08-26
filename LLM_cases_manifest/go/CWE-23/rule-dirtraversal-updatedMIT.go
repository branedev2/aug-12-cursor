package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_1() {
	// Mounting root directory directly
	// ruleid: rule-dirtraversal-updatedMIT
	fileServer := http.FileServer(http.Dir("/"))
	http.Handle("/files/", http.StripPrefix("/files/", fileServer))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_2() {
	// Using root directory with custom handler
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir("/"))
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_3() {
	// Using root directory with variable
	rootDir := "/"
	// ruleid: rule-dirtraversal-updatedMIT
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(rootDir))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_4() {
	// Using root directory in a more complex setup
	mux := http.NewServeMux()
	// ruleid: rule-dirtraversal-updatedMIT
	fileHandler := http.FileServer(http.Dir("/"))
	mux.Handle("/public/", http.StripPrefix("/public/", fileHandler))
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_5() {
	// Using root directory with custom routing
	router := http.NewServeMux()
	// ruleid: rule-dirtraversal-updatedMIT
	staticHandler := http.FileServer(http.Dir("/"))
	router.Handle("/static/", http.StripPrefix("/static/", staticHandler))
	log.Fatal(http.ListenAndServe(":8080", router))
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_6() {
	// Using root directory with conditional logic
	var fileSystemPath string
	if os.Getenv("DEBUG") == "true" {
		fileSystemPath = "/app/debug"
	} else {
		fileSystemPath = "/"
	}
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(fileSystemPath))
	http.Handle("/content/", http.StripPrefix("/content/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_7() {
	// Using root directory with function parameter
	serveFiles := func(path string) {
		// ruleid: rule-dirtraversal-updatedMIT
		fs := http.FileServer(http.Dir("/"))
		http.Handle(path, http.StripPrefix(path, fs))
	}
	serveFiles("/downloads/")
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_8() {
	// Using root directory with multiple handlers
	mux := http.NewServeMux()
	// ruleid: rule-dirtraversal-updatedMIT
	rootFS := http.FileServer(http.Dir("/"))
	mux.Handle("/files/", http.StripPrefix("/files/", rootFS))
	mux.HandleFunc("/api/", apiHandler)
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_9() {
	// Using root directory with string concatenation
	basePath := "/"
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(basePath + ""))
	http.Handle("/resources/", http.StripPrefix("/resources/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_10() {
	// Using root directory with a custom file server wrapper
	serveStaticFiles := func(urlPrefix string, dir string) {
		// ruleid: rule-dirtraversal-updatedMIT
		fileServer := http.FileServer(http.Dir(dir))
		http.Handle(urlPrefix, http.StripPrefix(urlPrefix, fileServer))
	}
	serveStaticFiles("/static/", "/")
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_11() {
	// Using root directory with a switch statement
	env := os.Getenv("ENVIRONMENT")
	var fsPath string
	switch env {
	case "dev":
		fsPath = "/app/dev"
	case "test":
		fsPath = "/app/test"
	default:
		fsPath = "/"
	}
	// ruleid: rule-dirtraversal-updatedMIT
	http.Handle("/data/", http.StripPrefix("/data/", http.FileServer(http.Dir(fsPath))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_12() {
	// Using root directory with a map
	pathMap := map[string]string{
		"images": "/var/www/images",
		"docs":   "/var/www/docs",
		"root":   "/",
	}
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(pathMap["root"]))
	http.Handle("/system/", http.StripPrefix("/system/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_13() {
	// Using root directory with a ternary-like operation
	isDebug := true
	rootPath := map[bool]string{
		true:  "/app/debug",
		false: "/",
	}
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(rootPath[isDebug]))
	http.Handle("/debug/", http.StripPrefix("/debug/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_14() {
	// Using root directory with string formatting
	format := "%s"
	path := "/"
	// ruleid: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(fmt.Sprintf(format, path)))
	http.Handle("/formatted/", http.StripPrefix("/formatted/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
func bad_case_15() {
	// Using root directory with a custom server
	mux := http.NewServeMux()
	// ruleid: rule-dirtraversal-updatedMIT
	mux.Handle("/", http.FileServer(http.Dir("/")))
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_1() {
	// Using a specific directory instead of root
	// ok: rule-dirtraversal-updatedMIT
	fileServer := http.FileServer(http.Dir("/app/static"))
	http.Handle("/files/", http.StripPrefix("/files/", fileServer))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_2() {
	// Using relative path instead of root
	// ok: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_3() {
	// Using specific directory with variable
	staticDir := "/app/assets"
	// ok: rule-dirtraversal-updatedMIT
	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(staticDir))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_4() {
	// Using specific directory in a more complex setup
	mux := http.NewServeMux()
	// ok: rule-dirtraversal-updatedMIT
	fileHandler := http.FileServer(http.Dir("/var/www/public"))
	mux.Handle("/public/", http.StripPrefix("/public/", fileHandler))
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_5() {
	// Using specific directory with custom routing
	router := http.NewServeMux()
	// ok: rule-dirtraversal-updatedMIT
	staticHandler := http.FileServer(http.Dir("./static"))
	router.Handle("/static/", http.StripPrefix("/static/", staticHandler))
	log.Fatal(http.ListenAndServe(":8080", router))
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_6() {
	// Using specific directory with conditional logic
	var fileSystemPath string
	if os.Getenv("DEBUG") == "true" {
		fileSystemPath = "/app/debug"
	} else {
		fileSystemPath = "/app/production"
	}
	// ok: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(fileSystemPath))
	http.Handle("/content/", http.StripPrefix("/content/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_7() {
	// Using specific directory with function parameter
	serveFiles := func(path string, fsPath string) {
		// ok: rule-dirtraversal-updatedMIT
		fs := http.FileServer(http.Dir(fsPath))
		http.Handle(path, http.StripPrefix(path, fs))
	}
	serveFiles("/downloads/", "/var/www/downloads")
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_8() {
	// Using specific directory with multiple handlers
	mux := http.NewServeMux()
	// ok: rule-dirtraversal-updatedMIT
	staticFS := http.FileServer(http.Dir("/app/static"))
	mux.Handle("/files/", http.StripPrefix("/files/", staticFS))
	mux.HandleFunc("/api/", apiHandler)
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_9() {
	// Using specific directory with string concatenation
	basePath := "/var/www"
	// ok: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(basePath + "/resources"))
	http.Handle("/resources/", http.StripPrefix("/resources/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_10() {
	// Using specific directory with a custom file server wrapper
	serveStaticFiles := func(urlPrefix string, dir string) {
		// ok: rule-dirtraversal-updatedMIT
		fileServer := http.FileServer(http.Dir(dir))
		http.Handle(urlPrefix, http.StripPrefix(urlPrefix, fileServer))
	}
	serveStaticFiles("/static/", "/app/static")
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_11() {
	// Using specific directory with a switch statement
	env := os.Getenv("ENVIRONMENT")
	var fsPath string
	switch env {
	case "dev":
		fsPath = "/app/dev"
	case "test":
		fsPath = "/app/test"
	default:
		fsPath = "/app/prod"
	}
	// ok: rule-dirtraversal-updatedMIT
	http.Handle("/data/", http.StripPrefix("/data/", http.FileServer(http.Dir(fsPath))))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_12() {
	// Using specific directory with a map
	pathMap := map[string]string{
		"images": "/var/www/images",
		"docs":   "/var/www/docs",
		"root":   "/var/www/root",
	}
	// ok: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(pathMap["root"]))
	http.Handle("/system/", http.StripPrefix("/system/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_13() {
	// Using a custom FileSystem implementation for security
	type secureFileSystem struct {
		fs http.FileSystem
	}

	func (sfs secureFileSystem) Open(path string) (http.File, error) {
		// Prevent directory traversal attacks
		if strings.Contains(path, "..") {
			return nil, os.ErrPermission
		}
		
		file, err := sfs.fs.Open(path)
		if err != nil {
			return nil, err
		}
		
		return file, nil
	}
	
	// ok: rule-dirtraversal-updatedMIT
	secureFs := secureFileSystem{fs: http.Dir("/var/www/public")}
	http.Handle("/secure/", http.StripPrefix("/secure/", http.FileServer(secureFs)))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_14() {
	// Using filepath.Join for safe path construction
	baseDir := "/app/static"
	// ok: rule-dirtraversal-updatedMIT
	fs := http.FileServer(http.Dir(filepath.Join(baseDir, "public")))
	http.Handle("/public/", http.StripPrefix("/public/", fs))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
func good_case_15() {
	// Using environment variable for safe directory path
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "./default-static" // Fallback to a safe default
	}
	// ok: rule-dirtraversal-updatedMIT
	http.Handle("/", http.FileServer(http.Dir(staticDir)))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// Helper function for examples
func apiHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API endpoint")
}