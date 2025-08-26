package main

import (
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
	"io/ioutil"
	"log"
	"net/url"
	"strings"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_1() {
	// Using CGI handler with Go < 1.6.3 without protecting against Httpoxy
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := new(cgi.Handler)
	handler.Path = "/usr/bin/python"
	handler.Env = append(os.Environ(), "SCRIPT_FILENAME=script.py")
	http.Handle("/cgi-bin/script", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_2() {
	// Using CGI handler with explicit environment passing but still vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/perl",
		Root: "/var/www/cgi-bin",
		Dir:  "/var/www",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_3() {
	// Using CGI handler with custom environment but still vulnerable
	env := []string{
		"DOCUMENT_ROOT=/var/www",
		"SERVER_NAME=example.com",
	}
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/php-cgi",
		Env:  append(os.Environ(), env...),
	}
	http.Handle("/cgi-bin/php", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_4() {
	// Using CGI handler with multiple scripts but all vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	phpHandler := &cgi.Handler{
		Path: "/usr/bin/php-cgi",
		Root: "/var/www/cgi-bin",
	}
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	pythonHandler := &cgi.Handler{
		Path: "/usr/bin/python",
		Root: "/var/www/cgi-bin",
	}
	
	http.Handle("/cgi-bin/php/", phpHandler)
	http.Handle("/cgi-bin/python/", pythonHandler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_5() {
	// Using CGI handler with custom HTTP server but still vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/ruby",
		Root: "/var/www/cgi-bin",
	}
	
	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}
	server.ListenAndServe()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_6() {
	// Using CGI handler with custom arguments but still vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Args: []string{"-u"},
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_7() {
	// Using CGI handler with custom directory but still vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/perl",
		Dir:  "/var/www/custom",
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_8() {
	// Using CGI handler with TLS but still vulnerable
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/php-cgi",
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_9() {
	// Using CGI handler with custom environment variables but still vulnerable
	env := []string{
		"APP_ENV=production",
		"DEBUG=false",
	}
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Env:  append(os.Environ(), env...),
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_10() {
	// Using CGI handler with custom logger but still vulnerable
	logger := log.New(os.Stderr, "CGI: ", log.LstdFlags)
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path:   "/usr/bin/python",
		Logger: logger,
		Root:   "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_11() {
	// Using CGI handler with custom stdin but still vulnerable
	stdin := strings.NewReader("custom input data")
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path:  "/usr/bin/perl",
		Stdin: stdin,
		Root:  "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_12() {
	// Using CGI handler with a wrapper function but still vulnerable
	createHandler := func(scriptPath string) http.Handler {
		// ruleid: rule-blocklist-cgi-updatedMIT
		return &cgi.Handler{
			Path: scriptPath,
			Root: "/var/www/cgi-bin",
		}
	}
	
	http.Handle("/cgi-bin/python", createHandler("/usr/bin/python"))
	http.Handle("/cgi-bin/perl", createHandler("/usr/bin/perl"))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_13() {
	// Using CGI handler with a custom HTTP mux but still vulnerable
	mux := http.NewServeMux()
	
	// ruleid: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Root: "/var/www/cgi-bin",
	}
	
	mux.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_14() {
	// Using CGI handler with path parameters but still vulnerable
	http.HandleFunc("/cgi-bin/", func(w http.ResponseWriter, r *http.Request) {
		script := r.URL.Path[len("/cgi-bin/"):]
		
		// ruleid: rule-blocklist-cgi-updatedMIT
		handler := &cgi.Handler{
			Path: "/usr/bin/" + script,
			Root: "/var/www/cgi-bin",
		}
		
		handler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_15() {
	// Using CGI handler with conditional script selection but still vulnerable
	http.HandleFunc("/cgi-bin/", func(w http.ResponseWriter, r *http.Request) {
		var scriptPath string
		
		if strings.HasSuffix(r.URL.Path, ".py") {
			scriptPath = "/usr/bin/python"
		} else if strings.HasSuffix(r.URL.Path, ".pl") {
			scriptPath = "/usr/bin/perl"
		} else {
			scriptPath = "/usr/bin/php-cgi"
		}
		
		// ruleid: rule-blocklist-cgi-updatedMIT
		handler := &cgi.Handler{
			Path: scriptPath,
			Root: "/var/www/cgi-bin",
		}
		
		handler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_1() {
	// Using CGI handler with Go >= 1.6.3 which is not vulnerable to Httpoxy
	// ok: rule-blocklist-cgi-updatedMIT
	handler := new(cgi.Handler)
	handler.Path = "/usr/bin/python"
	handler.Env = append(os.Environ(), "SCRIPT_FILENAME=script.py")
	// In Go >= 1.6.3, the CGI package automatically filters the Proxy header
	http.Handle("/cgi-bin/script", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_2() {
	// Using CGI handler with explicit filtering of the Proxy header
	// ok: rule-blocklist-cgi-updatedMIT
	http.HandleFunc("/cgi-bin/script", func(w http.ResponseWriter, r *http.Request) {
		// Explicitly delete the Proxy header before processing
		r.Header.Del("Proxy")
		
		handler := &cgi.Handler{
			Path: "/usr/bin/python",
			Root: "/var/www/cgi-bin",
		}
		handler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_3() {
	// Using a custom middleware to filter the Proxy header for all requests
	// ok: rule-blocklist-cgi-updatedMIT
	filterProxyHeader := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Remove the Proxy header to prevent Httpoxy
			r.Header.Del("Proxy")
			next.ServeHTTP(w, r)
		})
	}
	
	handler := &cgi.Handler{
		Path: "/usr/bin/perl",
		Root: "/var/www/cgi-bin",
	}
	
	http.Handle("/cgi-bin/", filterProxyHeader(handler))
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_4() {
	// Using CGI handler with environment variables that explicitly unset HTTP_PROXY
	env := []string{
		"HTTP_PROXY=",  // Explicitly unset HTTP_PROXY
		"http_proxy=",  // Unset lowercase variant too
	}
	
	// ok: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Env:  append(os.Environ(), env...),
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_5() {
	// Using a custom proxy configuration that ignores the HTTP_PROXY environment variable
	// ok: rule-blocklist-cgi-updatedMIT
	customTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // In Go >= 1.6.3 this is safe
	}
	
	client := &http.Client{
		Transport: customTransport,
	}
	
	handler := &cgi.Handler{
		Path: "/usr/bin/php-cgi",
		Root: "/var/www/cgi-bin",
	}
	
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_6() {
	// Using a non-CGI handler approach which is not vulnerable to Httpoxy
	// ok: rule-blocklist-cgi-updatedMIT
	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		// Process the request directly in Go without using CGI
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "success", "data": "example"}`)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_7() {
	// Using a custom proxy setting that overrides any HTTP_PROXY environment variable
	// ok: rule-blocklist-cgi-updatedMIT
	proxyURL, _ := url.Parse("http://trusted-proxy.example.com:8080")
	customTransport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), // Explicitly set proxy, ignoring environment
	}
	
	client := &http.Client{
		Transport: customTransport,
	}
	
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Root: "/var/www/cgi-bin",
	}
	
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_8() {
	// Using a header filter that removes all potentially dangerous headers
	// ok: rule-blocklist-cgi-updatedMIT
	http.HandleFunc("/cgi-bin/script", func(w http.ResponseWriter, r *http.Request) {
		// Remove potentially dangerous headers
		dangerousHeaders := []string{"Proxy", "X-Forwarded-For", "X-Real-IP"}
		for _, header := range dangerousHeaders {
			r.Header.Del(header)
		}
		
		handler := &cgi.Handler{
			Path: "/usr/bin/perl",
			Root: "/var/www/cgi-bin",
		}
		handler.ServeHTTP(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_9() {
	// Using a custom environment that explicitly sets HTTP_PROXY to a trusted value
	env := []string{
		"HTTP_PROXY=http://trusted-proxy.internal:8080",  // Set to trusted value
		"http_proxy=http://trusted-proxy.internal:8080",  // Set lowercase variant too
	}
	
	// ok: rule-blocklist-cgi-updatedMIT
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Env:  env, // Replace environment instead of appending
		Root: "/var/www/cgi-bin",
	}
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_10() {
	// Using a reverse proxy instead of CGI
	// ok: rule-blocklist-cgi-updatedMIT
	targetURL, _ := url.Parse("http://localhost:9000")
	proxy := http.NewSingleHostReverseProxy(targetURL)
	
	http.Handle("/api/", proxy)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_11() {
	// Using an alternative to CGI for executing scripts
	// ok: rule-blocklist-cgi-updatedMIT
	http.HandleFunc("/run/script", func(w http.ResponseWriter, r *http.Request) {
		// Execute script directly instead of using CGI
		cmd := exec.Command("/usr/bin/python", "script.py")
		output, err := cmd.CombinedOutput()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(output)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_12() {
	// Using a static file server instead of CGI for serving content
	// ok: rule-blocklist-cgi-updatedMIT
	fs := http.FileServer(http.Dir("/var/www/html"))
	http.Handle("/", fs)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_13() {
	// Using a custom handler that implements the http.Handler interface
	// ok: rule-blocklist-cgi-updatedMIT
	type CustomHandler struct{}
	
	func (h *CustomHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
		// Custom handling logic without CGI
		fmt.Fprintf(w, "Hello, World!")
	}
	
	handler := &CustomHandler{}
	http.Handle("/custom/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_14() {
	// Using a Go web framework instead of CGI
	// ok: rule-blocklist-cgi-updatedMIT
	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		// API implementation in pure Go
		data := map[string]string{
			"message": "Hello from Go API",
			"status":  "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_15() {
	// Using a secure proxy configuration with explicit environment control
	// ok: rule-blocklist-cgi-updatedMIT
	secureEnv := []string{}
	
	// Copy only safe environment variables
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "HTTP_PROXY=") && 
		   !strings.HasPrefix(env, "http_proxy=") {
			secureEnv = append(secureEnv, env)
		}
	}
	
	handler := &cgi.Handler{
		Path: "/usr/bin/python",
		Env:  secureEnv,
		Root: "/var/www/cgi-bin",
	}
	
	http.Handle("/cgi-bin/", handler)
	http.ListenAndServe(":8080", nil)
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("Server starting...")
}