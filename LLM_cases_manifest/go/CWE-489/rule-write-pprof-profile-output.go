package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

// BAD CASES - Vulnerable code examples

// bad_case_1 directly writes CPU profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	pprof.StartCPUProfile(w)
	time.Sleep(30 * time.Second)
	pprof.StopCPUProfile()
}
// {/fact}

// bad_case_2 writes heap profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	pprof.WriteHeapProfile(w)
}
// {/fact}

// bad_case_3 writes goroutine profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	p := pprof.Lookup("goroutine")
	p.WriteTo(w, 1)
}
// {/fact}

// bad_case_4 writes block profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	p := pprof.Lookup("block")
	p.WriteTo(w, 1)
}
// {/fact}

// bad_case_5 writes mutex profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	p := pprof.Lookup("mutex")
	p.WriteTo(w, 1)
}
// {/fact}

// bad_case_6 writes threadcreate profile to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	p := pprof.Lookup("threadcreate")
	p.WriteTo(w, 1)
}
// {/fact}

// bad_case_7 writes heap profile to HTTP response with conditional logic
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	profileType := r.URL.Query().Get("type")
	if profileType == "heap" {
		// ruleid: rule-write-pprof-profile-output
		pprof.WriteHeapProfile(w)
	} else {
		fmt.Fprintf(w, "Invalid profile type")
	}
}
// {/fact}

// bad_case_8 writes profile to HTTP response in a goroutine
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	go func() {
		// ruleid: rule-write-pprof-profile-output
		p := pprof.Lookup("heap")
		p.WriteTo(w, 1)
	}()
}
// {/fact}

// bad_case_9 writes CPU profile to HTTP response with error handling
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	err := pprof.StartCPUProfile(w)
	if err != nil {
		http.Error(w, "Could not start CPU profile", http.StatusInternalServerError)
		return
	}
	defer pprof.StopCPUProfile()
	time.Sleep(5 * time.Second)
}
// {/fact}

// bad_case_10 uses Gin framework to write profile to response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_10() {
	router := gin.Default()
	router.GET("/debug/profile", func(c *gin.Context) {
		// ruleid: rule-write-pprof-profile-output
		p := pprof.Lookup("heap")
		p.WriteTo(c.Writer, 1)
	})
	router.Run(":8080")
}
// {/fact}

// bad_case_11 uses Echo framework to write profile to response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_11() {
	e := echo.New()
	e.GET("/debug/profile", func(c echo.Context) error {
		// ruleid: rule-write-pprof-profile-output
		p := pprof.Lookup("goroutine")
		p.WriteTo(c.Response().Writer, 1)
		return nil
	})
	e.Start(":8080")
}
// {/fact}

// bad_case_12 uses Gorilla Mux to write profile to response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_12() {
	r := mux.NewRouter()
	r.HandleFunc("/debug/profile", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: rule-write-pprof-profile-output
		pprof.WriteHeapProfile(w)
	})
	http.ListenAndServe(":8080", r)
}
// {/fact}

// bad_case_13 writes multiple profiles to HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	profileType := r.URL.Query().Get("type")
	switch profileType {
	case "heap":
		// ruleid: rule-write-pprof-profile-output
		pprof.WriteHeapProfile(w)
	case "goroutine":
		// ruleid: rule-write-pprof-profile-output
		p := pprof.Lookup("goroutine")
		p.WriteTo(w, 1)
	default:
		fmt.Fprintf(w, "Unknown profile type")
	}
}
// {/fact}

// bad_case_14 writes profile to HTTP response with deferred cleanup
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// ruleid: rule-write-pprof-profile-output
	err := pprof.StartCPUProfile(w)
	if err != nil {
		log.Printf("Failed to start CPU profile: %v", err)
		return
	}
	defer func() {
		pprof.StopCPUProfile()
		log.Println("CPU profile stopped")
	}()
	
	// Simulate work
	for i := 0; i < 1000; i++ {
		_ = fmt.Sprintf("Working: %d", i)
	}
}
// {/fact}

// bad_case_15 writes profile to HTTP response based on environment check
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	env := os.Getenv("ENVIRONMENT")
	// Even checking for non-production is not safe
	if env != "production" {
		// ruleid: rule-write-pprof-profile-output
		p := pprof.Lookup("heap")
		p.WriteTo(w, 1)
	} else {
		fmt.Fprintf(w, "Profiling disabled in production")
	}
}
// {/fact}

// GOOD CASES - Secure code examples

// good_case_1 writes profile to a file instead of HTTP response
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	f, err := os.Create("cpu.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	
	// ok: rule-write-pprof-profile-output
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	
	time.Sleep(30 * time.Second)
	fmt.Fprintf(w, "Profile written to file")
}
// {/fact}

// good_case_2 writes heap profile to a file
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	f, err := os.Create("heap.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	
	// ok: rule-write-pprof-profile-output
	pprof.WriteHeapProfile(f)
	
	fmt.Fprintf(w, "Heap profile written to file")
}
// {/fact}

// good_case_3 writes goroutine profile to a file
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	f, err := os.Create("goroutine.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	
	// ok: rule-write-pprof-profile-output
	p := pprof.Lookup("goroutine")
	p.WriteTo(f, 1)
	
	fmt.Fprintf(w, "Goroutine profile written to file")
}
// {/fact}

// good_case_4 uses standard pprof HTTP handlers behind authentication
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_4() {
	// ok: rule-write-pprof-profile-output
	// This is safe because we're using the standard pprof HTTP handlers
	// which are designed for debugging and should be protected
	router := http.NewServeMux()
	
	// Add authentication middleware
	pprofHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "admin" || password != os.Getenv("ADMIN_PASSWORD") {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	})
	
	// Register pprof handlers on the default ServeMux
	// These are imported by the "net/http/pprof" package
	router.Handle("/debug/pprof/", pprofHandler)
	
	http.ListenAndServe(":8080", router)
}
// {/fact}

// good_case_5 returns profile data summary instead of raw profile
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// ok: rule-write-pprof-profile-output
	// Instead of writing the profile directly, we analyze it and return a summary
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	fmt.Fprintf(w, "Memory Stats Summary:\n")
	fmt.Fprintf(w, "Alloc: %v MiB\n", memStats.Alloc/1024/1024)
	fmt.Fprintf(w, "TotalAlloc: %v MiB\n", memStats.TotalAlloc/1024/1024)
	fmt.Fprintf(w, "Sys: %v MiB\n", memStats.Sys/1024/1024)
	fmt.Fprintf(w, "NumGC: %v\n", memStats.NumGC)
}
// {/fact}

// good_case_6 writes profile to a temporary file and serves the file content
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Create a temporary file
	f, err := os.CreateTemp("", "profile-*.pprof")
	if err != nil {
		http.Error(w, "Could not create temporary file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	
	// ok: rule-write-pprof-profile-output
	p := pprof.Lookup("heap")
	p.WriteTo(f, 1)
	
	// Reset file pointer to beginning
	f.Seek(0, 0)
	
	// Read file content and serve it with appropriate headers
	content, err := os.ReadFile(f.Name())
	if err != nil {
		http.Error(w, "Could not read profile data", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Disposition", "attachment; filename=heap.pprof")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(content)
}
// {/fact}

// good_case_7 restricts profile access based on IP address
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_7() {
	// ok: rule-write-pprof-profile-output
	// This is safe because we're restricting access to localhost only
	router := http.NewServeMux()
	
	// Add IP restriction middleware
	pprofHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only allow requests from localhost
		ip := r.RemoteAddr
		if ip != "127.0.0.1" && ip != "::1" && ip != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		http.DefaultServeMux.ServeHTTP(w, r)
	})
	
	// Register pprof handlers
	router.Handle("/debug/pprof/", pprofHandler)
	
	http.ListenAndServe("127.0.0.1:8080", router) // Only bind to localhost
}
// {/fact}

// good_case_8 uses a channel to communicate profile data instead of direct HTTP write
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// ok: rule-write-pprof-profile-output
	// Create a temporary file for the profile
	f, err := os.CreateTemp("", "cpu-*.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	
	pprof.StartCPUProfile(f)
	time.Sleep(5 * time.Second)
	pprof.StopCPUProfile()
	
	// Provide a download link instead of direct profile data
	fmt.Fprintf(w, "Profile collected. <a href=\"/download-profile?file=%s\">Download profile</a>", f.Name())
}
// {/fact}

// good_case_9 uses Gin framework with proper profile handling
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_9() {
	router := gin.Default()
	
	router.GET("/debug/profile", func(c *gin.Context) {
		// ok: rule-write-pprof-profile-output
		// Create a file for the profile instead of writing to response
		f, err := os.Create("heap.pprof")
		if err != nil {
			c.String(http.StatusInternalServerError, "Could not create profile file")
			return
		}
		defer f.Close()
		
		p := pprof.Lookup("heap")
		p.WriteTo(f, 1)
		
		c.String(http.StatusOK, "Profile written to file")
	})
	
	router.Run(":8080")
}
// {/fact}

// good_case_10 uses Echo framework with proper profile handling
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_10() {
	e := echo.New()
	
	e.GET("/debug/profile", func(c echo.Context) error {
		// ok: rule-write-pprof-profile-output
		// Create a file for the profile instead of writing to response
		f, err := os.Create("goroutine.pprof")
		if err != nil {
			return c.String(http.StatusInternalServerError, "Could not create profile file")
		}
		defer f.Close()
		
		p := pprof.Lookup("goroutine")
		p.WriteTo(f, 1)
		
		return c.String(http.StatusOK, "Profile written to file")
	})
	
	e.Start(":8080")
}
// {/fact}

// good_case_11 uses feature flag to completely disable profiling in production
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// ok: rule-write-pprof-profile-output
	// Check if we're in development mode
	if os.Getenv("ENVIRONMENT") != "development" {
		http.Error(w, "Profiling is disabled in production", http.StatusForbidden)
		return
	}
	
	// In development, write to a file instead of response
	f, err := os.Create("profile.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	
	pprof.WriteHeapProfile(f)
	fmt.Fprintf(w, "Profile written to file")
}
// {/fact}

// good_case_12 uses a separate admin server for profiling
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_12() {
	// Main application server
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		http.ListenAndServe(":8080", nil)
	}()
	
	// ok: rule-write-pprof-profile-output
	// Separate admin server on a different port, only accessible internally
	go func() {
		adminMux := http.NewServeMux()
		
		// Add authentication middleware
		pprofHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok || username != "admin" || password != os.Getenv("ADMIN_PASSWORD") {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.DefaultServeMux.ServeHTTP(w, r)
		})
		
		adminMux.Handle("/debug/pprof/", pprofHandler)
		http.ListenAndServe("127.0.0.1:8081", adminMux) // Internal admin port
	}()
}
// {/fact}

// good_case_13 uses a buffer to collect profile data before processing
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// ok: rule-write-pprof-profile-output
	// Use a file instead of direct HTTP response
	f, err := os.Create("mutex.pprof")
	if err != nil {
		http.Error(w, "Could not create profile file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	
	p := pprof.Lookup("mutex")
	p.WriteTo(f, 1)
	
	// Process the profile data and return a summary
	fmt.Fprintf(w, "Mutex profile collected and saved to file")
}
// {/fact}

// good_case_14 uses environment-specific configuration
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_14() {
	// ok: rule-write-pprof-profile-output
	// In production, disable direct profiling endpoints
	if os.Getenv("ENVIRONMENT") == "production" {
		// Set up regular production routes without profiling
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Production server")
		})
	} else {
		// In development, enable profiling but write to files
		http.HandleFunc("/debug/profile", func(w http.ResponseWriter, r *http.Request) {
			f, err := os.Create("profile.pprof")
			if err != nil {
				http.Error(w, "Could not create profile file", http.StatusInternalServerError)
				return
			}
			defer f.Close()
			
			pprof.WriteHeapProfile(f)
			fmt.Fprintf(w, "Profile written to file")
		})
	}
	
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// good_case_15 uses a dedicated profiling service
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_15() {
	// ok: rule-write-pprof-profile-output
	// This is a dedicated internal profiling service
	// It collects profiles and stores them for later analysis
	
	profileStore := make(map[string]string) // In a real app, this would be persistent storage
	
	http.HandleFunc("/collect-profile", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the request
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != os.Getenv("INTERNAL_API_KEY") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Create a unique ID for this profile
		profileID := fmt.Sprintf("profile-%d", time.Now().UnixNano())
		filename := profileID + ".pprof"
		
		// Save the profile to a file
		f, err := os.Create(filename)
		if err != nil {
			http.Error(w, "Could not create profile file", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		
		pprof.WriteHeapProfile(f)
		
		// Store the profile location
		profileStore[profileID] = filename
		
		// Return the profile ID
		fmt.Fprintf(w, profileID)
	})
	
	http.ListenAndServe("127.0.0.1:8082", nil) // Internal service only
}
// {/fact}

func main() {
	// Main function not implemented as it's not needed for the examples
}