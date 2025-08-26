package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	
	// True positive imports will include net/http/pprof
	// True negative examples will not include this import or will use it safely
	
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// BAD CASES - These should be detected as vulnerabilities

// bad_case_1 imports pprof and starts a standard HTTP server
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_1() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"net/http"
		"net/http/pprof"
	)
	
	func main() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_2 imports pprof in a production API server
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_2() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"encoding/json"
		"net/http"
		_ "net/http/pprof" // Still exposes debug endpoints even with blank import
	)
	
	func main() {
		http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
			users := []string{"user1", "user2", "user3"}
			json.NewEncoder(w).Encode(users)
		})
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_3 imports pprof with gorilla mux router
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_3() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"net/http/pprof"
		"github.com/gorilla/mux"
	)
	
	func main() {
		r := mux.NewRouter()
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Welcome to our service")
		})
		
		// pprof handlers are automatically registered to default mux
		http.ListenAndServe(":8080", r)
	}
}
// {/fact}

// bad_case_4 imports pprof in a microservice
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_4() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"encoding/json"
		"log"
		"net/http"
		_ "net/http/pprof"
	)
	
	type Order struct {
		ID     string `json:"id"`
		Amount float64 `json:"amount"`
	}
	
	func main() {
		http.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
			orders := []Order{
				{ID: "order1", Amount: 25.50},
				{ID: "order2", Amount: 15.75},
			}
			json.NewEncoder(w).Encode(orders)
		})
		
		log.Println("Starting order service on :8080")
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_5 imports pprof in a web application with multiple routes
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"html/template"
		"net/http"
		"net/http/pprof"
	)
	
	func main() {
		http.HandleFunc("/", homeHandler)
		http.HandleFunc("/about", aboutHandler)
		http.HandleFunc("/contact", contactHandler)
		
		http.ListenAndServe(":8080", nil)
	}
	
	func homeHandler(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("home").Parse("<h1>Home Page</h1>"))
		tmpl.Execute(w, nil)
	}
	
	func aboutHandler(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("about").Parse("<h1>About Us</h1>"))
		tmpl.Execute(w, nil)
	}
	
	func contactHandler(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("contact").Parse("<h1>Contact Us</h1>"))
		tmpl.Execute(w, nil)
	}
}
// {/fact}

// bad_case_6 imports pprof in a REST API
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_6() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"encoding/json"
		"net/http"
		_ "net/http/pprof"
		"github.com/gorilla/mux"
	)
	
	func main() {
		r := mux.NewRouter()
		r.HandleFunc("/api/products", getProducts).Methods("GET")
		r.HandleFunc("/api/products/{id}", getProduct).Methods("GET")
		
		http.ListenAndServe(":8080", r)
	}
	
	func getProducts(w http.ResponseWriter, r *http.Request) {
		products := []map[string]interface{}{
			{"id": 1, "name": "Product 1", "price": 19.99},
			{"id": 2, "name": "Product 2", "price": 29.99},
		}
		json.NewEncoder(w).Encode(products)
	}
	
	func getProduct(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		product := map[string]interface{}{"id": id, "name": "Product " + id, "price": 19.99}
		json.NewEncoder(w).Encode(product)
	}
}
// {/fact}

// bad_case_7 imports pprof in a server with TLS
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_7() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"log"
		"net/http"
		_ "net/http/pprof"
	)
	
	func main() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Secure server with TLS"))
		})
		
		log.Println("Starting secure server on :443")
		err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	}
}
// {/fact}

// bad_case_8 imports pprof in a server with custom middleware
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_8() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"log"
		"net/http"
		"net/http/pprof"
		"time"
	)
	
	func loggingMiddleware(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
		})
	}
	
	func main() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, world!"))
		})
		
		handler := loggingMiddleware(mux)
		http.ListenAndServe(":8080", handler)
	}
}
// {/fact}

// bad_case_9 imports pprof in a server with database connection
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_9() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"database/sql"
		"fmt"
		"log"
		"net/http"
		_ "net/http/pprof"
		_ "github.com/lib/pq"
	)
	
	func main() {
		db, err := sql.Open("postgres", "postgres://user:password@localhost/dbname?sslmode=disable")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		
		http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
			rows, err := db.Query("SELECT id, name FROM users LIMIT 10")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			
			fmt.Fprintf(w, "Users list")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_10 imports pprof in a server with context
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_10() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"context"
		"fmt"
		"net/http"
		_ "net/http/pprof"
		"time"
	)
	
	func main() {
		srv := &http.Server{
			Addr:    ":8080",
			Handler: http.DefaultServeMux,
		}
		
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("ListenAndServe(): %v\n", err)
			}
		}()
		
		// Graceful shutdown
		stop := make(chan os.Signal, 1)
		<-stop
		
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Printf("Server shutdown failed: %v\n", err)
		}
	}
}
// {/fact}

// bad_case_11 imports pprof in a server with custom handler
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_11() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		_ "net/http/pprof"
	)
	
	type CustomHandler struct{}
	
	func (h *CustomHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Custom handler response")
	}
	
	func main() {
		handler := &CustomHandler{}
		http.Handle("/custom", handler)
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Default handler")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_12 imports pprof in a server with JSON API
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_12() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"encoding/json"
		"net/http"
		_ "net/http/pprof"
	)
	
	type Response struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	
	func main() {
		http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := Response{
				Status:  "success",
				Message: "API is running",
			}
			json.NewEncoder(w).Encode(resp)
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_13 imports pprof in a server with file server
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_13() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"net/http"
		_ "net/http/pprof"
	)
	
	func main() {
		fs := http.FileServer(http.Dir("./static"))
		http.Handle("/static/", http.StripPrefix("/static/", fs))
		
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "./static/index.html")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// bad_case_14 imports pprof in a server with multiple ports
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_14() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		_ "net/http/pprof"
	)
	
	func main() {
		// Public API
		go func() {
			http.HandleFunc("/api/public", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "Public API")
			})
			http.ListenAndServe(":8080", nil)
		}()
		
		// Admin API
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Admin API")
		})
		http.ListenAndServe(":8081", adminMux)
	}
}
// {/fact}

// bad_case_15 imports pprof in a server with custom router
// {fact rule=detect-activated-debug-feature@v1.0 defects=1}
func bad_case_15() {
	// ruleid: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		_ "net/http/pprof"
		"strings"
	)
	
	type Router struct {
		routes map[string]http.HandlerFunc
	}
	
	func NewRouter() *Router {
		return &Router{
			routes: make(map[string]http.HandlerFunc),
		}
	}
	
	func (r *Router) HandleFunc(path string, handler http.HandlerFunc) {
		r.routes[path] = handler
	}
	
	func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
		for path, handler := range r.routes {
			if strings.HasPrefix(req.URL.Path, path) {
				handler(w, req)
				return
			}
		}
		http.NotFound(w, req)
	}
	
	func main() {
		router := NewRouter()
		router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Home page")
		})
		
		http.ListenAndServe(":8080", router)
	}
}
// {/fact}

// GOOD CASES - These should not be detected as vulnerabilities

// good_case_1 doesn't import pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_1() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
	)
	
	func main() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_2 uses a custom mux without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_2() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"github.com/gorilla/mux"
	)
	
	func main() {
		r := mux.NewRouter()
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Welcome to our service")
		})
		
		http.ListenAndServe(":8080", r)
	}
}
// {/fact}

// good_case_3 uses a custom profiling endpoint with authentication
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_3() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"runtime"
		"runtime/pprof"
		"os"
	)
	
	func isAuthorized(r *http.Request) bool {
		username, password, ok := r.BasicAuth()
		if !ok {
			return false
		}
		return username == os.Getenv("ADMIN_USER") && password == os.Getenv("ADMIN_PASSWORD")
	}
	
	func secureProfileHandler(w http.ResponseWriter, r *http.Request) {
		if !isAuthorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		// Custom profiling logic
		pprof.Lookup("heap").WriteTo(w, 1)
	}
	
	func main() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		// Secure profiling endpoint with authentication
		http.HandleFunc("/admin/profiling", secureProfileHandler)
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_4 uses a separate server for profiling on localhost only
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_4() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"log"
		"net/http"
		"runtime"
		"runtime/pprof"
	)
	
	func main() {
		// Main application server
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "Hello, World!")
			})
			http.ListenAndServe(":8080", nil)
		}()
		
		// Custom debug server only accessible from localhost
		debugMux := http.NewServeMux()
		debugMux.HandleFunc("/debug/heap", func(w http.ResponseWriter, r *http.Request) {
			pprof.Lookup("heap").WriteTo(w, 1)
		})
		
		log.Println("Debug server listening on localhost:6060")
		http.ListenAndServe("localhost:6060", debugMux)
	}
}
// {/fact}

// good_case_5 uses runtime/pprof directly for file-based profiling
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_5() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"log"
		"net/http"
		"os"
		"runtime/pprof"
	)
	
	func main() {
		// CPU profiling to file
		f, err := os.Create("cpu_profile.prof")
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()
		
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
		
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		http.ListenAndServe(":8080", nil)
		
		// Heap profile to file
		f2, err := os.Create("heap_profile.prof")
		if err != nil {
			log.Fatal("could not create heap profile: ", err)
		}
		defer f2.Close()
		
		if err := pprof.WriteHeapProfile(f2); err != nil {
			log.Fatal("could not write heap profile: ", err)
		}
	}
}
// {/fact}

// good_case_6 uses a feature flag to conditionally enable profiling in dev environments
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_6() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"log"
		"net/http"
		"os"
		"runtime/pprof"
	)
	
	func main() {
		// Main application handlers
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		// Only enable profiling in development environment
		if os.Getenv("ENVIRONMENT") == "development" {
			log.Println("Enabling profiling endpoints for development")
			
			http.HandleFunc("/debug/profile", func(w http.ResponseWriter, r *http.Request) {
				pprof.Lookup("goroutine").WriteTo(w, 1)
			})
			
			// Only bind to localhost in development
			go http.ListenAndServe("localhost:6060", nil)
		}
		
		// Main server
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_7 uses a third-party monitoring solution instead of pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_7() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"time"
	)
	
	// Custom metrics collector
	type MetricsCollector struct {
		requestCount   int
		responseTime   time.Duration
		lastCollection time.Time
	}
	
	func NewMetricsCollector() *MetricsCollector {
		return &MetricsCollector{
			lastCollection: time.Now(),
		}
	}
	
	func (m *MetricsCollector) TrackRequest(duration time.Duration) {
		m.requestCount++
		m.responseTime += duration
	}
	
	func (m *MetricsCollector) GetStats() map[string]interface{} {
		avgResponseTime := float64(m.responseTime) / float64(m.requestCount) / float64(time.Millisecond)
		requestsPerSecond := float64(m.requestCount) / time.Since(m.lastCollection).Seconds()
		
		return map[string]interface{}{
			"requests":            m.requestCount,
			"avg_response_time_ms": avgResponseTime,
			"requests_per_second": requestsPerSecond,
		}
	}
	
	func main() {
		metrics := NewMetricsCollector()
		
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			fmt.Fprintf(w, "Hello, World!")
			metrics.TrackRequest(time.Since(start))
		})
		
		http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			// Authenticate the metrics endpoint
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != os.Getenv("METRICS_API_KEY") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metrics.GetStats())
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_8 uses a separate process for monitoring
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_8() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"os"
		"os/exec"
	)
	
	func main() {
		// Start a separate monitoring process if needed
		if os.Getenv("ENABLE_MONITORING") == "true" {
			cmd := exec.Command("./monitoring-agent", 
				"--app-name", "myservice",
				"--port", "8080")
			
			err := cmd.Start()
			if err != nil {
				fmt.Printf("Failed to start monitoring: %v\n", err)
			}
		}
		
		// Main application without pprof
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_9 uses a custom router with health checks but no pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_9() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"encoding/json"
		"fmt"
		"net/http"
		"time"
	)
	
	type HealthStatus struct {
		Status    string `json:"status"`
		Timestamp string `json:"timestamp"`
		Version   string `json:"version"`
	}
	
	func main() {
		// Health check endpoint
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			status := HealthStatus{
				Status:    "UP",
				Timestamp: time.Now().Format(time.RFC3339),
				Version:   "1.0.0",
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(status)
		})
		
		// Main application routes
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_10 uses a custom middleware chain without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_10() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"log"
		"net/http"
		"time"
	)
	
	func loggingMiddleware(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
		})
	}
	
	func securityHeadersMiddleware(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			next.ServeHTTP(w, r)
		})
	}
	
	func main() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		// Apply middleware chain
		handler := loggingMiddleware(securityHeadersMiddleware(mux))
		http.ListenAndServe(":8080", handler)
	}
}
// {/fact}

// good_case_11 uses a database connection without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_11() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"database/sql"
		"fmt"
		"log"
		"net/http"
		_ "github.com/lib/pq"
	)
	
	func main() {
		db, err := sql.Open("postgres", "postgres://user:password@localhost/dbname?sslmode=disable")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		
		http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
			rows, err := db.Query("SELECT id, name FROM users LIMIT 10")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rows.Close()
			
			fmt.Fprintf(w, "Users list")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_12 uses graceful shutdown without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_12() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"context"
		"fmt"
		"net/http"
		"os"
		"os/signal"
		"syscall"
		"time"
	)
	
	func main() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello, World!")
		})
		
		server := &http.Server{
			Addr:    ":8080",
			Handler: mux,
		}
		
		// Start server in a goroutine
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("Server error: %v\n", err)
			}
		}()
		
		// Wait for interrupt signal
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		<-stop
		
		// Graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			fmt.Printf("Server shutdown error: %v\n", err)
		}
	}
}
// {/fact}

// good_case_13 uses a file server without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_13() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
	)
	
	func main() {
		// Serve static files
		fs := http.FileServer(http.Dir("./static"))
		http.Handle("/static/", http.StripPrefix("/static/", fs))
		
		// Serve index page
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, "Welcome to our website!")
		})
		
		http.ListenAndServe(":8080", nil)
	}
}
// {/fact}

// good_case_14 uses a custom router implementation without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_14() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
		"strings"
	)
	
	type Route struct {
		Method  string
		Pattern string
		Handler http.HandlerFunc
	}
	
	type Router struct {
		routes []Route
	}
	
	func NewRouter() *Router {
		return &Router{routes: []Route{}}
	}
	
	func (r *Router) AddRoute(method, pattern string, handler http.HandlerFunc) {
		r.routes = append(r.routes, Route{
			Method:  method,
			Pattern: pattern,
			Handler: handler,
		})
	}
	
	func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
		for _, route := range r.routes {
			if route.Method == req.Method && strings.HasPrefix(req.URL.Path, route.Pattern) {
				route.Handler(w, req)
				return
			}
		}
		http.NotFound(w, req)
	}
	
	func main() {
		router := NewRouter()
		
		router.AddRoute("GET", "/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Home page")
		})
		
		router.AddRoute("GET", "/about", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "About page")
		})
		
		http.ListenAndServe(":8080", router)
	}
}
// {/fact}

// good_case_15 uses a server with multiple ports without pprof
// {fact rule=detect-activated-debug-feature@v1.0 defects=0}
func good_case_15() {
	// ok: rule-pprof-debug-exposure-updatedMIT
	import (
		"fmt"
		"net/http"
	)
	
	func main() {
		// Public API
		go func() {
			publicMux := http.NewServeMux()
			publicMux.HandleFunc("/api/public", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "Public API")
			})
			http.ListenAndServe(":8080", publicMux)
		}()
		
		// Admin API with basic auth
		adminMux := http.NewServeMux()
		adminMux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
			// Basic authentication
			username, password, ok := r.BasicAuth()
			if !ok || username != "admin" || password != "secret" {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin API"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			
			fmt.Fprintf(w, "Admin API")
		})
		
		// Only bind admin API to localhost
		http.ListenAndServe("localhost:8081", adminMux)
	}
}
// {/fact}