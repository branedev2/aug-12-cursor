package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
	"github.com/labstack/echo/v4"
)

// True Positives (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_1() {
	r := mux.NewRouter()
	// ruleid: rule-unrestricted-request-mapping
	r.HandleFunc("/api/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fmt.Fprintf(w, "User ID: %v", vars["id"])
	})
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_2() {
	e := echo.New()
	// ruleid: rule-unrestricted-request-mapping
	e.Any("/api/data", func(c echo.Context) error {
		return c.String(http.StatusOK, "This endpoint accepts any HTTP method")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_3() {
	router := gin.Default()
	// ruleid: rule-unrestricted-request-mapping
	router.Any("/admin/settings", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Admin settings accessed",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_4() {
	http.HandleFunc("/api/sensitive-data", func(w http.ResponseWriter, r *http.Request) {
		// ruleid: rule-unrestricted-request-mapping
		data := map[string]string{"key": "sensitive value"}
		json.NewEncoder(w).Encode(data)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_5() {
	r := mux.NewRouter()
	// ruleid: rule-unrestricted-request-mapping
	r.PathPrefix("/api/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API endpoint: %s", r.URL.Path)
	}))
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_6() {
	e := echo.New()
	// ruleid: rule-unrestricted-request-mapping
	e.Match([]string{"GET", "POST", "PUT", "DELETE", "PATCH"}, "/user/profile", func(c echo.Context) error {
		return c.String(http.StatusOK, "Profile endpoint")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_7() {
	router := gin.Default()
	// ruleid: rule-unrestricted-request-mapping
	router.Handle("*", "/payment", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "payment processed",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_8() {
	r := mux.NewRouter()
	apiRouter := r.PathPrefix("/api").Subrouter()
	// ruleid: rule-unrestricted-request-mapping
	apiRouter.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Order management endpoint")
	})
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_9() {
	e := echo.New()
	// ruleid: rule-unrestricted-request-mapping
	e.Add("*", "/admin/users", func(c echo.Context) error {
		return c.String(http.StatusOK, "User management")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_10() {
	mux := http.NewServeMux()
	// ruleid: rule-unrestricted-request-mapping
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Configuration endpoint")
	})
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_11() {
	router := gin.Default()
	// ruleid: rule-unrestricted-request-mapping
	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(200, gin.H{"message": "API endpoint"})
			return
		}
		c.JSON(404, gin.H{"message": "Not found"})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_12() {
	e := echo.New()
	api := e.Group("/api")
	// ruleid: rule-unrestricted-request-mapping
	api.Any("/documents", func(c echo.Context) error {
		return c.String(http.StatusOK, "Document management")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_13() {
	r := mux.NewRouter()
	// ruleid: rule-unrestricted-request-mapping
	r.MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		return strings.HasPrefix(r.URL.Path, "/api/reports")
	}).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Reports API")
	})
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_14() {
	router := gin.Default()
	adminGroup := router.Group("/admin")
	// ruleid: rule-unrestricted-request-mapping
	adminGroup.Any("/backup", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "backup operation",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_15() {
	e := echo.New()
	// ruleid: rule-unrestricted-request-mapping
	e.File("/download/sensitive-file", "path/to/file")
	e.Start(":8080")
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_1() {
	r := mux.NewRouter()
	// ok: rule-unrestricted-request-mapping
	r.HandleFunc("/api/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		fmt.Fprintf(w, "User ID: %v", vars["id"])
	}).Methods("GET")
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_2() {
	e := echo.New()
	// ok: rule-unrestricted-request-mapping
	e.GET("/api/data", func(c echo.Context) error {
		return c.String(http.StatusOK, "Data endpoint")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_3() {
	router := gin.Default()
	// ok: rule-unrestricted-request-mapping
	router.GET("/admin/settings", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Admin settings viewed",
		})
	})
	// ok: rule-unrestricted-request-mapping
	router.POST("/admin/settings", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Admin settings updated",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_4() {
	http.HandleFunc("/api/sensitive-data", func(w http.ResponseWriter, r *http.Request) {
		// ok: rule-unrestricted-request-mapping
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data := map[string]string{"key": "sensitive value"}
		json.NewEncoder(w).Encode(data)
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_5() {
	r := mux.NewRouter()
	apiRouter := r.PathPrefix("/api/").Subrouter()
	// ok: rule-unrestricted-request-mapping
	apiRouter.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User data")
	}).Methods("GET", "POST")
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_6() {
	e := echo.New()
	// ok: rule-unrestricted-request-mapping
	e.POST("/user/profile", func(c echo.Context) error {
		return c.String(http.StatusOK, "Profile updated")
	})
	// ok: rule-unrestricted-request-mapping
	e.GET("/user/profile", func(c echo.Context) error {
		return c.String(http.StatusOK, "Profile data")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_7() {
	router := gin.Default()
	// ok: rule-unrestricted-request-mapping
	router.POST("/payment", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "payment processed",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_8() {
	mux := http.NewServeMux()
	// ok: rule-unrestricted-request-mapping
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprintf(w, "Configuration endpoint")
	})
	http.ListenAndServe(":8080", mux)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_9() {
	e := echo.New()
	api := e.Group("/api")
	// ok: rule-unrestricted-request-mapping
	api.GET("/documents", func(c echo.Context) error {
		return c.String(http.StatusOK, "List documents")
	})
	// ok: rule-unrestricted-request-mapping
	api.POST("/documents", func(c echo.Context) error {
		return c.String(http.StatusOK, "Create document")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_10() {
	r := mux.NewRouter()
	// ok: rule-unrestricted-request-mapping
	r.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Reports API")
	}).Methods("GET")
	// ok: rule-unrestricted-request-mapping
	r.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Report created")
	}).Methods("POST")
	http.ListenAndServe(":8080", r)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_11() {
	router := gin.Default()
	adminGroup := router.Group("/admin")
	// ok: rule-unrestricted-request-mapping
	adminGroup.GET("/backup", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "backup list",
		})
	})
	// ok: rule-unrestricted-request-mapping
	adminGroup.POST("/backup", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "backup created",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_12() {
	http.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		// ok: rule-unrestricted-request-mapping
		case http.MethodGet:
			fmt.Fprintf(w, "List users")
		case http.MethodPost:
			fmt.Fprintf(w, "Create user")
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_13() {
	e := echo.New()
	// ok: rule-unrestricted-request-mapping
	e.GET("/download/public-file", func(c echo.Context) error {
		return c.File("path/to/public/file")
	})
	e.Start(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_14() {
	router := gin.Default()
	// ok: rule-unrestricted-request-mapping
	router.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
		})
	})
	router.Run(":8080")
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_15() {
	r := mux.NewRouter()
	// ok: rule-unrestricted-request-mapping
	r.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprintf(w, "Login endpoint")
	})
	http.ListenAndServe(":8080", r)
}
// {/fact}

func main() {
	log.Println("Server examples")
}