package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

var db *sql.DB

func init() {
	// Initialize database connection
	var err error
	db, err = sql.Open("mysql", "user:password@tcp(127.0.0.1:3306)/testdb")
	if err != nil {
		log.Fatal(err)
	}
}

// True Positive Examples (Vulnerable Code)

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// Direct concatenation of user input into SQL query
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	// Process results...
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id := r.FormValue("id")
	
	// String formatting with user input
	query := fmt.Sprintf("SELECT * FROM products WHERE product_id = %s", id)
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	// Process results...
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	orderBy := data["sort"]
	query := "SELECT * FROM products ORDER BY " + orderBy
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Process results...
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	minPrice := r.URL.Query().Get("min_price")
	
	// Multiple concatenations
	query := "SELECT * FROM products WHERE category = '" + category + "'"
	if minPrice != "" {
		query += " AND price >= " + minPrice
	}
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]
	
	// Using string builder but still vulnerable
	var queryBuilder strings.Builder
	queryBuilder.WriteString("SELECT * FROM users WHERE id = ")
	queryBuilder.WriteString(userID)
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(queryBuilder.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("search")
	
	// Attempting to sanitize but still vulnerable
	searchTerm = strings.ReplaceAll(searchTerm, "'", "''") // Insufficient sanitization
	query := "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'"
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_filter")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Using cookie value in SQL query
	filter := cookie.Value
	query := "SELECT * FROM users WHERE role = '" + filter + "'"
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err = db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	
	// Getting input from multipart form
	tableName := r.FormValue("table")
	query := "DROP TABLE " + tableName
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Using header value in SQL query
	userAgent := r.Header.Get("User-Agent")
	
	// Storing user agent in database with direct concatenation
	query := "INSERT INTO analytics (user_agent, visit_time) VALUES ('" + userAgent + "', NOW())"
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Multiple inputs combined
	firstName := r.URL.Query().Get("first")
	lastName := r.URL.Query().Get("last")
	
	query := "SELECT * FROM customers WHERE first_name = '" + firstName + "' AND last_name = '" + lastName + "'"
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Input from URL path
	vars := mux.Vars(r)
	productID := vars["product_id"]
	
	// Concatenation with string formatting
	query := fmt.Sprintf("DELETE FROM products WHERE id = %s", productID)
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Input from query parameter with conditional logic
	status := r.URL.Query().Get("status")
	var query string
	
	if status == "" {
		query = "SELECT * FROM orders"
	} else {
		query = "SELECT * FROM orders WHERE status = '" + status + "'"
	}
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Processing input before using in query
	limit := r.URL.Query().Get("limit")
	offset := r.URL.Query().Get("offset")
	
	// Even with some processing, still vulnerable
	if limit == "" {
		limit = "10"
	}
	if offset == "" {
		offset = "0"
	}
	
	query := "SELECT * FROM products LIMIT " + limit + " OFFSET " + offset
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Input from JSON body for bulk operations
	var data struct {
		IDs []string `json:"ids"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Creating IN clause from user input
	idList := strings.Join(data.IDs, "','")
	query := "SELECT * FROM users WHERE id IN ('" + idList + "')"
	
	// ruleid: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Taking input from referer header
	referer := r.Header.Get("Referer")
	
	// Storing referer in database with direct concatenation
	query := "INSERT INTO visit_sources (referer, timestamp) VALUES ('" + referer + "', CURRENT_TIMESTAMP)"
	
	// ruleid: rule-concat_sqli-updatedMIT
	_, err := db.Exec(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	// Process results...
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	idStr := r.FormValue("id")
	
	// Convert string to int for type safety
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM products WHERE product_id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate input against allowed values
	orderBy := data["sort"]
	allowedColumns := map[string]bool{
		"name": true, "price": true, "date": true,
	}
	
	if !allowedColumns[orderBy] {
		orderBy = "name" // Default safe value
	}
	
	query := "SELECT * FROM products ORDER BY " + orderBy
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	minPriceStr := r.URL.Query().Get("min_price")
	
	// Convert and validate min_price
	var minPrice float64
	if minPriceStr != "" {
		var err error
		minPrice, err = strconv.ParseFloat(minPriceStr, 64)
		if err != nil {
			http.Error(w, "Invalid price", http.StatusBadRequest)
			return
		}
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM products WHERE category = ? AND price >= ?", category, minPrice)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	
	// Convert to int for type safety
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("search")
	
	// Using parameterized query with LIKE
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM products WHERE name LIKE ?", "%"+searchTerm+"%")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_filter")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Validate against allowed values
	filter := cookie.Value
	allowedFilters := map[string]bool{
		"admin": true, "user": true, "guest": true,
	}
	
	if !allowedFilters[filter] {
		http.Error(w, "Invalid filter", http.StatusBadRequest)
		return
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM users WHERE role = ?", filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	
	// Strict validation for table operations
	tableName := r.FormValue("table")
	allowedTables := map[string]bool{
		"temp_logs": true, "temp_data": true,
	}
	
	if !allowedTables[tableName] {
		http.Error(w, "Operation not allowed", http.StatusForbidden)
		return
	}
	
	// ok: rule-concat_sqli-updatedMIT
	_, err := db.Exec("DROP TABLE IF EXISTS " + tableName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using prepared statement for header value
	userAgent := r.Header.Get("User-Agent")
	
	// ok: rule-concat_sqli-updatedMIT
	stmt, err := db.Prepare("INSERT INTO analytics (user_agent, visit_time) VALUES (?, NOW())")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer stmt.Close()
	
	_, err = stmt.Exec(userAgent)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Multiple parameters with parameterized query
	firstName := r.URL.Query().Get("first")
	lastName := r.URL.Query().Get("last")
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM customers WHERE first_name = ? AND last_name = ?", firstName, lastName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Input from URL path with proper validation
	vars := mux.Vars(r)
	productIDStr := vars["product_id"]
	
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		http.Error(w, "Invalid product ID", http.StatusBadRequest)
		return
	}
	
	// ok: rule-concat_sqli-updatedMIT
	_, err = db.Exec("DELETE FROM products WHERE id = ?", productID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Input with conditional logic using parameterized queries
	status := r.URL.Query().Get("status")
	
	var rows *sql.Rows
	var err error
	
	if status == "" {
		// ok: rule-concat_sqli-updatedMIT
		rows, err = db.Query("SELECT * FROM orders")
	} else {
		// ok: rule-concat_sqli-updatedMIT
		rows, err = db.Query("SELECT * FROM orders WHERE status = ?", status)
	}
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Pagination with proper validation
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 10 // Default safe value
	}
	
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0 // Default safe value
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query("SELECT * FROM products LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Handling array of IDs safely
	var data struct {
		IDs []string `json:"ids"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Building parameterized query for IN clause
	query := "SELECT * FROM users WHERE id IN (?" + strings.Repeat(",?", len(data.IDs)-1) + ")"
	
	// Convert []string to []interface{} for db.Query
	args := make([]interface{}, len(data.IDs))
	for i, id := range data.IDs {
		args[i] = id
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using ORM or query builder (simulated)
	type QueryBuilder struct {
		table  string
		wheres []struct{ col, op, val string }
	}
	
	qb := QueryBuilder{table: "products"}
	
	// Add conditions from user input safely
	category := r.URL.Query().Get("category")
	if category != "" {
		qb.wheres = append(qb.wheres, struct{ col, op, val string }{
			col: "category", op: "=", val: category,
		})
	}
	
	// Build parameterized query
	query := "SELECT * FROM " + qb.table
	var args []interface{}
	
	if len(qb.wheres) > 0 {
		query += " WHERE "
		for i, where := range qb.wheres {
			if i > 0 {
				query += " AND "
			}
			query += where.col + " " + where.op + " ?"
			args = append(args, where.val)
		}
	}
	
	// ok: rule-concat_sqli-updatedMIT
	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
}
// {/fact}

func main() {
	r := mux.NewRouter()
	
	// Register handlers
	r.HandleFunc("/users", bad_case_1).Methods("GET")
	r.HandleFunc("/products", bad_case_2).Methods("GET")
	// ... other routes
	
	log.Fatal(http.ListenAndServe(":8080", r))
}