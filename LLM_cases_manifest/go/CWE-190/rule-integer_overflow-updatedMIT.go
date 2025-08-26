package main

import (
	"fmt"
	"net/http"
	"strconv"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user ID from query parameter
	userIDStr := r.URL.Query().Get("id")
	
	// Convert string to int
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	userID16 := int16(userID) // Potential overflow if userID > 32767
	
	fmt.Fprintf(w, "Processing user ID: %d", userID16)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get quantity from form data
	r.ParseForm()
	quantityStr := r.PostForm.Get("quantity")
	
	quantity, err := strconv.Atoi(quantityStr)
	if err != nil {
		http.Error(w, "Invalid quantity", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	quantity32 := int32(quantity) // Potential overflow on 64-bit systems if quantity > 2^31-1
	
	fmt.Fprintf(w, "Order quantity: %d", quantity32)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get age from header
	ageStr := r.Header.Get("X-User-Age")
	
	age, err := strconv.Atoi(ageStr)
	if err != nil {
		http.Error(w, "Invalid age", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	age8 := int8(age) // Potential overflow if age > 127
	
	if age8 < 18 {
		http.Error(w, "Access denied: Age restriction", http.StatusForbidden)
		return
	}
	
	fmt.Fprintf(w, "Welcome, you are %d years old", age8)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get product code from URL path parameter
	productCodeStr := r.PathValue("code")
	
	productCode, err := strconv.Atoi(productCodeStr)
	if err != nil {
		http.Error(w, "Invalid product code", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	shortCode := uint16(productCode) // Potential overflow if productCode > 65535 or < 0
	
	fmt.Fprintf(w, "Product short code: %d", shortCode)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get score from cookie
	cookie, err := r.Cookie("user_score")
	if err != nil {
		http.Error(w, "Score not found", http.StatusBadRequest)
		return
	}
	
	score, err := strconv.Atoi(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid score", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	scoreShort := int16(score) // Potential overflow if score > 32767
	
	fmt.Fprintf(w, "Your score: %d", scoreShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get temperature from query parameter
	tempStr := r.URL.Query().Get("temp")
	
	temp, err := strconv.Atoi(tempStr)
	if err != nil {
		http.Error(w, "Invalid temperature", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	tempByte := byte(temp) // Potential overflow if temp > 255 or < 0
	
	fmt.Fprintf(w, "Temperature: %d°C", tempByte)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get year from form data
	r.ParseForm()
	yearStr := r.PostForm.Get("year")
	
	year, err := strconv.Atoi(yearStr)
	if err != nil {
		http.Error(w, "Invalid year", http.StatusBadRequest)
		return
	}
	
	// Calculate years since 2000
	yearsSince2000 := year - 2000
	
	// ruleid: rule-integer_overflow-updatedMIT
	shortYears := int8(yearsSince2000) // Potential overflow if yearsSince2000 > 127
	
	fmt.Fprintf(w, "Years since 2000: %d", shortYears)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Get count from query parameter
	countStr := r.URL.Query().Get("count")
	
	count, err := strconv.Atoi(countStr)
	if err != nil {
		http.Error(w, "Invalid count", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	countShort := uint8(count) // Potential overflow if count > 255 or < 0
	
	for i := uint8(0); i < countShort; i++ {
		fmt.Fprintf(w, "Item %d\n", i)
	}
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Get price from form data
	r.ParseForm()
	priceStr := r.PostForm.Get("price")
	
	price, err := strconv.Atoi(priceStr)
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	priceShort := int16(price) // Potential overflow if price > 32767
	
	// Apply discount
	discountedPrice := priceShort * 90 / 100
	
	fmt.Fprintf(w, "Discounted price: %d", discountedPrice)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get duration from header
	durationStr := r.Header.Get("X-Duration")
	
	duration, err := strconv.Atoi(durationStr)
	if err != nil {
		http.Error(w, "Invalid duration", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	shortDuration := int16(duration) // Potential overflow if duration > 32767
	
	fmt.Fprintf(w, "Operation will take %d seconds", shortDuration)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get offset from query parameter
	offsetStr := r.URL.Query().Get("offset")
	
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		http.Error(w, "Invalid offset", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	offsetShort := uint16(offset) // Potential overflow if offset > 65535 or < 0
	
	fmt.Fprintf(w, "Data offset: %d", offsetShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get limit from query parameter
	limitStr := r.URL.Query().Get("limit")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		http.Error(w, "Invalid limit", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	limitShort := int16(limit) // Potential overflow if limit > 32767
	
	fmt.Fprintf(w, "Query limit: %d", limitShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get port from form data
	r.ParseForm()
	portStr := r.PostForm.Get("port")
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		http.Error(w, "Invalid port", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	portShort := uint16(port) // Potential overflow if port > 65535 or < 0
	
	fmt.Fprintf(w, "Using port: %d", portShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get color value from query parameter
	colorStr := r.URL.Query().Get("color")
	
	color, err := strconv.Atoi(colorStr)
	if err != nil {
		http.Error(w, "Invalid color value", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	redComponent := uint8(color) // Potential overflow if color > 255 or < 0
	
	fmt.Fprintf(w, "Red component: %d", redComponent)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get percentage from form data
	r.ParseForm()
	percentStr := r.PostForm.Get("percent")
	
	percent, err := strconv.Atoi(percentStr)
	if err != nil {
		http.Error(w, "Invalid percentage", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-integer_overflow-updatedMIT
	percentShort := int8(percent) // Potential overflow if percent > 127
	
	fmt.Fprintf(w, "Percentage: %d%%", percentShort)
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user ID from query parameter
	userIDStr := r.URL.Query().Get("id")
	
	// Convert string to int
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if userID > 32767 || userID < -32768 {
		http.Error(w, "User ID out of range", http.StatusBadRequest)
		return
	}
	userID16 := int16(userID) // Safe conversion after range check
	
	fmt.Fprintf(w, "Processing user ID: %d", userID16)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get quantity from form data
	r.ParseForm()
	quantityStr := r.PostForm.Get("quantity")
	
	quantity, err := strconv.Atoi(quantityStr)
	if err != nil {
		http.Error(w, "Invalid quantity", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if quantity > 2147483647 || quantity < -2147483648 {
		http.Error(w, "Quantity out of range", http.StatusBadRequest)
		return
	}
	quantity32 := int32(quantity) // Safe conversion after range check
	
	fmt.Fprintf(w, "Order quantity: %d", quantity32)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get age from header
	ageStr := r.Header.Get("X-User-Age")
	
	age, err := strconv.Atoi(ageStr)
	if err != nil {
		http.Error(w, "Invalid age", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if age > 127 || age < -128 {
		http.Error(w, "Age out of valid range", http.StatusBadRequest)
		return
	}
	age8 := int8(age) // Safe conversion after range check
	
	if age8 < 18 {
		http.Error(w, "Access denied: Age restriction", http.StatusForbidden)
		return
	}
	
	fmt.Fprintf(w, "Welcome, you are %d years old", age8)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get product code from URL path parameter
	productCodeStr := r.PathValue("code")
	
	productCode, err := strconv.Atoi(productCodeStr)
	if err != nil {
		http.Error(w, "Invalid product code", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if productCode > 65535 || productCode < 0 {
		http.Error(w, "Product code out of range", http.StatusBadRequest)
		return
	}
	shortCode := uint16(productCode) // Safe conversion after range check
	
	fmt.Fprintf(w, "Product short code: %d", shortCode)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Get score from cookie
	cookie, err := r.Cookie("user_score")
	if err != nil {
		http.Error(w, "Score not found", http.StatusBadRequest)
		return
	}
	
	score, err := strconv.Atoi(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid score", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	const maxInt16 = 32767
	const minInt16 = -32768
	if score > maxInt16 || score < minInt16 {
		http.Error(w, "Score out of range", http.StatusBadRequest)
		return
	}
	scoreShort := int16(score) // Safe conversion after range check
	
	fmt.Fprintf(w, "Your score: %d", scoreShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Get temperature from query parameter
	tempStr := r.URL.Query().Get("temp")
	
	temp, err := strconv.Atoi(tempStr)
	if err != nil {
		http.Error(w, "Invalid temperature", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if temp > 255 || temp < 0 {
		http.Error(w, "Temperature out of valid range (0-255)", http.StatusBadRequest)
		return
	}
	tempByte := byte(temp) // Safe conversion after range check
	
	fmt.Fprintf(w, "Temperature: %d°C", tempByte)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get year from form data
	r.ParseForm()
	yearStr := r.PostForm.Get("year")
	
	year, err := strconv.Atoi(yearStr)
	if err != nil {
		http.Error(w, "Invalid year", http.StatusBadRequest)
		return
	}
	
	// Calculate years since 2000
	yearsSince2000 := year - 2000
	
	// ok: rule-integer_overflow-updatedMIT
	if yearsSince2000 > 127 || yearsSince2000 < -128 {
		http.Error(w, "Year out of supported range", http.StatusBadRequest)
		return
	}
	shortYears := int8(yearsSince2000) // Safe conversion after range check
	
	fmt.Fprintf(w, "Years since 2000: %d", shortYears)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Get count from query parameter
	countStr := r.URL.Query().Get("count")
	
	count, err := strconv.Atoi(countStr)
	if err != nil {
		http.Error(w, "Invalid count", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if count > 255 || count < 0 {
		http.Error(w, "Count must be between 0 and 255", http.StatusBadRequest)
		return
	}
	countShort := uint8(count) // Safe conversion after range check
	
	for i := uint8(0); i < countShort; i++ {
		fmt.Fprintf(w, "Item %d\n", i)
	}
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Get price from form data
	r.ParseForm()
	priceStr := r.PostForm.Get("price")
	
	price, err := strconv.Atoi(priceStr)
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	if price > 32767 || price < -32768 {
		http.Error(w, "Price out of valid range", http.StatusBadRequest)
		return
	}
	priceShort := int16(price) // Safe conversion after range check
	
	// Apply discount
	discountedPrice := priceShort * 90 / 100
	
	fmt.Fprintf(w, "Discounted price: %d", discountedPrice)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Use ParseInt with explicit bit size instead of Atoi
	durationStr := r.Header.Get("X-Duration")
	
	// ok: rule-integer_overflow-updatedMIT
	duration, err := strconv.ParseInt(durationStr, 10, 16)
	if err != nil {
		http.Error(w, "Invalid duration or out of range", http.StatusBadRequest)
		return
	}
	
	shortDuration := int16(duration) // Safe conversion as ParseInt already enforced the range
	
	fmt.Fprintf(w, "Operation will take %d seconds", shortDuration)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get offset from query parameter
	offsetStr := r.URL.Query().Get("offset")
	
	// ok: rule-integer_overflow-updatedMIT
	// Use ParseUint with explicit bit size instead of Atoi
	offset, err := strconv.ParseUint(offsetStr, 10, 16)
	if err != nil {
		http.Error(w, "Invalid offset or out of range", http.StatusBadRequest)
		return
	}
	
	offsetShort := uint16(offset) // Safe conversion as ParseUint already enforced the range
	
	fmt.Fprintf(w, "Data offset: %d", offsetShort)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Get limit from query parameter
	limitStr := r.URL.Query().Get("limit")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		http.Error(w, "Invalid limit", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	// Use a constant for clarity
	const maxInt16 = 32767
	const minInt16 = -32768
	
	if limit <= maxInt16 && limit >= minInt16 {
		limitShort := int16(limit) // Safe conversion after range check
		fmt.Fprintf(w, "Query limit: %d", limitShort)
	} else {
		http.Error(w, "Limit out of range", http.StatusBadRequest)
		return
	}
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Get port from form data
	r.ParseForm()
	portStr := r.PostForm.Get("port")
	
	// ok: rule-integer_overflow-updatedMIT
	// Directly parse as uint16 to avoid overflow
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		http.Error(w, "Invalid port or out of range", http.StatusBadRequest)
		return
	}
	
	port := uint16(port64) // Safe conversion as ParseUint already enforced the range
	
	fmt.Fprintf(w, "Using port: %d", port)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Get color value from query parameter
	colorStr := r.URL.Query().Get("color")
	
	color, err := strconv.Atoi(colorStr)
	if err != nil {
		http.Error(w, "Invalid color value", http.StatusBadRequest)
		return
	}
	
	// ok: rule-integer_overflow-updatedMIT
	// Use a switch statement to handle range checking
	switch {
	case color < 0:
		http.Error(w, "Color value cannot be negative", http.StatusBadRequest)
		return
	case color > 255:
		http.Error(w, "Color value exceeds maximum (255)", http.StatusBadRequest)
		return
	default:
		redComponent := uint8(color) // Safe conversion after range check
		fmt.Fprintf(w, "Red component: %d", redComponent)
	}
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Get percentage from form data
	r.ParseForm()
	percentStr := r.PostForm.Get("percent")
	
	// ok: rule-integer_overflow-updatedMIT
	// Use a helper function to safely convert and check range
	percent8, err := safeConvertToInt8(percentStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Percentage: %d%%", percent8)
}
// {/fact}

// Helper function for safe conversion
func safeConvertToInt8(str string) (int8, error) {
	val, err := strconv.Atoi(str)
	if err != nil {
		return 0, fmt.Errorf("invalid number format")
	}
	
	if val > 127 || val < -128 {
		return 0, fmt.Errorf("value out of range for int8")
	}
	
	return int8(val), nil
}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// ... other handlers
	http.ListenAndServe(":8080", nil)
}