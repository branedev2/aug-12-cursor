package main

import (
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

// True Positives (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from query parameter
	input := r.URL.Query().Get("value")
	
	// Create a big.Rat from the input string
	rat := new(big.Rat)
	rat.SetString(input) // This could be a very large number
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	result := int16(rat.Num().Int64()) // Potential overflow
	
	fmt.Fprintf(w, "Result: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form data
	r.ParseForm()
	input := r.Form.Get("number")
	
	// Create a big.Rat from the input
	rat := new(big.Rat)
	rat.SetString(input)
	
	// Convert to int32 without checking if it fits
	// ruleid: rule-math_big_rat-updatedMIT
	value := int32(rat.Num().Int64())
	
	fmt.Fprintf(w, "Processed value: %d", value)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Get input from request header
	input := r.Header.Get("X-Custom-Value")
	
	// Parse as big.Rat
	numerator, denominator := parseRational(input)
	rat := new(big.Rat)
	rat.SetString(numerator + "/" + denominator)
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	smallInt := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "Calculated: %d", smallInt)
}
// {/fact}

func parseRational(input string) (string, string) {
	parts := strings.Split(input, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return input, "1"
}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Get input from cookie
	cookie, err := r.Cookie("value")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Create big.Rat from cookie value
	rat := new(big.Rat)
	rat.SetString(cookie.Value)
	
	// Convert to int32 without checking range
	// ruleid: rule-math_big_rat-updatedMIT
	result := int32(rat.Num().Int64())
	
	fmt.Fprintf(w, "Cookie value converted: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Get JSON data
	r.ParseForm()
	jsonData := r.Form.Get("json")
	
	// Extract value from JSON (simplified for example)
	value := strings.Trim(strings.Split(jsonData, ":")[1], "\"}")
// {/fact}
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(value)
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	smallValue := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "JSON value: %d", smallValue)
}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Get multiple parameters and perform calculation
	aStr := r.URL.Query().Get("a")
	bStr := r.URL.Query().Get("b")
	
	// Create big.Rat values
	aRat := new(big.Rat)
	bRat := new(big.Rat)
	aRat.SetString(aStr)
	bRat.SetString(bStr)
	
	// Perform calculation and convert to int32
	result := new(big.Rat).Add(aRat, bRat)
	
	// ruleid: rule-math_big_rat-updatedMIT
	intResult := int32(result.Num().Int64())
	
	fmt.Fprintf(w, "Sum: %d", intResult)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Get input from path parameter (simplified)
	pathValue := strings.TrimPrefix(r.URL.Path, "/convert/")
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(pathValue)
	
	// Convert to int16 directly
	// ruleid: rule-math_big_rat-updatedMIT
	converted := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "Path value converted: %d", converted)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Process a batch of values
	r.ParseForm()
	valuesStr := r.Form.Get("batch")
	values := strings.Split(valuesStr, ",")
	
	results := make([]int32, len(values))
	for i, val := range values {
		rat := new(big.Rat)
		rat.SetString(val)
		
		// Convert each value without validation
		// ruleid: rule-math_big_rat-updatedMIT
		results[i] = int32(rat.Num().Int64())
	}
	
	fmt.Fprintf(w, "Batch results: %v", results)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input and perform division
	numeratorStr := r.URL.Query().Get("numerator")
	denominatorStr := r.URL.Query().Get("denominator")
	
	numerator := new(big.Rat)
	denominator := new(big.Rat)
	numerator.SetString(numeratorStr)
	denominator.SetString(denominatorStr)
	
	// Perform division
	result := new(big.Rat).Quo(numerator, denominator)
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	intResult := int16(result.Num().Int64())
	
	fmt.Fprintf(w, "Division result: %d", intResult)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Get input with scientific notation
	input := r.URL.Query().Get("scientific")
	
	// Parse scientific notation (simplified)
	parts := strings.Split(input, "e")
	baseStr := parts[0]
	expStr := "1"
	if len(parts) > 1 {
		expStr = "1" + strings.Repeat("0", mustAtoi(parts[1]))
	}
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(baseStr + "*" + expStr)
	
	// Convert to int32 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	result := int32(rat.Num().Int64())
	
	fmt.Fprintf(w, "Scientific notation value: %d", result)
}
// {/fact}

func mustAtoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Get hexadecimal input
	hexInput := r.URL.Query().Get("hex")
	
	// Convert hex to decimal string (simplified)
	decimalStr := hexToDecimal(hexInput)
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(decimalStr)
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	result := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "Hex converted: %d", result)
}
// {/fact}

func hexToDecimal(hex string) string {
	// Simplified hex to decimal conversion
	hex = strings.TrimPrefix(hex, "0x")
	n := new(big.Int)
	n.SetString(hex, 16)
	return n.String()
}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Get input and perform calculation with multiple operations
	input := r.URL.Query().Get("complex")
	
	// Create initial big.Rat
	rat := new(big.Rat)
	rat.SetString(input)
	
	// Perform multiple operations
	rat.Mul(rat, big.NewRat(2, 1))
	rat.Add(rat, big.NewRat(10, 1))
	rat.Quo(rat, big.NewRat(3, 1))
	
	// Convert to int32 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	finalResult := int32(rat.Num().Int64())
	
	fmt.Fprintf(w, "Complex calculation result: %d", finalResult)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Get multiple inputs for a formula
	aStr := r.URL.Query().Get("a")
	bStr := r.URL.Query().Get("b")
	cStr := r.URL.Query().Get("c")
	
	// Create big.Rat values
	a := new(big.Rat)
	b := new(big.Rat)
	c := new(big.Rat)
	a.SetString(aStr)
	b.SetString(bStr)
	c.SetString(cStr)
	
	// Calculate quadratic formula (simplified)
	discriminant := new(big.Rat).Mul(b, b)
	discriminant.Sub(discriminant, new(big.Rat).Mul(new(big.Rat).Mul(a, c), big.NewRat(4, 1)))
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	result := int16(discriminant.Num().Int64())
	
	fmt.Fprintf(w, "Discriminant: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Get input for factorial calculation
	input := r.URL.Query().Get("factorial")
	
	// Create big.Rat for the result
	n := new(big.Rat)
	n.SetString(input)
	
	// Calculate factorial (simplified)
	result := calculateFactorial(n)
	
	// Convert to int32 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	intResult := int32(result.Num().Int64())
	
	fmt.Fprintf(w, "Factorial result: %d", intResult)
}
// {/fact}

func calculateFactorial(n *big.Rat) *big.Rat {
	// Simplified factorial calculation
	result := big.NewRat(1, 1)
	one := big.NewRat(1, 1)
	zero := big.NewRat(0, 1)
	
	for i := new(big.Rat).Set(n); i.Cmp(zero) > 0; i.Sub(i, one) {
		result.Mul(result, i)
	}
	
	return result
}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Get input for exponentiation
	baseStr := r.URL.Query().Get("base")
	expStr := r.URL.Query().Get("exponent")
	
	// Create big.Rat values
	base := new(big.Rat)
	exp := new(big.Rat)
	base.SetString(baseStr)
	exp.SetString(expStr)
	
	// Calculate power (simplified)
	result := calculatePower(base, exp)
	
	// Convert to int16 without validation
	// ruleid: rule-math_big_rat-updatedMIT
	intResult := int16(result.Num().Int64())
	
	fmt.Fprintf(w, "Power result: %d", intResult)
}
// {/fact}

func calculatePower(base, exp *big.Rat) *big.Rat {
	// Simplified power calculation
	result := big.NewRat(1, 1)
	one := big.NewRat(1, 1)
	zero := big.NewRat(0, 1)
	
	for i := new(big.Rat).Set(exp); i.Cmp(zero) > 0; i.Sub(i, one) {
		result.Mul(result, base)
	}
	
	return result
}

// True Negatives (Safe Code)

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Get user input from query parameter
	input := r.URL.Query().Get("value")
	
	// Create a big.Rat from the input string
	rat := new(big.Rat)
	rat.SetString(input)
	
	// Check if the value fits in int16 before converting
	// ok: rule-math_big_rat-updatedMIT
	num := rat.Num().Int64()
	if num > 32767 || num < -32768 {
		http.Error(w, "Value too large for int16", http.StatusBadRequest)
		return
	}
	result := int16(num)
	
	fmt.Fprintf(w, "Result: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Get user input from form data
	r.ParseForm()
	input := r.Form.Get("number")
	
	// Create a big.Rat from the input
	rat := new(big.Rat)
	rat.SetString(input)
	
	// Validate the value fits in int32 before converting
	// ok: rule-math_big_rat-updatedMIT
	num := rat.Num().Int64()
	if num > 2147483647 || num < -2147483648 {
		http.Error(w, "Value exceeds int32 range", http.StatusBadRequest)
		return
	}
	value := int32(num)
	
	fmt.Fprintf(w, "Processed value: %d", value)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Get input from request header
	input := r.Header.Get("X-Custom-Value")
	
	// Parse as big.Rat
	numerator, denominator := parseRational(input)
	rat := new(big.Rat)
	rat.SetString(numerator + "/" + denominator)
	
	// Check if the value fits in int16 range
	// ok: rule-math_big_rat-updatedMIT
	if !fitsInInt16(rat.Num()) {
		http.Error(w, "Value too large for int16", http.StatusBadRequest)
		return
	}
	smallInt := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "Calculated: %d", smallInt)
}
// {/fact}

func fitsInInt16(num *big.Int) bool {
	max := big.NewInt(32767)
	min := big.NewInt(-32768)
	return num.Cmp(max) <= 0 && num.Cmp(min) >= 0
}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Get input from cookie
	cookie, err := r.Cookie("value")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Create big.Rat from cookie value
	rat := new(big.Rat)
	rat.SetString(cookie.Value)
	
	// Check if the value fits in int32 range
	// ok: rule-math_big_rat-updatedMIT
	num := rat.Num().Int64()
	if num > 2147483647 || num < -2147483648 {
		http.Error(w, "Cookie value exceeds int32 range", http.StatusBadRequest)
		return
	}
	result := int32(num)
	
	fmt.Fprintf(w, "Cookie value converted: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Get JSON data
	r.ParseForm()
	jsonData := r.Form.Get("json")
	
	// Extract value from JSON (simplified for example)
	value := strings.Trim(strings.Split(jsonData, ":")[1], "\"}")
// {/fact}
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(value)
	
	// Validate before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	max := big.NewInt(32767)
	min := big.NewInt(-32768)
	if rat.Num().Cmp(max) > 0 || rat.Num().Cmp(min) < 0 {
		http.Error(w, "Value out of range for int16", http.StatusBadRequest)
		return
	}
	smallValue := int16(rat.Num().Int64())
	
	fmt.Fprintf(w, "JSON value: %d", smallValue)
}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Get multiple parameters and perform calculation
	aStr := r.URL.Query().Get("a")
	bStr := r.URL.Query().Get("b")
	
	// Create big.Rat values
	aRat := new(big.Rat)
	bRat := new(big.Rat)
	aRat.SetString(aStr)
	bRat.SetString(bStr)
	
	// Perform calculation
	result := new(big.Rat).Add(aRat, bRat)
	
	// Validate before converting to int32
	// ok: rule-math_big_rat-updatedMIT
	if !fitsInInt32(result.Num()) {
		http.Error(w, "Result too large for int32", http.StatusBadRequest)
		return
	}
	intResult := int32(result.Num().Int64())
	
	fmt.Fprintf(w, "Sum: %d", intResult)
}
// {/fact}

func fitsInInt32(num *big.Int) bool {
	max := big.NewInt(2147483647)
	min := big.NewInt(-2147483648)
	return num.Cmp(max) <= 0 && num.Cmp(min) >= 0
}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Get input from path parameter (simplified)
	pathValue := strings.TrimPrefix(r.URL.Path, "/convert/")
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(pathValue)
	
	// Validate the value before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	num := rat.Num()
	denom := rat.Denom()
	
	// Check if the value is an integer (denominator is 1)
	if denom.Cmp(big.NewInt(1)) != 0 {
		http.Error(w, "Value must be an integer", http.StatusBadRequest)
		return
	}
	
	// Check if it fits in int16
	if !fitsInInt16(num) {
		http.Error(w, "Value out of range for int16", http.StatusBadRequest)
		return
	}
	
	converted := int16(num.Int64())
	fmt.Fprintf(w, "Path value converted: %d", converted)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Process a batch of values
	r.ParseForm()
	valuesStr := r.Form.Get("batch")
	values := strings.Split(valuesStr, ",")
	
	results := make([]int32, 0, len(values))
	for _, val := range values {
		rat := new(big.Rat)
		rat.SetString(val)
		
		// Validate each value before conversion
		// ok: rule-math_big_rat-updatedMIT
		num := rat.Num().Int64()
		if num > 2147483647 || num < -2147483648 {
			// Skip invalid values
			continue
		}
		results = append(results, int32(num))
	}
	
	fmt.Fprintf(w, "Valid batch results: %v", results)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Get user input and perform division
	numeratorStr := r.URL.Query().Get("numerator")
	denominatorStr := r.URL.Query().Get("denominator")
	
	numerator := new(big.Rat)
	denominator := new(big.Rat)
	numerator.SetString(numeratorStr)
	denominator.SetString(denominatorStr)
	
	// Check if denominator is zero
	if denominator.Cmp(big.NewRat(0, 1)) == 0 {
		http.Error(w, "Division by zero", http.StatusBadRequest)
		return
	}
	
	// Perform division
	result := new(big.Rat).Quo(numerator, denominator)
	
	// Validate before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	if result.IsInt() && fitsInInt16(result.Num()) {
		intResult := int16(result.Num().Int64())
		fmt.Fprintf(w, "Division result: %d", intResult)
	} else {
		// Return as float if not an integer or too large
		floatResult, _ := result.Float64()
		fmt.Fprintf(w, "Division result (float): %f", floatResult)
	}
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Get input with scientific notation
	input := r.URL.Query().Get("scientific")
	
	// Parse scientific notation (simplified)
	parts := strings.Split(input, "e")
	baseStr := parts[0]
	expStr := "1"
	if len(parts) > 1 {
		expStr = "1" + strings.Repeat("0", mustAtoi(parts[1]))
	}
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(baseStr + "*" + expStr)
	
	// Validate before converting to int32
	// ok: rule-math_big_rat-updatedMIT
	if rat.Num().BitLen() > 31 {
		http.Error(w, "Value too large for int32", http.StatusBadRequest)
		return
	}
	
	result := int32(rat.Num().Int64())
	fmt.Fprintf(w, "Scientific notation value: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Get hexadecimal input
	hexInput := r.URL.Query().Get("hex")
	
	// Convert hex to decimal string (simplified)
	decimalStr := hexToDecimal(hexInput)
	
	// Create big.Rat
	rat := new(big.Rat)
	rat.SetString(decimalStr)
	
	// Validate before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	max := big.NewInt(32767)
	min := big.NewInt(-32768)
	num := rat.Num()
	
	if num.Cmp(max) > 0 || num.Cmp(min) < 0 {
		// Return error for values outside int16 range
		http.Error(w, "Hex value too large for int16", http.StatusBadRequest)
		return
	}
	
	result := int16(num.Int64())
	fmt.Fprintf(w, "Hex converted: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Get input and perform calculation with multiple operations
	input := r.URL.Query().Get("complex")
	
	// Create initial big.Rat
	rat := new(big.Rat)
	rat.SetString(input)
	
	// Perform multiple operations
	rat.Mul(rat, big.NewRat(2, 1))
	rat.Add(rat, big.NewRat(10, 1))
	rat.Quo(rat, big.NewRat(3, 1))
	
	// Validate the result before converting to int32
	// ok: rule-math_big_rat-updatedMIT
	if !rat.IsInt() {
		// Handle non-integer result
		floatVal, _ := rat.Float64()
		fmt.Fprintf(w, "Complex calculation result (float): %f", floatVal)
		return
	}
	
	if !fitsInInt32(rat.Num()) {
		http.Error(w, "Result too large for int32", http.StatusBadRequest)
		return
	}
	
	finalResult := int32(rat.Num().Int64())
	fmt.Fprintf(w, "Complex calculation result: %d", finalResult)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Get multiple inputs for a formula
	aStr := r.URL.Query().Get("a")
	bStr := r.URL.Query().Get("b")
	cStr := r.URL.Query().Get("c")
	
	// Create big.Rat values
	a := new(big.Rat)
	b := new(big.Rat)
	c := new(big.Rat)
	a.SetString(aStr)
	b.SetString(bStr)
	c.SetString(cStr)
	
	// Calculate quadratic formula (simplified)
	discriminant := new(big.Rat).Mul(b, b)
	discriminant.Sub(discriminant, new(big.Rat).Mul(new(big.Rat).Mul(a, c), big.NewRat(4, 1)))
	
	// Validate before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	if discriminant.Num().BitLen() > 15 {
		// Use a larger type if the result doesn't fit in int16
		if discriminant.Num().BitLen() <= 31 {
			result := int32(discriminant.Num().Int64())
			fmt.Fprintf(w, "Discriminant (int32): %d", result)
		} else {
			fmt.Fprintf(w, "Discriminant (big): %s", discriminant.String())
		}
		return
	}
	
	result := int16(discriminant.Num().Int64())
	fmt.Fprintf(w, "Discriminant: %d", result)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Get input for factorial calculation
	input := r.URL.Query().Get("factorial")
	
	// Validate input is small enough before calculation
	inputInt, err := strconv.Atoi(input)
	if err != nil || inputInt > 12 { // 12! fits in int32, 13! doesn't
		http.Error(w, "Input too large for factorial calculation", http.StatusBadRequest)
		return
	}
	
	// Create big.Rat for the result
	n := new(big.Rat)
	n.SetString(input)
	
	// Calculate factorial (simplified)
	result := calculateFactorial(n)
	
	// Validate before converting to int32
	// ok: rule-math_big_rat-updatedMIT
	if result.Num().BitLen() > 31 {
		http.Error(w, "Factorial result too large for int32", http.StatusBadRequest)
		return
	}
	
	intResult := int32(result.Num().Int64())
	fmt.Fprintf(w, "Factorial result: %d", intResult)
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Get input for exponentiation
	baseStr := r.URL.Query().Get("base")
	expStr := r.URL.Query().Get("exponent")
	
	// Validate inputs are small enough before calculation
	base, err1 := strconv.Atoi(baseStr)
	exp, err2 := strconv.Atoi(expStr)
	if err1 != nil || err2 != nil || base < 0 || exp < 0 || (base > 5 && exp > 5) {
		http.Error(w, "Input values too large for safe calculation", http.StatusBadRequest)
		return
	}
	
	// Create big.Rat values
	baseRat := new(big.Rat)
	expRat := new(big.Rat)
	baseRat.SetString(baseStr)
	expRat.SetString(expStr)
	
	// Calculate power (simplified)
	result := calculatePower(baseRat, expRat)
	
	// Validate before converting to int16
	// ok: rule-math_big_rat-updatedMIT
	if !result.IsInt() || result.Num().BitLen() > 15 {
		http.Error(w, "Power result too large for int16", http.StatusBadRequest)
		return
	}
	
	intResult := int16(result.Num().Int64())
	fmt.Fprintf(w, "Power result: %d", intResult)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	// Add more handlers for other functions
	http.ListenAndServe(":8080", nil)
}