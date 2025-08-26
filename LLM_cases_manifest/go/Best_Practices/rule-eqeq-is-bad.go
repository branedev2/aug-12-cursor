package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

// True Positives (bad cases)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	x := 5
	// ruleid: rule-eqeq-is-bad
	if x == x {
		fmt.Println("This will always be true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	const y = 10
	// ruleid: rule-eqeq-is-bad
	if y == 10 {
		fmt.Println("This will always be true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	// ruleid: rule-eqeq-is-bad
	if true == true {
		fmt.Println("This is always true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	// ruleid: rule-eqeq-is-bad
	if false == false {
		fmt.Println("This is always true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-eqeq-is-bad
	if 1 == 1 {
		fmt.Println("This is always true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	// ruleid: rule-eqeq-is-bad
	if "hello" == "hello" {
		fmt.Println("This is always true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	x := 5
	y := 10
	// ruleid: rule-eqeq-is-bad
	if x != x {
		fmt.Println("This will never execute")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	// ruleid: rule-eqeq-is-bad
	if 5 != 5 {
		fmt.Println("This will never execute")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	const PI = 3.14159
	// ruleid: rule-eqeq-is-bad
	if PI == 3.14159 {
		fmt.Println("This will always be true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	// ruleid: rule-eqeq-is-bad
	result := 10 == 10
	fmt.Println("Result:", result)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	// ruleid: rule-eqeq-is-bad
	for i := 0; i < 10 && true == true; i++ {
		fmt.Println(i)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	var x *int = nil
	// ruleid: rule-eqeq-is-bad
	if nil == nil {
		fmt.Println("This is always true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	// ruleid: rule-eqeq-is-bad
	switch {
	case 1 == 1:
		fmt.Println("This will always be selected")
	default:
		fmt.Println("This will never be reached")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	arr := []int{1, 2, 3}
	// ruleid: rule-eqeq-is-bad
	if len(arr) == len(arr) {
		fmt.Println("Array length equals itself")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	// ruleid: rule-eqeq-is-bad
	fmt.Println("Is empty string equal to empty string?", "" == "")
}
// {/fact}

// True Negatives (good cases)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	x := 5
	y := 10
	// ok: rule-eqeq-is-bad
	if x == y {
		fmt.Println("x equals y")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	x := rand.Intn(10)
	// ok: rule-eqeq-is-bad
	if x == 5 {
		fmt.Println("x equals 5")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	input := os.Getenv("USER_INPUT")
	// ok: rule-eqeq-is-bad
	if input == "admin" {
		fmt.Println("User is admin")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	// ok: rule-eqeq-is-bad
	if rand.Intn(2) == 0 {
		fmt.Println("Random number is 0")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	x := 5
	y := x
	z := 5
	// ok: rule-eqeq-is-bad
	if y == z {
		fmt.Println("y equals z")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	// ok: rule-eqeq-is-bad
	for i := 0; i < 10; i++ {
		if i == 5 {
			fmt.Println("i is 5")
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	now := time.Now()
	later := time.Now()
	// ok: rule-eqeq-is-bad
	if now.Before(later) {
		fmt.Println("Time has passed")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	a := []int{1, 2, 3}
	b := []int{1, 2, 3}
	// ok: rule-eqeq-is-bad
	if len(a) == len(b) {
		fmt.Println("Arrays have the same length")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	userInput := "5"
	num, _ := strconv.Atoi(userInput)
	// ok: rule-eqeq-is-bad
	if num == 5 {
		fmt.Println("User entered 5")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	// ok: rule-eqeq-is-bad
	switch rand.Intn(3) {
	case 0:
		fmt.Println("Got 0")
	case 1:
		fmt.Println("Got 1")
	default:
		fmt.Println("Got something else")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	x := 5
	y := x + 0 // Compiler might optimize this, but it's not a direct comparison of identical values
	// ok: rule-eqeq-is-bad
	if x == y {
		fmt.Println("x equals y")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	// ok: rule-eqeq-is-bad
	condition := rand.Float64() > 0.5
	if condition == true {
		fmt.Println("Condition is true")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	type Person struct {
		Name string
		Age  int
	}
	
	p1 := Person{"Alice", 30}
	p2 := Person{"Alice", 30}
	
	// ok: rule-eqeq-is-bad
	if p1 == p2 {
		fmt.Println("Persons are equal")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	m := make(map[string]int)
	m["key"] = 5
	
	// ok: rule-eqeq-is-bad
	if val, exists := m["key"]; exists && val == 5 {
		fmt.Println("Key exists and equals 5")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	// ok: rule-eqeq-is-bad
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			fmt.Println(i, "is even")
		}
	}
}
// {/fact}

func main() {
	// Just to make the code runnable
	rand.Seed(time.Now().UnixNano())
	bad_case_1()
	good_case_1()
}