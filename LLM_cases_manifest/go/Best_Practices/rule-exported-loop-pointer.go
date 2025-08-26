package main

import (
	"fmt"
	"sync"
	"time"
)

// True Positive Examples (Vulnerable Code)

// bad_case_1 demonstrates exporting loop variable pointers to a slice
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	var users = []string{"alice", "bob", "charlie"}
	var userPointers []*string
	
	for _, user := range users {
		// ruleid: rule-exported-loop-pointer
		userPointers = append(userPointers, &user)
	}
	
	// All pointers will point to the last element
	for _, p := range userPointers {
		fmt.Println(*p) // Will print "charlie" three times
	}
}
// {/fact}

// bad_case_2 demonstrates exporting loop variable pointers to goroutines
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	values := []int{1, 2, 3, 4, 5}
	var wg sync.WaitGroup
	
	for _, val := range values {
		wg.Add(1)
		// ruleid: rule-exported-loop-pointer
		go func() {
			defer wg.Done()
			fmt.Println(val) // Will likely print 5 multiple times
		}()
	}
	
	wg.Wait()
}
// {/fact}

// bad_case_3 demonstrates exporting loop variable pointers to a map
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	items := []string{"item1", "item2", "item3"}
	itemMap := make(map[int]*string)
	
	for i, item := range items {
		// ruleid: rule-exported-loop-pointer
		itemMap[i] = &item
	}
	
	// All map values will point to the last element
	for idx, ptr := range itemMap {
		fmt.Printf("Index %d: %s\n", idx, *ptr) // Will print "item3" for all indices
	}
}
// {/fact}

// bad_case_4 demonstrates exporting loop variable pointers to a closure
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	numbers := []int{10, 20, 30}
	var funcs []func()
	
	for _, num := range numbers {
		// ruleid: rule-exported-loop-pointer
		funcs = append(funcs, func() {
			fmt.Println(num) // Will print 30 for all functions
		})
	}
	
	for _, f := range funcs {
		f()
	}
}
// {/fact}

// bad_case_5 demonstrates exporting loop variable pointers to a channel
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	items := []string{"one", "two", "three"}
	ch := make(chan *string, len(items))
	
	for _, item := range items {
		// ruleid: rule-exported-loop-pointer
		ch <- &item
	}
	
	close(ch)
	
	// All received pointers will point to the last element
	for ptr := range ch {
		fmt.Println(*ptr) // Will print "three" multiple times
	}
}
// {/fact}

// bad_case_6 demonstrates exporting loop variable pointers to a struct
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	type Container struct {
		value *int
	}
	
	numbers := []int{5, 10, 15}
	var containers []Container
	
	for _, num := range numbers {
		// ruleid: rule-exported-loop-pointer
		containers = append(containers, Container{value: &num})
	}
	
	// All containers will have pointers to the last element
	for _, c := range containers {
		fmt.Println(*c.value) // Will print 15 multiple times
	}
}
// {/fact}

// bad_case_7 demonstrates exporting loop variable pointers in deferred functions
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	files := []string{"file1.txt", "file2.txt", "file3.txt"}
	
	for _, file := range files {
		// ruleid: rule-exported-loop-pointer
		defer func() {
			fmt.Println("Processing:", file) // Will print the last file multiple times
		}()
	}
}
// {/fact}

// bad_case_8 demonstrates exporting loop variable pointers to timer callbacks
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	ids := []int{100, 200, 300}
	
	for _, id := range ids {
		// ruleid: rule-exported-loop-pointer
		time.AfterFunc(time.Millisecond*10, func() {
			fmt.Println("Processing ID:", id) // Will print the last ID multiple times
		})
	}
	
	time.Sleep(time.Second) // Wait for timers to execute
}
// {/fact}

// bad_case_9 demonstrates exporting loop variable pointers in nested loops
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	matrix := [][]int{{1, 2}, {3, 4}, {5, 6}}
	var ptrs [][]*int
	
	for _, row := range matrix {
		var rowPtrs []*int
		for _, val := range row {
			// ruleid: rule-exported-loop-pointer
			rowPtrs = append(rowPtrs, &val)
		}
		ptrs = append(ptrs, rowPtrs)
	}
	
	// Each row will have pointers to the last element of that row
	for _, row := range ptrs {
		for _, ptr := range row {
			fmt.Print(*ptr, " ") // Each row will print its last value twice
		}
		fmt.Println()
	}
}
// {/fact}

// bad_case_10 demonstrates exporting loop variable pointers to a global variable
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	var globalPtr *string
	names := []string{"John", "Jane", "Jim"}
	
	for _, name := range names {
		// ruleid: rule-exported-loop-pointer
		globalPtr = &name
		// Do some work with the name
		time.Sleep(time.Millisecond)
	}
	
	fmt.Println(*globalPtr) // Will print "Jim"
}
// {/fact}

// bad_case_11 demonstrates exporting loop variable pointers to a slice of interfaces
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	values := []int{42, 84, 126}
	var interfaces []interface{}
	
	for _, val := range values {
		// ruleid: rule-exported-loop-pointer
		interfaces = append(interfaces, &val)
	}
	
	// All interfaces will point to the last element
	for _, iface := range interfaces {
		ptr := iface.(*int)
		fmt.Println(*ptr) // Will print 126 multiple times
	}
}
// {/fact}

// bad_case_12 demonstrates exporting loop variable pointers in a switch statement
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	cases := []string{"case1", "case2", "case3"}
	var handlers []func()
	
	for _, c := range cases {
		switch c {
		case "case1", "case2", "case3":
			// ruleid: rule-exported-loop-pointer
			handlers = append(handlers, func() {
				fmt.Println("Handling:", c) // Will print the last case multiple times
			})
		}
	}
	
	for _, h := range handlers {
		h()
	}
}
// {/fact}

// bad_case_13 demonstrates exporting loop variable pointers in a map of functions
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	items := []string{"apple", "banana", "cherry"}
	handlers := make(map[string]func())
	
	for _, item := range items {
		// ruleid: rule-exported-loop-pointer
		handlers[item] = func() {
			fmt.Println("Processing:", item) // Will print the last item for all handlers
		}
	}
	
	for _, handler := range handlers {
		handler()
	}
}
// {/fact}

// bad_case_14 demonstrates exporting loop variable pointers to a custom callback
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	type Callback struct {
		data *int
		run  func()
	}
	
	numbers := []int{1, 2, 3}
	var callbacks []Callback
	
	for _, num := range numbers {
		// ruleid: rule-exported-loop-pointer
		cb := Callback{
			data: &num,
			run: func() {
				fmt.Println("Number:", num) // Will print the last number
			},
		}
		callbacks = append(callbacks, cb)
	}
	
	for _, cb := range callbacks {
		fmt.Println(*cb.data) // Will print 3 multiple times
		cb.run()              // Will print "Number: 3" multiple times
	}
}
// {/fact}

// bad_case_15 demonstrates exporting loop variable pointers in multiple ways
// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	tasks := []string{"task1", "task2", "task3"}
	var taskPtrs []*string
	var taskFuncs []func()
	
	for _, task := range tasks {
		// ruleid: rule-exported-loop-pointer
		taskPtrs = append(taskPtrs, &task)
		// ruleid: rule-exported-loop-pointer
		taskFuncs = append(taskFuncs, func() {
			fmt.Println("Executing:", task)
		})
	}
	
	// Both will reference the last element
	for _, ptr := range taskPtrs {
		fmt.Println(*ptr) // Will print "task3" multiple times
	}
	
	for _, fn := range taskFuncs {
		fn() // Will print "Executing: task3" multiple times
	}
}
// {/fact}

// True Negative Examples (Safe Code)

// good_case_1 demonstrates proper copying of loop variables before exporting pointers
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	var users = []string{"alice", "bob", "charlie"}
	var userPointers []*string
	
	for _, user := range users {
		userCopy := user // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		userPointers = append(userPointers, &userCopy)
	}
	
	// Each pointer will point to the correct element
	for i, p := range userPointers {
		fmt.Printf("User %d: %s\n", i, *p) // Will print alice, bob, charlie
	}
}
// {/fact}

// good_case_2 demonstrates proper variable capture in goroutines
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	values := []int{1, 2, 3, 4, 5}
	var wg sync.WaitGroup
	
	for _, val := range values {
		wg.Add(1)
		val := val // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		go func() {
			defer wg.Done()
			fmt.Println(val) // Will print the correct value for each goroutine
		}()
	}
	
	wg.Wait()
}
// {/fact}

// good_case_3 demonstrates proper copying of loop variables for a map
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	items := []string{"item1", "item2", "item3"}
	itemMap := make(map[int]*string)
	
	for i, item := range items {
		itemCopy := item // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		itemMap[i] = &itemCopy
	}
	
	// Each map value will point to the correct element
	for idx, ptr := range itemMap {
		fmt.Printf("Index %d: %s\n", idx, *ptr) // Will print the correct items
	}
}
// {/fact}

// good_case_4 demonstrates proper variable capture in closures
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	numbers := []int{10, 20, 30}
	var funcs []func()
	
	for _, num := range numbers {
		num := num // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		funcs = append(funcs, func() {
			fmt.Println(num) // Will print the correct number for each function
		})
	}
	
	for _, f := range funcs {
		f() // Will print 10, 20, 30
	}
}
// {/fact}

// good_case_5 demonstrates proper copying of loop variables for a channel
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	items := []string{"one", "two", "three"}
	ch := make(chan *string, len(items))
	
	for _, item := range items {
		itemCopy := item // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		ch <- &itemCopy
	}
	
	close(ch)
	
	// Each received pointer will point to the correct element
	for ptr := range ch {
		fmt.Println(*ptr) // Will print one, two, three
	}
}
// {/fact}

// good_case_6 demonstrates proper copying of loop variables for structs
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	type Container struct {
		value *int
	}
	
	numbers := []int{5, 10, 15}
	var containers []Container
	
	for _, num := range numbers {
		numCopy := num // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		containers = append(containers, Container{value: &numCopy})
	}
	
	// Each container will have a pointer to the correct element
	for i, c := range containers {
		fmt.Printf("Container %d: %d\n", i, *c.value) // Will print 5, 10, 15
	}
}
// {/fact}

// good_case_7 demonstrates proper variable capture in deferred functions
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	files := []string{"file1.txt", "file2.txt", "file3.txt"}
	
	for _, file := range files {
		file := file // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		defer func() {
			fmt.Println("Processing:", file) // Will print the correct file for each deferred function
		}()
	}
}
// {/fact}

// good_case_8 demonstrates proper variable capture in timer callbacks
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	ids := []int{100, 200, 300}
	
	for _, id := range ids {
		id := id // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		time.AfterFunc(time.Millisecond*10, func() {
			fmt.Println("Processing ID:", id) // Will print the correct ID for each timer
		})
	}
	
	time.Sleep(time.Second) // Wait for timers to execute
}
// {/fact}

// good_case_9 demonstrates proper copying of loop variables in nested loops
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	matrix := [][]int{{1, 2}, {3, 4}, {5, 6}}
	var ptrs [][]*int
	
	for _, row := range matrix {
		var rowPtrs []*int
		for _, val := range row {
			valCopy := val // Create a new variable with the current value
			// ok: rule-exported-loop-pointer
			rowPtrs = append(rowPtrs, &valCopy)
		}
		ptrs = append(ptrs, rowPtrs)
	}
	
	// Each pointer will point to the correct element
	for i, row := range ptrs {
		for j, ptr := range row {
			fmt.Printf("Matrix[%d][%d] = %d\n", i, j, *ptr) // Will print the correct values
		}
	}
}
// {/fact}

// good_case_10 demonstrates proper copying of loop variables for a global variable
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	var globalPtr *string
	names := []string{"John", "Jane", "Jim"}
	
	for _, name := range names {
		nameCopy := name // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		globalPtr = &nameCopy
		// Do some work with the name
		time.Sleep(time.Millisecond)
	}
	
	fmt.Println(*globalPtr) // Will print "Jim"
}
// {/fact}

// good_case_11 demonstrates proper copying of loop variables for interfaces
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	values := []int{42, 84, 126}
	var interfaces []interface{}
	
	for _, val := range values {
		valCopy := val // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		interfaces = append(interfaces, &valCopy)
	}
	
	// Each interface will point to the correct element
	for i, iface := range interfaces {
		ptr := iface.(*int)
		fmt.Printf("Value %d: %d\n", i, *ptr) // Will print 42, 84, 126
	}
}
// {/fact}

// good_case_12 demonstrates proper variable capture in a switch statement
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	cases := []string{"case1", "case2", "case3"}
	var handlers []func()
	
	for _, c := range cases {
		c := c // Create a new variable with the current value
		switch c {
		case "case1", "case2", "case3":
			// ok: rule-exported-loop-pointer
			handlers = append(handlers, func() {
				fmt.Println("Handling:", c) // Will print the correct case for each handler
			})
		}
	}
	
	for _, h := range handlers {
		h() // Will print case1, case2, case3
	}
}
// {/fact}

// good_case_13 demonstrates proper variable capture in a map of functions
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	items := []string{"apple", "banana", "cherry"}
	handlers := make(map[string]func())
	
	for _, item := range items {
		item := item // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		handlers[item] = func() {
			fmt.Println("Processing:", item) // Will print the correct item for each handler
		}
	}
	
	for _, handler := range handlers {
		handler() // Will print apple, banana, cherry
	}
}
// {/fact}

// good_case_14 demonstrates proper variable capture in a custom callback
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	type Callback struct {
		data *int
		run  func()
	}
	
	numbers := []int{1, 2, 3}
	var callbacks []Callback
	
	for _, num := range numbers {
		num := num // Create a new variable with the current value
		// ok: rule-exported-loop-pointer
		cb := Callback{
			data: &num,
			run: func() {
				fmt.Println("Number:", num) // Will print the correct number for each callback
			},
		}
		callbacks = append(callbacks, cb)
	}
	
	for i, cb := range callbacks {
		fmt.Printf("Callback %d: %d\n", i, *cb.data) // Will print 1, 2, 3
		cb.run() // Will print "Number: 1", "Number: 2", "Number: 3"
	}
}
// {/fact}

// good_case_15 demonstrates using direct indexing to avoid the issue entirely
// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	tasks := []string{"task1", "task2", "task3"}
	var taskPtrs []*string
	var taskFuncs []func()
	
	// Using index-based iteration instead of range
	for i := 0; i < len(tasks); i++ {
		// ok: rule-exported-loop-pointer
		taskPtrs = append(taskPtrs, &tasks[i]) // Safe because we're pointing to array elements, not loop variables
		
		i := i // Capture the index if needed in a closure
		// ok: rule-exported-loop-pointer
		taskFuncs = append(taskFuncs, func() {
			fmt.Println("Executing:", tasks[i])
		})
	}
	
	// Each pointer will point to the correct element
	for i, ptr := range taskPtrs {
		fmt.Printf("Task %d: %s\n", i, *ptr) // Will print task1, task2, task3
	}
	
	for i, fn := range taskFuncs {
		fmt.Printf("Function %d: ", i)
		fn() // Will execute with the correct task
	}
}
// {/fact}

func main() {
	// Run examples
	fmt.Println("Running bad_case_1:")
	bad_case_1()
	
	fmt.Println("\nRunning good_case_1:")
	good_case_1()
}