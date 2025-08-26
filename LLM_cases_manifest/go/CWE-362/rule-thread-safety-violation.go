package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// True Positive Examples (Thread Safety Violations)

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_1() {
	counter := 0
	
	// Launch 10 goroutines that increment the counter
	for i := 0; i < 10; i++ {
		go func() {
			// ruleid: rule-thread-safety-violation
			counter++ // Shared variable access without synchronization
		}()
	}
	
	// Wait a bit for goroutines to complete
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Counter:", counter)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_2() {
	sharedMap := make(map[string]int)
	
	// Multiple goroutines writing to a shared map
	for i := 0; i < 5; i++ {
		go func(id int) {
			// ruleid: rule-thread-safety-violation
			sharedMap[fmt.Sprintf("key-%d", id)] = id // Concurrent map writes
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Map size:", len(sharedMap))
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_3() {
	balance := 1000
	
	// Simulate concurrent withdrawals
	for i := 0; i < 5; i++ {
		go func() {
			// ruleid: rule-thread-safety-violation
			if balance >= 200 {
				// Race condition: multiple goroutines might check balance and withdraw
				// before others update the balance
				time.Sleep(10 * time.Millisecond) // Increase chance of race condition
				balance -= 200
			}
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Final balance:", balance)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_4() {
	type UserData struct {
		Name  string
		Score int
	}
	
	userData := &UserData{Name: "User", Score: 0}
	
	// Multiple goroutines updating the same struct
	for i := 0; i < 10; i++ {
		go func() {
			// ruleid: rule-thread-safety-violation
			userData.Score++ // Concurrent access to shared struct field
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Final score:", userData.Score)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_5() {
	results := make([]int, 0)
	
	// Multiple goroutines appending to a slice
	for i := 0; i < 10; i++ {
		go func(val int) {
			// ruleid: rule-thread-safety-violation
			results = append(results, val) // Concurrent slice modification
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Results length:", len(results))
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_6() {
	http.HandleFunc("/increment", func(w http.ResponseWriter, r *http.Request) {
		static := 0
		
		// Launch multiple goroutines within the handler
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// ruleid: rule-thread-safety-violation
				static++ // This is a race condition if multiple requests hit this endpoint
			}()
		}
		
		wg.Wait()
		fmt.Fprintf(w, "Count: %d", static)
	})
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_7() {
	cache := make(map[string]string)
	
	// Set up a handler that uses a shared cache
	http.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		value := r.URL.Query().Get("value")
		
		if value != "" {
			// ruleid: rule-thread-safety-violation
			cache[key] = value // Concurrent map writes from different HTTP requests
		}
		
		fmt.Fprintf(w, "Cache value: %s", cache[key])
	})
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_8() {
	var lastID int
	
	// Generate unique IDs (but with a race condition)
	generateID := func() int {
		// ruleid: rule-thread-safety-violation
		lastID++
		return lastID
	}
	
	// Concurrent ID generation
	ids := make([]int, 0)
	for i := 0; i < 10; i++ {
		go func() {
			id := generateID()
			ids = append(ids, id)
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_9() {
	type Counter struct {
		value int
	}
	
	counter := &Counter{}
	
	// Method with race condition
	increment := func() {
		// ruleid: rule-thread-safety-violation
		counter.value++ // Shared struct field access without synchronization
	}
	
	// Concurrent increments
	for i := 0; i < 10; i++ {
		go increment()
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Counter value:", counter.value)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_10() {
	done := false
	
	// One goroutine sets the flag
	go func() {
		time.Sleep(50 * time.Millisecond)
		// ruleid: rule-thread-safety-violation
		done = true // Shared boolean access without synchronization
	}()
	
	// Another goroutine checks the flag
	go func() {
		for {
			// ruleid: rule-thread-safety-violation
			if done { // Race condition on reading the flag
				fmt.Println("Done!")
				break
			}
		}
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_11() {
	queue := make([]string, 0)
	
	// Producer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			// ruleid: rule-thread-safety-violation
			queue = append(queue, fmt.Sprintf("item-%d", i)) // Concurrent slice modification
			time.Sleep(10 * time.Millisecond)
		}
	}()
	
	// Consumer goroutine
	go func() {
		for {
			if len(queue) > 0 {
				// ruleid: rule-thread-safety-violation
				item := queue[0]      // Race condition reading from slice
				queue = queue[1:]     // Race condition modifying slice
				fmt.Println("Got:", item)
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	
	time.Sleep(200 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_12() {
	type SharedResource struct {
		data map[string]int
	}
	
	resource := &SharedResource{
		data: make(map[string]int),
	}
	
	// Multiple goroutines accessing the resource
	for i := 0; i < 5; i++ {
		go func(id int) {
			key := fmt.Sprintf("worker-%d", id)
			// ruleid: rule-thread-safety-violation
			resource.data[key] = id * 10 // Concurrent map access
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_13() {
	var buffer []byte
	
	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			// ruleid: rule-thread-safety-violation
			buffer = append(buffer, byte(i)) // Concurrent slice modification
		}
	}()
	
	// Reader goroutine
	go func() {
		time.Sleep(5 * time.Millisecond)
		// ruleid: rule-thread-safety-violation
		fmt.Println("Buffer length:", len(buffer)) // Race condition on reading buffer
		if len(buffer) > 0 {
			fmt.Println("First byte:", buffer[0])
		}
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_14() {
	processed := 0
	errors := 0
	
	// Worker goroutines updating shared counters
	for i := 0; i < 5; i++ {
		go func(id int) {
			// Simulate work
			time.Sleep(time.Duration(id) * 10 * time.Millisecond)
			
			if id%2 == 0 {
				// ruleid: rule-thread-safety-violation
				processed++ // Race condition
			} else {
				// ruleid: rule-thread-safety-violation
				errors++ // Race condition
			}
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	fmt.Printf("Processed: %d, Errors: %d\n", processed, errors)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=1}
func bad_case_15() {
	type Config struct {
		MaxConnections int
		Timeout        time.Duration
	}
	
	config := &Config{MaxConnections: 10, Timeout: 30 * time.Second}
	
	// Updater goroutine
	go func() {
		// ruleid: rule-thread-safety-violation
		config.MaxConnections = 20 // Race condition on shared struct
		config.Timeout = 60 * time.Second
	}()
	
	// Reader goroutine
	go func() {
		time.Sleep(5 * time.Millisecond)
		// ruleid: rule-thread-safety-violation
		fmt.Printf("Config: %+v\n", config) // Race condition reading config
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// True Negative Examples (Thread-Safe Code)

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_1() {
	counter := 0
	var mu sync.Mutex
	
	// Launch 10 goroutines that increment the counter
	for i := 0; i < 10; i++ {
		go func() {
			// ok: rule-thread-safety-violation
			mu.Lock()
			counter++
			mu.Unlock()
		}()
	}
	
	// Wait a bit for goroutines to complete
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Counter:", counter)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_2() {
	sharedMap := sync.Map{}
	
	// Multiple goroutines writing to a sync.Map
	for i := 0; i < 5; i++ {
		go func(id int) {
			// ok: rule-thread-safety-violation
			sharedMap.Store(fmt.Sprintf("key-%d", id), id) // Thread-safe map operations
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	count := 0
	sharedMap.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	
	fmt.Println("Map size:", count)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_3() {
	balance := 1000
	var mu sync.Mutex
	
	// Simulate concurrent withdrawals
	for i := 0; i < 5; i++ {
		go func() {
			// ok: rule-thread-safety-violation
			mu.Lock()
			defer mu.Unlock()
			
			if balance >= 200 {
				balance -= 200
			}
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
	
	mu.Lock()
	finalBalance := balance
	mu.Unlock()
	
	fmt.Println("Final balance:", finalBalance)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_4() {
	type UserData struct {
		Name  string
		Score int
		mu    sync.Mutex
	}
	
	userData := &UserData{Name: "User", Score: 0}
	
	// Multiple goroutines updating the same struct
	for i := 0; i < 10; i++ {
		go func() {
			// ok: rule-thread-safety-violation
			userData.mu.Lock()
			userData.Score++
			userData.mu.Unlock()
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
	
	userData.mu.Lock()
	finalScore := userData.Score
	userData.mu.Unlock()
	
	fmt.Println("Final score:", finalScore)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_5() {
	var mu sync.Mutex
	results := make([]int, 0)
	
	// Multiple goroutines appending to a slice
	for i := 0; i < 10; i++ {
		go func(val int) {
			// ok: rule-thread-safety-violation
			mu.Lock()
			results = append(results, val)
			mu.Unlock()
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	mu.Lock()
	length := len(results)
	mu.Unlock()
	
	fmt.Println("Results length:", length)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_6() {
	var counter int
	var mu sync.Mutex
	
	http.HandleFunc("/increment", func(w http.ResponseWriter, r *http.Request) {
		var wg sync.WaitGroup
		
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// ok: rule-thread-safety-violation
				mu.Lock()
				counter++
				mu.Unlock()
			}()
		}
		
		wg.Wait()
		
		mu.Lock()
		currentCount := counter
		mu.Unlock()
		
		fmt.Fprintf(w, "Count: %d", currentCount)
	})
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_7() {
	var cacheMu sync.RWMutex
	cache := make(map[string]string)
	
	// Set up a handler that uses a shared cache with proper locking
	http.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		value := r.URL.Query().Get("value")
		
		if value != "" {
			// ok: rule-thread-safety-violation
			cacheMu.Lock()
			cache[key] = value
			cacheMu.Unlock()
		}
		
		cacheMu.RLock()
		result := cache[key]
		cacheMu.RUnlock()
		
		fmt.Fprintf(w, "Cache value: %s", result)
	})
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_8() {
	var lastID int
	var mu sync.Mutex
	
	// Generate unique IDs with proper synchronization
	generateID := func() int {
		// ok: rule-thread-safety-violation
		mu.Lock()
		defer mu.Unlock()
		lastID++
		return lastID
	}
	
	// Concurrent ID generation
	var idsMu sync.Mutex
	ids := make([]int, 0)
	
	for i := 0; i < 10; i++ {
		go func() {
			id := generateID()
			
			idsMu.Lock()
			ids = append(ids, id)
			idsMu.Unlock()
		}()
	}
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_9() {
	type Counter struct {
		value int
		mu    sync.Mutex
	}
	
	counter := &Counter{}
	
	// Thread-safe method
	increment := func() {
		// ok: rule-thread-safety-violation
		counter.mu.Lock()
		counter.value++
		counter.mu.Unlock()
	}
	
	// Concurrent increments
	for i := 0; i < 10; i++ {
		go increment()
	}
	
	time.Sleep(100 * time.Millisecond)
	
	counter.mu.Lock()
	finalValue := counter.value
	counter.mu.Unlock()
	
	fmt.Println("Counter value:", finalValue)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_10() {
	var mu sync.Mutex
	done := false
	
	// One goroutine sets the flag
	go func() {
		time.Sleep(50 * time.Millisecond)
		// ok: rule-thread-safety-violation
		mu.Lock()
		done = true
		mu.Unlock()
	}()
	
	// Another goroutine checks the flag
	go func() {
		for {
			mu.Lock()
			isDone := done
			mu.Unlock()
			
			if isDone {
				fmt.Println("Done!")
				break
			}
			
			time.Sleep(5 * time.Millisecond)
		}
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_11() {
	var mu sync.Mutex
	queue := make([]string, 0)
	
	// Producer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			// ok: rule-thread-safety-violation
			mu.Lock()
			queue = append(queue, fmt.Sprintf("item-%d", i))
			mu.Unlock()
			
			time.Sleep(10 * time.Millisecond)
		}
	}()
	
	// Consumer goroutine
	go func() {
		for {
			mu.Lock()
			if len(queue) > 0 {
				item := queue[0]
				queue = queue[1:]
				mu.Unlock()
				fmt.Println("Got:", item)
			} else {
				mu.Unlock()
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	
	time.Sleep(200 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_12() {
	type SharedResource struct {
		data map[string]int
		mu   sync.RWMutex
	}
	
	resource := &SharedResource{
		data: make(map[string]int),
	}
	
	// Multiple goroutines accessing the resource
	for i := 0; i < 5; i++ {
		go func(id int) {
			key := fmt.Sprintf("worker-%d", id)
			// ok: rule-thread-safety-violation
			resource.mu.Lock()
			resource.data[key] = id * 10
			resource.mu.Unlock()
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_13() {
	var mu sync.Mutex
	var buffer []byte
	
	// Writer goroutine
	go func() {
		for i := 0; i < 10; i++ {
			// ok: rule-thread-safety-violation
			mu.Lock()
			buffer = append(buffer, byte(i))
			mu.Unlock()
		}
	}()
	
	// Reader goroutine
	go func() {
		time.Sleep(5 * time.Millisecond)
		
		mu.Lock()
		bufferLen := len(buffer)
		var firstByte byte
		if bufferLen > 0 {
			firstByte = buffer[0]
		}
		mu.Unlock()
		
		fmt.Println("Buffer length:", bufferLen)
		if bufferLen > 0 {
			fmt.Println("First byte:", firstByte)
		}
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_14() {
	var mu sync.Mutex
	processed := 0
	errors := 0
	
	// Worker goroutines updating shared counters
	for i := 0; i < 5; i++ {
		go func(id int) {
			// Simulate work
			time.Sleep(time.Duration(id) * 10 * time.Millisecond)
			
			// ok: rule-thread-safety-violation
			mu.Lock()
			if id%2 == 0 {
				processed++
			} else {
				errors++
			}
			mu.Unlock()
		}(i)
	}
	
	time.Sleep(100 * time.Millisecond)
	
	mu.Lock()
	finalProcessed := processed
	finalErrors := errors
	mu.Unlock()
	
	fmt.Printf("Processed: %d, Errors: %d\n", finalProcessed, finalErrors)
}
// {/fact}

// {fact rule=thread-safety-violation@v1.0 defects=0}
func good_case_15() {
	type Config struct {
		MaxConnections int
		Timeout        time.Duration
		mu             sync.RWMutex
	}
	
	config := &Config{MaxConnections: 10, Timeout: 30 * time.Second}
	
	// Updater goroutine
	go func() {
		// ok: rule-thread-safety-violation
		config.mu.Lock()
		config.MaxConnections = 20
		config.Timeout = 60 * time.Second
		config.mu.Unlock()
	}()
	
	// Reader goroutine
	go func() {
		time.Sleep(5 * time.Millisecond)
		
		config.mu.RLock()
		maxConn := config.MaxConnections
		timeout := config.Timeout
		config.mu.RUnlock()
		
		fmt.Printf("Config: MaxConnections=%d, Timeout=%v\n", maxConn, timeout)
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

func main() {
	// This function is just a placeholder and not meant to be executed
	fmt.Println("This file contains examples of thread safety violations and their fixes")
}