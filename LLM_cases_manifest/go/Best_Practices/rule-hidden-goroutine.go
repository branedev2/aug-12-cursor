package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// BAD CASES - Functions with hidden goroutines

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	// ruleid: rule-hidden-goroutine
	go func() {
		fmt.Println("This is a hidden goroutine inside a function")
	}()
	// No way to wait for this goroutine to complete
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2(urls []string) {
	for _, url := range urls {
		// ruleid: rule-hidden-goroutine
		go func(u string) {
			resp, err := http.Get(u)
			if err != nil {
				log.Printf("Error fetching %s: %v", u, err)
				return
			}
			defer resp.Body.Close()
		}(url)
	}
	// Function returns without waiting for goroutines
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// ruleid: rule-hidden-goroutine
	go func() {
		data := make([]byte, 1024)
		for {
			_, err := file.Read(data)
			if err == io.EOF {
				break
			}
			fmt.Println("Processing data...")
		}
	}()
	
	return nil // Returns while goroutine is still using the file
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4(message string) {
	// ruleid: rule-hidden-goroutine
	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("Delayed message:", message)
	}()
	// Function returns immediately, no way to know when message is printed
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5(ctx context.Context) {
	// ruleid: rule-hidden-goroutine
	go func() {
		select {
		case <-ctx.Done():
			fmt.Println("Context cancelled")
		case <-time.After(10 * time.Second):
			fmt.Println("Timeout")
		}
	}()
	// No synchronization with the goroutine
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6(ch chan int) {
	// ruleid: rule-hidden-goroutine
	go func() {
		for i := 0; i < 10; i++ {
			ch <- i
		}
		close(ch)
	}()
	// No way to know when the channel is closed
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	data := []int{1, 2, 3, 4, 5}
	
	// ruleid: rule-hidden-goroutine
	go func() {
		for _, v := range data {
			fmt.Println(v)
		}
	}()
	// Data might be accessed after function returns
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ruleid: rule-hidden-goroutine
		go func() {
			log.Printf("Request received: %s %s", r.Method, r.URL.Path)
		}()
		handler.ServeHTTP(w, r)
	})
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	var counter int
	var mu sync.Mutex
	
	// ruleid: rule-hidden-goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			mu.Lock()
			counter++
			mu.Unlock()
		}
	}()
	// No way to know when counter is done incrementing
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10(tasks []func()) {
	for _, task := range tasks {
		t := task // Capture the variable
		// ruleid: rule-hidden-goroutine
		go func() {
			t()
		}()
	}
	// No synchronization mechanism
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11(filePaths []string) {
	for _, path := range filePaths {
		// ruleid: rule-hidden-goroutine
		go func(p string) {
			content, err := os.ReadFile(p)
			if err != nil {
				log.Printf("Error reading file %s: %v", p, err)
				return
			}
			log.Printf("File %s has %d bytes", p, len(content))
		}(path)
	}
	// Function returns without waiting for file operations to complete
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	ticker := time.NewTicker(1 * time.Second)
	
	// ruleid: rule-hidden-goroutine
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Println("Tick")
			}
		}
	}()
	// Ticker will continue running indefinitely
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13(server *http.Server) {
	// ruleid: rule-hidden-goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()
	// No way to know when server starts or stops
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14(wg *sync.WaitGroup) {
	wg.Add(1)
	// ruleid: rule-hidden-goroutine
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Second)
		fmt.Println("Task completed")
	}()
	// WaitGroup is passed in, but caller might not know to wait
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15(quit chan struct{}) {
// {/fact}

	// ruleid: rule-hidden-goroutine
	go func() {
		for {
			select {
			case <-quit:
				fmt.Println("Worker stopped")
				return
			default:
				fmt.Println("Working...")
				time.Sleep(1 * time.Second)
			}
		}
	}()
	// Quit channel is passed in, but caller might not know to signal
}

// GOOD CASES - Functions without hidden goroutines

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	// ok: rule-hidden-goroutine
	fmt.Println("This function doesn't start any goroutines")
	// Should be called with "go good_case_1()" if concurrency is needed
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2(urls []string) []string {
	results := make([]string, 0, len(urls))
	
	// ok: rule-hidden-goroutine
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Error fetching %s: %v", url, err)
			continue
		}
		defer resp.Body.Close()
		results = append(results, url)
	}
	
	return results
	// Caller can use: go good_case_2(urls)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// ok: rule-hidden-goroutine
	data := make([]byte, 1024)
	for {
		_, err := file.Read(data)
		if err == io.EOF {
			break
		}
		fmt.Println("Processing data...")
	}
	
	return nil
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4(message string) {
	// ok: rule-hidden-goroutine
	time.Sleep(5 * time.Second)
	fmt.Println("Delayed message:", message)
	// Should be called with "go good_case_4(message)" if needed asynchronously
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5(ctx context.Context) bool {
	// ok: rule-hidden-goroutine
	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled")
		return false
	case <-time.After(10 * time.Second):
		fmt.Println("Timeout")
		return true
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6(ch chan int) {
	// ok: rule-hidden-goroutine
	for i := 0; i < 10; i++ {
		ch <- i
	}
	close(ch)
	// Should be called with "go good_case_6(ch)" if needed asynchronously
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	data := []int{1, 2, 3, 4, 5}
	
	// ok: rule-hidden-goroutine
	for _, v := range data {
		fmt.Println(v)
	}
	// Should be called with "go good_case_7()" if needed asynchronously
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ok: rule-hidden-goroutine
		log.Printf("Request received: %s %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() int {
	var counter int
	var mu sync.Mutex
	
	// ok: rule-hidden-goroutine
	for i := 0; i < 1000; i++ {
		mu.Lock()
		counter++
		mu.Unlock()
	}
	
	return counter
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10(tasks []func()) {
	// ok: rule-hidden-goroutine
	for _, task := range tasks {
		task()
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11(filePaths []string) []int {
	results := make([]int, 0, len(filePaths))
	
	// ok: rule-hidden-goroutine
	for _, path := range filePaths {
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Error reading file %s: %v", path, err)
			continue
		}
		results = append(results, len(content))
		log.Printf("File %s has %d bytes", path, len(content))
	}
	
	return results
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12(duration time.Duration) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	timeout := time.After(duration)
	
	// ok: rule-hidden-goroutine
	for {
		select {
		case <-ticker.C:
			fmt.Println("Tick")
		case <-timeout:
			fmt.Println("Timeout reached")
			return
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13(server *http.Server) error {
	// ok: rule-hidden-goroutine
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
	// Should be called with "go good_case_13(server)" if needed asynchronously
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14(duration time.Duration) {
	// ok: rule-hidden-goroutine
	time.Sleep(duration)
	fmt.Println("Task completed")
	// Should be called with "go good_case_14(duration)" if needed asynchronously
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15(quit chan struct{}) {
// {/fact}

	// ok: rule-hidden-goroutine
	for {
		select {
		case <-quit:
			fmt.Println("Worker stopped")
			return
		default:
			fmt.Println("Working...")
			time.Sleep(1 * time.Second)
		}
	}
	// Should be called with "go good_case_15(quit)" if needed asynchronously
}

func main() {
	// Example of proper usage of the good_case functions
	go good_case_1()
	go good_case_4("Hello, world!")
	
	// Example of proper synchronization with WaitGroup
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		good_case_3("example.txt")
	}()
	wg.Wait()
}