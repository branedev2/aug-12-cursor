package main

import (
	"fmt"
	"sync"
	"time"
)

// True Positives (Bad Cases) - Using mutex to guard channel operations

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	var mu sync.Mutex
	ch := make(chan int, 5)

	go func() {
		for i := 0; i < 10; i++ {
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			ch <- i
			mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
		close(ch)
	}()

	for val := range ch {
		fmt.Println("Received:", val)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	var mu sync.Mutex
	ch := make(chan string, 10)

	go func() {
		messages := []string{"hello", "world", "golang", "channels"}
		for _, msg := range messages {
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			ch <- msg
			mu.Unlock()
		}
		close(ch)
	}()

	for msg := range ch {
		fmt.Println(msg)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	var mu sync.RWMutex
	resultCh := make(chan int)

	go func() {
		sum := 0
		for i := 0; i < 100; i++ {
			sum += i
		}
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		resultCh <- sum
		mu.Unlock()
	}()

	result := <-resultCh
	fmt.Println("Sum:", result)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	var mu sync.Mutex
	doneCh := make(chan struct{})

	go func() {
		// Do some work
		time.Sleep(1 * time.Second)
		
		// Signal completion
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		close(doneCh)
		mu.Unlock()
	}()

	<-doneCh
	fmt.Println("Work completed")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	var mu sync.Mutex
	ch := make(chan int)
	
	go func() {
		for i := 0; i < 5; i++ {
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			ch <- i * i
			mu.Unlock()
		}
		close(ch)
	}()
	
	for val := range ch {
		fmt.Printf("Square: %d\n", val)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	var mu sync.Mutex
	requestCh := make(chan string)
	responseCh := make(chan string)
	
	// Server goroutine
	go func() {
		for req := range requestCh {
			// Process request
			resp := "Response to: " + req
			
			// Send response
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			responseCh <- resp
			mu.Unlock()
		}
	}()
	
	// Client code
	go func() {
		requestCh <- "Hello"
		resp := <-responseCh
		fmt.Println(resp)
		close(requestCh)
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	var mu sync.Mutex
	dataCh := make(chan []byte, 5)
	
	go func() {
		data := []byte("important data")
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		dataCh <- data
		mu.Unlock()
	}()
	
	receivedData := <-dataCh
	fmt.Printf("Received %d bytes\n", len(receivedData))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	var mu sync.RWMutex
	eventCh := make(chan string)
	
	// Event producer
	go func() {
		events := []string{"start", "processing", "end"}
		for _, event := range events {
			// ruleid: rule-channel-guarded-with-mutex
			mu.RLock()
			eventCh <- event
			mu.RUnlock()
		}
		close(eventCh)
	}()
	
	// Event consumer
	for event := range eventCh {
		fmt.Println("Event:", event)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	var mu sync.Mutex
	resultCh := make(chan error, 1)
	
	go func() {
		// Simulate some operation that might fail
		var err error
		// ... operation code ...
		
		// Send result
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		resultCh <- err
		mu.Unlock()
	}()
	
	if err := <-resultCh; err != nil {
		fmt.Println("Operation failed:", err)
	} else {
		fmt.Println("Operation succeeded")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	var mu sync.Mutex
	ch := make(chan struct{})
	
	for i := 0; i < 3; i++ {
		go func(id int) {
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			ch <- struct{}{}
			mu.Unlock()
			fmt.Printf("Worker %d sent signal\n", id)
		}(i)
	}
	
	// Wait for all workers
	for i := 0; i < 3; i++ {
		<-ch
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	var mu sync.Mutex
	taskCh := make(chan func(), 10)
	
	// Task producer
	go func() {
		for i := 0; i < 5; i++ {
			taskID := i
			task := func() {
				fmt.Printf("Executing task %d\n", taskID)
			}
			
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			taskCh <- task
			mu.Unlock()
		}
		close(taskCh)
	}()
	
	// Task executor
	for task := range taskCh {
		task()
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	type Message struct {
		ID   int
		Data string
	}
	
	var mu sync.Mutex
	msgCh := make(chan Message)
	
	go func() {
		for i := 0; i < 3; i++ {
			msg := Message{
				ID:   i,
				Data: fmt.Sprintf("Message %d", i),
			}
			
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			msgCh <- msg
			mu.Unlock()
		}
		close(msgCh)
	}()
	
	for msg := range msgCh {
		fmt.Printf("Received message: %+v\n", msg)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	var mu sync.Mutex
	controlCh := make(chan string)
	
	// Controller goroutine
	go func() {
		commands := []string{"start", "pause", "resume", "stop"}
		for _, cmd := range commands {
			time.Sleep(100 * time.Millisecond)
			// ruleid: rule-channel-guarded-with-mutex
			mu.Lock()
			controlCh <- cmd
			mu.Unlock()
		}
		close(controlCh)
	}()
	
	// Worker goroutine
	go func() {
		for cmd := range controlCh {
			fmt.Printf("Executing command: %s\n", cmd)
		}
	}()
	
	time.Sleep(1 * time.Second)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	var mu sync.Mutex
	resultCh := make(chan map[string]int)
	
	go func() {
		// Create a result map
		result := map[string]int{
			"success": 10,
			"failure": 2,
			"skipped": 3,
		}
		
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		resultCh <- result
		mu.Unlock()
	}()
	
	stats := <-resultCh
	fmt.Printf("Test results: %v\n", stats)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	var mu sync.Mutex
	boolCh := make(chan bool)
	
	go func() {
		// Some condition check
		condition := true
		
		// ruleid: rule-channel-guarded-with-mutex
		mu.Lock()
		boolCh <- condition
		mu.Unlock()
	}()
	
	if <-boolCh {
		fmt.Println("Condition is true")
	} else {
		fmt.Println("Condition is false")
	}
}
// {/fact}

// True Negatives (Good Cases) - Using channels without unnecessary mutex

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	ch := make(chan int, 5)

	go func() {
		for i := 0; i < 10; i++ {
			// ok: rule-channel-guarded-with-mutex
			ch <- i
			time.Sleep(100 * time.Millisecond)
		}
		close(ch)
	}()

	for val := range ch {
		fmt.Println("Received:", val)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	ch := make(chan string, 10)

	go func() {
		messages := []string{"hello", "world", "golang", "channels"}
		for _, msg := range messages {
			// ok: rule-channel-guarded-with-mutex
			ch <- msg
		}
		close(ch)
	}()

	for msg := range ch {
		fmt.Println(msg)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	resultCh := make(chan int)

	go func() {
		sum := 0
		for i := 0; i < 100; i++ {
			sum += i
		}
		// ok: rule-channel-guarded-with-mutex
		resultCh <- sum
	}()

	result := <-resultCh
	fmt.Println("Sum:", result)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	doneCh := make(chan struct{})

	go func() {
		// Do some work
		time.Sleep(1 * time.Second)
		
		// Signal completion
		// ok: rule-channel-guarded-with-mutex
		close(doneCh)
	}()

	<-doneCh
	fmt.Println("Work completed")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	// Using mutex for shared data structure, not for channel operations
	var mu sync.Mutex
	data := make(map[string]int)
	ch := make(chan int)
	
	go func() {
		for i := 0; i < 5; i++ {
			// Update shared map with mutex (correct usage)
			mu.Lock()
			data[fmt.Sprintf("key%d", i)] = i
			mu.Unlock()
			
			// Channel operation without mutex (correct)
			// ok: rule-channel-guarded-with-mutex
			ch <- i
		}
		close(ch)
	}()
	
	for val := range ch {
		fmt.Printf("Received: %d\n", val)
	}
	
	mu.Lock()
	fmt.Printf("Final data: %v\n", data)
	mu.Unlock()
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	requestCh := make(chan string)
	responseCh := make(chan string)
	
	// Server goroutine
	go func() {
		for req := range requestCh {
			// Process request
			resp := "Response to: " + req
			
			// Send response
			// ok: rule-channel-guarded-with-mutex
			responseCh <- resp
		}
	}()
	
	// Client code
	go func() {
		requestCh <- "Hello"
		resp := <-responseCh
		fmt.Println(resp)
		close(requestCh)
	}()
	
	time.Sleep(100 * time.Millisecond)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	// Using mutex for other operations, not for channel
	var mu sync.Mutex
	counter := 0
	dataCh := make(chan []byte, 5)
	
	go func() {
		data := []byte("important data")
		
		// Update counter with mutex (correct usage)
		mu.Lock()
		counter++
		mu.Unlock()
		
		// Channel operation without mutex (correct)
		// ok: rule-channel-guarded-with-mutex
		dataCh <- data
	}()
	
	receivedData := <-dataCh
	fmt.Printf("Received %d bytes\n", len(receivedData))
	
	mu.Lock()
	fmt.Printf("Counter: %d\n", counter)
	mu.Unlock()
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	eventCh := make(chan string)
	
	// Event producer
	go func() {
		events := []string{"start", "processing", "end"}
		for _, event := range events {
			// ok: rule-channel-guarded-with-mutex
			eventCh <- event
		}
		close(eventCh)
	}()
	
	// Event consumer
	for event := range eventCh {
		fmt.Println("Event:", event)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	// Using mutex for shared data, channel for signaling
	var mu sync.Mutex
	results := make([]string, 0)
	doneCh := make(chan struct{})
	
	go func() {
		// Update shared slice with mutex (correct usage)
		mu.Lock()
		results = append(results, "operation completed")
		mu.Unlock()
		
		// Signal completion without mutex (correct)
		// ok: rule-channel-guarded-with-mutex
		doneCh <- struct{}{}
	}()
	
	<-doneCh
	
	mu.Lock()
	fmt.Println("Results:", results)
	mu.Unlock()
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	ch := make(chan struct{})
	
	for i := 0; i < 3; i++ {
		go func(id int) {
			// ok: rule-channel-guarded-with-mutex
			ch <- struct{}{}
			fmt.Printf("Worker %d sent signal\n", id)
		}(i)
	}
	
	// Wait for all workers
	for i := 0; i < 3; i++ {
		<-ch
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	// Using buffered channel as a semaphore
	semaphore := make(chan struct{}, 3) // Allow 3 concurrent operations
	
	for i := 0; i < 5; i++ {
		go func(id int) {
			// ok: rule-channel-guarded-with-mutex
			semaphore <- struct{}{} // Acquire
			
			// Do work
			fmt.Printf("Worker %d is working\n", id)
			time.Sleep(100 * time.Millisecond)
			
			<-semaphore // Release
		}(i)
	}
	
	time.Sleep(1 * time.Second)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	type Message struct {
		ID   int
		Data string
	}
	
	msgCh := make(chan Message)
	
	go func() {
		for i := 0; i < 3; i++ {
			msg := Message{
				ID:   i,
				Data: fmt.Sprintf("Message %d", i),
			}
			
			// ok: rule-channel-guarded-with-mutex
			msgCh <- msg
		}
		close(msgCh)
	}()
	
	for msg := range msgCh {
		fmt.Printf("Received message: %+v\n", msg)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	// Using select with multiple channels
	ch1 := make(chan string)
	ch2 := make(chan string)
	
	go func() {
		// ok: rule-channel-guarded-with-mutex
		ch1 <- "message from channel 1"
	}()
	
	go func() {
		// ok: rule-channel-guarded-with-mutex
		ch2 <- "message from channel 2"
	}()
	
	// Select from multiple channels
	select {
	case msg1 := <-ch1:
		fmt.Println(msg1)
	case msg2 := <-ch2:
		fmt.Println(msg2)
	case <-time.After(1 * time.Second):
		fmt.Println("Timeout")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	// Using mutex for shared data structure, channel for communication
	var mu sync.Mutex
	cache := make(map[string]int)
	requestCh := make(chan string)
	responseCh := make(chan int)
	
	// Cache service
	go func() {
		for key := range requestCh {
			var value int
			
			// Access shared map with mutex (correct usage)
			mu.Lock()
			value = cache[key]
			mu.Unlock()
			
			// Send response without mutex (correct)
			// ok: rule-channel-guarded-with-mutex
			responseCh <- value
		}
	}()
	
	// Update cache
	mu.Lock()
	cache["foo"] = 42
	mu.Unlock()
	
	// Request value
	requestCh <- "foo"
	value := <-responseCh
	fmt.Printf("Value: %d\n", value)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	// Using channel for worker pool
	jobs := make(chan int, 100)
	results := make(chan int, 100)
	
	// Start workers
	for w := 1; w <= 3; w++ {
		go func(id int) {
			for job := range jobs {
				fmt.Printf("Worker %d processing job %d\n", id, job)
				// ok: rule-channel-guarded-with-mutex
				results <- job * 2
			}
		}(w)
	}
	
	// Send jobs
	for j := 1; j <= 5; j++ {
		jobs <- j
	}
	close(jobs)
	
	// Collect results
	for a := 1; a <= 5; a++ {
		<-results
	}
}
// {/fact}

func main() {
	// This function is just a placeholder
	fmt.Println("Run individual test cases to see their behavior")
}