package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_1() {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// Dynamic trace creation based on runtime condition
	traceEnabled := true
	if traceEnabled {
		// ruleid: rule-httptrace-nonstatic-trace-usage
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				fmt.Printf("Connection reused: %v\n", info.Reused)
			},
		}))
	}
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_2() {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// Dynamic trace with user input
	userInput := "Connection established"
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			fmt.Println(userInput + " to " + addr)
		},
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_3() {
	// Function that returns a dynamic trace
	createTrace := func() *httptrace.ClientTrace {
		return &httptrace.ClientTrace{
			DNSStart: func(info httptrace.DNSStartInfo) {
				fmt.Printf("Looking up %s\n", info.Host)
			},
		}
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), createTrace())
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_4() {
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// Dynamic trace based on environment variable
	debugMode := os.Getenv("DEBUG_MODE")
	
	trace := &httptrace.ClientTrace{}
	if debugMode == "verbose" {
		trace.GotConn = func(info httptrace.GotConnInfo) {
			fmt.Printf("Connection: %+v\n", info)
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_5() {
	// Dynamic trace in a loop
	urls := []string{"https://example.com", "https://example.org"}
	
	for _, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		
		// ruleid: rule-httptrace-nonstatic-trace-usage
		ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				fmt.Printf("Getting connection for %s to %s\n", url, hostPort)
			},
		})
		
		req = req.WithContext(ctx)
		http.DefaultClient.Do(req)
	}
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_6() {
	// Dynamic trace with conditional handlers
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	trace := &httptrace.ClientTrace{}
	
	// Conditionally set handlers
	logLevel := "debug"
	if logLevel == "debug" {
		trace.DNSDone = func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS Info: %+v\n", info)
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_7() {
	// Dynamic trace with function composition
	createLogger := func(prefix string) func(httptrace.GotConnInfo) {
		return func(info httptrace.GotConnInfo) {
			fmt.Printf("%s: %+v\n", prefix, info)
		}
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: createLogger("Connection"),
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_8() {
	// Dynamic trace with closure capturing variables
	startTime := time.Now()
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			duration := time.Since(startTime)
			fmt.Printf("Request wrote after %v\n", duration)
		},
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_9() {
	// Dynamic trace with map of handlers
	handlers := map[string]interface{}{
		"connect": func(network, addr string) {
			fmt.Printf("Connecting to %s via %s\n", addr, network)
		},
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		ConnectStart: handlers["connect"].(func(network, addr string)),
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_10() {
	// Dynamic trace with runtime configuration
	type Config struct {
		LogDNS      bool
		LogConnect  bool
		LogTLSStart bool
	}
	
	config := Config{
		LogDNS:      true,
		LogConnect:  false,
		LogTLSStart: true,
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	trace := &httptrace.ClientTrace{}
	
	if config.LogDNS {
		trace.DNSStart = func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup: %s\n", info.Host)
		}
	}
	
	if config.LogConnect {
		trace.ConnectStart = func(network, addr string) {
			fmt.Printf("Connecting to %s\n", addr)
		}
	}
	
	if config.LogTLSStart {
		trace.TLSHandshakeStart = func() {
			fmt.Println("TLS handshake starting")
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_11() {
	// Dynamic trace with error handling based on runtime condition
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	errorHandler := func(err error) {
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		DNSDone: func(info httptrace.DNSDoneInfo) {
			errorHandler(info.Err)
		},
		ConnectDone: func(network, addr string, err error) {
			errorHandler(err)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			errorHandler(err)
		},
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_12() {
	// Dynamic trace with user-provided callback
	type TraceCallback func(event string, data interface{})
	
	callback := func(event string, data interface{}) {
		fmt.Printf("%s: %+v\n", event, data)
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			callback("GetConn", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			callback("GotConn", info)
		},
		PutIdleConn: func(err error) {
			callback("PutIdleConn", err)
		},
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_13() {
	// Dynamic trace with conditional compilation
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	debug := true // This would be set by build tags in real code
	
	trace := &httptrace.ClientTrace{}
	
	if debug {
		trace.ConnectStart = func(network, addr string) {
			fmt.Printf("ConnectStart: %s %s\n", network, addr)
		}
		trace.ConnectDone = func(network, addr string, err error) {
			fmt.Printf("ConnectDone: %s %s %v\n", network, addr, err)
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_14() {
	// Dynamic trace with dependency injection
	type Logger interface {
		Log(format string, args ...interface{})
	}
	
	type ConsoleLogger struct{}
	
	func (l *ConsoleLogger) Log(format string, args ...interface{}) {
		fmt.Printf(format, args...)
	}
	
	logger := &ConsoleLogger{}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			logger.Log("DNS lookup for %s started\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			logger.Log("DNS lookup done: %+v\n", info)
		},
	})
	
	req = req.WithContext(ctx)
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
func bad_case_15() {
	// Dynamic trace with runtime configuration from environment
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// Get configuration from environment
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info" // Default
	}
	
	trace := &httptrace.ClientTrace{}
	
	// Configure trace based on log level
	switch strings.ToLower(logLevel) {
	case "debug":
		trace.DNSStart = func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		}
		trace.ConnectStart = func(network, addr string) {
			fmt.Printf("Connection to %s started\n", addr)
		}
		fallthrough
	case "info":
		trace.GotConn = func(info httptrace.GotConnInfo) {
			fmt.Printf("Connection established: %+v\n", info)
		}
	}
	
	// ruleid: rule-httptrace-nonstatic-trace-usage
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_1() {
	// Static trace definition
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf("Connection reused: %v\n", info.Reused)
		},
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_2() {
	// Static trace with multiple handlers
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		},
		ConnectStart: func(network, addr string) {
			fmt.Printf("Connection to %s started\n", addr)
		},
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_3() {
	// Static trace with predefined functions
	dnsStartHandler := func(info httptrace.DNSStartInfo) {
		fmt.Printf("DNS lookup for %s started\n", info.Host)
	}
	
	dnsEndHandler := func(info httptrace.DNSDoneInfo) {
		fmt.Printf("DNS lookup done: %+v\n", info)
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart: dnsStartHandler,
		DNSDone:  dnsEndHandler,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_4() {
	// Static trace with nil handlers
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart:        nil,
		DNSDone:         nil,
		ConnectStart:    nil,
		ConnectDone:     nil,
		GotConn:         nil,
		GotFirstResponseByte: nil,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_5() {
	// Static trace with empty struct
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_6() {
	// Static trace with reusable handlers
	type TraceHandlers struct {
		DNSStartHandler  func(info httptrace.DNSStartInfo)
		DNSDoneHandler   func(info httptrace.DNSDoneInfo)
		ConnectHandler   func(network, addr string)
	}
	
	handlers := TraceHandlers{
		DNSStartHandler: func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		},
		DNSDoneHandler: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		},
		ConnectHandler: func(network, addr string) {
			fmt.Printf("Connection to %s started\n", addr)
		},
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart:     handlers.DNSStartHandler,
		DNSDone:      handlers.DNSDoneHandler,
		ConnectStart: handlers.ConnectHandler,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_7() {
	// Static trace with function references
	logDNSStart := func(info httptrace.DNSStartInfo) {
		fmt.Printf("DNS lookup for %s started\n", info.Host)
	}
	
	logDNSDone := func(info httptrace.DNSDoneInfo) {
		fmt.Printf("DNS lookup done: %+v\n", info)
	}
	
	logConnect := func(network, addr string) {
		fmt.Printf("Connection to %s started\n", addr)
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart:     logDNSStart,
		DNSDone:      logDNSDone,
		ConnectStart: logConnect,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_8() {
	// Static trace with package-level functions
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		GotConn: logGotConn,
		PutIdleConn: logPutIdleConn,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// Package-level functions for good_case_8
func logGotConn(info httptrace.GotConnInfo) {
	fmt.Printf("Connection established: %+v\n", info)
}

func logPutIdleConn(err error) {
	if err != nil {
		fmt.Printf("Error putting idle connection: %v\n", err)
	} else {
		fmt.Println("Connection returned to pool")
	}
}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_9() {
	// Static trace with anonymous functions
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		},
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_10() {
	// Static trace with factory function
	createStaticTrace := func() *httptrace.ClientTrace {
		return &httptrace.ClientTrace{
			DNSStart: func(info httptrace.DNSStartInfo) {
				fmt.Printf("DNS lookup for %s started\n", info.Host)
			},
			DNSDone: func(info httptrace.DNSDoneInfo) {
				fmt.Printf("DNS lookup done: %+v\n", info)
			},
		}
	}
	
	// Create the trace before request handling
	// ok: rule-httptrace-nonstatic-trace-usage
	staticTrace := createStaticTrace()
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	ctx := httptrace.WithClientTrace(req.Context(), staticTrace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_11() {
	// Static trace with comprehensive handlers
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			fmt.Printf("Getting connection for %s\n", hostPort)
		},
		GotConn: func(info httptrace.GotConnInfo) {
			fmt.Printf("Got connection: %+v\n", info)
		},
		PutIdleConn: func(err error) {
			if err != nil {
				fmt.Printf("Error putting idle connection: %v\n", err)
			}
		},
		GotFirstResponseByte: func() {
			fmt.Println("Got first response byte")
		},
		Got100Continue: func() {
			fmt.Println("Got 100 Continue response")
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		},
		ConnectStart: func(network, addr string) {
			fmt.Printf("Connection to %s started\n", addr)
		},
		ConnectDone: func(network, addr string, err error) {
			if err != nil {
				fmt.Printf("Connection to %s failed: %v\n", addr, err)
			} else {
				fmt.Printf("Connection to %s established\n", addr)
			}
		},
		TLSHandshakeStart: func() {
			fmt.Println("TLS handshake started")
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				fmt.Printf("TLS handshake failed: %v\n", err)
			} else {
				fmt.Println("TLS handshake completed successfully")
			}
		},
		WroteHeaderField: func(key string, value []string) {
			fmt.Printf("Wrote header: %s: %v\n", key, value)
		},
		WroteHeaders: func() {
			fmt.Println("Wrote headers")
		},
		Wait100Continue: func() {
			fmt.Println("Waiting for 100 Continue")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				fmt.Printf("Error writing request: %v\n", info.Err)
			} else {
				fmt.Println("Request successfully written")
			}
		},
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_12() {
	// Static trace with method references
	logger := &HTTPLogger{}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart: logger.LogDNSStart,
		DNSDone:  logger.LogDNSDone,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// Helper type for good_case_12
type HTTPLogger struct{}

func (l *HTTPLogger) LogDNSStart(info httptrace.DNSStartInfo) {
	fmt.Printf("DNS lookup for %s started\n", info.Host)
}

func (l *HTTPLogger) LogDNSDone(info httptrace.DNSDoneInfo) {
	fmt.Printf("DNS lookup done: %+v\n", info)
}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_13() {
	// Static trace with constant functions
	const (
		enableDNSLogging     = true
		enableConnectLogging = true
		enableTLSLogging     = false
	)
	
	// Define all handlers statically
	var dnsStartHandler func(info httptrace.DNSStartInfo)
	var dnsEndHandler func(info httptrace.DNSDoneInfo)
	var connectStartHandler func(network, addr string)
	var tlsStartHandler func()
	
	if enableDNSLogging {
		dnsStartHandler = func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		}
		dnsEndHandler = func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		}
	}
	
	if enableConnectLogging {
		connectStartHandler = func(network, addr string) {
			fmt.Printf("Connection to %s started\n", addr)
		}
	}
	
	if enableTLSLogging {
		tlsStartHandler = func() {
			fmt.Println("TLS handshake started")
		}
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart:         dnsStartHandler,
		DNSDone:          dnsEndHandler,
		ConnectStart:     connectStartHandler,
		TLSHandshakeStart: tlsStartHandler,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_14() {
	// Static trace with conditional initialization
	var dnsHandler func(info httptrace.DNSStartInfo)
	
	// Conditionally initialize the handler, but do it before creating the trace
	debugMode := os.Getenv("DEBUG_MODE")
	if debugMode == "verbose" {
		dnsHandler = func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		}
	} else {
		dnsHandler = func(info httptrace.DNSStartInfo) {
			// Simplified logging in non-verbose mode
			fmt.Printf("DNS: %s\n", info.Host)
		}
	}
	
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	
	// ok: rule-httptrace-nonstatic-trace-usage
	trace := &httptrace.ClientTrace{
		DNSStart: dnsHandler,
	}
	
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	
	http.DefaultClient.Do(req)
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
func good_case_15() {
	// Static trace with reuse across multiple requests
	// ok: rule-httptrace-nonstatic-trace-usage
	sharedTrace := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			fmt.Printf("DNS lookup for %s started\n", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			fmt.Printf("DNS lookup done: %+v\n", info)
		},
	}
	
	// Use the same trace for multiple requests
	urls := []string{"https://example.com", "https://example.org", "https://example.net"}
	
	for _, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		ctx := httptrace.WithClientTrace(req.Context(), sharedTrace)
		req = req.WithContext(ctx)
		
		http.DefaultClient.Do(req)
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("HTTP trace examples")
}