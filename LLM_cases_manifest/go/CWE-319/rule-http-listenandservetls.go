package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_1() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	// ruleid: rule-http-listenandservetls
	http.ListenAndServe(":8080", nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_2() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to our service")
	})
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	// ruleid: rule-http-listenandservetls
	server.ListenAndServe()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_3() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API endpoint")
	})
	// ruleid: rule-http-listenandservetls
	http.ListenAndServe("localhost:8080", handler)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_4() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "success"}`)
	})
	// ruleid: rule-http-listenandservetls
	log.Fatal(http.ListenAndServe(":8080", mux))
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_5() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	// ruleid: rule-http-listenandservetls
	http.Serve(listener, nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_6() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")
		fmt.Fprintf(w, "Login attempt for %s", username)
	})
	// ruleid: rule-http-listenandservetls
	err := http.Serve(TCPKeepAliveListener{ln: ln}, mux)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_7() {
	http.HandleFunc("/payment", func(w http.ResponseWriter, r *http.Request) {
		cardNumber := r.FormValue("card")
		amount := r.FormValue("amount")
		fmt.Fprintf(w, "Processing payment of %s", amount)
	})
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	// ruleid: rule-http-listenandservetls
	http.ListenAndServe(":"+port, nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_8() {
	router := http.NewServeMux()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	// ruleid: rule-http-listenandservetls
	server.ListenAndServe()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_9() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	// ruleid: rule-http-listenandservetls
	http.Serve(listener, handler)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_10() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User data")
	})
	
	go func() {
		// ruleid: rule-http-listenandservetls
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Fatal(err)
		}
	}()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_11() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	addr := ":8080"
	server := &http.Server{
		Addr:    addr,
		Handler: http.DefaultServeMux,
	}
	// ruleid: rule-http-listenandservetls
	server.ListenAndServe()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_12() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})
	
	listener, _ := net.Listen("tcp", ":8080")
	// ruleid: rule-http-listenandservetls
	if err := http.Serve(listener, mux); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_13() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	for port := 8080; port < 8090; port++ {
		addr := fmt.Sprintf(":%d", port)
		// ruleid: rule-http-listenandservetls
		err := http.ListenAndServe(addr, nil)
		if err == nil {
			break
		}
	}
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_14() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	server := &http.Server{
		Handler: mux,
	}
	
	listener, _ := net.Listen("tcp", ":8080")
	// ruleid: rule-http-listenandservetls
	server.Serve(listener)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
func bad_case_15() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	server := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}
	
	go func() {
		// ruleid: rule-http-listenandservetls
		server.ListenAndServe()
	}()
	
	<-ctx.Done()
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_1() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	// ok: rule-http-listenandservetls
	http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_2() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome to our service")
	})
	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
	}
	// ok: rule-http-listenandservetls
	server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_3() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "API endpoint")
	})
	// ok: rule-http-listenandservetls
	http.ListenAndServeTLS("localhost:8443", "cert.pem", "key.pem", handler)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_4() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "success"}`)
	})
	// ok: rule-http-listenandservetls
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", mux))
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_5() {
	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	
	// Create TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	
	// Create TLS listener
	tlsListener := tls.NewListener(listener, tlsConfig)
	
	// ok: rule-http-listenandservetls
	http.Serve(tlsListener, nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_6() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		username := r.FormValue("username")
		password := r.FormValue("password")
		fmt.Fprintf(w, "Login attempt for %s", username)
	})
	
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	
	listener, _ := net.Listen("tcp", ":8443")
	tlsListener := tls.NewListener(listener, tlsConfig)
	
	// ok: rule-http-listenandservetls
	http.Serve(tlsListener, mux)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_7() {
	http.HandleFunc("/payment", func(w http.ResponseWriter, r *http.Request) {
		cardNumber := r.FormValue("card")
		amount := r.FormValue("amount")
		fmt.Fprintf(w, "Processing payment of %s", amount)
	})
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}
	
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	
	// ok: rule-http-listenandservetls
	http.ListenAndServeTLS(":"+port, certFile, keyFile, nil)
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_8() {
	router := http.NewServeMux()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	server := &http.Server{
		Addr:         ":8443",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	
	// ok: rule-http-listenandservetls
	server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_9() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	
	cert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsListener := tls.NewListener(listener, tlsConfig)
	
	// ok: rule-http-listenandservetls
	http.ServeTLS(listener, handler, "cert.pem", "key.pem")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_10() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User data")
	})
	
	go func() {
		// ok: rule-http-listenandservetls
		if err := http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", mux); err != nil {
			log.Fatal(err)
		}
	}()
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_11() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	addr := ":8443"
	server := &http.Server{
		Addr:    addr,
		Handler: http.DefaultServeMux,
	}
	
	// ok: rule-http-listenandservetls
	server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_12() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})
	
	listener, _ := net.Listen("tcp", ":8443")
	// ok: rule-http-listenandservetls
	if err := http.ServeTLS(listener, mux, "cert.pem", "key.pem"); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_13() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	certFile := "cert.pem"
	keyFile := "key.pem"
	
	for port := 8443; port < 8453; port++ {
		addr := fmt.Sprintf(":%d", port)
		// ok: rule-http-listenandservetls
		err := http.ListenAndServeTLS(addr, certFile, keyFile, nil)
		if err == nil {
			break
		}
	}
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_14() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	server := &http.Server{
		Handler: mux,
	}
	
	listener, _ := net.Listen("tcp", ":8443")
	// ok: rule-http-listenandservetls
	server.ServeTLS(listener, "cert.pem", "key.pem")
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
func good_case_15() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	server := &http.Server{
		Addr:    ":8443",
		Handler: handler,
	}
	
	go func() {
		// ok: rule-http-listenandservetls
		server.ListenAndServeTLS("cert.pem", "key.pem")
	}()
	
	<-ctx.Done()
}
// {/fact}

// Helper type for bad_case_6
type TCPKeepAliveListener struct {
	ln net.Listener
}

func main() {
	// This is just a placeholder main function
	fmt.Println("This file contains examples of secure and insecure HTTP server implementations.")
}