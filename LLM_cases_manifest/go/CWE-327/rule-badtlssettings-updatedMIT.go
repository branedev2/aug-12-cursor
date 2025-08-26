package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_1() {
	// Creating a TLS config with insecure cipher suites
	config := &tls.Config{
		// ruleid: rule-badtlssettings-updatedMIT
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_2() {
	// Using deprecated TLS version
	config := &tls.Config{
		// ruleid: rule-badtlssettings-updatedMIT
		MinVersion: tls.VersionSSL30,
		MaxVersion: tls.VersionTLS10,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_3() {
	// Using insecure cipher suites in a server configuration
	// ruleid: rule-badtlssettings-updatedMIT
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_RC4_128_SHA,
			},
		},
	}
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("Error:", err)
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_4() {
	// Using multiple insecure configurations
	// ruleid: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		InsecureSkipVerify: true,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_5() {
	// Using insecure cipher suites with conditional logic
	cipherSuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	}
	
	// Adding insecure cipher suites based on condition
	if os.Getenv("LEGACY_SUPPORT") == "true" {
		// ruleid: rule-badtlssettings-updatedMIT
		cipherSuites = append(cipherSuites, 
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	}
	
	config := &tls.Config{
		CipherSuites: cipherSuites,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_6() {
	// Using a variable to hold insecure cipher suites
	// ruleid: rule-badtlssettings-updatedMIT
	insecureCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}
	
	config := &tls.Config{
		CipherSuites: insecureCiphers,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_7() {
	// Using a function that returns insecure TLS config
	// ruleid: rule-badtlssettings-updatedMIT
	config := getInsecureTLSConfig()
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

func getInsecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		},
	}
}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_8() {
	// Using insecure cipher suites in a custom HTTPS server
	// ruleid: rule-badtlssettings-updatedMIT
	tlsConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(handleRequest),
	}
	
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("Error:", err)
	}
}
// {/fact}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, TLS!")
}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_9() {
	// Using a mix of secure and insecure cipher suites
	// ruleid: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // Secure
			tls.TLS_RSA_WITH_RC4_128_SHA,              // Insecure
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,  // Secure
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,   // Insecure
		},
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_10() {
	// Using insecure cipher suites with TLS 1.2
	// ruleid: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_11() {
	// Using insecure cipher suites with a custom dialer
	// ruleid: rule-badtlssettings-updatedMIT
	dialer := &tls.Dialer{
		Config: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			},
		},
	}
	
	conn, err := dialer.Dial("tcp", "example.com:443")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_12() {
	// Using insecure cipher suites with a switch statement
	var cipherSuites []uint16
	
	mode := "compatibility"
	switch mode {
	case "secure":
		cipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	case "compatibility":
		// ruleid: rule-badtlssettings-updatedMIT
		cipherSuites = []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
	}
	
	config := &tls.Config{
		CipherSuites: cipherSuites,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_13() {
	// Using insecure cipher suites with a map lookup
	cipherMap := map[string][]uint16{
		"modern": {
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		"legacy": {
			// ruleid: rule-badtlssettings-updatedMIT
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		},
	}
	
	profile := "legacy"
	config := &tls.Config{
		CipherSuites: cipherMap[profile],
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_14() {
	// Using insecure cipher suites with a loop to add them
	cipherSuites := []uint16{}
	
	insecureCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	}
	
	// ruleid: rule-badtlssettings-updatedMIT
	for _, cipher := range insecureCiphers {
		cipherSuites = append(cipherSuites, cipher)
	}
	
	config := &tls.Config{
		CipherSuites: cipherSuites,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
func bad_case_15() {
	// Using insecure cipher suites with a slice operation
	allCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	
	// ruleid: rule-badtlssettings-updatedMIT
	selectedCiphers := allCiphers[1:4] // Includes insecure ciphers
	
	config := &tls.Config{
		CipherSuites: selectedCiphers,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_1() {
	// Using only secure cipher suites
	// ok: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_2() {
	// Using secure TLS version
	// ok: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_3() {
	// Using secure cipher suites in a server configuration
	// ok: rule-badtlssettings-updatedMIT
	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			MinVersion: tls.VersionTLS12,
		},
	}
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("Error:", err)
	}
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_4() {
	// Using default cipher suites with TLS 1.3
	// ok: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// No explicit CipherSuites means Go will use secure defaults for TLS 1.3
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_5() {
	// Using secure cipher suites with conditional logic
	cipherSuites := []uint16{}
	
	// ok: rule-badtlssettings-updatedMIT
	if os.Getenv("HIGH_SECURITY") == "true" {
		cipherSuites = append(cipherSuites, 
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	} else {
		cipherSuites = append(cipherSuites, 
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305)
	}
	
	config := &tls.Config{
		CipherSuites: cipherSuites,
		MinVersion:   tls.VersionTLS12,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_6() {
	// Using a variable to hold secure cipher suites
	// ok: rule-badtlssettings-updatedMIT
	secureCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	
	config := &tls.Config{
		CipherSuites: secureCiphers,
		MinVersion:   tls.VersionTLS12,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_7() {
	// Using a function that returns secure TLS config
	// ok: rule-badtlssettings-updatedMIT
	config := getSecureTLSConfig()
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

func getSecureTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_8() {
	// Using secure cipher suites in a custom HTTPS server
	// ok: rule-badtlssettings-updatedMIT
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(handleSecureRequest),
	}
	
	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		fmt.Println("Error:", err)
	}
}
// {/fact}

func handleSecureRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, Secure TLS!")
}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_9() {
	// Using TLS 1.3 only (which has secure cipher suites by default)
	// ok: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_10() {
	// Using secure cipher suites with a custom dialer
	// ok: rule-badtlssettings-updatedMIT
	dialer := &tls.Dialer{
		Config: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
	}
	
	conn, err := dialer.Dial("tcp", "example.com:443")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_11() {
	// Using secure cipher suites with a switch statement
	var cipherSuites []uint16
	
	mode := "secure"
	switch mode {
	case "secure":
		// ok: rule-badtlssettings-updatedMIT
		cipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	case "compatibility":
		cipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}
	
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_12() {
	// Using secure cipher suites with a map lookup
	cipherMap := map[string][]uint16{
		"modern": {
			// ok: rule-badtlssettings-updatedMIT
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		"high_security": {
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	
	profile := "modern"
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherMap[profile],
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_13() {
	// Using secure cipher suites with a loop to add them
	cipherSuites := []uint16{}
	
	secureCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	
	// ok: rule-badtlssettings-updatedMIT
	for _, cipher := range secureCiphers {
		cipherSuites = append(cipherSuites, cipher)
	}
	
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_14() {
	// Using secure cipher suites with a slice operation
	allCiphers := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	
	// ok: rule-badtlssettings-updatedMIT
	selectedCiphers := allCiphers[0:2] // Only includes secure ciphers
	
	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: selectedCiphers,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
func good_case_15() {
	// Using system defaults with TLS 1.2+ (which are generally secure)
	// ok: rule-badtlssettings-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// No explicit CipherSuites means Go will use secure defaults
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("TLS Configuration Examples")
}