package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"time"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_1() {
	// Using deprecated TLS 1.0
	config := &tls.Config{
		// ruleid: rule-tlsversion-updatedMIT
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_2() {
	// Using deprecated TLS 1.1
	config := &tls.Config{
		// ruleid: rule-tlsversion-updatedMIT
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_3() {
	// Using SSL 3.0
	// ruleid: rule-tlsversion-updatedMIT
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionSSL30,
	}
	listener, _ := tls.Listen("tcp", ":443", tlsConfig)
	_ = http.Serve(listener, nil)
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_4() {
	// Not setting MinVersion at all
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_5() {
	// Setting TLS 1.2 which is not the recommended 1.3
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_6() {
	// Creating a custom dialer with TLS 1.0
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	// ruleid: rule-tlsversion-updatedMIT
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
	
	transport := &http.Transport{
		DialContext:     dialer.DialContext,
		TLSClientConfig: tlsConfig,
	}
	
	client := &http.Client{Transport: transport}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_7() {
	// Using a variable to set TLS version to 1.1
	var tlsVersion uint16 = tls.VersionTLS11
	
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tlsVersion,
	}
	
	conn, _ := tls.Dial("tcp", "example.com:443", config)
	defer conn.Close()
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_8() {
	// Setting both min and max to TLS 1.1
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS11,
		MaxVersion: tls.VersionTLS11,
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_9() {
	// Using TLS 1.0 with client authentication
	certPool := x509.NewCertPool()
	pem, _ := ioutil.ReadFile("ca.pem")
	certPool.AppendCertsFromPEM(pem)
	
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS10,
		RootCAs:    certPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_10() {
	// Setting up a server with TLS 1.2 and insecure cipher suites
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_11() {
	// Creating a TLS config with conditional TLS version
	secure := false
	var version uint16
	if secure {
		version = tls.VersionTLS13
	} else {
		version = tls.VersionTLS11
	}
	
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: version,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_12() {
	// Using a function to get TLS version (returning TLS 1.0)
	getTLSVersion := func() uint16 {
		return tls.VersionTLS10
	}
	
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: getTLSVersion(),
	}
	
	conn, _ := tls.Dial("tcp", "example.com:443", config)
	defer conn.Close()
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_13() {
	// Setting up a server with empty TLS config
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_14() {
	// Using a map to store and retrieve TLS version
	tlsVersions := map[string]uint16{
		"old":    tls.VersionTLS10,
		"medium": tls.VersionTLS12,
		"new":    tls.VersionTLS13,
	}
	
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tlsVersions["old"],
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
func bad_case_15() {
	// Creating a TLS listener with TLS 1.1
	// ruleid: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS11,
		ClientAuth: tls.NoClientCert,
	}
	
	listener, _ := tls.Listen("tcp", ":443", config)
	defer listener.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go handleConnection(conn)
	}
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_1() {
	// Using recommended TLS 1.3
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_2() {
	// Setting minimum to TLS 1.3 with maximum also specified
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_3() {
	// Using TLS 1.3 with client authentication
	certPool := x509.NewCertPool()
	pem, _ := ioutil.ReadFile("ca.pem")
	certPool.AppendCertsFromPEM(pem)
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    certPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_4() {
	// Creating a custom dialer with TLS 1.3
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	// ok: rule-tlsversion-updatedMIT
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	
	transport := &http.Transport{
		DialContext:     dialer.DialContext,
		TLSClientConfig: tlsConfig,
	}
	
	client := &http.Client{Transport: transport}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_5() {
	// Using a variable to set TLS version to 1.3
	var tlsVersion uint16 = tls.VersionTLS13
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tlsVersion,
	}
	
	conn, _ := tls.Dial("tcp", "example.com:443", config)
	defer conn.Close()
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_6() {
	// Setting up a server with TLS 1.3 and secure cipher suites
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_7() {
	// Creating a TLS config with conditional but always secure TLS version
	secure := false
	var version uint16
	if secure {
		version = tls.VersionTLS13
	} else {
		// Even in "insecure" mode, still use TLS 1.3
		version = tls.VersionTLS13
	}
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: version,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_8() {
	// Using a function to get TLS version (returning TLS 1.3)
	getTLSVersion := func() uint16 {
		return tls.VersionTLS13
	}
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: getTLSVersion(),
	}
	
	conn, _ := tls.Dial("tcp", "example.com:443", config)
	defer conn.Close()
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_9() {
	// Using a map to store and retrieve TLS version (using the secure one)
	tlsVersions := map[string]uint16{
		"old":    tls.VersionTLS10,
		"medium": tls.VersionTLS12,
		"new":    tls.VersionTLS13,
	}
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tlsVersions["new"],
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_10() {
	// Creating a TLS listener with TLS 1.3
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.NoClientCert,
	}
	
	listener, _ := tls.Listen("tcp", ":443", config)
	defer listener.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go handleConnection(conn)
	}
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_11() {
	// Using TLS 1.3 with custom certificate verification
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Custom certificate verification logic
			return nil
		},
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_12() {
	// Using TLS 1.3 with mutual TLS authentication
	cert, _ := tls.LoadX509KeyPair("client.crt", "client.key")
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_13() {
	// Using TLS 1.3 with session tickets disabled
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion:      tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_14() {
	// Using TLS 1.3 with custom key log
	keyLogFile, _ := ioutil.TempFile("", "tls-key-log")
	
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		KeyLogWriter: keyLogFile,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
func good_case_15() {
	// Using TLS 1.3 with custom curve preferences
	// ok: rule-tlsversion-updatedMIT
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
	
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}
	_ = server.ListenAndServeTLS("cert.pem", "key.pem")
}
// {/fact}

// Helper function for TLS listener example
func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Fprintf(conn, "Hello, TLS client\n")
}

func main() {
	log.Println("This file contains examples of secure and insecure TLS configurations")
}