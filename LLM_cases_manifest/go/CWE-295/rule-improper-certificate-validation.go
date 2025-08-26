package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-redis/redis/v8"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_1() {
	// Basic HTTP client with InsecureSkipVerify set to true
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// ruleid: rule-improper-certificate-validation
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_2() {
	// Creating a TLS config directly and using it in a custom dialer
	config := &tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: true,
	}
	
	conn, err := tls.Dial("tcp", "example.com:443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_3() {
	// Using InsecureSkipVerify with conditional logic that always evaluates to true
	isDevEnvironment := true
	
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// ruleid: rule-improper-certificate-validation
			InsecureSkipVerify: isDevEnvironment,
		},
	}
	client := &http.Client{Transport: tr}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_4() {
	// Using InsecureSkipVerify in a MySQL database connection
	mysql.RegisterTLSConfig("custom", &tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: true,
	})
	
	db, err := mysql.NewConnector(&mysql.Config{
		User:      "user",
		Passwd:    "password",
		Net:       "tcp",
		Addr:      "127.0.0.1:3306",
		TLSConfig: "custom",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(db)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_5() {
	// Using InsecureSkipVerify in a gRPC client connection
	creds := credentials.NewTLS(&tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: true,
	})
	
	conn, err := grpc.Dial("example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_6() {
	// Using InsecureSkipVerify in a Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		TLSConfig: &tls.Config{
			// ruleid: rule-improper-certificate-validation
			InsecureSkipVerify: true,
		},
	})
	
	ctx := context.Background()
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_7() {
	// Using InsecureSkipVerify in an SMTP client
	tlsConfig := &tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: true,
	}
	
	c, err := smtp.Dial("smtp.example.com:587")
	if err != nil {
		log.Fatal(err)
	}
	
	if err = c.StartTLS(tlsConfig); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_8() {
	// Using InsecureSkipVerify in an AWS S3 session
	sess, err := session.NewSession(&aws.Config{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// ruleid: rule-improper-certificate-validation
					InsecureSkipVerify: true,
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	
	s3Client := s3.New(sess)
	_, err = s3Client.ListBuckets(nil)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_9() {
	// Using InsecureSkipVerify with a variable assignment
	skipVerify := true
	
	config := &tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: skipVerify,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_10() {
	// Using InsecureSkipVerify in a custom HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// ruleid: rule-improper-certificate-validation
				InsecureSkipVerify: true,
			},
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_11() {
	// Using InsecureSkipVerify with a custom dialer
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	transport := &http.Transport{
		DialContext:     dialer.DialContext,
		TLSClientConfig: &tls.Config{
			// ruleid: rule-improper-certificate-validation
			InsecureSkipVerify: true,
		},
	}
	
	client := &http.Client{Transport: transport}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_12() {
	// Using InsecureSkipVerify in a function that returns a client
	getClient := func() *http.Client {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// ruleid: rule-improper-certificate-validation
					InsecureSkipVerify: true,
				},
			},
		}
	}
	
	client := getClient()
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_13() {
	// Using InsecureSkipVerify with a switch statement that always leads to true
	var environment string = "development"
	var skipVerify bool
	
	switch environment {
	case "development":
		skipVerify = true
	case "staging":
		skipVerify = true
	default:
		skipVerify = false
	}
	
	config := &tls.Config{
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: skipVerify,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_14() {
	// Using InsecureSkipVerify in a custom TLS listener
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		// ruleid: rule-improper-certificate-validation
		InsecureSkipVerify: true,
	}
	
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
func bad_case_15() {
	// Using InsecureSkipVerify in an SSH client with custom config
	sshConfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // This is also insecure but not what we're testing
	}
	
	// Create a custom HTTP client that uses SSH tunneling
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// ruleid: rule-improper-certificate-validation
			InsecureSkipVerify: true,
		},
	}
	
	client := &http.Client{Transport: httpTransport}
	_, _ = client.Get("https://example.com")
	
	// Just to use sshConfig
	fmt.Println(sshConfig.User)
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_1() {
	// Basic HTTP client with InsecureSkipVerify set to false
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// ok: rule-improper-certificate-validation
			InsecureSkipVerify: false,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://example.com")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_2() {
	// Creating a TLS config without specifying InsecureSkipVerify (defaults to false)
	// ok: rule-improper-certificate-validation
	config := &tls.Config{}
	
	conn, err := tls.Dial("tcp", "example.com:443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_3() {
	// Using a custom certificate pool
	certPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(pem) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	config := &tls.Config{
		RootCAs: certPool,
	}
	
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_4() {
	// Using a MySQL connection with proper certificate validation
	rootCertPool := x509.NewCertPool()
	pem, err := ioutil.ReadFile("/path/to/ca-cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		log.Fatal("Failed to append PEM.")
	}
	
	// ok: rule-improper-certificate-validation
	mysql.RegisterTLSConfig("custom", &tls.Config{
		RootCAs: rootCertPool,
	})
	
	db, err := mysql.NewConnector(&mysql.Config{
		User:      "user",
		Passwd:    "password",
		Net:       "tcp",
		Addr:      "127.0.0.1:3306",
		TLSConfig: "custom",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(db)
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_5() {
	// Using proper certificate validation in gRPC
	certPool := x509.NewCertPool()
	bs, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(bs) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	})
	
	conn, err := grpc.Dial("example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_6() {
	// Using proper certificate validation in Redis client
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	// ok: rule-improper-certificate-validation
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		TLSConfig: &tls.Config{
			RootCAs:      certPool,
			Certificates: []tls.Certificate{cert},
		},
	})
	
	ctx := context.Background()
	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_7() {
	// Using proper certificate validation in SMTP client
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}
	
	c, err := smtp.Dial("smtp.example.com:587")
	if err != nil {
		log.Fatal(err)
	}
	
	if err = c.StartTLS(tlsConfig); err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_8() {
	// Using proper certificate validation in AWS S3 session
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	sess, err := session.NewSession(&aws.Config{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	
	s3Client := s3.New(sess)
	_, err = s3Client.ListBuckets(nil)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_9() {
	// Using environment variable to control InsecureSkipVerify, defaulting to false
	skipVerifyStr := os.Getenv("SKIP_VERIFY")
	skipVerify := false
	if skipVerifyStr == "true" {
		skipVerify = true
	}
	
	// ok: rule-improper-certificate-validation
	if !skipVerify {
		config := &tls.Config{}
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
			},
		}
		_, _ = client.Get("https://example.com")
	}
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_10() {
	// Using a custom HTTP client with proper certificate validation and timeout
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_11() {
	// Using proper certificate validation with a custom dialer
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	
	client := &http.Client{Transport: transport}
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_12() {
	// Using a function that returns a client with proper certificate validation
	getClient := func() *http.Client {
		certPool := x509.NewCertPool()
		ca, err := ioutil.ReadFile("ca.pem")
		if err != nil {
			log.Fatal(err)
		}
		
		if !certPool.AppendCertsFromPEM(ca) {
			log.Fatal("Failed to append CA certificate")
		}
		
		// ok: rule-improper-certificate-validation
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			},
		}
	}
	
	client := getClient()
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_13() {
	// Using certificate pinning for additional security
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// Expected certificate fingerprint (SHA-256)
	expectedFingerprint := "PLACEHOLDER_SECRET_40_CHARS34567890abcdef1234567890"
	
	// ok: rule-improper-certificate-validation
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					// Verify certificate fingerprint
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					
					// This is a simplified example. In real code, you would compute the actual fingerprint
					fingerprint := base64.StdEncoding.EncodeToString(cert.Raw)
					if fingerprint != expectedFingerprint {
						return fmt.Errorf("certificate fingerprint mismatch")
					}
					
					return nil
				},
			},
		},
	}
	
	_, _ = client.Get("https://example.com")
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_14() {
	// Using proper certificate validation in a custom TLS listener
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	
	// ok: rule-improper-certificate-validation
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	
	listener, err := tls.Listen("tcp", ":443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
func good_case_15() {
	// Using proper host key callback in SSH client and proper TLS validation
	hostKeyCallback, err := ssh.NewKnownHostsCallback("/home/user/.ssh/known_hosts")
	if err != nil {
		log.Fatal(err)
	}
	
	sshConfig := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: hostKeyCallback,
	}
	
	certPool := x509.NewCertPool()
	ca, err := ioutil.ReadFile("ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	
	if !certPool.AppendCertsFromPEM(ca) {
		log.Fatal("Failed to append CA certificate")
	}
	
	// ok: rule-improper-certificate-validation
	httpTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	
	client := &http.Client{Transport: httpTransport}
	_, _ = client.Get("https://example.com")
	
	// Just to use sshConfig
	fmt.Println(sshConfig.User)
}
// {/fact}

func main() {
	// This function is just a placeholder to make the code compilable
	fmt.Println("TLS Certificate Validation Examples")
}