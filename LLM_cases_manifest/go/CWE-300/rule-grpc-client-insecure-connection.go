package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/examples/helloworld/helloworld"
)

// BAD CASES - Insecure gRPC connections

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_1() {
	// Basic insecure connection
	// ruleid: rule-grpc-client-insecure-connection
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := helloworld.NewGreeterClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "world"})
	if err != nil {
		log.Fatalf("Could not greet: %v", err)
	}
	fmt.Printf("Greeting: %s", resp.GetMessage())
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_2() {
	// Insecure connection with additional options
	opts := []grpc.DialOption{
		// ruleid: rule-grpc-client-insecure-connection
		grpc.WithInsecure(),
		grpc.WithBlock(),
	}
	conn, err := grpc.Dial("example.com:50051", opts...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := helloworld.NewGreeterClient(conn)
	ctx := context.Background()
	resp, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "user"})
	if err != nil {
		log.Fatalf("Could not greet: %v", err)
	}
	fmt.Printf("Greeting: %s", resp.GetMessage())
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_3() {
	// Insecure connection in a function that handles HTTP requests
	http.HandleFunc("/make-grpc-call", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "localhost:50051"
		}
		// ruleid: rule-grpc-client-insecure-connection
		conn, err := grpc.Dial(target, grpc.WithInsecure())
		if err != nil {
			http.Error(w, "Failed to connect to gRPC service", http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		client := helloworld.NewGreeterClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "web user"})
		if err != nil {
			http.Error(w, "gRPC call failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Response: %s", resp.GetMessage())
	})
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_4() {
	// Insecure connection with timeout and retry options
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// ruleid: rule-grpc-client-insecure-connection
	conn, err := grpc.DialContext(ctx, "api.example.com:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := helloworld.NewGreeterClient(conn)
	resp, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "timeout example"})
	if err != nil {
		log.Fatalf("Could not greet: %v", err)
	}
	fmt.Printf("Greeting: %s", resp.GetMessage())
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_5() {
	// Insecure connection with conditional logic
	useSecure := false
	var opts []grpc.DialOption
	if useSecure {
		creds := credentials.NewClientTLSFromCert(nil, "")
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		// ruleid: rule-grpc-client-insecure-connection
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial("localhost:50051", opts...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_6() {
	// Insecure connection with environment-based configuration
	var conn *grpc.ClientConn
	var err error
	env := os.Getenv("ENVIRONMENT")
	if env == "production" {
		// This would be secure, but we're not in production
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("grpc.example.com:443", grpc.WithTransportCredentials(creds))
	} else {
		// ruleid: rule-grpc-client-insecure-connection
		conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	}
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_7() {
	// Using a helper function that returns insecure options
	getDialOptions := func() []grpc.DialOption {
		return []grpc.DialOption{
			// ruleid: rule-grpc-client-insecure-connection
			grpc.WithInsecure(),
		}
	}
	conn, err := grpc.Dial("localhost:50051", getDialOptions()...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_8() {
	// Multiple connections, one secure and one insecure
	// First connection is secure
	creds := credentials.NewClientTLSFromCert(nil, "")
	secureConn, err := grpc.Dial("secure.example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect securely: %v", err)
	}
	defer secureConn.Close()
	
	// Second connection is insecure
	// ruleid: rule-grpc-client-insecure-connection
	insecureConn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect insecurely: %v", err)
	}
	defer insecureConn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_9() {
	// Insecure connection with a custom user agent
	// ruleid: rule-grpc-client-insecure-connection
	conn, err := grpc.Dial(
		"api.example.com:50051",
		grpc.WithInsecure(),
		grpc.WithUserAgent("MyCustomApp/1.0"),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_10() {
	// Insecure connection with a loop for multiple endpoints
	endpoints := []string{"server1:50051", "server2:50051", "server3:50051"}
	for _, endpoint := range endpoints {
		// ruleid: rule-grpc-client-insecure-connection
		conn, err := grpc.Dial(endpoint, grpc.WithInsecure())
		if err != nil {
			log.Printf("Failed to connect to %s: %v", endpoint, err)
			continue
		}
		defer conn.Close()
		client := helloworld.NewGreeterClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = client.SayHello(ctx, &helloworld.HelloRequest{Name: "multi-server test"})
		if err == nil {
			break
		}
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_11() {
	// Using insecure.NewCredentials() from newer gRPC versions
	// ruleid: rule-grpc-client-insecure-connection
	conn, err := grpc.Dial(
		"localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_12() {
	// Storing the insecure option in a variable
	// ruleid: rule-grpc-client-insecure-connection
	insecureOpt := grpc.WithInsecure()
	conn, err := grpc.Dial("localhost:50051", insecureOpt)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_13() {
	// Using a switch statement to determine connection type
	connType := "dev"
	var conn *grpc.ClientConn
	var err error
	
	switch connType {
	case "prod":
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("prod.example.com:443", grpc.WithTransportCredentials(creds))
	case "staging":
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("staging.example.com:443", grpc.WithTransportCredentials(creds))
	default:
		// ruleid: rule-grpc-client-insecure-connection
		conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	}
	
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_14() {
	// Using a map to store connection options
	optionsMap := map[string][]grpc.DialOption{
		"secure": {
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
		},
		"insecure": {
			// ruleid: rule-grpc-client-insecure-connection
			grpc.WithInsecure(),
		},
	}
	
	connType := "insecure"
	conn, err := grpc.Dial("localhost:50051", optionsMap[connType]...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_15() {
	// Using a struct to configure the connection
	type GrpcConfig struct {
		Target  string
		Secure  bool
		Options []grpc.DialOption
	}
	
	config := GrpcConfig{
		Target: "localhost:50051",
		Secure: false,
	}
	
	if config.Secure {
		config.Options = append(config.Options, 
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		// ruleid: rule-grpc-client-insecure-connection
		config.Options = append(config.Options, grpc.WithInsecure())
	}
	
	conn, err := grpc.Dial(config.Target, config.Options...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// GOOD CASES - Secure gRPC connections

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_1() {
	// Basic secure connection with system certificates
	// ok: rule-grpc-client-insecure-connection
	creds := credentials.NewClientTLSFromCert(nil, "")
	conn, err := grpc.Dial("secure.example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_2() {
	// Secure connection with custom TLS configuration
	// ok: rule-grpc-client-insecure-connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("api.example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_3() {
	// Secure connection with certificate loading
	// ok: rule-grpc-client-insecure-connection
	certFile := "cert.pem"
	keyFile := "key.pem"
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		log.Fatalf("Failed to read cert file: %v", err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to add cert to pool")
	}
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("secure.example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_4() {
	// Secure connection in an HTTP handler
	http.HandleFunc("/secure-grpc-call", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "api.example.com:443"
		}
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err := grpc.Dial(target, grpc.WithTransportCredentials(creds))
		if err != nil {
			http.Error(w, "Failed to connect to gRPC service", http.StatusInternalServerError)
			return
		}
		defer conn.Close()
		client := helloworld.NewGreeterClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := client.SayHello(ctx, &helloworld.HelloRequest{Name: "web user"})
		if err != nil {
			http.Error(w, "gRPC call failed", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Response: %s", resp.GetMessage())
	})
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_5() {
	// Secure connection with timeout and retry options
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// ok: rule-grpc-client-insecure-connection
	creds := credentials.NewClientTLSFromCert(nil, "")
	conn, err := grpc.DialContext(ctx, "api.example.com:443", grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_6() {
	// Secure connection with conditional logic
	useSecure := true
	var opts []grpc.DialOption
	if useSecure {
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		// This branch is not taken
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial("api.example.com:443", opts...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_7() {
	// Secure connection with environment-based configuration
	var conn *grpc.ClientConn
	var err error
	env := "production"
	if env == "production" {
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("grpc.example.com:443", grpc.WithTransportCredentials(creds))
	} else {
		// This branch is not taken
		conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	}
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_8() {
	// Using a helper function that returns secure options
	getDialOptions := func() []grpc.DialOption {
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		return []grpc.DialOption{
			grpc.WithTransportCredentials(creds),
		}
	}
	conn, err := grpc.Dial("api.example.com:443", getDialOptions()...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_9() {
	// Multiple secure connections
	// First connection
	// ok: rule-grpc-client-insecure-connection
	creds1 := credentials.NewClientTLSFromCert(nil, "")
	conn1, err := grpc.Dial("service1.example.com:443", grpc.WithTransportCredentials(creds1))
	if err != nil {
		log.Fatalf("Failed to connect to service1: %v", err)
	}
	defer conn1.Close()
	
	// Second connection
	// ok: rule-grpc-client-insecure-connection
	creds2 := credentials.NewClientTLSFromCert(nil, "")
	conn2, err := grpc.Dial("service2.example.com:443", grpc.WithTransportCredentials(creds2))
	if err != nil {
		log.Fatalf("Failed to connect to service2: %v", err)
	}
	defer conn2.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_10() {
	// Secure connection with a custom user agent
	// ok: rule-grpc-client-insecure-connection
	creds := credentials.NewClientTLSFromCert(nil, "")
	conn, err := grpc.Dial(
		"api.example.com:443",
		grpc.WithTransportCredentials(creds),
		grpc.WithUserAgent("MySecureApp/1.0"),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_11() {
	// Secure connection with a loop for multiple endpoints
	endpoints := []string{"server1.example.com:443", "server2.example.com:443"}
	for _, endpoint := range endpoints {
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err := grpc.Dial(endpoint, grpc.WithTransportCredentials(creds))
		if err != nil {
			log.Printf("Failed to connect to %s: %v", endpoint, err)
			continue
		}
		defer conn.Close()
		client := helloworld.NewGreeterClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = client.SayHello(ctx, &helloworld.HelloRequest{Name: "multi-server test"})
		if err == nil {
			break
		}
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_12() {
	// Using a switch statement to determine connection type
	connType := "prod"
	var conn *grpc.ClientConn
	var err error
	
	switch connType {
	case "prod":
		// ok: rule-grpc-client-insecure-connection
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("prod.example.com:443", grpc.WithTransportCredentials(creds))
	case "staging":
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err = grpc.Dial("staging.example.com:443", grpc.WithTransportCredentials(creds))
	default:
		// This branch is not taken
		conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	}
	
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_13() {
	// Using a map to store connection options
	optionsMap := map[string][]grpc.DialOption{
		"secure": {
			// ok: rule-grpc-client-insecure-connection
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
		},
		"insecure": {
			grpc.WithInsecure(),
		},
	}
	
	connType := "secure"
	conn, err := grpc.Dial("api.example.com:443", optionsMap[connType]...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_14() {
	// Using a struct to configure the connection
	type GrpcConfig struct {
		Target  string
		Secure  bool
		Options []grpc.DialOption
	}
	
	config := GrpcConfig{
		Target: "api.example.com:443",
		Secure: true,
	}
	
	if config.Secure {
		// ok: rule-grpc-client-insecure-connection
		config.Options = append(config.Options, 
			grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		// This branch is not taken
		config.Options = append(config.Options, grpc.WithInsecure())
	}
	
	conn, err := grpc.Dial(config.Target, config.Options...)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_15() {
	// Using mutual TLS authentication
	// ok: rule-grpc-client-insecure-connection
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatalf("Failed to load client cert: %v", err)
	}
	
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial("secure.example.com:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("gRPC security examples")
}