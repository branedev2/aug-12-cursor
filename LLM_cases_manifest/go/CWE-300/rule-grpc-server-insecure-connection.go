package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/examples/helloworld/helloworld"
)

// Simple implementation of the gRPC server for examples
type server struct {
	helloworld.UnimplementedGreeterServer
}

func (s *server) SayHello(ctx context.Context, in *helloworld.HelloRequest) (*helloworld.HelloReply, error) {
	return &helloworld.HelloReply{Message: "Hello " + in.GetName()}, nil
}

// BAD EXAMPLES - Insecure gRPC server configurations

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_1() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer()
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_2() {
	port := ":50052"
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(grpc.EmptyServerOption{})
	
	helloworld.RegisterGreeterServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_3() {
	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	var opts []grpc.ServerOption
	// No security options added
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(opts...)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_4() {
	// Create a listener on TCP port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 50054))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Create a gRPC server object with no security
	// ruleid: rule-grpc-server-insecure-connection
	grpcServer := grpc.NewServer()
	
	// Attach the Greeter service to the server
	helloworld.RegisterGreeterServer(grpcServer, &server{})
	
	// Serve gRPC server
	log.Println("Serving gRPC on 0.0.0.0:50054")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_5() {
	// Using a function to create the server
	createAndServeServer(":50055")
}
// {/fact}

func createAndServeServer(address string) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer()
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_6() {
	lis, err := net.Listen("tcp", ":50056")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Using multiple options but no security
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(
		grpc.MaxRecvMsgSize(1024*1024*10),
		grpc.MaxSendMsgSize(1024*1024*10),
	)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_7() {
	// Using a conditional but both paths are insecure
	useOption := true
	lis, err := net.Listen("tcp", ":50057")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	var s *grpc.Server
	if useOption {
		// ruleid: rule-grpc-server-insecure-connection
		s = grpc.NewServer(grpc.MaxConcurrentStreams(10))
	} else {
		// ruleid: rule-grpc-server-insecure-connection
		s = grpc.NewServer()
	}
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_8() {
	// Using a loop to create multiple servers, all insecure
	ports := []string{":50058", ":50059"}
	
	for _, port := range ports {
		go func(p string) {
			lis, err := net.Listen("tcp", p)
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}
			
			// ruleid: rule-grpc-server-insecure-connection
			s := grpc.NewServer()
			
			helloworld.RegisterGreeterServer(s, &server{})
			if err := s.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(port)
	}
	
	// Keep main goroutine alive
	select {}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_9() {
	// Using insecure transport credentials explicitly
	lis, err := net.Listen("tcp", ":50060")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_10() {
	// Creating server with options from a function that returns no security
	lis, err := net.Listen("tcp", ":50061")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(getServerOptions()...)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

func getServerOptions() []grpc.ServerOption {
	// No security options
	return []grpc.ServerOption{
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
	}
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_11() {
	// Using a switch statement but all cases are insecure
	serverType := "default"
	lis, err := net.Listen("tcp", ":50062")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	var s *grpc.Server
	switch serverType {
	case "high_performance":
		// ruleid: rule-grpc-server-insecure-connection
		s = grpc.NewServer(grpc.NumStreamWorkers(10))
	case "low_memory":
		// ruleid: rule-grpc-server-insecure-connection
		s = grpc.NewServer(grpc.MaxRecvMsgSize(1024))
	default:
		// ruleid: rule-grpc-server-insecure-connection
		s = grpc.NewServer()
	}
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_12() {
	// Creating a server with a custom interceptor but no security
	lis, err := net.Listen("tcp", ":50063")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			log.Printf("Request: %v", req)
			return handler(ctx, req)
		}),
	)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_13() {
	// Using environment variables but not for security
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50064"
	}
	
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer()
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_14() {
	// Creating multiple servers with different configurations but all insecure
	createInsecureServer(":50065", 1024*1024)
	createInsecureServer(":50066", 2*1024*1024)
}
// {/fact}

func createInsecureServer(address string, maxSize int) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ruleid: rule-grpc-server-insecure-connection
	s := grpc.NewServer(grpc.MaxRecvMsgSize(maxSize))
	
	helloworld.RegisterGreeterServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=1}
func bad_case_15() {
	// Using a map to store different server configurations, all insecure
	configs := map[string]int{
		":50067": 1024 * 1024,
		":50068": 2 * 1024 * 1024,
	}
	
	for addr, size := range configs {
		go func(address string, maxSize int) {
			lis, err := net.Listen("tcp", address)
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}
			
			// ruleid: rule-grpc-server-insecure-connection
			s := grpc.NewServer(grpc.MaxRecvMsgSize(maxSize))
			
			helloworld.RegisterGreeterServer(s, &server{})
			if err := s.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(addr, size)
	}
	
	// Keep main goroutine alive
	select {}
}
// {/fact}

// GOOD EXAMPLES - Secure gRPC server configurations

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_1() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	s := grpc.NewServer(grpc.Creds(creds))
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_2() {
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Create the TLS credentials
	certFile := "server.crt"
	keyFile := "server.key"
	
	// ok: rule-grpc-server-insecure-connection
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}
	
	s := grpc.NewServer(grpc.Creds(creds))
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_3() {
	lis, err := net.Listen("tcp", ":50053")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Create a certificate pool from the system certificate pool
	certPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("failed to load system cert pool: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	
	// ok: rule-grpc-server-insecure-connection
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_4() {
	// Create a listener on TCP port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", 50054))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key from environment variables
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" || keyFile == "" {
		certFile = "server.crt"
		keyFile = "server.key"
	}
	
	// ok: rule-grpc-server-insecure-connection
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}
	
	// Create a gRPC server with TLS credentials
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	
	// Attach the Greeter service to the server
	helloworld.RegisterGreeterServer(grpcServer, &server{})
	
	// Serve gRPC server
	log.Println("Serving gRPC on 0.0.0.0:50054")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_5() {
	// Using a function to create the secure server
	createAndServeSecureServer(":50055")
}
// {/fact}

func createAndServeSecureServer(address string) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	s := grpc.NewServer(grpc.Creds(creds))
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_6() {
	lis, err := net.Listen("tcp", ":50056")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	
	// Using multiple options including security
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(1024*1024*10),
		grpc.MaxSendMsgSize(1024*1024*10),
	)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_7() {
	// Using a conditional with secure options in both paths
	useStrictTLS := true
	lis, err := net.Listen("tcp", ":50057")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	var s *grpc.Server
	if useStrictTLS {
		// Create TLS configuration with client authentication
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		
		// ok: rule-grpc-server-insecure-connection
		s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		// ok: rule-grpc-server-insecure-connection
		creds := credentials.NewServerTLSFromCert(&cert)
		s = grpc.NewServer(grpc.Creds(creds))
	}
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_8() {
	// Using a loop to create multiple secure servers
	ports := []string{":50058", ":50059"}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	
	for _, port := range ports {
		go func(p string) {
			lis, err := net.Listen("tcp", p)
			if err != nil {
				log.Fatalf("failed to listen: %v", err)
			}
			
			s := grpc.NewServer(grpc.Creds(creds))
			
			helloworld.RegisterGreeterServer(s, &server{})
			if err := s.Serve(lis); err != nil {
				log.Fatalf("failed to serve: %v", err)
			}
		}(port)
	}
	
	// Keep main goroutine alive
	select {}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_9() {
	// Using environment variables for certificate paths
	lis, err := net.Listen("tcp", ":50060")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	
	if certFile == "" || keyFile == "" {
		certFile = "server.crt"
		keyFile = "server.key"
	}
	
	// ok: rule-grpc-server-insecure-connection
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}
	
	s := grpc.NewServer(grpc.Creds(creds))
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_10() {
	// Creating server with options from a function that returns security options
	lis, err := net.Listen("tcp", ":50061")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// ok: rule-grpc-server-insecure-connection
	s := grpc.NewServer(getSecureServerOptions()...)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

func getSecureServerOptions() []grpc.ServerOption {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	creds := credentials.NewServerTLSFromCert(&cert)
	
	return []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024),
	}
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_11() {
	// Using a switch statement with secure options in all cases
	serverType := "default"
	lis, err := net.Listen("tcp", ":50062")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	
	var s *grpc.Server
	switch serverType {
	case "high_performance":
		s = grpc.NewServer(
			grpc.Creds(creds),
			grpc.NumStreamWorkers(10),
		)
	case "low_memory":
		s = grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxRecvMsgSize(1024),
		)
	default:
		s = grpc.NewServer(grpc.Creds(creds))
	}
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_12() {
	// Creating a server with a custom interceptor and security
	lis, err := net.Listen("tcp", ":50063")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			log.Printf("Request: %v", req)
			return handler(ctx, req)
		}),
	)
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_13() {
	// Loading certificates from files in a specific directory
	lis, err := net.Listen("tcp", ":50064")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "."
	}
	
	certFile := filepath.Join(certDir, "server.crt")
	keyFile := filepath.Join(certDir, "server.key")
	
	// ok: rule-grpc-server-insecure-connection
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}
	
	s := grpc.NewServer(grpc.Creds(creds))
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_14() {
	// Creating multiple servers with different configurations but all secure
	createSecureServer(":50065", 1024*1024)
	createSecureServer(":50066", 2*1024*1024)
}
// {/fact}

func createSecureServer(address string, maxSize int) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load cert: %v", err)
	}
	
	// Create TLS credentials
	// ok: rule-grpc-server-insecure-connection
	creds := credentials.NewServerTLSFromCert(&cert)
	
	s := grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(maxSize),
	)
	
	helloworld.RegisterGreeterServer(s, &server{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()
}

// {fact rule=channel-accessible-by-non-endpoint@v1.0 defects=0}
func good_case_15() {
	// Using mutual TLS (mTLS) for server and client authentication
	lis, err := net.Listen("tcp", ":50067")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load server cert: %v", err)
	}
	
	// Load CA certificate for client authentication
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("failed to read ca cert: %v", err)
	}
	
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to add CA certificate")
	}
	
	// Create TLS configuration with client authentication
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	
	// ok: rule-grpc-server-insecure-connection
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	
	helloworld.RegisterGreeterServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

func main() {
	// This function is just a placeholder and not meant to be executed
	fmt.Println("This file contains examples of secure and insecure gRPC server configurations.")
}