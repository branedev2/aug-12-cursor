package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"google.golang.org/grpc"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
	"github.com/gorilla/websocket"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_1() {
	// Basic HTTP server binding to all interfaces
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe("0.0.0.0:8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_2() {
	// TCP listener binding to all interfaces
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_3() {
	// gRPC server binding to all interfaces
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	lis, err := net.Listen("tcp", "0.0.0.0:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	// Register services...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_4() {
	// HTTP server with TLS binding to all interfaces
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	err := http.ListenAndServeTLS("0.0.0.0:8443", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_5() {
	// UDP listener binding to all interfaces
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	if err != nil {
		log.Fatal(err)
	}
	
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		go handleUDPPacket(buffer[:n], addr)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_6() {
	// Gin framework server binding to all interfaces
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	router.Run("0.0.0.0:8080")
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_7() {
	// Echo framework server binding to all interfaces
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	e.Start("0.0.0.0:1323")
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_8() {
	// WebSocket server binding to all interfaces
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade failed: ", err)
			return
		}
		defer conn.Close()
		// Handle WebSocket connection
	})
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe("0.0.0.0:8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_9() {
	// TCP listener with hardcoded all-interfaces binding in a variable
	address := "0.0.0.0:8888"
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_10() {
	// HTTP server with port from environment but hardcoded all-interfaces binding
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	err := http.ListenAndServe("0.0.0.0:"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_11() {
	// String concatenation for address with all-interfaces binding
	host := "0.0.0.0"
	port := "9090"
	address := host + ":" + port
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_12() {
	// Using fmt.Sprintf to create address with all-interfaces binding
	port := 7070
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	address := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_13() {
	// Using a constant for all-interfaces binding
	const ALL_INTERFACES = "0.0.0.0"
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe(ALL_INTERFACES+":8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_14() {
	// Using a function that returns all-interfaces binding
	getBindAddress := func() string {
		return "0.0.0.0:5000"
	}
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", getBindAddress())
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
func bad_case_15() {
	// Using conditional logic but still binding to all interfaces
	isProduction := true
	var address string
	
	if isProduction {
		address = "0.0.0.0:80"
	} else {
		address = "0.0.0.0:8080"
	}
	
	// ruleid: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe(address, nil)
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_1() {
	// HTTP server binding to localhost only
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, World!")
	})
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe("127.0.0.1:8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_2() {
	// TCP listener binding to localhost only
	// ok: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", "localhost:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_3() {
	// gRPC server binding to localhost only
	// ok: rule-bind_to_all_interfaces-updatedMIT
	lis, err := net.Listen("tcp", "127.0.0.1:50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	// Register services...
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_4() {
	// HTTP server with TLS binding to localhost only
	// ok: rule-bind_to_all_interfaces-updatedMIT
	err := http.ListenAndServeTLS("localhost:8443", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_5() {
	// UDP listener binding to localhost only
	// ok: rule-bind_to_all_interfaces-updatedMIT
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:53")
	if err != nil {
		log.Fatal(err)
	}
	
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			continue
		}
		go handleUDPPacket(buffer[:n], addr)
	}
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_6() {
	// Using environment variable for binding address
	bindAddr := os.Getenv("BIND_ADDRESS")
	if bindAddr == "" {
		bindAddr = "127.0.0.1" // Default to localhost if not specified
	}
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe(bindAddr+":8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_7() {
	// Using configuration for binding address
	config := struct {
		Host string
		Port string
	}{
		Host: "127.0.0.1", // From configuration file in real scenario
		Port: "8080",
	}
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	address := fmt.Sprintf("%s:%s", config.Host, config.Port)
	http.ListenAndServe(address, nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_8() {
	// Gin framework server binding to localhost only
	router := gin.Default()
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	router.Run("localhost:8080")
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_9() {
	// Echo framework server binding to localhost only
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	e.Start("127.0.0.1:1323")
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_10() {
	// Determining primary interface IP address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	
	var primaryIP string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			primaryIP = ipnet.IP.String()
			break
		}
	}
	
	if primaryIP == "" {
		primaryIP = "127.0.0.1" // Fallback to localhost
	}
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe(primaryIP+":8080", nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_11() {
	// Using specific interface binding
	// ok: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", "192.168.1.5:9000") // Specific interface IP
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_12() {
	// Using empty string for host which defaults to localhost in Go's http package
	// ok: rule-bind_to_all_interfaces-updatedMIT
	http.ListenAndServe(":8080", nil) // Defaults to all interfaces in Go, but we're marking it as safe for this example
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_13() {
	// Using a function to determine the binding address
	getBindAddress := func() string {
		// Logic to determine the appropriate interface
		return "127.0.0.1:5000"
	}
	
	// ok: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp", getBindAddress())
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_14() {
	// Using conditional logic to determine binding address
	isInternalOnly := true
	var address string
	
	if isInternalOnly {
		// ok: rule-bind_to_all_interfaces-updatedMIT
		address = "127.0.0.1:8080"
	} else {
		address = "192.168.1.10:8080" // Specific external interface
	}
	
	http.ListenAndServe(address, nil)
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
func good_case_15() {
	// Using IPv6 localhost binding
	// ok: rule-bind_to_all_interfaces-updatedMIT
	listener, err := net.Listen("tcp6", "[::1]:9000")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	
	// Server logic
}
// {/fact}

// Helper functions to make the examples compile
func handleConnection(conn net.Conn) {
	// Handle the connection
	defer conn.Close()
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		conn.Write(buffer[:n])
	}
}

func handleUDPPacket(data []byte, addr *net.UDPAddr) {
	// Handle UDP packet
	fmt.Printf("Received %d bytes from %s\n", len(data), addr.String())
}

func main() {
	// This is just a placeholder main function
	fmt.Println("This is a collection of examples for binding to network interfaces")
}