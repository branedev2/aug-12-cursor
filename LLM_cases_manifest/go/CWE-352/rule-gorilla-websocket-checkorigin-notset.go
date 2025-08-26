package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"os"

	"github.com/gorilla/websocket"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_1() {
	// Basic case: Creating an Upgrader without CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{}
	
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_2() {
	// Creating an Upgrader with explicit fields but no CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	http.HandleFunc("/socket", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Error upgrading connection: %v", err)
			return
		}
		defer conn.Close()
		// WebSocket handling logic
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_3() {
	// Creating multiple Upgraders without CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	chatUpgrader := websocket.Upgrader{
		ReadBufferSize:  2048,
		WriteBufferSize: 2048,
	}
	
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	notificationUpgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		conn, err := chatUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Chat handling
	})
	
	http.HandleFunc("/notifications", func(w http.ResponseWriter, r *http.Request) {
		conn, err := notificationUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Notification handling
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_4() {
	// Creating an Upgrader with other security settings but missing CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		EnableCompression: true,
		HandshakeTimeout:  10, // Timeout in seconds
	}
	
	http.HandleFunc("/secure-but-missing-origin-check", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Failed to set websocket upgrade:", err)
			return
		}
		defer conn.Close()
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_5() {
	// Creating an Upgrader in a struct but without CheckOrigin
	type WSServer struct {
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		upgrader websocket.Upgrader
		clients  map[*websocket.Conn]bool
	}
	
	server := WSServer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients: make(map[*websocket.Conn]bool),
	}
	
	http.HandleFunc("/ws-server", func(w http.ResponseWriter, r *http.Request) {
		conn, err := server.upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
		server.clients[conn] = true
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_6() {
	// Creating an Upgrader with a nil CheckOrigin function
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		CheckOrigin: nil,
	}
	
	http.HandleFunc("/nil-check", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_7() {
	// Creating an Upgrader in a function that returns it
	wsHandler := func() http.HandlerFunc {
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
		
		return func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Println("upgrade failed:", err)
				return
			}
			defer conn.Close()
			// Handle connection
		}
	}
	
	http.HandleFunc("/ws-handler", wsHandler())
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_8() {
	// Creating an Upgrader with conditional logic but no CheckOrigin
	isProduction := os.Getenv("ENVIRONMENT") == "production"
	
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	if isProduction {
		upgrader.EnableCompression = true
	}
	
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_9() {
	// Creating an Upgrader with a commented-out CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// CheckOrigin: func(r *http.Request) bool {
		//     return true
		// },
	}
	
	http.HandleFunc("/commented-check", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_10() {
	// Creating an Upgrader with variable initialization
	readSize := 2048
	writeSize := 2048
	
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  readSize,
		WriteBufferSize: writeSize,
	}
	
	http.HandleFunc("/variable-init", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_11() {
	// Creating an Upgrader with custom response headers but no CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	http.HandleFunc("/custom-headers", func(w http.ResponseWriter, r *http.Request) {
		responseHeader := http.Header{}
		responseHeader.Add("X-Custom-Header", "value")
		
		conn, err := upgrader.Upgrade(w, r, responseHeader)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_12() {
	// Creating an Upgrader in an init function
	var upgrader websocket.Upgrader
	
	func() {
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
	}()
	
	http.HandleFunc("/init-upgrader", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_13() {
	// Creating an Upgrader with error handling but no CheckOrigin
	// ruleid: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	
	http.HandleFunc("/error-handling", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_14() {
	// Creating an Upgrader with a function that returns it
	getUpgrader := func() websocket.Upgrader {
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		return websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}
	}
	
	upgrader := getUpgrader()
	
	http.HandleFunc("/function-return", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=1}
func bad_case_15() {
	// Creating multiple Upgraders in a map without CheckOrigin
	upgraders := map[string]websocket.Upgrader{
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		"chat": websocket.Upgrader{
			ReadBufferSize:  2048,
			WriteBufferSize: 2048,
		},
		// ruleid: rule-gorilla-websocket-checkorigin-notset
		"notification": websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}
	
	http.HandleFunc("/dynamic", func(w http.ResponseWriter, r *http.Request) {
		upgraderType := r.URL.Query().Get("type")
		if upgrader, ok := upgraders[upgraderType]; ok {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Println(err)
				return
			}
			defer conn.Close()
			// Handle WebSocket
		}
	})
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_1() {
	// Basic case: Creating an Upgrader with CheckOrigin that validates against an allowlist
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "https://trusted-site.com" || origin == "https://admin.trusted-site.com"
		},
	}
	
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_2() {
	// Creating an Upgrader with CheckOrigin that checks for localhost in development
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return strings.HasPrefix(origin, "http://localhost:") || 
				   strings.HasPrefix(origin, "https://trusted-domain.com")
		},
	}
	
	http.HandleFunc("/socket", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Error upgrading connection: %v", err)
			return
		}
		defer conn.Close()
		// WebSocket handling logic
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_3() {
	// Creating multiple Upgraders with proper CheckOrigin functions
	// ok: rule-gorilla-websocket-checkorigin-notset
	chatUpgrader := websocket.Upgrader{
		ReadBufferSize:  2048,
		WriteBufferSize: 2048,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "https://chat.example.com"
		},
	}
	
	// ok: rule-gorilla-websocket-checkorigin-notset
	notificationUpgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "https://notifications.example.com"
		},
	}
	
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		conn, err := chatUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Chat handling
	})
	
	http.HandleFunc("/notifications", func(w http.ResponseWriter, r *http.Request) {
		conn, err := notificationUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Notification handling
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_4() {
	// Creating an Upgrader with comprehensive security settings including CheckOrigin
	allowedOrigins := []string{"https://example.com", "https://api.example.com"}
	
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:    1024,
		WriteBufferSize:   1024,
		EnableCompression: true,
		HandshakeTimeout:  10, // Timeout in seconds
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			for _, allowed := range allowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		},
	}
	
	http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Failed to set websocket upgrade:", err)
			return
		}
		defer conn.Close()
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_5() {
	// Creating an Upgrader in a struct with proper CheckOrigin
	type WSServer struct {
		// ok: rule-gorilla-websocket-checkorigin-notset
		upgrader websocket.Upgrader
		clients  map[*websocket.Conn]bool
	}
	
	server := WSServer{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == "https://myapp.com"
			},
		},
		clients: make(map[*websocket.Conn]bool),
	}
	
	http.HandleFunc("/ws-server", func(w http.ResponseWriter, r *http.Request) {
		conn, err := server.upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
		server.clients[conn] = true
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_6() {
	// Creating an Upgrader with a CheckOrigin function that uses a domain suffix check
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return strings.HasSuffix(origin, ".trusted-domain.com") || 
				   strings.HasSuffix(origin, ".trusted-domain.org")
		},
	}
	
	http.HandleFunc("/suffix-check", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_7() {
	// Creating an Upgrader in a function that returns it with proper CheckOrigin
	wsHandler := func() http.HandlerFunc {
		// ok: rule-gorilla-websocket-checkorigin-notset
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				return origin == "https://app.example.com"
			},
		}
		
		return func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Println("upgrade failed:", err)
				return
			}
			defer conn.Close()
			// Handle connection
		}
	}
	
	http.HandleFunc("/ws-handler", wsHandler())
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_8() {
	// Creating an Upgrader with conditional logic and proper CheckOrigin
	isProduction := os.Getenv("ENVIRONMENT") == "production"
	
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if isProduction {
				return origin == "https://production.example.com"
			}
			return origin == "http://localhost:3000" || origin == "https://staging.example.com"
		},
	}
	
	http.HandleFunc("/conditional", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_9() {
	// Creating an Upgrader with a CheckOrigin that uses a helper function
	isAllowedOrigin := func(origin string) bool {
		allowedOrigins := []string{
			"https://example.com",
			"https://api.example.com",
			"https://admin.example.com",
		}
		
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return false
	}
	
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return isAllowedOrigin(r.Header.Get("Origin"))
		},
	}
	
	http.HandleFunc("/helper-function", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle connection
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_10() {
	// Creating an Upgrader with variable initialization and proper CheckOrigin
	readSize := 2048
	writeSize := 2048
	
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  readSize,
		WriteBufferSize: writeSize,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return origin == "https://secure.example.com"
		},
	}
	
	http.HandleFunc("/variable-init", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_11() {
	// Creating an Upgrader with custom response headers and proper CheckOrigin
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return strings.HasPrefix(origin, "https://trusted.")
		},
	}
	
	http.HandleFunc("/custom-headers", func(w http.ResponseWriter, r *http.Request) {
		responseHeader := http.Header{}
		responseHeader.Add("X-Custom-Header", "value")
		
		conn, err := upgrader.Upgrade(w, r, responseHeader)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_12() {
	// Creating an Upgrader in an init function with proper CheckOrigin
	var upgrader websocket.Upgrader
	
	func() {
		// ok: rule-gorilla-websocket-checkorigin-notset
		upgrader = websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == "https://example.org"
			},
		}
	}()
	
	http.HandleFunc("/init-upgrader", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_13() {
	// Creating an Upgrader with error handling and proper CheckOrigin
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			allowedOrigins := map[string]bool{
				"https://app.example.com": true,
				"https://api.example.com": true,
			}
			return allowedOrigins[origin]
		},
	}
	
	http.HandleFunc("/error-handling", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_14() {
	// Creating an Upgrader with a function that returns it with proper CheckOrigin
	getUpgrader := func() websocket.Upgrader {
		// ok: rule-gorilla-websocket-checkorigin-notset
		return websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				return origin == "https://secure.example.com"
			},
		}
	}
	
	upgrader := getUpgrader()
	
	http.HandleFunc("/function-return", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()
		// Handle WebSocket
	})
}
// {/fact}

// {fact rule=coral-csrf-rule@v1.0 defects=0}
func good_case_15() {
	// Creating multiple Upgraders in a map with proper CheckOrigin functions
	// ok: rule-gorilla-websocket-checkorigin-notset
	upgraders := map[string]websocket.Upgrader{
		"chat": websocket.Upgrader{
			ReadBufferSize:  2048,
			WriteBufferSize: 2048,
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == "https://chat.example.com"
			},
		},
		"notification": websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == "https://notifications.example.com"
			},
		},
	}
	
	http.HandleFunc("/dynamic", func(w http.ResponseWriter, r *http.Request) {
		upgraderType := r.URL.Query().Get("type")
		if upgrader, ok := upgraders[upgraderType]; ok {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				log.Println(err)
				return
			}
			defer conn.Close()
			// Handle WebSocket
		}
	})
}
// {/fact}

func main() {
	// This is just a placeholder main function to make the code compilable
	fmt.Println("WebSocket server examples")
	http.ListenAndServe(":8080", nil)
}