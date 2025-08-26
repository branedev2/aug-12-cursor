package main

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_1() {
	// Simple case of using InsecureIgnoreHostKey
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_2() {
	// Using InsecureIgnoreHostKey in a function that creates SSH connections
	sshConfig := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password("admin123"),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "192.168.1.100:22", sshConfig)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_3() {
	// Using InsecureIgnoreHostKey with a more complex configuration
	privateKey, err := ioutil.ReadFile("/home/user/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", "server.example.com:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_4() {
	// Using InsecureIgnoreHostKey with HTTP input for server address
	http.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		server := r.URL.Query().Get("server")
		user := r.URL.Query().Get("user")
		password := r.URL.Query().Get("password")

		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			fmt.Fprintf(w, "Failed to connect: %v", err)
			return
		}
		defer client.Close()
		fmt.Fprintf(w, "Connected successfully")
	})
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_5() {
	// Using InsecureIgnoreHostKey in a function with conditional logic
	func connectToServer(useInsecure bool) {
		config := &ssh.ClientConfig{
			User: "admin",
			Auth: []ssh.AuthMethod{
				ssh.Password("secret"),
			},
		}

		if useInsecure {
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
		}

		client, err := ssh.Dial("tcp", "10.0.0.1:22", config)
		if err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()
	}

	connectToServer(true)
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_6() {
	// Using InsecureIgnoreHostKey with a variable assignment
	callback := ssh.InsecureIgnoreHostKey()
	
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password123"),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: callback,
	}

	client, err := ssh.Dial("tcp", "example.org:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_7() {
	// Using InsecureIgnoreHostKey in a loop connecting to multiple servers
	servers := []string{"server1.example.com", "server2.example.com", "server3.example.com"}
	
	for _, server := range servers {
		config := &ssh.ClientConfig{
			User: "user",
			Auth: []ssh.AuthMethod{
				ssh.Password("password"),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", server, err)
			continue
		}
		defer client.Close()
		log.Printf("Connected to %s", server)
	}
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_8() {
	// Using InsecureIgnoreHostKey with a switch statement
	connectionType := "production"
	
	var config *ssh.ClientConfig
	
	switch connectionType {
	case "development":
		config = &ssh.ClientConfig{
			User: "dev",
			Auth: []ssh.AuthMethod{
				ssh.Password("dev123"),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	case "production":
		config = &ssh.ClientConfig{
			User: "prod",
			Auth: []ssh.AuthMethod{
				ssh.Password("prod456"),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	}

	client, err := ssh.Dial("tcp", "example.net:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_9() {
	// Using InsecureIgnoreHostKey with a custom timeout
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", "slowserver.example.com:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_10() {
	// Using InsecureIgnoreHostKey with a web service that takes SSH parameters
	http.HandleFunc("/ssh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		host := r.FormValue("host")
		user := r.FormValue("user")
		password := r.FormValue("password")

		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", host+":22", config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
			return
		}
		defer client.Close()

		fmt.Fprintf(w, "Connected to %s successfully", host)
	})
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_11() {
	// Using InsecureIgnoreHostKey with a custom SSH client wrapper
	type SSHClient struct {
		Host     string
		User     string
		Password string
		Client   *ssh.Client
	}

	func NewSSHClient(host, user, password string) (*SSHClient, error) {
		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", host+":22", config)
		if err != nil {
			return nil, err
		}

		return &SSHClient{
			Host:     host,
			User:     user,
			Password: password,
			Client:   client,
		}, nil
	}

	client, err := NewSSHClient("example.com", "user", "password")
	if err != nil {
		log.Fatalf("Failed to create SSH client: %v", err)
	}
	defer client.Client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_12() {
	// Using InsecureIgnoreHostKey with environment variables for credentials
	host := os.Getenv("SSH_HOST")
	user := os.Getenv("SSH_USER")
	password := os.Getenv("SSH_PASSWORD")

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_13() {
	// Using InsecureIgnoreHostKey with a function that returns the config
	func getSSHConfig(user, password string) *ssh.ClientConfig {
		return &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	}

	config := getSSHConfig("admin", "admin123")
	client, err := ssh.Dial("tcp", "192.168.1.1:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_14() {
	// Using InsecureIgnoreHostKey with a map of configurations
	configs := map[string]*ssh.ClientConfig{
		"server1": {
			User: "user1",
			Auth: []ssh.AuthMethod{
				ssh.Password("pass1"),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
		"server2": {
			User: "user2",
			Auth: []ssh.AuthMethod{
				ssh.Password("pass2"),
			},
			// ruleid: rule-insecure_ignore_host_key-updatedMIT
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		},
	}

	server := "server1"
	client, err := ssh.Dial("tcp", server+".example.com:22", configs[server])
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=1}
func bad_case_15() {
	// Using InsecureIgnoreHostKey with a custom error handler
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		// ruleid: rule-insecure_ignore_host_key-updatedMIT
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		if err, ok := err.(*ssh.ServerError); ok {
			log.Printf("SSH server error: %v", err)
		} else {
			log.Printf("Network error: %v", err)
		}
		return
	}
	defer client.Close()
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_1() {
	// Using knownhosts package to validate host keys
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal("Failed to get home directory: ", err)
	}

	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New(filepath.Join(homedir, ".ssh", "known_hosts"))
	if err != nil {
		log.Fatal("Failed to load known_hosts: ", err)
	}

	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_2() {
	// Using a custom known_hosts file path
	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New("/etc/ssh/known_hosts")
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}

	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password("admin123"),
		},
		HostKeyCallback: hostKeyCallback,
	}

	conn, err := ssh.Dial("tcp", "192.168.1.100:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_3() {
	// Using knownhosts with key-based authentication
	privateKey, err := ioutil.ReadFile("/home/user/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}

	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", "server.example.com:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_4() {
	// Using knownhosts with HTTP input for server address
	http.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		server := r.URL.Query().Get("server")
		user := r.URL.Query().Get("user")
		password := r.URL.Query().Get("password")

		// ok: rule-insecure_ignore_host_key-updatedMIT
		hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to load known_hosts: %v", err), http.StatusInternalServerError)
			return
		}

		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: hostKeyCallback,
		}

		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			fmt.Fprintf(w, "Failed to connect: %v", err)
			return
		}
		defer client.Close()
		fmt.Fprintf(w, "Connected successfully")
	})
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_5() {
	// Using knownhosts in a function with conditional logic
	func connectToServer(useSecure bool) {
		config := &ssh.ClientConfig{
			User: "admin",
			Auth: []ssh.AuthMethod{
				ssh.Password("secret"),
			},
		}

		if useSecure {
			// ok: rule-insecure_ignore_host_key-updatedMIT
			hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
			if err != nil {
				log.Fatalf("Failed to load known_hosts: %v", err)
			}
			config.HostKeyCallback = hostKeyCallback
		}

		client, err := ssh.Dial("tcp", "10.0.0.1:22", config)
		if err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()
	}

	connectToServer(true)
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_6() {
	// Using knownhosts with a variable assignment
	// ok: rule-insecure_ignore_host_key-updatedMIT
	callback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}
	
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password123"),
		},
		HostKeyCallback: callback,
	}

	client, err := ssh.Dial("tcp", "example.org:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_7() {
	// Using knownhosts in a loop connecting to multiple servers
	servers := []string{"server1.example.com", "server2.example.com", "server3.example.com"}
	
	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}
	
	for _, server := range servers {
		config := &ssh.ClientConfig{
			User: "user",
			Auth: []ssh.AuthMethod{
				ssh.Password("password"),
			},
			HostKeyCallback: hostKeyCallback,
		}

		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", server, err)
			continue
		}
		defer client.Close()
		log.Printf("Connected to %s", server)
	}
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_8() {
	// Using a custom host key verification function
	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Custom logic to verify the host key
		knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
		
		// Load and check the key against known_hosts
		knownHostsData, err := ioutil.ReadFile(knownHostsFile)
		if err != nil {
			return fmt.Errorf("failed to read known_hosts file: %v", err)
		}
		
		// Simple check if the key is in the file
		knownHostsString := string(knownHostsData)
		keyString := string(key.Marshal())
		if !strings.Contains(knownHostsString, keyString) {
			return fmt.Errorf("unknown host key for %s", hostname)
		}
		
		return nil
	}
	
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", "example.net:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_9() {
	// Using knownhosts with a custom timeout
	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}
	
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", "slowserver.example.com:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_10() {
	// Using knownhosts with a web service that takes SSH parameters
	http.HandleFunc("/ssh", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		host := r.FormValue("host")
		user := r.FormValue("user")
		password := r.FormValue("password")

		// ok: rule-insecure_ignore_host_key-updatedMIT
		hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to load known_hosts: %v", err), http.StatusInternalServerError)
			return
		}

		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: hostKeyCallback,
		}

		client, err := ssh.Dial("tcp", host+":22", config)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to connect: %v", err), http.StatusInternalServerError)
			return
		}
		defer client.Close()

		fmt.Fprintf(w, "Connected to %s successfully", host)
	})
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_11() {
	// Using knownhosts with a custom SSH client wrapper
	type SSHClient struct {
		Host     string
		User     string
		Password string
		Client   *ssh.Client
	}

	func NewSSHClient(host, user, password string) (*SSHClient, error) {
		// ok: rule-insecure_ignore_host_key-updatedMIT
		hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts: %v", err)
		}
		
		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: hostKeyCallback,
		}

		client, err := ssh.Dial("tcp", host+":22", config)
		if err != nil {
			return nil, err
		}

		return &SSHClient{
			Host:     host,
			User:     user,
			Password: password,
			Client:   client,
		}, nil
	}

	client, err := NewSSHClient("example.com", "user", "password")
	if err != nil {
		log.Fatalf("Failed to create SSH client: %v", err)
	}
	defer client.Client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_12() {
	// Using knownhosts with environment variables for credentials and known_hosts path
	host := os.Getenv("SSH_HOST")
	user := os.Getenv("SSH_USER")
	password := os.Getenv("SSH_PASSWORD")
	knownHostsPath := os.Getenv("SSH_KNOWN_HOSTS")
	
	if knownHostsPath == "" {
		knownHostsPath = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	}

	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		log.Fatalf("Failed to load known_hosts: %v", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_13() {
	// Using knownhosts with a function that returns the config
	func getSSHConfig(user, password string) (*ssh.ClientConfig, error) {
		// ok: rule-insecure_ignore_host_key-updatedMIT
		hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts: %v", err)
		}
		
		return &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: hostKeyCallback,
		}, nil
	}

	config, err := getSSHConfig("admin", "admin123")
	if err != nil {
		log.Fatalf("Failed to create SSH config: %v", err)
	}
	
	client, err := ssh.Dial("tcp", "192.168.1.1:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_14() {
	// Using a fixed key callback for testing environments
	// ok: rule-insecure_ignore_host_key-updatedMIT
	fixedHostKey := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// For testing environments, we can use a fixed, known key
		expectedKey := []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...")
		
		if bytes.Equal(key.Marshal(), expectedKey) {
			return nil
		}
		return fmt.Errorf("host key verification failed")
	}
	
	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.Password("testpass"),
		},
		HostKeyCallback: fixedHostKey,
	}

	client, err := ssh.Dial("tcp", "testserver:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=do-not-auto-add-or-warning-missing-hostkey-policy@v1.0 defects=0}
func good_case_15() {
	// Using knownhosts with dynamic host key addition
	knownHostsFile := filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	
	// ok: rule-insecure_ignore_host_key-updatedMIT
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// First try to validate with existing known_hosts
		knownHostsCallback, err := knownhosts.New(knownHostsFile)
		if err == nil {
			err = knownHostsCallback(hostname, remote, key)
			if err == nil {
				return nil
			}
		}
		
		// If validation fails, ask user if they want to add the key
		fmt.Printf("Unknown host key for %s. Fingerprint: %s\n", hostname, ssh.FingerprintSHA256(key))
		fmt.Print("Do you want to add this key to known_hosts? (yes/no): ")
		
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(response)
		
		if response == "yes" {
			// Add the key to known_hosts
			f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return fmt.Errorf("failed to open known_hosts file: %v", err)
			}
			defer f.Close()
			
			line := knownhosts.Line([]string{hostname}, key)
			if _, err := f.WriteString(line + "\n"); err != nil {
				return fmt.Errorf("failed to add key to known_hosts: %v", err)
			}
			
			return nil
		}
		
		return fmt.Errorf("host key verification failed")
	}
	
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			ssh.Password("password"),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", "newserver.example.com:22", config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()
}
// {/fact}