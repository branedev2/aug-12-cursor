package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/joho/godotenv"
)

// True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_1() {
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(""),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_2() {
	emptyPass := ""
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(emptyPass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "192.168.1.1:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_3() {
	username := "admin"
	password := ""
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(password),
		},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "server.example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_4() {
	var password string // default empty string
	config := &ssh.ClientConfig{
		User: "deployer",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "10.0.0.1:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_5() {
	credentials := map[string]string{
		"username": "admin",
		"password": "",
	}
	config := &ssh.ClientConfig{
		User: credentials["username"],
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(credentials["password"]),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "db.example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_6() {
	type Server struct {
		Host     string
		Port     int
		Username string
		Password string
	}
	
	server := Server{
		Host:     "192.168.0.1",
		Port:     22,
		Username: "root",
		Password: "",
	}
	
	config := &ssh.ClientConfig{
		User: server.Username,
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(server.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", server.Host, server.Port), config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_7() {
	getPassword := func() string {
		return ""
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(getPassword()),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "server.local:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_8() {
	password := strings.TrimSpace("  ")
	config := &ssh.ClientConfig{
		User: "user",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "10.10.10.10:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_9() {
	// Simulate getting an empty password from a config file
	configData := map[string]string{
		"ssh_user": "admin",
		"ssh_pass": "",
	}
	
	config := &ssh.ClientConfig{
		User: configData["ssh_user"],
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(configData["ssh_pass"]),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "192.168.1.100:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_10() {
	// Multiple auth methods with one being an empty password
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(""),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				return []string{"some-answer"}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.org:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_11() {
	// Empty password in a loop connecting to multiple servers
	servers := []string{"server1.example.com", "server2.example.com", "server3.example.com"}
	
	for _, server := range servers {
		config := &ssh.ClientConfig{
			User: "admin",
			Auth: []ssh.AuthMethod{
				// ruleid: rule-ssh-empty-password
				ssh.Password(""),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		client, err := ssh.Dial("tcp", server+":22", config)
		if err != nil {
			log.Printf("Failed to connect to %s: %v", server, err)
			continue
		}
		defer client.Close()
		
		// Do something with the connection
		session, _ := client.NewSession()
		defer session.Close()
		output, _ := session.CombinedOutput("ls -la")
		fmt.Println(string(output))
	}
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_12() {
	// Conditional that still results in empty password
	useEmptyPassword := true
	password := "securePassword123"
	
	if useEmptyPassword {
		password = ""
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "192.168.1.5:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_13() {
	// Empty password in a function that creates an SSH client
	createSSHClient := func(host string, port int, username string) (*ssh.Client, error) {
		config := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				// ruleid: rule-ssh-empty-password
				ssh.Password(""),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	}
	
	client, err := createSSHClient("example.com", 22, "admin")
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_14() {
	// Empty password from a string concatenation
	part1 := ""
	part2 := ""
	password := part1 + part2
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "10.0.1.1:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_15() {
	// Empty password from a slice
	credentials := []string{"admin", ""}
	
	config := &ssh.ClientConfig{
		User: credentials[0],
		Auth: []ssh.AuthMethod{
			// ruleid: rule-ssh-empty-password
			ssh.Password(credentials[1]),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "192.168.10.10:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_1() {
	// Using a non-empty password
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			// ok: rule-ssh-empty-password
			ssh.Password("securePassword123"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_2() {
	// Using environment variable for password
	// ok: rule-ssh-empty-password
	password := os.Getenv("SSH_PASSWORD")
	if password == "" {
		log.Fatal("SSH_PASSWORD environment variable not set")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_3() {
	// Using SSH key authentication instead of password
	key, err := ioutil.ReadFile("/path/to/id_rsa")
	if err != nil {
		log.Fatal(err)
	}
	
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	
	// ok: rule-ssh-empty-password
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_4() {
	// Loading password from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	
	// ok: rule-ssh-empty-password
	password := os.Getenv("SSH_PASSWORD")
	if password == "" {
		log.Fatal("SSH_PASSWORD not set in .env file")
	}
	
	config := &ssh.ClientConfig{
		User: os.Getenv("SSH_USER"),
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_5() {
	// Using AWS Secrets Manager to retrieve password
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	
	svc := secretsmanager.New(sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String("ssh/credentials"),
	}
	
	result, err := svc.GetSecretValue(input)
	if err != nil {
		log.Fatal(err)
	}
	
	// ok: rule-ssh-empty-password
	password := *result.SecretString
	if password == "" {
		log.Fatal("Retrieved empty password from secrets manager")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_6() {
	// Using a password with validation
	password := os.Getenv("SSH_PASSWORD")
	
	// ok: rule-ssh-empty-password
	if password == "" {
		log.Fatal("SSH password cannot be empty")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_7() {
	// Using a configuration file to load credentials
	type Config struct {
		Username string
		Password string
	}
	
	// Simulate loading from config file
	loadConfig := func() Config {
		return Config{
			Username: "admin",
			Password: "securePassword123",
		}
	}
	
	config := loadConfig()
	
	// ok: rule-ssh-empty-password
	if config.Password == "" {
		log.Fatal("Password cannot be empty")
	}
	
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", sshConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_8() {
	// Using keyboard-interactive authentication instead of password
	// ok: rule-ssh-empty-password
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					if strings.Contains(questions[i], "Password") {
						answers[i] = "securePassword123"
					}
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_9() {
	// Using a password from command line arguments with validation
	var password string
	if len(os.Args) > 1 {
		password = os.Args[1]
	}
	
	// ok: rule-ssh-empty-password
	if password == "" {
		log.Fatal("Password must be provided as command line argument")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_10() {
	// Using a secure vault to retrieve password
	getPasswordFromVault := func() (string, error) {
		// Simulating retrieval from a secure vault
		return "secureVaultPassword", nil
	}
	
	// ok: rule-ssh-empty-password
	password, err := getPasswordFromVault()
	if err != nil {
		log.Fatal("Failed to retrieve password from vault:", err)
	}
	
	if password == "" {
		log.Fatal("Retrieved empty password from vault")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_11() {
	// Using certificate-based authentication
	// ok: rule-ssh-empty-password
	certSigner, err := ssh.NewSignerFromKey(loadPrivateKey())
	if err != nil {
		log.Fatal(err)
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_12() {
	// Using agent-based authentication
	// ok: rule-ssh-empty-password
	agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatal(err)
	}
	
	agentClient := ssh.NewAgentClient(agentConn)
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_13() {
	// Using a function to generate a strong password
	generateStrongPassword := func() string {
		// In a real scenario, this would generate a strong random password
		return "StrongRandomPassword123!@#"
	}
	
	// ok: rule-ssh-empty-password
	password := generateStrongPassword()
	if password == "" {
		log.Fatal("Generated password cannot be empty")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_14() {
	// Using multiple authentication methods with proper password
	key, err := ioutil.ReadFile("/path/to/id_rsa")
	if err != nil {
		log.Fatal(err)
	}
	
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	
	// ok: rule-ssh-empty-password
	password := os.Getenv("SSH_PASSWORD")
	if password == "" {
		log.Fatal("SSH_PASSWORD environment variable not set")
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_15() {
	// Using a password with proper validation and fallback
	password := os.Getenv("SSH_PASSWORD")
	fallbackPassword := os.Getenv("SSH_FALLBACK_PASSWORD")
	
	// ok: rule-ssh-empty-password
	if password == "" {
		if fallbackPassword == "" {
			log.Fatal("Both primary and fallback passwords are empty")
		}
		password = fallbackPassword
	}
	
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
// {/fact}

// Helper function for good_case_11
func loadPrivateKey() interface{} {
	// This is a placeholder - in a real scenario, this would load a private key
	return nil
}

func main() {
	// Main function to prevent compiler errors
	fmt.Println("SSH Password Security Test Cases")
}