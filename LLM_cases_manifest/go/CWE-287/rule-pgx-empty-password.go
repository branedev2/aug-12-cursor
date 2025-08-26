package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	vault "github.com/hashicorp/vault/api"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// BAD CASES - Empty password in pgx connection configurations

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_1() {
	// Direct connection with empty password
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), "postgres://postgres:@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())

	var greeting string
	err = conn.QueryRow(context.Background(), "select 'Hello, world!'").Scan(&greeting)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(greeting)
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_2() {
	// Using connection string with empty password
	connString := "user=postgres password= dbname=mydb host=localhost port=5432 sslmode=disable"
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
	
	// Execute a query
	rows, _ := conn.Query(context.Background(), "SELECT * FROM users")
	defer rows.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_3() {
	// Using pgxpool with empty password
	// ruleid: rule-pgx-empty-password
	dbpool, err := pgxpool.Connect(context.Background(), "postgresql://postgres:@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
	
	var id int
	var name string
	err = dbpool.QueryRow(context.Background(), "SELECT id, name FROM users WHERE id = $1", 1).Scan(&id, &name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
	}
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_4() {
	// Using connection config with empty password
	config, err := pgx.ParseConfig("postgres://postgres:@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse config: %v\n", err)
		os.Exit(1)
	}
	
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_5() {
	// Using pgxpool config with empty password
	config, err := pgxpool.ParseConfig("postgres://postgres:@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse config: %v\n", err)
		os.Exit(1)
	}
	
	// ruleid: rule-pgx-empty-password
	dbpool, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_6() {
	// Building connection string with empty password
	username := "postgres"
	password := ""
	host := "localhost"
	port := 5432
	dbname := "mydb"
	
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, host, port, dbname)
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_7() {
	// Using connection config with empty password field
	config := pgx.ConnConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "mydb",
		User:     "postgres",
		Password: "",
	}
	
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_8() {
	// Using pgxpool config with empty password field
	config := pgxpool.Config{
		ConnConfig: pgx.ConnConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "mydb",
			User:     "postgres",
			Password: "",
		},
	}
	
	// ruleid: rule-pgx-empty-password
	dbpool, err := pgxpool.ConnectConfig(context.Background(), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_9() {
	// Using URL with empty password
	dbURL := "postgres://postgres:@localhost:5432/mydb?sslmode=disable"
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_10() {
	// Using pgxpool with URL that has empty password
	dbURL := "postgres://postgres:@localhost:5432/mydb?sslmode=disable"
	// ruleid: rule-pgx-empty-password
	dbpool, err := pgxpool.Connect(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_11() {
	// Using connection string builder with empty password
	username := "postgres"
	password := ""
	host := "localhost"
	port := 5432
	dbname := "mydb"
	
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%d sslmode=disable", 
		username, password, dbname, host, port)
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_12() {
	// Using config with password set to empty after creation
	config, err := pgx.ParseConfig("postgres://postgres:placeholder@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse config: %v\n", err)
		os.Exit(1)
	}
	
	// Setting password to empty
	config.Password = ""
	
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_13() {
	// Using pgxpool config with password set to empty after creation
	config, err := pgxpool.ParseConfig("postgres://postgres:placeholder@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse config: %v\n", err)
		os.Exit(1)
	}
	
	// Setting password to empty
	config.ConnConfig.Password = ""
	
	// ruleid: rule-pgx-empty-password
	dbpool, err := pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_14() {
	// Using connection string with password= explicitly set to empty
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), "postgres://postgres@localhost:5432/mydb?password=")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_15() {
	// Using connection string with multiple parameters and empty password
	connParams := map[string]string{
		"user":     "postgres",
		"password": "",
		"host":     "localhost",
		"port":     "5432",
		"dbname":   "mydb",
		"sslmode":  "disable",
	}
	
	connStr := ""
	for key, value := range connParams {
		connStr += key + "=" + value + " "
	}
	
	// ruleid: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// GOOD CASES - Secure password handling in pgx connection configurations

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_1() {
	// Using environment variable for password
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		fmt.Fprintf(os.Stderr, "DB_PASSWORD environment variable not set\n")
		os.Exit(1)
	}
	
	connStr := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", password)
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_2() {
	// Using connection config with password from environment variable
	config := pgx.ConnConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "mydb",
		User:     "postgres",
		Password: os.Getenv("DB_PASSWORD"),
	}
	
	// ok: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_3() {
	// Using pgxpool with password from environment variable
	dbURL := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", os.Getenv("DB_PASSWORD"))
	// ok: rule-pgx-empty-password
	dbpool, err := pgxpool.Connect(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_4() {
	// Using HashiCorp Vault to retrieve password
	vaultClient, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Vault client: %v\n", err)
		os.Exit(1)
	}
	
	// Authenticate with Vault (using token for simplicity)
	vaultClient.SetToken(os.Getenv("VAULT_TOKEN"))
	
	// Get database credentials from Vault
	secret, err := vaultClient.Logical().Read("secret/data/database")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read secret: %v\n", err)
		os.Exit(1)
	}
	
	data := secret.Data["data"].(map[string]interface{})
	password := data["password"].(string)
	
	connStr := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", password)
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
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
		SecretId: aws.String("database/credentials"),
	}
	
	result, err := svc.GetSecretValue(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get secret: %v\n", err)
		os.Exit(1)
	}
	
	// For simplicity, assume the secret is the password directly
	password := *result.SecretString
	
	connStr := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", password)
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_6() {
	// Using a configuration file to retrieve password
	// In a real scenario, this file would be properly secured with restricted permissions
	data, err := os.ReadFile("/etc/app/db_config.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file: %v\n", err)
		os.Exit(1)
	}
	
	lines := strings.Split(string(data), "\n")
	var password string
	for _, line := range lines {
		if strings.HasPrefix(line, "DB_PASSWORD=") {
			password = strings.TrimPrefix(line, "DB_PASSWORD=")
			break
		}
	}
	
	if password == "" {
		fmt.Fprintf(os.Stderr, "DB_PASSWORD not found in config file\n")
		os.Exit(1)
	}
	
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_7() {
	// Using pgxpool config with password from environment variable
	config := pgxpool.Config{
		ConnConfig: pgx.ConnConfig{
			Host:     "localhost",
			Port:     5432,
			Database: "mydb",
			User:     "postgres",
			Password: os.Getenv("DB_PASSWORD"),
		},
	}
	
	// ok: rule-pgx-empty-password
	dbpool, err := pgxpool.ConnectConfig(context.Background(), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_8() {
	// Using a function to retrieve password from a secure source
	getSecurePassword := func() string {
		// In a real scenario, this would retrieve from a secure source
		// For this example, we'll use an environment variable
		password := os.Getenv("DB_PASSWORD")
		if password == "" {
			fmt.Fprintf(os.Stderr, "DB_PASSWORD environment variable not set\n")
			os.Exit(1)
		}
		return password
	}
	
	connStr := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", getSecurePassword())
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_9() {
	// Using connection URL with non-empty password
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), "postgres://postgres:securePassword123@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_10() {
	// Using a secure password storage service (simulated)
	type PasswordService struct{}
	
	getPassword := func(service *PasswordService, key string) string {
		// In a real scenario, this would retrieve from a secure service
		// For this example, we'll use an environment variable
		return os.Getenv("DB_PASSWORD")
	}
	
	passwordService := &PasswordService{}
	password := getPassword(passwordService, "database/postgres")
	
	connStr := fmt.Sprintf("postgres://postgres:%s@localhost:5432/mydb", password)
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_11() {
	// Using connection string with non-empty password
	connString := "user=postgres password=securePassword123 dbname=mydb host=localhost port=5432 sslmode=disable"
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_12() {
	// Using connection config with password loaded from a secure source
	loadPasswordFromSecureStore := func() string {
		// Simulate loading from a secure store
		return os.Getenv("DB_PASSWORD")
	}
	
	config, err := pgx.ParseConfig("postgres://postgres:placeholder@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse config: %v\n", err)
		os.Exit(1)
	}
	
	// Replace placeholder with actual password from secure store
	config.Password = loadPasswordFromSecureStore()
	
	// ok: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_13() {
	// Using pgxpool with connection string that has non-empty password
	// ok: rule-pgx-empty-password
	dbpool, err := pgxpool.Connect(context.Background(), "postgresql://postgres:securePassword123@localhost:5432/mydb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer dbpool.Close()
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_14() {
	// Using connection string with multiple parameters and password from environment
	connParams := map[string]string{
		"user":     "postgres",
		"password": os.Getenv("DB_PASSWORD"),
		"host":     "localhost",
		"port":     "5432",
		"dbname":   "mydb",
		"sslmode":  "disable",
	}
	
	connStr := ""
	for key, value := range connParams {
		connStr += key + "=" + value + " "
	}
	
	// ok: rule-pgx-empty-password
	conn, err := pgx.Connect(context.Background(), connStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_15() {
	// Using IAM authentication for PostgreSQL (simulated)
	generateAuthToken := func() string {
		// In a real scenario, this would generate an IAM auth token
		// For this example, we'll use a non-empty placeholder
		return "iam-auth-token-123"
	}
	
	config := pgx.ConnConfig{
		Host:     "localhost",
		Port:     5432,
		Database: "mydb",
		User:     "postgres",
		Password: generateAuthToken(),
	}
	
	// ok: rule-pgx-empty-password
	conn, err := pgx.ConnectConfig(context.Background(), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close(context.Background())
}
// {/fact}

func main() {
	// This function is just a placeholder and doesn't need to be called
	fmt.Println("This is a collection of test cases for pgx empty password detection")
}