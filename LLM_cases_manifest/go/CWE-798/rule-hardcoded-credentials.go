package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/smtp"
	"os"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/go-redis/redis/v8"
	"github.com/jlaffaye/ftp"
	_ "github.com/lib/pq"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/ssh"
	"google.golang.org/api/option"
)

// True Positive Examples (Vulnerable Code)

// Database connection with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_1() {
	// ruleid: rule-hardcoded-credentials
	db, err := sql.Open("postgres", "postgres://admin:supersecretpassword123@localhost:5432/mydb?sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM users")
	if err != nil {
		panic(err)
	}
	defer rows.Close()
}
// {/fact}

// Redis connection with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_2() {
	ctx := context.Background()
	// ruleid: rule-hardcoded-credentials
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "myRedisSecretPassword", // hardcoded password
		DB:       0,
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
}
// {/fact}

// AWS S3 access with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_3() {
	// ruleid: rule-hardcoded-credentials
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(
			"AKIA_PLACEHOLDER_ACCESS_KEY",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"",
		),
	})
	if err != nil {
		panic(err)
	}

	s3Client := s3.New(sess)
	_, err = s3Client.ListBuckets(nil)
	if err != nil {
		panic(err)
	}
}
// {/fact}

// SMTP email sending with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_4() {
	// SMTP server configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	
	// ruleid: rule-hardcoded-credentials
	auth := smtp.PlainAuth("", "user@example.com", "myEmailP@ssw0rd", smtpHost)
	
	// Sending email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "from@example.com", []string{"to@example.com"}, []byte("Subject: Test\n\nThis is a test email."))
	if err != nil {
		panic(err)
	}
}
// {/fact}

// SSH connection with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-hardcoded-credentials
	config := &ssh.ClientConfig{
		User: "admin",
		Auth: []ssh.AuthMethod{
			ssh.Password("superSecretAdminPass123!"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	
	client, err := ssh.Dial("tcp", "example.com:22", config)
	if err != nil {
		panic(err)
	}
	defer client.Close()
}
// {/fact}

// FTP connection with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_6() {
	// ruleid: rule-hardcoded-credentials
	conn, err := ftp.Dial("ftp.example.com:21")
	if err != nil {
		panic(err)
	}
	
	err = conn.Login("ftpuser", "ftpP@ssw0rd")
	if err != nil {
		panic(err)
	}
	defer conn.Quit()
}
// {/fact}

// API key in HTTP client
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_7() {
	// ruleid: rule-hardcoded-credentials
	apiKey := "sk_test_PLACEHOLDER_KEY"
	url := fmt.Sprintf("https://api.stripe.com/v1/charges?api_key=%s", apiKey)
	
	// Using the URL with the API key
	fmt.Println("Making request to:", url)
}
// {/fact}

// Google Cloud Storage with hardcoded service account key
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_8() {
	ctx := context.Background()
	// ruleid: rule-hardcoded-credentials
	serviceAccountKey := `{
		"type": "service_account",
		"project_id": "my-project",
		"private_key_id": "abcdef1234567890",
		"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----\n",
		"client_email": "service-account@my-project.iam.gserviceaccount.com",
		"client_id": "123456789012345678901",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`
	
	client, err := storage.NewClient(ctx, option.WithCredentialsJSON([]byte(serviceAccountKey)))
	if err != nil {
		panic(err)
	}
	defer client.Close()
}
// {/fact}

// MinIO client with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_9() {
	// ruleid: rule-hardcoded-credentials
	minioClient, err := minio.New("play.min.io", &minio.Options{
		Creds:  credentials.NewStaticV4("Q3AM3UQ867SPQQA43P2F", "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG", ""),
		Secure: true,
	})
	if err != nil {
		panic(err)
	}
	
	// List buckets
	_, err = minioClient.ListBuckets(context.Background())
	if err != nil {
		panic(err)
	}
}
// {/fact}

// Database connection string with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_10() {
	// ruleid: rule-hardcoded-credentials
	connectionString := "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myP@ssw0rd;"
	db, err := sql.Open("sqlserver", connectionString)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}
// {/fact}

// OAuth2 client with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_11() {
	// ruleid: rule-hardcoded-credentials
	clientID := "my-client-id"
	clientSecret := "my-client-secret-12345"
	
	// Using the credentials
	authURL := fmt.Sprintf("https://oauth2.example.com/token?client_id=%s&client_secret=%s&grant_type=client_credentials", 
		clientID, clientSecret)
	fmt.Println("Auth URL:", authURL)
}
// {/fact}

// Hardcoded JWT secret
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_12() {
	// ruleid: rule-hardcoded-credentials
	jwtSecret := "super-secret-jwt-token-signing-key-that-should-not-be-in-code"
	
	// Using the JWT secret
	token := generateJWT(jwtSecret)
	fmt.Println("Generated token:", token)
}
// {/fact}

func generateJWT(secret string) string {
	// Simplified for example
	return "jwt." + secret + ".signature"
}

// Hardcoded encryption key
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_13() {
	plaintext := "sensitive data"
	// ruleid: rule-hardcoded-credentials
	encryptionKey := "PLACEHOLDER_SECRET_32_CHARS"
	
	// Using the encryption key
	encryptedData := encrypt(plaintext, encryptionKey)
	fmt.Println("Encrypted:", encryptedData)
}
// {/fact}

func encrypt(data, key string) string {
	// Simplified for example
	return "encrypted-" + data + "-with-" + key
}

// MongoDB connection with hardcoded credentials
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_14() {
	// ruleid: rule-hardcoded-credentials
	mongoURI := "mongodb://dbadmin:dbpassword123@mongodb0.example.com:27017/admin"
	
	// Using the MongoDB URI
	fmt.Println("Connecting to MongoDB with URI:", mongoURI)
}
// {/fact}

// Hardcoded API token in configuration
// {fact rule=hardcoded-credentials@v1.0 defects=1}
func bad_case_15() {
	// ruleid: rule-hardcoded-credentials
	config := map[string]string{
		"api_endpoint": "https://api.example.com/v1",
		"api_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		"timeout": "30",
	}
	
	// Using the API token
	fmt.Println("API Token:", config["api_token"])
}
// {/fact}

// True Negative Examples (Secure Code)

// Database connection with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_1() {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbName := os.Getenv("DB_NAME")
	
	// ok: rule-hardcoded-credentials
	connectionString := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable", 
		dbUser, dbPassword, dbHost, dbName)
	
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}
// {/fact}

// Redis connection with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_2() {
	ctx := context.Background()
	redisHost := os.Getenv("REDIS_HOST")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	
	// ok: rule-hardcoded-credentials
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: redisPassword,
		DB:       0,
	})
	
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}
}
// {/fact}

// AWS S3 access with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_3() {
	// ok: rule-hardcoded-credentials
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION")),
		Credentials: credentials.NewEnvCredentials(), // Uses AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
	})
	if err != nil {
		panic(err)
	}
	
	s3Client := s3.New(sess)
	_, err = s3Client.ListBuckets(nil)
	if err != nil {
		panic(err)
	}
}
// {/fact}

// SMTP email sending with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_4() {
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	
	// ok: rule-hardcoded-credentials
	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)
	
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, "from@example.com", []string{"to@example.com"}, []byte("Subject: Test\n\nThis is a test email."))
	if err != nil {
		panic(err)
	}
}
// {/fact}

// SSH connection with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_5() {
	sshUser := os.Getenv("SSH_USER")
	sshPassword := os.Getenv("SSH_PASSWORD")
	sshHost := os.Getenv("SSH_HOST")
	
	// ok: rule-hardcoded-credentials
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	
	client, err := ssh.Dial("tcp", sshHost+":22", config)
	if err != nil {
		panic(err)
	}
	defer client.Close()
}
// {/fact}

// FTP connection with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_6() {
	ftpHost := os.Getenv("FTP_HOST")
	ftpUser := os.Getenv("FTP_USER")
	ftpPassword := os.Getenv("FTP_PASSWORD")
	
	conn, err := ftp.Dial(ftpHost + ":21")
	if err != nil {
		panic(err)
	}
	
	// ok: rule-hardcoded-credentials
	err = conn.Login(ftpUser, ftpPassword)
	if err != nil {
		panic(err)
	}
	defer conn.Quit()
}
// {/fact}

// API key from environment variable
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_7() {
	// ok: rule-hardcoded-credentials
	apiKey := os.Getenv("STRIPE_API_KEY")
	url := fmt.Sprintf("https://api.stripe.com/v1/charges?api_key=%s", apiKey)
	
	// Using the URL with the API key
	fmt.Println("Making request to:", url)
}
// {/fact}

// Google Cloud Storage with credentials from file
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_8() {
	ctx := context.Background()
	credentialsFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	
	// ok: rule-hardcoded-credentials
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(credentialsFile))
	if err != nil {
		panic(err)
	}
	defer client.Close()
}
// {/fact}

// MinIO client with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_9() {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	accessKeyID := os.Getenv("MINIO_ACCESS_KEY")
	secretAccessKey := os.Getenv("MINIO_SECRET_KEY")
	
	// ok: rule-hardcoded-credentials
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: true,
	})
	if err != nil {
		panic(err)
	}
	
	// List buckets
	_, err = minioClient.ListBuckets(context.Background())
	if err != nil {
		panic(err)
	}
}
// {/fact}

// Database connection string with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_10() {
	server := os.Getenv("DB_SERVER")
	database := os.Getenv("DB_NAME")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	
	// ok: rule-hardcoded-credentials
	connectionString := fmt.Sprintf("Server=%s;Database=%s;User Id=%s;Password=%s;", 
		server, database, user, password)
	
	db, err := sql.Open("sqlserver", connectionString)
	if err != nil {
		panic(err)
	}
	defer db.Close()
}
// {/fact}

// OAuth2 client with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_11() {
	clientID := os.Getenv("OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("OAUTH_CLIENT_SECRET")
	
	// ok: rule-hardcoded-credentials
	authURL := fmt.Sprintf("https://oauth2.example.com/token?client_id=%s&client_secret=%s&grant_type=client_credentials", 
		clientID, clientSecret)
	
	fmt.Println("Auth URL:", authURL)
}
// {/fact}

// JWT secret from environment variable
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_12() {
	// ok: rule-hardcoded-credentials
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	
	// Using the JWT secret
	token := generateSecureJWT(jwtSecret)
	fmt.Println("Generated token:", token)
}
// {/fact}

func generateSecureJWT(secret string) string {
	// Simplified for example
	return "jwt." + secret + ".signature"
}

// Encryption key from environment variable
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_13() {
	plaintext := "sensitive data"
	// ok: rule-hardcoded-credentials
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	
	// Using the encryption key
	encryptedData := encryptSecure(plaintext, encryptionKey)
	fmt.Println("Encrypted:", encryptedData)
}
// {/fact}

func encryptSecure(data, key string) string {
	// Simplified for example
	return "encrypted-" + data + "-with-" + key
}

// MongoDB connection with credentials from environment variables
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_14() {
	mongoUser := os.Getenv("MONGO_USER")
	mongoPassword := os.Getenv("MONGO_PASSWORD")
	mongoHost := os.Getenv("MONGO_HOST")
	mongoDatabase := os.Getenv("MONGO_DATABASE")
	
	// ok: rule-hardcoded-credentials
	mongoURI := fmt.Sprintf("mongodb://%s:%s@%s:27017/%s", 
		mongoUser, mongoPassword, mongoHost, mongoDatabase)
	
	// Using the MongoDB URI
	fmt.Println("Connecting to MongoDB...")
}
// {/fact}

// API token from configuration file or environment
// {fact rule=hardcoded-credentials@v1.0 defects=0}
func good_case_15() {
	// ok: rule-hardcoded-credentials
	config := map[string]string{
		"api_endpoint": "https://api.example.com/v1",
		"api_token":    os.Getenv("API_TOKEN"),
		"timeout":      "30",
	}
	
	// Using the API token
	fmt.Println("Using API endpoint:", config["api_endpoint"])
}
// {/fact}