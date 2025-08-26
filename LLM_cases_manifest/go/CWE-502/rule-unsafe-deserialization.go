package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/schema"
	"github.com/ugorji/go/codec"
	"gopkg.in/yaml.v2"
)

type User struct {
	ID       int
	Username string
	IsAdmin  bool
}

type Config struct {
	Database string
	APIKey   string
}

type Message struct {
	Content string
	From    string
}

type Command struct {
	Name string
	Args []string
	Exec func(args []string) error
}

func init() {
	gob.Register(User{})
	gob.Register(Config{})
	gob.Register(Message{})
	gob.Register(Command{})
}

// True positive examples

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_1(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided gob data without validation
	userData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var user User
	decoder := gob.NewDecoder(bytes.NewReader(userData))
	// ruleid: rule-unsafe-deserialization
	err = decoder.Decode(&user)
	if err != nil {
		http.Error(w, "Failed to decode user data", http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Welcome %s!", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_2(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided JSON data without validation
	var data map[string]interface{}
	
	// ruleid: rule-unsafe-deserialization
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Processed data with %d fields", len(data))
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_3(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided XML data without validation
	var data interface{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// ruleid: rule-unsafe-deserialization
	err = xml.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Invalid XML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "XML processed successfully")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_4(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided YAML data without validation
	serializedData := r.URL.Query().Get("data")
	var config map[string]interface{}
	
	// ruleid: rule-unsafe-deserialization
	err := yaml.Unmarshal([]byte(serializedData), &config)
	if err != nil {
		http.Error(w, "Invalid YAML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "YAML config loaded with %d items", len(config))
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_5(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided TOML data without validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var config Config
	// ruleid: rule-unsafe-deserialization
	err = toml.Unmarshal(body, &config)
	if err != nil {
		http.Error(w, "Invalid TOML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "TOML config loaded: %v", config)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_6(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided binary data with gob without validation
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	encodedData := r.FormValue("data")
	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}
	
	var message Message
	decoder := gob.NewDecoder(bytes.NewReader(decodedData))
	// ruleid: rule-unsafe-deserialization
	err = decoder.Decode(&message)
	if err != nil {
		http.Error(w, "Failed to decode message", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Message from %s: %s", message.From, message.Content)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_7(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided data with codec package without validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var data interface{}
	handle := new(codec.JsonHandle)
	decoder := codec.NewDecoderBytes(body, handle)
	// ruleid: rule-unsafe-deserialization
	err = decoder.Decode(&data)
	if err != nil {
		http.Error(w, "Failed to decode data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Data processed successfully")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_8(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided protobuf data without validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var message proto.Message
	// ruleid: rule-unsafe-deserialization
	err = proto.Unmarshal(body, message)
	if err != nil {
		http.Error(w, "Failed to unmarshal protobuf", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Protobuf processed successfully")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_9(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided form data with schema package without validation
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	var user User
	decoder := schema.NewDecoder()
	// ruleid: rule-unsafe-deserialization
	err := decoder.Decode(&user, r.Form)
	if err != nil {
		http.Error(w, "Failed to decode form data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s processed", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_10(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided JSON from cookie without validation
	cookie, err := r.Cookie("userData")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	var user User
	// ruleid: rule-unsafe-deserialization
	err = json.Unmarshal([]byte(cookie.Value), &user)
	if err != nil {
		http.Error(w, "Invalid cookie data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Welcome back, %s!", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_11(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided data from header without validation
	encodedData := r.Header.Get("X-User-Data")
	decodedData, err := base64.StdEncoding.DecodeString(encodedData)
	if err != nil {
		http.Error(w, "Invalid base64 data in header", http.StatusBadRequest)
		return
	}
	
	var user User
	// ruleid: rule-unsafe-deserialization
	err = json.Unmarshal(decodedData, &user)
	if err != nil {
		http.Error(w, "Invalid JSON in header", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s authenticated via header", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_12(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided command object without validation
	commandData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var cmd Command
	// ruleid: rule-unsafe-deserialization
	err = gob.NewDecoder(bytes.NewReader(commandData)).Decode(&cmd)
	if err != nil {
		http.Error(w, "Failed to decode command", http.StatusBadRequest)
		return
	}
	
	if cmd.Exec != nil {
		cmd.Exec(cmd.Args) // Potentially dangerous execution
	}
	
	fmt.Fprintf(w, "Command %s executed", cmd.Name)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_13(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided XML with external entities without validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var data interface{}
	// ruleid: rule-unsafe-deserialization
	err = xml.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Invalid XML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "XML processed successfully")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_14(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided JSON from URL parameter without validation
	jsonData := r.URL.Query().Get("config")
	var config Config
	
	// ruleid: rule-unsafe-deserialization
	err := json.Unmarshal([]byte(jsonData), &config)
	if err != nil {
		http.Error(w, "Invalid JSON in URL parameter", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Config loaded: %v", config)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
func bad_case_15(w http.ResponseWriter, r *http.Request) {
	// Deserializing user-provided binary data without validation
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}
	
	file, _, err := r.FormFile("data")
	if err != nil {
		http.Error(w, "Failed to get file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()
	
	var obj interface{}
	// ruleid: rule-unsafe-deserialization
	err = gob.NewDecoder(file).Decode(&obj)
	if err != nil {
		http.Error(w, "Failed to decode file data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "File data processed successfully")
}
// {/fact}

// True negative examples

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_1(w http.ResponseWriter, r *http.Request) {
	// Using a predefined struct type with validation before deserialization
	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	
	// ok: rule-unsafe-deserialization
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Validate the deserialized data
	if user.Username == "" || !strings.Contains(user.Email, "@") {
		http.Error(w, "Invalid user data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s with email %s processed", user.Username, user.Email)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_2(w http.ResponseWriter, r *http.Request) {
	// Using JSON with schema validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Validate JSON structure before unmarshaling
	if !isValidUserJSON(body) {
		http.Error(w, "Invalid user JSON format", http.StatusBadRequest)
		return
	}
	
	var user User
	// ok: rule-unsafe-deserialization
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Welcome %s!", user.Username)
}
// {/fact}

func isValidUserJSON(data []byte) bool {
	// Simple validation to check if JSON has expected structure
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return false
	}
	
	// Check required fields
	_, hasUsername := jsonMap["Username"]
	_, hasID := jsonMap["ID"]
	
	return hasUsername && hasID
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_3(w http.ResponseWriter, r *http.Request) {
	// Using a secure serialization format (JSON) with strict type checking
	var user struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		IsAdmin  bool   `json:"isAdmin"`
	}
	
	// ok: rule-unsafe-deserialization
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Additional validation
	if user.ID <= 0 || user.Username == "" {
		http.Error(w, "Invalid user data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s processed", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_4(w http.ResponseWriter, r *http.Request) {
	// Using signed data to ensure integrity before deserialization
	signedData := r.URL.Query().Get("data")
	signature := r.URL.Query().Get("signature")
	
	// Verify signature before deserializing
	if !verifySignature(signedData, signature) {
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}
	
	var config Config
	// ok: rule-unsafe-deserialization
	err := json.Unmarshal([]byte(signedData), &config)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Config loaded: %v", config)
}
// {/fact}

func verifySignature(data, signature string) bool {
	// In a real implementation, this would verify a cryptographic signature
	secretKey := []byte(os.Getenv("SECRET_KEY"))
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(data))
	expectedSignature := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_5(w http.ResponseWriter, r *http.Request) {
	// Using a whitelist of allowed types for deserialization
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(body, &jsonMap); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	// Check if the type is in our whitelist
	typeName, ok := jsonMap["type"].(string)
	if !ok || !isAllowedType(typeName) {
		http.Error(w, "Disallowed object type", http.StatusBadRequest)
		return
	}
	
	var message Message
	// ok: rule-unsafe-deserialization
	err = json.Unmarshal(body, &message)
	if err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Message processed: %s", message.Content)
}
// {/fact}

func isAllowedType(typeName string) bool {
	allowedTypes := []string{"Message", "SimpleConfig", "UserProfile"}
	for _, t := range allowedTypes {
		if t == typeName {
			return true
		}
	}
	return false
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_6(w http.ResponseWriter, r *http.Request) {
	// Using a custom decoder with validation
	var user User
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Strict parsing
	
	// ok: rule-unsafe-deserialization
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	// Additional validation
	if user.Username == "" {
		http.Error(w, "Username cannot be empty", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s processed", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_7(w http.ResponseWriter, r *http.Request) {
	// Using XML with a specific type and validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Validate XML structure before unmarshaling
	if !isValidXML(body) {
		http.Error(w, "Invalid XML format", http.StatusBadRequest)
		return
	}
	
	var message Message
	// ok: rule-unsafe-deserialization
	err = xml.Unmarshal(body, &message)
	if err != nil {
		http.Error(w, "Invalid XML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Message from %s: %s", message.From, message.Content)
}
// {/fact}

func isValidXML(data []byte) bool {
	// Simple validation to check if XML is well-formed
	return xml.Unmarshal(data, new(interface{})) == nil
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_8(w http.ResponseWriter, r *http.Request) {
	// Using YAML with schema validation
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Pre-validate YAML structure
	var preCheck map[string]interface{}
	if err := yaml.Unmarshal(body, &preCheck); err != nil {
		http.Error(w, "Invalid YAML format", http.StatusBadRequest)
		return
	}
	
	// Check required fields
	if _, hasDatabase := preCheck["database"]; !hasDatabase {
		http.Error(w, "Missing required field: database", http.StatusBadRequest)
		return
	}
	
	var config Config
	// ok: rule-unsafe-deserialization
	err = yaml.Unmarshal(body, &config)
	if err != nil {
		http.Error(w, "Invalid YAML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Config loaded: %v", config)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_9(w http.ResponseWriter, r *http.Request) {
	// Using JSON with depth limit to prevent deserialization attacks
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 10240)) // Limit input size
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Check JSON nesting depth before deserializing
	if jsonDepthExceeded(body, 5) {
		http.Error(w, "JSON nesting too deep", http.StatusBadRequest)
		return
	}
	
	var data map[string]interface{}
	// ok: rule-unsafe-deserialization
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Data processed with %d fields", len(data))
}
// {/fact}

func jsonDepthExceeded(data []byte, maxDepth int) bool {
	// Simple check for JSON nesting depth
	depth := 0
	maxReached := 0
	
	for _, b := range data {
		if b == '{' || b == '[' {
			depth++
			if depth > maxReached {
				maxReached = depth
			}
		} else if b == '}' || b == ']' {
			depth--
		}
	}
	
	return maxReached > maxDepth
}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_10(w http.ResponseWriter, r *http.Request) {
	// Using a secure serialization format with type enforcement
	var user struct {
		Username string `json:"username"`
		Age      int    `json:"age"`
	}
	
	// ok: rule-unsafe-deserialization
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	
	// Additional validation
	if user.Username == "" || user.Age <= 0 || user.Age > 120 {
		http.Error(w, "Invalid user data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "User %s (age %d) processed", user.Username, user.Age)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_11(w http.ResponseWriter, r *http.Request) {
	// Using protobuf with specific message type
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1024*1024)) // Limit input size
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Create a specific protobuf message type
	message := &proto.Message{}
	
	// ok: rule-unsafe-deserialization
	err = proto.Unmarshal(body, message)
	if err != nil {
		http.Error(w, "Invalid protobuf data", http.StatusBadRequest)
		return
	}
	
	// Additional validation would happen here
	
	fmt.Fprintf(w, "Protobuf message processed successfully")
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_12(w http.ResponseWriter, r *http.Request) {
	// Using JSON with expiration time validation
	cookie, err := r.Cookie("userData")
	if err != nil {
		http.Error(w, "Cookie not found", http.StatusBadRequest)
		return
	}
	
	// Parse the cookie value
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		http.Error(w, "Invalid cookie format", http.StatusBadRequest)
		return
	}
	
	// Validate expiration time
	expTime, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expTime {
		http.Error(w, "Cookie expired", http.StatusBadRequest)
		return
	}
	
	var user User
	// ok: rule-unsafe-deserialization
	err = json.Unmarshal([]byte(parts[1]), &user)
	if err != nil {
		http.Error(w, "Invalid cookie data", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "Welcome back, %s!", user.Username)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_13(w http.ResponseWriter, r *http.Request) {
	// Using XML with disabled entity expansion
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 10240)) // Limit input size
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Entity = nil // Disable entity expansion
	
	var data struct {
		Name    string `xml:"name"`
		Content string `xml:"content"`
	}
	
	// ok: rule-unsafe-deserialization
	err = decoder.Decode(&data)
	if err != nil {
		http.Error(w, "Invalid XML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "XML processed: %s", data.Name)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_14(w http.ResponseWriter, r *http.Request) {
	// Using form data with schema validation
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	
	// Manual extraction and validation of form fields
	username := r.FormValue("username")
	ageStr := r.FormValue("age")
	
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	
	age, err := strconv.Atoi(ageStr)
	if err != nil || age <= 0 || age > 120 {
		http.Error(w, "Invalid age", http.StatusBadRequest)
		return
	}
	
	// Create user object after validation
	user := User{
		Username: username,
		ID:       age, // Using age as ID for this example
	}
	
	// ok: rule-unsafe-deserialization
	// No unsafe deserialization here, we manually constructed the object
	
	fmt.Fprintf(w, "User %s (age %d) processed", user.Username, age)
}
// {/fact}

// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
func good_case_15(w http.ResponseWriter, r *http.Request) {
	// Using TOML with validation
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 10240)) // Limit input size
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Pre-validate TOML structure
	var preCheck map[string]interface{}
	if err := toml.Unmarshal(body, &preCheck); err != nil {
		http.Error(w, "Invalid TOML format", http.StatusBadRequest)
		return
	}
	
	// Check for required fields and validate structure
	if _, hasDatabase := preCheck["database"]; !hasDatabase {
		http.Error(w, "Missing required field: database", http.StatusBadRequest)
		return
	}
	
	var config Config
	// ok: rule-unsafe-deserialization
	err = toml.Unmarshal(body, &config)
	if err != nil {
		http.Error(w, "Invalid TOML", http.StatusBadRequest)
		return
	}
	
	fmt.Fprintf(w, "TOML config loaded: %v", config)
}
// {/fact}

func main() {
	http.HandleFunc("/bad1", bad_case_1)
	http.HandleFunc("/bad2", bad_case_2)
	http.HandleFunc("/bad3", bad_case_3)
	http.HandleFunc("/bad4", bad_case_4)
	http.HandleFunc("/bad5", bad_case_5)
	http.HandleFunc("/bad6", bad_case_6)
	http.HandleFunc("/bad7", bad_case_7)
	http.HandleFunc("/bad8", bad_case_8)
	http.HandleFunc("/bad9", bad_case_9)
	http.HandleFunc("/bad10", bad_case_10)
	http.HandleFunc("/bad11", bad_case_11)
	http.HandleFunc("/bad12", bad_case_12)
	http.HandleFunc("/bad13", bad_case_13)
	http.HandleFunc("/bad14", bad_case_14)
	http.HandleFunc("/bad15", bad_case_15)
	
	http.HandleFunc("/good1", good_case_1)
	http.HandleFunc("/good2", good_case_2)
	http.HandleFunc("/good3", good_case_3)
	http.HandleFunc("/good4", good_case_4)
	http.HandleFunc("/good5", good_case_5)
	http.HandleFunc("/good6", good_case_6)
	http.HandleFunc("/good7", good_case_7)
	http.HandleFunc("/good8", good_case_8)
	http.HandleFunc("/good9", good_case_9)
	http.HandleFunc("/good10", good_case_10)
	http.HandleFunc("/good11", good_case_11)
	http.HandleFunc("/good12", good_case_12)
	http.HandleFunc("/good13", good_case_13)
	http.HandleFunc("/good14", good_case_14)
	http.HandleFunc("/good15", good_case_15)
	
	http.ListenAndServe(":8080", nil)
}