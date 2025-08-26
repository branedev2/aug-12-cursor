#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <regex>
#include <random>
#include <chrono>
#include <ctime>
#include <fstream>

// Helper function for MD5 hash
std::string md5_hash(const std::string& input) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), digest);
    
    std::stringstream ss;
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}

// Helper function for SHA-256 hash
std::string sha256_hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Helper for CURL response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
        return newLength;
    } catch(std::bad_alloc& e) {
        return 0;
    }
}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// BAD CASES - Improper Authentication

// Case 1: Simple hardcoded credentials
void bad_case_1() {
    std::string username = "admin";
    std::string password = "admin123";
    
    std::string input_username = "admin";
    std::string input_password = "admin123";
    
    // ruleid: cpp-improper-authentication
    if (username == input_username && password == input_password) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 2: Weak password policy - accepting any password
void bad_case_2() {
    std::string username = "user123";
    std::string password = ""; // Empty password allowed
    
    // Get input from HTTP request (simplified)
    std::string input_username = "user123";
    std::string input_password = ""; // Empty password
    
    // ruleid: cpp-improper-authentication
    if (username == input_username) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 3: Using MD5 for password hashing (weak hash)
void bad_case_3() {
    // Database stored password (MD5 hash of "password123")
    std::string stored_hash = "PLACEHOLDER_SECRET_32_CHARS";
    
    // Get password from HTTP request
    std::string input_password = "password123";
    
    // ruleid: cpp-improper-authentication
    std::string hashed_input = md5_hash(input_password);
    
    if (hashed_input == stored_hash) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 4: No brute force protection
void bad_case_4() {
    std::string stored_username = "admin";
    std::string stored_password_hash = "PLACEHOLDER_SECRET_40_CHARS6aabbdd62a11ef721d1542d8"; // SHA-256 of "password"
    
    int attempts = 0;
    bool authenticated = false;
    
    while (!authenticated && attempts < 1000) { // No real limit
        // Simulating multiple login attempts
        std::string username = "admin";
        std::string password = "attempt" + std::to_string(attempts);
        
        std::string password_hash = sha256_hash(password);
        
        // ruleid: cpp-improper-authentication
        if (username == stored_username && password_hash == stored_password_hash) {
            authenticated = true;
            std::cout << "Authentication successful after " << attempts << " attempts!" << std::endl;
        }
        attempts++;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 5: Authentication without TLS/SSL
void bad_case_5() {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        // ruleid: cpp-improper-authentication
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/login"); // Using HTTP instead of HTTPS
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "username=admin&password=secret123");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 6: Insecure session management - no expiration
void bad_case_6() {
    std::map<std::string, std::string> sessions;
    
    // User logs in
    std::string username = "user123";
    std::string password = "password123";
    
    // Generate session token (simplified)
    std::string session_token = "abc123xyz789";
    
    // ruleid: cpp-improper-authentication
    sessions[username] = session_token; // No expiration time set
    
    // Later, check session
    std::string provided_token = "abc123xyz789";
    bool authenticated = false;
    
    for (const auto& session : sessions) {
        if (session.second == provided_token) {
            authenticated = true;
            break;
        }
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 7: Using basic authentication without HTTPS
void bad_case_7() {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        // ruleid: cpp-improper-authentication
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/data");
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, "admin");
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "password123");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 8: Insecure password recovery mechanism
void bad_case_8() {
    std::map<std::string, std::string> user_data = {
        {"john@example.com", "John Smith"},
        {"alice@example.com", "Alice Johnson"}
    };
    
    // User requests password reset
    std::string email = "john@example.com";
    
    if (user_data.find(email) != user_data.end()) {
        // ruleid: cpp-improper-authentication
        // Generate temporary password without verification
        std::string temp_password = "temp123";
        
        // Send email with temporary password (simplified)
        std::cout << "Email sent to " << email << " with temporary password: " << temp_password << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 9: Insecure storage of credentials in code
void bad_case_9() {
    sqlite3* db;
    char* errMsg = 0;
    
    // ruleid: cpp-improper-authentication
    int rc = sqlite3_open("users.db", &db);
    
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }
    
    std::string username = "admin";
    std::string password = "admin123";
    
    std::string sql = "INSERT INTO users (username, password) VALUES ('" + 
                      username + "', '" + password + "');"; // Storing plaintext password
    
    rc = sqlite3_exec(db, sql.c_str(), 0, 0, &errMsg);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 10: Authentication bypass through direct object reference
void bad_case_10() {
    // User data stored by ID
    std::map<int, std::map<std::string, std::string>> user_profiles = {
        {1, {{"name", "Admin User"}, {"role", "admin"}}},
        {2, {{"name", "Regular User"}, {"role", "user"}}}
    };
    
    // Get user ID from request parameter (simplified)
    int user_id = 1; // Assuming this comes from user input
    
    // ruleid: cpp-improper-authentication
    // No authentication check, directly accessing user data by ID
    auto user_data = user_profiles[user_id];
    
    std::cout << "Accessed profile: " << user_data["name"] << " with role: " << user_data["role"] << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 11: Insecure "remember me" functionality
void bad_case_11() {
    // User logs in and selects "remember me"
    std::string username = "user123";
    
    // Generate remember me token (simplified)
    std::string remember_token = username + "_token";
    
    // ruleid: cpp-improper-authentication
    // Store token in cookie without proper security measures
    std::cout << "Set-Cookie: remember=" << remember_token << "; path=/; expires=Fri, 31 Dec 2023 23:59:59 GMT" << std::endl;
    
    // Later, authenticate based on remember token
    std::string provided_token = "user123_token";
    if (provided_token == remember_token) {
        std::cout << "Auto-login successful!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 12: Weak random token generation
void bad_case_12() {
    // User logs in
    std::string username = "user123";
    
    // Generate session token using weak random
    srand(time(NULL));
    int random_number = rand() % 10000;
    std::string session_token = username + "_" + std::to_string(random_number);
    
    // ruleid: cpp-improper-authentication
    // Store session token
    std::cout << "Session established with token: " << session_token << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 13: Lack of multi-factor authentication for sensitive operations
void bad_case_13() {
    bool is_logged_in = true;
    std::string username = "admin";
    
    // User attempts to perform sensitive operation
    std::string operation = "delete_all_records";
    
    // ruleid: cpp-improper-authentication
    // Only checks if user is logged in, no additional verification
    if (is_logged_in) {
        std::cout << "Performing sensitive operation: " << operation << std::endl;
        // Perform the operation
    } else {
        std::cout << "Authentication required!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 14: Insecure OAuth implementation
void bad_case_14() {
    // OAuth callback handling
    std::string auth_code = "auth_code_from_request";
    std::string client_id = "my_client_id";
    std::string client_secret = "my_client_secret";
    
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        // ruleid: cpp-improper-authentication
        // Not validating the state parameter to prevent CSRF
        std::string post_fields = "code=" + auth_code + 
                                 "&client_id=" + client_id + 
                                 "&client_secret=" + client_secret + 
                                 "&grant_type=authorization_code";
        
        curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.example.com/token");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=1}

// Case 15: Insecure JWT validation
void bad_case_15() {
    // Received JWT token from client
    std::string jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    
    // ruleid: cpp-improper-authentication
    // Simplified JWT parsing without proper validation
    size_t first_dot = jwt_token.find('.');
    size_t second_dot = jwt_token.find('.', first_dot + 1);
    
    std::string header_b64 = jwt_token.substr(0, first_dot);
    std::string payload_b64 = jwt_token.substr(first_dot + 1, second_dot - first_dot - 1);
    
    // No signature validation performed
    std::cout << "JWT accepted without signature validation" << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// GOOD CASES - Proper Authentication

// Case 1: Secure password storage with strong hashing
void good_case_1() {
    // Database stored password (SHA-256 hash with salt)
    std::string stored_salt = "randomsalt123";
    std::string stored_hash = "a1b2c3d4e5f6..."; // Pretend this is a proper hash
    
    // Get password from HTTP request
    std::string input_password = "securePassword123";
    
    // ok: cpp-improper-authentication
    // Use strong hashing with salt
    std::string salted_input = input_password + stored_salt;
    std::string hashed_input = sha256_hash(salted_input);
    
    if (hashed_input == stored_hash) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 2: Strong password policy enforcement
void good_case_2() {
    std::string password = "Weak";
    
    // ok: cpp-improper-authentication
    // Enforce strong password policy
    std::regex password_policy("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");
    
    if (!std::regex_match(password, password_policy)) {
        std::cout << "Password does not meet security requirements. "
                  << "It must be at least 8 characters long and include uppercase, "
                  << "lowercase, number, and special character." << std::endl;
        return;
    }
    
    // Continue with secure password storage...
    std::cout << "Password meets security requirements." << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 3: Brute force protection with account lockout
void good_case_3() {
    std::map<std::string, int> failed_attempts;
    std::string username = "user123";
    std::string stored_hash = "PLACEHOLDER_SECRET_40_CHARS6aabbdd62a11ef721d1542d8"; // SHA-256 of "password"
    
    std::string input_password = "wrong_password";
    std::string input_hash = sha256_hash(input_password);
    
    // ok: cpp-improper-authentication
    // Check for account lockout
    if (failed_attempts[username] >= 5) {
        std::cout << "Account is locked due to too many failed attempts." << std::endl;
        return;
    }
    
    if (input_hash == stored_hash) {
        std::cout << "Authentication successful!" << std::endl;
        failed_attempts[username] = 0; // Reset counter on success
    } else {
        failed_attempts[username]++;
        std::cout << "Authentication failed! Attempts: " << failed_attempts[username] << std::endl;
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 4: Secure authentication over HTTPS
void good_case_4() {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        // ok: cpp-improper-authentication
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/login"); // Using HTTPS
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // Verify SSL certificate
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L); // Verify hostname
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "username=admin&password=secret123");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 5: Secure session management with expiration
void good_case_5() {
    struct Session {
        std::string token;
        std::time_t expiry;
    };
    
    std::map<std::string, Session> sessions;
    
    // User logs in
    std::string username = "user123";
    std::string password = "password123"; // Assume password is verified
    
    // Generate secure random session token (simplified)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << dis(gen);
    }
    std::string session_token = ss.str();
    
    // ok: cpp-improper-authentication
    // Set session with expiration time (30 minutes from now)
    std::time_t now = std::time(nullptr);
    std::time_t expiry = now + 1800; // 30 minutes
    
    sessions[username] = {session_token, expiry};
    
    // Later, check session
    std::string provided_token = session_token;
    bool authenticated = false;
    
    for (const auto& session : sessions) {
        if (session.second.token == provided_token) {
            // Check if session is still valid
            if (std::time(nullptr) < session.second.expiry) {
                authenticated = true;
            }
            break;
        }
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 6: Multi-factor authentication
void good_case_6() {
    std::string username = "user123";
    std::string password = "password123";
    std::string stored_password_hash = "PLACEHOLDER_SECRET_40_CHARS6aabbdd62a11ef721d1542d8";
    
    // First factor: password verification
    bool password_verified = (sha256_hash(password) == stored_password_hash);
    
    if (!password_verified) {
        std::cout << "Password verification failed!" << std::endl;
        return;
    }
    
    // Second factor: verification code
    std::string user_provided_code = "123456";
    
    // ok: cpp-improper-authentication
    // Verify the second factor (simplified)
    bool code_verified = verify_2fa_code(username, user_provided_code);
    
    if (code_verified) {
        std::cout << "Two-factor authentication successful!" << std::endl;
        // Grant access
    } else {
        std::cout << "Two-factor authentication failed!" << std::endl;
    }
}
// {/fact}

// Helper function for 2FA verification (simplified)
bool verify_2fa_code(const std::string& username, const std::string& code) {
    // In a real implementation, this would validate against a TOTP algorithm
    // or check a database of valid codes
    return code == "123456"; // Simplified for example
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 7: Secure OAuth implementation
void good_case_7() {
    // OAuth callback handling with state validation
    std::string auth_code = "auth_code_from_request";
    std::string received_state = "state_from_request";
    std::string expected_state = "previously_generated_state"; // Should be retrieved from session
    std::string client_id = "my_client_id";
    std::string client_secret = "my_client_secret";
    
    // ok: cpp-improper-authentication
    // Validate state parameter to prevent CSRF
    if (received_state != expected_state) {
        std::cout << "OAuth state mismatch! Possible CSRF attack." << std::endl;
        return;
    }
    
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        std::string post_fields = "code=" + auth_code + 
                                 "&client_id=" + client_id + 
                                 "&client_secret=" + client_secret + 
                                 "&grant_type=authorization_code";
        
        curl_easy_setopt(curl, CURLOPT_URL, "https://oauth.example.com/token");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 8: Secure JWT validation
void good_case_8() {
    // Received JWT token from client
    std::string jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    std::string secret_key = "your-256-bit-secret";
    
    // ok: cpp-improper-authentication
    // Proper JWT validation (simplified)
    bool is_valid = validate_jwt_signature(jwt_token, secret_key);
    
    if (is_valid) {
        // Extract and validate claims
        std::string payload = decode_jwt_payload(jwt_token);
        
        // Check expiration
        time_t exp = extract_exp_from_payload(payload);
        time_t now = time(NULL);
        
        if (exp < now) {
            std::cout << "JWT token has expired" << std::endl;
            return;
        }
        
        std::cout << "JWT token is valid" << std::endl;
    } else {
        std::cout << "JWT signature validation failed" << std::endl;
    }
}
// {/fact}

// Helper functions for JWT validation (simplified)
bool validate_jwt_signature(const std::string& token, const std::string& secret) {
    // In a real implementation, this would properly validate the signature
    return true; // Simplified for example
}

std::string decode_jwt_payload(const std::string& token) {
    // In a real implementation, this would decode the base64 payload
    return "{}"; // Simplified for example
}

time_t extract_exp_from_payload(const std::string& payload) {
    // In a real implementation, this would extract the exp claim
    return time(NULL) + 3600; // Simplified for example
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 9: Secure password recovery
void good_case_9() {
    std::map<std::string, std::string> user_data = {
        {"john@example.com", "John Smith"},
        {"alice@example.com", "Alice Johnson"}
    };
    
    // User requests password reset
    std::string email = "john@example.com";
    
    if (user_data.find(email) != user_data.end()) {
        // ok: cpp-improper-authentication
        // Generate one-time reset token with expiration
        std::string reset_token = generate_secure_token();
        time_t expiry = time(NULL) + 3600; // 1 hour expiry
        
        // Store token and expiry (would be in database in real implementation)
        std::cout << "Stored reset token for " << email << ": " << reset_token << " (expires in 1 hour)" << std::endl;
        
        // Send email with reset link (simplified)
        std::string reset_link = "https://example.com/reset-password?token=" + reset_token;
        std::cout << "Email sent to " << email << " with reset link: " << reset_link << std::endl;
    }
}
// {/fact}

// Helper function for secure token generation
std::string generate_secure_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 10: Secure credential storage using environment variables
void good_case_10() {
    // ok: cpp-improper-authentication
    // Get database credentials from environment variables
    const char* db_user = std::getenv("DB_USER");
    const char* db_pass = std::getenv("DB_PASS");
    const char* db_host = std::getenv("DB_HOST");
    
    if (!db_user || !db_pass || !db_host) {
        std::cerr << "Database credentials not properly configured in environment variables" << std::endl;
        return;
    }
    
    std::cout << "Connecting to database as " << db_user << " at " << db_host << std::endl;
    // Connect to database using secure credentials
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 11: Role-based access control
void good_case_11() {
    struct User {
        std::string username;
        std::string role;
        bool authenticated;
    };
    
    // Authenticated user from session
    User current_user = {"john_doe", "user", true};
    
    // Attempting to access admin functionality
    std::string requested_action = "delete_user";
    
    // ok: cpp-improper-authentication
    // Proper role-based authorization check
    if (!current_user.authenticated) {
        std::cout << "Authentication required" << std::endl;
        return;
    }
    
    if (requested_action == "delete_user" && current_user.role != "admin") {
        std::cout << "Access denied: Insufficient privileges" << std::endl;
        return;
    }
    
    std::cout << "Access granted: Performing " << requested_action << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 12: Secure "remember me" functionality
void good_case_12() {
    // User logs in and selects "remember me"
    std::string username = "user123";
    
    // ok: cpp-improper-authentication
    // Generate secure remember token
    std::string remember_token = generate_secure_token();
    std::string token_hash = sha256_hash(remember_token);
    
    // Store hashed token in database (simplified)
    std::cout << "Stored hashed remember token for " << username << ": " << token_hash << std::endl;
    
    // Set secure cookie
    std::cout << "Set-Cookie: remember=" << remember_token 
              << "; path=/; HttpOnly; Secure; SameSite=Strict; "
              << "expires=Fri, 31 Dec 2023 23:59:59 GMT" << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 13: Secure session ID generation
void good_case_13() {
    // User logs in
    std::string username = "user123";
    
    // ok: cpp-improper-authentication
    // Generate cryptographically secure session ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    unsigned char random_bytes[32];
    for (int i = 0; i < 32; i++) {
        random_bytes[i] = static_cast<unsigned char>(dis(gen));
    }
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(random_bytes[i]);
    }
    
    std::string session_id = ss.str();
    std::cout << "Secure session established with ID: " << session_id << std::endl;
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 14: IP-based rate limiting for login attempts
void good_case_14() {
    std::map<std::string, std::pair<int, time_t>> ip_attempts;
    std::string client_ip = "192.168.1.100";
    
    // ok: cpp-improper-authentication
    // Check for rate limiting
    time_t current_time = time(NULL);
    auto it = ip_attempts.find(client_ip);
    
    if (it != ip_attempts.end()) {
        // Reset counter if it's been more than 15 minutes
        if (current_time - it->second.second > 900) {
            ip_attempts[client_ip] = {1, current_time};
        } else if (it->second.first >= 5) {
            std::cout << "Too many login attempts from IP " << client_ip << ". Try again later." << std::endl;
            return;
        } else {
            // Increment attempt counter
            ip_attempts[client_ip].first++;
        }
    } else {
        // First attempt from this IP
        ip_attempts[client_ip] = {1, current_time};
    }
    
    std::cout << "Processing login attempt " << ip_attempts[client_ip].first << " from IP " << client_ip << std::endl;
    // Continue with authentication...
}
// {/fact}
// {fact rule=hardcoded-credentials@v1.0 defects=0}

// Case 15: Secure API authentication with HMAC
void good_case_15() {
    // Request details
    std::string request_method = "POST";
    std::string request_path = "/api/data";
    std::string request_body = "{\"name\":\"John\",\"age\":30}";
    std::string timestamp = "1634567890";
    
    // Client credentials
    std::string api_key = "client_api_key";
    std::string api_secret = "client_secret_key";
    
    // ok: cpp-improper-authentication
    // Generate HMAC signature for request authentication
    std::string string_to_sign = request_method + "\n" + 
                                request_path + "\n" + 
                                timestamp + "\n" + 
                                request_body;
    
    // In a real implementation, this would use HMAC-SHA256
    std::string signature = hmac_sha256(string_to_sign, api_secret);
    
    // Verify the signature (server-side)
    std::string provided_signature = signature; // In real scenario, this would come from the request
    std::string provided_key = api_key; // In real scenario, this would come from the request
    
    // Lookup the secret for the provided key (simplified)
    std::string expected_secret = api_secret;
    
    // Recalculate signature and compare
    std::string recalculated_signature = hmac_sha256(string_to_sign, expected_secret);
    
    if (provided_signature == recalculated_signature) {
        std::cout << "API request authenticated successfully" << std::endl;
    } else {
        std::cout << "API authentication failed" << std::endl;
    }
}
// {/fact}

// Helper function for HMAC-SHA256 (simplified)
std::string hmac_sha256(const std::string& data, const std::string& key) {
    // In a real implementation, this would use OpenSSL's HMAC functions
    return sha256_hash(key + data); // This is NOT a proper HMAC implementation, just for example
}

int main() {
    // This function is just to make the file compile
    return 0;
}