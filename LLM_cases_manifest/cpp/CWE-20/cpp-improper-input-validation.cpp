#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <limits>
#include <map>
#include <curl/curl.h>
#include <sqlite3.h>

// Helper function for CURL response handling
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
    } catch(std::bad_alloc &e) {
        return 0;
    }
    return newLength;
}
// {fact rule=improper-input-validation@v1.0 defects=1}

// BAD CASES - Vulnerable code examples

void bad_case_1() {
    // Command injection vulnerability with user input
    std::string userInput;
    std::cout << "Enter filename to process: ";
    std::getline(std::cin, userInput);
    
    std::string command = "cat " + userInput;
    // ruleid: cpp-improper-input-validation
    system(command.c_str());  // Vulnerable: No validation of user input before using in system command
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_2() {
    // Path traversal vulnerability
    std::string filename;
    std::cout << "Enter file to open: ";
    std::getline(std::cin, filename);
    
    // ruleid: cpp-improper-input-validation
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string content;
        std::getline(file, content);
        std::cout << "File content: " << content << std::endl;
        file.close();
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_3() {
    // SQL injection vulnerability
    std::string username;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    
    sqlite3* db;
    sqlite3_open("users.db", &db);
    
    std::string query = "SELECT * FROM users WHERE username = '" + username + "'";
    // ruleid: cpp-improper-input-validation
    sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_4() {
    // Buffer overflow vulnerability
    char buffer[10];
    std::string userInput;
    std::cout << "Enter input: ";
    std::getline(std::cin, userInput);
    
    // ruleid: cpp-improper-input-validation
    strcpy(buffer, userInput.c_str());  // No length check before copying
    std::cout << "Buffer content: " << buffer << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_5() {
    // Integer overflow vulnerability
    std::string input;
    std::cout << "Enter a number: ";
    std::getline(std::cin, input);
    
    int value = std::stoi(input);
    // ruleid: cpp-improper-input-validation
    int result = value * 100;  // No validation to prevent integer overflow
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_6() {
    // HTTP request parameter used without validation
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse response for user ID
        size_t pos = response.find("user_id=");
        if(pos != std::string::npos) {
            std::string userId = response.substr(pos + 8);
            std::string command = "get_user_data.sh " + userId;
            // ruleid: cpp-improper-input-validation
            system(command.c_str());  // Using external data without validation
        }
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_7() {
    // Format string vulnerability
    std::string format;
    std::cout << "Enter format string: ";
    std::getline(std::cin, format);
    
    char buffer[100];
    // ruleid: cpp-improper-input-validation
    sprintf(buffer, format.c_str(), 42, "test");  // User controls format string
    std::cout << buffer << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_8() {
    // Array index vulnerability
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::string indexStr;
    std::cout << "Enter array index: ";
    std::getline(std::cin, indexStr);
    
    int index = std::stoi(indexStr);
    // ruleid: cpp-improper-input-validation
    std::cout << "Value at index: " << numbers[index] << std::endl;  // No bounds checking
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_9() {
    // XML injection
    std::string userComment;
    std::cout << "Enter your comment: ";
    std::getline(std::cin, userComment);
    
    std::string xmlData = "<comment><text>" + userComment + "</text></comment>";
    // ruleid: cpp-improper-input-validation
    std::ofstream xmlFile("comments.xml", std::ios::app);
    xmlFile << xmlData;
    xmlFile.close();
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_10() {
    // Regex DoS (ReDoS) vulnerability
    std::string userInput;
    std::cout << "Enter text to validate: ";
    std::getline(std::cin, userInput);
    
    // ruleid: cpp-improper-input-validation
    std::regex pattern("(a+)+b");  // Vulnerable regex with user input
    bool isValid = std::regex_match(userInput, pattern);
    
    std::cout << "Input is " << (isValid ? "valid" : "invalid") << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_11() {
    // File inclusion vulnerability
    std::string templateName;
    std::cout << "Enter template name: ";
    std::getline(std::cin, templateName);
    
    std::string templatePath = "templates/" + templateName;
    // ruleid: cpp-improper-input-validation
    std::ifstream templateFile(templatePath);
    if (templateFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(templateFile)),
                           std::istreambuf_iterator<char>());
        std::cout << "Template content: " << content << std::endl;
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_12() {
    // Unvalidated redirect
    std::string redirectUrl;
    std::cout << "Enter redirect URL: ";
    std::getline(std::cin, redirectUrl);
    
    // ruleid: cpp-improper-input-validation
    std::cout << "HTTP/1.1 302 Found\r\n";
    std::cout << "Location: " << redirectUrl << "\r\n\r\n";
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_13() {
    // Deserialization vulnerability
    std::string serializedData;
    std::cout << "Enter serialized data: ";
    std::getline(std::cin, serializedData);
    
    // ruleid: cpp-improper-input-validation
    std::istringstream stream(serializedData);
    int value;
    stream >> value;  // Deserializing without validation
    
    std::cout << "Deserialized value: " << value << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_14() {
    // Dynamic code evaluation
    std::string expression;
    std::cout << "Enter math expression: ";
    std::getline(std::cin, expression);
    
    // ruleid: cpp-improper-input-validation
    std::string command = "echo '" + expression + "' | bc";
    FILE* pipe = popen(command.c_str(), "r");
    
    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        std::cout << "Result: " << buffer;
    }
    pclose(pipe);
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=1}

void bad_case_15() {
    // LDAP injection
    std::string username;
    std::cout << "Enter username to search: ";
    std::getline(std::cin, username);
    
    // ruleid: cpp-improper-input-validation
    std::string ldapQuery = "(uid=" + username + ")";
    std::cout << "Executing LDAP query: " << ldapQuery << std::endl;
    
    // Simulated LDAP search
    system(("ldapsearch -x -b 'dc=example,dc=com' '" + ldapQuery + "'").c_str());
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

// GOOD CASES - Secure code examples

void good_case_1() {
    // Command injection prevention with input validation
    std::string userInput;
    std::cout << "Enter filename to process: ";
    std::getline(std::cin, userInput);
    
    // ok: cpp-improper-input-validation
    if (userInput.find_first_of(";&|`\\\"'$()<>") != std::string::npos) {
        std::cerr << "Invalid characters in input" << std::endl;
        return;
    }
    
    std::string command = "cat " + userInput;
    system(command.c_str());
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_2() {
    // Path traversal prevention
    std::string filename;
    std::cout << "Enter file to open: ";
    std::getline(std::cin, filename);
    
    // ok: cpp-improper-input-validation
    if (filename.find("..") != std::string::npos || filename.find('/') != std::string::npos) {
        std::cerr << "Invalid filename" << std::endl;
        return;
    }
    
    std::string safePath = "allowed_directory/" + filename;
    std::ifstream file(safePath);
    if (file.is_open()) {
        std::string content;
        std::getline(file, content);
        std::cout << "File content: " << content << std::endl;
        file.close();
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_3() {
    // SQL injection prevention with prepared statements
    std::string username;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // ok: cpp-improper-input-validation
    const char* query = "SELECT * FROM users WHERE username = ?";
    sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Process results
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_4() {
    // Buffer overflow prevention
    char buffer[10];
    std::string userInput;
    std::cout << "Enter input: ";
    std::getline(std::cin, userInput);
    
    // ok: cpp-improper-input-validation
    if (userInput.length() >= sizeof(buffer)) {
        std::cerr << "Input too long" << std::endl;
        return;
    }
    
    strcpy(buffer, userInput.c_str());
    std::cout << "Buffer content: " << buffer << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_5() {
    // Integer overflow prevention
    std::string input;
    std::cout << "Enter a number: ";
    std::getline(std::cin, input);
    
    try {
        int value = std::stoi(input);
        
        // ok: cpp-improper-input-validation
        if (value > 0 && value > INT_MAX / 100) {
            std::cerr << "Value would cause overflow" << std::endl;
            return;
        }
        
        int result = value * 100;
        std::cout << "Result: " << result << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Invalid input: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_6() {
    // HTTP request parameter validation
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse response for user ID
        size_t pos = response.find("user_id=");
        if(pos != std::string::npos) {
            std::string userId = response.substr(pos + 8);
            
            // ok: cpp-improper-input-validation
            // Validate that userId contains only digits
            if (userId.find_first_not_of("0123456789") != std::string::npos) {
                std::cerr << "Invalid user ID format" << std::endl;
                return;
            }
            
            std::string command = "get_user_data.sh " + userId;
            system(command.c_str());
        }
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_7() {
    // Format string vulnerability prevention
    std::string userMessage;
    std::cout << "Enter your message: ";
    std::getline(std::cin, userMessage);
    
    char buffer[100];
    // ok: cpp-improper-input-validation
    // Use a fixed format string, not user input
    sprintf(buffer, "User message: %s", userMessage.c_str());
    std::cout << buffer << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_8() {
    // Array index bounds checking
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::string indexStr;
    std::cout << "Enter array index: ";
    std::getline(std::cin, indexStr);
    
    try {
        int index = std::stoi(indexStr);
        
        // ok: cpp-improper-input-validation
        if (index < 0 || index >= numbers.size()) {
            std::cerr << "Index out of bounds" << std::endl;
            return;
        }
        
        std::cout << "Value at index: " << numbers[index] << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Invalid input: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_9() {
    // XML injection prevention
    std::string userComment;
    std::cout << "Enter your comment: ";
    std::getline(std::cin, userComment);
    
    // ok: cpp-improper-input-validation
    // Escape XML special characters
    std::string escapedComment = userComment;
    size_t pos = 0;
    while ((pos = escapedComment.find('<', pos)) != std::string::npos) {
        escapedComment.replace(pos, 1, "&lt;");
        pos += 4;
    }
    pos = 0;
    while ((pos = escapedComment.find('>', pos)) != std::string::npos) {
        escapedComment.replace(pos, 1, "&gt;");
        pos += 4;
    }
    
    std::string xmlData = "<comment><text>" + escapedComment + "</text></comment>";
    std::ofstream xmlFile("comments.xml", std::ios::app);
    xmlFile << xmlData;
    xmlFile.close();
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_10() {
    // Safe regex usage with input validation
    std::string userInput;
    std::cout << "Enter text to validate: ";
    std::getline(std::cin, userInput);
    
    // ok: cpp-improper-input-validation
    // Limit input length to prevent ReDoS
    if (userInput.length() > 100) {
        std::cerr << "Input too long" << std::endl;
        return;
    }
    
    // Use a safer regex pattern
    std::regex pattern("^[a-z]+$");
    bool isValid = std::regex_match(userInput, pattern);
    
    std::cout << "Input is " << (isValid ? "valid" : "invalid") << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_11() {
    // Safe file inclusion with whitelist
    std::string templateName;
    std::cout << "Enter template name: ";
    std::getline(std::cin, templateName);
    
    // ok: cpp-improper-input-validation
    // Whitelist of allowed templates
    std::map<std::string, std::string> allowedTemplates = {
        {"welcome", "templates/welcome.html"},
        {"error", "templates/error.html"},
        {"login", "templates/login.html"}
    };
    
    auto it = allowedTemplates.find(templateName);
    if (it == allowedTemplates.end()) {
        std::cerr << "Template not found" << std::endl;
        return;
    }
    
    std::ifstream templateFile(it->second);
    if (templateFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(templateFile)),
                           std::istreambuf_iterator<char>());
        std::cout << "Template content: " << content << std::endl;
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_12() {
    // Validated redirect with whitelist
    std::string redirectId;
    std::cout << "Enter redirect ID: ";
    std::getline(std::cin, redirectId);
    
    // ok: cpp-improper-input-validation
    // Map of allowed redirect destinations
    std::map<std::string, std::string> allowedRedirects = {
        {"home", "https://example.com/home"},
        {"profile", "https://example.com/profile"},
        {"settings", "https://example.com/settings"}
    };
    
    auto it = allowedRedirects.find(redirectId);
    if (it == allowedRedirects.end()) {
        std::cerr << "Invalid redirect destination" << std::endl;
        return;
    }
    
    std::cout << "HTTP/1.1 302 Found\r\n";
    std::cout << "Location: " << it->second << "\r\n\r\n";
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_13() {
    // Safe deserialization with validation
    std::string serializedData;
    std::cout << "Enter serialized data: ";
    std::getline(std::cin, serializedData);
    
    // ok: cpp-improper-input-validation
    // Validate that input contains only digits
    if (serializedData.find_first_not_of("0123456789") != std::string::npos) {
        std::cerr << "Invalid serialized data format" << std::endl;
        return;
    }
    
    std::istringstream stream(serializedData);
    int value;
    stream >> value;
    
    std::cout << "Deserialized value: " << value << std::endl;
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_14() {
    // Safe alternative to dynamic code evaluation
    std::string expression;
    std::cout << "Enter math operation (+, -, *, /): ";
    std::string operation;
    std::getline(std::cin, operation);
    
    std::cout << "Enter first number: ";
    std::string num1Str;
    std::getline(std::cin, num1Str);
    
    std::cout << "Enter second number: ";
    std::string num2Str;
    std::getline(std::cin, num2Str);
    
    try {
        double num1 = std::stod(num1Str);
        double num2 = std::stod(num2Str);
        double result = 0;
        
        // ok: cpp-improper-input-validation
        // Validate operation and perform calculation directly
        if (operation == "+") {
            result = num1 + num2;
        } else if (operation == "-") {
            result = num1 - num2;
        } else if (operation == "*") {
            result = num1 * num2;
        } else if (operation == "/") {
            if (num2 == 0) {
                std::cerr << "Division by zero" << std::endl;
                return;
            }
            result = num1 / num2;
        } else {
            std::cerr << "Invalid operation" << std::endl;
            return;
        }
        
        std::cout << "Result: " << result << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Invalid input: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=improper-input-validation@v1.0 defects=0}

void good_case_15() {
    // LDAP injection prevention
    std::string username;
    std::cout << "Enter username to search: ";
    std::getline(std::cin, username);
    
    // ok: cpp-improper-input-validation
    // Escape LDAP special characters
    std::string escapedUsername = username;
    std::vector<char> specialChars = {'\\', '*', '(', ')', '\0'};
    
    for (char c : specialChars) {
        size_t pos = 0;
        std::string replacement = "\\" + std::string(1, c);
        while ((pos = escapedUsername.find(c, pos)) != std::string::npos) {
            escapedUsername.replace(pos, 1, replacement);
            pos += replacement.length();
        }
    }
    
    std::string ldapQuery = "(uid=" + escapedUsername + ")";
    std::cout << "Executing LDAP query: " << ldapQuery << std::endl;
    
    // Simulated LDAP search
    system(("ldapsearch -x -b 'dc=example,dc=com' '" + ldapQuery + "'").c_str());
}
// {/fact}

int main() {
    // Function calls can be added here for testing
    return 0;
}