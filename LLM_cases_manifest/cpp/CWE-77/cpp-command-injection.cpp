#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <sstream>
#include <regex>
#include <map>
#include <unistd.h>
#include <curl/curl.h>
#include <boost/algorithm/string.hpp>
#include <boost/process.hpp>

// Helper function to simulate HTTP request data retrieval
std::map<std::string, std::string> getHttpRequestData() {
    std::map<std::string, std::string> data;
    data["username"] = "john";
    data["filename"] = "report.txt";
    data["command"] = "ls -la";
    data["path"] = "/home/user/documents";
    data["ip"] = "192.168.1.1";
    data["query"] = "SELECT * FROM users";
    data["param"] = "value; rm -rf /";
    data["host"] = "example.com";
    data["port"] = "8080";
    data["args"] = "-l -a";
    data["script"] = "backup.sh";
    data["option"] = "--verbose";
    data["input"] = "hello; cat /etc/passwd";
    data["filter"] = "*.txt";
    data["directory"] = "/var/www";
    return data;
}

// Helper function to sanitize command input
std::string sanitizeCommand(const std::string& input) {
    std::string sanitized = input;
    // Remove shell metacharacters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), 
                                 [](char c) { 
                                     return c == '&' || c == '|' || c == ';' || 
                                            c == '`' || c == '$' || c == '(' || 
                                            c == ')' || c == '<' || c == '>' || 
                                            c == '\'' || c == '\"' || c == '\\'; 
                                 }), 
                  sanitized.end());
    return sanitized;
}

// Helper function to validate if input contains only allowed characters
bool isValidInput(const std::string& input, const std::string& allowedChars) {
    for (char c : input) {
        if (allowedChars.find(c) == std::string::npos) {
            return false;
        }
    }
    return true;
}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    auto request = getHttpRequestData();
    std::string userInput = request["command"];
    
    std::string cmd = "ls " + userInput;
    // ruleid: cpp-command-injection
    system(cmd.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_2() {
    auto request = getHttpRequestData();
    std::string filename = request["filename"];
    
    std::string cmd = "cat " + filename;
    // ruleid: cpp-command-injection
    std::system(cmd.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_3() {
    auto request = getHttpRequestData();
    std::string userDir = request["directory"];
    
    // ruleid: cpp-command-injection
    FILE* pipe = popen(("find " + userDir + " -name '*.log'").c_str(), "r");
    if (pipe) {
        char buffer[128];
        while (!feof(pipe)) {
            if (fgets(buffer, 128, pipe) != NULL)
                std::cout << buffer;
        }
        pclose(pipe);
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_4() {
    auto request = getHttpRequestData();
    std::string host = request["host"];
    
    std::string pingCmd = "ping -c 4 " + host;
    // ruleid: cpp-command-injection
    FILE* output = popen(pingCmd.c_str(), "r");
    pclose(output);
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_5() {
    auto request = getHttpRequestData();
    std::string script = request["script"];
    std::string args = request["args"];
    
    // ruleid: cpp-command-injection
    int result = std::system(("bash " + script + " " + args).c_str());
    std::cout << "Script execution result: " << result << std::endl;
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_6() {
    auto request = getHttpRequestData();
    std::string userInput = request["input"];
    
    std::string command = "echo " + userInput + " > output.txt";
    // ruleid: cpp-command-injection
    system(command.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_7() {
    auto request = getHttpRequestData();
    std::string filter = request["filter"];
    
    std::stringstream ss;
    ss << "grep -r " << filter << " /var/log/";
    // ruleid: cpp-command-injection
    FILE* pipe = popen(ss.str().c_str(), "r");
    pclose(pipe);
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_8() {
    auto request = getHttpRequestData();
    std::string path = request["path"];
    
    // Attempt to validate but still vulnerable
    if (path.find("/") != std::string::npos) {
        std::string cmd = "rm -rf " + path;
        // ruleid: cpp-command-injection
        system(cmd.c_str());
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_9() {
    auto request = getHttpRequestData();
    std::string ip = request["ip"];
    
    // Incomplete validation
    if (ip.length() < 20) {
        std::string cmd = "nslookup " + ip;
        // ruleid: cpp-command-injection
        std::system(cmd.c_str());
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_10() {
    auto request = getHttpRequestData();
    std::string option = request["option"];
    std::string filename = request["filename"];
    
    // ruleid: cpp-command-injection
    FILE* output = popen(("tar " + option + " " + filename).c_str(), "r");
    pclose(output);
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_11() {
    auto request = getHttpRequestData();
    std::string userInput = request["command"];
    
    // Ineffective escaping
    boost::replace_all(userInput, "\"", "\\\"");
    std::string cmd = "sh -c \"" + userInput + "\"";
    // ruleid: cpp-command-injection
    system(cmd.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_12() {
    auto request = getHttpRequestData();
    std::string username = request["username"];
    
    // ruleid: cpp-command-injection
    int result = std::system(("id " + username).c_str());
    if (result == 0) {
        std::cout << "User exists" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_13() {
    auto request = getHttpRequestData();
    std::string param = request["param"];
    
    // Trying to be safe by using execl, but still vulnerable
    std::string fullCommand = "/bin/sh -c 'ls " + param + "'";
    // ruleid: cpp-command-injection
    system(fullCommand.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_14() {
    auto request = getHttpRequestData();
    std::string port = request["port"];
    
    // ruleid: cpp-command-injection
    FILE* pipe = popen(("netstat -an | grep " + port).c_str(), "r");
    char buffer[128];
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            std::cout << buffer;
    }
    pclose(pipe);
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}

void bad_case_15() {
    auto request = getHttpRequestData();
    std::string directory = request["directory"];
    std::string filename = request["filename"];
    
    // ruleid: cpp-command-injection
    system(("cd " + directory + " && touch " + filename).c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

// True Negative Examples (Secure Code)

void good_case_1() {
    auto request = getHttpRequestData();
    std::string userInput = request["command"];
    
    // ok: cpp-command-injection
    std::string sanitized = sanitizeCommand(userInput);
    std::string cmd = "ls " + sanitized;
    system(cmd.c_str());
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_2() {
    auto request = getHttpRequestData();
    std::string filename = request["filename"];
    
    // ok: cpp-command-injection
    if (isValidInput(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")) {
        std::string cmd = "cat " + filename;
        std::system(cmd.c_str());
    } else {
        std::cerr << "Invalid filename" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_3() {
    auto request = getHttpRequestData();
    std::string userDir = request["directory"];
    
    // ok: cpp-command-injection
    std::regex dirPattern("^[a-zA-Z0-9_/.-]+$");
    if (std::regex_match(userDir, dirPattern)) {
        FILE* pipe = popen(("find " + userDir + " -name '*.log'").c_str(), "r");
        if (pipe) {
            char buffer[128];
            while (!feof(pipe)) {
                if (fgets(buffer, 128, pipe) != NULL)
                    std::cout << buffer;
            }
            pclose(pipe);
        }
    } else {
        std::cerr << "Invalid directory path" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_4() {
    auto request = getHttpRequestData();
    std::string host = request["host"];
    
    // ok: cpp-command-injection
    std::regex ipPattern("^[a-zA-Z0-9.-]+$");
    if (std::regex_match(host, ipPattern)) {
        std::string pingCmd = "ping -c 4 " + host;
        FILE* output = popen(pingCmd.c_str(), "r");
        pclose(output);
    } else {
        std::cerr << "Invalid hostname" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_5() {
    auto request = getHttpRequestData();
    std::string script = request["script"];
    std::string args = request["args"];
    
    // ok: cpp-command-injection
    // Using boost::process for safer command execution
    namespace bp = boost::process;
    bp::ipstream pipe_stream;
    bp::child c(bp::search_path("bash"), script, args, bp::std_out > pipe_stream);
    
    std::string line;
    while (pipe_stream && std::getline(pipe_stream, line)) {
        std::cout << line << std::endl;
    }
    c.wait();
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_6() {
    auto request = getHttpRequestData();
    std::string userInput = request["input"];
    
    // ok: cpp-command-injection
    // Using C++ file operations instead of system commands
    std::ofstream outfile("output.txt");
    if (outfile.is_open()) {
        outfile << userInput;
        outfile.close();
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_7() {
    auto request = getHttpRequestData();
    std::string filter = request["filter"];
    
    // ok: cpp-command-injection
    // Using a whitelist of allowed characters
    std::string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-*? ";
    bool valid = true;
    for (char c : filter) {
        if (allowedChars.find(c) == std::string::npos) {
            valid = false;
            break;
        }
    }
    
    if (valid) {
        std::stringstream ss;
        ss << "grep -r " << filter << " /var/log/";
        FILE* pipe = popen(ss.str().c_str(), "r");
        pclose(pipe);
    } else {
        std::cerr << "Invalid filter pattern" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_8() {
    auto request = getHttpRequestData();
    std::string path = request["path"];
    
    // ok: cpp-command-injection
    // Using C++ filesystem operations instead of system commands
    std::regex pathPattern("^[a-zA-Z0-9_/.-]+$");
    if (std::regex_match(path, pathPattern)) {
        // Use C++ filesystem operations (C++17)
        // std::filesystem::remove_all(path);
        // For pre-C++17, use boost::filesystem or other safe alternatives
        
        // If system must be used, validate input thoroughly
        std::string cmd = "rm -rf " + path;
        system(cmd.c_str());
    } else {
        std::cerr << "Invalid path" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_9() {
    auto request = getHttpRequestData();
    std::string ip = request["ip"];
    
    // ok: cpp-command-injection
    // Proper IP address validation
    std::regex ipPattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    if (std::regex_match(ip, ipPattern)) {
        // Additional validation for each octet
        bool valid = true;
        std::vector<std::string> octets;
        boost::split(octets, ip, boost::is_any_of("."));
        
        for (const auto& octet : octets) {
            int value = std::stoi(octet);
            if (value < 0 || value > 255) {
                valid = false;
                break;
            }
        }
        
        if (valid) {
            std::string cmd = "nslookup " + ip;
            std::system(cmd.c_str());
        } else {
            std::cerr << "Invalid IP address" << std::endl;
        }
    } else {
        std::cerr << "Invalid IP format" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_10() {
    auto request = getHttpRequestData();
    std::string option = request["option"];
    std::string filename = request["filename"];
    
    // ok: cpp-command-injection
    // Whitelist of allowed options
    std::vector<std::string> allowedOptions = {"-c", "-x", "-t", "--create", "--extract", "--list"};
    bool validOption = false;
    
    for (const auto& allowed : allowedOptions) {
        if (option == allowed) {
            validOption = true;
            break;
        }
    }
    
    if (validOption && isValidInput(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")) {
        FILE* output = popen(("tar " + option + " " + filename).c_str(), "r");
        pclose(output);
    } else {
        std::cerr << "Invalid option or filename" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_11() {
    auto request = getHttpRequestData();
    std::string userInput = request["command"];
    
    // ok: cpp-command-injection
    // Using a predefined set of commands
    std::map<std::string, std::string> allowedCommands = {
        {"list_files", "ls -l"},
        {"disk_space", "df -h"},
        {"memory_usage", "free -m"}
    };
    
    if (allowedCommands.find(userInput) != allowedCommands.end()) {
        system(allowedCommands[userInput].c_str());
    } else {
        std::cerr << "Command not allowed" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_12() {
    auto request = getHttpRequestData();
    std::string username = request["username"];
    
    // ok: cpp-command-injection
    // Using proper validation for username
    std::regex usernamePattern("^[a-zA-Z0-9_-]{1,32}$");
    if (std::regex_match(username, usernamePattern)) {
        int result = std::system(("id " + username).c_str());
        if (result == 0) {
            std::cout << "User exists" << std::endl;
        }
    } else {
        std::cerr << "Invalid username format" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_13() {
    auto request = getHttpRequestData();
    std::string param = request["param"];
    
    // ok: cpp-command-injection
    // Using execve with arguments as array elements instead of shell
    std::vector<std::string> args = {"ls", sanitizeCommand(param)};
    
    // In a real implementation, you would use execve like this:
    // char* argv[] = {"/bin/ls", sanitized.c_str(), NULL};
    // execve("/bin/ls", argv, NULL);
    
    // For this example, we'll use boost::process which is safer
    namespace bp = boost::process;
    bp::ipstream pipe_stream;
    bp::child c(bp::search_path("ls"), args[1], bp::std_out > pipe_stream);
    
    std::string line;
    while (pipe_stream && std::getline(pipe_stream, line)) {
        std::cout << line << std::endl;
    }
    c.wait();
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_14() {
    auto request = getHttpRequestData();
    std::string port = request["port"];
    
    // ok: cpp-command-injection
    // Validate port is numeric and in valid range
    std::regex portPattern("^\\d{1,5}$");
    if (std::regex_match(port, portPattern)) {
        int portNum = std::stoi(port);
        if (portNum > 0 && portNum <= 65535) {
            FILE* pipe = popen(("netstat -an | grep " + port).c_str(), "r");
            char buffer[128];
            while (!feof(pipe)) {
                if (fgets(buffer, 128, pipe) != NULL)
                    std::cout << buffer;
            }
            pclose(pipe);
        } else {
            std::cerr << "Port number out of range" << std::endl;
        }
    } else {
        std::cerr << "Invalid port format" << std::endl;
    }
}
// {/fact}
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}

void good_case_15() {
    auto request = getHttpRequestData();
    std::string directory = request["directory"];
    std::string filename = request["filename"];
    
    // ok: cpp-command-injection
    // Using C++ file operations instead of system commands
    std::regex dirPattern("^[a-zA-Z0-9_/.-]+$");
    std::regex filePattern("^[a-zA-Z0-9_.-]+$");
    
    if (std::regex_match(directory, dirPattern) && std::regex_match(filename, filePattern)) {
        // In a real implementation, you would use C++ filesystem operations:
        // std::filesystem::path dir(directory);
        // std::filesystem::path file = dir / filename;
        // std::ofstream(file.string());
        
        // For this example, we'll use system but with properly validated input
        system(("cd " + directory + " && touch " + filename).c_str());
    } else {
        std::cerr << "Invalid directory or filename" << std::endl;
    }
}
// {/fact}

int main() {
    // Example usage
    bad_case_1();
    good_case_1();
    return 0;
}