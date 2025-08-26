#include <iostream>
#include <string>
#include <cstdlib>
#include <vector>
#include <sstream>
#include <regex>
#include <cstring>
#include <unistd.h>
#include <curl/curl.h>
#include <boost/algorithm/string.hpp>
#include <boost/process.hpp>

// Helper function to simulate HTTP request data retrieval
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string getHttpParameter(const std::string& paramName) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    
    // Simulate parsing the parameter from the response
    // In a real application, you would parse the actual HTTP response
    if (paramName == "command") {
        return "echo hello";
    } else if (paramName == "filename") {
        return "user_data.txt";
    } else if (paramName == "username") {
        return "admin; rm -rf /";
    } else if (paramName == "id") {
        return "1234; cat /etc/passwd";
    } else {
        return "default_value";
    }
}
// {fact rule=os-command-injection@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    std::string userCommand = getHttpParameter("command");
    
    // ruleid: cpp-os-command-injection
    system(userCommand.c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_2() {
    std::string filename = getHttpParameter("filename");
    std::string command = "cat " + filename;
    
    // ruleid: cpp-os-command-injection
    system(command.c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_3() {
    std::string username = getHttpParameter("username");
    std::string command = "grep " + username + " /etc/passwd";
    
    // ruleid: cpp-os-command-injection
    std::system(command.c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_4() {
    std::string id = getHttpParameter("id");
    
    // ruleid: cpp-os-command-injection
    FILE* pipe = popen(("find /var/log -name '*" + id + "*'").c_str(), "r");
    if (pipe) {
        pclose(pipe);
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_5() {
    std::string userInput = getHttpParameter("command");
    std::string cmd = "/bin/bash -c '" + userInput + "'";
    
    // ruleid: cpp-os-command-injection
    execl("/bin/sh", "sh", "-c", cmd.c_str(), NULL);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_6() {
    std::string param = getHttpParameter("param");
    std::stringstream ss;
    ss << "ls -la " << param;
    
    // ruleid: cpp-os-command-injection
    int result = system(ss.str().c_str());
    std::cout << "Command executed with result: " << result << std::endl;
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_7() {
    std::vector<std::string> args;
    args.push_back("ping");
    args.push_back(getHttpParameter("host"));
    
    std::string command;
    for (const auto& arg : args) {
        command += arg + " ";
    }
    
    // ruleid: cpp-os-command-injection
    system(command.c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_8() {
    std::string input = getHttpParameter("input");
    // Simple transformation doesn't make it safe
    std::transform(input.begin(), input.end(), input.begin(), ::tolower);
    
    // ruleid: cpp-os-command-injection
    FILE* pipe = popen(("echo " + input).c_str(), "r");
    if (pipe) {
        pclose(pipe);
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_9() {
    namespace bp = boost::process;
    std::string userInput = getHttpParameter("command");
    
    // ruleid: cpp-os-command-injection
    bp::system(userInput);
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_10() {
    std::string scriptName = getHttpParameter("script");
    std::string args = getHttpParameter("args");
    
    // ruleid: cpp-os-command-injection
    system(("python " + scriptName + " " + args).c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_11() {
    char* args[4];
    args[0] = strdup("sh");
    args[1] = strdup("-c");
    args[2] = strdup(getHttpParameter("command").c_str());
    args[3] = nullptr;
    
    // ruleid: cpp-os-command-injection
    execvp(args[0], args);
    
    // Free memory (though this won't be reached if execvp succeeds)
    for (int i = 0; i < 3; i++) {
        free(args[i]);
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_12() {
    std::string filename = getHttpParameter("filename");
    // Attempt to filter but still vulnerable
    boost::replace_all(filename, " ", "_");
    
    // ruleid: cpp-os-command-injection
    system(("rm " + filename).c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_13() {
    std::string userId = getHttpParameter("id");
    std::string command;
    
    if (userId.length() > 0) {
        command = "id " + userId;
    } else {
        command = "id";
    }
    
    // ruleid: cpp-os-command-injection
    system(command.c_str());
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_14() {
    std::string path = getHttpParameter("path");
    std::ostringstream command;
    command << "find " << path << " -type f -name \"*.log\"";
    
    // ruleid: cpp-os-command-injection
    FILE* pipe = popen(command.str().c_str(), "r");
    if (pipe) {
        pclose(pipe);
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

void bad_case_15() {
    namespace bp = boost::process;
    std::string cmd = getHttpParameter("cmd");
    std::string arg = getHttpParameter("arg");
    
    // ruleid: cpp-os-command-injection
    bp::child c(cmd + " " + arg);
    c.wait();
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    std::string userCommand = getHttpParameter("command");
    
    // Validate against a whitelist of allowed commands
    std::vector<std::string> allowedCommands = {"ls", "echo", "pwd"};
    bool isAllowed = false;
    
    for (const auto& cmd : allowedCommands) {
        if (userCommand == cmd) {
            isAllowed = true;
            break;
        }
    }
    
    if (isAllowed) {
        // ok: cpp-os-command-injection
        system(userCommand.c_str());
    } else {
        std::cout << "Command not allowed" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_2() {
    std::string filename = getHttpParameter("filename");
    
    // Validate filename using regex to ensure it only contains alphanumeric characters
    std::regex pattern("^[a-zA-Z0-9_]+\\.txt$");
    
    if (std::regex_match(filename, pattern)) {
        std::string command = "cat ";
        // ok: cpp-os-command-injection
        system((command + filename).c_str());
    } else {
        std::cout << "Invalid filename" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_3() {
    // Use a safer alternative to system() with explicit arguments
    namespace bp = boost::process;
    std::string username = getHttpParameter("username");
    
    // Validate username contains only alphanumeric characters
    std::regex pattern("^[a-zA-Z0-9_]+$");
    
    if (std::regex_match(username, pattern)) {
        // ok: cpp-os-command-injection
        bp::child c("grep", username, "/etc/passwd");
        c.wait();
    } else {
        std::cout << "Invalid username format" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_4() {
    std::string id = getHttpParameter("id");
    
    // Validate id is numeric only
    std::regex pattern("^[0-9]+$");
    
    if (std::regex_match(id, pattern)) {
        // ok: cpp-os-command-injection
        FILE* pipe = popen(("find /var/log -name '*" + id + "*'").c_str(), "r");
        if (pipe) {
            pclose(pipe);
        }
    } else {
        std::cout << "Invalid ID format" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_5() {
    // Use a safer API that doesn't involve shell interpretation
    namespace bp = boost::process;
    
    std::vector<std::string> args;
    args.push_back("echo");
    args.push_back("hello");
    
    // ok: cpp-os-command-injection
    bp::child c(bp::exe("echo"), bp::args=args);
    c.wait();
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_6() {
    // Instead of executing a command, use C++ file operations
    std::string filename = getHttpParameter("filename");
    
    // Validate filename
    std::regex pattern("^[a-zA-Z0-9_]+\\.txt$");
    
    if (std::regex_match(filename, pattern)) {
        // ok: cpp-os-command-injection
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string line;
            while (getline(file, line)) {
                std::cout << line << std::endl;
            }
            file.close();
        }
    } else {
        std::cout << "Invalid filename" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_7() {
    std::string host = getHttpParameter("host");
    
    // Validate IP address format
    std::regex pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    
    if (std::regex_match(host, pattern)) {
        // Further validate each octet
        bool valid = true;
        std::vector<std::string> octets;
        boost::split(octets, host, boost::is_any_of("."));
        
        for (const auto& octet : octets) {
            int value = std::stoi(octet);
            if (value < 0 || value > 255) {
                valid = false;
                break;
            }
        }
        
        if (valid) {
            // ok: cpp-os-command-injection
            std::string command = "ping -c 4 " + host;
            system(command.c_str());
        }
    } else {
        std::cout << "Invalid IP address format" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_8() {
    // Use a dedicated API instead of command execution
    std::string path = getHttpParameter("path");
    
    // Validate path
    std::regex pattern("^[a-zA-Z0-9_/]+$");
    
    if (std::regex_match(path, pattern)) {
        // ok: cpp-os-command-injection
        // Using C++ filesystem operations instead of system commands
        std::cout << "Would list files in: " << path << std::endl;
        // In C++17 you would use std::filesystem here
    } else {
        std::cout << "Invalid path format" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_9() {
    // Use hardcoded commands instead of user input
    std::string option = getHttpParameter("option");
    
    if (option == "list_users") {
        // ok: cpp-os-command-injection
        system("cat /etc/passwd");
    } else if (option == "disk_space") {
        // ok: cpp-os-command-injection
        system("df -h");
    } else {
        std::cout << "Unknown option" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_10() {
    // Use command arguments array instead of string concatenation
    std::string filename = getHttpParameter("filename");
    
    // Validate filename
    std::regex pattern("^[a-zA-Z0-9_]+\\.txt$");
    
    if (std::regex_match(filename, pattern)) {
        char* args[3];
        args[0] = strdup("cat");
        args[1] = strdup(filename.c_str());
        args[2] = nullptr;
        
        // ok: cpp-os-command-injection
        pid_t pid = fork();
        if (pid == 0) {
            execvp(args[0], args);
            exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        
        free(args[0]);
        free(args[1]);
    } else {
        std::cout << "Invalid filename" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_11() {
    namespace bp = boost::process;
    std::string scriptName = getHttpParameter("script");
    
    // Validate script name
    std::regex pattern("^[a-zA-Z0-9_]+\\.py$");
    
    if (std::regex_match(scriptName, pattern)) {
        // ok: cpp-os-command-injection
        bp::child c(bp::exe("python"), bp::args={scriptName});
        c.wait();
    } else {
        std::cout << "Invalid script name" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_12() {
    // Use a mapping of allowed commands
    std::string cmdKey = getHttpParameter("cmd");
    
    std::map<std::string, std::string> allowedCommands = {
        {"list", "ls -la"},
        {"disk", "df -h"},
        {"memory", "free -m"}
    };
    
    auto it = allowedCommands.find(cmdKey);
    if (it != allowedCommands.end()) {
        // ok: cpp-os-command-injection
        system(it->second.c_str());
    } else {
        std::cout << "Command not allowed" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_13() {
    std::string userId = getHttpParameter("id");
    
    // Validate userId is numeric
    std::regex pattern("^[0-9]+$");
    
    if (std::regex_match(userId, pattern)) {
        // ok: cpp-os-command-injection
        system(("id " + userId).c_str());
    } else {
        std::cout << "Invalid user ID format" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_14() {
    // Use a safer API with explicit arguments
    namespace bp = boost::process;
    std::string searchTerm = getHttpParameter("search");
    
    // Sanitize search term
    std::regex pattern("^[a-zA-Z0-9_]+$");
    
    if (std::regex_match(searchTerm, pattern)) {
        // ok: cpp-os-command-injection
        bp::child c(bp::exe("find"), bp::args={"/var/log", "-name", "*" + searchTerm + "*"});
        c.wait();
    } else {
        std::cout << "Invalid search term" << std::endl;
    }
}
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

void good_case_15() {
    // Use an enum to limit possible commands
    enum class Command { LIST, DISK, MEMORY, UNKNOWN };
    
    std::string cmdStr = getHttpParameter("cmd");
    Command cmd = Command::UNKNOWN;
    
    if (cmdStr == "list") cmd = Command::LIST;
    else if (cmdStr == "disk") cmd = Command::DISK;
    else if (cmdStr == "memory") cmd = Command::MEMORY;
    
    switch (cmd) {
        case Command::LIST:
            // ok: cpp-os-command-injection
            system("ls -la");
            break;
        case Command::DISK:
            // ok: cpp-os-command-injection
            system("df -h");
            break;
        case Command::MEMORY:
            // ok: cpp-os-command-injection
            system("free -m");
            break;
        default:
            std::cout << "Unknown command" << std::endl;
            break;
    }
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "Command Injection Test Cases" << std::endl;
    return 0;
}