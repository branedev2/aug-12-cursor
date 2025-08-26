#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <filesystem>
#include <curl/curl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

// Helper function for curl requests
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}
// {fact rule=path-traversal@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable code examples)

// Example 1: Basic path traversal with direct file access
void bad_case_1() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile?filename=user_input.txt");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        std::ifstream file;
        // ruleid: cpp-path-traversal
        file.open(filename);
        
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>()));
            std::cout << "File content: " << content << std::endl;
            file.close();
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 2: Path traversal with file write operation
void bad_case_2() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getpath?dir=uploads");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string directory = readBuffer;
        std::string filepath = directory + "/output.txt";
        std::ofstream outfile;
        // ruleid: cpp-path-traversal
        outfile.open(filepath);
        
        if (outfile.is_open()) {
            outfile << "Some data to write" << std::endl;
            outfile.close();
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 3: Path traversal with C-style file operations
void bad_case_3() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilename");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        FILE* file;
        // ruleid: cpp-path-traversal
        file = fopen(filename.c_str(), "r");
        
        if (file != NULL) {
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), file)) {
                printf("%s", buffer);
            }
            fclose(file);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 4: Path traversal with directory operations
void bad_case_4() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdir");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string dirPath = readBuffer;
        DIR* dir;
        // ruleid: cpp-path-traversal
        dir = opendir(dirPath.c_str());
        
        if (dir != NULL) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                std::cout << entry->d_name << std::endl;
            }
            closedir(dir);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 5: Path traversal with file system operations
void bad_case_5() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getpath?file=config.ini");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filePath = readBuffer;
        // ruleid: cpp-path-traversal
        int fd = open(filePath.c_str(), O_RDONLY);
        
        if (fd != -1) {
            char buffer[1024];
            ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::cout << "File content: " << buffer << std::endl;
            }
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 6: Path traversal with std::filesystem
void bad_case_6() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filePath = readBuffer;
        // ruleid: cpp-path-traversal
        if (std::filesystem::exists(filePath)) {
            std::ifstream file(filePath);
            std::string content((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>()));
            std::cout << "File content: " << content << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 7: Path traversal with string concatenation
void bad_case_7() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilename");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        std::string basePath = "/var/data/";
        std::string fullPath = basePath + filename;
        
        // ruleid: cpp-path-traversal
        std::ifstream file(fullPath);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>()));
            std::cout << "File content: " << content << std::endl;
            file.close();
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 8: Path traversal with minimal processing
void bad_case_8() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        // Remove whitespace
        filename.erase(0, filename.find_first_not_of(" \n\r\t"));
        filename.erase(filename.find_last_not_of(" \n\r\t") + 1);
        
        // ruleid: cpp-path-traversal
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>()));
            std::cout << "File content: " << content << std::endl;
            file.close();
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 9: Path traversal with file deletion
void bad_case_9() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfiledelete");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        // ruleid: cpp-path-traversal
        if (std::remove(filename.c_str()) == 0) {
            std::cout << "File deleted successfully" << std::endl;
        } else {
            std::cout << "Error deleting file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 10: Path traversal with file renaming
void bad_case_10() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getsource");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdest");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string oldName = readBuffer;
        std::string newName = readBuffer2;
        
        // ruleid: cpp-path-traversal
        if (std::rename(oldName.c_str(), newName.c_str()) == 0) {
            std::cout << "File renamed successfully" << std::endl;
        } else {
            std::cout << "Error renaming file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 11: Path traversal with file stat
void bad_case_11() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilepath");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        struct stat fileInfo;
        
        // ruleid: cpp-path-traversal
        if (stat(filename.c_str(), &fileInfo) == 0) {
            std::cout << "File size: " << fileInfo.st_size << " bytes" << std::endl;
        } else {
            std::cout << "Error getting file info" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 12: Path traversal with file access check
void bad_case_12() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/checkfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // ruleid: cpp-path-traversal
        if (access(filename.c_str(), F_OK) != -1) {
            std::cout << "File exists" << std::endl;
        } else {
            std::cout << "File does not exist" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 13: Path traversal with file copy
void bad_case_13() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getsource");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdest");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string source = readBuffer;
        std::string destination = readBuffer2;
        
        // ruleid: cpp-path-traversal
        std::ifstream src(source, std::ios::binary);
        std::ofstream dst(destination, std::ios::binary);
        
        if (src && dst) {
            dst << src.rdbuf();
            std::cout << "File copied successfully" << std::endl;
        } else {
            std::cout << "Error copying file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 14: Path traversal with chmod
void bad_case_14() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilepath");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // ruleid: cpp-path-traversal
        if (chmod(filename.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0) {
            std::cout << "File permissions changed successfully" << std::endl;
        } else {
            std::cout << "Error changing file permissions" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=1}

// Example 15: Path traversal with symlink
void bad_case_15() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/gettarget");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getlinkname");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string target = readBuffer;
        std::string linkname = readBuffer2;
        
        // ruleid: cpp-path-traversal
        if (symlink(target.c_str(), linkname.c_str()) == 0) {
            std::cout << "Symbolic link created successfully" << std::endl;
        } else {
            std::cout << "Error creating symbolic link" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// TRUE NEGATIVES (Safe code examples)

// Example 1: Safe file access with whitelist validation
void good_case_1() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile?filename=user_input.txt");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Whitelist of allowed files
        std::vector<std::string> allowedFiles = {"file1.txt", "file2.txt", "user_input.txt"};
        bool isAllowed = false;
        
        for (const auto& allowedFile : allowedFiles) {
            if (filename == allowedFile) {
                isAllowed = true;
                break;
            }
        }
        
        // ok: cpp-path-traversal
        if (isAllowed) {
            std::ifstream file("data/" + filename);
            if (file.is_open()) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                   (std::istreambuf_iterator<char>()));
                std::cout << "File content: " << content << std::endl;
                file.close();
            }
        } else {
            std::cout << "Access denied: File not in whitelist" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 2: Safe file access with path normalization and validation
void good_case_2() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getpath?dir=uploads");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string userPath = readBuffer;
        std::string basePath = "/var/data/";
        
        // Normalize path and check if it's within the allowed directory
        std::filesystem::path normalizedPath = std::filesystem::weakly_canonical(basePath + userPath);
        std::filesystem::path basePathObj = std::filesystem::weakly_canonical(basePath);
        
        // ok: cpp-path-traversal
        if (normalizedPath.string().find(basePathObj.string()) == 0) {
            std::ofstream outfile(normalizedPath.string() + "/output.txt");
            if (outfile.is_open()) {
                outfile << "Some data to write" << std::endl;
                outfile.close();
            }
        } else {
            std::cout << "Access denied: Path traversal attempt detected" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 3: Safe file access with regex validation
void good_case_3() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilename");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Validate filename with regex (alphanumeric + extension only)
        std::regex filenameRegex("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$");
        
        // ok: cpp-path-traversal
        if (std::regex_match(filename, filenameRegex)) {
            std::string safePath = "/var/data/" + filename;
            std::ifstream file(safePath);
            if (file.is_open()) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                   (std::istreambuf_iterator<char>()));
                std::cout << "File content: " << content << std::endl;
                file.close();
            }
        } else {
            std::cout << "Invalid filename format" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 4: Safe directory access with path validation
void good_case_4() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdir");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string dirName = readBuffer;
        
        // Remove path traversal sequences
        std::string cleanPath = dirName;
        size_t pos;
        while ((pos = cleanPath.find("..")) != std::string::npos) {
            cleanPath.erase(pos, 2);
        }
        
        // Remove leading slashes
        while (!cleanPath.empty() && (cleanPath[0] == '/' || cleanPath[0] == '\\')) {
            cleanPath.erase(0, 1);
        }
        
        std::string basePath = "/var/www/uploads/";
        std::string fullPath = basePath + cleanPath;
        
        // ok: cpp-path-traversal
        DIR* dir = opendir(fullPath.c_str());
        if (dir != NULL) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                std::cout << entry->d_name << std::endl;
            }
            closedir(dir);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 5: Safe file access with sanitization
void good_case_5() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getpath?file=config.ini");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string userInput = readBuffer;
        
        // Sanitize input: remove all non-alphanumeric characters except for '.' and '_'
        std::string sanitized = "";
        for (char c : userInput) {
            if (isalnum(c) || c == '.' || c == '_') {
                sanitized += c;
            }
        }
        
        std::string basePath = "/var/data/";
        std::string fullPath = basePath + sanitized;
        
        // ok: cpp-path-traversal
        int fd = open(fullPath.c_str(), O_RDONLY);
        if (fd != -1) {
            char buffer[1024];
            ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::cout << "File content: " << buffer << std::endl;
            }
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 6: Safe file access with filesystem path validation
void good_case_6() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        std::string basePath = "/var/www/files/";
        
        // Validate path is within allowed directory
        std::filesystem::path requestedPath = std::filesystem::absolute(basePath + filename);
        std::filesystem::path allowedPath = std::filesystem::absolute(basePath);
        
        // ok: cpp-path-traversal
        if (requestedPath.string().find(allowedPath.string()) == 0) {
            if (std::filesystem::exists(requestedPath)) {
                std::ifstream file(requestedPath);
                std::string content((std::istreambuf_iterator<char>(file)),
                                   (std::istreambuf_iterator<char>()));
                std::cout << "File content: " << content << std::endl;
            }
        } else {
            std::cout << "Access denied: Path traversal attempt detected" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 7: Safe file access with filename extraction
void good_case_7() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilename");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string userInput = readBuffer;
        
        // Extract just the filename, ignoring any path components
        std::filesystem::path p(userInput);
        std::string filename = p.filename().string();
        
        std::string basePath = "/var/data/";
        
        // ok: cpp-path-traversal
        std::ifstream file(basePath + filename);
        if (file.is_open()) {
            std::string content((std::istreambuf_iterator<char>(file)),
                               (std::istreambuf_iterator<char>()));
            std::cout << "File content: " << content << std::endl;
            file.close();
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 8: Safe file access with extension validation
void good_case_8() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Check file extension
        std::filesystem::path p(filename);
        std::string extension = p.extension().string();
        
        std::vector<std::string> allowedExtensions = {".txt", ".log", ".dat"};
        bool isAllowedExtension = false;
        
        for (const auto& ext : allowedExtensions) {
            if (extension == ext) {
                isAllowedExtension = true;
                break;
            }
        }
        
        // Extract just the filename, ignoring any path components
        std::string safeFilename = p.filename().string();
        std::string basePath = "/var/logs/";
        
        // ok: cpp-path-traversal
        if (isAllowedExtension) {
            std::ifstream file(basePath + safeFilename);
            if (file.is_open()) {
                std::string content((std::istreambuf_iterator<char>(file)),
                                   (std::istreambuf_iterator<char>()));
                std::cout << "File content: " << content << std::endl;
                file.close();
            }
        } else {
            std::cout << "Access denied: File extension not allowed" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 9: Safe file deletion with path validation
void good_case_9() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfiledelete");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Validate filename (alphanumeric + extension only)
        std::regex filenameRegex("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$");
        
        // ok: cpp-path-traversal
        if (std::regex_match(filename, filenameRegex)) {
            std::string safePath = "/var/temp/" + filename;
            if (std::remove(safePath.c_str()) == 0) {
                std::cout << "File deleted successfully" << std::endl;
            } else {
                std::cout << "Error deleting file" << std::endl;
            }
        } else {
            std::cout << "Invalid filename format" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 10: Safe file renaming with path validation
void good_case_10() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getsource");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdest");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string oldName = readBuffer;
        std::string newName = readBuffer2;
        
        // Extract just the filenames
        std::filesystem::path oldPath(oldName);
        std::filesystem::path newPath(newName);
        std::string safeOldName = oldPath.filename().string();
        std::string safeNewName = newPath.filename().string();
        
        std::string basePath = "/var/uploads/";
        
        // ok: cpp-path-traversal
        if (std::rename((basePath + safeOldName).c_str(), (basePath + safeNewName).c_str()) == 0) {
            std::cout << "File renamed successfully" << std::endl;
        } else {
            std::cout << "Error renaming file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 11: Safe file stat with path validation
void good_case_11() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilepath");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Sanitize input: remove all non-alphanumeric characters except for '.' and '_'
        std::string sanitized = "";
        for (char c : filename) {
            if (isalnum(c) || c == '.' || c == '_') {
                sanitized += c;
            }
        }
        
        std::string basePath = "/var/www/files/";
        struct stat fileInfo;
        
        // ok: cpp-path-traversal
        if (stat((basePath + sanitized).c_str(), &fileInfo) == 0) {
            std::cout << "File size: " << fileInfo.st_size << " bytes" << std::endl;
        } else {
            std::cout << "Error getting file info" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 12: Safe file access check with path validation
void good_case_12() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/checkfile");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Validate filename with regex (alphanumeric + extension only)
        std::regex filenameRegex("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$");
        
        // ok: cpp-path-traversal
        if (std::regex_match(filename, filenameRegex)) {
            std::string safePath = "/var/data/" + filename;
            if (access(safePath.c_str(), F_OK) != -1) {
                std::cout << "File exists" << std::endl;
            } else {
                std::cout << "File does not exist" << std::endl;
            }
        } else {
            std::cout << "Invalid filename format" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 13: Safe file copy with path validation
void good_case_13() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getsource");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getdest");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string source = readBuffer;
        std::string destination = readBuffer2;
        
        // Extract just the filenames
        std::filesystem::path sourcePath(source);
        std::filesystem::path destPath(destination);
        std::string safeSource = sourcePath.filename().string();
        std::string safeDest = destPath.filename().string();
        
        std::string basePath = "/var/data/";
        
        // ok: cpp-path-traversal
        std::ifstream src((basePath + safeSource).c_str(), std::ios::binary);
        std::ofstream dst((basePath + safeDest).c_str(), std::ios::binary);
        
        if (src && dst) {
            dst << src.rdbuf();
            std::cout << "File copied successfully" << std::endl;
        } else {
            std::cout << "Error copying file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 14: Safe chmod with path validation
void good_case_14() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getfilepath");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string filename = readBuffer;
        
        // Whitelist of allowed files
        std::vector<std::string> allowedFiles = {"file1.txt", "file2.txt", "config.ini"};
        bool isAllowed = false;
        
        for (const auto& allowedFile : allowedFiles) {
            if (filename == allowedFile) {
                isAllowed = true;
                break;
            }
        }
        
        std::string basePath = "/var/app/";
        
        // ok: cpp-path-traversal
        if (isAllowed) {
            if (chmod((basePath + filename).c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == 0) {
                std::cout << "File permissions changed successfully" << std::endl;
            } else {
                std::cout << "Error changing file permissions" << std::endl;
            }
        } else {
            std::cout << "Access denied: File not in whitelist" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=path-traversal@v1.0 defects=0}

// Example 15: Safe symlink with path validation
void good_case_15() {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string readBuffer2;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/gettarget");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        res = curl_easy_perform(curl);
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/getlinkname");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer2);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        std::string target = readBuffer;
        std::string linkname = readBuffer2;
        
        // Extract just the filenames
        std::filesystem::path targetPath(target);
        std::filesystem::path linkPath(linkname);
        std::string safeTarget = targetPath.filename().string();
        std::string safeLink = linkPath.filename().string();
        
        std::string basePath = "/var/app/links/";
        std::string targetBasePath = "/var/app/targets/";
        
        // ok: cpp-path-traversal
        if (symlink((targetBasePath + safeTarget).c_str(), (basePath + safeLink).c_str()) == 0) {
            std::cout << "Symbolic link created successfully" << std::endl;
        } else {
            std::cout << "Error creating symbolic link" << std::endl;
        }
    }
}
// {/fact}

int main() {
    // Function calls can be added here for testing
    return 0;
}