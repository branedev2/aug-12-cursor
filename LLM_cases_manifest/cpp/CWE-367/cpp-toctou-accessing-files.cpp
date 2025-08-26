#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <mutex>
#include <filesystem>
#include <thread>
#include <chrono>
#include <vector>
#include <cstdio>
// {fact rule=file-race-bad@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    const char* filename = "config.txt";
    
    // Check if file exists
    struct stat st;
    if (stat(filename, &st) == 0) {
        std::cout << "File exists, proceeding to open" << std::endl;
        // Time window exists here for an attacker to modify the file
        // ruleid: cpp-toctou-accessing-files
        std::ifstream file(filename);
        if (file.is_open()) {
            std::string content;
            file >> content;
            std::cout << "File content: " << content << std::endl;
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_2() {
    const char* filename = "user_data.txt";
    
    // Check if file is accessible
    if (access(filename, R_OK) == 0) {
        std::cout << "File is readable" << std::endl;
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        FILE* file = fopen(filename, "r");
        if (file) {
            char buffer[256];
            fgets(buffer, sizeof(buffer), file);
            fclose(file);
            std::cout << "Read: " << buffer << std::endl;
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_3() {
    std::string filename = "sensitive.dat";
    
    // Check file size before reading
    struct stat st;
    if (stat(filename.c_str(), &st) == 0) {
        if (st.st_size < 1024 * 1024) { // Less than 1MB
            std::cout << "File size is acceptable" << std::endl;
            // Time window for race condition
            // ruleid: cpp-toctou-accessing-files
            int fd = open(filename.c_str(), O_RDONLY);
            if (fd != -1) {
                char buffer[1024];
                read(fd, buffer, sizeof(buffer));
                close(fd);
            }
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_4() {
    const char* filename = "temp.txt";
    
    // Check if file doesn't exist before creating
    if (access(filename, F_OK) != 0) {
        std::cout << "File doesn't exist, creating new file" << std::endl;
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        std::ofstream file(filename);
        file << "New file content" << std::endl;
        file.close();
    } else {
        std::cout << "File already exists" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_5() {
    std::string filename = "data.log";
    
    // Check if file is writable
    if (access(filename.c_str(), W_OK) == 0) {
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        std::ofstream file(filename, std::ios::app);
        if (file.is_open()) {
            file << "Appending new log entry" << std::endl;
            file.close();
        }
    } else {
        std::cout << "Cannot write to file" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_6() {
    const char* oldname = "original.txt";
    const char* newname = "renamed.txt";
    
    // Check if source exists and destination doesn't
    if (access(oldname, F_OK) == 0 && access(newname, F_OK) != 0) {
        std::cout << "Safe to rename file" << std::endl;
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        rename(oldname, newname);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_7() {
    std::string filename = "config.ini";
    
    // Check if file exists before removing
    struct stat st;
    if (stat(filename.c_str(), &st) == 0) {
        if (S_ISREG(st.st_mode)) { // Make sure it's a regular file
            std::cout << "File exists and is regular, removing" << std::endl;
            // Time window for race condition
            // ruleid: cpp-toctou-accessing-files
            std::remove(filename.c_str());
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_8() {
    const char* filename = "important.txt";
    
    // Check file permissions
    struct stat st;
    if (stat(filename, &st) == 0) {
        if ((st.st_mode & S_IWOTH) == 0) { // Not writable by others
            std::cout << "File is secure, proceeding" << std::endl;
            // Time window for race condition
            // ruleid: cpp-toctou-accessing-files
            std::ifstream file(filename);
            std::string content;
            std::getline(file, content);
            std::cout << "Content: " << content << std::endl;
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_9() {
    std::string directory = "/tmp/app_data";
    std::string filename = directory + "/user_prefs.txt";
    
    // Check if directory exists, if not create it
    struct stat st;
    if (stat(directory.c_str(), &st) != 0) {
        std::cout << "Directory doesn't exist, creating" << std::endl;
        mkdir(directory.c_str(), 0755);
    }
    
    // Time window for race condition
    // ruleid: cpp-toctou-accessing-files
    std::ofstream file(filename);
    file << "User preferences data" << std::endl;
    file.close();
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_10() {
    const char* filename = "database.sqlite";
    
    // Check if file exists and get its size
    struct stat st;
    if (stat(filename, &st) == 0) {
        std::cout << "Database size: " << st.st_size << " bytes" << std::endl;
        
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        int fd = open(filename, O_RDWR);
        if (fd != -1) {
            // Perform database operations
            // ...
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_11() {
    std::string filename = "counter.txt";
    
    // Read current counter value
    int counter = 0;
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        inFile >> counter;
        inFile.close();
        
        // Increment counter
        counter++;
        
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        std::ofstream outFile(filename);
        outFile << counter;
        outFile.close();
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_12() {
    const char* lockfile = "/tmp/app.lock";
    
    // Check if lock file exists
    if (access(lockfile, F_OK) != 0) {
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        std::ofstream file(lockfile);
        file << getpid();
        file.close();
        
        std::cout << "Lock acquired" << std::endl;
        // Do critical section work
        // ...
        
        // Remove lock when done
        std::remove(lockfile);
    } else {
        std::cout << "Another process has the lock" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_13() {
    std::string filename = "settings.conf";
    
    // Check if file is not too large before processing
    struct stat st;
    if (stat(filename.c_str(), &st) == 0) {
        if (st.st_size < 10000) { // Size limit
            std::cout << "File size is within limits" << std::endl;
            
            // Time window for race condition
            // ruleid: cpp-toctou-accessing-files
            std::vector<char> buffer(st.st_size);
            FILE* file = fopen(filename.c_str(), "rb");
            if (file) {
                fread(buffer.data(), 1, st.st_size, file);
                fclose(file);
                // Process buffer
            }
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_14() {
    const char* filename = "backup.tar";
    
    // Check if file exists before backing up
    if (access(filename, F_OK) != 0) {
        // Create backup file
        std::cout << "Creating backup file" << std::endl;
        
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        int fd = open(filename, O_WRONLY | O_CREAT, 0644);
        if (fd != -1) {
            // Write backup data
            const char* data = "backup data";
            write(fd, data, strlen(data));
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=1}

void bad_case_15() {
    std::string source = "source.dat";
    std::string dest = "destination.dat";
    
    // Check if source exists and destination doesn't
    struct stat source_st, dest_st;
    bool source_exists = (stat(source.c_str(), &source_st) == 0);
    bool dest_exists = (stat(dest.c_str(), &dest_st) == 0);
    
    if (source_exists && !dest_exists) {
        std::cout << "Safe to copy file" << std::endl;
        
        // Time window for race condition
        // ruleid: cpp-toctou-accessing-files
        std::ifstream src(source, std::ios::binary);
        std::ofstream dst(dest, std::ios::binary);
        dst << src.rdbuf();
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    const char* filename = "config.txt";
    
    // Open file directly without checking first
    // ok: cpp-toctou-accessing-files
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string content;
        file >> content;
        std::cout << "File content: " << content << std::endl;
    } else {
        std::cout << "Failed to open file" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_2() {
    const char* filename = "user_data.txt";
    
    // Use a mutex to synchronize access
    static std::mutex file_mutex;
    std::lock_guard<std::mutex> lock(file_mutex);
    
    // Check and use file under the same lock
    // ok: cpp-toctou-accessing-files
    if (access(filename, R_OK) == 0) {
        FILE* file = fopen(filename, "r");
        if (file) {
            char buffer[256];
            fgets(buffer, sizeof(buffer), file);
            fclose(file);
            std::cout << "Read: " << buffer << std::endl;
        }
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_3() {
    std::string filename = "sensitive.dat";
    
    // Open file first, then check size
    // ok: cpp-toctou-accessing-files
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if (st.st_size < 1024 * 1024) { // Less than 1MB
                char buffer[1024];
                read(fd, buffer, sizeof(buffer));
            }
        }
        close(fd);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_4() {
    const char* filename = "temp.txt";
    
    // Use O_EXCL flag to ensure atomic creation
    // ok: cpp-toctou-accessing-files
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd != -1) {
        // File was created exclusively
        const char* data = "New file content\n";
        write(fd, data, strlen(data));
        close(fd);
    } else if (errno == EEXIST) {
        std::cout << "File already exists" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_5() {
    std::string filename = "data.log";
    
    // Open file directly for append
    // ok: cpp-toctou-accessing-files
    std::ofstream file(filename, std::ios::app);
    if (file.is_open()) {
        file << "Appending new log entry" << std::endl;
        file.close();
    } else {
        std::cout << "Cannot write to file" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_6() {
    const char* oldname = "original.txt";
    const char* newname = "renamed.txt";
    
    // Use a mutex for synchronization
    static std::mutex rename_mutex;
    std::lock_guard<std::mutex> lock(rename_mutex);
    
    // Check and rename under the same lock
    // ok: cpp-toctou-accessing-files
    if (access(oldname, F_OK) == 0 && access(newname, F_OK) != 0) {
        rename(oldname, newname);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_7() {
    std::string filename = "config.ini";
    
    // Use filesystem operations that are more atomic
    // ok: cpp-toctou-accessing-files
    try {
        if (std::filesystem::is_regular_file(filename)) {
            std::filesystem::remove(filename);
            std::cout << "File removed" << std::endl;
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_8() {
    const char* filename = "important.txt";
    
    // Open file first, then check permissions on the open file descriptor
    // ok: cpp-toctou-accessing-files
    int fd = open(filename, O_RDONLY);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            if ((st.st_mode & S_IWOTH) == 0) { // Not writable by others
                // Read from the already open file descriptor
                char buffer[1024];
                read(fd, buffer, sizeof(buffer));
            }
        }
        close(fd);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_9() {
    std::string directory = "/tmp/app_data";
    std::string filename = directory + "/user_prefs.txt";
    
    // Use filesystem to create directories and handle errors
    // ok: cpp-toctou-accessing-files
    try {
        std::filesystem::create_directories(directory);
        std::ofstream file(filename);
        file << "User preferences data" << std::endl;
        file.close();
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_10() {
    const char* filename = "database.sqlite";
    
    // Open file first, then get its size
    // ok: cpp-toctou-accessing-files
    int fd = open(filename, O_RDWR);
    if (fd != -1) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            std::cout << "Database size: " << st.st_size << " bytes" << std::endl;
            // Perform database operations using the already open fd
            // ...
        }
        close(fd);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_11() {
    std::string filename = "counter.txt";
    static std::mutex counter_mutex;
    
    // Use a mutex to protect the entire read-modify-write operation
    std::lock_guard<std::mutex> lock(counter_mutex);
    
    // Read, modify, and write under the same lock
    // ok: cpp-toctou-accessing-files
    int counter = 0;
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        inFile >> counter;
        inFile.close();
        
        // Increment counter
        counter++;
        
        std::ofstream outFile(filename);
        outFile << counter;
        outFile.close();
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_12() {
    const char* lockfile = "/tmp/app.lock";
    
    // Use O_EXCL to create lock file atomically
    // ok: cpp-toctou-accessing-files
    int fd = open(lockfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd != -1) {
        // Lock acquired
        std::string pid = std::to_string(getpid());
        write(fd, pid.c_str(), pid.length());
        close(fd);
        
        std::cout << "Lock acquired" << std::endl;
        // Do critical section work
        // ...
        
        // Remove lock when done
        std::remove(lockfile);
    } else {
        std::cout << "Another process has the lock" << std::endl;
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_13() {
    std::string filename = "settings.conf";
    
    // Open file first, then check size
    // ok: cpp-toctou-accessing-files
    FILE* file = fopen(filename.c_str(), "rb");
    if (file) {
        // Get file size from the open file
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        if (size < 10000) { // Size limit
            std::vector<char> buffer(size);
            fread(buffer.data(), 1, size, file);
            // Process buffer
        }
        fclose(file);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_14() {
    const char* filename = "backup.tar";
    
    // Use file locking to prevent race conditions
    // ok: cpp-toctou-accessing-files
    int fd = open(filename, O_WRONLY | O_CREAT, 0644);
    if (fd != -1) {
        // Try to get an exclusive lock
        struct flock fl;
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0; // Lock the entire file
        
        if (fcntl(fd, F_SETLK, &fl) != -1) {
            // We have the lock, write backup data
            const char* data = "backup data";
            write(fd, data, strlen(data));
            
            // Release the lock
            fl.l_type = F_UNLCK;
            fcntl(fd, F_SETLK, &fl);
        }
        close(fd);
    }
}
// {/fact}
// {fact rule=file-race-bad@v1.0 defects=0}

void good_case_15() {
    std::string source = "source.dat";
    std::string dest = "destination.dat";
    
    // Use a mutex for synchronization
    static std::mutex file_mutex;
    std::lock_guard<std::mutex> lock(file_mutex);
    
    // Check and copy under the same lock
    // ok: cpp-toctou-accessing-files
    try {
        if (std::filesystem::exists(source) && !std::filesystem::exists(dest)) {
            std::filesystem::copy_file(source, dest);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "TOCTOU examples" << std::endl;
    return 0;
}