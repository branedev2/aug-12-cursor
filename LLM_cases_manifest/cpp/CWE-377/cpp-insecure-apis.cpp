#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string>
#include <vector>
#include <random>
#include <chrono>
// {fact rule=insecure-temp-file@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    // Using tmpnam which is insecure due to race conditions
    char buffer[L_tmpnam];
    // ruleid: cpp-insecure-apis
    char* filename = tmpnam(buffer);
    
    FILE* file = fopen(filename, "w+");
    if (file) {
        fprintf(file, "Sensitive data\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_2() {
    // Using tmpnam with NULL parameter is also insecure
    // ruleid: cpp-insecure-apis
    char* filename = tmpnam(NULL);
    
    std::ofstream outfile(filename);
    outfile << "Confidential information" << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_3() {
    // Using tempnam which is insecure
    // ruleid: cpp-insecure-apis
    char* filename = tempnam("/tmp", "prefix");
    
    FILE* file = fopen(filename, "w");
    if (file) {
        fputs("Secret data", file);
        fclose(file);
        free(filename); // tempnam allocates memory
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_4() {
    // Using tmpfile but not checking for NULL
    // ruleid: cpp-insecure-apis
    FILE* temp = tmpfile();
    
    fprintf(temp, "Important data\n");
    fclose(temp);
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_5() {
    // Creating a predictable temporary filename
    std::string filename = "/tmp/app_temp_file.txt";
    
    // ruleid: cpp-insecure-apis
    std::ofstream outfile(filename);
    outfile << "User credentials" << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_6() {
    // Using a timestamp for filename which is predictable
    time_t now = time(0);
    std::string filename = "/tmp/temp_" + std::to_string(now) + ".txt";
    
    // ruleid: cpp-insecure-apis
    FILE* file = fopen(filename.c_str(), "w");
    if (file) {
        fprintf(file, "Private key data\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_7() {
    // Using a fixed temporary filename with PID which is still predictable
    std::string filename = "/tmp/app_" + std::to_string(getpid()) + ".tmp";
    
    // ruleid: cpp-insecure-apis
    int fd = open(filename.c_str(), O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "Sensitive information", 21);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_8() {
    // Using a hardcoded path in /tmp
    const char* filename = "/tmp/hardcoded_temp.txt";
    
    // ruleid: cpp-insecure-apis
    FILE* file = fopen(filename, "w+");
    if (file) {
        fprintf(file, "Database credentials\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_9() {
    // Creating a temporary file with weak permissions
    char template_name[] = "/tmp/tempXXXXXX";
    
    // ruleid: cpp-insecure-apis
    int fd = open(template_name, O_CREAT | O_RDWR, 0666); // Insecure permissions
    if (fd != -1) {
        write(fd, "API keys", 8);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_10() {
    // Using a simple counter for temporary files
    static int counter = 0;
    std::string filename = "/tmp/temp_" + std::to_string(counter++) + ".dat";
    
    // ruleid: cpp-insecure-apis
    std::ofstream outfile(filename);
    outfile << "Authentication tokens" << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_11() {
    // Using environment variable without validation
    const char* temp_dir = getenv("TEMP_DIR");
    if (!temp_dir) temp_dir = "/tmp";
    
    std::string filename = std::string(temp_dir) + "/insecure_temp.txt";
    
    // ruleid: cpp-insecure-apis
    FILE* file = fopen(filename.c_str(), "w");
    if (file) {
        fprintf(file, "Private user data\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_12() {
    // Using a weak random number generator for filename
    srand(time(NULL));
    std::string filename = "/tmp/temp_" + std::to_string(rand()) + ".bin";
    
    // ruleid: cpp-insecure-apis
    int fd = open(filename.c_str(), O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "Confidential report", 19);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_13() {
    // Using tmpnam in a loop without proper cleanup
    for (int i = 0; i < 5; i++) {
        // ruleid: cpp-insecure-apis
        char* filename = tmpnam(NULL);
        
        FILE* file = fopen(filename, "w");
        if (file) {
            fprintf(file, "Temporary data %d\n", i);
            fclose(file);
            // No removal of the file
        }
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_14() {
    // Using a combination of user input and fixed path
    std::string username = "admin"; // Assume this comes from user input
    std::string filename = "/tmp/" + username + "_temp.txt";
    
    // ruleid: cpp-insecure-apis
    std::ofstream outfile(filename);
    outfile << "Session data for " << username << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=1}

void bad_case_15() {
    // Using a fixed template without proper randomization
    char template_name[] = "/tmp/appXXX.tmp"; // Not enough X's for security
    
    // ruleid: cpp-insecure-apis
    FILE* file = fopen(template_name, "w+");
    if (file) {
        fprintf(file, "Critical system data\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

// True Negative Examples (Secure Code)

void good_case_1() {
    // Using mkstemp which is secure
    char template_name[] = "/tmp/secureXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        write(fd, "Sensitive data\n", 15);
        close(fd);
        unlink(template_name); // Clean up after use
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_2() {
    // Using mkstemp with proper error handling and cleanup
    char template_name[] = "/tmp/app_tempXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd == -1) {
        perror("Failed to create temporary file");
        return;
    }
    
    FILE* file = fdopen(fd, "w+");
    if (!file) {
        close(fd);
        unlink(template_name);
        return;
    }
    
    fprintf(file, "Confidential information\n");
    fclose(file);
    unlink(template_name); // Clean up
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_3() {
    // Using mkostemp for additional security options
    char template_name[] = "/tmp/secure_tempXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkostemp(template_name, O_CLOEXEC);
    
    if (fd != -1) {
        write(fd, "Secret data", 11);
        close(fd);
        unlink(template_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_4() {
    // Using tmpfile() with proper error checking
    // ok: cpp-insecure-apis
    FILE* temp = tmpfile();
    
    if (!temp) {
        perror("Failed to create temporary file");
        return;
    }
    
    fprintf(temp, "Important data\n");
    fclose(temp); // tmpfile() automatically removes the file on close
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_5() {
    // Using mkdtemp for secure temporary directory
    char template_dir[] = "/tmp/secure_dirXXXXXX";
    
    // ok: cpp-insecure-apis
    char* dir_name = mkdtemp(template_dir);
    
    if (dir_name) {
        std::string filename = std::string(dir_name) + "/secure_file.txt";
        std::ofstream outfile(filename);
        outfile << "User credentials" << std::endl;
        outfile.close();
        
        // Clean up
        unlink(filename.c_str());
        rmdir(dir_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_6() {
    // Using mkstemp with proper permissions and cleanup
    char template_name[] = "/tmp/secure_fileXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        // Set restrictive permissions
        fchmod(fd, S_IRUSR | S_IWUSR);
        
        write(fd, "Private key data\n", 17);
        close(fd);
        unlink(template_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_7() {
    // Using C++17 filesystem for temporary directory
    char template_name[] = "/tmp/cpp17_tempXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        std::string data = "Sensitive information";
        write(fd, data.c_str(), data.length());
        close(fd);
        unlink(template_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_8() {
    // Using mkstemp with a more secure location if available
    const char* secure_tmp = getenv("SECURE_TEMP_DIR");
    char template_name[256];
    
    if (secure_tmp) {
        snprintf(template_name, sizeof(template_name), "%s/tempXXXXXX", secure_tmp);
    } else {
        strcpy(template_name, "/tmp/tempXXXXXX");
    }
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        write(fd, "Database credentials\n", 21);
        close(fd);
        unlink(template_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_9() {
    // Using mkstemp with immediate unlink for added security
    char template_name[] = "/tmp/secure_unlinkedXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        // Unlink immediately so file disappears when closed
        unlink(template_name);
        
        FILE* file = fdopen(fd, "w+");
        if (file) {
            fprintf(file, "API keys\n");
            fclose(file);
        } else {
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_10() {
    // Using a memory-based approach instead of temporary files
    std::vector<char> memory_buffer;
    
    // ok: cpp-insecure-apis
    // No temporary file is created, data stays in memory
    memory_buffer.resize(1024);
    snprintf(memory_buffer.data(), memory_buffer.size(), "Authentication tokens");
    
    // Process the data in memory
    std::string data(memory_buffer.data());
    // Use data...
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_11() {
    // Using mkstemp with proper error handling and secure permissions
    char template_name[] = "/tmp/secure_dataXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd == -1) {
        perror("Failed to create temporary file");
        return;
    }
    
    // Set secure permissions
    if (fchmod(fd, S_IRUSR | S_IWUSR) == -1) {
        close(fd);
        unlink(template_name);
        return;
    }
    
    write(fd, "Private user data\n", 18);
    close(fd);
    unlink(template_name);
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_12() {
    // Using a secure random generator for cases where mkstemp isn't available
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10000000, 99999999);
    
    std::string filename;
    int fd = -1;
    
    // Try to create a unique file with secure permissions
    for (int attempts = 0; attempts < 10 && fd == -1; attempts++) {
        filename = "/tmp/secure_" + std::to_string(dis(gen)) + ".tmp";
        
        // ok: cpp-insecure-apis
        fd = open(filename.c_str(), O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
    }
    
    if (fd != -1) {
        write(fd, "Confidential report", 19);
        close(fd);
        unlink(filename.c_str());
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_13() {
    // Using mkstemp in a loop with proper cleanup
    for (int i = 0; i < 5; i++) {
        char template_name[32];
        snprintf(template_name, sizeof(template_name), "/tmp/iter%d_XXXXXX", i);
        
        // ok: cpp-insecure-apis
        int fd = mkstemp(template_name);
        
        if (fd != -1) {
            write(fd, "Temporary data", 14);
            close(fd);
            unlink(template_name); // Clean up properly
        }
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_14() {
    // Using mkstemp with user-specific data
    std::string username = "admin"; // Assume this comes from user input
    char template_name[256];
    
    // Create a template with the username but still use XXXXXX for randomization
    snprintf(template_name, sizeof(template_name), "/tmp/%s_XXXXXX", username.c_str());
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        std::string content = "Session data for " + username;
        write(fd, content.c_str(), content.length());
        close(fd);
        unlink(template_name);
    }
}
// {/fact}
// {fact rule=insecure-temp-file@v1.0 defects=0}

void good_case_15() {
    // Using memfd_create for in-memory temporary file (Linux-specific)
    #ifdef __linux__
    // ok: cpp-insecure-apis
    int fd = memfd_create("secure_temp", 0);
    
    if (fd != -1) {
        write(fd, "Critical system data\n", 21);
        
        // Use the file descriptor as needed
        lseek(fd, 0, SEEK_SET);
        
        char buffer[100];
        read(fd, buffer, sizeof(buffer));
        
        close(fd); // No need to unlink, file is automatically removed
    }
    #else
    // Fall back to mkstemp on non-Linux systems
    char template_name[] = "/tmp/secure_tempXXXXXX";
    
    // ok: cpp-insecure-apis
    int fd = mkstemp(template_name);
    
    if (fd != -1) {
        write(fd, "Critical system data\n", 21);
        close(fd);
        unlink(template_name);
    }
    #endif
}
// {/fact}

int main() {
    // This is just a placeholder main function
    return 0;
}