#include <cstring>
#include <string>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <memory>
#include <cstdio>
#include <fstream>
// {fact rule=insecure-buffer-access@v1.0 defects=1}

// True Positives (vulnerable code that should be detected)

void bad_case_1() {
    char dest[10];
    char src[] = "This string is too long for the destination buffer";
    
    // ruleid: cpp-interesting-api-calls
    stpncpy(dest, src, sizeof(src)); // Potential buffer overflow if src is larger than dest
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_2() {
    char buffer[100];
    
    // ruleid: cpp-interesting-api-calls
    gets(buffer); // Notorious for buffer overflow vulnerabilities
    
    std::cout << "You entered: " << buffer << std::endl;
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_3() {
    char command[100];
    std::cout << "Enter command: ";
    std::cin >> command;
    
    // ruleid: cpp-interesting-api-calls
    system(command); // Executing user input directly is dangerous
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_4() {
    char* buffer = (char*)malloc(100);
    strcpy(buffer, "Hello, world!");
    
    // Memory leak - free is never called
    // ruleid: cpp-interesting-api-calls
    return; // Returning without freeing allocated memory
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_5() {
    FILE* file = fopen("sensitive.txt", "r");
    if (!file) {
        return;
    }
    
    // Process file...
    
    // ruleid: cpp-interesting-api-calls
    return; // File handle leak - fclose is never called
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_6() {
    char buffer[100];
    
    // ruleid: cpp-interesting-api-calls
    strcpy(buffer, "This string might be too long and cause a buffer overflow");
    // No bounds checking
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_7() {
    char* ptr = nullptr;
    
    // ruleid: cpp-interesting-api-calls
    free(ptr); // Freeing a null pointer
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_8() {
    int fd = open("file.txt", O_RDWR);
    if (fd == -1) {
        return;
    }
    
    // Process file...
    
    // ruleid: cpp-interesting-api-calls
    return; // File descriptor leak - close() is never called
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_9() {
    char* buffer = (char*)malloc(100);
    
    // ruleid: cpp-interesting-api-calls
    free(buffer);
    strcpy(buffer, "Hello"); // Use after free
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_10() {
    int* array = new int[10];
    
    // Process array...
    
    // ruleid: cpp-interesting-api-calls
    delete array; // Should use delete[] for arrays
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_11() {
    char buffer[10];
    char input[100];
    
    std::cin >> input;
    
    // ruleid: cpp-interesting-api-calls
    strncpy(buffer, input, sizeof(input)); // Potential buffer overflow if input is larger than buffer
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_12() {
    // ruleid: cpp-interesting-api-calls
    char* ptr = (char*)malloc(0); // Allocating zero bytes
    
    free(ptr);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_13() {
    std::string userInput;
    std::cout << "Enter command: ";
    std::getline(std::cin, userInput);
    
    std::string command = "echo " + userInput;
    
    // ruleid: cpp-interesting-api-calls
    popen(command.c_str(), "r"); // Command injection vulnerability
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_14() {
    char buffer[100];
    
    // ruleid: cpp-interesting-api-calls
    sprintf(buffer, "%s %s", "Hello", "World"); // Unsafe - no bounds checking
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_15() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    
    // Process socket...
    
    // ruleid: cpp-interesting-api-calls
    return; // Socket descriptor leak - close() is never called
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

// True Negatives (safe code that should not be detected)

void good_case_1() {
    char dest[20];
    char src[] = "Hello";
    
    // ok: cpp-interesting-api-calls
    size_t len = strnlen(src, sizeof(src));
    if (len < sizeof(dest)) {
        stpncpy(dest, src, len);
        dest[len] = '\0'; // Ensure null termination
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_2() {
    char buffer[100];
    
    // ok: cpp-interesting-api-calls
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        std::cout << "You entered: " << buffer << std::endl;
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_3() {
    std::string command = "ls -la";
    
    // ok: cpp-interesting-api-calls
    // Using a fixed, known command is safer
    system(command.c_str());
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_4() {
    char* buffer = (char*)malloc(100);
    if (buffer) {
        strcpy(buffer, "Hello, world!");
        
        // Process buffer...
        
        // ok: cpp-interesting-api-calls
        free(buffer); // Properly freeing allocated memory
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_5() {
    FILE* file = fopen("data.txt", "r");
    if (!file) {
        return;
    }
    
    // Process file...
    
    // ok: cpp-interesting-api-calls
    fclose(file); // Properly closing the file handle
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_6() {
    char buffer[100];
    const char* source = "Hello, world!";
    
    // ok: cpp-interesting-api-calls
    strncpy(buffer, source, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_7() {
    char* ptr = (char*)malloc(100);
    if (ptr) {
        // Process ptr...
        
        // ok: cpp-interesting-api-calls
        free(ptr); // Only free if not null
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_8() {
    int fd = open("file.txt", O_RDWR);
    if (fd == -1) {
        return;
    }
    
    // Process file...
    
    // ok: cpp-interesting-api-calls
    close(fd); // Properly closing the file descriptor
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_9() {
    char* buffer = (char*)malloc(100);
    if (buffer) {
        strcpy(buffer, "Hello");
        
        // Process buffer...
        
        // ok: cpp-interesting-api-calls
        free(buffer);
        buffer = nullptr; // Avoid use after free
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_10() {
    int* array = new int[10];
    
    // Process array...
    
    // ok: cpp-interesting-api-calls
    delete[] array; // Correctly using delete[] for arrays
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_11() {
    char buffer[10];
    char input[100];
    
    std::cin >> input;
    
    // ok: cpp-interesting-api-calls
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_12() {
    // ok: cpp-interesting-api-calls
    char* ptr = (char*)malloc(100); // Allocating a reasonable size
    
    if (ptr) {
        // Use ptr...
        free(ptr);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_13() {
    std::string userInput;
    std::cout << "Enter text: ";
    std::getline(std::cin, userInput);
    
    // Validate and sanitize input before using it
    bool valid = true;
    for (char c : userInput) {
        if (!isalnum(c) && !isspace(c)) {
            valid = false;
            break;
        }
    }
    
    if (valid) {
        std::string command = "echo " + userInput;
        // ok: cpp-interesting-api-calls
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe) {
            pclose(pipe);
        }
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_14() {
    char buffer[100];
    
    // ok: cpp-interesting-api-calls
    snprintf(buffer, sizeof(buffer), "%s %s", "Hello", "World"); // Safe - respects buffer size
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_15() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd != -1) {
        // Process socket...
        
        // ok: cpp-interesting-api-calls
        close(fd); // Properly closing the socket descriptor
    }
}
// {/fact}