#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

// True Positives (Vulnerable Code)

void bad_case_1() {
    char buffer[10];
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", buffer); // No field width specified, can overflow buffer
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_2() {
    int values[5];
    // ruleid: cpp-insecure-api-scanf
    scanf("%d %d %d %d %d %d", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]); // Accessing beyond array bounds
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_3() {
    char username[20];
    printf("Enter username: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", username); // No field width limit, vulnerable to buffer overflow
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_4() {
    char password[8];
    printf("Enter password: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", password); // Critical security info with no length check
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_5() {
    char filename[50];
    printf("Enter filename to open: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", filename); // No field width, could lead to buffer overflow
    FILE* file = fopen(filename, "r");
    // Process file...
    fclose(file);
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_6() {
    char command[100];
    printf("Enter system command: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", command); // No field width, vulnerable to buffer overflow
    system(command); // Could lead to command injection
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_7() {
    struct {
        char name[20];
        int id;
    } user;
    
    printf("Enter user name: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", user.name); // No field width for struct member
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_8() {
    char buffer[10];
    int count;
    
    printf("Enter string and count: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s %d", buffer, &count); // First parameter has no field width
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_9() {
    char first_name[10];
    char last_name[10];
    
    // ruleid: cpp-insecure-api-scanf
    scanf("%s %s", first_name, last_name); // Multiple unbounded string inputs
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_10() {
    char* dynamic_buffer = (char*)malloc(20);
    if (dynamic_buffer) {
        // ruleid: cpp-insecure-api-scanf
        scanf("%s", dynamic_buffer); // No field width for dynamically allocated buffer
        free(dynamic_buffer);
    }
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_11() {
    char multi_line[50];
    printf("Enter multi-line text: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%[^\n]", multi_line); // Using scanset without size limit
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_12() {
    char buffer[100];
    // ruleid: cpp-insecure-api-scanf
    scanf("%[a-zA-Z0-9]", buffer); // Using character class without size limit
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_13() {
    char ip_address[16];
    printf("Enter IP address: ");
    // ruleid: cpp-insecure-api-scanf
    scanf("%s", ip_address); // No field width for IP address input
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_14() {
    int values[5];
    int i = 0;
    printf("Enter numbers: ");
    while (i < 10) { // Potential out of bounds access
        // ruleid: cpp-insecure-api-scanf
        scanf("%d", &values[i++]); // Could write beyond array bounds
    }
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}

void bad_case_15() {
    char buffer[20];
    int choice;
    
    printf("1. Enter name\n2. Exit\nChoice: ");
    scanf("%d", &choice);
    
    if (choice == 1) {
        printf("Enter name: ");
        // ruleid: cpp-insecure-api-scanf
        scanf("%s", buffer); // No field width in conditional branch
    }
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

// True Negatives (Safe Code)

void good_case_1() {
    char buffer[10];
    // ok: cpp-insecure-api-scanf
    scanf("%9s", buffer); // Field width specified to prevent overflow
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_2() {
    char buffer[100];
    // ok: cpp-insecure-api-scanf
    fgets(buffer, sizeof(buffer), stdin); // Using safer fgets instead of scanf
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_3() {
    char buffer[50];
    // ok: cpp-insecure-api-scanf
    scanf("%49s", buffer); // Field width one less than buffer size to ensure null termination
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_4() {
    std::string input;
    // ok: cpp-insecure-api-scanf
    std::cin >> input; // Using C++ streams which handle memory safely
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_5() {
    char buffer[20];
    // ok: cpp-insecure-api-scanf
    if (scanf("%19s", buffer) != 1) {
        printf("Input error\n");
    }
    // Field width specified and return value checked
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_6() {
    char filename[50];
    printf("Enter filename to open: ");
    // ok: cpp-insecure-api-scanf
    scanf("%49s", filename); // Field width specified for filename
    FILE* file = fopen(filename, "r");
    if (file) {
        // Process file...
        fclose(file);
    }
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_7() {
    struct {
        char name[20];
        int id;
    } user;
    
    printf("Enter user name: ");
    // ok: cpp-insecure-api-scanf
    scanf("%19s", user.name); // Field width specified for struct member
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_8() {
    char buffer[100];
    printf("Enter text: ");
    // ok: cpp-insecure-api-scanf
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = 0; // Remove newline if present
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_9() {
    int num;
    // ok: cpp-insecure-api-scanf
    scanf("%d", &num); // Integer input is safe from buffer overflow
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_10() {
    char first_name[10];
    char last_name[10];
    
    // ok: cpp-insecure-api-scanf
    scanf("%9s %9s", first_name, last_name); // Field width specified for both inputs
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_11() {
    char* dynamic_buffer = (char*)malloc(20);
    if (dynamic_buffer) {
        // ok: cpp-insecure-api-scanf
        scanf("%19s", dynamic_buffer); // Field width specified for dynamic buffer
        free(dynamic_buffer);
    }
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_12() {
    char multi_line[50];
    printf("Enter multi-line text: ");
    // ok: cpp-insecure-api-scanf
    scanf("%49[^\n]", multi_line); // Using scanset with size limit
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_13() {
    std::string input;
    std::cout << "Enter text: ";
    // ok: cpp-insecure-api-scanf
    std::getline(std::cin, input); // Using C++ getline which handles memory safely
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_14() {
    char buffer[100];
    // ok: cpp-insecure-api-scanf
    snprintf(buffer, sizeof(buffer), "Safe format string"); // Using snprintf for safe formatting
}
// {/fact}
// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}

void good_case_15() {
    int values[5];
    for (int i = 0; i < 5; i++) {
        printf("Enter value %d: ", i+1);
        // ok: cpp-insecure-api-scanf
        scanf("%d", &values[i]); // Safe because index is bounded
    }
}
// {/fact}

int main() {
    // Function calls could go here for testing
    return 0;
}