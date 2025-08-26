#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
// {fact rule=insecure-buffer-access@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    char buffer[10];
    char* input = "This string is way too long for the buffer";
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, "%s", input); // Buffer overflow: input is larger than buffer
    
    printf("Buffer content: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_2() {
    char buffer[20];
    char* name = "John";
    int age = 30;
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, "Name: %s, Age: %d, Extra info: This will overflow", name, age);
    
    printf("Buffer content: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_3() {
    char buffer[10];
    const char* source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, "%s", source); // No size check, will overflow
    
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_4() {
    char buffer[50];
    char* username = "admin";
    char* password = "password123";
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, "User: %s\nPass: %s\nRole: %s\nAccess: %s", 
            username, password, "Administrator", "Full system access with many privileges that will overflow");
    
    printf("%s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_5() {
    char small_buffer[5];
    int values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(small_buffer, "%d%d%d%d%d", values[0], values[1], values[2], values[3], values[4]);
    
    printf("Values: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_6() {
    char buffer[10];
    
    // ruleid: cpp-insecure-buffer-access
    gets(buffer); // gets() is inherently unsafe as it has no bounds checking
    
    printf("You entered: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_7() {
    char buffer[20];
    const char* long_string = "This is a very long string that will definitely overflow the buffer";
    
    // ruleid: cpp-insecure-buffer-access
    snprintf(buffer, 50, "%s", long_string); // Incorrect size parameter (50 > buffer size of 20)
    
    printf("Buffer: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_8() {
    char buffer[10];
    time_t now = time(NULL);
    
    // ruleid: cpp-insecure-buffer-access
    struct tm* time_info = gmtime(&now); // gmtime uses a static buffer that could be overwritten
    
    sprintf(buffer, "%d-%d", time_info->tm_mon + 1, time_info->tm_mday);
    printf("Date: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_9(const char* user_input) {
    char small_buffer[5];
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(small_buffer, "U: %s", user_input); // No size check, potential overflow
    
    printf("User: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_10() {
    char dest[10];
    int a = 123456;
    int b = 789012;
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(dest, "%d-%d", a, b); // Could overflow if the resulting string is > 10 chars
    
    printf("Result: %s\n", dest);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_11() {
    char buffer[15];
    char* format = "%s-%s-%s"; // Format string with multiple substitutions
    char* part1 = "Hello";
    char* part2 = "World";
    char* part3 = "Program";
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, format, part1, part2, part3); // Could overflow
    
    printf("Combined: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_12() {
    char buffer[20];
    FILE* file = fopen("data.txt", "r");
    if (file) {
        // ruleid: cpp-insecure-buffer-access
        char* result = fgets(buffer, 100, file); // Incorrect size parameter (100 > buffer size of 20)
        fclose(file);
        printf("Read: %s\n", buffer);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_13() {
    char small_buf[5];
    const char* src = "12345678901234567890";
    
    // ruleid: cpp-insecure-buffer-access
    vsnprintf(small_buf, 20, "%s", (va_list)&src); // Incorrect size parameter and unsafe usage
    
    printf("Result: %s\n", small_buf);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_14() {
    char buffer[10];
    char input[100];
    
    printf("Enter your name: ");
    // ruleid: cpp-insecure-buffer-access
    scanf("%s", buffer); // No limit on input size, can overflow buffer
    
    printf("Hello, %s!\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_15() {
    char buffer[10];
    int year, month, day;
    time_t now = time(NULL);
    
    // ruleid: cpp-insecure-buffer-access
    struct tm* time_info = gmtime(&now);
    
    year = time_info->tm_year + 1900;
    month = time_info->tm_mon + 1;
    day = time_info->tm_mday;
    
    // ruleid: cpp-insecure-buffer-access
    sprintf(buffer, "%d/%d/%d", year, month, day); // Could overflow if date format is too long
    
    printf("Date: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    char buffer[50];
    char* input = "This string is way too long for a small buffer";
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "%s", input); // Safe: size is properly checked
    
    printf("Buffer content: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_2() {
    char buffer[20];
    char* name = "John";
    int age = 30;
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "Name: %s, Age: %d", name, age);
    
    printf("Buffer content: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_3() {
    char buffer[10];
    const char* source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    // ok: cpp-insecure-buffer-access
    strncpy(buffer, source, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
    
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_4() {
    char buffer[50];
    char* username = "admin";
    char* password = "password123";
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "User: %s\nPass: %s", username, password);
    
    printf("%s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_5() {
    char small_buffer[5];
    int values[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    // ok: cpp-insecure-buffer-access
    snprintf(small_buffer, sizeof(small_buffer), "%d", values[0]);
    
    printf("Value: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_6() {
    char buffer[100];
    FILE* file = stdin;
    
    printf("Enter text: ");
    // ok: cpp-insecure-buffer-access
    if (fgets(buffer, sizeof(buffer), file) != NULL) {
        printf("You entered: %s", buffer);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_7() {
    char buffer[20];
    const char* long_string = "This is a very long string that would overflow a small buffer";
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "%s", long_string);
    
    printf("Buffer: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_8() {
    char buffer[30];
    time_t now = time(NULL);
    struct tm time_info;
    
    // ok: cpp-insecure-buffer-access
    gmtime_r(&now, &time_info); // Thread-safe version of gmtime
    
    snprintf(buffer, sizeof(buffer), "%d-%d", time_info.tm_mon + 1, time_info.tm_mday);
    printf("Date: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_9(const char* user_input) {
    char buffer[100];
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "U: %s", user_input);
    
    printf("User: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_10() {
    char dest[20]; // Ensure buffer is large enough
    int a = 123456;
    int b = 789012;
    
    // ok: cpp-insecure-buffer-access
    snprintf(dest, sizeof(dest), "%d-%d", a, b);
    
    printf("Result: %s\n", dest);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_11() {
    char buffer[50]; // Ensure buffer is large enough
    char* format = "%s-%s-%s";
    char* part1 = "Hello";
    char* part2 = "World";
    char* part3 = "Program";
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), format, part1, part2, part3);
    
    printf("Combined: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_12() {
    char buffer[20];
    FILE* file = fopen("data.txt", "r");
    if (file) {
        // ok: cpp-insecure-buffer-access
        char* result = fgets(buffer, sizeof(buffer), file);
        fclose(file);
        printf("Read: %s\n", buffer);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_13() {
    char buffer[50];
    time_t now = time(NULL);
    struct tm time_result;
    
    // ok: cpp-insecure-buffer-access
    gmtime_r(&now, &time_result);
    
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &time_result);
    printf("Current time: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_14() {
    char buffer[10];
    
    printf("Enter a number (max 9 digits): ");
    // ok: cpp-insecure-buffer-access
    scanf("%9s", buffer); // Limit input to 9 characters + null terminator
    
    printf("You entered: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_15() {
    char buffer[50];
    char name[20];
    
    printf("Enter your name: ");
    // ok: cpp-insecure-buffer-access
    fgets(name, sizeof(name), stdin);
    
    // Remove newline if present
    size_t len = strlen(name);
    if (len > 0 && name[len-1] == '\n') {
        name[len-1] = '\0';
    }
    
    // ok: cpp-insecure-buffer-access
    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
    
    printf("%s\n", buffer);
}
// {/fact}

int main() {
    // Examples can be called from here for testing
    return 0;
}