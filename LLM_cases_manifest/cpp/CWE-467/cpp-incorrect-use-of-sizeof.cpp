#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

// True Positives (Vulnerable Code)

void bad_case_1() {
    int* numbers = (int*)malloc(10 * sizeof(int));
    if (numbers == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    memset(numbers, 0, sizeof(numbers)); // This only clears the size of the pointer (e.g., 4 or 8 bytes)
    
    free(numbers);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_2() {
    char* buffer = (char*)malloc(100);
    if (buffer == NULL) return;
    
    char input[] = "This is a test string that is longer than the pointer size";
    
    // ruleid: cpp-incorrect-use-of-sizeof
    if (strlen(input) < sizeof(buffer)) { // Comparing with pointer size, not allocated size
        strcpy(buffer, input); // Potential buffer overflow
    }
    
    free(buffer);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_3() {
    double* values = (double*)malloc(5 * sizeof(double));
    if (values == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    printf("Allocated memory size: %zu bytes\n", sizeof(values)); // Prints pointer size, not allocated size
    
    free(values);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_4() {
    struct Person {
        char name[50];
        int age;
    };
    
    struct Person* person = (struct Person*)malloc(sizeof(struct Person));
    if (person == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    memcpy(person, "John Doe", sizeof(person)); // Copies only pointer size bytes
    
    free(person);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_5() {
    int* array = (int*)malloc(10 * sizeof(int));
    if (array == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    for (int i = 0; i < sizeof(array) / sizeof(int); i++) { // Incorrect array size calculation
        array[i] = i;
    }
    
    free(array);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_6() {
    float* data = (float*)malloc(20 * sizeof(float));
    if (data == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    float* copy = (float*)malloc(sizeof(data)); // Allocates only enough for a pointer
    
    free(data);
    free(copy);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_7() {
    char* str = (char*)malloc(100);
    if (str == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    char* backup = (char*)malloc(sizeof(str)); // Allocates only pointer size
    
    strcpy(str, "Hello, world!");
    strcpy(backup, str); // Potential buffer overflow
    
    free(str);
    free(backup);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_8() {
    struct Data {
        int id;
        double value;
    };
    
    struct Data* items = (struct Data*)malloc(5 * sizeof(struct Data));
    if (items == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    int itemCount = sizeof(items) / sizeof(struct Data); // Incorrect count calculation
    printf("Item count: %d\n", itemCount); // Will print incorrect value
    
    free(items);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_9() {
    long* numbers = (long*)malloc(10 * sizeof(long));
    if (numbers == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    long total_bytes = sizeof(numbers) * 10; // Calculates pointer size * 10, not actual allocation
    printf("Total bytes: %ld\n", total_bytes);
    
    free(numbers);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_10() {
    unsigned char* buffer = (unsigned char*)malloc(1024);
    if (buffer == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    unsigned char* temp = (unsigned char*)malloc(sizeof(buffer) * 2); // Allocates 2 * pointer size
    
    free(buffer);
    free(temp);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_11() {
    int* matrix = (int*)malloc(10 * 10 * sizeof(int));
    if (matrix == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    int matrix_size = sizeof(matrix); // Gets pointer size, not allocated size
    printf("Matrix size: %d bytes\n", matrix_size);
    
    free(matrix);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_12() {
    char* message = (char*)malloc(200);
    if (message == NULL) return;
    
    strcpy(message, "Important data");
    
    // ruleid: cpp-incorrect-use-of-sizeof
    char* encrypted = (char*)malloc(sizeof(message)); // Allocates only pointer size
    memcpy(encrypted, message, strlen(message)); // Potential buffer overflow
    
    free(message);
    free(encrypted);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_13() {
    struct Record {
        int id;
        char name[100];
        double salary;
    };
    
    struct Record* records = (struct Record*)malloc(50 * sizeof(struct Record));
    if (records == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    printf("Records array size: %zu\n", sizeof(records)); // Prints pointer size
    
    free(records);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_14() {
    int* counters = (int*)malloc(5 * sizeof(int));
    if (counters == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    if (sizeof(counters) >= 20) { // Comparing pointer size, not allocated size
        printf("Enough space available\n");
    }
    
    free(counters);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=1}

void bad_case_15() {
    double* prices = (double*)malloc(100 * sizeof(double));
    if (prices == NULL) return;
    
    // ruleid: cpp-incorrect-use-of-sizeof
    double* discounted = (double*)realloc(prices, sizeof(prices) * 2); // Reallocates to 2 * pointer size
    
    free(discounted != NULL ? discounted : prices);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

// True Negatives (Safe Code)

void good_case_1() {
    int* numbers = (int*)malloc(10 * sizeof(int));
    if (numbers == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    memset(numbers, 0, 10 * sizeof(int)); // Correctly uses size of allocated memory
    
    free(numbers);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_2() {
    char* buffer = (char*)malloc(100);
    if (buffer == NULL) return;
    
    char input[] = "This is a test string";
    
    // ok: cpp-incorrect-use-of-sizeof
    if (strlen(input) < 100) { // Comparing with allocated size
        strcpy(buffer, input);
    }
    
    free(buffer);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_3() {
    double* values = (double*)malloc(5 * sizeof(double));
    if (values == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    printf("Allocated memory size: %zu bytes\n", 5 * sizeof(double)); // Prints actual allocated size
    
    free(values);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_4() {
    struct Person {
        char name[50];
        int age;
    };
    
    struct Person* person = (struct Person*)malloc(sizeof(struct Person));
    if (person == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    memcpy(person, "John Doe", sizeof(*person)); // Correctly uses size of the struct
    
    free(person);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_5() {
    int* array = (int*)malloc(10 * sizeof(int));
    if (array == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    for (int i = 0; i < 10; i++) { // Correctly uses known array size
        array[i] = i;
    }
    
    free(array);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_6() {
    float* data = (float*)malloc(20 * sizeof(float));
    if (data == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    float* copy = (float*)malloc(20 * sizeof(float)); // Correctly allocates same size
    
    free(data);
    free(copy);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_7() {
    char* str = (char*)malloc(100);
    if (str == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    char* backup = (char*)malloc(100); // Allocates correct size
    
    strcpy(str, "Hello, world!");
    strcpy(backup, str);
    
    free(str);
    free(backup);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_8() {
    struct Data {
        int id;
        double value;
    };
    
    struct Data* items = (struct Data*)malloc(5 * sizeof(struct Data));
    if (items == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    int itemCount = 5; // Correctly uses known count
    printf("Item count: %d\n", itemCount);
    
    free(items);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_9() {
    long* numbers = (long*)malloc(10 * sizeof(long));
    if (numbers == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    long total_bytes = sizeof(*numbers) * 10; // Correctly calculates size of allocation
    printf("Total bytes: %ld\n", total_bytes);
    
    free(numbers);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_10() {
    unsigned char* buffer = (unsigned char*)malloc(1024);
    if (buffer == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    unsigned char* temp = (unsigned char*)malloc(1024 * 2); // Correctly allocates double the size
    
    free(buffer);
    free(temp);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_11() {
    int* matrix = (int*)malloc(10 * 10 * sizeof(int));
    if (matrix == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    int matrix_size = 10 * 10 * sizeof(int); // Gets actual allocated size
    printf("Matrix size: %d bytes\n", matrix_size);
    
    free(matrix);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_12() {
    char* message = (char*)malloc(200);
    if (message == NULL) return;
    
    strcpy(message, "Important data");
    
    // ok: cpp-incorrect-use-of-sizeof
    char* encrypted = (char*)malloc(200); // Allocates correct size
    memcpy(encrypted, message, strlen(message) + 1);
    
    free(message);
    free(encrypted);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_13() {
    struct Record {
        int id;
        char name[100];
        double salary;
    };
    
    struct Record* records = (struct Record*)malloc(50 * sizeof(struct Record));
    if (records == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    printf("Records array size: %zu\n", 50 * sizeof(struct Record)); // Prints actual size
    
    free(records);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_14() {
    int* counters = (int*)malloc(5 * sizeof(int));
    if (counters == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    if (5 * sizeof(int) >= 20) { // Comparing actual allocated size
        printf("Enough space available\n");
    }
    
    free(counters);
}
// {/fact}
// {fact rule=incorrect-use-of-sizeof@v1.0 defects=0}

void good_case_15() {
    double* prices = (double*)malloc(100 * sizeof(double));
    if (prices == NULL) return;
    
    // ok: cpp-incorrect-use-of-sizeof
    double* discounted = (double*)realloc(prices, 200 * sizeof(double)); // Correctly reallocates to double the size
    
    free(discounted != NULL ? discounted : prices);
}
// {/fact}

int main() {
    // Function calls could go here for testing
    return 0;
}