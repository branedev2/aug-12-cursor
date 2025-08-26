#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <new>
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

// TRUE POSITIVES - Vulnerable code examples

void bad_case_1() {
    int *array;
    size_t size = 1000000;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    array = (int*)malloc(size * sizeof(int));
    
    // Using the pointer without checking if malloc succeeded
    array[0] = 42;
    
    free(array);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_2() {
    char *buffer;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    buffer = (char*)calloc(1024, sizeof(char));
    
    // Using the pointer without checking if calloc succeeded
    strcpy(buffer, "Hello, world!");
    printf("%s\n", buffer);
    
    free(buffer);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_3() {
    int *data = (int*)malloc(10 * sizeof(int));
    
    // Initialize data
    for (int i = 0; i < 10; i++) {
        data[i] = i;
    }
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    data = (int*)realloc(data, 20 * sizeof(int));
    
    // Using the pointer without checking if realloc succeeded
    data[15] = 100;
    
    free(data);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_4() {
    size_t large_size = 1024 * 1024 * 1024; // 1 GB
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    char *large_buffer = (char*)malloc(large_size);
    
    // Using buffer without checking allocation success
    memset(large_buffer, 0, large_size);
    
    free(large_buffer);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_5() {
    FILE *fp = fopen("data.txt", "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        rewind(fp);
        
        // ruleid: cpp-unchecked-malloc-calloc-realloc
        char *file_contents = (char*)malloc(file_size + 1);
        
        // Using pointer without checking
        fread(file_contents, 1, file_size, fp);
        file_contents[file_size] = '\0';
        printf("File contents: %s\n", file_contents);
        
        free(file_contents);
        fclose(fp);
    }
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_6() {
    int rows = 10, cols = 10;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    int **matrix = (int**)malloc(rows * sizeof(int*));
    
    for (int i = 0; i < rows; i++) {
        // ruleid: cpp-unchecked-malloc-calloc-realloc
        matrix[i] = (int*)malloc(cols * sizeof(int));
        
        // Using without checking
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i * j;
        }
    }
    
    // Cleanup
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_7() {
    int *array = (int*)malloc(10 * sizeof(int));
    
    // Initialize array
    for (int i = 0; i < 10; i++) {
        array[i] = i;
    }
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    int *temp = (int*)realloc(array, 20 * sizeof(int));
    
    // Directly reassigning without checking
    array = temp;
    
    // Using the potentially NULL pointer
    array[15] = 42;
    
    free(array);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_8() {
    struct Person {
        char name[50];
        int age;
    };
    
    int count = 100;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    struct Person *people = (struct Person*)calloc(count, sizeof(struct Person));
    
    // Using without checking
    strcpy(people[0].name, "John");
    people[0].age = 30;
    
    free(people);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_9() {
    char *str;
    const char *source = "Hello, world!";
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    str = (char*)malloc(strlen(source) + 1);
    
    // Using without checking
    strcpy(str, source);
    printf("%s\n", str);
    
    free(str);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_10() {
    int size = 1000;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    float *data = (float*)malloc(size * sizeof(float));
    
    // Complex calculation without checking allocation
    for (int i = 0; i < size; i++) {
        data[i] = (float)i / (i + 1);
    }
    
    free(data);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_11() {
    char *old_str = (char*)malloc(10);
    strcpy(old_str, "Hello");
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    char *new_str = (char*)realloc(old_str, 20);
    
    // Using without checking
    strcat(new_str, " World");
    printf("%s\n", new_str);
    
    free(new_str);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_12() {
    size_t num_elements = 1000000;
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    double *values = (double*)calloc(num_elements, sizeof(double));
    
    // Using without checking
    for (size_t i = 0; i < num_elements; i++) {
        values[i] = i * 3.14;
    }
    
    free(values);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_13() {
    struct Node {
        int data;
        struct Node* next;
    };
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    struct Node* head = (struct Node*)malloc(sizeof(struct Node));
    
    // Using without checking
    head->data = 1;
    head->next = NULL;
    
    free(head);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_14() {
    int *ptr = NULL;
    size_t current_size = 0;
    
    for (int i = 0; i < 10; i++) {
        // ruleid: cpp-unchecked-malloc-calloc-realloc
        ptr = (int*)realloc(ptr, (current_size + 10) * sizeof(int));
        
        // Using without checking
        for (size_t j = current_size; j < current_size + 10; j++) {
            ptr[j] = j;
        }
        
        current_size += 10;
    }
    
    free(ptr);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=1}

void bad_case_15() {
    // Dynamic allocation for a string
    const char* input = "This is a test string that needs to be copied";
    
    // ruleid: cpp-unchecked-malloc-calloc-realloc
    char* copy = (char*)malloc(strlen(input) + 1);
    
    // Using without checking
    strcpy(copy, input);
    printf("Copied string: %s\n", copy);
    
    free(copy);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

// TRUE NEGATIVES - Safe code examples

void good_case_1() {
    int *array;
    size_t size = 1000000;
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    array = (int*)malloc(size * sizeof(int));
    if (array == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    array[0] = 42;
    
    free(array);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_2() {
    char *buffer;
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    buffer = (char*)calloc(1024, sizeof(char));
    if (buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    strcpy(buffer, "Hello, world!");
    printf("%s\n", buffer);
    
    free(buffer);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_3() {
    int *data = (int*)malloc(10 * sizeof(int));
    if (data == NULL) {
        fprintf(stderr, "Initial memory allocation failed\n");
        return;
    }
    
    // Initialize data
    for (int i = 0; i < 10; i++) {
        data[i] = i;
    }
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    int *new_data = (int*)realloc(data, 20 * sizeof(int));
    if (new_data == NULL) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(data);  // Free the original memory
        return;
    }
    
    data = new_data;
    data[15] = 100;
    
    free(data);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_4() {
    size_t large_size = 1024 * 1024 * 1024; // 1 GB
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    char *large_buffer = (char*)malloc(large_size);
    if (large_buffer == NULL) {
        fprintf(stderr, "Failed to allocate large buffer\n");
        return;
    }
    
    memset(large_buffer, 0, large_size);
    
    free(large_buffer);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_5() {
    FILE *fp = fopen("data.txt", "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        rewind(fp);
        
        // ok: cpp-unchecked-malloc-calloc-realloc
        char *file_contents = (char*)malloc(file_size + 1);
        if (file_contents == NULL) {
            fprintf(stderr, "Failed to allocate memory for file contents\n");
            fclose(fp);
            return;
        }
        
        fread(file_contents, 1, file_size, fp);
        file_contents[file_size] = '\0';
        printf("File contents: %s\n", file_contents);
        
        free(file_contents);
        fclose(fp);
    }
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_6() {
    int rows = 10, cols = 10;
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    int **matrix = (int**)malloc(rows * sizeof(int*));
    if (matrix == NULL) {
        fprintf(stderr, "Failed to allocate memory for matrix rows\n");
        return;
    }
    
    for (int i = 0; i < rows; i++) {
        // ok: cpp-unchecked-malloc-calloc-realloc
        matrix[i] = (int*)malloc(cols * sizeof(int));
        if (matrix[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory for matrix column %d\n", i);
            // Free previously allocated memory
            for (int j = 0; j < i; j++) {
                free(matrix[j]);
            }
            free(matrix);
            return;
        }
        
        for (int j = 0; j < cols; j++) {
            matrix[i][j] = i * j;
        }
    }
    
    // Cleanup
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_7() {
    // Using C++ new with exception handling instead of malloc
    try {
        // ok: cpp-unchecked-malloc-calloc-realloc
        int *array = new int[1000000];
        
        // Use the array
        array[0] = 42;
        
        delete[] array;
    } catch (const std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_8() {
    struct Person {
        char name[50];
        int age;
    };
    
    int count = 100;
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    struct Person *people = (struct Person*)calloc(count, sizeof(struct Person));
    if (people == NULL) {
        fprintf(stderr, "Failed to allocate memory for people\n");
        return;
    }
    
    strcpy(people[0].name, "John");
    people[0].age = 30;
    
    free(people);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_9() {
    char *str;
    const char *source = "Hello, world!";
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    str = (char*)malloc(strlen(source) + 1);
    if (!str) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    strcpy(str, source);
    printf("%s\n", str);
    
    free(str);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_10() {
    // Using std::vector instead of manual memory management
    // ok: cpp-unchecked-malloc-calloc-realloc
    std::vector<float> data(1000);
    
    for (int i = 0; i < 1000; i++) {
        data[i] = (float)i / (i + 1);
    }
    
    // No need to free - vector handles memory management
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_11() {
    char *old_str = (char*)malloc(10);
    if (old_str == NULL) {
        fprintf(stderr, "Initial allocation failed\n");
        return;
    }
    
    strcpy(old_str, "Hello");
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    char *new_str = (char*)realloc(old_str, 20);
    if (new_str == NULL) {
        fprintf(stderr, "Reallocation failed\n");
        free(old_str);  // Don't forget to free the original memory
        return;
    }
    
    strcat(new_str, " World");
    printf("%s\n", new_str);
    
    free(new_str);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_12() {
    size_t num_elements = 1000000;
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    double *values = (double*)calloc(num_elements, sizeof(double));
    if (values == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    for (size_t i = 0; i < num_elements; i++) {
        values[i] = i * 3.14;
    }
    
    free(values);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_13() {
    struct Node {
        int data;
        struct Node* next;
    };
    
    // ok: cpp-unchecked-malloc-calloc-realloc
    struct Node* head = (struct Node*)malloc(sizeof(struct Node));
    if (head == NULL) {
        fprintf(stderr, "Failed to allocate memory for node\n");
        return;
    }
    
    head->data = 1;
    head->next = NULL;
    
    free(head);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_14() {
    int *ptr = NULL;
    int *temp = NULL;
    size_t current_size = 0;
    
    for (int i = 0; i < 10; i++) {
        // ok: cpp-unchecked-malloc-calloc-realloc
        temp = (int*)realloc(ptr, (current_size + 10) * sizeof(int));
        if (temp == NULL) {
            fprintf(stderr, "Memory reallocation failed\n");
            free(ptr);  // Free the original memory
            return;
        }
        
        ptr = temp;
        
        for (size_t j = current_size; j < current_size + 10; j++) {
            ptr[j] = j;
        }
        
        current_size += 10;
    }
    
    free(ptr);
}
// {/fact}
// {fact rule=missing-check-on-method-output@v1.0 defects=0}

void good_case_15() {
    // Using std::string instead of manual memory management
    // ok: cpp-unchecked-malloc-calloc-realloc
    const char* input = "This is a test string that needs to be copied";
    std::string copy(input);
    
    std::cout << "Copied string: " << copy << std::endl;
    
    // No need to free - string handles memory management
}
// {/fact}

int main() {
    // This function is just a placeholder to make the file compilable
    return 0;
}