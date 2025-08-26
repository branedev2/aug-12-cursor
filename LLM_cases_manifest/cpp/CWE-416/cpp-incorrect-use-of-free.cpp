#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
// {fact rule=use-after-free@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Basic double free
void bad_case_1() {
    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    
    free(ptr);
    // ruleid: cpp-incorrect-use-of-free
    free(ptr); // Double free vulnerability
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 2: Use after free
void bad_case_2() {
    char* buffer = (char*)malloc(100);
    strcpy(buffer, "Hello, World!");
    
    free(buffer);
    
    // ruleid: cpp-incorrect-use-of-free
    std::cout << "Buffer content: " << buffer << std::endl; // Use after free
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 3: Double free in conditional branch
void bad_case_3(bool condition) {
    int* data = (int*)malloc(sizeof(int));
    *data = 100;
    
    if (condition) {
        free(data);
    }
    
    // Other operations...
    
    // ruleid: cpp-incorrect-use-of-free
    free(data); // Potential double free if condition was true
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 4: Use after free in loop
void bad_case_4() {
    int* numbers = (int*)malloc(5 * sizeof(int));
    
    for (int i = 0; i < 5; i++) {
        numbers[i] = i * 10;
    }
    
    free(numbers);
    
    for (int i = 0; i < 5; i++) {
        // ruleid: cpp-incorrect-use-of-free
        std::cout << "Value: " << numbers[i] << std::endl; // Use after free
    }
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 5: Double free with multiple pointers
void bad_case_5() {
    int* ptr1 = (int*)malloc(sizeof(int));
    int* ptr2 = ptr1; // Both point to the same memory
    
    *ptr1 = 42;
    
    free(ptr1);
    // ruleid: cpp-incorrect-use-of-free
    free(ptr2); // Double free through alias
}
// {/fact}

// Example 6: Use after free with function call
void process_data(int* data) {
    std::cout << "Processing: " << *data << std::endl;
}
// {fact rule=use-after-free@v1.0 defects=1}

void bad_case_6() {
    int* value = (int*)malloc(sizeof(int));
    *value = 100;
    
    free(value);
    
    // ruleid: cpp-incorrect-use-of-free
    process_data(value); // Use after free
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 7: Double free in error handling
void bad_case_7() {
    char* buffer = NULL;
    
    try {
        buffer = (char*)malloc(1024);
        // Some operations that might throw
        throw std::runtime_error("Error occurred");
    }
    catch (const std::exception& e) {
        free(buffer);
        // Handle error
    }
    
    // ruleid: cpp-incorrect-use-of-free
    free(buffer); // Potential double free if exception was thrown
}
// {/fact}

// Example 8: Use after free with struct
struct Person {
    char* name;
    int age;
};
// {fact rule=use-after-free@v1.0 defects=1}

void bad_case_8() {
    Person* person = (Person*)malloc(sizeof(Person));
    person->name = (char*)malloc(50);
    strcpy(person->name, "John Doe");
    person->age = 30;
    
    free(person->name);
    
    // ruleid: cpp-incorrect-use-of-free
    std::cout << "Name: " << person->name << std::endl; // Use after free
    
    free(person);
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 9: Double free in complex control flow
void bad_case_9(int option) {
    int* data = (int*)malloc(sizeof(int));
    *data = 42;
    
    switch (option) {
        case 1:
            // Some operations
            free(data);
            break;
        case 2:
            // Different operations
            break;
        default:
            // More operations
            break;
    }
    
    // ruleid: cpp-incorrect-use-of-free
    free(data); // Potential double free if option was 1
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 10: Use after free with array indexing
void bad_case_10() {
    int* array = (int*)malloc(10 * sizeof(int));
    
    for (int i = 0; i < 10; i++) {
        array[i] = i * i;
    }
    
    free(array);
    
    // ruleid: cpp-incorrect-use-of-free
    int value = array[5]; // Use after free
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 11: Double free with realloc
void bad_case_11() {
    int* buffer = (int*)malloc(5 * sizeof(int));
    
    // Use buffer...
    
    int* new_buffer = (int*)realloc(buffer, 10 * sizeof(int));
    
    // ruleid: cpp-incorrect-use-of-free
    free(buffer); // Double free - buffer is either freed by realloc or is the same as new_buffer
    
    free(new_buffer);
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 12: Use after free with pointer arithmetic
void bad_case_12() {
    char* str = (char*)malloc(100);
    strcpy(str, "Hello, World!");
    
    char* ptr = str + 7; // Points to "World!"
    
    free(str);
    
    // ruleid: cpp-incorrect-use-of-free
    std::cout << "Substring: " << ptr << std::endl; // Use after free
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 13: Double free in nested conditions
void bad_case_13(bool condition1, bool condition2) {
    void* memory = malloc(1024);
    
    if (condition1) {
        if (condition2) {
            free(memory);
        }
        // Other operations
    }
    
    // ruleid: cpp-incorrect-use-of-free
    free(memory); // Potential double free if both conditions were true
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=1}

// Example 14: Use after free with function pointer
void bad_case_14() {
    typedef void (*FunctionPtr)();
    
    FunctionPtr* function_table = (FunctionPtr*)malloc(5 * sizeof(FunctionPtr));
    
    // Initialize function table...
    
    free(function_table);
    
    // ruleid: cpp-incorrect-use-of-free
    FunctionPtr func = function_table[2]; // Use after free
    func(); // Potentially dangerous call
}
// {/fact}

// Example 15: Double free with custom deallocator
void custom_free(void* ptr) {
    free(ptr);
}
// {fact rule=use-after-free@v1.0 defects=1}

void bad_case_15() {
    int* data = (int*)malloc(sizeof(int));
    *data = 100;
    
    free(data);
    
    // ruleid: cpp-incorrect-use-of-free
    custom_free(data); // Double free through custom function
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// TRUE NEGATIVES (Safe Code Examples)

// Example 1: Proper memory management with malloc/free
void good_case_1() {
    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    
    // ok: cpp-incorrect-use-of-free
    free(ptr);
    ptr = NULL; // Set to NULL after freeing
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 2: Using smart pointers
void good_case_2() {
    // ok: cpp-incorrect-use-of-free
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    // Memory automatically freed when ptr goes out of scope
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 3: Proper conditional freeing
void good_case_3(bool condition) {
    int* data = (int*)malloc(sizeof(int));
    *data = 100;
    
    if (condition) {
        // ok: cpp-incorrect-use-of-free
        free(data);
        data = NULL;
    } else {
        // ok: cpp-incorrect-use-of-free
        free(data);
        data = NULL;
    }
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 4: Safe memory management in loops
void good_case_4() {
    int* numbers = (int*)malloc(5 * sizeof(int));
    
    for (int i = 0; i < 5; i++) {
        numbers[i] = i * 10;
    }
    
    // Process the data while it's still valid
    for (int i = 0; i < 5; i++) {
        std::cout << "Value: " << numbers[i] << std::endl;
    }
    
    // ok: cpp-incorrect-use-of-free
    free(numbers);
    numbers = NULL;
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 5: Safe handling of multiple pointers
void good_case_5() {
    int* ptr1 = (int*)malloc(sizeof(int));
    int* ptr2 = ptr1; // Both point to the same memory
    
    *ptr1 = 42;
    
    // ok: cpp-incorrect-use-of-free
    free(ptr1);
    ptr1 = NULL;
    ptr2 = NULL; // Also update the alias
}
// {/fact}

// Example 6: Safe function call pattern
void safe_process_data(int value) {
    std::cout << "Processing: " << value << std::endl;
}
// {fact rule=use-after-free@v1.0 defects=0}

void good_case_6() {
    int* value = (int*)malloc(sizeof(int));
    *value = 100;
    
    // Copy the value before freeing
    int safe_value = *value;
    
    // ok: cpp-incorrect-use-of-free
    free(value);
    value = NULL;
    
    safe_process_data(safe_value); // Safe use of the data
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 7: Proper error handling with memory
void good_case_7() {
    char* buffer = NULL;
    
    try {
        buffer = (char*)malloc(1024);
        // Some operations that might throw
        throw std::runtime_error("Error occurred");
    }
    catch (const std::exception& e) {
        // ok: cpp-incorrect-use-of-free
        free(buffer);
        buffer = NULL;
        // Handle error
    }
    
    // No second free here
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 8: Safe struct memory management
void good_case_8() {
    Person* person = (Person*)malloc(sizeof(Person));
    person->name = (char*)malloc(50);
    strcpy(person->name, "John Doe");
    person->age = 30;
    
    // Make a copy if needed
    std::string name_copy = person->name;
    
    // ok: cpp-incorrect-use-of-free
    free(person->name);
    free(person);
    
    std::cout << "Name (copy): " << name_copy << std::endl; // Safe use of copied data
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 9: Safe complex control flow
void good_case_9(int option) {
    int* data = (int*)malloc(sizeof(int));
    *data = 42;
    bool is_freed = false;
    
    switch (option) {
        case 1:
            // Some operations
            // ok: cpp-incorrect-use-of-free
            free(data);
            is_freed = true;
            break;
        case 2:
            // Different operations
            break;
        default:
            // More operations
            break;
    }
    
    if (!is_freed) {
        // ok: cpp-incorrect-use-of-free
        free(data);
    }
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 10: Safe array handling
void good_case_10() {
    int* array = (int*)malloc(10 * sizeof(int));
    
    for (int i = 0; i < 10; i++) {
        array[i] = i * i;
    }
    
    // Copy needed values before freeing
    int value_copy = array[5];
    
    // ok: cpp-incorrect-use-of-free
    free(array);
    array = NULL;
    
    std::cout << "Value (copy): " << value_copy << std::endl; // Safe use of copied data
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 11: Safe use of realloc
void good_case_11() {
    int* buffer = (int*)malloc(5 * sizeof(int));
    
    // Use buffer...
    
    // ok: cpp-incorrect-use-of-free
    int* new_buffer = (int*)realloc(buffer, 10 * sizeof(int));
    if (new_buffer == NULL) {
        free(buffer); // Only free the original if realloc failed
        return;
    }
    
    // Use new_buffer...
    
    free(new_buffer);
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 12: Safe pointer arithmetic
void good_case_12() {
    char* str = (char*)malloc(100);
    strcpy(str, "Hello, World!");
    
    // Copy the substring before freeing
    std::string world_copy = str + 7;
    
    // ok: cpp-incorrect-use-of-free
    free(str);
    str = NULL;
    
    std::cout << "Substring (copy): " << world_copy << std::endl; // Safe use of copied data
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 13: Safe nested conditions
void good_case_13(bool condition1, bool condition2) {
    void* memory = malloc(1024);
    bool memory_freed = false;
    
    if (condition1) {
        if (condition2) {
            // ok: cpp-incorrect-use-of-free
            free(memory);
            memory_freed = true;
        }
        // Other operations
    }
    
    if (!memory_freed) {
        // ok: cpp-incorrect-use-of-free
        free(memory);
    }
}
// {/fact}
// {fact rule=use-after-free@v1.0 defects=0}

// Example 14: Safe function table handling
void good_case_14() {
    typedef void (*FunctionPtr)();
    
    FunctionPtr* function_table = (FunctionPtr*)malloc(5 * sizeof(FunctionPtr));
    
    // Initialize function table...
    
    // Copy any needed function pointers before freeing
    FunctionPtr func_copy = function_table[2];
    
    // ok: cpp-incorrect-use-of-free
    free(function_table);
    function_table = NULL;
    
    if (func_copy) {
        func_copy(); // Safe call to copied function pointer
    }
}
// {/fact}

// Example 15: Using RAII pattern with custom class
class Resource {
private:
    int* data;
    
public:
    Resource() {
        data = (int*)malloc(sizeof(int));
        *data = 42;
    }
    
    ~Resource() {
        // ok: cpp-incorrect-use-of-free
        free(data);
        data = NULL;
    }
    
    int getValue() const {
        return *data;
    }
};
// {fact rule=use-after-free@v1.0 defects=0}

void good_case_15() {
    {
        Resource res; // Resource automatically managed
        std::cout << "Value: " << res.getValue() << std::endl;
    } // Resource automatically freed when res goes out of scope
}
// {/fact}