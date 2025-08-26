#include <iostream>
#include <string>
#include <vector>
#include <memory>
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable code that should be detected)

// Example 1: Basic case of returning address of local variable
int* bad_case_1() {
    int x = 10;
    // ruleid: cpp-return-stack-address
    return &x; // Returns address of stack variable which will be invalid after function returns
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 2: Returning address of local array
int* bad_case_2() {
    int numbers[5] = {1, 2, 3, 4, 5};
    // ruleid: cpp-return-stack-address
    return numbers; // Arrays decay to pointers, returning address of stack array
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 3: Returning address of function parameter (which is on stack)
int* bad_case_3(int x) {
    // ruleid: cpp-return-stack-address
    return &x; // Function parameter is also allocated on stack
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 4: Returning address of local variable in a nested scope
int* bad_case_4() {
    if (true) {
        int y = 20;
        // ruleid: cpp-return-stack-address
        return &y; // Local variable in nested scope is still on stack
    }
    return nullptr;
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 5: Returning address of local variable in a loop
int* bad_case_5() {
    for (int i = 0; i < 5; i++) {
        int z = i * 10;
        if (i == 3) {
            // ruleid: cpp-return-stack-address
            return &z; // Local variable in loop is on stack
        }
    }
    return nullptr;
}
// {/fact}

// Example 6: Returning address of local struct
struct Point {
    int x, y;
};
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

Point* bad_case_6() {
    Point p = {10, 20};
    // ruleid: cpp-return-stack-address
    return &p; // Local struct is on stack
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 7: Returning address of local variable through conditional
int* bad_case_7(bool condition) {
    int a = 10;
    int b = 20;
    // ruleid: cpp-return-stack-address
    return condition ? &a : &b; // Both variables are on stack
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 8: Returning address of local string
std::string* bad_case_8() {
    std::string message = "Hello, World!";
    // ruleid: cpp-return-stack-address
    return &message; // Local string object is on stack
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 9: Returning address of local variable through another pointer
int* bad_case_9() {
    int value = 42;
    int* ptr = &value;
    // ruleid: cpp-return-stack-address
    return ptr; // ptr points to stack variable
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 10: Returning address of local variable in a switch statement
int* bad_case_10(int choice) {
    switch (choice) {
        case 1: {
            int result = 100;
            // ruleid: cpp-return-stack-address
            return &result; // Local variable in switch case is on stack
        }
        default:
            return nullptr;
    }
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 11: Returning address of local vector element
int* bad_case_11() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    // ruleid: cpp-return-stack-address
    return &vec[0]; // Vector is on stack, so its elements are too
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 12: Returning address of local variable through multiple indirection
int* bad_case_12() {
    int value = 100;
    int* ptr1 = &value;
    int** ptr2 = &ptr1;
    // ruleid: cpp-return-stack-address
    return *ptr2; // Ultimately points to stack variable
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 13: Returning address of function-local static array element
int* bad_case_13() {
    int arr[3] = {10, 20, 30};
    // ruleid: cpp-return-stack-address
    return &arr[1]; // Array element address is on stack
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

// Example 14: Returning address of local variable in a try-catch block
int* bad_case_14() {
    try {
        int result = 42;
        // ruleid: cpp-return-stack-address
        return &result; // Local variable in try block is on stack
    } catch (...) {
        return nullptr;
    }
}
// {/fact}

// Example 15: Returning address of local variable through a function call
int* getLocalAddress(int& ref) {
    return &ref;
}
// {fact rule=return-of-stack-variable-address@v1.0 defects=1}

int* bad_case_15() {
    int local = 42;
    // ruleid: cpp-return-stack-address
    return getLocalAddress(local); // Indirectly returns address of stack variable
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// TRUE NEGATIVES (Safe code that should not be detected)

// Example 1: Returning a heap-allocated variable
int* good_case_1() {
    // ok: cpp-return-stack-address
    int* ptr = new int(10); // Allocated on heap
    return ptr;
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 2: Returning address of static variable
int* good_case_2() {
    static int x = 10;
    // ok: cpp-return-stack-address
    return &x; // Static variables have program lifetime
}
// {/fact}

// Example 3: Returning address of global variable
int globalVar = 42;
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}
int* good_case_3() {
    // ok: cpp-return-stack-address
    return &globalVar; // Global variables have program lifetime
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 4: Returning a pointer passed as parameter
int* good_case_4(int* ptr) {
    // ok: cpp-return-stack-address
    return ptr; // Not returning address of local stack variable
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 5: Returning nullptr
int* good_case_5() {
    // ok: cpp-return-stack-address
    return nullptr; // Not returning any address
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 6: Returning a smart pointer to heap-allocated memory
std::shared_ptr<int> good_case_6() {
    // ok: cpp-return-stack-address
    return std::make_shared<int>(42); // Smart pointer to heap memory
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 7: Returning a unique pointer to heap-allocated memory
std::unique_ptr<int> good_case_7() {
    // ok: cpp-return-stack-address
    return std::make_unique<int>(42); // Unique pointer to heap memory
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 8: Returning by value instead of address
int good_case_8() {
    int x = 10;
    // ok: cpp-return-stack-address
    return x; // Returning by value, not address
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 9: Returning address of static array
int* good_case_9() {
    static int arr[5] = {1, 2, 3, 4, 5};
    // ok: cpp-return-stack-address
    return arr; // Static array has program lifetime
}
// {/fact}

// Example 10: Returning address from a static member variable
class Example {
public:
    static int value;
    static int* getValue() {
        // ok: cpp-return-stack-address
        return &value; // Static member has program lifetime
    }
};
int Example::value = 42;
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

int* good_case_10() {
    return Example::getValue();
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 11: Returning a copy of a pointer to heap memory
int* good_case_11() {
    int* heapPtr = new int(42);
    // ok: cpp-return-stack-address
    int* result = heapPtr; // Copying pointer to heap memory
    return result;
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 12: Returning address of memory from a custom allocator
int* good_case_12() {
    // ok: cpp-return-stack-address
    int* ptr = (int*)malloc(sizeof(int)); // Allocated on heap
    *ptr = 42;
    return ptr;
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 13: Returning a reference to static data
std::string& good_case_13() {
    static std::string data = "Hello, World!";
    // ok: cpp-return-stack-address
    return data; // Static data has program lifetime
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 14: Returning pointer to string literal (which has static lifetime)
const char* good_case_14() {
    // ok: cpp-return-stack-address
    return "Hello, World!"; // String literals have static lifetime
}
// {/fact}
// {fact rule=return-of-stack-variable-address@v1.0 defects=0}

// Example 15: Returning pointer to static const data
int* good_case_15() {
    static const int values[] = {1, 2, 3, 4, 5};
    // ok: cpp-return-stack-address
    return const_cast<int*>(values); // Static data has program lifetime
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "Test cases for returning stack addresses" << std::endl;
    return 0;
}