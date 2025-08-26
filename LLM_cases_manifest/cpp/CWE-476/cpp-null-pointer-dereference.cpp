#include <iostream>
#include <string>
#include <cstdlib>
#include <memory>
#include <vector>
#include <fstream>
// {fact rule=inconsistent-null-check@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    int* ptr = nullptr;
    // ruleid: cpp-null-pointer-dereference
    *ptr = 42; // Dereferencing null pointer directly
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_2() {
    int* ptr = NULL;
    if (rand() % 2) {
        ptr = new int(10);
    }
    // ruleid: cpp-null-pointer-dereference
    std::cout << "Value: " << *ptr << std::endl; // Potential null dereference if rand() % 2 == 0
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_3() {
    int* ptr = nullptr;
    int* ptr2 = ptr;
    // ruleid: cpp-null-pointer-dereference
    *ptr2 = 100; // Dereferencing null pointer through another pointer
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_4() {
    struct Node {
        int data;
        Node* next;
    };
    
    Node* head = nullptr;
    // ruleid: cpp-null-pointer-dereference
    head->data = 5; // Accessing member of null struct pointer
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_5() {
    int* arr[3] = {nullptr, new int(5), new int(10)};
    // ruleid: cpp-null-pointer-dereference
    std::cout << *arr[0] << std::endl; // Dereferencing null pointer in array
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_6() {
    int* ptr = new int(5);
    delete ptr;
    // ruleid: cpp-null-pointer-dereference
    *ptr = 10; // Use after free (ptr is dangling)
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_7() {
    int* ptr = nullptr;
    void* vptr = ptr;
    // ruleid: cpp-null-pointer-dereference
    *static_cast<int*>(vptr) = 42; // Null dereference after type casting
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_8() {
    class Example {
    public:
        void doSomething() { std::cout << "Doing something" << std::endl; }
    };
    
    Example* obj = nullptr;
    // ruleid: cpp-null-pointer-dereference
    obj->doSomething(); // Calling method on null object
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_9() {
    int* ptr = nullptr;
    int& ref = *ptr; // Creating reference from null pointer
    // ruleid: cpp-null-pointer-dereference
    ref = 10; // Using the reference (equivalent to dereferencing null)
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_10() {
    struct Data {
        int value;
        void setValue(int v) { value = v; }
    };
    
    Data* data = nullptr;
    // ruleid: cpp-null-pointer-dereference
    data->setValue(100); // Calling method on null struct
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_11() {
    int** pptr = new int*;
    *pptr = nullptr;
    // ruleid: cpp-null-pointer-dereference
    **pptr = 42; // Double dereferencing with null at second level
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_12() {
    auto func = [](int* p) {
        // ruleid: cpp-null-pointer-dereference
        return *p + 5; // Dereferencing potentially null pointer in lambda
    };
    
    func(nullptr);
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_13() {
    std::vector<int*> vec = {nullptr, new int(5)};
    // ruleid: cpp-null-pointer-dereference
    std::cout << *vec[0] << std::endl; // Dereferencing null pointer in vector
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_14() {
    int* ptr = nullptr;
    for (int i = 0; i < 5; i++) {
        if (i == 3) {
            ptr = new int(i);
        }
    }
    // ruleid: cpp-null-pointer-dereference
    *ptr = 100; // Potential null dereference if loop is modified
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

void bad_case_15() {
    std::ifstream file("nonexistent.txt");
    char* buffer = nullptr;
    if (file) {
        buffer = new char[100];
    }
    file.close();
    // ruleid: cpp-null-pointer-dereference
    buffer[0] = 'A'; // Dereferencing potentially null pointer
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    int* ptr = nullptr;
    // ok: cpp-null-pointer-dereference
    if (ptr != nullptr) {
        *ptr = 42; // Safe: null check before dereferencing
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_2() {
    int* ptr = NULL;
    if (rand() % 2) {
        ptr = new int(10);
    }
    // ok: cpp-null-pointer-dereference
    if (ptr) {
        std::cout << "Value: " << *ptr << std::endl; // Safe: null check before dereferencing
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_3() {
    int* ptr = nullptr;
    // ok: cpp-null-pointer-dereference
    ptr = new int(100); // Initialize before use
    *ptr = 100;
    delete ptr;
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_4() {
    struct Node {
        int data;
        Node* next;
    };
    
    Node* head = nullptr;
    // ok: cpp-null-pointer-dereference
    if (head) {
        head->data = 5; // Safe: null check before accessing member
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_5() {
    int* arr[3] = {nullptr, new int(5), new int(10)};
    // ok: cpp-null-pointer-dereference
    for (int i = 0; i < 3; i++) {
        if (arr[i]) {
            std::cout << *arr[i] << std::endl; // Safe: null check before dereferencing
        }
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_6() {
    int* ptr = new int(5);
    delete ptr;
    // ok: cpp-null-pointer-dereference
    ptr = nullptr; // Set to nullptr after free
    if (ptr) {
        *ptr = 10; // This won't execute
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_7() {
    int defaultValue = 42;
    int* ptr = nullptr;
    // ok: cpp-null-pointer-dereference
    int value = ptr ? *ptr : defaultValue; // Safe: conditional operator to handle null
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_8() {
    class Example {
    public:
        void doSomething() { std::cout << "Doing something" << std::endl; }
    };
    
    Example* obj = nullptr;
    // ok: cpp-null-pointer-dereference
    if (obj != nullptr) {
        obj->doSomething(); // Safe: null check before method call
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_9() {
    int defaultValue = 10;
    int* ptr = nullptr;
    // ok: cpp-null-pointer-dereference
    ptr = new int(defaultValue); // Initialize before creating reference
    int& ref = *ptr;
    ref = 20;
    delete ptr;
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_10() {
    struct Data {
        int value;
        void setValue(int v) { value = v; }
    };
    
    Data* data = new Data();
    // ok: cpp-null-pointer-dereference
    if (data) {
        data->setValue(100); // Safe: object is properly initialized
    }
    delete data;
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_11() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    // ok: cpp-null-pointer-dereference
    *ptr = 100; // Safe: smart pointer guarantees non-null
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_12() {
    auto func = [](int* p) {
        // ok: cpp-null-pointer-dereference
        if (p) {
            return *p + 5; // Safe: null check before dereferencing in lambda
        }
        return 0;
    };
    
    int value = 42;
    func(&value);
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_13() {
    std::vector<int*> vec = {nullptr, new int(5)};
    // ok: cpp-null-pointer-dereference
    for (auto ptr : vec) {
        if (ptr) {
            std::cout << *ptr << std::endl; // Safe: null check before dereferencing
        }
    }
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_14() {
    int defaultValue = 0;
    int* ptr = nullptr;
    // ok: cpp-null-pointer-dereference
    ptr = new int(defaultValue); // Always initialize
    *ptr = 100;
    delete ptr;
}
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

void good_case_15() {
    std::ifstream file("nonexistent.txt");
    char* buffer = nullptr;
    // ok: cpp-null-pointer-dereference
    if (file) {
        buffer = new char[100];
        buffer[0] = 'A'; // Safe: only access after allocation
    }
    if (buffer) {
        delete[] buffer;
    }
    file.close();
}
// {/fact}

int main() {
    // This function is just for demonstration
    // Don't actually call the vulnerable functions
    return 0;
}