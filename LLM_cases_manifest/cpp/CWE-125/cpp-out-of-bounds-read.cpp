#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <array>
#include <memory>
#include <algorithm>
// {fact rule=out-of-bounds-read@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    int arr[5] = {1, 2, 3, 4, 5};
    
    for (int i = 0; i <= 5; i++) {
        // ruleid: cpp-out-of-bounds-read
        std::cout << "Element " << i << ": " << arr[i] << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_2() {
    std::vector<int> vec = {10, 20, 30, 40, 50};
    int index = 5;
    
    // ruleid: cpp-out-of-bounds-read
    int value = vec[index]; // Accessing index 5 in a vector of size 5
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_3() {
    const char* str = "Hello";
    
    // ruleid: cpp-out-of-bounds-read
    char lastChar = str[10]; // String is only 6 characters (including null terminator)
    std::cout << "Last character: " << lastChar << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_4() {
    int* dynamicArray = new int[3]{1, 2, 3};
    
    // ruleid: cpp-out-of-bounds-read
    int value = dynamicArray[-1]; // Negative index
    std::cout << "Value at -1: " << value << std::endl;
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_5() {
    std::string text = "Example";
    int len = text.length();
    
    // ruleid: cpp-out-of-bounds-read
    char lastChar = text[len]; // Should be len-1 for last character
    std::cout << "Last character: " << lastChar << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_6() {
    int matrix[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    
    // ruleid: cpp-out-of-bounds-read
    int value = matrix[3][0]; // Out of bounds for first dimension
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_7() {
    std::array<int, 5> arr = {1, 2, 3, 4, 5};
    int index = 10;
    
    // ruleid: cpp-out-of-bounds-read
    int value = arr[index]; // Index is way out of bounds
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_8() {
    char buffer[10] = "Hello";
    int index = strlen(buffer);
    
    for (int i = 0; i <= index; i++) {
        // ruleid: cpp-out-of-bounds-read
        std::cout << buffer[i+5] << std::endl; // Will go out of bounds
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_9() {
    int arr[5] = {1, 2, 3, 4, 5};
    int* ptr = arr;
    
    // ruleid: cpp-out-of-bounds-read
    int value = *(ptr + 10); // Points way beyond the array
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_10() {
    std::vector<int> vec = {1, 2, 3};
    
    // ruleid: cpp-out-of-bounds-read
    for (int i = 0; i <= vec.size(); i++) {
        std::cout << vec[i] << std::endl; // Last iteration is out of bounds
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_11() {
    int arr[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    
    // ruleid: cpp-out-of-bounds-read
    int value = arr[1][3]; // Out of bounds for second dimension
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_12() {
    std::string str = "Test";
    
    try {
        // ruleid: cpp-out-of-bounds-read
        char c = str.at(10); // Will throw std::out_of_range exception
        std::cout << "Character: " << c << std::endl;
    } catch (const std::out_of_range& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_13() {
    const char* ptr = nullptr;
    
    // ruleid: cpp-out-of-bounds-read
    char c = ptr[0]; // Dereferencing null pointer
    std::cout << "Character: " << c << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_14() {
    int arr[5] = {1, 2, 3, 4, 5};
    int* ptr = arr + 5; // Points just past the end
    
    // ruleid: cpp-out-of-bounds-read
    int value = *ptr; // Reading just past the end
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

void bad_case_15() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    vec.clear(); // Empty the vector
    
    // ruleid: cpp-out-of-bounds-read
    int first = vec[0]; // Vector is empty now
    std::cout << "First element: " << first << std::endl;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    int arr[5] = {1, 2, 3, 4, 5};
    
    for (int i = 0; i < 5; i++) {
        // ok: cpp-out-of-bounds-read
        std::cout << "Element " << i << ": " << arr[i] << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_2() {
    std::vector<int> vec = {10, 20, 30, 40, 50};
    int index = 4; // Last valid index
    
    // ok: cpp-out-of-bounds-read
    if (index < vec.size()) {
        int value = vec[index];
        std::cout << "Value: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_3() {
    const char* str = "Hello";
    size_t len = strlen(str);
    
    for (size_t i = 0; i < len; i++) {
        // ok: cpp-out-of-bounds-read
        char c = str[i];
        std::cout << "Character: " << c << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_4() {
    int* dynamicArray = new int[3]{1, 2, 3};
    
    for (int i = 0; i < 3; i++) {
        // ok: cpp-out-of-bounds-read
        int value = dynamicArray[i];
        std::cout << "Value: " << value << std::endl;
    }
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_5() {
    std::string text = "Example";
    
    // ok: cpp-out-of-bounds-read
    for (size_t i = 0; i < text.length(); i++) {
        char c = text[i];
        std::cout << "Character: " << c << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_6() {
    int matrix[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            // ok: cpp-out-of-bounds-read
            int value = matrix[i][j];
            std::cout << "Value at [" << i << "][" << j << "]: " << value << std::endl;
        }
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_7() {
    std::array<int, 5> arr = {1, 2, 3, 4, 5};
    int index = 4;
    
    // ok: cpp-out-of-bounds-read
    if (index < arr.size()) {
        int value = arr[index];
        std::cout << "Value: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_8() {
    char buffer[10] = "Hello";
    size_t len = strlen(buffer);
    
    // ok: cpp-out-of-bounds-read
    for (size_t i = 0; i < len; i++) {
        std::cout << buffer[i] << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_9() {
    int arr[5] = {1, 2, 3, 4, 5};
    int* ptr = arr;
    
    for (int i = 0; i < 5; i++) {
        // ok: cpp-out-of-bounds-read
        int value = *(ptr + i);
        std::cout << "Value: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_10() {
    std::vector<int> vec = {1, 2, 3};
    
    // ok: cpp-out-of-bounds-read
    for (size_t i = 0; i < vec.size(); i++) {
        std::cout << vec[i] << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_11() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    int index = 10;
    
    // ok: cpp-out-of-bounds-read
    if (index < vec.size()) {
        std::cout << vec[index] << std::endl;
    } else {
        std::cout << "Index out of bounds" << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_12() {
    std::string str = "Test";
    
    try {
        // ok: cpp-out-of-bounds-read
        for (size_t i = 0; i < str.length(); i++) {
            char c = str.at(i); // at() does bounds checking
            std::cout << "Character: " << c << std::endl;
        }
    } catch (const std::out_of_range& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_13() {
    const char* ptr = "Hello";
    
    // ok: cpp-out-of-bounds-read
    if (ptr != nullptr) {
        char c = ptr[0];
        std::cout << "Character: " << c << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_14() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    
    // ok: cpp-out-of-bounds-read
    for (const auto& elem : vec) { // Range-based for loop avoids out-of-bounds access
        std::cout << "Element: " << elem << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

void good_case_15() {
    std::vector<int> vec;
    
    // ok: cpp-out-of-bounds-read
    if (!vec.empty()) {
        int first = vec[0];
        std::cout << "First element: " << first << std::endl;
    } else {
        std::cout << "Vector is empty" << std::endl;
    }
}
// {/fact}

int main() {
    // Function calls could go here for testing
    return 0;
}