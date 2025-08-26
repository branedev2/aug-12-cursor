#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <array>
#include <map>
// {fact rule=out-of-bound-write@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable code examples)

void bad_case_1() {
    int buffer[10];
    int index = 15;
    
    // ruleid: cpp-out-of-bounds-write
    buffer[index] = 42; // Writing beyond the array bounds
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_2() {
    char str[10];
    const char* source = "This string is way too long for the destination buffer";
    
    // ruleid: cpp-out-of-bounds-write
    strcpy(str, source); // Classic strcpy buffer overflow
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_3() {
    std::vector<int> vec(5);
    int* ptr = vec.data();
    
    for (int i = 0; i < 10; i++) {
        // ruleid: cpp-out-of-bounds-write
        ptr[i] = i; // Accessing beyond the allocated vector memory
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_4() {
    int arr[5] = {1, 2, 3, 4, 5};
    int* ptr = arr;
    
    // ruleid: cpp-out-of-bounds-write
    *(ptr + 10) = 100; // Pointer arithmetic leading to out-of-bounds write
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_5() {
    char buffer[10];
    std::string userInput = "A very long input that will cause buffer overflow";
    
    // ruleid: cpp-out-of-bounds-write
    for (size_t i = 0; i < userInput.length(); i++) {
        buffer[i] = userInput[i]; // Loop writes beyond buffer bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_6() {
    int matrix[3][3];
    int row = 5; // Out of bounds
    
    // ruleid: cpp-out-of-bounds-write
    for (int col = 0; col < 3; col++) {
        matrix[row][col] = col; // Writing to invalid row
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_7() {
    char dest[10];
    const char* src = "Hello, this is a test of buffer overflow";
    size_t src_len = strlen(src);
    
    // ruleid: cpp-out-of-bounds-write
    for (size_t i = 0; i <= src_len; i++) {
        dest[i] = src[i]; // Copying beyond destination buffer
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_8() {
    int* dynamicArray = new int[5];
    int index = -2;
    
    // ruleid: cpp-out-of-bounds-write
    dynamicArray[index] = 42; // Negative index causing out-of-bounds write
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_9() {
    std::array<int, 5> arr = {1, 2, 3, 4, 5};
    
    // ruleid: cpp-out-of-bounds-write
    arr[10] = 100; // Out-of-bounds write with std::array
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_10() {
    char buffer[10];
    char* ptr = buffer + 15; // Points beyond the buffer
    
    // ruleid: cpp-out-of-bounds-write
    *ptr = 'A'; // Writing through an out-of-bounds pointer
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_11() {
    int arr1[5] = {1, 2, 3, 4, 5};
    int arr2[10];
    
    // ruleid: cpp-out-of-bounds-write
    memcpy(arr2, arr1, 50); // Copying more bytes than arr1 contains
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_12() {
    std::vector<int> vec(3);
    
    // ruleid: cpp-out-of-bounds-write
    vec.at(5) = 10; // Out-of-bounds write using at() method
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_13() {
    int* ptr = (int*)malloc(5 * sizeof(int));
    
    // ruleid: cpp-out-of-bounds-write
    for (int i = 0; i < 10; i++) {
        ptr[i] = i * 10; // Writing beyond allocated memory
    }
    
    free(ptr);
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_14() {
    char buffer[10];
    std::string input = "This is a very long input string that will cause a buffer overflow";
    
    // ruleid: cpp-out-of-bounds-write
    snprintf(buffer, 50, "%s", input.c_str()); // Incorrect size parameter in snprintf
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=1}

void bad_case_15() {
    int matrix[3][4];
    
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 5; j++) { // Should be j < 4
            // ruleid: cpp-out-of-bounds-write
            matrix[i][j] = i + j; // Out-of-bounds write in the second dimension
        }
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

// TRUE NEGATIVES (Safe code examples)

void good_case_1() {
    int buffer[10];
    int index = 9; // Valid index
    
    // ok: cpp-out-of-bounds-write
    buffer[index] = 42; // Writing within array bounds
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_2() {
    char str[50]; // Buffer large enough for the source
    const char* source = "This string fits in the destination buffer";
    
    // ok: cpp-out-of-bounds-write
    strncpy(str, source, sizeof(str) - 1);
    str[sizeof(str) - 1] = '\0'; // Ensure null termination
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_3() {
    std::vector<int> vec(10);
    
    for (int i = 0; i < 10; i++) {
        // ok: cpp-out-of-bounds-write
        vec[i] = i; // Accessing within vector bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_4() {
    int arr[5] = {1, 2, 3, 4, 5};
    int* ptr = arr;
    
    for (int i = 0; i < 5; i++) {
        // ok: cpp-out-of-bounds-write
        *(ptr + i) = i * 10; // Safe pointer arithmetic within bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_5() {
    char buffer[50]; // Buffer large enough for the input
    std::string userInput = "A very long input that will fit in the buffer";
    
    // ok: cpp-out-of-bounds-write
    if (userInput.length() < sizeof(buffer)) {
        for (size_t i = 0; i < userInput.length(); i++) {
            buffer[i] = userInput[i]; // Safe write with bounds check
        }
        buffer[userInput.length()] = '\0';
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_6() {
    int matrix[3][3];
    
    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 3; col++) {
            // ok: cpp-out-of-bounds-write
            matrix[row][col] = row + col; // Safe 2D array access
        }
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_7() {
    std::string dest;
    const char* src = "Hello, this is a test of safe string handling";
    
    // ok: cpp-out-of-bounds-write
    dest = src; // Using std::string for automatic memory management
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_8() {
    std::vector<int> dynamicArray(5, 0);
    
    for (int i = 0; i < dynamicArray.size(); i++) {
        // ok: cpp-out-of-bounds-write
        dynamicArray[i] = i * 10; // Safe vector access within bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_9() {
    std::array<int, 5> arr = {1, 2, 3, 4, 5};
    
    for (size_t i = 0; i < arr.size(); i++) {
        // ok: cpp-out-of-bounds-write
        arr[i] = i * 100; // Safe std::array access within bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_10() {
    std::vector<int> vec(10);
    int index = 15;
    
    // ok: cpp-out-of-bounds-write
    if (index < vec.size()) {
        vec[index] = 100; // Bounds checking before write
    } else {
        std::cout << "Index out of bounds" << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_11() {
    int arr1[5] = {1, 2, 3, 4, 5};
    int arr2[10];
    
    // ok: cpp-out-of-bounds-write
    memcpy(arr2, arr1, sizeof(arr1)); // Copying the exact size of arr1
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_12() {
    std::vector<int> vec(3);
    int index = 5;
    
    try {
        // ok: cpp-out-of-bounds-write
        if (index < vec.size()) {
            vec.at(index) = 10; // Safe access with bounds check
        } else {
            std::cout << "Index out of bounds" << std::endl;
        }
    } catch (const std::out_of_range& e) {
        std::cerr << "Out of range error: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_13() {
    std::unique_ptr<int[]> ptr(new int[5]);
    
    for (int i = 0; i < 5; i++) {
        // ok: cpp-out-of-bounds-write
        ptr[i] = i * 10; // Safe access with smart pointer and proper bounds
    }
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_14() {
    char buffer[50]; // Buffer large enough
    std::string input = "This is a long input string that will fit in the buffer";
    
    // ok: cpp-out-of-bounds-write
    snprintf(buffer, sizeof(buffer), "%s", input.c_str()); // Correct size parameter in snprintf
}
// {/fact}
// {fact rule=out-of-bound-write@v1.0 defects=0}

void good_case_15() {
    const int rows = 3;
    const int cols = 4;
    int matrix[rows][cols];
    
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            // ok: cpp-out-of-bounds-write
            matrix[i][j] = i + j; // Safe 2D array access with proper bounds
        }
    }
}
// {/fact}

int main() {
    // Function calls could be placed here for testing
    return 0;
}