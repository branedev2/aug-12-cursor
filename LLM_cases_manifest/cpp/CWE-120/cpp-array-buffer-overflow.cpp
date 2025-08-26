#include <iostream>
#include <cstring>
#include <vector>
#include <string>
#include <cstdlib>
// {fact rule=classic-buffer-overflow defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    int buffer[5];
    
    for (int i = 0; i <= 5; i++) {
        // ruleid: cpp-array-buffer-overflow
        buffer[i] = i; // Buffer overflow on the 6th iteration
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_2() {
    char buffer[10];
    char source[] = "This string is too long for the buffer";
    
    // ruleid: cpp-array-buffer-overflow
    strcpy(buffer, source); // Classic buffer overflow with strcpy
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_3() {
    int arr[5] = {1, 2, 3, 4, 5};
    int index = 10;
    
    // ruleid: cpp-array-buffer-overflow
    int value = arr[index]; // Accessing an out-of-bounds index
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_4() {
    char dest[10];
    char src[] = "This is a very long string that will cause a buffer overflow";
    
    // ruleid: cpp-array-buffer-overflow
    for (size_t i = 0; i < strlen(src); i++) {
        dest[i] = src[i]; // Writing beyond the bounds of dest
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_5() {
    int matrix[3][3];
    
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 4; j++) { // Note the 4 here
            // ruleid: cpp-array-buffer-overflow
            matrix[i][j] = i * j; // Overflow in the second dimension
        }
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_6() {
    char buffer[10];
    char input[20] = "Input data here";
    
    // ruleid: cpp-array-buffer-overflow
    memcpy(buffer, input, sizeof(input)); // Copying more data than buffer can hold
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_7() {
    int arr[5] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    
    for (int i = 0; i < 10; i++) {
        // ruleid: cpp-array-buffer-overflow
        ptr[i] = i * 2; // Writing beyond the bounds using pointer arithmetic
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_8() {
    char buffer[10];
    std::string userInput = "This is a very long input string";
    
    // ruleid: cpp-array-buffer-overflow
    for (size_t i = 0; i < userInput.length(); i++) {
        buffer[i] = userInput[i]; // Writing beyond buffer bounds
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_9() {
    int small_array[5];
    int large_array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    // ruleid: cpp-array-buffer-overflow
    memcpy(small_array, large_array, sizeof(large_array)); // Copying too much data
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_10() {
    char buffer[5];
    int position = -1; // Negative index
    
    // ruleid: cpp-array-buffer-overflow
    buffer[position] = 'A'; // Negative index causes underflow
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_11() {
    const int size = 5;
    int buffer[size];
    int index = size; // One past the end
    
    // ruleid: cpp-array-buffer-overflow
    buffer[index] = 42; // Writing to index 5 in a 5-element array (indices 0-4)
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_12() {
    char src[10] = "Hello";
    char dest[5];
    
    // ruleid: cpp-array-buffer-overflow
    strncpy(dest, src, sizeof(src)); // strncpy with incorrect size parameter
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_13() {
    int arr[3][3];
    int row = 3; // Out of bounds for first dimension
    int col = 2;
    
    // ruleid: cpp-array-buffer-overflow
    arr[row][col] = 42; // Accessing out of bounds in multidimensional array
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_14() {
    char buffer[10];
    std::string data = "0123456789ABCDEF"; // 16 characters
    
    // ruleid: cpp-array-buffer-overflow
    for (char c : data) {
        static int i = 0;
        buffer[i++] = c; // Will eventually overflow
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=1}

void bad_case_15() {
    int arr[5] = {1, 2, 3, 4, 5};
    int offset = 5;
    
    // ruleid: cpp-array-buffer-overflow
    arr[offset] = 100; // Direct out-of-bounds write
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    int buffer[5];
    
    // ok: cpp-array-buffer-overflow
    for (int i = 0; i < 5; i++) {
        buffer[i] = i; // Proper bounds checking
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_2() {
    char buffer[50];
    char source[] = "This string fits in the buffer";
    
    // ok: cpp-array-buffer-overflow
    if (sizeof(buffer) > strlen(source)) {
        strcpy(buffer, source); // Checking size before copying
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_3() {
    int arr[5] = {1, 2, 3, 4, 5};
    int index = 4; // Valid index
    
    // ok: cpp-array-buffer-overflow
    if (index >= 0 && index < 5) {
        int value = arr[index]; // Bounds checking before access
        std::cout << "Value: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_4() {
    char dest[10];
    char src[] = "This is a very long string that will cause a buffer overflow";
    
    // ok: cpp-array-buffer-overflow
    for (size_t i = 0; i < strlen(src) && i < sizeof(dest) - 1; i++) {
        dest[i] = src[i]; // Checking bounds before writing
    }
    dest[sizeof(dest) - 1] = '\0'; // Ensure null termination
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_5() {
    int matrix[3][3];
    
    // ok: cpp-array-buffer-overflow
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            matrix[i][j] = i * j; // Proper bounds for both dimensions
        }
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_6() {
    char buffer[10];
    char input[20] = "Input data here";
    
    // ok: cpp-array-buffer-overflow
    memcpy(buffer, input, sizeof(buffer) < sizeof(input) ? sizeof(buffer) : sizeof(input));
    // Using the smaller of the two sizes
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_7() {
    std::vector<int> vec(5, 0); // Using std::vector instead of raw array
    
    // ok: cpp-array-buffer-overflow
    for (int i = 0; i < 10; i++) {
        if (i < vec.size()) {
            vec[i] = i * 2; // Safe access with bounds checking
        } else {
            vec.push_back(i * 2); // Dynamically resize if needed
        }
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_8() {
    std::string buffer; // Using std::string instead of char array
    std::string userInput = "This is a very long input string";
    
    // ok: cpp-array-buffer-overflow
    buffer = userInput; // std::string handles memory management automatically
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_9() {
    int small_array[5];
    int large_array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    // ok: cpp-array-buffer-overflow
    memcpy(small_array, large_array, sizeof(small_array)); // Copying only what fits
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_10() {
    char buffer[5];
    int position = -1; // Negative index
    
    // ok: cpp-array-buffer-overflow
    if (position >= 0 && position < sizeof(buffer)) {
        buffer[position] = 'A'; // Checking for valid index
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_11() {
    const int size = 5;
    std::vector<int> buffer(size);
    
    // ok: cpp-array-buffer-overflow
    for (int i = 0; i < size + 2; i++) {
        if (i < buffer.size()) {
            buffer[i] = 42; // Safe access with bounds checking
        } else {
            buffer.push_back(42); // Safely extend the vector
        }
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_12() {
    char src[10] = "Hello";
    char dest[5];
    
    // ok: cpp-array-buffer-overflow
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0'; // Ensure null termination
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_13() {
    int arr[3][3];
    int row = 2; // Valid index
    int col = 2; // Valid index
    
    // ok: cpp-array-buffer-overflow
    if (row >= 0 && row < 3 && col >= 0 && col < 3) {
        arr[row][col] = 42; // Checking bounds before access
    }
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_14() {
    std::string buffer; // Using std::string for automatic memory management
    std::string data = "0123456789ABCDEF";
    
    // ok: cpp-array-buffer-overflow
    buffer = data; // No buffer overflow with std::string
}
// {/fact}
// {fact rule=classic-buffer-overflow defects=0}

void good_case_15() {
    int arr[5] = {1, 2, 3, 4, 5};
    int offset = 5;
    
    // ok: cpp-array-buffer-overflow
    if (offset >= 0 && offset < sizeof(arr) / sizeof(arr[0])) {
        arr[offset] = 100; // Checking bounds before writing
    }
}
// {/fact}

int main() {
    // Function calls could be placed here for testing
    return 0;
}