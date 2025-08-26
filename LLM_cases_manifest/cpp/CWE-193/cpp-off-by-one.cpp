#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <memory>
// {fact rule=off-by-one-error@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

// Example 1: Classic off-by-one error in array access
void bad_case_1() {
    int array[10];
    
    // Initialize array
    for (int i = 0; i < 10; i++) {
        array[i] = i;
    }
    
    // Off-by-one error: accessing beyond array bounds
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= 10; i++) {
        std::cout << "Element " << i << ": " << array[i] << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 2: Off-by-one error in buffer copy
void bad_case_2() {
    char src[] = "Hello, World!";
    char dest[13]; // Not enough space for null terminator
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= strlen(src); i++) {
        dest[i] = src[i];
    }
    
    std::cout << "Copied string: " << dest << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 3: Off-by-one error in vector access
void bad_case_3() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= numbers.size(); i++) {
        std::cout << "Number at index " << i << ": " << numbers[i] << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 4: Off-by-one error in string manipulation
void bad_case_4() {
    std::string text = "Hello";
    char result[5]; // Not enough space for the string
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= text.length(); i++) {
        result[i] = text[i];
    }
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 5: Off-by-one error in dynamic memory allocation
void bad_case_5() {
    int size = 10;
    int* dynamicArray = new int[size];
    
    // Initialize array
    for (int i = 0; i < size; i++) {
        dynamicArray[i] = i * 2;
    }
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= size; i++) {
        std::cout << "Value at " << i << ": " << dynamicArray[i] << std::endl;
    }
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 6: Off-by-one error in nested loops
void bad_case_6() {
    int matrix[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= 3; i++) {
        for (int j = 0; j < 3; j++) {
            std::cout << matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 7: Off-by-one error in buffer allocation
void bad_case_7() {
    const char* source = "Testing";
    int length = strlen(source);
    
    // Allocate one byte less than needed
    // ruleid: cpp-off-by-one
    char* buffer = new char[length];
    
    for (int i = 0; i < length; i++) {
        buffer[i] = source[i];
    }
    
    std::cout << "Buffer content: " << buffer << std::endl;
    delete[] buffer;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 8: Off-by-one error in file reading
void bad_case_8() {
    std::ifstream file("example.txt");
    if (!file.is_open()) {
        std::cout << "Failed to open file" << std::endl;
        return;
    }
    
    char buffer[10];
    file.read(buffer, 10);
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= 10; i++) {
        std::cout << buffer[i];
    }
    
    file.close();
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 9: Off-by-one error in calculating array index
void bad_case_9() {
    int values[5] = {10, 20, 30, 40, 50};
    int index = 5;
    
    // ruleid: cpp-off-by-one
    std::cout << "Value at index " << index << ": " << values[index] << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 10: Off-by-one error in string comparison
void bad_case_10() {
    const char* password = "secret";
    char input[7];
    strcpy(input, "secret");
    
    bool isMatch = true;
    int len = strlen(password);
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= len; i++) {
        if (password[i] != input[i]) {
            isMatch = false;
            break;
        }
    }
    
    std::cout << "Password match: " << (isMatch ? "Yes" : "No") << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 11: Off-by-one error in memory copy
void bad_case_11() {
    int source[5] = {1, 2, 3, 4, 5};
    int destination[5];
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= 5; i++) {
        destination[i] = source[i];
    }
    
    for (int i = 0; i < 5; i++) {
        std::cout << destination[i] << " ";
    }
    std::cout << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 12: Off-by-one error in calculating buffer size
void bad_case_12() {
    std::string input = "Hello, World!";
    int size = input.length();
    
    // ruleid: cpp-off-by-one
    char* buffer = new char[size]; // Missing space for null terminator
    
    for (int i = 0; i < size; i++) {
        buffer[i] = input[i];
    }
    buffer[size] = '\0'; // This writes beyond allocated memory
    
    std::cout << "Buffer: " << buffer << std::endl;
    delete[] buffer;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 13: Off-by-one error in parsing input
void bad_case_13() {
    std::string input = "12345";
    int digits[5];
    
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= input.length(); i++) {
        if (i < input.length()) {
            digits[i] = input[i] - '0';
        } else {
            // This will access out of bounds
            digits[i] = 0;
        }
    }
    
    for (int i = 0; i < 5; i++) {
        std::cout << digits[i] << " ";
    }
    std::cout << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 14: Off-by-one error in calculating array bounds
void bad_case_14() {
    int data[10];
    for (int i = 0; i < 10; i++) {
        data[i] = i * 10;
    }
    
    int sum = 0;
    // ruleid: cpp-off-by-one
    for (int i = 0; i <= 10; i++) {
        sum += data[i];
    }
    
    std::cout << "Sum: " << sum << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=1}

// Example 15: Off-by-one error in string concatenation
void bad_case_15() {
    char first[6] = "Hello";
    char second[6] = "World";
    char result[10]; // Not enough space for both strings and null terminator
    
    int i = 0;
    // ruleid: cpp-off-by-one
    for (int j = 0; j <= strlen(first); j++) {
        result[i++] = first[j];
    }
    
    for (int j = 0; j < strlen(second); j++) {
        result[i++] = second[j];
    }
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// True Negative Examples (Safe Code)

// Example 1: Correct array access
void good_case_1() {
    int array[10];
    
    // Initialize array
    for (int i = 0; i < 10; i++) {
        array[i] = i;
    }
    
    // ok: cpp-off-by-one
    for (int i = 0; i < 10; i++) {
        std::cout << "Element " << i << ": " << array[i] << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 2: Correct buffer copy
void good_case_2() {
    char src[] = "Hello, World!";
    char dest[14]; // Enough space for string and null terminator
    
    // ok: cpp-off-by-one
    for (int i = 0; i < strlen(src); i++) {
        dest[i] = src[i];
    }
    dest[strlen(src)] = '\0'; // Properly null-terminate
    
    std::cout << "Copied string: " << dest << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 3: Correct vector access
void good_case_3() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    
    // ok: cpp-off-by-one
    for (int i = 0; i < numbers.size(); i++) {
        std::cout << "Number at index " << i << ": " << numbers[i] << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 4: Correct string manipulation
void good_case_4() {
    std::string text = "Hello";
    char result[6]; // Enough space for the string and null terminator
    
    // ok: cpp-off-by-one
    for (int i = 0; i < text.length(); i++) {
        result[i] = text[i];
    }
    result[text.length()] = '\0'; // Properly null-terminate
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 5: Correct dynamic memory allocation
void good_case_5() {
    int size = 10;
    int* dynamicArray = new int[size];
    
    // Initialize array
    for (int i = 0; i < size; i++) {
        dynamicArray[i] = i * 2;
    }
    
    // ok: cpp-off-by-one
    for (int i = 0; i < size; i++) {
        std::cout << "Value at " << i << ": " << dynamicArray[i] << std::endl;
    }
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 6: Correct nested loops
void good_case_6() {
    int matrix[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
    
    // ok: cpp-off-by-one
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            std::cout << matrix[i][j] << " ";
        }
        std::cout << std::endl;
    }
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 7: Correct buffer allocation
void good_case_7() {
    const char* source = "Testing";
    int length = strlen(source);
    
    // ok: cpp-off-by-one
    char* buffer = new char[length + 1]; // +1 for null terminator
    
    for (int i = 0; i < length; i++) {
        buffer[i] = source[i];
    }
    buffer[length] = '\0'; // Properly null-terminate
    
    std::cout << "Buffer content: " << buffer << std::endl;
    delete[] buffer;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 8: Correct file reading
void good_case_8() {
    std::ifstream file("example.txt");
    if (!file.is_open()) {
        std::cout << "Failed to open file" << std::endl;
        return;
    }
    
    char buffer[10];
    file.read(buffer, 10);
    
    // ok: cpp-off-by-one
    for (int i = 0; i < 10; i++) {
        std::cout << buffer[i];
    }
    
    file.close();
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 9: Correct array index calculation
void good_case_9() {
    int values[5] = {10, 20, 30, 40, 50};
    int index = 4; // Last valid index
    
    // ok: cpp-off-by-one
    std::cout << "Value at index " << index << ": " << values[index] << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 10: Correct string comparison
void good_case_10() {
    const char* password = "secret";
    char input[7];
    strcpy(input, "secret");
    
    bool isMatch = true;
    int len = strlen(password);
    
    // ok: cpp-off-by-one
    for (int i = 0; i < len; i++) {
        if (password[i] != input[i]) {
            isMatch = false;
            break;
        }
    }
    
    std::cout << "Password match: " << (isMatch ? "Yes" : "No") << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 11: Correct memory copy
void good_case_11() {
    int source[5] = {1, 2, 3, 4, 5};
    int destination[5];
    
    // ok: cpp-off-by-one
    for (int i = 0; i < 5; i++) {
        destination[i] = source[i];
    }
    
    for (int i = 0; i < 5; i++) {
        std::cout << destination[i] << " ";
    }
    std::cout << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 12: Correct buffer size calculation
void good_case_12() {
    std::string input = "Hello, World!";
    int size = input.length();
    
    // ok: cpp-off-by-one
    char* buffer = new char[size + 1]; // +1 for null terminator
    
    for (int i = 0; i < size; i++) {
        buffer[i] = input[i];
    }
    buffer[size] = '\0'; // Properly null-terminate
    
    std::cout << "Buffer: " << buffer << std::endl;
    delete[] buffer;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 13: Correct input parsing
void good_case_13() {
    std::string input = "12345";
    int digits[5];
    
    // ok: cpp-off-by-one
    for (int i = 0; i < input.length(); i++) {
        digits[i] = input[i] - '0';
    }
    
    for (int i = 0; i < 5; i++) {
        std::cout << digits[i] << " ";
    }
    std::cout << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 14: Correct array bounds calculation
void good_case_14() {
    int data[10];
    for (int i = 0; i < 10; i++) {
        data[i] = i * 10;
    }
    
    int sum = 0;
    // ok: cpp-off-by-one
    for (int i = 0; i < 10; i++) {
        sum += data[i];
    }
    
    std::cout << "Sum: " << sum << std::endl;
}
// {/fact}
// {fact rule=off-by-one-error@v1.0 defects=0}

// Example 15: Correct string concatenation
void good_case_15() {
    char first[6] = "Hello";
    char second[6] = "World";
    char result[12]; // Enough space for both strings and null terminator
    
    int i = 0;
    // ok: cpp-off-by-one
    for (int j = 0; j < strlen(first); j++) {
        result[i++] = first[j];
    }
    
    for (int j = 0; j < strlen(second); j++) {
        result[i++] = second[j];
    }
    result[i] = '\0'; // Properly null-terminate
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}

int main() {
    // Call functions to test
    return 0;
}