#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <memory>
// {fact rule=incorrect-operator@v1.0 defects=1}

// True Positives (Vulnerable/Insecure Code)

void bad_case_1() {
    int x = 5;
    int y = 10;
    
    // ruleid: cpp-accidental-operation
    if (x = y) {  // Accidental assignment instead of comparison
        std::cout << "x equals y" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_2() {
    bool isAdmin = false;
    std::string userInput = "admin";
    
    // ruleid: cpp-accidental-operation
    if (isAdmin = userInput == "admin") {  // Assignment in condition without parentheses
        std::cout << "Admin access granted" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_3() {
    int counter = 0;
    int limit = 10;
    
    // ruleid: cpp-accidental-operation
    while (counter = limit) {  // Infinite loop due to assignment instead of comparison
        std::cout << "Processing..." << std::endl;
        counter++;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_4() {
    int flags = 0x0F;
    int mask = 0x01;
    
    // ruleid: cpp-accidental-operation
    if (flags & mask = 0x01) {  // Incorrect operator precedence
        std::cout << "Flag is set" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_5() {
    int a = 5, b = 10, c = 15;
    
    // ruleid: cpp-accidental-operation
    int result = a + b * c / 2 - 1;  // Ambiguous operator precedence
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_6() {
    bool condition1 = true;
    bool condition2 = false;
    
    // ruleid: cpp-accidental-operation
    if (condition1 & condition2) {  // Bitwise AND instead of logical AND
        std::cout << "Both conditions are true" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_7() {
    int value = 42;
    
    // ruleid: cpp-accidental-operation
    if (value && value = 100) {  // Logical AND with assignment
        std::cout << "Value is now: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_8() {
    int x = 10;
    int y = 20;
    
    // ruleid: cpp-accidental-operation
    int z = x+++y;  // Ambiguous increment operation
    std::cout << "z = " << z << ", x = " << x << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_9() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    int index = 0;
    
    // ruleid: cpp-accidental-operation
    while (index < numbers.size())
        index++;
        std::cout << numbers[index] << std::endl;  // Missing braces, only increment is in the loop
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_10() {
    int status = 0;
    
    // ruleid: cpp-accidental-operation
    if (status != 0 || status = 1) {  // Assignment in second condition
        std::cout << "Status is valid" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_11() {
    int* ptr = nullptr;
    int value = 42;
    
    // ruleid: cpp-accidental-operation
    if (ptr = &value) {  // Assignment instead of comparison
        std::cout << "Pointer is not null" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_12() {
    int a = 5;
    int b = 10;
    
    // ruleid: cpp-accidental-operation
    int c = a < b ? a = 20 : b;  // Assignment in ternary condition
    std::cout << "c = " << c << ", a = " << a << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_13() {
    int flags = 0x0F;
    
    // ruleid: cpp-accidental-operation
    if (flags & 0x01 == 0x01) {  // Incorrect operator precedence (== has higher precedence than &)
        std::cout << "First bit is set" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_14() {
    bool a = true;
    bool b = false;
    bool c = true;
    
    // ruleid: cpp-accidental-operation
    if (a || b && c) {  // Ambiguous operator precedence
        std::cout << "Condition is true" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=1}

void bad_case_15() {
    int i = 0;
    int array[5] = {1, 2, 3, 4, 5};
    
    // ruleid: cpp-accidental-operation
    for (i = 0; i < 5; i++);  // Empty loop body due to semicolon
        std::cout << array[i] << std::endl;  // Will access out-of-bounds
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

// True Negatives (Safe/Secure Code)

void good_case_1() {
    int x = 5;
    int y = 10;
    
    // ok: cpp-accidental-operation
    if (x == y) {  // Proper comparison
        std::cout << "x equals y" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_2() {
    bool isAdmin = false;
    std::string userInput = "admin";
    
    // ok: cpp-accidental-operation
    isAdmin = (userInput == "admin");  // Assignment with clear intent
    if (isAdmin) {
        std::cout << "Admin access granted" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_3() {
    int counter = 0;
    int limit = 10;
    
    // ok: cpp-accidental-operation
    while (counter < limit) {  // Proper comparison
        std::cout << "Processing..." << std::endl;
        counter++;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_4() {
    int flags = 0x0F;
    int mask = 0x01;
    
    // ok: cpp-accidental-operation
    if ((flags & mask) == 0x01) {  // Proper operator precedence with parentheses
        std::cout << "Flag is set" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_5() {
    int a = 5, b = 10, c = 15;
    
    // ok: cpp-accidental-operation
    int result = a + ((b * c) / 2) - 1;  // Clear operator precedence with parentheses
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_6() {
    bool condition1 = true;
    bool condition2 = false;
    
    // ok: cpp-accidental-operation
    if (condition1 && condition2) {  // Logical AND
        std::cout << "Both conditions are true" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_7() {
    int value = 42;
    
    // ok: cpp-accidental-operation
    value = 100;
    if (value) {  // Separate assignment and condition
        std::cout << "Value is now: " << value << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_8() {
    int x = 10;
    int y = 20;
    
    // ok: cpp-accidental-operation
    int z = x++ + y;  // Clear increment operation with spacing
    std::cout << "z = " << z << ", x = " << x << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_9() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    int index = 0;
    
    // ok: cpp-accidental-operation
    while (index < numbers.size()) {
        std::cout << numbers[index] << std::endl;
        index++;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_10() {
    int status = 0;
    
    // ok: cpp-accidental-operation
    status = 1;
    if (status != 0) {  // Separate assignment and condition
        std::cout << "Status is valid" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_11() {
    int* ptr = nullptr;
    int value = 42;
    
    // ok: cpp-accidental-operation
    ptr = &value;
    if (ptr != nullptr) {  // Separate assignment and null check
        std::cout << "Pointer is not null" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_12() {
    int a = 5;
    int b = 10;
    
    // ok: cpp-accidental-operation
    a = 20;
    int c = a < b ? a : b;  // Separate assignment and ternary operation
    std::cout << "c = " << c << ", a = " << a << std::endl;
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_13() {
    int flags = 0x0F;
    
    // ok: cpp-accidental-operation
    if ((flags & 0x01) == 0x01) {  // Proper operator precedence with parentheses
        std::cout << "First bit is set" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_14() {
    bool a = true;
    bool b = false;
    bool c = true;
    
    // ok: cpp-accidental-operation
    if (a || (b && c)) {  // Clear operator precedence with parentheses
        std::cout << "Condition is true" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-operator@v1.0 defects=0}

void good_case_15() {
    int i = 0;
    int array[5] = {1, 2, 3, 4, 5};
    
    // ok: cpp-accidental-operation
    for (i = 0; i < 5; i++) {  // Proper loop with braces
        std::cout << array[i] << std::endl;
    }
}
// {/fact}

int main() {
    // This function is just to demonstrate the test cases
    // It doesn't need to be called
    return 0;
}