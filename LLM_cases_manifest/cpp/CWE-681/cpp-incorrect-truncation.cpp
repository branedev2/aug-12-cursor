#include <iostream>
#include <cstdint>
#include <limits>
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    int int_var = 300;
    // ruleid: cpp-incorrect-truncation
    char char_var = int_var; // Truncation occurs as 300 doesn't fit in a char
    std::cout << "Truncated value: " << static_cast<int>(char_var) << std::endl; // Will print something like 44
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_2() {
    long long_var = 70000;
    // ruleid: cpp-incorrect-truncation
    short short_var = long_var; // Truncation occurs as 70000 doesn't fit in a short
    std::cout << "Truncated value: " << short_var << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_3() {
    int int_var = -129;
    // ruleid: cpp-incorrect-truncation
    unsigned char uchar_var = int_var; // Truncation and sign change
    std::cout << "Truncated value: " << static_cast<int>(uchar_var) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_4() {
    int64_t large_var = 0x1FFFFFFFF;
    // ruleid: cpp-incorrect-truncation
    int32_t small_var = large_var; // Truncation of high-order bits
    std::cout << "Truncated value: " << small_var << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_5() {
    double double_var = 1234.56;
    // ruleid: cpp-incorrect-truncation
    char char_var = double_var; // Floating point to char truncation
    std::cout << "Truncated value: " << static_cast<int>(char_var) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_6() {
    int array_size = 300;
    // ruleid: cpp-incorrect-truncation
    char buffer_size = array_size; // Truncation in buffer size calculation
    char* buffer = new char[buffer_size]; // Buffer will be smaller than intended
    delete[] buffer;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_7() {
    int counter = 256;
    for (int i = 0; i < 10; i++) {
        // ruleid: cpp-incorrect-truncation
        unsigned char byte = counter++; // Truncation in loop
        std::cout << "Byte value: " << static_cast<int>(byte) << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_8() {
    int data = 1000;
    // ruleid: cpp-incorrect-truncation
    unsigned char packet_data = data; // Truncation in network packet preparation
    std::cout << "Packet data: " << static_cast<int>(packet_data) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_9() {
    int user_id = 70000;
    // ruleid: cpp-incorrect-truncation
    short stored_id = user_id; // Truncation of user identifier
    std::cout << "Stored ID: " << stored_id << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_10() {
    int calculation_result = 500;
    // ruleid: cpp-incorrect-truncation
    unsigned char result_byte = calculation_result; // Truncation of calculation result
    std::cout << "Result byte: " << static_cast<int>(result_byte) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_11() {
    int large_value = 0x12345678;
    // ruleid: cpp-incorrect-truncation
    char small_value = large_value; // Truncation of hexadecimal value
    std::cout << "Small value: " << static_cast<int>(small_value) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_12() {
    int seconds = 86400; // 24 hours in seconds
    // ruleid: cpp-incorrect-truncation
    unsigned char time_value = seconds; // Truncation of time value
    std::cout << "Time value: " << static_cast<int>(time_value) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_13() {
    int32_t file_position = 0x10000000;
    // ruleid: cpp-incorrect-truncation
    int16_t position_marker = file_position; // Truncation in file position
    std::cout << "Position marker: " << position_marker << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_14() {
    int color_value = 0xFFFFFF; // White in RGB
    // ruleid: cpp-incorrect-truncation
    unsigned char blue_component = color_value; // Truncation in color extraction
    std::cout << "Blue component: " << static_cast<int>(blue_component) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=1}

void bad_case_15() {
    int hash_value = 0xABCDEF;
    // ruleid: cpp-incorrect-truncation
    char hash_byte = hash_value; // Truncation in hash processing
    std::cout << "Hash byte: " << static_cast<int>(hash_byte) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    int int_var = 300;
    // ok: cpp-incorrect-truncation
    int preserved_var = int_var; // No truncation, same type
    std::cout << "Preserved value: " << preserved_var << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_2() {
    int int_var = 300;
    // ok: cpp-incorrect-truncation
    if (int_var >= 0 && int_var <= 255) {
        unsigned char char_var = static_cast<unsigned char>(int_var); // Safe with range check
        std::cout << "Safe conversion: " << static_cast<int>(char_var) << std::endl;
    } else {
        std::cout << "Value out of range for unsigned char" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_3() {
    long long_var = 70000;
    // ok: cpp-incorrect-truncation
    int int_var = static_cast<int>(long_var); // Safe if int can hold the value
    std::cout << "Safe conversion: " << int_var << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_4() {
    int int_var = 127;
    // ok: cpp-incorrect-truncation
    char char_var = static_cast<char>(int_var); // Safe with value in range
    std::cout << "Safe conversion: " << static_cast<int>(char_var) << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_5() {
    int64_t large_var = 0x1FFFFFFFF;
    // ok: cpp-incorrect-truncation
    std::cout << "Original value: " << large_var << std::endl;
    // Using the original value without truncation
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_6() {
    double double_var = 1234.56;
    // ok: cpp-incorrect-truncation
    int int_var = static_cast<int>(double_var); // Acceptable truncation of decimal part
    std::cout << "Integer part: " << int_var << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_7() {
    int array_size = 300;
    // ok: cpp-incorrect-truncation
    size_t buffer_size = static_cast<size_t>(array_size); // Proper type for sizes
    char* buffer = new char[buffer_size];
    delete[] buffer;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_8() {
    int counter = 256;
    for (int i = 0; i < 10; i++) {
        // ok: cpp-incorrect-truncation
        int byte_value = counter++ % 256; // Modulo to get valid byte value
        unsigned char byte = static_cast<unsigned char>(byte_value);
        std::cout << "Byte value: " << static_cast<int>(byte) << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_9() {
    int data = 1000;
    // ok: cpp-incorrect-truncation
    if (data <= std::numeric_limits<unsigned char>::max()) {
        unsigned char packet_data = static_cast<unsigned char>(data);
        std::cout << "Packet data: " << static_cast<int>(packet_data) << std::endl;
    } else {
        std::cout << "Data too large for packet byte" << std::endl;
    }
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_10() {
    int user_id = 70000;
    // ok: cpp-incorrect-truncation
    int stored_id = user_id; // Using appropriate type to store the ID
    std::cout << "Stored ID: " << stored_id << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_11() {
    int calculation_result = 500;
    // ok: cpp-incorrect-truncation
    int full_result = calculation_result; // Preserving full value
    std::cout << "Full result: " << full_result << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_12() {
    int large_value = 0x12345678;
    // ok: cpp-incorrect-truncation
    int preserved_value = large_value; // No truncation
    std::cout << "Preserved value: " << preserved_value << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_13() {
    int seconds = 86400; // 24 hours in seconds
    // ok: cpp-incorrect-truncation
    int time_value = seconds; // Using appropriate type
    std::cout << "Time value: " << time_value << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_14() {
    int32_t file_position = 0x10000000;
    // ok: cpp-incorrect-truncation
    int32_t position_marker = file_position; // Using same size type
    std::cout << "Position marker: " << position_marker << std::endl;
}
// {/fact}
// {fact rule=incorrect-conversion-of-integers@v1.0 defects=0}

void good_case_15() {
    int color_value = 0xFFFFFF; // White in RGB
    // ok: cpp-incorrect-truncation
    unsigned char blue_component = static_cast<unsigned char>(color_value & 0xFF); // Proper extraction
    unsigned char green_component = static_cast<unsigned char>((color_value >> 8) & 0xFF);
    unsigned char red_component = static_cast<unsigned char>((color_value >> 16) & 0xFF);
    std::cout << "RGB: " << static_cast<int>(red_component) << "," 
              << static_cast<int>(green_component) << "," 
              << static_cast<int>(blue_component) << std::endl;
}
// {/fact}

int main() {
    // Examples can be called here for testing
    return 0;
}