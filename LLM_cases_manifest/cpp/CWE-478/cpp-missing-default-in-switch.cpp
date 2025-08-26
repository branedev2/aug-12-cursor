#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cstdlib>
#include <fstream>
#include <ctime>

// Enums used in examples
enum Color { RED, GREEN, BLUE, YELLOW };
enum HttpStatus { OK = 200, NOT_FOUND = 404, SERVER_ERROR = 500, BAD_REQUEST = 400 };
enum LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };
enum Direction { NORTH, SOUTH, EAST, WEST };
enum FileMode { READ, WRITE, APPEND, READ_WRITE };
// {fact rule=missing-default-condition@v1.0 defects=1}

// TRUE POSITIVES - Missing default in switch statements

void bad_case_1() {
    Color selectedColor = BLUE;
    
    // ruleid: cpp-missing-default-in-switch
    switch (selectedColor) {
        case RED:
            std::cout << "Selected color is red" << std::endl;
            break;
        case GREEN:
            std::cout << "Selected color is green" << std::endl;
            break;
        case BLUE:
            std::cout << "Selected color is blue" << std::endl;
            break;
        // Missing default case - what if a new color is added?
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_2(int userInput) {
    // ruleid: cpp-missing-default-in-switch
    switch (userInput) {
        case 1:
            std::cout << "Processing option 1" << std::endl;
            break;
        case 2:
            std::cout << "Processing option 2" << std::endl;
            break;
        case 3:
            std::cout << "Processing option 3" << std::endl;
            break;
        // No default case to handle unexpected input
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_3() {
    HttpStatus response = NOT_FOUND;
    std::string message;
    
    // ruleid: cpp-missing-default-in-switch
    switch (response) {
        case OK:
            message = "Request successful";
            break;
        case NOT_FOUND:
            message = "Resource not found";
            break;
        case SERVER_ERROR:
            message = "Internal server error";
            break;
        // Missing default case for other HTTP status codes
    }
    
    std::cout << "Response message: " << message << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_4() {
    char operation = '+';
    int a = 5, b = 3, result = 0;
    
    // ruleid: cpp-missing-default-in-switch
    switch (operation) {
        case '+':
            result = a + b;
            break;
        case '-':
            result = a - b;
            break;
        case '*':
            result = a * b;
            break;
        case '/':
            if (b != 0) result = a / b;
            break;
        // Missing default case for invalid operations
    }
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_5() {
    LogLevel level = WARNING;
    
    // ruleid: cpp-missing-default-in-switch
    switch (level) {
        case DEBUG:
            std::cout << "[DEBUG] ";
            break;
        case INFO:
            std::cout << "[INFO] ";
            break;
        case WARNING:
            std::cout << "[WARNING] ";
            break;
        case ERROR:
            std::cout << "[ERROR] ";
            break;
        // Missing default for CRITICAL or future log levels
    }
    
    std::cout << "Log message content" << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_6() {
    Direction dir = NORTH;
    int x = 0, y = 0;
    
    // ruleid: cpp-missing-default-in-switch
    switch (dir) {
        case NORTH:
            y++;
            break;
        case SOUTH:
            y--;
            break;
        case EAST:
            x++;
            break;
        case WEST:
            x--;
            break;
        // No default case if new directions are added
    }
    
    std::cout << "New position: (" << x << ", " << y << ")" << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_7() {
    int month = 3;
    std::string season;
    
    // ruleid: cpp-missing-default-in-switch
    switch (month) {
        case 12:
        case 1:
        case 2:
            season = "Winter";
            break;
        case 3:
        case 4:
        case 5:
            season = "Spring";
            break;
        case 6:
        case 7:
        case 8:
            season = "Summer";
            break;
        case 9:
        case 10:
        case 11:
            season = "Fall";
            break;
        // Missing default for invalid month values
    }
    
    std::cout << "Season: " << season << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_8() {
    FileMode mode = READ;
    std::string modeStr;
    
    // ruleid: cpp-missing-default-in-switch
    switch (mode) {
        case READ:
            modeStr = "r";
            break;
        case WRITE:
            modeStr = "w";
            break;
        case APPEND:
            modeStr = "a";
            break;
        case READ_WRITE:
            modeStr = "r+";
            break;
        // Missing default case for future file modes
    }
    
    std::cout << "File mode: " << modeStr << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_9() {
    char grade = 'B';
    
    // ruleid: cpp-missing-default-in-switch
    switch (grade) {
        case 'A':
            std::cout << "Excellent!" << std::endl;
            break;
        case 'B':
            std::cout << "Good job!" << std::endl;
            break;
        case 'C':
            std::cout << "Satisfactory" << std::endl;
            break;
        case 'D':
            std::cout << "Needs improvement" << std::endl;
            break;
        case 'F':
            std::cout << "Failed" << std::endl;
            break;
        // Missing default for invalid grades
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_10() {
    int day = 3;
    bool isWorkday;
    
    // ruleid: cpp-missing-default-in-switch
    switch (day) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
            isWorkday = true;
            break;
        case 6:
        case 7:
            isWorkday = false;
            break;
        // Missing default for invalid day values
    }
    
    std::cout << "Is workday: " << (isWorkday ? "Yes" : "No") << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_11() {
    int errorCode = 404;
    std::string errorMessage;
    
    // ruleid: cpp-missing-default-in-switch
    switch (errorCode) {
        case 400:
            errorMessage = "Bad Request";
            break;
        case 401:
            errorMessage = "Unauthorized";
            break;
        case 403:
            errorMessage = "Forbidden";
            break;
        case 404:
            errorMessage = "Not Found";
            break;
        case 500:
            errorMessage = "Internal Server Error";
            break;
        // Missing default for other error codes
    }
    
    std::cout << "Error: " << errorMessage << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_12() {
    char command = 'q';
    
    // ruleid: cpp-missing-default-in-switch
    switch (command) {
        case 'h':
            std::cout << "Help menu" << std::endl;
            break;
        case 'q':
            std::cout << "Quitting application" << std::endl;
            break;
        case 's':
            std::cout << "Saving data" << std::endl;
            break;
        case 'r':
            std::cout << "Refreshing view" << std::endl;
            break;
        // Missing default for unrecognized commands
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_13() {
    int configOption = 2;
    std::string configValue;
    
    // ruleid: cpp-missing-default-in-switch
    switch (configOption) {
        case 1:
            configValue = "debug=true";
            break;
        case 2:
            configValue = "logging=verbose";
            break;
        case 3:
            configValue = "cache=enabled";
            break;
        // Missing default for unknown config options
    }
    
    std::cout << "Setting configuration: " << configValue << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_14() {
    int signal = 9;
    
    // ruleid: cpp-missing-default-in-switch
    switch (signal) {
        case 1:
            std::cout << "Handling SIGHUP" << std::endl;
            break;
        case 2:
            std::cout << "Handling SIGINT" << std::endl;
            break;
        case 9:
            std::cout << "Handling SIGKILL" << std::endl;
            break;
        case 15:
            std::cout << "Handling SIGTERM" << std::endl;
            break;
        // Missing default for other signals
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=1}

void bad_case_15() {
    int permission = 4;
    std::string permissionDesc;
    
    // ruleid: cpp-missing-default-in-switch
    switch (permission) {
        case 1:
            permissionDesc = "Execute";
            break;
        case 2:
            permissionDesc = "Write";
            break;
        case 4:
            permissionDesc = "Read";
            break;
        // Missing default for combined permissions or invalid values
    }
    
    std::cout << "Permission: " << permissionDesc << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

// TRUE NEGATIVES - Switch statements with default cases

void good_case_1() {
    Color selectedColor = BLUE;
    
    // ok: cpp-missing-default-in-switch
    switch (selectedColor) {
        case RED:
            std::cout << "Selected color is red" << std::endl;
            break;
        case GREEN:
            std::cout << "Selected color is green" << std::endl;
            break;
        case BLUE:
            std::cout << "Selected color is blue" << std::endl;
            break;
        default:
            std::cout << "Unknown color selected" << std::endl;
            break;
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_2(int userInput) {
    // ok: cpp-missing-default-in-switch
    switch (userInput) {
        case 1:
            std::cout << "Processing option 1" << std::endl;
            break;
        case 2:
            std::cout << "Processing option 2" << std::endl;
            break;
        case 3:
            std::cout << "Processing option 3" << std::endl;
            break;
        default:
            std::cout << "Invalid option selected" << std::endl;
            break;
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_3() {
    HttpStatus response = NOT_FOUND;
    std::string message;
    
    // ok: cpp-missing-default-in-switch
    switch (response) {
        case OK:
            message = "Request successful";
            break;
        case NOT_FOUND:
            message = "Resource not found";
            break;
        case SERVER_ERROR:
            message = "Internal server error";
            break;
        default:
            message = "Unknown status code";
            break;
    }
    
    std::cout << "Response message: " << message << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_4() {
    char operation = '+';
    int a = 5, b = 3, result = 0;
    
    // ok: cpp-missing-default-in-switch
    switch (operation) {
        case '+':
            result = a + b;
            break;
        case '-':
            result = a - b;
            break;
        case '*':
            result = a * b;
            break;
        case '/':
            if (b != 0) result = a / b;
            break;
        default:
            std::cout << "Invalid operation" << std::endl;
            break;
    }
    
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_5() {
    LogLevel level = WARNING;
    
    // ok: cpp-missing-default-in-switch
    switch (level) {
        case DEBUG:
            std::cout << "[DEBUG] ";
            break;
        case INFO:
            std::cout << "[INFO] ";
            break;
        case WARNING:
            std::cout << "[WARNING] ";
            break;
        case ERROR:
            std::cout << "[ERROR] ";
            break;
        case CRITICAL:
            std::cout << "[CRITICAL] ";
            break;
        default:
            std::cout << "[UNKNOWN] ";
            break;
    }
    
    std::cout << "Log message content" << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_6() {
    Direction dir = NORTH;
    int x = 0, y = 0;
    
    // ok: cpp-missing-default-in-switch
    switch (dir) {
        case NORTH:
            y++;
            break;
        case SOUTH:
            y--;
            break;
        case EAST:
            x++;
            break;
        case WEST:
            x--;
            break;
        default:
            std::cout << "Invalid direction" << std::endl;
            break;
    }
    
    std::cout << "New position: (" << x << ", " << y << ")" << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_7() {
    int month = 3;
    std::string season;
    
    // ok: cpp-missing-default-in-switch
    switch (month) {
        case 12:
        case 1:
        case 2:
            season = "Winter";
            break;
        case 3:
        case 4:
        case 5:
            season = "Spring";
            break;
        case 6:
        case 7:
        case 8:
            season = "Summer";
            break;
        case 9:
        case 10:
        case 11:
            season = "Fall";
            break;
        default:
            season = "Invalid month";
            break;
    }
    
    std::cout << "Season: " << season << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_8() {
    FileMode mode = READ;
    std::string modeStr;
    
    // ok: cpp-missing-default-in-switch
    switch (mode) {
        case READ:
            modeStr = "r";
            break;
        case WRITE:
            modeStr = "w";
            break;
        case APPEND:
            modeStr = "a";
            break;
        case READ_WRITE:
            modeStr = "r+";
            break;
        default:
            modeStr = "unknown";
            break;
    }
    
    std::cout << "File mode: " << modeStr << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_9() {
    char grade = 'B';
    
    // ok: cpp-missing-default-in-switch
    switch (grade) {
        case 'A':
            std::cout << "Excellent!" << std::endl;
            break;
        case 'B':
            std::cout << "Good job!" << std::endl;
            break;
        case 'C':
            std::cout << "Satisfactory" << std::endl;
            break;
        case 'D':
            std::cout << "Needs improvement" << std::endl;
            break;
        case 'F':
            std::cout << "Failed" << std::endl;
            break;
        default:
            std::cout << "Invalid grade" << std::endl;
            break;
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_10() {
    int day = 3;
    bool isWorkday;
    
    // ok: cpp-missing-default-in-switch
    switch (day) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
            isWorkday = true;
            break;
        case 6:
        case 7:
            isWorkday = false;
            break;
        default:
            std::cout << "Invalid day value" << std::endl;
            isWorkday = false;
            break;
    }
    
    std::cout << "Is workday: " << (isWorkday ? "Yes" : "No") << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_11() {
    int errorCode = 404;
    std::string errorMessage;
    
    // ok: cpp-missing-default-in-switch
    switch (errorCode) {
        case 400:
            errorMessage = "Bad Request";
            break;
        case 401:
            errorMessage = "Unauthorized";
            break;
        case 403:
            errorMessage = "Forbidden";
            break;
        case 404:
            errorMessage = "Not Found";
            break;
        case 500:
            errorMessage = "Internal Server Error";
            break;
        default:
            errorMessage = "Unknown Error";
            break;
    }
    
    std::cout << "Error: " << errorMessage << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_12() {
    char command = 'q';
    
    // ok: cpp-missing-default-in-switch
    switch (command) {
        case 'h':
            std::cout << "Help menu" << std::endl;
            break;
        case 'q':
            std::cout << "Quitting application" << std::endl;
            break;
        case 's':
            std::cout << "Saving data" << std::endl;
            break;
        case 'r':
            std::cout << "Refreshing view" << std::endl;
            break;
        default:
            std::cout << "Unknown command" << std::endl;
            break;
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_13() {
    int configOption = 2;
    std::string configValue;
    
    // ok: cpp-missing-default-in-switch
    switch (configOption) {
        case 1:
            configValue = "debug=true";
            break;
        case 2:
            configValue = "logging=verbose";
            break;
        case 3:
            configValue = "cache=enabled";
            break;
        default:
            configValue = "invalid_option";
            std::cout << "Warning: Unknown configuration option" << std::endl;
            break;
    }
    
    std::cout << "Setting configuration: " << configValue << std::endl;
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_14() {
    int signal = 9;
    
    // ok: cpp-missing-default-in-switch
    switch (signal) {
        case 1:
            std::cout << "Handling SIGHUP" << std::endl;
            break;
        case 2:
            std::cout << "Handling SIGINT" << std::endl;
            break;
        case 9:
            std::cout << "Handling SIGKILL" << std::endl;
            break;
        case 15:
            std::cout << "Handling SIGTERM" << std::endl;
            break;
        default:
            std::cout << "Unhandled signal: " << signal << std::endl;
            break;
    }
}
// {/fact}
// {fact rule=missing-default-condition@v1.0 defects=0}

void good_case_15() {
    int permission = 4;
    std::string permissionDesc;
    
    // ok: cpp-missing-default-in-switch
    switch (permission) {
        case 1:
            permissionDesc = "Execute";
            break;
        case 2:
            permissionDesc = "Write";
            break;
        case 4:
            permissionDesc = "Read";
            break;
        default:
            permissionDesc = "Combined or invalid permission";
            break;
    }
    
    std::cout << "Permission: " << permissionDesc << std::endl;
}
// {/fact}

int main() {
    // Test cases can be called here
    return 0;
}