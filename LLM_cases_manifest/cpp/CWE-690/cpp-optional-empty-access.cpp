#include <iostream>
#include <optional>
#include <memory>
#include <string>
#include <vector>
#include <boost/optional.hpp>
#include <map>
#include <functional>
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    std::optional<int> maybeValue;
    // ruleid: cpp-optional-empty-access
    int value = maybeValue.value(); // Accessing without checking if it contains a value
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_2() {
    std::optional<std::string> maybeString;
    // ruleid: cpp-optional-empty-access
    std::cout << "String length: " << maybeString->length() << std::endl; // Dereferencing without checking
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_3() {
    std::unique_ptr<int> ptr;
    // ruleid: cpp-optional-empty-access
    int value = *ptr; // Dereferencing a potentially null unique_ptr
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_4() {
    std::shared_ptr<double> sharedPtr;
    // ruleid: cpp-optional-empty-access
    double value = *sharedPtr; // Dereferencing a potentially null shared_ptr
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_5() {
    boost::optional<int> maybeInt;
    // ruleid: cpp-optional-empty-access
    int value = *maybeInt; // Dereferencing without checking
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_6() {
    std::map<std::string, std::optional<int>> userScores;
    std::string username = "user1";
    
    // ruleid: cpp-optional-empty-access
    int score = userScores[username].value(); // Accessing value without checking
    std::cout << "Score: " << score << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_7() {
    std::vector<std::optional<std::string>> messages;
    messages.push_back(std::nullopt);
    
    // ruleid: cpp-optional-empty-access
    std::string firstMessage = messages[0].value(); // Accessing without checking
    std::cout << "Message: " << firstMessage << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_8() {
    std::optional<std::function<int(int)>> maybeFunc;
    int input = 5;
    
    // ruleid: cpp-optional-empty-access
    int result = maybeFunc.value()(input); // Accessing and calling without checking
    std::cout << "Result: " << result << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_9() {
    std::weak_ptr<int> weakPtr;
    // ruleid: cpp-optional-empty-access
    std::shared_ptr<int> sharedPtr = weakPtr.lock(); // Not checking if lock() returns null
    int value = *sharedPtr; // Dereferencing potentially null shared_ptr
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_10() {
    std::optional<std::optional<int>> nestedOptional;
    
    // ruleid: cpp-optional-empty-access
    int value = nestedOptional.value().value(); // Nested access without checking
    std::cout << "Value: " << value << std::endl;
}
// {/fact}

struct UserData {
    std::optional<std::string> email;
};
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_11() {
    std::optional<UserData> userData;
    
    // ruleid: cpp-optional-empty-access
    std::string email = userData->email.value(); // Nested access without checking
    std::cout << "Email: " << email << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_12() {
    int* rawPtr = nullptr;
    
    // ruleid: cpp-optional-empty-access
    int value = *rawPtr; // Dereferencing null raw pointer
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_13() {
    std::optional<int> maybeValue;
    if (rand() % 2) {
        maybeValue = 42;
    }
    
    // ruleid: cpp-optional-empty-access
    int value = maybeValue.value(); // No check before accessing value
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_14() {
    std::shared_ptr<std::string> strPtr;
    
    // ruleid: cpp-optional-empty-access
    std::cout << "String: " << *strPtr << ", length: " << strPtr->length() << std::endl; // Multiple dereferences without checking
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=1}

void bad_case_15() {
    boost::optional<std::vector<int>> maybeVector;
    
    // ruleid: cpp-optional-empty-access
    int size = maybeVector->size(); // Dereferencing without checking
    std::cout << "Vector size: " << size << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    std::optional<int> maybeValue;
    // ok: cpp-optional-empty-access
    if (maybeValue.has_value()) {
        int value = maybeValue.value();
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "No value" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_2() {
    std::optional<std::string> maybeString;
    // ok: cpp-optional-empty-access
    if (maybeString) { // Implicit boolean conversion
        std::cout << "String length: " << maybeString->length() << std::endl;
    } else {
        std::cout << "No string" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_3() {
    std::unique_ptr<int> ptr;
    // ok: cpp-optional-empty-access
    if (ptr) {
        int value = *ptr;
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "Null pointer" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_4() {
    std::shared_ptr<double> sharedPtr;
    // ok: cpp-optional-empty-access
    if (sharedPtr != nullptr) {
        double value = *sharedPtr;
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "Null pointer" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_5() {
    boost::optional<int> maybeInt;
    // ok: cpp-optional-empty-access
    if (maybeInt) {
        int value = *maybeInt;
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "No value" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_6() {
    std::map<std::string, std::optional<int>> userScores;
    std::string username = "user1";
    
    // ok: cpp-optional-empty-access
    auto it = userScores.find(username);
    if (it != userScores.end() && it->second.has_value()) {
        int score = it->second.value();
        std::cout << "Score: " << score << std::endl;
    } else {
        std::cout << "No score found" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_7() {
    std::vector<std::optional<std::string>> messages;
    messages.push_back(std::nullopt);
    
    // ok: cpp-optional-empty-access
    if (!messages.empty() && messages[0].has_value()) {
        std::string firstMessage = messages[0].value();
        std::cout << "Message: " << firstMessage << std::endl;
    } else {
        std::cout << "No message" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_8() {
    std::optional<std::function<int(int)>> maybeFunc;
    int input = 5;
    
    // ok: cpp-optional-empty-access
    if (maybeFunc) {
        int result = maybeFunc.value()(input);
        std::cout << "Result: " << result << std::endl;
    } else {
        std::cout << "No function" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_9() {
    std::weak_ptr<int> weakPtr;
    // ok: cpp-optional-empty-access
    std::shared_ptr<int> sharedPtr = weakPtr.lock();
    if (sharedPtr) {
        int value = *sharedPtr;
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "Expired pointer" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_10() {
    std::optional<std::optional<int>> nestedOptional;
    
    // ok: cpp-optional-empty-access
    if (nestedOptional && nestedOptional->has_value()) {
        int value = nestedOptional->value();
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "No value" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_11() {
    std::optional<UserData> userData;
    
    // ok: cpp-optional-empty-access
    if (userData && userData->email) {
        std::string email = userData->email.value();
        std::cout << "Email: " << email << std::endl;
    } else {
        std::cout << "No email" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_12() {
    int* rawPtr = nullptr;
    
    // ok: cpp-optional-empty-access
    if (rawPtr != nullptr) {
        int value = *rawPtr;
        std::cout << "Value: " << value << std::endl;
    } else {
        std::cout << "Null pointer" << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_13() {
    std::optional<int> maybeValue;
    if (rand() % 2) {
        maybeValue = 42;
    }
    
    // ok: cpp-optional-empty-access
    try {
        int value = maybeValue.value();
        std::cout << "Value: " << value << std::endl;
    } catch (const std::bad_optional_access& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_14() {
    std::optional<int> maybeValue;
    
    // ok: cpp-optional-empty-access
    int value = maybeValue.value_or(0); // Using value_or to provide a default
    std::cout << "Value: " << value << std::endl;
}
// {/fact}
// {fact rule=unchecked-return-value-null-dereference@v1.0 defects=0}

void good_case_15() {
    boost::optional<std::vector<int>> maybeVector;
    
    // ok: cpp-optional-empty-access
    if (maybeVector) {
        int size = maybeVector->size();
        std::cout << "Vector size: " << size << std::endl;
    } else {
        std::cout << "No vector" << std::endl;
    }
}
// {/fact}

int main() {
    // Function calls would go here
    return 0;
}