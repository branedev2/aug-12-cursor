#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <memory>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <ctime>
#include <map>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <functional>
// {fact rule=sensitive-information-leak@v1.0 defects=1}

// True Positives (Vulnerable Code)

void bad_case_1() {
    int* ptr = new int[10];
    try {
        // Some operations with ptr
        throw std::runtime_error("Memory allocation error");
    } catch (const std::exception& e) {
        // ruleid: cpp-memory-address-exposure
        std::cerr << "Error occurred with pointer at: " << ptr << " - " << e.what() << std::endl;
    }
    delete[] ptr;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_2() {
    std::string* userData = new std::string("sensitive data");
    std::ofstream logFile("app.log", std::ios::app);
    
    if (!logFile.is_open()) {
        // ruleid: cpp-memory-address-exposure
        std::cerr << "Failed to open log file. User data pointer: " << userData << std::endl;
    }
    
    delete userData;
}
// {/fact}

class Resource {
public:
    void* data;
    Resource() : data(malloc(1024)) {}
    ~Resource() { free(data); }
};
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_3() {
    Resource res;
    std::ofstream logFile("debug.log");
    
    // ruleid: cpp-memory-address-exposure
    logFile << "Resource allocated at address: " << res.data << std::endl;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_4() {
    std::vector<int> vec(100);
    try {
        vec.at(1000) = 42; // This will throw an out_of_range exception
    } catch (const std::exception& e) {
        // ruleid: cpp-memory-address-exposure
        printf("Exception caught: %s. Vector address: %p\n", e.what(), vec.data());
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_5() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    std::string log_message;
    
    // ruleid: cpp-memory-address-exposure
    log_message = "Debug info: Pointer value = " + std::to_string(reinterpret_cast<uintptr_t>(ptr.get()));
    std::cout << log_message << std::endl;
}
// {/fact}

class Logger {
public:
    static void log(const std::string& message) {
        std::cout << "[LOG] " << message << std::endl;
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_6() {
    int* array = new int[50];
    
    // ruleid: cpp-memory-address-exposure
    Logger::log("Array allocated at: " + std::to_string(reinterpret_cast<uintptr_t>(array)));
    
    delete[] array;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_7() {
    std::map<int, std::string> dataMap;
    
    try {
        // Some operations
        throw std::runtime_error("Map operation failed");
    } catch (const std::exception& e) {
        std::stringstream ss;
        // ruleid: cpp-memory-address-exposure
        ss << "Error with map at " << &dataMap << ": " << e.what();
        std::cerr << ss.str() << std::endl;
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_8() {
    FILE* file = fopen("data.txt", "r");
    if (!file) {
        // ruleid: cpp-memory-address-exposure
        fprintf(stderr, "Failed to open file. File handle would be at: %p\n", &file);
    } else {
        fclose(file);
    }
}
// {/fact}

class Connection {
private:
    void* socket;
public:
    Connection() : socket(nullptr) {}
    void debug() {
        // ruleid: cpp-memory-address-exposure
        std::cout << "Socket address: " << socket << std::endl;
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_9() {
    Connection conn;
    conn.debug();
}
// {/fact}

std::mutex mtx;
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_10() {
    std::thread t([]() {
        // Some thread operation
    });
    
    // ruleid: cpp-memory-address-exposure
    std::cout << "Thread ID: " << &t << ", Mutex address: " << &mtx << std::endl;
    
    t.join();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_11() {
    std::unordered_map<std::string, int> cache;
    
    try {
        // Some operations
        throw std::runtime_error("Cache error");
    } catch (...) {
        // ruleid: cpp-memory-address-exposure
        std::cerr << "Error with cache at address: " << &cache << std::endl;
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_12() {
    std::function<void()> callback = []() { /* do something */ };
    
    // ruleid: cpp-memory-address-exposure
    std::cout << "Callback function address: " << &callback << std::endl;
}
// {/fact}

class MemoryPool {
private:
    void* pool;
    size_t size;
public:
    MemoryPool(size_t s) : size(s) {
        pool = malloc(size);
    }
    
    void logStatus() {
        // ruleid: cpp-memory-address-exposure
        std::cout << "Memory pool status: Address=" << pool << ", Size=" << size << std::endl;
    }
    
    ~MemoryPool() {
        free(pool);
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_13() {
    MemoryPool pool(1024);
    pool.logStatus();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_14() {
    int* dynamicArray = nullptr;
    try {
        dynamicArray = new int[1000000000]; // Might cause bad_alloc
    } catch (const std::bad_alloc& e) {
        // ruleid: cpp-memory-address-exposure
        std::cerr << "Memory allocation failed at address: " << &dynamicArray << " with error: " << e.what() << std::endl;
    }
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=1}

void bad_case_15() {
    char buffer[256];
    void* ptr = &buffer;
    
    // ruleid: cpp-memory-address-exposure
    snprintf(buffer, sizeof(buffer), "Buffer is located at memory address: %p", ptr);
    std::cout << buffer << std::endl;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

// True Negatives (Secure Code)

void good_case_1() {
    int* ptr = new int[10];
    try {
        // Some operations with ptr
        throw std::runtime_error("Memory allocation error");
    } catch (const std::exception& e) {
        // ok: cpp-memory-address-exposure
        std::cerr << "Error occurred: " << e.what() << std::endl;
    }
    delete[] ptr;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_2() {
    std::string* userData = new std::string("sensitive data");
    std::ofstream logFile("app.log", std::ios::app);
    
    if (!logFile.is_open()) {
        // ok: cpp-memory-address-exposure
        std::cerr << "Failed to open log file. Please check file permissions." << std::endl;
    }
    
    delete userData;
}
// {/fact}

class SecureResource {
public:
    void* data;
    SecureResource() : data(malloc(1024)) {}
    ~SecureResource() { free(data); }
    
    void logStatus() {
        // ok: cpp-memory-address-exposure
        std::ofstream logFile("debug.log");
        logFile << "Resource allocated successfully. Size: 1024 bytes" << std::endl;
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_3() {
    SecureResource res;
    res.logStatus();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_4() {
    std::vector<int> vec(100);
    try {
        vec.at(1000) = 42; // This will throw an out_of_range exception
    } catch (const std::exception& e) {
        // ok: cpp-memory-address-exposure
        printf("Exception caught: %s. Vector size: %zu\n", e.what(), vec.size());
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_5() {
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    std::string log_message;
    
    // ok: cpp-memory-address-exposure
    log_message = "Debug info: Value stored = " + std::to_string(*ptr);
    std::cout << log_message << std::endl;
}
// {/fact}

class SecureLogger {
public:
    static void log(const std::string& message) {
        std::cout << "[LOG] " << message << std::endl;
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_6() {
    int* array = new int[50];
    
    // ok: cpp-memory-address-exposure
    SecureLogger::log("Array allocated successfully. Size: 50 elements");
    
    delete[] array;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_7() {
    std::map<int, std::string> dataMap;
    
    try {
        // Some operations
        throw std::runtime_error("Map operation failed");
    } catch (const std::exception& e) {
        std::stringstream ss;
        // ok: cpp-memory-address-exposure
        ss << "Error with map operation: " << e.what() << ". Map size: " << dataMap.size();
        std::cerr << ss.str() << std::endl;
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_8() {
    FILE* file = fopen("data.txt", "r");
    if (!file) {
        // ok: cpp-memory-address-exposure
        fprintf(stderr, "Failed to open file 'data.txt'. Please check if the file exists.\n");
    } else {
        fclose(file);
    }
}
// {/fact}

class SecureConnection {
private:
    void* socket;
public:
    SecureConnection() : socket(nullptr) {}
    void debug() {
        // ok: cpp-memory-address-exposure
        std::cout << "Socket status: " << (socket ? "Connected" : "Disconnected") << std::endl;
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_9() {
    SecureConnection conn;
    conn.debug();
}
// {/fact}

std::mutex secure_mtx;
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_10() {
    std::thread t([]() {
        // Some thread operation
    });
    
    // ok: cpp-memory-address-exposure
    std::cout << "Thread started successfully. Mutex status: Initialized" << std::endl;
    
    t.join();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_11() {
    std::unordered_map<std::string, int> cache;
    
    try {
        // Some operations
        throw std::runtime_error("Cache error");
    } catch (...) {
        // ok: cpp-memory-address-exposure
        std::cerr << "Error with cache operation. Cache size: " << cache.size() << " entries" << std::endl;
    }
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_12() {
    std::function<void()> callback = []() { /* do something */ };
    
    // ok: cpp-memory-address-exposure
    std::cout << "Callback function registered successfully" << std::endl;
}
// {/fact}

class SecureMemoryPool {
private:
    void* pool;
    size_t size;
public:
    SecureMemoryPool(size_t s) : size(s) {
        pool = malloc(size);
    }
    
    void logStatus() {
        // ok: cpp-memory-address-exposure
        std::cout << "Memory pool status: Size=" << size << " bytes, Status=" 
                  << (pool ? "Allocated" : "Allocation failed") << std::endl;
    }
    
    ~SecureMemoryPool() {
        free(pool);
    }
};
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_13() {
    SecureMemoryPool pool(1024);
    pool.logStatus();
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_14() {
    int* dynamicArray = nullptr;
    try {
        dynamicArray = new int[1000000000]; // Might cause bad_alloc
    } catch (const std::bad_alloc& e) {
        // ok: cpp-memory-address-exposure
        std::cerr << "Memory allocation failed: " << e.what() << ". Requested size was too large." << std::endl;
    }
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=sensitive-information-leak@v1.0 defects=0}

void good_case_15() {
    char buffer[256];
    
    // ok: cpp-memory-address-exposure
    snprintf(buffer, sizeof(buffer), "Buffer initialized successfully. Size: %zu bytes", sizeof(buffer));
    std::cout << buffer << std::endl;
}
// {/fact}

int main() {
    // This function is just to avoid compiler warnings about unused functions
    return 0;
}