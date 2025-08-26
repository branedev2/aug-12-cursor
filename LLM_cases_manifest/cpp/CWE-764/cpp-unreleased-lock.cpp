#include <mutex>
#include <thread>
#include <iostream>
#include <vector>
#include <condition_variable>
#include <exception>
#include <fstream>
#include <map>
#include <memory>
#include <queue>
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

// True Positive Examples (Bad Cases)

void bad_case_1() {
    std::mutex mtx;
    
    // Acquire the lock
    mtx.lock();
    
    // Critical section
    std::cout << "Performing critical operation" << std::endl;
    
    // No unlock before function returns
    // ruleid: cpp-unreleased-lock
    return; // Lock is not released before returning
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_2() {
    std::mutex mtx;
    
    // Acquire the lock
    mtx.lock();
    
    // Critical section
    std::cout << "Performing critical operation" << std::endl;
    
    if (rand() % 2 == 0) {
        std::cout << "Early return path" << std::endl;
        // ruleid: cpp-unreleased-lock
        return; // Lock is not released in this path
    }
    
    // Only released in one path
    mtx.unlock();
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_3() {
    std::mutex mtx;
    
    try {
        mtx.lock();
        
        // Critical section that might throw
        int* arr = new int[1000000000]; // Might throw std::bad_alloc
        delete[] arr;
        
        mtx.unlock();
    } catch (const std::exception& e) {
        // ruleid: cpp-unreleased-lock
        std::cerr << "Exception caught: " << e.what() << std::endl;
        // No unlock in exception handler
    }
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_4() {
    std::mutex mtx;
    std::vector<int> data = {1, 2, 3, 4, 5};
    
    mtx.lock();
    
    for (int i = 0; i < data.size(); i++) {
        if (data[i] == 3) {
            // ruleid: cpp-unreleased-lock
            break; // Exit loop without unlocking
        }
    }
    
    // Code continues but mutex remains locked
    std::cout << "Processing complete" << std::endl;
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_5() {
    std::recursive_mutex rmtx;
    
    rmtx.lock();
    rmtx.lock(); // Recursive lock
    
    std::cout << "Double-locked critical section" << std::endl;
    
    rmtx.unlock();
    // ruleid: cpp-unreleased-lock
    // Missing second unlock
}
// {/fact}

class ResourceManager {
private:
    std::mutex mtx;
    
public:
    void bad_case_6() {
        mtx.lock();
        
        // Critical section
        std::cout << "Managing resources" << std::endl;
        
        if (std::rand() % 10 == 0) {
            // ruleid: cpp-unreleased-lock
            throw std::runtime_error("Random failure"); // Exception without unlock
        }
        
        mtx.unlock();
    }
};
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_7() {
    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    
    mtx.lock();
    
    // Incorrect usage - should use unique_lock for cv.wait
    // ruleid: cpp-unreleased-lock
    cv.wait(mtx, [&ready]{ return ready; }); // This won't compile, but demonstrates the issue
    
    mtx.unlock();
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_8() {
    std::mutex mtx1, mtx2;
    
    mtx1.lock();
    mtx2.lock();
    
    std::cout << "Critical section with two locks" << std::endl;
    
    mtx1.unlock();
    // ruleid: cpp-unreleased-lock
    // Forgot to unlock mtx2
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_9() {
    static std::mutex mtx;
    
    // Lock in a loop but only unlock sometimes
    for (int i = 0; i < 5; i++) {
        mtx.lock();
        
        std::cout << "Iteration " << i << std::endl;
        
        if (i % 2 == 0) {
            mtx.unlock();
        } else {
            // ruleid: cpp-unreleased-lock
            // No unlock for odd iterations
        }
    }
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_10() {
    std::mutex mtx;
    std::ifstream file("data.txt");
    
    mtx.lock();
    
    if (!file.is_open()) {
        std::cerr << "Failed to open file" << std::endl;
        // ruleid: cpp-unreleased-lock
        return; // Early return without unlock
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }
    
    mtx.unlock();
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_11() {
    std::mutex mtx;
    std::map<int, std::string> cache;
    
    auto process_data = [&mtx, &cache](int key) {
        mtx.lock();
        
        if (cache.find(key) != cache.end()) {
            std::cout << "Cache hit: " << cache[key] << std::endl;
            // ruleid: cpp-unreleased-lock
            return; // Return without unlocking in lambda
        }
        
        cache[key] = "Computed value for " + std::to_string(key);
        mtx.unlock();
    };
    
    process_data(42);
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_12() {
    std::mutex mtx;
    
    mtx.lock();
    
    // Critical section
    std::cout << "Starting critical section" << std::endl;
    
    // Nested scope
    {
        if (std::rand() % 2 == 0) {
            std::cout << "Condition met" << std::endl;
            // ruleid: cpp-unreleased-lock
            goto cleanup; // Jump bypasses unlock
        }
    }
    
    mtx.unlock();
    
cleanup:
    std::cout << "Cleanup" << std::endl;
}
// {/fact}

class ThreadPool {
private:
    std::mutex queue_mutex;
    std::queue<int> tasks;
    
public:
    void bad_case_13() {
        queue_mutex.lock();
        
        if (tasks.empty()) {
            // ruleid: cpp-unreleased-lock
            return; // Return without unlocking if queue is empty
        }
        
        int task = tasks.front();
        tasks.pop();
        
        queue_mutex.unlock();
        
        // Process task
        std::cout << "Processing task: " << task << std::endl;
    }
};
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_14() {
    std::mutex mtx;
    int error_code = 0;
    
    mtx.lock();
    
    // Simulate error checking
    error_code = std::rand() % 3;
    
    switch (error_code) {
        case 0:
            std::cout << "Success" << std::endl;
            mtx.unlock();
            break;
        case 1:
            std::cout << "Warning" << std::endl;
            mtx.unlock();
            break;
        case 2:
            std::cout << "Error" << std::endl;
            // ruleid: cpp-unreleased-lock
            return; // Return without unlocking in one case
    }
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=1}

void bad_case_15() {
    std::shared_ptr<std::mutex> mtx = std::make_shared<std::mutex>();
    
    mtx->lock();
    
    // Critical section
    std::cout << "Using shared mutex" << std::endl;
    
    // Reset the shared_ptr without unlocking first
    // ruleid: cpp-unreleased-lock
    mtx.reset(); // Destroys mutex while it's still locked
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

// True Negative Examples (Good Cases)

void good_case_1() {
    std::mutex mtx;
    
    // Acquire the lock
    mtx.lock();
    
    // Critical section
    std::cout << "Performing critical operation" << std::endl;
    
    // ok: cpp-unreleased-lock
    mtx.unlock(); // Properly release the lock
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_2() {
    std::mutex mtx;
    
    // Using RAII with lock_guard
    // ok: cpp-unreleased-lock
    std::lock_guard<std::mutex> lock(mtx); // Automatically unlocks when going out of scope
    
    // Critical section
    std::cout << "Performing critical operation" << std::endl;
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_3() {
    std::mutex mtx;
    
    // Acquire the lock
    mtx.lock();
    
    // Critical section
    std::cout << "Performing critical operation" << std::endl;
    
    if (rand() % 2 == 0) {
        std::cout << "Early return path" << std::endl;
        // ok: cpp-unreleased-lock
        mtx.unlock(); // Unlock before early return
        return;
    }
    
    // ok: cpp-unreleased-lock
    mtx.unlock(); // Unlock in normal path
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_4() {
    std::mutex mtx;
    
    try {
        // Using RAII with unique_lock
        // ok: cpp-unreleased-lock
        std::unique_lock<std::mutex> lock(mtx); // Automatically unlocks when going out of scope
        
        // Critical section that might throw
        int* arr = new int[1000000000]; // Might throw std::bad_alloc
        delete[] arr;
    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        // Lock is automatically released by unique_lock's destructor
    }
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_5() {
    std::mutex mtx;
    std::vector<int> data = {1, 2, 3, 4, 5};
    
    mtx.lock();
    
    for (int i = 0; i < data.size(); i++) {
        if (data[i] == 3) {
            // ok: cpp-unreleased-lock
            mtx.unlock(); // Unlock before breaking
            break;
        }
    }
    
    std::cout << "Processing complete" << std::endl;
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_6() {
    std::recursive_mutex rmtx;
    
    rmtx.lock();
    rmtx.lock(); // Recursive lock
    
    std::cout << "Double-locked critical section" << std::endl;
    
    // ok: cpp-unreleased-lock
    rmtx.unlock();
    rmtx.unlock(); // Properly unlock the same number of times
}
// {/fact}

class SafeResourceManager {
private:
    std::mutex mtx;
    
public:
    void good_case_7() {
        try {
            // ok: cpp-unreleased-lock
            std::lock_guard<std::mutex> lock(mtx); // RAII lock
            
            // Critical section
            std::cout << "Managing resources" << std::endl;
            
            if (std::rand() % 10 == 0) {
                throw std::runtime_error("Random failure"); // Exception with automatic unlock
            }
        } catch (const std::exception& e) {
            std::cerr << "Caught exception: " << e.what() << std::endl;
            // Lock is automatically released
        }
    }
};
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_8() {
    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    
    // ok: cpp-unreleased-lock
    std::unique_lock<std::mutex> lock(mtx); // Proper usage with condition_variable
    
    cv.wait(lock, [&ready]{ return ready; });
    
    // Lock is automatically released when unique_lock goes out of scope
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_9() {
    std::mutex mtx1, mtx2;
    
    mtx1.lock();
    mtx2.lock();
    
    std::cout << "Critical section with two locks" << std::endl;
    
    // ok: cpp-unreleased-lock
    mtx2.unlock();
    mtx1.unlock(); // Properly unlock all mutexes
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_10() {
    static std::mutex mtx;
    
    // Lock in a loop and always unlock
    for (int i = 0; i < 5; i++) {
        // ok: cpp-unreleased-lock
        std::lock_guard<std::mutex> lock(mtx); // RAII lock for each iteration
        
        std::cout << "Iteration " << i << std::endl;
    }
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_11() {
    std::mutex mtx;
    std::ifstream file("data.txt");
    
    mtx.lock();
    
    if (!file.is_open()) {
        std::cerr << "Failed to open file" << std::endl;
        // ok: cpp-unreleased-lock
        mtx.unlock(); // Unlock before early return
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        std::cout << line << std::endl;
    }
    
    // ok: cpp-unreleased-lock
    mtx.unlock();
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_12() {
    std::mutex mtx;
    std::map<int, std::string> cache;
    
    auto process_data = [&mtx, &cache](int key) {
        // ok: cpp-unreleased-lock
        std::lock_guard<std::mutex> lock(mtx); // RAII lock in lambda
        
        if (cache.find(key) != cache.end()) {
            std::cout << "Cache hit: " << cache[key] << std::endl;
            return; // Lock automatically released
        }
        
        cache[key] = "Computed value for " + std::to_string(key);
    };
    
    process_data(42);
}
// {/fact}
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_13() {
    std::mutex mtx;
    
    mtx.lock();
    
    // Critical section
    std::cout << "Starting critical section" << std::endl;
    
    // Nested scope
    {
        if (std::rand() % 2 == 0) {
            std::cout << "Condition met" << std::endl;
            // ok: cpp-unreleased-lock
            mtx.unlock(); // Unlock before goto
            goto cleanup;
        }
    }
    
    // ok: cpp-unreleased-lock
    mtx.unlock();
    
cleanup:
    std::cout << "Cleanup" << std::endl;
}
// {/fact}

class SafeThreadPool {
private:
    std::mutex queue_mutex;
    std::queue<int> tasks;
    
public:
    void good_case_14() {
        // ok: cpp-unreleased-lock
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        if (tasks.empty()) {
            lock.unlock(); // Explicitly unlock if needed before return
            return;
        }
        
        int task = tasks.front();
        tasks.pop();
        
        lock.unlock(); // Explicitly unlock before processing
        
        // Process task
        std::cout << "Processing task: " << task << std::endl;
    }
};
// {fact rule=multiple-locks-of-a-critical-resource@v1.0 defects=0}

void good_case_15() {
    std::mutex mtx;
    int error_code = 0;
    
    mtx.lock();
    
    // Simulate error checking
    error_code = std::rand() % 3;
    
    switch (error_code) {
        case 0:
            std::cout << "Success" << std::endl;
            break;
        case 1:
            std::cout << "Warning" << std::endl;
            break;
        case 2:
            std::cout << "Error" << std::endl;
            // ok: cpp-unreleased-lock
            mtx.unlock(); // Unlock before return
            return;
    }
    
    // ok: cpp-unreleased-lock
    mtx.unlock(); // Unlock at the end
}
// {/fact}

int main() {
    // This function is just to make the code compilable
    // It doesn't call any of the example functions
    return 0;
}