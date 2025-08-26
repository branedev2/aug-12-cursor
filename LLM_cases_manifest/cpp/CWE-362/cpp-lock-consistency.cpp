#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <condition_variable>
#include <shared_mutex>
#include <atomic>
// {fact rule=thread-safety-violation@v1.0 defects=1}

// True Positives (Bad Cases)

// Example 1: Classic deadlock due to inconsistent lock order
void bad_case_1() {
    std::mutex mutex1;
    std::mutex mutex2;
    
    std::thread t1([&]() {
        std::lock_guard<std::mutex> lock1(mutex1);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // ruleid: cpp-lock-consistency
        std::lock_guard<std::mutex> lock2(mutex2); // Potential deadlock: t1 locks mutex1 then mutex2
        std::cout << "Thread 1 working" << std::endl;
    });
    
    std::thread t2([&]() {
        std::lock_guard<std::mutex> lock2(mutex2);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // ruleid: cpp-lock-consistency
        std::lock_guard<std::mutex> lock1(mutex1); // Potential deadlock: t2 locks mutex2 then mutex1
        std::cout << "Thread 2 working" << std::endl;
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 2: Forgetting to release a lock
void bad_case_2() {
    std::mutex mtx;
    
    auto worker = [&]() {
        // ruleid: cpp-lock-consistency
        mtx.lock(); // Lock acquired but never released in this code path
        if (rand() % 2) {
            return; // Early return without unlocking
        }
        // Some work
        mtx.unlock();
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 3: Inconsistent lock usage across functions
class BadResource {
private:
    std::mutex mtx;
    int data = 0;
    
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx);
        data++;
    }
    
    int getValue() {
        // ruleid: cpp-lock-consistency
        // Inconsistent locking - should lock here too
        return data; // Race condition: data might be modified while reading
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_3() {
    BadResource resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.increment();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 10; i++) {
            std::cout << resource.getValue() << std::endl;
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 4: Nested locks causing potential deadlock
void bad_case_4() {
    std::mutex mtx;
    
    auto worker = [&]() {
        std::lock_guard<std::mutex> lock1(mtx);
        // Some work
        
        // ruleid: cpp-lock-consistency
        std::lock_guard<std::mutex> lock2(mtx); // Trying to lock the same mutex again - deadlock
        // More work
    };
    
    std::thread t(worker);
    t.join();
}
// {/fact}

// Example 5: Using different locks for the same shared resource
class InconsistentLocking {
private:
    std::mutex mtx1;
    std::mutex mtx2;
    int sharedData = 0;
    
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx1);
        sharedData++;
    }
    
    void decrement() {
        // ruleid: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx2); // Using different mutex for the same resource
        sharedData--;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_5() {
    InconsistentLocking resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.increment();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.decrement();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 6: Lock released too early
void bad_case_6() {
    std::mutex mtx;
    int sharedCounter = 0;
    
    auto worker = [&]() {
        mtx.lock();
        sharedCounter++; // Protected operation
        // ruleid: cpp-lock-consistency
        mtx.unlock(); // Lock released too early
        
        // This operation should also be protected
        std::cout << "Counter value: " << sharedCounter << std::endl;
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 7: Inconsistent lock usage in conditional paths
void bad_case_7() {
    std::mutex mtx;
    int sharedData = 0;
    
    auto worker = [&](bool condition) {
        if (condition) {
            std::lock_guard<std::mutex> lock(mtx);
            sharedData++;
        } else {
            // ruleid: cpp-lock-consistency
            // Missing lock in this path
            sharedData--; // Race condition
        }
    };
    
    std::thread t1(worker, true);
    std::thread t2(worker, false);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 8: Mixing different lock types for the same resource
class MixedLockTypes {
private:
    std::mutex writeMutex;
    std::shared_mutex readWriteMutex;
    int data = 0;
    
public:
    void write() {
        std::lock_guard<std::mutex> lock(writeMutex);
        data++;
    }
    
    int read() {
        // ruleid: cpp-lock-consistency
        std::shared_lock<std::shared_mutex> lock(readWriteMutex); // Using different mutex type
        return data;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_8() {
    MixedLockTypes resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.write();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            std::cout << resource.read() << std::endl;
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 9: Inconsistent lock scope
void bad_case_9() {
    std::mutex mtx;
    std::vector<int> sharedVector;
    
    auto worker = [&]() {
        // ruleid: cpp-lock-consistency
        mtx.lock();
        sharedVector.push_back(1); // Protected
        mtx.unlock();
        
        // Should be protected but isn't
        sharedVector.push_back(2); // Race condition
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 10: Using try_lock incorrectly
void bad_case_10() {
    std::mutex mtx;
    int sharedData = 0;
    
    auto worker = [&]() {
        // ruleid: cpp-lock-consistency
        if (mtx.try_lock()) {
            sharedData++;
            // No unlock if try_lock succeeds
        }
        // Continue regardless of whether lock was acquired
        sharedData++; // Race condition
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 11: Inconsistent lock granularity
class InconsistentGranularity {
private:
    std::mutex mtx;
    std::vector<int> data = {1, 2, 3, 4, 5};
    
public:
    void updateAll() {
        std::lock_guard<std::mutex> lock(mtx); // Locks entire vector
        for (auto& item : data) {
            item++;
        }
    }
    
    void updateOne(int index) {
        // ruleid: cpp-lock-consistency
        // Should lock the entire vector for consistency
        if (index >= 0 && index < data.size()) {
            data[index]++; // Race condition
        }
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_11() {
    InconsistentGranularity resource;
    
    std::thread t1([&]() { resource.updateAll(); });
    std::thread t2([&]() { resource.updateOne(2); });
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 12: Lock-free operations mixed with locked operations
class MixedSynchronization {
private:
    std::mutex mtx;
    int protectedData = 0;
    
public:
    void incrementProtected() {
        std::lock_guard<std::mutex> lock(mtx);
        protectedData++;
    }
    
    void incrementUnprotected() {
        // ruleid: cpp-lock-consistency
        // Inconsistent protection for the same data
        protectedData++; // Race condition
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_12() {
    MixedSynchronization resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementProtected();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementUnprotected();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 13: Inconsistent lock usage in inheritance
class BaseWithLock {
protected:
    std::mutex mtx;
    int data = 0;
    
public:
    virtual void update() {
        std::lock_guard<std::mutex> lock(mtx);
        data++;
    }
};

class DerivedInconsistent : public BaseWithLock {
public:
    void update() override {
        // ruleid: cpp-lock-consistency
        // Forgot to lock in the override
        data++; // Race condition
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_13() {
    DerivedInconsistent resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.update();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.update();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

// Example 14: Inconsistent lock usage with condition variables
void bad_case_14() {
    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    
    auto producer = [&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // ruleid: cpp-lock-consistency
        // Should use lock_guard or unique_lock
        ready = true; // Race condition
        cv.notify_one();
    };
    
    auto consumer = [&]() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]{ return ready; });
        std::cout << "Data processed" << std::endl;
    };
    
    std::thread t1(producer);
    std::thread t2(consumer);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 15: Mixing atomic and mutex for the same data
class MixedSyncMechanisms {
private:
    std::mutex mtx;
    int sharedCounter = 0;
    
public:
    void incrementWithMutex() {
        std::lock_guard<std::mutex> lock(mtx);
        sharedCounter++;
    }
    
    void incrementWithoutMutex() {
        // ruleid: cpp-lock-consistency
        // Inconsistent synchronization mechanism
        sharedCounter++; // Race condition
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_15() {
    MixedSyncMechanisms resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementWithMutex();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementWithoutMutex();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// True Negatives (Good Cases)

// Example 1: Consistent lock order to prevent deadlocks
void good_case_1() {
    std::mutex mutex1;
    std::mutex mutex2;
    
    auto worker = [&](int id) {
        // ok: cpp-lock-consistency
        std::scoped_lock lock(mutex1, mutex2); // Always locks in the same order
        std::cout << "Thread " << id << " working" << std::endl;
    };
    
    std::thread t1(worker, 1);
    std::thread t2(worker, 2);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 2: Proper lock release with RAII
void good_case_2() {
    std::mutex mtx;
    
    auto worker = [&]() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // RAII ensures lock is always released
        
        if (rand() % 2) {
            return; // Early return, but lock_guard will release the mutex
        }
        // Some work
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 3: Consistent lock usage across functions
class GoodResource {
private:
    std::mutex mtx;
    int data = 0;
    
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx);
        data++;
    }
    
    int getValue() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Consistent locking
        return data;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_3() {
    GoodResource resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.increment();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 10; i++) {
            std::cout << resource.getValue() << std::endl;
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 4: Using recursive mutex for nested locks
void good_case_4() {
    std::recursive_mutex mtx;
    
    auto worker = [&]() {
        std::lock_guard<std::recursive_mutex> lock1(mtx);
        // Some work
        
        // ok: cpp-lock-consistency
        std::lock_guard<std::recursive_mutex> lock2(mtx); // Safe with recursive_mutex
        // More work
    };
    
    std::thread t(worker);
    t.join();
}
// {/fact}

// Example 5: Using the same lock for the same shared resource
class ConsistentLocking {
private:
    std::mutex mtx;
    int sharedData = 0;
    
public:
    void increment() {
        std::lock_guard<std::mutex> lock(mtx);
        sharedData++;
    }
    
    void decrement() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Using the same mutex for consistency
        sharedData--;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_5() {
    ConsistentLocking resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.increment();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.decrement();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 6: Proper lock scope
void good_case_6() {
    std::mutex mtx;
    int sharedCounter = 0;
    
    auto worker = [&]() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Lock covers all operations on shared data
        sharedCounter++;
        std::cout << "Counter value: " << sharedCounter << std::endl;
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 7: Consistent lock usage in conditional paths
void good_case_7() {
    std::mutex mtx;
    int sharedData = 0;
    
    auto worker = [&](bool condition) {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Lock regardless of condition
        
        if (condition) {
            sharedData++;
        } else {
            sharedData--;
        }
    };
    
    std::thread t1(worker, true);
    std::thread t2(worker, false);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 8: Consistent lock types for the same resource
class ConsistentLockTypes {
private:
    std::shared_mutex mtx;
    int data = 0;
    
public:
    void write() {
        std::unique_lock<std::shared_mutex> lock(mtx);
        data++;
    }
    
    int read() {
        // ok: cpp-lock-consistency
        std::shared_lock<std::shared_mutex> lock(mtx); // Using the same mutex consistently
        return data;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_8() {
    ConsistentLockTypes resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.write();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            std::cout << resource.read() << std::endl;
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 9: Consistent lock scope
void good_case_9() {
    std::mutex mtx;
    std::vector<int> sharedVector;
    
    auto worker = [&]() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Lock covers all operations on shared data
        sharedVector.push_back(1);
        sharedVector.push_back(2);
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 10: Using try_lock correctly
void good_case_10() {
    std::mutex mtx;
    int sharedData = 0;
    
    auto worker = [&]() {
        // ok: cpp-lock-consistency
        if (mtx.try_lock()) {
            std::lock_guard<std::mutex> lock(mtx, std::adopt_lock);
            sharedData++;
            // lock_guard will release the mutex
        } else {
            // Handle the case when lock cannot be acquired
            std::cout << "Could not acquire lock" << std::endl;
        }
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 11: Consistent lock granularity
class ConsistentGranularity {
private:
    std::mutex mtx;
    std::vector<int> data = {1, 2, 3, 4, 5};
    
public:
    void updateAll() {
        std::lock_guard<std::mutex> lock(mtx);
        for (auto& item : data) {
            item++;
        }
    }
    
    void updateOne(int index) {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Consistent locking granularity
        if (index >= 0 && index < data.size()) {
            data[index]++;
        }
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_11() {
    ConsistentGranularity resource;
    
    std::thread t1([&]() { resource.updateAll(); });
    std::thread t2([&]() { resource.updateOne(2); });
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 12: Consistent synchronization mechanism
class ConsistentSynchronization {
private:
    std::mutex mtx;
    int protectedData = 0;
    
public:
    void incrementProtected() {
        std::lock_guard<std::mutex> lock(mtx);
        protectedData++;
    }
    
    void incrementAlsoProtected() {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Consistent protection
        protectedData++;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_12() {
    ConsistentSynchronization resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementProtected();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.incrementAlsoProtected();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}

// Example 13: Consistent lock usage in inheritance
class BaseWithConsistentLock {
protected:
    std::mutex mtx;
    int data = 0;
    
public:
    virtual void update() {
        std::lock_guard<std::mutex> lock(mtx);
        data++;
    }
};

class DerivedConsistent : public BaseWithConsistentLock {
public:
    void update() override {
        // ok: cpp-lock-consistency
        std::lock_guard<std::mutex> lock(mtx); // Consistent locking in override
        data += 2;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_13() {
    DerivedConsistent resource;
    
    std::thread t1([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.update();
        }
    });
    
    std::thread t2([&]() {
        for (int i = 0; i < 1000; i++) {
            resource.update();
        }
    });
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 14: Consistent lock usage with condition variables
void good_case_14() {
    std::mutex mtx;
    std::condition_variable cv;
    bool ready = false;
    
    auto producer = [&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        // ok: cpp-lock-consistency
        {
            std::lock_guard<std::mutex> lock(mtx); // Properly protecting shared data
            ready = true;
        }
        cv.notify_one();
    };
    
    auto consumer = [&]() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [&]{ return ready; });
        std::cout << "Data processed" << std::endl;
    };
    
    std::thread t1(producer);
    std::thread t2(consumer);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// Example 15: Using atomic for thread-safe operations without locks
void good_case_15() {
    std::atomic<int> counter(0);
    
    auto worker = [&]() {
        for (int i = 0; i < 1000; i++) {
            // ok: cpp-lock-consistency
            counter++; // Thread-safe without explicit locks
        }
    };
    
    std::thread t1(worker);
    std::thread t2(worker);
    
    t1.join();
    t2.join();
    
    std::cout << "Final count: " << counter << std::endl;
}
// {/fact}

int main() {
    // Call the examples
    return 0;
}