#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <shared_mutex>
#include <condition_variable>
#include <atomic>
#include <future>
// {fact rule=thread-safety-violation@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    // Multiple threads accessing the same file without synchronization
    std::string filename = "shared_data.txt";
    
    auto thread_func = [&filename]() {
        std::ofstream file(filename, std::ios::app);
        // ruleid: cpp-file-system-access
        file << "Thread ID: " << std::this_thread::get_id() << " wrote data\n";
        file.close();
    };
    
    std::thread t1(thread_func);
    std::thread t2(thread_func);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_2() {
    // Race condition when reading and writing to the same file
    std::string filename = "counter.txt";
    
    auto increment_counter = [&filename]() {
        for (int i = 0; i < 5; i++) {
            int current_value = 0;
            {
                std::ifstream in_file(filename);
                if (in_file.is_open()) {
                    in_file >> current_value;
                }
            }
            
            current_value++;
            
            {
                // ruleid: cpp-file-system-access
                std::ofstream out_file(filename);
                out_file << current_value;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread t1(increment_counter);
    std::thread t2(increment_counter);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_3() {
    // Multiple processes-like simulation with file access
    std::string log_file = "application.log";
    
    auto log_activity = [&log_file](const std::string& process_name) {
        for (int i = 0; i < 3; i++) {
            // ruleid: cpp-file-system-access
            std::ofstream log(log_file, std::ios::app);
            log << process_name << " - Activity " << i << " at " 
                << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            log.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    };
    
    std::thread process1(log_activity, "Process1");
    std::thread process2(log_activity, "Process2");
    std::thread process3(log_activity, "Process3");
    
    process1.join();
    process2.join();
    process3.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_4() {
    // File-based counter without synchronization
    std::string counter_file = "request_counter.txt";
    
    auto increment_request = [&counter_file]() {
        for (int i = 0; i < 10; i++) {
            int count = 0;
            {
                std::ifstream in(counter_file);
                if (in.is_open()) {
                    in >> count;
                }
            }
            
            count++;
            
            {
                // ruleid: cpp-file-system-access
                std::ofstream out(counter_file);
                out << count;
            }
        }
    };
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 3; i++) {
        threads.emplace_back(increment_request);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_5() {
    // Multiple threads appending to a CSV file
    std::string data_file = "sensor_data.csv";
    
    auto record_sensor_data = [&data_file](int sensor_id) {
        for (int i = 0; i < 5; i++) {
            float reading = static_cast<float>(rand()) / static_cast<float>(RAND_MAX) * 100.0f;
            
            // ruleid: cpp-file-system-access
            std::ofstream data(data_file, std::ios::app);
            data << sensor_id << "," << reading << "," 
                 << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
            data.close();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    
    std::thread sensor1(record_sensor_data, 1);
    std::thread sensor2(record_sensor_data, 2);
    std::thread sensor3(record_sensor_data, 3);
    
    sensor1.join();
    sensor2.join();
    sensor3.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_6() {
    // Multiple threads checking and creating files
    auto create_if_not_exists = [](const std::string& filename, const std::string& content) {
        if (!std::filesystem::exists(filename)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Simulate delay
            // ruleid: cpp-file-system-access
            std::ofstream file(filename);
            file << content;
            file.close();
        }
    };
    
    std::thread t1(create_if_not_exists, "config.ini", "[Settings]\nvalue=1");
    std::thread t2(create_if_not_exists, "config.ini", "[Settings]\nvalue=2");
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_7() {
    // Multiple threads reading and updating a JSON-like config file
    std::string config_file = "app_config.json";
    
    auto update_config = [&config_file](const std::string& key, const std::string& value) {
        // Read current config
        std::string content;
        {
            std::ifstream in(config_file);
            if (in.is_open()) {
                std::string line;
                while (std::getline(in, line)) {
                    content += line + "\n";
                }
            } else {
                content = "{}";
            }
        }
        
        // Update config (simplified, not real JSON parsing)
        size_t pos = content.find("\"" + key + "\"");
        if (pos != std::string::npos) {
            // Update existing key
            size_t value_start = content.find(":", pos) + 1;
            size_t value_end = content.find(",", value_start);
            if (value_end == std::string::npos) {
                value_end = content.find("}", value_start);
            }
            content.replace(value_start, value_end - value_start, " \"" + value + "\"");
        } else {
            // Add new key
            content.insert(content.length() - 1, "\"" + key + "\": \"" + value + "\",");
        }
        
        // Write updated config
        // ruleid: cpp-file-system-access
        std::ofstream out(config_file);
        out << content;
        out.close();
    };
// {/fact}
    
    std::thread t1(update_config, "server", "localhost");
    std::thread t2(update_config, "port", "8080");
    std::thread t3(update_config, "timeout", "30");
    
    t1.join();
    t2.join();
    t3.join();
}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_8() {
    // Multiple threads updating a file-based cache
    std::string cache_file = "data_cache.bin";
    
    auto update_cache_entry = [&cache_file](int key, const std::string& value) {
        // Simplified cache implementation
        std::vector<std::pair<int, std::string>> cache;
        
        // Read current cache
        {
            std::ifstream in(cache_file, std::ios::binary);
            if (in.is_open()) {
                int count;
                in.read(reinterpret_cast<char*>(&count), sizeof(count));
                
                for (int i = 0; i < count; i++) {
                    int k;
                    int len;
                    in.read(reinterpret_cast<char*>(&k), sizeof(k));
                    in.read(reinterpret_cast<char*>(&len), sizeof(len));
                    
                    std::string v(len, ' ');
                    in.read(&v[0], len);
                    
                    cache.emplace_back(k, v);
                }
            }
        }
        
        // Update or add entry
        bool found = false;
        for (auto& entry : cache) {
            if (entry.first == key) {
                entry.second = value;
                found = true;
                break;
            }
        }
        
        if (!found) {
            cache.emplace_back(key, value);
        }
        
        // Write updated cache
        // ruleid: cpp-file-system-access
        std::ofstream out(cache_file, std::ios::binary);
        int count = static_cast<int>(cache.size());
        out.write(reinterpret_cast<const char*>(&count), sizeof(count));
        
        for (const auto& entry : cache) {
            out.write(reinterpret_cast<const char*>(&entry.first), sizeof(entry.first));
            int len = static_cast<int>(entry.second.length());
            out.write(reinterpret_cast<const char*>(&len), sizeof(len));
            out.write(entry.second.c_str(), len);
        }
        out.close();
    };
    
    std::thread t1(update_cache_entry, 1, "Value 1");
    std::thread t2(update_cache_entry, 2, "Value 2");
    std::thread t3(update_cache_entry, 1, "Updated Value 1");
    
    t1.join();
    t2.join();
    t3.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_9() {
    // Multiple threads checking and modifying file permissions
    std::string target_file = "secure_data.txt";
    
    auto ensure_permissions = [&target_file](bool make_readonly) {
        if (std::filesystem::exists(target_file)) {
            auto perms = std::filesystem::status(target_file).permissions();
            
            if (make_readonly) {
                // ruleid: cpp-file-system-access
                std::filesystem::permissions(target_file, 
                    std::filesystem::perms::owner_read | 
                    std::filesystem::perms::group_read,
                    std::filesystem::perm_options::replace);
            } else {
                // ruleid: cpp-file-system-access
                std::filesystem::permissions(target_file,
                    std::filesystem::perms::owner_read | 
                    std::filesystem::perms::owner_write |
                    std::filesystem::perms::group_read,
                    std::filesystem::perm_options::replace);
            }
        }
    };
    
    // Create the file if it doesn't exist
    if (!std::filesystem::exists(target_file)) {
        std::ofstream file(target_file);
        file << "Secure content";
        file.close();
    }
    
    std::thread t1(ensure_permissions, true);
    std::thread t2(ensure_permissions, false);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_10() {
    // Multiple threads renaming files
    std::string source_file = "temp_data.txt";
    std::string dest_file1 = "final_data_v1.txt";
    std::string dest_file2 = "final_data_v2.txt";
    
    // Create the source file
    {
        std::ofstream file(source_file);
        file << "This is temporary data";
        file.close();
    }
    
    auto rename_file = [&source_file](const std::string& dest) {
        if (std::filesystem::exists(source_file)) {
            // ruleid: cpp-file-system-access
            std::filesystem::rename(source_file, dest);
        }
    };
    
    std::thread t1(rename_file, dest_file1);
    std::thread t2(rename_file, dest_file2);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_11() {
    // Multiple threads creating directories with the same name
    std::string dir_path = "data_directory";
    
    auto create_directory = [&dir_path]() {
        if (!std::filesystem::exists(dir_path)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Simulate delay
            // ruleid: cpp-file-system-access
            std::filesystem::create_directory(dir_path);
        }
    };
    
    std::thread t1(create_directory);
    std::thread t2(create_directory);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_12() {
    // Multiple threads checking file existence and creating if not exists
    std::string log_file = "system.log";
    
    auto initialize_log = [&log_file](const std::string& header) {
        if (!std::filesystem::exists(log_file)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Simulate delay
            // ruleid: cpp-file-system-access
            std::ofstream file(log_file);
            file << header << std::endl;
            file.close();
        }
    };
    
    std::thread t1(initialize_log, "=== System Log v1 ===");
    std::thread t2(initialize_log, "=== System Log v2 ===");
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_13() {
    // Multiple threads reading and writing to a file-based queue
    std::string queue_file = "task_queue.txt";
    
    auto add_task = [&queue_file](const std::string& task) {
        // ruleid: cpp-file-system-access
        std::ofstream file(queue_file, std::ios::app);
        file << task << std::endl;
        file.close();
    };
    
    auto process_next_task = [&queue_file]() {
        std::string task;
        std::vector<std::string> remaining_tasks;
        
        {
            std::ifstream file(queue_file);
            if (file.is_open()) {
                if (std::getline(file, task)) {
                    std::string line;
                    while (std::getline(file, line)) {
                        remaining_tasks.push_back(line);
                    }
                }
                file.close();
            }
        }
        
        if (!task.empty()) {
            // Process the task (simulated)
            std::cout << "Processing: " << task << std::endl;
            
            // Write back remaining tasks
            // ruleid: cpp-file-system-access
            std::ofstream out_file(queue_file);
            for (const auto& t : remaining_tasks) {
                out_file << t << std::endl;
            }
            out_file.close();
        }
    };
    
    std::thread producer1(add_task, "Task 1");
    std::thread producer2(add_task, "Task 2");
    std::thread consumer1(process_next_task);
    std::thread consumer2(process_next_task);
    
    producer1.join();
    producer2.join();
    consumer1.join();
    consumer2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_14() {
    // Multiple threads updating a file-based counter with read-modify-write pattern
    std::string counter_file = "global_counter.txt";
    
    // Initialize counter if it doesn't exist
    if (!std::filesystem::exists(counter_file)) {
        std::ofstream file(counter_file);
        file << "0";
        file.close();
    }
    
    auto increment_counter = [&counter_file]() {
        for (int i = 0; i < 5; i++) {
            // Read current value
            int current_value = 0;
            {
                std::ifstream file(counter_file);
                if (file.is_open()) {
                    file >> current_value;
                }
            }
            
            // Increment
            current_value++;
            
            // Write back
            // ruleid: cpp-file-system-access
            std::ofstream file(counter_file);
            file << current_value;
            file.close();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    
    std::thread t1(increment_counter);
    std::thread t2(increment_counter);
    std::thread t3(increment_counter);
    
    t1.join();
    t2.join();
    t3.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_15() {
    // Multiple threads checking and updating file timestamps
    std::string data_file = "last_access.txt";
    
    // Create file if it doesn't exist
    if (!std::filesystem::exists(data_file)) {
        std::ofstream file(data_file);
        file << "Access log";
        file.close();
    }
    
    auto update_timestamp = [&data_file]() {
        auto now = std::filesystem::file_time_type::clock::now();
        // ruleid: cpp-file-system-access
        std::filesystem::last_write_time(data_file, now);
        
        // Also append to the file
        std::ofstream file(data_file, std::ios::app);
        file << "\nAccessed at: " << now.time_since_epoch().count();
        file.close();
    };
    
    std::thread t1(update_timestamp);
    std::thread t2(update_timestamp);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    // Using mutex to synchronize file access
    std::string filename = "shared_data_safe.txt";
    std::mutex file_mutex;
    
    auto thread_func = [&filename, &file_mutex]() {
        std::lock_guard<std::mutex> lock(file_mutex);
        // ok: cpp-file-system-access
        std::ofstream file(filename, std::ios::app);
        file << "Thread ID: " << std::this_thread::get_id() << " wrote data\n";
        file.close();
    };
    
    std::thread t1(thread_func);
    std::thread t2(thread_func);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_2() {
    // Using mutex for read-modify-write pattern
    std::string filename = "counter_safe.txt";
    std::mutex counter_mutex;
    
    auto increment_counter = [&filename, &counter_mutex]() {
        for (int i = 0; i < 5; i++) {
            int current_value = 0;
            
            std::lock_guard<std::mutex> lock(counter_mutex);
            // ok: cpp-file-system-access
            {
                std::ifstream in_file(filename);
                if (in_file.is_open()) {
                    in_file >> current_value;
                }
            }
            
            current_value++;
            
            {
                std::ofstream out_file(filename);
                out_file << current_value;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread t1(increment_counter);
    std::thread t2(increment_counter);
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_3() {
    // Using a shared mutex for reader-writer pattern
    std::string data_file = "shared_data.bin";
    std::shared_mutex rwlock;
    
    auto reader = [&data_file, &rwlock]() {
        for (int i = 0; i < 5; i++) {
            std::shared_lock<std::shared_mutex> read_lock(rwlock);
            // ok: cpp-file-system-access
            std::ifstream file(data_file);
            std::string content;
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    content += line;
                }
            }
            read_lock.unlock();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto writer = [&data_file, &rwlock](const std::string& data) {
        for (int i = 0; i < 3; i++) {
            std::unique_lock<std::shared_mutex> write_lock(rwlock);
            // ok: cpp-file-system-access
            std::ofstream file(data_file, std::ios::app);
            file << data << " - " << i << std::endl;
            file.close();
            write_lock.unlock();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    
    std::thread r1(reader);
    std::thread r2(reader);
    std::thread w1(writer, "Writer 1");
    std::thread w2(writer, "Writer 2");
    
    r1.join();
    r2.join();
    w1.join();
    w2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_4() {
    // Using a single thread for file operations
    std::string log_file = "application_safe.log";
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::vector<std::string> message_queue;
    bool stop_thread = false;
    
    // Logger thread
    std::thread logger([&]() {
        while (true) {
            std::vector<std::string> current_batch;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]() { return !message_queue.empty() || stop_thread; });
                
                if (stop_thread && message_queue.empty()) {
                    break;
                }
                
                current_batch.swap(message_queue);
            }
            
            // ok: cpp-file-system-access
            std::ofstream log(log_file, std::ios::app);
            for (const auto& msg : current_batch) {
                log << msg << std::endl;
            }
            log.close();
        }
    });
    
    // Producer threads
    auto log_activity = [&](const std::string& process_name) {
        for (int i = 0; i < 5; i++) {
            std::string message = process_name + " - Activity " + std::to_string(i) + " at " +
                std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
            
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                message_queue.push_back(message);
            }
            cv.notify_one();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread p1(log_activity, "Process1");
    std::thread p2(log_activity, "Process2");
    
    p1.join();
    p2.join();
    
    // Stop logger thread
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        stop_thread = true;
    }
    cv.notify_one();
    logger.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_5() {
    // Using file locks for inter-process synchronization
    std::string data_file = "shared_data_locked.txt";
    
    auto process_func = [&data_file](const std::string& process_name) {
        for (int i = 0; i < 3; i++) {
            // ok: cpp-file-system-access
            FILE* file = fopen(data_file.c_str(), "a+");
            if (file) {
                // Lock the file
                #ifdef _WIN32
                _lock_file(file);
                #else
                flockfile(file);
                #endif
                
                // Write to the file
                fprintf(file, "%s - Activity %d at %lld\n", 
                        process_name.c_str(), i, 
                        std::chrono::system_clock::now().time_since_epoch().count());
                
                // Unlock the file
                #ifdef _WIN32
                _unlock_file(file);
                #else
                funlockfile(file);
                #endif
                
                fclose(file);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    
    std::thread t1(process_func, "Process1");
    std::thread t2(process_func, "Process2");
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_6() {
    // Using atomic operations for a file-based counter
    std::string counter_file = "atomic_counter.txt";
    std::mutex file_mutex;
    std::atomic<int> memory_counter(0);
    
    // Initialize counter file
    {
        std::lock_guard<std::mutex> lock(file_mutex);
        std::ofstream file(counter_file);
        file << "0";
        file.close();
    }
    
    auto increment_counter = [&]() {
        for (int i = 0; i < 10; i++) {
            // Increment in-memory counter atomically
            int new_value = ++memory_counter;
            
            // Periodically flush to disk with proper synchronization
            if (new_value % 5 == 0) {
                std::lock_guard<std::mutex> lock(file_mutex);
                // ok: cpp-file-system-access
                std::ofstream file(counter_file);
                file << new_value;
                file.close();
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    
    std::thread t1(increment_counter);
    std::thread t2(increment_counter);
    std::thread t3(increment_counter);
    
    t1.join();
    t2.join();
    t3.join();
    
    // Final flush to disk
    {
        std::lock_guard<std::mutex> lock(file_mutex);
        std::ofstream file(counter_file);
        file << memory_counter.load();
        file.close();
    }
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_7() {
    // Using a dedicated file manager class with proper synchronization
    class FileManager {
    private:
        std::string filename;
        std::mutex file_mutex;
        
    public:
        FileManager(const std::string& name) : filename(name) {}
        
        void write_data(const std::string& data) {
            std::lock_guard<std::mutex> lock(file_mutex);
            std::ofstream file(filename, std::ios::app);
            file << data << std::endl;
            file.close();
        }
        
        std::string read_data() {
            std::lock_guard<std::mutex> lock(file_mutex);
            std::ifstream file(filename);
            std::string content;
            std::string line;
            while (std::getline(file, line)) {
                content += line + "\n";
            }
            file.close();
            return content;
        }
    };
    
    FileManager manager("managed_file.txt");
    
    auto writer = [&manager](const std::string& prefix) {
        for (int i = 0; i < 5; i++) {
            std::string data = prefix + " - Data " + std::to_string(i);
            // ok: cpp-file-system-access
            manager.write_data(data);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto reader = [&manager]() {
        for (int i = 0; i < 3; i++) {
            std::string content = manager.read_data();
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
    };
    
    std::thread w1(writer, "Writer1");
    std::thread w2(writer, "Writer2");
    std::thread r1(reader);
    
    w1.join();
    w2.join();
    r1.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_8() {
    // Using a queue and worker thread for file operations
    std::string output_file = "worker_output.txt";
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::vector<std::string> work_items;
    bool stop_worker = false;
    
    // Worker thread that handles all file operations
    std::thread worker([&]() {
        while (true) {
            std::string item;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]() { return !work_items.empty() || stop_worker; });
                
                if (work_items.empty() && stop_worker) {
                    break;
                }
                
                if (!work_items.empty()) {
                    item = work_items.front();
                    work_items.erase(work_items.begin());
                }
            }
            
            if (!item.empty()) {
                // ok: cpp-file-system-access
                std::ofstream file(output_file, std::ios::app);
                file << item << std::endl;
                file.close();
            }
        }
    });
    
    // Producer threads
    auto produce_work = [&](const std::string& producer_name) {
        for (int i = 0; i < 5; i++) {
            std::string work = producer_name + " task " + std::to_string(i);
            
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                work_items.push_back(work);
            }
            cv.notify_one();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread p1(produce_work, "Producer1");
    std::thread p2(produce_work, "Producer2");
    
    p1.join();
    p2.join();
    
    // Stop worker
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        stop_worker = true;
    }
    cv.notify_one();
    worker.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_9() {
    // Using a thread-safe singleton for file operations
    class LoggerSingleton {
    private:
        static LoggerSingleton* instance;
        static std::mutex singleton_mutex;
        std::string log_file;
        std::mutex file_mutex;
        
        LoggerSingleton() : log_file("singleton_log.txt") {}
        
    public:
        static LoggerSingleton* getInstance() {
            std::lock_guard<std::mutex> lock(singleton_mutex);
            if (instance == nullptr) {
                instance = new LoggerSingleton();
            }
            return instance;
        }
        
        void log(const std::string& message) {
            std::lock_guard<std::mutex> lock(file_mutex);
            // ok: cpp-file-system-access
            std::ofstream file(log_file, std::ios::app);
            file << message << std::endl;
            file.close();
        }
    };
    
    LoggerSingleton* LoggerSingleton::instance = nullptr;
    std::mutex LoggerSingleton::singleton_mutex;
    
    auto log_activity = [](const std::string& component) {
        for (int i = 0; i < 5; i++) {
            std::string message = component + " - Log entry " + std::to_string(i);
            LoggerSingleton::getInstance()->log(message);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread t1(log_activity, "Component1");
    std::thread t2(log_activity, "Component2");
    std::thread t3(log_activity, "Component3");
    
    t1.join();
    t2.join();
    t3.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_10() {
    // Using async tasks with proper synchronization
    std::string data_file = "async_data.txt";
    std::mutex file_mutex;
    
    auto write_data = [&file_mutex, &data_file](const std::string& data) {
        std::lock_guard<std::mutex> lock(file_mutex);
        // ok: cpp-file-system-access
        std::ofstream file(data_file, std::ios::app);
        file << data << std::endl;
        file.close();
        return true;
    };
    
    // Launch async tasks
    std::vector<std::future<bool>> futures;
    for (int i = 0; i < 10; i++) {
        std::string data = "Data entry " + std::to_string(i);
        futures.push_back(std::async(std::launch::async, write_data, data));
    }
    
    // Wait for all tasks to complete
    for (auto& future : futures) {
        future.wait();
    }
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_11() {
    // Using a file-based lock file for synchronization
    std::string data_file = "protected_data.txt";
    std::string lock_file = data_file + ".lock";
    
    auto acquire_lock = [&lock_file]() -> bool {
        // Try to create the lock file
        std::ofstream lock(lock_file);
        if (!lock.is_open()) {
            return false;
        }
        lock << std::this_thread::get_id();
        lock.close();
        return true;
    };
    
    auto release_lock = [&lock_file]() {
        std::filesystem::remove(lock_file);
    };
    
    auto write_with_lock = [&](const std::string& data) {
        // Try to acquire lock with timeout
        auto start_time = std::chrono::steady_clock::now();
        bool locked = false;
        
        while (!locked) {
            locked = acquire_lock();
            if (!locked) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (!locked && elapsed > std::chrono::seconds(2)) {
                std::cout << "Failed to acquire lock after timeout" << std::endl;
                return;
            }
        }
        
        // We have the lock, perform file operation
        try {
            // ok: cpp-file-system-access
            std::ofstream file(data_file, std::ios::app);
            file << data << std::endl;
            file.close();
        } catch (...) {
            // Ensure lock is released even if an exception occurs
            release_lock();
            throw;
        }
        
        // Release lock
        release_lock();
    };
    
    std::thread t1(write_with_lock, "Data from thread 1");
    std::thread t2(write_with_lock, "Data from thread 2");
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_12() {
    // Using a semaphore for limiting concurrent file access
    std::string log_file = "limited_access.log";
    
    // Simple semaphore implementation
    class Semaphore {
    private:
        std::mutex mutex;
        std::condition_variable cv;
        int count;
        
    public:
        Semaphore(int count) : count(count) {}
        
        void acquire() {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [this]() { return count > 0; });
            count--;
        }
        
        void release() {
            std::unique_lock<std::mutex> lock(mutex);
            count++;
            cv.notify_one();
        }
    };
    
    Semaphore sem(1); // Allow only one thread at a time
    
    auto log_message = [&](const std::string& message) {
        sem.acquire();
        try {
            // ok: cpp-file-system-access
            std::ofstream file(log_file, std::ios::app);
            file << message << " at " << std::chrono::system_clock::now().time_since_epoch().count() << std::endl;
            file.close();
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Simulate work
        } catch (...) {
            sem.release();
            throw;
        }
        sem.release();
    };
    
    std::vector<std::thread> threads;
    for (int i = 0; i < 5; i++) {
        threads.emplace_back(log_message, "Message " + std::to_string(i));
    }
    
    for (auto& t : threads) {
        t.join();
    }
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_13() {
    // Using a reader-writer lock pattern for file access
    std::string database_file = "user_database.txt";
    
    class RWLock {
    private:
        std::mutex mutex;
        std::condition_variable write_cv;
        std::condition_variable read_cv;
        int readers = 0;
        bool writer = false;
        
    public:
        void read_lock() {
            std::unique_lock<std::mutex> lock(mutex);
            read_cv.wait(lock, [this]() { return !writer; });
            readers++;
        }
        
        void read_unlock() {
            std::unique_lock<std::mutex> lock(mutex);
            readers--;
            if (readers == 0) {
                write_cv.notify_one();
            }
        }
        
        void write_lock() {
            std::unique_lock<std::mutex> lock(mutex);
            write_cv.wait(lock, [this]() { return !writer && readers == 0; });
            writer = true;
        }
        
        void write_unlock() {
            std::unique_lock<std::mutex> lock(mutex);
            writer = false;
            read_cv.notify_all();
            write_cv.notify_one();
        }
    };
    
    RWLock rwlock;
    
    auto reader = [&](int id) {
        for (int i = 0; i < 3; i++) {
            rwlock.read_lock();
            // ok: cpp-file-system-access
            std::ifstream file(database_file);
            std::string content;
            std::string line;
            while (std::getline(file, line)) {
                content += line + "\n";
            }
            file.close();
            rwlock.read_unlock();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    auto writer = [&](int id) {
        for (int i = 0; i < 2; i++) {
            rwlock.write_lock();
            // ok: cpp-file-system-access
            std::ofstream file(database_file, std::ios::app);
            file << "Writer " << id << " entry " << i << std::endl;
            file.close();
            rwlock.write_unlock();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };
    
    // Initialize the file
    {
        std::ofstream file(database_file);
        file << "Initial database content" << std::endl;
        file.close();
    }
    
    std::thread r1(reader, 1);
    std::thread r2(reader, 2);
    std::thread w1(writer, 1);
    std::thread w2(writer, 2);
    
    r1.join();
    r2.join();
    w1.join();
    w2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_14() {
    // Using a thread-local buffer with synchronized flush
    std::string output_file = "buffered_output.txt";
    std::mutex file_mutex;
    
    auto buffered_writer = [&](const std::string& prefix) {
        // Thread-local buffer
        std::vector<std::string> buffer;
        
        for (int i = 0; i < 10; i++) {
            // Add to local buffer
            buffer.push_back(prefix + " - Entry " + std::to_string(i));
            
            // Flush buffer when it reaches a certain size
            if (buffer.size() >= 5 || i == 9) {
                std::lock_guard<std::mutex> lock(file_mutex);
                // ok: cpp-file-system-access
                std::ofstream file(output_file, std::ios::app);
                for (const auto& entry : buffer) {
                    file << entry << std::endl;
                }
                file.close();
                buffer.clear();
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };
    
    std::thread t1(buffered_writer, "Thread1");
    std::thread t2(buffered_writer, "Thread2");
    
    t1.join();
    t2.join();
}
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_15() {
    // Using a file operation queue with batch processing
    std::string data_file = "batch_processed.txt";
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::vector<std::string> operation_queue;
    bool stop_processing = false;
    
    // Batch processor thread
    std::thread processor([&]() {
        while (true) {
            std::vector<std::string> batch;
            
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]() { 
                    return !operation_queue.empty() || stop_processing; 
                });
                
                if (operation_queue.empty() && stop_processing) {
                    break;
                }
                
                // Take all current operations for batch processing
                batch.swap(operation_queue);
            }
            
            if (!batch.empty()) {
                // Process batch
                // ok: cpp-file-system-access
                std::ofstream file(data_file, std::ios::app);
                file << "--- Batch start ---" << std::endl;
                for (const auto& op : batch) {
                    file << op << std::endl;
                }
                file << "--- Batch end ---" << std::endl;
                file.close();
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Batch interval
        }
    });
    
    // Producer threads
    auto produce_operations = [&](const std::string& source) {
        for (int i = 0; i < 10; i++) {
            std::string operation = source + " operation " + std::to_string(i);
            
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                operation_queue.push_back(operation);
            }
            cv.notify_one();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    };
    
    std::thread p1(produce_operations, "Source1");
    std::thread p2(produce_operations, "Source2");
    
    p1.join();
    p2.join();
    
    // Stop processor
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        stop_processing = true;
    }
    cv.notify_one();
    processor.join();
}
// {/fact}

int main() {
    // This function is just for demonstration purposes
    // In a real scenario, you would call the test functions as needed
    std::cout << "File system race condition examples" << std::endl;
    return 0;
}