// Static Initialization Order Fiasco Examples
// Rule ID: cpp-static-initialization-order-fiasco
// CWE: CWE-362

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <fstream>
#include <map>
#include <set>
#include <thread>

// ==================== TRUE POSITIVES ====================

// File: globals_a.h (Simulated in comments)
// int globalCounter = 0;
// std::string globalName = "Default";

// File: globals_b.h (Simulated in comments)
// extern int globalCounter;
// extern std::string globalName;

// File: bad_case_1.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global variable in one translation unit depends on a global from another unit
std::string globalAppName = "MyApp";
class Logger {
public:
    Logger() {
        std::cout << "Logger initialized with app name: " << globalAppName << std::endl;
    }
    void log(const std::string& message) {
        std::cout << "[" << globalAppName << "] " << message << std::endl;
    }
};

// In another translation unit (simulated)
Logger globalLogger; // Depends on globalAppName, but initialization order is not guaranteed
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_1() {
    // Using the logger might access uninitialized globalAppName
    globalLogger.log("Application started");
}
// {/fact}

// File: bad_case_2.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global configuration depends on global database connection
class Database {
public:
    Database() { std::cout << "Database initialized" << std::endl; }
    bool isConnected() const { return true; }
};

// In one translation unit
Database globalDb;

// In another translation unit (simulated)
class Config {
public:
    Config() {
        // This might use globalDb before it's initialized
        if (globalDb.isConnected()) {
            std::cout << "Loading config from database" << std::endl;
        }
    }
};
Config globalConfig; // Depends on globalDb
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_2() {
    // Using globalConfig might have already caused issues during initialization
    std::cout << "Application configured" << std::endl;
}
// {/fact}

// File: bad_case_3.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global registry depends on global factory
class Factory {
public:
    Factory() { std::cout << "Factory initialized" << std::endl; }
    int createObject() const { return 42; }
};

// In one translation unit
Factory globalFactory;

// In another translation unit (simulated)
class Registry {
public:
    Registry() {
        // This might use globalFactory before it's initialized
        registeredObjects.push_back(globalFactory.createObject());
    }
    std::vector<int> registeredObjects;
};
Registry globalRegistry; // Depends on globalFactory
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_3() {
    // Using globalRegistry might access objects created with uninitialized globalFactory
    std::cout << "Registry has " << globalRegistry.registeredObjects.size() << " objects" << std::endl;
}
// {/fact}

// File: bad_case_4.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global mutex used by global resource manager
std::mutex globalMutex;

// In another translation unit (simulated)
class ResourceManager {
public:
    ResourceManager() {
        // This might use globalMutex before it's initialized
        std::lock_guard<std::mutex> lock(globalMutex);
        std::cout << "Resource manager initialized with lock" << std::endl;
    }
};
ResourceManager globalResourceManager;
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_4() {
    // Using globalResourceManager might have already caused issues during initialization
    std::cout << "Resource manager ready" << std::endl;
}
// {/fact}

// File: bad_case_5.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global settings object depends on global file system
class FileSystem {
public:
    FileSystem() { std::cout << "FileSystem initialized" << std::endl; }
    bool fileExists(const std::string& path) const { return true; }
};

// In one translation unit
FileSystem globalFileSystem;

// In another translation unit (simulated)
class Settings {
public:
    Settings() {
        // This might use globalFileSystem before it's initialized
        if (globalFileSystem.fileExists("settings.conf")) {
            std::cout << "Loading settings from file" << std::endl;
        }
    }
};
Settings globalSettings; // Depends on globalFileSystem
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_5() {
    // Using globalSettings might have already caused issues during initialization
    std::cout << "Settings loaded" << std::endl;
}
// {/fact}

// File: bad_case_6.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global cache depends on global memory manager
class MemoryManager {
public:
    MemoryManager() { std::cout << "Memory manager initialized" << std::endl; }
    void* allocate(size_t size) const { return malloc(size); }
};

// In one translation unit
MemoryManager globalMemoryManager;

// In another translation unit (simulated)
class Cache {
public:
    Cache() {
        // This might use globalMemoryManager before it's initialized
        buffer = globalMemoryManager.allocate(1024);
    }
    ~Cache() { free(buffer); }
    void* buffer;
};
Cache globalCache; // Depends on globalMemoryManager
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_6() {
    // Using globalCache might access memory allocated with uninitialized globalMemoryManager
    std::cout << "Cache initialized with buffer at " << globalCache.buffer << std::endl;
}
// {/fact}

// File: bad_case_7.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global event dispatcher depends on global event queue
class EventQueue {
public:
    EventQueue() { std::cout << "Event queue initialized" << std::endl; }
    bool hasEvents() const { return false; }
};

// In one translation unit
EventQueue globalEventQueue;

// In another translation unit (simulated)
class EventDispatcher {
public:
    EventDispatcher() {
        // This might use globalEventQueue before it's initialized
        if (globalEventQueue.hasEvents()) {
            std::cout << "Processing initial events" << std::endl;
        }
    }
};
EventDispatcher globalEventDispatcher; // Depends on globalEventQueue
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_7() {
    // Using globalEventDispatcher might have already caused issues during initialization
    std::cout << "Event dispatcher ready" << std::endl;
}
// {/fact}

// File: bad_case_8.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global network manager depends on global configuration
class NetworkConfig {
public:
    NetworkConfig() { std::cout << "Network config initialized" << std::endl; }
    int getPort() const { return 8080; }
};

// In one translation unit
NetworkConfig globalNetworkConfig;

// In another translation unit (simulated)
class NetworkManager {
public:
    NetworkManager() {
        // This might use globalNetworkConfig before it's initialized
        port = globalNetworkConfig.getPort();
    }
    int port;
};
NetworkManager globalNetworkManager; // Depends on globalNetworkConfig
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_8() {
    // Using globalNetworkManager might access values from uninitialized globalNetworkConfig
    std::cout << "Network manager listening on port " << globalNetworkManager.port << std::endl;
}
// {/fact}

// File: bad_case_9.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global error handler depends on global logger instance
class LoggerService {
public:
    LoggerService() { std::cout << "Logger service initialized" << std::endl; }
    void log(const std::string& message) const { std::cout << message << std::endl; }
};

// In one translation unit
LoggerService globalLoggerService;

// In another translation unit (simulated)
class ErrorHandler {
public:
    ErrorHandler() {
        // This might use globalLoggerService before it's initialized
        globalLoggerService.log("Error handler initialized");
    }
};
ErrorHandler globalErrorHandler; // Depends on globalLoggerService
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_9() {
    // Using globalErrorHandler might have already caused issues during initialization
    std::cout << "Error handler ready" << std::endl;
}
// {/fact}

// File: bad_case_10.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global UI manager depends on global theme
class Theme {
public:
    Theme() { std::cout << "Theme initialized" << std::endl; }
    std::string getBackgroundColor() const { return "#FFFFFF"; }
};

// In one translation unit
Theme globalTheme;

// In another translation unit (simulated)
class UIManager {
public:
    UIManager() {
        // This might use globalTheme before it's initialized
        backgroundColor = globalTheme.getBackgroundColor();
    }
    std::string backgroundColor;
};
UIManager globalUIManager; // Depends on globalTheme
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_10() {
    // Using globalUIManager might access values from uninitialized globalTheme
    std::cout << "UI manager using background color: " << globalUIManager.backgroundColor << std::endl;
}
// {/fact}

// File: bad_case_11.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global plugin manager depends on global registry
class PluginRegistry {
public:
    PluginRegistry() { std::cout << "Plugin registry initialized" << std::endl; }
    bool isPluginRegistered(const std::string& name) const { return true; }
};

// In one translation unit
PluginRegistry globalPluginRegistry;

// In another translation unit (simulated)
class PluginManager {
public:
    PluginManager() {
        // This might use globalPluginRegistry before it's initialized
        if (globalPluginRegistry.isPluginRegistered("core")) {
            std::cout << "Core plugin found" << std::endl;
        }
    }
};
PluginManager globalPluginManager; // Depends on globalPluginRegistry
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_11() {
    // Using globalPluginManager might have already caused issues during initialization
    std::cout << "Plugin manager ready" << std::endl;
}
// {/fact}

// File: bad_case_12.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global security manager depends on global credentials store
class CredentialsStore {
public:
    CredentialsStore() { std::cout << "Credentials store initialized" << std::endl; }
    bool hasCredentials() const { return true; }
};

// In one translation unit
CredentialsStore globalCredentialsStore;

// In another translation unit (simulated)
class SecurityManager {
public:
    SecurityManager() {
        // This might use globalCredentialsStore before it's initialized
        isSecure = globalCredentialsStore.hasCredentials();
    }
    bool isSecure;
};
SecurityManager globalSecurityManager; // Depends on globalCredentialsStore
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_12() {
    // Using globalSecurityManager might access values from uninitialized globalCredentialsStore
    std::cout << "Security manager secure status: " << globalSecurityManager.isSecure << std::endl;
}
// {/fact}

// File: bad_case_13.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global task scheduler depends on global thread pool
class ThreadPool {
public:
    ThreadPool() { std::cout << "Thread pool initialized" << std::endl; }
    int getThreadCount() const { return 4; }
};

// In one translation unit
ThreadPool globalThreadPool;

// In another translation unit (simulated)
class TaskScheduler {
public:
    TaskScheduler() {
        // This might use globalThreadPool before it's initialized
        threadCount = globalThreadPool.getThreadCount();
    }
    int threadCount;
};
TaskScheduler globalTaskScheduler; // Depends on globalThreadPool
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_13() {
    // Using globalTaskScheduler might access values from uninitialized globalThreadPool
    std::cout << "Task scheduler using " << globalTaskScheduler.threadCount << " threads" << std::endl;
}
// {/fact}

// File: bad_case_14.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global data processor depends on global data source
class DataSource {
public:
    DataSource() { std::cout << "Data source initialized" << std::endl; }
    bool hasData() const { return true; }
};

// In one translation unit
DataSource globalDataSource;

// In another translation unit (simulated)
class DataProcessor {
public:
    DataProcessor() {
        // This might use globalDataSource before it's initialized
        if (globalDataSource.hasData()) {
            std::cout << "Processing initial data" << std::endl;
        }
    }
};
DataProcessor globalDataProcessor; // Depends on globalDataSource
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_14() {
    // Using globalDataProcessor might have already caused issues during initialization
    std::cout << "Data processor ready" << std::endl;
}
// {/fact}

// File: bad_case_15.cpp
// ruleid: cpp-static-initialization-order-fiasco
// Global metrics collector depends on global metrics registry
class MetricsRegistry {
public:
    MetricsRegistry() { std::cout << "Metrics registry initialized" << std::endl; }
    void registerMetric(const std::string& name) { std::cout << "Registered metric: " << name << std::endl; }
};

// In one translation unit
MetricsRegistry globalMetricsRegistry;

// In another translation unit (simulated)
class MetricsCollector {
public:
    MetricsCollector() {
        // This might use globalMetricsRegistry before it's initialized
        globalMetricsRegistry.registerMetric("startup_time");
    }
};
MetricsCollector globalMetricsCollector; // Depends on globalMetricsRegistry
// {fact rule=thread-safety-violation@v1.0 defects=1}

void bad_case_15() {
    // Using globalMetricsCollector might have already caused issues during initialization
    std::cout << "Metrics collector ready" << std::endl;
}
// {/fact}

// ==================== TRUE NEGATIVES ====================

// File: good_case_1.cpp
// ok: cpp-static-initialization-order-fiasco
// Using the Singleton pattern to ensure proper initialization
class LoggerSingleton {
private:
    LoggerSingleton() {
        std::cout << "Logger singleton initialized" << std::endl;
    }
    
public:
    static LoggerSingleton& getInstance() {
        static LoggerSingleton instance; // Initialized on first use
        return instance;
    }
    
    void log(const std::string& message) {
        std::cout << "[LOG] " << message << std::endl;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_1() {
    // Safe access to logger through singleton pattern
    LoggerSingleton::getInstance().log("Application started");
}
// {/fact}

// File: good_case_2.cpp
// ok: cpp-static-initialization-order-fiasco
// Using local static variables instead of globals
class Database {
public:
    Database() { std::cout << "Database initialized" << std::endl; }
    bool isConnected() const { return true; }
};

class Config {
public:
    Config() {
        // Get database instance safely
        if (getDatabase().isConnected()) {
            std::cout << "Loading config from database" << std::endl;
        }
    }
    
    static Database& getDatabase() {
        static Database instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_2() {
    // Safe access to config and database through local static variables
    Config config;
    std::cout << "Application configured" << std::endl;
}
// {/fact}

// File: good_case_3.cpp
// ok: cpp-static-initialization-order-fiasco
// Using function local statics for registry and factory
class Factory {
public:
    Factory() { std::cout << "Factory initialized" << std::endl; }
    int createObject() const { return 42; }
    
    static Factory& getInstance() {
        static Factory instance; // Initialized on first use
        return instance;
    }
};

class Registry {
public:
    Registry() {
        // Safe access to factory through getInstance
        registeredObjects.push_back(Factory::getInstance().createObject());
    }
    
    static Registry& getInstance() {
        static Registry instance; // Initialized on first use
        return instance;
    }
    
    std::vector<int> registeredObjects;
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_3() {
    // Safe access to registry and factory through getInstance
    std::cout << "Registry has " << Registry::getInstance().registeredObjects.size() << " objects" << std::endl;
}
// {/fact}

// File: good_case_4.cpp
// ok: cpp-static-initialization-order-fiasco
// Using function to get mutex instance
std::mutex& getMutex() {
    static std::mutex instance; // Initialized on first use
    return instance;
}

class ResourceManager {
public:
    ResourceManager() {
        // Safe access to mutex through function
        std::lock_guard<std::mutex> lock(getMutex());
        std::cout << "Resource manager initialized with lock" << std::endl;
    }
    
    static ResourceManager& getInstance() {
        static ResourceManager instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_4() {
    // Safe access to resource manager through getInstance
    ResourceManager::getInstance();
    std::cout << "Resource manager ready" << std::endl;
}
// {/fact}

// File: good_case_5.cpp
// ok: cpp-static-initialization-order-fiasco
// Using initialization function that's explicitly called in main
class FileSystem {
public:
    FileSystem() { std::cout << "FileSystem initialized" << std::endl; }
    bool fileExists(const std::string& path) const { return true; }
    
    static FileSystem& getInstance() {
        static FileSystem instance; // Initialized on first use
        return instance;
    }
};

class Settings {
public:
    Settings() {
        // Safe access to file system through getInstance
        if (FileSystem::getInstance().fileExists("settings.conf")) {
            std::cout << "Loading settings from file" << std::endl;
        }
    }
    
    static Settings& getInstance() {
        static Settings instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_5() {
    // Safe access to settings and file system through getInstance
    Settings::getInstance();
    std::cout << "Settings loaded" << std::endl;
}
// {/fact}

// File: good_case_6.cpp
// ok: cpp-static-initialization-order-fiasco
// Using dependency injection instead of global variables
class MemoryManager {
public:
    MemoryManager() { std::cout << "Memory manager initialized" << std::endl; }
    void* allocate(size_t size) const { return malloc(size); }
};

class Cache {
private:
    void* buffer;
    
public:
    Cache(const MemoryManager& mm) {
        // Safe access to memory manager through constructor parameter
        buffer = mm.allocate(1024);
    }
    
    ~Cache() { free(buffer); }
    void* getBuffer() const { return buffer; }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_6() {
    // Explicitly control initialization order
    MemoryManager mm;
    Cache cache(mm);
    std::cout << "Cache initialized with buffer at " << cache.getBuffer() << std::endl;
}
// {/fact}

// File: good_case_7.cpp
// ok: cpp-static-initialization-order-fiasco
// Using Meyer's singleton for event system
class EventQueue {
private:
    EventQueue() { std::cout << "Event queue initialized" << std::endl; }
    
public:
    static EventQueue& getInstance() {
        static EventQueue instance; // Initialized on first use
        return instance;
    }
    
    bool hasEvents() const { return false; }
};

class EventDispatcher {
public:
    EventDispatcher() {
        // Safe access to event queue through getInstance
        if (EventQueue::getInstance().hasEvents()) {
            std::cout << "Processing initial events" << std::endl;
        }
    }
    
    static EventDispatcher& getInstance() {
        static EventDispatcher instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_7() {
    // Safe access to event dispatcher through getInstance
    EventDispatcher::getInstance();
    std::cout << "Event dispatcher ready" << std::endl;
}
// {/fact}

// File: good_case_8.cpp
// ok: cpp-static-initialization-order-fiasco
// Using initialization method that's explicitly called
class NetworkConfig {
public:
    NetworkConfig() { std::cout << "Network config initialized" << std::endl; }
    int getPort() const { return 8080; }
    
    static NetworkConfig& getInstance() {
        static NetworkConfig instance; // Initialized on first use
        return instance;
    }
};

class NetworkManager {
private:
    int port;
    
public:
    void initialize() {
        // Safe access to network config through getInstance
        port = NetworkConfig::getInstance().getPort();
    }
    
    int getPort() const { return port; }
    
    static NetworkManager& getInstance() {
        static NetworkManager instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_8() {
    // Explicitly control initialization order
    NetworkManager::getInstance().initialize();
    std::cout << "Network manager listening on port " << NetworkManager::getInstance().getPort() << std::endl;
}
// {/fact}

// File: good_case_9.cpp
// ok: cpp-static-initialization-order-fiasco
// Using lazy initialization for error handler
class LoggerService {
private:
    LoggerService() { std::cout << "Logger service initialized" << std::endl; }
    
public:
    static LoggerService& getInstance() {
        static LoggerService instance; // Initialized on first use
        return instance;
    }
    
    void log(const std::string& message) const { std::cout << message << std::endl; }
};

class ErrorHandler {
private:
    ErrorHandler() {
        // Safe access to logger service through getInstance
        LoggerService::getInstance().log("Error handler initialized");
    }
    
public:
    static ErrorHandler& getInstance() {
        static ErrorHandler instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_9() {
    // Safe access to error handler through getInstance
    ErrorHandler::getInstance();
    std::cout << "Error handler ready" << std::endl;
}
// {/fact}

// File: good_case_10.cpp
// ok: cpp-static-initialization-order-fiasco
// Using local initialization for UI components
class Theme {
public:
    Theme() { std::cout << "Theme initialized" << std::endl; }
    std::string getBackgroundColor() const { return "#FFFFFF"; }
    
    static Theme& getInstance() {
        static Theme instance; // Initialized on first use
        return instance;
    }
};

class UIManager {
private:
    std::string backgroundColor;
    
public:
    void initialize() {
        // Safe access to theme through getInstance
        backgroundColor = Theme::getInstance().getBackgroundColor();
    }
    
    std::string getBackgroundColor() const { return backgroundColor; }
    
    static UIManager& getInstance() {
        static UIManager instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_10() {
    // Explicitly control initialization order
    UIManager::getInstance().initialize();
    std::cout << "UI manager using background color: " << UIManager::getInstance().getBackgroundColor() << std::endl;
}
// {/fact}

// File: good_case_11.cpp
// ok: cpp-static-initialization-order-fiasco
// Using function-local static for plugin system
class PluginRegistry {
private:
    PluginRegistry() { std::cout << "Plugin registry initialized" << std::endl; }
    
public:
    static PluginRegistry& getInstance() {
        static PluginRegistry instance; // Initialized on first use
        return instance;
    }
    
    bool isPluginRegistered(const std::string& name) const { return true; }
};

class PluginManager {
public:
    PluginManager() {
        // Safe access to plugin registry through getInstance
        if (PluginRegistry::getInstance().isPluginRegistered("core")) {
            std::cout << "Core plugin found" << std::endl;
        }
    }
    
    static PluginManager& getInstance() {
        static PluginManager instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_11() {
    // Safe access to plugin manager through getInstance
    PluginManager::getInstance();
    std::cout << "Plugin manager ready" << std::endl;
}
// {/fact}

// File: good_case_12.cpp
// ok: cpp-static-initialization-order-fiasco
// Using explicit initialization for security components
class CredentialsStore {
private:
    CredentialsStore() { std::cout << "Credentials store initialized" << std::endl; }
    
public:
    static CredentialsStore& getInstance() {
        static CredentialsStore instance; // Initialized on first use
        return instance;
    }
    
    bool hasCredentials() const { return true; }
};

class SecurityManager {
private:
    bool isSecure;
    
public:
    void initialize() {
        // Safe access to credentials store through getInstance
        isSecure = CredentialsStore::getInstance().hasCredentials();
    }
    
    bool getSecureStatus() const { return isSecure; }
    
    static SecurityManager& getInstance() {
        static SecurityManager instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_12() {
    // Explicitly control initialization order
    SecurityManager::getInstance().initialize();
    std::cout << "Security manager secure status: " << SecurityManager::getInstance().getSecureStatus() << std::endl;
}
// {/fact}

// File: good_case_13.cpp
// ok: cpp-static-initialization-order-fiasco
// Using function-local static for thread management
class ThreadPool {
private:
    ThreadPool() { std::cout << "Thread pool initialized" << std::endl; }
    
public:
    static ThreadPool& getInstance() {
        static ThreadPool instance; // Initialized on first use
        return instance;
    }
    
    int getThreadCount() const { return 4; }
};

class TaskScheduler {
private:
    int threadCount;
    
public:
    void initialize() {
        // Safe access to thread pool through getInstance
        threadCount = ThreadPool::getInstance().getThreadCount();
    }
    
    int getThreadCount() const { return threadCount; }
    
    static TaskScheduler& getInstance() {
        static TaskScheduler instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_13() {
    // Explicitly control initialization order
    TaskScheduler::getInstance().initialize();
    std::cout << "Task scheduler using " << TaskScheduler::getInstance().getThreadCount() << " threads" << std::endl;
}
// {/fact}

// File: good_case_14.cpp
// ok: cpp-static-initialization-order-fiasco
// Using dependency injection for data components
class DataSource {
public:
    DataSource() { std::cout << "Data source initialized" << std::endl; }
    bool hasData() const { return true; }
};

class DataProcessor {
public:
    DataProcessor(const DataSource& ds) {
        // Safe access to data source through constructor parameter
        if (ds.hasData()) {
            std::cout << "Processing initial data" << std::endl;
        }
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_14() {
    // Explicitly control initialization order
    DataSource dataSource;
    DataProcessor dataProcessor(dataSource);
    std::cout << "Data processor ready" << std::endl;
}
// {/fact}

// File: good_case_15.cpp
// ok: cpp-static-initialization-order-fiasco
// Using function-local static for metrics system
class MetricsRegistry {
private:
    MetricsRegistry() { std::cout << "Metrics registry initialized" << std::endl; }
    
public:
    static MetricsRegistry& getInstance() {
        static MetricsRegistry instance; // Initialized on first use
        return instance;
    }
    
    void registerMetric(const std::string& name) { std::cout << "Registered metric: " << name << std::endl; }
};

class MetricsCollector {
public:
    MetricsCollector() {
        // Safe access to metrics registry through getInstance
        MetricsRegistry::getInstance().registerMetric("startup_time");
    }
    
    static MetricsCollector& getInstance() {
        static MetricsCollector instance; // Initialized on first use
        return instance;
    }
};
// {fact rule=thread-safety-violation@v1.0 defects=0}

void good_case_15() {
    // Safe access to metrics collector through getInstance
    MetricsCollector::getInstance();
    std::cout << "Metrics collector ready" << std::endl;
}
// {/fact}

int main() {
    // Call all test cases
    return 0;
}