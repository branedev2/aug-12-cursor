#include <ctime>
#include <iostream>
#include <chrono>
#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <unordered_map>
// {fact rule=numeric-truncation-error@v1.0 defects=1}

// True Positives (Vulnerable Code)

void bad_case_1() {
    // Using int to store time_t
    // ruleid: cpp-time-data-corruption
    int currentTime = time(NULL);
    std::cout << "Current time: " << currentTime << std::endl;
    
    // Potential data loss when currentTime is used for calculations
    int futureTime = currentTime + 3600; // Add an hour
    std::cout << "Time in an hour: " << futureTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_2() {
    // Using short to store time_t, even worse than int
    time_t now = time(NULL);
    // ruleid: cpp-time-data-corruption
    short timeValue = now;
    
    // Using the truncated time value
    std::cout << "Current time (truncated): " << timeValue << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_3() {
    // Storing time_t in a char array with fixed size
    time_t now = time(NULL);
    // ruleid: cpp-time-data-corruption
    char timeBuffer[2];
    *((short*)timeBuffer) = now;
    
    // Using the corrupted time value
    short extractedTime = *((short*)timeBuffer);
    std::cout << "Extracted time: " << extractedTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_4() {
    // Using int16_t explicitly to store time_t
    time_t currentTime = time(NULL);
    // ruleid: cpp-time-data-corruption
    int16_t shortTime = currentTime;
    
    // Using the truncated time for a calculation
    int16_t timeAfterOneDay = shortTime + 86400; // seconds in a day
    std::cout << "Time after one day: " << timeAfterOneDay << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_5() {
    // Storing time_t in a vector of integers
    std::vector<int> timeHistory;
    time_t now = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    timeHistory.push_back(static_cast<int>(now));
    
    // Using the potentially truncated time
    std::cout << "Stored time: " << timeHistory[0] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_6() {
    // Using unsigned int to store time_t (still potentially too small)
    time_t timestamp = time(NULL);
    // ruleid: cpp-time-data-corruption
    unsigned int timeUint = timestamp;
    
    // Using the potentially truncated time
    std::cout << "Time as unsigned int: " << timeUint << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_7() {
    // Storing time_t in a map with int keys
    std::map<int, std::string> eventLog;
    time_t eventTime = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    int timeKey = eventTime;
    eventLog[timeKey] = "System startup";
    
    // Using the potentially corrupted time key
    std::cout << "Event at " << timeKey << ": " << eventLog[timeKey] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_8() {
    // Converting time_t to int before serialization
    time_t currentTime = time(NULL);
    // ruleid: cpp-time-data-corruption
    int serializedTime = currentTime;
    
    std::ofstream outFile("time_log.dat", std::ios::binary);
    outFile.write(reinterpret_cast<char*>(&serializedTime), sizeof(serializedTime));
    outFile.close();
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_9() {
    // Using int for time difference calculation
    time_t start = time(NULL);
    // Simulate some processing
    for (int i = 0; i < 1000000; i++) {
        // Do something
    }
    time_t end = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    int elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed << " seconds" << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_10() {
    // Storing time_t in a custom structure with int
    struct TimeRecord {
        int timestamp;
        std::string event;
    };
    
    time_t now = time(NULL);
    TimeRecord record;
    // ruleid: cpp-time-data-corruption
    record.timestamp = now;
    record.event = "User login";
    
    std::cout << "Event: " << record.event << " at " << record.timestamp << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_11() {
    // Converting time_t to int32_t explicitly
    time_t largeTime = time(NULL) + 100000000; // Far in the future
    
    // ruleid: cpp-time-data-corruption
    int32_t convertedTime = static_cast<int32_t>(largeTime);
    
    // Using the potentially truncated time
    std::cout << "Future time: " << convertedTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_12() {
    // Using long int which might be too small on some platforms
    time_t currentTime = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    long int timeValue = currentTime;
    
    // Using the potentially truncated time
    std::cout << "Current time as long int: " << timeValue << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_13() {
    // Storing time_t in an unordered_map with int keys
    std::unordered_map<int, std::string> timeEvents;
    time_t eventTime = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    int timeKey = eventTime;
    timeEvents[timeKey] = "Database backup";
    
    // Using the potentially corrupted time key
    std::cout << "Event at " << timeKey << ": " << timeEvents[timeKey] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_14() {
    // Using int for time arithmetic operations
    time_t now = time(NULL);
    // ruleid: cpp-time-data-corruption
    int baseTime = now;
    
    // Calculate a future time (potential overflow)
    int futureTime = baseTime + (86400 * 365); // Roughly a year later
    std::cout << "Time a year from now: " << futureTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=1}

void bad_case_15() {
    // Converting time_t to float (loss of precision)
    time_t currentTime = time(NULL);
    
    // ruleid: cpp-time-data-corruption
    float timeFloat = static_cast<float>(currentTime);
    
    // Using the potentially imprecise time
    std::cout << "Current time as float: " << timeFloat << std::endl;
    float timeAfterOneWeek = timeFloat + (86400 * 7);
    std::cout << "Time after one week: " << timeAfterOneWeek << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

// True Negatives (Safe Code)

void good_case_1() {
    // Using time_t directly without conversion
    // ok: cpp-time-data-corruption
    time_t currentTime = time(NULL);
    std::cout << "Current time: " << currentTime << std::endl;
    
    // Proper time arithmetic
    time_t futureTime = currentTime + 3600; // Add an hour
    std::cout << "Time in an hour: " << futureTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_2() {
    // Using int64_t which is large enough on most platforms
    time_t now = time(NULL);
    // ok: cpp-time-data-corruption
    int64_t timeValue = now;
    
    std::cout << "Current time: " << timeValue << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_3() {
    // Proper storage of time_t in a buffer
    time_t now = time(NULL);
    // ok: cpp-time-data-corruption
    char timeBuffer[sizeof(time_t)];
    *((time_t*)timeBuffer) = now;
    
    time_t extractedTime = *((time_t*)timeBuffer);
    std::cout << "Extracted time: " << extractedTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_4() {
    // Using appropriate type for time storage
    time_t currentTime = time(NULL);
    // ok: cpp-time-data-corruption
    time_t shortTime = currentTime;
    
    // Proper time arithmetic
    time_t timeAfterOneDay = shortTime + 86400; // seconds in a day
    std::cout << "Time after one day: " << timeAfterOneDay << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_5() {
    // Storing time_t in a vector of time_t
    std::vector<time_t> timeHistory;
    time_t now = time(NULL);
    
    // ok: cpp-time-data-corruption
    timeHistory.push_back(now);
    
    std::cout << "Stored time: " << timeHistory[0] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_6() {
    // Using time_t directly
    // ok: cpp-time-data-corruption
    time_t timestamp = time(NULL);
    
    std::cout << "Current timestamp: " << timestamp << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_7() {
    // Storing time_t in a map with time_t keys
    std::map<time_t, std::string> eventLog;
    time_t eventTime = time(NULL);
    
    // ok: cpp-time-data-corruption
    eventLog[eventTime] = "System startup";
    
    std::cout << "Event at " << eventTime << ": " << eventLog[eventTime] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_8() {
    // Serializing time_t directly
    // ok: cpp-time-data-corruption
    time_t currentTime = time(NULL);
    
    std::ofstream outFile("time_log.dat", std::ios::binary);
    outFile.write(reinterpret_cast<char*>(&currentTime), sizeof(currentTime));
    outFile.close();
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_9() {
    // Using time_t for time difference calculation
    time_t start = time(NULL);
    // Simulate some processing
    for (int i = 0; i < 1000000; i++) {
        // Do something
    }
    time_t end = time(NULL);
    
    // ok: cpp-time-data-corruption
    time_t elapsed = end - start;
    std::cout << "Elapsed time: " << elapsed << " seconds" << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_10() {
    // Storing time_t in a custom structure with time_t
    struct TimeRecord {
        time_t timestamp;
        std::string event;
    };
    
    time_t now = time(NULL);
    TimeRecord record;
    // ok: cpp-time-data-corruption
    record.timestamp = now;
    record.event = "User login";
    
    std::cout << "Event: " << record.event << " at " << record.timestamp << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_11() {
    // Using std::chrono for modern time handling
    // ok: cpp-time-data-corruption
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "Current time: " << now_time_t << std::endl;
    
    // Proper time arithmetic with std::chrono
    auto future = now + std::chrono::hours(24);
    auto future_time_t = std::chrono::system_clock::to_time_t(future);
    std::cout << "Time in 24 hours: " << future_time_t << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_12() {
    // Using uint64_t which is large enough for time_t
    time_t currentTime = time(NULL);
    // ok: cpp-time-data-corruption
    uint64_t timeValue = static_cast<uint64_t>(currentTime);
    
    std::cout << "Current time as uint64_t: " << timeValue << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_13() {
    // Storing time_t in an unordered_map with time_t keys
    std::unordered_map<time_t, std::string> timeEvents;
    time_t eventTime = time(NULL);
    
    // ok: cpp-time-data-corruption
    timeEvents[eventTime] = "Database backup";
    
    std::cout << "Event at " << eventTime << ": " << timeEvents[eventTime] << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_14() {
    // Using time_t for time arithmetic operations
    // ok: cpp-time-data-corruption
    time_t now = time(NULL);
    
    // Calculate a future time
    time_t futureTime = now + (86400 * 365); // Roughly a year later
    std::cout << "Time a year from now: " << futureTime << std::endl;
}
// {/fact}
// {fact rule=numeric-truncation-error@v1.0 defects=0}

void good_case_15() {
    // Using double for high precision time if needed
    time_t currentTime = time(NULL);
    
    // ok: cpp-time-data-corruption
    double timeDouble = static_cast<double>(currentTime);
    
    std::cout << "Current time as double: " << timeDouble << std::endl;
    double timeAfterOneWeek = timeDouble + (86400 * 7);
    std::cout << "Time after one week: " << timeAfterOneWeek << std::endl;
}
// {/fact}

int main() {
    // This function is just for demonstration purposes
    std::cout << "Running examples for cpp-time-data-corruption rule" << std::endl;
    return 0;
}