#include <iostream>
#include <cstdlib>
#include <ctime>
#include <random>
#include <chrono>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
// {fact rule=weak-random-number-generation@v1.0 defects=1}

// True Positives (Vulnerable Code Examples)

void bad_case_1() {
    int secretToken;
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    secretToken = rand() % 1000000; // Generates a predictable "random" token
    std::cout << "Your authentication token is: " << secretToken << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_2() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(42); // Fixed seed makes the sequence completely predictable
    int randomNumber = rand();
    std::cout << "Random number: " << randomNumber << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_3() {
    std::vector<int> numbers = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL)); // Using time as seed is still predictable
    std::random_shuffle(numbers.begin(), numbers.end());
    std::cout << "First shuffled number: " << numbers[0] << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_4() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    int randomKey = rand() % 256; // Using rand() for cryptographic purposes
    char data[] = "Sensitive information";
    // Simple XOR encryption with weak random key
    for (int i = 0; data[i] != '\0'; i++) {
        data[i] ^= randomKey;
    }
    std::cout << "Encrypted: " << data << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_5() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL));
    std::string password;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 12; i++) {
        password += charset[rand() % (sizeof(charset) - 1)];
    }
    std::cout << "Generated password: " << password << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_6() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    int sessionId = rand() % 1000000000; // Using rand() for session ID generation
    std::cout << "Your session ID: " << sessionId << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_7() {
    int array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL));
    int randomIndex = rand() % 10;
    std::cout << "Random element: " << array[randomIndex] << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_8() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(static_cast<unsigned int>(time(nullptr)));
    int dice1 = rand() % 6 + 1;
    int dice2 = rand() % 6 + 1;
    std::cout << "You rolled: " << dice1 << " and " << dice2 << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_9() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    int randomPort = 1024 + (rand() % 64000); // Using rand() to select a network port
    std::cout << "Starting server on port: " << randomPort << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_10() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(42);
    int randomDelay = rand() % 1000; // Using rand() with fixed seed for timing
    std::cout << "Waiting for " << randomDelay << " milliseconds" << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_11() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    int nonce = rand(); // Using rand() to generate a cryptographic nonce
    std::cout << "Using nonce: " << nonce << " for encryption" << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_12() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL));
    int iv[4]; // Initialization vector for encryption
    for (int i = 0; i < 4; i++) {
        iv[i] = rand();
    }
    std::cout << "Using IV: " << iv[0] << iv[1] << iv[2] << iv[3] << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_13() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL));
    int salt = rand(); // Using rand() to generate a salt for password hashing
    std::cout << "Password salt: " << salt << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_14() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    int randomPivot = rand() % 100; // Using rand() for a quicksort pivot
    std::cout << "Pivot element: " << randomPivot << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=1}

void bad_case_15() {
    // ruleid: cpp-incorrect-pseudorandom-number-generator
    srand(time(NULL));
    int randomSeed = rand(); // Using rand() to generate another seed
    std::cout << "Generated seed: " << randomSeed << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

// True Negatives (Secure Code Examples)

void good_case_1() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 999999);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int secretToken = dis(gen); // Using proper PRNG for token generation
    std::cout << "Your authentication token is: " << secretToken << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_2() {
    std::random_device rd;
    std::mt19937 gen(rd());
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomNumber = gen(); // Using mt19937 for better randomness
    std::cout << "Random number: " << randomNumber << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_3() {
    std::vector<int> numbers = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::random_device rd;
    std::mt19937 g(rd());
    // ok: cpp-incorrect-pseudorandom-number-generator
    std::shuffle(numbers.begin(), numbers.end(), g); // Using proper PRNG for shuffling
    std::cout << "First shuffled number: " << numbers[0] << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_4() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomKey = dis(gen); // Using proper PRNG for key generation
    char data[] = "Sensitive information";
    // Simple XOR encryption with better random key
    for (int i = 0; data[i] != '\0'; i++) {
        data[i] ^= randomKey;
    }
    std::cout << "Encrypted: " << data << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_5() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 61);
    std::string password;
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // ok: cpp-incorrect-pseudorandom-number-generator
    for (int i = 0; i < 12; i++) {
        password += charset[dis(gen)]; // Using proper PRNG for password generation
    }
    std::cout << "Generated password: " << password << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_6() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<long long> dis(0, 999999999);
    // ok: cpp-incorrect-pseudorandom-number-generator
    long long sessionId = dis(gen); // Using proper PRNG for session ID
    std::cout << "Your session ID: " << sessionId << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_7() {
    int array[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomIndex = dis(gen); // Using proper PRNG for array index
    std::cout << "Random element: " << array[randomIndex] << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_8() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dice(1, 6);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int dice1 = dice(gen); // Using proper PRNG for dice roll
    int dice2 = dice(gen);
    std::cout << "You rolled: " << dice1 << " and " << dice2 << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_9() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1024, 65000);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomPort = dis(gen); // Using proper PRNG for port selection
    std::cout << "Starting server on port: " << randomPort << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_10() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 999);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomDelay = dis(gen); // Using proper PRNG for delay
    std::cout << "Waiting for " << randomDelay << " milliseconds" << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_11() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // ok: cpp-incorrect-pseudorandom-number-generator
    uint64_t nonce = gen(); // Using proper PRNG for cryptographic nonce
    std::cout << "Using nonce: " << nonce << " for encryption" << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_12() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    uint8_t iv[16]; // Initialization vector for encryption
    // ok: cpp-incorrect-pseudorandom-number-generator
    for (int i = 0; i < 16; i++) {
        iv[i] = dis(gen); // Using proper PRNG for IV generation
    }
    std::cout << "IV generated with secure random numbers" << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_13() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    // ok: cpp-incorrect-pseudorandom-number-generator
    uint64_t salt = gen(); // Using proper PRNG for password salt
    std::cout << "Password salt: " << salt << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_14() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 99);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomPivot = dis(gen); // Using proper PRNG for quicksort pivot
    std::cout << "Pivot element: " << randomPivot << std::endl;
}
// {/fact}
// {fact rule=weak-random-number-generation@v1.0 defects=0}

void good_case_15() {
    // Using system time as entropy source but with a more secure generator
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::mt19937 gen(seed);
    // ok: cpp-incorrect-pseudorandom-number-generator
    int randomValue = gen(); // Using proper PRNG seeded with high-resolution time
    std::cout << "Generated value: " << randomValue << std::endl;
}
// {/fact}

int main() {
    // Just to demonstrate the functions
    std::cout << "Running examples..." << std::endl;
    return 0;
}