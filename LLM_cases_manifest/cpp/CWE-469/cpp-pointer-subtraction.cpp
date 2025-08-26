#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <algorithm>
// {fact rule=pointer-subtraction@v1.0 defects=1}

// BAD CASES - Unsafe pointer subtraction

void bad_case_1() {
    int arr1[10];
    int arr2[10];
    
    int* p1 = &arr1[5];
    int* p2 = &arr2[3];
    
    // ruleid: cpp-pointer-subtraction
    size_t size = p1 - p2; // Subtracting pointers from different arrays
    std::cout << "Calculated size: " << size << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_2() {
    struct Node {
        int data;
        Node* next;
    };
    
    Node* node1 = new Node{1, nullptr};
    Node* node2 = new Node{2, nullptr};
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = node2 - node1; // Subtracting pointers to unrelated heap objects
    std::cout << "Distance between nodes: " << diff << std::endl;
    
    delete node1;
    delete node2;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_3() {
    std::string str1 = "Hello";
    std::string str2 = "World";
    
    const char* p1 = str1.c_str();
    const char* p2 = str2.c_str();
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = p2 - p1; // Subtracting pointers from different string objects
    std::cout << "Difference: " << diff << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_4() {
    struct Person {
        char name[50];
        int age;
    };
    
    Person person1;
    Person person2;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t offset = reinterpret_cast<char*>(&person2) - reinterpret_cast<char*>(&person1);
    std::cout << "Offset between persons: " << offset << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_5() {
    int* dynamicArray1 = new int[100];
    int* dynamicArray2 = new int[100];
    
    // ruleid: cpp-pointer-subtraction
    size_t distance = dynamicArray2 - dynamicArray1; // Different allocations
    std::cout << "Distance between arrays: " << distance << std::endl;
    
    delete[] dynamicArray1;
    delete[] dynamicArray2;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_6() {
    struct ComplexData {
        int id;
        double value;
        char description[100];
    };
    
    ComplexData* data1 = new ComplexData;
    ComplexData* data2 = new ComplexData;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = data2 - data1; // Unrelated heap objects
    std::cout << "Difference: " << diff << std::endl;
    
    delete data1;
    delete data2;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_7() {
    std::vector<int> vec1 = {1, 2, 3, 4, 5};
    std::vector<int> vec2 = {6, 7, 8, 9, 10};
    
    int* ptr1 = &vec1[0];
    int* ptr2 = &vec2[0];
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = ptr2 - ptr1; // Different vector storage
    std::cout << "Difference between vectors: " << diff << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_8() {
    char buffer1[1024];
    char buffer2[1024];
    
    memset(buffer1, 'A', 1024);
    memset(buffer2, 'B', 1024);
    
    char* end1 = buffer1 + 500;
    char* start2 = buffer2 + 200;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t bytes = end1 - start2; // Different buffers
    std::cout << "Bytes between buffers: " << bytes << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_9() {
    struct {
        int x;
        int y;
    } point1, point2;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t offset = reinterpret_cast<char*>(&point2.y) - reinterpret_cast<char*>(&point1.x);
    std::cout << "Offset: " << offset << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_10() {
    int global1[10];
    int global2[10];
    
    // ruleid: cpp-pointer-subtraction
    size_t distance = &global2[0] - &global1[0]; // Different global arrays
    std::cout << "Distance: " << distance << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_11() {
    std::unique_ptr<int[]> array1(new int[50]);
    std::unique_ptr<int[]> array2(new int[50]);
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = array2.get() - array1.get(); // Different smart pointer managed arrays
    std::cout << "Difference: " << diff << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_12() {
    class MyClass {
    public:
        int value;
    };
    
    MyClass obj1, obj2;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = reinterpret_cast<char*>(&obj2) - reinterpret_cast<char*>(&obj1);
    std::cout << "Object distance: " << diff << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_13() {
    int stack_var;
    int* heap_var = new int;
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = reinterpret_cast<char*>(heap_var) - reinterpret_cast<char*>(&stack_var);
    std::cout << "Stack to heap distance: " << diff << std::endl;
    
    delete heap_var;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_14() {
    struct Node {
        int data;
        char padding[100];
    };
    
    Node nodes[2];
    
    char* p1 = reinterpret_cast<char*>(&nodes[0].data);
    char* p2 = reinterpret_cast<char*>(&nodes[1].padding);
    
    // ruleid: cpp-pointer-subtraction
    ptrdiff_t diff = p2 - p1; // Different members, even though in same array
    std::cout << "Offset: " << diff << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=1}

void bad_case_15() {
    FILE* file1 = fopen("file1.txt", "w");
    FILE* file2 = fopen("file2.txt", "w");
    
    if (file1 && file2) {
        // ruleid: cpp-pointer-subtraction
        ptrdiff_t diff = reinterpret_cast<char*>(file2) - reinterpret_cast<char*>(file1);
        std::cout << "File handle difference: " << diff << std::endl;
        
        fclose(file1);
        fclose(file2);
    }
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

// GOOD CASES - Safe alternatives to pointer subtraction

void good_case_1() {
    int arr[10];
    int* start = &arr[0];
    int* end = &arr[5];
    
    // ok: cpp-pointer-subtraction
    size_t elements = end - start; // Safe: pointers within same array
    std::cout << "Elements: " << elements << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_2() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    
    // ok: cpp-pointer-subtraction
    size_t size = vec.size(); // Using container's size method instead of pointer arithmetic
    std::cout << "Vector size: " << size << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_3() {
    char buffer[100];
    char* start = buffer;
    char* current = buffer + 50;
    
    // ok: cpp-pointer-subtraction
    size_t bytesProcessed = current - start; // Safe: pointers within same buffer
    std::cout << "Bytes processed: " << bytesProcessed << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_4() {
    std::string str = "Hello, world!";
    
    // ok: cpp-pointer-subtraction
    size_t length = str.length(); // Using string's length method
    std::cout << "String length: " << length << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_5() {
    int arr[100];
    
    // ok: cpp-pointer-subtraction
    size_t arraySize = sizeof(arr) / sizeof(arr[0]); // Using sizeof for array size
    std::cout << "Array size: " << arraySize << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_6() {
    int* dynamicArray = new int[100];
    size_t size = 100; // Explicitly tracking size
    
    // Process array
    for (size_t i = 0; i < size; i++) {
        dynamicArray[i] = i;
    }
    
    // ok: cpp-pointer-subtraction
    std::cout << "Array size: " << size << std::endl; // Using tracked size instead of pointer subtraction
    
    delete[] dynamicArray;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_7() {
    struct Buffer {
        char* data;
        size_t size;
    };
    
    Buffer buffer;
    buffer.data = new char[1024];
    buffer.size = 1024;
    
    // ok: cpp-pointer-subtraction
    std::cout << "Buffer size: " << buffer.size << std::endl; // Using explicit size field
    
    delete[] buffer.data;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_8() {
    int arr[10];
    int* p1 = &arr[3];
    int* p2 = &arr[7];
    
    // ok: cpp-pointer-subtraction
    if (p2 > p1) { // Comparing pointers within the same array
        size_t elements = p2 - p1;
        std::cout << "Elements between pointers: " << elements << std::endl;
    }
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_9() {
    std::vector<int> numbers = {10, 20, 30, 40, 50};
    auto it1 = numbers.begin();
    auto it2 = numbers.begin() + 3;
    
    // ok: cpp-pointer-subtraction
    std::ptrdiff_t distance = std::distance(it1, it2); // Using std::distance for iterators
    std::cout << "Distance: " << distance << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_10() {
    char text[] = "Hello, world!";
    char* end = text + strlen(text);
    char* current = strchr(text, ',');
    
    if (current) {
        // ok: cpp-pointer-subtraction
        size_t position = current - text; // Safe: pointers within same string
        std::cout << "Comma position: " << position << std::endl;
    }
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_11() {
    struct Record {
        int id;
        double value;
    };
    
    Record records[100];
    
    // ok: cpp-pointer-subtraction
    size_t recordCount = sizeof(records) / sizeof(Record); // Using sizeof for count
    std::cout << "Record count: " << recordCount << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_12() {
    int matrix[10][10];
    
    // ok: cpp-pointer-subtraction
    size_t rows = sizeof(matrix) / sizeof(matrix[0]);
    size_t cols = sizeof(matrix[0]) / sizeof(matrix[0][0]);
    
    std::cout << "Matrix dimensions: " << rows << "x" << cols << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_13() {
    int* array = new int[50];
    size_t arraySize = 50;
    
    int* p1 = &array[10];
    int* p2 = &array[20];
    
    // ok: cpp-pointer-subtraction
    if (p1 < p2 && p2 < array + arraySize) { // Safe comparison within same allocation
        size_t elementsBetween = p2 - p1;
        std::cout << "Elements between pointers: " << elementsBetween << std::endl;
    }
    
    delete[] array;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_14() {
    std::string data = "Example data for processing";
    const char* start = data.c_str();
    const char* end = start + data.length();
    const char* current = start;
    
    while (current < end) {
        // Process character
        current++;
    }
    
    // ok: cpp-pointer-subtraction
    size_t processed = current - start; // Safe: pointers within same string data
    std::cout << "Processed " << processed << " characters" << std::endl;
}
// {/fact}
// {fact rule=pointer-subtraction@v1.0 defects=0}

void good_case_15() {
    int arr[100];
    int* begin = arr;
    int* end = arr + 100;
    
    // Fill array
    for (int* p = begin; p != end; ++p) {
        *p = 0;
    }
    
    // ok: cpp-pointer-subtraction
    size_t count = end - begin; // Safe: pointers within same array
    std::cout << "Array count: " << count << std::endl;
}
// {/fact}

int main() {
    // Test cases can be called here
    return 0;
}