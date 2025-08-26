#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <curl/curl.h>

// Helper structure for HTTP responses
struct HttpResponse {
    char* data;
    size_t size;
};

// Helper function to initialize HTTP response
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct HttpResponse* mem = (struct HttpResponse*)userp;
    
    char* ptr = (char*)realloc(mem->data, mem->size + realsize + 1);
    if(!ptr) {
        printf("Not enough memory\n");
        return 0;
    }
    
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    
    return realsize;
}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    char buffer[50];
    char* user_input = "This is a very long string that will cause buffer overflow";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(buffer, "User input: %s", user_input);
    
    printf("Formatted string: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_2() {
    char small_buffer[10];
    int value = 12345;
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(small_buffer, "Number: %d", value);
    
    printf("Result: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_3() {
    // HTTP request to get user data
    CURL* curl;
    CURLcode res;
    struct HttpResponse chunk;
    chunk.data = (char*)malloc(1);
    chunk.size = 0;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/user");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if(res == CURLE_OK) {
            char output_buffer[100];
            // ruleid: cpp-insecure-api-sprintf-vsprintf
            sprintf(output_buffer, "Response: %s", chunk.data);
            printf("%s\n", output_buffer);
        }
        
        free(chunk.data);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_4() {
    char buffer[20];
    const char* format = "%s %s %s %s";
    const char* str1 = "Hello";
    const char* str2 = "World";
    const char* str3 = "This";
    const char* str4 = "Works";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(buffer, format, str1, str2, str3, str4);
    
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_5(const char* username) {
    char log_message[50];
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(log_message, "User %s logged in", username);
    
    printf("%s\n", log_message);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_6() {
    va_list args;
    char buffer[100];
    const char* format = "This is a %s with %d parameters";
    
    // Simulating va_list initialization
    va_list args_copy;
    va_copy(args_copy, args);
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    vsprintf(buffer, format, args_copy);
    
    va_end(args_copy);
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_7() {
    char filename[20];
    int file_id = 12345;
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(filename, "file_%d.txt", file_id);
    
    FILE* file = fopen(filename, "w");
    if(file) {
        fprintf(file, "Some content");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_8() {
    CURL* curl;
    CURLcode res;
    struct HttpResponse chunk;
    chunk.data = (char*)malloc(1);
    chunk.size = 0;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/data");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if(res == CURLE_OK) {
            char query[200];
            // ruleid: cpp-insecure-api-sprintf-vsprintf
            sprintf(query, "SELECT * FROM users WHERE name='%s'", chunk.data);
            printf("Executing query: %s\n", query);
        }
        
        free(chunk.data);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_9() {
    char command[100];
    const char* user_input = "file.txt; rm -rf /";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(command, "cat %s", user_input);
    
    system(command);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_10() {
    va_list args;
    char small_buffer[10];
    const char* format = "Long format string with many arguments: %s %d %f";
    
    // Simulating va_list initialization
    va_list args_copy;
    va_copy(args_copy, args);
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    vsprintf(small_buffer, format, args_copy);
    
    va_end(args_copy);
    printf("Result: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_11() {
    char url[50];
    const char* base_url = "https://example.com/api";
    const char* endpoint = "/users/profile";
    const char* query_params = "?id=12345&full=true&details=complete";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(url, "%s%s%s", base_url, endpoint, query_params);
    
    printf("URL: %s\n", url);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_12() {
    char html_output[100];
    const char* username = "<script>alert('XSS')</script>";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(html_output, "<div>Welcome, %s!</div>", username);
    
    printf("HTML: %s\n", html_output);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_13() {
    char error_log[30];
    int error_code = 404;
    const char* error_message = "Page not found - This is a very detailed error message that explains what happened";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(error_log, "Error %d: %s", error_code, error_message);
    
    printf("Logged: %s\n", error_log);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_14() {
    char buffer[20];
    for(int i = 0; i < 10; i++) {
        // ruleid: cpp-insecure-api-sprintf-vsprintf
        sprintf(buffer, "Count: %d of 10", i);
        printf("%s\n", buffer);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=1}

void bad_case_15() {
    char json_buffer[50];
    const char* user_data = "John Doe, 30 years old, Software Engineer with 8 years of experience";
    
    // ruleid: cpp-insecure-api-sprintf-vsprintf
    sprintf(json_buffer, "{\"user\": \"%s\"}", user_data);
    
    printf("JSON: %s\n", json_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    char buffer[50];
    char* user_input = "This is a very long string that will cause buffer overflow";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(buffer, sizeof(buffer), "User input: %s", user_input);
    
    printf("Formatted string: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_2() {
    char small_buffer[10];
    int value = 12345;
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(small_buffer, sizeof(small_buffer), "Number: %d", value);
    
    printf("Result: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_3() {
    // HTTP request to get user data
    CURL* curl;
    CURLcode res;
    struct HttpResponse chunk;
    chunk.data = (char*)malloc(1);
    chunk.size = 0;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/user");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if(res == CURLE_OK) {
            char output_buffer[100];
            // ok: cpp-insecure-api-sprintf-vsprintf
            snprintf(output_buffer, sizeof(output_buffer), "Response: %s", chunk.data);
            printf("%s\n", output_buffer);
        }
        
        free(chunk.data);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_4() {
    char buffer[20];
    const char* format = "%s %s %s %s";
    const char* str1 = "Hello";
    const char* str2 = "World";
    const char* str3 = "This";
    const char* str4 = "Works";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(buffer, sizeof(buffer), format, str1, str2, str3, str4);
    
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_5(const char* username) {
    char log_message[50];
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(log_message, sizeof(log_message), "User %s logged in", username);
    
    printf("%s\n", log_message);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_6() {
    va_list args;
    char buffer[100];
    const char* format = "This is a %s with %d parameters";
    
    // Simulating va_list initialization
    va_list args_copy;
    va_copy(args_copy, args);
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    vsnprintf(buffer, sizeof(buffer), format, args_copy);
    
    va_end(args_copy);
    printf("Result: %s\n", buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_7() {
    char filename[20];
    int file_id = 12345;
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(filename, sizeof(filename), "file_%d.txt", file_id);
    
    FILE* file = fopen(filename, "w");
    if(file) {
        fprintf(file, "Some content");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_8() {
    CURL* curl;
    CURLcode res;
    struct HttpResponse chunk;
    chunk.data = (char*)malloc(1);
    chunk.size = 0;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api/data");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if(res == CURLE_OK) {
            char query[200];
            // ok: cpp-insecure-api-sprintf-vsprintf
            snprintf(query, sizeof(query), "SELECT * FROM users WHERE name='%s'", chunk.data);
            printf("Executing query: %s\n", query);
        }
        
        free(chunk.data);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_9() {
    char command[100];
    const char* user_input = "file.txt; rm -rf /";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(command, sizeof(command), "cat %s", user_input);
    
    // Note: This is still vulnerable to command injection, but the buffer overflow is prevented
    system(command);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_10() {
    va_list args;
    char small_buffer[10];
    const char* format = "Long format string with many arguments: %s %d %f";
    
    // Simulating va_list initialization
    va_list args_copy;
    va_copy(args_copy, args);
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    vsnprintf(small_buffer, sizeof(small_buffer), format, args_copy);
    
    va_end(args_copy);
    printf("Result: %s\n", small_buffer);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_11() {
    char url[50];
    const char* base_url = "https://example.com/api";
    const char* endpoint = "/users/profile";
    const char* query_params = "?id=12345&full=true&details=complete";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(url, sizeof(url), "%s%s%s", base_url, endpoint, query_params);
    
    printf("URL: %s\n", url);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_12() {
    char html_output[100];
    const char* username = "<script>alert('XSS')</script>";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(html_output, sizeof(html_output), "<div>Welcome, %s!</div>", username);
    
    printf("HTML: %s\n", html_output);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_13() {
    char error_log[30];
    int error_code = 404;
    const char* error_message = "Page not found - This is a very detailed error message that explains what happened";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(error_log, sizeof(error_log), "Error %d: %s", error_code, error_message);
    
    printf("Logged: %s\n", error_log);
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_14() {
    char buffer[20];
    for(int i = 0; i < 10; i++) {
        // ok: cpp-insecure-api-sprintf-vsprintf
        snprintf(buffer, sizeof(buffer), "Count: %d of 10", i);
        printf("%s\n", buffer);
    }
}
// {/fact}
// {fact rule=insecure-buffer-access@v1.0 defects=0}

void good_case_15() {
    char json_buffer[50];
    const char* user_data = "John Doe, 30 years old, Software Engineer with 8 years of experience";
    
    // ok: cpp-insecure-api-sprintf-vsprintf
    snprintf(json_buffer, sizeof(json_buffer), "{\"user\": \"%s\"}", user_data);
    
    printf("JSON: %s\n", json_buffer);
}
// {/fact}

int main() {
    // Function calls can be added here for testing
    return 0;
}