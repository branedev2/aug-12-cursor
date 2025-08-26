#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
// {fact rule=insecure-file-permissions@v1.0 defects=1}

// True Positives (Vulnerable Code Examples)

void bad_case_1() {
    // Creating a file with overly permissive permissions (0777)
    // ruleid: cpp-loose-resource-permissions
    int fd = open("sensitive_data.txt", O_CREAT | O_WRONLY, 0777);
    if (fd != -1) {
        write(fd, "Sensitive information", 20);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_2() {
    // Using chmod to set overly permissive permissions on an existing file
    // ruleid: cpp-loose-resource-permissions
    chmod("config.ini", 0777);
    
    FILE* file = fopen("config.ini", "w");
    if (file) {
        fprintf(file, "password=secret123\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_3() {
    // Creating a directory with overly permissive permissions
    // ruleid: cpp-loose-resource-permissions
    mkdir("secure_data", 0777);
    
    // Write sensitive data to a file in this directory
    std::ofstream outfile("secure_data/credentials.txt");
    outfile << "username=admin\npassword=admin123" << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_4() {
    int fd = open("temp_file.txt", O_CREAT | O_WRONLY, 0644);
    if (fd != -1) {
        // Changing permissions of an open file descriptor to be overly permissive
        // ruleid: cpp-loose-resource-permissions
        fchmod(fd, 0777);
        write(fd, "Sensitive data that should be protected", 38);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_5() {
    // Creating a file with world-writable permissions
    // ruleid: cpp-loose-resource-permissions
    int fd = open("database.conf", O_CREAT | O_WRONLY, 0666);
    if (fd != -1) {
        write(fd, "db_password=password123", 22);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_6() {
    std::string filename = "user_data.json";
    // Setting permissions that allow anyone to read and write
    // ruleid: cpp-loose-resource-permissions
    chmod(filename.c_str(), S_IRWXU | S_IRWXG | S_IRWXO); // 0777
    
    std::ofstream file(filename);
    file << "{\"users\": [{\"name\": \"admin\", \"password\": \"secret\"}]}" << std::endl;
    file.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_7() {
    // Creating a directory for logs with overly permissive permissions
    // ruleid: cpp-loose-resource-permissions
    mkdir("logs", S_IRWXU | S_IRWXG | S_IRWXO); // 0777
    
    std::ofstream logfile("logs/system.log");
    logfile << "System started with admin privileges" << std::endl;
    logfile.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_8() {
    // Creating a temporary file with world-writable permissions
    // ruleid: cpp-loose-resource-permissions
    int fd = open("/tmp/app_data.tmp", O_CREAT | O_WRONLY, 0666);
    if (fd != -1) {
        write(fd, "Temporary but sensitive data", 27);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_9() {
    int fd = open("settings.conf", O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "api_key=12345", 13);
        // Changing permissions after writing sensitive data
        // ruleid: cpp-loose-resource-permissions
        chmod("settings.conf", S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // 0666
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_10() {
    // Creating a directory for backups with overly permissive permissions
    // ruleid: cpp-loose-resource-permissions
    if (mkdir("backups", 0777) == 0) {
        system("cp important_data.db backups/");
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_11() {
    // Using umask(0) to remove permission restrictions, then creating a file
    umask(0);
    // ruleid: cpp-loose-resource-permissions
    int fd = open("unrestricted_file.txt", O_CREAT | O_WRONLY, 0666);
    if (fd != -1) {
        write(fd, "This file has no permission restrictions", 39);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_12() {
    // Creating multiple files with overly permissive permissions
    for (int i = 1; i <= 3; i++) {
        std::string filename = "data_" + std::to_string(i) + ".txt";
        // ruleid: cpp-loose-resource-permissions
        int fd = open(filename.c_str(), O_CREAT | O_WRONLY, 0777);
        if (fd != -1) {
            write(fd, "Multiple files with bad permissions", 34);
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_13() {
    // Creating a named pipe with overly permissive permissions
    // ruleid: cpp-loose-resource-permissions
    if (mkfifo("command_pipe", 0777) == 0) {
        printf("Created command pipe with overly permissive permissions\n");
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_14() {
    // Setting loose permissions on a directory and then creating files in it
    // ruleid: cpp-loose-resource-permissions
    mkdir("public_data", 0777);
    
    std::ofstream file("public_data/user_list.txt");
    file << "admin:admin@example.com\nuser:user@example.com" << std::endl;
    file.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

void bad_case_15() {
    int fd;
    // Opening a file with loose permissions based on a condition
    if (getuid() == 0) { // If running as root
        // ruleid: cpp-loose-resource-permissions
        fd = open("root_data.txt", O_CREAT | O_WRONLY, 0777);
    } else {
        fd = open("user_data.txt", O_CREAT | O_WRONLY, 0600);
    }
    
    if (fd != -1) {
        write(fd, "Conditional permission setting", 29);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

// True Negatives (Secure Code Examples)

void good_case_1() {
    // Creating a file with appropriate permissions (0600 - only owner can read/write)
    // ok: cpp-loose-resource-permissions
    int fd = open("sensitive_data.txt", O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "Sensitive information", 20);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_2() {
    // Using chmod to set appropriate permissions on an existing file
    // ok: cpp-loose-resource-permissions
    chmod("config.ini", 0600);
    
    FILE* file = fopen("config.ini", "w");
    if (file) {
        fprintf(file, "password=secret123\n");
        fclose(file);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_3() {
    // Creating a directory with appropriate permissions (0700 - only owner has access)
    // ok: cpp-loose-resource-permissions
    mkdir("secure_data", 0700);
    
    // Write sensitive data to a file in this directory
    std::ofstream outfile("secure_data/credentials.txt");
    outfile << "username=admin\npassword=admin123" << std::endl;
    outfile.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_4() {
    int fd = open("temp_file.txt", O_CREAT | O_WRONLY, 0644);
    if (fd != -1) {
        // Changing permissions of an open file descriptor to be more restrictive
        // ok: cpp-loose-resource-permissions
        fchmod(fd, 0600);
        write(fd, "Sensitive data that should be protected", 38);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_5() {
    // Creating a file with appropriate permissions for a configuration file
    // ok: cpp-loose-resource-permissions
    int fd = open("database.conf", O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "db_password=password123", 22);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_6() {
    std::string filename = "user_data.json";
    // Setting permissions that only allow owner to read and write
    // ok: cpp-loose-resource-permissions
    chmod(filename.c_str(), S_IRUSR | S_IWUSR); // 0600
    
    std::ofstream file(filename);
    file << "{\"users\": [{\"name\": \"admin\", \"password\": \"secret\"}]}" << std::endl;
    file.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_7() {
    // Creating a directory for logs with appropriate permissions
    // ok: cpp-loose-resource-permissions
    mkdir("logs", S_IRWXU); // 0700 - only owner has full access
    
    std::ofstream logfile("logs/system.log");
    logfile << "System started with admin privileges" << std::endl;
    logfile.close();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_8() {
    // Creating a temporary file with restricted permissions
    // ok: cpp-loose-resource-permissions
    int fd = open("/tmp/app_data.tmp", O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "Temporary but sensitive data", 27);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_9() {
    // Creating a file with appropriate permissions and not changing them later
    // ok: cpp-loose-resource-permissions
    int fd = open("settings.conf", O_CREAT | O_WRONLY, 0600);
    if (fd != -1) {
        write(fd, "api_key=12345", 13);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_10() {
    // Creating a directory for backups with appropriate permissions
    // ok: cpp-loose-resource-permissions
    if (mkdir("backups", 0700) == 0) {
        system("cp important_data.db backups/");
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_11() {
    // Setting a restrictive umask before creating files
    mode_t old_mask = umask(0077); // Only allow owner access
    // ok: cpp-loose-resource-permissions
    int fd = open("protected_file.txt", O_CREAT | O_WRONLY, 0666);
    // The actual permissions will be 0600 due to the umask
    if (fd != -1) {
        write(fd, "This file has proper permission restrictions", 43);
        close(fd);
    }
    umask(old_mask); // Restore original umask
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_12() {
    // Creating multiple files with appropriate permissions
    for (int i = 1; i <= 3; i++) {
        std::string filename = "data_" + std::to_string(i) + ".txt";
        // ok: cpp-loose-resource-permissions
        int fd = open(filename.c_str(), O_CREAT | O_WRONLY, 0600);
        if (fd != -1) {
            write(fd, "Multiple files with good permissions", 35);
            close(fd);
        }
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_13() {
    // Creating a named pipe with appropriate permissions
    // ok: cpp-loose-resource-permissions
    if (mkfifo("command_pipe", 0600) == 0) {
        printf("Created command pipe with appropriate permissions\n");
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_14() {
    // Creating a public directory with appropriate permissions and files inside
    // ok: cpp-loose-resource-permissions
    mkdir("public_data", 0755); // Owner can write, others can read/execute
    
    // Creating a file with appropriate permissions inside the directory
    int fd = open("public_data/user_list.txt", O_CREAT | O_WRONLY, 0644);
    if (fd != -1) {
        write(fd, "admin:admin@example.com\nuser:user@example.com", 44);
        close(fd);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

void good_case_15() {
    // Setting permissions based on file content sensitivity
    const char* data = "This is public information";
    const char* sensitive_data = "This is sensitive information";
    
    // Public data can be readable by others but not writable
    int fd1 = open("public_info.txt", O_CREAT | O_WRONLY, 0644);
    if (fd1 != -1) {
        write(fd1, data, strlen(data));
        close(fd1);
    }
    
    // Sensitive data should be restricted
    // ok: cpp-loose-resource-permissions
    int fd2 = open("private_info.txt", O_CREAT | O_WRONLY, 0600);
    if (fd2 != -1) {
        write(fd2, sensitive_data, strlen(sensitive_data));
        close(fd2);
    }
}
// {/fact}

int main() {
    // This function is just for demonstration purposes
    return 0;
}