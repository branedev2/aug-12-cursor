<?php
/**
 * Test cases for php-sensitive-file-permission rule
 * This file contains examples of secure and insecure file permission settings in PHP
 */
// {fact rule=insecure-file-permissions@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

function bad_case_1() {
    // Creating a file with overly permissive permissions
    $file = fopen("sensitive_data.txt", "w");
    fwrite($file, "This contains sensitive information");
    fclose($file);
    
    // ruleid: php-sensitive-file-permission
    chmod("sensitive_data.txt", 0777);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_2() {
    // Creating a directory with overly permissive permissions
    if (!file_exists("config_directory")) {
        mkdir("config_directory");
    }
    
    // ruleid: php-sensitive-file-permission
    chmod("config_directory", 0777);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_3() {
    $filename = "user_credentials.txt";
    $content = "username=admin\npassword=secret123";
    file_put_contents($filename, $content);
    
    // ruleid: php-sensitive-file-permission
    chmod($filename, 0777);
    echo "File permissions set to allow anyone to read, write, and execute";
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_4() {
    // Setting umask to 0 (too permissive)
    $old_umask = umask();
    
    // ruleid: php-sensitive-file-permission
    umask(0);
    
    $file = fopen("financial_data.csv", "w");
    fwrite($file, "Account,Balance\n12345,1000.00");
    fclose($file);
    
    umask($old_umask); // Restore original umask
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_5() {
    // Creating a temporary file with insecure permissions
    $temp_file = tempnam(sys_get_temp_dir(), "data_");
    file_put_contents($temp_file, "Sensitive temporary data");
    
    // ruleid: php-sensitive-file-permission
    chmod($temp_file, 0777);
    
    // Process the file
    $data = file_get_contents($temp_file);
    unlink($temp_file);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_6() {
    // Using variable to store permission value, but still insecure
    $permissions = 0777; // Full permissions for everyone
    $config_file = "app_config.ini";
    
    file_put_contents($config_file, "[database]\nhost=localhost\nuser=dbuser\npassword=dbpass");
    
    // ruleid: php-sensitive-file-permission
    chmod($config_file, $permissions);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_7() {
    // Using octal notation in string form
    $log_file = "application.log";
    file_put_contents($log_file, "Application started");
    
    // ruleid: php-sensitive-file-permission
    system("chmod 0777 " . escapeshellarg($log_file));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_8() {
    // Using symbolic notation but still giving everyone write access
    $data_file = "customer_data.json";
    file_put_contents($data_file, '{"customers":[{"id":1,"name":"John"}]}');
    
    // ruleid: php-sensitive-file-permission
    system("chmod a+rwx " . escapeshellarg($data_file));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_9() {
    // Creating multiple files with insecure permissions in a loop
    for ($i = 1; $i <= 3; $i++) {
        $filename = "report_$i.txt";
        file_put_contents($filename, "Report $i content");
        
        // ruleid: php-sensitive-file-permission
        chmod($filename, 0777);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_10() {
    // Setting umask to 0 before creating files
    $original_umask = umask();
    
    // ruleid: php-sensitive-file-permission
    umask(0);
    
    // Create files that will inherit the permissive umask
    file_put_contents("config.json", '{"debug": true}');
    file_put_contents("secrets.json", '{"api_key": "sk_test_PLACEHOLDER_KEY"}');
    
    umask($original_umask); // Restore original umask
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_11() {
    // Using hexadecimal notation for permissions (equivalent to 0777)
    $backup_file = "database_backup.sql";
    file_put_contents($backup_file, "-- Database backup");
    
    // ruleid: php-sensitive-file-permission
    chmod($backup_file, 0x1FF); // Hex for 0777
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_12() {
    // Using bitwise operations but still resulting in 0777
    $read = 4;
    $write = 2;
    $execute = 1;
    
    // Calculate permissions for user, group, and others
    $user = $read | $write | $execute;  // 7
    $group = $read | $write | $execute; // 7
    $others = $read | $write | $execute; // 7
    
    $permissions = $user * 100 + $group * 10 + $others; // 777
    
    $file = "encryption_keys.txt";
    file_put_contents($file, "encryption_key=abcdef123456");
    
    // ruleid: php-sensitive-file-permission
    chmod($file, octdec($permissions));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_13() {
    // Creating a directory and setting recursive permissions
    if (!file_exists("data_directory")) {
        mkdir("data_directory", 0755, true);
    }
    
    // ruleid: php-sensitive-file-permission
    chmod("data_directory", 0777);
    
    // Recursively change permissions for all files in the directory
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("data_directory"));
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            // ruleid: php-sensitive-file-permission
            chmod($file->getPathname(), 0777);
        }
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_14() {
    // Using umask in a function that creates multiple files
    function create_log_files() {
        // ruleid: php-sensitive-file-permission
        umask(0);
        
        file_put_contents("system.log", "System log initialized");
        file_put_contents("error.log", "No errors");
        file_put_contents("access.log", "Access log initialized");
    }
    
    create_log_files();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=1}

function bad_case_15() {
    // Using conditional logic but still setting insecure permissions
    $file = "user_uploads/document.pdf";
    $is_development = true;
    
    if (!file_exists(dirname($file))) {
        mkdir(dirname($file), 0755, true);
    }
    
    file_put_contents($file, "PDF content here");
    
    if ($is_development) {
        // Even in development, this is insecure
        // ruleid: php-sensitive-file-permission
        chmod($file, 0777);
    } else {
        // This would be more secure, but we're in development mode
        // chmod($file, 0644);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

// True Negative Examples (Secure Code)

function good_case_1() {
    // Creating a file with appropriate permissions
    $file = fopen("config.txt", "w");
    fwrite($file, "Configuration data");
    fclose($file);
    
    // ok: php-sensitive-file-permission
    chmod("config.txt", 0644); // Read/write for owner, read for group and others
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_2() {
    // Creating a directory with appropriate permissions
    if (!file_exists("secure_directory")) {
        // ok: php-sensitive-file-permission
        mkdir("secure_directory", 0755); // rwxr-xr-x
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_3() {
    $filename = "secure_credentials.txt";
    $content = "username=admin\npassword=secret123";
    file_put_contents($filename, $content);
    
    // ok: php-sensitive-file-permission
    chmod($filename, 0600); // Read/write for owner only
    echo "File permissions set securely";
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_4() {
    // Setting a secure umask
    $old_umask = umask();
    
    // ok: php-sensitive-file-permission
    umask(0022); // Files will be created with 0644 permissions
    
    $file = fopen("financial_data_secure.csv", "w");
    fwrite($file, "Account,Balance\n12345,1000.00");
    fclose($file);
    
    umask($old_umask); // Restore original umask
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_5() {
    // Creating a temporary file with secure permissions
    $temp_file = tempnam(sys_get_temp_dir(), "data_");
    file_put_contents($temp_file, "Sensitive temporary data");
    
    // ok: php-sensitive-file-permission
    chmod($temp_file, 0600); // Only owner can read/write
    
    // Process the file
    $data = file_get_contents($temp_file);
    unlink($temp_file);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_6() {
    // Using variable to store permission value - secure version
    $permissions = 0640; // Owner can read/write, group can read
    $config_file = "app_config_secure.ini";
    
    file_put_contents($config_file, "[database]\nhost=localhost\nuser=dbuser\npassword=dbpass");
    
    // ok: php-sensitive-file-permission
    chmod($config_file, $permissions);
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_7() {
    // Using octal notation in string form - secure version
    $log_file = "application_secure.log";
    file_put_contents($log_file, "Application started");
    
    // ok: php-sensitive-file-permission
    system("chmod 0644 " . escapeshellarg($log_file));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_8() {
    // Using symbolic notation with secure permissions
    $data_file = "customer_data_secure.json";
    file_put_contents($data_file, '{"customers":[{"id":1,"name":"John"}]}');
    
    // ok: php-sensitive-file-permission
    system("chmod u=rw,g=r,o=r " . escapeshellarg($data_file));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_9() {
    // Creating multiple files with secure permissions in a loop
    for ($i = 1; $i <= 3; $i++) {
        $filename = "secure_report_$i.txt";
        file_put_contents($filename, "Report $i content");
        
        // ok: php-sensitive-file-permission
        chmod($filename, 0640);
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_10() {
    // Setting secure umask before creating files
    $original_umask = umask();
    
    // ok: php-sensitive-file-permission
    umask(0022);
    
    // Create files that will inherit the secure umask
    file_put_contents("secure_config.json", '{"debug": true}');
    file_put_contents("secure_secrets.json", '{"api_key": "sk_test_PLACEHOLDER_KEY"}');
    
    umask($original_umask); // Restore original umask
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_11() {
    // Using different permission levels for different file types
    $config_file = "app_settings.conf";
    $executable_file = "run_backup.sh";
    
    file_put_contents($config_file, "# Configuration settings");
    file_put_contents($executable_file, "#!/bin/bash\necho 'Running backup'");
    
    // ok: php-sensitive-file-permission
    chmod($config_file, 0640); // Config file: rw-r-----
    
    // ok: php-sensitive-file-permission
    chmod($executable_file, 0750); // Script: rwxr-x---
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_12() {
    // Using bitwise operations for secure permissions
    $read = 4;
    $write = 2;
    $execute = 1;
    
    // Calculate permissions for user, group, and others
    $user = $read | $write;  // 6 (rw-)
    $group = $read;          // 4 (r--)
    $others = 0;             // 0 (---)
    
    $permissions = $user * 100 + $group * 10 + $others; // 640
    
    $file = "secure_keys.txt";
    file_put_contents($file, "encryption_key=abcdef123456");
    
    // ok: php-sensitive-file-permission
    chmod($file, octdec($permissions));
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_13() {
    // Creating a directory and setting secure recursive permissions
    if (!file_exists("secure_data_directory")) {
        // ok: php-sensitive-file-permission
        mkdir("secure_data_directory", 0750, true);
    }
    
    // Recursively set secure permissions for all files in the directory
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator("secure_data_directory"));
    foreach ($iterator as $file) {
        if ($file->isFile()) {
            // ok: php-sensitive-file-permission
            chmod($file->getPathname(), 0640);
        }
    }
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_14() {
    // Using umask in a function that creates multiple files - secure version
    function create_secure_log_files() {
        // ok: php-sensitive-file-permission
        umask(0027); // Files will be created with 0640 permissions
        
        file_put_contents("secure_system.log", "System log initialized");
        file_put_contents("secure_error.log", "No errors");
        file_put_contents("secure_access.log", "Access log initialized");
    }
    
    create_secure_log_files();
}
// {/fact}
// {fact rule=insecure-file-permissions@v1.0 defects=0}

function good_case_15() {
    // Using environment-specific permissions but keeping them secure
    $file = "user_uploads/secure_document.pdf";
    $is_development = true;
    
    if (!file_exists(dirname($file))) {
        // ok: php-sensitive-file-permission
        mkdir(dirname($file), 0750, true);
    }
    
    file_put_contents($file, "PDF content here");
    
    if ($is_development) {
        // Even in development, keep permissions secure
        // ok: php-sensitive-file-permission
        chmod($file, 0640);
    } else {
        // Production might be even more restrictive
        // ok: php-sensitive-file-permission
        chmod($file, 0600);
    }
}
// {/fact}
?>