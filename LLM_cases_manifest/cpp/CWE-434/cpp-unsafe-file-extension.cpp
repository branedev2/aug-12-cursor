#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <regex>
#include <algorithm>
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

// True Positives (Vulnerable Code)

void bad_case_1() {
    std::string filename = "user_upload.exe";
    std::ofstream outfile(filename);
    // ruleid: cpp-unsafe-file-extension
    outfile << "Content of the executable file";
    outfile.close();
    std::cout << "File saved as " << filename << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_2() {
    std::string userInput = "malicious_script.php";
    // ruleid: cpp-unsafe-file-extension
    std::ifstream file(userInput);
    if (file.is_open()) {
        std::cout << "Processing PHP file: " << userInput << std::endl;
        file.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_3() {
    std::vector<std::string> allowedExtensions = {".txt", ".pdf", ".doc", ".exe"};
    std::string filename = "user_document.exe";
    
    std::string extension = filename.substr(filename.find_last_of("."));
    if (std::find(allowedExtensions.begin(), allowedExtensions.end(), extension) != allowedExtensions.end()) {
        // ruleid: cpp-unsafe-file-extension
        std::ofstream outfile(filename);
        outfile << "Content of the file";
        outfile.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_4() {
    std::string uploadDir = "/var/www/uploads/";
    std::string filename = "script.jsp";
    std::string fullPath = uploadDir + filename;
    
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(fullPath);
    file << "<%@ page language=\"java\" %><html><body>JSP Content</body></html>";
    file.close();
    std::cout << "JSP file saved successfully" << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_5() {
    std::vector<std::string> files = {"doc.txt", "image.png", "script.js"};
    for (const auto& file : files) {
        if (file.find(".js") != std::string::npos) {
            // ruleid: cpp-unsafe-file-extension
            std::ofstream outfile(file);
            outfile << "console.log('JavaScript code')";
            outfile.close();
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_6() {
    std::string filename = "user_upload.aspx";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(filename);
    file << "<%@ Page Language=\"C#\" %>";
    file.close();
    std::cout << "ASPX file created" << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_7() {
    std::string extension = ".bat";
    std::string filename = "user_script" + extension;
    
    // ruleid: cpp-unsafe-file-extension
    std::ofstream outfile(filename);
    outfile << "@echo off\necho Batch file executed";
    outfile.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_8() {
    std::string userFilename = "malicious.cgi";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(userFilename);
    file << "#!/usr/bin/perl\nprint \"Content-type: text/html\\n\\n\";\nprint \"<html><body>CGI Script</body></html>\";\n";
    file.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_9() {
    std::vector<std::string> uploadedFiles = {"document.pdf", "image.jpg", "script.vbs"};
    
    for (const auto& file : uploadedFiles) {
        if (file.ends_with(".vbs")) {
            // ruleid: cpp-unsafe-file-extension
            std::ofstream outfile(file);
            outfile << "WScript.Echo \"VBScript execution\"";
            outfile.close();
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_10() {
    std::string filename = "config.msi";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(filename);
    file << "MSI installer content";
    file.close();
    std::cout << "MSI file created" << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_11() {
    std::string userInput = "shell_commands.sh";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream scriptFile(userInput);
    scriptFile << "#!/bin/bash\necho \"Shell script executed\"\n";
    scriptFile.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_12() {
    std::string filename = "user_macro.docm";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(filename);
    file << "Document with macros content";
    file.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_13() {
    std::string uploadedFile = "remote_access.rdp";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream file(uploadedFile);
    file << "screen mode id:i:2\ndesktopwidth:i:1920\ndesktopheight:i:1080\n";
    file.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_14() {
    std::string filename = "startup.cmd";
    // ruleid: cpp-unsafe-file-extension
    std::ofstream cmdFile(filename);
    cmdFile << "@echo off\necho Command script executed";
    cmdFile.close();
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=1}

void bad_case_15() {
    std::vector<std::string> extensions = {".txt", ".pl", ".pdf"};
    for (const auto& ext : extensions) {
        std::string filename = "user_file" + ext;
        if (ext == ".pl") {
            // ruleid: cpp-unsafe-file-extension
            std::ofstream file(filename);
            file << "#!/usr/bin/perl\nprint \"Perl script executed\\n\";";
            file.close();
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

// True Negatives (Safe Code)

void good_case_1() {
    std::string filename = "user_upload.txt";
    // ok: cpp-unsafe-file-extension
    std::ofstream outfile(filename);
    outfile << "Content of the text file";
    outfile.close();
    std::cout << "File saved as " << filename << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_2() {
    std::vector<std::string> safeExtensions = {".txt", ".pdf", ".jpg", ".png"};
    std::string userInput = "document.exe";
    
    std::string extension = userInput.substr(userInput.find_last_of("."));
    // ok: cpp-unsafe-file-extension
    if (std::find(safeExtensions.begin(), safeExtensions.end(), extension) != safeExtensions.end()) {
        std::ofstream outfile(userInput);
        outfile << "Content of the file";
        outfile.close();
    } else {
        std::cout << "Unsafe file extension rejected" << std::endl;
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_3() {
    std::string filename = "user_upload.php";
    std::string safeFilename = "user_upload.txt";
    
    // ok: cpp-unsafe-file-extension
    if (filename.ends_with(".php") || filename.ends_with(".exe") || 
        filename.ends_with(".js") || filename.ends_with(".jsp")) {
        std::cout << "Unsafe file extension detected, renaming to safe extension" << std::endl;
        std::ofstream outfile(safeFilename);
        outfile << "Content of the file";
        outfile.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_4() {
    std::string uploadDir = "/var/www/uploads/";
    std::string filename = "image.jpg";
    std::string fullPath = uploadDir + filename;
    
    // ok: cpp-unsafe-file-extension
    std::regex safePattern("\\.(jpg|jpeg|png|gif|pdf|txt|csv)$", std::regex::icase);
    if (std::regex_search(filename, safePattern)) {
        std::ofstream file(fullPath);
        file << "Content of the image file";
        file.close();
        std::cout << "Image file saved successfully" << std::endl;
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_5() {
    std::vector<std::string> files = {"doc.txt", "image.png", "script.js"};
    for (const auto& file : files) {
        // ok: cpp-unsafe-file-extension
        if (file.ends_with(".txt") || file.ends_with(".png")) {
            std::ofstream outfile(file);
            outfile << "Safe file content";
            outfile.close();
        } else {
            std::cout << "Skipping file with unsafe extension: " << file << std::endl;
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_6() {
    std::string originalFilename = "user_upload.aspx";
    std::string safeFilename = originalFilename + ".txt";
    
    // ok: cpp-unsafe-file-extension
    std::ofstream file(safeFilename);
    file << "Content of the file (stored as text)";
    file.close();
    std::cout << "File saved with safe extension: " << safeFilename << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_7() {
    std::string userFilename = "script.bat";
    std::vector<std::string> dangerousExtensions = {".exe", ".bat", ".cmd", ".sh", ".php", ".js", ".vbs"};
    
    std::string extension = userFilename.substr(userFilename.find_last_of("."));
    // ok: cpp-unsafe-file-extension
    if (std::find(dangerousExtensions.begin(), dangerousExtensions.end(), extension) != dangerousExtensions.end()) {
        std::cout << "Rejected file with dangerous extension: " << userFilename << std::endl;
    } else {
        std::ofstream file(userFilename);
        file << "File content";
        file.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_8() {
    std::string filename = "user_document.pdf";
    
    // ok: cpp-unsafe-file-extension
    std::regex safeDocPattern("\\.(pdf|doc|docx|txt|rtf|odt)$", std::regex::icase);
    if (std::regex_search(filename, safeDocPattern)) {
        std::ofstream file(filename);
        file << "Document content";
        file.close();
        std::cout << "Document saved successfully" << std::endl;
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_9() {
    std::vector<std::string> uploadedFiles = {"document.pdf", "image.jpg", "script.vbs"};
    
    for (const auto& file : uploadedFiles) {
        // ok: cpp-unsafe-file-extension
        if (!file.ends_with(".exe") && !file.ends_with(".vbs") && 
            !file.ends_with(".bat") && !file.ends_with(".php")) {
            std::ofstream outfile(file);
            outfile << "Safe file content";
            outfile.close();
            std::cout << "Processed safe file: " << file << std::endl;
        }
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_10() {
    std::string originalFilename = "config.msi";
    // ok: cpp-unsafe-file-extension
    std::string sanitizedFilename = originalFilename + "_blocked";
    std::ofstream file(sanitizedFilename);
    file << "Original MSI content (blocked from execution)";
    file.close();
    std::cout << "Potentially dangerous file saved with safe name: " << sanitizedFilename << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_11() {
    std::string userInput = "shell_commands.sh";
    std::string safeFilename = "shell_commands_txt.txt";
    
    // ok: cpp-unsafe-file-extension
    if (userInput.ends_with(".sh") || userInput.ends_with(".bash")) {
        std::cout << "Converting script file to safe text file" << std::endl;
        std::ofstream scriptFile(safeFilename);
        scriptFile << "# Original shell script content (saved as text)\n";
        scriptFile.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_12() {
    std::string filename = "user_document.csv";
    
    // ok: cpp-unsafe-file-extension
    std::vector<std::string> safeDataFormats = {".csv", ".json", ".xml", ".yaml", ".txt"};
    std::string extension = filename.substr(filename.find_last_of("."));
    
    if (std::find(safeDataFormats.begin(), safeDataFormats.end(), extension) != safeDataFormats.end()) {
        std::ofstream file(filename);
        file << "Data content";
        file.close();
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_13() {
    std::string uploadedFile = "image.svg";
    
    // ok: cpp-unsafe-file-extension
    if (uploadedFile.ends_with(".svg")) {
        // SVG can contain script, so save it with a different extension
        std::string safeFilename = "image_svg.txt";
        std::ofstream file(safeFilename);
        file << "<!-- Original SVG content saved as text -->";
        file.close();
        std::cout << "SVG content saved as text file for security" << std::endl;
    }
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_14() {
    std::string filename = "user_data.json";
    
    // ok: cpp-unsafe-file-extension
    std::ofstream jsonFile(filename);
    jsonFile << "{\"name\": \"User\", \"data\": \"Safe JSON content\"}";
    jsonFile.close();
    std::cout << "JSON data file saved" << std::endl;
}
// {/fact}
// {fact rule=unrestricted-file-upload@v1.0 defects=0}

void good_case_15() {
    std::vector<std::string> allowedImageTypes = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"};
    std::string userUpload = "profile_picture.jpg";
    
    std::string extension = userUpload.substr(userUpload.find_last_of("."));
    // ok: cpp-unsafe-file-extension
    if (std::find(allowedImageTypes.begin(), allowedImageTypes.end(), extension) != allowedImageTypes.end()) {
        std::ofstream imageFile(userUpload);
        imageFile << "Image binary data";
        imageFile.close();
        std::cout << "Image file saved successfully" << std::endl;
    }
}
// {/fact}

int main() {
    // Function calls could go here for testing
    return 0;
}