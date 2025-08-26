#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <map>
#include <regex>
#include <curl/curl.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

// Helper function for curl requests
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
    } catch(std::bad_alloc& e) {
        return 0;
    }
    return newLength;
}
// {fact rule=autoescape-disabled@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code)

void bad_case_1() {
    // Fetching user input from HTTP GET parameter
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?script=system('ls')");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract script parameter
        std::string script = response.substr(response.find("script=") + 7);
        script = script.substr(0, script.find("&"));
        
        // ruleid: cpp-code-injection
        system(("g++ -o temp " + script + " && ./temp").c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_2() {
    // Fetching user input from HTTP POST data
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "code=cout << \"Hello World\";");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract code from response
        std::string userCode = response.substr(response.find("code=") + 5);
        
        // Create a temporary file with user code
        std::ofstream tempFile("temp.cpp");
        tempFile << "#include <iostream>\nint main() {\n" << userCode << "\nreturn 0;\n}";
        tempFile.close();
        
        // ruleid: cpp-code-injection
        system("g++ temp.cpp -o temp && ./temp");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_3() {
    // Fetching user input from HTTP header
    CURL* curl = curl_easy_init();
    std::string response;
    struct curl_slist* headers = NULL;
    
    if(curl) {
        headers = curl_slist_append(headers, "X-Custom-Code: int x = 10; cout << x;");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract code from header in response
        std::string headerCode = response.substr(response.find("X-Custom-Code: ") + 15);
        headerCode = headerCode.substr(0, headerCode.find("\r\n"));
        
        std::string filename = "dynamic_code.cpp";
        std::ofstream file(filename);
        file << "#include <iostream>\nusing namespace std;\nint main() {\n" << headerCode << "\nreturn 0;\n}";
        file.close();
        
        // ruleid: cpp-code-injection
        std::system(("g++ " + filename + " -o dynamic_exe && ./dynamic_exe").c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_4() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?template=basic");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse JSON response
        std::istringstream jsonStream(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(jsonStream, pt);
        
        std::string scriptContent = pt.get<std::string>("scriptContent");
        
        // Create a Python script with user content
        std::ofstream scriptFile("user_script.py");
        scriptFile << scriptContent;
        scriptFile.close();
        
        // ruleid: cpp-code-injection
        system("python user_script.py");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_5() {
    // Fetching user input from HTTP cookie
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_COOKIE, "user_script=console.log('Hello');");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract script from cookie in response
        std::string cookieScript = response.substr(response.find("user_script=") + 12);
        cookieScript = cookieScript.substr(0, cookieScript.find(";"));
        
        // Write to JavaScript file
        std::ofstream jsFile("user_script.js");
        jsFile << cookieScript;
        jsFile.close();
        
        // ruleid: cpp-code-injection
        system("node user_script.js");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_6() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?command=ls -la");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract command parameter
        std::string command = response.substr(response.find("command=") + 8);
        command = command.substr(0, command.find("&"));
        
        // Create a shell script with user command
        std::ofstream shellScript("user_command.sh");
        shellScript << "#!/bin/bash\n" << command;
        shellScript.close();
        
        // ruleid: cpp-code-injection
        system("chmod +x user_command.sh && ./user_command.sh");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_7() {
    // Fetching user input from HTTP request body
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "sqlQuery=SELECT * FROM users");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract SQL query from response
        std::string sqlQuery = response.substr(response.find("sqlQuery=") + 9);
        
        // Create a SQL file with user query
        std::ofstream sqlFile("user_query.sql");
        sqlFile << sqlQuery;
        sqlFile.close();
        
        // ruleid: cpp-code-injection
        system("sqlite3 database.db < user_query.sql");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_8() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?expression=2+2*10");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract expression parameter
        std::string expression = response.substr(response.find("expression=") + 11);
        expression = expression.substr(0, expression.find("&"));
        
        // Create a temporary Python file to evaluate the expression
        std::ofstream pyFile("eval_expr.py");
        pyFile << "print(" << expression << ")";
        pyFile.close();
        
        // ruleid: cpp-code-injection
        system("python eval_expr.py");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_9() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?template=report");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse JSON response
        std::istringstream jsonStream(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(jsonStream, pt);
        
        std::string templateCode = pt.get<std::string>("templateCode");
        
        // Create a PHP file with user template
        std::ofstream phpFile("template.php");
        phpFile << "<?php\n" << templateCode << "\n?>";
        phpFile.close();
        
        // ruleid: cpp-code-injection
        system("php template.php");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_10() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?config=debug:true");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract config parameter
        std::string config = response.substr(response.find("config=") + 7);
        config = config.substr(0, config.find("&"));
        
        // Create a temporary configuration file
        std::ofstream configFile("temp_config.json");
        configFile << "{\n\"" << config << "\"\n}";
        configFile.close();
        
        // ruleid: cpp-code-injection
        system("node -e \"console.log(require('./temp_config.json'))\"");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_11() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?regex=^[a-z]+$");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract regex parameter
        std::string regexPattern = response.substr(response.find("regex=") + 6);
        regexPattern = regexPattern.substr(0, regexPattern.find("&"));
        
        // Create a Perl script with user regex
        std::ofstream perlFile("regex_test.pl");
        perlFile << "#!/usr/bin/perl\n";
        perlFile << "$pattern = \"" << regexPattern << "\";\n";
        perlFile << "if (\"test\" =~ /$pattern/) { print \"Match found\\n\"; }";
        perlFile.close();
        
        // ruleid: cpp-code-injection
        system("perl regex_test.pl");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_12() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?formula=A1+B1");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract formula parameter
        std::string formula = response.substr(response.find("formula=") + 8);
        formula = formula.substr(0, formula.find("&"));
        
        // Create a CSV file for data
        std::ofstream csvFile("data.csv");
        csvFile << "A1,B1\n10,20";
        csvFile.close();
        
        // Create an R script with user formula
        std::ofstream rScript("process_data.R");
        rScript << "data <- read.csv('data.csv')\n";
        rScript << "result <- with(data, " << formula << ")\n";
        rScript << "write.csv(result, 'result.csv')";
        rScript.close();
        
        // ruleid: cpp-code-injection
        system("Rscript process_data.R");
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_13() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?makefile_target=all");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract makefile target parameter
        std::string target = response.substr(response.find("makefile_target=") + 16);
        target = target.substr(0, target.find("&"));
        
        // Create a Makefile with user target
        std::ofstream makeFile("Makefile");
        makeFile << target << ":\n\techo \"Building " << target << "\"";
        makeFile.close();
        
        // ruleid: cpp-code-injection
        system(("make " + target).c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_14() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?awk_script=print $1");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract awk script parameter
        std::string awkScript = response.substr(response.find("awk_script=") + 11);
        awkScript = awkScript.substr(0, awkScript.find("&"));
        
        // Create a sample data file
        std::ofstream dataFile("data.txt");
        dataFile << "Hello World\nTest Data";
        dataFile.close();
        
        // ruleid: cpp-code-injection
        system(("awk '{" + awkScript + "}' data.txt").c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_15() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?sed_command=s/hello/world/g");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract sed command parameter
        std::string sedCommand = response.substr(response.find("sed_command=") + 12);
        sedCommand = sedCommand.substr(0, sedCommand.find("&"));
        
        // Create a sample text file
        std::ofstream textFile("sample.txt");
        textFile << "hello hello hello";
        textFile.close();
        
        // ruleid: cpp-code-injection
        system(("sed '" + sedCommand + "' sample.txt").c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// TRUE NEGATIVES (Safe Code)

void good_case_1() {
    // Fetching user input from HTTP GET parameter
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?script=system('ls')");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract script parameter
        std::string script = response.substr(response.find("script=") + 7);
        script = script.substr(0, script.find("&"));
        
        // ok: cpp-code-injection
        // Use a whitelist of allowed commands
        std::vector<std::string> allowedCommands = {"list", "status", "version"};
        bool isAllowed = false;
        
        for (const auto& cmd : allowedCommands) {
            if (script == cmd) {
                isAllowed = true;
                break;
            }
        }
        
        if (isAllowed) {
            system(("./safe_script.sh " + script).c_str());
        } else {
            std::cerr << "Unauthorized command: " << script << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_2() {
    // Fetching user input from HTTP POST data
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "code=cout << \"Hello World\";");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract code from response
        std::string userCode = response.substr(response.find("code=") + 5);
        
        // ok: cpp-code-injection
        // Instead of executing user code, use a template approach
        std::map<std::string, std::string> templates = {
            {"hello", "#include <iostream>\nint main() { std::cout << \"Hello World\"; return 0; }"},
            {"add", "#include <iostream>\nint main() { std::cout << 2 + 2; return 0; }"}
        };
        
        if (templates.find(userCode) != templates.end()) {
            std::ofstream tempFile("safe_template.cpp");
            tempFile << templates[userCode];
            tempFile.close();
            system("g++ safe_template.cpp -o safe_template && ./safe_template");
        } else {
            std::cerr << "Unknown template: " << userCode << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_3() {
    // Fetching user input from HTTP header
    CURL* curl = curl_easy_init();
    std::string response;
    struct curl_slist* headers = NULL;
    
    if(curl) {
        headers = curl_slist_append(headers, "X-Custom-Code: int x = 10; cout << x;");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract code from header in response
        std::string headerCode = response.substr(response.find("X-Custom-Code: ") + 15);
        headerCode = headerCode.substr(0, headerCode.find("\r\n"));
        
        // ok: cpp-code-injection
        // Validate input against a regex pattern for safe expressions
        std::regex safePattern("^[0-9+\\-*/\\s()]+$");
        if (std::regex_match(headerCode, safePattern)) {
            // Use a calculator library to evaluate the expression safely
            std::cout << "Safe expression: " << headerCode << std::endl;
            // Example: calculator.evaluate(headerCode);
        } else {
            std::cerr << "Unsafe expression rejected: " << headerCode << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_4() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?template=basic");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse JSON response
        std::istringstream jsonStream(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(jsonStream, pt);
        
        std::string templateName = pt.get<std::string>("template");
        
        // ok: cpp-code-injection
        // Use predefined templates instead of executing user code
        std::map<std::string, std::string> templates = {
            {"basic", "print('Basic template')"},
            {"advanced", "print('Advanced template')"}
        };
        
        if (templates.find(templateName) != templates.end()) {
            std::ofstream scriptFile("safe_template.py");
            scriptFile << templates[templateName];
            scriptFile.close();
            system("python safe_template.py");
        } else {
            std::cerr << "Unknown template: " << templateName << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_5() {
    // Fetching user input from HTTP cookie
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_COOKIE, "user_script=console.log('Hello');");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract script from cookie in response
        std::string cookieScript = response.substr(response.find("user_script=") + 12);
        cookieScript = cookieScript.substr(0, cookieScript.find(";"));
        
        // ok: cpp-code-injection
        // Sanitize and validate the input
        std::regex safePattern("^[a-zA-Z0-9\\s'\"().,;]+$");
        if (std::regex_match(cookieScript, safePattern)) {
            // Process the script in a controlled environment
            std::cout << "Processing safe script: " << cookieScript << std::endl;
            // Example: interpreter.processScript(cookieScript);
        } else {
            std::cerr << "Potentially unsafe script rejected: " << cookieScript << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_6() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?command=ls -la");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract command parameter
        std::string command = response.substr(response.find("command=") + 8);
        command = command.substr(0, command.find("&"));
        
        // ok: cpp-code-injection
        // Use a command whitelist approach
        std::map<std::string, std::string> safeCommands = {
            {"ls", "ls"},
            {"dir", "dir"},
            {"status", "echo 'System status: OK'"}
        };
        
        if (safeCommands.find(command) != safeCommands.end()) {
            system(safeCommands[command].c_str());
        } else {
            std::cerr << "Unauthorized command: " << command << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_7() {
    // Fetching user input from HTTP request body
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "sqlQuery=SELECT * FROM users");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract SQL query from response
        std::string sqlQuery = response.substr(response.find("sqlQuery=") + 9);
        
        // ok: cpp-code-injection
        // Use parameterized queries or prepared statements
        // This is a simplified example - in real code, you'd use a proper SQL library
        std::map<std::string, std::string> allowedQueries = {
            {"users", "SELECT * FROM users WHERE active = 1"},
            {"products", "SELECT * FROM products WHERE in_stock = 1"}
        };
        
        std::string queryType = sqlQuery.substr(0, sqlQuery.find(" "));
        if (allowedQueries.find(queryType) != allowedQueries.end()) {
            std::cout << "Executing safe query: " << allowedQueries[queryType] << std::endl;
            // Example: db.executeQuery(allowedQueries[queryType]);
        } else {
            std::cerr << "Unauthorized query type: " << queryType << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_8() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?expression=2+2*10");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract expression parameter
        std::string expression = response.substr(response.find("expression=") + 11);
        expression = expression.substr(0, expression.find("&"));
        
        // ok: cpp-code-injection
        // Implement a safe expression evaluator
        std::regex safeExprPattern("^[0-9+\\-*/\\s()]+$");
        if (std::regex_match(expression, safeExprPattern)) {
            // Use a safe expression evaluator library
            std::cout << "Safe expression to evaluate: " << expression << std::endl;
            // Example: double result = safeEvaluator.evaluate(expression);
        } else {
            std::cerr << "Potentially unsafe expression rejected: " << expression << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_9() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?template=report");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Parse JSON response
        std::istringstream jsonStream(response);
        boost::property_tree::ptree pt;
        boost::property_tree::read_json(jsonStream, pt);
        
        std::string templateName = pt.get<std::string>("templateName");
        
        // ok: cpp-code-injection
        // Use a template engine with predefined templates
        std::map<std::string, std::string> templates = {
            {"report", "templates/report.tpl"},
            {"invoice", "templates/invoice.tpl"},
            {"summary", "templates/summary.tpl"}
        };
        
        if (templates.find(templateName) != templates.end()) {
            std::cout << "Using safe template: " << templates[templateName] << std::endl;
            // Example: templateEngine.render(templates[templateName], data);
        } else {
            std::cerr << "Unknown template: " << templateName << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_10() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?config=debug:true");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract config parameter
        std::string config = response.substr(response.find("config=") + 7);
        config = config.substr(0, config.find("&"));
        
        // ok: cpp-code-injection
        // Parse and validate configuration safely
        std::map<std::string, std::string> configMap;
        size_t pos = 0;
        std::string token;
        std::string delimiter = ":";
        
        if ((pos = config.find(delimiter)) != std::string::npos) {
            std::string key = config.substr(0, pos);
            std::string value = config.substr(pos + delimiter.length());
            
            // Validate key and value
            std::regex keyPattern("^[a-zA-Z0-9_]+$");
            std::regex valuePattern("^[a-zA-Z0-9_]+$");
            
            if (std::regex_match(key, keyPattern) && std::regex_match(value, valuePattern)) {
                configMap[key] = value;
                std::cout << "Valid config: " << key << " = " << value << std::endl;
            } else {
                std::cerr << "Invalid config format: " << config << std::endl;
            }
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_11() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?regex=^[a-z]+$");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract regex parameter
        std::string regexPattern = response.substr(response.find("regex=") + 6);
        regexPattern = regexPattern.substr(0, regexPattern.find("&"));
        
        // ok: cpp-code-injection
        // Validate regex pattern before using it
        try {
            // Check if the regex is valid and safe
            std::regex testRegex(regexPattern);
            
            // Limit regex complexity to prevent ReDoS attacks
            if (regexPattern.length() <= 100) {
                std::string testString = "test";
                bool match = std::regex_match(testString, testRegex);
                std::cout << "Regex test result: " << (match ? "match" : "no match") << std::endl;
            } else {
                std::cerr << "Regex pattern too complex: " << regexPattern << std::endl;
            }
        } catch (const std::regex_error& e) {
            std::cerr << "Invalid regex pattern: " << e.what() << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_12() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?formula=A1+B1");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract formula parameter
        std::string formula = response.substr(response.find("formula=") + 8);
        formula = formula.substr(0, formula.find("&"));
        
        // ok: cpp-code-injection
        // Implement a safe formula parser
        std::regex safeFormulaPattern("^[A-Z0-9+\\-*/\\s()]+$");
        if (std::regex_match(formula, safeFormulaPattern)) {
            // Parse and evaluate the formula safely
            std::map<std::string, double> cells = {{"A1", 10.0}, {"B1", 20.0}, {"C1", 30.0}};
            
            // Simple formula evaluator (for demonstration)
            if (formula == "A1+B1") {
                double result = cells["A1"] + cells["B1"];
                std::cout << "Formula result: " << result << std::endl;
            } else if (formula == "A1*B1") {
                double result = cells["A1"] * cells["B1"];
                std::cout << "Formula result: " << result << std::endl;
            } else {
                std::cout << "Unsupported formula: " << formula << std::endl;
            }
        } else {
            std::cerr << "Potentially unsafe formula rejected: " << formula << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_13() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?makefile_target=all");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract makefile target parameter
        std::string target = response.substr(response.find("makefile_target=") + 16);
        target = target.substr(0, target.find("&"));
        
        // ok: cpp-code-injection
        // Use a whitelist of allowed targets
        std::vector<std::string> allowedTargets = {"all", "clean", "test", "build"};
        bool isAllowed = false;
        
        for (const auto& allowedTarget : allowedTargets) {
            if (target == allowedTarget) {
                isAllowed = true;
                break;
            }
        }
        
        if (isAllowed) {
            std::cout << "Running make with safe target: " << target << std::endl;
            system(("make " + target).c_str());
        } else {
            std::cerr << "Unauthorized make target: " << target << std::endl;
        }
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_14() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?awk_script=print $1");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract awk script parameter
        std::string awkScript = response.substr(response.find("awk_script=") + 11);
        awkScript = awkScript.substr(0, awkScript.find("&"));
        
        // ok: cpp-code-injection
        // Use predefined awk scripts instead of user input
        std::map<std::string, std::string> safeAwkScripts = {
            {"print_first", "print $1"},
            {"print_last", "print $NF"},
            {"count_fields", "print NF"}
        };
        
        // Create a sample data file
        std::ofstream dataFile("data.txt");
        dataFile << "Hello World\nTest Data";
        dataFile.close();
        
        // Find the closest matching safe script
        std::string safeScript = "print $1";  // Default
        for (const auto& entry : safeAwkScripts) {
            if (awkScript.find(entry.first) != std::string::npos) {
                safeScript = entry.second;
                break;
            }
        }
        
        std::cout << "Using safe awk script: " << safeScript << std::endl;
        system(("awk '{" + safeScript + "}' data.txt").c_str());
    }
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_15() {
    // Fetching user input from HTTP request
    CURL* curl = curl_easy_init();
    std::string response;
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://example.com/api?sed_command=s/hello/world/g");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        // Extract sed command parameter
        std::string sedCommand = response.substr(response.find("sed_command=") + 12);
        sedCommand = sedCommand.substr(0, sedCommand.find("&"));
        
        // ok: cpp-code-injection
        // Validate sed command against a whitelist of patterns
        std::regex safePattern("^s/[a-zA-Z0-9]+/[a-zA-Z0-9]+/g$");
        
        if (std::regex_match(sedCommand, safePattern)) {
            // Create a sample text file
            std::ofstream textFile("sample.txt");
            textFile << "hello hello hello";
            textFile.close();
            
            std::cout << "Using safe sed command: " << sedCommand << std::endl;
            system(("sed '" + sedCommand + "' sample.txt").c_str());
        } else {
            std::cerr << "Potentially unsafe sed command rejected: " << sedCommand << std::endl;
        }
    }
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "Code injection vulnerability test cases" << std::endl;
    return 0;
}