#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstdlib>

// Common user and permission structures
struct User {
    std::string username;
    std::string role;
    std::vector<std::string> permissions;
};

class Database {
public:
    void executeQuery(const std::string& query) {
        std::cout << "Executing query: " << query << std::endl;
    }
    
    std::vector<std::string> fetchData(const std::string& query) {
        std::cout << "Fetching data with query: " << query << std::endl;
        return {"data1", "data2"};
    }
    
    void updateRecord(const std::string& table, int id, const std::string& data) {
        std::cout << "Updating record in " << table << " with ID " << id << std::endl;
    }
    
    void deleteRecord(const std::string& table, int id) {
        std::cout << "Deleting record from " << table << " with ID " << id << std::endl;
    }
};

class AuthorizationService {
public:
    bool hasPermission(const User& user, const std::string& permission) {
        for (const auto& p : user.permissions) {
            if (p == permission) return true;
        }
        return false;
    }
    
    bool isAdmin(const User& user) {
        return user.role == "admin";
    }
};

// HTTP request simulation
class HttpRequest {
public:
    HttpRequest(std::map<std::string, std::string> params, 
                std::map<std::string, std::string> headers,
                std::string body) 
        : params(params), headers(headers), body(body) {}
    
    std::string getParam(const std::string& name) const {
        auto it = params.find(name);
        return it != params.end() ? it->second : "";
    }
    
    std::string getHeader(const std::string& name) const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : "";
    }
    
    std::string getBody() const {
        return body;
    }
    
private:
    std::map<std::string, std::string> params;
    std::map<std::string, std::string> headers;
    std::string body;
};

// Session management
class Session {
public:
    Session(const std::string& sessionId, const User& user)
        : sessionId(sessionId), user(user) {}
    
    std::string getSessionId() const { return sessionId; }
    User getUser() const { return user; }
    
private:
    std::string sessionId;
    User user;
};

// Session store
class SessionStore {
public:
    void addSession(const Session& session) {
        sessions[session.getSessionId()] = session;
    }
    
    Session* getSession(const std::string& sessionId) {
        auto it = sessions.find(sessionId);
        if (it != sessions.end()) {
            return &(it->second);
        }
        return nullptr;
    }
    
private:
    std::map<std::string, Session> sessions;
};

// Global session store for examples
SessionStore globalSessionStore;
AuthorizationService authService;
Database db;
// {fact rule=missing-authorization@v1.0 defects=1}

// TRUE POSITIVES (Vulnerable Code)

void bad_case_1(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    // User is authenticated, but no authorization check for admin-only operation
    // ruleid: cpp-missing-authorization
    std::string query = "DELETE FROM users WHERE id = " + request.getParam("userId");
    db.executeQuery(query);
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_2(const HttpRequest& request) {
    std::string fileId = request.getParam("fileId");
    
    // No authorization check before accessing sensitive file
    // ruleid: cpp-missing-authorization
    std::ifstream file("/sensitive/data/" + fileId);
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    std::cout << content << std::endl;
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_3(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // User is authenticated but there's no check if they can modify this specific user
        // ruleid: cpp-missing-authorization
        db.updateRecord("users", std::stoi(request.getParam("userId")), request.getBody());
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_4(const HttpRequest& request) {
    std::string action = request.getParam("action");
    std::string resourceId = request.getParam("resourceId");
    
    // Missing authorization check for API action
    // ruleid: cpp-missing-authorization
    if (action == "delete") {
        db.executeQuery("DELETE FROM resources WHERE id = " + resourceId);
    } else if (action == "update") {
        db.executeQuery("UPDATE resources SET data = '" + request.getBody() + "' WHERE id = " + resourceId);
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_5(const HttpRequest& request) {
    // Accessing admin panel with no authorization check
    std::string page = request.getParam("page");
    
    // ruleid: cpp-missing-authorization
    if (page == "admin") {
        std::cout << "Displaying admin panel..." << std::endl;
        // Code to render admin panel
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_6(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string targetUserId = request.getParam("targetUserId");
        
        // No check if the current user has permission to change another user's role
        // ruleid: cpp-missing-authorization
        std::string newRole = request.getParam("newRole");
        db.executeQuery("UPDATE users SET role = '" + newRole + "' WHERE id = " + targetUserId);
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_7(const HttpRequest& request) {
    // API endpoint that returns all user data without authorization check
    // ruleid: cpp-missing-authorization
    std::vector<std::string> userData = db.fetchData("SELECT * FROM users");
    
    std::stringstream response;
    for (const auto& data : userData) {
        response << data << "\n";
    }
    std::cout << response.str() << std::endl;
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_8(const HttpRequest& request) {
    std::string configName = request.getParam("configName");
    std::string configValue = request.getParam("configValue");
    
    // System configuration change without authorization check
    // ruleid: cpp-missing-authorization
    db.executeQuery("UPDATE system_config SET value = '" + configValue + "' WHERE name = '" + configName + "'");
    std::cout << "Configuration updated successfully" << std::endl;
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_9(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // User is authenticated, but there's no check for specific permission
        std::string reportType = request.getParam("reportType");
        
        // ruleid: cpp-missing-authorization
        if (reportType == "financial") {
            std::vector<std::string> financialData = db.fetchData("SELECT * FROM financial_records");
            // Process and return financial data
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_10(const HttpRequest& request) {
    std::string backupPath = request.getParam("backupPath");
    
    // No authorization check before initiating system backup
    // ruleid: cpp-missing-authorization
    std::string command = "tar -czf backup.tar.gz " + backupPath;
    system(command.c_str());
    std::cout << "Backup completed" << std::endl;
}
// {/fact}

class UserController {
public:
    void deleteUser(const HttpRequest& request) {
        std::string userId = request.getParam("userId");
        
        // No authorization check before deleting a user
        // ruleid: cpp-missing-authorization
        db.executeQuery("DELETE FROM users WHERE id = " + userId);
        std::cout << "User deleted successfully" << std::endl;
    }
};
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_11(const HttpRequest& request) {
    UserController controller;
    controller.deleteUser(request);
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_12(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // User is authenticated, but there's no check if they can access this API
        std::string apiKey = request.getParam("regenerateApiKey");
        
        // ruleid: cpp-missing-authorization
        std::string newApiKey = "generated-key-" + std::to_string(rand());
        db.executeQuery("UPDATE api_keys SET key = '" + newApiKey + "' WHERE id = " + apiKey);
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_13(const HttpRequest& request) {
    // Direct access to logs without authorization check
    std::string logFile = request.getParam("logFile");
    
    // ruleid: cpp-missing-authorization
    std::ifstream file("/var/logs/" + logFile);
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    std::cout << content << std::endl;
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_14(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    // Authentication check but no authorization for this specific action
    if (session) {
        std::string serverId = request.getParam("serverId");
        std::string action = request.getParam("action");
        
        // ruleid: cpp-missing-authorization
        if (action == "restart") {
            std::string command = "ssh admin@server" + serverId + " 'sudo reboot'";
            system(command.c_str());
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=1}

void bad_case_15(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // User is authenticated but no check for specific permission to view PII
        std::string userId = request.getParam("userId");
        
        // ruleid: cpp-missing-authorization
        std::vector<std::string> userData = db.fetchData(
            "SELECT name, address, ssn, credit_card FROM users WHERE id = " + userId);
        
        // Return sensitive PII data
        for (const auto& data : userData) {
            std::cout << data << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

// TRUE NEGATIVES (Secure Code)

void good_case_1(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "user.delete")) {
            std::string query = "DELETE FROM users WHERE id = " + request.getParam("userId");
            db.executeQuery(query);
        } else {
            std::cout << "Unauthorized access attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_2(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    std::string fileId = request.getParam("fileId");
    
    if (session) {
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "file.read")) {
            std::ifstream file("/sensitive/data/" + fileId);
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            std::cout << content << std::endl;
        } else {
            std::cout << "Access denied to file" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_3(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string targetUserId = request.getParam("userId");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "user.update") || 
            (session->getUser().username == "user-" + targetUserId)) {
            db.updateRecord("users", std::stoi(targetUserId), request.getBody());
        } else {
            std::cout << "Unauthorized modification attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_4(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string action = request.getParam("action");
        std::string resourceId = request.getParam("resourceId");
        
        // ok: cpp-missing-authorization
        if (action == "delete" && authService.hasPermission(session->getUser(), "resource.delete")) {
            db.executeQuery("DELETE FROM resources WHERE id = " + resourceId);
        } else if (action == "update" && authService.hasPermission(session->getUser(), "resource.update")) {
            db.executeQuery("UPDATE resources SET data = '" + request.getBody() + "' WHERE id = " + resourceId);
        } else {
            std::cout << "Unauthorized action attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_5(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    std::string page = request.getParam("page");
    
    if (session) {
        // ok: cpp-missing-authorization
        if (page == "admin" && authService.isAdmin(session->getUser())) {
            std::cout << "Displaying admin panel..." << std::endl;
            // Code to render admin panel
        } else if (page == "admin") {
            std::cout << "Unauthorized access to admin panel" << std::endl;
        } else {
            std::cout << "Displaying regular page: " << page << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_6(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string targetUserId = request.getParam("targetUserId");
        std::string newRole = request.getParam("newRole");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "user.change_role")) {
            db.executeQuery("UPDATE users SET role = '" + newRole + "' WHERE id = " + targetUserId);
        } else {
            std::cout << "Unauthorized role change attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_7(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "user.view_all")) {
            std::vector<std::string> userData = db.fetchData("SELECT * FROM users");
            
            std::stringstream response;
            for (const auto& data : userData) {
                response << data << "\n";
            }
            std::cout << response.str() << std::endl;
        } else {
            std::cout << "Access denied to user data" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_8(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string configName = request.getParam("configName");
        std::string configValue = request.getParam("configValue");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "config.update")) {
            db.executeQuery("UPDATE system_config SET value = '" + configValue + "' WHERE name = '" + configName + "'");
            std::cout << "Configuration updated successfully" << std::endl;
        } else {
            std::cout << "Unauthorized configuration change attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_9(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string reportType = request.getParam("reportType");
        
        // ok: cpp-missing-authorization
        if (reportType == "financial" && authService.hasPermission(session->getUser(), "report.financial")) {
            std::vector<std::string> financialData = db.fetchData("SELECT * FROM financial_records");
            // Process and return financial data
        } else {
            std::cout << "Access denied to financial reports" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_10(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string backupPath = request.getParam("backupPath");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "system.backup")) {
            std::string command = "tar -czf backup.tar.gz " + backupPath;
            system(command.c_str());
            std::cout << "Backup completed" << std::endl;
        } else {
            std::cout << "Unauthorized backup attempt" << std::endl;
        }
    }
}
// {/fact}

class SecureUserController {
public:
    void deleteUser(const HttpRequest& request, const Session* session) {
        if (session) {
            std::string userId = request.getParam("userId");
            
            // ok: cpp-missing-authorization
            if (authService.hasPermission(session->getUser(), "user.delete")) {
                db.executeQuery("DELETE FROM users WHERE id = " + userId);
                std::cout << "User deleted successfully" << std::endl;
            } else {
                std::cout << "Unauthorized user deletion attempt" << std::endl;
            }
        }
    }
};
// {fact rule=missing-authorization@v1.0 defects=1}

void good_case_11(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    SecureUserController controller;
    controller.deleteUser(request, session);
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_12(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string apiKey = request.getParam("regenerateApiKey");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "api.manage_keys")) {
            std::string newApiKey = "generated-key-" + std::to_string(rand());
            db.executeQuery("UPDATE api_keys SET key = '" + newApiKey + "' WHERE id = " + apiKey);
        } else {
            std::cout << "Unauthorized API key regeneration attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_13(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string logFile = request.getParam("logFile");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "logs.view")) {
            std::ifstream file("/var/logs/" + logFile);
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            std::cout << content << std::endl;
        } else {
            std::cout << "Access denied to log files" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_14(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string serverId = request.getParam("serverId");
        std::string action = request.getParam("action");
        
        // ok: cpp-missing-authorization
        if (action == "restart" && authService.hasPermission(session->getUser(), "server.restart")) {
            std::string command = "ssh admin@server" + serverId + " 'sudo reboot'";
            system(command.c_str());
        } else {
            std::cout << "Unauthorized server management attempt" << std::endl;
        }
    }
}
// {/fact}
// {fact rule=missing-authorization@v1.0 defects=0}

void good_case_15(const HttpRequest& request) {
    std::string sessionId = request.getHeader("Session-Id");
    Session* session = globalSessionStore.getSession(sessionId);
    
    if (session) {
        std::string userId = request.getParam("userId");
        
        // ok: cpp-missing-authorization
        if (authService.hasPermission(session->getUser(), "user.view_pii") || 
            session->getUser().username == "user-" + userId) {
            std::vector<std::string> userData = db.fetchData(
                "SELECT name, address, ssn, credit_card FROM users WHERE id = " + userId);
            
            // Return sensitive PII data
            for (const auto& data : userData) {
                std::cout << data << std::endl;
            }
        } else {
            std::cout << "Access denied to PII data" << std::endl;
        }
    }
}
// {/fact}

int main() {
    // This is just a placeholder main function
    std::cout << "Authorization examples" << std::endl;
    return 0;
}