#include <iostream>
#include <string>
#include <sqlite3.h>
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>
#include <regex>

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1(http_request request) {
    // Get username from HTTP request
    auto params = uri::split_query(request.request_uri().query());
    std::string username = params["username"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Constructing SQL query with user input directly
    std::string sql = "SELECT * FROM users WHERE username = '" + username + "'";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_2(http_request request) {
    // Get user credentials from POST data
    auto json_value = request.extract_json().get();
    std::string username = json_value["username"].as_string();
    std::string password = json_value["password"].as_string();
    
    sqlite3* db;
    sqlite3_open("users.db", &db);
    
    // Vulnerable SQL query construction
    std::string sql = "SELECT * FROM users WHERE username = '" + username + 
                      "' AND password = '" + password + "'";
    
    // ruleid: cpp-sql-injection
    char* errMsg;
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_3(http_request request) {
    // Get user ID from request headers
    std::string user_id = request.headers()["User-ID"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Vulnerable query with user input in WHERE clause
    std::string sql = "DELETE FROM users WHERE id = " + user_id;
    
    // ruleid: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_4(http_request request) {
    // Get search term from query parameters
    auto params = uri::split_query(request.request_uri().query());
    std::string search = params["search"];
    
    sqlite3* db;
    sqlite3_open("products.db", &db);
    
    // Vulnerable LIKE query
    std::string sql = "SELECT * FROM products WHERE name LIKE '%" + search + "%'";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_5(http_request request) {
    // Get sort column from request
    auto params = uri::split_query(request.request_uri().query());
    std::string sort_col = params["sort"];
    std::string sort_dir = params["direction"];
    
    sqlite3* db;
    sqlite3_open("products.db", &db);
    
    // Vulnerable ORDER BY clause
    std::string sql = "SELECT * FROM products ORDER BY " + sort_col + " " + sort_dir;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_6(http_request request) {
    // Get filter values from request
    auto json_value = request.extract_json().get();
    std::string min_price = json_value["min_price"].as_string();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("products.db", &db);
    
    // Vulnerable numeric parameter
    std::string sql = "SELECT * FROM products WHERE price > " + min_price;
    
    // ruleid: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_7(http_request request) {
    // Get table name from request
    auto params = uri::split_query(request.request_uri().query());
    std::string table = params["table"];
    
    sqlite3* db;
    sqlite3_open("database.db", &db);
    
    // Vulnerable dynamic table name
    std::string sql = "SELECT * FROM " + table;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_8(http_request request) {
    // Get user input from cookies
    std::string user_filter = request.headers()["Cookie"];
    // Extract value from cookie string
    size_t pos = user_filter.find("filter=");
    if (pos != std::string::npos) {
        user_filter = user_filter.substr(pos + 7);
        pos = user_filter.find(";");
        if (pos != std::string::npos) {
            user_filter = user_filter.substr(0, pos);
        }
    }
    
    sqlite3* db;
    sqlite3_open("data.db", &db);
    
    // Vulnerable WHERE clause with user input
    std::string sql = "SELECT * FROM data WHERE category = '" + user_filter + "'";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_9(http_request request) {
    // Get limit from request
    auto params = uri::split_query(request.request_uri().query());
    std::string limit = params["limit"];
    std::string offset = params["offset"];
    
    sqlite3* db;
    sqlite3_open("logs.db", &db);
    
    // Vulnerable LIMIT and OFFSET
    std::string sql = "SELECT * FROM logs LIMIT " + limit + " OFFSET " + offset;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_10(http_request request) {
    // Get user IDs from request
    auto json_value = request.extract_json().get();
    std::string ids = json_value["user_ids"].as_string();
    
    sqlite3* db;
    sqlite3_open("users.db", &db);
    
    // Vulnerable IN clause
    std::string sql = "SELECT * FROM users WHERE id IN (" + ids + ")";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_11(http_request request) {
    // Get column names from request
    auto params = uri::split_query(request.request_uri().query());
    std::string columns = params["columns"];
    
    sqlite3* db;
    sqlite3_open("data.db", &db);
    
    // Vulnerable column selection
    std::string sql = "SELECT " + columns + " FROM data";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_12(http_request request) {
    // Get user input for a batch update
    auto json_value = request.extract_json().get();
    std::string status = json_value["status"].as_string();
    std::string user_type = json_value["user_type"].as_string();
    
    sqlite3* db;
    sqlite3_open("users.db", &db);
    
    // Vulnerable UPDATE with multiple user inputs
    std::string sql = "UPDATE users SET status = '" + status + 
                      "' WHERE user_type = '" + user_type + "'";
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_13(http_request request) {
    // Get group by parameter from request
    auto params = uri::split_query(request.request_uri().query());
    std::string group_by = params["group"];
    
    sqlite3* db;
    sqlite3_open("analytics.db", &db);
    
    // Vulnerable GROUP BY clause
    std::string sql = "SELECT count(*), " + group_by + " FROM events GROUP BY " + group_by;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_14(http_request request) {
    // Get join condition from request
    auto json_value = request.extract_json().get();
    std::string join_condition = json_value["condition"].as_string();
    
    sqlite3* db;
    sqlite3_open("data.db", &db);
    
    // Vulnerable JOIN condition
    std::string sql = "SELECT * FROM table1 JOIN table2 ON " + join_condition;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_15(http_request request) {
    // Get having clause from request
    auto params = uri::split_query(request.request_uri().query());
    std::string having = params["having"];
    
    sqlite3* db;
    sqlite3_open("sales.db", &db);
    
    // Vulnerable HAVING clause
    std::string sql = "SELECT product, SUM(amount) FROM sales GROUP BY product HAVING " + having;
    
    // ruleid: cpp-sql-injection
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1(http_request request) {
    // Get username from HTTP request
    auto params = uri::split_query(request.request_uri().query());
    std::string username = params["username"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Using parameterized query
    std::string sql = "SELECT * FROM users WHERE username = ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_2(http_request request) {
    // Get user credentials from POST data
    auto json_value = request.extract_json().get();
    std::string username = json_value["username"].as_string();
    std::string password = json_value["password"].as_string();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Using parameterized query for authentication
    std::string sql = "SELECT * FROM users WHERE username = ? AND password = ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_3(http_request request) {
    // Get user ID from request headers
    std::string user_id = request.headers()["User-ID"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Safe parameterized DELETE query
    std::string sql = "DELETE FROM users WHERE id = ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, std::stoi(user_id));
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_4(http_request request) {
    // Get search term from query parameters
    auto params = uri::split_query(request.request_uri().query());
    std::string search = params["search"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("products.db", &db);
    
    // Safe LIKE query with parameter
    std::string sql = "SELECT * FROM products WHERE name LIKE ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    std::string search_pattern = "%" + search + "%";
    sqlite3_bind_text(stmt, 1, search_pattern.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_5(http_request request) {
    // Get sort column from request
    auto params = uri::split_query(request.request_uri().query());
    std::string sort_col = params["sort"];
    std::string sort_dir = params["direction"];
    
    // Validate sort column against allowed values
    std::vector<std::string> allowed_columns = {"name", "price", "date", "rating"};
    bool valid_column = false;
    for (const auto& col : allowed_columns) {
        if (sort_col == col) {
            valid_column = true;
            break;
        }
    }
    
    // Validate sort direction
    if (sort_dir != "ASC" && sort_dir != "DESC") {
        sort_dir = "ASC";
    }
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("products.db", &db);
    
    std::string sql;
    if (valid_column) {
        // ok: cpp-sql-injection
        sql = "SELECT * FROM products ORDER BY " + sort_col + " " + sort_dir;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_step(stmt);
    } else {
        // Default safe query if invalid column
        sql = "SELECT * FROM products ORDER BY name ASC";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_step(stmt);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_6(http_request request) {
    // Get filter values from request
    auto json_value = request.extract_json().get();
    std::string min_price_str = json_value["min_price"].as_string();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("products.db", &db);
    
    // Safe numeric parameter binding
    std::string sql = "SELECT * FROM products WHERE price > ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    double min_price = std::stod(min_price_str);
    sqlite3_bind_double(stmt, 1, min_price);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_7(http_request request) {
    // Get table name from request
    auto params = uri::split_query(request.request_uri().query());
    std::string table = params["table"];
    
    // Whitelist validation for table names
    std::map<std::string, std::string> table_map = {
        {"users", "users"},
        {"products", "products"},
        {"orders", "orders"}
    };
    
    sqlite3* db;
    sqlite3_open("database.db", &db);
    
    if (table_map.find(table) != table_map.end()) {
        // ok: cpp-sql-injection
        std::string sql = "SELECT * FROM " + table_map[table];
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    } else {
        // Default to a safe table if not in whitelist
        std::string sql = "SELECT * FROM default_table";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    }
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_8(http_request request) {
    // Get user input from cookies
    std::string user_filter = request.headers()["Cookie"];
    // Extract value from cookie string
    size_t pos = user_filter.find("filter=");
    if (pos != std::string::npos) {
        user_filter = user_filter.substr(pos + 7);
        pos = user_filter.find(";");
        if (pos != std::string::npos) {
            user_filter = user_filter.substr(0, pos);
        }
    }
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("data.db", &db);
    
    // Safe parameterized query
    std::string sql = "SELECT * FROM data WHERE category = ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, user_filter.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_9(http_request request) {
    // Get limit from request
    auto params = uri::split_query(request.request_uri().query());
    std::string limit_str = params["limit"];
    std::string offset_str = params["offset"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("logs.db", &db);
    
    // Safe parameterized LIMIT and OFFSET
    std::string sql = "SELECT * FROM logs LIMIT ? OFFSET ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    int limit = std::stoi(limit_str);
    int offset = std::stoi(offset_str);
    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_10(http_request request) {
    // Get user IDs from request as array
    auto json_value = request.extract_json().get();
    auto ids_array = json_value["user_ids"].as_array();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Prepare a safe parameterized query with the right number of placeholders
    std::string placeholders;
    for (size_t i = 0; i < ids_array.size(); i++) {
        if (i > 0) placeholders += ",";
        placeholders += "?";
    }
    
    std::string sql = "SELECT * FROM users WHERE id IN (" + placeholders + ")";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    
    // Bind each parameter individually
    for (size_t i = 0; i < ids_array.size(); i++) {
        int id = ids_array[i].as_integer();
        sqlite3_bind_int(stmt, i+1, id);
    }
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_11(http_request request) {
    // Get column names from request
    auto params = uri::split_query(request.request_uri().query());
    std::string columns_param = params["columns"];
    
    // Whitelist validation for column names
    std::map<std::string, bool> allowed_columns = {
        {"id", true},
        {"name", true},
        {"email", true},
        {"created_at", true}
    };
    
    // Parse and validate requested columns
    std::vector<std::string> requested_columns;
    std::stringstream ss(columns_param);
    std::string column;
    while (std::getline(ss, column, ',')) {
        if (allowed_columns.find(column) != allowed_columns.end()) {
            requested_columns.push_back(column);
        }
    }
    
    // Build safe column list
    std::string safe_columns = requested_columns.empty() ? "*" : "";
    for (size_t i = 0; i < requested_columns.size(); i++) {
        if (i > 0) safe_columns += ", ";
        safe_columns += requested_columns[i];
    }
    
    sqlite3* db;
    sqlite3_open("data.db", &db);
    
    // ok: cpp-sql-injection
    std::string sql = "SELECT " + safe_columns + " FROM data";
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_12(http_request request) {
    // Get user input for a batch update
    auto json_value = request.extract_json().get();
    std::string status = json_value["status"].as_string();
    std::string user_type = json_value["user_type"].as_string();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("users.db", &db);
    
    // Safe parameterized UPDATE
    std::string sql = "UPDATE users SET status = ? WHERE user_type = ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user_type.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_13(http_request request) {
    // Get group by parameter from request
    auto params = uri::split_query(request.request_uri().query());
    std::string group_by = params["group"];
    
    // Whitelist validation for group by columns
    std::vector<std::string> allowed_columns = {"date", "category", "region", "product"};
    bool valid_column = false;
    for (const auto& col : allowed_columns) {
        if (group_by == col) {
            valid_column = true;
            break;
        }
    }
    
    sqlite3* db;
    sqlite3_open("analytics.db", &db);
    
    if (valid_column) {
        // ok: cpp-sql-injection
        std::string sql = "SELECT count(*), " + group_by + " FROM events GROUP BY " + group_by;
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    } else {
        // Default safe query if invalid column
        std::string sql = "SELECT count(*), date FROM events GROUP BY date";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    }
    
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_14(http_request request) {
    // Get join parameters from request
    auto json_value = request.extract_json().get();
    std::string join_field1 = json_value["field1"].as_string();
    std::string join_field2 = json_value["field2"].as_string();
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("data.db", &db);
    
    // Safe parameterized JOIN
    std::string sql = "SELECT * FROM table1 JOIN table2 ON table1.? = table2.?";
    
    // Validate fields against whitelist
    std::vector<std::string> allowed_fields = {"id", "user_id", "product_id", "order_id"};
    bool valid_field1 = false, valid_field2 = false;
    
    for (const auto& field : allowed_fields) {
        if (join_field1 == field) valid_field1 = true;
        if (join_field2 == field) valid_field2 = true;
    }
    
    if (valid_field1 && valid_field2) {
        // ok: cpp-sql-injection
        sql = "SELECT * FROM table1 JOIN table2 ON table1." + join_field1 + " = table2." + join_field2;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_step(stmt);
    } else {
        // Default safe join if invalid fields
        sql = "SELECT * FROM table1 JOIN table2 ON table1.id = table2.id";
        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        sqlite3_step(stmt);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_15(http_request request) {
    // Get having clause from request
    auto params = uri::split_query(request.request_uri().query());
    std::string min_sum = params["min_sum"];
    
    sqlite3* db;
    sqlite3_stmt* stmt;
    sqlite3_open("sales.db", &db);
    
    // Safe parameterized HAVING clause
    std::string sql = "SELECT product, SUM(amount) as total FROM sales GROUP BY product HAVING total > ?";
    
    // ok: cpp-sql-injection
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    double min_sum_value = std::stod(min_sum);
    sqlite3_bind_double(stmt, 1, min_sum_value);
    sqlite3_step(stmt);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}
// {/fact}