#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <mysql/mysql.h>
#include <sqlite3.h>
#include <cppconn/driver.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/resultset.h>
#include <pqxx/pqxx>
#include <cpprest/http_client.h>
#include <cpprest/json.h>

using namespace std;
using namespace web;
using namespace web::http;
using namespace web::http::client;
// {fact rule=cross-site-scripting@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    // Simple string concatenation with user input from HTTP request
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string username = query_params["username"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        string query = "SELECT * FROM users WHERE username = '" + username + "'";
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_2() {
    // Using string concatenation with POST data
    http_client client(U("http://api.example.com"));
    http_request request(methods::POST);
    
    client.request(request).then([](http_response response) {
        json::value body = response.extract_json().get();
        string user_id = body["user_id"].as_string();
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        string query = "DELETE FROM users WHERE id = " + user_id;
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_3() {
    // Using string concatenation with HTTP headers
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto headers = response.headers();
        string sort_column = headers["Sort-Column"];
        
        sqlite3* db;
        sqlite3_open("example.db", &db);
        
        string query = "SELECT * FROM products ORDER BY " + sort_column;
        // ruleid: cpp-sql-injection-string-concat
        sqlite3_exec(db, query.c_str(), NULL, NULL, NULL);
        
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_4() {
    // Using string concatenation with multiple parameters
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string min_price = query_params["min_price"];
        string max_price = query_params["max_price"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        string query = "SELECT * FROM products WHERE price >= " + min_price + " AND price <= " + max_price;
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_5() {
    // Using string concatenation with C++/CLI SQL connection
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string category = query_params["category"];
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        sql::Statement* stmt = con->createStatement();
        
        string query = "SELECT * FROM products WHERE category = '" + category + "'";
        // ruleid: cpp-sql-injection-string-concat
        stmt->execute(query);
        
        delete stmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_6() {
    // Using string concatenation with PostgreSQL
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string email = query_params["email"];
        
        pqxx::connection conn("dbname=testdb user=postgres password=password");
        pqxx::work txn(conn);
        
        string query = "SELECT * FROM users WHERE email = '" + email + "'";
        // ruleid: cpp-sql-injection-string-concat
        pqxx::result result = txn.exec(query);
        
        txn.commit();
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_7() {
    // Using string concatenation with complex query
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string search_term = query_params["search"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        string query = "SELECT p.*, c.name FROM products p JOIN categories c ON p.category_id = c.id WHERE p.name LIKE '%" + search_term + "%'";
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_8() {
    // Using string concatenation with variable processing
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string user_input = query_params["input"];
        string processed_input = user_input + "_processed";
        
        sqlite3* db;
        sqlite3_open("example.db", &db);
        
        string query = "INSERT INTO logs (entry) VALUES ('" + processed_input + "')";
        // ruleid: cpp-sql-injection-string-concat
        sqlite3_exec(db, query.c_str(), NULL, NULL, NULL);
        
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_9() {
    // Using string concatenation with conditional logic
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string status = query_params["status"];
        string query = "SELECT * FROM orders WHERE ";
        
        if (!status.empty()) {
            query += "status = '" + status + "'";
        } else {
            query += "status = 'pending'";
        }
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_10() {
    // Using string concatenation with multiple inputs and string operations
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string first_name = query_params["first_name"];
        string last_name = query_params["last_name"];
        string full_name = first_name + " " + last_name;
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        sql::Statement* stmt = con->createStatement();
        
        string query = "SELECT * FROM employees WHERE full_name = '" + full_name + "'";
        // ruleid: cpp-sql-injection-string-concat
        stmt->execute(query);
        
        delete stmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_11() {
    // Using string concatenation with ostringstream
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string product_id = query_params["product_id"];
        
        ostringstream query_stream;
        query_stream << "SELECT * FROM products WHERE id = " << product_id;
        string query = query_stream.str();
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query.c_str());
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_12() {
    // Using string concatenation with string append method
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string date = query_params["date"];
        
        string query = "SELECT * FROM events WHERE event_date = '";
        query.append(date);
        query.append("'");
        
        sqlite3* db;
        sqlite3_open("example.db", &db);
        
        // ruleid: cpp-sql-injection-string-concat
        sqlite3_exec(db, query.c_str(), NULL, NULL, NULL);
        
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_13() {
    // Using string concatenation with string operator +=
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string user_role = query_params["role"];
        
        string query = "SELECT * FROM users WHERE role = '";
        query += user_role;
        query += "'";
        
        pqxx::connection conn("dbname=testdb user=postgres password=password");
        pqxx::work txn(conn);
        
        // ruleid: cpp-sql-injection-string-concat
        pqxx::result result = txn.exec(query);
        
        txn.commit();
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_14() {
    // Using string concatenation with sprintf
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string limit = query_params["limit"];
        
        char query[256];
        sprintf(query, "SELECT * FROM products LIMIT %s", limit.c_str());
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        // ruleid: cpp-sql-injection-string-concat
        mysql_query(conn, query);
        
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=1}

void bad_case_15() {
    // Using string concatenation with multiple string operations
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string table_name = query_params["table"];
        string column_name = query_params["column"];
        string value = query_params["value"];
        
        string query = "SELECT * FROM " + table_name + " WHERE " + column_name + " = '" + value + "'";
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        sql::Statement* stmt = con->createStatement();
        
        // ruleid: cpp-sql-injection-string-concat
        stmt->execute(query);
        
        delete stmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    // Using parameterized query with MySQL
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string username = query_params["username"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        // ok: cpp-sql-injection-string-concat
        mysql_stmt_prepare(stmt, "SELECT * FROM users WHERE username = ?", strlen("SELECT * FROM users WHERE username = ?"));
        
        MYSQL_BIND bind[1];
        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)username.c_str();
        bind[0].buffer_length = username.length();
        
        mysql_stmt_bind_param(stmt, bind);
        mysql_stmt_execute(stmt);
        mysql_stmt_close(stmt);
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_2() {
    // Using parameterized query with SQLite
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string user_id = query_params["user_id"];
        
        sqlite3* db;
        sqlite3_stmt* stmt;
        sqlite3_open("example.db", &db);
        
        // ok: cpp-sql-injection-string-concat
        sqlite3_prepare_v2(db, "DELETE FROM users WHERE id = ?", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_3() {
    // Using parameterized query with C++ SQL connector
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string category = query_params["category"];
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        
        // ok: cpp-sql-injection-string-concat
        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT * FROM products WHERE category = ?");
        pstmt->setString(1, category);
        pstmt->executeQuery();
        
        delete pstmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_4() {
    // Using parameterized query with PostgreSQL
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string email = query_params["email"];
        
        pqxx::connection conn("dbname=testdb user=postgres password=password");
        pqxx::work txn(conn);
        
        // ok: cpp-sql-injection-string-concat
        pqxx::result result = txn.exec_params(
            "SELECT * FROM users WHERE email = $1",
            email
        );
        
        txn.commit();
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_5() {
    // Using parameterized query with multiple parameters
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string min_price = query_params["min_price"];
        string max_price = query_params["max_price"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        // ok: cpp-sql-injection-string-concat
        mysql_stmt_prepare(stmt, "SELECT * FROM products WHERE price >= ? AND price <= ?", 
                          strlen("SELECT * FROM products WHERE price >= ? AND price <= ?"));
        
        MYSQL_BIND bind[2];
        memset(bind, 0, sizeof(bind));
        
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)min_price.c_str();
        bind[0].buffer_length = min_price.length();
        
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (char*)max_price.c_str();
        bind[1].buffer_length = max_price.length();
        
        mysql_stmt_bind_param(stmt, bind);
        mysql_stmt_execute(stmt);
        mysql_stmt_close(stmt);
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_6() {
    // Using whitelist validation for column names
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto headers = response.headers();
        string sort_column = headers["Sort-Column"];
        
        // Validate column name against whitelist
        vector<string> allowed_columns = {"name", "price", "date_added", "stock"};
        bool valid_column = false;
        
        for (const auto& col : allowed_columns) {
            if (sort_column == col) {
                valid_column = true;
                break;
            }
        }
        
        if (!valid_column) {
            sort_column = "name"; // Default to a safe value
        }
        
        sqlite3* db;
        sqlite3_open("example.db", &db);
        
        string query = "SELECT * FROM products ORDER BY " + sort_column;
        // ok: cpp-sql-injection-string-concat
        sqlite3_exec(db, query.c_str(), NULL, NULL, NULL);
        
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_7() {
    // Using prepared statement with search term
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string search_term = query_params["search"];
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        
        // ok: cpp-sql-injection-string-concat
        sql::PreparedStatement* pstmt = con->prepareStatement(
            "SELECT p.*, c.name FROM products p JOIN categories c ON p.category_id = c.id WHERE p.name LIKE ?"
        );
        pstmt->setString(1, "%" + search_term + "%");
        pstmt->executeQuery();
        
        delete pstmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_8() {
    // Using prepared statement with variable processing
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string user_input = query_params["input"];
        string processed_input = user_input + "_processed";
        
        sqlite3* db;
        sqlite3_stmt* stmt;
        sqlite3_open("example.db", &db);
        
        // ok: cpp-sql-injection-string-concat
        sqlite3_prepare_v2(db, "INSERT INTO logs (entry) VALUES (?)", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, processed_input.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_9() {
    // Using prepared statement with conditional logic
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string status = query_params["status"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        
        if (!status.empty()) {
            // ok: cpp-sql-injection-string-concat
            mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE status = ?", 
                              strlen("SELECT * FROM orders WHERE status = ?"));
            
            MYSQL_BIND bind[1];
            memset(bind, 0, sizeof(bind));
            bind[0].buffer_type = MYSQL_TYPE_STRING;
            bind[0].buffer = (char*)status.c_str();
            bind[0].buffer_length = status.length();
            
            mysql_stmt_bind_param(stmt, bind);
        } else {
            mysql_stmt_prepare(stmt, "SELECT * FROM orders WHERE status = 'pending'", 
                              strlen("SELECT * FROM orders WHERE status = 'pending'"));
        }
        
        mysql_stmt_execute(stmt);
        mysql_stmt_close(stmt);
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_10() {
    // Using prepared statement with multiple inputs
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string first_name = query_params["first_name"];
        string last_name = query_params["last_name"];
        
        pqxx::connection conn("dbname=testdb user=postgres password=password");
        pqxx::work txn(conn);
        
        // ok: cpp-sql-injection-string-concat
        pqxx::result result = txn.exec_params(
            "SELECT * FROM employees WHERE first_name = $1 AND last_name = $2",
            first_name, last_name
        );
        
        txn.commit();
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_11() {
    // Using prepared statement instead of ostringstream
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string product_id = query_params["product_id"];
        
        sqlite3* db;
        sqlite3_stmt* stmt;
        sqlite3_open("example.db", &db);
        
        // ok: cpp-sql-injection-string-concat
        sqlite3_prepare_v2(db, "SELECT * FROM products WHERE id = ?", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, product_id.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_12() {
    // Using prepared statement instead of string append
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string date = query_params["date"];
        
        sql::Driver* driver = get_driver_instance();
        sql::Connection* con = driver->connect("tcp://127.0.0.1:3306", "root", "password");
        con->setSchema("test");
        
        // ok: cpp-sql-injection-string-concat
        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT * FROM events WHERE event_date = ?");
        pstmt->setString(1, date);
        pstmt->executeQuery();
        
        delete pstmt;
        delete con;
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_13() {
    // Using stored procedure instead of direct query
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string user_role = query_params["role"];
        
        MYSQL* conn = mysql_init(NULL);
        mysql_real_connect(conn, "localhost", "root", "password", "database", 0, NULL, 0);
        
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        // ok: cpp-sql-injection-string-concat
        mysql_stmt_prepare(stmt, "CALL get_users_by_role(?)", strlen("CALL get_users_by_role(?)"));
        
        MYSQL_BIND bind[1];
        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)user_role.c_str();
        bind[0].buffer_length = user_role.length();
        
        mysql_stmt_bind_param(stmt, bind);
        mysql_stmt_execute(stmt);
        mysql_stmt_close(stmt);
        mysql_close(conn);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_14() {
    // Using prepared statement instead of sprintf
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string limit = query_params["limit"];
        
        sqlite3* db;
        sqlite3_stmt* stmt;
        sqlite3_open("example.db", &db);
        
        // ok: cpp-sql-injection-string-concat
        sqlite3_prepare_v2(db, "SELECT * FROM products LIMIT ?", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, limit.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    });
}
// {/fact}
// {fact rule=cross-site-scripting@v1.0 defects=0}

void good_case_15() {
    // Using ORM library to prevent SQL injection
    http_client client(U("http://api.example.com"));
    http_request request(methods::GET);
    
    client.request(request).then([](http_response response) {
        auto query_params = uri::split_query(response.extract_string().get());
        string value = query_params["value"];
        
        // This is a simplified example of how an ORM might work
        // In a real ORM, this would be handled by the library
        class ORM {
        public:
            ORM(const string& db_name) {
                sqlite3_open(db_name.c_str(), &db);
            }
            
            void select(const string& table, const string& column, const string& value) {
                sqlite3_stmt* stmt;
                // ok: cpp-sql-injection-string-concat
                sqlite3_prepare_v2(db, "SELECT * FROM ? WHERE ? = ?", -1, &stmt, NULL);
                sqlite3_bind_text(stmt, 1, table.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 2, column.c_str(), -1, SQLITE_STATIC);
                sqlite3_bind_text(stmt, 3, value.c_str(), -1, SQLITE_STATIC);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
            
            ~ORM() {
                sqlite3_close(db);
            }
            
        private:
            sqlite3* db;
        };
        
        ORM orm("example.db");
        orm.select("users", "username", value);
    });
}
// {/fact}

int main() {
    // This is just a placeholder main function
    return 0;
}