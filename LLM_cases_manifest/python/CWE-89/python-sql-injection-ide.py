import sqlite3
import mysql.connector
import psycopg2
from flask import Flask, request, g
import os
from pymongo import MongoClient
import re
from sqlalchemy import create_engine, text
import pymysql
import cx_Oracle
import django.db
from django.db import connection
from werkzeug.datastructures import ImmutableMultiDict

app = Flask(__name__)

# True Positive Examples (Vulnerable Code)

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1():
    # Direct string concatenation with user input
    user_id = request.args.get('user_id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2():
    # String formatting with user input
    username = request.form.get('username')
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '%s'" % username
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3():
    # Format string with multiple inputs
    product_id = request.args.get('product_id')
    category = request.args.get('category')
    conn = psycopg2.connect("dbname=test user=postgres password=postgres")
    cur = conn.cursor()
    query = "SELECT * FROM products WHERE id = {} AND category = '{}'".format(product_id, category)
    # ruleid: python-sql-injection-ide
    cur.execute(query)
    results = cur.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4():
    # F-string with user input
    email = request.form.get('email')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE email = '{email}'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5():
    # String concatenation with processed input
    search = request.args.get('search', '')
    search_term = "%" + search + "%"
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '" + search_term + "'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6():
    # SQLAlchemy with string formatting
    user_id = request.args.get('user_id')
    engine = create_engine('sqlite:///example.db')
    conn = engine.connect()
    query = text("SELECT * FROM users WHERE id = " + user_id)
    # ruleid: python-sql-injection-ide
    result = conn.execute(query)
    conn.close()
    return result.fetchall()

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7():
    # Django raw query with string concatenation
    user_id = request.GET.get('user_id')
    query = "SELECT * FROM auth_user WHERE id = " + user_id
    # ruleid: python-sql-injection-ide
    results = django.db.connection.cursor().execute(query)
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8():
    # PyMySQL with string formatting
    username = request.form.get('username')
    conn = pymysql.connect(host='localhost', user='user', password='password', db='testdb')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9():
    # Oracle connection with string concatenation
    order_id = request.args.get('order_id')
    conn = cx_Oracle.connect('username/password@localhost:1521/xe')
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE id = " + order_id
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10():
    # Multiple operations with string concatenation
    user_id = request.args.get('user_id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # First query
    query1 = "SELECT username FROM users WHERE id = " + user_id
    # ruleid: python-sql-injection-ide
    cursor.execute(query1)
    username = cursor.fetchone()[0]
    
    # Second query using result from first
    query2 = "SELECT * FROM orders WHERE username = '" + username + "'"
    # ruleid: python-sql-injection-ide
    cursor.execute(query2)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11():
    # String concatenation with header input
    user_agent = request.headers.get('User-Agent')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "INSERT INTO logs (user_agent, timestamp) VALUES ('" + user_agent + "', datetime('now'))"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    conn.commit()
    conn.close()
    return "Log saved"

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12():
    # String formatting with cookie input
    session_id = request.cookies.get('session_id')
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM sessions WHERE id = '%s'" % session_id
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13():
    # String concatenation with minimal input processing
    sort_field = request.args.get('sort', 'id')
    sort_dir = request.args.get('dir', 'ASC')
    
    # Simple validation that doesn't prevent injection
    if sort_dir not in ['ASC', 'DESC']:
        sort_dir = 'ASC'
    
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products ORDER BY " + sort_field + " " + sort_dir
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14():
    # String concatenation with JSON input
    data = request.get_json()
    user_id = data.get('user_id')
    conn = psycopg2.connect("dbname=test user=postgres password=postgres")
    cur = conn.cursor()
    query = "DELETE FROM users WHERE id = " + str(user_id)
    # ruleid: python-sql-injection-ide
    cur.execute(query)
    conn.commit()
    conn.close()
    return "User deleted"

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15():
    # String concatenation with form data in a list
    form_data = request.form
    ids = form_data.getlist('ids')
    id_string = ','.join(ids)
    
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE id IN (" + id_string + ")"
    # ruleid: python-sql-injection-ide
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

# True Negative Examples (Safe Code)

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1():
    # Using parameterized query with SQLite
    user_id = request.args.get('user_id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    # ok: python-sql-injection-ide
    cursor.execute(query, (user_id,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2():
    # Using parameterized query with MySQL
    username = request.form.get('username')
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = %s"
    # ok: python-sql-injection-ide
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3():
    # Using parameterized query with PostgreSQL
    product_id = request.args.get('product_id')
    category = request.args.get('category')
    conn = psycopg2.connect("dbname=test user=postgres password=postgres")
    cur = conn.cursor()
    query = "SELECT * FROM products WHERE id = %s AND category = %s"
    # ok: python-sql-injection-ide
    cur.execute(query, (product_id, category))
    results = cur.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4():
    # Using parameterized query with SQLAlchemy
    email = request.form.get('email')
    engine = create_engine('sqlite:///example.db')
    conn = engine.connect()
    query = text("SELECT * FROM users WHERE email = :email")
    # ok: python-sql-injection-ide
    result = conn.execute(query, {"email": email})
    conn.close()
    return result.fetchall()

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5():
    # Using parameterized query with search term
    search = request.args.get('search', '')
    search_term = "%" + search + "%"
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE %s"
    # ok: python-sql-injection-ide
    cursor.execute(query, (search_term,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6():
    # Using Django ORM instead of raw SQL
    user_id = request.GET.get('user_id')
    from django.contrib.auth.models import User
    # ok: python-sql-injection-ide
    user = User.objects.get(id=user_id)
    return user

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7():
    # Using PyMySQL with parameterized query
    username = request.form.get('username')
    conn = pymysql.connect(host='localhost', user='user', password='password', db='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = %s"
    # ok: python-sql-injection-ide
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8():
    # Using Oracle with parameterized query
    order_id = request.args.get('order_id')
    conn = cx_Oracle.connect('username/password@localhost:1521/xe')
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE id = :id"
    # ok: python-sql-injection-ide
    cursor.execute(query, id=order_id)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9():
    # Using SQLite with multiple parameterized operations
    user_id = request.args.get('user_id')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # First query
    query1 = "SELECT username FROM users WHERE id = ?"
    # ok: python-sql-injection-ide
    cursor.execute(query1, (user_id,))
    username = cursor.fetchone()[0]
    
    # Second query using result from first
    query2 = "SELECT * FROM orders WHERE username = ?"
    # ok: python-sql-injection-ide
    cursor.execute(query2, (username,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10():
    # Using parameterized query with header input
    user_agent = request.headers.get('User-Agent')
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = "INSERT INTO logs (user_agent, timestamp) VALUES (?, datetime('now'))"
    # ok: python-sql-injection-ide
    cursor.execute(query, (user_agent,))
    conn.commit()
    conn.close()
    return "Log saved"

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11():
    # Using parameterized query with cookie input
    session_id = request.cookies.get('session_id')
    conn = mysql.connector.connect(user='root', password='password', host='localhost', database='testdb')
    cursor = conn.cursor()
    query = "SELECT * FROM sessions WHERE id = %s"
    # ok: python-sql-injection-ide
    cursor.execute(query, (session_id,))
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12():
    # Safe handling of sort parameters
    sort_field = request.args.get('sort', 'id')
    sort_dir = request.args.get('dir', 'ASC')
    
    # Whitelist validation
    allowed_fields = ['id', 'name', 'price', 'date']
    allowed_dirs = ['ASC', 'DESC']
    
    if sort_field not in allowed_fields:
        sort_field = 'id'
    if sort_dir not in allowed_dirs:
        sort_dir = 'ASC'
    
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM products ORDER BY {sort_field} {sort_dir}"
    # ok: python-sql-injection-ide
    cursor.execute(query)  # Safe because we've validated against a whitelist
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13():
    # Using parameterized query with JSON input
    data = request.get_json()
    user_id = data.get('user_id')
    conn = psycopg2.connect("dbname=test user=postgres password=postgres")
    cur = conn.cursor()
    query = "DELETE FROM users WHERE id = %s"
    # ok: python-sql-injection-ide
    cur.execute(query, (user_id,))
    conn.commit()
    conn.close()
    return "User deleted"

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14():
    # Using parameterized query with form data in a list
    form_data = request.form
    ids = form_data.getlist('ids')
    
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    placeholders = ','.join(['?'] * len(ids))
    query = f"SELECT * FROM products WHERE id IN ({placeholders})"
    # ok: python-sql-injection-ide
    cursor.execute(query, ids)
    results = cursor.fetchall()
    conn.close()
    return results

# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15():
    # Using SQLAlchemy ORM instead of raw SQL
    from sqlalchemy import create_engine, Column, Integer, String
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    
    Base = declarative_base()
    
    class User(Base):
        __tablename__ = 'users'
        id = Column(Integer, primary_key=True)
        username = Column(String)
    
    engine = create_engine('sqlite:///example.db')
    Session = sessionmaker(bind=engine)
    session = Session()
    
    user_id = request.args.get('user_id')
    # ok: python-sql-injection-ide
    user = session.query(User).filter(User.id == user_id).first()
    session.close()
    return user
# {/fact}