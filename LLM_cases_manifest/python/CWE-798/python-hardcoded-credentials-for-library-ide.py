# Examples for python-hardcoded-credentials-for-library-ide rule
# This file contains examples of hardcoded credentials in Python code

import os
import boto3
import pymysql
import psycopg2
import requests
import smtplib
import paramiko
import redis
import pymongo
import azure.storage.blob
from google.cloud import storage
from azure.identity import DefaultAzureCredential
from elasticsearch import Elasticsearch
from ftplib import FTP
from sqlalchemy import create_engine
from dotenv import load_dotenv
from configparser import ConfigParser
import keyring
import json
from cryptography.fernet import Fernet

# True Positive Examples (Vulnerable Code)

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_1():
    # Database connection with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    connection = pymysql.connect(
        host='database.example.com',
        user='admin',
        password='super_secret_password123',
        database='customer_data'
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_2():
    # AWS S3 access with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    s3_client = boto3.client(
        's3',
        aws_access_key_id='AKIA_PLACEHOLDER_ACCESS_KEY',
        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    )
    response = s3_client.list_buckets()
    return response['Buckets']

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_3():
    # REST API call with hardcoded API key
    headers = {
        'Content-Type': 'application/json',
        # ruleid: python-hardcoded-credentials-for-library-ide
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
    }
    response = requests.get('https://api.example.com/data', headers=headers)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_4():
    # SMTP configuration with hardcoded password
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    # ruleid: python-hardcoded-credentials-for-library-ide
    server.login('user@example.com', 'email_password_123')
    message = "Hello, this is a test email."
    server.sendmail('user@example.com', 'recipient@example.com', message)
    server.quit()
    return "Email sent successfully"

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_5():
    # SSH connection with hardcoded credentials
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ruleid: python-hardcoded-credentials-for-library-ide
    client.connect('server.example.com', username='admin', password='ssh_secret_password')
    stdin, stdout, stderr = client.exec_command('ls -la')
    result = stdout.read().decode()
    client.close()
    return result

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_6():
    # PostgreSQL connection with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    conn = psycopg2.connect(
        host="postgres.example.com",
        database="analytics",
        user="postgres_user",
        password="postgres_password_2023"
    )
    cur = conn.cursor()
    cur.execute("SELECT version();")
    version = cur.fetchone()
    cur.close()
    conn.close()
    return version

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_7():
    # Redis connection with hardcoded password
    # ruleid: python-hardcoded-credentials-for-library-ide
    r = redis.Redis(
        host='redis.example.com',
        port=6379,
        password='redis_secret_auth_string',
        db=0
    )
    r.set('test_key', 'test_value')
    return r.get('test_key')

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_8():
    # MongoDB connection with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    client = pymongo.MongoClient(
        "mongodb+srv://mongo_user:mongo_password_456@cluster0.mongodb.net/test"
    )
    db = client.test_database
    collection = db.test_collection
    result = collection.find_one()
    return result

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_9():
    # Azure Blob Storage with hardcoded connection string
    # ruleid: python-hardcoded-credentials-for-library-ide
    connection_string = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY;EndpointSuffix=core.windows.net"
    blob_service_client = azure.storage.blob.BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("mycontainer")
    blob_list = container_client.list_blobs()
    return [blob.name for blob in blob_list]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_10():
    # Google Cloud Storage with hardcoded key file content
    # ruleid: python-hardcoded-credentials-for-library-ide
    key_json = {
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": "private-key-id-value",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----\n",
        "client_email": "service-account@my-project.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
    
    with open('temp_key.json', 'w') as f:
        json.dump(key_json, f)
    
    client = storage.Client.from_service_account_json('temp_key.json')
    bucket = client.get_bucket('my-bucket')
    blobs = bucket.list_blobs()
    os.remove('temp_key.json')
    return [blob.name for blob in blobs]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_11():
    # FTP connection with hardcoded credentials
    ftp = FTP('ftp.example.com')
    # ruleid: python-hardcoded-credentials-for-library-ide
    ftp.login(user='ftpuser', passwd='ftp_password_789')
    files = ftp.nlst()
    ftp.quit()
    return files

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_12():
    # SQLAlchemy connection with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    engine = create_engine('postgresql://user:db_password_321@localhost:5432/mydatabase')
    connection = engine.connect()
    result = connection.execute("SELECT * FROM users LIMIT 5")
    connection.close()
    return [row for row in result]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_13():
    # Elasticsearch connection with hardcoded credentials
    # ruleid: python-hardcoded-credentials-for-library-ide
    es = Elasticsearch(
        ['https://elasticsearch.example.com:9200'],
        http_auth=('elastic', 'elastic_password_2023')
    )
    result = es.search(index="my-index", body={"query": {"match_all": {}}})
    return result['hits']['hits']

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_14():
    # Encryption key hardcoded
    # ruleid: python-hardcoded-credentials-for-library-ide
    encryption_key = b'TluxwB3fV_GWuLkR1_BzGs1Zk90TYAuhNMZP_0q4WyM='
    f = Fernet(encryption_key)
    encrypted_data = f.encrypt(b"Secret message")
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_15():
    # API key in configuration dictionary
    config = {
        'api_url': 'https://api.service.com/v1',
        # ruleid: python-hardcoded-credentials-for-library-ide
        'api_key': '9a8b7c6d5e4f3g2h1i',
        'timeout': 30
    }
    headers = {'Authorization': f'Bearer {config["api_key"]}'}
    response = requests.get(f"{config['api_url']}/data", headers=headers)
    return response.json()

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_1():
    # Database connection with credentials from environment variables
    # ok: python-hardcoded-credentials-for-library-ide
    connection = pymysql.connect(
        host=os.environ.get('DB_HOST'),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        database=os.environ.get('DB_NAME')
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_2():
    # AWS S3 access with credentials from environment variables
    # ok: python-hardcoded-credentials-for-library-ide
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    response = s3_client.list_buckets()
    return response['Buckets']

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_3():
    # REST API call with API key from environment variable
    # ok: python-hardcoded-credentials-for-library-ide
    api_key = os.environ.get('API_KEY')
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    response = requests.get('https://api.example.com/data', headers=headers)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_4():
    # SMTP configuration with password from environment variable
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    # ok: python-hardcoded-credentials-for-library-ide
    server.login(os.environ.get('EMAIL_USER'), os.environ.get('EMAIL_PASSWORD'))
    message = "Hello, this is a test email."
    server.sendmail(os.environ.get('EMAIL_USER'), 'recipient@example.com', message)
    server.quit()
    return "Email sent successfully"

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_5():
    # SSH connection with credentials from environment variables
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # ok: python-hardcoded-credentials-for-library-ide
    client.connect(
        os.environ.get('SSH_HOST'),
        username=os.environ.get('SSH_USER'),
        password=os.environ.get('SSH_PASSWORD')
    )
    stdin, stdout, stderr = client.exec_command('ls -la')
    result = stdout.read().decode()
    client.close()
    return result

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_6():
    # PostgreSQL connection with credentials from .env file
    load_dotenv()  # Load environment variables from .env file
    # ok: python-hardcoded-credentials-for-library-ide
    conn = psycopg2.connect(
        host=os.environ.get('PG_HOST'),
        database=os.environ.get('PG_DATABASE'),
        user=os.environ.get('PG_USER'),
        password=os.environ.get('PG_PASSWORD')
    )
    cur = conn.cursor()
    cur.execute("SELECT version();")
    version = cur.fetchone()
    cur.close()
    conn.close()
    return version

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_7():
    # Redis connection with password from configuration file
    config = ConfigParser()
    config.read('config.ini')
    # ok: python-hardcoded-credentials-for-library-ide
    r = redis.Redis(
        host=config.get('redis', 'host'),
        port=config.getint('redis', 'port'),
        password=config.get('redis', 'password'),
        db=config.getint('redis', 'db')
    )
    r.set('test_key', 'test_value')
    return r.get('test_key')

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_8():
    # MongoDB connection with credentials from environment variables
    # ok: python-hardcoded-credentials-for-library-ide
    mongo_uri = os.environ.get('MONGO_URI')
    client = pymongo.MongoClient(mongo_uri)
    db = client.test_database
    collection = db.test_collection
    result = collection.find_one()
    return result

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_9():
    # Azure Blob Storage with connection string from environment variable
    # ok: python-hardcoded-credentials-for-library-ide
    connection_string = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client = azure.storage.blob.BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("mycontainer")
    blob_list = container_client.list_blobs()
    return [blob.name for blob in blob_list]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_10():
    # Google Cloud Storage with default credentials
    # ok: python-hardcoded-credentials-for-library-ide
    # Uses GOOGLE_APPLICATION_CREDENTIALS environment variable
    client = storage.Client()
    bucket = client.get_bucket(os.environ.get('GCS_BUCKET_NAME'))
    blobs = bucket.list_blobs()
    return [blob.name for blob in blobs]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_11():
    # FTP connection with credentials from keyring
    ftp = FTP('ftp.example.com')
    # ok: python-hardcoded-credentials-for-library-ide
    username = os.environ.get('FTP_USER')
    password = keyring.get_password('ftp_service', username)
    ftp.login(user=username, passwd=password)
    files = ftp.nlst()
    ftp.quit()
    return files

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_12():
    # SQLAlchemy connection with credentials from environment variables
    # ok: python-hardcoded-credentials-for-library-ide
    db_user = os.environ.get('DB_USER')
    db_pass = os.environ.get('DB_PASS')
    db_host = os.environ.get('DB_HOST')
    db_name = os.environ.get('DB_NAME')
    engine = create_engine(f'postgresql://{db_user}:{db_pass}@{db_host}:5432/{db_name}')
    connection = engine.connect()
    result = connection.execute("SELECT * FROM users LIMIT 5")
    connection.close()
    return [row for row in result]

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_13():
    # Elasticsearch connection with credentials from environment variables
    # ok: python-hardcoded-credentials-for-library-ide
    es = Elasticsearch(
        [os.environ.get('ES_HOST')],
        http_auth=(os.environ.get('ES_USER'), os.environ.get('ES_PASSWORD'))
    )
    result = es.search(index="my-index", body={"query": {"match_all": {}}})
    return result['hits']['hits']

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_14():
    # Encryption key from environment variable
    # ok: python-hardcoded-credentials-for-library-ide
    encryption_key = os.environ.get('ENCRYPTION_KEY').encode()
    f = Fernet(encryption_key)
    encrypted_data = f.encrypt(b"Secret message")
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_15():
    # Azure authentication using managed identity
    # ok: python-hardcoded-credentials-for-library-ide
    credential = DefaultAzureCredential()
    blob_service_client = azure.storage.blob.BlobServiceClient(
        account_url=f"https://{os.environ.get('STORAGE_ACCOUNT')}.blob.core.windows.net",
        credential=credential
    )
    container_client = blob_service_client.get_container_client("mycontainer")
    blob_list = container_client.list_blobs()
    return [blob.name for blob in blob_list]
# {/fact}