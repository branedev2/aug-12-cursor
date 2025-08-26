import os
import boto3
import pymysql
import requests
import smtplib
import paramiko
import firebase_admin
import redis
from azure.storage.blob import BlobServiceClient
from google.cloud import storage
from pymongo import MongoClient
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from configparser import ConfigParser
from flask import Flask, request
import json
import keyring
import hashlib
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from google.oauth2 import service_account
import base64

# True Positive Examples (Vulnerable Code)

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_1():
    """Database connection with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
    connection = pymysql.connect(
        host='database.example.com',
        user='admin',
        password='super_secret_password123',
        db='customer_data'
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_2():
    """AWS S3 access with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
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
    """API authentication with hardcoded token"""
    # ruleid: python-hardcoded-credentials-ide
    api_key = "sk_test_PLACEHOLDER_KEY"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get("https://api.stripe.com/v1/charges", headers=headers)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_4():
    """SMTP configuration with hardcoded password"""
    # ruleid: python-hardcoded-credentials-ide
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('company@gmail.com', 'email_password_2023!')
    server.sendmail('company@gmail.com', 'recipient@example.com', 'Email content')
    server.quit()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_5():
    """SSH connection with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('server.example.com', username='admin', password='secure_ssh_pwd!')
    stdin, stdout, stderr = client.exec_command('ls -la')
    return stdout.read()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_6():
    """Firebase configuration with hardcoded API key"""
    # ruleid: python-hardcoded-credentials-ide
    config = {
        "apiKey": "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",
        "authDomain": "myapp-project-123.firebaseapp.com",
        "databaseURL": "https://myapp-project-123.firebaseio.com",
        "projectId": "myapp-project-123",
        "storageBucket": "myapp-project-123.appspot.com",
        "messagingSenderId": "65211879809",
        "appId": "1:65211879909:web:3ae38ef1cdcb2e01fe5f0c"
    }
    firebase_admin.initialize_app(config)
    return "Firebase initialized"

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_7():
    """MongoDB connection with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
    client = MongoClient(
        "mongodb+srv://admin:mongodb_password_2023@cluster0.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
    )
    db = client.test_database
    collection = db.test_collection
    return collection.find_one()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_8():
    """Azure Blob Storage with hardcoded connection string"""
    # ruleid: python-hardcoded-credentials-ide
    connection_string = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY==;EndpointSuffix=core.windows.net"
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("mycontainer")
    return list(container_client.list_blobs())

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_9():
    """Elasticsearch connection with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
    es = Elasticsearch(
        ['https://elastic.example.com:9200'],
        http_auth=('elastic', 'changeme123!')
    )
    return es.info()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_10():
    """Redis connection with hardcoded password"""
    # ruleid: python-hardcoded-credentials-ide
    r = redis.Redis(
        host='redis.example.com',
        port=6379,
        password='redis_strong_password',
        db=0
    )
    r.set('key', 'value')
    return r.get('key')

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_11():
    """Google Cloud Storage with hardcoded service account key"""
    # ruleid: python-hardcoded-credentials-ide
    service_account_info = {
        "type": "service_account",
        "project_id": "my-project",
        "private_key_id": "1234567890abcdef",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----\n",
        "client_email": "my-service-account@my-project.iam.gserviceaccount.com",
        "client_id": "123456789012345678901",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/my-service-account%40my-project.iam.gserviceaccount.com"
    }
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    client = storage.Client(credentials=credentials)
    return list(client.list_buckets())

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_12():
    """Flask app with hardcoded secret key"""
    # ruleid: python-hardcoded-credentials-ide
    app = Flask(__name__)
    app.secret_key = 'a_very_secret_key_that_should_not_be_hardcoded'
    
    @app.route('/')
    def index():
        return 'Hello World!'
    
    return app

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_13():
    """Encryption with hardcoded key"""
    # ruleid: python-hardcoded-credentials-ide
    key = b'TluxwB3fV_GWuLkR1_BzGs1Zk90TYAuhNMZP_0q4WyM='
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(b"A really secret message.")
    return cipher_text

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_14():
    """OAuth2 client with hardcoded credentials"""
    # ruleid: python-hardcoded-credentials-ide
    client_id = "3MVG9lKcPoNINVBIPJjdw1J68RvMFbvMQsWqyY9RvpQB9rHcUcs_jtGcWH1glgFp"
    client_secret = "9205371918321623741"
    
    auth_url = "https://login.salesforce.com/services/oauth2/token"
    params = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    response = requests.post(auth_url, data=params)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_15():
    """Configuration file with hardcoded database credentials"""
    # ruleid: python-hardcoded-credentials-ide
    config = ConfigParser()
    config['DATABASE'] = {
        'host': 'localhost',
        'database': 'mydatabase',
        'user': 'dbadmin',
        'password': 'supersecretdbpassword'
    }
    with open('config.ini', 'w') as f:
        config.write(f)
    return "Config file created"

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_1():
    """Database connection with credentials from environment variables"""
    # ok: python-hardcoded-credentials-ide
    connection = pymysql.connect(
        host=os.environ.get('DB_HOST'),
        user=os.environ.get('DB_USER'),
        password=os.environ.get('DB_PASSWORD'),
        db=os.environ.get('DB_NAME')
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_2():
    """AWS S3 access using boto3 default credential provider chain"""
    # ok: python-hardcoded-credentials-ide
    s3_client = boto3.client('s3')  # Uses AWS credential provider chain
    response = s3_client.list_buckets()
    return response['Buckets']

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_3():
    """API authentication with token from environment variable"""
    # ok: python-hardcoded-credentials-ide
    api_key = os.environ.get('API_KEY')
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get("https://api.stripe.com/v1/charges", headers=headers)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_4():
    """SMTP configuration with password from environment variable"""
    # ok: python-hardcoded-credentials-ide
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    email = os.environ.get('EMAIL_USER')
    password = os.environ.get('EMAIL_PASSWORD')
    server.login(email, password)
    server.sendmail(email, 'recipient@example.com', 'Email content')
    server.quit()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_5():
    """SSH connection with credentials from environment variables"""
    # ok: python-hardcoded-credentials-ide
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        os.environ.get('SSH_HOST'),
        username=os.environ.get('SSH_USER'),
        password=os.environ.get('SSH_PASSWORD')
    )
    stdin, stdout, stderr = client.exec_command('ls -la')
    return stdout.read()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_6():
    """Firebase configuration with API key from environment variable"""
    # ok: python-hardcoded-credentials-ide
    config = {
        "apiKey": os.environ.get('FIREBASE_API_KEY'),
        "authDomain": os.environ.get('FIREBASE_AUTH_DOMAIN'),
        "databaseURL": os.environ.get('FIREBASE_DB_URL'),
        "projectId": os.environ.get('FIREBASE_PROJECT_ID'),
        "storageBucket": os.environ.get('FIREBASE_STORAGE_BUCKET'),
        "messagingSenderId": os.environ.get('FIREBASE_MESSAGING_SENDER_ID'),
        "appId": os.environ.get('FIREBASE_APP_ID')
    }
    firebase_admin.initialize_app(config)
    return "Firebase initialized"

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_7():
    """MongoDB connection with credentials from environment variables"""
    # ok: python-hardcoded-credentials-ide
    username = os.environ.get('MONGO_USER')
    password = os.environ.get('MONGO_PASSWORD')
    host = os.environ.get('MONGO_HOST')
    client = MongoClient(f"mongodb+srv://{username}:{password}@{host}/myFirstDatabase?retryWrites=true&w=majority")
    db = client.test_database
    collection = db.test_collection
    return collection.find_one()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_8():
    """Azure Blob Storage with connection string from environment variable"""
    # ok: python-hardcoded-credentials-ide
    connection_string = os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_client = blob_service_client.get_container_client("mycontainer")
    return list(container_client.list_blobs())

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_9():
    """Elasticsearch connection with credentials from environment variables"""
    # ok: python-hardcoded-credentials-ide
    es = Elasticsearch(
        [os.environ.get('ES_HOST')],
        http_auth=(os.environ.get('ES_USER'), os.environ.get('ES_PASSWORD'))
    )
    return es.info()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_10():
    """Redis connection with password from environment variable"""
    # ok: python-hardcoded-credentials-ide
    r = redis.Redis(
        host=os.environ.get('REDIS_HOST'),
        port=int(os.environ.get('REDIS_PORT', 6379)),
        password=os.environ.get('REDIS_PASSWORD'),
        db=int(os.environ.get('REDIS_DB', 0))
    )
    r.set('key', 'value')
    return r.get('key')

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_11():
    """Google Cloud Storage using application default credentials"""
    # ok: python-hardcoded-credentials-ide
    # Assumes GOOGLE_APPLICATION_CREDENTIALS environment variable is set
    client = storage.Client()
    return list(client.list_buckets())

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_12():
    """Flask app with secret key from environment variable"""
    # ok: python-hardcoded-credentials-ide
    app = Flask(__name__)
    app.secret_key = os.environ.get('FLASK_SECRET_KEY')
    
    @app.route('/')
    def index():
        return 'Hello World!'
    
    return app

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_13():
    """Encryption with key from environment variable"""
    # ok: python-hardcoded-credentials-ide
    key = os.environ.get('ENCRYPTION_KEY')
    key_bytes = base64.b64decode(key)
    cipher_suite = Fernet(key_bytes)
    cipher_text = cipher_suite.encrypt(b"A really secret message.")
    return cipher_text

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_14():
    """OAuth2 client with credentials from environment variables"""
    # ok: python-hardcoded-credentials-ide
    client_id = os.environ.get('OAUTH_CLIENT_ID')
    client_secret = os.environ.get('OAUTH_CLIENT_SECRET')
    
    auth_url = "https://login.salesforce.com/services/oauth2/token"
    params = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret
    }
    response = requests.post(auth_url, data=params)
    return response.json()

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_15():
    """Using Azure Key Vault to retrieve secrets"""
    # ok: python-hardcoded-credentials-ide
    key_vault_name = os.environ.get("KEY_VAULT_NAME")
    key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
    
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_uri, credential=credential)
    
    db_username = client.get_secret("db-username").value
    db_password = client.get_secret("db-password").value
    
    connection = pymysql.connect(
        host=client.get_secret("db-host").value,
        user=db_username,
        password=db_password,
        db=client.get_secret("db-name").value
    )
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
# {/fact}