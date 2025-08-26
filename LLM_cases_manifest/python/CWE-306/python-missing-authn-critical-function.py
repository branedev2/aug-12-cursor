# Examples for python-missing-authn-critical-function (CWE-306)
# This rule detects when critical functions lack proper authentication checks

import os
import sqlite3
import hashlib
import boto3
import requests
from flask import Flask, request, session, redirect, url_for, jsonify
from functools import wraps
from werkzeug.security import check_password_hash
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# ======= TRUE POSITIVES (Vulnerable Code) =======

# Case 1: API endpoint exposing sensitive user data without authentication
app = Flask(__name__)

@app.route('/api/user/<user_id>', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(user_id):
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    conn.close()
    return jsonify({"user": user_data})

# Case 2: Admin function without authentication check
# {/fact}

@app.route('/admin/delete_user', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2():
    user_id = request.form.get('user_id')
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# Case 3: Password reset without verifying identity
# {/fact}

@app.route('/reset_password', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    cursor.execute(f"UPDATE users SET password = '{hashed_password}' WHERE username = '{username}'")
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})

# Case 4: Django view exposing sensitive data without authentication
# {/fact}

@require_http_methods(["GET"])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(request, user_id):
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    conn.close()
    return JsonResponse({"user": user_data})

# Case 5: API for file access without authentication
# {/fact}

@app.route('/api/get_file', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5():
    filename = request.args.get('filename')
    # ruleid: python-missing-authn-critical-function
    with open(f"sensitive_files/{filename}", 'r') as file:
        content = file.read()
    return jsonify({"content": content})

# Case 6: FastAPI endpoint for payment processing without authentication
# {/fact}

fastapi_app = FastAPI()

@fastapi_app.post("/process_payment")
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(amount: float, account_id: str):
    # ruleid: python-missing-authn-critical-function
    # Process payment without authentication
    payment_result = process_payment_function(amount, account_id)
    return {"status": "payment processed", "result": payment_result}

# {/fact}

def process_payment_function(amount, account_id):
    # Simulate payment processing
    return {"transaction_id": "12345", "amount": amount, "account": account_id}

# Case 7: AWS resource access without authentication
@app.route('/aws/s3_files', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7():
    bucket_name = request.args.get('bucket')
    # ruleid: python-missing-authn-critical-function
    s3_client = boto3.client('s3')
    response = s3_client.list_objects_v2(Bucket=bucket_name)
    files = [obj['Key'] for obj in response.get('Contents', [])]
    return jsonify({"files": files})

# Case 8: User settings modification without authentication
# {/fact}

@app.route('/api/update_settings', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8():
    user_id = request.form.get('user_id')
    settings = request.form.get('settings')
    
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"UPDATE user_settings SET settings = '{settings}' WHERE user_id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "settings updated"})

# Case 9: External API call with sensitive operation without authentication
# {/fact}

@app.route('/api/send_message', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9():
    recipient = request.form.get('recipient')
    message = request.form.get('message')
    
    # ruleid: python-missing-authn-critical-function
    # Send message to external API without authentication check
    response = requests.post(
        'https://api.messaging.com/send',
        json={'recipient': recipient, 'message': message, 'api_key': 'secret_key'}
    )
    return jsonify({"status": response.json()})

# Case 10: Database backup function without authentication
# {/fact}

@app.route('/admin/backup_db', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10():
    backup_name = request.form.get('backup_name')
    
    # ruleid: python-missing-authn-critical-function
    conn = sqlite3.connect('users.db')
    with open(f"backups/{backup_name}.sql", 'w') as f:
        for line in conn.iterdump():
            f.write(f"{line}\n")
    conn.close()
    return jsonify({"status": "backup created"})

# Case 11: User impersonation without authentication
# {/fact}

@app.route('/api/act_as_user', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11():
    target_user_id = request.form.get('user_id')
    action = request.form.get('action')
    
    # ruleid: python-missing-authn-critical-function
    # Perform action as the specified user without authentication
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {target_user_id}")
    user_data = cursor.fetchone()
    
    # Perform action as user
    result = perform_user_action(user_data, action)
    conn.close()
    return jsonify({"result": result})

# {/fact}

def perform_user_action(user_data, action):
    # Simulate performing an action as a user
    return f"Action {action} performed for user {user_data[0]}"

# Case 12: System configuration change without authentication
@app.route('/system/update_config', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12():
    config_key = request.form.get('key')
    config_value = request.form.get('value')
    
    # ruleid: python-missing-authn-critical-function
    # Update system configuration without authentication
    with open('system_config.ini', 'a') as config_file:
        config_file.write(f"{config_key}={config_value}\n")
    
    return jsonify({"status": "configuration updated"})

# Case 13: Log access without authentication
# {/fact}

@app.route('/logs/view', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13():
    log_date = request.args.get('date')
    
    # ruleid: python-missing-authn-critical-function
    # Access logs without authentication
    log_path = f"logs/system_{log_date}.log"
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            log_content = log_file.read()
        return jsonify({"logs": log_content})
    else:
        return jsonify({"error": "Log file not found"}), 404

# Case 14: User data export without authentication
# {/fact}

@app.route('/api/export_user_data', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14():
    user_id = request.args.get('user_id')
    
    # ruleid: python-missing-authn-critical-function
    # Export user data without authentication
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    cursor.execute(f"SELECT * FROM user_activity WHERE user_id = {user_id}")
    activity_data = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "user": user_data,
        "activity": activity_data
    })

# Case 15: API to run system commands without authentication
# {/fact}

@app.route('/system/run_command', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15():
    command = request.form.get('command')
    
    # ruleid: python-missing-authn-critical-function
    # Execute system command without authentication
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })

# ======= TRUE NEGATIVES (Secure Code) =======

# Case 1: API endpoint with proper authentication check
# {/fact}

@app.route('/api/user/<user_id>', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(user_id):
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    conn.close()
    return jsonify({"user": user_data})

# Case 2: Admin function with authentication and authorization check
# {/fact}

@app.route('/admin/delete_user', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    user_id = request.form.get('user_id')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

# Case 3: Password reset with proper authentication
# {/fact}

@app.route('/reset_password', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    
    # Verify current user can only change their own password
    if username != session.get('username'):
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    cursor.execute(f"UPDATE users SET password = '{hashed_password}' WHERE username = '{username}'")
    conn.commit()
    conn.close()
    return jsonify({"status": "password updated"})

# Case 4: Authentication decorator for Django views
# {/fact}

def require_auth(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponse('Unauthorized', status=401)
        return view_func(request, *args, **kwargs)
    return wrapped_view

@require_http_methods(["GET"])
@require_auth
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(request, user_id):
    # ok: python-missing-authn-critical-function
    # Authentication is handled by the decorator
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    conn.close()
    return JsonResponse({"user": user_data})

# Case 5: File access with authentication
# {/fact}

@app.route('/api/get_file', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return jsonify({"error": "Authentication required"}), 401
    
    filename = request.args.get('filename')
    with open(f"sensitive_files/{filename}", 'r') as file:
        content = file.read()
    return jsonify({"content": content})

# Case 6: FastAPI endpoint with OAuth2 authentication
# {/fact}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    # Validate token and get user
    user = validate_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def validate_token(token):
    # Simulate token validation
    if token == "valid_token":
        return {"username": "testuser"}
    return None

@fastapi_app.post("/process_payment")
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(amount: float, account_id: str, current_user: dict = Depends(get_current_user)):
    # ok: python-missing-authn-critical-function
    # Authentication is handled by the dependency
    payment_result = process_payment_function(amount, account_id)
    return {"status": "payment processed", "result": payment_result, "user": current_user["username"]}

# Case 7: AWS resource access with authentication
# {/fact}

@app.route('/aws/s3_files', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return jsonify({"error": "Authentication required"}), 401
    
    if not session.get('has_s3_access'):
        return jsonify({"error": "Unauthorized access to S3"}), 403
    
    bucket_name = request.args.get('bucket')
    s3_client = boto3.client('s3')
    response = s3_client.list_objects_v2(Bucket=bucket_name)
    files = [obj['Key'] for obj in response.get('Contents', [])]
    return jsonify({"files": files})

# Case 8: User settings with authentication check
# {/fact}

@app.route('/api/update_settings', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = request.form.get('user_id')
    
    # Ensure users can only modify their own settings
    if str(user_id) != str(session.get('user_id')):
        return jsonify({"error": "Unauthorized"}), 403
    
    settings = request.form.get('settings')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"UPDATE user_settings SET settings = '{settings}' WHERE user_id = {user_id}")
    conn.commit()
    conn.close()
    return jsonify({"status": "settings updated"})

# Case 9: External API call with authentication check
# {/fact}

@app.route('/api/send_message', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return jsonify({"error": "Authentication required"}), 401
    
    recipient = request.form.get('recipient')
    message = request.form.get('message')
    
    # Send message to external API with authentication check
    response = requests.post(
        'https://api.messaging.com/send',
        json={'recipient': recipient, 'message': message, 'api_key': 'secret_key'}
    )
    return jsonify({"status": response.json()})

# Case 10: Database backup with admin authentication
# {/fact}

@app.route('/admin/backup_db', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Admin authentication required"}), 403
    
    backup_name = request.form.get('backup_name')
    conn = sqlite3.connect('users.db')
    with open(f"backups/{backup_name}.sql", 'w') as f:
        for line in conn.iterdump():
            f.write(f"{line}\n")
    conn.close()
    return jsonify({"status": "backup created"})

# Case 11: User impersonation with proper authentication and authorization
# {/fact}

@app.route('/api/act_as_user', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Admin authentication required"}), 403
    
    target_user_id = request.form.get('user_id')
    action = request.form.get('action')
    
    # Log the impersonation for audit purposes
    log_impersonation(session.get('user_id'), target_user_id, action)
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {target_user_id}")
    user_data = cursor.fetchone()
    
    # Perform action as user
    result = perform_user_action(user_data, action)
    conn.close()
    return jsonify({"result": result})

# {/fact}

def log_impersonation(admin_id, target_id, action):
    # Log impersonation for audit
    with open('audit_log.txt', 'a') as log:
        log.write(f"Admin {admin_id} impersonated user {target_id} to perform {action}\n")

# Case 12: System configuration with admin authentication
@app.route('/system/update_config', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Admin authentication required"}), 403
    
    config_key = request.form.get('key')
    config_value = request.form.get('value')
    
    # Update system configuration with authentication
    with open('system_config.ini', 'a') as config_file:
        config_file.write(f"{config_key}={config_value}\n")
    
    return jsonify({"status": "configuration updated"})

# Case 13: Log access with authentication
# {/fact}

@app.route('/logs/view', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Admin authentication required"}), 403
    
    log_date = request.args.get('date')
    log_path = f"logs/system_{log_date}.log"
    
    if os.path.exists(log_path):
        with open(log_path, 'r') as log_file:
            log_content = log_file.read()
        return jsonify({"logs": log_content})
    else:
        return jsonify({"error": "Log file not found"}), 404

# Case 14: User data export with authentication and authorization
# {/fact}

@app.route('/api/export_user_data', methods=['GET'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in'):
        return jsonify({"error": "Authentication required"}), 401
    
    user_id = request.args.get('user_id')
    
    # Ensure users can only export their own data unless they're an admin
    if str(user_id) != str(session.get('user_id')) and not session.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 403
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    user_data = cursor.fetchone()
    cursor.execute(f"SELECT * FROM user_activity WHERE user_id = {user_id}")
    activity_data = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "user": user_data,
        "activity": activity_data
    })

# Case 15: System command execution with authentication and authorization
# {/fact}

@app.route('/system/run_command', methods=['POST'])
# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15():
    # ok: python-missing-authn-critical-function
    if not session.get('logged_in') or not session.get('is_admin'):
        return jsonify({"error": "Admin authentication required"}), 403
    
    # Additional security check for system commands
    if not session.get('can_execute_commands'):
        return jsonify({"error": "Not authorized to execute system commands"}), 403
    
    command = request.form.get('command')
    
    # Log command execution for audit
    with open('command_audit.log', 'a') as audit_log:
        audit_log.write(f"User {session.get('user_id')} executed: {command}\n")
    
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })

# {/fact}

if __name__ == '__main__':
    app.secret_key = os.urandom(24)
    app.run(debug=True)