import flask
from flask import Flask, request, session, redirect, url_for
import django
from django.http import HttpRequest, HttpResponse
from django.contrib.auth.decorators import login_required
import fastapi
from fastapi import FastAPI, Header, Cookie, Depends, HTTPException
from typing import Optional, Dict, List
import os
import requests
import json
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
fastapi_app = FastAPI()

# True Positive Examples (Vulnerable Code)

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_1():
    # Using client-controlled cookie for role determination
    @app.route('/admin_dashboard')
    def admin_dashboard():
        # ruleid: python-incorrect-authorization
        user_role = request.cookies.get('user_role')
        
        if user_role == 'admin':
            return "Admin Dashboard Content"
        else:
            return "Access Denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_2():
    # Using URL parameter for authorization
    @app.route('/view_report/<report_id>')
    def view_report(report_id):
        # ruleid: python-incorrect-authorization
        access_level = request.args.get('access_level')
        
        if access_level == 'confidential':
            return f"Confidential Report {report_id}"
        else:
            return "Standard Report Content"

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_3():
    # Using header for role verification
    @app.route('/api/users')
    def get_all_users():
        # ruleid: python-incorrect-authorization
        role = request.headers.get('X-User-Role')
        
        if role == 'admin':
            return json.dumps({"users": ["user1", "user2", "user3"]})
        else:
            return json.dumps({"error": "Unauthorized"}), 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_4():
    # Using POST data for permission check
    @app.route('/update_settings', methods=['POST'])
    def update_settings():
        # ruleid: python-incorrect-authorization
        is_admin = request.form.get('is_admin')
        
        if is_admin == 'true':
            return "Settings updated successfully"
        else:
            return "Permission denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_5():
    # Using client-side JWT without verification
    @app.route('/api/sensitive_data')
    def get_sensitive_data():
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return "No token provided", 401
        
        token = auth_header.split(' ')[1]
        # Decode without verification
        import base64
        import json
        
        # ruleid: python-incorrect-authorization
        payload = json.loads(base64.b64decode(token.split('.')[1] + '==').decode('utf-8'))
        
        if payload.get('role') == 'admin':
            return "Sensitive data here"
        return "Access denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_6():
    # FastAPI example using query parameter for role
    @fastapi_app.get("/admin/settings")
    async def admin_settings(role: str = None):
        # ruleid: python-incorrect-authorization
        if role == "admin":
            return {"message": "Admin settings page"}
        return {"error": "Access denied"}

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_7():
    # Using Django with request parameter for authorization
    def user_profile(request, user_id):
        # ruleid: python-incorrect-authorization
        is_admin = request.GET.get('is_admin', 'false')
        
        if is_admin.lower() == 'true':
            # Admin can view any profile
            return HttpResponse(f"User profile for {user_id}")
        else:
            # Regular users can only view their own profile
            if str(request.user.id) != user_id:
                return HttpResponse("Access denied", status=403)
            return HttpResponse(f"Your profile: {user_id}")

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_8():
    # Using JSON body data for permission check
    @app.route('/api/delete_user', methods=['DELETE'])
    def delete_user():
        data = request.get_json()
        user_id = data.get('user_id')
        
        # ruleid: python-incorrect-authorization
        requester_permissions = data.get('permissions', [])
        
        if 'delete_users' in requester_permissions:
            return f"User {user_id} deleted"
        else:
            return "Permission denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_9():
    # Using client-provided token without server validation
    @app.route('/api/reports')
    def get_reports():
        # ruleid: python-incorrect-authorization
        auth_token = request.args.get('auth_token')
        
        if auth_token and auth_token.startswith('admin_'):
            return json.dumps({"reports": ["report1", "report2"]})
        else:
            return json.dumps({"reports": ["report1"]}), 200

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_10():
    # Using a hidden form field for authorization
    @app.route('/process_payment', methods=['POST'])
    def process_payment():
        # ruleid: python-incorrect-authorization
        user_type = request.form.get('user_type')
        
        if user_type == 'premium':
            discount = 0.2  # 20% discount for premium users
        else:
            discount = 0
            
        amount = float(request.form.get('amount', 0))
        final_amount = amount * (1 - discount)
        
        return f"Processing payment of ${final_amount}"

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_11():
    # Using client-side state for authorization in FastAPI
    @fastapi_app.post("/api/update_account")
    async def update_account(user_data: Dict, user_state: Optional[str] = Cookie(None)):
        # ruleid: python-incorrect-authorization
        state_data = json.loads(user_state) if user_state else {}
        
        if state_data.get('is_admin', False):
            return {"status": "Account updated with admin privileges"}
        else:
            return {"status": "Account updated with limited privileges"}

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_12():
    # Using referer header for authorization
    @app.route('/internal_api')
    def internal_api():
        # ruleid: python-incorrect-authorization
        referer = request.headers.get('Referer', '')
        
        if 'admin.example.com' in referer:
            return json.dumps({"internal_data": "sensitive information"})
        else:
            return json.dumps({"error": "Unauthorized access"}), 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_13():
    # Using client IP for authorization without verification
    @app.route('/admin_functions')
    def admin_functions():
        # ruleid: python-incorrect-authorization
        client_ip = request.remote_addr
        
        trusted_ips = ['192.168.1.1', '10.0.0.1']
        if client_ip in trusted_ips:
            return "Admin functions available"
        else:
            return "Access denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_14():
    # Using user-agent for authorization
    @app.route('/api/debug')
    def debug_info():
        # ruleid: python-incorrect-authorization
        user_agent = request.headers.get('User-Agent', '')
        
        if 'AdminClient' in user_agent:
            return json.dumps({"debug": "Full system information", "logs": "Complete logs"})
        else:
            return json.dumps({"debug": "Limited information"}), 200

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_15():
    # Using custom header for feature flag/authorization
    @app.route('/beta_features')
    def beta_features():
        # ruleid: python-incorrect-authorization
        access_tier = request.headers.get('X-Access-Tier', 'basic')
        
        if access_tier in ['premium', 'enterprise']:
            return json.dumps({"features": ["feature1", "feature2", "feature3", "beta1", "beta2"]})
        else:
            return json.dumps({"features": ["feature1", "feature2"]}), 200


# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_1():
    # Using server-side session for role determination
    @app.route('/admin_dashboard')
    def admin_dashboard():
        # ok: python-incorrect-authorization
        if 'user_role' in session and session['user_role'] == 'admin':
            return "Admin Dashboard Content"
        else:
            return "Access Denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_2():
    # Using server-side authentication decorator
    @app.route('/view_report/<report_id>')
    @login_required
    def view_report(report_id):
        # ok: python-incorrect-authorization
        if current_user.has_permission('view_confidential_reports'):
            return f"Confidential Report {report_id}"
        else:
            return "Standard Report Content"

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_3():
    # Using database lookup for role verification
    @app.route('/api/users')
    def get_all_users():
        if not request.headers.get('Authorization'):
            return json.dumps({"error": "No token provided"}), 401
            
        token = request.headers.get('Authorization').split(' ')[1]
        
        # ok: python-incorrect-authorization
        user = db.users.find_one({"token": token})
        if user and user.get('role') == 'admin':
            return json.dumps({"users": ["user1", "user2", "user3"]})
        else:
            return json.dumps({"error": "Unauthorized"}), 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_4():
    # Using server-side session for permission check
    @app.route('/update_settings', methods=['POST'])
    def update_settings():
        # ok: python-incorrect-authorization
        if 'user_id' in session and is_admin_user(session['user_id']):
            # Update settings logic
            return "Settings updated successfully"
        else:
            return "Permission denied", 403
            
    def is_admin_user(user_id):
        # Check in database if user is admin
        return db.users.find_one({"_id": user_id, "role": "admin"}) is not None

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_5():
    # Using proper JWT verification
    @app.route('/api/sensitive_data')
    def get_sensitive_data():
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return "No token provided", 401
        
        token = auth_header.split(' ')[1]
        
        try:
            # ok: python-incorrect-authorization
            import jwt
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            
            if payload.get('role') == 'admin':
                return "Sensitive data here"
            return "Access denied", 403
        except jwt.InvalidTokenError:
            return "Invalid token", 401

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_6():
    # FastAPI example using proper dependency injection for auth
    def get_current_user(token: str = Header(...)):
        try:
            import jwt
            payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
            return payload
        except:
            raise HTTPException(status_code=401, detail="Invalid token")

    @fastapi_app.get("/admin/settings")
    async def admin_settings(current_user: dict = Depends(get_current_user)):
        # ok: python-incorrect-authorization
        if current_user.get("role") == "admin":
            return {"message": "Admin settings page"}
        raise HTTPException(status_code=403, detail="Access denied")

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_7():
    # Using Django with proper authentication decorator
    @login_required
    def user_profile(request, user_id):
        # ok: python-incorrect-authorization
        if request.user.is_staff or str(request.user.id) == user_id:
            # Admin can view any profile, users can view their own
            return HttpResponse(f"User profile for {user_id}")
        else:
            return HttpResponse("Access denied", status=403)

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_8():
    # Using server-side permission check
    @app.route('/api/delete_user', methods=['DELETE'])
    def delete_user():
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not request.headers.get('Authorization'):
            return "No token provided", 401
            
        token = request.headers.get('Authorization').split(' ')[1]
        
        # ok: python-incorrect-authorization
        requester = db.users.find_one({"token": token})
        if requester and requester.get('permissions', []).includes('delete_users'):
            return f"User {user_id} deleted"
        else:
            return "Permission denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_9():
    # Using proper session-based authentication
    @app.route('/api/reports')
    def get_reports():
        # ok: python-incorrect-authorization
        if 'user_id' in session:
            user = db.users.find_one({"_id": session['user_id']})
            
            if user and user.get('role') == 'admin':
                return json.dumps({"reports": ["report1", "report2"]})
            else:
                return json.dumps({"reports": ["report1"]}), 200
        else:
            return json.dumps({"error": "Not logged in"}), 401

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_10():
    # Using proper role-based access control
    @app.route('/process_payment', methods=['POST'])
    def process_payment():
        if 'user_id' not in session:
            return "Not logged in", 401
            
        # ok: python-incorrect-authorization
        user = db.users.find_one({"_id": session['user_id']})
        
        if user and user.get('account_type') == 'premium':
            discount = 0.2  # 20% discount for premium users
        else:
            discount = 0
            
        amount = float(request.form.get('amount', 0))
        final_amount = amount * (1 - discount)
        
        return f"Processing payment of ${final_amount}"

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_11():
    # Using proper authentication middleware in FastAPI
    def verify_token(token: str = Header(...)):
        try:
            import jwt
            payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
            return payload
        except:
            raise HTTPException(status_code=401, detail="Invalid authentication")

    @fastapi_app.post("/api/update_account")
    async def update_account(user_data: Dict, current_user: dict = Depends(verify_token)):
        # ok: python-incorrect-authorization
        if current_user.get('is_admin', False):
            return {"status": "Account updated with admin privileges"}
        else:
            return {"status": "Account updated with limited privileges"}

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_12():
    # Using proper authentication for internal API
    @app.route('/internal_api')
    def internal_api():
        if 'user_id' not in session:
            return json.dumps({"error": "Not authenticated"}), 401
            
        # ok: python-incorrect-authorization
        user = db.users.find_one({"_id": session['user_id']})
        
        if user and user.get('role') == 'internal':
            return json.dumps({"internal_data": "sensitive information"})
        else:
            return json.dumps({"error": "Unauthorized access"}), 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_13():
    # Using proper authentication and IP verification
    @app.route('/admin_functions')
    def admin_functions():
        if 'user_id' not in session:
            return "Not logged in", 401
            
        # ok: python-incorrect-authorization
        user = db.users.find_one({"_id": session['user_id']})
        
        if user and user.get('role') == 'admin':
            # Additional IP check for extra security, but not the primary auth mechanism
            client_ip = request.remote_addr
            trusted_ips = ['192.168.1.1', '10.0.0.1']
            
            if client_ip not in trusted_ips:
                log_suspicious_access(user['_id'], client_ip)
                
            return "Admin functions available"
        else:
            return "Access denied", 403

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_14():
    # Using proper authentication for debug info
    @app.route('/api/debug')
    def debug_info():
        if 'user_id' not in session:
            return json.dumps({"error": "Not authenticated"}), 401
            
        # ok: python-incorrect-authorization
        user = db.users.find_one({"_id": session['user_id']})
        
        if user and user.get('role') in ['admin', 'developer']:
            return json.dumps({"debug": "Full system information", "logs": "Complete logs"})
        else:
            return json.dumps({"debug": "Limited information"}), 200

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_15():
    # Using proper feature flag system
    @app.route('/beta_features')
    def beta_features():
        if 'user_id' not in session:
            return json.dumps({"error": "Not authenticated"}), 401
            
        # ok: python-incorrect-authorization
        user = db.users.find_one({"_id": session['user_id']})
        
        if user and user.get('subscription_tier') in ['premium', 'enterprise']:
            return json.dumps({"features": ["feature1", "feature2", "feature3", "beta1", "beta2"]})
        else:
            return json.dumps({"features": ["feature1", "feature2"]}), 200
# {/fact}