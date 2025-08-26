import logging
import re
import os
import flask
from flask import Flask, request, session
import fastapi
from fastapi import FastAPI, Header, Request
import tornado.web
import django
from django.http import HttpRequest, HttpResponse
import cherrypy
import bottle
from bottle import route, request as bottle_request
import pyramid
from pyramid.request import Request as PyramidRequest
from pyramid.response import Response as PyramidResponse
import werkzeug
from werkzeug.wrappers import Request as WerkzeugRequest
import aiohttp
from aiohttp import web
import html

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
fastapi_app = FastAPI()

# True Positive Examples (Vulnerable Code)

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_1():
    # Flask example with direct logging of user input
    @app.route('/login')
    def login():
        username = request.args.get('username')
        # ruleid: python-log-injection-ide
        logger.info("User login attempt: " + username)
        return "Login attempt logged"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_2():
    # FastAPI example with f-string interpolation
    @fastapi_app.get("/profile")
    async def profile(user_id: str):
        # ruleid: python-log-injection-ide
        logger.info(f"Profile accessed by user: {user_id}")
        return {"message": "Profile accessed"}

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_3():
    # Django example with format method
    def user_action(request):
        action = request.GET.get('action', '')
        # ruleid: python-log-injection-ide
        logger.warning("User performed action: {}".format(action))
        return HttpResponse("Action logged")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_4():
    # Tornado example with multiple inputs
    class ProfileHandler(tornado.web.RequestHandler):
        def get(self):
            user_id = self.get_argument("user_id")
            section = self.get_argument("section")
            # ruleid: python-log-injection-ide
            logging.error("Error in section %s for user %s" % (section, user_id))
            self.write("Error logged")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_5():
    # Bottle example with header logging
    @route('/api/data')
    def api_data():
        auth_token = bottle_request.headers.get('Authorization')
        # ruleid: python-log-injection-ide
        logger.info("API accessed with token: " + auth_token)
        return "API access logged"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_6():
    # Pyramid example with POST data
    def submit_form(request: PyramidRequest):
        form_data = request.POST.get('comments')
        # ruleid: python-log-injection-ide
        logging.warning("Form submission with comments: " + form_data)
        return PyramidResponse("Form processed")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_7():
    # Flask example with cookie data
    @app.route('/dashboard')
    def dashboard():
        user_theme = request.cookies.get('theme')
        # ruleid: python-log-injection-ide
        logger.info(f"Dashboard accessed with theme: {user_theme}")
        return "Dashboard loaded"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_8():
    # Werkzeug example with direct string concatenation
    def process_request(request: WerkzeugRequest):
        query = request.args.get('search')
        # ruleid: python-log-injection-ide
        logging.info("Search query: " + query)
        return "Search processed"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_9():
    # AIOHTTP example with multiple parameters
    async def handle_request(request):
        name = request.query.get('name')
        age = request.query.get('age')
        # ruleid: python-log-injection-ide
        logger.info(f"New user registration: {name}, age {age}")
        return web.Response(text="Registration logged")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_10():
    # Flask example with JSON data
    @app.route('/api/submit', methods=['POST'])
    def submit_api():
        data = request.json
        # ruleid: python-log-injection-ide
        logger.info("API submission: {}".format(data['message']))
        return "API submission logged"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_11():
    # CherryPy example with query parameters
    @cherrypy.expose
    def search(query=None):
        # ruleid: python-log-injection-ide
        logging.info("Search performed with query: " + query)
        return "Search logged"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_12():
    # Django example with session data
    def user_session(request):
        session_id = request.session.session_key
        # ruleid: python-log-injection-ide
        logger.warning("Session activity: %s" % session_id)
        return HttpResponse("Session logged")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_13():
    # FastAPI example with headers
    @fastapi_app.get("/api/check")
    async def check_api(user_agent: str = Header(None)):
        # ruleid: python-log-injection-ide
        logger.info("API check from user agent: " + user_agent)
        return {"status": "checked"}

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_14():
    # Flask example with form data
    @app.route('/submit', methods=['POST'])
    def submit_form():
        feedback = request.form.get('feedback')
        # ruleid: python-log-injection-ide
        logging.warning("User feedback received: {}".format(feedback))
        return "Feedback submitted"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=1}
def bad_case_15():
    # Bottle example with URL parameters
    @route('/user/<user_id>')
    def get_user(user_id):
        # ruleid: python-log-injection-ide
        logger.info(f"User profile accessed: {user_id}")
        return f"User {user_id} profile"

# True Negative Examples (Safe Code)

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_1():
    # Flask example with proper sanitization
    @app.route('/login')
    def login_safe():
        username = request.args.get('username')
        sanitized_username = re.sub(r'[\r\n]', '', username) if username else ""
        # ok: python-log-injection-ide
        logger.info("User login attempt: " + sanitized_username)
        return "Login attempt logged safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_2():
    # FastAPI example with proper encoding
    @fastapi_app.get("/profile")
    async def profile_safe(user_id: str):
        # ok: python-log-injection-ide
        logger.info(f"Profile accessed by user: {html.escape(user_id)}")
        return {"message": "Profile accessed safely"}

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_3():
    # Django example with sanitization before format
    def user_action_safe(request):
        action = request.GET.get('action', '')
        safe_action = action.replace('\n', '').replace('\r', '')
        # ok: python-log-injection-ide
        logger.warning("User performed action: {}".format(safe_action))
        return HttpResponse("Action logged safely")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_4():
    # Tornado example with proper sanitization for multiple inputs
    class ProfileHandlerSafe(tornado.web.RequestHandler):
        def get(self):
            user_id = self.get_argument("user_id")
            section = self.get_argument("section")
            safe_user_id = re.sub(r'[\r\n]', '', user_id)
            safe_section = re.sub(r'[\r\n]', '', section)
            # ok: python-log-injection-ide
            logging.error("Error in section %s for user %s" % (safe_section, safe_user_id))
            self.write("Error logged safely")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_5():
    # Bottle example with header sanitization
    @route('/api/data')
    def api_data_safe():
        auth_token = bottle_request.headers.get('Authorization', '')
        safe_token = auth_token.replace('\n', '').replace('\r', '')
        # ok: python-log-injection-ide
        logger.info("API accessed with token: " + safe_token)
        return "API access logged safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_6():
    # Pyramid example with POST data sanitization
    def submit_form_safe(request: PyramidRequest):
        form_data = request.POST.get('comments', '')
        safe_data = re.sub(r'[\r\n]', ' ', form_data)
        # ok: python-log-injection-ide
        logging.warning("Form submission with comments: " + safe_data)
        return PyramidResponse("Form processed safely")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_7():
    # Flask example with cookie data sanitization
    @app.route('/dashboard')
    def dashboard_safe():
        user_theme = request.cookies.get('theme', '')
        safe_theme = html.escape(user_theme)
        # ok: python-log-injection-ide
        logger.info(f"Dashboard accessed with theme: {safe_theme}")
        return "Dashboard loaded safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_8():
    # Werkzeug example with proper sanitization
    def process_request_safe(request: WerkzeugRequest):
        query = request.args.get('search', '')
        safe_query = query.replace('\r', '').replace('\n', '')
        # ok: python-log-injection-ide
        logging.info("Search query: " + safe_query)
        return "Search processed safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_9():
    # AIOHTTP example with sanitization for multiple parameters
    async def handle_request_safe(request):
        name = request.query.get('name', '')
        age = request.query.get('age', '')
        safe_name = re.sub(r'[\r\n]', '', name)
        safe_age = re.sub(r'[\r\n]', '', age)
        # ok: python-log-injection-ide
        logger.info(f"New user registration: {safe_name}, age {safe_age}")
        return web.Response(text="Registration logged safely")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_10():
    # Flask example with JSON data sanitization
    @app.route('/api/submit', methods=['POST'])
    def submit_api_safe():
        data = request.json
        if data and 'message' in data:
            safe_message = data['message'].replace('\n', '').replace('\r', '')
            # ok: python-log-injection-ide
            logger.info("API submission: {}".format(safe_message))
        return "API submission logged safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_11():
    # CherryPy example with query parameter sanitization
    @cherrypy.expose
    def search_safe(query=None):
        safe_query = html.escape(query) if query else ""
        # ok: python-log-injection-ide
        logging.info("Search performed with query: " + safe_query)
        return "Search logged safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_12():
    # Django example with session data validation
    def user_session_safe(request):
        session_id = request.session.session_key
        if session_id and re.match(r'^[a-zA-Z0-9]+$', session_id):
            # ok: python-log-injection-ide
            logger.warning("Session activity: %s" % session_id)
        return HttpResponse("Session logged safely")

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_13():
    # FastAPI example with headers sanitization
    @fastapi_app.get("/api/check")
    async def check_api_safe(user_agent: str = Header(None)):
        safe_agent = re.sub(r'[\r\n]', '', user_agent) if user_agent else ""
        # ok: python-log-injection-ide
        logger.info("API check from user agent: " + safe_agent)
        return {"status": "checked safely"}

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_14():
    # Flask example with form data sanitization
    @app.route('/submit', methods=['POST'])
    def submit_form_safe():
        feedback = request.form.get('feedback', '')
        safe_feedback = feedback.replace('\r', '').replace('\n', ' ')
        # ok: python-log-injection-ide
        logging.warning("User feedback received: {}".format(safe_feedback))
        return "Feedback submitted safely"

# {/fact}

# {fact rule=ldap-injection@v1.0 defects=0}
def good_case_15():
    # Bottle example with URL parameter sanitization
    @route('/user/<user_id>')
    def get_user_safe(user_id):
        safe_id = html.escape(user_id)
        # ok: python-log-injection-ide
        logger.info(f"User profile accessed: {safe_id}")
        return f"User {safe_id} profile"

# {/fact}

if __name__ == "__main__":
    app.run(debug=False)