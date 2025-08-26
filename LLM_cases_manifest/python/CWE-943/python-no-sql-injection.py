import pymongo
from pymongo import MongoClient
from bson.objectid import ObjectId
import flask
from flask import Flask, request, jsonify
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
from fastapi import FastAPI, Query
from starlette.requests import Request
import tornado.web
import tornado.ioloop
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
import motor.motor_asyncio
import asyncio
from aiohttp import web

# MongoDB Vulnerable Examples

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_1():
    """MongoDB injection via direct string interpolation in query"""
    app = Flask(__name__)
    
    @app.route('/user')
    def get_user():
        username = request.args.get('username')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.user_database
        collection = db.users
        
        # ruleid: python-no-sql-injection
        query = {'username': username}
        user = collection.find_one(query)
        
        return jsonify(user) if user else jsonify({"error": "User not found"})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_2():
    """MongoDB injection via f-string in query operator"""
    app = Flask(__name__)
    
    @app.route('/search')
    def search_products():
        search_term = request.args.get('q', '')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.product_database
        
        # ruleid: python-no-sql-injection
        query = {"$where": f"this.description.match(/{search_term}/i)"}
        results = db.products.find(query)
        
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_3():
    """MongoDB injection via JSON parsing from user input"""
    app = Flask(__name__)
    
    @app.route('/query', methods=['POST'])
    def custom_query():
        user_query = request.json.get('query', '{}')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.app_database
        
        # ruleid: python-no-sql-injection
        parsed_query = json.loads(user_query)
        results = db.collection.find(parsed_query)
        
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_4():
    """MongoDB injection via direct query object manipulation"""
    app = FastAPI()
    
    @app.get("/users/filter")
    async def filter_users(field: str = Query(...), value: str = Query(...)):
        client = motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost:27017')
        db = client.user_db
        
        # ruleid: python-no-sql-injection
        query = {field: value}
        cursor = db.users.find(query)
        
        result = []
        async for document in cursor:
            result.append(document)
        return result

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_5():
    """MongoDB injection via operator construction"""
    app = Flask(__name__)
    
    @app.route('/advanced-search')
    def advanced_search():
        field = request.args.get('field', 'name')
        operator = request.args.get('operator', '$eq')
        value = request.args.get('value', '')
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.customer_database
        
        # ruleid: python-no-sql-injection
        query = {field: {operator: value}}
        results = db.customers.find(query)
        
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_6():
    """DynamoDB injection via expression attribute construction"""
    app = Flask(__name__)
    
    @app.route('/dynamo-query')
    def query_dynamo():
        attribute = request.args.get('attribute', 'username')
        value = request.args.get('value', '')
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Users')
        
        # ruleid: python-no-sql-injection
        response = table.scan(
            FilterExpression=f"contains({attribute}, '{value}')"
        )
        
        return jsonify(response['Items'])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_7():
    """MongoDB injection in aggregation pipeline"""
    app = Flask(__name__)
    
    @app.route('/aggregate')
    def aggregate_data():
        match_field = request.args.get('field', 'category')
        match_value = request.args.get('value', '')
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.analytics_db
        
        # ruleid: python-no-sql-injection
        pipeline = [
            {"$match": {match_field: match_value}},
            {"$group": {"_id": "$" + match_field, "count": {"$sum": 1}}}
        ]
        
        results = db.events.aggregate(pipeline)
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_8():
    """MongoDB injection via update operation"""
    app = Flask(__name__)
    
    @app.route('/update-profile', methods=['POST'])
    def update_profile():
        user_id = request.form.get('user_id')
        field = request.form.get('field')
        value = request.form.get('value')
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.user_database
        
        # ruleid: python-no-sql-injection
        update_result = db.users.update_one(
            {"_id": user_id},
            {"$set": {field: value}}
        )
        
        return jsonify({"modified_count": update_result.modified_count})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_9():
    """MongoDB injection via eval command"""
    app = Flask(__name__)
    
    @app.route('/execute')
    def execute_command():
        command = request.args.get('cmd', '')
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.admin
        
        # ruleid: python-no-sql-injection
        result = db.command('eval', command)
        
        return jsonify(result)
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_10():
    """MongoDB injection in Tornado web app"""
    class UserHandler(tornado.web.RequestHandler):
        def get(self):
            username = self.get_argument('username', '')
            client = MongoClient('mongodb://localhost:27017/')
            db = client.tornado_db
            
            # ruleid: python-no-sql-injection
            user = db.users.find_one({"username": username})
            
            self.write(json.dumps(user) if user else '{"error": "User not found"}')
    
    app = tornado.web.Application([
        (r"/user", UserHandler),
    ])
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_11():
    """MongoDB injection in Django view"""
    @require_http_methods(["GET"])
    def find_document(request):
        doc_id = request.GET.get('id', '')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.django_db
        
        # ruleid: python-no-sql-injection
        document = db.documents.find_one({"custom_id": doc_id})
        
        return HttpResponse(json.dumps(document) if document else '{"error": "Not found"}')

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_12():
    """DynamoDB injection via key construction"""
    app = Flask(__name__)
    
    @app.route('/dynamo-get')
    def get_dynamo_item():
        partition_key = request.args.get('partition', '')
        sort_key = request.args.get('sort', '')
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Orders')
        
        # ruleid: python-no-sql-injection
        response = table.get_item(
            Key={
                'OrderId': partition_key,
                'CustomerId': sort_key
            }
        )
        
        return jsonify(response.get('Item', {}))
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_13():
    """MongoDB injection via async motor client"""
    async def handle_request(request):
        query_param = request.query.get('query', '')
        client = motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost:27017')
        db = client.async_db
        
        # ruleid: python-no-sql-injection
        query = {"status": query_param}
        cursor = db.tasks.find(query)
        
        result = []
        async for document in cursor:
            result.append(document)
        return web.json_response(result)
    
    app = web.Application()
    app.router.add_get('/tasks', handle_request)
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_14():
    """MongoDB injection via direct string in find_one"""
    app = Flask(__name__)
    
    @app.route('/direct-query')
    def direct_query():
        email = request.args.get('email', '')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.users_db
        
        # ruleid: python-no-sql-injection
        user = db.users.find_one({"email": email})
        
        return jsonify(user) if user else jsonify({"error": "User not found"})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=1}
def bad_case_15():
    """MongoDB injection via regex pattern"""
    app = Flask(__name__)
    
    @app.route('/search-regex')
    def search_regex():
        pattern = request.args.get('pattern', '')
        client = MongoClient('mongodb://localhost:27017/')
        db = client.content_db
        
        # ruleid: python-no-sql-injection
        query = {"content": {"$regex": pattern}}
        results = db.articles.find(query)
        
        return jsonify([r for r in results])
    
    return app

# Secure Examples

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_1():
    """Safe MongoDB query with ObjectId conversion"""
    app = Flask(__name__)
    
    @app.route('/user/<user_id>')
    def get_user(user_id):
        client = MongoClient('mongodb://localhost:27017/')
        db = client.user_database
        
        try:
            # ok: python-no-sql-injection
            query = {"_id": ObjectId(user_id)}
            user = db.users.find_one(query)
            return jsonify(user) if user else jsonify({"error": "User not found"})
        except:
            return jsonify({"error": "Invalid ID format"})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_2():
    """Safe MongoDB query with input validation"""
    app = Flask(__name__)
    
    @app.route('/product')
    def get_product():
        product_id = request.args.get('id', '')
        
        # Input validation
        if not product_id.isalnum() or len(product_id) > 24:
            return jsonify({"error": "Invalid product ID"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.product_database
        
        # ok: python-no-sql-injection
        product = db.products.find_one({"product_id": product_id})
        
        return jsonify(product) if product else jsonify({"error": "Product not found"})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_3():
    """Safe DynamoDB query using conditions"""
    app = Flask(__name__)
    
    @app.route('/items')
    def get_items():
        category = request.args.get('category', '')
        
        # Input validation
        allowed_categories = ['electronics', 'books', 'clothing', 'food']
        if category not in allowed_categories:
            return jsonify({"error": "Invalid category"})
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Items')
        
        # ok: python-no-sql-injection
        response = table.query(
            KeyConditionExpression=Key('category').eq(category)
        )
        
        return jsonify(response['Items'])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_4():
    """Safe MongoDB query with parameterized query"""
    app = Flask(__name__)
    
    @app.route('/search')
    def search_users():
        name = request.args.get('name', '')
        age = request.args.get('age', '')
        
        # Input validation
        try:
            if age:
                age = int(age)
        except ValueError:
            return jsonify({"error": "Age must be a number"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.user_database
        
        query = {}
        if name:
            query["name"] = name
        if age:
            query["age"] = age
        
        # ok: python-no-sql-injection
        users = db.users.find(query)
        
        return jsonify([user for user in users])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_5():
    """Safe MongoDB aggregation with validated input"""
    app = Flask(__name__)
    
    @app.route('/stats')
    def get_stats():
        category = request.args.get('category', '')
        
        # Input validation
        allowed_categories = ['sales', 'inventory', 'customers']
        if category not in allowed_categories:
            return jsonify({"error": "Invalid category"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.business_db
        
        # ok: python-no-sql-injection
        pipeline = [
            {"$match": {"category": category}},
            {"$group": {"_id": "$region", "total": {"$sum": "$amount"}}}
        ]
        
        results = db.transactions.aggregate(pipeline)
        
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_6():
    """Safe DynamoDB scan with validated attributes"""
    app = Flask(__name__)
    
    @app.route('/filter')
    def filter_items():
        status = request.args.get('status', '')
        
        # Input validation
        allowed_statuses = ['active', 'pending', 'completed', 'cancelled']
        if status not in allowed_statuses:
            return jsonify({"error": "Invalid status"})
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Tasks')
        
        # ok: python-no-sql-injection
        response = table.scan(
            FilterExpression=Attr('status').eq(status)
        )
        
        return jsonify(response['Items'])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_7():
    """Safe MongoDB update with validated fields"""
    app = Flask(__name__)
    
    @app.route('/update-status', methods=['POST'])
    def update_status():
        user_id = request.form.get('user_id', '')
        status = request.form.get('status', '')
        
        # Input validation
        try:
            user_id_obj = ObjectId(user_id)
        except:
            return jsonify({"error": "Invalid user ID"})
        
        allowed_statuses = ['active', 'inactive', 'suspended']
        if status not in allowed_statuses:
            return jsonify({"error": "Invalid status"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.user_database
        
        # ok: python-no-sql-injection
        update_result = db.users.update_one(
            {"_id": user_id_obj},
            {"$set": {"status": status}}
        )
        
        return jsonify({"modified_count": update_result.modified_count})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_8():
    """Safe MongoDB query with type conversion"""
    app = Flask(__name__)
    
    @app.route('/products')
    def get_products_by_price():
        min_price = request.args.get('min_price', '0')
        max_price = request.args.get('max_price', '1000')
        
        # Input validation with type conversion
        try:
            min_price = float(min_price)
            max_price = float(max_price)
        except ValueError:
            return jsonify({"error": "Price must be a number"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.store_db
        
        # ok: python-no-sql-injection
        query = {"price": {"$gte": min_price, "$lte": max_price}}
        products = db.products.find(query)
        
        return jsonify([p for p in products])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_9():
    """Safe MongoDB query with whitelisted fields"""
    app = FastAPI()
    
    @app.get("/sort")
    async def sort_items(sort_field: str = Query(...)):
        # Input validation with whitelist
        allowed_fields = ["name", "price", "date_added", "popularity"]
        if sort_field not in allowed_fields:
            sort_field = "name"  # Default to a safe value
        
        client = motor.motor_asyncio.AsyncIOMotorClient('mongodb://localhost:27017')
        db = client.store_db
        
        # ok: python-no-sql-injection
        cursor = db.items.find().sort(sort_field, 1)
        
        result = []
        async for document in cursor:
            result.append(document)
        return result

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_10():
    """Safe DynamoDB query with validated key"""
    app = Flask(__name__)
    
    @app.route('/order/<order_id>')
    def get_order(order_id):
        # Input validation
        if not order_id.isalnum() or len(order_id) > 20:
            return jsonify({"error": "Invalid order ID"})
        
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table('Orders')
        
        # ok: python-no-sql-injection
        response = table.get_item(
            Key={
                'OrderId': order_id
            }
        )
        
        return jsonify(response.get('Item', {}))
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_11():
    """Safe MongoDB find with enum validation"""
    app = Flask(__name__)
    
    @app.route('/filter-by-role')
    def filter_by_role():
        role = request.args.get('role', '')
        
        # Input validation with enum
        valid_roles = ['admin', 'user', 'guest', 'moderator']
        if role not in valid_roles:
            return jsonify({"error": "Invalid role"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.access_db
        
        # ok: python-no-sql-injection
        users = db.users.find({"role": role})
        
        return jsonify([u for u in users])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_12():
    """Safe MongoDB query with regex pattern validation"""
    app = Flask(__name__)
    
    @app.route('/search-name')
    def search_name():
        name_pattern = request.args.get('pattern', '')
        
        # Input validation for regex safety
        import re
        if not re.match(r'^[a-zA-Z0-9 ]+$', name_pattern):
            return jsonify({"error": "Invalid search pattern"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.directory_db
        
        # ok: python-no-sql-injection
        query = {"name": {"$regex": name_pattern, "$options": "i"}}
        results = db.contacts.find(query)
        
        return jsonify([r for r in results])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_13():
    """Safe MongoDB delete with validated ID"""
    app = Flask(__name__)
    
    @app.route('/delete/<doc_id>', methods=['DELETE'])
    def delete_document(doc_id):
        # Input validation
        try:
            doc_id_obj = ObjectId(doc_id)
        except:
            return jsonify({"error": "Invalid document ID"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.content_db
        
        # ok: python-no-sql-injection
        result = db.documents.delete_one({"_id": doc_id_obj})
        
        return jsonify({"deleted_count": result.deleted_count})
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_14():
    """Safe MongoDB query with validated numeric range"""
    app = Flask(__name__)
    
    @app.route('/age-range')
    def get_by_age_range():
        min_age = request.args.get('min', '0')
        max_age = request.args.get('max', '100')
        
        # Input validation with numeric range
        try:
            min_age = int(min_age)
            max_age = int(max_age)
            
            if min_age < 0 or max_age > 120 or min_age > max_age:
                return jsonify({"error": "Invalid age range"})
                
        except ValueError:
            return jsonify({"error": "Age must be a number"})
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.demographics_db
        
        # ok: python-no-sql-injection
        query = {"age": {"$gte": min_age, "$lte": max_age}}
        people = db.people.find(query)
        
        return jsonify([p for p in people])
    
    return app

# {/fact}

# {fact rule=nosql-injection@v1.0 defects=0}
def good_case_15():
    """Safe MongoDB query with sanitized input for text search"""
    app = Flask(__name__)
    
    @app.route('/text-search')
    def text_search():
        search_text = request.args.get('q', '')
        
        # Sanitize input for text search
        import re
        search_text = re.sub(r'[^\w\s]', '', search_text)
        
        client = MongoClient('mongodb://localhost:27017/')
        db = client.content_db
        
        # ok: python-no-sql-injection
        query = {"$text": {"$search": search_text}}
        results = db.articles.find(query)
        
        return jsonify([r for r in results])
    
    return app
# {/fact}