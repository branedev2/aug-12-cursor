import cloudpickle
import pickle
import json
import yaml
import os
import base64
import io
from flask import Flask, request, jsonify
import requests
from tempfile import NamedTemporaryFile
import dill

app = Flask(__name__)

# True Positives (Vulnerable Code)

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_1():
    """Directly loading cloudpickle data from HTTP request"""
    @app.route('/deserialize', methods=['POST'])
    def deserialize_data():
        serialized_data = request.data
        # ruleid: unsafe-cloudpickle-load
        result = cloudpickle.load(io.BytesIO(serialized_data))
        return jsonify({"result": str(result)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_2():
    """Loading cloudpickle data from a file uploaded by a user"""
    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return "No file part"
        file = request.files['file']
        if file.filename == '':
            return "No selected file"
        # ruleid: unsafe-cloudpickle-load
        data = cloudpickle.load(file)
        return jsonify({"data": str(data)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_3():
    """Loading cloudpickle data from base64 encoded request parameter"""
    @app.route('/process', methods=['POST'])
    def process_data():
        encoded_data = request.form.get('data', '')
        decoded_data = base64.b64decode(encoded_data)
        # ruleid: unsafe-cloudpickle-load
        obj = cloudpickle.load(io.BytesIO(decoded_data))
        return jsonify({"processed": str(obj)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_4():
    """Loading cloudpickle data from a file path specified in request"""
    @app.route('/load_file', methods=['GET'])
    def load_file():
        file_path = request.args.get('path')
        with open(file_path, 'rb') as f:
            # ruleid: unsafe-cloudpickle-load
            data = cloudpickle.load(f)
        return jsonify({"file_data": str(data)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_5():
    """Loading cloudpickle data from an API response"""
    @app.route('/fetch_and_load', methods=['GET'])
    def fetch_and_load():
        url = request.args.get('url')
        response = requests.get(url)
        # ruleid: unsafe-cloudpickle-load
        data = cloudpickle.load(io.BytesIO(response.content))
        return jsonify({"remote_data": str(data)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_6():
    """Loading cloudpickle data with loads() function"""
    @app.route('/loads_data', methods=['POST'])
    def loads_data():
        serialized_data = request.data
        # ruleid: unsafe-cloudpickle-load
        result = cloudpickle.loads(serialized_data)
        return jsonify({"result": str(result)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_7():
    """Loading cloudpickle data from a temporary file"""
    @app.route('/temp_file', methods=['POST'])
    def temp_file_load():
        serialized_data = request.data
        with NamedTemporaryFile(delete=False) as temp:
            temp.write(serialized_data)
            temp_path = temp.name
        
        with open(temp_path, 'rb') as f:
            # ruleid: unsafe-cloudpickle-load
            data = cloudpickle.load(f)
        
        os.unlink(temp_path)
        return jsonify({"data": str(data)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_8():
    """Loading cloudpickle data from a request with error handling"""
    @app.route('/safe_load', methods=['POST'])
    def safe_load():
        try:
            serialized_data = request.data
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(serialized_data))
            return jsonify({"result": str(result)})
        except Exception as e:
            return jsonify({"error": str(e)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_9():
    """Loading cloudpickle data from a JSON field in request"""
    @app.route('/json_pickle', methods=['POST'])
    def json_pickle():
        json_data = request.get_json()
        if 'pickled_data' in json_data:
            pickled_data = base64.b64decode(json_data['pickled_data'])
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(pickled_data))
            return jsonify({"result": str(result)})
        return jsonify({"error": "No pickled data found"})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_10():
    """Loading cloudpickle data from a cookie"""
    @app.route('/cookie_load', methods=['GET'])
    def cookie_load():
        if 'pickled_data' in request.cookies:
            pickled_data = base64.b64decode(request.cookies.get('pickled_data'))
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(pickled_data))
            return jsonify({"result": str(result)})
        return "No pickled data in cookies"

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_11():
    """Loading cloudpickle data from a header"""
    @app.route('/header_load', methods=['GET'])
    def header_load():
        if 'X-Pickled-Data' in request.headers:
            pickled_data = base64.b64decode(request.headers.get('X-Pickled-Data'))
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(pickled_data))
            return jsonify({"result": str(result)})
        return "No pickled data in headers"

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_12():
    """Loading cloudpickle data with protocol specification"""
    @app.route('/protocol_load', methods=['POST'])
    def protocol_load():
        serialized_data = request.data
        # ruleid: unsafe-cloudpickle-load
        result = cloudpickle.load(io.BytesIO(serialized_data), protocol=4)
        return jsonify({"result": str(result)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_13():
    """Loading cloudpickle data from a query parameter"""
    @app.route('/query_load', methods=['GET'])
    def query_load():
        if 'data' in request.args:
            pickled_data = base64.b64decode(request.args.get('data'))
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(pickled_data))
            return jsonify({"result": str(result)})
        return "No pickled data in query"

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_14():
    """Loading cloudpickle data from a multipart form"""
    @app.route('/form_load', methods=['POST'])
    def form_load():
        if 'pickled_data' in request.form:
            pickled_data = base64.b64decode(request.form['pickled_data'])
            # ruleid: unsafe-cloudpickle-load
            result = cloudpickle.load(io.BytesIO(pickled_data))
            return jsonify({"result": str(result)})
        return "No pickled data in form"

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
def bad_case_15():
    """Loading cloudpickle data with a custom file-like object"""
    @app.route('/custom_load', methods=['POST'])
    def custom_load():
        class CustomBytesIO(io.BytesIO):
            pass
        
        serialized_data = request.data
        custom_io = CustomBytesIO(serialized_data)
        # ruleid: unsafe-cloudpickle-load
        result = cloudpickle.load(custom_io)
        return jsonify({"result": str(result)})


# True Negatives (Safe Code)

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_1():
    """Using JSON instead of cloudpickle for deserialization"""
    @app.route('/deserialize_json', methods=['POST'])
    def deserialize_json():
        # ok: unsafe-cloudpickle-load
        data = json.loads(request.data)
        return jsonify({"result": data})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_2():
    """Using YAML instead of cloudpickle for deserialization"""
    @app.route('/deserialize_yaml', methods=['POST'])
    def deserialize_yaml():
        # ok: unsafe-cloudpickle-load
        data = yaml.safe_load(request.data)
        return jsonify({"result": data})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_3():
    """Using cloudpickle only for trusted, internally generated data"""
    def internal_function():
        data = {"name": "internal", "value": 42}
        serialized = cloudpickle.dumps(data)
        # ok: unsafe-cloudpickle-load
        result = cloudpickle.loads(serialized)  # Safe because data is generated internally
        return result

    @app.route('/internal_data', methods=['GET'])
    def get_internal_data():
        result = internal_function()
        return jsonify(result)

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_4():
    """Using a custom validation function before deserialization"""
    @app.route('/validated_deserialize', methods=['POST'])
    def validated_deserialize():
        def is_safe_structure(data):
            # Implement validation logic to ensure the structure is safe
            # This is a simplified example
            try:
                obj = json.loads(data)
                # Check if it's a simple dictionary with expected keys
                if isinstance(obj, dict) and all(k in ['name', 'value'] for k in obj.keys()):
                    return True
                return False
            except:
                return False
        
        if is_safe_structure(request.data):
            # Convert to JSON and back to ensure safety
            # ok: unsafe-cloudpickle-load
            safe_data = json.loads(request.data)
            return jsonify({"result": safe_data})
        else:
            return jsonify({"error": "Invalid data structure"})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_5():
    """Using a secure serialization format with schema validation"""
    @app.route('/schema_validated', methods=['POST'])
    def schema_validated():
        from marshmallow import Schema, fields, ValidationError
        
        class DataSchema(Schema):
            name = fields.String(required=True)
            value = fields.Integer(required=True)
        
        schema = DataSchema()
        try:
            # ok: unsafe-cloudpickle-load
            result = schema.loads(request.data)
            return jsonify({"result": result})
        except ValidationError as err:
            return jsonify({"errors": err.messages}), 400

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_6():
    """Using pickle with a custom unpickler for safety"""
    @app.route('/safe_unpickle', methods=['POST'])
    def safe_unpickle():
        class SafeUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Only allow safe classes
                if module == "__main__" and name == "SafeClass":
                    return SafeClass
                raise pickle.UnpicklingError(f"Unpickling {module}.{name} is forbidden")
        
        class SafeClass:
            def __init__(self, value):
                self.value = value
        
        try:
            # ok: unsafe-cloudpickle-load
            unpickler = SafeUnpickler(io.BytesIO(request.data))
            result = unpickler.load()
            return jsonify({"result": str(result.value)})
        except Exception as e:
            return jsonify({"error": str(e)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_7():
    """Using a secure serialization library"""
    @app.route('/secure_serialize', methods=['POST'])
    def secure_serialize():
        import msgpack
        try:
            # ok: unsafe-cloudpickle-load
            data = msgpack.unpackb(request.data)
            return jsonify({"result": data})
        except Exception as e:
            return jsonify({"error": str(e)})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_8():
    """Using cloudpickle only in a controlled environment with trusted data"""
    def process_trusted_data():
        # This function is only called internally with trusted data
        trusted_data = cloudpickle.dumps({"trusted": True})
        # ok: unsafe-cloudpickle-load
        result = cloudpickle.loads(trusted_data)
        return result

    @app.route('/get_processed_data', methods=['GET'])
    def get_processed_data():
        # No user input is used in the deserialization
        result = process_trusted_data()
        return jsonify(result)

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_9():
    """Using a database instead of serialization for data storage"""
    @app.route('/store_data', methods=['POST'])
    def store_data():
        data = request.get_json()
        # ok: unsafe-cloudpickle-load
        # Using a database to store data instead of serialization
        # This is a simplified example - in a real app, you'd use an actual database
        stored_data = {"id": 1, "data": data}
        return jsonify({"stored": stored_data})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_10():
    """Converting untrusted data to a safe format before processing"""
    @app.route('/convert_and_process', methods=['POST'])
    def convert_and_process():
        # Parse the incoming data as JSON
        data = request.get_json()
        
        # Convert to a safe format
        safe_data = {
            "name": str(data.get("name", "")),
            "value": int(data.get("value", 0))
        }
        
        # ok: unsafe-cloudpickle-load
        # Process the safe data
        result = {"processed": safe_data}
        return jsonify(result)

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_11():
    """Using environment variables for configuration instead of deserialization"""
    @app.route('/config', methods=['GET'])
    def get_config():
        # ok: unsafe-cloudpickle-load
        config = {
            "debug": os.environ.get("DEBUG", "False") == "True",
            "api_key": os.environ.get("API_KEY", ""),
            "max_connections": int(os.environ.get("MAX_CONNECTIONS", "10"))
        }
        return jsonify(config)

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_12():
    """Using a type-safe serialization format"""
    @app.route('/protobuf', methods=['POST'])
    def process_protobuf():
        try:
            from google.protobuf.json_format import Parse
            from example_pb2 import ExampleMessage  # Assuming this is defined
            
            # ok: unsafe-cloudpickle-load
            # Parse JSON into a strongly-typed protobuf message
            message = Parse(request.data, ExampleMessage())
            return jsonify({"processed": True})
        except ImportError:
            # Simplified example - in real code, you'd handle this differently
            return jsonify({"error": "Protobuf not available"})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_13():
    """Using a custom data format with explicit parsing"""
    @app.route('/custom_format', methods=['POST'])
    def custom_format():
        data = request.data.decode('utf-8')
        
        # ok: unsafe-cloudpickle-load
        # Parse a custom format manually
        parts = data.split('|')
        if len(parts) >= 2:
            result = {
                "command": parts[0],
                "parameters": parts[1].split(',')
            }
            return jsonify(result)
        return jsonify({"error": "Invalid format"})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_14():
    """Using cloudpickle only for serialization, not deserialization"""
    @app.route('/serialize_only', methods=['GET'])
    def serialize_only():
        data = {"name": "example", "value": 42}
        
        # ok: unsafe-cloudpickle-load
        # Only using cloudpickle for serialization, not deserialization
        serialized = cloudpickle.dumps(data)
        return jsonify({"serialized": base64.b64encode(serialized).decode('utf-8')})

# {/fact}

# {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
def good_case_15():
    """Using a different serialization library that doesn't execute code"""
    @app.route('/safe_serialization', methods=['POST'])
    def safe_serialization():
        import simplejson
        
        # ok: unsafe-cloudpickle-load
        data = simplejson.loads(request.data)
        return jsonify({"result": data})

# {/fact}

if __name__ == '__main__':
    app.run(debug=True)