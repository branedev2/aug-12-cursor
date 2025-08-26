# Examples for python-import-specific-module-from-library rule
# This rule detects broad library imports instead of specific module imports

# True Positives (Bad Cases) - Using broad imports

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1():
    # ruleid: python-import-specific-module-from-library
    import numpy
    
    # Only using array function but importing entire library
    data = numpy.array([1, 2, 3, 4, 5])
    return numpy.mean(data)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2():
    # ruleid: python-import-specific-module-from-library
    import pandas
    
    # Only using DataFrame but importing entire library
    df = pandas.DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
    return df.describe()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3():
    # ruleid: python-import-specific-module-from-library
    import matplotlib.pyplot
    
    # Only using plot function but importing entire module
    x = [1, 2, 3, 4]
    y = [10, 20, 25, 30]
    matplotlib.pyplot.plot(x, y)
    matplotlib.pyplot.show()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4():
    # ruleid: python-import-specific-module-from-library
    import requests
    
    # Only using get function but importing entire library
    response = requests.get('https://api.example.com/data')
    return response.json()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5():
    # ruleid: python-import-specific-module-from-library
    import os.path
    
    # Only using join function but importing entire module
    file_path = os.path.join('directory', 'file.txt')
    return file_path


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6():
    # ruleid: python-import-specific-module-from-library
    import json
    
    # Only using dumps function but importing entire library
    data = {'name': 'John', 'age': 30}
    return json.dumps(data)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7():
    # ruleid: python-import-specific-module-from-library
    import datetime
    
    # Only using datetime class but importing entire library
    current_time = datetime.datetime.now()
    return current_time.strftime('%Y-%m-%d')


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8():
    # ruleid: python-import-specific-module-from-library
    import collections
    
    # Only using Counter but importing entire library
    words = ['apple', 'banana', 'apple', 'orange', 'banana', 'apple']
    return collections.Counter(words)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9():
    # ruleid: python-import-specific-module-from-library
    import re
    
    # Only using search function but importing entire library
    text = "The quick brown fox jumps over the lazy dog"
    match = re.search(r'fox', text)
    return match.group() if match else None


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10():
    # ruleid: python-import-specific-module-from-library
    import urllib.parse
    
    # Only using urlencode function but importing entire module
    params = {'q': 'python programming', 'page': 1}
    return urllib.parse.urlencode(params)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11():
    # ruleid: python-import-specific-module-from-library
    import flask
    
    # Only using Flask class but importing entire library
    app = flask.Flask(__name__)
    
    @app.route('/')
    def home():
        return 'Hello, World!'
    
    return app


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12():
    # ruleid: python-import-specific-module-from-library
    import sqlalchemy
    
    # Only using create_engine function but importing entire library
    engine = sqlalchemy.create_engine('sqlite:///example.db')
    return engine


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13():
    # ruleid: python-import-specific-module-from-library
    import xml.etree.ElementTree
    
    # Only using parse function but importing entire module
    tree = xml.etree.ElementTree.parse('data.xml')
    root = tree.getroot()
    return root


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14():
    # ruleid: python-import-specific-module-from-library
    import itertools
    
    # Only using cycle function but importing entire library
    colors = ['red', 'green', 'blue']
    color_cycle = itertools.cycle(colors)
    return [next(color_cycle) for _ in range(5)]


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15():
    # ruleid: python-import-specific-module-from-library
    import hashlib
    
    # Only using sha256 function but importing entire library
    text = "secure this text"
    hash_obj = hashlib.sha256(text.encode())
    return hash_obj.hexdigest()


# True Negatives (Good Cases) - Using specific imports

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1():
    # ok: python-import-specific-module-from-library
    from numpy import array, mean
    
    # Importing only the specific functions needed
    data = array([1, 2, 3, 4, 5])
    return mean(data)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2():
    # ok: python-import-specific-module-from-library
    from pandas import DataFrame
    
    # Importing only the specific class needed
    df = DataFrame({'A': [1, 2, 3], 'B': [4, 5, 6]})
    return df.describe()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3():
    # ok: python-import-specific-module-from-library
    from matplotlib.pyplot import plot, show
    
    # Importing only the specific functions needed
    x = [1, 2, 3, 4]
    y = [10, 20, 25, 30]
    plot(x, y)
    show()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4():
    # ok: python-import-specific-module-from-library
    from requests import get
    
    # Importing only the specific function needed
    response = get('https://api.example.com/data')
    return response.json()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5():
    # ok: python-import-specific-module-from-library
    from os.path import join
    
    # Importing only the specific function needed
    file_path = join('directory', 'file.txt')
    return file_path


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6():
    # ok: python-import-specific-module-from-library
    from json import dumps
    
    # Importing only the specific function needed
    data = {'name': 'John', 'age': 30}
    return dumps(data)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7():
    # ok: python-import-specific-module-from-library
    from datetime import datetime
    
    # Importing only the specific class needed
    current_time = datetime.now()
    return current_time.strftime('%Y-%m-%d')


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8():
    # ok: python-import-specific-module-from-library
    from collections import Counter
    
    # Importing only the specific class needed
    words = ['apple', 'banana', 'apple', 'orange', 'banana', 'apple']
    return Counter(words)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9():
    # ok: python-import-specific-module-from-library
    from re import search
    
    # Importing only the specific function needed
    text = "The quick brown fox jumps over the lazy dog"
    match = search(r'fox', text)
    return match.group() if match else None


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10():
    # ok: python-import-specific-module-from-library
    from urllib.parse import urlencode
    
    # Importing only the specific function needed
    params = {'q': 'python programming', 'page': 1}
    return urlencode(params)


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11():
    # ok: python-import-specific-module-from-library
    from flask import Flask
    
    # Importing only the specific class needed
    app = Flask(__name__)
    
    @app.route('/')
    def home():
        return 'Hello, World!'
    
    return app


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12():
    # ok: python-import-specific-module-from-library
    from sqlalchemy import create_engine
    
    # Importing only the specific function needed
    engine = create_engine('sqlite:///example.db')
    return engine


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13():
    # ok: python-import-specific-module-from-library
    from xml.etree.ElementTree import parse
    
    # Importing only the specific function needed
    tree = parse('data.xml')
    root = tree.getroot()
    return root


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14():
    # ok: python-import-specific-module-from-library
    from itertools import cycle
    
    # Importing only the specific function needed
    colors = ['red', 'green', 'blue']
    color_cycle = cycle(colors)
    return [next(color_cycle) for _ in range(5)]


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15():
    # ok: python-import-specific-module-from-library
    from hashlib import sha256
    
    # Importing only the specific function needed
    text = "secure this text"
    hash_obj = sha256(text.encode())
    return hash_obj.hexdigest()
# {/fact}